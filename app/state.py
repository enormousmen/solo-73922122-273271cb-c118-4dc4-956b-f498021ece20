"""共享的样例设备状态。

IPv4 / IPv6 两个监听栈共用同一个 DeviceState，因此重载计数是“两路共用”的。
TLS 1.2 会话恢复演示的会话缓存（:class:`~app.session_store.SessionStore`）也挂在这里，
值班台与竞速客户端共享同一份按栈隔离的缓存。
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from .session_store import SessionStore

MODE_OK = "ok"
MODE_STALL = "stall"   # 接受 TCP 后卡住 TLS 握手
MODE_RESET = "reset"   # 接受后立即 RST/关闭，制造“提前失败”

VALID_MODES = (MODE_OK, MODE_STALL, MODE_RESET)

MODE_LABELS = {
    MODE_OK: "正常",
    MODE_STALL: "握手卡住",
    MODE_RESET: "快速拒绝",
}


class DeviceState:
    def __init__(self, device_name: str = "switch-demo.local", execution_delay: float = 0.15):
        self.device_name = device_name
        # 正常下发后模拟设备处理的耗时；断连模式下“执行”到断连之间的耗时
        self.execution_delay = execution_delay
        self.started_at = time.time()
        self._lock = threading.RLock()
        self.reload_count = 0
        self.stack_count = {"ipv4": 0, "ipv6": 0}
        self.settings: dict[str, Any] = {
            "ipv6_mode": MODE_OK,
            "ipv4_mode": MODE_OK,
            "disconnect_after_execute": False,
            # TLS 1.2 会话恢复演示开关：
            # 关闭（默认）时 TLS 协议协商与缓存行为完全照旧；
            # 开启后客户端/服务端都限定 TLS 1.2，并启用按栈的会话缓存。
            "tls12_demo": False,
            # 服务端按栈拒绝会话恢复（OP_NO_TICKET + 重建 context 清空服务端缓存）
            "ipv6_reject_resume": False,
            "ipv4_reject_resume": False,
        }
        self._history: deque[dict[str, Any]] = deque(maxlen=30)
        self.sessions = SessionStore()

    def get_mode(self, stack: str) -> str:
        with self._lock:
            return self.settings.get(f"{stack}_mode", MODE_OK)

    def rejects_resume(self, stack: str) -> bool:
        with self._lock:
            return bool(self.settings.get(f"{stack}_reject_resume", False))

    def tls12_demo_enabled(self) -> bool:
        with self._lock:
            return bool(self.settings.get("tls12_demo", False))

    def update_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if "ipv6_mode" in patch:
                mode = patch["ipv6_mode"]
                if mode not in VALID_MODES:
                    raise ValueError(f"invalid ipv6_mode: {mode!r}")
                self.settings["ipv6_mode"] = mode
            if "ipv4_mode" in patch:
                mode = patch["ipv4_mode"]
                if mode not in VALID_MODES:
                    raise ValueError(f"invalid ipv4_mode: {mode!r}")
                self.settings["ipv4_mode"] = mode
            if "disconnect_after_execute" in patch:
                self.settings["disconnect_after_execute"] = bool(
                    patch["disconnect_after_execute"]
                )
            if "tls12_demo" in patch:
                self.settings["tls12_demo"] = bool(patch["tls12_demo"])
            if "ipv6_reject_resume" in patch:
                self.settings["ipv6_reject_resume"] = bool(patch["ipv6_reject_resume"])
            if "ipv4_reject_resume" in patch:
                self.settings["ipv4_reject_resume"] = bool(patch["ipv4_reject_resume"])
            return dict(self.settings)

    def register_reload(
        self,
        stack: str,
        request_id: str,
        peer: str = "",
        tls_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """设备真正执行一次重载时调用；两个栈共用同一计数。"""
        with self._lock:
            self.reload_count += 1
            if stack in self.stack_count:
                self.stack_count[stack] += 1
            entry = {
                "seq": self.reload_count,
                "time": time.time(),
                "stack": stack,
                "request_id": request_id,
                "peer": peer,
                "disconnect": bool(self.settings["disconnect_after_execute"]),
                # 服务端视角的实际握手方式（TLS 1.2 演示开启时有值）
                "handshake_kind": (tls_info or {}).get("handshake_kind"),
                "tls_version": (tls_info or {}).get("tls_version"),
                "session_reused": (tls_info or {}).get("session_reused"),
            }
            self._history.append(entry)
            return {
                "reload_count": self.reload_count,
                "stack_count": dict(self.stack_count),
                "entry": dict(entry),
            }

    def reset_count(self) -> None:
        with self._lock:
            self.reload_count = 0
            self.stack_count = {"ipv4": 0, "ipv6": 0}
            self._history.clear()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "device_name": self.device_name,
                "reload_count": self.reload_count,
                "stack_count": dict(self.stack_count),
                "settings": dict(self.settings),
                "mode_labels": dict(MODE_LABELS),
                "uptime_s": round(time.time() - self.started_at, 1),
                "history": list(reversed(self._history)),
                "sessions": self.sessions.snapshot(),
            }
