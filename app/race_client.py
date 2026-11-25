"""双栈竞速重载客户端（含 TLS 1.2 会话恢复演示）。

竞速规则（与值班台需求一一对应）：

1. 先连 IPv6（目标字面地址 ``::1``），TLS 证书校验使用同一个 ``device_name``。
2. IPv6 在 ``parallel_delay``（默认 0.25s）内没有通过证书校验，就并行启动 IPv4。
3. IPv6 在等待窗口内提前失败，则立刻启动 IPv4，不等满 250ms。
4. 两路都用同一个 ``device_name`` 做 SNI / hostname 校验，信任同一张内置 CA。
5. 最先通过证书校验的一路成为 winner，在该连接上发送且仅发送一次 POST；
   其余连接立刻关闭释放。
6. 整次操作上限 ``deadline``（默认 3.0s）。
7. 截止时 POST 尚未开始发送 -> ``not_sent``（未下发）。
8. POST 已开始发送但没拿到完整回执 -> ``unknown``（结果未知），绝不换路重发。

TLS 1.2 会话恢复演示（``tls12_demo`` 开启时生效；关闭时行为与历史版本完全一致，
协议默认协商照旧、不接触会话缓存）：

9. 每次尝试都新建 TCP 连接；IPv4/IPv6 各在 :class:`~app.session_store.SessionStore`
   中保留至多一份经现有 CA + 设备名完整校验后保存的会话，证书到期后停用。
10. 发起握手前按栈领取单调世代号；携带缓存会话发起恢复时，若服务端未接受
    （拒绝恢复开关/票据失效/会话缓存不匹配），OpenSSL 会在**同一连接**上
    退化为完整握手，校验通过才允许继续并保存新会话。
11. 缓存操作全部在短临界区内完成（仅字典读写），并发握手绝不排队等缓存；
    较早发起的握手即使晚完成，也不能覆盖/清掉较新握手已保存的会话。

实现采用“每路一个工作线程 + 协调线程（调用 run 的线程）”，
winner 判定与“是否已开始发送”都在同一把锁下与截止时刻做原子协调。
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .session_store import HS_FULL, HS_RESUMED, IPV4, IPV6, STACKS, SessionStore

OTHER = {IPV6: IPV4, IPV4: IPV6}

HOSTS = {
    IPV6: os.environ.get("DEVICE_HOST_V6", "::1"),
    IPV4: os.environ.get("DEVICE_HOST_V4", "127.0.0.1"),
}

PARALLEL_DELAY = float(os.environ.get("RACE_PARALLEL_DELAY", "0.25"))
DEADLINE = float(os.environ.get("RACE_DEADLINE", "3.0"))

STATUS_DELIVERED = "delivered"
STATUS_NOT_SENT = "not_sent"
STATUS_UNKNOWN = "unknown"

STATUS_TEXT = {
    STATUS_DELIVERED: "已下发，收到设备回执",
    STATUS_NOT_SENT: "未下发",
    STATUS_UNKNOWN: "结果未知",
}


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


@dataclass
class RaceResult:
    request_id: str
    status: str
    status_text: str
    device_name: str
    winner: str | None = None
    post_started: bool = False
    receipt: dict[str, Any] | None = None
    error: str | None = None
    elapsed_ms: int = 0
    parallel_delay_s: float = PARALLEL_DELAY
    deadline_s: float = DEADLINE
    timeline: list[dict[str, Any]] = field(default_factory=list)
    attempts: dict[str, Any] = field(default_factory=dict)
    # winner 实际采用的握手方式：full（完整握手）/ resumed（会话恢复）/ None
    winner_handshake_kind: str | None = None
    tls12_demo: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "status_text": self.status_text,
            "device_name": self.device_name,
            "winner": self.winner,
            "post_started": self.post_started,
            "receipt": self.receipt,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "parallel_delay_ms": int(self.parallel_delay_s * 1000),
            "deadline_ms": int(self.deadline_s * 1000),
            "timeline": self.timeline,
            "attempts": self.attempts,
            "winner_handshake_kind": self.winner_handshake_kind,
            "tls12_demo": self.tls12_demo,
        }


def build_client_context(ca_cert: str | Path, tls12_only: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True          # 按 device_name 校验
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca_cert))
    if tls12_only:
        # 仅在演示开关打开期限定 TLS 1.2；默认不传时协议协商照旧
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class ReloadRace:
    """一次重载操作对应一个 ReloadRace 实例（不可复用）。"""

    def __init__(
        self,
        *,
        port: int,
        ca_cert: str | Path,
        device_name: str = "switch-demo.local",
        path: str = "/reload",
        parallel_delay: float = PARALLEL_DELAY,
        deadline: float = DEADLINE,
        request_id: str | None = None,
        payload: dict[str, Any] | None = None,
        tls12_demo: bool = False,
        session_store: SessionStore | None = None,
    ) -> None:
        self.port = port
        self.ca_cert = Path(ca_cert)
        self.device_name = device_name
        self.path = path
        self.parallel_delay = parallel_delay
        self.deadline = deadline
        self.request_id = request_id or f"req-{uuid.uuid4().hex[:12]}"
        self.payload = payload or {}

        # TLS 1.2 会话恢复演示；关闭时全程不读取/写入共享缓存
        self.tls12_demo = bool(tls12_demo)
        self.session_store = session_store if self.tls12_demo else None

        self._t0 = time.monotonic()
        self._deadline_mono = self._t0 + deadline

        self._lock = threading.RLock()
        self._timeline: list[dict[str, Any]] = []
        self._socks: dict[str, socket.socket] = {}
        self._v4_started = False
        self._winner: str | None = None
        self._post_started = False
        self._canceled = False

        self._cert_passed = {s: threading.Event() for s in STACKS}
        self._failed = {s: threading.Event() for s in STACKS}
        # 任一路到达终态（证书通过 或 失败）都会 set 对应的 settled
        self._settled = {s: threading.Event() for s in STACKS}
        self._post_done = threading.Event()

        self._attempt_errors: dict[str, str] = {}
        self._cert_info: dict[str, dict[str, Any]] = {}
        self._receipt: dict[str, Any] | None = None
        self._post_error: str | None = None
        self._post_started_mono: float | None = None

        # 演示模式：复用 SessionStore 持有的共享 SSLContext
        # （SSLSession 与 context 绑定，且共享 context 支持并发握手）
        if self.tls12_demo and self.session_store is not None:
            self._ctx = self.session_store.client_context(
                self.ca_cert, tls12_only=True
            )
        else:
            self._ctx = build_client_context(self.ca_cert, tls12_only=False)
        self._threads: list[threading.Thread] = []

    # ---------- 工具 ----------

    def _remaining(self) -> float:
        return self._deadline_mono - time.monotonic()

    def _emit(self, event: str, stack: str | None = None, **detail: Any) -> None:
        item = {
            "t_ms": int((time.monotonic() - self._t0) * 1000),
            "event": event,
        }
        if stack:
            item["stack"] = stack
        item.update(detail)
        with self._lock:
            self._timeline.append(item)

    def _register_sock(self, stack: str, sock: socket.socket) -> None:
        with self._lock:
            self._socks[stack] = sock

    def _release_stack(self, stack: str) -> bool:
        with self._lock:
            sock = self._socks.pop(stack, None)
        if sock is None:
            return False
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
        return True

    def _release_all(self) -> None:
        with self._lock:
            items = list(self._socks.items())
            self._socks.clear()
        for _stack, sock in items:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    # ---------- 主入口 / 协调逻辑 ----------

    def run(self) -> RaceResult:
        body = json.dumps(
            {"request_id": self.request_id, "device": self.device_name, **self.payload}
        ).encode("utf-8")
        self._body = body
        self._request_bytes = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.device_name}\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + body

        self._emit(
            "race_start",
            detail={
                "device": self.device_name,
                "targets": {s: f"https://{HOSTS[s]}:{self.port}" for s in STACKS},
                "parallel_delay_ms": int(self.parallel_delay * 1000),
                "deadline_ms": int(self.deadline * 1000),
                "tls12_demo": self.tls12_demo,
            },
        )

        t6 = threading.Thread(target=self._attempt, args=(IPV6,), name="race-v6", daemon=True)
        self._threads.append(t6)
        t6.start()

        # 阶段 1：先等 IPv6，最多 parallel_delay；提前失败立刻切 IPv4
        wait_s = min(self.parallel_delay, max(0.0, self._remaining()))
        self._settled[IPV6].wait(wait_s)
        if self._cert_passed[IPV6].is_set():
            self._emit("ipv6_passed_within_window")
        elif self._failed[IPV6].is_set():
            self._emit("ipv6_early_failure_detected")
            self._start_v4(reason="ipv6_early_failure")
        else:
            # 等待超时（250ms 到点）且 IPv6 仍未通过校验
            if self._remaining() > 0:
                self._emit("parallel_window_elapsed")
                self._start_v4(reason="parallel_delay_250ms")

        # 阶段 2：等 POST 完成，或截止，或两路都提前失败
        while True:
            rem = self._remaining()
            if rem <= 0:
                self._emit("deadline_reached")
                break
            if self._post_done.wait(timeout=min(0.02, rem)):
                break
            if self._both_failed_without_winner():
                self._emit("both_paths_failed_early")
                break

        result = self._finalize()

        # 给工作线程一点时间响应 socket 关闭（仅为了测试/进程整洁）
        for t in self._threads:
            t.join(timeout=0.5)
        return result

    def _both_failed_without_winner(self) -> bool:
        with self._lock:
            if self._winner is not None:
                return False
            v4_running = self._v4_started
        if not self._failed[IPV6].is_set():
            return False
        if not v4_running:
            return False
        return self._failed[IPV4].is_set()

    def _start_v4(self, reason: str) -> None:
        with self._lock:
            if self._v4_started:
                return
            self._v4_started = True
        self._emit("start_path", IPV4, reason=reason)
        t4 = threading.Thread(target=self._attempt, args=(IPV4,), name="race-v4", daemon=True)
        self._threads.append(t4)
        t4.start()

    # ---------- 单路尝试 ----------

    def _attempt(self, stack: str) -> None:
        host = HOSTS[stack]
        family = socket.AF_INET6 if stack == IPV6 else socket.AF_INET
        raw: socket.socket | None = None
        # 世代号在任何 I/O 之前领取：先发起的握手世代号一定更小，
        # 之后无论何时完成都无法覆盖更晚握手保存的会话。
        generation = self.session_store.begin(stack) if self.session_store else 0
        resumption_attempted = False
        try:
            with self._lock:
                if self._canceled:
                    return

            raw = socket.socket(family, socket.SOCK_STREAM)
            raw.settimeout(max(0.02, self._remaining()))
            self._register_sock(stack, raw)

            connect_addr: tuple[Any, ...]
            if family == socket.AF_INET6:
                connect_addr = (host, self.port, 0, 0)
            else:
                connect_addr = (host, self.port)
            t_connect = time.monotonic()
            raw.connect(connect_addr)  # 每次尝试都是全新 TCP 连接
            self._emit(
                "tcp_connected",
                stack,
                connect_ms=int((time.monotonic() - t_connect) * 1000),
            )

            # 演示模式：尝试取本栈缓存的会话（证书/会话到期、context 重建由 SessionStore 拦截）
            cached_session = None
            if self.session_store is not None:
                cached_session = self.session_store.take(
                    stack, context_id=id(self._ctx)
                )
                resumption_attempted = cached_session is not None
                if resumption_attempted:
                    self._emit("session_resume_attempted", stack, generation=generation)

            # wrap_socket(do_handshake_on_connect 默认 True)：
            # 返回成功即代表 TLS 握手 + 证书校验（含 hostname）通过。
            # 携带 session 时若服务端拒绝恢复，OpenSSL 在同一连接上自动退化为完整握手。
            raw.settimeout(max(0.02, self._remaining()))
            t_hs = time.monotonic()
            if cached_session is not None:
                tls_sock = self._ctx.wrap_socket(
                    raw, server_hostname=self.device_name, session=cached_session
                )
            else:
                tls_sock = self._ctx.wrap_socket(raw, server_hostname=self.device_name)
            raw = None  # 所有权已移交 TLS socket
            hs_ms = int((time.monotonic() - t_hs) * 1000)

            with self._lock:
                if self._canceled:
                    should_close = tls_sock
                else:
                    self._socks[stack] = tls_sock
                    should_close = None
            if should_close is not None:
                should_close.close()
                return

            # 实际握手方式：以 OpenSSL 报告的 session_reused 为准；
            # 演示关闭时不暴露该字段，行为与历史版本完全一致。
            session_reused = bool(tls_sock.session_reused)
            handshake_kind = HS_RESUMED if session_reused else HS_FULL
            if self.tls12_demo:
                if session_reused:
                    self._emit(
                        "session_resumed",
                        stack,
                        generation=generation,
                        handshake_ms=hs_ms,
                    )
                elif resumption_attempted:
                    # 携带了缓存会话但服务端没有接受（拒绝恢复开关、票据失效、
                    # 服务端会话缓存不匹配等）：同一连接已按原规则完成完整握手且校验通过
                    self._emit(
                        "session_resume_declined_full_handshake",
                        stack,
                        generation=generation,
                        handshake_ms=hs_ms,
                    )
                else:
                    self._emit(
                        "full_handshake",
                        stack,
                        generation=generation,
                        handshake_ms=hs_ms,
                    )

            cert = tls_sock.getpeercert() or {}
            subject = dict(x[0] for x in cert.get("subject", ()))
            san = cert.get("subjectAltName", ())
            cert_not_after_epoch: float | None = None
            if "notAfter" in cert:
                try:
                    cert_not_after_epoch = float(ssl.cert_time_to_seconds(cert["notAfter"]))
                except Exception:
                    cert_not_after_epoch = None
            info: dict[str, Any] = {
                "subject_cn": subject.get("commonName"),
                "subject_alt_name": [f"{k}:{v}" for k, v in san],
                "cipher": (tls_sock.cipher() or [None])[0],
                "version": tls_sock.version(),
                "handshake_ms": hs_ms,
                "verified_against_name": self.device_name,
            }
            if self.tls12_demo:
                info.update(
                    handshake_kind=handshake_kind,
                    session_reused=session_reused,
                    generation=generation,
                )
            if cert_not_after_epoch is not None:
                info["cert_not_after_epoch"] = cert_not_after_epoch
            self._cert_info[stack] = info
            if self.tls12_demo:
                self._emit(
                    "cert_verified",
                    stack,
                    handshake_ms=hs_ms,
                    cn=subject.get("commonName"),
                    handshake_kind=handshake_kind,
                )
            else:
                self._emit(
                    "cert_verified",
                    stack,
                    handshake_ms=hs_ms,
                    cn=subject.get("commonName"),
                )

            # 校验通过后立即保存/刷新本栈会话（在 winner 判定之前，
            # 落败路径的会话同样保留，供下一次同栈重载恢复）。
            # 世代守卫保证旧握手不会覆盖新握手保存的会话。
            saved = False
            save_skipped_reason: str | None = None
            if self.session_store is not None and cert_not_after_epoch is not None:
                saved = self.session_store.save(
                    stack,
                    ssl_session=tls_sock.session,
                    handshake_kind=handshake_kind,
                    tls_version=tls_sock.version() or "",
                    cipher=(tls_sock.cipher() or [None, None, None])[0] or "",
                    generation=generation,
                    cert_not_after=cert_not_after_epoch,
                    context_id=id(self._ctx),
                )
                if not saved:
                    save_skipped_reason = "stale_generation"
                    self._emit("session_save_skipped_stale_generation", stack, generation=generation)
            self._cert_passed[stack].set()
            self._settled[stack].set()

            if not self._claim_winner(stack):
                # 另一路已经先通过：本连接立即释放，绝不发送
                self._emit("loser_released", stack, session_saved=saved,
                           save_skipped=save_skipped_reason)
                try:
                    tls_sock.close()
                except OSError:
                    pass
                return

            self._send_and_receive(stack, tls_sock)

        except BaseException as exc:  # 包括 socket.timeout / ssl.SSLError / OSError
            err = f"{type(exc).__name__}: {exc}"
            with self._lock:
                winner_is_this = self._winner == stack
                post_started = self._post_started
                canceled = self._canceled
            if winner_is_this and post_started:
                # 发送开始后的任何失败都归类为“结果未知”，且不重发
                self._post_error = self._post_error or err
                self._emit("post_connection_error", stack, error=err)
                self._post_done.set()
            elif canceled:
                # 协调方已取消本路（winner 选出后释放另一路、或截止关闭 socket）：
                # 这不是对端证书/协议问题，绝不能因此作废已缓存的会话。
                self._emit("attempt_canceled", stack, error=err)
            else:
                self._attempt_errors[stack] = err
                self._failed[stack].set()
                self._settled[stack].set()
                self._emit("attempt_failed", stack, error=err)
                # 仅 TLS 层失败（如证书过期/校验失败、协议告警）才作废本世代及更旧的
                # 会话；TCP 层的 stall 超时/RST 不代表会话失效，保留缓存。
                # 世代守卫保证不会清掉更晚发起的握手已保存的新会话。
                if self.session_store is not None and isinstance(exc, ssl.SSLError):
                    self.session_store.invalidate(stack, generation)
        finally:
            # 若 winner 已进入/完成自己的收发，socket 由 _send_and_receive 关闭；
            # 这里的 pop-close 是幂等兜底。
            with self._lock:
                owner = self._winner == stack and self._post_started
            if not owner:
                self._release_stack(stack)

    def _claim_winner(self, stack: str) -> bool:
        with self._lock:
            if self._canceled or self._winner is not None:
                return False
            self._winner = stack
        self._emit("winner_selected", stack)
        # 最先通过 -> 立即释放另一路（无论它还在握手还是已通过待判定）。
        # 若另一路尚未创建 socket，则等它自己运行时看到 winner 后自行释放。
        if self._release_stack(OTHER[stack]):
            self._emit("other_path_released", OTHER[stack])
        return True

    # ---------- 仅 winner 执行一次 ----------

    def _send_and_receive(self, stack: str, sock: ssl.SSLSocket) -> None:
        try:
            # 与截止时刻原子协调：截止已到 / 已被取消，则不能再开始发送，
            # 最终归类为 not_sent。
            with self._lock:
                if self._canceled or self._remaining() <= 0:
                    self._post_error = "deadline before POST start"
                    self._post_done.set()
                    return
                self._post_started = True
                self._post_started_mono = time.monotonic()

            self._emit("post_started", stack, bytes=len(self._request_bytes))
            sock.settimeout(max(0.02, self._remaining()))
            sock.sendall(self._request_bytes)
            self._emit("post_sent", stack)

            # 用 http.client 解析响应；连接被掐断 / 响应不完整会抛异常或
            # IncompleteRead，统一落入“结果未知”。
            sock.settimeout(max(0.02, self._remaining()))
            response = http.client.HTTPResponse(sock, method="POST")
            response.begin()
            status = response.status
            reason = response.reason
            raw_body = response.read()  # Content-Length 不足时抛 IncompleteRead
            if self._remaining() <= 0:
                raise socket.timeout("deadline reached while reading receipt")
            try:
                receipt_json = json.loads(raw_body.decode("utf-8")) if raw_body else None
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"receipt not valid JSON: {exc}") from exc
            if receipt_json is None:
                raise ValueError("empty receipt body")

            self._receipt = {
                "http_status": status,
                "http_reason": reason,
                "body": receipt_json,
                "bytes": len(raw_body),
            }
            self._emit("receipt_received", stack, http_status=status)
        except BaseException as exc:
            self._post_error = f"{type(exc).__name__}: {exc}"
            self._emit("receipt_failed", stack, error=self._post_error)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._release_stack(stack)
            self._post_done.set()

    # ---------- 汇总 ----------

    def _finalize(self) -> RaceResult:
        with self._lock:
            if self._receipt is not None:
                status = STATUS_DELIVERED
                error = None
            elif self._post_started:
                status = STATUS_UNKNOWN
                error = self._post_error or "connection lost before complete receipt"
            else:
                status = STATUS_NOT_SENT
                error = self._post_error or "no path passed certificate verification in time"
            # 通知所有残留工作线程停止，并关闭剩余 socket
            self._canceled = True
            post_started = self._post_started
            winner = self._winner

        self._release_all()

        elapsed_ms = int((time.monotonic() - self._t0) * 1000)
        attempts: dict[str, Any] = {}
        for s in STACKS:
            cert = self._cert_info.get(s)
            attempts[s] = {
                "host": HOSTS[s],
                "error": self._attempt_errors.get(s),
                "cert": cert,
                "cert_passed": self._cert_passed[s].is_set(),
                "failed": self._failed[s].is_set(),
                "handshake_kind": cert.get("handshake_kind") if cert else None,
                "tls_version": cert.get("version") if cert else None,
                "session_reused": cert.get("session_reused") if cert else None,
            }

        winner_handshake_kind = None
        if winner is not None:
            winner_handshake_kind = attempts[winner].get("handshake_kind")

        self._emit("finalized", detail={"status": status, "post_started": post_started})

        return RaceResult(
            request_id=self.request_id,
            status=status,
            status_text=STATUS_TEXT[status],
            device_name=self.device_name,
            winner=winner,
            post_started=post_started,
            receipt=self._receipt,
            error=error,
            elapsed_ms=elapsed_ms,
            parallel_delay_s=self.parallel_delay,
            deadline_s=self.deadline,
            timeline=list(self._timeline),
            attempts=attempts,
            winner_handshake_kind=winner_handshake_kind,
            tls12_demo=self.tls12_demo,
        )


def run_reload(
    *,
    port: int,
    ca_cert: str | Path,
    device_name: str = "switch-demo.local",
    parallel_delay: float = PARALLEL_DELAY,
    deadline: float = DEADLINE,
    tls12_demo: bool = False,
    session_store: SessionStore | None = None,
) -> RaceResult:
    return ReloadRace(
        port=port,
        ca_cert=ca_cert,
        device_name=device_name,
        parallel_delay=parallel_delay,
        deadline=deadline,
        tls12_demo=tls12_demo,
        session_store=session_store,
    ).run()
