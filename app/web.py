"""Flask 值班台应用工厂与 HTTP 路由。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from . import race_client
from .certutil import DEFAULT_DEVICE_NAME, ensure_certs
from .device import DualStackDevice
from .state import DeviceState


def create_app(
    *,
    device: DualStackDevice | None = None,
    state: DeviceState | None = None,
    ca_cert: str | Path | None = None,
    device_port: int | None = None,
    device_name: str = DEFAULT_DEVICE_NAME,
) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    # 直接输出中文 JSON（Flask 3 使用 json provider）
    app.config["JSON_AS_ASCII"] = False
    try:
        app.json.ensure_ascii = False  # type: ignore[attr-defined]
    except AttributeError:
        pass

    # 允许 main.py 注入已启动的内置设备；测试也可注入临时端口
    app.extensions["device_state"] = state or (device.state if device else DeviceState(device_name))
    app.extensions["device_handle"] = device
    paths = ensure_certs(device_name)
    app.extensions["ca_cert"] = Path(ca_cert) if ca_cert else paths["ca_cert"]
    app.extensions["device_name"] = device_name
    if device_port is not None:
        app.extensions["device_port"] = device_port
    elif device is not None:
        app.extensions["device_port"] = device.port
    else:
        app.extensions["device_port"] = int(os.environ.get("DEVICE_PORT", "8443"))

    def apply_device_tls() -> None:
        handle: DualStackDevice | None = app.extensions.get("device_handle")
        if handle is not None:
            handle.apply_tls_settings()

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"ok": True})

    @app.get("/")
    def index() -> str:
        st: DeviceState = app.extensions["device_state"]
        return render_template(
            "index.html",
            device_name=device_name,
            device_port=app.extensions["device_port"],
            parallel_delay_ms=int(race_client.PARALLEL_DELAY * 1000),
            deadline_ms=int(race_client.DEADLINE * 1000),
            tls12_demo=st.tls12_demo_enabled(),
        )

    @app.get("/api/state")
    def api_state() -> Any:
        st: DeviceState = app.extensions["device_state"]
        return jsonify(st.snapshot())

    @app.post("/api/settings")
    def api_settings() -> Any:
        st: DeviceState = app.extensions["device_state"]
        patch = request.get_json(silent=True) or {}
        demo_was_on = st.tls12_demo_enabled()
        try:
            settings = st.update_settings(patch)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        # 演示被关闭：回到默认协商，清空 TLS 1.2 会话缓存（context 也会重建，
        # 旧条目本就无法取用，这里让观测状态同步回到干净起点）
        if demo_was_on and not st.tls12_demo_enabled():
            st.sessions.forget("ipv4")
            st.sessions.forget("ipv6")
        # 协议版本/拒绝恢复相关开关变化后，热重建受影响栈的服务端 TLS context
        apply_device_tls()
        return jsonify({"ok": True, "settings": settings, "state": st.snapshot()})

    @app.post("/api/reset-count")
    def api_reset_count() -> Any:
        st: DeviceState = app.extensions["device_state"]
        st.reset_count()
        return jsonify({"ok": True, "state": st.snapshot()})

    @app.post("/api/session/forget")
    def api_session_forget() -> Any:
        """值班员让样例设备忘掉指定入口（ipv4/ipv6，或 both）的 TLS 会话。"""
        st: DeviceState = app.extensions["device_state"]
        body = request.get_json(silent=True) or {}
        stack = str(body.get("stack", "")).lower()
        targets = ("ipv4", "ipv6") if stack in ("both", "all", "") else (stack,)
        unknown = [s for s in targets if s not in ("ipv4", "ipv6")]
        if unknown:
            return jsonify({"ok": False, "error": f"invalid stack: {unknown[0]!r}"}), 400
        removed = {}
        for s in targets:
            removed[s] = st.sessions.forget(s)
        return jsonify({"ok": True, "removed": removed, "state": st.snapshot()})

    @app.post("/api/reload")
    def api_reload() -> Any:
        body = request.get_json(silent=True) or {}
        request_id = body.get("request_id")
        st: DeviceState = app.extensions["device_state"]
        race = race_client.ReloadRace(
            port=int(app.extensions["device_port"]),
            ca_cert=app.extensions["ca_cert"],
            device_name=app.extensions["device_name"],
            parallel_delay=float(
                body.get("parallel_delay_s", race_client.PARALLEL_DELAY)
            ),
            deadline=float(body.get("deadline_s", race_client.DEADLINE)),
            request_id=str(request_id) if request_id else None,
            tls12_demo=st.tls12_demo_enabled(),
            session_store=st.sessions,
        )
        result = race.run()
        return jsonify({"result": result.to_dict(), "device": st.snapshot()})

    return app
