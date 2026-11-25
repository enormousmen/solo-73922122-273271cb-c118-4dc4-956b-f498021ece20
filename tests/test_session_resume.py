"""TLS 1.2 会话恢复演示的端到端自测。

真实启动双栈 TLS 样例设备，验证：

- 同栈连续重载：第一次完整握手、第二次会话恢复（客户端与服务端视角一致）；
- 换栈：IPv4/IPv6 各存各的会话，互不覆盖；
- 忘记会话：缓存清空且在途旧握手世代作废，下一次重新完整握手；
- 服务端拒绝恢复：同一连接退化为完整握手，关闭拒绝后下一次可再次恢复；
- 会话缓存的并发语义：世代守卫阻止旧握手覆盖/清掉新会话，缓存操作不阻塞并发握手；
- 证书到期：take() 直接停用，且 OpenSSL 对过期证书即使带 session 也拒绝；
- 演示开关关闭（默认）时行为照旧：不读写缓存、协议默认协商。
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from app.certutil import ensure_certs  # noqa: E402
from app.device import DualStackDevice, build_server_tls_context  # noqa: E402
from app.race_client import IPV4, IPV6, ReloadRace  # noqa: E402
from app.session_store import (  # noqa: E402
    HS_FULL,
    HS_RESUMED,
    REASON_EXPIRED_CERT,
    SessionStore,
)
from app.state import MODE_OK, MODE_STALL, DeviceState  # noqa: E402


def free_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class SessionResumeScenarioTests(unittest.TestCase):
    device: DualStackDevice
    state: DeviceState
    certs: dict
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="tls12-resume-")
        cls.certs = ensure_certs("switch-demo.local", Path(cls.tmp.name))
        cls.state = DeviceState(execution_delay=0.02)
        cls.device = DualStackDevice(
            port=free_tcp_port(),
            cert_path=cls.certs["server_cert"],
            key_path=cls.certs["server_key"],
            state=cls.state,
        )
        cls.device.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.device.stop()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        self.state.reset_count()
        self.state.update_settings(
            {
                "ipv6_mode": MODE_OK,
                "ipv4_mode": MODE_OK,
                "disconnect_after_execute": False,
                "tls12_demo": False,
                "ipv6_reject_resume": False,
                "ipv4_reject_resume": False,
            }
        )
        self.device.apply_tls_settings()
        # 每轮从干净的会话缓存开始
        self.state.sessions.forget(IPV6)
        self.state.sessions.forget(IPV4)
        time.sleep(0.1)

    def run_race(self, **kw) -> dict:
        kwargs = dict(
            port=self.device.port,
            ca_cert=self.certs["ca_cert"],
            device_name="switch-demo.local",
            tls12_demo=True,
            session_store=self.state.sessions,
        )
        kwargs.update(kw)
        return ReloadRace(**kwargs).run().to_dict()

    def find_event(self, result: dict, name: str, stack: str | None = None) -> dict | None:
        for e in result["timeline"]:
            if e["event"] == name and (stack is None or e.get("stack") == stack):
                return e
        return None

    def enable_demo(self) -> None:
        self.state.update_settings({"tls12_demo": True})
        self.device.apply_tls_settings()

    # ------------------------------------------------------------------

    def test_01_same_stack_full_then_resumed(self) -> None:
        self.enable_demo()
        first = self.run_race()
        self.assertEqual(first["status"], "delivered", first.get("error"))
        self.assertEqual(first["winner"], IPV6)
        self.assertEqual(first["winner_handshake_kind"], HS_FULL)
        self.assertEqual(first["attempts"][IPV6]["tls_version"], "TLSv1.2")
        self.assertIsNotNone(self.find_event(first, "full_handshake", IPV6))
        snap = self.state.sessions.snapshot()
        self.assertTrue(snap[IPV6]["present"])
        self.assertEqual(snap[IPV6]["handshake_kind"], HS_FULL)

        second = self.run_race()
        self.assertEqual(second["status"], "delivered")
        self.assertEqual(second["winner"], IPV6)
        self.assertEqual(second["winner_handshake_kind"], HS_RESUMED)
        self.assertTrue(second["attempts"][IPV6]["session_reused"])
        self.assertIsNotNone(self.find_event(second, "session_resume_attempted", IPV6))
        self.assertIsNotNone(self.find_event(second, "session_resumed", IPV6))
        # 服务端视角也必须是 resumed
        hist = self.state.snapshot()["history"]
        self.assertEqual(hist[0]["handshake_kind"], "resumed")
        self.assertEqual(hist[1]["handshake_kind"], "full")

    def test_02_each_stack_keeps_its_own_session(self) -> None:
        self.enable_demo()
        # IPv6 一份
        self.run_race()
        # 让 IPv6 卡住，IPv4 接管并建立自己的会话
        self.state.update_settings({"ipv6_mode": MODE_STALL})
        r_v4 = self.run_race()
        self.assertEqual(r_v4["winner"], IPV4)
        self.assertEqual(r_v4["winner_handshake_kind"], HS_FULL)
        self.state.update_settings({"ipv6_mode": MODE_OK})
        time.sleep(0.1)

        snap = self.state.sessions.snapshot()
        self.assertTrue(snap[IPV6]["present"])
        self.assertTrue(snap[IPV4]["present"])
        self.assertNotEqual(snap[IPV6]["saved_at"], 0)
        # 两份会话相互独立（世代号各自增长）
        self.assertGreaterEqual(snap[IPV6]["generation"], 1)
        self.assertGreaterEqual(snap[IPV4]["generation"], 1)

        # 恢复正常后 IPv6 仍然能恢复自己的那份（带重试吸收调度抖动）
        r_v6_again = None
        for _ in range(3):
            candidate = self.run_race()
            if candidate["winner_handshake_kind"] == HS_RESUMED:
                r_v6_again = candidate
                break
        self.assertIsNotNone(r_v6_again, "IPv6 应复用其独立保存的会话")
        self.assertEqual(r_v6_again["winner"], IPV6)

    def test_03_forget_forces_full_handshake(self) -> None:
        self.enable_demo()
        self.run_race()
        self.assertEqual(
            self.state.sessions.snapshot()[IPV6]["handshake_kind"], HS_FULL
        )
        self.assertTrue(self.state.sessions.forget(IPV6))
        self.assertFalse(self.state.sessions.snapshot()[IPV6]["present"])

        after_forget = self.run_race()
        self.assertEqual(after_forget["winner_handshake_kind"], HS_FULL)
        self.assertIsNone(self.find_event(after_forget, "session_resume_attempted", IPV6))
        self.assertIsNotNone(self.find_event(after_forget, "full_handshake", IPV6))

        # 再下一次同栈重载可再次恢复（带重试吸收调度抖动）
        again = None
        for _ in range(3):
            candidate = self.run_race()
            if candidate["winner_handshake_kind"] == HS_RESUMED:
                again = candidate
                break
        self.assertIsNotNone(again, "忘记并重新完整握手后，下一次同栈重载应能恢复")

    def test_04_server_rejects_resume_then_reenables(self) -> None:
        self.enable_demo()
        self.run_race()  # 建立会话
        self.state.update_settings({"ipv6_reject_resume": True})
        self.device.apply_tls_settings()
        time.sleep(0.1)

        rejected = self.run_race()
        self.assertEqual(rejected["status"], "delivered")
        self.assertEqual(rejected["winner_handshake_kind"], HS_FULL)
        self.assertIsNotNone(
            self.find_event(rejected, "session_resume_declined_full_handshake", IPV6)
        )
        # 服务端记录的仍是完整握手
        self.assertEqual(self.state.snapshot()["history"][0]["handshake_kind"], "full")
        # 完整握手校验通过后已保存新会话（客户端侧）
        self.assertTrue(self.state.sessions.snapshot()[IPV6]["present"])

        # 关闭拒绝开关：OpenSSL 语义上拒绝期间不签发新票据，因此关闭后
        # 第一次同栈连接仍为完整握手（重新签发票据）……
        self.state.update_settings({"ipv6_reject_resume": False})
        self.device.apply_tls_settings()
        time.sleep(0.1)
        reestablished = self.run_race()
        self.assertEqual(reestablished["winner_handshake_kind"], HS_FULL)
        self.assertIsNotNone(
            self.find_event(reestablished, "session_resume_declined_full_handshake", IPV6)
        )
        # ……再下一次同栈重载即可再次恢复（带少量重试以吸收 CI 调度抖动）
        resumed = None
        for _ in range(3):
            candidate = self.run_race()
            if candidate["winner_handshake_kind"] == HS_RESUMED:
                resumed = candidate
                break
        self.assertIsNotNone(resumed, "关闭拒绝并重建票据后，同栈重载应能再次恢复")
        self.assertIsNotNone(self.find_event(resumed, "session_resumed", IPV6))

    def test_05_demo_off_default_negotiation_untouched(self) -> None:
        # 默认关闭：不传 tls12_demo，协议版本由 OpenSSL 默认协商，缓存不被触碰
        result = ReloadRace(
            port=self.device.port,
            ca_cert=self.certs["ca_cert"],
            device_name="switch-demo.local",
        ).run().to_dict()
        self.assertEqual(result["status"], "delivered")
        self.assertFalse(result["tls12_demo"])
        # 演示关闭时不产生 winner_handshake_kind 字段语义（结果中为 None）
        self.assertIsNone(result["winner_handshake_kind"])
        snap = self.state.sessions.snapshot()
        self.assertFalse(snap[IPV6]["present"])
        self.assertFalse(snap[IPV4]["present"])
        # 默认协商不限制版本（不强制 TLS 1.2）
        self.assertIn(
            result["attempts"][IPV6]["tls_version"], ("TLSv1.2", "TLSv1.3")
        )
        # 时间线中不应出现任何会话恢复相关事件
        for e in result["timeline"]:
            self.assertNotIn("session", e["event"])

    def test_06_each_attempt_is_a_new_tcp_connection(self) -> None:
        self.enable_demo()
        r1 = self.run_race()
        r2 = self.run_race()
        for r in (r1, r2):
            tcp_events = [e for e in r["timeline"] if e["event"] == "tcp_connected"]
            self.assertGreaterEqual(len(tcp_events), 1)
        # 第二次是恢复握手，但 TCP 仍然是新建的（有 tcp_connected 事件）
        self.assertIsNotNone(self.find_event(r2, "tcp_connected", IPV6))
        self.assertIsNotNone(self.find_event(r2, "session_resumed", IPV6))

    def test_07_reject_resume_per_stack_isolation(self) -> None:
        self.enable_demo()
        # 先让两栈各有一份会话
        self.run_race()
        self.state.update_settings({"ipv6_mode": MODE_STALL})
        self.run_race()  # IPv4 完整握手
        self.state.update_settings({"ipv6_mode": MODE_OK})
        time.sleep(0.1)
        # 只让 IPv4 拒绝
        self.state.update_settings({"ipv4_reject_resume": True})
        self.device.apply_tls_settings()
        time.sleep(0.1)

        # IPv6 仍可恢复（带重试吸收调度抖动）
        r6 = None
        for _ in range(3):
            candidate = self.run_race()
            if candidate["winner"] == IPV6 and candidate["winner_handshake_kind"] == HS_RESUMED:
                r6 = candidate
                break
        self.assertIsNotNone(r6, "IPv4 拒绝恢复不应影响 IPv6 的会话恢复")

        # IPv6 卡住后走 IPv4：应被拒绝并完整握手
        self.state.update_settings({"ipv6_mode": MODE_STALL})
        r4 = self.run_race()
        self.assertEqual(r4["winner"], IPV4)
        self.assertEqual(r4["winner_handshake_kind"], HS_FULL)
        self.assertIsNotNone(
            self.find_event(r4, "session_resume_declined_full_handshake", IPV4)
        )
        self.state.update_settings({"ipv6_mode": MODE_OK})

    def test_08_tcp_failure_does_not_invalidate_cached_session(self) -> None:
        self.enable_demo()
        self.run_race()  # 建立 IPv6 会话
        self.assertTrue(self.state.sessions.snapshot()[IPV6]["present"])
        # IPv6 握手卡住（TCP 层超时），IPv4 接管；IPv6 的缓存会话不得被作废
        self.state.update_settings({"ipv6_mode": MODE_STALL})
        r = self.run_race()
        self.assertEqual(r["winner"], IPV4)
        self.state.update_settings({"ipv6_mode": MODE_OK})
        time.sleep(0.1)
        self.assertTrue(
            self.state.sessions.snapshot()[IPV6]["present"],
            "TCP 层 stall 不应作废 TLS 会话缓存",
        )
        # 之后 IPv6 仍可用原会话恢复（带重试吸收调度抖动）
        again = None
        for _ in range(3):
            candidate = self.run_race()
            if candidate["winner_handshake_kind"] == HS_RESUMED:
                again = candidate
                break
        self.assertIsNotNone(again, "TCP stall 后 IPv6 会话应仍可恢复")
        self.assertEqual(again["winner"], IPV6)

    def test_09_disabling_demo_clears_cached_sessions(self) -> None:
        from app.web import create_app

        self.enable_demo()
        self.run_race()
        self.assertTrue(self.state.sessions.snapshot()[IPV6]["present"])
        app = create_app(
            device=self.device,
            state=self.state,
            ca_cert=self.certs["ca_cert"],
            device_port=self.device.port,
        )
        client = app.test_client()
        resp = client.post("/api/settings", json={"tls12_demo": False})
        self.assertEqual(resp.status_code, 200)
        snap = resp.get_json()["state"]["sessions"]
        self.assertFalse(snap[IPV6]["present"])
        self.assertFalse(snap[IPV4]["present"])


class SessionStoreUnitTests(unittest.TestCase):
    def _fake_session(self, has_ticket=True, timeout=7200.0):
        class _S:
            def __init__(self):
                self.has_ticket = has_ticket
                self.timeout = timeout
                self.id = b"x" * 32
        return _S()

    def test_generation_guard_older_cannot_overwrite_newer(self) -> None:
        store = SessionStore()
        now = 1000.0
        g_old = store.begin(IPV6)
        g_new = store.begin(IPV6)
        self.assertLess(g_old, g_new)
        # 新握手先完成并保存
        self.assertTrue(
            store.save(
                IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
                tls_version="TLSv1.2", cipher="c", generation=g_new,
                cert_not_after=now + 9999, context_id=42, now_wall=now,
            )
        )
        # 旧握手晚到：保存被拒绝，不能覆盖
        self.assertFalse(
            store.save(
                IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
                tls_version="TLSv1.2", cipher="old", generation=g_old,
                cert_not_after=now + 9999, context_id=42, now_wall=now,
            )
        )
        self.assertEqual(store.snapshot(now)[IPV6]["generation"], g_new)

    def test_invalidate_cannot_remove_newer_session(self) -> None:
        store = SessionStore()
        g_old = store.begin(IPV4)
        g_new = store.begin(IPV4)
        store.save(
            IPV4, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
            tls_version="TLSv1.2", cipher="c", generation=g_new,
            cert_not_after=2000.0, context_id=42, now_wall=1000.0,
        )
        # 旧握手失败：不得清掉新会话
        self.assertFalse(store.invalidate(IPV4, g_old))
        self.assertTrue(store.snapshot(1000.0)[IPV4]["present"])
        # 同世代或更旧世代的条目可以被作废
        self.assertTrue(store.invalidate(IPV4, g_new))
        self.assertFalse(store.snapshot(1000.0)[IPV4]["present"])

    def test_forget_raises_barrier_against_inflight(self) -> None:
        store = SessionStore()
        g = store.begin(IPV6)
        store.forget(IPV6)
        # 忘记之前已发起的在途握手之后完成，保存必须被屏障拒绝
        self.assertFalse(
            store.save(
                IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
                tls_version="TLSv1.2", cipher="c", generation=g,
                cert_not_after=2000.0, context_id=42, now_wall=1000.0,
            )
        )
        self.assertFalse(store.snapshot(1000.0)[IPV6]["present"])
        # 忘记之后新发起的握手可以正常保存
        g2 = store.begin(IPV6)
        self.assertTrue(
            store.save(
                IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
                tls_version="TLSv1.2", cipher="c", generation=g2,
                cert_not_after=2000.0, context_id=42, now_wall=1000.0,
            )
        )

    def test_expired_cert_disables_session(self) -> None:
        store = SessionStore()
        g = store.begin(IPV6)
        store.save(
            IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
            tls_version="TLSv1.2", cipher="c", generation=g,
            cert_not_after=100.0, context_id=42, now_wall=0.0,
        )
        self.assertIsNone(store.take(IPV6, now_wall=101.0))
        self.assertEqual(store.snapshot(101.0)[IPV6]["reason"], REASON_EXPIRED_CERT)

    def test_ticket_timeout_disables_session(self) -> None:
        store = SessionStore()
        g = store.begin(IPV4)
        store.save(
            IPV4, ssl_session=self._fake_session(timeout=100.0),
            handshake_kind=HS_FULL, tls_version="TLSv1.2", cipher="c",
            generation=g, cert_not_after=9999.0, context_id=42, now_wall=0.0,
        )
        self.assertIsNotNone(store.take(IPV4, now_wall=99.0))
        # 到 ticket 寿命后停用
        self.assertIsNone(store.take(IPV4, now_wall=101.0))

    def test_concurrent_begins_get_distinct_generations(self) -> None:
        store = SessionStore()
        gens: list[int] = []
        def worker() -> None:
            for _ in range(200):
                gens.append(store.begin(IPV6))
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(gens), 1600)
        self.assertEqual(len(set(gens)), 1600)
        self.assertEqual(min(gens), 1)
        self.assertEqual(max(gens), 1600)

    def test_lock_never_held_during_slow_operations(self) -> None:
        # 结构性保证：并发 begin/take/save/forget 在有延迟调度时不互相卡死
        store = SessionStore()
        stop = threading.Event()

        def churn() -> None:
            i = 0
            while not stop.is_set():
                g = store.begin(IPV6)
                store.take(IPV6)
                store.save(
                    IPV6, ssl_session=self._fake_session(), handshake_kind=HS_FULL,
                    tls_version="TLSv1.2", cipher="c", generation=g,
                    cert_not_after=time.time() + 9999, context_id=42,
                )
                if i % 7 == 0:
                    store.forget(IPV6)
                i += 1

        threads = [threading.Thread(target=churn, daemon=True) for _ in range(6)]
        for t in threads:
            t.start()
        time.sleep(0.4)
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
            self.assertFalse(t.is_alive(), "缓存锁导致并发握手排队/卡死")


class ExpiredCertIntegrationTests(unittest.TestCase):
    """过期证书：带缓存会话恢复时仍必须被完整校验拒绝。"""

    def test_openssl_rejects_expired_cert_even_with_session(self) -> None:
        import ssl

        tmp = Path(tempfile.mkdtemp())
        certs = ensure_certs("switch-demo.local", tmp)

        # 用同一 CA 签一张已过期的服务器证书
        now = dt.datetime.now(dt.timezone.utc)
        ca_cert = x509.load_pem_x509_certificate((tmp / "ca.pem").read_bytes())
        ca_key = serialization.load_pem_private_key(
            (tmp / "ca-key.pem").read_bytes(), password=None
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "switch-demo.local")])
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("switch-demo.local"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1")),
            ]
        )
        expired = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=10))
            .not_valid_after(now - dt.timedelta(days=1))
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (tmp / "expired.pem").write_bytes(expired.public_bytes(serialization.Encoding.PEM))
        (tmp / "expired-key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        port = free_tcp_port()
        ready = threading.Event()

        def serve_once(certfile: str, keyfile: str) -> None:
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            ready.set()  # 监听 socket 已就绪，客户端此时连接才不会被拒
            raw, _ = listener.accept()
            ctx = build_server_tls_context(certfile, keyfile, tls12_only=True)
            try:
                tls = ctx.wrap_socket(raw, server_side=True)
                tls.close()
            except Exception:
                pass
            listener.close()

        # 先用有效证书拿到一份会话
        t = threading.Thread(
            target=serve_once, args=(certs["server_cert"], certs["server_key"]), daemon=True
        )
        t.start()
        self.assertTrue(ready.wait(timeout=2.0), "测试监听线程未在时限内就绪")
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = True
        cctx.verify_mode = ssl.CERT_REQUIRED
        cctx.load_verify_locations(cafile=str(certs["ca_cert"]))
        cctx.maximum_version = ssl.TLSVersion.TLSv1_2
        sock = cctx.wrap_socket(
            socket.create_connection(("127.0.0.1", port)),
            server_hostname="switch-demo.local",
        )
        saved_session = sock.session
        sock.close()
        t.join(timeout=2)

        # 再用过期证书起服务，带同一份会话尝试恢复：必须被拒
        ready.clear()
        t2 = threading.Thread(
            target=serve_once, args=(tmp / "expired.pem", tmp / "expired-key.pem"),
            daemon=True,
        )
        t2.start()
        self.assertTrue(ready.wait(timeout=2.0), "过期证书测试监听线程未在时限内就绪")
        with self.assertRaises(ssl.SSLError) as cm:
            cctx.wrap_socket(
                socket.create_connection(("127.0.0.1", port)),
                server_hostname="switch-demo.local",
                session=saved_session,
            )
        self.assertIn("certificate has expired", str(cm.exception))
        t2.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
