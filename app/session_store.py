"""按栈（IPv4/IPv6）隔离的 TLS 会话缓存。

需求对应关系：

1. 每个栈至多保存**一份**最近通过完整 CA 校验与设备名校验后得到的 TLS 会话；
2. “证书到期后停用”——:meth:`take` 在发还会话前检查证书有效期与 ticket 超时；
3. 值班员可按入口“忘记会话”——:meth:`forget` 清掉缓存并抬高世代屏障，
   使忘记时刻之前已经发起、尚未结束的在途握手无法再把旧会话写回；
4. “较早发起的握手即使晚到，也不能覆盖或清掉较新握手已保存的会话”——
   每次 :meth:`begin` 领取单调递增的序号，:meth:`save` 拒绝序号更旧的写入，
   :meth:`invalidate` 只允许清除本序号及更旧序号保存的条目；
5. “并发握手不能排队等缓存”——锁只保护字典 O(1) 操作，
   任何 TLS/网络 I/O 都在锁外完成，临界区内没有系统调用、没有 sleep。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import ssl

IPV6 = "ipv6"
IPV4 = "ipv4"
STACKS = (IPV6, IPV4)

HS_FULL = "full"          # 完整握手（含证书校验）
HS_RESUMED = "resumed"    # 会话恢复握手

REASON_NONE = "none"
REASON_EXPIRED_CERT = "expired_cert"
REASON_EXPIRED_SESSION = "expired_session"


@dataclass
class SessionEntry:
    stack: str
    ssl_session: ssl.SSLSession
    handshake_kind: str          # 保存该会话的那次握手本身的类型
    tls_version: str
    cipher: str
    generation: int              # 握手发起时领取的序号
    saved_at_wall: float         # time.time()
    cert_not_after: float        # 对端证书 notAfter（epoch 秒）
    has_ticket: bool
    session_timeout_s: float
    # Python 要求 SSLSession 只能在创建它的那个 SSLContext 上复用；
    # 记录 context 身份，take 时校验，context 重建后旧会话自动失效。
    context_id: int

    def expiry_reason(self, now_wall: float) -> str | None:
        if now_wall >= self.cert_not_after:
            return REASON_EXPIRED_CERT
        # OpenSSL 给的 ticket/session 寿命（TLS 1.2 常见 7200s）
        if self.session_timeout_s > 0 and now_wall - self.saved_at_wall >= self.session_timeout_s:
            return REASON_EXPIRED_SESSION
        return None


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, SessionEntry] = {}
        # 每个栈一个单调序号：begin 领取，forget 把屏障抬到当前序号之后
        self._seq: dict[str, int] = {s: 0 for s in STACKS}
        self._barrier: dict[str, int] = {s: 0 for s in STACKS}
        self._last_skip: dict[str, str] = {s: "" for s in STACKS}
        # 共享的客户端 SSLContext（SSLSession 与 context 绑定，必须复用同一对象）
        self._client_ctx: ssl.SSLContext | None = None
        self._client_ctx_tls12: bool | None = None

    # ---------- 共享客户端 SSLContext ----------

    def client_context(self, ca_cert: str | Path, tls12_only: bool) -> ssl.SSLContext:
        """返回进程级共享的客户端 SSLContext。

        SSLSession 只能在创建它的 context 上复用，因此演示期间所有竞速
        共用同一个 context；OpenSSL 的 context 可被多线程并发用于握手，
        不需要在缓存锁内做 I/O。tls12_only 翻转时重建 context，
        旧会话因 context_id 不匹配而在 :meth:`take` 时自动失效。
        """
        with self._lock:
            if (
                self._client_ctx is None
                or self._client_ctx_tls12 != tls12_only
            ):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile=str(Path(ca_cert)))
                if tls12_only:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                self._client_ctx = ctx
                self._client_ctx_tls12 = tls12_only
            return self._client_ctx

    # ---------- 握手生命周期 ----------

    def begin(self, stack: str) -> int:
        """一次新握手发起时调用，领取本栈单调序号。"""
        with self._lock:
            self._seq[stack] += 1
            return self._seq[stack]

    def take(self, stack: str, context_id: int | None = None,
             now_wall: float | None = None) -> ssl.SSLSession | None:
        """取本栈缓存的会话用于恢复；不存在、已到期或 context 不匹配则返回 None。

        Python 的 SSLSession 与创建它的 SSLContext 绑定；context 重建
        （例如演示开关翻转）后，旧条目不匹配新 context，直接摘除。
        """
        now_wall = time.time() if now_wall is None else now_wall
        with self._lock:
            entry = self._entries.get(stack)
            if entry is None:
                return None
            if context_id is not None and entry.context_id != context_id:
                self._entries.pop(stack, None)
                self._last_skip[stack] = "ssl_context_rebuilt"
                return None
            reason = entry.expiry_reason(now_wall)
            if reason is not None:
                # 到期停用：直接摘除，后续握手必然走完整握手
                self._entries.pop(stack, None)
                self._last_skip[stack] = reason
                return None
            return entry.ssl_session

    def save(
        self,
        stack: str,
        *,
        ssl_session: ssl.SSLSession,
        handshake_kind: str,
        tls_version: str,
        cipher: str,
        generation: int,
        cert_not_after: float,
        context_id: int,
        now_wall: float | None = None,
    ) -> bool:
        """保存一次**已通过完整校验**的握手产生的会话。

        返回 False 表示该握手的世代已过期（期间发生过 forget，或已有更晚发起的
        握手保存了会话），本次写入被拒绝——旧握手不得覆盖新会话。
        """
        now_wall = time.time() if now_wall is None else now_wall
        with self._lock:
            if generation <= self._barrier[stack]:
                self._last_skip[stack] = "generation_barrier"
                return False
            existing = self._entries.get(stack)
            if existing is not None and existing.generation > generation:
                self._last_skip[stack] = "superseded_by_newer_handshake"
                return False
            self._entries[stack] = SessionEntry(
                stack=stack,
                ssl_session=ssl_session,
                handshake_kind=handshake_kind,
                tls_version=tls_version,
                cipher=cipher,
                generation=generation,
                saved_at_wall=now_wall,
                cert_not_after=cert_not_after,
                has_ticket=bool(getattr(ssl_session, "has_ticket", False)),
                session_timeout_s=float(getattr(ssl_session, "timeout", 0) or 0),
                context_id=context_id,
            )
            self._last_skip[stack] = ""
            return True

    def invalidate(self, stack: str, generation: int) -> bool:
        """握手失败时作废缓存；只允许清除本序号及更旧序号写下的条目。

        更晚发起的握手保存的新会话不会被晚到的失败清掉。
        """
        with self._lock:
            entry = self._entries.get(stack)
            if entry is not None and entry.generation <= generation:
                self._entries.pop(stack, None)
                self._last_skip[stack] = "invalidated_after_failed_handshake"
                return True
            return False

    def forget(self, stack: str) -> bool:
        """值班员手动忘记指定入口的会话；在途旧握手的世代同时作废。"""
        with self._lock:
            existed = self._entries.pop(stack, None) is not None
            # 屏障抬到当前序号：所有在途握手的 generation 都 <= 新屏障
            self._barrier[stack] = self._seq[stack]
            self._last_skip[stack] = "manually_forgotten"
            return existed

    # ---------- 观测 ----------

    def snapshot(self, now_wall: float | None = None) -> dict[str, Any]:
        now_wall = time.time() if now_wall is None else now_wall
        out: dict[str, Any] = {}
        with self._lock:
            for stack in STACKS:
                entry = self._entries.get(stack)
                if entry is None:
                    out[stack] = {
                        "present": False,
                        "reason": self._last_skip.get(stack) or REASON_NONE,
                        "generation": self._seq[stack],
                    }
                    continue
                reason = entry.expiry_reason(now_wall)
                out[stack] = {
                    "present": reason is None,
                    "reason": reason or REASON_NONE,
                    "handshake_kind": entry.handshake_kind,
                    "tls_version": entry.tls_version,
                    "cipher": entry.cipher,
                    "has_ticket": entry.has_ticket,
                    "session_timeout_s": entry.session_timeout_s,
                    "generation": entry.generation,
                    "saved_at": entry.saved_at_wall,
                    "age_s": round(now_wall - entry.saved_at_wall, 1),
                    "cert_not_after": entry.cert_not_after,
                    "cert_remaining_s": max(0, int(entry.cert_not_after - now_wall)),
                }
        return out
