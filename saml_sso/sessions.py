"""本地会话存储。

会话与断言来源的 IdP 绑定；支持单点登出立即失效；
所有读写都在同一把锁下完成，保证并发在途请求与会话失效之间的一致性：
一旦会话被失效，其后的任何授权检查都会失败，在途请求无法借此会话写入数据。
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .errors import SessionInvalidError


@dataclass(frozen=True)
class Session:
    """本地会话。"""

    session_id: str
    idp_id: str
    name_id: str
    attributes: dict[str, str] = field(default_factory=dict)
    saml_session_index: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None


class SessionStore:
    """内存会话存储（线程安全）。"""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        idp_id: str,
        name_id: str,
        attributes: dict[str, str],
        saml_session_index: str | None,
        ttl_seconds: float,
        now: datetime | None = None,
    ) -> Session:
        now = now or datetime.now(timezone.utc)
        session = Session(
            session_id=secrets.token_urlsafe(32),
            idp_id=idp_id,
            name_id=name_id,
            attributes=dict(attributes),
            saml_session_index=saml_session_index,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str, *, now: datetime | None = None) -> Session:
        """获取有效会话；不存在、过期或已失效时抛出 SessionInvalidError。"""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionInvalidError("session not found or already invalidated")
            if session.expires_at is not None and now >= session.expires_at:
                # 惰性清理过期会话
                del self._sessions[session_id]
                raise SessionInvalidError("session expired")
            return session

    def invalidate(self, session_id: str) -> bool:
        """使指定会话立即失效（本地登出）。返回是否命中。"""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def invalidate_by_name_id(
        self, idp_id: str, name_id: str, session_index: str | None = None
    ) -> int:
        """按 IdP + NameID（可选 SessionIndex）失效会话（单点登出），返回失效数量。"""
        with self._lock:
            targets = [
                sid
                for sid, s in self._sessions.items()
                if s.idp_id == idp_id
                and s.name_id == name_id
                and (session_index is None or s.saml_session_index == session_index)
            ]
            for sid in targets:
                del self._sessions[sid]
            return len(targets)
