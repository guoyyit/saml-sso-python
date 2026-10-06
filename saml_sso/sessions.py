"""本地会话存储。

会话与断言来源的 IdP 绑定；支持单点登出立即失效；
通过锁保证并发在途请求与会话失效之间的一致性。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


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
        raise NotImplementedError

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
        raise NotImplementedError

    def get(self, session_id: str, *, now: datetime | None = None) -> Session:
        """获取有效会话；不存在、过期或已失效时抛出 SessionInvalidError。"""
        raise NotImplementedError

    def invalidate(self, session_id: str) -> bool:
        """使指定会话立即失效（本地登出）。"""
        raise NotImplementedError

    def invalidate_by_name_id(self, idp_id: str, name_id: str, session_index: str | None = None) -> int:
        """按 IdP + NameID（可选 SessionIndex）失效会话（单点登出），返回失效数量。"""
        raise NotImplementedError
