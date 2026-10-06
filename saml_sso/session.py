"""本地会话管理：由断言属性映射建立，可独立失效。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Session:
    """本地会话。"""

    session_id: str
    idp_entity_id: str
    name_id: str
    saml_session_index: str | None
    assertion_id: str
    attributes: dict[str, str] = field(default_factory=dict)
    created_at: datetime | None = None
    expires_at: datetime | None = None


class SessionStore:
    """基于 SQLite 的会话存储，支持按会话/按 NameID 失效。"""

    def __init__(self, db_path: str) -> None:
        raise NotImplementedError

    def create(
        self,
        *,
        idp_entity_id: str,
        name_id: str,
        saml_session_index: str | None,
        assertion_id: str,
        attributes: dict[str, str],
        ttl_seconds: int,
        now: datetime,
    ) -> Session:
        raise NotImplementedError

    def get(self, session_id: str, now: datetime) -> Session | None:
        """获取有效会话；不存在或已过期返回 None。"""
        raise NotImplementedError

    def destroy(self, session_id: str) -> bool:
        """立即使指定会话失效。"""
        raise NotImplementedError

    def destroy_by_name_id(
        self, idp_entity_id: str, name_id: str, session_index: str | None
    ) -> int:
        """单点登出：使某 IdP 下某用户的会话失效，返回失效数量。"""
        raise NotImplementedError
