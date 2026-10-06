"""本地会话管理：由断言属性映射建立，可独立失效。

会话持久化在 SQLite 中，进程重启不丢失；
登出（本地或 IdP 发起）通过删除记录使会话立即失效。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


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


def _to_str(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _from_str(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


class SessionStore:
    """基于 SQLite 的会话存储，支持按会话/按 NameID 失效。"""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id         TEXT PRIMARY KEY,
                    idp_entity_id      TEXT NOT NULL,
                    name_id            TEXT NOT NULL,
                    saml_session_index TEXT,
                    assertion_id       TEXT NOT NULL,
                    attributes_json    TEXT NOT NULL,
                    created_at         TEXT NOT NULL,
                    expires_at         TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_name_id "
                "ON sessions (idp_entity_id, name_id)"
            )

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
        session = Session(
            session_id=uuid.uuid4().hex,
            idp_entity_id=idp_entity_id,
            name_id=name_id,
            saml_session_index=saml_session_index,
            assertion_id=assertion_id,
            attributes=dict(attributes),
            created_at=now.astimezone(timezone.utc),
            expires_at=now.astimezone(timezone.utc)
            + timedelta(seconds=ttl_seconds),
        )
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO sessions (session_id, idp_entity_id, name_id,"
                " saml_session_index, assertion_id, attributes_json,"
                " created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    session.session_id,
                    session.idp_entity_id,
                    session.name_id,
                    session.saml_session_index,
                    session.assertion_id,
                    json.dumps(session.attributes, ensure_ascii=False),
                    _to_str(session.created_at),
                    _to_str(session.expires_at),
                ),
            )
        return session

    @staticmethod
    def _row_to_session(row: tuple) -> Session:
        return Session(
            session_id=row[0],
            idp_entity_id=row[1],
            name_id=row[2],
            saml_session_index=row[3],
            assertion_id=row[4],
            attributes=json.loads(row[5]),
            created_at=_from_str(row[6]),
            expires_at=_from_str(row[7]),
        )

    def get(self, session_id: str, now: datetime) -> Session | None:
        """获取有效会话；不存在或已过期返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT session_id, idp_entity_id, name_id,"
                " saml_session_index, assertion_id, attributes_json,"
                " created_at, expires_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        session = self._row_to_session(row)
        if session.expires_at <= now.astimezone(timezone.utc):
            return None
        return session

    def destroy(self, session_id: str) -> bool:
        """立即使指定会话失效。"""
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM sessions WHERE session_id = ?", (session_id,)
            )
            return cursor.rowcount > 0

    def destroy_by_name_id(
        self, idp_entity_id: str, name_id: str, session_index: str | None
    ) -> int:
        """单点登出：使某 IdP 下某用户的会话失效，返回失效数量。

        给出 SessionIndex 时只失效对应 SAML 会话，否则失效该用户全部会话。
        """
        with self._lock, self._conn:
            if session_index is not None:
                cursor = self._conn.execute(
                    "DELETE FROM sessions WHERE idp_entity_id = ?"
                    " AND name_id = ? AND saml_session_index = ?",
                    (idp_entity_id, name_id, session_index),
                )
            else:
                cursor = self._conn.execute(
                    "DELETE FROM sessions WHERE idp_entity_id = ?"
                    " AND name_id = ?",
                    (idp_entity_id, name_id),
                )
            return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
