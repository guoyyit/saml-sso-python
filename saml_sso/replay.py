"""断言重放防护：同一断言标识在有效期内只能被消费一次。

使用 SQLite 持久化，进程重启后已消费记录不丢失；
主键约束保证并发消费同一标识时只有一个成功。
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone


class ReplayCache:
    """基于 SQLite 的持久化重放缓存，进程重启后状态不丢失。"""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_assertions (
                    assertion_id TEXT PRIMARY KEY,
                    expires_at   TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _to_str(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat()

    def consume_once(self, assertion_id: str, expires_at: datetime) -> bool:
        """原子地尝试消费断言标识；成功返回 True，重复返回 False。"""
        with self._lock, self._conn:
            try:
                self._conn.execute(
                    "INSERT INTO consumed_assertions (assertion_id, expires_at)"
                    " VALUES (?, ?)",
                    (assertion_id, self._to_str(expires_at)),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self, now: datetime) -> int:
        """清理已过期的记录，返回清理条数。"""
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM consumed_assertions WHERE expires_at <= ?",
                (self._to_str(now),),
            )
            return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
