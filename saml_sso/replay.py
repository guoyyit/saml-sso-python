"""断言重放防护。

基于 SQLite 的持久化消费记录：同一断言 ID 在有效期内只能被消费一次，
进程重启后记录不丢失；并发消费由数据库唯一约束保证只有一个成功。
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .errors import ReplayDetectedError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_assertions (
    assertion_id TEXT PRIMARY KEY,
    expires_at   TEXT NOT NULL
);
"""


class ReplayCache:
    """持久化的断言 ID 消费记录（线程安全）。"""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        # check_same_thread=False + 锁：多线程共享一个连接
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    @staticmethod
    def _fmt(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat()

    def consume(self, assertion_id: str, expires_at: datetime) -> None:
        """消费一个断言 ID；已被消费时抛出 ReplayDetectedError。

        依赖 PRIMARY KEY 唯一约束：并发插入同一 ID 时只有第一个事务成功。
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO consumed_assertions (assertion_id, expires_at) VALUES (?, ?)",
                    (assertion_id, self._fmt(expires_at)),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                raise ReplayDetectedError(
                    f"assertion {assertion_id!r} has already been consumed"
                ) from None

    def purge_expired(self, now: datetime | None = None) -> int:
        """清理已过有效期记录，返回清理条数。"""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM consumed_assertions WHERE expires_at <= ?",
                (self._fmt(now),),
            )
            self._conn.commit()
            return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
