"""断言重放防护。

基于 SQLite 的持久化消费记录：同一断言 ID 在有效期内只能被消费一次，
进程重启后记录不丢失；并发消费由数据库唯一约束保证只有一个成功。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path


class ReplayCache:
    """持久化的断言 ID 消费记录。"""

    def __init__(self, db_path: str | Path) -> None:
        raise NotImplementedError

    def consume(self, assertion_id: str, expires_at: datetime) -> None:
        """消费一个断言 ID；已被消费时抛出 ReplayDetectedError。"""
        raise NotImplementedError

    def purge_expired(self, now: datetime | None = None) -> int:
        """清理已过已过期记录，返回清理条数。"""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
