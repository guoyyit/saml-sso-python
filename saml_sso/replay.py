"""断言重放防护：同一断言标识在有效期内只能被消费一次。"""

from __future__ import annotations

from datetime import datetime


class ReplayCache:
    """基于 SQLite 的持久化重放缓存，进程重启后状态不丢失。"""

    def __init__(self, db_path: str) -> None:
        raise NotImplementedError

    def consume_once(self, assertion_id: str, expires_at: datetime) -> bool:
        """原子地尝试消费断言标识；成功返回 True，重复返回 False。"""
        raise NotImplementedError

    def purge_expired(self, now: datetime) -> int:
        """清理已过期的记录，返回清理条数。"""
        raise NotImplementedError
