"""审计日志。

以 JSONL 形式记录会话与断言相关事件；敏感属性在写入前脱敏，
绝不记录原始断言 XML。
"""

from __future__ import annotations

from pathlib import Path


class AuditLogger:
    """脱敏的审计记录器。"""

    def __init__(self, log_path: str | Path, *, sensitive_attributes: tuple[str, ...] = ()) -> None:
        raise NotImplementedError

    def log(self, event: str, **fields: object) -> None:
        """写入一条审计记录；敏感字段值会被脱敏。"""
        raise NotImplementedError

    @staticmethod
    def redact(value: object) -> str:
        """把任意值脱敏为不可逆的摘要形式。"""
        raise NotImplementedError
