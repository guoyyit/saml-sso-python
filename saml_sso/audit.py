"""审计记录：会话与断言事件，敏感字段脱敏。"""

from __future__ import annotations

from datetime import datetime
from typing import Any


class AuditLogger:
    """将审计事件追加写入日志文件，敏感属性一律脱敏。"""

    def __init__(self, log_path: str, sensitive_fields: tuple[str, ...] = ()) -> None:
        raise NotImplementedError

    def log(
        self,
        event: str,
        *,
        idp_entity_id: str | None = None,
        name_id: str | None = None,
        assertion_id: str | None = None,
        session_id: str | None = None,
        attributes: dict[str, Any] | None = None,
        detail: str | None = None,
        now: datetime | None = None,
    ) -> None:
        raise NotImplementedError
