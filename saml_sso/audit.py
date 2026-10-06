"""审计记录：会话与断言事件，敏感字段脱敏。

审计事件以 JSON Lines 追加写入日志文件。
敏感属性值一律替换为 "***"，原始断言内容不进入审计日志。
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

REDACTED = "***"


class AuditLogger:
    """将审计事件追加写入日志文件，敏感属性一律脱敏。"""

    def __init__(self, log_path: str, sensitive_fields: tuple[str, ...] = ()) -> None:
        self._log_path = log_path
        self._sensitive = set(sensitive_fields)
        self._lock = threading.Lock()

    def _redact(self, attributes: dict[str, Any] | None) -> dict[str, Any] | None:
        if attributes is None:
            return None
        return {
            key: (REDACTED if key in self._sensitive else value)
            for key, value in attributes.items()
        }

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
        record = {
            "ts": (now or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .isoformat(),
            "event": event,
            "idp": idp_entity_id,
            "name_id": name_id,
            "assertion_id": assertion_id,
            "session_id": session_id,
            "attributes": self._redact(attributes),
            "detail": detail,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
