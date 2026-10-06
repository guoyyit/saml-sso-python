"""审计日志。

以 JSONL 形式记录会话与断言相关事件；敏感属性在写入前脱敏，
绝不记录原始断言 XML。
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """脱敏的审计记录器（线程安全）。"""

    def __init__(self, log_path: str | Path, *, sensitive_attributes: tuple[str, ...] = ()) -> None:
        self._log_path = Path(log_path)
        self._sensitive = frozenset(sensitive_attributes)
        self._lock = threading.Lock()

    def log(self, event: str, **fields: Any) -> None:
        """写入一条审计记录；敏感字段值会被脱敏。

        特殊处理：
        - ``attributes`` 字典中属于敏感列表的键会被脱敏
        - 任何名为 ``assertion_xml``/``saml_response`` 的原始报文字段一律丢弃
        """
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        for key, value in fields.items():
            if key in ("assertion_xml", "saml_response"):
                # 原始断言可能包含敏感属性，绝不落盘
                continue
            if key == "attributes" and isinstance(value, dict):
                record[key] = {
                    k: (self.redact(v) if k in self._sensitive else v)
                    for k, v in value.items()
                }
            elif key in self._sensitive:
                record[key] = self.redact(value)
            else:
                record[key] = value

        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    @staticmethod
    def redact(value: object) -> str:
        """把任意值脱敏为不可逆的摘要形式。"""
        digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        return f"sha256:{digest[:12]}"
