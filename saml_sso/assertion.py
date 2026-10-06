"""SAML 断言的解析与校验。

校验顺序：XML 解析 -> 签名（含密钥信任）-> 时间条件 -> 受众限制。
任何一步失败都抛出可区分的异常类型。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .config import IdpConfig, Settings


@dataclass(frozen=True)
class AssertionData:
    """校验通过后提取的断言数据。"""

    assertion_id: str
    issuer: str
    name_id: str
    session_index: str | None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    not_before: datetime | None = None
    not_on_or_after: datetime | None = None
    audience: str | None = None


def validate_response(
    xml_bytes: bytes,
    idp: IdpConfig,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> AssertionData:
    """校验 IdP POST 过来的 SAML Response，返回提取的断言数据。"""
    raise NotImplementedError
