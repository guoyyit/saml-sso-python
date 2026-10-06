"""断言解析与条件校验（时间窗口、受众）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from lxml import etree


@dataclass(frozen=True)
class AssertionData:
    """从断言中提取出的结构化数据。"""

    assertion_id: str
    issuer: str
    name_id: str
    session_index: str | None
    not_before: datetime | None
    not_on_or_after: datetime | None
    audiences: tuple[str, ...] = ()
    attributes: dict[str, list[str]] = field(default_factory=dict)


def extract_assertion_data(assertion_el: etree._Element) -> AssertionData:
    """从已验签的 Assertion 元素提取结构化数据。"""
    raise NotImplementedError


def validate_conditions(
    data: AssertionData,
    *,
    expected_audience: str,
    clock_skew_seconds: int,
    now: datetime,
) -> None:
    """校验 NotBefore / NotOnOrAfter / AudienceRestriction。"""
    raise NotImplementedError
