"""断言解析与条件校验（时间窗口、受众）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from lxml import etree

from saml_sso.errors import (
    AssertionExpiredError,
    AssertionNotYetValidError,
    AudienceMismatchError,
    SamlError,
)

NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"


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


def _parse_instant(value: str | None) -> datetime | None:
    """解析 SAML 时间戳（UTC，允许小数秒）。"""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SamlError(f"invalid SAML timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_assertion_data(assertion_el: etree._Element) -> AssertionData:
    """从已验签的 Assertion 元素提取结构化数据。"""
    assertion_id = assertion_el.get("ID")
    if not assertion_id:
        raise SamlError("assertion missing ID")

    issuer_el = assertion_el.find(f"{{{NS_SAML}}}Issuer")
    if issuer_el is None or not (issuer_el.text or "").strip():
        raise SamlError("assertion missing Issuer")
    issuer = issuer_el.text.strip()

    name_id_el = assertion_el.find(
        f"{{{NS_SAML}}}Subject/{{{NS_SAML}}}NameID"
    )
    if name_id_el is None or not (name_id_el.text or "").strip():
        raise SamlError("assertion missing Subject/NameID")
    name_id = name_id_el.text.strip()

    conditions = assertion_el.find(f"{{{NS_SAML}}}Conditions")
    not_before = not_on_or_after = None
    audiences: list[str] = []
    if conditions is not None:
        not_before = _parse_instant(conditions.get("NotBefore"))
        not_on_or_after = _parse_instant(conditions.get("NotOnOrAfter"))
        for aud in conditions.iter(f"{{{NS_SAML}}}Audience"):
            if aud.text and aud.text.strip():
                audiences.append(aud.text.strip())

    session_index: str | None = None
    authn = assertion_el.find(f"{{{NS_SAML}}}AuthnStatement")
    if authn is not None:
        session_index = authn.get("SessionIndex")

    attributes: dict[str, list[str]] = {}
    for attr in assertion_el.iter(f"{{{NS_SAML}}}Attribute"):
        name = attr.get("Name")
        if not name:
            continue
        values = [
            (v.text or "").strip()
            for v in attr.findall(f"{{{NS_SAML}}}AttributeValue")
            if (v.text or "").strip()
        ]
        attributes.setdefault(name, []).extend(values)

    return AssertionData(
        assertion_id=assertion_id,
        issuer=issuer,
        name_id=name_id,
        session_index=session_index,
        not_before=not_before,
        not_on_or_after=not_on_or_after,
        audiences=tuple(audiences),
        attributes=attributes,
    )


def validate_conditions(
    data: AssertionData,
    *,
    expected_audience: str,
    clock_skew_seconds: int,
    now: datetime,
) -> None:
    """校验 NotBefore / NotOnOrAfter / AudienceRestriction。

    时钟偏移容忍窗口对称地应用于两个时间边界。
    """
    now = now.astimezone(timezone.utc)
    skew = timedelta(seconds=clock_skew_seconds)

    if data.not_before is not None and now < data.not_before - skew:
        raise AssertionNotYetValidError(
            f"assertion not valid before {data.not_before.isoformat()}"
        )
    if data.not_on_or_after is not None and now >= data.not_on_or_after + skew:
        raise AssertionExpiredError(
            f"assertion expired at {data.not_on_or_after.isoformat()}"
        )

    if data.audiences and expected_audience not in data.audiences:
        raise AudienceMismatchError(
            f"audience restriction {list(data.audiences)} does not include "
            f"{expected_audience}"
        )
