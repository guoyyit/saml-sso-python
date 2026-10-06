"""SAML 断言的解析与校验。

校验顺序：XML 解析 -> 签名（含密钥信任）-> 时间条件 -> 受众限制 -> 发行方。
任何一步失败都抛出可区分的异常类型。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidSignature

from .config import IdpConfig, Settings
from .errors import (
    AudienceRestrictionError,
    ExpiredAssertionError,
    IssuerMismatchError,
    MalformedAssertionError,
    NotYetValidError,
    SignatureValidationError,
    UnsignedAssertionError,
    UntrustedKeyError,
)
from .metadata import _normalize_pem

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

# 安全的 XML 解析器：禁用外部实体、DTD 与网络访问，防 XXE / 实体膨胀
_SAFE_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False
)


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


def _parse_xml(xml_bytes: bytes) -> etree._Element:
    try:
        return etree.fromstring(xml_bytes, parser=_SAFE_PARSER)
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise MalformedAssertionError(f"unparseable SAML XML: {exc}") from exc


def _local(el: etree._Element) -> str:
    return etree.QName(el).localname


def _direct_signature(el: etree._Element) -> etree._Element | None:
    """返回元素的直接子级 ds:Signature（若存在）。"""
    for child in el:
        if child.tag == f"{{{DS_NS}}}Signature":
            return child
    return None


def _find_assertion(el: etree._Element) -> etree._Element | None:
    if _local(el) == "Assertion" and el.tag == f"{{{SAML_NS}}}Assertion":
        return el
    for child in el.iter(f"{{{SAML_NS}}}Assertion"):
        return child
    return None


def _locate_signed_element(root: etree._Element) -> etree._Element:
    """定位需要验签的元素（Assertion 优先，其次 Response）。

    两者都没有签名时抛出 UnsignedAssertionError。
    """
    if _local(root) not in ("Response", "Assertion"):
        raise MalformedAssertionError(f"unexpected root element: {_local(root)!r}")

    assertion = _find_assertion(root)
    if assertion is not None and _direct_signature(assertion) is not None:
        return assertion
    if _direct_signature(root) is not None:
        return root
    raise UnsignedAssertionError("neither Response nor Assertion carries a signature")


def _embedded_certs(signed_el: etree._Element) -> list[str]:
    """提取签名 KeyInfo 中内嵌的 X.509 证书（归一化后的内容）。"""
    sig = _direct_signature(signed_el)
    if sig is None:
        return []
    certs = []
    for cert_el in sig.iter(f"{{{DS_NS}}}X509Certificate"):
        if cert_el.text and cert_el.text.strip():
            certs.append("".join(cert_el.text.split()))
    return certs


def _verify_signature(signed_el: etree._Element, idp: IdpConfig) -> etree._Element:
    """验证签名并返回已验证的元素。

    - KeyInfo 内嵌证书不在信任列表 -> UntrustedKeyError
    - 信任列表中的证书均验签失败 -> SignatureValidationError（篡改或损坏）
    """
    trusted = list(idp.certificates)
    if not trusted:
        raise UntrustedKeyError(f"no trusted certificates configured for idp {idp.idp_id!r}")

    embedded = _embedded_certs(signed_el)
    trusted_norm = {_normalize_pem(pem) for pem in trusted}
    if embedded and not any(cert in trusted_norm for cert in embedded):
        raise UntrustedKeyError("assertion signed with an untrusted certificate")

    verifier = XMLVerifier()
    last_error: Exception | None = None
    for pem in trusted:
        try:
            result = verifier.verify(signed_el, x509_cert=pem, id_attribute="ID")
            return result.signed_xml
        except InvalidSignature as exc:
            last_error = exc
            continue
    raise SignatureValidationError(
        f"signature verification failed: {last_error}"
    ) from last_error


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.strip())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _validate_conditions(
    assertion: etree._Element, settings: Settings, now: datetime
) -> tuple[datetime | None, datetime | None, str | None]:
    """校验时间条件与受众限制，返回 (not_before, not_on_or_after, audience)。"""
    conditions = assertion.find(f"{{{SAML_NS}}}Conditions")
    not_before = not_on_or_after = None
    audience: str | None = None
    if conditions is None:
        return None, None, None

    skew = settings.clock_skew
    not_before = _parse_time(conditions.get("NotBefore"))
    not_on_or_after = _parse_time(conditions.get("NotOnOrAfter"))

    if not_before is not None and now + skew < not_before:
        raise NotYetValidError(
            f"assertion not valid before {not_before.isoformat()} "
            f"(now {now.isoformat()}, skew {skew})"
        )
    if not_on_or_after is not None and now - skew >= not_on_or_after:
        raise ExpiredAssertionError(
            f"assertion expired at {not_on_or_after.isoformat()} "
            f"(now {now.isoformat()}, skew {skew})"
        )

    restriction = conditions.find(f"{{{SAML_NS}}}AudienceRestriction")
    if restriction is not None:
        audiences = [
            el.text.strip()
            for el in restriction.findall(f"{{{SAML_NS}}}Audience")
            if el.text and el.text.strip()
        ]
        audience = audiences[0] if audiences else None
        if settings.sp_entity_id not in audiences:
            raise AudienceRestrictionError(
                f"audience {audiences!r} does not include {settings.sp_entity_id!r}"
            )
    return not_before, not_on_or_after, audience


def _extract(assertion: etree._Element, idp: IdpConfig) -> tuple[str, str, str, str | None, dict[str, list[str]]]:
    assertion_id = assertion.get("ID", "")
    if not assertion_id:
        raise MalformedAssertionError("assertion missing ID attribute")

    issuer_el = assertion.find(f"{{{SAML_NS}}}Issuer")
    issuer = (issuer_el.text or "").strip() if issuer_el is not None else ""
    if issuer != idp.entity_id:
        raise IssuerMismatchError(
            f"assertion issuer {issuer!r} does not match idp {idp.idp_id!r} "
            f"(expected {idp.entity_id!r})"
        )

    name_id_el = assertion.find(f"{{{SAML_NS}}}Subject/{{{SAML_NS}}}NameID")
    name_id = (name_id_el.text or "").strip() if name_id_el is not None else ""
    if not name_id:
        raise MalformedAssertionError("assertion missing Subject/NameID")

    session_index: str | None = None
    authn = assertion.find(f"{{{SAML_NS}}}AuthnStatement")
    if authn is not None:
        session_index = authn.get("SessionIndex")

    attributes: dict[str, list[str]] = {}
    for attr in assertion.iter(f"{{{SAML_NS}}}Attribute"):
        name = attr.get("Name") or attr.get("FriendlyName") or ""
        if not name:
            continue
        values = [
            (v.text or "").strip()
            for v in attr.findall(f"{{{SAML_NS}}}AttributeValue")
            if (v.text or "").strip()
        ]
        attributes.setdefault(name, []).extend(values)

    return assertion_id, issuer, name_id, session_index, attributes


@dataclass(frozen=True)
class LogoutRequestData:
    """校验通过的 LogoutRequest 数据。"""

    request_id: str
    issuer: str
    name_id: str
    session_index: str | None


def validate_logout_request(xml_bytes: bytes, idp: IdpConfig) -> LogoutRequestData:
    """校验 IdP 发来的 LogoutRequest（单点登出）。

    必须携带有效签名；发行方必须与所选 IdP 配置一致。
    """
    root = _parse_xml(xml_bytes)
    if _local(root) != "LogoutRequest":
        raise MalformedAssertionError(f"expected LogoutRequest, got {_local(root)!r}")
    if _direct_signature(root) is None:
        raise UnsignedAssertionError("LogoutRequest is not signed")

    verified = _verify_signature(root, idp)

    request_id = verified.get("ID", "")
    issuer_el = verified.find(f"{{{SAML_NS}}}Issuer")
    issuer = (issuer_el.text or "").strip() if issuer_el is not None else ""
    if issuer != idp.entity_id:
        raise IssuerMismatchError(
            f"logout request issuer {issuer!r} does not match idp {idp.idp_id!r}"
        )

    name_id_el = verified.find(f"{{{SAML_NS}}}NameID")
    name_id = (name_id_el.text or "").strip() if name_id_el is not None else ""
    if not name_id:
        raise MalformedAssertionError("LogoutRequest missing NameID")

    session_index_el = verified.find(f"{{{SAMLP_NS}}}SessionIndex")
    session_index = (
        (session_index_el.text or "").strip() or None if session_index_el is not None else None
    )

    return LogoutRequestData(
        request_id=request_id,
        issuer=issuer,
        name_id=name_id,
        session_index=session_index,
    )


def validate_response(
    xml_bytes: bytes,
    idp: IdpConfig,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> AssertionData:
    """校验 IdP POST 过来的 SAML Response，返回提取的断言数据。

    校验失败时抛出 errors 模块中可区分的异常。
    """
    now = now or datetime.now(timezone.utc)
    root = _parse_xml(xml_bytes)
    signed_el = _locate_signed_element(root)
    verified_el = _verify_signature(signed_el, idp)

    # 从验签通过的元素中提取断言，防止签名包装（XSW）攻击
    assertion = _find_assertion(verified_el)
    if assertion is None:
        raise MalformedAssertionError("no Assertion found in verified content")

    not_before, not_on_or_after, audience = _validate_conditions(assertion, settings, now)
    assertion_id, issuer, name_id, session_index, attributes = _extract(assertion, idp)

    return AssertionData(
        assertion_id=assertion_id,
        issuer=issuer,
        name_id=name_id,
        session_index=session_index,
        attributes=attributes,
        not_before=not_before,
        not_on_or_after=not_on_or_after,
        audience=audience,
    )
