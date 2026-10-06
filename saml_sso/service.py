"""SAML 核心服务：串联验签、条件校验、重放防护、属性映射与会话建立。"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone

from lxml import etree

from saml_sso.assertion import (
    AssertionData,
    extract_assertion_data,
    validate_conditions,
)
from saml_sso.audit import AuditLogger
from saml_sso.config import IdpConfig, Settings
from saml_sso.errors import (
    LogoutError,
    MissingAttributeError,
    ReplayDetectedError,
    SamlError,
    UnknownIdpError,
)
from saml_sso.replay import ReplayCache
from saml_sso.session import Session, SessionStore
from saml_sso.signature import verify_response_signature, verify_xml_signature

NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"


def _decode_b64(payload: str) -> bytes:
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SamlError(f"invalid base64 payload: {exc}") from exc


def _peek_issuer(xml_bytes: bytes) -> str:
    """在验签前读取 Issuer 以选择信任配置；验签后会再次核对。"""
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        root = etree.fromstring(xml_bytes, parser)
    except etree.XMLSyntaxError as exc:
        raise SamlError(f"malformed SAML message: {exc}") from exc
    issuer_el = root.find(f"{{{NS_SAML}}}Issuer")
    if issuer_el is None or not (issuer_el.text or "").strip():
        raise SamlError("SAML message missing Issuer")
    return issuer_el.text.strip()


class SamlService:
    """对外提供 ACS 消费与单点登出能力。"""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._replay = ReplayCache(settings.db_path)
        self._sessions = SessionStore(settings.db_path)
        sensitive = tuple(
            dict.fromkeys(
                field
                for idp in settings.idps
                for field in idp.sensitive_fields
            )
        )
        self._audit = AuditLogger(settings.audit_log_path, sensitive)

    # ---- 内部工具 -----------------------------------------------------

    def _idp_for_issuer(self, issuer: str) -> IdpConfig:
        idp = self._settings.idp_by_entity_id(issuer)
        if idp is None:
            raise UnknownIdpError(f"untrusted issuer: {issuer}")
        return idp

    def _reject(self, exc: SamlError, *, issuer: str | None = None) -> None:
        self._audit.log(
            "assertion_rejected",
            idp_entity_id=issuer,
            detail=f"{exc.code}: {exc}",
        )

    def _map_attributes(
        self, idp: IdpConfig, data: AssertionData
    ) -> dict[str, str]:
        """按 IdP 专属映射把断言属性转换为本地会话属性。"""
        mapped: dict[str, str] = {}
        for saml_name, local_name in idp.required_attributes.items():
            values = data.attributes.get(saml_name)
            if not values:
                raise MissingAttributeError(
                    f"required attribute missing: {saml_name}"
                )
            mapped[local_name] = values[0]
        for saml_name, local_name in idp.optional_attributes.items():
            values = data.attributes.get(saml_name)
            if values:
                mapped[local_name] = values[0]
        return mapped

    # ---- 登录（ACS） --------------------------------------------------

    def consume_response(self, saml_response_b64: str, now: datetime) -> Session:
        """处理 POST 绑定送达的 SAMLResponse，成功则建立本地会话。"""
        issuer: str | None = None
        try:
            xml_bytes = _decode_b64(saml_response_b64)
            issuer = _peek_issuer(xml_bytes)
            idp = self._idp_for_issuer(issuer)

            assertion_el = verify_response_signature(
                xml_bytes, list(idp.certificates)
            )
            data = extract_assertion_data(assertion_el)
            if data.issuer != issuer:
                raise SamlError("verified assertion issuer mismatch")

            validate_conditions(
                data,
                expected_audience=self._settings.sp.entity_id,
                clock_skew_seconds=self._settings.clock_skew_seconds,
                now=now,
            )

            expires_at = data.not_on_or_after or (
                now.astimezone(timezone.utc)
                + timedelta(seconds=self._settings.clock_skew_seconds)
            )
            if not self._replay.consume_once(data.assertion_id, expires_at):
                raise ReplayDetectedError(
                    f"assertion already consumed: {data.assertion_id}"
                )

            attributes = self._map_attributes(idp, data)

            session = self._sessions.create(
                idp_entity_id=idp.entity_id,
                name_id=data.name_id,
                saml_session_index=data.session_index,
                assertion_id=data.assertion_id,
                attributes=attributes,
                ttl_seconds=self._settings.session_ttl_seconds,
                now=now,
            )
            self._audit.log(
                "session_created",
                idp_entity_id=idp.entity_id,
                name_id=data.name_id,
                assertion_id=data.assertion_id,
                session_id=session.session_id,
                attributes=attributes,
                now=now,
            )
            return session
        except SamlError as exc:
            self._reject(exc, issuer=issuer)
            raise

    # ---- 登出 ---------------------------------------------------------

    def handle_logout_request(self, saml_request_b64: str, now: datetime) -> int:
        """处理 IdP 发起的单点登出请求，返回失效会话数。"""
        xml_bytes = _decode_b64(saml_request_b64)
        issuer = _peek_issuer(xml_bytes)
        idp = self._idp_for_issuer(issuer)

        signed_el = verify_xml_signature(xml_bytes, list(idp.certificates))
        if not signed_el.tag.endswith("LogoutRequest"):
            raise LogoutError(f"unexpected message type: {signed_el.tag}")

        name_id_el = signed_el.find(f"{{{NS_SAML}}}NameID")
        if name_id_el is None or not (name_id_el.text or "").strip():
            raise LogoutError("LogoutRequest missing NameID")
        name_id = name_id_el.text.strip()

        session_index_el = signed_el.find(f"{{{NS_SAMLP}}}SessionIndex")
        session_index = (
            session_index_el.text.strip()
            if session_index_el is not None and session_index_el.text
            else None
        )

        count = self._sessions.destroy_by_name_id(
            idp.entity_id, name_id, session_index
        )
        self._audit.log(
            "logout_request",
            idp_entity_id=idp.entity_id,
            name_id=name_id,
            detail=f"invalidated_sessions={count}",
            now=now,
        )
        return count

    def logout(self, session_id: str) -> bool:
        """本地登出：立即使会话失效。"""
        destroyed = self._sessions.destroy(session_id)
        if destroyed:
            self._audit.log("logout_local", session_id=session_id)
        return destroyed

    def get_session(self, session_id: str, now: datetime) -> Session | None:
        """查询有效会话。"""
        return self._sessions.get(session_id, now)
