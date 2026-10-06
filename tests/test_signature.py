"""签名校验：篡改、未签名、未知密钥必须分别以可区分的原因拒绝。"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from saml_sso.errors import (
    SignatureInvalidError,
    SignatureMissingError,
    UntrustedKeyError,
)
from saml_sso.service import SamlService

from idp import FakeIdP


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


def test_valid_signature_creates_session(service: SamlService, idp: FakeIdP):
    session = service.consume_response(
        idp.build_response_b64(), datetime.now(timezone.utc)
    )
    assert session.name_id == "user@example.com"
    assert session.attributes["uid"] == "u-1001"


def test_unsigned_assertion_rejected(service: SamlService, idp: FakeIdP):
    with pytest.raises(SignatureMissingError) as exc_info:
        service.consume_response(
            _b64(idp.build_response_xml(sign=False)),
            datetime.now(timezone.utc),
        )
    assert exc_info.value.code == "signature_missing"


def test_tampered_assertion_rejected(service: SamlService, idp: FakeIdP):
    tampered = idp.build_response_xml().replace("Test User", "Admin User")
    assert tampered != idp.build_response_xml.__doc__  # sanity: changed
    with pytest.raises(SignatureInvalidError) as exc_info:
        service.consume_response(_b64(tampered), datetime.now(timezone.utc))
    assert exc_info.value.code == "signature_invalid"


def test_tampered_conditions_rejected(service: SamlService, idp: FakeIdP):
    xml = idp.build_response_xml()
    tampered = xml.replace("u-1001", "u-9999")
    with pytest.raises(SignatureInvalidError):
        service.consume_response(_b64(tampered), datetime.now(timezone.utc))


def test_untrusted_key_rejected(service: SamlService):
    attacker = FakeIdP.create("https://idp.test/metadata")  # 同 entityID，不同密钥
    with pytest.raises(UntrustedKeyError) as exc_info:
        service.consume_response(
            attacker.build_response_b64(), datetime.now(timezone.utc)
        )
    assert exc_info.value.code == "untrusted_key"


def test_assertion_level_signature_accepted(service: SamlService, idp: FakeIdP):
    session = service.consume_response(
        _b64(idp.build_response_xml(sign_assertion_only=True)),
        datetime.now(timezone.utc),
    )
    assert session.name_id == "user@example.com"


def test_rejection_reasons_are_distinct(service: SamlService, idp: FakeIdP):
    """三种拒绝原因的机器可读 code 互不相同。"""
    codes = set()
    with pytest.raises(SignatureMissingError) as e1:
        service.consume_response(
            _b64(idp.build_response_xml(sign=False)),
            datetime.now(timezone.utc),
        )
    codes.add(e1.value.code)
    with pytest.raises(SignatureInvalidError) as e2:
        service.consume_response(
            _b64(idp.build_response_xml().replace("u-1001", "u-2")),
            datetime.now(timezone.utc),
        )
    codes.add(e2.value.code)
    with pytest.raises(UntrustedKeyError) as e3:
        service.consume_response(
            FakeIdP.create(idp.entity_id).build_response_b64(),
            datetime.now(timezone.utc),
        )
    codes.add(e3.value.code)
    assert codes == {"signature_missing", "signature_invalid", "untrusted_key"}
