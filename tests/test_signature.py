"""签名校验场景：有效、篡改、未签名、未知密钥、响应级签名。"""

from __future__ import annotations

import base64

import pytest

from helpers import LocalIdP

from saml_sso import errors
from saml_sso.assertion import validate_response
from saml_sso.config import IdpConfig


def _b64(xml: bytes) -> str:
    return base64.b64encode(xml).decode()


def test_valid_assertion_accepted(idp, idp_config, settings):
    xml = idp.build_response(attributes={"uid": ["u1"]})
    data = validate_response(xml, idp_config, settings)
    assert data.name_id == "user@example.com"
    assert data.attributes["uid"] == ["u1"]
    assert data.assertion_id


def test_tampered_assertion_rejected(idp, idp_config, settings):
    xml = idp.build_response()
    tampered = xml.replace(b"user@example.com", b"admin@evil.com")
    assert tampered != xml
    with pytest.raises(errors.SignatureValidationError) as exc_info:
        validate_response(tampered, idp_config, settings)
    assert exc_info.value.code == "invalid_signature"


def test_tampered_attributes_rejected(idp, idp_config, settings):
    xml = idp.build_response(attributes={"uid": ["u1"]})
    tampered = xml.replace(b">u1<", b">root<")
    with pytest.raises(errors.SignatureValidationError):
        validate_response(tampered, idp_config, settings)


def test_unsigned_assertion_rejected(idp, idp_config, settings):
    xml = idp.build_response(sign=False)
    with pytest.raises(errors.UnsignedAssertionError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "unsigned_assertion"


def test_untrusted_key_rejected(idp_config, settings):
    attacker = LocalIdP(entity_id="urn:test:idp", common_name="attacker")
    xml = attacker.build_response()
    with pytest.raises(errors.UntrustedKeyError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "untrusted_key"


def test_response_level_signature_accepted(idp, idp_config, settings):
    xml = idp.build_response(sign_assertion=False)
    data = validate_response(xml, idp_config, settings)
    assert data.name_id == "user@example.com"


def test_malformed_xml_rejected(idp_config, settings):
    with pytest.raises(errors.MalformedAssertionError):
        validate_response(b"<not-xml", idp_config, settings)


def test_error_codes_distinguishable_via_acs(client, idp):
    """通过 ACS 端点确认不同拒绝原因返回不同错误码。"""
    cases = []

    tampered = idp.build_response().replace(b"user@example.com", b"admin@evil.com")
    cases.append((tampered, "invalid_signature"))
    cases.append((idp.build_response(sign=False), "unsigned_assertion"))
    cases.append((LocalIdP(entity_id="urn:test:idp").build_response(), "untrusted_key"))

    for xml, expected_code in cases:
        resp = client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})
        assert resp.status_code == 400
        assert resp.json()["error"] == expected_code, resp.text


def test_unknown_idp_rejected(client, idp):
    xml = idp.build_response()
    resp = client.post("/saml/acs/nope", data={"SAMLResponse": _b64(xml)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "unknown_idp"
