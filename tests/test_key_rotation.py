"""密钥轮换场景：多把受信任密钥并存、轮换期新旧均可验证、未知密钥拒绝、元数据解析。"""

from __future__ import annotations

import base64

import pytest

from helpers import LocalIdP

from saml_sso import errors
from saml_sso.assertion import validate_response
from saml_sso.config import IdpConfig
from saml_sso.metadata import KeyStore, parse_idp_metadata


@pytest.fixture()
def old_idp() -> LocalIdP:
    return LocalIdP(entity_id="urn:test:idp", common_name="old-key")


@pytest.fixture()
def new_idp() -> LocalIdP:
    # 同一 entity_id，持有新密钥的 IdP（模拟轮换）
    return LocalIdP(entity_id="urn:test:idp", common_name="new-key")


def _metadata_xml(entity_id: str, certs_b64: list[str], sso_url: str) -> str:
    keys = "".join(
        f"""<md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{c}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>"""
        for c in certs_b64
    )
    return f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {keys}
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def _cert_b64(pem: str) -> str:
    return "".join(
        line for line in pem.splitlines() if not line.startswith("-----")
    )


def test_metadata_parsing_extracts_signing_keys():
    xml = _metadata_xml("urn:corp:idp", ["QUJD", "REVG"], "https://idp.example.com/sso")
    md = parse_idp_metadata(xml)
    assert md.entity_id == "urn:corp:idp"
    assert md.sso_url == "https://idp.example.com/sso"
    assert len(md.signing_certificates) == 2
    assert all(c.startswith("-----BEGIN CERTIFICATE-----") for c in md.signing_certificates)


def test_metadata_rejects_malformed():
    with pytest.raises(errors.MalformedAssertionError):
        parse_idp_metadata("<broken")


def test_rotation_both_keys_accepted(old_idp, new_idp, settings):
    """轮换期间：信任列表同时包含新旧证书，两个密钥签名的断言都通过。"""
    rotating = IdpConfig(
        idp_id="test",
        entity_id=old_idp.entity_id,
        certificates=(old_idp.cert_pem, new_idp.cert_pem),
        attribute_mapping={"uid": "uid"},
    )
    validate_response(old_idp.build_response(), rotating, settings)
    validate_response(new_idp.build_response(), rotating, settings)


def test_old_key_rejected_after_rotation(old_idp, new_idp, settings):
    """轮换完成后：信任列表只保留新证书，旧密钥签名的断言被拒绝。"""
    rotated = IdpConfig(
        idp_id="test",
        entity_id=old_idp.entity_id,
        certificates=(new_idp.cert_pem,),
    )
    validate_response(new_idp.build_response(), rotated, settings)
    with pytest.raises(errors.UntrustedKeyError):
        validate_response(old_idp.build_response(), rotated, settings)


def test_unknown_key_rejected(old_idp, settings):
    """从未出现在信任列表中的密钥必须被拒绝。"""
    stranger = LocalIdP(entity_id="urn:test:idp", common_name="stranger")
    cfg = IdpConfig(
        idp_id="test",
        entity_id=old_idp.entity_id,
        certificates=(old_idp.cert_pem,),
    )
    with pytest.raises(errors.UntrustedKeyError):
        validate_response(stranger.build_response(), cfg, settings)


def test_key_store_add_remove_dedupe(old_idp, new_idp):
    store = KeyStore()
    store.add_certificate(old_idp.cert_pem)
    store.add_certificate(old_idp.cert_pem)  # 重复添加
    store.add_certificate(new_idp.cert_pem)
    assert len(store.trusted_certificates()) == 2

    store.remove_certificate(old_idp.cert_pem)
    remaining = store.trusted_certificates()
    assert len(remaining) == 1
    assert "new-key" not in remaining[0]  # 内容比较，不依赖 subject


def test_metadata_driven_key_rollover(old_idp, new_idp, settings):
    """端到端：从 IdP 新元数据导入新证书完成轮换。"""
    store = KeyStore([old_idp.cert_pem])

    # IdP 发布包含新证书的元数据
    xml = _metadata_xml(
        old_idp.entity_id,
        [_cert_b64(old_idp.cert_pem), _cert_b64(new_idp.cert_pem)],
        "https://idp.example.com/sso",
    )
    md = parse_idp_metadata(xml)
    for pem in md.signing_certificates:
        store.add_certificate(pem)
    assert len(store.trusted_certificates()) == 2

    cfg = IdpConfig(
        idp_id="test",
        entity_id=old_idp.entity_id,
        certificates=tuple(store.trusted_certificates()),
    )
    validate_response(old_idp.build_response(), cfg, settings)
    validate_response(new_idp.build_response(), cfg, settings)

    # 旧密钥下线
    store.remove_certificate(old_idp.cert_pem)
    cfg = IdpConfig(
        idp_id="test",
        entity_id=old_idp.entity_id,
        certificates=tuple(store.trusted_certificates()),
    )
    with pytest.raises(errors.UntrustedKeyError):
        validate_response(old_idp.build_response(), cfg, settings)
    validate_response(new_idp.build_response(), cfg, settings)
