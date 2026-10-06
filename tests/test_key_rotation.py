"""密钥轮换：多受信任密钥并存，轮换期间新旧均可验证，未知密钥被拒绝。"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from saml_sso.config import IdpConfig
from saml_sso.errors import UntrustedKeyError
from saml_sso.metadata import TrustedKeyStore, parse_metadata
from saml_sso.service import SamlService

from idp import FakeIdP

NOW = datetime.now(timezone.utc)


def _metadata_xml(idp: FakeIdP, *cert_pems: str) -> str:
    """把若干 PEM 证书拼进一份 IdP 元数据文档。"""
    blocks = ""
    for pem in cert_pems:
        der_b64 = "".join(
            line for line in pem.splitlines() if "-----" not in line
        )
        blocks += (
            '<md:KeyDescriptor use="signing"><ds:KeyInfo '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Data><ds:X509Certificate>{der_b64}"
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
            "</md:KeyDescriptor>"
        )
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
        f' entityID="{idp.entity_id}"><md:IDPSSODescriptor>{blocks}'
        '<md:SingleSignOnService Location="https://idp.test/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


def test_metadata_parsing_extracts_all_signing_keys(idp: FakeIdP):
    other = FakeIdP.create("https://idp2.test")
    md = parse_metadata(_metadata_xml(idp, idp.cert_pem, other.cert_pem))
    assert md.entity_id == idp.entity_id
    assert len(md.signing_certificates) == 2


def test_metadata_driven_key_loading(make_settings, idp: FakeIdP):
    """从元数据解析出的密钥可直接用于建立信任配置。"""
    md = parse_metadata(_metadata_xml(idp, idp.cert_pem))
    settings = make_settings(
        [IdpConfig(entity_id=md.entity_id, certificates=md.signing_certificates)]
    )
    svc = SamlService(settings)
    session = svc.consume_response(idp.build_response_b64(), NOW)
    assert session.name_id == "user@example.com"


def test_rotation_window_accepts_old_and_new_keys(
    make_settings, idp: FakeIdP
):
    """轮换期间：新旧密钥签发的断言都可通过。"""
    new_idp = FakeIdP.create(idp.entity_id)  # 同一 IdP，新密钥
    settings = make_settings(
        [
            IdpConfig(
                entity_id=idp.entity_id,
                certificates=(idp.cert_pem, new_idp.cert_pem),
            )
        ]
    )
    svc = SamlService(settings)
    s_old = svc.consume_response(idp.build_response_b64(), NOW)
    s_new = svc.consume_response(new_idp.build_response_b64(), NOW)
    assert s_old.session_id != s_new.session_id


def test_retired_key_rejected_after_rotation(make_settings, idp: FakeIdP):
    """轮换完成后：旧密钥被移除，其签发的断言必须被拒绝。"""
    new_idp = FakeIdP.create(idp.entity_id)
    store = TrustedKeyStore()
    store.set_keys(idp.entity_id, [idp.cert_pem])
    store.add_key(idp.entity_id, new_idp.cert_pem)  # 轮换期：双密钥
    assert len(store.keys_for(idp.entity_id)) == 2
    store.remove_key(idp.entity_id, idp.cert_pem)  # 轮换完成：下线旧密钥

    settings = make_settings(
        [IdpConfig(entity_id=idp.entity_id, certificates=tuple(store.keys_for(idp.entity_id)))]
    )
    svc = SamlService(settings)
    svc.consume_response(new_idp.build_response_b64(), NOW)  # 新密钥可用
    with pytest.raises(UntrustedKeyError):
        svc.consume_response(idp.build_response_b64(), NOW)  # 旧密钥拒绝


def test_unknown_source_key_rejected(make_settings, idp: FakeIdP):
    stranger = FakeIdP.create(idp.entity_id)
    settings = make_settings(
        [IdpConfig(entity_id=idp.entity_id, certificates=(idp.cert_pem,))]
    )
    svc = SamlService(settings)
    with pytest.raises(UntrustedKeyError) as exc_info:
        svc.consume_response(stranger.build_response_b64(), NOW)
    assert exc_info.value.code == "untrusted_key"


def test_tampered_metadata_cert_not_silently_trusted(idp: FakeIdP):
    """元数据中的证书被篡改（非法 DER）时必须报错而不是跳过。"""
    from saml_sso.errors import MetadataError

    bad_der = base64.b64encode(b"not-a-certificate").decode()
    xml = (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
        f' entityID="{idp.entity_id}"><md:IDPSSODescriptor>'
        '<md:KeyDescriptor use="signing"><ds:KeyInfo '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f"<ds:X509Data><ds:X509Certificate>{bad_der}"
        "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )
    with pytest.raises(MetadataError):
        parse_metadata(xml)
