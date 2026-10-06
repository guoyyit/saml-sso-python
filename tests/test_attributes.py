"""属性映射：缺少必需属性拒绝建会话；不同 IdP 的映射与会话相互隔离。"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from saml_sso.config import IdpConfig
from saml_sso.errors import MissingAttributeError
from saml_sso.service import SamlService

from idp import FakeIdP

NOW = datetime.now(timezone.utc)


def test_missing_required_attribute_rejected(
    service: SamlService, idp: FakeIdP
):
    b64 = idp.build_response_b64(attributes={"uid": ["u-1"]})  # 缺 email
    with pytest.raises(MissingAttributeError) as exc_info:
        service.consume_response(b64, NOW)
    assert exc_info.value.code == "missing_attribute"
    assert "email" in str(exc_info.value)


def test_missing_all_attributes_rejected(service: SamlService, idp: FakeIdP):
    b64 = idp.build_response_b64(attributes={})
    with pytest.raises(MissingAttributeError):
        service.consume_response(b64, NOW)


def test_optional_attribute_absent_still_logs_in(make_settings, idp_config, idp: FakeIdP):
    svc = SamlService(make_settings([idp_config]))
    b64 = idp.build_response_b64(
        attributes={"uid": ["u-1"], "email": ["a@b.c"]}  # 无 displayName
    )
    session = svc.consume_response(b64, NOW)
    assert session.attributes == {"uid": "u-1", "email": "a@b.c"}
    assert "display_name" not in session.attributes


def test_attribute_mapping_applied(service: SamlService, idp: FakeIdP):
    session = service.consume_response(idp.build_response_b64(), NOW)
    # SAML 属性名 -> 本地字段名
    assert session.attributes["display_name"] == "Test User"
    assert "displayName" not in session.attributes


def test_mappings_isolated_between_idps(make_settings):
    """两个 IdP 对同一 SAML 属性映射到不同本地字段，互不干扰。"""
    idp_a = FakeIdP.create("https://idp-a.test")
    idp_b = FakeIdP.create("https://idp-b.test")
    settings = make_settings(
        [
            IdpConfig(
                entity_id=idp_a.entity_id,
                certificates=(idp_a.cert_pem,),
                required_attributes={"uid": "a_uid"},
            ),
            IdpConfig(
                entity_id=idp_b.entity_id,
                certificates=(idp_b.cert_pem,),
                required_attributes={"uid": "b_uid"},
                optional_attributes={"email": "b_email"},
            ),
        ]
    )
    svc = SamlService(settings)

    sa = svc.consume_response(
        idp_a.build_response_b64(attributes={"uid": ["u-a"]}), NOW
    )
    sb = svc.consume_response(
        idp_b.build_response_b64(
            attributes={"uid": ["u-b"], "email": ["b@x.y"]}
        ),
        NOW,
    )
    assert sa.attributes == {"a_uid": "u-a"}
    assert sb.attributes == {"b_uid": "u-b", "b_email": "b@x.y"}
    assert sa.idp_entity_id == idp_a.entity_id
    assert sb.idp_entity_id == idp_b.entity_id

    # 会话按 IdP 隔离存储，互不可见
    fetched_a = svc.get_session(sa.session_id, NOW)
    fetched_b = svc.get_session(sb.session_id, NOW)
    assert fetched_a.idp_entity_id == idp_a.entity_id
    assert fetched_b.idp_entity_id == idp_b.entity_id


def test_idp_b_assertion_fails_idp_a_mapping(make_settings):
    """IdP B 的断言缺少 IdP A 所要求的属性时，按各自映射独立判定。"""
    idp_a = FakeIdP.create("https://idp-a.test")
    idp_b = FakeIdP.create("https://idp-b.test")
    settings = make_settings(
        [
            IdpConfig(
                entity_id=idp_a.entity_id,
                certificates=(idp_a.cert_pem,),
                required_attributes={"employee_id": "emp"},
            ),
            IdpConfig(
                entity_id=idp_b.entity_id,
                certificates=(idp_b.cert_pem,),
                required_attributes={"uid": "uid"},
            ),
        ]
    )
    svc = SamlService(settings)
    # B 不提供 employee_id，但 B 的映射不要求它 -> 成功
    sb = svc.consume_response(
        idp_b.build_response_b64(attributes={"uid": ["u-b"]}), NOW
    )
    assert sb.attributes == {"uid": "u-b"}
    # A 要求 employee_id，断言没有 -> 拒绝
    with pytest.raises(MissingAttributeError):
        svc.consume_response(
            idp_a.build_response_b64(attributes={"uid": ["u-a"]}), NOW
        )
