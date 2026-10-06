"""属性映射场景：正常映射、缺少必需属性拒绝、IdP 之间映射与会话隔离。"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from helpers import LocalIdP

from saml_sso import errors
from saml_sso.app import create_app
from saml_sso.attributes import map_attributes
from saml_sso.config import IdpConfig, Settings


def _b64(xml: bytes) -> str:
    return base64.b64encode(xml).decode()


def test_attributes_mapped(idp_config):
    local = map_attributes(
        idp_config,
        {"uid": ["u1"], "mail": ["a@b.c"], "displayName": ["Alice"]},
    )
    assert local == {"uid": "u1", "email": "a@b.c", "display_name": "Alice"}


def test_unmapped_attributes_dropped(idp_config):
    """映射表之外的断言属性不进入本地会话。"""
    local = map_attributes(idp_config, {"uid": ["u1"], "role": ["admin"]})
    assert "role" not in local


def test_multi_value_takes_first(idp_config):
    local = map_attributes(idp_config, {"uid": ["u1", "u2"]})
    assert local["uid"] == "u1"


def test_missing_required_attribute_rejected(idp_config):
    with pytest.raises(errors.MissingAttributeError) as exc_info:
        map_attributes(idp_config, {"mail": ["a@b.c"]})
    assert exc_info.value.code == "missing_attribute"
    assert exc_info.value.detail["missing"] == ["uid"]


def test_empty_required_attribute_rejected(idp_config):
    with pytest.raises(errors.MissingAttributeError):
        map_attributes(idp_config, {"uid": []})


def test_missing_attribute_rejected_via_acs(client, idp):
    xml = idp.build_response(attributes={"mail": ["a@b.c"]})  # 缺 uid
    resp = client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "missing_attribute"


def test_idp_isolation(tmp_path):
    """两个 IdP 使用不同映射规则；会话互不串扰。"""
    idp_a = LocalIdP(entity_id="urn:idp:a", common_name="idp-a")
    idp_b = LocalIdP(entity_id="urn:idp:b", common_name="idp-b")

    cfg_a = IdpConfig(
        idp_id="a",
        entity_id=idp_a.entity_id,
        certificates=(idp_a.cert_pem,),
        attribute_mapping={"uid": "uid", "mail": "email"},
        required_attributes=("uid",),
    )
    cfg_b = IdpConfig(
        idp_id="b",
        entity_id=idp_b.entity_id,
        certificates=(idp_b.cert_pem,),
        attribute_mapping={"employeeId": "uid", "department": "dept"},
        required_attributes=("uid", "dept"),
    )
    settings = Settings(
        sp_entity_id="urn:example:sp",
        replay_db_path=tmp_path / "r.sqlite3",
        audit_log_path=tmp_path / "a.log",
        idps={"a": cfg_a, "b": cfg_b},
    )
    app = create_app(settings)

    # IdP A 登录：email 被映射
    client_a = TestClient(app)
    xml_a = idp_a.build_response(
        name_id="alice", attributes={"uid": ["u1"], "mail": ["alice@a.c"]}
    )
    resp = client_a.post("/saml/acs/a", data={"SAMLResponse": _b64(xml_a)})
    assert resp.status_code == 200, resp.text
    me_a = client_a.get("/me").json()
    assert me_a["idp"] == "a"
    assert me_a["attributes"] == {"uid": "u1", "email": "alice@a.c"}

    # IdP B 登录：不同映射；mail 属性被隔离（不在 B 的映射中）
    client_b = TestClient(app)
    xml_b = idp_b.build_response(
        name_id="bob",
        attributes={"employeeId": ["E7"], "department": ["eng"], "mail": ["bob@b.c"]},
    )
    resp = client_b.post("/saml/acs/b", data={"SAMLResponse": _b64(xml_b)})
    assert resp.status_code == 200, resp.text
    me_b = client_b.get("/me").json()
    assert me_b["idp"] == "b"
    assert me_b["attributes"] == {"uid": "E7", "dept": "eng"}

    # A 的会话不能用 B 的断言属性；两个会话互不影响
    assert client_a.get("/me").json()["attributes"]["uid"] == "u1"

    # A 的密钥签的断言不能用于 B 的端点（密钥隔离）
    xml_cross = idp_a.build_response(attributes={"employeeId": ["E9"], "department": ["x"]})
    resp = client_b.post("/saml/acs/b", data={"SAMLResponse": _b64(xml_cross)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "untrusted_key"
