"""端到端：本地 IdP + 自签名证书，走完整 HTTP 登录/访问/登出链路。"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from idp import FakeIdP, build_logout_request_b64

NOW = datetime.now(timezone.utc)


def test_full_federated_login_journey(client, idp):
    # 未登录访问受保护资源 -> 401
    assert client.get("/me").status_code == 401

    # IdP 通过 POST 绑定送达签名断言 -> 建立会话
    response = client.post(
        "/saml/acs", data={"SAMLResponse": idp.build_response_b64()}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["idp"] == idp.entity_id
    assert body["attributes"]["uid"] == "u-1001"

    # 会话可用于受保护资源
    assert client.get("/me").status_code == 200
    write = client.post("/protected/write", json={"doc": "v1"})
    assert write.status_code == 200
    assert write.json()["written_by"] == "user@example.com"

    # IdP 发起单点登出 -> 会话立即失效
    slo = client.post(
        "/saml/slo",
        data={
            "SAMLRequest": build_logout_request_b64(
                idp, name_id="user@example.com", session_index="sess-1"
            )
        },
    )
    assert slo.status_code == 200
    assert client.get("/me").status_code == 401
    assert client.post("/protected/write", json={"doc": "v2"}).status_code == 401


def test_http_error_codes_distinguishable(client, idp):
    """HTTP 层不同拒绝原因返回不同状态码与机器可读 error。"""
    # 篡改 -> 403 signature_invalid
    tampered = base64.b64encode(
        idp.build_response_xml().replace("u-1001", "u-9").encode()
    ).decode()
    r = client.post("/saml/acs", data={"SAMLResponse": tampered})
    assert r.status_code == 403
    assert r.json()["error"] == "signature_invalid"

    # 过期 -> 403 assertion_expired
    expired = idp.build_response_b64(
        not_before=NOW - timedelta(hours=2),
        not_on_or_after=NOW - timedelta(minutes=10),
    )
    r = client.post("/saml/acs", data={"SAMLResponse": expired})
    assert r.status_code == 403
    assert r.json()["error"] == "assertion_expired"

    # 缺必需属性 -> 422 missing_attribute
    missing = idp.build_response_b64(attributes={"uid": ["u-1"]})
    r = client.post("/saml/acs", data={"SAMLResponse": missing})
    assert r.status_code == 422
    assert r.json()["error"] == "missing_attribute"

    # 重放 -> 409 replay_detected
    fixed = idp.build_response_b64(assertion_id="e2e-fixed-id")
    assert client.post("/saml/acs", data={"SAMLResponse": fixed}).status_code == 200
    r = client.post("/saml/acs", data={"SAMLResponse": fixed})
    assert r.status_code == 409
    assert r.json()["error"] == "replay_detected"

    # 未知 IdP -> 403 unknown_idp
    stranger = FakeIdP.create("https://stranger.test")
    r = client.post(
        "/saml/acs", data={"SAMLResponse": stranger.build_response_b64()}
    )
    assert r.status_code == 403
    assert r.json()["error"] == "unknown_idp"
