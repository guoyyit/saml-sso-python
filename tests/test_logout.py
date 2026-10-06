"""登出场景：本地登出、单点登出（SLO）、在途请求一致性、会话隔离。"""

from __future__ import annotations

import base64
import threading

from fastapi.testclient import TestClient

from saml_sso.app import create_app


def _b64(xml: bytes) -> str:
    return base64.b64encode(xml).decode()


def _login(client: TestClient, idp, idp_id: str = "test", **kwargs) -> str:
    xml = idp.build_response(attributes={"uid": ["u1"]}, **kwargs)
    resp = client.post(f"/saml/acs/{idp_id}", data={"SAMLResponse": _b64(xml)})
    assert resp.status_code == 200, resp.text
    return resp.json()["session_id"]


def test_local_logout_invalidates_session(client, idp):
    _login(client, idp)
    assert client.get("/me").status_code == 200

    resp = client.post("/logout")
    assert resp.status_code == 200

    # 会话立即失效
    assert client.get("/me").status_code == 401
    # 重复登出也会话失效
    assert client.post("/logout").status_code == 401


def test_single_logout_via_idp(client, idp):
    """IdP 发送签名的 LogoutRequest 后，对应本地会话立即失效。"""
    _login(client, idp, name_id="user@example.com", session_index="_s1")
    assert client.get("/me").status_code == 200

    logout_xml = idp.build_logout_request(name_id="user@example.com", session_index="_s1")
    resp = client.post("/saml/slo/test", data={"SAMLRequest": _b64(logout_xml)})
    assert resp.status_code == 200
    assert resp.json()["invalidated"] == 1

    assert client.get("/me").status_code == 401


def test_slo_requires_valid_signature(client, idp):
    _login(client, idp, name_id="user@example.com", session_index="_s1")

    # 未签名的 LogoutRequest 被拒绝，会话保持有效
    logout_xml = idp.build_logout_request(name_id="user@example.com", sign=False)
    resp = client.post("/saml/slo/test", data={"SAMLRequest": _b64(logout_xml)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsigned_assertion"
    assert client.get("/me").status_code == 200

    # 篡改的 LogoutRequest 被拒绝
    logout_xml = idp.build_logout_request(name_id="user@example.com").replace(
        b"user@example.com", b"admin@evil.com"
    )
    resp = client.post("/saml/slo/test", data={"SAMLRequest": _b64(logout_xml)})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_signature"
    assert client.get("/me").status_code == 200


def test_slo_only_affects_matching_session(client, idp):
    """SLO 按 NameID + SessionIndex 精确匹配，不误伤其他会话。"""
    _login(client, idp, name_id="user@example.com", session_index="_s1")
    other = TestClient(client.app)
    _login(other, idp, name_id="other@example.com", session_index="_s2")

    logout_xml = idp.build_logout_request(name_id="user@example.com", session_index="_s1")
    resp = client.post("/saml/slo/test", data={"SAMLRequest": _b64(logout_xml)})
    assert resp.json()["invalidated"] == 1

    assert client.get("/me").status_code == 401
    assert other.get("/me").status_code == 200  # 其他用户会话不受影响


def test_inflight_requests_after_logout(client, idp):
    """登出与在途请求并发：登出完成后的任何请求都不得再通过授权。"""
    _login(client, idp)
    cookie = client.cookies.get("saml_session")

    results = {"authorized_after_logout": 0}
    lock = threading.Lock()
    logout_done = threading.Event()

    def inflight():
        # 模拟在途请求：登出完成后仍持旧凭证访问
        logout_done.wait()
        c = TestClient(client.app)
        c.cookies.set("saml_session", cookie)
        if c.get("/me").status_code == 200:
            with lock:
                results["authorized_after_logout"] += 1

    threads = [threading.Thread(target=inflight) for _ in range(10)]
    for t in threads:
        t.start()

    assert client.post("/logout").status_code == 200
    logout_done.set()
    for t in threads:
        t.join()

    assert results["authorized_after_logout"] == 0


def test_logout_then_relogin(client, idp):
    """登出后可以用新断言重新登录（新断言 ID）。"""
    _login(client, idp)
    client.post("/logout")
    _login(client, idp)
    assert client.get("/me").status_code == 200
