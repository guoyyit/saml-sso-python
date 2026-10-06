"""登出：本地登出与 IdP 单点登出；会话失效后在途请求不得越权写入。"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from idp import build_logout_request_b64

NOW = datetime.now(timezone.utc)


def _login(client: TestClient, idp, **kwargs) -> str:
    response = client.post(
        "/saml/acs", data={"SAMLResponse": idp.build_response_b64(**kwargs)}
    )
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


def test_local_logout_invalidates_session(client, idp):
    _login(client, idp)
    assert client.get("/me").status_code == 200
    assert client.post("/logout").json()["logged_out"] is True
    assert client.get("/me").status_code == 401


def test_protected_write_blocked_after_logout(client, idp):
    _login(client, idp)
    assert client.post("/protected/write", json={"x": 1}).status_code == 200
    client.post("/logout")
    response = client.post("/protected/write", json={"x": 1})
    assert response.status_code == 401
    assert response.json()["error"] == "not_authenticated"


def test_slo_logout_request_invalidates_session(client, idp):
    _login(client, idp, session_index="idx-42")
    assert client.get("/me").status_code == 200
    response = client.post(
        "/saml/slo",
        data={
            "SAMLRequest": build_logout_request_b64(
                idp, name_id="user@example.com", session_index="idx-42"
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["invalidated_sessions"] == 1
    assert client.get("/me").status_code == 401


def test_slo_without_session_index_invalidates_all_user_sessions(
    client, idp, service
):
    _login(client, idp, session_index="idx-1")
    _login(client, idp, session_index="idx-2")
    response = client.post(
        "/saml/slo",
        data={
            "SAMLRequest": build_logout_request_b64(
                idp, name_id="user@example.com"
            )
        },
    )
    assert response.json()["invalidated_sessions"] == 2
    assert client.get("/me").status_code == 401


def test_slo_only_affects_matching_session_index(client, idp):
    _login(client, idp, session_index="idx-1")
    _login(client, idp, session_index="idx-2")
    client.post(
        "/saml/slo",
        data={
            "SAMLRequest": build_logout_request_b64(
                idp, name_id="user@example.com", session_index="idx-1"
            )
        },
    )
    # 当前 cookie 对应 idx-2 的会话，仍然有效
    assert client.get("/me").status_code == 200


def test_unsigned_slo_request_rejected(client, idp):
    _login(client, idp)
    response = client.post(
        "/saml/slo",
        data={
            "SAMLRequest": build_logout_request_b64(
                idp, name_id="user@example.com", sign=False
            )
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "signature_missing"
    # 会话未被波及
    assert client.get("/me").status_code == 200


def test_concurrent_requests_after_logout_cannot_write(client, idp):
    """登出与在途请求并发：登出生效后，任何写请求都不得成功。"""
    _login(client, idp)
    client.post("/logout")

    def attempt_write(i):
        return client.post("/protected/write", json={"i": i}).status_code

    with ThreadPoolExecutor(max_workers=16) as pool:
        statuses = list(pool.map(attempt_write, range(64)))
    assert set(statuses) == {401}
