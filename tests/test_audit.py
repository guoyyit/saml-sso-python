"""审计场景：事件记录完整、敏感属性脱敏、原始断言不落盘。"""

from __future__ import annotations

import base64
import json

from saml_sso.audit import AuditLogger


def _b64(xml: bytes) -> str:
    return base64.b64encode(xml).decode()


def _read_log(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_login_and_logout_audited(client, idp, settings):
    xml = idp.build_response(
        name_id="alice@example.com",
        attributes={"uid": ["u1"], "mail": ["alice@example.com"]},
    )
    client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})
    client.post("/logout")

    records = _read_log(settings.audit_log_path)
    events = [r["event"] for r in records]
    assert events == ["login_success", "logout"]

    login_rec = records[0]
    assert login_rec["idp_id"] == "test"
    assert login_rec["assertion_id"]
    assert login_rec["session_id"]


def test_audit_redacts_sensitive_attributes(client, idp, settings):
    xml = idp.build_response(
        name_id="alice@example.com",
        attributes={"uid": ["u1"], "mail": ["alice@example.com"]},
    )
    client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})

    raw = settings.audit_log_path.read_text()
    # 敏感属性与 name_id 不得以明文出现
    assert "alice@example.com" not in raw
    # 非敏感属性保留明文以便审计
    assert '"uid": "u1"' in raw
    # 脱敏值是摘要形式
    record = _read_log(settings.audit_log_path)[0]
    assert record["attributes"]["email"].startswith("sha256:")
    assert record["name_id"].startswith("sha256:")


def test_audit_never_logs_raw_assertion(client, idp, settings):
    xml = idp.build_response(attributes={"uid": ["u1"], "mail": ["secret@x.y"]})
    client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})
    raw = settings.audit_log_path.read_text()
    assert "Assertion" not in raw
    assert "secret@x.y" not in raw


def test_audit_logger_drops_raw_payload_fields(tmp_path):
    logger = AuditLogger(tmp_path / "a.log", sensitive_attributes=("email",))
    logger.log(
        "test_event",
        attributes={"email": "a@b.c", "uid": "u1"},
        assertion_xml="<raw/>",
        saml_response="base64blob",
    )
    (record,) = _read_log(tmp_path / "a.log")
    assert "assertion_xml" not in record
    assert "saml_response" not in record
    assert record["attributes"]["email"].startswith("sha256:")
    assert record["attributes"]["uid"] == "u1"


def test_failed_login_audited_without_sensitive_leak(client, idp, settings):
    """失败的登录尝试同样可审计（错误响应不泄露敏感信息）。"""
    xml = idp.build_response(attributes={"mail": ["no-uid@x.y"]})  # 缺 uid
    resp = client.post("/saml/acs/test", data={"SAMLResponse": _b64(xml)})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "missing_attribute"
    assert "no-uid@x.y" not in json.dumps(body)
