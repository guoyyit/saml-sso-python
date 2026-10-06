"""审计：会话与断言事件留痕，敏感属性脱敏，原始断言内容不外泄。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from idp import build_logout_request_b64

NOW = datetime.now(timezone.utc)


def _read_audit(settings) -> list[dict]:
    with open(settings.audit_log_path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_session_creation_audited_with_redaction(service, settings, idp):
    service.consume_response(idp.build_response_b64(), NOW)
    records = _read_audit(settings)
    created = [r for r in records if r["event"] == "session_created"]
    assert len(created) == 1
    record = created[0]
    assert record["idp"] == idp.entity_id
    assert record["name_id"] == "user@example.com"
    assert record["assertion_id"]
    assert record["session_id"]
    # 敏感字段脱敏，非敏感字段保留
    assert record["attributes"]["email"] == "***"
    assert record["attributes"]["uid"] == "u-1001"


def test_rejected_assertions_audited_without_attributes(
    service, settings, idp
):
    import base64

    tampered = base64.b64encode(
        idp.build_response_xml().replace("u-1001", "u-9999").encode()
    ).decode()
    for payload in (tampered, tampered):
        try:
            service.consume_response(payload, NOW)
        except Exception:
            pass
    records = _read_audit(settings)
    rejected = [r for r in records if r["event"] == "assertion_rejected"]
    assert len(rejected) == 2
    for record in rejected:
        assert record["detail"].startswith("signature_invalid")
        # 拒绝事件不记录任何断言属性
        assert record["attributes"] is None


def test_raw_assertion_not_leaked_to_audit(service, settings, idp):
    """审计日志全文不得出现原始断言中的敏感取值。"""
    secret = "TopSecretDisplayName-12345"
    service.consume_response(
        idp.build_response_b64(
            attributes={
                "uid": ["u-1"],
                "email": ["secret-user@corp.example"],
                "displayName": [secret],
            }
        ),
        NOW,
    )
    content = open(settings.audit_log_path, encoding="utf-8").read()
    assert "secret-user@corp.example" not in content  # 敏感字段已脱敏
    assert "<saml" not in content  # 原始断言 XML 不进入审计


def test_logout_events_audited(service, settings, idp):
    session = service.consume_response(idp.build_response_b64(), NOW)
    service.logout(session.session_id)
    service.handle_logout_request(
        build_logout_request_b64(idp, name_id="someone@example.com"), NOW
    )
    events = [r["event"] for r in _read_audit(settings)]
    assert "logout_local" in events
    assert "logout_request" in events


def test_replay_rejection_audited(service, settings, idp):
    b64 = idp.build_response_b64()
    service.consume_response(b64, NOW)
    try:
        service.consume_response(b64, NOW)
    except Exception:
        pass
    records = _read_audit(settings)
    replay = [
        r
        for r in records
        if r["event"] == "assertion_rejected"
        and r["detail"].startswith("replay_detected")
    ]
    assert len(replay) == 1
