"""重放防护场景：重复消费、并发消费、进程重启后状态保留。"""

from __future__ import annotations

import base64
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from saml_sso import errors
from saml_sso.app import create_app
from saml_sso.replay import ReplayCache


def _b64(xml: bytes) -> str:
    return base64.b64encode(xml).decode()


def test_same_assertion_consumed_once(tmp_path):
    cache = ReplayCache(tmp_path / "r.sqlite3")
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    cache.consume("_a1", exp)
    with pytest.raises(errors.ReplayDetectedError):
        cache.consume("_a1", exp)
    cache.close()


def test_concurrent_consume_single_winner(tmp_path):
    cache = ReplayCache(tmp_path / "r.sqlite3")
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)
    outcomes = {"ok": 0, "replay": 0}
    lock = threading.Lock()

    def worker():
        try:
            cache.consume("_race", exp)
            with lock:
                outcomes["ok"] += 1
        except errors.ReplayDetectedError:
            with lock:
                outcomes["replay"] += 1

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes == {"ok": 1, "replay": 19}
    cache.close()


def test_replay_state_survives_restart(tmp_path):
    db = tmp_path / "r.sqlite3"
    exp = datetime.now(timezone.utc) + timedelta(minutes=5)

    ReplayCache(db).consume("_persist", exp)
    # 模拟进程重启：新建实例指向同一数据库文件
    cache2 = ReplayCache(db)
    with pytest.raises(errors.ReplayDetectedError):
        cache2.consume("_persist", exp)
    cache2.close()


def test_expired_records_purged(tmp_path):
    db = tmp_path / "r.sqlite3"
    now = datetime.now(timezone.utc)
    cache = ReplayCache(db)
    cache.consume("_old", now + timedelta(seconds=30))
    assert cache.purge_expired(now + timedelta(minutes=1)) == 1
    # 清理后同一 ID 可再次消费（原断言已过有效期，无重放风险）
    cache.consume("_old", now + timedelta(minutes=10))
    cache.close()


def test_replay_rejected_via_acs(client, idp):
    """同一断言通过 ACS 提交两次，第二次被拒绝且可区分。"""
    xml = idp.build_response(attributes={"uid": ["u1"]})
    payload = {"SAMLResponse": _b64(xml)}

    resp1 = client.post("/saml/acs/test", data=payload)
    assert resp1.status_code == 200, resp1.text

    resp2 = client.post("/saml/acs/test", data=payload)
    assert resp2.status_code == 400
    assert resp2.json()["error"] == "replay_detected"


def test_replay_protection_across_app_restart(idp, settings):
    """应用重启（新建 app，同一数据库文件）后重放仍被拒绝。"""
    xml = idp.build_response(attributes={"uid": ["u1"]})
    payload = {"SAMLResponse": _b64(xml)}

    client1 = TestClient(create_app(settings))
    assert client1.post("/saml/acs/test", data=payload).status_code == 200

    client2 = TestClient(create_app(settings))
    resp = client2.post("/saml/acs/test", data=payload)
    assert resp.status_code == 400
    assert resp.json()["error"] == "replay_detected"
