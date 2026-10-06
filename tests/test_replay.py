"""重放防护：同一断言只能消费一次；并发只有一个成功；重启后状态不丢。"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from saml_sso.errors import ReplayDetectedError
from saml_sso.service import SamlService

from idp import FakeIdP

NOW = datetime.now(timezone.utc)


def test_same_assertion_consumed_once(service: SamlService, idp: FakeIdP):
    b64 = idp.build_response_b64()
    service.consume_response(b64, NOW)
    with pytest.raises(ReplayDetectedError) as exc_info:
        service.consume_response(b64, NOW)
    assert exc_info.value.code == "replay_detected"


def test_different_assertions_both_accepted(service: SamlService, idp: FakeIdP):
    s1 = service.consume_response(idp.build_response_b64(), NOW)
    s2 = service.consume_response(idp.build_response_b64(), NOW)
    assert s1.session_id != s2.session_id


def test_concurrent_consumption_single_winner(
    service: SamlService, idp: FakeIdP
):
    """并发提交同一断言：恰好一个成功，其余全部因重放被拒绝。"""
    b64 = idp.build_response_b64()

    def attempt(_):
        try:
            service.consume_response(b64, NOW)
            return "ok"
        except ReplayDetectedError:
            return "replay"

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(64)))
    assert results.count("ok") == 1
    assert results.count("replay") == 63


def test_replay_state_survives_restart(
    make_settings, idp: FakeIdP, idp_config
):
    """进程重启（新建服务实例、复用同一数据库文件）后重放仍被拒绝。"""
    settings = make_settings([idp_config])
    svc1 = SamlService(settings)
    b64 = idp.build_response_b64()
    svc1.consume_response(b64, NOW)

    svc2 = SamlService(settings)  # 模拟重启：新实例，同一 db_path
    with pytest.raises(ReplayDetectedError):
        svc2.consume_response(b64, NOW)
