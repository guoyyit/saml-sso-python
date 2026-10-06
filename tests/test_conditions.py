"""时间条件与受众校验：NotBefore / NotOnOrAfter / Audience + 时钟偏移窗口。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from saml_sso.errors import (
    AssertionExpiredError,
    AssertionNotYetValidError,
    AudienceMismatchError,
)
from saml_sso.service import SamlService

from idp import FakeIdP

NOW = datetime.now(timezone.utc)


def test_expired_assertion_rejected(service: SamlService, idp: FakeIdP):
    b64 = idp.build_response_b64(
        not_before=NOW - timedelta(hours=2),
        not_on_or_after=NOW - timedelta(minutes=5),
    )
    with pytest.raises(AssertionExpiredError) as exc_info:
        service.consume_response(b64, NOW)
    assert exc_info.value.code == "assertion_expired"


def test_not_yet_valid_assertion_rejected(service: SamlService, idp: FakeIdP):
    b64 = idp.build_response_b64(
        not_before=NOW + timedelta(minutes=10),
        not_on_or_after=NOW + timedelta(hours=1),
    )
    with pytest.raises(AssertionNotYetValidError) as exc_info:
        service.consume_response(b64, NOW)
    assert exc_info.value.code == "assertion_not_yet_valid"


def test_clock_skew_window_allows_small_expiry(
    service: SamlService, idp: FakeIdP
):
    """过期 30 秒、容忍窗口 60 秒：应被接受。"""
    b64 = idp.build_response_b64(
        not_before=NOW - timedelta(hours=1),
        not_on_or_after=NOW - timedelta(seconds=30),
    )
    session = service.consume_response(b64, NOW)
    assert session.name_id == "user@example.com"


def test_beyond_clock_skew_rejected(service: SamlService, idp: FakeIdP):
    """过期 90 秒、容忍窗口 60 秒：必须拒绝。"""
    b64 = idp.build_response_b64(
        not_before=NOW - timedelta(hours=1),
        not_on_or_after=NOW - timedelta(seconds=90),
    )
    with pytest.raises(AssertionExpiredError):
        service.consume_response(b64, NOW)


def test_clock_skew_configurable(make_settings, idp: FakeIdP, idp_config):
    """容忍窗口可配置：窗口收紧到 10 秒时，过期 30 秒即被拒绝。"""
    settings = make_settings([idp_config], clock_skew_seconds=10)
    from saml_sso.service import SamlService

    svc = SamlService(settings)
    b64 = idp.build_response_b64(
        not_before=NOW - timedelta(hours=1),
        not_on_or_after=NOW - timedelta(seconds=30),
    )
    with pytest.raises(AssertionExpiredError):
        svc.consume_response(b64, NOW)


def test_audience_mismatch_rejected(service: SamlService, idp: FakeIdP):
    b64 = idp.build_response_b64(audience="https://someone-else.test")
    with pytest.raises(AudienceMismatchError) as exc_info:
        service.consume_response(b64, NOW)
    assert exc_info.value.code == "audience_mismatch"


def test_future_not_before_within_skew_accepted(
    service: SamlService, idp: FakeIdP
):
    """NotBefore 在未来 30 秒、容忍窗口 60 秒：应被接受。"""
    b64 = idp.build_response_b64(
        not_before=NOW + timedelta(seconds=30),
        not_on_or_after=NOW + timedelta(minutes=5),
    )
    session = service.consume_response(b64, NOW)
    assert session.name_id == "user@example.com"
