"""时间条件与受众限制场景：过期、未生效、时钟偏移窗口、受众。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from saml_sso import errors
from saml_sso.assertion import validate_response
from saml_sso.config import Settings


@pytest.fixture()
def now() -> datetime:
    return datetime.now(timezone.utc)


def test_expired_assertion_rejected(idp, idp_config, settings, now):
    xml = idp.build_response(
        not_before=now - timedelta(hours=2),
        not_on_or_after=now - timedelta(minutes=5),
    )
    with pytest.raises(errors.ExpiredAssertionError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "assertion_expired"


def test_not_yet_valid_rejected(idp, idp_config, settings, now):
    xml = idp.build_response(
        not_before=now + timedelta(minutes=5),
        not_on_or_after=now + timedelta(minutes=10),
    )
    with pytest.raises(errors.NotYetValidError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "assertion_not_yet_valid"


def test_clock_skew_tolerance(idp, idp_config, settings, now):
    """默认 60s 容忍窗口：过期 30s 仍接受，未生效 30s 也接受。"""
    skew = settings.clock_skew
    assert skew == timedelta(seconds=60)

    xml = idp.build_response(
        not_before=now - timedelta(hours=1),
        not_on_or_after=now - timedelta(seconds=30),
    )
    validate_response(xml, idp_config, settings)

    xml = idp.build_response(
        not_before=now + timedelta(seconds=30),
        not_on_or_after=now + timedelta(minutes=5),
    )
    validate_response(xml, idp_config, settings)


def test_beyond_skew_rejected(idp, idp_config, settings, now):
    """超出容忍窗口一律拒绝。"""
    xml = idp.build_response(
        not_before=now - timedelta(hours=1),
        not_on_or_after=now - timedelta(seconds=90),
    )
    with pytest.raises(errors.ExpiredAssertionError):
        validate_response(xml, idp_config, settings)

    xml = idp.build_response(
        not_before=now + timedelta(seconds=90),
        not_on_or_after=now + timedelta(minutes=5),
    )
    with pytest.raises(errors.NotYetValidError):
        validate_response(xml, idp_config, settings)


def test_configurable_skew_window(idp, idp_config, settings, now):
    """容忍窗口可配置：收紧到 10s 后，过期 30s 的断言被拒绝。"""
    strict = Settings(
        sp_entity_id=settings.sp_entity_id,
        clock_skew=timedelta(seconds=10),
        idps=settings.idps,
    )
    xml = idp.build_response(
        not_before=now - timedelta(hours=1),
        not_on_or_after=now - timedelta(seconds=30),
    )
    with pytest.raises(errors.ExpiredAssertionError):
        validate_response(xml, idp_config, strict)


def test_audience_mismatch_rejected(idp, idp_config, settings):
    xml = idp.build_response(audience="urn:other:sp")
    with pytest.raises(errors.AudienceRestrictionError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "audience_restriction"


def test_audience_match_accepted(idp, idp_config, settings):
    xml = idp.build_response(audience="urn:example:sp")
    data = validate_response(xml, idp_config, settings)
    assert data.audience == "urn:example:sp"


def test_issuer_mismatch_rejected(idp, idp_config, settings):
    xml = idp.build_response(issuer="urn:evil:idp")
    with pytest.raises(errors.IssuerMismatchError) as exc_info:
        validate_response(xml, idp_config, settings)
    assert exc_info.value.code == "issuer_mismatch"
