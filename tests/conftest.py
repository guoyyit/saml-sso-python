"""pytest 公共夹具：本地 IdP、SP 配置与测试客户端。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from helpers import LocalIdP  # noqa: E402

from saml_sso.app import create_app  # noqa: E402
from saml_sso.config import IdpConfig, Settings  # noqa: E402


@pytest.fixture()
def idp() -> LocalIdP:
    return LocalIdP(entity_id="urn:test:idp")


@pytest.fixture()
def idp_config(idp: LocalIdP) -> IdpConfig:
    return IdpConfig(
        idp_id="test",
        entity_id=idp.entity_id,
        sso_url="https://idp.example.com/sso",
        certificates=(idp.cert_pem,),
        attribute_mapping={"uid": "uid", "mail": "email", "displayName": "display_name"},
        required_attributes=("uid",),
        sensitive_attributes=("email",),
    )


@pytest.fixture()
def settings(idp_config: IdpConfig, tmp_path: Path) -> Settings:
    return Settings(
        sp_entity_id="urn:example:sp",
        sp_acs_url="http://testserver/saml/acs",
        replay_db_path=tmp_path / "replay.sqlite3",
        audit_log_path=tmp_path / "audit.log",
        idps={"test": idp_config},
    )


@pytest.fixture()
def client(settings: Settings):
    from fastapi.testclient import TestClient

    return TestClient(create_app(settings))
