"""共享测试夹具：本地 IdP、服务配置、HTTP 客户端。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from idp import FakeIdP  # noqa: E402

from saml_sso.app import create_app  # noqa: E402
from saml_sso.config import IdpConfig, Settings, SpConfig  # noqa: E402
from saml_sso.service import SamlService  # noqa: E402

SP_ENTITY_ID = "https://sp.test/metadata"
SP_ACS_URL = "https://sp.test/saml/acs"


@pytest.fixture()
def idp() -> FakeIdP:
    return FakeIdP.create()


@pytest.fixture()
def make_settings(tmp_path):
    """按 IdP 列表构造配置，数据库与审计日志落在临时目录。"""

    def _make(idp_configs: list[IdpConfig], **overrides) -> Settings:
        kwargs = {
            "sp": SpConfig(entity_id=SP_ENTITY_ID, acs_url=SP_ACS_URL),
            "idps": tuple(idp_configs),
            "db_path": str(tmp_path / "saml.db"),
            "audit_log_path": str(tmp_path / "audit.log"),
        }
        kwargs.update(overrides)
        return Settings(**kwargs)

    return _make


@pytest.fixture()
def idp_config(idp) -> IdpConfig:
    return IdpConfig(
        entity_id=idp.entity_id,
        certificates=(idp.cert_pem,),
        required_attributes={"uid": "uid", "email": "email"},
        optional_attributes={"displayName": "display_name"},
        sensitive_fields=("email",),
    )


@pytest.fixture()
def settings(make_settings, idp_config) -> Settings:
    return make_settings([idp_config])


@pytest.fixture()
def service(settings) -> SamlService:
    return SamlService(settings)


@pytest.fixture()
def client(settings) -> TestClient:
    return TestClient(create_app(settings))
