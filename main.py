"""应用入口：从环境变量加载配置并创建 FastAPI 应用。

配置项（环境变量）：
    SP_ENTITY_ID            本服务（SP）的 entityID
    SP_ACS_URL              断言消费服务（ACS）URL
    SAML_IDP_ENTITY_ID      身份提供方 entityID
    SAML_IDP_METADATA_FILE  IdP 元数据 XML 文件路径（解析签名密钥）
    SAML_IDP_CERT_FILE      无元数据时，单独的 IdP 签名证书 PEM 路径
    SAML_REQUIRED_ATTRS     必需属性映射，如 "uid=uid,email=email"
    SAML_OPTIONAL_ATTRS     可选属性映射，格式同上
    SAML_SENSITIVE_FIELDS   审计脱敏字段，如 "email,phone"
    SAML_CLOCK_SKEW         时钟偏移容忍秒数（默认 60）
    SAML_SESSION_TTL        本地会话有效期秒数（默认 3600）
    SAML_DB_PATH            SQLite 数据库路径（默认 saml_sso.db）
    SAML_AUDIT_LOG          审计日志路径（默认 saml_audit.log）
"""

from __future__ import annotations

import os
from pathlib import Path

from saml_sso.app import create_app
from saml_sso.config import IdpConfig, Settings, SpConfig
from saml_sso.metadata import parse_metadata


def _parse_mapping(value: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for pair in value.split(","):
        pair = pair.strip()
        if pair:
            saml_name, local_name = pair.split("=", 1)
            mapping[saml_name.strip()] = local_name.strip()
    return mapping


def load_settings() -> Settings:
    idp_entity_id = os.environ["SAML_IDP_ENTITY_ID"]

    certificates: tuple[str, ...] = ()
    metadata_file = os.environ.get("SAML_IDP_METADATA_FILE")
    cert_file = os.environ.get("SAML_IDP_CERT_FILE")
    if metadata_file:
        metadata = parse_metadata(Path(metadata_file).read_text())
        certificates = metadata.signing_certificates
    elif cert_file:
        certificates = (Path(cert_file).read_text(),)

    idp = IdpConfig(
        entity_id=idp_entity_id,
        certificates=certificates,
        required_attributes=_parse_mapping(
            os.environ.get("SAML_REQUIRED_ATTRS", "uid=uid")
        ),
        optional_attributes=_parse_mapping(
            os.environ.get("SAML_OPTIONAL_ATTRS", "")
        ),
        sensitive_fields=tuple(
            f.strip()
            for f in os.environ.get("SAML_SENSITIVE_FIELDS", "").split(",")
            if f.strip()
        ),
    )
    return Settings(
        sp=SpConfig(
            entity_id=os.environ.get("SP_ENTITY_ID", "http://localhost:8000"),
            acs_url=os.environ.get(
                "SP_ACS_URL", "http://localhost:8000/saml/acs"
            ),
        ),
        idps=(idp,),
        clock_skew_seconds=int(os.environ.get("SAML_CLOCK_SKEW", "60")),
        session_ttl_seconds=int(os.environ.get("SAML_SESSION_TTL", "3600")),
        db_path=os.environ.get("SAML_DB_PATH", "saml_sso.db"),
        audit_log_path=os.environ.get("SAML_AUDIT_LOG", "saml_audit.log"),
    )


app = create_app(load_settings())
