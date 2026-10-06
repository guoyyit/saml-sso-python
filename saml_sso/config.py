"""配置模型与加载。

支持多个身份提供方（IdP），每个 IdP 拥有独立的信任密钥列表、
属性映射与必需属性，保证 IdP 之间的会话与属性相互隔离。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from .errors import UnknownIdPError


@dataclass(frozen=True)
class IdpConfig:
    """单个身份提供方的配置。"""

    idp_id: str
    entity_id: str
    sso_url: str = ""
    # 受信任的签名证书（PEM 文本，支持多个以完成密钥轮换）
    certificates: tuple[str, ...] = ()
    # 远程属性名 -> 本地属性名
    attribute_mapping: dict[str, str] = field(default_factory=dict)
    # 建立会话所必需的（映射后）本地属性
    required_attributes: tuple[str, ...] = ("uid",)
    # 审计时需要脱敏的（映射后）本地属性
    sensitive_attributes: tuple[str, ...] = ("email",)


@dataclass(frozen=True)
class Settings:
    """服务提供方（SP）全局配置。"""

    sp_entity_id: str = "urn:example:sp"
    sp_acs_url: str = "http://localhost:8000/saml/acs"
    clock_skew: timedelta = timedelta(seconds=60)
    session_ttl: timedelta = timedelta(hours=8)
    replay_db_path: Path = Path("replay_cache.sqlite3")
    audit_log_path: Path = Path("audit.log")
    idps: dict[str, IdpConfig] = field(default_factory=dict)

    def get_idp(self, idp_id: str) -> IdpConfig:
        """按 idp_id 查找配置，未配置时抛出 UnknownIdPError。"""
        try:
            return self.idps[idp_id]
        except KeyError:
            raise UnknownIdPError(f"unknown identity provider: {idp_id!r}") from None


def load_settings(path: str | Path) -> Settings:
    """从 JSON 文件加载配置。

    文件结构示例::

        {
          "sp_entity_id": "urn:example:sp",
          "sp_acs_url": "https://sp.example.com/saml/acs",
          "clock_skew_seconds": 60,
          "session_ttl_seconds": 28800,
          "replay_db_path": "replay_cache.sqlite3",
          "audit_log_path": "audit.log",
          "idps": {
            "corp-idp": {
              "entity_id": "urn:corp:idp",
              "sso_url": "https://idp.example.com/sso",
              "certificates": ["<PEM 文本>", ...],
              "attribute_mapping": {"mail": "email", "uid": "uid"},
              "required_attributes": ["uid"],
              "sensitive_attributes": ["email"]
            }
          }
        }
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    idps = {
        idp_id: IdpConfig(
            idp_id=idp_id,
            entity_id=cfg["entity_id"],
            sso_url=cfg.get("sso_url", ""),
            certificates=tuple(cfg.get("certificates", ())),
            attribute_mapping=dict(cfg.get("attribute_mapping", {})),
            required_attributes=tuple(cfg.get("required_attributes", ("uid",))),
            sensitive_attributes=tuple(cfg.get("sensitive_attributes", ("email",))),
        )
        for idp_id, cfg in raw.get("idps", {}).items()
    }
    return Settings(
        sp_entity_id=raw.get("sp_entity_id", "urn:example:sp"),
        sp_acs_url=raw.get("sp_acs_url", "http://localhost:8000/saml/acs"),
        clock_skew=timedelta(seconds=raw.get("clock_skew_seconds", 60)),
        session_ttl=timedelta(seconds=raw.get("session_ttl_seconds", 8 * 3600)),
        replay_db_path=Path(raw.get("replay_db_path", "replay_cache.sqlite3")),
        audit_log_path=Path(raw.get("audit_log_path", "audit.log")),
        idps=idps,
    )
