"""配置模型与加载。

支持多个身份提供方（IdP），每个 IdP 拥有独立的信任密钥列表、
属性映射与必需属性，保证 IdP 之间的会话与属性相互隔离。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path


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
        raise NotImplementedError


def load_settings(path: str | Path) -> Settings:
    """从 JSON 文件加载配置。"""
    raise NotImplementedError
