"""配置模型：SP 自身、各 IdP 信任配置、时钟偏移与属性映射。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IdpConfig:
    """单个身份提供方的本地信任配置。"""

    entity_id: str
    #: 受信任的签名证书（PEM，可多个以支持轮换）
    certificates: tuple[str, ...] = ()
    #: 必需属性：SAML 属性名 -> 本地会话字段名
    required_attributes: dict[str, str] = field(default_factory=dict)
    #: 可选属性映射
    optional_attributes: dict[str, str] = field(default_factory=dict)
    #: 审计时需脱敏的本地字段名
    sensitive_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class SpConfig:
    """本服务（SP）自身配置。"""

    entity_id: str
    acs_url: str


@dataclass(frozen=True)
class Settings:
    """全局设置。"""

    sp: SpConfig
    idps: tuple[IdpConfig, ...] = ()
    #: 时钟偏移容忍窗口（秒）
    clock_skew_seconds: int = 60
    #: 本地会话有效期（秒）
    session_ttl_seconds: int = 3600
    #: 持久化数据库路径（重放缓存 / 会话）
    db_path: str = "saml_sso.db"
    #: 审计日志路径
    audit_log_path: str = "saml_audit.log"

    def idp_by_entity_id(self, entity_id: str) -> IdpConfig | None:
        """按 entityID 查找 IdP 配置。"""
        raise NotImplementedError
