"""IdP 元数据解析与签名密钥管理（支持轮换）。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IdpMetadata:
    """从 IdP 元数据 XML 解析出的信息。"""

    entity_id: str
    sso_url: str | None = None
    slo_url: str | None = None
    #: 签名证书（PEM 列表，按出现顺序）
    signing_certificates: tuple[str, ...] = ()


def parse_metadata(xml: str | bytes) -> IdpMetadata:
    """解析 SAML 元数据 XML，提取 entityID、SSO/SLO 端点与签名密钥。"""
    raise NotImplementedError


@dataclass
class TrustedKeyStore:
    """管理各 IdP 的受信任签名密钥，支持轮换期间多密钥并存。"""

    _keys: dict[str, list[str]] = field(default_factory=dict)

    def set_keys(self, entity_id: str, certs_pem: list[str]) -> None:
        """整体替换某 IdP 的受信任密钥集合。"""
        raise NotImplementedError

    def add_key(self, entity_id: str, cert_pem: str) -> None:
        """为某 IdP 追加一个受信任密钥（轮换时先加新密钥）。"""
        raise NotImplementedError

    def remove_key(self, entity_id: str, cert_pem: str) -> None:
        """移除某 IdP 的一个密钥（轮换完成后下线旧密钥）。"""
        raise NotImplementedError

    def keys_for(self, entity_id: str) -> list[str]:
        """返回某 IdP 当前全部受信任密钥。"""
        raise NotImplementedError
