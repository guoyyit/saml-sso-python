"""身份提供方元数据解析与受信任密钥管理。

支持从 IdP 元数据 XML 中提取实体 ID、SSO 地址与签名证书，
并允许为同一 IdP 配置多个受信任密钥以完成平滑轮换。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IdpMetadata:
    """从 IdP 元数据解析出的信息。"""

    entity_id: str
    sso_url: str = ""
    # PEM 编码的 X.509 签名证书列表
    signing_certificates: tuple[str, ...] = ()


def parse_idp_metadata(xml_text: str) -> IdpMetadata:
    """解析 SAML 2.0 IdP 元数据 XML。"""
    raise NotImplementedError


@dataclass
class KeyStore:
    """一个 IdP 的受信任签名密钥集合（支持轮换期多把密钥并存）。"""

    certificates: list[str] = field(default_factory=list)

    def add_certificate(self, pem: str) -> None:
        """添加受信任证书（去重）。"""
        raise NotImplementedError

    def remove_certificate(self, pem: str) -> None:
        """移除证书（轮换完成后下线旧密钥）。"""
        raise NotImplementedError

    def trusted_certificates(self) -> list[str]:
        """返回当前全部受信任证书。"""
        raise NotImplementedError
