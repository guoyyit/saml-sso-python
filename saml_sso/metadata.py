"""IdP 元数据解析与签名密钥管理（支持轮换）。"""

from __future__ import annotations

from dataclasses import dataclass, field

from lxml import etree

from saml_sso.certs import der_b64_to_pem, normalize_pem
from saml_sso.errors import MetadataError

NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class IdpMetadata:
    """从 IdP 元数据 XML 解析出的信息。"""

    entity_id: str
    sso_url: str | None = None
    slo_url: str | None = None
    #: 签名证书（PEM 列表，按出现顺序）
    signing_certificates: tuple[str, ...] = ()


def parse_metadata(xml: str | bytes) -> IdpMetadata:
    """解析 SAML 元数据 XML，提取 entityID、SSO/SLO 端点与签名密钥。

    只采纳 KeyDescriptor 中 use 为 signing 或未声明 use 的密钥。
    """
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True)
        root = etree.fromstring(
            xml.encode() if isinstance(xml, str) else xml, parser
        )
    except etree.XMLSyntaxError as exc:
        raise MetadataError(f"malformed metadata XML: {exc}") from exc

    if root.tag != f"{{{NS_MD}}}EntityDescriptor":
        raise MetadataError(f"unexpected root element: {root.tag}")

    entity_id = root.get("entityID")
    if not entity_id:
        raise MetadataError("metadata missing entityID")

    idp_descriptor = root.find(f"{{{NS_MD}}}IDPSSODescriptor")
    if idp_descriptor is None:
        raise MetadataError("metadata has no IDPSSODescriptor")

    certs: list[str] = []
    for key_desc in idp_descriptor.findall(f"{{{NS_MD}}}KeyDescriptor"):
        use = key_desc.get("use")
        if use not in (None, "signing"):
            continue
        for cert_el in key_desc.iter(f"{{{NS_DS}}}X509Certificate"):
            if cert_el.text:
                pem = der_b64_to_pem(cert_el.text)
                if pem not in certs:
                    certs.append(pem)

    sso_url: str | None = None
    slo_url: str | None = None
    for svc in idp_descriptor.findall(f"{{{NS_MD}}}SingleSignOnService"):
        if svc.get("Location"):
            sso_url = svc.get("Location")
            break
    for svc in idp_descriptor.findall(f"{{{NS_MD}}}SingleLogoutService"):
        if svc.get("Location"):
            slo_url = svc.get("Location")
            break

    return IdpMetadata(
        entity_id=entity_id,
        sso_url=sso_url,
        slo_url=slo_url,
        signing_certificates=tuple(certs),
    )


@dataclass
class TrustedKeyStore:
    """管理各 IdP 的受信任签名密钥，支持轮换期间多密钥并存。"""

    _keys: dict[str, list[str]] = field(default_factory=dict)

    def set_keys(self, entity_id: str, certs_pem: list[str]) -> None:
        """整体替换某 IdP 的受信任密钥集合。"""
        seen: list[str] = []
        for pem in certs_pem:
            norm = normalize_pem(pem)
            if norm not in seen:
                seen.append(norm)
        self._keys[entity_id] = seen

    def add_key(self, entity_id: str, cert_pem: str) -> None:
        """为某 IdP 追加一个受信任密钥（轮换时先加新密钥）。"""
        norm = normalize_pem(cert_pem)
        keys = self._keys.setdefault(entity_id, [])
        if norm not in keys:
            keys.append(norm)

    def remove_key(self, entity_id: str, cert_pem: str) -> None:
        """移除某 IdP 的一个密钥（轮换完成后下线旧密钥）。"""
        norm = normalize_pem(cert_pem)
        keys = self._keys.get(entity_id, [])
        if norm in keys:
            keys.remove(norm)

    def keys_for(self, entity_id: str) -> list[str]:
        """返回某 IdP 当前全部受信任密钥。"""
        return list(self._keys.get(entity_id, []))
