"""身份提供方元数据解析与受信任密钥管理。

支持从 IdP 元数据 XML 中提取实体 ID、SSO 地址与签名证书，
并允许为同一 IdP 配置多个受信任密钥以完成平滑轮换。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lxml import etree

from .errors import MalformedAssertionError

MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

# 安全的 XML 解析器：禁用外部实体与网络访问，防 XXE
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)


def _der_to_pem(b64_der: str) -> str:
    """把 base64 的 DER 证书包装为 PEM 文本。"""
    body = "".join(b64_der.split())
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _normalize_pem(pem: str) -> str:
    """归一化 PEM（去掉空白差异），用于去重比较。"""
    return "".join(
        line.strip()
        for line in pem.splitlines()
        if line.strip() and not line.startswith("-----")
    )


@dataclass(frozen=True)
class IdpMetadata:
    """从 IdP 元数据解析出的信息。"""

    entity_id: str
    sso_url: str = ""
    # PEM 编码的 X.509 签名证书列表
    signing_certificates: tuple[str, ...] = ()


def parse_idp_metadata(xml_text: str) -> IdpMetadata:
    """解析 SAML 2.0 IdP 元数据 XML。

    提取 entityID、第一个 SingleSignOnService 地址以及全部
    用于签名的 KeyDescriptor 中的 X.509 证书。
    """
    try:
        root = etree.fromstring(xml_text.encode("utf-8"), parser=_SAFE_PARSER)
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise MalformedAssertionError(f"invalid metadata XML: {exc}") from exc

    if etree.QName(root).localname != "EntityDescriptor":
        raise MalformedAssertionError("metadata root is not EntityDescriptor")

    entity_id = root.get("entityID", "")
    if not entity_id:
        raise MalformedAssertionError("metadata missing entityID")

    sso_url = ""
    certs: list[str] = []
    for idp_desc in root.iter(f"{{{MD_NS}}}IDPSSODescriptor"):
        if not sso_url:
            sso = idp_desc.find(f"{{{MD_NS}}}SingleSignOnService")
            if sso is not None:
                sso_url = sso.get("Location", "")
        for key_desc in idp_desc.iter(f"{{{MD_NS}}}KeyDescriptor"):
            use = key_desc.get("use", "signing")
            if use != "signing":
                continue
            for cert_el in key_desc.iter(f"{{{DS_NS}}}X509Certificate"):
                if cert_el.text and cert_el.text.strip():
                    certs.append(_der_to_pem(cert_el.text))

    return IdpMetadata(
        entity_id=entity_id,
        sso_url=sso_url,
        signing_certificates=tuple(certs),
    )


@dataclass
class KeyStore:
    """一个 IdP 的受信任签名密钥集合（支持轮换期多把密钥并存）。"""

    certificates: list[str] = field(default_factory=list)

    def add_certificate(self, pem: str) -> None:
        """添加受信任证书（按归一化内容去重）。"""
        new = _normalize_pem(pem)
        if all(_normalize_pem(existing) != new for existing in self.certificates):
            self.certificates.append(pem)

    def remove_certificate(self, pem: str) -> None:
        """移除证书（轮换完成后下线旧密钥）。"""
        target = _normalize_pem(pem)
        self.certificates = [
            existing for existing in self.certificates if _normalize_pem(existing) != target
        ]

    def trusted_certificates(self) -> list[str]:
        """返回当前全部受信任证书。"""
        return list(self.certificates)
