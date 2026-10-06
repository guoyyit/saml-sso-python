"""断言 XML 数字签名校验。

安全要点：
- 只接受 Response 或 Assertion 上携带的 XML-DSig 签名；
- KeyInfo 中内嵌的证书必须出现在本地受信任密钥集合中，否则视为未知来源密钥；
- 验签通过后只使用 signxml 返回的已签名元素提取断言，避免签名包装（XSW）攻击；
- 依赖 signxml 默认配置，仅允许 SHA-2 系列签名与摘要算法。
"""

from __future__ import annotations

from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidSignature

from saml_sso.certs import der_b64_to_pem, normalize_pem
from saml_sso.errors import (
    SignatureInvalidError,
    SignatureMissingError,
    SamlError,
    UntrustedKeyError,
)

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"


def _parse_xml(response_xml: bytes) -> etree._Element:
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        return etree.fromstring(response_xml, parser)
    except etree.XMLSyntaxError as exc:
        raise SamlError(f"malformed SAML response XML: {exc}") from exc


def _find_signature(root: etree._Element) -> etree._Element | None:
    """优先取 Response 直接子级的签名，其次取 Assertion 直接子级的签名。"""
    for child in root:
        if child.tag == f"{{{NS_DS}}}Signature":
            return child
    for assertion in root.iter(f"{{{NS_SAML}}}Assertion"):
        for child in assertion:
            if child.tag == f"{{{NS_DS}}}Signature":
                return child
    return None


def _embedded_cert_pem(signature_el: etree._Element) -> str | None:
    """提取签名 KeyInfo 中内嵌的 X509 证书（PEM），没有则返回 None。"""
    for cert_el in signature_el.iter(f"{{{NS_DS}}}X509Certificate"):
        if cert_el.text and cert_el.text.strip():
            return der_b64_to_pem(cert_el.text)
    return None


def _extract_verified_assertion(signed_el: etree._Element) -> etree._Element:
    """从已验签的元素中取出 Assertion（已签名元素本身或其子孙）。"""
    if signed_el.tag == f"{{{NS_SAML}}}Assertion":
        return signed_el
    for assertion in signed_el.iter(f"{{{NS_SAML}}}Assertion"):
        return assertion
    raise SignatureInvalidError("signed content contains no Assertion")


def verify_response_signature(
    response_xml: bytes, trusted_certs_pem: list[str]
) -> etree._Element:
    """校验 SAML Response（或其内 Assertion）的签名。

    返回已验证的 Assertion 元素。
    未签名 / 签名无效 / 密钥不受信任分别抛出对应错误。
    """
    root = _parse_xml(response_xml)

    signature_el = _find_signature(root)
    if signature_el is None:
        raise SignatureMissingError("SAML response carries no signature")

    embedded_pem = _embedded_cert_pem(signature_el)
    if embedded_pem is None:
        raise SignatureInvalidError("signature KeyInfo has no X509 certificate")

    trusted_normalized = {normalize_pem(p) for p in trusted_certs_pem}
    if normalize_pem(embedded_pem) not in trusted_normalized:
        raise UntrustedKeyError("assertion signed with an untrusted key")

    verifier = XMLVerifier()
    try:
        result = verifier.verify(root, x509_cert=embedded_pem)
    except InvalidSignature as exc:
        raise SignatureInvalidError(f"signature verification failed: {exc}") from exc

    results = result if isinstance(result, list) else [result]
    for item in results:
        try:
            return _extract_verified_assertion(item.signed_xml)
        except SignatureInvalidError:
            continue
    raise SignatureInvalidError("no signed Assertion could be verified")
