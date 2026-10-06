"""断言 XML 数字签名校验。"""

from __future__ import annotations

from lxml import etree


def verify_response_signature(
    response_xml: bytes, trusted_certs_pem: list[str]
) -> etree._Element:
    """校验 SAML Response（或其内 Assertion）的签名。

    返回已验证的 Assertion 元素。
    未签名 / 签名无效 / 密钥不受信任分别抛出对应错误。
    """
    raise NotImplementedError
