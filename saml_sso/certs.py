"""证书工具：DER/PEM 转换与规范化比较。"""

from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from saml_sso.errors import MetadataError


def der_b64_to_pem(b64_der: str) -> str:
    """把 base64 编码的 DER 证书规范化为 PEM 文本。"""
    try:
        der = base64.b64decode("".join(b64_der.split()))
        cert = x509.load_der_x509_certificate(der)
        return cert.public_bytes(Encoding.PEM).decode("ascii")
    except Exception as exc:  # noqa: BLE001 - 统一归一为元数据错误
        raise MetadataError(f"invalid X.509 certificate: {exc}") from exc


def normalize_pem(pem: str) -> str:
    """去除全部空白，用于比较两份 PEM 是否为同一证书。"""
    return "".join(pem.split())
