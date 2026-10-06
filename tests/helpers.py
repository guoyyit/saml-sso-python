"""测试辅助：本地生成的身份提供方与自签名证书。

用 cryptography 生成自签名 CA 证书，用 signxml 对断言做真实签名，
从而完成端到端的签名校验验证。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from signxml import XMLSigner

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"


def make_self_signed_cert(common_name: str = "test-idp") -> tuple[str, str]:
    """生成 RSA 密钥对与自签名 X.509 证书，返回 (key_pem, cert_pem)。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LocalIdP:
    """一个本地模拟的身份提供方：持有密钥，可签发并签名断言。"""

    def __init__(self, entity_id: str = "urn:test:idp", common_name: str = "test-idp") -> None:
        self.entity_id = entity_id
        self.key_pem, self.cert_pem = make_self_signed_cert(common_name)

    def build_response(
        self,
        *,
        assertion_id: str | None = None,
        name_id: str = "user@example.com",
        attributes: dict[str, list[str]] | None = None,
        audience: str | None = "urn:example:sp",
        not_before: datetime | None = None,
        not_on_or_after: datetime | None = None,
        session_index: str | None = "_session1",
        issuer: str | None = None,
        sign: bool = True,
        sign_assertion: bool = True,
    ) -> bytes:
        """构造一个 SAML Response（内含一条断言），默认对断言签名。"""
        now = datetime.now(timezone.utc)
        assertion_id = assertion_id or f"_{uuid.uuid4().hex}"
        issuer = issuer if issuer is not None else self.entity_id
        not_before = not_before if not_before is not None else now - timedelta(minutes=1)
        not_on_or_after = (
            not_on_or_after if not_on_or_after is not None else now + timedelta(minutes=5)
        )

        nsmap = {"saml": SAML_NS, "samlp": SAMLP_NS}
        response = etree.Element(f"{{{SAMLP_NS}}}Response", nsmap=nsmap)
        response.set("ID", f"_{uuid.uuid4().hex}")
        response.set("Version", "2.0")
        response.set("IssueInstant", _fmt(now))

        assertion = etree.SubElement(response, f"{{{SAML_NS}}}Assertion")
        assertion.set("ID", assertion_id)
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", _fmt(now))

        issuer_el = etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer")
        issuer_el.text = issuer

        subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
        name_id_el = etree.SubElement(subject, f"{{{SAML_NS}}}NameID")
        name_id_el.text = name_id

        conditions = etree.SubElement(assertion, f"{{{SAML_NS}}}Conditions")
        conditions.set("NotBefore", _fmt(not_before))
        conditions.set("NotOnOrAfter", _fmt(not_on_or_after))
        if audience is not None:
            restriction = etree.SubElement(conditions, f"{{{SAML_NS}}}AudienceRestriction")
            aud_el = etree.SubElement(restriction, f"{{{SAML_NS}}}Audience")
            aud_el.text = audience

        if attributes:
            stmt = etree.SubElement(assertion, f"{{{SAML_NS}}}AttributeStatement")
            for name, values in attributes.items():
                attr = etree.SubElement(stmt, f"{{{SAML_NS}}}Attribute")
                attr.set("Name", name)
                for value in values:
                    val_el = etree.SubElement(attr, f"{{{SAML_NS}}}AttributeValue")
                    val_el.text = value

        authn = etree.SubElement(assertion, f"{{{SAML_NS}}}AuthnStatement")
        authn.set("AuthnInstant", _fmt(now))
        if session_index is not None:
            authn.set("SessionIndex", session_index)

        if sign:
            signer = XMLSigner(
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm=EXCLUSIVE_C14N,
            )
            target = assertion if sign_assertion else response
            signed = signer.sign(
                target,
                key=self.key_pem,
                cert=self.cert_pem,
                reference_uri=f"#{target.get('ID')}",
                id_attribute="ID",
            )
            if signed is not target and target is assertion:
                # sign 可能返回新树，需要替换 response 中的 assertion
                response.remove(assertion)
                response.append(signed)

        return etree.tostring(response, xml_declaration=True, encoding="utf-8")

    def build_logout_request(
        self,
        *,
        name_id: str = "user@example.com",
        session_index: str | None = "_session1",
        issuer: str | None = None,
        sign: bool = True,
    ) -> bytes:
        """构造一个 IdP 发起的 LogoutRequest，默认签名。"""
        now = datetime.now(timezone.utc)
        nsmap = {"saml": SAML_NS, "samlp": SAMLP_NS}
        request = etree.Element(f"{{{SAMLP_NS}}}LogoutRequest", nsmap=nsmap)
        request.set("ID", f"_{uuid.uuid4().hex}")
        request.set("Version", "2.0")
        request.set("IssueInstant", _fmt(now))

        issuer_el = etree.SubElement(request, f"{{{SAML_NS}}}Issuer")
        issuer_el.text = issuer if issuer is not None else self.entity_id

        name_id_el = etree.SubElement(request, f"{{{SAML_NS}}}NameID")
        name_id_el.text = name_id

        if session_index is not None:
            idx_el = etree.SubElement(request, f"{{{SAMLP_NS}}}SessionIndex")
            idx_el.text = session_index

        if sign:
            signer = XMLSigner(
                signature_algorithm="rsa-sha256",
                digest_algorithm="sha256",
                c14n_algorithm=EXCLUSIVE_C14N,
            )
            request = signer.sign(
                request,
                key=self.key_pem,
                cert=self.cert_pem,
                reference_uri=f"#{request.get('ID')}",
                id_attribute="ID",
            )

        return etree.tostring(request, xml_declaration=True, encoding="utf-8")
