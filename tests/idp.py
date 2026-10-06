"""测试用本地身份提供方模拟器：自签名证书 + 可定制的断言签发。"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

SAML_RESPONSE_TEMPLATE = """<samlp:Response xmlns:samlp="{samlp}" xmlns:saml="{saml}"
    ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}"
    Destination="{acs_url}" InResponseTo="">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {assertion_xml}
</samlp:Response>"""

ASSERTION_TEMPLATE = """<saml:Assertion xmlns:saml="{saml}" ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{session_index}">
    <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    {attributes_xml}
  </saml:AttributeStatement>
</saml:Assertion>"""

ATTRIBUTE_TEMPLATE = """<saml:Attribute Name="{name}">{values}</saml:Attribute>"""
ATTRIBUTE_VALUE_TEMPLATE = """<saml:AttributeValue>{value}</saml:AttributeValue>"""


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_self_signed_cert(common_name: str = "idp.test"):
    """生成 RSA 密钥对与自签名证书，返回 (key_pem, cert_pem)。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
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


@dataclass
class FakeIdP:
    """一个可签发签名断言的本地身份提供方。请用 FakeIdP.create() 构造。"""

    entity_id: str
    key_pem: str
    cert_pem: str

    @classmethod
    def create(cls, entity_id: str = "https://idp.test/metadata") -> "FakeIdP":
        key_pem, cert_pem = generate_self_signed_cert(entity_id)
        return cls(entity_id=entity_id, key_pem=key_pem, cert_pem=cert_pem)

    def build_assertion_xml(
        self,
        *,
        name_id: str = "user@example.com",
        audience: str = "https://sp.test/metadata",
        acs_url: str = "https://sp.test/saml/acs",
        attributes: dict[str, list[str]] | None = None,
        not_before: datetime | None = None,
        not_on_or_after: datetime | None = None,
        assertion_id: str | None = None,
        session_index: str = "sess-1",
    ) -> str:
        now = datetime.now(timezone.utc)
        not_before = not_before or now - timedelta(minutes=1)
        not_on_or_after = not_on_or_after or now + timedelta(minutes=5)
        attributes = attributes if attributes is not None else {
            "uid": ["u-1001"],
            "email": ["user@example.com"],
            "displayName": ["Test User"],
        }
        attributes_xml = "".join(
            ATTRIBUTE_TEMPLATE.format(
                name=name,
                values="".join(
                    ATTRIBUTE_VALUE_TEMPLATE.format(value=v) for v in values
                ),
            )
            for name, values in attributes.items()
        )
        return ASSERTION_TEMPLATE.format(
            saml=NS_SAML,
            assertion_id=assertion_id or f"_a{uuid.uuid4().hex}",
            issue_instant=_utc(now),
            issuer=self.entity_id,
            name_id=name_id,
            session_index=session_index,
            not_before=_utc(not_before),
            not_on_or_after=_utc(not_on_or_after),
            audience=audience,
            acs_url=acs_url,
            attributes_xml=attributes_xml,
        )

    def build_response_xml(
        self,
        *,
        sign: bool = True,
        sign_assertion_only: bool = False,
        **assertion_kwargs,
    ) -> str:
        """构造 SAML Response；默认对 Response 整体签名。"""
        now = datetime.now(timezone.utc)
        assertion_xml = self.build_assertion_xml(**assertion_kwargs)
        response_xml = SAML_RESPONSE_TEMPLATE.format(
            samlp=NS_SAMLP,
            saml=NS_SAML,
            response_id=f"_r{uuid.uuid4().hex}",
            issue_instant=_utc(now),
            acs_url=assertion_kwargs.get("acs_url", "https://sp.test/saml/acs"),
            issuer=self.entity_id,
            assertion_xml=assertion_xml,
        )
        if not sign:
            return response_xml

        root = etree.fromstring(response_xml.encode())
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )
        if sign_assertion_only:
            assertion_el = root.find(f"{{{NS_SAML}}}Assertion")
            signed_assertion = signer.sign(
                assertion_el,
                key=self.key_pem,
                cert=self.cert_pem,
                reference_uri=f"#{assertion_el.get('ID')}",
            )
            root.replace(assertion_el, signed_assertion)
        else:
            root = signer.sign(
                root,
                key=self.key_pem,
                cert=self.cert_pem,
                reference_uri=f"#{root.get('ID')}",
            )
        return etree.tostring(root).decode()

    def build_response_b64(self, **kwargs) -> str:
        """构造并 base64 编码，模拟 POST 绑定表单字段。"""
        return base64.b64encode(self.build_response_xml(**kwargs).encode()).decode()


LOGOUT_REQUEST_TEMPLATE = """<samlp:LogoutRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}"
    ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
  {session_index_xml}
</samlp:LogoutRequest>"""


def build_logout_request_b64(
    idp: "FakeIdP",
    *,
    name_id: str,
    session_index: str | None = None,
    sign: bool = True,
) -> str:
    """构造（可选签名的）LogoutRequest 并 base64 编码。"""
    now = datetime.now(timezone.utc)
    session_index_xml = (
        f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>"
        if session_index
        else ""
    )
    xml = LOGOUT_REQUEST_TEMPLATE.format(
        samlp=NS_SAMLP,
        saml=NS_SAML,
        request_id=f"_lr{uuid.uuid4().hex}",
        issue_instant=_utc(now),
        issuer=idp.entity_id,
        name_id=name_id,
        session_index_xml=session_index_xml,
    )
    if sign:
        root = etree.fromstring(xml.encode())
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )
        root = signer.sign(
            root, key=idp.key_pem, cert=idp.cert_pem,
            reference_uri=f"#{root.get('ID')}",
        )
        xml = etree.tostring(root).decode()
    return base64.b64encode(xml.encode()).decode()
