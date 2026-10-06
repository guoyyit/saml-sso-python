"""基于 SAML 2.0 的联邦身份接入。"""

from saml_sso.errors import (
    AssertionExpiredError,
    AssertionNotYetValidError,
    AudienceMismatchError,
    LogoutError,
    MetadataError,
    MissingAttributeError,
    ReplayDetectedError,
    SamlError,
    SignatureError,
    SignatureInvalidError,
    SignatureMissingError,
    UnknownIdpError,
    UntrustedKeyError,
)

__all__ = [
    "AssertionExpiredError",
    "AssertionNotYetValidError",
    "AudienceMismatchError",
    "LogoutError",
    "MetadataError",
    "MissingAttributeError",
    "ReplayDetectedError",
    "SamlError",
    "SignatureError",
    "SignatureInvalidError",
    "SignatureMissingError",
    "UnknownIdpError",
    "UntrustedKeyError",
]
