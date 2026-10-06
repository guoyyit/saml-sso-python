"""基于 SAML 2.0 的联邦身份接入。"""

from .config import IdpConfig, Settings, load_settings
from .errors import SAMLError

__all__ = ["IdpConfig", "Settings", "SAMLError", "load_settings"]
