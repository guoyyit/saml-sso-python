"""SAML SSO 错误类型。

所有校验失败原因都映射为可区分的异常类型，便于上层返回明确的错误码。
"""

from __future__ import annotations


class SAMLError(Exception):
    """所有 SAML 相关错误的基类。"""

    code: str = "saml_error"

    def __init__(self, message: str = "", *, detail: dict | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail or {}


class UnknownIdPError(SAMLError):
    """请求中引用的身份提供方未配置。"""

    code = "unknown_idp"


class MalformedAssertionError(SAMLError):
    """断言 XML 无法解析或结构不合法。"""

    code = "malformed_assertion"


class UnsignedAssertionError(SAMLError):
    """断言缺少数字签名。"""

    code = "unsigned_assertion"


class SignatureValidationError(SAMLError):
    """断言签名无效或被篡改。"""

    code = "invalid_signature"


class UntrustedKeyError(SAMLError):
    """断言使用了不在信任列表中的签名密钥。"""

    code = "untrusted_key"


class NotYetValidError(SAMLError):
    """断言尚未生效（NotBefore 超出容忍窗口）。"""

    code = "assertion_not_yet_valid"


class ExpiredAssertionError(SAMLError):
    """断言已过期（NotOnOrAfter 超出容忍窗口）。"""

    code = "assertion_expired"


class AudienceRestrictionError(SAMLError):
    """断言受众限制不包含本服务。"""

    code = "audience_restriction"


class ReplayDetectedError(SAMLError):
    """同一断言标识被重复消费。"""

    code = "replay_detected"


class MissingAttributeError(SAMLError):
    """断言缺少建立本地会话所必需的属性。"""

    code = "missing_attribute"


class SessionInvalidError(SAMLError):
    """会话不存在、已过期或已被登出失效。"""

    code = "session_invalid"
