"""SAML 错误类型层级：不同拒绝原因必须可区分。"""


class SamlError(Exception):
    """所有 SAML 处理错误的基类。"""

    code: str = "saml_error"


class SignatureError(SamlError):
    """签名校验相关错误的基类。"""

    code: str = "signature_error"


class SignatureMissingError(SignatureError):
    """断言未携带签名。"""

    code: str = "signature_missing"


class SignatureInvalidError(SignatureError):
    """签名存在但校验失败（含被篡改）。"""

    code: str = "signature_invalid"


class UntrustedKeyError(SignatureError):
    """签名使用了不在信任列表中的密钥。"""

    code: str = "untrusted_key"


class AssertionExpiredError(SamlError):
    """断言已过 NotOnOrAfter（含时钟偏移窗口）。"""

    code: str = "assertion_expired"


class AssertionNotYetValidError(SamlError):
    """断言尚未到 NotBefore（含时钟偏移窗口）。"""

    code: str = "assertion_not_yet_valid"


class AudienceMismatchError(SamlError):
    """受众限制不包含本服务。"""

    code: str = "audience_mismatch"


class ReplayDetectedError(SamlError):
    """同一断言标识被重复消费。"""

    code: str = "replay_detected"


class MissingAttributeError(SamlError):
    """断言缺少建立会话所必需的属性。"""

    code: str = "missing_attribute"


class MetadataError(SamlError):
    """身份提供方元数据解析或信任配置错误。"""

    code: str = "metadata_error"


class UnknownIdpError(SamlError):
    """断言签发方不在已配置的身份提供方中。"""

    code: str = "unknown_idp"


class LogoutError(SamlError):
    """单点登出处理错误。"""

    code: str = "logout_error"


class AuthenticationError(SamlError):
    """请求未携带有效本地会话。"""

    code: str = "not_authenticated"
