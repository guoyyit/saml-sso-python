"""SAML 核心服务：串联验签、条件校验、重放防护、属性映射与会话建立。"""

from __future__ import annotations

from datetime import datetime

from saml_sso.config import Settings
from saml_sso.session import Session


class SamlService:
    """对外提供 ACS 消费与单点登出能力。"""

    def __init__(self, settings: Settings) -> None:
        raise NotImplementedError

    def consume_response(self, saml_response_b64: str, now: datetime) -> Session:
        """处理 POST 绑定送达的 SAMLResponse，成功则建立本地会话。"""
        raise NotImplementedError

    def handle_logout_request(self, saml_request_b64: str, now: datetime) -> int:
        """处理 IdP 发起的单点登出请求，返回失效会话数。"""
        raise NotImplementedError

    def logout(self, session_id: str) -> bool:
        """本地登出：立即使会话失效。"""
        raise NotImplementedError

    def get_session(self, session_id: str, now: datetime) -> Session | None:
        """查询有效会话。"""
        raise NotImplementedError
