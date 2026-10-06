"""FastAPI 路由：ACS、SLO、会话查询与受保护示例资源。"""

from __future__ import annotations

from fastapi import FastAPI

from saml_sso.config import Settings
from saml_sso.service import SamlService


def create_app(settings: Settings, service: SamlService | None = None) -> FastAPI:
    """构建应用。service 可注入以便测试。"""
    raise NotImplementedError
