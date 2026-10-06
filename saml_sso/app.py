"""FastAPI 应用与 SAML 端点。

端点：
- GET  /login/{idp_id}        生成 AuthnRequest 并重定向到 IdP
- POST /saml/acs/{idp_id}     接收 IdP POST 绑定的断言，建立本地会话
- POST /saml/slo/{idp_id}     接收 IdP 的 LogoutRequest，执行单点登出
- POST /logout                本地登出
- GET  /me                    查看当前会话（验证会话有效性）
"""

from __future__ import annotations

from fastapi import FastAPI

from .config import Settings


def create_app(settings: Settings) -> FastAPI:
    """根据配置创建 FastAPI 应用。"""
    app = FastAPI(title="saml-sso-python")
    # TODO: 注册 SAML 端点
    return app
