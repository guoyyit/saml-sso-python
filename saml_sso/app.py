"""FastAPI 路由：ACS、SLO、会话查询与受保护示例资源。"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Form, Request, Response
from fastapi.responses import JSONResponse

from saml_sso.config import Settings
from saml_sso.errors import (
    AssertionExpiredError,
    AuthenticationError,
    AssertionNotYetValidError,
    AudienceMismatchError,
    LogoutError,
    MissingAttributeError,
    ReplayDetectedError,
    SamlError,
    SignatureError,
    UnknownIdpError,
)
from saml_sso.service import SamlService
from saml_sso.session import Session

SESSION_COOKIE = "saml_session"

#: 错误类型 -> HTTP 状态码；响应体中的 error 字段携带可区分的机器可读原因
_ERROR_STATUS = {
    AuthenticationError: 401,
    SignatureError: 403,
    UnknownIdpError: 403,
    AssertionExpiredError: 403,
    AssertionNotYetValidError: 403,
    AudienceMismatchError: 403,
    ReplayDetectedError: 409,
    MissingAttributeError: 422,
    LogoutError: 400,
}


def _status_for(exc: SamlError) -> int:
    for error_type, status in _ERROR_STATUS.items():
        if isinstance(exc, error_type):
            return status
    return 400


def create_app(settings: Settings, service: SamlService | None = None) -> FastAPI:
    """构建应用。service 可注入以便测试。"""
    app = FastAPI(title="SAML SSO Service")
    svc = service or SamlService(settings)
    app.state.saml_service = svc

    @app.exception_handler(SamlError)
    async def saml_error_handler(_request: Request, exc: SamlError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for(exc),
            content={"error": exc.code, "detail": str(exc)},
        )

    def current_session(request: Request) -> Session:
        """会话依赖：每次请求都从存储实时校验，登出后立即失效。"""
        session_id = request.cookies.get(SESSION_COOKIE)
        if not session_id:
            raise AuthenticationError("no session cookie")
        session = svc.get_session(session_id, datetime.now(timezone.utc))
        if session is None:
            raise AuthenticationError("session invalid or expired")
        return session

    @app.post("/saml/acs")
    async def acs(response: Response, SAMLResponse: str = Form(...)) -> dict:
        """接收 IdP 通过 POST 绑定发送的断言，验签通过后建立本地会话。"""
        session = svc.consume_response(
            SAMLResponse, datetime.now(timezone.utc)
        )
        response.set_cookie(
            SESSION_COOKIE,
            session.session_id,
            httponly=True,
            samesite="lax",
        )
        return {
            "session_id": session.session_id,
            "idp": session.idp_entity_id,
            "name_id": session.name_id,
            "attributes": session.attributes,
        }

    @app.post("/saml/slo")
    async def slo(SAMLRequest: str = Form(...)) -> dict:
        """接收 IdP 单点登出请求，使对应本地会话立即失效。"""
        count = svc.handle_logout_request(
            SAMLRequest, datetime.now(timezone.utc)
        )
        return {"invalidated_sessions": count}

    @app.get("/me")
    async def me(session: Session = Depends(current_session)) -> dict:
        return {
            "session_id": session.session_id,
            "idp": session.idp_entity_id,
            "name_id": session.name_id,
            "attributes": session.attributes,
        }

    @app.post("/logout")
    async def logout(
        request: Request, response: Response
    ) -> dict:
        session_id = request.cookies.get(SESSION_COOKIE)
        destroyed = svc.logout(session_id) if session_id else False
        response.delete_cookie(SESSION_COOKIE)
        return {"logged_out": destroyed}

    @app.post("/protected/write")
    async def protected_write(
        payload: dict, session: Session = Depends(current_session)
    ) -> dict:
        """示例受保护写操作：只有持有效会话才能写入。"""
        return {"written_by": session.name_id, "payload": payload}

    return app
