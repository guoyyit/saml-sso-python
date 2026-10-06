"""FastAPI 应用与 SAML 端点。

端点：
- GET  /login/{idp_id}        生成 AuthnRequest 并重定向到 IdP
- POST /saml/acs/{idp_id}     接收 IdP POST 绑定的断言，建立本地会话
- POST /saml/slo/{idp_id}     接收 IdP 的 LogoutRequest，执行单点登出
- POST /logout                本地登出
- GET  /me                    查看当前会话（每次请求都重新授权）
"""

from __future__ import annotations

import base64
import uuid
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from .assertion import validate_logout_request, validate_response
from .attributes import map_attributes
from .audit import AuditLogger
from .config import Settings
from .errors import SAMLError, SessionInvalidError
from .replay import ReplayCache
from .sessions import Session, SessionStore

SESSION_COOKIE = "saml_session"


def _b64decode_payload(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except Exception as exc:
        from .errors import MalformedAssertionError

        raise MalformedAssertionError(f"cannot base64-decode payload: {exc}") from exc


def _build_authn_redirect(settings: Settings, idp_id: str) -> str:
    """构造 HTTP-Redirect 绑定的 AuthnRequest 重定向地址。"""
    idp = settings.get_idp(idp_id)
    request_id = f"_{uuid.uuid4().hex}"
    acs_url = f"{settings.sp_acs_url.rstrip('/')}/{idp_id}"
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    authn_request = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{idp.sso_url}" AssertionConsumerServiceURL="{acs_url}">'
        f'<saml:Issuer>{settings.sp_entity_id}</saml:Issuer>'
        f"</samlp:AuthnRequest>"
    )
    compressed = zlib.compress(authn_request.encode("utf-8"))[2:-4]  # raw deflate
    encoded = base64.b64encode(compressed).decode("ascii")
    separator = "&" if "?" in idp.sso_url else "?"
    return f"{idp.sso_url}{separator}{urlencode({'SAMLRequest': encoded})}"


def create_app(settings: Settings) -> FastAPI:
    """根据配置创建 FastAPI 应用。"""
    app = FastAPI(title="saml-sso-python")
    app.state.settings = settings
    app.state.sessions = SessionStore()
    app.state.replay_cache = ReplayCache(settings.replay_db_path)
    # 汇总所有 IdP 声明的敏感属性；name_id 属于身份信息，同样脱敏
    sensitive = {"name_id"} | {
        attr for idp in settings.idps.values() for attr in idp.sensitive_attributes
    }
    app.state.audit = AuditLogger(settings.audit_log_path, sensitive_attributes=tuple(sensitive))

    @app.exception_handler(SAMLError)
    async def saml_error_handler(_request: Request, exc: SAMLError) -> JSONResponse:
        status = 401 if isinstance(exc, SessionInvalidError) else 400
        return JSONResponse(
            status_code=status,
            content={"error": exc.code, "message": exc.message, "detail": exc.detail},
        )

    def _current_session(request: Request) -> Session:
        """每次请求都重新授权：会话一旦被登出失效，后续请求立即被拒绝。"""
        session_id = request.cookies.get(SESSION_COOKIE, "")
        if not session_id:
            raise SessionInvalidError("no session cookie")
        store: SessionStore = request.app.state.sessions
        return store.get(session_id)

    @app.get("/login/{idp_id}")
    async def login(idp_id: str) -> RedirectResponse:
        return RedirectResponse(_build_authn_redirect(settings, idp_id), status_code=302)

    @app.post("/saml/acs/{idp_id}")
    async def acs(idp_id: str, request: Request, SAMLResponse: str = Form(...)) -> Response:
        idp = settings.get_idp(idp_id)
        audit: AuditLogger = request.app.state.audit

        xml_bytes = _b64decode_payload(SAMLResponse)
        data = validate_response(xml_bytes, idp, settings)

        # 重放防护：断言有效期过后记录才可清理
        expires_at = data.not_on_or_after or (datetime.now(timezone.utc) + settings.session_ttl)
        request.app.state.replay_cache.consume(data.assertion_id, expires_at)

        local_attrs = map_attributes(idp, data.attributes)
        session = request.app.state.sessions.create(
            idp_id=idp.idp_id,
            name_id=data.name_id,
            attributes=local_attrs,
            saml_session_index=data.session_index,
            ttl_seconds=settings.session_ttl.total_seconds(),
        )
        audit.log(
            "login_success",
            idp_id=idp.idp_id,
            assertion_id=data.assertion_id,
            name_id=data.name_id,
            session_id=session.session_id,
            attributes=local_attrs,
        )
        response = JSONResponse({"status": "ok", "idp": idp.idp_id, "session_id": session.session_id})
        response.set_cookie(
            SESSION_COOKIE, session.session_id, httponly=True, samesite="lax"
        )
        return response

    @app.post("/saml/slo/{idp_id}")
    async def slo(idp_id: str, request: Request, SAMLRequest: str = Form(...)) -> JSONResponse:
        idp = settings.get_idp(idp_id)
        xml_bytes = _b64decode_payload(SAMLRequest)
        logout = validate_logout_request(xml_bytes, idp)

        store: SessionStore = request.app.state.sessions
        count = store.invalidate_by_name_id(idp.idp_id, logout.name_id, logout.session_index)
        request.app.state.audit.log(
            "single_logout",
            idp_id=idp.idp_id,
            name_id=logout.name_id,
            session_index=logout.session_index,
            invalidated=count,
        )
        return JSONResponse({"status": "ok", "invalidated": count})

    @app.post("/logout")
    async def logout(request: Request) -> JSONResponse:
        session = _current_session(request)
        request.app.state.sessions.invalidate(session.session_id)
        request.app.state.audit.log(
            "logout", idp_id=session.idp_id, name_id=session.name_id,
            session_id=session.session_id,
        )
        response = JSONResponse({"status": "ok"})
        response.delete_cookie(SESSION_COOKIE)
        return response

    @app.get("/me")
    async def me(request: Request) -> JSONResponse:
        session = _current_session(request)
        return JSONResponse(
            {
                "idp": session.idp_id,
                "name_id": session.name_id,
                "attributes": session.attributes,
                "expires_at": session.expires_at.isoformat() if session.expires_at else None,
            }
        )

    return app
