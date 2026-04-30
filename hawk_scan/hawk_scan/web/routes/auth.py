"""Entra ID OAuth2 auth routes."""

import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import JSONResponse, RedirectResponse

from hawk_scan.web.config import get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

_SESSION_COOKIE = "session_id"
_FLOW_COOKIE = "flow_id"


def _redis_client():
    """Return a Redis client, or None if Redis is unavailable."""
    try:
        import redis as redis_lib
        settings = get_settings()
        r = redis_lib.Redis.from_url(settings.redis_url)
        r.ping()
        return r
    except Exception:
        return None


def _session_key(session_id: str) -> str:
    return f"session:{session_id}"


def _get_session(session_id: str) -> dict | None:
    """Retrieve session data from Redis, or None if not found / Redis down."""
    r = _redis_client()
    if r is None:
        return None
    try:
        raw = r.get(_session_key(session_id))
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def _create_session(user_email: str) -> str | None:
    """Store a new session in Redis and return the session ID, or None on error."""
    r = _redis_client()
    if r is None:
        return None
    settings = get_settings()
    session_id = str(uuid.uuid4())
    data = json.dumps({"email": user_email})
    ttl = int(timedelta(hours=settings.session_ttl_hours).total_seconds())
    try:
        r.setex(_session_key(session_id), ttl, data)
        return session_id
    except Exception:
        return None


def _delete_session(session_id: str) -> None:
    """Delete a session from Redis (best effort)."""
    r = _redis_client()
    if r is None:
        return
    try:
        r.delete(_session_key(session_id))
    except Exception:
        pass


@router.get("/login")
def login(request: Request):
    settings = get_settings()

    # Dev mode: no Azure client ID configured — skip straight to dev callback.
    if not settings.azure_client_id:
        return RedirectResponse(url="/api/auth/callback?dev=1", status_code=302)

    # Production: build MSAL auth flow and redirect to Microsoft's authorize endpoint.
    import msal

    authority = f"https://login.microsoftonline.com/{settings.azure_tenant_id}"
    scopes = ["openid", "profile", "email"]
    redirect_uri = f"{settings.base_url}/api/auth/callback"

    app_auth = msal.ConfidentialClientApplication(
        settings.azure_client_id,
        authority=authority,
        client_credential=settings.azure_client_secret,
    )
    flow = app_auth.initiate_auth_code_flow(scopes=scopes, redirect_uri=redirect_uri)

    # Store flow keyed by a UUID so the callback can retrieve it.
    if not hasattr(request.app.state, "auth_flows") or request.app.state.auth_flows is None:
        request.app.state.auth_flows = {}

    flow_id = str(uuid.uuid4())
    request.app.state.auth_flows[flow_id] = flow

    response = RedirectResponse(url=flow["auth_uri"], status_code=302)
    response.set_cookie(_FLOW_COOKIE, flow_id, httponly=True, samesite="lax")
    return response


@router.get("/callback")
def callback(
    request: Request,
    dev: int = 0,
    flow_id: str | None = Cookie(default=None, alias=_FLOW_COOKIE),
):
    settings = get_settings()

    # Dev mode: create a dummy session.
    if dev and not settings.azure_client_id:
        session_id = _create_session("dev@localhost")
        if session_id is None:
            # Redis down in testing — still return 200-ish with a placeholder cookie
            # so the dev workflow doesn't hard-fail.
            session_id = "dev-no-redis"
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(_SESSION_COOKIE, session_id, httponly=True, samesite="lax")
        return response

    # Production: exchange auth code for tokens.
    import msal

    if not hasattr(request.app.state, "auth_flows") or request.app.state.auth_flows is None:
        return JSONResponse({"detail": "No auth flow found"}, status_code=400)

    flow = request.app.state.auth_flows.pop(flow_id or "", None)
    if flow is None:
        return JSONResponse({"detail": "Invalid or expired auth flow"}, status_code=400)

    authority = f"https://login.microsoftonline.com/{settings.azure_tenant_id}"
    scopes = ["openid", "profile", "email"]
    redirect_uri = f"{settings.base_url}/api/auth/callback"

    app_auth = msal.ConfidentialClientApplication(
        settings.azure_client_id,
        authority=authority,
        client_credential=settings.azure_client_secret,
    )

    # MSAL expects the full query string dict.
    auth_response = dict(request.query_params)
    result = app_auth.acquire_token_by_auth_code_flow(flow, auth_response, scopes=scopes, redirect_uri=redirect_uri)

    if "error" in result:
        return JSONResponse({"detail": result.get("error_description", result["error"])}, status_code=400)

    # Extract email from ID token claims.
    claims = result.get("id_token_claims", {})
    email = claims.get("preferred_username") or claims.get("email") or claims.get("upn", "unknown@unknown")

    session_id = _create_session(email)
    if session_id is None:
        return JSONResponse({"detail": "Session store unavailable"}, status_code=503)

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(_SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    return response


@router.get("/me")
def me(session_id: str | None = Cookie(default=None, alias=_SESSION_COOKIE)):
    if not session_id:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    session_data = _get_session(session_id)
    if session_data is None:
        return JSONResponse({"detail": "Session expired or not found"}, status_code=401)

    return JSONResponse({"email": session_data.get("email")})


@router.post("/logout")
def logout(session_id: str | None = Cookie(default=None, alias=_SESSION_COOKIE)):
    if session_id:
        _delete_session(session_id)

    response = JSONResponse({"detail": "Logged out"})
    response.delete_cookie(_SESSION_COOKIE)
    return response
