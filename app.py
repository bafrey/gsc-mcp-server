"""Hosted entrypoint for the Session Media GSC MCP server (Railway).

Wraps the unmodified upstream ``gsc_server.py`` (AminForou/mcp-gsc) with:

1. Google credentials from env vars, held in memory. Upstream reads token.json
   and DELETES it when a refresh fails, after which the server can't recover
   without a restart. That is what broke the old deployment on 2026-10-22. Here
   a failed refresh fails that one call and the next call simply retries.
2. OAuth for Claude connectors (discovery + dynamic client registration +
   authorization code with PKCE + refresh). Tokens are HMAC-signed and
   stateless, so a restart or redeploy doesn't sign anyone out. The sign-in
   page asks for MCP_AUTH_SECRET; changing that secret revokes every token.
3. Streamable HTTP MCP served at ``/`` (the URL the connector already uses).

Env:
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN  (webmasters scope)
  MCP_AUTH_SECRET     sign-in password; also accepted directly as a Bearer token
  PUBLIC_BASE_URL     optional; defaults to https://$RAILWAY_PUBLIC_DOMAIN
  OAUTH_ALLOWED_REDIRECT_PREFIXES  optional, comma-separated
  PORT                set by Railway
"""

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import threading
import time
from urllib.parse import urlencode

import uvicorn
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

import gsc_server

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("gsc-mcp")

ACCESS_TTL = 60 * 60
REFRESH_TTL = 90 * 24 * 60 * 60
CODE_TTL = 5 * 60
DEFAULT_REDIRECT_PREFIXES = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost:",
    "http://127.0.0.1:",
)
PUBLIC_PATHS = ("/health", "/authorize", "/token", "/register")


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


AUTH_SECRET = _env("MCP_AUTH_SECRET")
if not AUTH_SECRET:
    raise SystemExit("MCP_AUTH_SECRET must be set; refusing to serve GSC data unauthenticated.")
SIGNING_KEY = hashlib.sha256(b"gsc-mcp-oauth:" + AUTH_SECRET.encode()).digest()

REDIRECT_PREFIXES = tuple(
    p.strip() for p in _env("OAUTH_ALLOWED_REDIRECT_PREFIXES").split(",") if p.strip()
) or DEFAULT_REDIRECT_PREFIXES


# --- Google credentials -----------------------------------------------------

_creds_lock = threading.Lock()
_creds = None


def _google_credentials() -> Credentials:
    global _creds
    with _creds_lock:
        if _creds is None:
            missing = [n for n in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN") if not _env(n)]
            if missing:
                raise RuntimeError(f"Missing Railway variables: {', '.join(missing)}")
            _creds = Credentials(
                token=None,
                refresh_token=_env("GOOGLE_REFRESH_TOKEN"),
                client_id=_env("GOOGLE_CLIENT_ID"),
                client_secret=_env("GOOGLE_CLIENT_SECRET"),
                token_uri="https://oauth2.googleapis.com/token",
                scopes=gsc_server.SCOPES,
            )
        if not _creds.valid:
            _creds.refresh(GoogleRequest())
        return _creds


def get_gsc_service():
    return build("searchconsole", "v1", credentials=_google_credentials(), cache_discovery=False)


# Upstream tools look this up as a module global on every call.
gsc_server.get_gsc_service = get_gsc_service
# Opens a desktop browser login; meaningless on a server.
gsc_server.mcp._tool_manager._tools.pop("reauthenticate", None)


def _probe_google() -> None:
    try:
        _google_credentials()
        log.info("Google credentials OK (token refresh succeeded)")
    except Exception as e:  # noqa: BLE001 - startup diagnostic only
        log.error("Google credentials FAILED: %s", e)


# --- Signed tokens ------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(typ: str, ttl: int, **claims) -> str:
    payload = _b64(json.dumps({"typ": typ, "exp": int(time.time()) + ttl, **claims}).encode())
    sig = _b64(hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def _verify(token: str, typ: str):
    try:
        payload, sig = token.split(".")
        expected = _b64(hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_unb64(payload))
    except Exception:  # noqa: BLE001 - any malformed token is just invalid
        return None
    if claims.get("typ") != typ or claims.get("exp", 0) < time.time():
        return None
    return claims


_used_codes: dict = {}


def _consume_code(code: str) -> bool:
    now = time.time()
    for c, exp in list(_used_codes.items()):
        if exp < now:
            del _used_codes[c]
    if code in _used_codes:
        return False
    _used_codes[code] = now + CODE_TTL
    return True


def _token_pair(client_id: str) -> dict:
    return {
        "access_token": _sign("access", ACCESS_TTL, cid=client_id),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": _sign("refresh", REFRESH_TTL, cid=client_id),
    }


# --- OAuth endpoints ----------------------------------------------------------

def _base_url(request: Request) -> str:
    if _env("PUBLIC_BASE_URL"):
        return _env("PUBLIC_BASE_URL").rstrip("/")
    if _env("RAILWAY_PUBLIC_DOMAIN"):
        return f"https://{_env('RAILWAY_PUBLIC_DOMAIN')}"
    return str(request.base_url).rstrip("/")


def _redirect_allowed(uri: str) -> bool:
    return any(uri.startswith(p) for p in REDIRECT_PREFIXES)


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


async def protected_resource(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse({"resource": base, "authorization_servers": [base], "bearer_methods_supported": ["header"]})


async def authorization_server(request: Request) -> JSONResponse:
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    })


async def register(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    redirect_uris = body.get("redirect_uris") or []
    bad = [u for u in redirect_uris if not _redirect_allowed(u)]
    if not redirect_uris or bad:
        return _oauth_error("invalid_redirect_uri", f"Redirect URI not allowed: {bad or 'none given'}")
    return JSONResponse({
        "client_id": f"client-{secrets.token_urlsafe(12)}",
        "client_id_issued_at": int(time.time()),
        "client_name": body.get("client_name", ""),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }, status_code=201)


_FORM_FIELDS = ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope")


def _login_page(params: dict, error: str = "") -> HTMLResponse:
    hidden = "".join(
        f'<input type="hidden" name="{f}" value="{html.escape(params.get(f, ""))}">' for f in _FORM_FIELDS
    )
    err = f'<p style="color:#b00020">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GSC MCP sign-in</title></head>
<body style="font-family:system-ui,sans-serif;max-width:420px;margin:64px auto;padding:0 16px">
<h2>Google Search Console MCP</h2><p>Enter the access password to connect.</p>{err}
<form method="post" action="/authorize">{hidden}
<input type="password" name="password" autofocus required style="width:100%;padding:8px;font-size:16px">
<button type="submit" style="margin-top:12px;padding:8px 16px;font-size:16px">Connect</button>
</form></body></html>""", status_code=401 if error else 200)


def _check_authorize_params(params: dict):
    if not params.get("client_id"):
        return "Missing client_id."
    if not _redirect_allowed(params.get("redirect_uri", "")):
        return "Redirect URI not allowed."
    if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
        return "PKCE with S256 is required."
    return None


async def authorize(request: Request) -> Response:
    if request.method == "GET":
        params = dict(request.query_params)
        if params.get("response_type") != "code":
            return HTMLResponse("Unsupported response_type.", status_code=400)
        problem = _check_authorize_params(params)
        if problem:
            return HTMLResponse(html.escape(problem), status_code=400)
        return _login_page(params)

    params = {k: str(v) for k, v in (await request.form()).items()}
    problem = _check_authorize_params(params)
    if problem:
        return HTMLResponse(html.escape(problem), status_code=400)
    if not hmac.compare_digest(params.get("password", "").encode(), AUTH_SECRET.encode()):
        log.warning("Sign-in refused: wrong password")
        return _login_page(params, "Wrong password.")
    code = _sign("code", CODE_TTL, cid=params["client_id"], ru=params["redirect_uri"], cc=params["code_challenge"])
    query = {"code": code}
    if params.get("state"):
        query["state"] = params["state"]
    sep = "&" if "?" in params["redirect_uri"] else "?"
    return RedirectResponse(f"{params['redirect_uri']}{sep}{urlencode(query)}", status_code=302)


async def token(request: Request) -> JSONResponse:
    form = {k: str(v) for k, v in (await request.form()).items()}
    grant = form.get("grant_type")
    if grant == "authorization_code":
        claims = _verify(form.get("code", ""), "code")
        if not claims or not _consume_code(form["code"]):
            return _oauth_error("invalid_grant", "Authorization code is invalid, expired or already used.")
        if form.get("redirect_uri") and form["redirect_uri"] != claims["ru"]:
            return _oauth_error("invalid_grant", "redirect_uri mismatch.")
        verifier = form.get("code_verifier", "")
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        if not verifier or not hmac.compare_digest(challenge, claims["cc"]):
            return _oauth_error("invalid_grant", "PKCE verification failed.")
        return JSONResponse(_token_pair(claims["cid"]), headers={"Cache-Control": "no-store"})
    if grant == "refresh_token":
        claims = _verify(form.get("refresh_token", ""), "refresh")
        if not claims:
            return _oauth_error("invalid_grant", "Refresh token is invalid or expired.")
        return JSONResponse(_token_pair(claims["cid"]), headers={"Cache-Control": "no-store"})
    return _oauth_error("unsupported_grant_type", f"Unsupported grant_type: {grant}")


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


# --- Bearer auth in front of MCP -------------------------------------------------

class BearerAuth:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in PUBLIC_PATHS or path.startswith("/.well-known/"):
            return await self.app(scope, receive, send)
        auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
        bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if bearer and (hmac.compare_digest(bearer.encode(), AUTH_SECRET.encode()) or _verify(bearer, "access")):
            return await self.app(scope, receive, send)
        base = _base_url(Request(scope))
        await JSONResponse(
            {"error": "invalid_token", "error_description": "Missing or invalid bearer token."},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'},
        )(scope, receive, send)


def create_app():
    settings = gsc_server.mcp.settings
    settings.streamable_http_path = "/"
    # Stateless JSON mode: no server-side MCP sessions to lose on restart.
    settings.stateless_http = True
    settings.json_response = True
    # The SDK's default Host allowlist is localhost-only (421s behind Railway).
    settings.transport_security.enable_dns_rebinding_protection = False

    app = gsc_server.mcp.streamable_http_app()
    app.router.routes[0:0] = [
        Route("/health", health, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authorization_server, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/token", token, methods=["POST"]),
    ]
    app.add_middleware(BearerAuth)
    return app


if __name__ == "__main__":
    threading.Thread(target=_probe_google, daemon=True).start()
    uvicorn.run(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), proxy_headers=True, forwarded_allow_ips="*")
