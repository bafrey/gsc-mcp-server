"""Offline tests for app.py: OAuth flow, bearer gate, MCP over HTTP. No Google calls."""

import base64
import contextlib
import hashlib
import os
import secrets
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("MCP_AUTH_SECRET", "test-secret")
os.environ.setdefault("PUBLIC_BASE_URL", "https://gsc.example.test")

from starlette.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402

CALLBACK = "https://claude.ai/api/mcp/auth_callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


# FastMCP's session manager can only run once per process, so every test shares
# one started client (entering a TestClient runs the app's lifespan).
_CLIENT = TestClient(app_module.create_app(), follow_redirects=False).__enter__()


def client():
    return contextlib.nullcontext(_CLIENT)


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def sign_in(c, password="test-secret"):
    reg = c.post("/register", json={"redirect_uris": [CALLBACK], "client_name": "Claude"})
    assert reg.status_code == 201, reg.text
    cid = reg.json()["client_id"]
    verifier, challenge = pkce()
    params = {
        "response_type": "code", "client_id": cid, "redirect_uri": CALLBACK,
        "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256",
    }
    assert c.get("/authorize", params=params).status_code == 200
    resp = c.post("/authorize", data={**params, "password": password})
    return resp, cid, verifier


def test_discovery_and_unauthenticated_mcp_is_refused():
    with client() as c:
        meta = c.get("/.well-known/oauth-authorization-server").json()
        assert meta["token_endpoint"] == "https://gsc.example.test/token"
        assert c.get("/.well-known/oauth-protected-resource").json()["authorization_servers"] == ["https://gsc.example.test"]
        r = c.post("/", json={}, headers=MCP_HEADERS)
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]
        assert c.get("/health").json() == {"ok": True}


def test_full_oauth_flow_then_mcp_tools_list():
    with client() as c:
        resp, cid, verifier = sign_in(c)
        assert resp.status_code == 302
        q = parse_qs(urlparse(resp.headers["location"]).query)
        assert q["state"] == ["xyz"]
        code = q["code"][0]
        tok = c.post("/token", data={"grant_type": "authorization_code", "code": code,
                                     "redirect_uri": CALLBACK, "code_verifier": verifier, "client_id": cid})
        assert tok.status_code == 200, tok.text
        pair = tok.json()
        # Code replay is refused.
        again = c.post("/token", data={"grant_type": "authorization_code", "code": code,
                                       "redirect_uri": CALLBACK, "code_verifier": verifier})
        assert again.status_code == 400
        # Refresh works.
        ref = c.post("/token", data={"grant_type": "refresh_token", "refresh_token": pair["refresh_token"]})
        assert ref.status_code == 200
        access = ref.json()["access_token"]

        h = {**MCP_HEADERS, "Authorization": f"Bearer {access}"}
        init = c.post("/", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        assert init.status_code == 200, init.text
        tools = c.post("/", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in tools.json()["result"]["tools"]}
        assert "list_properties" in names
        assert "reauthenticate" not in names


def test_wrong_password_bad_pkce_and_foreign_redirect():
    with client() as c:
        resp, _, _ = sign_in(c, password="nope")
        assert resp.status_code == 401
        resp, cid, _ = sign_in(c)
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        bad = c.post("/token", data={"grant_type": "authorization_code", "code": code, "code_verifier": "wrong"})
        assert bad.status_code == 400
        assert c.post("/register", json={"redirect_uris": ["https://evil.example/cb"]}).status_code == 400


def test_raw_secret_bearer_and_access_token_type_is_enforced():
    with client() as c:
        h = {**MCP_HEADERS, "Authorization": "Bearer test-secret"}
        r = c.post("/", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 200, r.text
        refresh = app_module._sign("refresh", 60, cid="x")
        r = c.post("/", headers={**MCP_HEADERS, "Authorization": f"Bearer {refresh}"}, json={})
        assert r.status_code == 401


def test_google_refresh_failure_does_not_stick(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REFRESH_TOKEN", "rt")
    app_module._creds = None
    calls = {"n": 0}

    def fake_refresh(self, request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        self.token = "access"
        self.expiry = None  # google-auth treats no expiry as valid

    monkeypatch.setattr(app_module.Credentials, "refresh", fake_refresh)
    try:
        app_module._google_credentials()
        raise AssertionError("first call should fail")
    except RuntimeError:
        pass
    assert app_module._google_credentials().token == "access"
    app_module._creds = None
