"""
Tests for the FastAPI middleware — OIDC session cookies, cache, proxying.

The middleware now has two authentication modes:
  - oidc_provider=None  : fallback header mode (X-Forwarded-User etc.) for dev/legacy
  - oidc_provider set   : full OIDC cookie flow (Authorization Code + session cookie)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
import respx
import httpx
from fastapi.testclient import TestClient

from src.cache import MemoryCache
from src.cloudstack_client import CloudStackClient
from src.middleware import build_app, _parse_identity_headers
from src.models import (
    AppConfig,
    CacheEntry,
    OidcIdentity,
    ProvisionedUser,
)
from src.oidc_auth import OidcProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config() -> AppConfig:
    return AppConfig.model_validate({
        "cloudstack": {
            "api_url": "https://cs.example.com/client/api",
            "api_key": "ak",
            "secret_key": "sk",
        },
        "server": {"upstream_url": "https://cs.example.com"},
    })


def _make_provisioned() -> ProvisionedUser:
    return ProvisionedUser(
        sub="alice",
        email="alice@example.com",
        user_slug="alice",
        account_name="oidc-admin",
        domain_id="dom-1",
        account_id="acc-1",
        user_id="usr-1",
        api_key="test-api-key",
        secret_key="test-secret-key",
        is_admin=True,
    )


def _make_app(config: AppConfig | None = None, oidc_provider: OidcProvider | None = None):
    if config is None:
        config = _make_config()
    cs = MagicMock(spec=CloudStackClient)
    cs._ensure_client = AsyncMock()
    cs.close = AsyncMock()
    cs.probe = AsyncMock(return_value=True)
    cache = MemoryCache(ttl=60)
    return build_app(config, cs, cache, oidc_provider), cs, cache


def _make_oidc_provider(
    identity: OidcIdentity | None = None,
    callback_result: tuple[OidcIdentity, str] | None = None,
) -> MagicMock:
    """Return a mock OidcProvider.

    parse_session_cookie → always returns `identity` (simulate valid/invalid cookie).
    handle_callback → returns `callback_result` (identity, original_path).
    """
    provider = MagicMock(spec=OidcProvider)
    provider.parse_session_cookie = MagicMock(return_value=identity)
    provider.probe = AsyncMock(return_value=True)
    provider.create_session_cookie = MagicMock(return_value="signed-cookie-value")
    provider.authorization_redirect_url = AsyncMock(
        return_value="https://idp.example.com/auth?response_type=code&client_id=test"
    )
    if callback_result is not None:
        provider.handle_callback = AsyncMock(return_value=callback_result)
    else:
        from src.oidc_auth import OidcAuthError
        provider.handle_callback = AsyncMock(side_effect=OidcAuthError("no callback"))
    return provider


# ---------------------------------------------------------------------------
# Header-based identity parsing (fallback / legacy mode)
# ---------------------------------------------------------------------------

class TestParseIdentityHeaders:
    def _fake_request(self, headers: dict):
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
        from starlette.requests import Request
        return Request(scope)

    def test_parses_all_headers(self):
        config = _make_config()
        req = self._fake_request({
            "X-Forwarded-User": "alice",
            "X-Forwarded-Email": "alice@example.com",
            "X-Forwarded-Groups": "developers,cloud-admins",
            "X-Forwarded-Preferred-Username": "alice.smith",
        })
        identity = _parse_identity_headers(req, config)
        assert identity is not None
        assert identity.sub == "alice"
        assert identity.email == "alice@example.com"
        assert set(identity.groups) == {"developers", "cloud-admins"}
        assert identity.preferred_username == "alice.smith"

    def test_returns_none_when_user_header_missing(self):
        config = _make_config()
        req = self._fake_request({"X-Forwarded-Email": "alice@example.com"})
        assert _parse_identity_headers(req, config) is None

    def test_handles_empty_groups_header(self):
        config = _make_config()
        req = self._fake_request({
            "X-Forwarded-User": "alice",
            "X-Forwarded-Groups": "",
        })
        identity = _parse_identity_headers(req, config)
        assert identity is not None
        assert identity.groups == []

    def test_groups_whitespace_stripped(self):
        config = _make_config()
        req = self._fake_request({
            "X-Forwarded-User": "alice",
            "X-Forwarded-Groups": " developers , cloud-admins ",
        })
        identity = _parse_identity_headers(req, config)
        assert "developers" in identity.groups
        assert "cloud-admins" in identity.groups


# ---------------------------------------------------------------------------
# Middleware endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHealthEndpoints:
    async def test_healthz(self):
        app, _, _ = _make_app()
        with TestClient(app) as client:
            resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    async def test_readyz_when_cs_up(self):
        app, cs, _ = _make_app()
        cs.probe = AsyncMock(return_value=True)
        with TestClient(app) as client:
            resp = client.get("/readyz")
        assert resp.status_code == 200

    async def test_readyz_when_cs_down(self):
        app, cs, _ = _make_app()
        cs.probe = AsyncMock(return_value=False)
        with TestClient(app) as client:
            resp = client.get("/readyz")
        assert resp.status_code == 503


@pytest.mark.asyncio
class TestProxyEndpoint:
    async def test_returns_401_without_identity_headers(self):
        app, _, _ = _make_app()
        with TestClient(app) as client:
            resp = client.get("/client/api?command=listVirtualMachines")
        assert resp.status_code == 401

    @respx.mock
    async def test_cache_hit_skips_provisioner(self):
        config = _make_config()
        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cache = MemoryCache(ttl=60)

        provisioned = _make_provisioned()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["developers"])
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )

        # Pre-populate cache
        await cache.set(identity.cache_key(), entry)

        # Mock upstream
        respx.get("https://cs.example.com/client/api").mock(
            return_value=httpx.Response(200, json={"listdomainsresponse": {"domain": []}})
        )

        app = build_app(config, cs, cache)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/client/api?command=listDomains",
                headers={
                    "X-Forwarded-User": "alice",
                    "X-Forwarded-Email": "alice@example.com",
                    "X-Forwarded-Groups": "developers",
                },
            )

        assert resp.status_code == 200
        # Provisioner methods should NOT have been called — all from cache
        cs.list_roles.assert_not_called()

    @respx.mock
    async def test_proxy_does_not_inject_cs_auth_headers(self):
        """Proxy must NOT inject X-CloudStack-ApiKey / X-CloudStack-SecretKey.

        CloudStack ignores these headers completely; authentication happens
        via the CS session cookies (JSESSIONID + sessionkey) that are
        established during the OIDC callback.
        """
        config = _make_config()
        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cache = MemoryCache(ttl=60)

        provisioned = _make_provisioned()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["developers"])
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)

        captured_headers: dict = {}

        def capture(request):
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json={})

        respx.get("https://cs.example.com/client/api").mock(side_effect=capture)

        app = build_app(config, cs, cache)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get(
                "/client/api?command=listDomains",
                headers={
                    "X-Forwarded-User": "alice",
                    "X-Forwarded-Email": "alice@example.com",
                    "X-Forwarded-Groups": "developers",
                },
            )

        assert "x-cloudstack-apikey" not in captured_headers
        assert "x-cloudstack-secretkey" not in captured_headers


@pytest.mark.asyncio
class TestAdminEndpoints:
    async def test_admin_cache_clear(self):
        app, _, cache = _make_app()
        identity = OidcIdentity(sub="alice", groups=["developers"])
        entry = CacheEntry(
            identity=identity,
            provisioned=_make_provisioned(),
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)
        assert len(cache) == 1

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/admin/cache/clear")
        assert resp.status_code == 200
        assert len(cache) == 0

    async def test_admin_reconcile(self):
        app, cs, _ = _make_app()
        cs.list_domains = AsyncMock(return_value=[{"id": "dom-1", "name": "oidc"}])
        cs.list_accounts = AsyncMock(return_value=[])

        with TestClient(app) as client:
            resp = client.post("/admin/reconcile")
        assert resp.status_code == 200
        assert resp.json()["status"] == "complete"


# ---------------------------------------------------------------------------
# OIDC cookie-based authentication (oidc_provider mode)
# ---------------------------------------------------------------------------

def _make_oidc_config_dict() -> dict:
    """Minimal OidcProviderConfig dict for AppConfig.model_validate."""
    return {
        "issuer_url": "https://idp.example.com",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "redirect_uri": "http://localhost/auth/callback",
        "session_secret": "very-secret-key",
    }


def _make_config_with_oidc() -> AppConfig:
    return AppConfig.model_validate({
        "cloudstack": {
            "api_url": "https://cs.example.com/client/api",
            "api_key": "ak",
            "secret_key": "sk",
        },
        "server": {"upstream_url": "https://cs.example.com"},
        "oidc": _make_oidc_config_dict(),
    })


@pytest.mark.asyncio
class TestOidcCookieAuth:
    """Proxy catch-all with OidcProvider wired in."""

    async def test_redirects_to_idp_when_no_cookie(self):
        """No session cookie → 200 HTML hash-save micro-page that JS-redirects to /auth/login.
        Returns 200 (not 302) so the browser can execute the inline script that saves
        window.location.hash to the _gw_hash cookie before the redirect fires."""
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)  # no valid session
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/some/page", headers={"Accept": "text/html"})

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "/auth/login" in resp.text
        assert "_gw_hash" in resp.text

    @respx.mock
    async def test_serves_request_with_valid_cookie(self):
        """Valid session cookie → proxied to CloudStack."""
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_READONLY"])
        provider = _make_oidc_provider(identity=identity)

        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cache = MemoryCache(ttl=60)

        provisioned = _make_provisioned()
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)

        respx.get("https://cs.example.com/client/api").mock(
            return_value=httpx.Response(200, json={"listdomainsresponse": {}})
        )

        app = build_app(config, cs, cache, provider)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/client/api?command=listDomains",
                cookies={"oidcgw_session": "valid-cookie"},
            )

        assert resp.status_code == 200
        provider.parse_session_cookie.assert_called_once_with("valid-cookie")

    async def test_readyz_checks_oidc_provider(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        provider.probe = AsyncMock(return_value=False)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/readyz")

        assert resp.status_code == 503
        assert "OIDC" in resp.json()["reason"]


@pytest.mark.asyncio
class TestAuthCallbackEndpoint:
    async def test_callback_success_sets_cookie_and_redirects(self):
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_ADMIN"])
        provider = _make_oidc_provider(
            identity=identity,
            callback_result=(identity, "/dashboard"),
        )

        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cache = MemoryCache(ttl=60)

        # Pre-fill cache so provisioner is not called
        provisioned = _make_provisioned()
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)

        app = build_app(config, cs, cache, provider)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/callback?code=abc&state=xyz")

        # Callback now serves a bridge page (200 HTML) instead of a bare redirect.
        # The page's JS populates localStorage then redirects client-side.
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "/dashboard" in resp.text   # redirect target embedded in page
        assert "oidcgw_session" in resp.cookies

    async def test_callback_missing_params_returns_400(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/callback")

        assert resp.status_code == 400

    async def test_callback_idp_error_returns_401(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/callback?error=access_denied&error_description=User+denied+access")

        assert resp.status_code == 401
        assert "OIDC error" in resp.json()["error"]

    async def test_callback_oidc_auth_error_restarts_flow(self):
        """On OidcAuthError (e.g. expired state after server restart) the
        callback should silently restart the OIDC flow (302 → IdP) rather
        than returning a raw JSON 401 to the user."""
        from src.oidc_auth import OidcAuthError
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        provider.handle_callback = AsyncMock(side_effect=OidcAuthError("state mismatch"))
        # authorization_redirect_url is called to restart the flow
        provider.authorization_redirect_url = AsyncMock(
            return_value="https://idp.example.com/auth?state=new"
        )
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/callback?code=bad&state=bad")

        assert resp.status_code == 302
        assert "idp.example.com" in resp.headers["location"]

    async def test_callback_sets_cs_session_cookies(self):
        """After a successful OIDC callback, JSESSIONID/sessionkey/userid cookies
        from the CS loginUser call must be set in the redirect response so the
        Vue SPA can authenticate without a login prompt."""
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_ADMIN"])
        provider = _make_oidc_provider(
            identity=identity,
            callback_result=(identity, "/"),
        )

        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cs.update_user = AsyncMock(return_value={"id": "usr-1"})
        cs.login_user = AsyncMock(
            return_value=(
                {"sessionkey": "sk-abc123", "userid": "uid-xyz", "account": "oidc-admin"},
                {"JSESSIONID": "jsid-test"},
            )
        )
        cache = MemoryCache(ttl=60)

        # Pre-fill cache so provisioner.provision() is skipped
        provisioned = _make_provisioned()
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)

        app = build_app(config, cs, cache, provider)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/callback?code=abc&state=xyz")

        # Callback serves a bridge page (200 HTML); cookies still set on this response.
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        # update_user and login_user must have been called
        cs.update_user.assert_awaited_once_with("usr-1", password=cs.update_user.call_args.kwargs["password"])
        cs.login_user.assert_awaited_once()

        # All three CS session cookies must be in the response
        assert resp.cookies.get("JSESSIONID") == "jsid-test"
        assert resp.cookies.get("sessionkey") == "sk-abc123"
        assert resp.cookies.get("userid") == "uid-xyz"

    async def test_callback_cs_login_failure_still_redirects(self):
        """If establishing a CS session fails, the callback must still succeed
        and set the OIDC gateway cookie — the user just gets a login prompt."""
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_ADMIN"])
        provider = _make_oidc_provider(
            identity=identity,
            callback_result=(identity, "/"),
        )

        cs = MagicMock(spec=CloudStackClient)
        cs._ensure_client = AsyncMock()
        cs.close = AsyncMock()
        cs.probe = AsyncMock(return_value=True)
        cs.update_user = AsyncMock(side_effect=Exception("CS unavailable"))
        cache = MemoryCache(ttl=60)

        provisioned = _make_provisioned()
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        await cache.set(identity.cache_key(), entry)

        app = build_app(config, cs, cache, provider)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/callback?code=abc&state=xyz")

        # Bridge page must still be served even when CS session setup fails.
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "oidcgw_session" in resp.cookies
        # No CS session cookies when login failed
        assert "JSESSIONID" not in resp.cookies
        assert "sessionkey" not in resp.cookies


@pytest.mark.asyncio
class TestAuthLogoutEndpoint:
    async def test_logout_clears_cookie_and_redirects(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get(
                "/auth/logout",
                cookies={"oidcgw_session": "some-cookie"},
            )

        assert resp.status_code == 302
        assert resp.headers["location"] == "/auth/login"
        # Cookie should be deleted (max-age=0 or expires in the past)
        set_cookie = resp.headers.get("set-cookie", "")
        assert "oidcgw_session" in set_cookie

    async def test_logout_no_cookie_still_redirects(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider()
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/logout")

        assert resp.status_code == 302
        assert resp.headers["location"] == "/auth/login"


@pytest.mark.asyncio
class TestAuthLoginStartEndpoints:
    """Tests for /auth/login (branded login page) and /auth/start (OIDC flow)."""

    async def test_auth_login_returns_html_page(self):
        """GET /auth/login → 200 HTML with a sign-in button."""
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/login")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Sign in with Microsoft" in resp.text
        assert "/auth/start" in resp.text

    async def test_auth_login_with_next_param_embeds_it(self):
        """?next= is forwarded to /auth/start href."""
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/login?next=/client/")

        assert resp.status_code == 200
        assert "/auth/start?next=" in resp.text

    async def test_auth_login_redirects_already_authenticated_user(self):
        """Valid session → redirect straight to /client/ without showing page."""
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=[])
        provider = _make_oidc_provider(identity=identity)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/login", cookies={"oidcgw_session": "valid"})

        assert resp.status_code == 302
        assert resp.headers["location"] == "/client/"

    async def test_auth_start_redirects_to_idp(self):
        """GET /auth/start → 302 to IdP auth URL."""
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/start")

        assert resp.status_code == 302
        assert "idp.example.com" in resp.headers["location"]

    async def test_auth_start_passes_next_to_idp(self):
        """?next= param is passed to authorization_redirect_url as the return path."""
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", follow_redirects=False
        ) as client:
            resp = await client.get("/auth/start?next=/client/")

        assert resp.status_code == 302
        provider.authorization_redirect_url.assert_called_once_with("/client/")

    async def test_auth_start_returns_501_when_oidc_not_configured(self):
        """No OIDC provider → 501."""
        config = _make_config()  # no OIDC config
        app, _, _ = _make_app(config, oidc_provider=None)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/start")

        assert resp.status_code == 501


@pytest.mark.asyncio
class TestAuthMeEndpoint:
    async def test_me_returns_identity_when_authenticated(self):
        config = _make_config_with_oidc()
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_READONLY"])
        provider = _make_oidc_provider(identity=identity)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/auth/me", cookies={"oidcgw_session": "valid-cookie"}
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["sub"] == "alice"
        assert data["email"] == "alice@example.com"
        assert "CS_ROOT_READONLY" in data["groups"]

    async def test_me_returns_401_when_not_authenticated(self):
        config = _make_config_with_oidc()
        provider = _make_oidc_provider(identity=None)
        app, _, _ = _make_app(config, provider)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/auth/me")

        assert resp.status_code == 401
        assert resp.json()["authenticated"] is False
