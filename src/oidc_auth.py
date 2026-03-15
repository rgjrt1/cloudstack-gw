"""
OIDC Authentication Provider.

Implements the OpenID Connect Authorization Code flow so the middleware
acts as its own relying party — no oauth2-proxy needed.

Flow:
  1. Unauthenticated request → redirect browser to IdP authorization endpoint.
  2. IdP redirects back to /auth/callback with ?code=&state=
  3. Middleware exchanges code → tokens, validates the ID token.
  4. Identity (sub, email, groups) is extracted from the ID token claims.
  5. A signed, time-limited session cookie is set on the browser.
  6. Subsequent requests read identity from the cookie.

Session cookies are signed with itsdangerous (HMAC-SHA1) using the
configured session_secret.  They are not encrypted — don't put secrets in them.

The OIDC discovery document and JWKS are fetched once and cached for the
life of the process.  Call ``invalidate_cache()`` to force re-fetch
(e.g. after a key rotation).

In-memory state store (_PENDING_STATES) is process-local.  For multi-replica
deployments, replace it with a shared Redis store.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
import time
import urllib.parse
from typing import Any

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .graph_client import GraphClient, extract_tenant_id, looks_like_guids
from .models import OidcIdentity, OidcProviderConfig

logger = logging.getLogger(__name__)

# state_token → (original_path, nonce, issued_at)
# Process-local; fine for single-instance deployments.
_PENDING_STATES: dict[str, tuple[str, str, float]] = {}

# Max age for a pending auth state before it's considered expired (seconds)
_STATE_TTL = 600


class OidcAuthError(Exception):
    """Raised when OIDC authentication fails."""


class OidcProvider:
    """Handles OIDC authorization code flow and session cookie management."""

    def __init__(self, config: OidcProviderConfig) -> None:
        self._config = config
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._graph_client: GraphClient | None = None
        if config.graph_group_lookup:
            tenant_id = extract_tenant_id(config.issuer_url)
            if tenant_id:
                self._graph_client = GraphClient(
                    tenant_id=tenant_id,
                    client_id=config.client_id,
                    client_secret=config.client_secret,
                    verify_ssl=config.verify_ssl,
                )
                logger.info(
                    "Graph group lookup enabled — tenant=%s client=%s",
                    tenant_id,
                    config.client_id,
                )
            else:
                logger.warning(
                    "graph_group_lookup=true but could not extract tenant_id from "
                    "issuer_url=%r — Graph lookup disabled",
                    config.issuer_url,
                )
        self._serializer = URLSafeTimedSerializer(config.session_secret)

    # ------------------------------------------------------------------
    # Cache invalidation
    # ------------------------------------------------------------------

    def invalidate_cache(self) -> None:
        self._discovery = None
        self._jwks = None

    # ------------------------------------------------------------------
    # OIDC discovery
    # ------------------------------------------------------------------

    async def discover(self) -> dict[str, Any]:
        """Fetch and cache the OIDC discovery document."""
        if self._discovery is None:
            url = f"{self._config.issuer_url.rstrip('/')}/.well-known/openid-configuration"
            async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=15) as client:
                r = await client.get(url)
                r.raise_for_status()
                self._discovery = r.json()
            logger.info("OIDC discovery loaded from %s", url)
        return self._discovery

    async def _jwks_data(self) -> dict[str, Any]:
        if self._jwks is None:
            discovery = await self.discover()
            async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=15) as client:
                r = await client.get(discovery["jwks_uri"])
                r.raise_for_status()
                self._jwks = r.json()
        return self._jwks

    async def probe(self) -> bool:
        """Return True if the OIDC discovery endpoint is reachable."""
        try:
            await self.discover()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Authorization redirect
    # ------------------------------------------------------------------

    async def authorization_redirect_url(self, original_path: str) -> str:
        """Build the IdP authorization URL and stash state for CSRF validation."""
        discovery = await self.discover()
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        _PENDING_STATES[state] = (original_path, nonce, time.monotonic())

        # Prune expired states
        cutoff = time.monotonic() - _STATE_TTL
        expired = [k for k, (_, _, ts) in _PENDING_STATES.items() if ts < cutoff]
        for k in expired:
            _PENDING_STATES.pop(k, None)

        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
        }
        auth_endpoint = discovery["authorization_endpoint"]
        return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

    # ------------------------------------------------------------------
    # Callback: code exchange
    # ------------------------------------------------------------------

    async def handle_callback(self, code: str, state: str) -> tuple[OidcIdentity, str]:
        """Exchange authorization code for tokens and return (identity, original_path)."""
        entry = _PENDING_STATES.pop(state, None)
        if entry is None:
            raise OidcAuthError("Invalid or expired state — possible CSRF attempt or session timeout")
        original_path, nonce, issued_at = entry
        if time.monotonic() - issued_at > _STATE_TTL:
            raise OidcAuthError("Auth state expired — please try again")

        discovery = await self.discover()

        # Token exchange
        async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=15) as client:
            r = await client.post(
                discovery["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._config.redirect_uri,
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                },
                headers={"Accept": "application/json"},
            )
            if not r.is_success:
                raise OidcAuthError(f"Token exchange failed ({r.status_code}): {r.text[:300]}")
            tokens = r.json()

        if "error" in tokens:
            raise OidcAuthError(
                f"Token error '{tokens['error']}': {tokens.get('error_description', '')}"
            )

        id_token = tokens.get("id_token", "")
        if not id_token:
            raise OidcAuthError("IdP returned no id_token in token response")

        claims = await self._validate_id_token(id_token, nonce, discovery)

        # Extract groups — may be a list, a comma-string, or absent
        raw_groups = claims.get(self._config.groups_claim, [])
        if isinstance(raw_groups, str):
            raw_groups = [g.strip() for g in raw_groups.split(",") if g.strip()]

        # Entra ID groups overage: when a user exceeds the token group limit,
        # Entra omits the 'groups' claim and sets '_claim_names' instead.
        overage = (
            not raw_groups
            and "_claim_names" in claims
            and self._config.groups_claim in claims.get("_claim_names", {})
        )
        if overage:
            logger.warning(
                "Entra ID groups overage detected for sub=%s — token group list truncated. "
                "Graph lookup will be used if enabled.",
                claims.get("sub", "?")
            )

        # Microsoft Graph group resolution ----------------------------------------
        # When graph_group_lookup=true, resolve GUIDs (or fill in overage groups)
        # by calling /users/{oid}/transitiveMemberOf via client credentials.
        oid = claims.get("oid") or claims.get("sub", "")
        should_use_graph = self._graph_client and (
            looks_like_guids(list(raw_groups)) or overage
        )
        if should_use_graph and oid:
            try:
                graph_names = await self._graph_client.resolve_group_display_names(oid)  # type: ignore[union-attr]
                if graph_names:
                    logger.info(
                        "Graph resolved %d groups for oid=%s (was token groups=%r)",
                        len(graph_names), oid, list(raw_groups),
                    )
                    raw_groups = graph_names
                else:
                    logger.warning(
                        "Graph returned no groups for oid=%s — keeping token groups %r",
                        oid, list(raw_groups),
                    )
            except Exception as exc:
                logger.warning(
                    "Graph group lookup failed for oid=%s: %s — keeping token groups %r",
                    oid, exc, list(raw_groups),
                )
        elif self._graph_client and not oid:
            logger.warning("graph_group_lookup enabled but no 'oid' claim in token — skipping")

        # Entra ID may not include 'email' for all account types;
        # fall back to 'upn' (user principal name) which is always present.
        email = claims.get("email") or claims.get("upn") or claims.get("preferred_username", "")

        identity = OidcIdentity(
            sub=claims.get("sub", ""),
            email=email,
            preferred_username=claims.get("preferred_username", ""),
            given_name=claims.get("given_name", ""),
            family_name=claims.get("family_name", ""),
            groups=list(raw_groups),
            raw_claims=claims,
        )

        if not identity.sub:
            raise OidcAuthError("ID token is missing the required 'sub' claim")

        logger.info(
            "OIDC login: sub=%s email=%s groups=%s",
            identity.sub, identity.email, identity.groups,
        )
        return identity, original_path

    # ------------------------------------------------------------------
    # ID token validation
    # ------------------------------------------------------------------

    async def _validate_id_token(
        self,
        id_token: str,
        nonce: str,
        discovery: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate ID token signature and standard claims via authlib + JWKS."""
        try:
            from authlib.jose import JsonWebKeySet
            from authlib.jose import jwt as jose_jwt
            from authlib.jose.errors import JoseError
        except ImportError:
            logger.warning(
                "authlib not installed — skipping ID token signature verification. "
                "Install authlib for production use."
            )
            return self._decode_unsafe(id_token)

        try:
            jwks_data = await self._jwks_data()
            key_set = JsonWebKeySet.import_key_set(jwks_data)
            claims_options = {
                "iss": {"value": discovery.get("issuer", self._config.issuer_url)},
                "aud": {"value": self._config.client_id},
            }
            claims = jose_jwt.decode(id_token, key_set, claims_options=claims_options)
            claims.validate(leeway=60)

            if nonce and claims.get("nonce") and claims["nonce"] != nonce:
                raise OidcAuthError("Nonce mismatch in ID token")

            return dict(claims)
        except JoseError as exc:
            raise OidcAuthError(f"ID token validation failed: {exc}") from exc

    @staticmethod
    def _decode_unsafe(id_token: str) -> dict[str, Any]:
        """Decode JWT payload without signature verification (fallback only)."""
        parts = id_token.split(".")
        if len(parts) != 3:
            raise OidcAuthError("Malformed ID token (expected 3 parts)")
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception as exc:
            raise OidcAuthError(f"Failed to decode ID token payload: {exc}") from exc

    # ------------------------------------------------------------------
    # Session cookie
    # ------------------------------------------------------------------

    def create_session_cookie(self, identity: OidcIdentity) -> str:
        """Return a signed, serialized session cookie value.

        raw_claims is intentionally excluded — it can be several KB (Entra ID
        tokens are large) which bloats the Cookie header and causes CloudStack's
        Jetty server to return 431.  raw_claims is only used transiently at
        callback time to populate the /auth/denied debug page.
        """
        return self._serializer.dumps({
            "sub": identity.sub,
            "email": identity.email,
            "preferred_username": identity.preferred_username,
            "given_name": identity.given_name,
            "family_name": identity.family_name,
            "groups": identity.groups,
        })

    def parse_session_cookie(self, cookie_value: str) -> OidcIdentity | None:
        """Verify and parse the session cookie. Returns None if invalid or expired."""
        try:
            data = self._serializer.loads(cookie_value, max_age=self._config.session_ttl)
            return OidcIdentity(
                sub=data["sub"],
                email=data.get("email", ""),
                preferred_username=data.get("preferred_username", ""),
                given_name=data.get("given_name", ""),
                family_name=data.get("family_name", ""),
                groups=data.get("groups", []),
                # raw_claims is not persisted in the cookie; default to empty.
            )
        except (SignatureExpired, BadSignature, KeyError):
            return None
