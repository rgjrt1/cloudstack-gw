"""
Microsoft Graph API client — resolves Entra ID group GUIDs to display names.

Uses the **OAuth 2.0 client credentials flow** with the same client_id and
client_secret that are already configured for OIDC.  No extra credentials are
needed, but the Entra ID app registration must have the following
**application permission** granted (requires admin consent):

    GroupMember.Read.All   (preferred — least-privilege)
    or Directory.Read.All  (broader, not recommended)

Grant consent in Entra ID:
  App registrations → <your app> → API permissions
    → Add a permission → Microsoft Graph → Application permissions
    → GroupMember.Read.All → Grant admin consent

The app token is cached in-process and automatically renewed before expiry.

Usage example (called from OidcProvider.handle_callback):
    client = GraphClient(tenant_id, client_id, client_secret)
    display_names = await client.resolve_group_display_names(oid)
    # e.g. ['CS_ROOT_ADMIN', 'CS_ROOT_READONLY', 'All Staff']
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Regex to detect a bare UUID (Entra ID Object ID)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def looks_like_guids(groups: list[str]) -> bool:
    """Return True if every non-empty entry looks like a UUID (Entra GUID)."""
    if not groups:
        return False
    return all(_UUID_RE.match(g) for g in groups if g)


def extract_tenant_id(issuer_url: str) -> str | None:
    """Parse the Entra ID tenant UUID from an issuer URL.

    Handles both common formats::

        https://login.microsoftonline.com/{tenant_id}/v2.0
        https://sts.windows.net/{tenant_id}/
    """
    m = re.search(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", issuer_url, re.IGNORECASE)
    return m.group(1) if m else None


class GraphClientError(Exception):
    """Raised when a Graph API call fails in a non-recoverable way."""


class GraphClient:
    """Minimal Microsoft Graph client using app-only (client credentials) auth.

    Thread-safe for use inside a single asyncio event loop — the token is
    stored as instance state and refreshed lazily.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        verify_ssl: bool = True,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._verify_ssl = verify_ssl
        self._token: str | None = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def _get_token(self) -> str:
        """Return a valid app-only Graph access token, refreshing if needed."""
        if self._token and time.monotonic() < self._token_expiry - 60:
            return self._token

        url = _TOKEN_URL.format(tenant_id=self._tenant_id)
        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=15) as client:
            r = await client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            if not r.is_success:
                raise GraphClientError(
                    f"Graph token request failed ({r.status_code}): {r.text[:300]}"
                )
            data: dict[str, Any] = r.json()

        if "access_token" not in data:
            raise GraphClientError(
                f"Graph token response missing access_token: {data.get('error_description', data)}"
            )

        self._token = data["access_token"]
        self._token_expiry = time.monotonic() + int(data.get("expires_in", 3600))
        logger.debug(
            "Acquired Graph API app-token (expires in %ss)", data.get("expires_in")
        )
        return self._token

    # ------------------------------------------------------------------
    # Group membership lookup
    # ------------------------------------------------------------------

    async def get_user_groups(self, oid: str) -> list[dict[str, str]]:
        """Return ``[{id, displayName}, ...]`` for all transitive group memberships.

        Uses ``GET /users/{oid}/transitiveMemberOf/microsoft.graph.group``
        and pages through ``@odata.nextLink`` responses automatically.

        Requires ``GroupMember.Read.All`` application permission.
        """
        token = await self._get_token()
        url: str | None = (
            f"{_GRAPH_BASE}/users/{oid}/transitiveMemberOf/microsoft.graph.group"
        )
        params: dict[str, str] = {"$select": "id,displayName", "$top": "999"}
        headers = {"Authorization": f"Bearer {token}"}

        groups: list[dict[str, str]] = []
        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=15) as client:
            while url:
                r = await client.get(url, params=params, headers=headers)
                if not r.is_success:
                    logger.error(
                        "Graph /transitiveMemberOf failed for oid=%s: %s — %s",
                        oid,
                        r.status_code,
                        r.text[:300],
                    )
                    return []
                data = r.json()
                groups.extend(data.get("value", []))
                # Follow pagination — nextLink already includes params
                url = data.get("@odata.nextLink")
                params = {}

        logger.debug("Graph returned %d groups for oid=%s", len(groups), oid)
        return groups

    async def resolve_group_display_names(self, oid: str) -> list[str]:
        """Return displayName strings for every transitive group the user belongs to.

        Silently drops entries without a displayName (should not occur in practice).
        Returns an empty list on API errors so the caller can fall back to token groups.
        """
        try:
            groups = await self.get_user_groups(oid)
        except GraphClientError as exc:
            logger.error("Graph group lookup error for oid=%s: %s", oid, exc)
            return []

        names = [g["displayName"] for g in groups if g.get("displayName")]
        logger.info(
            "Graph resolved %d group display names for oid=%s: %r",
            len(names),
            oid,
            names,
        )
        return names
