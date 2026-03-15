"""
Pydantic models for configuration, identity, provisioning results, and cache entries.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Slugify helper
# ---------------------------------------------------------------------------

def slugify(value: str, max_length: int = 60) -> str:
    """Convert an arbitrary string to a CloudStack-safe identifier.

    Lowercases, replaces runs of non-alphanumeric characters with a single
    hyphen, strips leading/trailing hyphens, and truncates.
    """
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value[:max_length]


# ---------------------------------------------------------------------------
# Configuration models
# ---------------------------------------------------------------------------

class CloudStackConfig(BaseModel):
    api_url: str
    api_key: str
    secret_key: str
    verify_ssl: bool = True
    domain_path: str = ""  # unused — accounts are placed in ROOT domain
    timeout: int = 30


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    upstream_url: str
    log_level: str = "INFO"


class CacheConfig(BaseModel):
    type: str = "memory"  # "memory" or "redis"
    redis_url: str = "redis://localhost:6379/0"
    ttl: int = 300


class OidcProviderConfig(BaseModel):
    """OIDC provider settings — the middleware is its own relying party."""
    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    groups_claim: str = "groups"
    # When True, the middleware calls Microsoft Graph API at login time to resolve
    # Entra ID group Object ID GUIDs to their displayNames.  Uses the same
    # client_id/client_secret as the OIDC flow (client credentials grant).
    # Requires the app to have GroupMember.Read.All application permission
    # with admin consent in the Entra ID app registration.
    graph_group_lookup: bool = False
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    session_secret: str
    session_cookie_name: str = "oidcgw_session"
    session_ttl: int = 3600
    verify_ssl: bool = True

    @field_validator("scopes")
    @classmethod
    def ensure_openid_scope(cls, v: list[str]) -> list[str]:
        if "openid" not in v:
            v = ["openid"] + v
        return v


class ReconciliationConfig(BaseModel):
    enabled: bool = True
    interval: int = 3600
    disable_orphaned_users: bool = True
    cleanup_empty_accounts: bool = False


class UiPluginConfig(BaseModel):
    """A custom page injected into the CloudStack SPA sidebar."""
    model_config = ConfigDict(extra="ignore")

    id: str
    """Unique slug — also used as the hash: #/gw-<id> when hash is not set."""
    label: str
    """Sidebar label text."""
    icon: str = "🔌"
    """Emoji or character shown in the sidebar nav item."""
    hash: str = ""
    """Deep-link hash, e.g. #/gw-access-map. Defaults to #/gw-<id>."""
    iframe_src: str = ""
    """Render the plugin as an iframe pointing at this URL."""
    html: str = ""
    """Render the plugin as raw HTML/JS (injected into the overlay div)."""
    api_src: str = ""
    """Fetch JSON from this URL and render as a searchable table."""
    roles: list[str] = Field(default_factory=list)
    """Role types that can see this plugin. Empty = visible to all.
    Valid values: ROOT_ADMIN | ADMIN | OPERATIONS | READONLY | USER"""


class UiConfig(BaseModel):
    """Optional per-role UI customisation: command filtering, CSS hiding, plugin pages."""
    model_config = ConfigDict(extra="ignore")

    hide_commands: dict[str, list[str]] = Field(default_factory=dict)
    """Map of role-type → CS API commands to strip from listApis responses.
    Keys: ROOT_ADMIN | ADMIN | OPERATIONS | READONLY | USER
    The SPA will not render action buttons for commands missing from listApis."""

    hide_selectors: dict[str, list[str]] = Field(default_factory=dict)
    """Map of role-type → CSS selectors to inject as display:none for that role.
    Useful for UI chrome not tied to a single API command."""

    plugins: list[UiPluginConfig] = Field(default_factory=list)
    """Custom pages injected into the SPA sidebar."""


class AppConfig(BaseModel):
    """Top-level application configuration.

    Extra keys in the config file (e.g. legacy ``group_mappings``) are
    silently ignored so that old config files keep working during the
    migration period.
    """
    model_config = ConfigDict(extra="ignore")

    cloudstack: CloudStackConfig
    server: ServerConfig
    cache: CacheConfig = Field(default_factory=CacheConfig)
    oidc: OidcProviderConfig | None = None
    reconciliation: ReconciliationConfig = Field(default_factory=ReconciliationConfig)
    ui: UiConfig = Field(default_factory=UiConfig)


# ---------------------------------------------------------------------------
# Identity / request models
# ---------------------------------------------------------------------------

class OidcIdentity(BaseModel):
    """Parsed identity extracted from OIDC session cookie or forwarded headers."""
    sub: str
    email: str = ""
    preferred_username: str = ""
    given_name: str = ""    # OIDC given_name claim (first name)
    family_name: str = ""   # OIDC family_name claim (last name)
    groups: list[str] = Field(default_factory=list)
    raw_claims: dict[str, Any] = Field(default_factory=dict)

    @property
    def sam_account_name(self) -> str:
        """Short username for CS account / user naming.

        Uses the local part of preferred_username (UPN before the @), falling
        back to the email local part, then slugify(sub).
        """
        raw = self.preferred_username or self.email or ""
        if "@" in raw:
            raw = raw.split("@")[0]
        return raw or slugify(self.sub)

    @property
    def user_slug(self) -> str:
        return slugify(self.sub)

    def groups_hash(self) -> str:
        """SHA-256 of sorted groups list, first 16 hex chars."""
        import hashlib
        key = ",".join(sorted(self.groups))
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def cache_key(self) -> str:
        return f"{self.sub}:{self.groups_hash()}"


# ---------------------------------------------------------------------------
# Provisioning result models
# ---------------------------------------------------------------------------

class ProvisionedUser(BaseModel):
    """Describes the result of a provisioning run for one identity."""
    sub: str
    email: str
    user_slug: str

    # Per-domain placement: domain_id → {account_id, user_id, account_name}
    domain_accounts: dict[str, dict[str, str]] = Field(default_factory=dict)

    # Primary account details (used for API key injection)
    account_name: str = ""
    domain_id: str = ""
    account_id: str = ""
    user_id: str = ""
    api_key: str = ""
    secret_key: str = ""

    # True when the user's highest-privilege CS account is the admin-tier one
    is_admin: bool = False
    cs_password: str = ""

    # project_key (uppercase) → project_id  (across all domains)
    project_ids: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------

class CacheEntry(BaseModel):
    identity: OidcIdentity
    provisioned: ProvisionedUser
    groups_hash: str

    # Extra metadata stored by the reconciler
    extra: dict[str, Any] = Field(default_factory=dict)
