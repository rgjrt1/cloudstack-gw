"""
CloudStack provisioner — per-user account placement model.

Account placement
-----------------
Each OIDC user maps to exactly ONE CloudStack account whose domain is
determined by their CS_* group memberships:

  account name   = slugify(identity.sam_account_name) — the AD sAMAccountName
  account domain = ROOT           if CS_ROOT_ADMIN (the only domain where
                                  account_type=1 is valid)
                   <domain>       the user's primary CS_<DOMAIN>_* domain
                                  (created under ROOT if it doesn't exist)
                   ROOT           fallback when no domain grants at all
  account role   = oidc-rootadmin-role  if CS_ROOT_ADMIN
                   oidc-admin-role      if any domain-level ADMIN /
                                        OPERATIONS / READONLY grant
                   oidc-user-role       project-only or no CS_* groups

Primary domain selection (non-root-admin users):
  1. Highest-privilege domain grant (ADMIN > OPERATIONS > READONLY)
  2. If tied, alphabetically first domain name
  3. If only project grants, the first project's domain
  4. Fallback: ROOT
  CS username    = account_name
  CS firstname   = identity.given_name  (from OIDC claim)
  CS lastname    = identity.family_name (from OIDC claim)
  CS email       = identity.email

The account role is updated on each login if the user's privilege level changes.
All real per-command access control is enforced by the proxy tier (permission.py).
CloudStack roles only gate whether the SPA can connect at all.
"""
from __future__ import annotations

import logging
import secrets
from typing import Any

from .cloudstack_client import CloudStackClient, CloudStackError
from .group_parser import ParsedGroups, parse_groups
from .models import AppConfig, OidcIdentity, ProvisionedUser, slugify

logger = logging.getLogger(__name__)

# CloudStack's four built-in roles — always present, never created by the gateway.
_BUILTIN_ROOT_ADMIN_ROLE  = "Root Admin"    # type=Admin,       account_type=1
_BUILTIN_DOMAIN_ADMIN_ROLE = "Domain Admin" # type=DomainAdmin, account_type=2
_BUILTIN_USER_ROLE         = "User"         # type=User,        account_type=0

_PLACEHOLDER_PW_LEN = 24


def _random_password() -> str:
    return secrets.token_urlsafe(_PLACEHOLDER_PW_LEN)


def _primary_domain_name(parsed: ParsedGroups) -> str:
    """Return the CloudStack domain name that should hold this user's account.

    Returns ``"ROOT"`` for root admins and as a fallback.  For all others
    the domain is derived from the highest-privilege group grant:
      - Highest PermLevel wins across all domain grants.
      - If tied, alphabetically first domain name.
      - If only project grants, the first project's domain.
    """
    if parsed.is_root_admin:
        return "ROOT"
    if parsed.domain_access:
        best = max(parsed.domain_access, key=lambda da: (int(da.level), da.domain))
        return best.domain  # e.g. "ORGX"
    if parsed.project_access:
        return parsed.project_access[0].domain
    return "ROOT"


class Provisioner:
    """Handles all CloudStack object provisioning for a single identity."""

    def __init__(self, cs: CloudStackClient, config: AppConfig) -> None:
        self._cs = cs
        self._config = config

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def provision(self, identity: OidcIdentity) -> ProvisionedUser:
        """Ensure all required CloudStack objects exist for *identity* and
        return the provisioned user details (including session credentials).
        """
        parsed = parse_groups(identity.groups)

        # Three-tier privilege mapping:
        #   CS_ROOT_ADMIN group          → root_admin tier (account_type=1)
        #   Any other domain-level grant → domain_admin tier (account_type=2)
        #   Project-only / no CS_* groups → user tier (account_type=0)
        #
        # CS_ROOT_ADMIN supersedes everything — a user with that group is
        # always placed in the rootadmin tier regardless of other groups.
        is_root_admin   = parsed.is_root_admin
        is_domain_admin = (not is_root_admin) and bool(parsed.domain_access)
        is_admin        = is_root_admin or is_domain_admin  # any elevated tier

        # 1. Resolve the three built-in CloudStack roles (never created by the gateway).
        rootadmin_role_id  = await self._get_builtin_role_id(_BUILTIN_ROOT_ADMIN_ROLE)
        admin_role_id      = await self._get_builtin_role_id(_BUILTIN_DOMAIN_ADMIN_ROLE)
        user_role_id       = await self._get_builtin_role_id(_BUILTIN_USER_ROLE)

        if is_root_admin:
            role_id = rootadmin_role_id
        elif is_domain_admin:
            role_id = admin_role_id
        else:
            role_id = user_role_id

        # 2. Determine the target domain for this user's account.
        #    Root admins MUST be in ROOT (account_type=1 is ROOT-only).
        #    Domain admins go to a domain named after their CS_<DOMAIN> group
        #    (created under ROOT if it doesn't exist yet — e.g. CS_ORGX_ADMIN
        #    → domain "orgx").  Project-only users go to their project's domain.
        #    No /oidc domain is ever auto-created.
        if is_root_admin:
            domain_id = await self._get_root_domain_id()
        else:
            primary_domain = _primary_domain_name(parsed)
            if primary_domain == "ROOT":
                domain_id = await self._get_root_domain_id()
            else:
                domain_id = await self._ensure_domain(primary_domain)

        # 3. One account + user per OIDC identity, named after sAMAccountName
        account_name = slugify(identity.sam_account_name)
        account_id, user_id = await self._ensure_user_account(
            identity, account_name, domain_id, role_id,
            is_root_admin=is_root_admin, is_admin=is_admin,
        )

        # 4. Project memberships — find-only; projects must be pre-created by CS admins
        project_ids: dict[str, str] = {}
        for pa in parsed.project_access:
            project_id = await self._ensure_project(pa.project)
            if project_id is None:
                continue  # project not found in CS — skip, never create
            project_ids[pa.project] = project_id
            await self._ensure_account_in_project(account_name, project_id)

        # 5. API keys
        api_key, secret_key = await self._ensure_api_keys(user_id)

        return ProvisionedUser(
            sub=identity.sub,
            email=identity.email,
            user_slug=account_name,
            account_name=account_name,
            domain_id=domain_id,
            account_id=account_id,
            user_id=user_id,
            api_key=api_key,
            secret_key=secret_key,
            is_admin=is_admin,
            cs_password=_random_password(),
            project_ids=project_ids,
        )

    # ------------------------------------------------------------------
    # Domain resolution
    # ------------------------------------------------------------------

    async def _get_root_domain_id(self) -> str:
        """Return the ID of the CloudStack root domain.

        Tries name=ROOT first (most installs); falls back to sorting all
        visible domains by level and taking level=0.  Logs what it sees so
        misconfigured credentials are easy to diagnose.
        """
        domains = await self._cs.list_domains(name="ROOT")
        root = next((d for d in domains if d.get("name", "").upper() == "ROOT"), None)
        if root:
            logger.debug("Root domain found by name: id=%s", root["id"])
            return root["id"]
        # Fallback: list everything and take the lowest-level domain.
        all_domains = await self._cs.list_domains()
        logger.debug("Root-domain fallback — visible domains: %s", all_domains)
        if all_domains:
            def _level(d: dict) -> int:
                lv = d.get("level")
                if lv is None or lv == "":
                    return 999
                try:
                    return int(lv)  # do NOT use `lv or 999` — 0 is falsy
                except (ValueError, TypeError):
                    return 999
            best = sorted(all_domains, key=_level)[0]
            logger.warning(
                "ROOT domain not found by name; using domain id=%s name=%s level=%s",
                best.get("id"), best.get("name"), best.get("level"),
            )
            return best["id"]
        raise RuntimeError(
            "Cannot determine ROOT domain ID — check that the configured "
            "API key belongs to a root-admin account."
        )

    async def _ensure_domain(self, name: str) -> str:
        """Find or create a top-level CloudStack domain by name.

        The *name* comes from the CS_<DOMAIN>_* group token (already
        uppercased by the parser); it is slugified before use so it is
        a valid CloudStack identifier.
        Returns the domain's ID.
        """
        slug = slugify(name)
        domains = await self._cs.list_domains(name=slug)
        domain = next(
            (d for d in domains if d.get("name", "").lower() == slug),
            None,
        )
        if domain is None:
            logger.info("Creating domain '%s'", slug)
            domain = await self._cs.create_domain(slug)
        return domain["id"]

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    async def _get_builtin_role_id(self, name: str) -> str:
        """Return the ID of a CloudStack built-in role by exact name.

        CloudStack ships with 'Root Admin', 'Domain Admin', and 'User' roles
        that are always present.  The gateway looks them up and never creates
        or modifies them.  Raises ``CloudStackError`` if the role is missing
        (which should never happen on a standard installation).
        """
        roles = await self._cs.list_roles(name=name)
        role = next((r for r in roles if r["name"] == name), None)
        if role is not None:
            return role["id"]
        raise CloudStackError(
            404,
            f"Built-in CloudStack role '{name}' not found. "
            "Ensure this role exists in your CloudStack installation.",
        )

    async def _ensure_role(self, name: str, role_type: str) -> str:
        """Return the ID of the named role, creating it if needed.

        Also ensures at least one wildcard ALLOW rule exists so the CloudStack
        SPA can function.  Real per-request ACLs are enforced by permission.py.
        """
        roles = await self._cs.list_roles(name=name)
        role = next((r for r in roles if r["name"] == name), None)

        # If the role exists with the wrong type, try to update it in-place
        # first (works even when accounts are attached).  Only fall back to
        # delete+recreate if updateRole is unsupported.
        if role is not None and role.get("type") != role_type:
            logger.warning(
                "Role '%s' has type '%s', expected '%s' — updating",
                name, role.get("type"), role_type,
            )
            try:
                await self._cs.update_role(role["id"], role_type)
                role["type"] = role_type  # reflect update locally
            except Exception as exc:  # noqa: BLE001
                logger.warning("updateRole failed (%s) — trying delete+recreate", exc)
                try:
                    await self._cs.delete_role(role["id"])
                    role = None
                except Exception as exc2:  # noqa: BLE001
                    logger.error(
                        "Cannot fix role '%s' type (update: %s, delete: %s) — "
                        "account creation will likely fail",
                        name, exc, exc2,
                    )

        if role is None:
            logger.info("Creating role '%s' (type=%s)", name, role_type)
            role = await self._cs.create_role(
                name=name,
                role_type=role_type,
                description=f"Auto-managed OIDC gateway role ({role_type})",
            )
        role_id: str = role["id"]

        # Ensure at least one ALLOW rule exists — without rules CloudStack
        # denies every API call.
        perms = await self._cs.list_role_permissions(role_id=role_id)
        if not perms:
            logger.info("Adding wildcard ALLOW rule to role '%s'", name)
            await self._cs.create_role_permission(
                role_id=role_id,
                rule="*",
                permission="allow",
                description="Auto-added by OIDC gateway — proxy enforces real ACLs",
            )

        return role_id

    # ------------------------------------------------------------------
    # Per-user account
    # ------------------------------------------------------------------

    async def _ensure_user_account(
        self,
        identity: OidcIdentity,
        account_name: str,
        domain_id: str,
        role_id: str,
        *,
        is_root_admin: bool = False,
        is_admin: bool = False,
    ) -> tuple[str, str]:
        """Find or create the per-user CloudStack account and user.

        Returns ``(account_id, user_id)``.

        If the account exists but its role no longer matches the user's
        current privilege level, the role is updated via ``update_account``.
        """
        # account_type must exactly match the role type (CS validates the pair):
        #   "Admin"       role -> account_type=1  (Root Admin)
        #   "DomainAdmin" role -> account_type=2  (Domain Admin, isAdmin()=True)
        #   "User"        role -> account_type=0  (Normal User)
        if is_root_admin:
            account_type = 1
        elif is_admin:
            account_type = 2
        else:
            account_type = 0

        # --- Account ---
        accounts = await self._cs.list_accounts(name=account_name, domain_id=domain_id)
        account = next((a for a in accounts if a["name"] == account_name), None)

        if account is None:
            logger.info("Creating account '%s' in domain %s", account_name, domain_id)
            account = await self._cs.create_account(
                account_name=account_name,
                account_type=account_type,
                email=identity.email or f"{account_name}@cloudstack.local",
                firstname=identity.given_name or account_name,
                lastname=identity.family_name or "(OIDC)",
                username=account_name,
                password=_random_password(),
                domain_id=domain_id,
                role_id=role_id,
            )
        else:
            current_role_id = (account.get("roleid") or "").strip()
            if current_role_id != role_id:
                logger.info(
                    "Updating account '%s' role: %s → %s",
                    account_name, current_role_id, role_id,
                )
                account = await self._cs.update_account(
                    account_id=account["id"],
                    role_id=role_id,
                )

        account_id: str = account["id"]

        # --- User ---
        users = await self._cs.list_users(username=account_name, domain_id=domain_id)
        user = next((u for u in users if u.get("username") == account_name), None)

        if user is None:
            logger.info("Creating user '%s' in account '%s'", account_name, account_name)
            user = await self._cs.create_user(
                account=account_name,
                email=identity.email or f"{account_name}@cloudstack.local",
                firstname=identity.given_name or account_name,
                lastname=identity.family_name or "(OIDC)",
                username=account_name,
                password=_random_password(),
                domain_id=domain_id,
            )

        user_id: str = user["id"]
        return account_id, user_id

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    async def _ensure_project(self, project_key: str) -> str | None:
        """Find an existing project matching *project_key* (case-insensitive).

        Searches globally (no domain filter) so the admin CS client finds
        projects in any domain.  NEVER creates a project — projects must be
        pre-created by a CloudStack administrator.  Returns None if not found.
        """
        name_to_find = project_key.lower()
        projects = await self._cs.list_projects(name=name_to_find)
        proj = next(
            (p for p in projects if p["name"].lower() == name_to_find), None
        )
        if proj is not None:
            return proj["id"]
        logger.warning(
            "Project '%s' not found in CloudStack — create it manually; "
            "users with group CS_*_PRJ_%s_USER will be added on next login.",
            name_to_find, project_key,
        )
        return None

    async def _ensure_account_in_project(
        self, account_name: str, project_id: str
    ) -> None:
        """Add *account_name* to *project_id* if not already a member."""
        members = await self._cs.list_project_accounts(project_id)
        if not any(m.get("account") == account_name for m in members):
            logger.info("Adding account '%s' to project %s", account_name, project_id)
            await self._cs.add_account_to_project(project_id, account_name)

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    async def _ensure_api_keys(self, user_id: str) -> tuple[str, str]:
        """Return (api_key, secret_key), registering fresh keys if none exist."""
        keys = await self._cs.get_user_keys(user_id)
        api_key: str = keys.get("apikey", "")
        secret_key: str = keys.get("secretkey", "")
        if not api_key:
            logger.info("Registering API keys for user %s", user_id)
            keys = await self._cs.register_user_keys(user_id)
            api_key = keys.get("apikey", "")
            secret_key = keys.get("secretkey", "")
        return api_key, secret_key
