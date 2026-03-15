"""
Background reconciliation task.

Runs on a configurable interval and performs cleanup of stale CloudStack
objects that are no longer backed by active IdP group memberships:

  - Detects orphaned users (users whose last-seen groups no longer match
    their current account) and optionally disables them.
  - Optionally removes empty ``oidc-*`` accounts (disabled by default).
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from .cache import BaseCache
from .cloudstack_client import CloudStackClient, CloudStackError
from .models import AppConfig

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class Reconciler:
    """Background reconciliation loop."""

    def __init__(
        self,
        cs: CloudStackClient,
        cache: BaseCache,
        config: AppConfig,
    ) -> None:
        self._cs = cs
        self._cache = cache
        self._config = config
        self._task: asyncio.Task | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Schedule the background reconciliation loop."""
        if not self._config.reconciliation.enabled:
            logger.info("Reconciliation is disabled in config — skipping")
            return
        if self._task is not None and not self._task.done():
            logger.warning("Reconciler already running")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop(), name="reconciler")
        logger.info(
            "Reconciler started (interval=%ds)", self._config.reconciliation.interval
        )

    def stop(self) -> None:
        """Cancel the background loop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("Reconciler stopped")

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Reconciler run failed — will retry next cycle")

            try:
                await asyncio.sleep(self._config.reconciliation.interval)
            except asyncio.CancelledError:
                break

    # ------------------------------------------------------------------
    # Single reconciliation run
    # ------------------------------------------------------------------

    async def run_once(self) -> dict:
        """Execute one full reconciliation pass.

        Returns a summary dict describing what was done.
        """
        logger.info("Starting reconciliation run")
        summary: dict = {
            "disabled_users": [],
            "removed_accounts": [],
            "errors": [],
        }

        try:
            domain = await self._find_oidc_domain()
            if domain is None:
                logger.info("OIDC domain not found — nothing to reconcile")
                return summary

            domain_id: str = domain["id"]
            await self._reconcile_accounts(domain_id, summary)
        except Exception as exc:
            logger.exception("Reconciliation error: %s", exc)
            summary["errors"].append(str(exc))

        logger.info("Reconciliation complete: %s", summary)
        return summary

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _find_oidc_domain(self) -> dict | None:
        """Return the CloudStack domain dict for the configured domain path."""
        domain_path = self._config.cloudstack.domain_path.strip("/")
        parts = domain_path.split("/") if domain_path else ["oidc"]
        leaf = parts[-1]
        domains = await self._cs.list_domains(name=leaf)
        return next((d for d in domains if d["name"] == leaf), None)

    async def _reconcile_accounts(self, domain_id: str, summary: dict) -> None:
        """Check all oidc-* accounts under the OIDC domain."""
        accounts = await self._cs.list_accounts(domain_id=domain_id)
        managed_accounts = [a for a in accounts if a.get("name", "").startswith("oidc-")]

        # New architecture: two shared accounts per domain
        valid_account_names = {"oidc-admin", "oidc-user"}

        for account in managed_accounts:
            account_name: str = account["name"]
            account_id: str = account["id"]

            if account_name not in valid_account_names:
                logger.info(
                    "Account '%s' no longer maps to any configured group",
                    account_name,
                )
                if self._config.reconciliation.disable_orphaned_users:
                    await self._disable_account_users(account_id, account_name, summary)
                if self._config.reconciliation.cleanup_empty_accounts:
                    await self._maybe_remove_empty_account(
                        account_id, account_name, summary
                    )
                continue

            # Account is still valid — check individual users
            await self._reconcile_account_users(account, domain_id, summary)

    async def _reconcile_account_users(
        self,
        account: dict,
        domain_id: str,
        summary: dict,
    ) -> None:
        """Disable users whose last-seen group membership no longer matches this account."""
        account_name: str = account["name"]
        # Derive the expected group name from the account naming convention:
        users = await self._cs.list_users(domain_id=domain_id, account=account_name)
        for user in users:
            username: str = user.get("username", "")
            # Skip the seed user created during account creation
            if username.startswith("_seed-"):
                continue

            user_id: str = user["id"]
            state: str = user.get("state", "").lower()
            if state == "disabled":
                continue

            # Check whether this user's cached groups still justify membership
            # in the current account (oidc-admin requires domain-level grants;
            # oidc-user is always kept active).
            still_member = await self._check_user_still_member(
                username, account_name
            )
            if not still_member:
                logger.info(
                    "Disabling orphaned user '%s' (not seen in group '%s' recently)",
                    username,
                    expected_mapping.group,
                )
                try:
                    await self._cs.disable_user(user_id)
                    summary["disabled_users"].append(username)
                except CloudStackError as exc:
                    logger.warning("Failed to disable user %s: %s", username, exc)
                    summary["errors"].append(f"disable_user({username}): {exc}")

    async def _check_user_still_member(
        self, username: str, account_name: str
    ) -> bool:
        """Heuristic: check the in-memory cache for this user's last-seen groups.

        Returns True (keep user enabled) if:
          - No cache info is available (unknown — assume still valid), OR
          - The account is ``oidc-user`` (project-only users always stay), OR
          - The account is ``oidc-admin`` and the user still has domain-level
            CS_* grants in their last-seen group list.
        """
        from .group_parser import parse_groups

        # oidc-user is always kept active; project access is reconciled separately
        if account_name != "oidc-admin":
            return True

        # The cache keys are "{sub}:{groups_hash}", not indexed by username.
        # For MemoryCache we can iterate the internal store; for Redis this
        # would require a key pattern scan.  We check what we can and default
        # to "keep enabled" for unknown users (safe default).
        cache = self._cache
        if hasattr(cache, "_store"):
            import time
            for _key, (expiry, entry) in list(cache._store.items()):  # type: ignore[attr-defined]
                if time.monotonic() > expiry:
                    continue
                if entry.identity.user_slug == username:
                    parsed = parse_groups(entry.identity.groups)
                    return bool(parsed.domain_access)
        # Unknown — assume still valid to avoid incorrect lockouts
        return True

    async def _disable_account_users(
        self,
        account_id: str,
        account_name: str,
        summary: dict,
    ) -> None:
        users = await self._cs.list_users(account=account_name)
        for user in users:
            username: str = user.get("username", "")
            if username.startswith("_seed-"):
                continue
            if user.get("state", "").lower() == "disabled":
                continue
            try:
                await self._cs.disable_user(user["id"])
                summary["disabled_users"].append(username)
            except CloudStackError as exc:
                logger.warning("Failed to disable user %s: %s", username, exc)
                summary["errors"].append(f"disable_user({username}): {exc}")

    async def _maybe_remove_empty_account(
        self,
        account_id: str,
        account_name: str,
        summary: dict,
    ) -> None:
        """Remove an account if it has no non-seed, non-disabled users."""
        users = await self._cs.list_users(account=account_name)
        active = [
            u for u in users
            if not u.get("username", "").startswith("_seed-")
            and u.get("state", "").lower() != "disabled"
        ]
        if not active:
            logger.info("Removing empty account '%s'", account_name)
            try:
                await self._cs._call("deleteAccount", id=account_id)  # type: ignore[attr-defined]
                summary["removed_accounts"].append(account_name)
            except CloudStackError as exc:
                logger.warning("Failed to remove account %s: %s", account_name, exc)
                summary["errors"].append(f"deleteAccount({account_name}): {exc}")
