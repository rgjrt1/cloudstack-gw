"""
Proxy-tier permission enforcement.

All real access control lives here.  CloudStack roles only determine
"can this user touch CS at all" (admin vs user account placement).

Access matrix
-------------
  ROOT ADMIN      → every command in every domain
  ROOT OPERATIONS → every non-destructive + create command (same as ADMIN for now)
  ROOT READONLY   → list* / get* / query* commands only
  DOMAIN ADMIN    → every command scoped to that domain
  DOMAIN READONLY → list* / get* / query* scoped to that domain
  PROJECT USER    → project-scoped commands only (projectid must match)
  (no grants)     → denied

A "list/read" command is one whose name starts with "list", "get", or
"query" (case-insensitive).

Project-scoped detection
------------------------
CloudStack marks a request as project-scoped when it carries a
``projectid`` query parameter.  The middleware resolves that UUID to a
project key and passes it here.
"""
from __future__ import annotations

from .group_parser import ParsedGroups, PermLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_READ_PREFIXES = ("list", "get", "query", "describe")


def _is_read_command(command: str) -> bool:
    c = command.lower()
    return any(c.startswith(p) for p in _READ_PREFIXES)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_permission(
    parsed: ParsedGroups,
    command: str,
    *,
    domain_name: str | None = None,
    project_key: str | None = None,
) -> bool:
    """Return *True* if the request should be forwarded to CloudStack.

    Parameters
    ----------
    parsed:
        Resolved group access grants for the authenticated user.
    command:
        The CloudStack API command name, e.g. ``"listVirtualMachines"``.
    domain_name:
        The CloudStack domain name the request targets (derived from the
        user's active session / account context).  Pass *None* if unknown.
    project_key:
        The project key (uppercase) the request targets, if any.
    """
    if not parsed.has_any_access:
        return False

    # ------------------------------------------------------------------
    # 1. Root grants
    # ------------------------------------------------------------------
    root_level = parsed.level_for_domain("ROOT")
    if root_level is not None:
        if root_level >= PermLevel.OPERATIONS:
            return True
        if root_level == PermLevel.READONLY:
            return _is_read_command(command)

    # ------------------------------------------------------------------
    # 2. Domain grants
    # ------------------------------------------------------------------
    if domain_name:
        domain_level = parsed.level_for_domain(domain_name)
        if domain_level is not None:
            if domain_level >= PermLevel.OPERATIONS:
                return True
            if domain_level == PermLevel.READONLY:
                return _is_read_command(command)
    else:
        # No domain context in the request — CloudStack scopes the call to
        # the user's session domain automatically.  Permit the command if the
        # user has any domain-level grant of appropriate strength so the SPA
        # can operate without always sending a ``domain`` parameter.
        for da in parsed.domain_access:
            if da.level >= PermLevel.OPERATIONS:
                return True
            if da.level == PermLevel.READONLY and _is_read_command(command):
                return True

    # ------------------------------------------------------------------
    # 3. Project grants — user may run project-scoped API calls
    # ------------------------------------------------------------------
    if project_key:
        # Accept if the user has project access in any domain, or
        # specifically the request domain when provided.
        if domain_name:
            if parsed.has_project_access(domain_name, project_key):
                return True
        else:
            # No domain context — accept if user has this project anywhere
            for pa in parsed.project_access:
                if pa.project == project_key.upper():
                    return True
    elif not domain_name:
        # No domain AND no project context — allow read commands for any
        # user with project-only access (e.g. listUsers self-lookup at startup).
        if _is_read_command(command) and parsed.project_access:
            return True

    return False
