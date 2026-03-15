"""
Parse CS_* group names into structured access descriptors.

Group naming convention
-----------------------
  CS_ROOT_ADMIN                   → Root domain, admin level
  CS_ROOT_OPERATIONS              → Root domain, operations level
  CS_ROOT_READONLY                → Root domain, read-only level
  CS_<DOMAIN>_ADMIN               → Named domain, admin level
  CS_<DOMAIN>_OPERATIONS          → Named domain, operations level
  CS_<DOMAIN>_READONLY            → Named domain, read-only level
  CS_<DOMAIN>_PRJ_<PROJECT>_USER  → Project member in named domain

Constraints
-----------
* Groups not matching the ``CS_`` prefix are silently ignored.
* Domain names must not contain underscores — use hyphens instead.
  Example: ``CS_MY-ORG_ADMIN`` is valid; ``CS_MY_ORG_ADMIN`` is ambiguous.
* Domain names and project keys are normalised to UPPERCASE internally.

Privilege ordering (highest to lowest): ADMIN > OPERATIONS > READONLY

When a user has multiple groups for the same domain the highest level wins.
Root admin (CS_ROOT_ADMIN) supersedes all other access grants.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class PermLevel(IntEnum):
    READONLY   = 1
    OPERATIONS = 2
    ADMIN      = 3


_LEVEL_MAP: dict[str, PermLevel] = {
    "ADMIN":      PermLevel.ADMIN,
    "OPERATIONS": PermLevel.OPERATIONS,
    "READONLY":   PermLevel.READONLY,
}

# Matches:
#   CS_<DOMAIN>_ADMIN | CS_<DOMAIN>_OPERATIONS | CS_<DOMAIN>_READONLY
#   CS_<DOMAIN>_PRJ_<PROJECT>_USER
# Domain and project tokens: alphanumeric + hyphens only (no underscores).
_GROUP_RE = re.compile(
    r"^CS_"
    r"(?P<domain>[A-Za-z0-9-]+)"
    r"(?:"
      r"_PRJ_(?P<project>[A-Za-z0-9-]+)_USER"
      r"|_(?P<level>ADMIN|OPERATIONS|READONLY)"
    r")$"
)


@dataclass(frozen=True)
class DomainAccess:
    """Permission level for a single domain."""
    domain: str       # always uppercase; "ROOT" means the CloudStack root domain
    level: PermLevel


@dataclass(frozen=True)
class ProjectAccess:
    """Project membership for a user in a domain."""
    domain:  str   # always uppercase
    project: str   # project key, always uppercase


@dataclass
class ParsedGroups:
    """Resolved access grants derived from a user's CS_* group memberships."""

    # One entry per domain, deduplicated to the highest level granted
    domain_access: list[DomainAccess] = field(default_factory=list)
    # All project memberships
    project_access: list[ProjectAccess] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def is_root_admin(self) -> bool:
        """True if the user holds CS_ROOT_ADMIN."""
        return any(
            d.domain == "ROOT" and d.level == PermLevel.ADMIN
            for d in self.domain_access
        )

    @property
    def is_admin(self) -> bool:
        """True if the user should be placed in the admin CS account.

        This covers both root admin and any domain-level ADMIN grant.
        """
        return any(d.level == PermLevel.ADMIN for d in self.domain_access)

    @property
    def has_any_access(self) -> bool:
        return bool(self.domain_access or self.project_access)

    def level_for_domain(self, domain: str) -> PermLevel | None:
        """Return the highest permission level for *domain*, or None if no access."""
        domain = domain.upper()
        for da in self.domain_access:
            if da.domain == domain:
                return da.level
        return None

    def has_project_access(self, domain: str, project: str) -> bool:
        return ProjectAccess(domain.upper(), project.upper()) in set(self.project_access)

    def projects_for_domain(self, domain: str) -> list[str]:
        domain = domain.upper()
        return [pa.project for pa in self.project_access if pa.domain == domain]


def parse_groups(groups: list[str]) -> ParsedGroups:
    """Parse raw group names into a :class:`ParsedGroups` instance.

    Groups that do not match the ``CS_`` convention are silently skipped.
    """
    # domain → highest level seen so far
    domain_levels: dict[str, PermLevel] = {}
    project_set: set[ProjectAccess] = set()

    for group in groups:
        m = _GROUP_RE.match(group)
        if not m:
            continue  # not a CS_ group — ignore

        domain  = m.group("domain").upper()
        project = m.group("project")
        level_s = m.group("level")

        if project:
            project_set.add(ProjectAccess(domain=domain, project=project.upper()))
        elif level_s:
            level = _LEVEL_MAP[level_s]
            if domain not in domain_levels or level > domain_levels[domain]:
                domain_levels[domain] = level

    domain_access = [
        DomainAccess(domain=d, level=l)
        for d, l in sorted(domain_levels.items())
    ]
    project_access = sorted(project_set, key=lambda pa: (pa.domain, pa.project))
    return ParsedGroups(domain_access=domain_access, project_access=project_access)
