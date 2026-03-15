#!/usr/bin/env python3
"""Generate CLOUDSTACK_ROLE_MATRIX.md with all 9 built-in CloudStack roles."""

import re

# ─── PATHS ────────────────────────────────────────────────────────────────────
SCHEMA_DIR = (
    "/home/rgjrt1/Documents/Projects/cloudstack_oidcwrap"
    "/cloudstack/engine/schema/src/main/resources/META-INF/db"
)
PRIMARY_SQL = f"{SCHEMA_DIR}/create-default-role-api-mappings.sql"
OUT_FILE = "/home/rgjrt1/Documents/Projects/cloudstack_oidcwrap/cloudstack-gw/CLOUDSTACK_ROLE_MATRIX.md"


# ─── CRUD classification (matches original scheme) ────────────────────────────
def classify(api: str) -> str:
    a = api.lower()
    if any(a.startswith(p) for p in ("list", "get", "query", "extract", "quota")):
        return "Read"
    if any(a.startswith(p) for p in (
        "create", "add", "deploy", "register", "upload", "associate", "attach",
        "authorize", "copy", "import", "ldap", "link", "assign", "acquire",
        "archive", "issue", "lock",
    )):
        return "Create"
    if any(a.startswith(p) for p in (
        "delete", "destroy", "expunge", "remove", "revoke",
        "disassociate", "dissociate", "purge",
    )):
        return "Delete"
    return "Update"   # start/stop/reboot/update/migrate/resize/prepare/cancel/enable/disable/setup/scale/validate/…


# ─── Parse primary SQL for roles 2, 3, 4 ─────────────────────────────────────
role_allows: dict[int, set[str]] = {2: set(), 3: set(), 4: set()}

with open(PRIMARY_SQL) as f:
    for line in f:
        m = re.search(r"VALUES\s*\(UUID\(\),\s*(\d+),\s*'([^']+)',\s*'(ALLOW|DENY)'", line, re.IGNORECASE)
        if m:
            rid, rule, perm = int(m.group(1)), m.group(2), m.group(3)
            if rid in role_allows and perm == "ALLOW":
                role_allows[rid].add(rule)

print(f"Primary SQL – Role 2: {len(role_allows[2])} APIs, "
      f"Role 3: {len(role_allows[3])} APIs, Role 4: {len(role_allows[4])} APIs")


# ─── Apply schema migrations to original roles ────────────────────────────────

# schema-41400to41500-cleanup.sql: removes old NetApp APIs (not present, no-op)

# schema-41610to41700.sql: add listConfigurations / updateConfiguration to Domain Admin
role_allows[3].add("listConfigurations")
role_allows[3].add("updateConfiguration")

# schema-41720to41800.sql:
#   DELETE migrateVolume FROM non-Admin is_default=1 roles
#   (Resource Admin role_type='ResourceAdmin', Domain Admin='DomainAdmin', User='User' – all != 'Admin')
for rid in (2, 3, 4):
    role_allows[rid].discard("migrateVolume")

#   ADD assignVolume to Resource Admin and Domain Admin
role_allows[2].add("assignVolume")
role_allows[3].add("assignVolume")

#   ADD isAccountAllowedToCreateOfferingsWithTags to DomainAdmin roles
role_allows[3].add("isAccountAllowedToCreateOfferingsWithTags")

# schema-42010to42100.sql: add quotaCreditsList to any role that has quotaStatement
for rid in (2, 3, 4):
    if "quotaStatement" in role_allows[rid]:
        role_allows[rid].add("quotaCreditsList")


# ─── Read-Only Admin – Default (role 5) ──────────────────────────────────────
# Ordered rules (first-match-wins):
#   list*                   → ALLOW
#   getUploadParamsFor*     → DENY
#   get*                    → ALLOW
#   <explicit extras>       → ALLOW
#   *                       → DENY
# Migrations add: quotaStatement, quotaBalance, setupUserTwoFactorAuthentication,
#                 validateUserTwoFactorAuthenticationCode, quotaCreditsList

RO_ADMIN_EXPLICIT_ALLOW = {
    "cloudianIsEnabled", "queryAsyncJobResult",
    "quotaIsEnabled", "quotaTariffList", "quotaSummary",
    "quotaStatement", "quotaBalance",
    "setupUserTwoFactorAuthentication", "validateUserTwoFactorAuthenticationCode",
    "quotaCreditsList",
}


def ro_admin_allows(api: str) -> bool:
    if api.startswith("list"):
        return True
    if api.startswith("getUploadParamsFor"):
        return False
    if api.startswith("get"):
        return True
    return api in RO_ADMIN_EXPLICIT_ALLOW


# ─── Read-Only User – Default (role 6) ───────────────────────────────────────
# Copies User (role 4) list% and get% (NOT getUploadParamsFor%) rules,
# plus explicit extras + migrations
# + * DENY catch-all

_user_list_get = {
    api for api in role_allows[4]
    if api.startswith("list")
    or (api.startswith("get") and not api.startswith("getUploadParamsFor"))
}
RO_USER_ALLOW = _user_list_get | {
    "cloudianIsEnabled", "queryAsyncJobResult",
    "quotaIsEnabled", "quotaTariffList", "quotaSummary",
    "quotaStatement", "quotaBalance",
    "setupUserTwoFactorAuthentication", "validateUserTwoFactorAuthenticationCode",
    "listUserTwoFactorAuthenticatorProviders",
    "quotaCreditsList",
}


def ro_user_allows(api: str) -> bool:
    return api in RO_USER_ALLOW


# ─── Support Admin – Default (role 7) ────────────────────────────────────────
# Read-Only Admin permissions + additional write ops + * DENY

SUPPORT_ADMIN_EXTRA = {
    "prepareHostForMaintenance", "cancelHostMaintenance",
    "enableStorageMaintenance", "cancelStorageMaintenance",
    "createServiceOffering", "createDiskOffering",
    "createNetworkOffering", "createVPCOffering",
    "startVirtualMachine", "stopVirtualMachine", "rebootVirtualMachine",
    "startKubernetesCluster", "stopKubernetesCluster",
    "createVolume", "attachVolume", "detachVolume", "uploadVolume",
    "attachIso", "detachIso",
    "registerTemplate", "registerIso",
}


def support_admin_allows(api: str) -> bool:
    return ro_admin_allows(api) or api in SUPPORT_ADMIN_EXTRA


# ─── Support User – Default (role 8) ─────────────────────────────────────────
# Read-Only User permissions + additional write ops + getUploadParamsFor* ALLOW + * DENY

SUPPORT_USER_EXTRA = {
    "startVirtualMachine", "stopVirtualMachine", "rebootVirtualMachine",
    "startKubernetesCluster", "stopKubernetesCluster",
    "createVolume", "attachVolume", "detachVolume", "uploadVolume",
    "attachIso", "detachIso",
    "registerTemplate", "registerIso",
}


def support_user_allows(api: str) -> bool:
    if ro_user_allows(api):
        return True
    if api in SUPPORT_USER_EXTRA:
        return True
    if api.startswith("getUploadParamsFor"):
        return True
    return False


# ─── Project Kubernetes Service Role (role 9) ─────────────────────────────────
# Defined in KubernetesClusterManagerImpl.PROJECT_KUBERNETES_ACCOUNT_ROLE_ALLOWED_APIS

K8S_ROLE_ALLOW = {
    "queryAsyncJobResult",
    "listVirtualMachines", "listVolumes", "listNetworks", "listSnapshots",
    "listPublicIpAddresses", "listLoadBalancerRules", "listLoadBalancerRuleInstances",
    "listFirewallRules", "listNetworkACLs", "listKubernetesClusters",
    "createVolume", "deleteVolume", "attachVolume", "detachVolume", "resizeVolume",
    "createSnapshot", "deleteSnapshot",
    "associateIpAddress", "disassociateIpAddress",
    "createLoadBalancerRule", "updateLoadBalancerRule", "deleteLoadBalancerRule",
    "assignToLoadBalancerRule", "removeFromLoadBalancerRule",
    "createFirewallRule", "updateFirewallRule", "deleteFirewallRule",
    "createNetworkACL", "deleteNetworkACL",
    "scaleKubernetesCluster",
}


def k8s_allows(api: str) -> bool:
    return api in K8S_ROLE_ALLOW


# ─── Master API set ───────────────────────────────────────────────────────────
# Union of all explicitly-named APIs across every role
all_apis: set[str] = set()
for rid in (2, 3, 4):
    all_apis |= role_allows[rid]
all_apis |= RO_ADMIN_EXPLICIT_ALLOW
all_apis |= RO_USER_ALLOW
all_apis |= SUPPORT_ADMIN_EXTRA
all_apis |= SUPPORT_USER_EXTRA
all_apis |= K8S_ROLE_ALLOW
# Include migrateVolume even though it was removed from original roles
# (Root Admin can still do it; it's a known CS API)
all_apis.add("migrateVolume")

print(f"Total unique APIs in matrix: {len(all_apis)}")


# ─── Access checker ───────────────────────────────────────────────────────────
def check_access(role_id: int, api: str) -> bool:
    if role_id == 1:       return True               # Root Admin: * ALLOW
    if role_id in (2, 3, 4): return api in role_allows[role_id]
    if role_id == 5:       return ro_admin_allows(api)
    if role_id == 6:       return ro_user_allows(api)
    if role_id == 7:       return support_admin_allows(api)
    if role_id == 8:       return support_user_allows(api)
    if role_id == 9:       return k8s_allows(api)
    return False


# ─── Group APIs by CRUD ───────────────────────────────────────────────────────
CRUD_ORDER = ("Read", "Create", "Update", "Delete")
grouped: dict[str, list[str]] = {c: [] for c in CRUD_ORDER}
for api in all_apis:
    grouped[classify(api)].append(api)
for c in CRUD_ORDER:
    grouped[c].sort(key=str.lower)

for c in CRUD_ORDER:
    print(f"  {c}: {len(grouped[c])} APIs")


# ─── Role metadata ────────────────────────────────────────────────────────────
ROLE_IDS    = [1, 2, 3, 4, 5, 6, 7, 8, 9]
ROLE_COLS   = [
    "Root Admin",
    "Resource Admin",
    "Domain Admin",
    "User",
    "Read-Only Admin",
    "Read-Only User",
    "Support Admin",
    "Support User",
    "Proj. K8s Svc",
]


# ─── Render markdown ──────────────────────────────────────────────────────────
lines: list[str] = []

def H(n, t): return f"{'#'*n} {t}"

lines += [
    H(1, "CloudStack Built-In Role Permission Matrix"),
    "",
    "> **Sources:** `create-default-role-api-mappings.sql` (roles 1–4) · "
    "`Upgrade41400to41500.java` (roles 5–8 base) · schema migrations up to 4.21.0.x · "
    "`KubernetesClusterManagerImpl.java` (role 9)  ",
    "> ✅ = Allowed &nbsp;&nbsp; 🚫 = Denied / Not in role_permissions",
    "",
]

# ── Permission matrix ─────────────────────────────────────────────────────────
header_sep_col = " | ".join([":---:"] + [":---"] + [":---:"] * len(ROLE_IDS))
lines += [
    "| Cat | API Rule | " + " | ".join(ROLE_COLS) + " |",
    "| " + header_sep_col + " |",
]

totals: dict[int, dict[str, int]] = {rid: {c: 0 for c in CRUD_ORDER} for rid in ROLE_IDS}
prev_cat = ""

for cat in CRUD_ORDER:
    for api in grouped[cat]:
        cat_label = f"**{cat}**" if cat != prev_cat else ""
        prev_cat = cat
        cells = []
        for rid in ROLE_IDS:
            allow = check_access(rid, api)
            cells.append("✅" if allow else "🚫")
            if allow:
                totals[rid][cat] += 1
        lines.append(f"| {cat_label} | `{api}` | " + " | ".join(cells) + " |")

lines += [""]

# ── Count summary ─────────────────────────────────────────────────────────────
lines += [
    "---",
    "",
    H(2, "Permission Count Summary"),
    "",
    "| Category | " + " | ".join(ROLE_COLS) + " |",
    "| :---: | " + " | ".join([":---:"] * len(ROLE_IDS)) + " |",
]
for cat in CRUD_ORDER:
    row = " | ".join(str(totals[rid][cat]) for rid in ROLE_IDS)
    lines.append(f"| **{cat}** | {row} |")
total_row = " | ".join(str(sum(totals[rid].values())) for rid in ROLE_IDS)
lines.append(f"| **Total** | {total_row} |")

lines += [""]

# ── Notes ─────────────────────────────────────────────────────────────────────
lines += [
    "---",
    "",
    H(2, "Role Reference"),
    "",
    "| # | Full Name | Role Type | `is_default` | Defined In |",
    "| --- | --- | --- | :---: | --- |",
    "| 1 | Root Admin | Admin | ✅ | `create-default-role-api-mappings.sql` – wildcard `*` ALLOW |",
    "| 2 | Resource Admin | ResourceAdmin | ✅ | `create-default-role-api-mappings.sql` |",
    "| 3 | Domain Admin | DomainAdmin | ✅ | `create-default-role-api-mappings.sql` |",
    "| 4 | User | User | ✅ | `create-default-role-api-mappings.sql` |",
    "| 5 | Read-Only Admin – Default | Admin | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |",
    "| 6 | Read-Only User – Default | User | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |",
    "| 7 | Support Admin – Default | Admin | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |",
    "| 8 | Support User – Default | User | ✅ | `schema-41400to41500` + `Upgrade41400to41500.java` |",
    "| 9 | Project Kubernetes Service Role | User | 🚫 | `KubernetesClusterManagerImpl.java` (created on-demand per cluster) |",
    "",
    H(2, "Read-Only Admin wildcard evaluation (first-match-wins)"),
    "",
    "```",
    "list*                  → ALLOW",
    "getUploadParamsFor*    → DENY  (overrides get* below)",
    "get*                   → ALLOW",
    "cloudianIsEnabled      → ALLOW",
    "queryAsyncJobResult    → ALLOW",
    "quotaIsEnabled         → ALLOW",
    "quotaTariffList        → ALLOW",
    "quotaSummary           → ALLOW",
    "quotaStatement         → ALLOW  (added by schema-41720to41800)",
    "quotaBalance           → ALLOW  (added by schema-41720to41800)",
    "setupUserTwoFactorAuthentication          → ALLOW  (added by schema-41910to41920)",
    "validateUserTwoFactorAuthenticationCode   → ALLOW  (added by schema-41910to41920)",
    "quotaCreditsList       → ALLOW  (added by schema-42010to42100)",
    "*                      → DENY",
    "```",
    "",
    H(2, "Read-Only User derivation"),
    "",
    "All `list%` and `get%` (excluding `getUploadParamsFor%`) ALLOW rules are copied from the",
    "**User** role at migration time, then a fixed set of extras is appended, and a catch-all",
    "`* DENY` terminates the rule list.",
    "",
    H(2, "Support roles"),
    "",
    "- **Support Admin** = all Read-Only Admin ALLOWs + VM lifecycle + storage maintenance + offering creation + ISO/template registration",
    "- **Support User** = all Read-Only User ALLOWs + VM lifecycle + volume/ISO/template ops + `getUploadParamsFor*` ALLOW",
    "",
    H(2, "Key migration changes"),
    "",
    "| Migration File | Change |",
    "| --- | --- |",
    "| `schema-41400to41500.sql` + `Upgrade41400to41500.java` | Creates roles 5–8 with initial permissions |",
    "| `schema-41610to41700.sql` | Adds `listConfigurations`, `updateConfiguration` to Domain Admin |",
    "| `schema-41720to41800.sql` | Removes `migrateVolume` from all non-Admin `is_default` roles; adds `assignVolume` to Resource Admin & Domain Admin; adds `quotaStatement`/`quotaBalance` to Read-Only Admin & Read-Only User; adds `isAccountAllowedToCreateOfferingsWithTags` to Domain Admin |",
    "| `schema-41910to41920.sql` + `schema-42000to42010.sql` | Adds 2FA APIs to Read-Only and Support roles (idempotent pair) |",
    "| `schema-42010to42100.sql` | Adds `quotaCreditsList` to every role that already has `quotaStatement` |",
]

output = "\n".join(lines) + "\n"
with open(OUT_FILE, "w") as f:
    f.write(output)

print(f"\nWritten → {OUT_FILE}")
