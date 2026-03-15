# cloudstack-gw — Session Memory File
> Last updated: 2026-02-28 — written after workstation crash recovery

---

## Current project state

**Status: COMPLETE and FUNCTIONAL.**
- All 156 unit tests pass (`pytest tests/ -v`).
- No git repository has been initialised yet — the next action is `git init && git push`.
- The `cloudstack/` directory in the workspace is the upstream Apache CloudStack source tree used only for reference; it is never modified.
- `.gitignore` already excludes `config.yaml`, `.env.local`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `*.egg-info/`, `dist/`, `.venv/`.

---

## What this project IS

A **standalone OIDC-to-CloudStack reverse proxy / gateway**.

```
Browser → cloudstack-gw (:8080) → CloudStack API / UI
```

- **No oauth2-proxy involved.** The gateway IS the OIDC relying party.
- It implements the full Authorization Code flow itself (`src/oidc_auth.py`).
- It auto-provisions CloudStack objects on first login, then proxies traffic transparently.
- Users authenticate once; the browser gets a signed `oidcgw_session` cookie plus real CloudStack JSESSIONID / sessionkey / userid cookies so the Vue SPA works without modification.

---

## Major migration completed just before the crash

We **replaced the old `group_mappings` config model** with a **convention-based `CS_*` group naming scheme**.

### Old approach (removed)
- `config.yaml` had an explicit `group_mappings:` list with `group`, `priority`, `role_type`, `permissions` per entry.
- `AppConfig` had `GroupMapping` and `PermissionEntry` pydantic models.
- The provisioner created a unique `oidc-<group-slug>` account and role per group.
- Per-account role permissions were reconciled on every login.

### New approach (current)
- No `group_mappings` section in config.
- Groups are parsed purely by naming convention — the `CS_*` prefix signals access.
- Two **shared** accounts are created per CloudStack domain:
  - `oidc-admin` (role: `oidc-admin-role`, type Admin) — for ADMIN/OPERATIONS/READONLY users
  - `oidc-user` (role: `oidc-user-role`, type User) — for project-only users
- Real per-user permission enforcement is in the **proxy tier** (`src/permission.py`), not in CloudStack roles.
- `AppConfig` ignores extra keys (`model_config = ConfigDict(extra="ignore")`) so old config files with `group_mappings:` still load without error during migration.

---

## Group naming convention

| Group pattern | Meaning |
|---|---|
| `CS_ROOT_ADMIN` | Root domain, admin |
| `CS_ROOT_OPERATIONS` | Root domain, operator |
| `CS_ROOT_READONLY` | Root domain, read-only |
| `CS_<DOMAIN>_ADMIN` | Named domain, admin (use hyphens in domain name, not underscores) |
| `CS_<DOMAIN>_OPERATIONS` | Named domain, operator |
| `CS_<DOMAIN>_READONLY` | Named domain, read-only |
| `CS_<DOMAIN>_PRJ_<PROJECT>_USER` | Project member in named domain |

- Groups **not** matching `CS_` prefix are silently ignored.
- Privilege order: `ADMIN > OPERATIONS > READONLY`; highest wins per domain.
- Domain names and project keys are normalised to UPPERCASE internally.
- `ROOT` is special — resolves to the CloudStack root domain, not a subdomain.

Parser: `src/group_parser.py` → returns `ParsedGroups` with `domain_access: list[DomainAccess]` and `project_access: list[ProjectAccess]`.

---

## Architecture decisions and gotchas

### CloudStack session establishment at OIDC callback
After the OIDC callback completes provisioning, the middleware:
1. Generates a random one-shot password.
2. Calls `updateUser` to set that password.
3. Calls the unauthenticated CS `login` API to create a real Jetty HTTP session.
4. Forwards `JSESSIONID`, `sessionkey`, and `userid` cookies to the browser.

This lets the CloudStack Vue SPA work without modification — it sees a normal CS session.

The JSESSIONID is set with `path="/"` so it is visible regardless of whether the browser is on `/client` or `/`.

### raw_claims excluded from session cookie
Entra ID tokens can be several KB. If `raw_claims` were stored in the cookie, Jetty returns HTTP 431 (Request Header Fields Too Large). The cookie only stores `sub`, `email`, `preferred_username`, `groups`. The `raw_claims` dict is only available during the callback handler (used for the `/auth/denied` debug page).

### Proxy strips the gateway session cookie upstream
`_proxy_request` strips the `oidcgw_session` cookie from forwarded requests so CloudStack never sees it (it would be meaningless to CloudStack and could overflow Jetty headers).

### _PENDING_STATES is process-local
The OIDC state/nonce store is a simple `dict` in `oidc_auth.py`. Multi-replica deployments require a shared Redis store. Single-instance deployments are fine as-is.

### authlib for JWT validation
`oidc_auth.py` imports `authlib.jose` at call time. If authlib is not installed, it falls back to unsafe base64 decode (no signature check). **authlib is NOT listed in requirements.txt** — add it for production:
```
authlib>=1.3.0
```

### Entra ID / GUID groups
When Entra ID emits group Object IDs (GUIDs) instead of display names, set `oidc.graph_group_lookup: true`. The middleware calls Microsoft Graph `/users/{oid}/transitiveMemberOf` using client credentials. Requires `GroupMember.Read.All` app permission with admin consent. Also handles the Entra "groups overage" scenario (when a user has too many groups for the token).

### CloudStack async jobs
`CloudStackClient` polls async jobs until completion. Do not add extra polling elsewhere.

### slugify
`models.slugify()` MUST be used for any CloudStack object name derived from user input (lowercases, replaces non-alphanumeric with hyphens, truncates to 60 chars).

---

## Module map

| File | Lines | Responsibility |
|---|---|---|
| `src/main.py` | 78 | Uvicorn entry point; wires config → dependencies → `build_app()` |
| `src/middleware.py` | 622 | FastAPI app, OIDC routes, proxy catch-all, CS session creation |
| `src/oidc_auth.py` | 349 | Authorization Code flow, JWKS validation, session cookie sign/verify |
| `src/provisioner.py` | 411 | Idempotent CS object creation (domains, accounts, users, projects) |
| `src/permission.py` | ~100 | Proxy-tier ACL — all real access control |
| `src/group_parser.py` | 153 | `CS_*` group name → `ParsedGroups` |
| `src/cloudstack_client.py` | 524 | Async CS API client with HMAC-SHA1 signing |
| `src/cache.py` | 167 | `MemoryCache` / `RedisCache` with TTL |
| `src/reconciler.py` | 270 | Background loop; disables orphaned users, cleans empty accounts |
| `src/models.py` | 170 | Pydantic v2 config + domain models; `slugify()` |
| `src/graph_client.py` | 187 | Microsoft Graph client: GUID→displayName, groups overage |
| `src/config.py` | 68 | YAML loader with `${ENV_VAR:default}` interpolation |

---

## API endpoints

| Path | Method | Description |
|---|---|---|
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe (checks CS + OIDC reachability) |
| `/auth/callback` | GET | OIDC Authorization Code callback |
| `/auth/logout` | GET | Clear session cookie, redirect to `/` |
| `/auth/me` | GET | Current identity JSON (debug) |
| `/auth/denied` | GET | Styled 403 page — user authenticated but no `CS_*` groups |
| `/admin/cache/clear` | POST | Invalidate provisioning cache |
| `/admin/reconcile` | POST | Trigger manual reconciliation run |
| `/{path:path}` | ANY | Main proxy — provision if needed, check permission, forward to CS |

---

## Configuration (config.yaml)

Key sections:
```yaml
cloudstack:
  api_url: "..."          # CS API endpoint
  api_key: "..."          # Root admin API key (for provisioning)
  secret_key: "..."
  domain_path: "/oidc"    # All OIDC objects live under this path
  verify_ssl: true
  timeout: 30

server:
  upstream_url: "..."     # CS management server URL (for proxying)
  port: 8080
  log_level: "INFO"

cache:
  type: "memory"          # or "redis"
  redis_url: "redis://..."
  ttl: 300

oidc:
  issuer_url: "..."       # OIDC discovery URL
  client_id: "..."
  client_secret: "..."
  redirect_uri: "https://your-gw/auth/callback"
  groups_claim: "groups"
  scopes: ["openid", "email", "profile", "groups"]
  session_secret: "..."   # openssl rand -hex 32
  session_ttl: 3600
  graph_group_lookup: false   # Set true for Entra ID with GUID groups

reconciliation:
  enabled: true
  interval: 3600
  disable_orphaned_users: true
  cleanup_empty_accounts: false
```
Env-var interpolation: `${VAR_NAME}` and `${VAR_NAME:default}` anywhere in the file.

---

## Testing

```bash
# All tests (from cloudstack-gw/ directory)
pytest tests/ -v

# Targeted
pytest tests/test_provisioner.py -v
pytest tests/test_middleware.py -v
pytest tests/test_permission.py -v
pytest tests/test_group_parser.py -v

# Run the app locally
CONFIG_PATH=config.yaml python -m src.main
```

Test patterns:
- `AsyncMock` + `MagicMock` for CS client doubles.
- `respx` for HTTP mocking in OIDC / Graph client tests.
- `pytest-asyncio` with `asyncio_mode = auto` (in `pytest.ini`) — no `@pytest.mark.asyncio` needed.
- Pydantic v2: use `AppConfig.model_validate({...})` in tests, not `parse_obj`.

---

## Docker

```bash
# Standalone (no oauth2-proxy needed anymore)
docker compose up -d
# Exposes middleware on :8080 only

# Required env vars
CS_API_KEY=...
CS_SECRET_KEY=...
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant>/v2.0
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_SESSION_SECRET=$(openssl rand -hex 32)
```

The `docker-compose.yml` **no longer has an oauth2-proxy service** — that was removed as part of the migration to standalone OIDC mode.

---

## Next steps / TODOs

1. **Initialise git and push.**
   ```bash
   cd cloudstack-gw
   git init
   git add .
   git commit -m "feat: standalone OIDC gateway, CS_* group model, 156 tests passing"
   git remote add origin <your-remote>
   git push -u origin main
   ```

2. **Add `authlib` to `requirements.txt`** for production JWT signature verification:
   ```
   authlib>=1.3.0
   ```
   Currently if authlib is absent the ID token signature is skipped (warning logged).

3. **Redis-backed OIDC state store** for multi-replica deployments.
   `_PENDING_STATES` in `oidc_auth.py` is process-local. Replace it with a Redis-backed dict for HA.

4. **Smoke test against a real CloudStack instance.**
   `smoke_test.py` exists in the root — review and run it.

5. **Admin endpoint auth.** `/admin/cache/clear` and `/admin/reconcile` are currently unauthenticated. Consider protecting them with a shared secret header or restricting by source IP in the reverse proxy layer.

6. **Entra groups overage.** Tested in code, but worth verifying with a real Entra tenant that has >150 group memberships per user.

7. **(Optional) `itsdangerous` rotation.** Session cookies are signed with a static `session_secret`. No key rotation mechanism exists yet.

---

## File layout reminder

```
cloudstack-gw/
  src/
    __init__.py
    cache.py
    cloudstack_client.py
    config.py
    graph_client.py
    group_parser.py
    main.py
    middleware.py
    models.py
    oidc_auth.py
    permission.py
    provisioner.py
    reconciler.py
  tests/
    __init__.py
    test_cloudstack_client.py
    test_graph_client.py
    test_group_parser.py
    test_middleware.py
    test_models.py
    test_permission.py
    test_provisioner.py
  config.example.yaml   # copy to config.yaml and fill in
  config.yaml           # gitignored — real secrets here
  .env.local            # gitignored — local env overrides
  docker-compose.yml    # standalone middleware only (:8080)
  Dockerfile
  pytest.ini
  requirements.txt
  README.md
  MEMORY.md             # this file
  smoke_test.py
  get_cs_keys.py        # helper: fetch root admin API keys from CS
```
