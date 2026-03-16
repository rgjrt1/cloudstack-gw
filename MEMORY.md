# cloudstack-gw — Session Memory File
> Last updated: 2026-03-15

---

## Current project state

**Status: FUNCTIONAL — deployed locally, git repo live on GitHub.**

- All 156 unit tests pass (`pytest tests/ -v`).
- GitHub repo: `https://github.com/rgjrt1/cloudstack-gw` (`main` branch, latest commit `c352a3f`).
- Running locally at `http://127.0.0.1:9999` (port set via `.env.local`).
- `.gitignore` excludes `config.yaml`, `.env.local`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `*.egg-info/`, `dist/`, `.venv/`.
- `cloudstack/` in the workspace root is the upstream Apache CloudStack source — reference only, never modified.

---

## What this project IS

A **standalone OIDC-to-CloudStack reverse proxy / gateway**.

```
Browser → cloudstack-gw (:9999 dev / :8080 prod) → CloudStack API / UI
```

- **No oauth2-proxy.** The gateway IS the OIDC relying party.
- It implements the full Authorization Code flow itself (`src/oidc_auth.py`).
- Auto-provisions CloudStack objects on first login, then proxies traffic transparently.
- Users authenticate once; the browser gets a signed `oidcgw_session` cookie plus real CloudStack `JSESSIONID` / `sessionkey` / `userid` cookies so the Vue SPA works without modification.
- Injects a custom header bar + plugin overlay system into every CloudStack SPA page.

---

## Major migration (completed 2026-02)

Replaced the old `group_mappings` config model with a **convention-based `CS_*` group naming scheme**.

- Old: explicit `group_mappings:` list; unique `oidc-<group-slug>` account + role per group; per-account role permissions reconciled on every login.
- New: no `group_mappings` section; two shared accounts per domain (`oidc-admin`, `oidc-user`); real enforcement is in `src/permission.py`.

`AppConfig` has `model_config = ConfigDict(extra="ignore")` so old configs with `group_mappings:` still load without error.

---

## Injected UI bar system

`_inject_footer()` in `middleware.py` injects HTML + CSS + JS before `</body>` on every proxied page.

### Bar structure

```
#oidcgw-bar  (position:fixed; top:0; z-index:99999; height:64px — replaces native CS header)
  #gw-toggle        sidebar collapse button
  #gw-logo          CloudStack logo/text
  #gw-proj-wrap     project selector <select> (always shown; populated via listProjects fetch)
  [flex spacer]
  #gw-create-wrap   "+ Create" dropdown (shown only if create-able APIs exist)
  #gw-notify-wrap   notification bell
  #gw-role-badge    server-rendered role badge
  #gw-user-wrap
    #gw-user-btn    avatar + username (click to open dropdown)
    #gw-user-drop   user profile dropdown
      [plugin items] ← injected by window._gwAddPluginsToMenu()
      [separator]
      #gw-mi-profile
      #gw-mi-limits
      [separator]
      #gw-mi-signout
```

The native `.ant-layout-header` is hidden via `visibility:hidden` (keeps its layout dimensions).

### Plugin overlay system (`_PLUGIN_JS_TMPL`)

A separate `<script>` block injected **only when plugins are configured** (`visible_plugins` non-empty). It is a **plain Python string** (not f-string) — JS curly braces need no escaping.

```
#gw-plugin-ov  (position:fixed; top:64px; bottom:0; right:0; z-index:9000)
```

- `PLUGINS` — IIFE-local `var` populated from `/*PLUGINS_JSON*/` placeholder replaced at render time via `str.replace()`.
- `_onHash()` — called on `hashchange`, `popstate`, and a 300 ms `setInterval` poll (covers Vue Router 4 navigations that use `history.pushState` without firing either event). Shows overlay if hash matches a plugin, hides it otherwise.
- **`window._gwAddPluginsToMenu` hook** — exposed from inside the IIFE so the footer script can inject plugin shortcuts into `#gw-user-drop` without accessing the IIFE-local `PLUGINS` var. Called from `_initUser()` with a `typeof` guard.

### ⚠ Critical scope boundary

`_inject_footer()` is an **f-string** — all `{{` / `}}` in the source become literal `{` / `}` in output.  
`_PLUGIN_JS_TMPL` is a **plain string** — JS braces are already literal.  
**Never reference `PLUGINS` (or any `_PLUGIN_JS_TMPL`-local variable) from the footer f-string.** Use the `window._gwAddPluginsToMenu` hook pattern instead.

### Icons

`ui.plugins[*].icon` can be a named key or raw SVG. Named keys (e.g. `"table"`) are resolved via `_ICON_SVG_MAP` dict in `middleware.py` to AntD-compatible monochrome SVG paths.

### Project selector

- Always shown — no API-availability gate.
- `_initProject()` fetches `listProjects` with the sessionkey from `localStorage.getItem('primate__Access-Token')`.
- Server-side intercept in `proxy_request` catches `command=listProjects`:
  - Admins → `cs_client.list_projects()` (all projects).
  - Project-only users → loops over `provisioned.project_ids`.

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
| `src/main.py` | 69 | Uvicorn entry point; wires config → dependencies → `build_app()` |
| `src/middleware.py` | 2409 | FastAPI app, OIDC routes, proxy catch-all, CS session creation, injected UI bar |
| `src/oidc_auth.py` | 354 | Authorization Code flow, JWKS validation, session cookie sign/verify |
| `src/provisioner.py` | 431 | Idempotent CS object creation (domains, accounts, users, projects) |
| `src/permission.py` | 121 | Proxy-tier ACL — all real access control |
| `src/group_parser.py` | 152 | `CS_*` group name → `ParsedGroups` |
| `src/cloudstack_client.py` | 541 | Async CS API client with HMAC-SHA1 signing |
| `src/cache.py` | 166 | `MemoryCache` / `RedisCache` with TTL |
| `src/reconciler.py` | 269 | Background loop; disables orphaned users, cleans empty accounts |
| `src/models.py` | 224 | Pydantic v2 config + domain models; `slugify()` |
| `src/graph_client.py` | 186 | Microsoft Graph client: GUID→displayName, groups overage |
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
  domain_path: ""          # empty = ROOT domain; set to e.g. "/oidc" for a sub-domain
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

ui:
  plugins:
    - id: "access-map"
      label: "Access Map"
      icon: "table"       # named icon (resolved via _ICON_SVG_MAP) or raw SVG
      api_src: "/auth/me" # renders a JSON table; or use iframe_src / html
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

1. **Add `authlib` to `requirements.txt`** for production JWT signature verification:
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
  MEMORY.md
  smoke_test.py
  get_cs_keys.py
  gen_role_matrix.py
  CLOUDSTACK_ROLE_MATRIX.md
```
