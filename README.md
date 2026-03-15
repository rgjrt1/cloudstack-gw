# cloudstack-gw — OIDC Gateway for Apache CloudStack

A standalone Python/FastAPI reverse proxy that acts as its own **OIDC relying party** in front of Apache CloudStack. It authenticates users via the OpenID Connect Authorization Code flow, maps their IdP group memberships to CloudStack objects using a `CS_*` naming convention, auto-provisions those objects on first login, and transparently proxies all traffic upstream — without modifying any CloudStack code.

## Architecture

```
Browser → cloudstack-gw (:8080) → CloudStack API/UI
```

> No oauth2-proxy or other external authenticator is needed. The gateway handles the full OIDC flow itself.

On every request the gateway:

1. Reads identity from a signed `oidcgw_session` cookie (set at login).
2. If no valid session exists, redirects the browser to the IdP authorization endpoint.
3. On the OIDC callback: validates the ID token, resolves group memberships, and auto-provisions the required CloudStack objects (domains, shared accounts, user record, project memberships).
4. Establishes a real CloudStack HTTP session (`JSESSIONID` / `sessionkey` / `userid` cookies) so the CloudStack Vue SPA works natively.
5. Checks proxy-tier ACLs on every subsequent API call.
6. Forwards the request upstream.

## Quick Start

### Prerequisites (CloudStack admin)

```bash
# Generate root admin API keys for the gateway service account
# UI → Accounts → admin → View Keys
```

The gateway auto-creates the `/oidc` domain and all sub-objects on first login — no manual CloudStack setup is required.

### Configuration

```bash
cp config.example.yaml config.yaml
# Edit config.yaml or set environment variables (${VAR} / ${VAR:default} syntax supported)
```

Minimum required variables:

| Variable | Description |
|---|---|
| `CS_API_KEY` | CloudStack root admin API key |
| `CS_SECRET_KEY` | CloudStack root admin secret key |
| `OIDC_ISSUER_URL` | OIDC discovery URL (e.g. `https://login.microsoftonline.com/<tenant>/v2.0`) |
| `OIDC_CLIENT_ID` | OAuth2 client ID registered in your IdP |
| `OIDC_CLIENT_SECRET` | OAuth2 client secret |
| `OIDC_SESSION_SECRET` | Cookie signing secret (`openssl rand -hex 32`) |

### Running with Docker Compose

```bash
export CS_API_KEY=...
export CS_SECRET_KEY=...
export OIDC_ISSUER_URL=https://login.microsoftonline.com/TENANT/v2.0
export OIDC_CLIENT_ID=...
export OIDC_CLIENT_SECRET=...
export OIDC_SESSION_SECRET=$(openssl rand -hex 32)

docker compose up -d
```

The gateway listens on `:8080`.

### Running locally

```bash
pip install -r requirements.txt
source .env.local   # or export the variables above
CONFIG_PATH=config.yaml python -m src.main
```

## Group Naming Convention

Access is controlled entirely by IdP group names following the `CS_*` convention — no extra configuration in `config.yaml` is required.

| Group pattern | Access granted |
|---|---|
| `CS_ROOT_ADMIN` | Root CloudStack administrator |
| `CS_ROOT_OPERATIONS` | Root operator (most commands, no destructive deletes) |
| `CS_ROOT_READONLY` | Global read-only (`list*` / `get*` / `query*` only) |
| `CS_<DOMAIN>_ADMIN` | Administrator of the named CloudStack domain |
| `CS_<DOMAIN>_OPERATIONS` | Operator of the named domain |
| `CS_<DOMAIN>_READONLY` | Read-only access to the named domain |
| `CS_<DOMAIN>_PRJ_<KEY>_USER` | Project member in the named domain |

- Domain names use **hyphens**, not underscores (e.g. `CS_MY-ORG_ADMIN`).
- Groups not matching the `CS_` prefix are silently ignored.
- Privilege order: `ADMIN > OPERATIONS > READONLY` — highest level wins per domain.
- Users with no `CS_*` groups are shown an access-denied page (`/auth/denied`) after login.

### Account placement model

Two shared CloudStack accounts are maintained per domain — no per-user accounts:

| Account | Used for |
|---|---|
| `oidc-admin` | Users with any `ADMIN`, `OPERATIONS`, or `READONLY` domain grant |
| `oidc-user` | Users with project-only grants (`PRJ_*_USER`) |

All real per-user permission enforcement happens in the **proxy tier** (`permission.py`), not in CloudStack roles.

### Entra ID — GUID group resolution

When Entra ID emits group Object ID GUIDs instead of display names, set `oidc.graph_group_lookup: true`. The gateway calls the Microsoft Graph API at login time to resolve GUIDs to display names. Requires the `GroupMember.Read.All` application permission with admin consent in the app registration.

## CloudStack Object Naming

| Object | Name |
|---|---|
| Base domain | configured `cloudstack.domain_path` (default `/oidc`) |
| Sub-domain | `<domain-key>.lower()` under base path |
| Shared admin account | `oidc-admin` |
| Shared user account | `oidc-user` |
| Role | `oidc-admin-role` / `oidc-user-role` |
| User | `slugify(sub)` |
| Project | `oidc-<project-key>.lower()` |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe (checks CloudStack + OIDC provider) |
| `/auth/callback` | GET | OIDC Authorization Code callback |
| `/auth/logout` | GET | Clear session cookie, redirect to `/` |
| `/auth/me` | GET | Current user identity (JSON, for debugging) |
| `/auth/denied` | GET | Access-denied page (authenticated but no `CS_*` groups) |
| `/admin/cache/clear` | POST | Invalidate provisioning cache |
| `/admin/reconcile` | POST | Trigger manual reconciliation run |
| `/{path:path}` | ANY | Main proxy — provision if needed, ACL check, forward to CloudStack |

## Running Tests

```bash
pytest tests/ -v
```

## Cache

Two backends are supported:

- **`memory`** (default): process-local dict with TTL. Suitable for single-instance deployments.
- **`redis`**: shared TTL cache for multi-replica deployments. Set `cache.type: redis` and `cache.redis_url` in config.

Cache key format: `{sub}:{sha256(sorted_groups)[:16]}`

## Background Reconciliation

A background async task runs at `reconciliation.interval` seconds. It:

1. Lists all CloudStack accounts under the base domain matching the `oidc-*` prefix.
2. Checks users against the last-seen cache entry.
3. Optionally disables orphaned users (`disable_orphaned_users: true`).
4. Optionally removes empty accounts (`cleanup_empty_accounts: false` by default).

Trigger manually via `POST /admin/reconcile`.
