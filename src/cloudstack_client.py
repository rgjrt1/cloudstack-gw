"""
Async CloudStack API client with HMAC-SHA1 request signing.

Signing algorithm (matches CloudStack's ApiServer.java verifier):
  1. Build params dict: {command, apiKey, response=json, ...extra}
  2. Sort params by key, case-insensitively
  3. URL-encode each value using Java URLEncoder semantics:
       - safe chars: A-Z a-z 0-9 * - . _  (note: * is safe, ~ is NOT)
       - spaces → %20  (Java uses + but ApiServer replaces + with %20)
     In Python: urllib.parse.quote(value, safe='*')
  4. Lowercase the key (already lowercase for all CS params)
  5. Concatenate as key=value pairs with '&', lowercase the whole string
  6. HMAC-SHA1 sign the concatenated string with the secret key
  7. Base64-encode the HMAC digest, then URL-encode the result
  8. Append as ?signature=... to the final request
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import urllib.parse
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# How long to wait between async-job polls (seconds)
_POLL_INTERVAL = 2
# Maximum number of poll attempts before giving up
_POLL_MAX_ATTEMPTS = 60


class CloudStackError(Exception):
    """Raised when CloudStack returns an error response."""

    def __init__(self, errorcode: int, errortext: str) -> None:
        super().__init__(f"CloudStack error {errorcode}: {errortext}")
        self.errorcode = errorcode
        self.errortext = errortext


class CloudStackClient:
    """Async CloudStack API client."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        secret_key: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._secret_key = secret_key
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "CloudStackClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=self._verify_ssl,
                timeout=self._timeout,
            )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Request signing
    # ------------------------------------------------------------------

    @staticmethod
    def _sign(params: dict[str, str], secret_key: str) -> str:
        """Return the HMAC-SHA1 base64 signature for the given params dict.

        CloudStack's server-side verifier (ApiServer.java) uses Java's
        URLEncoder.encode() + replaceAll("\\+", "%20") to re-encode each
        parameter value, then lowercases the entire string.  Java's
        URLEncoder treats * (asterisk) as a safe character and leaves it
        unencoded, whereas Python's urllib.parse.quote with safe='' would
        encode it as %2A.  We must add '*' to safe= so that the signing
        string matches what CloudStack computes server-side.

        Safe chars in Java URLEncoder: A-Z a-z 0-9  *  -  .  _
        """
        # Sort by lowercase key
        sorted_pairs = sorted(params.items(), key=lambda kv: kv[0].lower())
        # Build query string: lowercase key, percent-encode value (%20 for
        # spaces; * left unencoded to match Java URLEncoder behaviour).
        query_string = "&".join(
            f"{k.lower()}={urllib.parse.quote(str(v), safe='*').lower()}"
            for k, v in sorted_pairs
        )
        digest = hmac.new(
            secret_key.encode("utf-8"),
            query_string.encode("utf-8"),
            hashlib.sha1,
        ).digest()
        return base64.b64encode(digest).decode("utf-8")

    def _build_url(self, command: str, **kwargs: Any) -> str:
        """Build a signed CloudStack API URL."""
        params: dict[str, str] = {
            "command": command,
            "apiKey": self._api_key,
            "response": "json",
        }
        for k, v in kwargs.items():
            if v is not None:
                params[k] = str(v)

        sig = self._sign(params, self._secret_key)
        params["signature"] = sig
        return f"{self._api_url}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"

    # ------------------------------------------------------------------
    # Core HTTP call
    # ------------------------------------------------------------------

    async def _call(self, command: str, **kwargs: Any) -> dict[str, Any]:
        """Execute a CloudStack API command and return the inner response dict.

        Raises :class:`CloudStackError` on API-level errors.
        """
        await self._ensure_client()
        assert self._client is not None

        url = self._build_url(command, **kwargs)
        logger.debug("CloudStack API call: %s", command)

        resp = await self._client.get(url)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise CloudStackError(
                exc.response.status_code,
                f"HTTP {exc.response.status_code} from CloudStack on {command}: {exc.response.text[:200]}",
            ) from exc
        data = resp.json()

        # CloudStack wraps the response in a key like "createaccountresponse"
        response_key = f"{command.lower()}response"
        inner = data.get(response_key, data)

        if "errorcode" in inner:
            raise CloudStackError(inner["errorcode"], inner.get("errortext", "unknown error"))

        return inner

    # ------------------------------------------------------------------
    # Async job polling
    # ------------------------------------------------------------------

    async def _poll_async_job(self, job_id: str) -> dict[str, Any]:
        """Poll queryAsyncJobResult until the job completes.

        Returns the ``jobresult`` dict on success.
        Raises :class:`CloudStackError` if the job fails.
        """
        for attempt in range(_POLL_MAX_ATTEMPTS):
            await asyncio.sleep(_POLL_INTERVAL)
            inner = await self._call("queryAsyncJobResult", jobid=job_id)
            job = inner.get("asyncjobs", [inner])[0] if "asyncjobs" in inner else inner

            status = job.get("jobstatus", 0)
            if status == 0:
                logger.debug("Async job %s still pending (attempt %d)", job_id, attempt + 1)
                continue
            if status == 1:
                return job.get("jobresult", {})
            # status == 2 → error
            result = job.get("jobresult", {})
            raise CloudStackError(
                result.get("errorcode", -1),
                result.get("errortext", "async job failed"),
            )

        raise TimeoutError(f"Async job {job_id} did not complete after {_POLL_MAX_ATTEMPTS} attempts")

    async def _call_async(self, command: str, **kwargs: Any) -> dict[str, Any]:
        """Execute a command that may return an async job and wait for completion."""
        inner = await self._call(command, **kwargs)
        job_id = inner.get("jobid")
        if job_id:
            return await self._poll_async_job(job_id)
        return inner

    # ------------------------------------------------------------------
    # Domain operations
    # ------------------------------------------------------------------

    async def list_domains(self, name: str | None = None, **kwargs: Any) -> list[dict]:
        inner = await self._call("listDomains", name=name, listall=True, **kwargs)
        return inner.get("domain", [])

    async def create_domain(self, name: str, parent_domain_id: str | None = None) -> dict:
        kwargs: dict[str, Any] = {"name": name}
        if parent_domain_id:
            kwargs["parentdomainid"] = parent_domain_id
        inner = await self._call("createDomain", **kwargs)
        return inner.get("domain", inner)

    # ------------------------------------------------------------------
    # Role operations
    # ------------------------------------------------------------------

    async def list_roles(self, name: str | None = None, **kwargs: Any) -> list[dict]:
        inner = await self._call("listRoles", name=name, **kwargs)
        return inner.get("role", [])

    async def create_role(self, name: str, role_type: str, description: str = "") -> dict:
        inner = await self._call(
            "createRole",
            name=name,
            type=role_type,
            description=description,
        )
        return inner.get("role", inner)

    async def list_role_permissions(self, role_id: str) -> list[dict]:
        inner = await self._call("listRolePermissions", roleid=role_id)
        return inner.get("rolepermission", [])

    async def create_role_permission(
        self,
        role_id: str,
        rule: str,
        permission: str,
        description: str = "",
    ) -> dict:
        inner = await self._call(
            "createRolePermission",
            roleid=role_id,
            rule=rule,
            permission=permission,
            description=description,
        )
        return inner.get("rolepermission", inner)

    async def update_role(self, role_id: str, role_type: str) -> dict:
        inner = await self._call("updateRole", id=role_id, type=role_type)
        return inner.get("role", inner)

    async def delete_role(self, role_id: str) -> None:
        await self._call("deleteRole", id=role_id)

    async def delete_role_permission(self, permission_id: str) -> None:
        await self._call("deleteRolePermission", id=permission_id)

    # ------------------------------------------------------------------
    # Account operations
    # ------------------------------------------------------------------

    async def list_accounts(
        self,
        name: str | None = None,
        domain_id: str | None = None,
        **kwargs: Any,
    ) -> list[dict]:
        inner = await self._call(
            "listAccounts",
            name=name,
            domainid=domain_id,
            listall=True,
            **kwargs,
        )
        return inner.get("account", [])

    async def create_account(
        self,
        account_name: str,
        account_type: int,
        email: str,
        firstname: str,
        lastname: str,
        username: str,
        password: str,
        domain_id: str | None = None,
        role_id: str | None = None,
    ) -> dict:
        kwargs: dict[str, Any] = {
            "accounttype": account_type,
            "email": email,
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "password": password,
            "account": account_name,
        }
        if domain_id:
            kwargs["domainid"] = domain_id
        if role_id:
            kwargs["roleid"] = role_id
        inner = await self._call("createAccount", **kwargs)
        return inner.get("account", inner)

    async def update_account(
        self,
        account_id: str,
        role_id: str | None = None,
        new_name: str | None = None,
    ) -> dict:
        kwargs: dict[str, Any] = {"id": account_id}
        if role_id:
            kwargs["roleid"] = role_id
        if new_name:
            kwargs["newname"] = new_name
        inner = await self._call("updateAccount", **kwargs)
        return inner.get("account", inner)

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------

    async def list_users(
        self,
        username: str | None = None,
        domain_id: str | None = None,
        account: str | None = None,
        **kwargs: Any,
    ) -> list[dict]:
        inner = await self._call(
            "listUsers",
            username=username,
            domainid=domain_id,
            account=account,
            listall=True,
            **kwargs,
        )
        return inner.get("user", [])

    async def create_user(
        self,
        account: str,
        email: str,
        firstname: str,
        lastname: str,
        username: str,
        password: str,
        domain_id: str | None = None,
    ) -> dict:
        kwargs: dict[str, Any] = {
            "account": account,
            "email": email,
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "password": password,
        }
        if domain_id:
            kwargs["domainid"] = domain_id
        inner = await self._call("createUser", **kwargs)
        return inner.get("user", inner)

    async def move_user(self, user_id: str, account_id: str) -> bool:
        """Move a user to a different account within the same domain.

        CloudStack's moveUser returns a SuccessResponse (not a user object),
        so the caller must use the original user id — it does not change.
        """
        inner = await self._call("moveUser", id=user_id, accountid=account_id)
        return str(inner.get("success", "false")).lower() == "true"

    async def update_user(self, user_id: str, **kwargs: Any) -> dict:
        """Update user attributes.

        Typical usage: ``await cs.update_user(user_id, password="new_cleartext")``
        CloudStack stores the password using the configured hashing scheme
        (default: SHA-256 with salt), so always pass the clear-text value here.
        """
        inner = await self._call("updateUser", id=user_id, **kwargs)
        return inner.get("user", inner)

    async def login_user(
        self,
        username: str,
        password: str,
        *,
        domain_id: str | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Authenticate via the unauthenticated ``login`` endpoint.

        This endpoint does not require API-key signing.  CloudStack validates
        the credentials and, on success, sets a ``JSESSIONID`` session cookie.

        Returns a ``(login_response_dict, cookies_dict)`` tuple where:
        - ``login_response_dict`` contains ``sessionkey``, ``userid``, etc.
        - ``cookies_dict`` contains server-side ``Set-Cookie`` values
          (typically ``JSESSIONID``).

        The ``password`` should be the *clear-text* value — CloudStack's own
        authenticators will hash it server-side before comparing.
        """
        post_data: dict[str, str] = {
            "command": "login",
            "username": username,
            "password": password,
            "response": "json",
        }
        if domain_id:
            post_data["domainId"] = domain_id

        # Use a fresh client so the user session cookie never contaminates the
        # shared admin client used for signed API calls.
        async with httpx.AsyncClient(
            verify=self._verify_ssl,
            timeout=self._timeout,
        ) as client:
            resp = await client.post(self._api_url, data=post_data)

        if resp.status_code not in (200,):
            raise CloudStackError(
                resp.status_code,
                f"login HTTP {resp.status_code}: {resp.text[:200]}",
            )

        data = resp.json()
        inner = data.get("loginresponse", data)
        if "errorcode" in inner:
            raise CloudStackError(
                inner["errorcode"],
                inner.get("errortext", "login failed"),
            )

        cookies: dict[str, str] = dict(resp.cookies)
        return inner, cookies

    async def disable_user(self, user_id: str) -> dict:
        inner = await self._call("disableUser", id=user_id)
        return inner.get("user", inner)

    # ------------------------------------------------------------------
    # API key operations
    # ------------------------------------------------------------------

    async def get_user_keys(self, user_id: str) -> dict:
        """Return {apikey, secretkey} for the user, or empty dict if none."""
        try:
            inner = await self._call("getUserKeys", id=user_id)
            return inner.get("userkeys", inner)
        except CloudStackError as exc:
            if exc.errorcode == 531:
                # No keys registered yet
                return {}
            raise

    async def register_user_keys(self, user_id: str) -> dict:
        inner = await self._call("registerUserKeys", id=user_id)
        return inner.get("userkeys", inner)

    # ------------------------------------------------------------------
    # Project operations
    # ------------------------------------------------------------------

    async def list_projects(
        self,
        name: str | None = None,
        domain_id: str | None = None,
        **kwargs: Any,
    ) -> list[dict]:
        inner = await self._call(
            "listProjects",
            name=name,
            domainid=domain_id,
            listall=True,
            **kwargs,
        )
        return inner.get("project", [])

    async def create_project(
        self,
        name: str,
        display_text: str,
        account: str | None = None,
        domain_id: str | None = None,
    ) -> dict:
        kwargs: dict[str, Any] = {"name": name, "displaytext": display_text}
        if account:
            kwargs["account"] = account
        if domain_id:
            kwargs["domainid"] = domain_id
        result = await self._call_async("createProject", **kwargs)
        return result.get("project", result)

    async def list_project_accounts(self, project_id: str) -> list[dict]:
        inner = await self._call("listProjectAccounts", projectid=project_id, listall=True)
        return inner.get("projectaccount", [])

    async def add_account_to_project(
        self,
        project_id: str,
        account: str,
        role_id: str | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {"projectid": project_id, "account": account}
        if role_id:
            kwargs["projectroleid"] = role_id
        await self._call("addAccountToProject", **kwargs)

    async def remove_account_from_project(
        self,
        project_id: str,
        account: str,
    ) -> None:
        await self._call(
            "removeAccountFromProject",
            projectid=project_id,
            account=account,
        )

    # ------------------------------------------------------------------
    # Connectivity probe
    # ------------------------------------------------------------------

    async def probe(self) -> bool:
        """Return True if we can reach the CloudStack API successfully."""
        try:
            await self._call("listApis", name="listApis")
            return True
        except Exception:
            return False
