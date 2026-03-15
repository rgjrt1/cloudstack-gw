"""
Tests for src/graph_client.py

Covers:
  - looks_like_guids / extract_tenant_id helpers
  - GraphClient._get_token: success, caching, failure
  - GraphClient.get_user_groups: success, pagination, API error
  - GraphClient.resolve_group_display_names: happy path, empty result, error swallowed
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from src.graph_client import (
    GraphClient,
    GraphClientError,
    extract_tenant_id,
    looks_like_guids,
)

# ---------------------------------------------------------------------------
# Helper constants
# ---------------------------------------------------------------------------

_TENANT = "ae54efc5-598d-4a9c-af25-f60456fed429"
_CLIENT_ID = "feaa8cb9-7083-4a7c-98dd-e03c774902bf"
_CLIENT_SECRET = "supersecret"
_OID = "00000000-0000-0000-0000-000000000001"
_TOKEN_URL = f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
_GROUPS_URL = f"https://graph.microsoft.com/v1.0/users/{_OID}/transitiveMemberOf/microsoft.graph.group"


def _make_client() -> GraphClient:
    return GraphClient(
        tenant_id=_TENANT,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
        verify_ssl=True,
    )


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

class TestLooksLikeGuids:
    def test_all_guids_returns_true(self):
        assert looks_like_guids([
            "3ff44980-d18f-4817-8382-b1fe101f1690",
            "48429743-07ec-4930-8a95-f4afebd1cb98",
        ]) is True

    def test_display_names_returns_false(self):
        assert looks_like_guids(["CS_ROOT_ADMIN", "CS_ROOT_READONLY"]) is False

    def test_mixed_returns_false(self):
        assert looks_like_guids(["3ff44980-d18f-4817-8382-b1fe101f1690", "CS_ROOT_ADMIN"]) is False

    def test_empty_list_returns_false(self):
        assert looks_like_guids([]) is False

    def test_uppercase_guids_are_recognised(self):
        assert looks_like_guids(["3FF44980-D18F-4817-8382-B1FE101F1690"]) is True


class TestExtractTenantId:
    def test_v2_issuer_url(self):
        url = f"https://login.microsoftonline.com/{_TENANT}/v2.0"
        assert extract_tenant_id(url) == _TENANT

    def test_sts_issuer_url(self):
        url = f"https://sts.windows.net/{_TENANT}/"
        assert extract_tenant_id(url) == _TENANT

    def test_no_uuid_returns_none(self):
        assert extract_tenant_id("https://accounts.google.com") is None

    def test_well_known_url_also_works(self):
        url = f"https://login.microsoftonline.com/{_TENANT}/v2.0/.well-known/openid-configuration"
        assert extract_tenant_id(url) == _TENANT


# ---------------------------------------------------------------------------
# GraphClient._get_token
# ---------------------------------------------------------------------------

class TestGetToken:
    @pytest.mark.asyncio
    @respx.mock
    async def test_acquires_token_on_first_call(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(
            200,
            json={"access_token": "tok-abc", "expires_in": 3600},
        ))

        client = _make_client()
        token = await client._get_token()

        assert token == "tok-abc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_cached_token_not_re_fetched(self):
        call_count = 0

        def handler(request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 3600})

        respx.post(_TOKEN_URL).mock(side_effect=handler)

        client = _make_client()
        await client._get_token()
        await client._get_token()

        assert call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_expired_token_is_renewed(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(
            200,
            json={"access_token": "tok-new", "expires_in": 3600},
        ))

        client = _make_client()
        client._token = "tok-old"
        client._token_expiry = time.monotonic() - 1  # already expired

        token = await client._get_token()
        assert token == "tok-new"

    @pytest.mark.asyncio
    @respx.mock
    async def test_http_error_raises_graph_client_error(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))

        client = _make_client()
        with pytest.raises(GraphClientError, match="token request failed"):
            await client._get_token()

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_access_token_in_response_raises(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(
            200,
            json={"error": "unauthorized_client", "error_description": "AADSTS70011"},
        ))

        client = _make_client()
        with pytest.raises(GraphClientError, match="missing access_token"):
            await client._get_token()


# ---------------------------------------------------------------------------
# GraphClient.get_user_groups
# ---------------------------------------------------------------------------

class TestGetUserGroups:
    def _token_mock(self):
        return respx.post(_TOKEN_URL).mock(return_value=httpx.Response(
            200,
            json={"access_token": "tok", "expires_in": 3600},
        ))

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_groups_list(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(200, json={
            "value": [
                {"id": "aaa", "displayName": "CS_ROOT_ADMIN"},
                {"id": "bbb", "displayName": "CS_ROOT_READONLY"},
            ]
        }))

        client = _make_client()
        groups = await client.get_user_groups(_OID)

        assert [g["displayName"] for g in groups] == ["CS_ROOT_ADMIN", "CS_ROOT_READONLY"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_pagination_followed(self):
        self._token_mock()
        page2_url = f"{_GROUPS_URL}?$skiptoken=abc"

        # respx.get(url) with no params specified matches ANY query string, so
        # both the first and second requests would match the same route and loop
        # forever.  Use side_effect with an iterator so successive calls to the
        # same URL pattern return different responses.
        pages = iter([
            httpx.Response(200, json={
                "value": [{"id": "aaa", "displayName": "Group A"}],
                "@odata.nextLink": page2_url,
            }),
            httpx.Response(200, json={
                "value": [{"id": "bbb", "displayName": "Group B"}],
            }),
        ])
        respx.get(_GROUPS_URL).mock(side_effect=lambda _req: next(pages))

        client = _make_client()
        groups = await client.get_user_groups(_OID)

        assert len(groups) == 2
        assert groups[0]["displayName"] == "Group A"
        assert groups[1]["displayName"] == "Group B"

    @pytest.mark.asyncio
    @respx.mock
    async def test_api_error_returns_empty_list(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(403, json={
            "error": {"code": "Authorization_RequestDenied"}
        }))

        client = _make_client()
        groups = await client.get_user_groups(_OID)

        assert groups == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_group_list(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(200, json={"value": []}))

        client = _make_client()
        groups = await client.get_user_groups(_OID)

        assert groups == []


# ---------------------------------------------------------------------------
# GraphClient.resolve_group_display_names
# ---------------------------------------------------------------------------

class TestResolveGroupDisplayNames:
    def _token_mock(self):
        return respx.post(_TOKEN_URL).mock(return_value=httpx.Response(
            200,
            json={"access_token": "tok", "expires_in": 3600},
        ))

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_display_names(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(200, json={
            "value": [
                {"id": "aaa", "displayName": "CS_ROOT_ADMIN"},
                {"id": "bbb", "displayName": "CS_DOMAIN_USER"},
            ]
        }))

        client = _make_client()
        names = await client.resolve_group_display_names(_OID)

        assert names == ["CS_ROOT_ADMIN", "CS_DOMAIN_USER"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_entries_without_displayname_skipped(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(200, json={
            "value": [
                {"id": "aaa"},                          # no displayName
                {"id": "bbb", "displayName": "CS_ROOT_ADMIN"},
                {"id": "ccc", "displayName": ""},       # empty — falsy, skipped
            ]
        }))

        client = _make_client()
        names = await client.resolve_group_display_names(_OID)

        assert names == ["CS_ROOT_ADMIN"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_failure_returns_empty_list(self):
        respx.post(_TOKEN_URL).mock(return_value=httpx.Response(401, json={"error": "invalid_client"}))

        client = _make_client()
        names = await client.resolve_group_display_names(_OID)

        assert names == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_api_error_returns_empty_list(self):
        self._token_mock()
        respx.get(_GROUPS_URL).mock(return_value=httpx.Response(403, json={}))

        client = _make_client()
        names = await client.resolve_group_display_names(_OID)

        assert names == []
