"""
Tests for the CloudStack API client — signing, response parsing, async job polling.
"""
import base64
import hashlib
import hmac
import urllib.parse

import pytest
import respx
import httpx

from src.cloudstack_client import CloudStackClient, CloudStackError


BASE_URL = "https://cs.example.com/client/api"
API_KEY = "testapikey"
SECRET = "testsecret"


def make_client() -> CloudStackClient:
    return CloudStackClient(
        api_url=BASE_URL,
        api_key=API_KEY,
        secret_key=SECRET,
        verify_ssl=False,
        timeout=5,
    )


def expected_signature(params: dict) -> str:
    """Reproduce the signing algorithm to verify client correctness."""
    sorted_pairs = sorted(params.items(), key=lambda kv: kv[0].lower())
    query = "&".join(
        f"{k.lower()}={urllib.parse.quote_plus(str(v)).lower()}"
        for k, v in sorted_pairs
    )
    digest = hmac.new(
        SECRET.encode(),
        query.encode(),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode()


class TestCloudStackSigning:
    def test_sign_basic(self):
        client = make_client()
        params = {"command": "listDomains", "apiKey": API_KEY, "response": "json"}
        sig = client._sign(params, SECRET)
        assert sig == expected_signature(params)

    def test_sign_case_insensitive_sort(self):
        client = make_client()
        params_a = {"Command": "listDomains", "ApiKey": API_KEY, "Response": "json"}
        params_b = {"command": "listDomains", "apiKey": API_KEY, "response": "json"}
        # Both should produce the same signature since keys are lowercased
        assert client._sign(params_a, SECRET) == client._sign(params_b, SECRET)

    def test_build_url_contains_signature(self):
        client = make_client()
        url = client._build_url("listDomains")
        assert "signature=" in url
        assert "command=listdomains" in url.lower()

    def test_build_url_none_params_excluded(self):
        client = make_client()
        url = client._build_url("listDomains", name=None)
        assert "name=" not in url


@pytest.mark.asyncio
class TestCloudStackClient:
    @respx.mock
    async def test_list_domains_success(self):
        route = respx.get(BASE_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "listdomainsresponse": {
                        "count": 1,
                        "domain": [{"id": "d-1", "name": "oidc"}],
                    }
                },
            )
        )
        client = make_client()
        async with client:
            domains = await client.list_domains(name="oidc")
        assert len(domains) == 1
        assert domains[0]["name"] == "oidc"

    @respx.mock
    async def test_error_response_raises(self):
        respx.get(BASE_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "createaccountresponse": {
                        "errorcode": 431,
                        "errortext": "Unable to create account, account already exists",
                    }
                },
            )
        )
        client = make_client()
        async with client:
            with pytest.raises(CloudStackError) as exc_info:
                await client.create_account(
                    account_name="test",
                    account_type=0,
                    email="t@t.com",
                    firstname="T",
                    lastname="T",
                    username="tuser",
                    password="pass",
                )
        assert exc_info.value.errorcode == 431

    @respx.mock
    async def test_async_job_polling(self):
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(str(request.url)).query))
            cmd = qs.get("command", "")
            if cmd.lower() == "createproject":
                return httpx.Response(
                    200,
                    json={"createprojectresponse": {"jobid": "job-123"}},
                )
            # queryAsyncJobResult
            if call_count < 4:
                return httpx.Response(
                    200,
                    json={
                        "queryasyncjobresultresponse": {
                            "asyncjobs": [{"jobstatus": 0, "jobid": "job-123"}]
                        }
                    },
                )
            return httpx.Response(
                200,
                json={
                    "queryasyncjobresultresponse": {
                        "asyncjobs": [
                            {
                                "jobstatus": 1,
                                "jobid": "job-123",
                                "jobresult": {"project": {"id": "p-1", "name": "oidc-proj-dev"}},
                            }
                        ]
                    }
                },
            )

        respx.get(BASE_URL).mock(side_effect=side_effect)

        client = make_client()
        async with client:
            result = await client._call_async("createProject", name="oidc-proj-dev", displaytext="test")
        assert result.get("project", {}).get("id") == "p-1"

    @respx.mock
    async def test_probe_returns_true_on_success(self):
        respx.get(BASE_URL).mock(
            return_value=httpx.Response(
                200,
                json={"listapisresponse": {"count": 1, "api": []}},
            )
        )
        client = make_client()
        async with client:
            ok = await client.probe()
        assert ok is True

    @respx.mock
    async def test_probe_returns_false_on_error(self):
        respx.get(BASE_URL).mock(side_effect=httpx.ConnectError("refused"))
        client = make_client()
        async with client:
            ok = await client.probe()
        assert ok is False

    @respx.mock
    async def test_move_user_sends_id_not_userid(self):
        """Regression: moveUser must send 'id', not 'userid' (CS error 431)."""
        captured: dict = {}

        def handler(request):
            qs = request.url.query
            if isinstance(qs, bytes):
                qs = qs.decode()
            captured.update(dict(urllib.parse.parse_qsl(qs)))
            # CloudStack moveUser returns SuccessResponse, not a user object
            return httpx.Response(200, json={
                "moveuserresponse": {"success": "true"}
            })

        respx.get(BASE_URL).mock(side_effect=handler)
        client = make_client()
        async with client:
            result = await client.move_user("usr-1", "acc-2")

        assert "id" in captured, "moveUser must send 'id' parameter"
        assert "userid" not in captured, "moveUser must NOT send 'userid' parameter"
        assert captured["id"] == "usr-1"
        assert result is True, "move_user() should return True on success"

    @respx.mock
    async def test_update_user_sends_id_and_kwargs(self):
        """update_user must call updateUser with id=user_id and the extra kwargs."""
        captured: dict = {}

        def handler(request):
            qs = request.url.query
            if isinstance(qs, bytes):
                qs = qs.decode()
            captured.update(dict(urllib.parse.parse_qsl(qs)))
            return httpx.Response(200, json={
                "updateuserresponse": {"user": {"id": "usr-1", "username": "alice"}}
            })

        respx.get(BASE_URL).mock(side_effect=handler)
        client = make_client()
        async with client:
            result = await client.update_user("usr-1", password="newpass")

        assert captured["command"] == "updateUser"
        assert captured["id"] == "usr-1"
        assert captured["password"] == "newpass"
        assert result == {"id": "usr-1", "username": "alice"}

    @respx.mock
    async def test_login_user_posts_to_api_url(self):
        """login_user must POST command=login with username/password/domainId."""
        captured_body: dict = {}

        def handler(request):
            captured_body.update(dict(urllib.parse.parse_qsl(request.content.decode())))
            return httpx.Response(200, json={
                "loginresponse": {
                    "sessionkey": "sk-abc",
                    "userid": "uid-123",
                    "account": "oidc-admin",
                    "domainid": "dom-1",
                }
            })

        respx.post(BASE_URL).mock(side_effect=handler)
        client = make_client()
        login_resp, cookies = await client.login_user(
            "alice", "secret", domain_id="dom-uuid-1"
        )

        assert captured_body["command"] == "login"
        assert captured_body["username"] == "alice"
        assert captured_body["password"] == "secret"
        assert captured_body["domainId"] == "dom-uuid-1"
        assert captured_body["response"] == "json"
        assert login_resp["sessionkey"] == "sk-abc"
        assert login_resp["userid"] == "uid-123"
        # cookies is empty dict when no Set-Cookie headers (httpx default)
        assert isinstance(cookies, dict)

    @respx.mock
    async def test_login_user_raises_on_http_error(self):
        """login_user must raise CloudStackError if the HTTP status is not 200."""
        respx.post(BASE_URL).mock(return_value=httpx.Response(401, text="Unauthorized"))
        client = make_client()
        with pytest.raises(CloudStackError) as exc_info:
            await client.login_user("alice", "wrong")
        assert exc_info.value.errorcode == 401

    @respx.mock
    async def test_login_user_raises_on_api_error(self):
        """login_user must raise CloudStackError when the JSON contains errorcode."""
        respx.post(BASE_URL).mock(return_value=httpx.Response(200, json={
            "loginresponse": {"errorcode": 531, "errortext": "invalid credentials"}
        }))
        client = make_client()
        with pytest.raises(CloudStackError) as exc_info:
            await client.login_user("alice", "wrong")
        assert exc_info.value.errorcode == 531
        assert "invalid credentials" in str(exc_info.value)

    @respx.mock
    async def test_login_user_without_domain_id(self):
        """login_user works without domainId (defaults to ROOT domain)."""
        captured_body: dict = {}

        def handler(request):
            captured_body.update(dict(urllib.parse.parse_qsl(request.content.decode())))
            return httpx.Response(200, json={
                "loginresponse": {"sessionkey": "sk-root", "userid": "uid-root"}
            })

        respx.post(BASE_URL).mock(side_effect=handler)
        client = make_client()
        await client.login_user("bob", "pass123")

        assert "domainId" not in captured_body
        assert captured_body["username"] == "bob"
