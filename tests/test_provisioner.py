"""
Tests for the per-user account Provisioner.

Per-user placement rules
------------------------
  Any ADMIN / OPERATIONS / READONLY grant  →  is_admin=True,  oidc-admin-role
  Project-only or no CS_* groups           →  is_admin=False, oidc-user-role

Account name = slugify(identity.sam_account_name)
Username     = same as account name
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cloudstack_client import CloudStackError
from src.models import AppConfig, OidcIdentity
from src.provisioner import Provisioner, _BUILTIN_ROOT_ADMIN_ROLE, _BUILTIN_DOMAIN_ADMIN_ROLE, _BUILTIN_USER_ROLE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_config() -> AppConfig:
    return AppConfig.model_validate({
        "cloudstack": {
            "api_url": "https://cs.example.com/client/api",
            "api_key": "k",
            "secret_key": "s",
        },
        "server": {"upstream_url": "https://cs.example.com"},
    })


def _make_cs() -> MagicMock:
    cs = MagicMock()

    cs.list_domains = AsyncMock(
        return_value=[{"id": "dom-root", "name": "ROOT", "level": 0}]
    )
    cs.create_domain = AsyncMock(
        side_effect=lambda name, parent_domain_id=None: {
            "id": f"dom-{name}", "name": name,
        }
    )
    cs.list_roles = AsyncMock(side_effect=lambda name="", **kw: (
        [{"id": f"role-{name}", "name": name}]
        if name in (_BUILTIN_ROOT_ADMIN_ROLE, _BUILTIN_DOMAIN_ADMIN_ROLE, _BUILTIN_USER_ROLE)
        else []
    ))
    cs.create_role = AsyncMock(
        side_effect=lambda name, role_type, description="": {
            "id": f"role-{name}", "name": name, "type": role_type,
        }
    )
    cs.update_role = AsyncMock(return_value={})
    cs.delete_role = AsyncMock(return_value=None)
    cs.list_role_permissions = AsyncMock(return_value=[])
    cs.create_role_permission = AsyncMock(return_value={})
    cs.list_accounts = AsyncMock(return_value=[])
    cs.create_account = AsyncMock(
        side_effect=lambda **kw: {
            "id": f"acc-{kw['account_name']}",
            "name": kw["account_name"],
            "roleid": kw.get("role_id", ""),
        }
    )
    cs.update_account = AsyncMock(
        side_effect=lambda **kw: {"id": kw["account_id"], "name": "updated"}
    )
    cs.list_users = AsyncMock(return_value=[])
    cs.create_user = AsyncMock(
        side_effect=lambda **kw: {
            "id": f"user-{kw['username']}",
            "username": kw["username"],
            "accountid": f"acc-{kw['account']}",
            "account": kw["account"],
        }
    )
    cs.get_user_keys = AsyncMock(
        return_value={"apikey": "ak123", "secretkey": "sk456"}
    )
    cs.register_user_keys = AsyncMock(
        return_value={"apikey": "new-ak", "secretkey": "new-sk"}
    )
    cs.list_projects = AsyncMock(return_value=[])
    cs.create_project = AsyncMock(
        side_effect=lambda **kw: {"id": f"proj-{kw['name']}", "name": kw["name"]}
    )
    cs.list_project_accounts = AsyncMock(return_value=[])
    cs.add_account_to_project = AsyncMock()
    cs.remove_account_from_project = AsyncMock()
    return cs


def _identity(**kw) -> OidcIdentity:
    return OidcIdentity(
        sub=kw.get("sub", "user-123"),
        email=kw.get("email", "user@example.com"),
        preferred_username=kw.get("preferred_username", "alice.smith@corp.example.com"),
        given_name=kw.get("given_name", "Alice"),
        family_name=kw.get("family_name", "Smith"),
        groups=kw.get("groups", []),
    )


# ---------------------------------------------------------------------------
# Account naming — sAMAccountName-based
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAccountNaming:
    async def test_account_named_after_preferred_username_local_part(self):
        """Account name = slugify(local part of preferred_username UPN)."""
        result = await Provisioner(_make_cs(), _make_config()).provision(
            _identity(preferred_username="alice.smith@corp.example.com")
        )
        assert result.account_name == "alice-smith"

    async def test_account_name_uses_email_when_no_preferred_username(self):
        result = await Provisioner(_make_cs(), _make_config()).provision(
            _identity(preferred_username="", email="bob@example.com")
        )
        assert result.account_name == "bob"

    async def test_account_name_falls_back_to_sub(self):
        result = await Provisioner(_make_cs(), _make_config()).provision(
            _identity(sub="sub-abc-123", preferred_username="", email="")
        )
        assert result.account_name == "sub-abc-123"

    async def test_user_slug_matches_account_name(self):
        result = await Provisioner(_make_cs(), _make_config()).provision(_identity())
        assert result.user_slug == result.account_name

    async def test_result_contains_root_domain_id(self):
        result = await Provisioner(_make_cs(), _make_config()).provision(_identity())
        assert result.domain_id == "dom-root"

    async def test_result_sub_and_email_preserved(self):
        result = await Provisioner(_make_cs(), _make_config()).provision(
            _identity(sub="alice-123", email="alice@example.com")
        )
        assert result.sub == "alice-123"
        assert result.email == "alice@example.com"


# ---------------------------------------------------------------------------
# Admin vs user role assignment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRoleAssignment:
    async def test_root_admin_gets_rootadmin_role(self):
        """CS_ROOT_ADMIN → built-in 'Root Admin' role, account_type=1."""
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN"])
        )
        kw = cs.create_account.call_args.kwargs
        assert kw["role_id"] == f"role-{_BUILTIN_ROOT_ADMIN_ROLE}"
        assert kw["account_type"] == 1

    async def test_domain_admin_gets_admin_role(self):
        """Domain-level admin (no CS_ROOT_ADMIN) → oidc-admin-role, account_type=2."""
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_ADMIN"])
        )
        kw = cs.create_account.call_args.kwargs
        assert kw["role_id"] == f"role-{_BUILTIN_DOMAIN_ADMIN_ROLE}"
        assert kw["account_type"] == 2

    async def test_user_gets_user_role(self):
        """No domain grants → oidc-user-role, account_type=0."""
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        kw = cs.create_account.call_args.kwargs
        assert kw["role_id"] == f"role-{_BUILTIN_USER_ROLE}"
        assert kw["account_type"] == 0

    async def test_root_admin_with_extra_groups_still_rootadmin(self):
        """CS_ROOT_ADMIN supersedes all other groups."""
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN", "CS_ORGX_ADMIN", "CS_ORGX_PRJ_WEB_USER"])
        )
        kw = cs.create_account.call_args.kwargs
        assert kw["role_id"] == f"role-{_BUILTIN_ROOT_ADMIN_ROLE}"
        assert kw["account_type"] == 1

    async def test_root_admin_is_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN"])
        )).is_admin is True

    async def test_root_operations_is_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ROOT_OPERATIONS"])
        )).is_admin is True

    async def test_root_readonly_is_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ROOT_READONLY"])
        )).is_admin is True

    async def test_domain_admin_is_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ORGX_ADMIN"])
        )).is_admin is True

    async def test_project_only_not_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )).is_admin is False

    async def test_no_groups_not_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=[])
        )).is_admin is False

    async def test_unknown_groups_not_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["SOME_RANDOM_GROUP"])
        )).is_admin is False

    async def test_mixed_admin_and_project_is_admin(self):
        assert (await Provisioner(_make_cs(), _make_config()).provision(
            _identity(groups=["CS_ORGX_ADMIN", "CS_ORGX_PRJ_WEB_USER"])
        )).is_admin is True


# ---------------------------------------------------------------------------
# Account role update on privilege change
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPrivilegeChange:
    async def test_account_role_updated_when_promoted(self):
        """User gains root-admin access — existing account role is updated."""
        cs = _make_cs()
        rootadmin_role_id = f"role-{_BUILTIN_ROOT_ADMIN_ROLE}"
        user_role_id = f"role-{_BUILTIN_USER_ROLE}"
        cs.list_accounts = AsyncMock(return_value=[{
            "id": "acc-alice-smith", "name": "alice-smith", "roleid": user_role_id,
        }])
        cs.list_roles = AsyncMock(side_effect=lambda name="", **kw: (
            [{"id": f"role-{name}", "name": name}]
            if name in (_BUILTIN_ROOT_ADMIN_ROLE, _BUILTIN_DOMAIN_ADMIN_ROLE, _BUILTIN_USER_ROLE)
            else []
        ))

        await Provisioner(cs, _make_config()).provision(_identity(groups=["CS_ROOT_ADMIN"]))

        cs.update_account.assert_called_once()
        kw = cs.update_account.call_args.kwargs
        assert kw["account_id"] == "acc-alice-smith"
        assert kw["role_id"] == rootadmin_role_id

    async def test_account_role_not_updated_when_unchanged(self):
        """Role already correct — update_account must not be called."""
        cs = _make_cs()
        rootadmin_role_id = f"role-{_BUILTIN_ROOT_ADMIN_ROLE}"
        cs.list_accounts = AsyncMock(return_value=[{
            "id": "acc-alice-smith", "name": "alice-smith", "roleid": rootadmin_role_id,
        }])
        cs.list_roles = AsyncMock(side_effect=lambda name="", **kw: (
            [{"id": f"role-{name}", "name": name}]
            if name in (_BUILTIN_ROOT_ADMIN_ROLE, _BUILTIN_DOMAIN_ADMIN_ROLE, _BUILTIN_USER_ROLE)
            else []
        ))

        await Provisioner(cs, _make_config()).provision(_identity(groups=["CS_ROOT_ADMIN"]))
        cs.update_account.assert_not_called()

# User creation details
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestUserDetails:
    async def test_user_created_with_given_and_family_name(self):
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(
            _identity(given_name="Alice", family_name="Smith")
        )
        kw = cs.create_user.call_args.kwargs
        assert kw["firstname"] == "Alice"
        assert kw["lastname"] == "Smith"

    async def test_user_created_with_email(self):
        cs = _make_cs()
        await Provisioner(cs, _make_config()).provision(_identity(email="alice@corp.com"))
        assert cs.create_user.call_args.kwargs["email"] == "alice@corp.com"

    async def test_existing_user_not_recreated(self):
        cs = _make_cs()
        account_name = "alice-smith"
        account_id = f"acc-{account_name}"
        admin_role_id = f"role-{_BUILTIN_DOMAIN_ADMIN_ROLE}"
        cs.list_accounts = AsyncMock(return_value=[{
            "id": account_id, "name": account_name, "roleid": admin_role_id,
        }])
        cs.list_users = AsyncMock(return_value=[{
            "id": "usr-alice-smith", "username": account_name,
            "accountid": account_id, "account": account_name,
        }])
        cs.list_roles = AsyncMock(side_effect=lambda name="", **kw: (
            [{"id": f"role-{name}", "name": name}]
            if name in (_BUILTIN_ROOT_ADMIN_ROLE, _BUILTIN_DOMAIN_ADMIN_ROLE, _BUILTIN_USER_ROLE)
            else []
        ))

        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN"])
        )
        cs.create_user.assert_not_called()
        assert result.user_id == "usr-alice-smith"


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestProjects:
    async def test_project_membership_assigned_when_project_exists(self):
        """When CS has a matching project, the user is added and the ID is recorded."""
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[{"id": "proj-web", "name": "web"}])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        cs.create_project.assert_not_called()  # NEVER creates
        assert "WEB" in result.project_ids

    async def test_project_not_created_when_not_found(self):
        """When CS has no matching project, create_project is never called."""
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[])  # no projects in CS
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_MYAPP_USER"])
        )
        cs.create_project.assert_not_called()
        assert "MYAPP" not in result.project_ids  # skipped, not created

    async def test_existing_project_found_without_oidc_prefix(self):
        """Project lookup uses the raw key (lowercased), not an oidc- prefix."""
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[{"id": "proj-web", "name": "web"}])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        cs.create_project.assert_not_called()
        assert result.project_ids["WEB"] == "proj-web"

    async def test_account_added_to_project(self):
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[{"id": "proj-web", "name": "web"}])
        await Provisioner(cs, _make_config()).provision(
            _identity(preferred_username="alice@corp.com", groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        cs.add_account_to_project.assert_called_once()

    async def test_multiple_projects_tracked(self):
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[
            {"id": "proj-alpha", "name": "alpha"},
            {"id": "proj-beta",  "name": "beta"},
        ])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_ALPHA_USER", "CS_ORGX_PRJ_BETA_USER"])
        )
        assert "ALPHA" in result.project_ids
        assert "BETA" in result.project_ids

    async def test_project_ids_keyed_by_uppercase_project_key(self):
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[{"id": "proj-myproj", "name": "myproj"}])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_MYPROJ_USER"])
        )
        assert "MYPROJ" in result.project_ids

    async def test_project_match_is_case_insensitive(self):
        """A CS project named with mixed-case matches the lowercased group key."""
        cs = _make_cs()
        cs.list_projects = AsyncMock(return_value=[{"id": "proj-web", "name": "Web"}])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        assert "WEB" in result.project_ids
        cs.create_project.assert_not_called()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestApiKeys:
    async def test_existing_keys_returned_without_registration(self):
        cs = _make_cs()
        cs.get_user_keys = AsyncMock(return_value={"apikey": "ak123", "secretkey": "sk456"})
        result = await Provisioner(cs, _make_config()).provision(_identity())
        assert result.api_key == "ak123"
        assert result.secret_key == "sk456"
        cs.register_user_keys.assert_not_called()

    async def test_new_keys_registered_when_none_exist(self):
        cs = _make_cs()
        cs.get_user_keys = AsyncMock(return_value={})
        cs.register_user_keys = AsyncMock(
            return_value={"apikey": "new-ak", "secretkey": "new-sk"}
        )
        result = await Provisioner(cs, _make_config()).provision(_identity())
        assert result.api_key == "new-ak"
        cs.register_user_keys.assert_called_once()


# ---------------------------------------------------------------------------
# Domain handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDomainHandling:
    async def test_root_admin_lands_in_root(self):
        """CS_ROOT_ADMIN → ROOT domain."""
        cs = _make_cs()
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN"])
        )
        assert result.domain_id == "dom-root"
        cs.create_domain.assert_not_called()

    async def test_no_groups_lands_in_root(self):
        """No CS_* groups → ROOT domain (fallback)."""
        cs = _make_cs()
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=[])
        )
        assert result.domain_id == "dom-root"
        cs.create_domain.assert_not_called()

    async def test_domain_admin_lands_in_their_domain(self):
        """CS_ORGX_ADMIN → account created in the orgx domain."""
        cs = _make_cs()
        cs.list_domains = AsyncMock(return_value=[])  # no domains exist yet
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_ADMIN"])
        )
        cs.create_domain.assert_called_once_with("orgx")
        assert result.domain_id == "dom-orgx"

    async def test_existing_domain_not_recreated(self):
        """If the domain already exists it is reused, not recreated."""
        cs = _make_cs()
        cs.list_domains = AsyncMock(
            return_value=[{"id": "dom-orgx-existing", "name": "orgx", "level": 1}]
        )
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_ADMIN"])
        )
        cs.create_domain.assert_not_called()
        assert result.domain_id == "dom-orgx-existing"

    async def test_root_readonly_lands_in_root(self):
        """CS_ROOT_READONLY has domain=ROOT in parser → ROOT domain."""
        cs = _make_cs()
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_READONLY"])
        )
        assert result.domain_id == "dom-root"
        cs.create_domain.assert_not_called()

    async def test_project_only_user_lands_in_their_domain(self):
        """CS_ORGX_PRJ_WEB_USER → account in orgx domain."""
        cs = _make_cs()
        cs.list_domains = AsyncMock(return_value=[])
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_PRJ_WEB_USER"])
        )
        cs.create_domain.assert_called_once_with("orgx")
        assert result.domain_id == "dom-orgx"

    async def test_highest_privilege_domain_wins(self):
        """Multi-domain user: highest-privilege domain is chosen."""
        cs = _make_cs()
        cs.list_domains = AsyncMock(return_value=[])
        # ORGX=READONLY, ORGY=ADMIN → ORGY wins
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ORGX_READONLY", "CS_ORGY_ADMIN"])
        )
        cs.create_domain.assert_called_once_with("orgy")
        assert result.domain_id == "dom-orgy"

    async def test_root_domain_id_by_name_match(self):
        """Root domain id is taken from the ROOT-named domain in the response."""
        cs = _make_cs()
        cs.list_domains = AsyncMock(
            return_value=[{"id": "dom-root-alt", "name": "ROOT", "level": 0}]
        )
        result = await Provisioner(cs, _make_config()).provision(
            _identity(groups=["CS_ROOT_ADMIN"])
        )
        assert result.domain_id == "dom-root-alt"


# ---------------------------------------------------------------------------
# Role type mismatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestBuiltinRoles:
    async def test_no_roles_created_for_any_tier(self):
        """The gateway never calls create_role — all three tiers use built-in roles."""
        for groups in (["CS_ROOT_ADMIN"], ["CS_ORGX_ADMIN"], ["CS_ORGX_PRJ_WEB_USER"], []):
            cs = _make_cs()
            await Provisioner(cs, _make_config()).provision(_identity(groups=groups))
            cs.create_role.assert_not_called()

    async def test_role_permissions_never_modified(self):
        """Built-in roles are looked up only — create_role_permission is never called."""
        for groups in (["CS_ROOT_ADMIN"], ["CS_ORGX_ADMIN"], []):
            cs = _make_cs()
            await Provisioner(cs, _make_config()).provision(_identity(groups=groups))
            cs.create_role_permission.assert_not_called()

    async def test_missing_builtin_role_raises(self):
        """If a built-in role is absent from CS, CloudStackError is raised."""
        cs = _make_cs()
        cs.list_roles = AsyncMock(return_value=[])  # nothing found
        with pytest.raises(CloudStackError):
            await Provisioner(cs, _make_config()).provision(_identity())


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestErrorHandling:
    async def test_cloudstack_error_on_account_creation_propagates(self):
        cs = _make_cs()
        cs.create_account = AsyncMock(side_effect=CloudStackError(431, "quota exceeded"))
        with pytest.raises(CloudStackError):
            await Provisioner(cs, _make_config()).provision(_identity())

    async def test_cloudstack_error_when_builtin_role_missing(self):
        """If a built-in role cannot be found, CloudStackError propagates."""
        cs = _make_cs()
        cs.list_roles = AsyncMock(return_value=[])
        with pytest.raises(CloudStackError):
            await Provisioner(cs, _make_config()).provision(_identity())
