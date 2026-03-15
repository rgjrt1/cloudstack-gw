"""
Tests for src/permission.py
"""
import pytest

from src.group_parser import parse_groups
from src.permission import check_permission


# ---------------------------------------------------------------------------
# Root-level grants
# ---------------------------------------------------------------------------

class TestRootAdmin:
    def _parsed(self, groups):
        return parse_groups(groups)

    def test_root_admin_allows_any_command(self):
        p = self._parsed(["CS_ROOT_ADMIN"])
        assert check_permission(p, "deleteVirtualMachine")
        assert check_permission(p, "createAccount")
        assert check_permission(p, "listDomains")

    def test_root_operations_allows_any_command(self):
        p = self._parsed(["CS_ROOT_OPERATIONS"])
        assert check_permission(p, "deployVirtualMachine")
        assert check_permission(p, "createNetwork")

    def test_root_readonly_allows_list_commands(self):
        p = self._parsed(["CS_ROOT_READONLY"])
        assert check_permission(p, "listVirtualMachines")
        assert check_permission(p, "listDomains")
        assert check_permission(p, "getVMPassword")
        assert check_permission(p, "queryAsyncJobResult")

    def test_root_readonly_denies_create_commands(self):
        p = self._parsed(["CS_ROOT_READONLY"])
        assert not check_permission(p, "createAccount")
        assert not check_permission(p, "deployVirtualMachine")
        assert not check_permission(p, "deleteVirtualMachine")

    def test_no_groups_denies_all(self):
        p = self._parsed([])
        assert not check_permission(p, "listVirtualMachines")
        assert not check_permission(p, "createAccount")

    def test_non_cs_groups_denies_all(self):
        p = self._parsed(["developers", "cloud-admins"])
        assert not check_permission(p, "listDomains")


# ---------------------------------------------------------------------------
# Domain-level grants
# ---------------------------------------------------------------------------

class TestDomainGrants:
    def test_domain_admin_allows_all_in_domain(self):
        p = parse_groups(["CS_ORGX_ADMIN"])
        assert check_permission(p, "createVirtualMachine", domain_name="ORGX")
        assert check_permission(p, "deleteVirtualMachine", domain_name="ORGX")

    def test_domain_operations_allows_all_in_domain(self):
        p = parse_groups(["CS_ORGX_OPERATIONS"])
        assert check_permission(p, "deployVirtualMachine", domain_name="ORGX")

    def test_domain_readonly_allows_list_in_domain(self):
        p = parse_groups(["CS_ORGX_READONLY"])
        assert check_permission(p, "listVirtualMachines", domain_name="ORGX")

    def test_domain_readonly_denies_create_in_domain(self):
        p = parse_groups(["CS_ORGX_READONLY"])
        assert not check_permission(p, "createVirtualMachine", domain_name="ORGX")

    def test_domain_grant_does_not_apply_to_other_domain(self):
        p = parse_groups(["CS_ORGX_ADMIN"])
        # Domain is ORGY — no match
        assert not check_permission(p, "listVirtualMachines", domain_name="ORGY")

    def test_domain_grant_without_domain_context_allowed_for_admin(self):
        # Domain admin CAN operate without domain context: CloudStack scopes it
        # to their session domain (oidc/<domain>).
        p = parse_groups(["CS_ORGX_ADMIN"])
        assert check_permission(p, "createVirtualMachine")
        assert check_permission(p, "listVirtualMachines")

    def test_domain_readonly_without_domain_context_allows_reads_only(self):
        p = parse_groups(["CS_ORGX_READONLY"])
        assert check_permission(p, "listVirtualMachines")
        assert not check_permission(p, "createVirtualMachine")

    def test_domain_grant_still_denied_for_wrong_domain_with_context(self):
        # Explicit domain mismatch is still denied
        p = parse_groups(["CS_ORGX_ADMIN"])
        assert not check_permission(p, "listVirtualMachines", domain_name="ORGY")

    def test_case_insensitive_domain_match(self):
        p = parse_groups(["CS_ORGX_ADMIN"])
        assert check_permission(p, "listVMs", domain_name="orgx")


# ---------------------------------------------------------------------------
# Project grants
# ---------------------------------------------------------------------------

class TestProjectGrants:
    def test_project_user_allowed_for_matching_project(self):
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert check_permission(
            p, "listVirtualMachines", domain_name="ORGX", project_key="P1"
        )

    def test_project_user_allowed_without_domain_context(self):
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        # When domain_name is unknown we still allow if project matches
        assert check_permission(p, "listVirtualMachines", project_key="P1")

    def test_project_user_denied_for_different_project(self):
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert not check_permission(
            p, "listVirtualMachines", domain_name="ORGX", project_key="P2"
        )

    def test_project_user_read_allowed_without_context(self):
        # Project users CAN make read commands with no context — CloudStack
        # scopes the response to their session (e.g. listUsers self-lookup
        # at SPA startup).
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert check_permission(p, "listVirtualMachines")
        assert check_permission(p, "listUsers")

    def test_project_user_write_denied_without_context(self):
        # Write commands still require explicit project context for project users
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert not check_permission(p, "deployVirtualMachine")

    def test_project_user_denied_for_wrong_domain(self):
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert not check_permission(
            p, "listVirtualMachines", domain_name="ORGY", project_key="P1"
        )

    def test_case_insensitive_project_match(self):
        p = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert check_permission(p, "listVMs", project_key="p1")


# ---------------------------------------------------------------------------
# Combined grants
# ---------------------------------------------------------------------------

class TestCombinedGrants:
    def test_root_admin_plus_domain_allows_everything(self):
        p = parse_groups(["CS_ROOT_ADMIN", "CS_ORGX_READONLY"])
        # Root admin supersedes everything
        assert check_permission(p, "deleteAccount")
        assert check_permission(p, "createAccount")

    def test_multiple_domain_grants(self):
        p = parse_groups(["CS_ORG1_ADMIN", "CS_ORG2_READONLY"])
        assert check_permission(p, "createVM", domain_name="ORG1")
        assert check_permission(p, "listVMs", domain_name="ORG2")
        assert not check_permission(p, "createVM", domain_name="ORG2")

    def test_domain_admin_plus_project(self):
        # Domain admin can do anything in the domain; project grant is redundant
        p = parse_groups(["CS_ORGX_ADMIN", "CS_ORGX_PRJ_P1_USER"])
        assert check_permission(p, "createVM", domain_name="ORGX")
        assert check_permission(p, "listVMs", domain_name="ORGX", project_key="P1")
