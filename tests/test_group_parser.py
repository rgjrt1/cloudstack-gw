"""
Tests for src/group_parser.py
"""
import pytest

from src.group_parser import (
    DomainAccess,
    ParsedGroups,
    PermLevel,
    ProjectAccess,
    parse_groups,
)


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------

class TestParseGroupsBasic:
    def test_empty_list_returns_empty_result(self):
        result = parse_groups([])
        assert result.domain_access == []
        assert result.project_access == []
        assert not result.has_any_access

    def test_non_cs_groups_ignored(self):
        result = parse_groups(["developers", "cloud-admins", "viewers"])
        assert not result.has_any_access

    def test_root_admin(self):
        result = parse_groups(["CS_ROOT_ADMIN"])
        assert len(result.domain_access) == 1
        assert result.domain_access[0] == DomainAccess(domain="ROOT", level=PermLevel.ADMIN)

    def test_root_operations(self):
        result = parse_groups(["CS_ROOT_OPERATIONS"])
        assert result.domain_access[0].level == PermLevel.OPERATIONS

    def test_root_readonly(self):
        result = parse_groups(["CS_ROOT_READONLY"])
        assert result.domain_access[0].level == PermLevel.READONLY

    def test_domain_admin(self):
        result = parse_groups(["CS_ORGX_ADMIN"])
        assert len(result.domain_access) == 1
        da = result.domain_access[0]
        assert da.domain == "ORGX"
        assert da.level == PermLevel.ADMIN

    def test_domain_is_uppercased(self):
        result = parse_groups(["CS_myOrg_READONLY"])
        assert result.domain_access[0].domain == "MYORG"

    def test_project_user(self):
        result = parse_groups(["CS_ORGX_PRJ_MYPROJ_USER"])
        assert len(result.project_access) == 1
        pa = result.project_access[0]
        assert pa.domain == "ORGX"
        assert pa.project == "MYPROJ"

    def test_project_key_is_uppercased(self):
        result = parse_groups(["CS_ORGX_PRJ_myProj_USER"])
        assert result.project_access[0].project == "MYPROJ"

    def test_cs_prefix_case_sensitive(self):
        # lowercase "cs_" must not match
        result = parse_groups(["cs_ROOT_ADMIN"])
        assert not result.has_any_access

    def test_mixed_cs_and_non_cs(self):
        result = parse_groups(["developers", "CS_ROOT_ADMIN", "viewers"])
        assert len(result.domain_access) == 1
        assert not result.project_access


# ---------------------------------------------------------------------------
# Deduplication / highest-level wins
# ---------------------------------------------------------------------------

class TestHighestLevelDeduplication:
    def test_duplicate_domain_keeps_highest(self):
        result = parse_groups(["CS_ORGX_READONLY", "CS_ORGX_ADMIN"])
        assert len(result.domain_access) == 1
        assert result.domain_access[0].level == PermLevel.ADMIN

    def test_operations_beats_readonly(self):
        result = parse_groups(["CS_ROOT_READONLY", "CS_ROOT_OPERATIONS"])
        assert result.domain_access[0].level == PermLevel.OPERATIONS

    def test_admin_beats_operations(self):
        result = parse_groups(["CS_ROOT_OPERATIONS", "CS_ROOT_ADMIN"])
        assert result.domain_access[0].level == PermLevel.ADMIN

    def test_project_duplicates_deduplicated(self):
        result = parse_groups(["CS_ORGX_PRJ_P1_USER", "CS_ORGX_PRJ_P1_USER"])
        assert len(result.project_access) == 1


# ---------------------------------------------------------------------------
# Multi-domain / multi-project
# ---------------------------------------------------------------------------

class TestMultiDomainAndProject:
    def test_two_domains(self):
        result = parse_groups(["CS_ORG1_ADMIN", "CS_ORG2_READONLY"])
        domains = {da.domain: da.level for da in result.domain_access}
        assert domains["ORG1"] == PermLevel.ADMIN
        assert domains["ORG2"] == PermLevel.READONLY

    def test_root_and_domain_grants_coexist(self):
        result = parse_groups(["CS_ROOT_ADMIN", "CS_ORGX_READONLY"])
        assert len(result.domain_access) == 2

    def test_multiple_projects_same_domain(self):
        result = parse_groups(["CS_ORGX_PRJ_P1_USER", "CS_ORGX_PRJ_P2_USER"])
        projects = {pa.project for pa in result.project_access}
        assert projects == {"P1", "P2"}

    def test_projects_across_domains(self):
        result = parse_groups(["CS_ORG1_PRJ_PROJ_USER", "CS_ORG2_PRJ_PROJ_USER"])
        assert len(result.project_access) == 2
        domains = {pa.domain for pa in result.project_access}
        assert domains == {"ORG1", "ORG2"}


# ---------------------------------------------------------------------------
# ParsedGroups convenience properties
# ---------------------------------------------------------------------------

class TestParsedGroupsProperties:
    def test_is_root_admin_true(self):
        result = parse_groups(["CS_ROOT_ADMIN"])
        assert result.is_root_admin

    def test_is_root_admin_false_for_operations(self):
        result = parse_groups(["CS_ROOT_OPERATIONS"])
        assert not result.is_root_admin

    def test_is_admin_true_for_any_admin_grant(self):
        result = parse_groups(["CS_ORGX_ADMIN"])
        assert result.is_admin

    def test_is_admin_false_for_readonly_only(self):
        result = parse_groups(["CS_ORGX_READONLY"])
        assert not result.is_admin

    def test_is_admin_false_for_project_only(self):
        result = parse_groups(["CS_ORGX_PRJ_P_USER"])
        assert not result.is_admin

    def test_level_for_domain_returns_correct(self):
        result = parse_groups(["CS_ORGX_OPERATIONS"])
        assert result.level_for_domain("ORGX") == PermLevel.OPERATIONS
        assert result.level_for_domain("orgx") == PermLevel.OPERATIONS

    def test_level_for_domain_returns_none_for_absent(self):
        result = parse_groups(["CS_ORGX_ADMIN"])
        assert result.level_for_domain("ORGY") is None

    def test_has_project_access(self):
        result = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert result.has_project_access("ORGX", "P1")
        assert result.has_project_access("orgx", "p1")  # case-insensitive

    def test_has_project_access_false(self):
        result = parse_groups(["CS_ORGX_PRJ_P1_USER"])
        assert not result.has_project_access("ORGX", "P2")

    def test_projects_for_domain(self):
        result = parse_groups([
            "CS_ORGX_PRJ_P1_USER",
            "CS_ORGX_PRJ_P2_USER",
            "CS_ORGY_PRJ_P3_USER",
        ])
        orgx_projects = set(result.projects_for_domain("ORGX"))
        assert orgx_projects == {"P1", "P2"}
        assert result.projects_for_domain("ORGZ") == []


# ---------------------------------------------------------------------------
# Domain names with hyphens
# ---------------------------------------------------------------------------

class TestHyphenatedDomains:
    def test_hyphen_in_domain_name(self):
        result = parse_groups(["CS_MY-ORG_ADMIN"])
        assert result.domain_access[0].domain == "MY-ORG"

    def test_hyphen_in_project_key(self):
        result = parse_groups(["CS_ORGX_PRJ_MY-PROJ_USER"])
        assert result.project_access[0].project == "MY-PROJ"
