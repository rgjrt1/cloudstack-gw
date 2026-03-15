"""
Tests for Pydantic models and helpers.
"""
import pytest

from src.models import (
    AppConfig,
    CacheEntry,
    OidcIdentity,
    ProvisionedUser,
    slugify,
)


# ---------------------------------------------------------------------------
# slugify
# ---------------------------------------------------------------------------

class TestSlugify:
    def test_basic(self):
        assert slugify("cloud-admins") == "cloud-admins"

    def test_spaces_replaced(self):
        assert slugify("cloud admins") == "cloud-admins"

    def test_uppercase_lowercased(self):
        assert slugify("CloudAdmins") == "cloudadmins"

    def test_special_chars(self):
        assert slugify("cloud@admins!group") == "cloud-admins-group"

    def test_truncation(self):
        long = "a" * 100
        assert len(slugify(long)) == 60

    def test_leading_trailing_hyphens_stripped(self):
        assert slugify("@cloud@") == "cloud"

    def test_multiple_non_alphanum_collapsed(self):
        assert slugify("cloud---admins") == "cloud-admins"


# ---------------------------------------------------------------------------
# OidcIdentity
# ---------------------------------------------------------------------------

class TestOidcIdentity:
    def test_user_slug(self):
        identity = OidcIdentity(sub="user@example.com", groups=[])
        assert identity.user_slug == slugify("user@example.com")

    def test_groups_hash_stable(self):
        i1 = OidcIdentity(sub="alice", groups=["a", "b"])
        i2 = OidcIdentity(sub="alice", groups=["b", "a"])
        # Hash is based on sorted groups — order independent
        assert i1.groups_hash() == i2.groups_hash()

    def test_groups_hash_different_for_different_groups(self):
        i1 = OidcIdentity(sub="alice", groups=["a"])
        i2 = OidcIdentity(sub="alice", groups=["b"])
        assert i1.groups_hash() != i2.groups_hash()

    def test_cache_key_format(self):
        identity = OidcIdentity(sub="alice", groups=["dev"])
        key = identity.cache_key()
        assert key.startswith("alice:")
        assert len(key) == len("alice:") + 16  # 16 hex chars

    def test_empty_groups_hash_is_deterministic(self):
        i1 = OidcIdentity(sub="alice", groups=[])
        i2 = OidcIdentity(sub="alice", groups=[])
        assert i1.groups_hash() == i2.groups_hash()


# ---------------------------------------------------------------------------
# AppConfig
# ---------------------------------------------------------------------------

class TestAppConfig:
    def _minimal_config_dict(self):
        return {
            "cloudstack": {
                "api_url": "https://cs.example.com/client/api",
                "api_key": "key",
                "secret_key": "secret",
            },
            "server": {
                "upstream_url": "https://cs.example.com",
            },
        }

    def test_minimal_valid(self):
        cfg = AppConfig.model_validate(self._minimal_config_dict())
        assert cfg.cloudstack.api_url == "https://cs.example.com/client/api"

    def test_extra_keys_ignored(self):
        """Legacy group_mappings / default_mapping keys must not cause a validation error."""
        data = self._minimal_config_dict()
        data["group_mappings"] = [
            {"group": "admins", "priority": 1, "role_type": "Admin"}
        ]
        data["default_mapping"] = {"role_type": "User"}
        # Should not raise
        cfg = AppConfig.model_validate(data)
        assert cfg.cloudstack.api_key == "key"

    def test_reconciliation_defaults(self):
        cfg = AppConfig.model_validate(self._minimal_config_dict())
        assert cfg.reconciliation.interval == 3600
        assert cfg.reconciliation.disable_orphaned_users is True

    def test_oidc_none_when_not_configured(self):
        cfg = AppConfig.model_validate(self._minimal_config_dict())
        assert cfg.oidc is None


# ---------------------------------------------------------------------------
# ProvisionedUser / CacheEntry round-trip
# ---------------------------------------------------------------------------

class TestCacheEntry:
    def test_serialise_round_trip(self):
        identity = OidcIdentity(sub="alice", email="alice@example.com", groups=["CS_ROOT_ADMIN"])
        provisioned = ProvisionedUser(
            sub="alice",
            email="alice@example.com",
            user_slug="alice",
            account_name="oidc-admin",
            domain_id="dom-1",
            account_id="acc-1",
            user_id="usr-1",
            api_key="ak",
            secret_key="sk",
            is_admin=True,
        )
        entry = CacheEntry(
            identity=identity,
            provisioned=provisioned,
            groups_hash=identity.groups_hash(),
        )
        json_str = entry.model_dump_json()
        reconstructed = CacheEntry.model_validate_json(json_str)
        assert reconstructed.provisioned.api_key == "ak"
        assert reconstructed.provisioned.is_admin is True
        assert reconstructed.identity.sub == "alice"
