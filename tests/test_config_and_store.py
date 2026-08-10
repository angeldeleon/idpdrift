"""Config parsing and baseline persistence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from idpdrift.config import ALL_CHECKS, load_config, parse_config
from idpdrift.models import Determination, Snapshot
from idpdrift.severity import RoleTier
from idpdrift.store import STATE_VERSION, SnapshotStore, StateError
from idpdrift.validation import ValidationError

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"

FILE_SOURCE = {"source": {"type": "file", "file": {"path": "export.json"}}}


def entra(**overrides: object) -> dict:
    entra_block = {"tenant_id": TENANT, "client_id": CLIENT}
    entra_block.update(overrides)  # type: ignore[arg-type]
    return {"source": {"type": "entra", "entra": entra_block}}


class TestSourceParsing:
    def test_file_source(self) -> None:
        config = parse_config(FILE_SOURCE)
        assert config.source.type == "file"
        assert config.source.file is not None

    def test_entra_source(self) -> None:
        config = parse_config(entra())
        assert config.source.entra is not None
        assert config.source.entra.graph_url == "https://graph.microsoft.com"

    def test_entra_requires_a_guid_tenant(self) -> None:
        with pytest.raises(ValidationError, match="GUID"):
            parse_config(entra(tenant_id="contoso.onmicrosoft.com"))

    def test_okta_source(self) -> None:
        config = parse_config({"source": {"type": "okta", "okta": {"org_url": "https://example.okta.com"}}})
        assert config.source.okta is not None
        assert config.source.okta.org_url == "https://example.okta.com"

    def test_okta_requires_https(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            parse_config({"source": {"type": "okta", "okta": {"org_url": "http://example.okta.com"}}})

    def test_okta_internal_url_is_refused_without_opt_in(self) -> None:
        with pytest.raises(ValidationError, match="non-public"):
            parse_config({"source": {"type": "okta", "okta": {"org_url": "https://10.0.0.5"}}})

    def test_okta_internal_url_is_allowed_with_opt_in(self) -> None:
        config = parse_config(
            {
                "source": {
                    "type": "okta",
                    "okta": {"org_url": "https://10.0.0.5", "allow_internal": True},
                }
            }
        )
        assert config.source.okta is not None

    def test_unknown_source_type(self) -> None:
        with pytest.raises(ValidationError, match="not supported"):
            parse_config({"source": {"type": "ldap"}})

    def test_missing_source(self) -> None:
        with pytest.raises(ValidationError, match="source is required"):
            parse_config({"settings": {}})


class TestSecretHandling:
    def test_a_secret_pasted_into_an_env_field_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment variable"):
            parse_config(entra(client_secret_env="https://vault.example/secret"))

    def test_env_var_is_read_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_SECRET", "s3cr3t")
        config = parse_config(entra(client_secret_env="MY_SECRET"))
        assert config.source.entra is not None
        assert config.source.entra.client_secret() == "s3cr3t"

    def test_an_unset_variable_reads_as_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MY_SECRET", raising=False)
        config = parse_config(entra(client_secret_env="MY_SECRET"))
        assert config.source.entra is not None
        assert config.source.entra.client_secret() is None

    def test_no_secret_value_is_stored_on_the_config_object(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_SECRET", "s3cr3t")
        config = parse_config(entra(client_secret_env="MY_SECRET"))
        assert "s3cr3t" not in repr(config)


class TestUnknownKeys:
    def test_an_unknown_top_level_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            parse_config({**FILE_SOURCE, "polciy": {}})

    def test_an_unknown_policy_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            parse_config({**FILE_SOURCE, "policy": {"dormant_dayz": 30}})

    def test_an_unknown_check_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown check"):
            parse_config({**FILE_SOURCE, "settings": {"checks": ["not_a_check"]}})

    def test_an_empty_check_list_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="omit the key"):
            parse_config({**FILE_SOURCE, "settings": {"checks": []}})

    def test_all_checks_are_selectable(self) -> None:
        config = parse_config({**FILE_SOURCE, "settings": {"checks": list(ALL_CHECKS)}})
        assert set(config.settings.checks) == set(ALL_CHECKS)


class TestPolicy:
    def test_privileged_roles_as_a_list_default_to_privileged(self) -> None:
        config = parse_config({**FILE_SOURCE, "policy": {"privileged_roles": ["Break Glass Operator"]}})
        assert config.policy.privileged_roles["break glass operator"] is RoleTier.PRIVILEGED

    def test_privileged_roles_as_a_mapping_carry_a_tier(self) -> None:
        config = parse_config(
            {**FILE_SOURCE, "policy": {"privileged_roles": {"Break Glass": "tenant_admin"}}}
        )
        assert config.policy.privileged_roles["break glass"] is RoleTier.TENANT_ADMIN

    def test_an_unknown_tier_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="expected one of"):
            parse_config({**FILE_SOURCE, "policy": {"privileged_roles": {"X": "very_bad"}}})

    def test_credential_windows_must_not_overlap(self) -> None:
        with pytest.raises(ValidationError, match="shorter than"):
            parse_config(
                {
                    **FILE_SOURCE,
                    "policy": {"credential_expiry_days": 400, "credential_max_lifetime_days": 365},
                }
            )

    def test_an_application_cannot_be_both_ignored_and_approved(self) -> None:
        with pytest.raises(ValidationError, match="both"):
            parse_config(
                {
                    **FILE_SOURCE,
                    "policy": {"ignore_applications": ["Payroll"], "approved_applications": ["payroll"]},
                }
            )

    def test_out_of_range_values_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between"):
            parse_config({**FILE_SOURCE, "policy": {"dormant_days": 0}})


class TestEmailValidation:
    def test_header_injection_in_an_address_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="illegal character"):
            parse_config(
                {
                    **FILE_SOURCE,
                    "notify": {
                        "email": {
                            "smtp_host": "smtp.example.com",
                            "from_address": "a@example.com\nBcc: attacker@evil.example",
                            "to_addresses": ["b@example.com"],
                        }
                    },
                }
            )

    def test_smtp_host_without_recipients_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="from_address"):
            parse_config({**FILE_SOURCE, "notify": {"email": {"smtp_host": "smtp.example.com"}}})


class TestLoadConfig:
    def test_yaml_is_parsed_safely(self, tmp_path: Path) -> None:
        path = tmp_path / "idp.yml"
        path.write_text("source: !!python/object/apply:os.system ['echo pwned']\n")
        with pytest.raises(ValidationError, match="not valid YAML"):
            load_config(path)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="not found"):
            load_config(tmp_path / "absent.yml")

    def test_oversized_file(self, tmp_path: Path) -> None:
        path = tmp_path / "idp.yml"
        path.write_text("# " + "x" * (6 * 1024 * 1024))
        with pytest.raises(ValidationError, match="too large"):
            load_config(path)

    def test_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "idp.yml"
        path.write_text(yaml.safe_dump(FILE_SOURCE))
        assert load_config(path).source.type == "file"


class TestStore:
    def test_absent_state_reads_as_no_baseline(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "state.json")
        assert store.get() is None

    def test_round_trip(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "state.json", scope="file-abc")
        store.save(Snapshot(tenant="corp", collected_at="t", checks={"guests": {"guests": {}}}))
        reloaded = SnapshotStore(tmp_path / "state.json", scope="file-abc").get()
        assert reloaded is not None
        assert reloaded.tenant == "corp"

    def test_scopes_do_not_see_each_other(self, tmp_path: Path) -> None:
        """Two configs sharing a state file must keep separate baselines."""
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="a").save(Snapshot(tenant="a", collected_at="t"))
        assert SnapshotStore(path, scope="b").get() is None
        assert SnapshotStore(path, scope="a").get() is not None

    def test_saving_one_scope_preserves_another(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="a").save(Snapshot(tenant="a", collected_at="t"))
        SnapshotStore(path, scope="b").save(Snapshot(tenant="b", collected_at="t"))
        assert SnapshotStore(path, scope="a").get() is not None

    def test_the_state_file_is_0600(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path).save(Snapshot(tenant="a", collected_at="t"))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_permissions_are_repaired_on_read(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path).save(Snapshot(tenant="a", collected_at="t"))
        os.chmod(path, 0o644)
        SnapshotStore(path).load()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_corrupt_file_degrades_to_no_baseline(self, tmp_path: Path) -> None:
        """Losing drift for one run beats a monitoring job that stops running."""
        path = tmp_path / "state.json"
        path.write_text("{not json")
        assert SnapshotStore(path).get() is None

    def test_a_wrong_version_rebuilds_the_baseline(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"version": STATE_VERSION + 99, "snapshots": {}}))
        assert SnapshotStore(path).get() is None

    def test_a_malformed_snapshot_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(
            json.dumps({"version": STATE_VERSION, "snapshots": {"a": {"no": "tenant"}, "b": {"tenant": "t"}}})
        )
        assert set(SnapshotStore(path).load()) == {"b"}

    def test_a_symlink_at_the_state_path_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere.json"
        target.write_text("{}")
        link = tmp_path / "state.json"
        link.symlink_to(target)
        with pytest.raises(StateError, match="cannot open"):
            SnapshotStore(link).load()

    def test_a_fifo_at_the_state_path_fails_rather_than_hanging(self, tmp_path: Path) -> None:
        """O_NONBLOCK is what makes this a failure rather than a hung run."""
        path = tmp_path / "state.json"
        os.mkfifo(path)
        with pytest.raises(StateError, match="not a regular file"):
            SnapshotStore(path).load()

    def test_an_implausibly_large_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        with path.open("wb") as handle:
            handle.truncate(200 * 1024 * 1024)
        with pytest.raises(StateError, match="implausibly large"):
            SnapshotStore(path).load()

    def test_coverage_survives_a_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path).save(
            Snapshot(tenant="a", collected_at="t", coverage={"role_assignments": "unknown"})
        )
        reloaded = SnapshotStore(path).get()
        assert reloaded is not None
        assert Determination.parse(reloaded.coverage["role_assignments"]).is_unknown

    def test_a_write_failure_leaves_no_temp_file_behind(self, tmp_path: Path) -> None:
        path = tmp_path / "sub" / "state.json"
        SnapshotStore(path).save(Snapshot(tenant="a", collected_at="t"))
        leftovers = [p for p in (tmp_path / "sub").iterdir() if p.name.startswith(".idpdrift-state-")]
        assert not leftovers
