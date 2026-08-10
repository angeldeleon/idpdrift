"""The whole pipeline: file source, runner, renderers, CLI, exit codes."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from idpdrift import cli
from idpdrift.config import Config as AppConfig
from idpdrift.config import FileSourceConfig, PolicyConfig, Settings, SourceConfig
from idpdrift.models import Determination, FindingKind, ScanReport, Severity
from idpdrift.privacy import PrivacyMode
from idpdrift.report import render, render_html, render_json, render_markdown
from idpdrift.runner import scan, state_scope
from idpdrift.severity import Issue
from idpdrift.sources.base import SourceError
from idpdrift.sources.file import FileSource
from idpdrift.store import SnapshotStore

EXPORT: dict[str, Any] = {
    "source": "entra",
    "tenant": "corp.example",
    "principals": [
        {
            "id": "u1",
            "display_name": "Alice Admin",
            "user_principal_name": "alice@corp.example",
            "kind": "user",
            "enabled": True,
            "last_sign_in": "2026-08-09T09:00:00Z",
            "phishing_resistant": False,
            "second_factor": True,
            "auth_methods": ["microsoftAuthenticatorPush"],
            "group_count": 3,
        }
    ],
    "role_assignments": [
        {
            "id": "ra1",
            "role_id": "role-ga",
            "role_name": "Global Administrator",
            "principal_id": "u1",
            "scope": "/",
            "standing": True,
        }
    ],
    "service_principals": [],
    "oauth_grants": [],
    "policies": [{"id": "p1", "display_name": "Require MFA", "state": "enabled"}],
}


def write_export(path: Path, payload: dict[str, Any] | None = None) -> Path:
    target = path / "export.json"
    target.write_text(json.dumps(payload if payload is not None else EXPORT))
    return target


def make_app_config(tmp_path: Path, export: Path, **settings: Any) -> AppConfig:
    return AppConfig(
        source=SourceConfig(type="file", file=FileSourceConfig(path=str(export))),
        settings=Settings(
            state_path=str(tmp_path / "state.json"),
            salt_path=str(tmp_path / "salt"),
            **settings,
        ),
        policy=PolicyConfig(),
    )


class TestFileSource:
    def test_a_full_export_is_parsed(self, tmp_path: Path) -> None:
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path)))).collect()
        assert state.tenant == "corp.example"
        assert len(state.principals) == 1
        assert state.covers("access_policies").is_present

    def test_a_missing_key_reads_as_indeterminate_not_empty(self, tmp_path: Path) -> None:
        """The rule the whole file source is built around."""
        payload = {k: v for k, v in EXPORT.items() if k != "policies"}
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path, payload)))).collect()
        assert state.covers("access_policies").is_unknown

    def test_an_empty_list_reads_as_confirmed_empty(self, tmp_path: Path) -> None:
        payload = {**EXPORT, "policies": []}
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path, payload)))).collect()
        assert state.covers("access_policies").is_present
        assert state.policies == []

    def test_a_declared_coverage_block_wins(self, tmp_path: Path) -> None:
        payload = {**EXPORT, "coverage": {"authentication_methods": "unknown"}}
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path, payload)))).collect()
        assert state.covers("authentication_methods").is_unknown

    def test_a_null_field_reads_as_unknown(self, tmp_path: Path) -> None:
        payload = json.loads(json.dumps(EXPORT))
        payload["principals"][0]["phishing_resistant"] = None
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path, payload)))).collect()
        assert state.principals[0].phishing_resistant.is_unknown

    def test_guest_status_is_unknown_when_no_row_declares_a_kind(self, tmp_path: Path) -> None:
        payload = json.loads(json.dumps(EXPORT))
        payload["principals"][0].pop("kind")
        state = FileSource(FileSourceConfig(path=str(write_export(tmp_path, payload)))).collect()
        assert state.covers("guest_status").is_unknown

    def test_a_missing_file_is_a_source_error(self, tmp_path: Path) -> None:
        with pytest.raises(SourceError, match="not found"):
            FileSource(FileSourceConfig(path=str(tmp_path / "nope.json"))).collect()

    def test_a_symlinked_export_is_refused(self, tmp_path: Path) -> None:
        real = write_export(tmp_path)
        link = tmp_path / "link.json"
        link.symlink_to(real)
        with pytest.raises(SourceError, match="cannot open"):
            FileSource(FileSourceConfig(path=str(link))).collect()

    def test_a_fifo_export_fails_rather_than_hanging(self, tmp_path: Path) -> None:
        path = tmp_path / "fifo.json"
        os.mkfifo(path)
        with pytest.raises(SourceError, match="not a regular file"):
            FileSource(FileSourceConfig(path=str(path))).collect()

    def test_an_oversized_export_is_refused(self, tmp_path: Path) -> None:
        export = write_export(tmp_path)
        with pytest.raises(SourceError, match="max_bytes"):
            FileSource(FileSourceConfig(path=str(export), max_bytes=10)).collect()

    def test_invalid_json_is_a_source_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{nope")
        with pytest.raises(SourceError, match="not valid JSON"):
            FileSource(FileSourceConfig(path=str(path))).collect()

    def test_a_top_level_array_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "arr.json"
        path.write_text("[]")
        with pytest.raises(SourceError, match="JSON object"):
            FileSource(FileSourceConfig(path=str(path))).collect()

    def test_exceeding_max_identities_makes_the_facet_indeterminate(self, tmp_path: Path) -> None:
        payload = json.loads(json.dumps(EXPORT))
        payload["principals"] = [{**payload["principals"][0], "id": f"u{i}"} for i in range(10)]
        state = FileSource(
            FileSourceConfig(path=str(write_export(tmp_path, payload))), max_identities=3
        ).collect()
        assert state.covers("principals").is_unknown
        assert len(state.principals) == 3


class TestRunner:
    def test_a_first_run_reports_posture_only(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
        report = scan(config, store=store)
        assert report.baseline_available is False
        assert all(f.kind is not FindingKind.DRIFT for f in report.findings)

    def test_a_second_run_reports_drift(self, tmp_path: Path) -> None:
        export = write_export(tmp_path)
        config = make_app_config(tmp_path, export)
        store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
        scan(config, store=store)

        payload = json.loads(json.dumps(EXPORT))
        payload["role_assignments"].append(
            {
                "id": "ra2",
                "role_id": "role-appadmin",
                "role_name": "Application Administrator",
                "principal_id": "u1",
                "scope": "/",
                "standing": True,
            }
        )
        export.write_text(json.dumps(payload))

        report = scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        assert report.baseline_available is True
        drift = [f for f in report.findings if f.kind is FindingKind.DRIFT]
        assert [f.issue for f in drift] == [Issue.ROLE_ASSIGNMENT_NEW.value]

    def test_an_unchanged_second_run_reports_no_drift(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
        scan(config, store=store)
        report = scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        assert not [f for f in report.findings if f.kind is FindingKind.DRIFT]

    def test_no_save_leaves_the_baseline_alone(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
        scan(config, store=store, save=False)
        assert SnapshotStore(config.settings.state_path, scope=state_scope(config)).get() is None

    def test_an_empty_collection_does_not_overwrite_the_baseline(self, tmp_path: Path) -> None:
        """Otherwise the next run reports the whole directory as newly created."""
        export = write_export(tmp_path)
        config = make_app_config(tmp_path, export)
        scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        export.write_text(json.dumps({"tenant": "corp.example"}))
        scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        baseline = SnapshotStore(config.settings.state_path, scope=state_scope(config)).get()
        assert baseline is not None
        assert baseline.checks["privileged_roles"]["assignments"]

    def test_an_unreadable_facet_does_not_erase_the_baseline(self, tmp_path: Path) -> None:
        """The partial-merge path: role assignments become unreadable for one
        run, and the following run must not report every administrator as new."""
        export = write_export(tmp_path)
        config = make_app_config(tmp_path, export)
        scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))

        degraded = {k: v for k, v in EXPORT.items() if k != "role_assignments"}
        export.write_text(json.dumps(degraded))
        scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))

        export.write_text(json.dumps(EXPORT))
        report = scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        assert not [f for f in report.findings if f.issue == Issue.ROLE_ASSIGNMENT_NEW.value]

    def test_a_baseline_from_a_different_tenant_is_reported(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        scope = state_scope(config)
        store = SnapshotStore(config.settings.state_path, scope=scope)
        scan(config, store=store)

        from idpdrift.models import Snapshot

        SnapshotStore(config.settings.state_path, scope=scope).save(
            Snapshot(tenant="other", collected_at="t", checks={"nothing_in_common": {"x": 1}})
        )
        report = scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))
        assert Issue.BASELINE_MISMATCH.value in {f.issue for f in report.findings}

    def test_state_scope_differs_per_source_target(self, tmp_path: Path) -> None:
        a = make_app_config(tmp_path, write_export(tmp_path))
        other = tmp_path / "other"
        other.mkdir()
        b = make_app_config(tmp_path, write_export(other))
        assert state_scope(a) != state_scope(b)

    def test_a_crashing_check_does_not_kill_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import idpdrift.runner as runner

        def boom(name: str):
            def _run(ctx):
                raise RuntimeError("no")

            return _run if name == "guests" else runner.get_check(name)

        real = runner.get_check
        monkeypatch.setattr(runner, "get_check", lambda name: boom(name) if name == "guests" else real(name))
        config = make_app_config(tmp_path, write_export(tmp_path))
        report = scan(config, store=None)
        assert report.checks_failed == 1
        assert any(f.check == "guests" and f.determination.is_unknown for f in report.findings)


class TestPseudonymisation:
    def test_reports_do_not_carry_the_real_account_name(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        report = scan(config, store=None)
        rendered = render_json(report)
        assert "alice@corp.example" not in rendered
        assert "Alice Admin" not in rendered

    def test_the_pseudonym_is_stable_across_runs(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        first = {f.subject for f in scan(config, store=None).findings}
        second = {f.subject for f in scan(config, store=None).findings}
        assert first == second

    def test_identified_mode_names_the_account(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        config.privacy_mode = PrivacyMode.IDENTIFIED
        report = scan(config, store=None)
        assert "Alice Admin" in render_json(report)

    def test_the_salt_is_0600(self, tmp_path: Path) -> None:
        config = make_app_config(tmp_path, write_export(tmp_path))
        scan(config, store=None)
        assert stat.S_IMODE(Path(config.settings.salt_path).stat().st_mode) == 0o600


class TestRenderers:
    def _report(self, tmp_path: Path) -> ScanReport:
        return scan(make_app_config(tmp_path, write_export(tmp_path)), store=None)

    def test_markdown_states_the_baseline_status(self, tmp_path: Path) -> None:
        assert "this run establishes the baseline" in render_markdown(self._report(tmp_path))

    def test_markdown_publishes_the_determination_counts(self, tmp_path: Path) -> None:
        assert "could not be determined" in render_markdown(self._report(tmp_path))

    def test_json_is_parseable_and_bounded(self, tmp_path: Path) -> None:
        payload = json.loads(render_json(self._report(tmp_path)))
        assert payload["tool"] == "idpdrift"
        assert "findings_truncated" in payload
        assert "counts_by_determination" in payload

    def test_html_is_self_contained(self, tmp_path: Path) -> None:
        html = render_html(self._report(tmp_path))
        assert "<script" not in html
        assert "http://" not in html and "https://" not in html

    def test_html_carries_the_baseline_notice(self, tmp_path: Path) -> None:
        assert "No baseline" in render_html(self._report(tmp_path))

    def test_an_unknown_format_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown output format"):
            render(self._report(tmp_path), "pdf")

    def test_every_advertised_format_renders(self, tmp_path: Path) -> None:
        from idpdrift.report import FORMATS

        report = self._report(tmp_path)
        for fmt in FORMATS:
            assert render(report, fmt)


class TestExitCodes:
    def _write_config(self, tmp_path: Path, export: Path) -> Path:
        path = tmp_path / "idp.yml"
        path.write_text(
            f"source:\n  type: file\n  file:\n    path: {export}\n"
            f"settings:\n  state_path: {tmp_path / 'state.json'}\n"
            f"  salt_path: {tmp_path / 'salt'}\n"
        )
        return path

    def test_findings_exit_one(self, tmp_path: Path) -> None:
        config = self._write_config(tmp_path, write_export(tmp_path))
        code = cli.main(["scan", "-c", str(config), "-o", str(tmp_path / "r.md"), "--no-notify"])
        assert code == cli.EXIT_FINDINGS

    def test_a_high_threshold_can_return_clean(self, tmp_path: Path) -> None:
        config = self._write_config(tmp_path, write_export(tmp_path))
        code = cli.main(
            [
                "scan",
                "-c",
                str(config),
                "-o",
                str(tmp_path / "r.md"),
                "--no-notify",
                "--fail-on",
                "critical",
            ]
        )
        assert code == cli.EXIT_OK

    def test_a_broken_source_exits_two(self, tmp_path: Path) -> None:
        config = self._write_config(tmp_path, tmp_path / "absent.json")
        assert cli.main(["scan", "-c", str(config), "--no-notify"]) == cli.EXIT_ERROR

    def test_an_empty_tenant_exits_two_rather_than_clean(self, tmp_path: Path) -> None:
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"tenant": "corp.example", "principals": []}))
        config = self._write_config(tmp_path, export)
        assert cli.main(["scan", "-c", str(config), "--no-notify"]) == cli.EXIT_ERROR

    def test_a_bad_config_exits_two(self, tmp_path: Path) -> None:
        path = tmp_path / "idp.yml"
        path.write_text("source:\n  type: nonsense\n")
        assert cli.main(["scan", "-c", str(path), "--no-notify"]) == cli.EXIT_ERROR

    def test_validate_accepts_the_shipped_example(self) -> None:
        example = Path(__file__).resolve().parents[1] / "idp.example.yml"
        assert cli.main(["validate", "-c", str(example)]) == cli.EXIT_OK

    def test_the_report_file_is_0600(self, tmp_path: Path) -> None:
        config = self._write_config(tmp_path, write_export(tmp_path))
        out = tmp_path / "report.json"
        cli.main(["scan", "-c", str(config), "-f", "json", "-o", str(out), "--no-notify"])
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_a_symlinked_report_path_is_refused(self, tmp_path: Path) -> None:
        """A report is an inventory of privileged access, and it is usually
        written into a shared artefact directory. A symlink planted at the path
        would otherwise redirect it to a file the attacker can read, and have
        the 0600 tightening applied to their target."""
        config = self._write_config(tmp_path, write_export(tmp_path))
        victim = tmp_path / "victim.txt"
        victim.write_text("do not overwrite me")
        victim.chmod(0o644)
        link = tmp_path / "report.md"
        link.symlink_to(victim)

        assert cli.main(["scan", "-c", str(config), "-o", str(link), "--no-notify"]) == cli.EXIT_ERROR
        assert victim.read_text() == "do not overwrite me"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_an_existing_report_is_retightened_rather_than_left_loose(self, tmp_path: Path) -> None:
        config = self._write_config(tmp_path, write_export(tmp_path))
        out = tmp_path / "report.md"
        out.write_text("stale")
        out.chmod(0o644)
        cli.main(["scan", "-c", str(config), "-o", str(out), "--no-notify"])
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_severity_subcommand_prints_the_table(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["severity"]) == cli.EXIT_OK
        out = capsys.readouterr().out
        assert "role_assignment_new" in out
        assert "capped at low" in out

    def test_coverage_subcommand_names_the_gaps(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        payload = {k: v for k, v in EXPORT.items() if k != "policies"}
        config = self._write_config(tmp_path, write_export(tmp_path, payload))
        assert cli.main(["coverage", "-c", str(config)]) == cli.EXIT_OK
        assert "COULD NOT DETERMINE" in capsys.readouterr().out

    def test_an_unexpected_crash_exits_two_not_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exit 1 means findings. A crash must never be mistaken for one."""
        config = self._write_config(tmp_path, write_export(tmp_path))
        monkeypatch.setattr(cli, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        assert cli.main(["scan", "-c", str(config), "--no-notify"]) == cli.EXIT_ERROR


class TestReportModel:
    def test_degraded_when_nothing_was_collected(self) -> None:
        report = ScanReport(started_at="a", finished_at="b", tool_version="0", source="file")
        assert report.scan_degraded is True

    def test_not_degraded_for_a_small_check_selection(self) -> None:
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=5,
            checks_run=2,
            checks_failed=1,
        )
        assert report.scan_degraded is False

    def test_degraded_when_most_checks_failed(self) -> None:
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=5,
            checks_run=7,
            checks_failed=5,
        )
        assert report.scan_degraded is True

    def test_max_severity_of_an_empty_report(self) -> None:
        report = ScanReport(started_at="a", finished_at="b", tool_version="0", source="file")
        assert report.max_severity is None

    def test_determination_counts_add_up(self, tmp_path: Path) -> None:
        report = scan(make_app_config(tmp_path, write_export(tmp_path)), store=None)
        assert sum(report.counts_by_determination().values()) == len(report.findings)

    def test_severity_counts_add_up(self, tmp_path: Path) -> None:
        report = scan(make_app_config(tmp_path, write_export(tmp_path)), store=None)
        assert sum(report.counts_by_severity().values()) == len(report.findings)


class TestSerialisationBounds:
    def _big_report(self) -> ScanReport:
        from idpdrift.models import Finding

        findings = [
            Finding(
                subject=f"id-{i}",
                subject_id=f"id-{i}",
                check="privileged_roles",
                issue=Issue.ROLE_ASSIGNMENT_NEW.value,
                kind=FindingKind.DRIFT,
                severity=Severity.HIGH,
                title=f"finding {i}",
                detail="x",
                determination=Determination.PRESENT,
            )
            for i in range(1200)
        ]
        return ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=10,
            findings=findings,
            collection_errors=[f"error {i}" for i in range(200)],
            indeterminate_facets=[f"facet{i}" for i in range(200)],
        )

    def test_json_output_is_capped_and_says_so(self) -> None:
        payload = json.loads(self._big_report().to_json())
        assert payload["findings_truncated"] is True
        assert payload["findings_total"] == 1200
        assert len(payload["findings"]) < 1200

    def test_collection_errors_are_capped(self) -> None:
        payload = json.loads(self._big_report().to_json())
        assert len(payload["collection_errors"]) == 50

    def test_markdown_is_capped_and_says_so(self) -> None:
        rendered = render_markdown(self._big_report())
        assert "further finding" in rendered

    def test_html_is_capped(self) -> None:
        rendered = render_html(self._big_report())
        assert rendered.count("<tr>") <= 401
