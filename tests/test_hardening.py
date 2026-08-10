"""Regression tests for the hardening pass.

Each corresponds to a specific defect found during adversarial review. Grouped
separately from the feature tests so it stays obvious that deleting one re-opens
a known hole.

The recurring adversary is the same throughout: somebody who can create an
account, a group or an application registration in the tenant being watched, and
who therefore chooses the display names this tool renders, hashes, persists and
sends to a webhook.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from unittest import mock

import pytest

from conftest import assignment, make_state, principal, run_check
from idpdrift import ai, notify
from idpdrift.catalog import (
    HIGH_IMPACT_SCOPES,
    PHISHING_RESISTANT_METHODS,
    ROLE_TIERS,
    WEAK_METHODS,
    looks_non_human,
    reads_files,
    reads_mail,
)
from idpdrift.checks import registered_checks
from idpdrift.config import ALL_CHECKS, AIConfig, NotifyConfig, parse_config
from idpdrift.drift import registered_rules
from idpdrift.logging_setup import redact
from idpdrift.models import (
    Credential,
    Determination,
    Finding,
    FindingKind,
    PrincipalKind,
    ScanReport,
    Severity,
)
from idpdrift.notify import _escape, _escape_code, _plain
from idpdrift.privacy import Pseudonymiser
from idpdrift.report import _code, _md, _md_block, _md_url, _render_findings, render_html
from idpdrift.severity import Issue
from idpdrift.validation import normalize_key, safe_text, scrub_evidence

HOSTILE_NAME = (
    "Payroll ![](https://evil.example/beacon.png) [Approved](https://evil.example/phish) <img src=x>"
)


def _finding(*, subject: str = "id-abc", title: str = "New assignment", detail: str = "x") -> Finding:
    return Finding(
        subject=subject,
        subject_id="id-abc",
        check="privileged_roles",
        issue=Issue.ROLE_ASSIGNMENT_NEW.value,
        kind=FindingKind.DRIFT,
        severity=Severity.HIGH,
        title=title,
        detail=detail,
    )


class TestMarkdownInjection:
    """Display names are attacker-chosen; reports get read in tickets."""

    def test_link_and_image_syntax_is_neutralised(self) -> None:
        rendered = _md(HOSTILE_NAME)
        assert "](https://evil.example" not in rendered
        assert "\\[" in rendered and "\\!" in rendered

    def test_html_tags_cannot_survive(self) -> None:
        assert "<img" not in _md(HOSTILE_NAME)

    def test_backtick_cannot_break_out_of_a_code_span(self) -> None:
        rendered = _md("Payroll` is approved **owned**")
        assert "\\`" in rendered
        assert not re.search(r"(?<!\\)`", rendered)
        # Emphasis markers are deliberately left alone: the worst they do is make
        # text bold, and escaping them mangles every `role_assignment_new`.
        assert "**owned**" in rendered

    def test_arrows_and_ordinary_text_survive(self) -> None:
        assert _md("enabled -> disabled") == "enabled -> disabled"
        assert _md("Microsoft 365 E5") == "Microsoft 365 E5"

    def test_a_bare_url_is_quarantined_in_a_code_span(self) -> None:
        """Autolinking needs no metacharacter, so escaping cannot fix it."""
        rendered = _md("Re-authenticate https://evil.example/mfa now")
        assert "`https://evil.example/mfa`" in rendered

    def test_a_www_prefixed_url_is_quarantined_too(self) -> None:
        assert "`www.evil.example/mfa`" in _md("Go to www.evil.example/mfa")

    def test_the_quarantine_span_always_closes(self) -> None:
        """The URL run stops at a backtick, so the span it opens always closes;
        the backtick that stopped it is escaped as ordinary text."""
        rendered = _md("see https://evil.example/`backtick")
        assert "`https://evil.example/`" in rendered
        assert "\\`backtick" in rendered

    def test_a_leading_blockquote_is_neutralised(self) -> None:
        assert _md("> all clear").startswith("&gt;")

    def test_control_characters_cannot_forge_a_line(self) -> None:
        assert "\n" not in _md("Payroll\n🟢 CRITICAL — all clear")


class TestCodeSpanRendering:
    def test_backslashes_are_not_printed_inside_a_span(self) -> None:
        """_md inside backticks shows the reader literal backslashes."""
        assert _code("Payroll (EU)") == "Payroll (EU)"

    def test_a_backtick_cannot_close_the_span(self) -> None:
        assert "`" not in _code("Payroll`")

    def test_angle_brackets_are_entity_escaped_even_inside_a_span(self) -> None:
        assert _code("<img src=x>") == "&lt;img src=x&gt;"

    def test_the_rendered_finding_line_is_readable_and_inert(self) -> None:
        """Two properties a code-span value has to hold at once.

        Readable: an analyst sees the real name, not a soup of backslashes —
        backslash escapes are inert inside backticks and render literally.
        Inert: the code span is the only place the raw link syntax appears, and
        no CommonMark implementation interprets it there. The title and detail,
        which render as prose, still go through ``_md``.
        """
        payload = "Payroll ![](https://evil.example/px.png) [Fix](https://evil.example/phish)"
        rendered = "\n".join(_render_findings([_finding(subject=payload)]))
        assert f"`{payload}`" in rendered
        assert "](https://evil.example" not in rendered.replace(f"`{payload}`", "")
        assert "\\!" not in rendered

    def test_a_tag_in_a_subject_is_entity_escaped_even_in_a_span(self) -> None:
        rendered = "\n".join(_render_findings([_finding(subject="Payroll <img src=x>")]))
        assert "<img" not in rendered


class TestSummaryInjection:
    """Model output is prose, but it lands in a Markdown surface."""

    def test_a_forged_heading_cannot_open_a_section(self) -> None:
        assert _md_block("## Changes since last scan (0)").startswith("\\#")

    def test_a_forged_table_cannot_be_opened(self) -> None:
        assert _md_block("| Critical | High |\n| --- | --- |").splitlines()[0].startswith("\\|")

    def test_a_tilde_fence_cannot_swallow_the_report(self) -> None:
        assert _md_block("~~~").startswith("\\~")

    def test_an_ordered_list_marker_is_escaped_without_a_stray_backslash(self) -> None:
        rendered = _md_block("3 accounts gained Global Administrator")
        assert rendered.startswith("3\\.") or rendered.startswith("3 accounts")
        assert not rendered.startswith("\\3")

    def test_a_numbered_list_is_suppressed(self) -> None:
        assert _md_block("1. all clear").startswith("1\\.")

    def test_paragraph_breaks_survive(self) -> None:
        assert "\n\n" in _md_block("first\n\nsecond")

    def test_runs_of_blank_lines_are_collapsed(self) -> None:
        assert "\n\n\n" not in _md_block("a\n\n\n\n\nb")

    def test_a_bare_url_in_the_summary_is_quarantined(self) -> None:
        assert "`https://evil.example`" in _md_block("visit https://evil.example")


class TestReferenceUrls:
    def test_a_non_http_reference_is_dropped(self) -> None:
        assert _md_url("javascript:alert(1)") == ""

    def test_a_reference_with_a_closing_paren_is_dropped(self) -> None:
        assert _md_url("https://evil.example/a)b") == ""

    def test_an_ordinary_reference_survives(self) -> None:
        assert _md_url("https://attack.mitre.org/techniques/T1528/").startswith("https://")


class TestHtmlEscaping:
    def _report(self, **kwargs: object) -> ScanReport:
        return ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0.1.0",
            source="file",
            identities_seen=1,
            **kwargs,  # type: ignore[arg-type]
        )

    def test_a_hostile_subject_cannot_inject_a_tag(self) -> None:
        html = render_html(self._report(findings=[_finding(subject=HOSTILE_NAME)]))
        assert "<img src=x>" not in html
        assert "&lt;img src=x&gt;" in html

    def test_a_hostile_title_cannot_inject_a_tag(self) -> None:
        html = render_html(self._report(findings=[_finding(title="<script>alert(1)</script>")]))
        assert "<script>alert(1)" not in html

    def test_the_summary_is_escaped(self) -> None:
        html = render_html(self._report(ai_summary="<script>x</script>"))
        assert "<script>x" not in html

    def test_collection_notes_are_escaped(self) -> None:
        html = render_html(self._report(collection_errors=["<b>bad</b>"]))
        assert "<b>bad</b>" not in html

    def test_an_incomplete_scan_never_looks_clean_in_html(self) -> None:
        """Markdown and JSON both carried the coverage notes; HTML must too."""
        html = render_html(self._report(indeterminate_facets=["role_assignments"]))
        assert "Could not determine: role_assignments" in html

    def test_indeterminate_findings_are_marked_in_html(self) -> None:
        finding = Finding(
            subject="tenant",
            subject_id="tenant",
            check="dormancy",
            issue=Issue.FACET_INDETERMINATE.value,
            kind=FindingKind.OPERATIONAL,
            severity=Severity.LOW,
            title="sign in activity could not be determined",
            detail="x",
            determination=Determination.UNKNOWN,
        )
        assert "could not determine" in render_html(self._report(findings=[finding]))


class TestSlackInjection:
    def test_control_characters_cannot_forge_a_line(self) -> None:
        assert "\n" not in _escape("Payroll\n:white_check_mark: all clear")

    def test_angle_brackets_cannot_build_a_slack_link(self) -> None:
        assert "<https://evil.example|click>" not in _escape("<https://evil.example|click>")

    def test_a_backtick_cannot_close_a_code_span(self) -> None:
        assert "`" not in _escape_code("payroll`*owned*")

    def test_plain_text_is_not_entity_escaped(self) -> None:
        """plain_text interprets no mrkdwn, so &lt; would print literally."""
        assert _plain("a < b") == "a < b"

    def test_plain_text_still_collapses_control_characters(self) -> None:
        assert "\n" not in _plain("a\nb")

    def test_finding_prose_goes_into_a_plain_text_block(self) -> None:
        """Slack mrkdwn has no backslash escape; the only defence is context."""
        sent: dict = {}

        def fake_request(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})
            return mock.Mock(status_code=200)

        config = NotifyConfig(slack_webhook_url_env="HOOK")
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding(title="*bold* :white_check_mark:")],
        )
        with (
            mock.patch.dict(os.environ, {"HOOK": "https://hooks.slack.com/services/x"}),
            mock.patch("idpdrift.notify.safe_request", fake_request),
        ):
            assert notify.notify(report, config) == []

        prose = [b for b in sent["blocks"] if b.get("text", {}).get("type") == "plain_text"]
        assert prose and prose[0]["text"]["emoji"] is False
        assert "*bold*" in prose[0]["text"]["text"]


class TestWebhookBounds:
    def test_the_generic_webhook_honours_the_limit(self) -> None:
        """The scan that finds the most must not be the one whose alert is dropped."""
        sent: dict = {}

        def fake_request(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})
            return mock.Mock(status_code=200)

        findings = [_finding(subject=f"id-{i}") for i in range(200)]
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=10,
            findings=findings,
        )
        config = NotifyConfig(webhook_url_env="HOOK", max_findings_per_message=5)
        with (
            mock.patch.dict(os.environ, {"HOOK": "https://example.com/hook"}),
            mock.patch("idpdrift.notify.safe_request", fake_request),
        ):
            notify.notify(report, config)

        assert len(sent["findings"]) == 5
        assert sent["findings_total"] == 200
        assert sent["findings_truncated"] is True

    def test_slack_blocks_stay_under_the_platform_limit(self) -> None:
        sent: dict = {}

        def fake_request(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})
            return mock.Mock(status_code=200)

        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=10,
            findings=[_finding(subject=f"id-{i}") for i in range(100)],
        )
        config = NotifyConfig(slack_webhook_url_env="HOOK", max_findings_per_message=100)
        with (
            mock.patch.dict(os.environ, {"HOOK": "https://hooks.slack.com/services/x"}),
            mock.patch("idpdrift.notify.safe_request", fake_request),
        ):
            notify.notify(report, config)
        assert len(sent["blocks"]) <= 50

    def test_a_delivery_failure_does_not_raise(self) -> None:
        from idpdrift.httpclient import HTTPError

        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding()],
        )
        config = NotifyConfig(webhook_url_env="HOOK")
        with (
            mock.patch.dict(os.environ, {"HOOK": "https://example.com/hook"}),
            mock.patch("idpdrift.notify.safe_request", side_effect=HTTPError("down")),
        ):
            errors = notify.notify(report, config)
        assert errors and "webhook delivery failed" in errors[0]


class TestEvidenceRedaction:
    """Redaction at the construction boundary, not at the sinks."""

    def test_a_finding_never_holds_a_secret(self) -> None:
        finding = Finding(
            subject="Payroll",
            subject_id="sp1",
            check="service_principals",
            issue=Issue.CREDENTIAL_NEW.value,
            kind=FindingKind.DRIFT,
            severity=Severity.HIGH,
            title="t",
            detail="d",
            evidence={"client_secret": "hunter2", "keyId": "abc"},
        )
        assert "hunter2" not in json.dumps(finding.to_dict())
        assert finding.evidence["keyId"] == "abc"

    def test_the_credential_model_never_accepts_key_material(self) -> None:
        credential = Credential.from_raw(
            {"keyId": "k1", "secretText": "hunter2", "endDateTime": "2027-01-01T00:00:00Z"},
            kind="secret",
        )
        assert "hunter2" not in repr(credential)
        assert credential.credential_id == "k1"

    def test_redaction_survives_every_renderer(self) -> None:
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[
                Finding(
                    subject="Payroll",
                    subject_id="sp1",
                    check="service_principals",
                    issue=Issue.CREDENTIAL_NEW.value,
                    kind=FindingKind.DRIFT,
                    severity=Severity.HIGH,
                    title="t",
                    detail="d",
                    evidence={"password": "hunter2"},
                )
            ],
        )
        from idpdrift.report import FORMATS, render

        for fmt in FORMATS:
            assert "hunter2" not in render(report, fmt)

    def test_evidence_is_bounded_at_construction(self) -> None:
        finding = Finding(
            subject="x",
            subject_id="x",
            check="c",
            issue="i",
            kind=FindingKind.POSTURE,
            severity=Severity.LOW,
            title="t",
            detail="d",
            evidence={"items": list(range(5000))},
        )
        assert len(finding.evidence["items"]) <= 51


class TestLogRedaction:
    def test_a_slack_webhook_url_is_redacted(self) -> None:
        assert "T00/B00/xoxb" not in redact("posting to https://hooks.slack.com/services/T00/B00/xoxb")

    def test_an_okta_token_header_is_redacted(self) -> None:
        assert "00abcdefgh" not in redact("Authorization: SSWS 00abcdefghijklmnop")

    def test_a_jwt_is_redacted(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJ0aWQiOiJjb250b3NvIn0.signaturevalue"
        assert token not in redact(f"token={token}")

    def test_a_client_secret_assignment_is_redacted(self) -> None:
        assert "abcd1234efgh" not in redact("client_secret=abcd1234efgh5678")

    def test_a_bearer_header_is_redacted(self) -> None:
        assert "abcdefghijklmnop" not in redact("Authorization: Bearer abcdefghijklmnopqrst")


class TestSaltHandling:
    def test_the_salt_is_created_0600(self, tmp_path: Path) -> None:
        pseudonymiser = Pseudonymiser(tmp_path / "salt")
        pseudonymiser.pseudonym("id", "u1")
        assert stat.S_IMODE((tmp_path / "salt").stat().st_mode) == 0o600

    def test_loose_permissions_are_tightened(self, tmp_path: Path) -> None:
        path = tmp_path / "salt"
        path.write_bytes(b"x" * 32)
        os.chmod(path, 0o644)
        Pseudonymiser(path).pseudonym("id", "u1")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_symlinked_salt_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_bytes(b"x" * 32)
        link = tmp_path / "salt"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="cannot read salt"):
            Pseudonymiser(link).pseudonym("id", "u1")

    def test_a_fifo_salt_fails_rather_than_hanging(self, tmp_path: Path) -> None:
        """O_NONBLOCK is the difference between a failure and a hung cron job."""
        path = tmp_path / "salt"
        os.mkfifo(path)
        with pytest.raises(ValueError, match="not a regular file"):
            Pseudonymiser(path).pseudonym("id", "u1")

    def test_a_truncated_salt_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "salt"
        path.write_bytes(b"short")
        with pytest.raises(ValueError, match="too short"):
            Pseudonymiser(path).pseudonym("id", "u1")

    def test_pseudonyms_are_namespaced(self, tmp_path: Path) -> None:
        pseudonymiser = Pseudonymiser(tmp_path / "salt")
        assert pseudonymiser.pseudonym("id", "x") != pseudonymiser.pseudonym("group", "x")

    def test_pseudonyms_differ_between_salts(self, tmp_path: Path) -> None:
        a = Pseudonymiser(tmp_path / "a" / "salt").pseudonym("id", "u1")
        b = Pseudonymiser(tmp_path / "b" / "salt").pseudonym("id", "u1")
        assert a != b

    def test_a_pseudonym_does_not_contain_the_input(self, tmp_path: Path) -> None:
        pseudonymiser = Pseudonymiser(tmp_path / "salt")
        assert "alice" not in pseudonymiser.principal_label("u1", "alice@corp.example")


class TestNameSpoofing:
    def test_a_bidi_override_cannot_hide_a_role_name(self) -> None:
        assert normalize_key("Global‮rotartsinimdA") == normalize_key("GlobalrotartsinimdA")

    def test_a_fullwidth_role_name_still_matches_the_catalog(self) -> None:
        from idpdrift.catalog import role_tier
        from idpdrift.severity import RoleTier

        assert role_tier("Ｇｌｏｂａｌ　Ａｄｍｉｎｉｓｔｒａｔｏｒ") is RoleTier.TENANT_ADMIN

    def test_a_zero_width_split_does_not_evade_the_catalog(self) -> None:
        from idpdrift.catalog import role_tier
        from idpdrift.severity import RoleTier

        assert role_tier("Global​Administrator") is RoleTier.TENANT_ADMIN

    def test_an_unlisted_role_defaults_downward(self) -> None:
        from idpdrift.catalog import role_tier
        from idpdrift.severity import RoleTier

        assert role_tier("Reporting - Finance") is RoleTier.STANDARD

    def test_an_object_named_only_with_emoji_stays_visible(self) -> None:
        """A name that normalises to nothing would be skipped by every caller."""
        assert normalize_key("🔒") != ""

    def test_a_surrogate_in_a_name_cannot_break_serialisation(self) -> None:
        state = make_state(role_assignments=[assignment(display="bad\ud800name")])
        result = run_check("privileged_roles", state)
        json.dumps(result.observations)  # must not raise


class TestNonHumanHeuristic:
    def test_it_never_returns_absent_for_an_unknown_kind(self) -> None:
        """A human-looking name proves only that somebody chose one."""
        answer = looks_non_human(kind=PrincipalKind.UNKNOWN, display="Jane Smith")
        assert answer is Determination.UNKNOWN

    def test_the_directory_beats_the_naming_convention(self) -> None:
        answer = looks_non_human(kind=PrincipalKind.USER, display="svc-backup")
        assert answer is Determination.ABSENT

    def test_a_declared_workload_is_present(self) -> None:
        answer = looks_non_human(kind=PrincipalKind.SERVICE_PRINCIPAL, display="Anything")
        assert answer is Determination.PRESENT

    def test_the_upn_local_part_is_considered(self) -> None:
        answer = looks_non_human(
            kind=PrincipalKind.UNKNOWN, display="Reporting", upn="svc-reporting@corp.example"
        )
        assert answer is Determination.PRESENT


class TestTriStateInvariants:
    def test_parse_defaults_to_unknown_not_absent(self) -> None:
        """An older state file must not read as a directory full of gaps."""
        assert Determination.parse(None).is_unknown
        assert Determination.parse("nonsense").is_unknown
        assert Determination.parse("").is_unknown

    def test_from_optional_maps_none_to_unknown(self) -> None:
        assert Determination.from_optional(None).is_unknown
        assert Determination.from_optional(False).is_absent
        assert Determination.from_optional(True).is_present

    def test_an_undeclared_facet_reads_as_unknown(self) -> None:
        state = make_state()
        state.coverage.clear()
        assert state.covers("role_assignments").is_unknown

    @pytest.mark.parametrize("check", list(ALL_CHECKS))
    def test_every_check_declines_to_conclude_on_a_blind_collection(self, check: str) -> None:
        """A source that could read nothing must produce no posture finding."""
        blind = make_state(
            principals=[principal()],
            role_assignments=[assignment()],
            coverage=dict.fromkeys(make_state().coverage, Determination.UNKNOWN),
        )
        result = run_check(check, blind)
        assert all(f.determination.is_unknown for f in result.findings)
        assert all(f.kind is FindingKind.OPERATIONAL for f in result.findings)

    @pytest.mark.parametrize("check", list(ALL_CHECKS))
    def test_a_blind_collection_never_overwrites_the_baseline(self, check: str) -> None:
        blind = make_state(coverage=dict.fromkeys(make_state().coverage, Determination.UNKNOWN))
        result = run_check(check, blind)
        assert result.partial is True or not result.observations


class TestRegistryInvariants:
    def test_every_declared_check_is_implemented(self) -> None:
        """A check an operator can select and no code implements is a blind scan."""
        assert set(ALL_CHECKS) == set(registered_checks())

    def test_every_check_has_a_drift_rule(self) -> None:
        assert set(ALL_CHECKS) == set(registered_rules())

    def test_every_catalog_role_survives_normalisation(self) -> None:
        assert all(key for key in ROLE_TIERS)

    def test_every_catalog_scope_survives_normalisation(self) -> None:
        assert all(key for key in HIGH_IMPACT_SCOPES)

    def test_every_auth_method_entry_survives_normalisation(self) -> None:
        assert all(PHISHING_RESISTANT_METHODS) and all(WEAK_METHODS)

    def test_no_method_is_both_strong_and_weak(self) -> None:
        assert not (PHISHING_RESISTANT_METHODS & WEAK_METHODS)


class TestAiBoundary:
    def test_the_summariser_never_sends_a_display_name(self) -> None:
        sent: dict = {}

        def fake_request(method, url, **kwargs):
            sent.update(kwargs.get("json_body") or {})
            return mock.Mock(status_code=200, json=lambda: {"content": [{"type": "text", "text": "summary"}]})

        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding(subject="alice@corp.example")],
        )
        config = AIConfig(enabled=True, api_key_env="KEY")
        with (
            mock.patch.dict(os.environ, {"KEY": "sk-test"}),
            mock.patch("idpdrift.ai.safe_request", fake_request),
        ):
            assert ai.summarize(report, config) == "summary"

        payload = json.dumps(sent)
        assert "alice@corp.example" not in payload
        assert "identity-1" in payload

    def test_the_summary_is_length_bounded(self) -> None:
        def fake_request(method, url, **kwargs):
            return mock.Mock(
                status_code=200, json=lambda: {"content": [{"type": "text", "text": "x" * 99999}]}
            )

        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding()],
        )
        with (
            mock.patch.dict(os.environ, {"KEY": "sk-test"}),
            mock.patch("idpdrift.ai.safe_request", fake_request),
        ):
            summary = ai.summarize(report, AIConfig(enabled=True, api_key_env="KEY"))
        assert summary is not None and len(summary) <= 4000

    def test_a_provider_failure_returns_none(self) -> None:
        def fake_request(method, url, **kwargs):
            return mock.Mock(status_code=500)

        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding()],
        )
        with (
            mock.patch.dict(os.environ, {"KEY": "sk-test"}),
            mock.patch("idpdrift.ai.safe_request", fake_request),
        ):
            assert ai.summarize(report, AIConfig(enabled=True, api_key_env="KEY")) is None

    def test_a_missing_api_key_returns_none(self) -> None:
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="file",
            identities_seen=1,
            findings=[_finding()],
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            assert ai.summarize(report, AIConfig(enabled=True, api_key_env="ABSENT")) is None

    def test_the_summariser_is_off_by_default(self) -> None:
        assert AIConfig().enabled is False

    def test_the_declared_payload_keys_are_the_safe_ones(self) -> None:
        keys = set(ai.redacted_context_keys())
        assert "detail" not in keys
        assert "subject" in keys


class TestConfigInjection:
    def test_a_yaml_object_tag_cannot_execute(self, tmp_path: Path) -> None:
        from idpdrift.config import load_config
        from idpdrift.validation import ValidationError

        path = tmp_path / "idp.yml"
        path.write_text("!!python/object/apply:os.system ['id']\n")
        with pytest.raises(ValidationError):
            load_config(path)

    def test_a_config_cannot_supply_an_api_path(self) -> None:
        from idpdrift.validation import ValidationError

        with pytest.raises(ValidationError, match="unknown key"):
            parse_config(
                {
                    "source": {
                        "type": "okta",
                        "okta": {"org_url": "https://example.okta.com", "path": "/api/v1/users"},
                    }
                }
            )


class TestSafeTextAtIngestion:
    def test_ingestion_caps_length_before_anything_persists(self, tmp_path: Path) -> None:
        """The cap lives in the source, so nothing downstream has to remember it."""
        from idpdrift.config import FileSourceConfig
        from idpdrift.sources.file import FileSource

        export = tmp_path / "export.json"
        export.write_text(
            json.dumps(
                {
                    "tenant": "corp.example",
                    "principals": [{"id": "u1", "display_name": "x" * 5000, "kind": "user"}],
                }
            )
        )
        state = FileSource(FileSourceConfig(path=str(export))).collect()
        assert len(state.principals[0].display) <= 256

    def test_ingestion_strips_control_characters_from_a_display_name(self, tmp_path: Path) -> None:
        from idpdrift.config import FileSourceConfig
        from idpdrift.sources.file import FileSource

        export = tmp_path / "export.json"
        export.write_text(
            json.dumps(
                {
                    "tenant": "corp.example",
                    "principals": [{"id": "u1", "display_name": "a\nb", "kind": "user"}],
                }
            )
        )
        state = FileSource(FileSourceConfig(path=str(export))).collect()
        assert "\n" not in state.principals[0].display

    def test_scrub_evidence_is_idempotent(self) -> None:
        once = scrub_evidence({"secret": "x", "a": [1, 2]})
        assert scrub_evidence(once) == once

    def test_safe_text_is_idempotent(self) -> None:
        assert safe_text(safe_text(HOSTILE_NAME)) == safe_text(HOSTILE_NAME)


class TestAllowListsAreKeyedOnIdentifiers:
    """Suppressing a finding is the most valuable thing an attacker can make
    this tool do, so nothing that suppresses one may be keyed on a string the
    attacker chose. Both lists used to match the display name, which meant
    registering an application called ``Atlassian Cloud`` removed it from the
    report *and* from the baseline the drift rule reads."""

    def test_a_display_name_does_not_buy_an_approval(self) -> None:
        from conftest import grant, make_config, workload

        hostile = grant("og-evil", client_id="sp-evil", client_display="Atlassian Cloud", tenant_wide=True)
        result = run_check(
            "oauth_grants",
            make_state(oauth_grants=[hostile], workloads=[workload("sp-evil", display="Atlassian Cloud")]),
            make_config(approved_applications=("atlassian cloud",)),
        )
        assert Issue.OAUTH_TENANT_WIDE.value in {f.issue for f in result.findings}

    def test_an_approved_client_id_still_suppresses(self) -> None:
        from conftest import grant, make_config

        result = run_check(
            "oauth_grants",
            make_state(oauth_grants=[grant(client_id="sp-known", tenant_wide=True)]),
            make_config(approved_applications=("sp known",)),
        )
        assert not result.findings

    def test_a_display_name_does_not_buy_an_ignore(self) -> None:
        from conftest import credential, make_config, workload

        result = run_check(
            "service_principals",
            make_state(workloads=[workload("sp-evil", display="Payroll Sync", credentials=(credential(),))]),
            make_config(ignore_applications=("payroll sync",)),
        )
        assert result.findings

    def test_a_suppressed_application_is_still_absent_from_the_baseline(self) -> None:
        """The bypass was worse than a missing finding: an approved grant is not
        recorded either, so the drift rule never sees it appear."""
        from conftest import grant, make_config, workload

        hostile = grant("og-evil", client_id="sp-evil", client_display="Atlassian Cloud")
        result = run_check(
            "oauth_grants",
            make_state(oauth_grants=[hostile], workloads=[workload("sp-evil", display="Atlassian Cloud")]),
            make_config(approved_applications=("atlassian cloud",)),
        )
        assert result.observations["grants"]


class TestGroupCountTriState:
    """``group_membership`` coverage says the source can count groups in
    general. Whether it returned a count for one account is a separate answer,
    and reading a missing count as zero both suppressed the allowance finding
    and persisted a fabricated zero for the next run to diff against."""

    def _guest(self, *, known: Determination, count: int):
        from idpdrift.models import Principal

        return Principal(
            principal_id="g1",
            display="Ext",
            upn="ext@partner.example",
            kind=PrincipalKind.GUEST,
            enabled=Determination.PRESENT,
            sign_in_known=Determination.PRESENT,
            last_sign_in="2026-08-09T00:00:00Z",
            second_factor=Determination.PRESENT,
            phishing_resistant=Determination.PRESENT,
            group_count=count,
            group_count_known=known,
        )

    def test_an_uncounted_guest_is_not_recorded_as_holding_no_groups(self) -> None:
        result = run_check(
            "guests", make_state(principals=[self._guest(known=Determination.UNKNOWN, count=0)])
        )
        assert result.observations["guests"]["Ext"]["group_count"] == -1

    def test_a_counted_guest_over_the_allowance_is_still_reported(self) -> None:
        result = run_check(
            "guests", make_state(principals=[self._guest(known=Determination.PRESENT, count=99)])
        )
        assert Issue.GUEST_OVER_ALLOWANCE.value in {f.issue for f in result.findings}

    def test_an_uncounted_account_is_not_dormant_with_group_access(self) -> None:
        from idpdrift.models import Principal

        stale = Principal(
            principal_id="u9",
            display="Stale",
            upn="stale@corp.example",
            kind=PrincipalKind.USER,
            enabled=Determination.PRESENT,
            sign_in_known=Determination.PRESENT,
            last_sign_in="2020-01-01T00:00:00Z",
            second_factor=Determination.PRESENT,
            phishing_resistant=Determination.PRESENT,
            group_count=7,
            group_count_known=Determination.UNKNOWN,
        )
        result = run_check("dormancy", make_state(principals=[stale]))
        assert Issue.DORMANT_WITH_ACCESS.value not in {f.issue for f in result.findings}


class TestPolicyExclusionsArePseudonymised:
    """An excluded user is named by their directory object id, which resolves to
    a person in one lookup. PRIVACY.md promises a stable label instead, in every
    report, alert and webhook payload — and this list reaches all three through
    the exclusion-added drift finding."""

    def test_an_excluded_user_id_does_not_reach_the_observations(self, tmp_path: Path) -> None:
        from conftest import make_config, policy
        from idpdrift.checks import CheckContext, get_check
        from idpdrift.privacy import Pseudonymiser

        pseudonymiser = Pseudonymiser(tmp_path / "salt")
        state = make_state(policies=[policy(excluded_users=("11111111-2222-3333-4444-555555555555",))])
        ctx = CheckContext(state=state, config=make_config(), label=pseudonymiser.principal_label)
        exclusions = get_check("conditional_access")(ctx).observations["policies"]["cap1"]["exclusions"]
        assert "11111111-2222-3333-4444-555555555555" not in exclusions
        assert exclusions and all(x.startswith("id-") for x in exclusions)

    def test_a_group_exclusion_stays_legible(self) -> None:
        from idpdrift.models import AccessPolicy

        state = make_state(
            policies=[AccessPolicy(policy_id="cap1", display="Require MFA", excluded_groups=("grp-1",))]
        )
        result = run_check("conditional_access", state)
        assert result.observations["policies"]["cap1"]["exclusions"] == ["grp-1"]


class TestToolProseRendersWithoutBackslashes:
    """Markdown escaping is applied to finding text because that text
    interpolates directory-chosen names. The cost is that the tool's *own* prose
    has to avoid the metacharacters, or the reader sees ``account\\(s\\)`` and
    concludes the report is broken."""

    def test_no_finding_from_any_check_renders_a_stray_backslash(self) -> None:
        from conftest import credential, grant, make_config, permission, policy, workload
        from idpdrift.models import ScanReport
        from idpdrift.report import render_markdown

        state = make_state(
            principals=[
                principal(
                    "u1", second_factor=Determination.UNKNOWN, phishing_resistant=Determination.UNKNOWN
                ),
                principal("u2", last_sign_in="not-a-date"),
                principal("g1", kind=PrincipalKind.GUEST, group_count=99),
            ],
            role_assignments=[assignment()],
            workloads=[
                workload(
                    credentials=(credential(expires_at="2026-08-20T00:00:00Z"),),
                    permissions=(permission("Mail.Read"),),
                )
            ],
            oauth_grants=[grant(scopes=("Mail.Read", "Files.Read.All"), tenant_wide=True)],
            policies=[policy(state="disabled")],
        )
        findings = []
        for check in ALL_CHECKS:
            findings.extend(run_check(check, state, make_config()).findings)

        rendered = render_markdown(
            ScanReport(
                started_at="a",
                finished_at="b",
                tool_version="0",
                source="file",
                tenant="corp.example",
                findings=findings,
            )
        )
        assert findings
        assert "\\" not in rendered


class TestSlackSubjectIsInert:
    """A finding's subject is a pseudonym for a person and the raw display name
    for a workload. mrkdwn has no backslash escape, so the subject is placed in
    a code span rather than escaped into a bold run."""

    def test_a_workload_name_cannot_format_itself_in_the_header(self) -> None:
        blocks = _slack_blocks(_finding(subject="*RESOLVED* ~ignore~"))
        header = blocks[3]["text"]["text"]
        assert "`*RESOLVED* ~ignore~`" in header

    def test_a_backtick_in_a_subject_cannot_close_the_span(self) -> None:
        blocks = _slack_blocks(_finding(subject="a`b"))
        assert "`a'b`" in blocks[3]["text"]["text"]


def _slack_blocks(finding: Finding) -> list[dict]:
    """Capture the block list a Slack delivery would post."""
    report = ScanReport(
        started_at="a",
        finished_at="b",
        tool_version="0",
        source="file",
        identities_seen=1,
        findings=[finding],
    )
    captured: dict = {}

    def fake_request(method, url, **kwargs):
        captured.update(kwargs.get("json_body") or {})
        return mock.Mock(status_code=200)

    with (
        mock.patch.object(notify, "safe_request", fake_request),
        mock.patch.dict(os.environ, {"HOOK": "https://hooks.slack.example/services/abc"}),
    ):
        notify.notify(report, NotifyConfig(slack_webhook_url_env="HOOK", min_severity=Severity.INFO))
    return captured["blocks"]


class TestScopeSemantics:
    """A catalog entry that claims the wrong thing costs more than a missing
    one. `okta.users.read` was listed as a mail scope; it reads user profiles,
    and the finding it produced told the reader an integration could read their
    organisation's correspondence when nothing of the sort had been granted."""

    def test_a_user_profile_read_is_not_a_mail_read(self) -> None:
        assert not reads_mail("okta.users.read")
        assert not reads_files("okta.users.read")

    def test_the_real_mail_and_file_scopes_still_match(self) -> None:
        assert reads_mail("Mail.Read")
        assert reads_files("Files.Read.All")

    def test_a_profile_read_grant_produces_no_correspondence_finding(self) -> None:
        from conftest import grant

        result = run_check("oauth_grants", make_state(oauth_grants=[grant(scopes=("okta.users.read",))]))
        assert Issue.OAUTH_SENSITIVE_SCOPE.value not in {f.issue for f in result.findings}
