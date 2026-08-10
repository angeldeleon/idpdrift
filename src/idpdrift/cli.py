"""Command-line interface.

Exit codes are the contract with CI and cron:

* ``0`` — scan completed, nothing at or above the fail-on threshold
* ``1`` — scan completed, findings at or above the threshold
* ``2`` — the scan could not run, or ran degraded (no identities, or over half
  the checks failed)

Keeping "found problems" (1) distinct from "could not check" (2) matters: a
pipeline that treats them alike eventually goes green because the token expired,
which is the worst possible failure for a monitoring tool.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .ai import summarize
from .checks import registered_checks
from .config import ALL_CHECKS, load_config
from .logging_setup import configure_logging
from .models import FACETS, Determination, ScanReport, Severity
from .notify import notify
from .privacy import PrivacyMode
from .report import FORMATS, render
from .runner import scan, state_scope
from .severity import BASE_SEVERITY, TIER_ADJUSTMENT, Issue, RoleTier, rate
from .sources.base import SourceError
from .store import SnapshotStore, StateError
from .validation import ValidationError

log = logging.getLogger("idpdrift")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idpdrift",
        description=(
            "Agentless drift detection for identity and access posture. Read-only: it "
            "reads directory state through APIs you already have and never writes to a tenant."
        ),
    )
    parser.add_argument("--version", action="version", version=f"idpdrift {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    common.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", parents=[common], help="read the tenant, report findings and drift")
    scan_parser.add_argument("-c", "--config", required=True, help="path to the YAML config file")
    scan_parser.add_argument(
        "-o", "--output", default="-", help="write the report here ('-' for stdout, the default)"
    )
    scan_parser.add_argument("-f", "--format", default="markdown", choices=FORMATS)
    scan_parser.add_argument(
        "--no-save", action="store_true", help="do not update the baseline (useful for a dry run)"
    )
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        choices=[s.value for s in Severity],
        help="minimum severity that sets exit code 1; overrides the config",
    )
    scan_parser.add_argument("--no-notify", action="store_true", help="skip all notification delivery")
    scan_parser.add_argument("--no-ai", action="store_true", help="skip LLM summarisation")
    scan_parser.set_defaults(func=cmd_scan)

    coverage_parser = sub.add_parser(
        "coverage",
        parents=[common],
        help="read the tenant and report only what could and could not be determined",
    )
    coverage_parser.add_argument("-c", "--config", required=True)
    coverage_parser.set_defaults(func=cmd_coverage)

    severity_parser = sub.add_parser(
        "severity", parents=[common], help="print the severity table every finding is rated from"
    )
    severity_parser.set_defaults(func=cmd_severity)

    validate_parser = sub.add_parser(
        "validate", parents=[common], help="validate a config file without reading a tenant"
    )
    validate_parser.add_argument("-c", "--config", required=True)
    validate_parser.set_defaults(func=cmd_validate)

    return parser


# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    if args.fail_on:
        config.settings.fail_on = Severity.parse(args.fail_on)

    store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
    try:
        store.check_readable()
    except StateError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    try:
        report = scan(config, store=store, save=not args.no_save)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR
    except StateError as exc:
        log.error("state error: %s", exc)
        return EXIT_ERROR

    if config.ai.enabled and not args.no_ai:
        report.ai_summary = summarize(report, config.ai)

    _write_report(report, args.output, args.format)

    if not args.no_notify:
        for error in notify(report, config.notify, user_agent=config.settings.user_agent):
            log.error("%s", error)

    return _exit_code(report, config.settings.fail_on)


def cmd_coverage(args: argparse.Namespace) -> int:
    """Answer "what can this deployment actually see?" without a full report.

    Worth its own subcommand because it is the first question to ask of a new
    deployment and the one an operator will otherwise answer by reading a report
    and assuming silence means clean.
    """
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    try:
        from .runner import collect

        state = collect(config)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR

    print(f"Source:     {state.source}")
    print(f"Tenant:     {state.tenant or '(not reported)'}")
    print(f"Identities: {state.identity_count}")
    print()
    width = max(len(facet) for facet in FACETS)
    for facet in FACETS:
        determination = state.covers(facet)
        marker = {
            Determination.PRESENT: "read",
            Determination.ABSENT: "confirmed empty",
            Determination.UNKNOWN: "COULD NOT DETERMINE",
        }[determination]
        print(f"  {facet.ljust(width)}  {marker}")

    if state.errors:
        print()
        print("Notes:")
        for error in state.errors[:50]:
            print(f"  - {error}")

    indeterminate = state.indeterminate_facets
    if indeterminate:
        print()
        print(
            f"{len(indeterminate)} facet(s) could not be determined. Nothing is concluded about "
            "them, so a clean report does not mean a clean tenant in those areas."
        )
    return EXIT_OK


def cmd_severity(args: argparse.Namespace) -> int:
    """Print the table, so a disputed rating can be argued about specifically."""
    print("Base severity per issue, assuming the privileged role tier:")
    print()
    width = max(len(issue.value) for issue in Issue)
    for issue in Issue:
        print(f"  {issue.value.ljust(width)}  {BASE_SEVERITY[issue].value}")
    print()
    print("Adjustment by role tier (rank delta, clamped to the enum):")
    for tier, delta in TIER_ADJUSTMENT.items():
        print(f"  {tier.value:<14} {delta:+d}")
    print()
    print("Anything resting on a determination of 'unknown' is capped at low and")
    print("reported as operational, so an unreadable facet can never trip a threshold.")
    print()
    print("Worked example:")
    example = rate(Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.TENANT_ADMIN)
    print(f"  role_assignment_new at the tenant_admin tier -> {example.value}")
    capped = rate(Issue.ROLE_ASSIGNMENT_NEW, determination=Determination.UNKNOWN)
    print(f"  the same issue when the fact could not be determined -> {capped.value}")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    print("Config is valid.")
    print(f"  source:      {config.source.type}")
    print(f"  checks:      {', '.join(config.settings.checks)}")
    print(f"  privacy:     {config.privacy_mode.value}")
    print(f"  fail_on:     {config.settings.fail_on.value}")
    print(f"  dormant:     {config.policy.dormant_days} days")
    print(f"  custom roles:{len(config.policy.privileged_roles):>3} classified in policy")

    if config.privacy_mode is PrivacyMode.IDENTIFIED:
        print()
        print("  NOTE: privacy.mode is 'identified'. Reports will name real accounts.")

    missing: list[str] = []
    if config.source.type == "entra" and config.source.entra and not config.source.entra.client_secret():
        missing.append(config.source.entra.client_secret_env)
    if config.source.type == "okta" and config.source.okta and not config.source.okta.api_token():
        missing.append(config.source.okta.api_token_env)
    if config.notify.slack_webhook_url_env and not config.notify.slack_webhook_url():
        missing.append(config.notify.slack_webhook_url_env)
    if config.notify.webhook_url_env and not config.notify.webhook_url():
        missing.append(config.notify.webhook_url_env)
    if config.ai.enabled and not config.ai.api_key():
        missing.append(config.ai.api_key_env)

    if missing:
        print()
        print("Referenced but unset environment variable(s): " + ", ".join(missing))

    unimplemented = set(config.settings.checks) - set(registered_checks())
    if unimplemented:  # pragma: no cover - the invariants job makes this unreachable
        print(f"Checks with no implementation: {', '.join(sorted(unimplemented))}")
        return EXIT_ERROR

    unknown_checks = set(config.settings.checks) - set(ALL_CHECKS)
    if unknown_checks:  # pragma: no cover - config parsing rejects these first
        print(f"Unknown checks: {', '.join(sorted(unknown_checks))}")
        return EXIT_ERROR

    return EXIT_OK


# --------------------------------------------------------------------------


def _write_report(report: ScanReport, output: str, fmt: str) -> None:
    rendered = render(report, fmt)
    if output == "-":
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    # 0600, for the same reason the state file is: a report from this tool is a
    # list of who administers your tenant and which of them is weakly protected.
    # Inheriting the process umask would leave that world-readable on a shared
    # host or a multi-tenant runner.
    #
    # O_NOFOLLOW for the same reason the state file has it. Reports are usually
    # written to a shared artefact directory on a build agent, and a symlink
    # planted at the path would otherwise redirect that inventory to a file the
    # attacker can read — and then have the chmod below tighten *their* target,
    # which is a working denial of service against anything the service account
    # owns. Failing is the right answer: a report going somewhere unexpected is
    # not a thing to recover from quietly.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        # ELOOP lands here: the path is a symlink and we refused to follow it.
        raise ValidationError(f"cannot write report to {path}: {exc}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        # O_CREAT leaves the mode of an already-existing file alone, and a
        # report path is usually reused run after run, so set it explicitly
        # too — through the descriptor, never the path.
        os.fchmod(handle.fileno(), 0o600)
        handle.write(rendered)
    log.info("wrote %s report to %s", fmt, path)


def _exit_code(report: ScanReport, fail_on: Severity) -> int:
    if report.scan_degraded:
        log.error(
            "scan is degraded (%d identities, %d of %d checks failed); refusing to report a clean result",
            report.identities_seen,
            report.checks_failed,
            report.checks_run,
        )
        return EXIT_ERROR

    highest = report.max_severity
    if highest is not None and highest >= fail_on:
        log.info("highest severity %s meets the %s threshold", highest.value, fail_on.value)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", 0), quiet=getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except (ValidationError, SourceError, StateError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception:  # noqa: BLE001 - exit 1 means "findings", never "crashed"
        # Python exits 1 on an unhandled exception, which is indistinguishable
        # from EXIT_FINDINGS. Anything unexpected must surface as EXIT_ERROR.
        log.exception("unexpected error; the scan did not complete")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
