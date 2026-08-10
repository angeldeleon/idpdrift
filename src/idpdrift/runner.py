"""Scan orchestration.

Collect once, run every configured check against that one collection, fold the
observations into a snapshot, diff the snapshot against the baseline, persist,
report. Kept out of the CLI so the whole pipeline can be tested without a process
boundary.

Checks run sequentially and in memory. Unlike a DNS or endpoint scanner there is
no per-check I/O to overlap: the source has already produced the complete state,
and a check is a pass over it. That also means one hostile object cannot hang a
worker pool, because there is no worker pool.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from . import __version__
from .checks import CheckContext, get_check
from .config import Config
from .drift import diff_snapshots
from .models import (
    CheckResult,
    Determination,
    Finding,
    FindingKind,
    IdentityState,
    ScanReport,
    Severity,
    Snapshot,
    plural,
)
from .privacy import Pseudonymiser
from .severity import Issue, rate
from .sources import EntraSource, FileSource, OktaSource
from .sources.base import Source, SourceError
from .store import SnapshotStore

log = logging.getLogger(__name__)

# Per-check cap. One misconfigured area of a tenant must not be able to drown the
# report for the rest of it; the count is reported instead.
MAX_FINDINGS_PER_CHECK = 200


def state_scope(config: Config) -> str:
    """A stable namespace for this config's snapshots.

    Derived from the source type and its target so that two configs sharing a
    state file keep separate baselines. Hashed rather than stored plainly because
    a tenant id is an identifier for an organisation, and the state file is
    routinely committed to a private repository.
    """
    if config.source.type == "entra" and config.source.entra is not None:
        target = config.source.entra.tenant_id
    elif config.source.type == "okta" and config.source.okta is not None:
        target = config.source.okta.org_url
    elif config.source.file is not None:
        target = str(Path(config.source.file.path).expanduser().resolve())
    else:  # pragma: no cover - config parsing guarantees one of the three
        target = ""
    digest = hashlib.sha256(f"{config.source.type}:{target}".encode()).hexdigest()
    return f"{config.source.type}-{digest[:12]}"


def build_source(config: Config) -> Source:
    """Construct the configured source. Read-only by construction."""
    if config.source.type == "entra":
        if config.source.entra is None:  # pragma: no cover - guaranteed by config parsing
            raise SourceError("entra source is selected but not configured")
        return EntraSource(
            config.source.entra,
            timeout=config.settings.http_timeout,
            user_agent=config.settings.user_agent,
            max_identities=config.settings.max_identities,
        )
    if config.source.type == "okta":
        if config.source.okta is None:  # pragma: no cover - guaranteed by config parsing
            raise SourceError("okta source is selected but not configured")
        return OktaSource(
            config.source.okta,
            timeout=config.settings.http_timeout,
            user_agent=config.settings.user_agent,
            max_identities=config.settings.max_identities,
        )
    if config.source.file is None:  # pragma: no cover - guaranteed by config parsing
        raise SourceError("file source is selected but not configured")
    return FileSource(config.source.file, max_identities=config.settings.max_identities)


def collect(config: Config) -> IdentityState:
    return build_source(config).collect()


def scan(
    config: Config,
    *,
    state: IdentityState | None = None,
    store: SnapshotStore | None = None,
    save: bool = True,
) -> ScanReport:
    """Run a full scan and return the report."""
    started = Snapshot.now_iso()

    if state is None:
        state = collect(config)

    pseudonymiser = Pseudonymiser(config.settings.salt_path, mode=config.privacy_mode)

    def label(principal_id: str, display: str) -> str:
        return pseudonymiser.principal_label(principal_id, display)

    baseline = store.get() if store is not None else None
    ctx = CheckContext(state=state, config=config, label=label)

    snapshot = Snapshot(
        tenant=state.tenant or (config.source.type),
        collected_at=state.collected_at,
        source=state.source,
        coverage={facet: value.value for facet, value in sorted(state.coverage.items())},
    )

    findings: list[Finding] = []
    checks_run = 0
    checks_failed = 0

    for check_name in config.settings.checks:
        checks_run += 1
        try:
            result = get_check(check_name)(ctx)
        except Exception as exc:  # noqa: BLE001 - a crashing check must not kill the scan
            log.exception("check %s crashed", check_name)
            result = CheckResult(check=check_name, error=f"internal error: {type(exc).__name__}: {exc}")

        if result.error:
            checks_failed += 1
            snapshot.errors[check_name] = result.error
            findings.append(_check_failed(check_name, result.error, snapshot.tenant))
            # A check that errored has unreliable observations. Recording them
            # would make the next run diff good data against bad and emit phantom
            # drift, so failed checks contribute nothing and simply leave the
            # previous baseline in place.
            continue

        findings.extend(_capped(result, snapshot.tenant))

        if not result.observations:
            continue
        if result.partial and baseline is not None:
            # Layer the partial observation over the last known-good one so
            # facets the check could not determine this run survive. Replacing
            # would erase the baseline for an unreadable facet and report the
            # whole of it as new on the following run.
            merged = dict(baseline.checks.get(check_name, {}))
            merged.update(result.observations)
            snapshot.checks[check_name] = merged
        else:
            snapshot.checks[check_name] = result.observations

    baseline_available = baseline is not None
    baseline_warning: str | None = None
    if baseline is not None:
        if _shares_nothing(baseline, snapshot):
            # Diffing would silently produce nothing while the report claimed a
            # baseline comparison — the failure this tool exists to avoid,
            # applied to itself.
            baseline_warning = (
                "the stored baseline shares no observations with this collection, so no drift "
                "could be computed. This usually means the tenant was re-created, the source "
                "changed, or the state file belongs to a different config."
            )
            log.warning("%s", baseline_warning)
            findings.append(
                Finding(
                    subject=snapshot.tenant,
                    subject_id="tenant",
                    check="baseline",
                    issue=Issue.BASELINE_MISMATCH.value,
                    kind=FindingKind.OPERATIONAL,
                    severity=rate(Issue.BASELINE_MISMATCH, determination=Determination.UNKNOWN),
                    title="The baseline does not correspond to this tenant",
                    detail=baseline_warning,
                    remediation="Move the state file aside to start a fresh baseline.",
                    determination=Determination.UNKNOWN,
                )
            )
        findings.extend(diff_snapshots(baseline, snapshot))

    # Carry forward observations for checks that did not run this time, so that
    # narrowing settings.checks for one run does not erase their history.
    if baseline is not None:
        for check_name, observations in baseline.checks.items():
            snapshot.checks.setdefault(check_name, observations)

    report = ScanReport(
        started_at=started,
        finished_at=Snapshot.now_iso(),
        tool_version=__version__,
        source=state.source,
        tenant=snapshot.tenant,
        snapshot=snapshot,
        findings=findings,
        baseline_available=baseline_available,
        identities_seen=state.identity_count,
        checks_run=checks_run,
        checks_failed=checks_failed,
        indeterminate_facets=state.indeterminate_facets,
        collection_errors=[*state.errors, *([baseline_warning] if baseline_warning else [])],
    )

    report.findings.sort(key=lambda f: (-f.severity.rank, f.kind.value, f.check, f.subject, f.title))

    # Persist last. A scan that produced a report but could not save is still
    # useful; a scan that saved a baseline it then failed to report on is not.
    if save and store is not None:
        if state.identity_count == 0:
            # Saving an empty collection would make the next run report the whole
            # directory as newly created.
            log.warning("collection returned no identities; not updating the baseline")
        else:
            store.save(snapshot)

    return report


def _capped(result: CheckResult, tenant: str) -> list[Finding]:
    if len(result.findings) <= MAX_FINDINGS_PER_CHECK:
        return result.findings
    dropped = len(result.findings) - MAX_FINDINGS_PER_CHECK
    kept = sorted(result.findings, key=lambda f: -f.severity.rank)[:MAX_FINDINGS_PER_CHECK]
    kept.append(
        Finding(
            subject=tenant,
            subject_id="tenant",
            check=result.check,
            issue=Issue.FINDINGS_TRUNCATED.value,
            kind=FindingKind.OPERATIONAL,
            severity=rate(Issue.FINDINGS_TRUNCATED, determination=Determination.UNKNOWN),
            title=f"{dropped} further {result.check} {plural(dropped, 'finding')} not reported",
            detail=(
                f"This check produced more than {MAX_FINDINGS_PER_CHECK} findings. The most severe "
                "are shown; the rest are suppressed so that one area of the tenant cannot drown out "
                "the others."
            ),
            remediation="Narrow the scope, or work through this check's findings in the identity provider.",
            determination=Determination.UNKNOWN,
            evidence={"dropped": dropped},
        )
    )
    return kept


def _check_failed(check_name: str, error: str, tenant: str) -> Finding:
    return Finding(
        subject=tenant,
        subject_id="tenant",
        check=check_name,
        issue=Issue.FACET_INDETERMINATE.value,
        kind=FindingKind.OPERATIONAL,
        severity=Severity.LOW,
        title=f"The {check_name} check did not complete",
        detail=(
            f"{error}. Nothing this check would have reported is in this report, and its previous "
            "observations were left in place rather than overwritten."
        ),
        remediation="Re-run with -v to see the failure in context.",
        determination=Determination.UNKNOWN,
    )


def _shares_nothing(baseline: Snapshot, current: Snapshot) -> bool:
    """True when the two snapshots have no check in common with content.

    Deliberately not "the tenant ids differ": the store already namespaces by
    scope, and a tenant renamed in the export would otherwise read as a mismatch
    forever.
    """
    if not baseline.checks or not current.checks:
        return False
    shared = set(baseline.checks) & set(current.checks)
    return not any(baseline.checks.get(name) and current.checks.get(name) for name in shared)
