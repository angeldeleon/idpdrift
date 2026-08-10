"""Snapshot diffing — the part that turns a posture scanner into a monitor.

A posture check tells you that four people hold Global Administrator. You knew
that; three of them are in the change record and the fourth is the break-glass
account. Drift tells you there are five today, and that is either a change
somebody made or an incident, and either way somebody has to answer for it
before the end of the day.

Three rules keep this from becoming a noise generator:

1. **Only meaningful transitions.** An assignment appearing is a finding. An
   assignment disappearing is recorded at INFO, because the report should reflect
   remediation as well as regression. A field that merely re-serialised
   differently is not a transition at all, which is why every check sorts its
   observations.

2. **Indeterminate is not a transition.** A facet the source could not read this
   run is merged over the baseline rather than replacing it, so there is nothing
   here to diff and no phantom "everything was removed". This module additionally
   refuses to compare a value against a baseline that recorded it as unknown.

3. **Bulk changes aggregate.** Forty new assignments at once is a migration, a
   group-based rollout, or somebody re-creating a tenant — one finding, with the
   count. Two new assignments is the shape of an intrusion, and both are named.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .catalog import reads_files, reads_mail, scope_impact
from .models import Determination, Finding, FindingKind, Snapshot, plural
from .severity import Issue, RoleTier, explain, rate

log = logging.getLogger(__name__)

# Above this many changes of one kind, the change is a rollout rather than an
# anomaly and is reported once with a count.
BULK_THRESHOLD = 25
MAX_NAMED = 10
MAX_DRIFT_FINDINGS = 300

DriftRule = Callable[[str, dict[str, Any], dict[str, Any]], list[Finding]]

_RULES: dict[str, DriftRule] = {}


def rule(check: str) -> Callable[[DriftRule], DriftRule]:
    def decorator(func: DriftRule) -> DriftRule:
        _RULES[check] = func
        return func

    return decorator


def diff_snapshots(previous: Snapshot | None, current: Snapshot) -> list[Finding]:
    """Compare two snapshots of the same tenant and return drift findings.

    Returns an empty list when there is no baseline. A first run has nothing to
    compare against, and manufacturing findings there would misrepresent an
    existing tenant as a set of changes somebody made overnight.
    """
    if previous is None:
        return []

    findings: list[Finding] = []
    for check, current_obs in sorted(current.checks.items()):
        previous_obs = previous.checks.get(check)
        if previous_obs is None:
            # The check did not run last time (newly enabled, or its facet was
            # unreadable). Absence of a baseline is not drift.
            continue
        handler = _RULES.get(check)
        if handler is None:
            continue
        try:
            findings.extend(handler(current.tenant, previous_obs, current_obs))
        except (AttributeError, KeyError, TypeError, ValueError):
            # A malformed historical snapshot must not abort the whole scan.
            # AttributeError is included deliberately: a hand-edited or
            # older-format state file can hold a string where a mapping is
            # expected, and .get() on it would otherwise kill the run.
            log.warning("skipping drift comparison for %s: malformed baseline", check)
            continue

    if len(findings) > MAX_DRIFT_FINDINGS:
        dropped = len(findings) - MAX_DRIFT_FINDINGS
        findings.sort(key=lambda f: -f.severity.rank)
        findings = findings[:MAX_DRIFT_FINDINGS]
        findings.append(
            _finding(
                Issue.FINDINGS_TRUNCATED,
                subject=current.tenant or "tenant",
                subject_id="tenant",
                check="drift",
                title=f"{dropped} further changes were not reported",
                detail=(
                    "The number of changes since the last scan exceeded the reporting cap. That "
                    "usually means a migration, a re-created tenant, or a stale baseline."
                ),
                remediation="Compare against the previous snapshot directly if you need the full list.",
                determination=Determination.UNKNOWN,
            )
        )

    return findings


def _finding(
    issue: Issue,
    *,
    subject: str,
    subject_id: str,
    check: str,
    title: str,
    detail: str,
    remediation: str = "",
    tier: RoleTier = RoleTier.PRIVILEGED,
    determination: Determination = Determination.PRESENT,
    evidence: dict[str, Any] | None = None,
    references: tuple[str, ...] = (),
) -> Finding:
    payload = dict(evidence or {})
    payload["severity_basis"] = explain(issue, tier=tier, determination=determination)
    return Finding(
        subject=subject,
        subject_id=subject_id,
        check=check,
        issue=issue.value,
        kind=FindingKind.DRIFT if not determination.is_unknown else FindingKind.OPERATIONAL,
        severity=rate(issue, tier=tier, determination=determination),
        title=title,
        detail=detail,
        remediation=remediation,
        determination=determination,
        evidence=payload,
        references=references,
    )


def _tier(value: Any) -> RoleTier:
    try:
        return RoleTier(str(value))
    except ValueError:
        return RoleTier.STANDARD


def _mapping(obs: dict[str, Any], key: str) -> dict[str, Any]:
    value = obs.get(key)
    return value if isinstance(value, dict) else {}


def _bulk(
    issue: Issue,
    *,
    tenant: str,
    check: str,
    changes: list[str],
    noun: str,
    detail: str,
    remediation: str,
) -> Finding:
    shown = sorted(changes)[:MAX_NAMED]
    return _finding(
        issue,
        subject=f"{len(changes)} {noun}",
        subject_id=f"tenant:{issue.value}",
        check=check,
        tier=RoleTier.SENSITIVE,
        title=f"{len(changes)} {noun} changed since the last scan",
        detail=detail + f" Showing {len(shown)} of {len(changes)}.",
        remediation=remediation,
        evidence={"changes": shown, "total": len(changes), "tenant": tenant},
    )


# --------------------------------------------------------------------------
# privileged_roles
# --------------------------------------------------------------------------


@rule("privileged_roles")
def _role_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "assignments")
    after = _mapping(new, "assignments")

    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))

    if len(added) > BULK_THRESHOLD:
        findings.append(
            _bulk(
                Issue.ROLE_ASSIGNMENT_NEW,
                tenant=tenant,
                check="privileged_roles",
                changes=[f"{after[k].get('principal', k)} -> {after[k].get('role', '?')}" for k in added],
                noun="role assignments",
                detail=(
                    "That many assignments appearing at once is a migration, a group-based "
                    "rollout, or a re-created tenant rather than an intrusion, so they are reported "
                    "together."
                ),
                remediation="Confirm the bulk change was expected, then let the next run baseline it.",
            )
        )
    else:
        for key in added:
            entry = after[key]
            tier = _tier(entry.get("tier"))
            principal = str(entry.get("principal") or key)
            role = str(entry.get("role") or "an unnamed role")
            findings.append(
                _finding(
                    Issue.ROLE_ASSIGNMENT_NEW,
                    subject=principal,
                    subject_id=principal,
                    check="privileged_roles",
                    tier=tier,
                    title=f"New assignment to {role}",
                    detail=(
                        f"This principal did not hold {role} at the previous scan and does now. A "
                        "role assignment appearing outside a change record is the single clearest "
                        "signal this tool produces."
                    ),
                    remediation=(
                        "Match it to an approved change. If there is none, treat the granting "
                        "account as compromised until you can show otherwise."
                    ),
                    evidence={"role": role, "tier": tier.value, "standing": entry.get("standing")},
                )
            )

    if len(removed) > BULK_THRESHOLD:
        findings.append(
            _bulk(
                Issue.ROLE_ASSIGNMENT_REMOVED,
                tenant=tenant,
                check="privileged_roles",
                changes=[f"{before[k].get('principal', k)} -> {before[k].get('role', '?')}" for k in removed],
                noun="role assignments",
                detail="Assignments present at the previous scan are gone.",
                remediation="Confirm the removals were intentional.",
            )
        )
    else:
        for key in removed:
            entry = before[key]
            principal = str(entry.get("principal") or key)
            role = str(entry.get("role") or "an unnamed role")
            findings.append(
                _finding(
                    Issue.ROLE_ASSIGNMENT_REMOVED,
                    subject=principal,
                    subject_id=principal,
                    check="privileged_roles",
                    tier=_tier(entry.get("tier")),
                    title=f"Assignment to {role} was removed",
                    detail=(
                        "Recorded so the report reflects remediation as well as regression. An "
                        "assignment disappearing is usually a leaver process working."
                    ),
                    evidence={"role": role},
                )
            )

    for key in sorted(set(before) & set(after)):
        was = Determination.parse(before[key].get("standing"))
        now = Determination.parse(after[key].get("standing"))
        if not (was.is_absent and now.is_present):
            # Anything involving UNKNOWN on either side is not a transition. An
            # eligibility lookup that failed this run would otherwise read as
            # "every just-in-time assignment became permanent overnight".
            continue
        entry = after[key]
        principal = str(entry.get("principal") or key)
        role = str(entry.get("role") or "an unnamed role")
        findings.append(
            _finding(
                Issue.ROLE_ASSIGNMENT_ELEVATED,
                subject=principal,
                subject_id=principal,
                check="privileged_roles",
                tier=_tier(entry.get("tier")),
                title=f"{role} became a standing assignment",
                detail=(
                    "The assignment previously required activation and is now permanent. The "
                    "approval step and the activation record that made the role reviewable are "
                    "both gone."
                ),
                remediation="Convert it back to eligible unless the change was approved.",
                evidence={"role": role},
            )
        )

    return findings


# --------------------------------------------------------------------------
# auth_strength
# --------------------------------------------------------------------------


@rule("auth_strength")
def _auth_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "accounts")
    after = _mapping(new, "accounts")

    for label in sorted(set(before) & set(after)):
        old_entry, new_entry = before[label], after[label]
        tier = _tier(new_entry.get("tier"))

        for field, description in (
            ("phishing_resistant", "phishing-resistant method"),
            ("second_factor", "second factor"),
        ):
            was = Determination.parse(old_entry.get(field))
            now = Determination.parse(new_entry.get(field))
            if not (was.is_present and now.is_absent):
                # Requires a determinate answer on both sides. A run where the
                # registration report was refused must not read as every
                # administrator deregistering their security key overnight.
                continue
            findings.append(
                _finding(
                    Issue.MFA_WEAKENED,
                    subject=label,
                    subject_id=label,
                    check="auth_strength",
                    tier=tier,
                    title=f"Privileged account lost its {description}",
                    detail=(
                        f"This account had a {description} at the previous scan and does not now. "
                        "Deregistering a strong method is a step an attacker takes deliberately "
                        "after taking over an account, because it removes the thing that would "
                        "stop them signing in again."
                    ),
                    remediation=(
                        "Confirm the account holder made this change. If they did not, treat the "
                        "account as compromised and re-register from a known-good device."
                    ),
                    evidence={
                        "previous_methods": old_entry.get("methods"),
                        "current_methods": new_entry.get("methods"),
                    },
                )
            )
    return findings


# --------------------------------------------------------------------------
# dormancy
# --------------------------------------------------------------------------


@rule("dormancy")
def _dormancy_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    """Report a dormant privileged account coming back to life.

    Deliberately not "became dormant": the posture check already reports every
    dormant privileged account on every run, and a drift finding saying the same
    thing on the day it crossed the threshold is the same line twice. What the
    baseline adds is the opposite transition — an account nobody had used for
    months is being used again, which is either a returning employee or somebody
    who found the credential.
    """
    was_dormant = {str(x) for x in (old.get("dormant_privileged") or [])}
    is_dormant = {str(x) for x in (new.get("dormant_privileged") or [])}
    tracked_now = _mapping(new, "accounts")

    reactivated = sorted(was_dormant - is_dormant)
    if not reactivated:
        return []

    findings: list[Finding] = []
    for label in reactivated[:MAX_NAMED]:
        findings.append(
            _finding(
                Issue.DORMANT_REACTIVATED,
                subject=label,
                subject_id=label,
                check="dormancy",
                tier=_tier(tracked_now.get(label, {}).get("tier")),
                title="Dormant privileged account signed in again",
                detail=(
                    "This account holds an administrative role, had not signed in inside the "
                    "dormancy window at the previous scan, and has now. Nobody was watching it "
                    "while it was idle, so there is no baseline of normal behaviour to compare "
                    "this sign-in against."
                ),
                remediation="Confirm with the account holder that the sign-in was theirs.",
                evidence={"threshold_days": new.get("threshold_days")},
            )
        )
    return findings


# --------------------------------------------------------------------------
# service_principals
# --------------------------------------------------------------------------


@rule("service_principals")
def _workload_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "workloads")
    after = _mapping(new, "workloads")

    # Gathered across every workload before anything is emitted, because the
    # bulk rule is either/or: the role and grant rules above report the
    # aggregate *instead of* the individual findings, and reporting both meant a
    # scripted rotation produced twenty-five high-severity lines and then a line
    # saying it was a scripted rotation.
    new_credentials: list[tuple[str, str, str, dict[str, Any]]] = []
    for workload_id in sorted(set(before) & set(after)):
        old_entry, new_entry = before[workload_id], after[workload_id]
        label = str(new_entry.get("display") or workload_id)

        old_creds = old_entry.get("credentials")
        new_creds = new_entry.get("credentials")
        if isinstance(old_creds, dict) and isinstance(new_creds, dict):
            for credential_id in sorted(set(new_creds) - set(old_creds)):
                entry = new_creds[credential_id] if isinstance(new_creds[credential_id], dict) else {}
                new_credentials.append((workload_id, label, credential_id, entry))

        old_scopes = {str(s) for s in (old_entry.get("application_permissions") or [])}
        new_scopes = {str(s) for s in (new_entry.get("application_permissions") or [])}
        for scope in sorted(new_scopes - old_scopes):
            impact = scope_impact(scope)
            findings.append(
                _finding(
                    Issue.APP_PERMISSION_NEW,
                    subject=label,
                    subject_id=workload_id,
                    check="service_principals",
                    tier=RoleTier.TENANT_ADMIN if impact else RoleTier.PRIVILEGED,
                    title=f"New application permission {scope}",
                    detail=(
                        "This application gained an app-only permission since the last scan, which "
                        "applies with no user present to every object in the tenant."
                        + (f" It {impact}." if impact else "")
                    ),
                    remediation="Confirm the grant went through your consent review.",
                    evidence={"scope": scope},
                )
            )

    if len(new_credentials) > BULK_THRESHOLD:
        findings.append(
            _bulk(
                Issue.CREDENTIAL_NEW,
                tenant=tenant,
                check="service_principals",
                changes=[f"{label}:{credential_id}" for _, label, credential_id, _ in new_credentials],
                noun="application credentials",
                detail="That many credentials appearing at once is a scripted rotation.",
                remediation="Confirm the rotation was yours.",
            )
        )
    else:
        for workload_id, label, credential_id, entry in new_credentials:
            findings.append(
                _finding(
                    Issue.CREDENTIAL_NEW,
                    subject=label,
                    subject_id=workload_id,
                    check="service_principals",
                    tier=RoleTier.PRIVILEGED,
                    title=f"New {entry.get('kind', 'unknown')} credential on an existing application",
                    detail=(
                        "A credential was added to an application registration that already "
                        "existed. This is the standard way to keep access to a tenant after the "
                        "account used to get in is reset: the application keeps every permission "
                        "it already had, and the new credential is one more row in a list nobody "
                        "reviews."
                    ),
                    remediation=(
                        "Match it to a rotation you performed. If there is none, delete it and "
                        "review everything the application can reach."
                    ),
                    evidence={"credential": credential_id, "expires": entry.get("expires")},
                    references=("https://attack.mitre.org/techniques/T1098/001/",),
                )
            )

    return findings


# --------------------------------------------------------------------------
# oauth_grants
# --------------------------------------------------------------------------


@rule("oauth_grants")
def _grant_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "grants")
    after = _mapping(new, "grants")

    added = sorted(set(after) - set(before))
    if len(added) > BULK_THRESHOLD:
        findings.append(
            _bulk(
                Issue.OAUTH_GRANT_NEW,
                tenant=tenant,
                check="oauth_grants",
                changes=[str(after[k].get("client") or k) for k in added],
                noun="consent grants",
                detail="A large number of applications were consented to at once.",
                remediation="Confirm this was an onboarding you performed.",
            )
        )
    else:
        for key in added:
            entry = after[key]
            label = str(entry.get("client") or key)
            scopes = [str(s) for s in (entry.get("scopes") or [])]
            sensitive = [s for s in scopes if reads_mail(s) or reads_files(s)]
            findings.append(
                _finding(
                    Issue.OAUTH_GRANT_NEW,
                    subject=label,
                    subject_id=label,
                    check="oauth_grants",
                    tier=RoleTier.PRIVILEGED
                    if (sensitive or entry.get("tenant_wide"))
                    else RoleTier.SENSITIVE,
                    title="New consent grant",
                    detail=(
                        "An application was granted consent since the last scan."
                        + (" The consent is tenant-wide." if entry.get("tenant_wide") else "")
                        + (
                            f" It can read mail or files through {', '.join(sorted(sensitive)[:5])}."
                            if sensitive
                            else ""
                        )
                        + " Illicit consent needs no credential and survives a password reset, so a"
                        " grant nobody requested is worth treating as an intrusion until shown"
                        " otherwise."
                    ),
                    remediation=(
                        "Revoke the grant and its refresh tokens if you cannot attribute it to a "
                        "deliberate onboarding."
                    ),
                    evidence={"scopes": scopes[:50], "tenant_wide": bool(entry.get("tenant_wide"))},
                    references=("https://attack.mitre.org/techniques/T1528/",),
                )
            )

    for key in sorted(set(before) & set(after)):
        old_entry, new_entry = before[key], after[key]
        label = str(new_entry.get("client") or key)
        old_scopes = {str(s) for s in (old_entry.get("scopes") or [])}
        new_scopes = {str(s) for s in (new_entry.get("scopes") or [])}
        gained = sorted(new_scopes - old_scopes)
        if gained:
            sensitive = [s for s in gained if reads_mail(s) or reads_files(s)]
            findings.append(
                _finding(
                    Issue.OAUTH_SCOPE_ADDED,
                    subject=label,
                    subject_id=label,
                    check="oauth_grants",
                    tier=RoleTier.PRIVILEGED if sensitive else RoleTier.SENSITIVE,
                    title=f"Consent grant gained {len(gained)} {plural(len(gained), 'scope')}",
                    detail=(
                        "An application that already had consent now has more of it. Incremental "
                        "consent is how an application that looked harmless at review time acquires "
                        "the permission that matters, without appearing as a new grant."
                    ),
                    remediation="Confirm the additional scopes were requested through your review process.",
                    evidence={"added": gained[:50]},
                )
            )

        if not old_entry.get("tenant_wide") and new_entry.get("tenant_wide"):
            findings.append(
                _finding(
                    Issue.OAUTH_TENANT_WIDE,
                    subject=label,
                    subject_id=label,
                    check="oauth_grants",
                    tier=RoleTier.PRIVILEGED,
                    title="Consent was escalated to tenant-wide",
                    detail=(
                        "A grant that applied to one user now applies to every account in the "
                        "organisation. Whatever the application could read for one person, it can "
                        "now read for everyone."
                    ),
                    remediation="Confirm an administrator made this decision deliberately.",
                    evidence={"scopes": [str(s) for s in (new_entry.get("scopes") or [])][:50]},
                )
            )

    return findings


# --------------------------------------------------------------------------
# guests
# --------------------------------------------------------------------------


@rule("guests")
def _guest_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "guests")
    after = _mapping(new, "guests")

    for label in sorted(set(before) & set(after)):
        old_entry, new_entry = before[label], after[label]
        old_roles = {str(r) for r in (old_entry.get("roles") or [])}
        new_roles = {str(r) for r in (new_entry.get("roles") or [])}
        gained = sorted(new_roles - old_roles)

        old_groups = _as_int(old_entry.get("group_count"))
        new_groups = _as_int(new_entry.get("group_count"))
        # -1 is how the checks record "the source could not count groups". A
        # transition into or out of that sentinel is a coverage change, not a
        # guest gaining access.
        group_gain = new_groups - old_groups if old_groups is not None and new_groups is not None else 0

        if not gained and group_gain <= 0:
            continue

        findings.append(
            _finding(
                Issue.GUEST_GAINED_ACCESS,
                subject=label,
                subject_id=label,
                check="guests",
                tier=RoleTier.PRIVILEGED if gained else RoleTier.SENSITIVE,
                title="Guest account gained access",
                detail=(
                    "An external identity now reaches further into the tenant than at the previous "
                    "scan."
                    + (
                        f" It gained the {plural(len(gained), 'role')}: {', '.join(gained[:5])}."
                        if gained
                        else ""
                    )
                    + (
                        f" It joined {group_gain} further {plural(group_gain, 'group')}."
                        if group_gain > 0
                        else ""
                    )
                ),
                remediation="Confirm the additional access matches a current engagement.",
                evidence={"roles_gained": gained[:20], "groups_gained": max(group_gain, 0)},
            )
        )
    return findings


# --------------------------------------------------------------------------
# conditional_access
# --------------------------------------------------------------------------

_POLICY_STRENGTH = {"disabled": 0, "report_only": 1, "enabled": 2}


@rule("conditional_access")
def _policy_drift(tenant: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    before = _mapping(old, "policies")
    after = _mapping(new, "policies")

    for policy_id in sorted(set(before) - set(after)):
        entry = before[policy_id]
        label = str(entry.get("display") or policy_id)
        findings.append(
            _finding(
                Issue.POLICY_REMOVED,
                subject=label,
                subject_id=policy_id,
                check="conditional_access",
                tier=RoleTier.PRIVILEGED,
                title="Access policy was deleted",
                detail=(
                    "A policy present at the previous scan no longer exists. Deleting a policy is "
                    "quieter than disabling one: there is no longer an object to notice."
                ),
                remediation="Restore it, or record the decision to retire it.",
                evidence={"previous_state": entry.get("state")},
            )
        )

    for policy_id in sorted(set(before) & set(after)):
        old_entry, new_entry = before[policy_id], after[policy_id]
        label = str(new_entry.get("display") or policy_id)
        old_state = str(old_entry.get("state") or "unknown")
        new_state = str(new_entry.get("state") or "unknown")
        old_strength = _POLICY_STRENGTH.get(old_state)
        new_strength = _POLICY_STRENGTH.get(new_state)

        if old_strength is not None and new_strength is not None and new_strength < old_strength:
            issue = Issue.POLICY_DISABLED if new_state == "disabled" else Issue.POLICY_REPORT_ONLY
            findings.append(
                _finding(
                    issue,
                    subject=label,
                    subject_id=policy_id,
                    check="conditional_access",
                    tier=RoleTier.PRIVILEGED,
                    title=f"Access policy weakened: {old_state} -> {new_state}",
                    detail=(
                        "Enforcement was reduced since the previous scan. Sign-ins that would have "
                        "been blocked are now allowed, and nothing about the tenant looks different "
                        "until somebody uses that."
                    ),
                    remediation=(
                        "Confirm this was an approved, time-boxed change; otherwise restore the "
                        "previous state."
                    ),
                    evidence={"previous": old_state, "current": new_state},
                )
            )

        old_exclusions = {str(x) for x in (old_entry.get("exclusions") or [])}
        new_exclusions = {str(x) for x in (new_entry.get("exclusions") or [])}
        added = sorted(new_exclusions - old_exclusions)
        if added:
            findings.append(
                _finding(
                    Issue.POLICY_EXCLUSION_ADDED,
                    subject=label,
                    subject_id=policy_id,
                    check="conditional_access",
                    tier=RoleTier.PRIVILEGED,
                    title=f"{len(added)} {plural(len(added), 'exclusion')} added to an access policy",
                    detail=(
                        "Principals were exempted from this policy since the last scan. Adding "
                        "oneself to an exclusion list is a quieter way to bypass a control than "
                        "disabling it: the policy still shows as enabled, and the exclusion list is "
                        "several clicks below where anybody looks."
                    ),
                    remediation=(
                        "Confirm each addition. An exclusion added outside a change record should "
                        "be treated as an attempt to bypass the control."
                    ),
                    evidence={"added": added[:50], "total_exclusions": len(new_exclusions)},
                )
            )

    return findings


def _as_int(value: Any) -> int | None:
    """Parse a count, mapping the -1 "not counted" sentinel to None."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return None if parsed < 0 else parsed


def registered_rules() -> tuple[str, ...]:
    return tuple(sorted(_RULES))


__all__ = ["diff_snapshots", "rule", "registered_rules", "BULK_THRESHOLD", "MAX_DRIFT_FINDINGS"]
