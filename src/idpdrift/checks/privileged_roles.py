"""Who holds administrative roles, how permanently, and whether they are a person.

This is the check the tool exists for. Everything else here is context for
answering one question on a schedule: *did anybody gain administrative access to
the directory since yesterday, and was it supposed to happen?*

Three posture findings, and the drift rule in :mod:`idpdrift.drift` that turns
the recorded assignments into "new since last scan".

**Standing assignment where just-in-time was expected.** Only produced when the
operator says their tenant runs privileged identity management
(``policy.expect_just_in_time``) *and* the source could actually read eligibility.
Without both, every assignment in the tenant is standing, and saying so several
hundred times is a description of the product rather than a finding.

**Assignment to a non-human account.** A workload holding an administrative role
has no second factor, no sign-in risk evaluation and usually no owner watching
it, so it is a strictly better target than the administrator who created it. The
non-human test is a heuristic and is treated as one: it raises attention on an
assignment, and never dismisses one.
"""

from __future__ import annotations

from typing import Any

from ..catalog import PRIVILEGED_TIERS, looks_non_human
from ..models import CheckResult, Determination, PrincipalKind, plural
from ..severity import Issue
from .base import CheckContext, register

CHECK = "privileged_roles"

# Assignments recorded in the baseline. A directory with more privileged
# assignments than this has a problem the state file cannot help with, and an
# unbounded observation blob would make every run slower and the file unopenable.
MAX_TRACKED_ASSIGNMENTS = 20000


@register(CHECK)
def check_privileged_roles(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)
    coverage = ctx.covers("role_assignments")

    if coverage.is_unknown:
        # Partial, so the scanner merges over the baseline instead of replacing
        # it. Recording "no assignments" here would erase the record of every
        # administrator and then report them all as newly appointed next run.
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "role_assignments"))
        return result

    eligibility = ctx.covers("role_eligibility")
    assignments: dict[str, dict[str, Any]] = {}
    truncated = 0

    for assignment in ctx.state.role_assignments:
        if ctx.is_ignored_principal(assignment.principal_id):
            continue
        tier = ctx.role_tier(assignment.role_name)
        label = ctx.label_for_id(assignment.principal_id, assignment.principal_display)

        if len(assignments) >= MAX_TRACKED_ASSIGNMENTS:
            truncated += 1
            continue

        assignments[assignment.key] = {
            "role": assignment.role_name,
            "tier": tier.value,
            "principal": label,
            "kind": assignment.principal_kind.value,
            "standing": assignment.standing.value,
        }

        if tier not in PRIVILEGED_TIERS:
            # Standard and sensitive roles are recorded so drift can report a
            # change to them, but they do not generate posture findings: an
            # organisation's Reports Readers are not a security backlog.
            continue

        if ctx.policy.expect_just_in_time and eligibility.is_present and assignment.standing.is_present:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.ROLE_ASSIGNMENT_STANDING,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title=f"Standing assignment to {assignment.role_name}",
                    detail=(
                        f"This account holds {assignment.role_name} permanently rather than through "
                        "activation. A standing assignment is available to anyone who compromises the "
                        "account at any moment, with no approval step and no activation record to "
                        "review afterwards."
                    ),
                    remediation=(
                        "Convert the assignment to eligible, so holding the role requires an "
                        "activation that is approved and logged."
                    ),
                    evidence={"role": assignment.role_name, "scope": assignment.scope},
                )
            )

        non_human = looks_non_human(
            kind=assignment.principal_kind,
            display=assignment.principal_display,
        )
        if non_human.is_present:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.ROLE_ASSIGNMENT_NON_HUMAN,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title=f"Non-human account holds {assignment.role_name}",
                    detail=(
                        f"{assignment.role_name} is assigned to what appears to be a workload or "
                        "service account rather than a person. Such an account authenticates with a "
                        "credential rather than a second factor, is rarely covered by conditional "
                        "access, and its sign-ins look identical whether the automation or an "
                        "attacker made them."
                    ),
                    remediation=(
                        "Confirm the automation genuinely needs this role. If it does, scope it "
                        "down, give it a certificate rather than a secret, and give it an owner."
                    ),
                    evidence={
                        "role": assignment.role_name,
                        "principal_kind": assignment.principal_kind.value,
                        "basis": (
                            "the directory records this principal as a workload"
                            if assignment.principal_kind
                            in (PrincipalKind.SERVICE_PRINCIPAL, PrincipalKind.SERVICE_ACCOUNT)
                            else "the account name matches a service-account naming convention"
                        ),
                    },
                )
            )

    if ctx.policy.expect_just_in_time and eligibility.is_unknown:
        result.findings.append(
            ctx.indeterminate(
                CHECK,
                "role_eligibility",
                detail=(
                    "policy.expect_just_in_time is set, but the source could not read role "
                    "eligibility, so a permanent assignment cannot be distinguished from an "
                    "activated one. Standing assignments are not reported rather than reporting "
                    "every assignment in the tenant as standing."
                ),
            )
        )

    if truncated:
        result.findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.FINDINGS_TRUNCATED,
                subject=ctx.state.tenant or "tenant",
                subject_id="tenant",
                determination=Determination.UNKNOWN,
                title=(
                    f"{truncated} role {plural(truncated, 'assignment')} beyond the "
                    "tracking cap were not recorded"
                ),
                detail=(
                    f"More than {MAX_TRACKED_ASSIGNMENTS} role assignments were returned. The "
                    "remainder are neither reported nor baselined, so a change to them will not be "
                    "detected."
                ),
                remediation="Scope the collection to the tenant you mean to monitor.",
                evidence={"dropped": truncated},
            )
        )

    result.observations = {
        "assignments": assignments,
        "eligibility_known": eligibility.value,
        "privileged_count": sum(
            1 for entry in assignments.values() if entry["tier"] in {t.value for t in PRIVILEGED_TIERS}
        ),
    }
    return result
