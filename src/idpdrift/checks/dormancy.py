"""Accounts nobody is using that can still do things.

A dormant account is not dangerous because it is idle. It is dangerous because
nobody would notice it being used. The person who owned it has moved on or moved
teams, the mailbox goes to nobody, and a sign-in from an unfamiliar country
produces no complaint because there is no one to complain.

Two findings, and the distinction between them is the point:

**Dormant but still holding access.** No interactive sign-in inside the window,
and still a member of groups or a holder of roles. Worse the more the account can
do, which is what the tier adjustment in the severity table is for.

**Disabled and still holding a privileged role.** Disabling an account does not
remove its role assignments. Re-enabling it — a helpdesk action, requiring far
less than the role itself — restores every one of them at once, which makes a
disabled administrator a quieter path back in than creating a new one.

The tri-state governs the first of these completely. "No last sign-in timestamp"
is returned both by an account that has never signed in and by a directory that
will not tell you: on Entra, sign-in activity needs an additional licence and an
additional scope, and a tenant without them is normal rather than broken.
Treating the second case as the first reports the entire directory as dormant on
the first run, which is not a report anybody reads twice.
"""

from __future__ import annotations

from typing import Any

from ..catalog import PRIVILEGED_TIERS
from ..models import CheckResult, PrincipalKind, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, days_between, parse_timestamp, register

CHECK = "dormancy"

MAX_TRACKED_ACCOUNTS = 5000
MAX_NAMED_IN_AGGREGATE = 10


@register(CHECK)
def check_dormancy(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)

    sign_in = ctx.covers("sign_in_activity")
    groups_known = ctx.covers("group_membership").is_present
    roles_known = ctx.covers("role_assignments").is_present

    role_tiers = _role_tiers(ctx) if roles_known else {}
    threshold = ctx.policy.dormant_days

    dormant_privileged: list[str] = []
    dormant_with_groups: list[str] = []
    disabled_with_role: list[str] = []
    tracked: dict[str, dict[str, Any]] = {}
    unparseable = 0

    if sign_in.is_unknown:
        # Not a failure of the whole check: the disabled-with-role finding below
        # needs only the account's enabled state, which is a different facet.
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "sign_in_activity"))

    for principal in ctx.state.principals:
        if ctx.is_ignored_principal(principal.principal_id, principal.upn):
            continue
        if principal.kind is PrincipalKind.SERVICE_PRINCIPAL:
            # A workload identity has no interactive sign-in by construction, so
            # "has not signed in for 90 days" is a description of what it is.
            continue

        label = ctx.principal_label(principal)
        tier = role_tiers.get(principal.principal_id)

        if principal.enabled.is_absent and tier is not None:
            disabled_with_role.append(label)
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.DISABLED_WITH_ROLE,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title="Disabled account still holds a privileged role",
                    detail=(
                        "The account cannot sign in today, but the role assignment survives being "
                        "disabled. Re-enabling an account is a routine helpdesk action that needs "
                        "far less privilege than the role it would restore, so this is a quieter "
                        "way back into the tenant than creating a new administrator."
                    ),
                    remediation="Remove the role assignment as part of the leaver process, not just the account.",
                    evidence={"roles": sorted(_roles_for(ctx, principal.principal_id))[:20]},
                )
            )

        if sign_in.is_unknown or principal.sign_in_known.is_unknown:
            continue

        idle_days: int | None = None
        if principal.sign_in_known.is_absent:
            # Definitively never signed in. Age from creation instead, so a
            # brand-new account is not reported the morning it is provisioned.
            created = parse_timestamp(principal.created_at)
            idle_days = days_between(created, ctx.now) if created else None
        else:
            last = parse_timestamp(principal.last_sign_in)
            if last is None:
                unparseable += 1
                continue
            idle_days = days_between(last, ctx.now)

        if idle_days is None or idle_days < threshold:
            continue

        # Per account, not per facet: the source may be able to count groups in
        # general and still not have returned a count for this row, and a
        # missing count is not a count of zero.
        groups_counted = groups_known and principal.group_count_known.is_present
        has_groups = groups_counted and principal.group_count > 0
        if tier is None and not has_groups:
            # Dormant with no access is a licensing question, not a security one.
            continue

        if len(tracked) < MAX_TRACKED_ACCOUNTS:
            tracked[label] = {
                "idle_days_at_or_above": threshold,
                "tier": tier.value if tier else "",
                "groups": principal.group_count if groups_counted else -1,
            }

        if tier is not None:
            dormant_privileged.append(label)
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.DORMANT_WITH_ROLE,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title=f"Dormant account holds an administrative role — {idle_days} days idle",
                    detail=(
                        f"No interactive sign-in for {idle_days} days, and the account still holds "
                        f"an administrative role. Nobody is watching this account's behaviour, "
                        "because nobody is using it."
                    ),
                    remediation=(
                        "Remove the role, or confirm the account is a break-glass identity and "
                        "monitor it explicitly."
                    ),
                    evidence={
                        "idle_days": idle_days,
                        "roles": sorted(_roles_for(ctx, principal.principal_id))[:20],
                    },
                )
            )
        else:
            dormant_with_groups.append(label)

    if dormant_with_groups:
        shown = sorted(dormant_with_groups)[:MAX_NAMED_IN_AGGREGATE]
        result.findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.DORMANT_WITH_ACCESS,
                subject=f"{len(dormant_with_groups)} accounts",
                subject_id="tenant:dormant",
                tier=RoleTier.STANDARD,
                title=(
                    f"{len(dormant_with_groups)} dormant "
                    f"{plural(len(dormant_with_groups), 'account')} still hold group membership"
                ),
                detail=(
                    f"No interactive sign-in for at least {threshold} days, and still a member of "
                    "groups that confer access. Reported together because at this severity a list "
                    "is more useful than a finding each."
                ),
                remediation="Fold this into the leaver process: disable, then strip membership.",
                evidence={"accounts": shown, "total": len(dormant_with_groups)},
            )
        )

    if not groups_known and sign_in.is_present:
        result.findings.append(ctx.indeterminate(CHECK, "group_membership"))

    if unparseable:
        result.findings.append(
            ctx.indeterminate(
                CHECK,
                "sign_in_activity",
                detail=(
                    f"{unparseable} {plural(unparseable, 'account')} carried a last-sign-in "
                    "timestamp that could not be parsed. They are excluded rather than treated as "
                    "never having signed in, which would have reported each of them as dormant."
                ),
            )
        )

    result.observations = {
        "accounts": tracked,
        "dormant_privileged": sorted(dormant_privileged),
        "disabled_with_role": sorted(disabled_with_role),
        "threshold_days": threshold,
    }
    return result


def _role_tiers(ctx: CheckContext) -> dict[str, RoleTier]:
    tiers: dict[str, RoleTier] = {}
    for assignment in ctx.state.role_assignments:
        tier = ctx.role_tier(assignment.role_name)
        if tier not in PRIVILEGED_TIERS:
            continue
        current = tiers.get(assignment.principal_id)
        if current is None or tier.rank > current.rank:
            tiers[assignment.principal_id] = tier
    return tiers


def _roles_for(ctx: CheckContext, principal_id: str) -> set[str]:
    return {a.role_name for a in ctx.state.role_assignments if a.principal_id == principal_id}
