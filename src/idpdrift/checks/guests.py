"""External identities, and how far into the tenant they reach.

Guest accounts are how collaboration works, and they are also an account in your
directory belonging to somebody whose employment status you do not know, whose
device you do not manage, and whose own identity provider you do not administer.
When the contract ends, the account usually stays.

Two findings, both measured against an allowance the operator sets rather than
against zero:

**A guest holding a directory role.** ``policy.guest_role_allowance`` defaults to
zero, because there is very rarely a good reason for an external identity to hold
an administrative role, and when there is, the operator can say so.

**A guest with group membership beyond the allowance.** Group membership is where
guest access actually lives, and a guest in twenty groups has usually accumulated
them rather than been granted them.

Both depend on the directory telling us that an account is external, which not
every provider does. Okta records external collaborators as ordinary users, so
this check reports that guest status is indeterminate rather than concluding an
org has no guests — an org with no guests and an org whose provider does not
distinguish them look identical from here, and only one of those is good news.
"""

from __future__ import annotations

from typing import Any

from ..models import CheckResult, PrincipalKind, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, register

CHECK = "guests"

MAX_TRACKED_GUESTS = 10000
MAX_NAMED_IN_AGGREGATE = 10


@register(CHECK)
def check_guests(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)

    if ctx.covers("principals").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "principals"))
        return result

    if ctx.covers("guest_status").is_unknown:
        # The source does not mark external accounts. An organisation with no
        # guests and one whose provider does not distinguish them are
        # indistinguishable from here, and only one of those is good news.
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "guest_status"))
        return result

    guests = [p for p in ctx.state.principals if p.kind is PrincipalKind.GUEST]

    roles_known = ctx.covers("role_assignments").is_present
    groups_known = ctx.covers("group_membership").is_present

    if not roles_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "role_assignments"))
    if not groups_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "group_membership"))

    roles_by_principal: dict[str, list[str]] = {}
    if roles_known:
        for assignment in ctx.state.role_assignments:
            roles_by_principal.setdefault(assignment.principal_id, []).append(assignment.role_name)

    tracked: dict[str, dict[str, Any]] = {}
    over_group_allowance: list[str] = []

    for guest in guests:
        if ctx.is_ignored_principal(guest.principal_id, guest.upn):
            continue
        label = ctx.principal_label(guest)
        roles = sorted(set(roles_by_principal.get(guest.principal_id, [])))
        # The facet says the source can count groups in general; this account's
        # own count is a separate answer, and an export that carried no
        # group_count for a row leaves it UNKNOWN. Reading that as zero would
        # both suppress the allowance finding and persist a fabricated zero,
        # after which the next run reports the guest as having joined every
        # group they were already in.
        groups_counted = groups_known and guest.group_count_known.is_present

        if len(tracked) < MAX_TRACKED_GUESTS:
            tracked[label] = {
                "roles": roles[:20],
                "role_count": len(roles) if roles_known else -1,
                "group_count": guest.group_count if groups_counted else -1,
            }

        if roles_known and len(roles) > ctx.policy.guest_role_allowance:
            tier = max(
                (ctx.role_tier(name) for name in roles),
                key=lambda t: t.rank,
                default=RoleTier.STANDARD,
            )
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.GUEST_WITH_ROLE,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title=f"Guest account holds {len(roles)} directory {plural(len(roles), 'role')}",
                    detail=(
                        "An external identity holds a role in this directory. The account belongs "
                        "to somebody whose employment status, device and home identity provider are "
                        "all outside your control, and none of those change state when their "
                        "engagement ends."
                    ),
                    remediation=(
                        "Remove the role, or raise policy.guest_role_allowance deliberately if this "
                        "is a partner arrangement you have accepted."
                    ),
                    evidence={"roles": roles[:20], "allowance": ctx.policy.guest_role_allowance},
                )
            )

        if groups_counted and guest.group_count > ctx.policy.guest_group_allowance:
            over_group_allowance.append(f"{label} ({guest.group_count})")

    if over_group_allowance:
        shown = sorted(over_group_allowance)[:MAX_NAMED_IN_AGGREGATE]
        result.findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.GUEST_OVER_ALLOWANCE,
                subject=f"{len(over_group_allowance)} guests",
                subject_id="tenant:guests",
                tier=RoleTier.STANDARD,
                title=(
                    f"{len(over_group_allowance)} "
                    f"{plural(len(over_group_allowance), 'guest')} exceed the group "
                    "membership allowance"
                ),
                detail=(
                    "These external accounts are members of more than "
                    f"{ctx.policy.guest_group_allowance} "
                    f"{plural(ctx.policy.guest_group_allowance, 'group')}. Guest access "
                    "accumulates: each addition is individually reasonable and nobody reviews the "
                    "total."
                ),
                remediation="Run an access review over external identities, or lower the allowance and act on it.",
                evidence={"guests": shown, "total": len(over_group_allowance)},
            )
        )

    result.observations = {"guests": tracked, "guest_total": len(guests)}
    return result
