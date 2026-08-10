"""Conditional access and sign-on policies: what is actually being enforced.

A policy that exists and a policy that is enforced look the same in a compliance
questionnaire. This check reads the difference.

Two posture findings, and — deliberately — nothing about exclusions:

**A disabled policy.** Somebody turned it off, usually to unblock a vendor
integration on a Tuesday, and the change was never reverted. The policy is still
in the list, still named after the control it implements, still cited in the
audit response.

**A report-only policy.** Report-only is a real and useful state during rollout.
It is also indistinguishable, from the outside, from a control that was never
finished, and it is the state a policy gets moved to when it blocks something
urgent. Neither the portal nor an evidence screenshot makes the distinction
loudly.

**Exclusions are recorded but not reported as posture.** Every real tenant
excludes a break-glass account, a service identity or a migration group from at
least one policy, and listing those every morning is how a check gets ignored.
What matters is an exclusion being *added*, which is what the drift rule in
:mod:`idpdrift.drift` reports — and adding oneself to an exclusion list is a
quieter way to bypass MFA than disabling the policy that requires it.
"""

from __future__ import annotations

from typing import Any

from ..models import AccessPolicy, CheckResult, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, register

CHECK = "conditional_access"

MAX_TRACKED_POLICIES = 2000
MAX_TRACKED_EXCLUSIONS = 200


@register(CHECK)
def check_conditional_access(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)

    if ctx.covers("access_policies").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "access_policies"))
        return result

    tracked: dict[str, dict[str, Any]] = {}
    enabled = 0

    for policy in ctx.state.policies:
        label = policy.display or policy.policy_id
        exclusions = _exclusion_keys(ctx, policy)
        if len(tracked) < MAX_TRACKED_POLICIES:
            tracked[policy.policy_id] = {
                "display": policy.display,
                "state": policy.state,
                "exclusions": list(exclusions[:MAX_TRACKED_EXCLUSIONS]),
                "exclusion_count": len(exclusions),
            }

        if policy.state == "enabled":
            enabled += 1
            continue

        if policy.state == "disabled":
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.POLICY_DISABLED,
                    subject=label,
                    subject_id=policy.policy_id,
                    tier=RoleTier.PRIVILEGED,
                    title="Access policy is disabled",
                    detail=(
                        "The policy exists and enforces nothing. It still appears in the policy "
                        "list, still carries the name of the control it was written for, and will "
                        "still be cited as evidence that the control exists."
                    ),
                    remediation="Re-enable it, or delete it so it stops reading as a control that is in place.",
                    evidence={"exclusions": len(exclusions)},
                )
            )
        elif policy.state == "report_only":
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.POLICY_REPORT_ONLY,
                    subject=label,
                    subject_id=policy.policy_id,
                    tier=RoleTier.PRIVILEGED,
                    title="Access policy is report-only",
                    detail=(
                        "The policy evaluates and logs but does not block. That is the correct "
                        "state during a rollout and the same state a policy is moved to when it "
                        "blocks something urgent — and from outside, and in an audit screenshot, "
                        "those look identical."
                    ),
                    remediation=(
                        "Move it to enabled, or record why it is staying in report-only and for how long."
                    ),
                    evidence={"exclusions": len(exclusions)},
                )
            )

    if ctx.state.policies and enabled == 0:
        result.findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.POLICY_WEAKENED,
                subject=ctx.state.tenant or "tenant",
                subject_id="tenant",
                tier=RoleTier.TENANT_ADMIN,
                title="No access policy is enforcing anything",
                detail=(
                    f"All {len(ctx.state.policies)} "
                    f"{plural(len(ctx.state.policies), 'policy', 'policies')} are disabled or "
                    "report-only, so no sign-in is being blocked by any of them. A tenant in this "
                    "state has the documentation of a conditional access deployment and none of "
                    "the effect."
                ),
                remediation="Enable at least the policies covering administrative roles.",
                evidence={"policy_count": len(ctx.state.policies)},
            )
        )

    result.observations = {"policies": tracked}
    return result


def _exclusion_keys(ctx: CheckContext, policy: AccessPolicy) -> tuple[str, ...]:
    """The policy's exemptions, with the account ones pseudonymised.

    An excluded user is named by their directory object id, and an object id is
    an account identifier: it resolves to a named person in a single lookup.
    This list is persisted, rendered into the exclusion-added drift finding, and
    posted to whatever webhook the operator configured, so leaving it raw would
    put a directory identifier into exactly the three places PRIVACY.md promises
    a stable label instead.

    Groups and roles are left legible for the reason application names are: they
    are organisational objects rather than people, and "somebody was exempted
    through a group you cannot identify" is not a finding anybody can act on.
    The pseudonym is stable across runs, so the drift comparison still works.
    """
    return tuple(
        sorted(
            {
                *(ctx.label_for_id(user_id) for user_id in policy.excluded_users),
                *policy.excluded_groups,
                *policy.excluded_roles,
            }
        )
    )
