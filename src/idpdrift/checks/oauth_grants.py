"""Consent grants: which applications users have let into the tenant.

Illicit consent is the intrusion technique that needs no credential and survives
every password reset. The user is shown a real consent screen, on the real
identity provider's domain, for an application whose display name the attacker
chose. They click Accept, and the attacker holds a refresh token for the scopes
they asked for — commonly ``Mail.Read`` and ``offline_access``, which is a
permanent mailbox feed.

Three posture findings:

**A third-party application holds a grant.** Reported at a low band on purpose:
most organisations have dozens of legitimate ones, and treating each as an
incident is how the check gets switched off before it catches the one that
matters. ``policy.approved_applications`` exists so that the list shrinks to the
ones nobody has looked at.

**Tenant-wide admin consent.** One administrator's decision applied to every
account in the organisation. Worth knowing about every time it happens.

**A scope that reads mail or files.** The correspondence and documents of whoever
consented, available over an API, without a sign-in that anybody reviews.

The tri-state gates the whole check. An identity provider that will not return
consent grants produces an empty list, and an empty list is exactly what a clean
tenant produces too.
"""

from __future__ import annotations

from typing import Any

from ..catalog import reads_files, reads_mail, scope_impact
from ..models import CheckResult, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, register

CHECK = "oauth_grants"

MAX_TRACKED_GRANTS = 10000
MAX_TRACKED_SCOPES = 60


@register(CHECK)
def check_oauth_grants(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)

    if ctx.covers("oauth_grants").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "oauth_grants"))
        return result

    third_party = {w.workload_id: w.third_party for w in ctx.state.workloads}
    tracked: dict[str, dict[str, Any]] = {}

    for grant in ctx.state.oauth_grants:
        label = grant.client_display or grant.client_id
        # The client id, never the display name: see
        # CheckContext.is_ignored_application for why an allow list must not be
        # keyed on a string whoever registered the application chose.
        if ctx.is_approved_application(grant.client_id):
            continue

        scopes = sorted({s for s in grant.scopes if s})
        if len(tracked) < MAX_TRACKED_GRANTS:
            tracked[grant.key] = {
                "client": label,
                "scopes": scopes[:MAX_TRACKED_SCOPES],
                "tenant_wide": grant.tenant_wide,
                "resource": grant.resource,
            }

        if grant.tenant_wide:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.OAUTH_TENANT_WIDE,
                    subject=label,
                    subject_id=grant.client_id,
                    tier=RoleTier.PRIVILEGED,
                    title="Application holds tenant-wide admin consent",
                    detail=(
                        "An administrator consented on behalf of every account in the organisation, "
                        "so no individual user was ever shown a consent screen for this. Whatever "
                        "the application can read, it can read for everyone."
                    ),
                    remediation=(
                        "Confirm the grant was requested through your change process and that the "
                        "scopes match what the application actually needs."
                    ),
                    evidence={"scopes": scopes[:MAX_TRACKED_SCOPES], "resource": grant.resource},
                )
            )

        sensitive = sorted({s for s in scopes if reads_mail(s) or reads_files(s)})
        if sensitive:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.OAUTH_SENSITIVE_SCOPE,
                    subject=label,
                    subject_id=grant.client_id,
                    tier=RoleTier.PRIVILEGED if grant.tenant_wide else RoleTier.SENSITIVE,
                    title="Consent grants access to mail or files",
                    detail=(
                        "This application can read correspondence or documents through an API. "
                        "There is no interactive sign-in behind those reads, so they do not appear "
                        "in the places anyone looks for unusual access, and a refresh token "
                        "survives a password reset."
                        + (
                            " The grant is tenant-wide, so this applies to every account."
                            if grant.tenant_wide
                            else ""
                        )
                    ),
                    remediation=(
                        "Revoke the grant if the application is not one you deliberately "
                        "onboarded, and revoke its refresh tokens as well — deleting the grant "
                        "alone does not."
                    ),
                    evidence={"scopes": sensitive[:MAX_TRACKED_SCOPES], "resource": grant.resource},
                    references=("https://attack.mitre.org/techniques/T1550/001/",),
                )
            )

        high_impact = sorted({s for s in scopes if scope_impact(s)})
        origin = third_party.get(grant.client_id)
        if origin is not None and origin.is_present:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.OAUTH_THIRD_PARTY,
                    subject=label,
                    subject_id=grant.client_id,
                    tier=RoleTier.SENSITIVE,
                    title="Third-party application holds a consent grant",
                    detail=(
                        "The application is registered outside this tenant. That is ordinary for "
                        "software you bought and is also exactly what an illicit consent grant "
                        "looks like, so it is listed rather than judged."
                        + (
                            f" It holds {len(high_impact)} high-impact {plural(len(high_impact), 'scope')}."
                            if high_impact
                            else ""
                        )
                    ),
                    remediation=(
                        "Add it to policy.approved_applications once you have reviewed it, so the "
                        "next unreviewed one stands out."
                    ),
                    evidence={"scopes": scopes[:MAX_TRACKED_SCOPES], "high_impact": high_impact},
                )
            )

    result.observations = {"grants": tracked}
    return result
