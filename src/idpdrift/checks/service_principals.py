"""Workload identities: their credentials, and what they are allowed to do.

Service principals are where identity security goes quiet. They have no owner in
the sense a person does, they authenticate with a credential that lives in
somebody's pipeline, and they hold application permissions that apply to every
object in the tenant rather than to whatever a signed-in user could reach. An
attacker who adds a credential to an existing application registration keeps
access through every password reset the incident response runs.

Four posture findings:

**A credential expiring soon.** Reported at a low band because it is an
availability problem — but it is the one finding here that reliably gets acted
on, which makes it the reason the rest get read.

**A credential with an excessive lifetime.** A two-year secret is a two-year
window. Nothing about the credential changes when the person who created it
leaves.

**A secret rather than a certificate.** A secret is a bearer string that has to
exist in plaintext wherever it is used. A certificate can live in a key store
that will not export it.

**An application permission on a high-impact scope.** This is the one that turns
into an incident. ``Mail.Read`` as an application permission is every mailbox in
the organisation, with no user in the loop, and it looks identical in the portal
to the delegated permission of the same name — which is why the distinction is
modelled explicitly rather than inferred.
"""

from __future__ import annotations

from typing import Any

from ..catalog import scope_impact
from ..models import CheckResult, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, days_between, parse_timestamp, register

CHECK = "service_principals"

MAX_TRACKED_WORKLOADS = 5000
MAX_TRACKED_CREDENTIALS = 50
MAX_TRACKED_PERMISSIONS = 100


@register(CHECK)
def check_service_principals(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)

    if ctx.covers("service_principals").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "service_principals"))
        return result

    credentials_known = ctx.covers("application_credentials").is_present
    permissions_known = ctx.covers("application_permissions").is_present

    if not credentials_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "application_credentials"))
    if not permissions_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "application_permissions"))

    tracked: dict[str, dict[str, Any]] = {}

    for workload in ctx.state.workloads:
        if ctx.is_ignored_application(workload):
            continue
        label = workload.display or workload.app_id or workload.workload_id
        entry: dict[str, Any] = {"display": workload.display}

        if credentials_known:
            entry["credentials"] = _credential_observations(workload)
            result.findings.extend(_credential_findings(ctx, workload, label))

        if permissions_known:
            application_scopes = sorted({p.scope for p in workload.permissions if p.application and p.scope})
            entry["application_permissions"] = application_scopes[:MAX_TRACKED_PERMISSIONS]
            entry["delegated_permissions"] = sorted(
                {p.scope for p in workload.permissions if not p.application and p.scope}
            )[:MAX_TRACKED_PERMISSIONS]
            result.findings.extend(_permission_findings(ctx, workload, label))

        if len(tracked) < MAX_TRACKED_WORKLOADS:
            tracked[workload.workload_id] = entry

    result.observations = {"workloads": tracked}
    return result


def _credential_observations(workload: Any) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for credential in workload.credentials[:MAX_TRACKED_CREDENTIALS]:
        key = credential.credential_id or f"{credential.kind}:{credential.expires_at}"
        # Deliberately not the expiry date on its own: a credential id that is
        # stable across runs is what makes "a new credential appeared" a real
        # signal rather than a rounding artefact.
        out[key] = {"kind": credential.kind, "expires": credential.expires_at}
    return out


def _credential_findings(ctx: CheckContext, workload: Any, label: str) -> list[Any]:
    findings: list[Any] = []
    secrets_present = False

    for credential in workload.credentials:
        expires = parse_timestamp(credential.expires_at)
        starts = parse_timestamp(credential.starts_at)

        if credential.is_secret:
            secrets_present = True

        if expires is not None:
            remaining = days_between(ctx.now, expires)
            if remaining <= ctx.policy.credential_expiry_days:
                findings.append(
                    ctx.finding(
                        check=CHECK,
                        issue=Issue.CREDENTIAL_EXPIRING,
                        subject=label,
                        subject_id=workload.workload_id,
                        tier=RoleTier.SENSITIVE,
                        title=(
                            f"Credential expires in {remaining} {plural(remaining, 'day')}"
                            if remaining >= 0
                            else f"Credential expired {abs(remaining)} {plural(abs(remaining), 'day')} ago"
                        ),
                        detail=(
                            "Whatever this application does stops working when the credential "
                            "lapses, and the usual response under time pressure is a fresh "
                            "long-lived secret pasted somewhere convenient."
                        ),
                        remediation="Rotate it on a schedule, and prefer a certificate so rotation is automatable.",
                        evidence={"credential": credential.credential_id, "expires": credential.expires_at},
                    )
                )

            if starts is not None:
                lifetime = days_between(starts, expires)
                if lifetime > ctx.policy.credential_max_lifetime_days:
                    findings.append(
                        ctx.finding(
                            check=CHECK,
                            issue=Issue.CREDENTIAL_LONG_LIVED,
                            subject=label,
                            subject_id=workload.workload_id,
                            tier=RoleTier.PRIVILEGED,
                            title=f"Credential has a {lifetime}-day lifetime",
                            detail=(
                                f"The credential is valid for {lifetime} days, above the "
                                f"{ctx.policy.credential_max_lifetime_days}-day limit in policy. A "
                                "credential's blast radius is its lifetime: nothing about it changes "
                                "when the person who created it leaves, or when the pipeline holding "
                                "it is decommissioned."
                            ),
                            remediation="Reissue with a shorter validity and automate rotation.",
                            evidence={
                                "credential": credential.credential_id,
                                "lifetime_days": lifetime,
                                "limit_days": ctx.policy.credential_max_lifetime_days,
                            },
                        )
                    )

    if secrets_present:
        certificates = [c for c in workload.credentials if c.kind == "certificate"]
        findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.CREDENTIAL_SECRET_NOT_CERTIFICATE,
                subject=label,
                subject_id=workload.workload_id,
                tier=RoleTier.SENSITIVE,
                title="Application authenticates with a client secret",
                detail=(
                    "A client secret is a bearer string: it exists in plaintext wherever it is used, "
                    "it is copied into a pipeline variable at least once, and anyone who reads it "
                    "once can use it until it expires. A certificate can live in a key store that "
                    "will not export the private key."
                    + (
                        " This application also has a certificate, so the secret may simply be a "
                        "leftover from the migration — which is worth removing rather than leaving "
                        "valid."
                        if certificates
                        else ""
                    )
                ),
                remediation="Move to certificate credentials, then delete the secret rather than letting it expire.",
                evidence={
                    "secret_count": sum(1 for c in workload.credentials if c.is_secret),
                    "certificate_count": len(certificates),
                },
            )
        )
    return findings


def _permission_findings(ctx: CheckContext, workload: Any, label: str) -> list[Any]:
    findings: list[Any] = []
    for permission in workload.permissions:
        if not permission.application:
            # A delegated permission is bounded by the signed-in user's own
            # access. It is worth recording and is not the same finding.
            continue
        impact = scope_impact(permission.scope)
        if impact is None:
            continue
        findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.APP_PERMISSION_HIGH_IMPACT,
                subject=label,
                subject_id=workload.workload_id,
                tier=RoleTier.TENANT_ADMIN,
                title=f"Application permission {permission.scope} granted",
                detail=(
                    f"This is an application permission, not a delegated one: it applies with no "
                    f"user present, to every object in the tenant. It {impact}."
                ),
                remediation=(
                    "Replace it with a delegated permission, or scope it to specific resources if "
                    "the API supports that. If neither is possible, treat this application as a "
                    "tier-0 asset and watch its credentials accordingly."
                ),
                evidence={
                    "scope": permission.scope,
                    "resource": permission.resource,
                    "granted_at": permission.granted_at,
                },
            )
        )
    return findings
