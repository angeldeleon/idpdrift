"""How strongly each account can prove it is who it says it is.

Three posture findings, in descending order of how much they should worry you:

**No second factor at all.** A password is a shared secret that appears in every
credential-stuffing list ever published.

**Only SMS or voice.** These are second factors in the sense that there are two
of them. A phone number is transferable by anyone who can convince a carrier's
retention desk, and both codes are typed into whatever window asked for them.

**No phishing-resistant method on a privileged account.** An authenticator app
push or a one-time code is a genuine improvement over a password and is still
relayed in real time by every off-the-shelf phishing kit. Only an origin-bound
method — a security key, a passkey, Windows Hello, a certificate — survives a
proxy sitting in the middle, and an account that can administer the directory is
exactly the one worth putting behind one.

Every one of those is an *absence*, which makes this the check where the tri-state
matters most. A directory that declines to return authentication methods produces
the same shape of answer as an account with none, and reporting the first as the
second means the report opens with "nobody in your organisation has MFA" — after
which nobody reads the rest of it. So the facet is consulted first and, if it is
UNKNOWN, this check reports that it could not look and produces nothing else.

Non-privileged accounts are aggregated rather than listed. Ten thousand
individually-listed findings is not a report, and the per-account detail for
ordinary users belongs in the identity provider's own registration report.
"""

from __future__ import annotations

from typing import Any

from ..catalog import PRIVILEGED_TIERS, is_phishing_resistant, is_weak_method
from ..models import CheckResult, PrincipalKind, plural
from ..severity import Issue, RoleTier
from .base import CheckContext, register

CHECK = "auth_strength"

# Accounts whose posture is recorded in the baseline. Only privileged accounts
# are tracked: they are the ones whose MFA posture weakening is worth an alert,
# and recording every account would make the state file a copy of the directory.
MAX_TRACKED_ACCOUNTS = 5000

# Ordinary accounts named individually in the aggregate finding, so the reader
# has somewhere to start without the finding becoming a directory dump.
MAX_NAMED_IN_AGGREGATE = 10


@register(CHECK)
def check_auth_strength(ctx: CheckContext) -> CheckResult:
    result = CheckResult(check=CHECK)
    coverage = ctx.covers("authentication_methods")

    if coverage.is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(CHECK, "authentication_methods"))
        return result

    privileged_ids = _privileged_principal_ids(ctx)
    tracked: dict[str, dict[str, Any]] = {}
    unprotected: list[str] = []
    indeterminate_accounts = 0

    for principal in ctx.state.principals:
        if ctx.is_ignored_principal(principal.principal_id, principal.upn):
            continue
        if principal.kind is PrincipalKind.SERVICE_PRINCIPAL:
            # A workload does not have a second factor and is not supposed to.
            # Reporting one as lacking MFA is the noise that makes an operator
            # switch the check off, taking the human findings with it.
            continue

        tier = privileged_ids.get(principal.principal_id)
        label = ctx.principal_label(principal)

        if principal.second_factor.is_unknown and principal.phishing_resistant.is_unknown:
            # The facet is readable but this account's entry was not returned.
            # Counted, not reported: one line per account would drown the report,
            # and one aggregate line is enough for a reader to notice a gap.
            indeterminate_accounts += 1
            continue

        if tier is not None and len(tracked) < MAX_TRACKED_ACCOUNTS:
            tracked[label] = {
                "phishing_resistant": principal.phishing_resistant.value,
                "second_factor": principal.second_factor.value,
                "methods": sorted(principal.auth_methods),
                "tier": tier.value,
            }

        if principal.second_factor.is_absent:
            if tier is not None:
                result.findings.append(
                    ctx.finding(
                        check=CHECK,
                        issue=Issue.MFA_ABSENT,
                        subject=label,
                        subject_id=label,
                        tier=tier,
                        title="Privileged account has no second factor",
                        detail=(
                            "This account holds an administrative role and can sign in with a "
                            "password alone. Whatever else is true of the tenant's security, one "
                            "credential-stuffing hit ends it."
                        ),
                        remediation=(
                            "Register a phishing-resistant method and require it for this account "
                            "through conditional access."
                        ),
                        evidence={"methods": sorted(principal.auth_methods)},
                    )
                )
            else:
                unprotected.append(label)
            continue

        if not principal.second_factor.is_present:
            continue

        methods = [m for m in principal.auth_methods if m]
        weak_only = bool(methods) and all(is_weak_method(m) for m in methods)
        if weak_only:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.MFA_WEAK_FACTOR_ONLY,
                    subject=label,
                    subject_id=label,
                    tier=tier or RoleTier.STANDARD,
                    title="Second factor is SMS or voice only",
                    detail=(
                        "Every registered method for this account is delivered to a phone number or "
                        "a mailbox. A number is transferable by anyone who can talk a carrier into "
                        "porting it, and a code sent to a mailbox is protected by the account it is "
                        "meant to protect."
                    ),
                    remediation="Register an authenticator app at minimum, and a security key for anyone privileged.",
                    evidence={"methods": sorted(methods)},
                )
            )

        if tier is not None and principal.phishing_resistant.is_absent:
            result.findings.append(
                ctx.finding(
                    check=CHECK,
                    issue=Issue.MFA_NOT_PHISHING_RESISTANT,
                    subject=label,
                    subject_id=label,
                    tier=tier,
                    title="Privileged account has no phishing-resistant method",
                    detail=(
                        "This account holds an administrative role and its strongest registered "
                        "method can be relayed by a proxy. An off-the-shelf phishing kit puts a "
                        "page in front of the real sign-in, forwards the code the moment it is "
                        "typed, and keeps the session."
                    ),
                    remediation=(
                        "Register a security key, passkey or certificate for this account and "
                        "require an authentication strength that only accepts one."
                    ),
                    evidence={
                        "methods": sorted(principal.auth_methods),
                        "phishing_resistant_registered": [
                            m for m in principal.auth_methods if is_phishing_resistant(m)
                        ],
                    },
                )
            )

    if unprotected:
        shown = sorted(unprotected)[:MAX_NAMED_IN_AGGREGATE]
        more = len(unprotected) - len(shown)
        result.findings.append(
            ctx.finding(
                check=CHECK,
                issue=Issue.MFA_ABSENT,
                subject=f"{len(unprotected)} accounts",
                subject_id="tenant:mfa_absent",
                tier=RoleTier.STANDARD,
                title=f"{len(unprotected)} {plural(len(unprotected), 'account')} with no second factor",
                detail=(
                    "These accounts hold no administrative role, so they are reported together "
                    "rather than one per line. They can each sign in with a password alone, which "
                    "is where an intrusion starts before it reaches the accounts above."
                    + (f" Showing {len(shown)} of {len(unprotected)}." if more else "")
                ),
                remediation="Enforce registration through a policy rather than account by account.",
                evidence={"accounts": shown, "total": len(unprotected)},
            )
        )

    if indeterminate_accounts:
        result.partial = True
        result.findings.append(
            ctx.indeterminate(
                CHECK,
                "authentication_methods",
                detail=(
                    f"{indeterminate_accounts} {plural(indeterminate_accounts, 'account')} were "
                    "returned without authentication method data. They are neither reported as "
                    "lacking MFA nor counted as covered; the remaining accounts were assessed "
                    "normally."
                ),
            )
        )

    result.observations = {
        "accounts": tracked,
        "unprotected_total": len(unprotected),
        "indeterminate_total": indeterminate_accounts,
    }
    return result


def _privileged_principal_ids(ctx: CheckContext) -> dict[str, RoleTier]:
    """Principals holding a privileged role, and the highest tier they hold.

    Returns an empty mapping when role assignments could not be read — the
    dedicated finding for that comes from the privileged_roles check, and
    producing a second one here would report the same gap twice.
    """
    if not ctx.covers("role_assignments").is_present:
        return {}
    tiers: dict[str, RoleTier] = {}
    for assignment in ctx.state.role_assignments:
        tier = ctx.role_tier(assignment.role_name)
        if tier not in PRIVILEGED_TIERS:
            continue
        current = tiers.get(assignment.principal_id)
        if current is None or tier.rank > current.rank:
            tiers[assignment.principal_id] = tier
    return tiers
