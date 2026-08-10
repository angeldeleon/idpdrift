"""Severity, computed from a table rather than chosen at each call site.

Severity decided inline is severity that drifts. One contributor rates a new
Global Administrator as HIGH because that is what the neighbouring line said,
another rates a dormant guest as HIGH because it felt serious while they were
writing it, and within a few releases the band means nothing and the ``fail_on``
threshold is either permanently tripped or permanently silent.

So every finding names an :class:`Issue`, and the band comes from
:data:`BASE_SEVERITY` adjusted by exactly two documented modifiers:

* **Role tier.** The same issue is worse the more the affected principal can do.
  A standing assignment to a role that can grant other roles is a tenant
  takeover waiting to happen; the same standing assignment to a reports reader
  is bookkeeping.
* **Determination.** A finding that rests on ``UNKNOWN`` is capped at LOW and
  reported as OPERATIONAL. "We could not read authentication methods" is worth
  saying and is not worth waking anyone up, and letting it inherit the severity
  of the thing it could not check is precisely how a tool becomes a
  false-positive generator.

Both modifiers are bounded and the result is clamped to the enum, so no
combination can produce something outside the table. :func:`explain` prints the
derivation next to the rating, so a reader who thinks a finding is overblown can
name the input they disagree with instead of concluding the tool is noisy.

The table is reproduced in the README. If you change it here, change it there.
"""

from __future__ import annotations

from enum import Enum

from .models import Determination, Severity


class RoleTier(str, Enum):
    """How much damage the holder of a role can do.

    Four bands, deliberately coarse. A security team triages by "can this
    principal grant itself more access", not by a 0-100 score whose derivation
    nobody can reconstruct.
    """

    TENANT_ADMIN = "tenant_admin"
    """Full control, or the ability to take it: Global Administrator, Privileged
    Role Administrator, Super Administrator. Compromise ends the incident
    response conversation and starts the rebuild conversation."""

    PRIVILEGED = "privileged"
    """Can grant themselves more, reset credentials for others, or read
    everyone's data: Application Administrator, User Administrator, Exchange
    Administrator, Okta Organization Administrator."""

    SENSITIVE = "sensitive"
    """Reads or changes real data but cannot escalate on its own: Groups
    Administrator, Intune Administrator, Report Administrator."""

    STANDARD = "standard"
    """Everything else, including read-only administrative roles and ordinary
    membership."""

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK: dict[RoleTier, int] = {
    RoleTier.STANDARD: 0,
    RoleTier.SENSITIVE: 1,
    RoleTier.PRIVILEGED: 2,
    RoleTier.TENANT_ADMIN: 3,
}


class Issue(str, Enum):
    """The stable identifier for a class of finding.

    Also the rule id in JSON output and the key into :data:`BASE_SEVERITY`, so a
    consumer can suppress one class of finding without pattern-matching on
    prose that will be reworded.
    """

    # privileged_roles
    ROLE_ASSIGNMENT_NEW = "role_assignment_new"
    ROLE_ASSIGNMENT_STANDING = "role_assignment_standing"
    ROLE_ASSIGNMENT_NON_HUMAN = "role_assignment_non_human"
    ROLE_ASSIGNMENT_ELEVATED = "role_assignment_elevated"
    ROLE_ASSIGNMENT_REMOVED = "role_assignment_removed"

    # auth_strength
    MFA_NOT_PHISHING_RESISTANT = "mfa_not_phishing_resistant"
    MFA_WEAK_FACTOR_ONLY = "mfa_weak_factor_only"
    MFA_ABSENT = "mfa_absent"
    MFA_WEAKENED = "mfa_weakened"

    # dormancy
    DORMANT_WITH_ACCESS = "dormant_with_access"
    DORMANT_WITH_ROLE = "dormant_with_role"
    DORMANT_REACTIVATED = "dormant_reactivated"
    DISABLED_WITH_ROLE = "disabled_with_role"

    # workloads
    CREDENTIAL_EXPIRING = "credential_expiring"
    CREDENTIAL_LONG_LIVED = "credential_long_lived"
    CREDENTIAL_SECRET_NOT_CERTIFICATE = "credential_secret_not_certificate"  # noqa: S105
    CREDENTIAL_NEW = "credential_new"
    APP_PERMISSION_HIGH_IMPACT = "app_permission_high_impact"
    APP_PERMISSION_NEW = "app_permission_new"

    # oauth_grants
    OAUTH_THIRD_PARTY = "oauth_third_party"
    OAUTH_TENANT_WIDE = "oauth_tenant_wide"
    OAUTH_SENSITIVE_SCOPE = "oauth_sensitive_scope"
    OAUTH_GRANT_NEW = "oauth_grant_new"
    OAUTH_SCOPE_ADDED = "oauth_scope_added"

    # guests
    GUEST_WITH_ROLE = "guest_with_role"
    GUEST_OVER_ALLOWANCE = "guest_over_allowance"
    GUEST_GAINED_ACCESS = "guest_gained_access"

    # conditional_access
    POLICY_DISABLED = "policy_disabled"
    POLICY_REPORT_ONLY = "policy_report_only"
    POLICY_EXCLUSION_ADDED = "policy_exclusion_added"
    POLICY_REMOVED = "policy_removed"
    POLICY_WEAKENED = "policy_weakened"

    # operational
    FACET_INDETERMINATE = "facet_indeterminate"
    FINDINGS_TRUNCATED = "findings_truncated"
    BASELINE_MISMATCH = "baseline_mismatch"


# Severity assuming the affected principal sits at RoleTier.PRIVILEGED. The tier
# adjustment below moves it from there. Reproduced in README.md.
BASE_SEVERITY: dict[Issue, Severity] = {
    # A new administrator is the single most useful line this tool produces.
    Issue.ROLE_ASSIGNMENT_NEW: Severity.HIGH,
    Issue.ROLE_ASSIGNMENT_STANDING: Severity.MEDIUM,
    # A workload holding an administrative role has no MFA, no sign-in risk
    # evaluation and usually no owner watching it.
    Issue.ROLE_ASSIGNMENT_NON_HUMAN: Severity.HIGH,
    Issue.ROLE_ASSIGNMENT_ELEVATED: Severity.HIGH,
    Issue.ROLE_ASSIGNMENT_REMOVED: Severity.INFO,
    Issue.MFA_NOT_PHISHING_RESISTANT: Severity.MEDIUM,
    Issue.MFA_WEAK_FACTOR_ONLY: Severity.MEDIUM,
    Issue.MFA_ABSENT: Severity.HIGH,
    Issue.MFA_WEAKENED: Severity.HIGH,
    Issue.DORMANT_WITH_ACCESS: Severity.LOW,
    Issue.DORMANT_WITH_ROLE: Severity.MEDIUM,
    # An account nobody has used in months signing in again is either a returning
    # employee or somebody who found the credential. Both are worth a look.
    Issue.DORMANT_REACTIVATED: Severity.MEDIUM,
    Issue.DISABLED_WITH_ROLE: Severity.MEDIUM,
    Issue.CREDENTIAL_EXPIRING: Severity.LOW,
    Issue.CREDENTIAL_LONG_LIVED: Severity.MEDIUM,
    Issue.CREDENTIAL_SECRET_NOT_CERTIFICATE: Severity.LOW,
    # Adding a credential to an existing application is how an attacker keeps
    # access after the account they phished is reset.
    Issue.CREDENTIAL_NEW: Severity.HIGH,
    Issue.APP_PERMISSION_HIGH_IMPACT: Severity.HIGH,
    Issue.APP_PERMISSION_NEW: Severity.HIGH,
    Issue.OAUTH_THIRD_PARTY: Severity.LOW,
    Issue.OAUTH_TENANT_WIDE: Severity.MEDIUM,
    Issue.OAUTH_SENSITIVE_SCOPE: Severity.HIGH,
    Issue.OAUTH_GRANT_NEW: Severity.MEDIUM,
    Issue.OAUTH_SCOPE_ADDED: Severity.MEDIUM,
    Issue.GUEST_WITH_ROLE: Severity.HIGH,
    Issue.GUEST_OVER_ALLOWANCE: Severity.LOW,
    Issue.GUEST_GAINED_ACCESS: Severity.MEDIUM,
    Issue.POLICY_DISABLED: Severity.HIGH,
    Issue.POLICY_REPORT_ONLY: Severity.HIGH,
    Issue.POLICY_EXCLUSION_ADDED: Severity.HIGH,
    Issue.POLICY_REMOVED: Severity.HIGH,
    Issue.POLICY_WEAKENED: Severity.MEDIUM,
    # Operational findings describe the tool, not the tenant. They are never
    # meant to trip a threshold, and the UNKNOWN cap below holds them there.
    Issue.FACET_INDETERMINATE: Severity.LOW,
    Issue.FINDINGS_TRUNCATED: Severity.LOW,
    Issue.BASELINE_MISMATCH: Severity.MEDIUM,
}

# Rank delta applied per role tier, relative to PRIVILEGED. Capped at one band
# in each direction: a bigger swing would let the tier, which is a judgement
# about a role name, overwhelm the issue, which is an observation about the
# tenant.
TIER_ADJUSTMENT: dict[RoleTier, int] = {
    RoleTier.TENANT_ADMIN: +1,
    RoleTier.PRIVILEGED: 0,
    RoleTier.SENSITIVE: -1,
    RoleTier.STANDARD: -1,
}

# The ceiling for anything resting on "could not determine". See the module
# docstring: an unreadable facet must never sound like a discovered weakness.
UNKNOWN_CEILING = Severity.LOW

_BY_RANK: dict[int, Severity] = {s.rank: s for s in Severity}


def rate(
    issue: Issue,
    *,
    tier: RoleTier = RoleTier.PRIVILEGED,
    determination: Determination = Determination.PRESENT,
) -> Severity:
    """Return the band for *issue*, adjusted for *tier* and *determination*."""
    base = BASE_SEVERITY[issue]
    if determination.is_unknown:
        return min(base, UNKNOWN_CEILING)
    adjusted = base.rank + TIER_ADJUSTMENT[tier]
    clamped = max(Severity.INFO.rank, min(Severity.CRITICAL.rank, adjusted))
    return _BY_RANK[clamped]


def explain(
    issue: Issue,
    *,
    tier: RoleTier = RoleTier.PRIVILEGED,
    determination: Determination = Determination.PRESENT,
) -> str:
    """One line stating why a finding scored what it did."""
    base = BASE_SEVERITY[issue]
    if determination.is_unknown:
        return (
            f"{issue.value} is normally {base.value}; capped at "
            f"{min(base, UNKNOWN_CEILING).value} because the underlying fact could not be determined"
        )
    delta = TIER_ADJUSTMENT[tier]
    if delta == 0:
        return f"{issue.value} at the {tier.value} tier: {base.value}"
    direction = "raised" if delta > 0 else "lowered"
    return (
        f"{issue.value} is {base.value} at the privileged tier, {direction} one band "
        f"for the {tier.value} tier"
    )
