"""Check protocol, registry and the context every check is given.

A check receives a :class:`CheckContext` and returns a
:class:`~idpdrift.models.CheckResult`. It does not open sockets, read files or
decide severities: everything it is allowed to reach is on the context, and the
band comes from :mod:`idpdrift.severity`. That is what keeps a new check from
quietly acquiring its own HTTP client, its own opinion about what is critical, or
its own way of turning "could not determine" into "absent".

Three helpers on the context carry most of the weight:

* :meth:`CheckContext.covers` — the tri-state for a facet. Every check that is
  about to report an *absence* has to consult it first.
* :meth:`CheckContext.indeterminate` — the finding to emit instead. It is
  OPERATIONAL, capped at LOW by the severity table, and says what was not read
  and what that means for the conclusion.
* :meth:`CheckContext.finding` — builds a finding with the severity derived from
  the issue, the role tier and the determination, so no check picks a band.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from ..catalog import role_tier as catalog_role_tier
from ..config import Config, PolicyConfig, Settings
from ..models import (
    CheckResult,
    Determination,
    Finding,
    FindingKind,
    IdentityState,
    Principal,
    Workload,
)
from ..severity import Issue, RoleTier, explain, rate
from ..validation import normalize_key

# What each facet being unreadable means for the reader, in one sentence. Kept
# here rather than in each check so the wording cannot drift between them.
FACET_CONSEQUENCE: dict[str, str] = {
    "principals": "no account-level finding can be produced",
    "guest_status": "external accounts are not distinguished from internal ones, so no guest finding is produced",
    "authentication_methods": "accounts are not reported as lacking MFA, because that cannot be distinguished from a directory that declined to say",
    "sign_in_activity": "no account is reported as dormant, because a missing sign-in timestamp is not the same as no sign-in",
    "group_membership": "group-based access is not counted towards the guest allowance",
    "role_assignments": "role holders are not reported, and no assignment is reported as removed",
    "role_eligibility": "standing assignments are not distinguished from just-in-time ones",
    "service_principals": "workload identities are not assessed",
    "application_credentials": "credential expiry and lifetime are not assessed",
    "application_permissions": "application permissions are not assessed",
    "oauth_grants": "consent grants are not assessed",
    "access_policies": "conditional access posture is not assessed",
}


def parse_timestamp(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, or return None.

    Returning ``None`` is a first-class answer that callers turn into UNKNOWN.
    Guessing — treating an unparseable date as the epoch, say — would make every
    account with a malformed timestamp read as dormant since 1970, and the
    timestamp format is chosen by the provider rather than by us.
    """
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # A naive timestamp from a provider is UTC in every API this tool reads.
        # Assuming local time instead would shift every age calculation by the
        # runner's timezone, which is not a property of the tenant.
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def days_between(earlier: datetime, later: datetime) -> int:
    return int((later - earlier).total_seconds() // 86400)


@dataclass(slots=True)
class CheckContext:
    """Everything a check is allowed to reach."""

    state: IdentityState
    config: Config
    label: Callable[[str, str], str] = field(default=lambda principal_id, display: display or principal_id)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def policy(self) -> PolicyConfig:
        return self.config.policy

    @property
    def settings(self) -> Settings:
        return self.config.settings

    # -- tri-state -----------------------------------------------------

    def covers(self, facet: str) -> Determination:
        return self.state.covers(facet)

    def indeterminate(self, check: str, facet: str, *, detail: str = "") -> Finding:
        """The finding to emit when a facet could not be read.

        Deliberately OPERATIONAL: it describes the tool, not the tenant. The
        severity table caps anything resting on UNKNOWN at LOW, so this can never
        trip an operator's ``fail_on`` threshold and can never be mistaken for a
        discovered weakness.
        """
        consequence = FACET_CONSEQUENCE.get(facet, "the corresponding findings are not produced")
        return Finding(
            subject=self.state.tenant or "tenant",
            subject_id="tenant",
            check=check,
            issue=Issue.FACET_INDETERMINATE.value,
            kind=FindingKind.OPERATIONAL,
            severity=rate(Issue.FACET_INDETERMINATE, determination=Determination.UNKNOWN),
            title=f"{facet.replace('_', ' ')} could not be determined",
            detail=(
                detail
                or f"The source could not read {facet.replace('_', ' ')} for this tenant, so {consequence}. "
                "This is reported rather than treated as a clean result: absence of data is not "
                "evidence of absence."
            ),
            remediation=(
                "Grant the read scope this facet needs, or accept that this check is not covered. "
                "See the permissions table in the README."
            ),
            determination=Determination.UNKNOWN,
            evidence={"facet": facet},
        )

    # -- findings ------------------------------------------------------

    def finding(
        self,
        *,
        check: str,
        issue: Issue,
        subject: str,
        subject_id: str,
        title: str,
        detail: str,
        remediation: str = "",
        kind: FindingKind = FindingKind.POSTURE,
        tier: RoleTier = RoleTier.PRIVILEGED,
        determination: Determination = Determination.PRESENT,
        evidence: dict[str, Any] | None = None,
        references: tuple[str, ...] = (),
    ) -> Finding:
        """Build a finding with its severity derived, never chosen.

        The derivation is appended to the evidence so a reader can see why the
        band is what it is without reading the source.
        """
        payload = dict(evidence or {})
        payload["severity_basis"] = explain(issue, tier=tier, determination=determination)
        return Finding(
            subject=subject,
            subject_id=subject_id,
            check=check,
            issue=issue.value,
            kind=kind if not determination.is_unknown else FindingKind.OPERATIONAL,
            severity=rate(issue, tier=tier, determination=determination),
            title=title,
            detail=detail,
            remediation=remediation,
            determination=determination,
            evidence=payload,
            references=references,
        )

    # -- lookups -------------------------------------------------------

    def role_tier(self, role_name: str) -> RoleTier:
        """Tier for a role, with the operator's own classification taking priority.

        A custom role cannot be classified from its name, so
        ``policy.privileged_roles`` wins over the built-in catalog rather than
        merely supplementing it — an operator who says their
        ``Break Glass Operator`` role is tenant-admin equivalent knows something
        the catalog cannot.
        """
        override = self.policy.privileged_roles.get(normalize_key(role_name))
        if override is not None:
            return override
        return catalog_role_tier(role_name)

    def principal_label(self, principal: Principal) -> str:
        return self.label(principal.principal_id, principal.display or principal.upn)

    def label_for_id(self, principal_id: str, display: str = "") -> str:
        return self.label(principal_id, display)

    def is_ignored_principal(self, principal_id: str, upn: str = "") -> bool:
        if not self.policy.ignore_principals:
            return False
        keys = {normalize_key(principal_id), normalize_key(upn)} - {""}
        return bool(keys & set(self.policy.ignore_principals))

    def is_ignored_application(self, workload: Workload) -> bool:
        """Is this workload on the operator's ignore list?

        Matched on the object id and the application id only, never on the
        display name. A display name is chosen by whoever registered the
        application, which in the scenario this tool exists to catch is the
        attacker: matching on it means registering an application called
        ``Atlassian Cloud`` removes it from the report *and* from the baseline,
        so the drift rule never sees it either. An allow list keyed on a string
        the adversary picks is an allow list for the adversary.
        """
        if not self.policy.ignore_applications:
            return False
        keys = {normalize_key(workload.workload_id), normalize_key(workload.app_id)} - {""}
        return bool(keys & set(self.policy.ignore_applications))

    def is_approved_application(self, *identifiers: str) -> bool:
        """Has the operator reviewed and accepted this application?

        Callers pass identifiers only, for the reason
        :meth:`is_ignored_application` gives. Suppressing a finding is the most
        valuable thing an attacker can make this tool do, so nothing that
        suppresses one is keyed on a name the attacker controls.
        """
        if not self.policy.approved_applications:
            return False
        keys = {normalize_key(identifier) for identifier in identifiers} - {""}
        return bool(keys & set(self.policy.approved_applications))


CheckFunc = Callable[[CheckContext], CheckResult]


class Check(Protocol):
    name: str

    def __call__(self, ctx: CheckContext) -> CheckResult: ...


_REGISTRY: dict[str, CheckFunc] = {}


def register(name: str) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check under *name* so config can select it."""

    def decorator(func: CheckFunc) -> CheckFunc:
        if name in _REGISTRY:
            raise RuntimeError(f"check {name!r} is already registered")
        func.name = name  # type: ignore[attr-defined]
        _REGISTRY[name] = func
        return func

    return decorator


def get_check(name: str) -> CheckFunc:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"no such check: {name}") from exc


def registered_checks() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))
