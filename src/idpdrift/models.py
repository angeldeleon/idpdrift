"""Core data model.

Plain dataclasses on purpose: a tool that makes claims about who can administer
your identity provider should be auditable by reading it, without the reader
having to understand a validation framework first.

Three types carry the weight.

:class:`Determination` is the tri-state. Every fact this tool asserts is
*present*, *definitively absent*, or *could not be determined*. Collapsing the
third into the second is the single largest source of false positives in tools
of this shape — a directory that declines to return authentication methods
becomes "nobody has MFA", and the report is thrown away along with the real
findings inside it. Nothing in this codebase converts ``UNKNOWN`` to ``ABSENT``;
what CI can mechanically enforce, and does, is the consequence — the invariants
job fails the build if any issue resting on ``UNKNOWN`` rates above the cap in
:mod:`idpdrift.severity`, so a collapse that slipped through could never sound
like a discovered weakness.

:class:`IdentityState` is everything one collection observed, plus a per-facet
:class:`Determination` recording what the source could actually see.

:class:`Finding` is one thing a human should look at. It carries the
determination that produced it, so a reader can tell a real gap from an
unreadable one, and it scrubs its own evidence at construction so no output sink
has to remember to.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .validation import safe_text, scrub_evidence


def plural(count: int, singular: str, plural_form: str = "") -> str:
    """Pluralise without parentheses.

    Titles are escaped for Markdown before rendering, so "role assignment(s)"
    comes out as "role assignment\\(s\\)" — the escaping is correct and the
    English is the thing to fix. Cheaper to write correct English than to
    un-escape.
    """
    if count == 1:
        return singular
    return plural_form or f"{singular}s"


class Severity(str, Enum):
    """Finding severity, ordered.

    ``rank`` drives comparisons and exit-code thresholds; the string value is
    what humans and JSON consumers see. Which severity a given issue gets is not
    decided here — see :mod:`idpdrift.severity` for the table.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {valid})") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Determination(str, Enum):
    """Present, definitively absent, or could not be determined.

    The third value is the reason this enum exists rather than a ``bool``. A
    directory API returns "no authentication methods" both when an account
    genuinely has none and when the caller lacks
    ``UserAuthenticationMethod.Read.All``; a ``bool | None`` invites the reader
    to write ``if not mfa:`` and silently merge the two. Naming the third state
    makes the merge something you have to type on purpose.
    """

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"

    @property
    def is_present(self) -> bool:
        return self is Determination.PRESENT

    @property
    def is_absent(self) -> bool:
        return self is Determination.ABSENT

    @property
    def is_unknown(self) -> bool:
        return self is Determination.UNKNOWN

    @classmethod
    def parse(cls, raw: object) -> Determination:
        """Parse a persisted or source-supplied value, defaulting to UNKNOWN.

        Defaulting the *other* way would be the bug this type exists to stop: an
        older state file, or a source that omits the field, would read as
        "definitively absent" and manufacture a finding for every account.
        """
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_optional(cls, value: bool | None) -> Determination:
        """Map ``True``/``False``/``None`` onto the tri-state."""
        if value is None:
            return cls.UNKNOWN
        return cls.PRESENT if value else cls.ABSENT


class FindingKind(str, Enum):
    """Why a finding exists.

    POSTURE describes the tenant as it stands right now. DRIFT describes a change
    since the previous scan — the reason to run this on a schedule. OPERATIONAL
    means the tool could not complete something and is saying so rather than
    reporting a clean result.
    """

    POSTURE = "posture"
    DRIFT = "drift"
    OPERATIONAL = "operational"


class PrincipalKind(str, Enum):
    """What sort of identity this is.

    The distinction between a person and a workload matters for almost every
    check here: "no second factor" is a finding for a human and meaningless for a
    service principal, and "holds Global Administrator" is far worse for a
    workload nobody signs in to.
    """

    USER = "user"
    GUEST = "guest"
    SERVICE_ACCOUNT = "service_account"
    SERVICE_PRINCIPAL = "service_principal"
    GROUP = "group"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, raw: object) -> PrincipalKind:
        text = str(raw or "").strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "member": cls.USER,
            "human": cls.USER,
            "external": cls.GUEST,
            "b2b": cls.GUEST,
            "guest_user": cls.GUEST,
            "serviceprincipal": cls.SERVICE_PRINCIPAL,
            "application": cls.SERVICE_PRINCIPAL,
            "app": cls.SERVICE_PRINCIPAL,
            "workload": cls.SERVICE_PRINCIPAL,
            "serviceaccount": cls.SERVICE_ACCOUNT,
            "service": cls.SERVICE_ACCOUNT,
            "bot": cls.SERVICE_ACCOUNT,
        }
        if text in aliases:
            return aliases[text]
        try:
            return cls(text)
        except ValueError:
            return cls.UNKNOWN

    @property
    def is_human(self) -> bool:
        return self in (PrincipalKind.USER, PrincipalKind.GUEST)


# Everything a source might or might not be able to read. Each carries its own
# Determination in IdentityState.coverage, because permission to read a
# directory is granted per scope: a caller can hold Directory.Read.All and see
# every role assignment while seeing no authentication methods at all.
FACETS: tuple[str, ...] = (
    "principals",
    "guest_status",
    "authentication_methods",
    "sign_in_activity",
    "group_membership",
    "role_assignments",
    "role_eligibility",
    "service_principals",
    "application_credentials",
    "application_permissions",
    "oauth_grants",
    "access_policies",
)


@dataclass(frozen=True, slots=True)
class Principal:
    """One identity: a person, a guest, or a workload account.

    ``display`` and ``upn`` are attacker-influenced — whoever creates an account
    chooses them — and are sanitised at ingestion. ``label`` is what a human sees
    and may be pseudonymised; see :mod:`idpdrift.privacy`.
    """

    principal_id: str
    display: str
    upn: str = ""
    kind: PrincipalKind = PrincipalKind.UNKNOWN
    enabled: Determination = Determination.UNKNOWN
    last_sign_in: str = ""
    sign_in_known: Determination = Determination.UNKNOWN
    phishing_resistant: Determination = Determination.UNKNOWN
    second_factor: Determination = Determination.UNKNOWN
    auth_methods: tuple[str, ...] = ()
    group_count: int = 0
    group_count_known: Determination = Determination.UNKNOWN
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        for key in ("enabled", "sign_in_known", "phishing_resistant", "second_factor", "group_count_known"):
            out[key] = getattr(self, key).value
        out["auth_methods"] = list(self.auth_methods)
        return out


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    """One principal holding one directory role at one scope.

    ``standing`` answers "is this permanent, or does it have to be activated?"
    and is a :class:`Determination` rather than a bool because a tenant without
    privileged identity management has no eligibility concept at all — which is
    "we cannot tell you", not "everything is just-in-time".
    """

    assignment_id: str
    role_id: str
    role_name: str
    principal_id: str
    principal_display: str
    principal_kind: PrincipalKind = PrincipalKind.UNKNOWN
    scope: str = "/"
    standing: Determination = Determination.UNKNOWN
    assigned_at: str = ""

    @property
    def key(self) -> str:
        """Identity for drift.

        Built from role, principal and scope rather than the provider's
        assignment id: recreating an assignment produces a new id, and keying on
        it would report every re-grant of an unchanged permission as new while
        missing a genuine re-grant at a different scope.
        """
        return f"{self.role_id or self.role_name}|{self.principal_id}|{self.scope}"

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["principal_kind"] = self.principal_kind.value
        out["standing"] = self.standing.value
        return out


@dataclass(frozen=True, slots=True)
class Credential:
    """One secret or certificate on an application registration.

    Constructed through :meth:`from_raw`, which never accepts key material into
    the object in the first place.
    """

    credential_id: str
    kind: str = "unknown"  # secret / certificate / unknown
    display: str = ""
    starts_at: str = ""
    expires_at: str = ""

    @property
    def is_secret(self) -> bool:
        return self.kind == "secret"

    @classmethod
    def from_raw(cls, raw: dict[str, Any], *, kind: str) -> Credential:
        """Build from an API payload, dropping the credential material.

        Graph's ``passwordCredentials`` carries ``secretText`` on creation and
        ``keyCredentials`` carries ``key``. Neither is needed to report that a
        credential exists and when it expires, and an object that never holds
        them cannot leak them through a renderer, a webhook, or the state file.
        """
        return cls(
            credential_id=safe_text(raw.get("keyId") or raw.get("id") or "", limit=64),
            kind=kind,
            display=safe_text(raw.get("displayName") or raw.get("name") or "", limit=120),
            starts_at=safe_text(raw.get("startDateTime") or raw.get("start") or "", limit=40),
            expires_at=safe_text(raw.get("endDateTime") or raw.get("expires") or "", limit=40),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PermissionGrant:
    """One permission a workload holds against a resource API.

    ``application`` distinguishes an app-only permission — which the workload
    exercises with no user present, against every object in the tenant — from a
    delegated one, which is bounded by the signed-in user's own access. Confusing
    the two is the most common way a "read-only reporting app" turns out to be
    able to read every mailbox in the organisation.
    """

    permission_id: str
    scope: str
    resource: str = ""
    application: bool = True
    granted_at: str = ""

    @property
    def key(self) -> str:
        return f"{self.resource}|{self.scope}|{'app' if self.application else 'delegated'}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Workload:
    """A service principal / application registration."""

    workload_id: str
    display: str
    app_id: str = ""
    third_party: Determination = Determination.UNKNOWN
    credentials: tuple[Credential, ...] = ()
    permissions: tuple[PermissionGrant, ...] = ()
    enabled: Determination = Determination.UNKNOWN
    owner_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "display": self.display,
            "app_id": self.app_id,
            "third_party": self.third_party.value,
            "enabled": self.enabled.value,
            "owner_count": self.owner_count,
            "credentials": [c.to_dict() for c in self.credentials],
            "permissions": [p.to_dict() for p in self.permissions],
        }


@dataclass(frozen=True, slots=True)
class OAuthGrant:
    """One consent grant: an application allowed to act with certain scopes.

    ``tenant_wide`` is Graph's ``consentType: AllPrincipals`` and Okta's
    org-level grant — an administrator consenting on behalf of everyone, which
    turns one user's decision into an organisation-wide one.
    """

    grant_id: str
    client_id: str
    client_display: str
    resource: str = ""
    scopes: tuple[str, ...] = ()
    tenant_wide: bool = False
    principal_id: str = ""

    @property
    def key(self) -> str:
        return f"{self.client_id}|{self.resource}|{self.principal_id or 'all'}"

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["scopes"] = list(self.scopes)
        return out


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """A conditional-access or sign-on policy, and who is exempt from it."""

    policy_id: str
    display: str
    state: str = "unknown"  # enabled / disabled / report_only / unknown
    excluded_users: tuple[str, ...] = ()
    excluded_groups: tuple[str, ...] = ()
    excluded_roles: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        for key in ("excluded_users", "excluded_groups", "excluded_roles"):
            out[key] = list(getattr(self, key))
        return out


@dataclass(slots=True)
class IdentityState:
    """Everything one collection observed about one tenant.

    ``coverage`` is the honest part. A source records, per facet, whether it read
    it, confirmed it is empty, or could not tell. Checks consult it before
    reporting an absence, and the store merges rather than replaces an
    unreadable facet so a permissions problem for one run cannot wipe a baseline
    and manufacture a directory's worth of drift on the next.
    """

    collected_at: str
    source: str
    tenant: str = ""
    principals: list[Principal] = field(default_factory=list)
    role_assignments: list[RoleAssignment] = field(default_factory=list)
    workloads: list[Workload] = field(default_factory=list)
    oauth_grants: list[OAuthGrant] = field(default_factory=list)
    policies: list[AccessPolicy] = field(default_factory=list)
    coverage: dict[str, Determination] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def covers(self, facet: str) -> Determination:
        """What the source could see for *facet*.

        Unrecorded facets read as UNKNOWN, never as ABSENT. A source that forgets
        to declare coverage should make the tool quieter, not louder.
        """
        return self.coverage.get(facet, Determination.UNKNOWN)

    def principal_by_id(self, principal_id: str) -> Principal | None:
        return self._index().get(principal_id)

    def _index(self) -> dict[str, Principal]:
        return {p.principal_id: p for p in self.principals}

    @property
    def identity_count(self) -> int:
        return len(self.principals) + len(self.workloads)

    @property
    def indeterminate_facets(self) -> list[str]:
        return [facet for facet in FACETS if self.covers(facet).is_unknown]


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a human should look at.

    ``evidence`` is scrubbed in ``__post_init__`` rather than at the renderers.
    That is the whole point: there are four sinks today and the fifth one will
    not remember, so a finding simply never holds a credential.
    """

    subject: str
    subject_id: str
    check: str
    issue: str
    kind: FindingKind
    severity: Severity
    title: str
    detail: str
    remediation: str = ""
    determination: Determination = Determination.PRESENT
    evidence: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        scrubbed = scrub_evidence(self.evidence)
        if scrubbed != self.evidence:
            object.__setattr__(self, "evidence", scrubbed)

    @property
    def fingerprint(self) -> str:
        """Stable ID for deduplication and alert suppression.

        Excludes ``detail`` and ``evidence`` so that rewording a check, or an
        expiry date ticking down, does not resurface a finding somebody already
        triaged.
        """
        raw = f"{self.subject_id}|{self.check}|{self.issue}|{self.kind.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        out["severity"] = self.severity.value
        out["determination"] = self.determination.value
        out["references"] = list(self.references)
        out["fingerprint"] = self.fingerprint
        return out


@dataclass(slots=True)
class CheckResult:
    """What one check observed, and what it wants reported.

    ``observations`` is persisted and diffed against the next run, so it must be
    JSON-serialisable and deterministic — no timestamps, no set ordering, no
    object reprs. A field that varies run to run produces a drift finding on
    every scan and gets the tool muted inside a week.
    """

    check: str
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    partial: bool = False
    """Observations are correct but describe only part of the picture.

    A partial result is *merged over* the previous baseline instead of replacing
    it. Every check sets this when a facet it needs came back UNKNOWN: recording
    "no role assignments" because the token lacked a scope would erase the
    baseline, and the next successful run would then report every administrator
    in the tenant as newly appointed.
    """

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(slots=True)
class Snapshot:
    """The persisted state of one tenant at one point in time."""

    tenant: str
    collected_at: str
    source: str = ""
    checks: dict[str, dict[str, Any]] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "collected_at": self.collected_at,
            "source": self.source,
            "checks": self.checks,
            "coverage": self.coverage,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Snapshot:
        if not isinstance(raw, dict):
            raise ValueError("snapshot must be an object")
        tenant = raw.get("tenant")
        if not isinstance(tenant, str) or not tenant:
            raise ValueError("snapshot is missing a tenant")
        checks = raw.get("checks") or {}
        coverage = raw.get("coverage") or {}
        errors = raw.get("errors") or {}
        if not isinstance(checks, dict) or not isinstance(errors, dict) or not isinstance(coverage, dict):
            raise ValueError("snapshot checks/coverage/errors must be objects")
        return cls(
            tenant=tenant,
            collected_at=str(raw.get("collected_at") or ""),
            source=str(raw.get("source") or ""),
            checks=checks,
            coverage={str(k): str(v) for k, v in coverage.items()},
            errors={str(k): str(v) for k, v in errors.items()},
        )


# Serialisation caps. A tenant with fifty thousand assignments must not be able
# to produce a report nobody can open or a webhook payload the receiver drops.
MAX_SERIALISED_FINDINGS = 500
MAX_SERIALISED_ERRORS = 50


@dataclass(slots=True)
class ScanReport:
    """Everything one ``idpdrift scan`` produced."""

    started_at: str
    finished_at: str
    tool_version: str
    source: str
    tenant: str = ""
    snapshot: Snapshot | None = None
    findings: list[Finding] = field(default_factory=list)
    baseline_available: bool = False
    identities_seen: int = 0
    checks_run: int = 0
    checks_failed: int = 0
    indeterminate_facets: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    ai_summary: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def scan_degraded(self) -> bool:
        """True when the collection failed badly enough that "no findings" is a lie.

        A tool that reports a clean tenant because its token expired is worse
        than one that fails loudly: the dashboard goes green and everyone assumes
        nobody has been granted Global Administrator this week.
        """
        if self.identities_seen == 0:
            return True
        if self.checks_run == 0:
            return False
        # A floor of three keeps one flaky check in a small selection from
        # tripping the whole scan.
        return self.checks_run >= 3 and self.checks_failed * 2 > self.checks_run

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def counts_by_determination(self) -> dict[str, int]:
        """How many findings rest on each tri-state answer.

        Published in every rendering so a reader can see at a glance how much of
        the report is "we found this" and how much is "we could not look".
        """
        counts = {d.value: 0 for d in Determination}
        for finding in self.findings:
            counts[finding.determination.value] += 1
        return counts

    def affected_subjects(self) -> int:
        return len({f.subject_id for f in self.findings if f.kind is not FindingKind.OPERATIONAL})

    def to_dict(self) -> dict[str, Any]:
        findings = self.findings[:MAX_SERIALISED_FINDINGS]
        return {
            "tool": "idpdrift",
            "tool_version": self.tool_version,
            "source": self.source,
            "tenant": self.tenant,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "identities_seen": self.identities_seen,
            "affected_subjects": self.affected_subjects(),
            "baseline_available": self.baseline_available,
            "scan_degraded": self.scan_degraded,
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "indeterminate_facets": self.indeterminate_facets[:MAX_SERIALISED_ERRORS],
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_determination": self.counts_by_determination(),
            "collection_errors": self.collection_errors[:MAX_SERIALISED_ERRORS],
            "findings": [f.to_dict() for f in findings],
            "findings_total": len(self.findings),
            "findings_truncated": len(self.findings) > len(findings),
            "ai_summary": self.ai_summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
