"""Shared builders.

Every test constructs its state explicitly rather than reading a fixture file:
the interesting cases here are all about a single field being absent versus
being unreadable, and that distinction is invisible in a JSON fixture somebody
edits six months later.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from idpdrift.checks import CheckContext, get_check
from idpdrift.config import Config, FileSourceConfig, PolicyConfig, Settings, SourceConfig
from idpdrift.models import (
    AccessPolicy,
    CheckResult,
    Credential,
    Determination,
    IdentityState,
    OAuthGrant,
    PermissionGrant,
    Principal,
    PrincipalKind,
    RoleAssignment,
    Workload,
)

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)

# Everything readable unless a test says otherwise. Tests that care about the
# tri-state override one facet, which keeps the interesting line visible.
FULL_COVERAGE = {
    "principals": Determination.PRESENT,
    "guest_status": Determination.PRESENT,
    "authentication_methods": Determination.PRESENT,
    "sign_in_activity": Determination.PRESENT,
    "group_membership": Determination.PRESENT,
    "role_assignments": Determination.PRESENT,
    "role_eligibility": Determination.PRESENT,
    "service_principals": Determination.PRESENT,
    "application_credentials": Determination.PRESENT,
    "application_permissions": Determination.PRESENT,
    "oauth_grants": Determination.PRESENT,
    "access_policies": Determination.PRESENT,
}


def principal(
    principal_id: str = "u1",
    *,
    display: str = "Alice Admin",
    upn: str = "alice@corp.example",
    kind: PrincipalKind = PrincipalKind.USER,
    enabled: Determination = Determination.PRESENT,
    last_sign_in: str = "2026-08-09T09:00:00Z",
    sign_in_known: Determination = Determination.PRESENT,
    phishing_resistant: Determination = Determination.PRESENT,
    second_factor: Determination = Determination.PRESENT,
    auth_methods: tuple[str, ...] = ("fido2SecurityKey",),
    group_count: int = 3,
    created_at: str = "2020-01-01T00:00:00Z",
) -> Principal:
    return Principal(
        principal_id=principal_id,
        display=display,
        upn=upn,
        kind=kind,
        enabled=enabled,
        last_sign_in=last_sign_in,
        sign_in_known=sign_in_known,
        phishing_resistant=phishing_resistant,
        second_factor=second_factor,
        auth_methods=auth_methods,
        group_count=group_count,
        group_count_known=Determination.PRESENT,
        created_at=created_at,
    )


def assignment(
    principal_id: str = "u1",
    role_name: str = "Global Administrator",
    *,
    role_id: str = "role-ga",
    standing: Determination = Determination.PRESENT,
    kind: PrincipalKind = PrincipalKind.USER,
    display: str = "Alice Admin",
    scope: str = "/",
) -> RoleAssignment:
    return RoleAssignment(
        assignment_id=f"{role_id}:{principal_id}",
        role_id=role_id,
        role_name=role_name,
        principal_id=principal_id,
        principal_display=display,
        principal_kind=kind,
        scope=scope,
        standing=standing,
    )


def workload(
    workload_id: str = "sp1",
    *,
    display: str = "Payroll Sync",
    credentials: tuple[Credential, ...] = (),
    permissions: tuple[PermissionGrant, ...] = (),
    third_party: Determination = Determination.PRESENT,
) -> Workload:
    return Workload(
        workload_id=workload_id,
        display=display,
        app_id="app-1",
        third_party=third_party,
        enabled=Determination.PRESENT,
        credentials=credentials,
        permissions=permissions,
    )


def credential(
    credential_id: str = "c1",
    *,
    kind: str = "secret",
    starts_at: str = "2026-07-01T00:00:00Z",
    expires_at: str = "2027-07-01T00:00:00Z",
) -> Credential:
    return Credential(credential_id=credential_id, kind=kind, starts_at=starts_at, expires_at=expires_at)


def permission(scope: str = "Mail.Read", *, application: bool = True) -> PermissionGrant:
    return PermissionGrant(
        permission_id=f"perm-{scope}", scope=scope, resource="Microsoft Graph", application=application
    )


def grant(
    grant_id: str = "og1",
    *,
    client_id: str = "sp1",
    client_display: str = "Payroll Sync",
    scopes: tuple[str, ...] = ("Mail.Read",),
    tenant_wide: bool = False,
) -> OAuthGrant:
    return OAuthGrant(
        grant_id=grant_id,
        client_id=client_id,
        client_display=client_display,
        resource="Microsoft Graph",
        scopes=scopes,
        tenant_wide=tenant_wide,
    )


def policy(
    policy_id: str = "cap1",
    *,
    display: str = "Require MFA for admins",
    state: str = "enabled",
    excluded_users: tuple[str, ...] = (),
) -> AccessPolicy:
    return AccessPolicy(policy_id=policy_id, display=display, state=state, excluded_users=excluded_users)


def make_state(
    *,
    principals: list[Principal] | None = None,
    role_assignments: list[RoleAssignment] | None = None,
    workloads: list[Workload] | None = None,
    oauth_grants: list[OAuthGrant] | None = None,
    policies: list[AccessPolicy] | None = None,
    coverage: dict[str, Determination] | None = None,
    tenant: str = "corp.example",
) -> IdentityState:
    merged = dict(FULL_COVERAGE)
    merged.update(coverage or {})
    return IdentityState(
        collected_at="2026-08-10T12:00:00+00:00",
        source="file",
        tenant=tenant,
        principals=principals or [],
        role_assignments=role_assignments or [],
        workloads=workloads or [],
        oauth_grants=oauth_grants or [],
        policies=policies or [],
        coverage=merged,
    )


def make_config(**policy_kwargs: Any) -> Config:
    return Config(
        source=SourceConfig(type="file", file=FileSourceConfig(path="export.json")),
        settings=Settings(),
        policy=PolicyConfig(**policy_kwargs),
    )


def run_check(name: str, state: IdentityState, config: Config | None = None) -> CheckResult:
    """Run one check with identity labels left in the clear.

    Pseudonymisation is exercised in its own tests; using the identity function
    here keeps every other assertion readable.
    """
    ctx = CheckContext(
        state=state,
        config=config or make_config(),
        label=lambda principal_id, display: display or principal_id,
        now=NOW,
    )
    return get_check(name)(ctx)


def issues(result: CheckResult) -> set[str]:
    return {f.issue for f in result.findings}


@pytest.fixture
def now() -> datetime:
    return NOW
