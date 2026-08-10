"""Provider semantics: what a field from Graph or the Okta API actually means.

These are the tests that would have caught a wrong reading of an API rather than
a wrong line of Python. Getting a directory's own vocabulary wrong is the most
expensive class of bug this tool can have, because the output is still a
confident sentence about somebody's access — it just is not true, and nobody
downstream has the context to notice.

Both providers are stubbed at :func:`idpdrift.httpclient.safe_request`, so the
guarded client, the URL validation and the token handling are all still in the
path and only the network is replaced.
"""

from __future__ import annotations

import os
from typing import Any
from unittest import mock

import pytest

from idpdrift.catalog import scope_impact
from idpdrift.config import EntraSourceConfig, OktaSourceConfig
from idpdrift.models import Determination
from idpdrift.report import render_markdown
from idpdrift.sources.entra import EntraSource
from idpdrift.sources.okta import OktaSource

TENANT = "00000000-0000-0000-0000-000000000000"

# A directoryRole carries two different GUIDs: `id` is the role object in this
# tenant, `roleTemplateId` is the role *definition*. The eligibility endpoint
# keys on the second one.
GA_OBJECT_ID = "9b3a1c2d-1111-4000-8000-aaaaaaaaaaaa"
GA_DEFINITION_ID = "62e90394-69f5-4237-9190-012177145e10"

# The GUID Microsoft Graph publishes for the Mail.Read application permission.
MAIL_READ_ROLE_ID = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"


class _Response:
    def __init__(self, payload: Any, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}

    def json(self) -> Any:
        return self._payload


def _graph(**overrides: Any):
    """A minimal but shape-accurate Graph, with per-endpoint overrides."""
    registration = overrides.get(
        "registration",
        [{"id": "u1", "isMfaCapable": True, "methodsRegistered": ["fido2SecurityKey"]}],
    )
    service_principals = overrides.get(
        "service_principals",
        [
            {
                "id": "sp1",
                "appId": "app-1",
                "displayName": "Payroll Sync",
                "accountEnabled": True,
                "passwordCredentials": [],
                "keyCredentials": [],
            },
            {
                "id": "sp-graph",
                "appId": "00000003-0000-0000-c000-000000000000",
                "displayName": "Microsoft Graph",
                "accountEnabled": True,
                "passwordCredentials": [],
                "keyCredentials": [],
                "appRoles": [{"id": MAIL_READ_ROLE_ID, "value": "Mail.Read"}],
            },
        ],
    )
    eligibility = overrides.get("eligibility", [{"roleDefinitionId": GA_DEFINITION_ID, "principalId": "u1"}])
    refuse = set(overrides.get("refuse", ()))

    def request(method: str, url: str, **kwargs: Any) -> _Response:
        if "oauth2/v2.0/token" in url:
            return _Response({"access_token": "not-a-real-token"})
        for fragment in refuse:
            if fragment in url:
                return _Response({}, status=403)
        if "/directoryRoles/" in url and url.endswith("/members"):
            return _Response(
                {"value": [{"id": "u1", "displayName": "Alice", "@odata.type": "#microsoft.graph.user"}]}
            )
        if url.endswith("/directoryRoles"):
            return _Response(
                {
                    "value": [
                        {
                            "id": GA_OBJECT_ID,
                            "roleTemplateId": GA_DEFINITION_ID,
                            "displayName": "Global Administrator",
                        }
                    ]
                }
            )
        if "roleEligibilityScheduleInstances" in url:
            return _Response({"value": eligibility})
        if "userRegistrationDetails" in url:
            return _Response({"value": registration})
        if "/users" in url:
            return _Response(
                {
                    "value": [
                        {
                            "id": "u1",
                            "displayName": "Alice Admin",
                            "userPrincipalName": "alice@corp.example",
                            "accountEnabled": True,
                            "userType": "Member",
                        }
                    ]
                }
            )
        if "appRoleAssignments" in url:
            return _Response(
                {
                    "value": [
                        {
                            "appRoleId": MAIL_READ_ROLE_ID,
                            "resourceDisplayName": "Microsoft Graph",
                            "createdDateTime": "2026-01-01T00:00:00Z",
                        }
                    ]
                }
            )
        if "servicePrincipals" in url:
            return _Response({"value": service_principals})
        return _Response({"value": []})

    return request


def _collect_entra(**overrides: Any):
    with (
        mock.patch("idpdrift.sources.entra.safe_request", _graph(**overrides)),
        mock.patch.dict(os.environ, {"IDPDRIFT_ENTRA_CLIENT_SECRET": "secret"}),
    ):
        return EntraSource(EntraSourceConfig(tenant_id=TENANT, client_id=TENANT)).collect()


class TestEntraRoleEligibility:
    """`directoryRole.id` and `roleEligibilityScheduleInstance.roleDefinitionId`
    are different GUIDs. Joining on the wrong one matches nothing in any tenant,
    which is indistinguishable from a tenant where nobody is eligible — so every
    activated just-in-time assignment reads as permanent and the tool reports
    the privileged identity management deployment as if it were not there."""

    def test_an_eligible_assignment_is_not_standing(self) -> None:
        state = _collect_entra()
        assert state.role_assignments[0].standing.is_absent

    def test_an_assignment_with_no_eligibility_row_stays_standing(self) -> None:
        state = _collect_entra(eligibility=[])
        assert state.role_assignments[0].standing.is_present

    def test_a_refused_eligibility_endpoint_leaves_the_facet_indeterminate(self) -> None:
        state = _collect_entra(refuse=("roleEligibilityScheduleInstances",))
        assert state.covers("role_eligibility").is_unknown
        assert state.role_assignments[0].standing.is_present


class TestEntraApplicationPermissions:
    """`appRoleAssignments` names a permission by GUID. Every rule downstream
    matches on the value, so recording the GUID as the scope meant no
    application permission was ever rated high-impact against a real tenant —
    the check the module docstring calls the one that turns into an incident
    detected precisely nothing."""

    def test_an_app_role_id_is_resolved_to_its_permission_name(self) -> None:
        state = _collect_entra()
        permission = state.workloads[0].permissions[0]
        assert permission.scope == "Mail.Read"
        assert permission.permission_id == MAIL_READ_ROLE_ID

    def test_the_resolved_scope_matches_the_high_impact_catalog(self) -> None:
        state = _collect_entra()
        assert scope_impact(state.workloads[0].permissions[0].scope)

    def test_an_unresolvable_role_id_makes_the_facet_indeterminate(self) -> None:
        """Not silently rated on its GUID: a permission we cannot name is a
        permission we cannot rate, and "nothing high-impact here" would then be
        a claim about a list we could not read."""
        state = _collect_entra(
            service_principals=[
                {
                    "id": "sp1",
                    "appId": "app-1",
                    "displayName": "Payroll Sync",
                    "accountEnabled": True,
                    "passwordCredentials": [],
                    "keyCredentials": [],
                }
            ]
        )
        assert state.covers("application_permissions").is_unknown
        assert any("could not be resolved" in error for error in state.errors)


class TestEntraPhishingResistance:
    """`isPasswordlessCapable` is not the same claim as phishing-resistant.
    Microsoft counts Authenticator passwordless phone sign-in as passwordless,
    and a push approval is relayed in real time by every off-the-shelf phishing
    proxy — so the flag cleared exactly the administrators the check exists to
    find."""

    def test_a_security_key_reads_as_phishing_resistant(self) -> None:
        state = _collect_entra()
        assert state.principals[0].phishing_resistant.is_present

    def test_passwordless_push_does_not_read_as_phishing_resistant(self) -> None:
        state = _collect_entra(
            registration=[
                {
                    "id": "u1",
                    "isMfaCapable": True,
                    "isPasswordlessCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                }
            ]
        )
        assert state.principals[0].phishing_resistant.is_absent

    def test_a_row_with_no_method_list_stays_indeterminate(self) -> None:
        state = _collect_entra(registration=[{"id": "u1", "isMfaCapable": True}])
        assert state.principals[0].phishing_resistant.is_unknown


class TestSourceNotesRenderCleanly:
    """A source's coverage notes go through the same Markdown escaping a display
    name does, because they land in the same report. Tool-authored prose has to
    avoid the metacharacters or the reader sees stray backslashes and concludes
    the report is broken."""

    @pytest.mark.parametrize(
        "refuse",
        [
            ("userRegistrationDetails",),
            ("directoryRoles",),
            ("servicePrincipals",),
            ("conditionalAccess",),
        ],
    )
    def test_a_refusal_note_renders_without_backslashes(self, refuse: tuple[str, ...]) -> None:
        from idpdrift.models import ScanReport

        state = _collect_entra(refuse=refuse)
        assert state.errors
        report = ScanReport(
            started_at="a",
            finished_at="b",
            tool_version="0",
            source="entra",
            tenant="corp.example",
            collection_errors=state.errors,
        )
        assert "\\" not in render_markdown(report)


def _okta(users: list[dict[str, Any]]):
    def request(method: str, url: str, **kwargs: Any) -> _Response:
        if "/factors" in url:
            return _Response([])
        if "/roles" in url:
            return _Response([{"id": "r1", "type": "SUPER_ADMIN", "label": "Super Administrator"}])
        if "/api/v1/users" in url:
            return _Response(users)
        return _Response([])

    return request


def _collect_okta(users: list[dict[str, Any]]):
    with (
        mock.patch("idpdrift.sources.okta.safe_request", _okta(users)),
        mock.patch.dict(os.environ, {"OKTA_API_TOKEN": "not-a-real-token"}),
    ):
        return OktaSource(OktaSourceConfig(org_url="https://example.okta.com")).collect()


class TestOktaAccountStatus:
    """A lockout is what happens when somebody mistypes their password. It
    clears on unlock, often within the hour. Reading it as "disabled" produced a
    finding telling the reader to strip an administrator's roles as part of the
    leaver process, about somebody sitting at their desk."""

    def _user(self, status: str) -> list[dict[str, Any]]:
        return [
            {
                "id": "u1",
                "status": status,
                "profile": {"login": "alice@corp.example", "displayName": "Alice Admin"},
                "lastLogin": "2026-08-09T09:00:00Z",
            }
        ]

    @pytest.mark.parametrize("status", ["DEPROVISIONED", "SUSPENDED"])
    def test_a_deactivated_account_is_absent(self, status: str) -> None:
        state = _collect_okta(self._user(status))
        assert state.principals[0].enabled is Determination.ABSENT

    @pytest.mark.parametrize("status", ["LOCKED_OUT", "PASSWORD_EXPIRED", "RECOVERY", "ACTIVE"])
    def test_a_transient_state_is_not_a_deactivated_account(self, status: str) -> None:
        state = _collect_okta(self._user(status))
        assert state.principals[0].enabled is Determination.PRESENT

    def test_an_unreported_status_stays_indeterminate(self) -> None:
        state = _collect_okta([{"id": "u1", "profile": {"login": "alice@corp.example"}}])
        assert state.principals[0].enabled is Determination.UNKNOWN
