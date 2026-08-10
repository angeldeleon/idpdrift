"""Read-only client for Microsoft Entra ID, through Microsoft Graph.

Authenticates with the OAuth2 client-credentials flow and reads six things:

* ``/users`` — accounts, their enabled state and, where licensing allows, when
  they last signed in interactively
* ``/reports/authenticationMethods/userRegistrationDetails`` — which second
  factors each account has registered, in one paged call rather than one request
  per user
* ``/directoryRoles`` and their members — who holds which directory role, right
  now, permanently
* ``/roleManagement/directory/roleEligibilityScheduleInstances`` — who is
  *eligible* for a role but has to activate it, which is what makes "standing
  assignment" a meaningful finding rather than a description of every tenant
* ``/servicePrincipals`` — workload identities, their credentials and their
  application permissions
* ``/oauth2PermissionGrants`` and ``/identity/conditionalAccess/policies``

Every one of those is a GET. Nothing here creates, patches or deletes, and the
application registration it uses needs only ``.Read.All`` scopes:
``Directory.Read.All``, ``RoleManagement.Read.Directory``,
``Application.Read.All``, ``AuditLog.Read.All``,
``Policy.Read.All`` and ``UserAuthenticationMethod.Read.All``.

**Each of those scopes can be refused independently**, which is the reason this
module is written around coverage rather than around exceptions. A tenant that
grants directory read but not audit log read is a normal, sensible tenant; it
means sign-in activity is UNKNOWN, the dormancy check declines to conclude
anything, and the report says so. It does not mean nobody has signed in since
2019.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any
from urllib.parse import urlencode

from ..catalog import is_phishing_resistant
from ..config import EntraSourceConfig
from ..httpclient import HTTPError, safe_request
from ..models import (
    AccessPolicy,
    Credential,
    Determination,
    IdentityState,
    OAuthGrant,
    PermissionGrant,
    Principal,
    PrincipalKind,
    RoleAssignment,
    Workload,
    plural,
)
from ..validation import ValidationError, safe_text
from .base import SourceError

log = logging.getLogger(__name__)

GRAPH_VERSION = "v1.0"

# Bounds on what we will accept from the service. A compromised or simply broken
# Graph must not be able to make this process allocate without limit.
_MAX_PAGES = 2000
_MAX_ROLE_MEMBER_PAGES = 50


class EntraSource:
    """Collects identity state from Microsoft Entra ID."""

    name = "entra"

    def __init__(
        self,
        config: EntraSourceConfig,
        *,
        timeout: float = 30.0,
        user_agent: str = "idpdrift",
        max_identities: int = 100000,
    ) -> None:
        self.config = config
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_identities = max_identities
        self._token: str | None = None

    # ------------------------------------------------------------------
    # authentication
    # ------------------------------------------------------------------

    def _access_token(self) -> str:
        """Fetch an application token.

        The client secret is read from the environment at the moment it is
        needed and is never stored on this object; only the resulting bearer
        token is, and that is dropped on any cross-origin redirect by the HTTP
        client. Error paths deliberately never include the response body: the
        token endpoint echoes request parameters back on failure, and the request
        carried the secret.
        """
        if self._token is not None:
            return self._token

        secret = self.config.client_secret()
        if not secret:
            raise SourceError(
                f"no Entra client secret: set the {self.config.client_secret_env} environment variable"
            )

        url = f"{self.config.authority}/{self.config.tenant_id}/oauth2/v2.0/token"
        try:
            response = safe_request(
                "POST",
                url,
                timeout=self.timeout,
                headers={"content-type": "application/x-www-form-urlencoded"},
                form_body={
                    "client_id": self.config.client_id,
                    "client_secret": secret,
                    "scope": f"{self.config.graph_url}/.default",
                    "grant_type": "client_credentials",
                },
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Entra token request failed: {exc}") from exc

        if response.status_code != 200:
            raise SourceError(
                f"Entra rejected the client credentials (HTTP {response.status_code}). "
                "Check the tenant id, client id, and that the secret has not expired."
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError(f"Entra token endpoint returned non-JSON: {exc}") from exc

        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceError("Entra token endpoint returned no access token")
        self._token = token
        return token

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        # urlencode, not f-strings: every value here is a bounded literal today,
        # but building query strings by concatenation is how that stops being
        # true later.
        query = "?" + urlencode({k: v for k, v in (params or {}).items() if v is not None}) if params else ""
        url = f"{self.config.graph_url}/{GRAPH_VERSION}/{path.lstrip('/')}{query}"
        return self._request(url)

    def _request(self, url: str) -> dict[str, Any]:
        try:
            response = safe_request(
                "GET",
                url,
                timeout=self.timeout,
                headers={"Authorization": f"Bearer {self._access_token()}"},
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Graph request failed: {exc}") from exc

        if response.status_code in (401, 403):
            # Raised as a distinct type so callers can turn one refused scope
            # into UNKNOWN coverage rather than aborting the whole collection.
            raise _Forbidden(response.status_code)
        if response.status_code == 404:
            raise _Forbidden(404)
        if response.status_code != 200:
            raise SourceError(f"Graph returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError(f"Graph returned a non-JSON response: {exc}") from exc
        if not isinstance(payload, dict):
            raise SourceError("Graph returned an unexpected payload shape")
        return payload

    def _pages(
        self, path: str, params: dict[str, Any] | None = None, *, max_pages: int = _MAX_PAGES
    ) -> tuple[list[dict[str, Any]], bool]:
        """Follow ``@odata.nextLink`` and return ``(rows, complete)``.

        ``complete`` is False when the page cap or the identity cap stopped the
        walk. A caller that gets an incomplete list must record the facet as
        UNKNOWN: "the first ten thousand users have no role" says nothing about
        the rest, and treating it as a complete answer would report every
        administrator past the cap as newly removed.
        """
        rows: list[dict[str, Any]] = []
        payload = self._get(path, params)
        pages = 1
        while True:
            values = payload.get("value")
            if isinstance(values, list):
                rows.extend(item for item in values if isinstance(item, dict))
            if len(rows) >= self.max_identities:
                return rows[: self.max_identities], False
            next_link = payload.get("@odata.nextLink")
            if not isinstance(next_link, str) or not next_link:
                return rows, True
            if pages >= max_pages:
                return rows, False
            payload = self._request(next_link)
            pages += 1

    # ------------------------------------------------------------------
    # collection
    # ------------------------------------------------------------------

    def collect(self) -> IdentityState:
        state = IdentityState(
            collected_at=IdentityState.now_iso(), source=self.name, tenant=self.config.tenant_id
        )

        principals = self._collect_users(state)
        self._collect_auth_methods(principals, state)
        state.principals = list(principals.values())
        self._collect_roles(principals, state)
        self._collect_workloads(state)
        self._collect_grants(state)
        self._collect_policies(state)
        return state

    def _collect_users(self, state: IdentityState) -> dict[str, Principal]:
        select = "id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType,signInActivity"
        sign_in_coverage = Determination.PRESENT
        try:
            rows, complete = self._pages("users", {"$select": select, "$top": self.config.page_size})
        except _Forbidden:
            # signInActivity needs an Entra ID P1 licence and AuditLog.Read.All.
            # Retry without it rather than losing the user list entirely — the
            # accounts are the foundation every other check builds on.
            sign_in_coverage = Determination.UNKNOWN
            state.errors.append(
                "sign-in activity was refused — it needs AuditLog.Read.All and an Entra ID P1 "
                "licence; accounts were read without it and dormancy is reported as "
                "indeterminate rather than assumed"
            )
            try:
                rows, complete = self._pages(
                    "users",
                    {"$select": select.replace(",signInActivity", ""), "$top": self.config.page_size},
                )
            except _Forbidden as exc:
                raise SourceError(
                    "Graph refused the user list; the application registration needs Directory.Read.All"
                ) from exc

        if not complete:
            state.errors.append(
                "the user list was truncated by settings.max_identities; every facet derived "
                "from it is reported as indeterminate"
            )
            sign_in_coverage = Determination.UNKNOWN

        state.coverage["principals"] = Determination.PRESENT if complete else Determination.UNKNOWN
        state.coverage["sign_in_activity"] = sign_in_coverage
        # Graph always returns userType on the user object, so external accounts
        # are distinguishable whenever the user list itself was readable.
        state.coverage["guest_status"] = state.coverage["principals"]
        # Graph does not return group membership counts on the user list, and
        # one transitiveMemberOf call per user is a request budget nobody wants
        # spent this way. Declared unknown rather than defaulted to zero.
        state.coverage["group_membership"] = Determination.UNKNOWN

        principals: dict[str, Principal] = {}
        for row in rows:
            principal_id = safe_text(row.get("id") or "", limit=128)
            if not principal_id:
                continue
            activity = _dict(row.get("signInActivity"))
            last_sign_in = ""
            if activity:
                last_sign_in = safe_text(
                    activity.get("lastSignInDateTime")
                    or activity.get("lastNonInteractiveSignInDateTime")
                    or "",
                    limit=40,
                )
            user_type = str(row.get("userType") or "").strip().lower()
            principals[principal_id] = Principal(
                principal_id=principal_id,
                display=safe_text(row.get("displayName") or "", limit=200),
                upn=safe_text(row.get("userPrincipalName") or "", limit=254),
                kind=PrincipalKind.GUEST if user_type == "guest" else PrincipalKind.USER,
                enabled=Determination.from_optional(
                    row["accountEnabled"] if isinstance(row.get("accountEnabled"), bool) else None
                ),
                last_sign_in=last_sign_in,
                sign_in_known=(
                    Determination.UNKNOWN
                    if sign_in_coverage.is_unknown
                    else (Determination.PRESENT if last_sign_in else Determination.ABSENT)
                ),
                created_at=safe_text(row.get("createdDateTime") or "", limit=40),
            )
        return principals

    def _collect_auth_methods(self, principals: dict[str, Principal], state: IdentityState) -> None:
        """Fold the authentication-methods registration report into the principals.

        One paged report rather than a request per user. The per-user endpoint
        exists and is more detailed, but on a directory of any size it is tens of
        thousands of requests, and a monitoring tool that exhausts a tenant's
        Graph throttling budget every morning does not stay deployed.

        Phishing resistance is derived from ``methodsRegistered`` against the
        catalog, not from ``isPasswordlessCapable``. Those are different claims:
        Microsoft counts Authenticator passwordless phone sign-in as
        passwordless, and a push approval is relayed in real time by every
        off-the-shelf phishing proxy. Reading the flag as "phishing-resistant"
        silently cleared exactly the administrators the check exists to find.
        """
        try:
            rows, complete = self._pages(
                "reports/authenticationMethods/userRegistrationDetails",
                {"$top": self.config.page_size},
            )
        except _Forbidden:
            state.coverage["authentication_methods"] = Determination.UNKNOWN
            state.errors.append(
                "authentication method registration was refused — it needs "
                "UserAuthenticationMethod.Read.All; MFA posture is reported as indeterminate "
                "rather than absent"
            )
            return

        state.coverage["authentication_methods"] = (
            Determination.PRESENT if complete else Determination.UNKNOWN
        )
        if not complete:
            state.errors.append(
                "the authentication method report was truncated; MFA posture is reported as "
                "indeterminate for every account rather than absent for the ones not read"
            )
            return

        for row in rows:
            principal_id = safe_text(row.get("id") or "", limit=128)
            existing = principals.get(principal_id)
            if existing is None:
                continue
            registered = row.get("methodsRegistered")
            methods = (
                tuple(safe_text(m, limit=64) for m in registered if isinstance(m, str))[:20]
                if isinstance(registered, list)
                else ()
            )
            mfa_capable = row.get("isMfaCapable")
            principals[principal_id] = dataclasses.replace(
                existing,
                auth_methods=methods,
                second_factor=Determination.from_optional(
                    mfa_capable if isinstance(mfa_capable, bool) else None
                ),
                # A row without a method list says nothing about the account's
                # strongest method, so it stays UNKNOWN rather than reading as
                # "no phishing-resistant method registered".
                phishing_resistant=(
                    Determination.from_optional(any(is_phishing_resistant(m) for m in methods))
                    if isinstance(registered, list)
                    else Determination.UNKNOWN
                ),
            )

    def _collect_roles(self, principals: dict[str, Principal], state: IdentityState) -> None:
        try:
            roles, complete = self._pages("directoryRoles")
        except _Forbidden:
            state.coverage["role_assignments"] = Determination.UNKNOWN
            state.coverage["role_eligibility"] = Determination.UNKNOWN
            state.errors.append(
                "directory roles were refused — they need RoleManagement.Read.Directory; "
                "role assignments are reported as indeterminate"
            )
            return

        assignments: list[RoleAssignment] = []
        truncated = not complete
        # directoryRole.id is the role's object id in this tenant;
        # directoryRole.roleTemplateId is the id of the role *definition*, which
        # is what the eligibility endpoint keys on. They are different GUIDs, so
        # the eligibility join below has to use the second one.
        definition_by_role: dict[str, str] = {}
        for role in roles:
            role_id = safe_text(role.get("id") or "", limit=128)
            role_name = safe_text(role.get("displayName") or "", limit=200)
            if not role_id:
                continue
            definition_by_role[role_id] = safe_text(role.get("roleTemplateId") or "", limit=128) or role_id
            try:
                members, members_complete = self._pages(
                    f"directoryRoles/{role_id}/members", max_pages=_MAX_ROLE_MEMBER_PAGES
                )
            except _Forbidden:
                truncated = True
                continue
            truncated = truncated or not members_complete
            for member in members:
                principal_id = safe_text(member.get("id") or "", limit=128)
                if not principal_id:
                    continue
                known = principals.get(principal_id)
                odata_type = str(member.get("@odata.type") or "")
                assignments.append(
                    RoleAssignment(
                        assignment_id=f"{role_id}:{principal_id}",
                        role_id=role_id,
                        role_name=role_name,
                        principal_id=principal_id,
                        principal_display=(
                            known.display
                            if known is not None
                            else safe_text(member.get("displayName") or "", limit=200)
                        ),
                        principal_kind=(
                            known.kind
                            if known is not None
                            else PrincipalKind.parse(odata_type.rsplit(".", 1)[-1])
                        ),
                        scope="/",
                        # Membership of a directoryRole is by definition active
                        # right now. Whether it is *permanent* depends on the
                        # eligibility data fetched below.
                        standing=Determination.PRESENT,
                    )
                )

        eligible_keys = self._collect_eligibility(state)
        if eligible_keys is not None:
            assignments = [
                dataclasses.replace(a, standing=Determination.ABSENT)
                if f"{definition_by_role.get(a.role_id, a.role_id)}|{a.principal_id}" in eligible_keys
                else a
                for a in assignments
            ]

        state.role_assignments = assignments
        state.coverage["role_assignments"] = Determination.UNKNOWN if truncated else Determination.PRESENT
        if truncated:
            state.errors.append(
                "the role assignment walk was incomplete; assignments are reported as "
                "indeterminate so that unseen ones are not read as removed"
            )

    def _collect_eligibility(self, state: IdentityState) -> set[str] | None:
        """Return ``roleDefinition|principal`` keys that are eligible rather than permanent.

        ``None`` means we could not tell — which is the normal answer for a
        tenant without privileged identity management, and is why
        ``policy.expect_just_in_time`` is off by default. Returning an empty set
        there would report every administrator in the tenant as holding a
        standing assignment, which is true, unactionable, and the fastest way to
        get a report ignored.

        The key is the *role definition* id, which is what this endpoint
        returns. Joining it against ``directoryRole.id`` instead matches nothing
        in any tenant, and a join that never matches looks exactly like a tenant
        where nobody is eligible: every activated just-in-time assignment reads
        as permanent, which is the finding this data exists to suppress.
        """
        try:
            rows, complete = self._pages("roleManagement/directory/roleEligibilityScheduleInstances")
        except _Forbidden:
            state.coverage["role_eligibility"] = Determination.UNKNOWN
            return None
        if not complete:
            state.coverage["role_eligibility"] = Determination.UNKNOWN
            return None

        state.coverage["role_eligibility"] = Determination.PRESENT
        keys: set[str] = set()
        for row in rows:
            role_id = safe_text(row.get("roleDefinitionId") or "", limit=128)
            principal_id = safe_text(row.get("principalId") or "", limit=128)
            if role_id and principal_id:
                keys.add(f"{role_id}|{principal_id}")
        return keys

    def _collect_workloads(self, state: IdentityState) -> None:
        # appRoles is selected so the appRoleId GUIDs below can be turned back
        # into the permission names the rest of the tool reasons about. See
        # _app_role_values.
        select = (
            "id,appId,displayName,accountEnabled,appOwnerOrganizationId,"
            "passwordCredentials,keyCredentials,appRoles"
        )
        try:
            rows, complete = self._pages(
                "servicePrincipals", {"$select": select, "$top": self.config.page_size}
            )
        except _Forbidden:
            for facet in ("service_principals", "application_credentials", "application_permissions"):
                state.coverage[facet] = Determination.UNKNOWN
            state.errors.append(
                "service principals were refused — they need Application.Read.All; workload "
                "identity findings are reported as indeterminate"
            )
            return

        coverage = Determination.PRESENT if complete else Determination.UNKNOWN
        state.coverage["service_principals"] = coverage
        state.coverage["application_credentials"] = coverage

        workloads: list[Workload] = []
        permissions_complete = True
        unresolved_permissions = 0
        role_values = _app_role_values(rows)
        budget = self.config.max_detail_lookups
        for row in rows:
            workload_id = safe_text(row.get("id") or "", limit=128)
            if not workload_id:
                continue
            owner_org = row.get("appOwnerOrganizationId")
            credentials = tuple(
                Credential.from_raw(cred, kind="secret")
                for cred in (row.get("passwordCredentials") or [])
                if isinstance(cred, dict)
            ) + tuple(
                Credential.from_raw(cred, kind="certificate")
                for cred in (row.get("keyCredentials") or [])
                if isinstance(cred, dict)
            )

            permissions: tuple[PermissionGrant, ...] = ()
            if budget > 0:
                budget -= 1
                try:
                    grants, grants_complete = self._pages(
                        f"servicePrincipals/{workload_id}/appRoleAssignments", max_pages=20
                    )
                    permissions_complete = permissions_complete and grants_complete
                    granted: list[PermissionGrant] = []
                    for g in grants:
                        if not isinstance(g, dict) or not g.get("appRoleId"):
                            continue
                        role_id = safe_text(g.get("appRoleId") or "", limit=128)
                        # This endpoint names the permission by the GUID of the
                        # app role, not by its value. Everything downstream —
                        # the high-impact catalog, the mail and file scope
                        # lists, the sentence in the finding — matches on the
                        # value, so recording the GUID as the scope meant the
                        # scope matched nothing and no application permission
                        # was ever reported as high-impact against a real
                        # tenant. The lookup below turns it back into
                        # `Mail.Read`; an id that cannot be resolved is counted
                        # rather than quietly passed through as a scope name.
                        value = role_values.get(role_id)
                        if value is None:
                            unresolved_permissions += 1
                        granted.append(
                            PermissionGrant(
                                permission_id=role_id,
                                scope=value or role_id,
                                resource=safe_text(g.get("resourceDisplayName") or "", limit=200),
                                application=True,
                                granted_at=safe_text(g.get("createdDateTime") or "", limit=40),
                            )
                        )
                    permissions = tuple(granted)
                except _Forbidden:
                    permissions_complete = False
            else:
                permissions_complete = False

            workloads.append(
                Workload(
                    workload_id=workload_id,
                    display=safe_text(row.get("displayName") or "", limit=200),
                    app_id=safe_text(row.get("appId") or "", limit=128),
                    third_party=(
                        Determination.UNKNOWN
                        if not isinstance(owner_org, str) or not owner_org
                        else Determination.from_optional(owner_org != self.config.tenant_id)
                    ),
                    enabled=Determination.from_optional(
                        row["accountEnabled"] if isinstance(row.get("accountEnabled"), bool) else None
                    ),
                    credentials=credentials,
                    permissions=permissions,
                )
            )

        state.workloads = workloads
        if not permissions_complete:
            state.errors.append(
                "application permissions were not read for every service principal within "
                "source.entra.max_detail_lookups; they are reported as indeterminate"
            )
        if unresolved_permissions:
            # A permission we cannot name is a permission we cannot rate, and
            # "no high-impact permission found" would then be a claim about a
            # list we could not read. Say so instead.
            state.errors.append(
                f"{unresolved_permissions} application "
                f"{plural(unresolved_permissions, 'permission')} could not be resolved to a "
                "permission name because the resource application was not in the service "
                "principal list; they are reported as indeterminate rather than rated on their id"
            )
        state.coverage["application_permissions"] = (
            Determination.PRESENT
            if (complete and permissions_complete and not unresolved_permissions)
            else Determination.UNKNOWN
        )

    def _collect_grants(self, state: IdentityState) -> None:
        try:
            rows, complete = self._pages("oauth2PermissionGrants", {"$top": self.config.page_size})
        except _Forbidden:
            state.coverage["oauth_grants"] = Determination.UNKNOWN
            state.errors.append(
                "OAuth2 permission grants were refused; consent findings are reported as indeterminate"
            )
            return

        state.coverage["oauth_grants"] = Determination.PRESENT if complete else Determination.UNKNOWN
        by_id = {w.workload_id: w for w in state.workloads}
        grants: list[OAuthGrant] = []
        for row in rows:
            client_id = safe_text(row.get("clientId") or "", limit=128)
            if not client_id:
                continue
            client = by_id.get(client_id)
            scope_text = safe_text(row.get("scope") or "", limit=2000)
            grants.append(
                OAuthGrant(
                    grant_id=safe_text(row.get("id") or "", limit=128),
                    client_id=client_id,
                    client_display=client.display if client is not None else "",
                    resource=safe_text(row.get("resourceId") or "", limit=200),
                    scopes=tuple(sorted({s for s in scope_text.split() if s}))[:100],
                    tenant_wide=str(row.get("consentType") or "").strip().lower() == "allprincipals",
                    principal_id=safe_text(row.get("principalId") or "", limit=128),
                )
            )
        state.oauth_grants = grants

    def _collect_policies(self, state: IdentityState) -> None:
        try:
            rows, complete = self._pages("identity/conditionalAccess/policies")
        except _Forbidden:
            state.coverage["access_policies"] = Determination.UNKNOWN
            state.errors.append(
                "conditional access policies were refused — they need Policy.Read.All; "
                "policy findings are reported as indeterminate"
            )
            return

        state.coverage["access_policies"] = Determination.PRESENT if complete else Determination.UNKNOWN
        policies: list[AccessPolicy] = []
        for row in rows:
            policy_id = safe_text(row.get("id") or "", limit=128)
            if not policy_id:
                continue
            conditions = _dict(row.get("conditions"))
            users = _dict(conditions.get("users"))
            policies.append(
                AccessPolicy(
                    policy_id=policy_id,
                    display=safe_text(row.get("displayName") or "", limit=200),
                    state=_policy_state(row.get("state")),
                    excluded_users=_id_tuple(users.get("excludeUsers")),
                    excluded_groups=_id_tuple(users.get("excludeGroups")),
                    excluded_roles=_id_tuple(users.get("excludeRoles")),
                )
            )
        state.policies = policies


class _Forbidden(Exception):
    """Graph refused one endpoint. Handled locally as UNKNOWN coverage."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


def _app_role_values(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Map every published app role id in the tenant to its value.

    ``appRoleAssignments`` identifies a granted permission by the GUID of the
    app role, and the resource application publishes the id-to-value mapping on
    its own service principal — Microsoft Graph's service principal is where
    ``Mail.Read`` is defined. Both are in the list this walk already fetched, so
    the mapping is built from it rather than costing a request per grant.

    Built across every service principal rather than per resource: an app role
    id is a GUID minted by the publisher, so a collision between two resources
    is not a case worth handling, and a per-resource index would miss a grant
    whose ``resourceId`` did not come back.
    """
    values: dict[str, str] = {}
    for row in rows:
        for role in row.get("appRoles") or []:
            if not isinstance(role, dict):
                continue
            role_id = safe_text(role.get("id") or "", limit=128)
            value = safe_text(role.get("value") or "", limit=200)
            if role_id and value:
                values.setdefault(role_id, value)
    return values


def _policy_state(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "enabled":
        return "enabled"
    if text == "disabled":
        return "disabled"
    if text == "enabledforreportingbutnotenforced":
        return "report_only"
    return "unknown"


def _id_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({safe_text(item, limit=128) for item in value[:500] if isinstance(item, str)}))


def _dict(value: Any) -> dict[str, Any]:
    """Coerce an untrusted payload field to a mapping.

    A provider that returns ``null``, a string or a list where an object is
    documented must not be able to raise from the middle of a collection: the
    field is simply absent, and every ``.get`` below returns the default.
    """
    return value if isinstance(value, dict) else {}
