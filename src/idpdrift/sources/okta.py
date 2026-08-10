"""Read-only client for an Okta org.

Reads users, their enrolled factors, their administrator roles, application
integrations and their grants, and sign-on policies. Every request is a GET with
an ``SSWS`` token; nothing here creates, updates or deletes.

Okta's API shape forces two honest admissions, and both are expressed as UNKNOWN
coverage rather than papered over:

**Roles and factors are per-user endpoints.** There is no org-wide listing of
"who holds which administrator role" that is available on every plan, so this
walks users individually up to ``source.okta.max_detail_lookups``. If the walk
does not cover every user, the facet is recorded as indeterminate — because
"the first two thousand users hold no admin role" says nothing about user two
thousand and one, and treating it as complete would report every administrator
past the cap as newly *removed* on the following run.

**Credential expiry is not exposed for most integrations.** Okta reports that an
OAuth client has a secret, not when that secret expires. Reporting "expires in
0 days" would be a fabrication and reporting nothing would look like a clean
result, so ``application_credentials`` is recorded as indeterminate and the
service-principal check says so in the report.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import Any
from urllib.parse import urlencode

from ..catalog import is_phishing_resistant
from ..config import OktaSourceConfig
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

_MAX_PAGES = 2000
_LINK_NEXT_RE = re.compile(r'<([^>]+)>\s*;\s*rel="next"')

# Okta statuses that mean an administrator has taken the account out of service.
#
# LOCKED_OUT is deliberately not one of them, though it was. A lockout is what
# happens when somebody mistypes their password too many times: it clears on
# unlock, or on the org's automatic expiry, often within the hour. Reading it as
# "disabled" produced a `disabled_with_role` finding — with leaver-process
# remediation — against an administrator who was sitting at their desk, and by
# the time anybody looked the account was signing in normally again.
# PASSWORD_EXPIRED and RECOVERY are transient in the same way and are treated
# the same.
_INACTIVE_STATUSES = frozenset({"DEPROVISIONED", "SUSPENDED"})


class OktaSource:
    """Collects identity state from an Okta org."""

    name = "okta"

    def __init__(
        self,
        config: OktaSourceConfig,
        *,
        timeout: float = 30.0,
        user_agent: str = "idpdrift",
        max_identities: int = 100000,
    ) -> None:
        self.config = config
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_identities = max_identities

    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        token = self.config.api_token()
        if not token:
            raise SourceError(f"no Okta API token: set the {self.config.api_token_env} environment variable")
        return {"Authorization": f"SSWS {token}"}

    def _request(self, url: str) -> tuple[Any, str | None]:
        try:
            response = safe_request(
                "GET",
                url,
                timeout=self.timeout,
                headers=self._headers(),
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Okta request failed: {exc}") from exc

        if response.status_code in (401, 403, 404):
            raise _Refused(response.status_code)
        if response.status_code != 200:
            raise SourceError(f"Okta returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError(f"Okta returned a non-JSON response: {exc}") from exc

        # Okta paginates with a Link header rather than a body field. The URL it
        # supplies goes through the same guard as every other request — a
        # provider that starts handing back a link to somewhere else does not get
        # to take the API token with it.
        next_url = None
        link = response.headers.get("link")
        if link:
            match = _LINK_NEXT_RE.search(link)
            if match:
                next_url = match.group(1)
        return payload, next_url

    def _pages(self, path: str, params: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], bool]:
        query = "?" + urlencode({k: v for k, v in (params or {}).items() if v is not None}) if params else ""
        url = f"{self.config.org_url}/{path.lstrip('/')}{query}"
        rows: list[dict[str, Any]] = []
        pages = 0
        while True:
            payload, next_url = self._request(url)
            pages += 1
            if isinstance(payload, list):
                rows.extend(item for item in payload if isinstance(item, dict))
            elif isinstance(payload, dict):
                rows.append(payload)
            if len(rows) >= self.max_identities:
                return rows[: self.max_identities], False
            if not next_url:
                return rows, True
            if pages >= _MAX_PAGES:
                return rows, False
            url = next_url

    # ------------------------------------------------------------------

    def collect(self) -> IdentityState:
        state = IdentityState(
            collected_at=IdentityState.now_iso(),
            source=self.name,
            tenant=self.config.org_url.split("://", 1)[-1],
        )

        principals = self._collect_users(state)
        self._collect_factors_and_roles(principals, state)
        state.principals = list(principals.values())
        self._collect_apps(state)
        self._collect_policies(state)

        # Okta has no first-class equivalent of a directory-wide group
        # membership count on the user object; obtaining it is another per-user
        # walk and is not worth a second request budget.
        state.coverage.setdefault("group_membership", Determination.UNKNOWN)
        # Okta records external collaborators as ordinary users. An org with no
        # guests and an org whose provider does not mark them look identical from
        # here, and only one of those is good news, so neither is asserted.
        state.coverage["guest_status"] = Determination.UNKNOWN
        return state

    def _collect_users(self, state: IdentityState) -> dict[str, Principal]:
        try:
            rows, complete = self._pages("api/v1/users", {"limit": self.config.page_size})
        except _Refused as exc:
            raise SourceError(
                "Okta refused the user list; the API token needs at least read-only administrator scope"
            ) from exc

        state.coverage["principals"] = Determination.PRESENT if complete else Determination.UNKNOWN
        state.coverage["sign_in_activity"] = Determination.PRESENT if complete else Determination.UNKNOWN
        if not complete:
            state.errors.append(
                "the Okta user list was truncated; every facet derived from it is reported as "
                "indeterminate rather than short"
            )

        principals: dict[str, Principal] = {}
        for row in rows:
            principal_id = safe_text(row.get("id") or "", limit=128)
            if not principal_id:
                continue
            profile = _dict(row.get("profile"))
            status = str(row.get("status") or "").strip().upper()
            last_login = safe_text(row.get("lastLogin") or "", limit=40)
            display = safe_text(
                profile.get("displayName")
                or " ".join(x for x in (profile.get("firstName"), profile.get("lastName")) if x)
                or profile.get("login")
                or "",
                limit=200,
            )
            principals[principal_id] = Principal(
                principal_id=principal_id,
                display=display,
                upn=safe_text(profile.get("login") or profile.get("email") or "", limit=254),
                # Okta records external collaborators as ordinary users. Guest
                # status is a directory fact this API does not carry, so it is
                # not invented here — the guests check reports it as
                # indeterminate rather than concluding an org has no guests.
                kind=PrincipalKind.USER,
                enabled=Determination.from_optional(status not in _INACTIVE_STATUSES)
                if status
                else Determination.UNKNOWN,
                last_sign_in=last_login,
                sign_in_known=(
                    Determination.UNKNOWN
                    if not complete
                    else (Determination.PRESENT if last_login else Determination.ABSENT)
                ),
                created_at=safe_text(row.get("created") or "", limit=40),
            )
        return principals

    def _collect_factors_and_roles(self, principals: dict[str, Principal], state: IdentityState) -> None:
        """Walk per-user factor and role endpoints, within the lookup budget."""
        budget = self.config.max_detail_lookups
        covered = 0
        assignments: list[RoleAssignment] = []
        refused = False

        for principal_id, principal in list(principals.items()):
            if budget <= 0:
                break
            budget -= 1
            covered += 1

            methods: tuple[str, ...] = ()
            try:
                factor_rows, _ = self._pages(f"api/v1/users/{principal_id}/factors")
                methods = tuple(
                    sorted(
                        {
                            safe_text(f.get("factorType") or "", limit=64)
                            for f in factor_rows
                            if isinstance(f, dict) and str(f.get("status") or "").upper() in ("ACTIVE", "")
                        }
                        - {""}
                    )
                )[:20]
                principals[principal_id] = dataclasses.replace(
                    principal,
                    auth_methods=methods,
                    second_factor=Determination.from_optional(bool(methods)),
                    phishing_resistant=Determination.from_optional(
                        any(is_phishing_resistant(m) for m in methods)
                    ),
                )
            except _Refused:
                refused = True

            try:
                role_rows, _ = self._pages(f"api/v1/users/{principal_id}/roles")
            except _Refused:
                refused = True
                continue
            for role in role_rows:
                role_type = safe_text(role.get("type") or "", limit=128)
                label = safe_text(role.get("label") or role_type, limit=200)
                if not label:
                    continue
                assignments.append(
                    RoleAssignment(
                        assignment_id=safe_text(role.get("id") or f"{principal_id}:{role_type}", limit=128),
                        role_id=role_type,
                        role_name=label,
                        principal_id=principal_id,
                        principal_display=principal.display,
                        principal_kind=principal.kind,
                        scope=safe_text(role.get("resource-set") or "/", limit=200),
                        # Okta administrator roles are permanent once granted;
                        # there is no activation step to observe.
                        standing=Determination.PRESENT,
                        assigned_at=safe_text(role.get("created") or "", limit=40),
                    )
                )

        complete = covered >= len(principals) and not refused
        state.role_assignments = assignments
        state.coverage["role_assignments"] = Determination.PRESENT if complete else Determination.UNKNOWN
        state.coverage["authentication_methods"] = (
            Determination.PRESENT if complete else Determination.UNKNOWN
        )
        # Okta grants an administrator role outright; there is no eligibility
        # concept to read, so the answer is "cannot tell", never "no".
        state.coverage["role_eligibility"] = Determination.UNKNOWN

        if not complete:
            state.errors.append(
                f"role and factor detail was read for {covered} of {len(principals)} "
                f"{plural(len(principals), 'account')} within source.okta.max_detail_lookups; "
                "both facets are reported as indeterminate so that unread accounts are not "
                "treated as having neither"
            )

    def _collect_apps(self, state: IdentityState) -> None:
        try:
            rows, complete = self._pages("api/v1/apps", {"limit": self.config.page_size})
        except _Refused:
            for facet in (
                "service_principals",
                "application_credentials",
                "application_permissions",
                "oauth_grants",
            ):
                state.coverage[facet] = Determination.UNKNOWN
            state.errors.append(
                "Okta refused the application list; workload identity findings are reported as indeterminate"
            )
            return

        state.coverage["service_principals"] = Determination.PRESENT if complete else Determination.UNKNOWN
        # See the module docstring: Okta reports that a secret exists, not when
        # it expires, so expiry-based findings cannot be produced honestly.
        state.coverage["application_credentials"] = Determination.UNKNOWN
        state.errors.append(
            "Okta does not expose credential expiry for application integrations; credential "
            "lifetime findings are reported as indeterminate rather than as clean"
        )

        workloads: list[Workload] = []
        grants: list[OAuthGrant] = []
        budget = self.config.max_detail_lookups
        grants_complete = complete

        for row in rows:
            app_id = safe_text(row.get("id") or "", limit=128)
            if not app_id:
                continue
            credentials = _credentials_from_app(row)
            scopes: list[PermissionGrant] = []

            if budget > 0:
                budget -= 1
                try:
                    grant_rows, _ = self._pages(f"api/v1/apps/{app_id}/grants")
                except _Refused:
                    grants_complete = False
                    grant_rows = []
                for grant in grant_rows:
                    scope_id = safe_text(grant.get("scopeId") or "", limit=200)
                    if not scope_id:
                        continue
                    scopes.append(
                        PermissionGrant(
                            permission_id=safe_text(grant.get("id") or "", limit=128),
                            scope=scope_id,
                            resource=safe_text(grant.get("issuer") or "", limit=200),
                            # An Okta app grant is org-wide by construction: it
                            # authorises the integration itself, with no user in
                            # the loop.
                            application=True,
                            granted_at=safe_text(grant.get("created") or "", limit=40),
                        )
                    )
                    grants.append(
                        OAuthGrant(
                            grant_id=safe_text(grant.get("id") or "", limit=128),
                            client_id=app_id,
                            client_display=safe_text(row.get("label") or "", limit=200),
                            resource=safe_text(grant.get("issuer") or "", limit=200),
                            scopes=(scope_id,),
                            tenant_wide=True,
                        )
                    )
            else:
                grants_complete = False

            workloads.append(
                Workload(
                    workload_id=app_id,
                    display=safe_text(row.get("label") or "", limit=200),
                    app_id=safe_text(row.get("name") or "", limit=128),
                    # "Is this a third-party integration" is not a field Okta
                    # returns; the catalogue name is a hint and not a fact.
                    third_party=Determination.UNKNOWN,
                    enabled=Determination.from_optional(
                        str(row.get("status") or "").strip().upper() == "ACTIVE"
                    ),
                    credentials=credentials,
                    permissions=tuple(scopes),
                )
            )

        state.workloads = workloads
        state.oauth_grants = grants
        coverage = Determination.PRESENT if grants_complete else Determination.UNKNOWN
        state.coverage["application_permissions"] = coverage
        state.coverage["oauth_grants"] = coverage
        if not grants_complete:
            state.errors.append(
                "application grants were not read for every integration within "
                "source.okta.max_detail_lookups; consent findings are reported as indeterminate"
            )

    def _collect_policies(self, state: IdentityState) -> None:
        try:
            rows, complete = self._pages("api/v1/policies", {"type": "OKTA_SIGN_ON"})
        except _Refused:
            state.coverage["access_policies"] = Determination.UNKNOWN
            state.errors.append(
                "Okta refused the sign-on policy list; policy findings are reported as indeterminate"
            )
            return

        policies: list[AccessPolicy] = []
        rules_complete = complete
        budget = self.config.max_detail_lookups
        for row in rows:
            policy_id = safe_text(row.get("id") or "", limit=128)
            if not policy_id:
                continue
            excluded_users: set[str] = set()
            excluded_groups: set[str] = set()
            if budget > 0:
                budget -= 1
                try:
                    rules, _ = self._pages(f"api/v1/policies/{policy_id}/rules")
                except _Refused:
                    rules_complete = False
                    rules = []
                for rule in rules:
                    conditions = _dict(rule.get("conditions"))
                    people = _dict(conditions.get("people"))
                    excluded_users |= _excluded(people.get("users"))
                    excluded_groups |= _excluded(people.get("groups"))
            else:
                rules_complete = False

            policies.append(
                AccessPolicy(
                    policy_id=policy_id,
                    display=safe_text(row.get("name") or "", limit=200),
                    state="enabled" if str(row.get("status") or "").upper() == "ACTIVE" else "disabled",
                    excluded_users=tuple(sorted(excluded_users)),
                    excluded_groups=tuple(sorted(excluded_groups)),
                )
            )

        state.policies = policies
        state.coverage["access_policies"] = Determination.PRESENT if rules_complete else Determination.UNKNOWN
        if not rules_complete:
            state.errors.append(
                "policy rules were not read for every policy; exclusions are reported as indeterminate"
            )


class _Refused(Exception):
    """Okta refused one endpoint. Handled locally as UNKNOWN coverage."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


def _credentials_from_app(row: dict[str, Any]) -> tuple[Credential, ...]:
    """Record that an integration holds a client secret, without the secret.

    Okta returns ``client_secret`` inline on this endpoint for OAuth
    integrations. It is dropped here rather than at a renderer, which is the
    whole argument for redacting at the construction boundary: nothing
    downstream can leak a value the object never held.
    """
    credentials = _dict(row.get("credentials"))
    oauth_client = _dict(credentials.get("oauthClient"))
    out: list[Credential] = []
    if oauth_client.get("client_secret") or str(
        oauth_client.get("token_endpoint_auth_method") or ""
    ).lower() in (
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
    ):
        out.append(
            Credential(
                credential_id=safe_text(oauth_client.get("client_id") or row.get("id") or "", limit=64),
                kind="secret",
                display="OAuth client secret",
            )
        )
    if str(oauth_client.get("token_endpoint_auth_method") or "").lower() == "private_key_jwt":
        out.append(
            Credential(
                credential_id=safe_text(oauth_client.get("client_id") or row.get("id") or "", limit=64),
                kind="certificate",
                display="private_key_jwt",
            )
        )
    return tuple(out)


def _excluded(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    exclude = value.get("exclude")
    if not isinstance(exclude, list):
        return set()
    return {safe_text(item, limit=128) for item in exclude[:500] if isinstance(item, str) and item}


def _dict(value: Any) -> dict[str, Any]:
    """Coerce an untrusted payload field to a mapping.

    A provider that returns ``null``, a string or a list where an object is
    documented must not be able to raise from the middle of a collection: the
    field is simply absent, and every ``.get`` below returns the default.
    """
    return value if isinstance(value, dict) else {}
