"""The seven checks, with the tri-state cases given as much space as the happy paths."""

from __future__ import annotations

from conftest import (
    assignment,
    credential,
    grant,
    issues,
    make_config,
    make_state,
    permission,
    policy,
    principal,
    run_check,
    workload,
)
from idpdrift.models import Determination, FindingKind, PrincipalKind, Severity
from idpdrift.severity import Issue, RoleTier


class TestPrivilegedRoles:
    def test_a_privileged_assignment_is_recorded_for_drift(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(principals=[principal()], role_assignments=[assignment()]),
        )
        assert result.observations["assignments"]
        assert result.observations["privileged_count"] == 1

    def test_a_standard_role_produces_no_posture_finding(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment(role_name="Reports Reader")]),
        )
        assert not result.findings
        assert result.observations["privileged_count"] == 0

    def test_standing_assignment_is_silent_without_expect_just_in_time(self) -> None:
        """Every assignment in a tenant without PIM is standing; saying so
        hundreds of times describes the product, not the tenant."""
        result = run_check("privileged_roles", make_state(role_assignments=[assignment()]))
        assert Issue.ROLE_ASSIGNMENT_STANDING.value not in issues(result)

    def test_standing_assignment_is_reported_when_expected_to_be_jit(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment()]),
            make_config(expect_just_in_time=True),
        )
        assert Issue.ROLE_ASSIGNMENT_STANDING.value in issues(result)

    def test_eligible_assignment_is_not_reported_as_standing(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment(standing=Determination.ABSENT)]),
            make_config(expect_just_in_time=True),
        )
        assert Issue.ROLE_ASSIGNMENT_STANDING.value not in issues(result)

    def test_unreadable_eligibility_reports_indeterminate_rather_than_standing(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(
                role_assignments=[assignment()],
                coverage={"role_eligibility": Determination.UNKNOWN},
            ),
            make_config(expect_just_in_time=True),
        )
        assert Issue.ROLE_ASSIGNMENT_STANDING.value not in issues(result)
        assert Issue.FACET_INDETERMINATE.value in issues(result)

    def test_service_principal_holding_a_role_is_reported(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(
                role_assignments=[assignment(kind=PrincipalKind.SERVICE_PRINCIPAL, display="Backup Runner")]
            ),
        )
        assert Issue.ROLE_ASSIGNMENT_NON_HUMAN.value in issues(result)

    def test_service_account_naming_convention_is_reported(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment(kind=PrincipalKind.UNKNOWN, display="svc-backup")]),
        )
        assert Issue.ROLE_ASSIGNMENT_NON_HUMAN.value in issues(result)

    def test_a_person_is_never_reported_as_non_human(self) -> None:
        """A naming convention does not get to overrule the directory."""
        result = run_check(
            "privileged_roles",
            make_state(
                role_assignments=[assignment(kind=PrincipalKind.USER, display="Service Delivery Sam")]
            ),
        )
        assert Issue.ROLE_ASSIGNMENT_NON_HUMAN.value not in issues(result)

    def test_unreadable_assignments_produce_no_observations(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(coverage={"role_assignments": Determination.UNKNOWN}),
        )
        assert result.partial is True
        assert not result.observations
        assert issues(result) == {Issue.FACET_INDETERMINATE.value}

    def test_ignored_principals_are_skipped(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment(kind=PrincipalKind.SERVICE_PRINCIPAL)]),
            make_config(ignore_principals=("u1",)),
        )
        assert not result.findings

    def test_custom_role_tier_from_policy_is_honoured(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(
                role_assignments=[
                    assignment(role_name="Break Glass Operator", kind=PrincipalKind.SERVICE_PRINCIPAL)
                ]
            ),
            make_config(privileged_roles={"break glass operator": RoleTier.TENANT_ADMIN}),
        )
        assert Issue.ROLE_ASSIGNMENT_NON_HUMAN.value in issues(result)
        assert max(f.severity for f in result.findings) is Severity.CRITICAL


class TestAuthStrength:
    def test_privileged_account_without_a_second_factor(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[
                    principal(second_factor=Determination.ABSENT, phishing_resistant=Determination.ABSENT)
                ],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.MFA_ABSENT.value in issues(result)

    def test_privileged_account_without_a_phishing_resistant_method(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[
                    principal(
                        phishing_resistant=Determination.ABSENT,
                        auth_methods=("microsoftAuthenticatorPush",),
                    )
                ],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.MFA_NOT_PHISHING_RESISTANT.value in issues(result)

    def test_sms_only_is_reported(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[principal(phishing_resistant=Determination.ABSENT, auth_methods=("sms",))]
            ),
        )
        assert Issue.MFA_WEAK_FACTOR_ONLY.value in issues(result)

    def test_a_strong_method_alongside_sms_is_not_weak_only(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(principals=[principal(auth_methods=("sms", "fido2SecurityKey"))]),
        )
        assert Issue.MFA_WEAK_FACTOR_ONLY.value not in issues(result)

    def test_ordinary_accounts_are_aggregated(self) -> None:
        principals = [
            principal(f"u{i}", display=f"User {i}", second_factor=Determination.ABSENT) for i in range(40)
        ]
        result = run_check("auth_strength", make_state(principals=principals))
        absent = [f for f in result.findings if f.issue == Issue.MFA_ABSENT.value]
        assert len(absent) == 1
        assert absent[0].evidence["total"] == 40
        assert len(absent[0].evidence["accounts"]) == 10

    def test_unreadable_methods_report_nothing_about_mfa(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[principal(second_factor=Determination.ABSENT)],
                coverage={"authentication_methods": Determination.UNKNOWN},
            ),
        )
        assert issues(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial is True

    def test_an_account_with_no_method_data_is_counted_not_reported(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[
                    principal(second_factor=Determination.UNKNOWN, phishing_resistant=Determination.UNKNOWN)
                ]
            ),
        )
        assert Issue.MFA_ABSENT.value not in issues(result)
        assert result.observations["indeterminate_total"] == 1

    def test_service_principals_are_not_expected_to_have_mfa(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[
                    principal(kind=PrincipalKind.SERVICE_PRINCIPAL, second_factor=Determination.ABSENT)
                ]
            ),
        )
        assert not result.findings

    def test_only_privileged_accounts_are_baselined(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(
                principals=[principal("u1"), principal("u2", display="Bob")],
                role_assignments=[assignment("u1")],
            ),
        )
        assert list(result.observations["accounts"]) == ["Alice Admin"]


class TestDormancy:
    def test_dormant_privileged_account(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(last_sign_in="2025-01-01T00:00:00Z")],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DORMANT_WITH_ROLE.value in issues(result)

    def test_recent_sign_in_is_not_dormant(self) -> None:
        result = run_check(
            "dormancy",
            make_state(principals=[principal()], role_assignments=[assignment()]),
        )
        assert Issue.DORMANT_WITH_ROLE.value not in issues(result)

    def test_disabled_account_holding_a_role(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(enabled=Determination.ABSENT)],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DISABLED_WITH_ROLE.value in issues(result)

    def test_unknown_enabled_state_is_not_reported_as_disabled(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(enabled=Determination.UNKNOWN)],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DISABLED_WITH_ROLE.value not in issues(result)

    def test_unreadable_sign_in_activity_reports_nothing_dormant(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(last_sign_in="2020-01-01T00:00:00Z")],
                role_assignments=[assignment()],
                coverage={"sign_in_activity": Determination.UNKNOWN},
            ),
        )
        assert Issue.DORMANT_WITH_ROLE.value not in issues(result)
        assert Issue.FACET_INDETERMINATE.value in issues(result)

    def test_disabled_finding_survives_unreadable_sign_in_activity(self) -> None:
        """Different facet, different answer: `enabled` is still readable."""
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(enabled=Determination.ABSENT)],
                role_assignments=[assignment()],
                coverage={"sign_in_activity": Determination.UNKNOWN},
            ),
        )
        assert Issue.DISABLED_WITH_ROLE.value in issues(result)

    def test_never_signed_in_ages_from_creation(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[
                    principal(
                        last_sign_in="",
                        sign_in_known=Determination.ABSENT,
                        created_at="2019-01-01T00:00:00Z",
                    )
                ],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DORMANT_WITH_ROLE.value in issues(result)

    def test_a_brand_new_account_that_has_not_signed_in_is_not_dormant(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[
                    principal(
                        last_sign_in="",
                        sign_in_known=Determination.ABSENT,
                        created_at="2026-08-09T00:00:00Z",
                    )
                ],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DORMANT_WITH_ROLE.value not in issues(result)

    def test_unparseable_timestamp_is_excluded_rather_than_treated_as_epoch(self) -> None:
        result = run_check(
            "dormancy",
            make_state(
                principals=[principal(last_sign_in="last tuesday")],
                role_assignments=[assignment()],
            ),
        )
        assert Issue.DORMANT_WITH_ROLE.value not in issues(result)
        assert Issue.FACET_INDETERMINATE.value in issues(result)

    def test_dormant_ordinary_accounts_are_aggregated(self) -> None:
        principals = [
            principal(f"u{i}", display=f"User {i}", last_sign_in="2024-01-01T00:00:00Z") for i in range(5)
        ]
        result = run_check("dormancy", make_state(principals=principals))
        aggregate = [f for f in result.findings if f.issue == Issue.DORMANT_WITH_ACCESS.value]
        assert len(aggregate) == 1
        assert aggregate[0].evidence["total"] == 5

    def test_dormant_with_no_access_is_not_a_security_finding(self) -> None:
        result = run_check(
            "dormancy",
            make_state(principals=[principal(last_sign_in="2024-01-01T00:00:00Z", group_count=0)]),
        )
        assert Issue.DORMANT_WITH_ACCESS.value not in issues(result)


class TestServicePrincipals:
    def test_expiring_credential(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(credentials=(credential(expires_at="2026-08-20T00:00:00Z"),))]),
        )
        assert Issue.CREDENTIAL_EXPIRING.value in issues(result)

    def test_expired_credential_reads_as_expired(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(credentials=(credential(expires_at="2026-01-01T00:00:00Z"),))]),
        )
        titles = [f.title for f in result.findings if f.issue == Issue.CREDENTIAL_EXPIRING.value]
        assert titles and "ago" in titles[0]

    def test_excessive_lifetime(self) -> None:
        result = run_check(
            "service_principals",
            make_state(
                workloads=[
                    workload(
                        credentials=(
                            credential(starts_at="2026-01-01T00:00:00Z", expires_at="2029-01-01T00:00:00Z"),
                        )
                    )
                ]
            ),
        )
        assert Issue.CREDENTIAL_LONG_LIVED.value in issues(result)

    def test_secret_rather_than_certificate(self) -> None:
        result = run_check(
            "service_principals", make_state(workloads=[workload(credentials=(credential(),))])
        )
        assert Issue.CREDENTIAL_SECRET_NOT_CERTIFICATE.value in issues(result)

    def test_certificate_only_is_not_reported(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(credentials=(credential(kind="certificate"),))]),
        )
        assert Issue.CREDENTIAL_SECRET_NOT_CERTIFICATE.value not in issues(result)

    def test_high_impact_application_permission(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(permissions=(permission("Mail.Read"),))]),
        )
        finding = next(f for f in result.findings if f.issue == Issue.APP_PERMISSION_HIGH_IMPACT.value)
        assert finding.severity is Severity.CRITICAL
        assert "every mailbox" in finding.detail

    def test_delegated_permission_is_not_the_same_finding(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(permissions=(permission("Mail.Read", application=False),))]),
        )
        assert Issue.APP_PERMISSION_HIGH_IMPACT.value not in issues(result)

    def test_unlisted_scope_is_not_reported(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(permissions=(permission("User.Read"),))]),
        )
        assert Issue.APP_PERMISSION_HIGH_IMPACT.value not in issues(result)

    def test_unreadable_credentials_report_indeterminate(self) -> None:
        result = run_check(
            "service_principals",
            make_state(
                workloads=[workload(credentials=(credential(),))],
                coverage={"application_credentials": Determination.UNKNOWN},
            ),
        )
        assert Issue.CREDENTIAL_SECRET_NOT_CERTIFICATE.value not in issues(result)
        assert Issue.FACET_INDETERMINATE.value in issues(result)
        assert result.partial is True

    def test_unreadable_workloads_stop_the_check(self) -> None:
        result = run_check(
            "service_principals",
            make_state(coverage={"service_principals": Determination.UNKNOWN}),
        )
        assert not result.observations
        assert result.partial is True

    def test_ignored_applications_are_skipped(self) -> None:
        result = run_check(
            "service_principals",
            make_state(workloads=[workload(credentials=(credential(),))]),
            make_config(ignore_applications=("app 1",)),
        )
        assert not result.findings


class TestOAuthGrants:
    def test_tenant_wide_consent(self) -> None:
        result = run_check("oauth_grants", make_state(oauth_grants=[grant(tenant_wide=True)]))
        assert Issue.OAUTH_TENANT_WIDE.value in issues(result)

    def test_mail_scope(self) -> None:
        result = run_check("oauth_grants", make_state(oauth_grants=[grant(scopes=("Mail.Read",))]))
        assert Issue.OAUTH_SENSITIVE_SCOPE.value in issues(result)

    def test_file_scope(self) -> None:
        result = run_check("oauth_grants", make_state(oauth_grants=[grant(scopes=("Files.ReadWrite.All",))]))
        assert Issue.OAUTH_SENSITIVE_SCOPE.value in issues(result)

    def test_third_party_application(self) -> None:
        result = run_check(
            "oauth_grants",
            make_state(
                oauth_grants=[grant(scopes=("User.Read",))],
                workloads=[workload(third_party=Determination.PRESENT)],
            ),
        )
        assert Issue.OAUTH_THIRD_PARTY.value in issues(result)

    def test_first_party_application_is_not_reported_as_third_party(self) -> None:
        result = run_check(
            "oauth_grants",
            make_state(
                oauth_grants=[grant(scopes=("User.Read",))],
                workloads=[workload(third_party=Determination.ABSENT)],
            ),
        )
        assert Issue.OAUTH_THIRD_PARTY.value not in issues(result)

    def test_unknown_origin_is_not_reported_as_third_party(self) -> None:
        result = run_check(
            "oauth_grants",
            make_state(
                oauth_grants=[grant(scopes=("User.Read",))],
                workloads=[workload(third_party=Determination.UNKNOWN)],
            ),
        )
        assert Issue.OAUTH_THIRD_PARTY.value not in issues(result)

    def test_approved_applications_are_skipped(self) -> None:
        result = run_check(
            "oauth_grants",
            make_state(oauth_grants=[grant(tenant_wide=True)]),
            make_config(approved_applications=("sp1",)),
        )
        assert not result.findings

    def test_unreadable_grants_stop_the_check(self) -> None:
        result = run_check(
            "oauth_grants",
            make_state(
                oauth_grants=[grant(tenant_wide=True)],
                coverage={"oauth_grants": Determination.UNKNOWN},
            ),
        )
        assert issues(result) == {Issue.FACET_INDETERMINATE.value}


class TestGuests:
    def test_guest_holding_a_role(self) -> None:
        result = run_check(
            "guests",
            make_state(
                principals=[principal("g1", kind=PrincipalKind.GUEST, display="Partner Pat")],
                role_assignments=[assignment("g1", display="Partner Pat")],
            ),
        )
        assert Issue.GUEST_WITH_ROLE.value in issues(result)

    def test_allowance_can_permit_a_role(self) -> None:
        result = run_check(
            "guests",
            make_state(
                principals=[principal("g1", kind=PrincipalKind.GUEST)],
                role_assignments=[assignment("g1")],
            ),
            make_config(guest_role_allowance=1),
        )
        assert Issue.GUEST_WITH_ROLE.value not in issues(result)

    def test_group_allowance_is_enforced(self) -> None:
        result = run_check(
            "guests",
            make_state(principals=[principal("g1", kind=PrincipalKind.GUEST, group_count=12)]),
        )
        assert Issue.GUEST_OVER_ALLOWANCE.value in issues(result)

    def test_a_provider_that_does_not_mark_guests_concludes_nothing(self) -> None:
        result = run_check(
            "guests",
            make_state(
                principals=[principal("u1")],
                coverage={"guest_status": Determination.UNKNOWN},
            ),
        )
        assert issues(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial is True

    def test_an_org_with_no_guests_is_clean_when_guest_status_is_readable(self) -> None:
        result = run_check("guests", make_state(principals=[principal("u1")]))
        assert not result.findings

    def test_unreadable_group_counts_do_not_produce_an_allowance_finding(self) -> None:
        result = run_check(
            "guests",
            make_state(
                principals=[principal("g1", kind=PrincipalKind.GUEST, group_count=99)],
                coverage={"group_membership": Determination.UNKNOWN},
            ),
        )
        assert Issue.GUEST_OVER_ALLOWANCE.value not in issues(result)
        assert Issue.FACET_INDETERMINATE.value in issues(result)


class TestConditionalAccess:
    def test_disabled_policy(self) -> None:
        result = run_check("conditional_access", make_state(policies=[policy(state="disabled")]))
        assert Issue.POLICY_DISABLED.value in issues(result)

    def test_report_only_policy(self) -> None:
        result = run_check("conditional_access", make_state(policies=[policy(state="report_only")]))
        assert Issue.POLICY_REPORT_ONLY.value in issues(result)

    def test_enabled_policy_is_clean(self) -> None:
        result = run_check("conditional_access", make_state(policies=[policy()]))
        assert not result.findings

    def test_existing_exclusions_are_recorded_but_not_reported(self) -> None:
        """Every real tenant excludes a break-glass account from something."""
        result = run_check(
            "conditional_access",
            make_state(policies=[policy(excluded_users=("u9",))]),
        )
        assert not result.findings
        assert result.observations["policies"]["cap1"]["exclusions"] == ["u9"]

    def test_no_enforcing_policy_at_all(self) -> None:
        result = run_check(
            "conditional_access",
            make_state(policies=[policy(state="disabled"), policy("cap2", state="report_only")]),
        )
        assert Issue.POLICY_WEAKENED.value in issues(result)

    def test_unreadable_policies_stop_the_check(self) -> None:
        result = run_check(
            "conditional_access",
            make_state(
                policies=[policy(state="disabled")],
                coverage={"access_policies": Determination.UNKNOWN},
            ),
        )
        assert issues(result) == {Issue.FACET_INDETERMINATE.value}


class TestIndeterminateFindingShape:
    def test_indeterminate_findings_are_operational_and_capped(self) -> None:
        result = run_check(
            "auth_strength",
            make_state(coverage={"authentication_methods": Determination.UNKNOWN}),
        )
        finding = result.findings[0]
        assert finding.kind is FindingKind.OPERATIONAL
        assert finding.determination is Determination.UNKNOWN
        assert finding.severity <= Severity.LOW

    def test_indeterminate_findings_say_what_was_not_concluded(self) -> None:
        result = run_check("dormancy", make_state(coverage={"sign_in_activity": Determination.UNKNOWN}))
        finding = next(f for f in result.findings if f.determination.is_unknown)
        assert "not the same as no sign-in" in finding.detail

    def test_every_finding_carries_its_severity_derivation(self) -> None:
        result = run_check(
            "privileged_roles",
            make_state(role_assignments=[assignment(kind=PrincipalKind.SERVICE_PRINCIPAL)]),
        )
        assert all("severity_basis" in f.evidence for f in result.findings)
