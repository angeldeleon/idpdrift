"""Snapshot diffing.

The recurring theme: a transition needs a determinate answer on *both* sides.
Half of these tests exist to prove that a run where a facet could not be read
does not manufacture a directory's worth of change.
"""

from __future__ import annotations

from typing import Any

import pytest

from idpdrift.drift import BULK_THRESHOLD, MAX_DRIFT_FINDINGS, diff_snapshots, registered_rules
from idpdrift.models import FindingKind, Severity, Snapshot
from idpdrift.severity import Issue


def snapshot(checks: dict[str, Any], *, tenant: str = "corp.example") -> Snapshot:
    return Snapshot(tenant=tenant, collected_at="2026-08-10T00:00:00+00:00", checks=checks)


def entry(
    role: str = "Global Administrator",
    *,
    tier: str = "tenant_admin",
    principal: str = "id-aaa",
    standing: str = "present",
) -> dict[str, Any]:
    return {"role": role, "tier": tier, "principal": principal, "standing": standing, "kind": "user"}


def issues(findings: list) -> set[str]:
    return {f.issue for f in findings}


class TestNoBaseline:
    def test_a_first_run_produces_no_drift(self) -> None:
        assert diff_snapshots(None, snapshot({"privileged_roles": {"assignments": {}}})) == []

    def test_a_check_absent_from_the_baseline_is_not_drift(self) -> None:
        findings = diff_snapshots(
            snapshot({}), snapshot({"privileged_roles": {"assignments": {"k": entry()}}})
        )
        assert findings == []

    def test_a_malformed_baseline_is_skipped_not_fatal(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": "corrupt"}),  # type: ignore[dict-item]
            snapshot({"privileged_roles": {"assignments": {"k": entry()}}}),
        )
        assert findings == []


class TestRoleDrift:
    def test_new_assignment(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {}}}),
            snapshot({"privileged_roles": {"assignments": {"k": entry()}}}),
        )
        assert [f.issue for f in findings] == [Issue.ROLE_ASSIGNMENT_NEW.value]
        assert findings[0].kind is FindingKind.DRIFT
        assert findings[0].severity is Severity.CRITICAL

    def test_removed_assignment_is_informational(self) -> None:
        """A removal is remediation. The tenant-admin tier still raises it one
        band, which is the table doing what it says — and LOW is far below any
        sane fail_on, so it records the change without waking anyone."""
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {"k": entry()}}}),
            snapshot({"privileged_roles": {"assignments": {}}}),
        )
        assert findings[0].issue == Issue.ROLE_ASSIGNMENT_REMOVED.value
        assert findings[0].severity < Severity.MEDIUM

    def test_removal_of_an_ordinary_role_is_info(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {"k": entry(tier="privileged")}}}),
            snapshot({"privileged_roles": {"assignments": {}}}),
        )
        assert findings[0].severity is Severity.INFO

    def test_unchanged_assignment_is_silent(self) -> None:
        both = {"privileged_roles": {"assignments": {"k": entry()}}}
        assert diff_snapshots(snapshot(both), snapshot(both)) == []

    def test_eligible_becoming_standing(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="absent")}}}),
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="present")}}}),
        )
        assert Issue.ROLE_ASSIGNMENT_ELEVATED.value in issues(findings)

    def test_unknown_standing_is_not_an_elevation(self) -> None:
        """An eligibility lookup that failed must not read as every just-in-time
        assignment becoming permanent overnight."""
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="unknown")}}}),
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="present")}}}),
        )
        assert Issue.ROLE_ASSIGNMENT_ELEVATED.value not in issues(findings)

    def test_standing_becoming_eligible_is_not_reported(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="present")}}}),
            snapshot({"privileged_roles": {"assignments": {"k": entry(standing="absent")}}}),
        )
        assert Issue.ROLE_ASSIGNMENT_ELEVATED.value not in issues(findings)

    def test_a_bulk_change_aggregates(self) -> None:
        after = {f"k{i}": entry(principal=f"id-{i}") for i in range(BULK_THRESHOLD + 5)}
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {}}}),
            snapshot({"privileged_roles": {"assignments": after}}),
        )
        assert len(findings) == 1
        assert findings[0].evidence["total"] == BULK_THRESHOLD + 5
        assert len(findings[0].evidence["changes"]) == 10

    def test_tier_drives_the_band(self) -> None:
        findings = diff_snapshots(
            snapshot({"privileged_roles": {"assignments": {}}}),
            snapshot(
                {
                    "privileged_roles": {
                        "assignments": {"k": entry(role="Groups Administrator", tier="sensitive")}
                    }
                }
            ),
        )
        assert findings[0].severity is Severity.MEDIUM


class TestAuthDrift:
    def _snapshots(self, before: str, after: str, field: str = "phishing_resistant") -> list:
        return diff_snapshots(
            snapshot({"auth_strength": {"accounts": {"id-a": {field: before, "tier": "privileged"}}}}),
            snapshot({"auth_strength": {"accounts": {"id-a": {field: after, "tier": "privileged"}}}}),
        )

    def test_losing_a_phishing_resistant_method(self) -> None:
        findings = self._snapshots("present", "absent")
        assert Issue.MFA_WEAKENED.value in issues(findings)

    def test_losing_a_second_factor(self) -> None:
        findings = self._snapshots("present", "absent", field="second_factor")
        assert Issue.MFA_WEAKENED.value in issues(findings)

    def test_gaining_a_method_is_not_a_weakening(self) -> None:
        assert self._snapshots("absent", "present") == []

    def test_unknown_on_either_side_is_not_a_weakening(self) -> None:
        """A refused registration report must not read as mass deregistration."""
        assert self._snapshots("present", "unknown") == []
        assert self._snapshots("unknown", "absent") == []

    def test_an_account_only_in_the_new_snapshot_is_not_compared(self) -> None:
        findings = diff_snapshots(
            snapshot({"auth_strength": {"accounts": {}}}),
            snapshot({"auth_strength": {"accounts": {"id-a": {"second_factor": "absent"}}}}),
        )
        assert findings == []


class TestDormancyDrift:
    def test_a_reactivated_dormant_admin_is_reported(self) -> None:
        findings = diff_snapshots(
            snapshot({"dormancy": {"dormant_privileged": ["id-a"], "accounts": {}}}),
            snapshot({"dormancy": {"dormant_privileged": [], "accounts": {}}}),
        )
        assert Issue.DORMANT_REACTIVATED.value in issues(findings)

    def test_becoming_dormant_is_left_to_the_posture_check(self) -> None:
        findings = diff_snapshots(
            snapshot({"dormancy": {"dormant_privileged": [], "accounts": {}}}),
            snapshot({"dormancy": {"dormant_privileged": ["id-a"], "accounts": {}}}),
        )
        assert findings == []


class TestWorkloadDrift:
    def test_a_new_credential_on_an_existing_application(self) -> None:
        before = {"service_principals": {"workloads": {"sp1": {"display": "Payroll", "credentials": {}}}}}
        after = {
            "service_principals": {
                "workloads": {"sp1": {"display": "Payroll", "credentials": {"c2": {"kind": "secret"}}}}
            }
        }
        findings = diff_snapshots(snapshot(before), snapshot(after))
        assert Issue.CREDENTIAL_NEW.value in issues(findings)
        assert findings[0].severity is Severity.HIGH

    def test_a_new_application_is_not_a_credential_finding(self) -> None:
        """Only applications present in both snapshots are compared."""
        findings = diff_snapshots(
            snapshot({"service_principals": {"workloads": {}}}),
            snapshot(
                {"service_principals": {"workloads": {"sp1": {"credentials": {"c1": {"kind": "secret"}}}}}}
            ),
        )
        assert findings == []

    def test_a_new_application_permission(self) -> None:
        findings = diff_snapshots(
            snapshot({"service_principals": {"workloads": {"sp1": {"application_permissions": []}}}}),
            snapshot(
                {"service_principals": {"workloads": {"sp1": {"application_permissions": ["Mail.Read"]}}}}
            ),
        )
        finding = next(f for f in findings if f.issue == Issue.APP_PERMISSION_NEW.value)
        assert finding.severity is Severity.CRITICAL
        assert "every mailbox" in finding.detail

    def test_a_scripted_rotation_aggregates_instead_of_listing(self) -> None:
        """The bulk rule is either/or, as it is for roles and grants. Emitting
        twenty-five high-severity lines *and* a line saying the change was a
        scripted rotation is the noise the aggregation exists to prevent."""
        credentials = {f"c{i}": {"kind": "secret"} for i in range(BULK_THRESHOLD + 5)}
        findings = diff_snapshots(
            snapshot({"service_principals": {"workloads": {"sp1": {"credentials": {}}}}}),
            snapshot({"service_principals": {"workloads": {"sp1": {"credentials": credentials}}}}),
        )
        assert len(findings) == 1
        assert findings[0].evidence["total"] == BULK_THRESHOLD + 5

    def test_a_change_at_the_threshold_is_still_named_individually(self) -> None:
        credentials = {f"c{i}": {"kind": "secret"} for i in range(BULK_THRESHOLD)}
        findings = diff_snapshots(
            snapshot({"service_principals": {"workloads": {"sp1": {"credentials": {}}}}}),
            snapshot({"service_principals": {"workloads": {"sp1": {"credentials": credentials}}}}),
        )
        assert len(findings) == BULK_THRESHOLD

    def test_an_unremarkable_new_permission_is_lower(self) -> None:
        findings = diff_snapshots(
            snapshot({"service_principals": {"workloads": {"sp1": {"application_permissions": []}}}}),
            snapshot(
                {"service_principals": {"workloads": {"sp1": {"application_permissions": ["User.Read"]}}}}
            ),
        )
        assert findings[0].severity is Severity.HIGH


class TestGrantDrift:
    def test_a_new_grant(self) -> None:
        findings = diff_snapshots(
            snapshot({"oauth_grants": {"grants": {}}}),
            snapshot({"oauth_grants": {"grants": {"g1": {"client": "Reader", "scopes": ["Mail.Read"]}}}}),
        )
        assert Issue.OAUTH_GRANT_NEW.value in issues(findings)
        assert "mail or files" in findings[0].detail

    def test_scopes_added_to_an_existing_grant(self) -> None:
        findings = diff_snapshots(
            snapshot({"oauth_grants": {"grants": {"g1": {"client": "Reader", "scopes": ["User.Read"]}}}}),
            snapshot(
                {
                    "oauth_grants": {
                        "grants": {"g1": {"client": "Reader", "scopes": ["User.Read", "Mail.Read"]}}
                    }
                }
            ),
        )
        assert Issue.OAUTH_SCOPE_ADDED.value in issues(findings)

    def test_consent_escalated_to_tenant_wide(self) -> None:
        findings = diff_snapshots(
            snapshot({"oauth_grants": {"grants": {"g1": {"client": "R", "tenant_wide": False}}}}),
            snapshot({"oauth_grants": {"grants": {"g1": {"client": "R", "tenant_wide": True}}}}),
        )
        assert Issue.OAUTH_TENANT_WIDE.value in issues(findings)

    def test_a_removed_scope_is_not_reported(self) -> None:
        findings = diff_snapshots(
            snapshot({"oauth_grants": {"grants": {"g1": {"scopes": ["Mail.Read", "User.Read"]}}}}),
            snapshot({"oauth_grants": {"grants": {"g1": {"scopes": ["User.Read"]}}}}),
        )
        assert findings == []


class TestGuestDrift:
    def test_a_guest_gaining_a_role(self) -> None:
        findings = diff_snapshots(
            snapshot({"guests": {"guests": {"id-g": {"roles": [], "group_count": 2}}}}),
            snapshot({"guests": {"guests": {"id-g": {"roles": ["User Administrator"], "group_count": 2}}}}),
        )
        assert Issue.GUEST_GAINED_ACCESS.value in issues(findings)

    def test_a_guest_gaining_groups(self) -> None:
        findings = diff_snapshots(
            snapshot({"guests": {"guests": {"id-g": {"roles": [], "group_count": 2}}}}),
            snapshot({"guests": {"guests": {"id-g": {"roles": [], "group_count": 9}}}}),
        )
        assert findings[0].evidence["groups_gained"] == 7

    def test_the_not_counted_sentinel_is_not_a_gain(self) -> None:
        """-1 records "the source could not count groups"; a transition into or
        out of it is a coverage change, not a guest gaining access."""
        findings = diff_snapshots(
            snapshot({"guests": {"guests": {"id-g": {"roles": [], "group_count": -1}}}}),
            snapshot({"guests": {"guests": {"id-g": {"roles": [], "group_count": 9}}}}),
        )
        assert findings == []

    def test_losing_access_is_not_reported(self) -> None:
        findings = diff_snapshots(
            snapshot({"guests": {"guests": {"id-g": {"roles": ["x"], "group_count": 9}}}}),
            snapshot({"guests": {"guests": {"id-g": {"roles": ["x"], "group_count": 2}}}}),
        )
        assert findings == []


class TestPolicyDrift:
    def _diff(self, before: str, after: str) -> list:
        return diff_snapshots(
            snapshot({"conditional_access": {"policies": {"p1": {"display": "MFA", "state": before}}}}),
            snapshot({"conditional_access": {"policies": {"p1": {"display": "MFA", "state": after}}}}),
        )

    def test_enabled_to_disabled(self) -> None:
        findings = self._diff("enabled", "disabled")
        assert Issue.POLICY_DISABLED.value in issues(findings)
        assert findings[0].severity is Severity.HIGH

    def test_enabled_to_report_only(self) -> None:
        assert Issue.POLICY_REPORT_ONLY.value in issues(self._diff("enabled", "report_only"))

    def test_strengthening_is_not_reported(self) -> None:
        assert self._diff("disabled", "enabled") == []

    def test_unknown_state_is_not_a_transition(self) -> None:
        assert self._diff("unknown", "disabled") == []
        assert self._diff("enabled", "unknown") == []

    def test_a_deleted_policy(self) -> None:
        findings = diff_snapshots(
            snapshot({"conditional_access": {"policies": {"p1": {"display": "MFA", "state": "enabled"}}}}),
            snapshot({"conditional_access": {"policies": {}}}),
        )
        assert Issue.POLICY_REMOVED.value in issues(findings)

    def test_an_exclusion_added(self) -> None:
        findings = diff_snapshots(
            snapshot({"conditional_access": {"policies": {"p1": {"exclusions": ["u1"]}}}}),
            snapshot({"conditional_access": {"policies": {"p1": {"exclusions": ["u1", "u2"]}}}}),
        )
        finding = next(f for f in findings if f.issue == Issue.POLICY_EXCLUSION_ADDED.value)
        assert finding.evidence["added"] == ["u2"]
        assert finding.severity is Severity.HIGH

    def test_an_exclusion_removed_is_not_reported(self) -> None:
        findings = diff_snapshots(
            snapshot({"conditional_access": {"policies": {"p1": {"exclusions": ["u1", "u2"]}}}}),
            snapshot({"conditional_access": {"policies": {"p1": {"exclusions": ["u1"]}}}}),
        )
        assert findings == []


class TestBounds:
    def test_the_finding_count_is_capped(self) -> None:
        after = {
            "conditional_access": {
                "policies": {
                    f"p{i}": {"display": f"P{i}", "state": "disabled"} for i in range(MAX_DRIFT_FINDINGS + 50)
                }
            }
        }
        before = {
            "conditional_access": {
                "policies": {
                    f"p{i}": {"display": f"P{i}", "state": "enabled"} for i in range(MAX_DRIFT_FINDINGS + 50)
                }
            }
        }
        findings = diff_snapshots(snapshot(before), snapshot(after))
        assert len(findings) == MAX_DRIFT_FINDINGS + 1
        assert findings[-1].issue == Issue.FINDINGS_TRUNCATED.value

    @pytest.mark.parametrize("check", list(registered_rules()))
    def test_every_registered_rule_tolerates_empty_observations(self, check: str) -> None:
        assert diff_snapshots(snapshot({check: {}}), snapshot({check: {}})) == []
