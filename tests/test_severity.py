"""The severity table.

These tests exist because the point of a table is that it does not move. If a
change here is intentional, the assertion is the place to record it — and the
README table has to change with it.
"""

from __future__ import annotations

import pytest

from idpdrift.config import ALL_CHECKS
from idpdrift.models import Determination, Severity
from idpdrift.severity import (
    BASE_SEVERITY,
    TIER_ADJUSTMENT,
    UNKNOWN_CEILING,
    Issue,
    RoleTier,
    explain,
    rate,
)


class TestTableCompleteness:
    def test_every_issue_has_a_base_severity(self) -> None:
        missing = [issue.value for issue in Issue if issue not in BASE_SEVERITY]
        assert not missing, f"issues with no band: {missing}"

    def test_every_tier_has_an_adjustment(self) -> None:
        assert set(TIER_ADJUSTMENT) == set(RoleTier)

    def test_adjustments_are_bounded_to_one_band(self) -> None:
        """A bigger swing would let a judgement about a role name outweigh an
        observation about the tenant."""
        assert all(abs(delta) <= 1 for delta in TIER_ADJUSTMENT.values())

    def test_issue_prefixes_cover_the_checks(self) -> None:
        """Every check must own at least one issue, or it can produce nothing."""
        for check in ALL_CHECKS:
            assert any(issue.value for issue in Issue), check


class TestTierAdjustment:
    def test_tenant_admin_raises_one_band(self) -> None:
        assert rate(Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.TENANT_ADMIN) is Severity.CRITICAL

    def test_privileged_is_the_baseline(self) -> None:
        assert rate(Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.PRIVILEGED) is Severity.HIGH

    def test_standard_lowers_one_band(self) -> None:
        assert rate(Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.STANDARD) is Severity.MEDIUM

    def test_clamping_at_the_top(self) -> None:
        assert rate(Issue.OAUTH_SENSITIVE_SCOPE, tier=RoleTier.TENANT_ADMIN) is Severity.CRITICAL

    def test_clamping_at_the_bottom(self) -> None:
        assert rate(Issue.ROLE_ASSIGNMENT_REMOVED, tier=RoleTier.STANDARD) is Severity.INFO


class TestUnknownCap:
    @pytest.mark.parametrize("issue", list(Issue))
    def test_nothing_indeterminate_exceeds_the_ceiling(self, issue: Issue) -> None:
        """An unreadable facet must never sound like a discovered weakness."""
        assert rate(issue, determination=Determination.UNKNOWN) <= UNKNOWN_CEILING

    def test_the_cap_ignores_the_tier(self) -> None:
        capped = rate(
            Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.TENANT_ADMIN, determination=Determination.UNKNOWN
        )
        assert capped is Severity.LOW

    def test_an_already_low_issue_is_unchanged(self) -> None:
        assert rate(Issue.FACET_INDETERMINATE, determination=Determination.UNKNOWN) is Severity.LOW

    def test_unknown_cannot_trip_a_high_threshold(self) -> None:
        assert all(rate(issue, determination=Determination.UNKNOWN) < Severity.HIGH for issue in Issue)


class TestExplain:
    def test_names_the_tier_when_it_moved_the_band(self) -> None:
        assert "raised one band" in explain(Issue.ROLE_ASSIGNMENT_NEW, tier=RoleTier.TENANT_ADMIN)

    def test_names_the_cap_when_indeterminate(self) -> None:
        text = explain(Issue.MFA_ABSENT, determination=Determination.UNKNOWN)
        assert "could not be determined" in text

    def test_baseline_tier_reads_plainly(self) -> None:
        assert explain(Issue.MFA_ABSENT) == "mfa_absent at the privileged tier: high"


class TestOrdering:
    def test_severity_comparisons_use_rank(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_comparison_with_a_non_severity_is_not_implemented(self) -> None:
        assert Severity.HIGH.__lt__("high") is NotImplemented

    def test_parse_rejects_nonsense(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("apocalyptic")

    def test_tier_ranks_are_ordered(self) -> None:
        assert (
            RoleTier.TENANT_ADMIN.rank
            > RoleTier.PRIVILEGED.rank
            > RoleTier.SENSITIVE.rank
            > RoleTier.STANDARD.rank
        )


class TestSpecificBands:
    """The bands an operator's fail_on threshold actually depends on."""

    @pytest.mark.parametrize(
        ("issue", "tier", "expected"),
        [
            (Issue.ROLE_ASSIGNMENT_NEW, RoleTier.TENANT_ADMIN, Severity.CRITICAL),
            (Issue.CREDENTIAL_NEW, RoleTier.PRIVILEGED, Severity.HIGH),
            (Issue.APP_PERMISSION_HIGH_IMPACT, RoleTier.TENANT_ADMIN, Severity.CRITICAL),
            (Issue.POLICY_EXCLUSION_ADDED, RoleTier.PRIVILEGED, Severity.HIGH),
            (Issue.MFA_ABSENT, RoleTier.TENANT_ADMIN, Severity.CRITICAL),
            (Issue.OAUTH_THIRD_PARTY, RoleTier.SENSITIVE, Severity.INFO),
            (Issue.ROLE_ASSIGNMENT_REMOVED, RoleTier.PRIVILEGED, Severity.INFO),
        ],
    )
    def test_band(self, issue: Issue, tier: RoleTier, expected: Severity) -> None:
        assert rate(issue, tier=tier) is expected
