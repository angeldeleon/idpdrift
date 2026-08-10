"""The trust boundary: sanitisation, normalisation, redaction and the SSRF guard."""

from __future__ import annotations

import ipaddress

import pytest

from idpdrift.validation import (
    REDACTED,
    ValidationError,
    assert_http_url,
    assert_public_http_url,
    is_public_address,
    normalize_key,
    safe_text,
    scrub_evidence,
    validate_env_var_name,
)


class TestSafeText:
    def test_control_characters_become_spaces(self) -> None:
        assert safe_text("Payroll\nSync\tteam") == "Payroll Sync team"

    def test_bidi_override_is_removed(self) -> None:
        """A name that renders as one thing and stores as another is a forgery."""
        assert "‮" not in safe_text("admin‮nimda")
        assert safe_text("admin‮nimda") == "adminnimda"

    def test_zero_width_characters_are_removed(self) -> None:
        assert safe_text("Glo​bal Admin") == "Global Admin"

    def test_lone_surrogates_are_replaced(self) -> None:
        cleaned = safe_text("bad\ud800name")
        cleaned.encode("utf-8")  # must not raise
        assert "\ud800" not in cleaned

    def test_length_is_capped(self) -> None:
        assert len(safe_text("x" * 5000, limit=64)) == 64

    def test_ordinary_text_is_untouched(self) -> None:
        assert safe_text("Alice O'Brien (Contractor)") == "Alice O'Brien (Contractor)"


class TestNormalizeKey:
    @pytest.mark.parametrize(
        "spelling",
        ["Global Administrator", "GlobalAdministrator", "global-administrator", "GLOBAL_ADMINISTRATOR"],
    )
    def test_role_spellings_converge(self, spelling: str) -> None:
        assert normalize_key(spelling) == "global administrator"

    def test_fullwidth_spelling_converges(self) -> None:
        assert normalize_key("Ｇｌｏｂａｌ Ａｄｍｉｎ") == normalize_key("Global Admin")

    def test_non_latin_script_survives(self) -> None:
        """A [^a-z0-9] strip would empty this, and callers skip empty keys."""
        assert normalize_key("管理者") != ""

    def test_punctuation_only_name_survives(self) -> None:
        assert normalize_key("+++") != ""
        assert normalize_key("🔒") != ""

    def test_scope_spellings_converge(self) -> None:
        assert normalize_key("Mail.ReadWrite") == normalize_key("mail read write")


class TestScrubEvidence:
    def test_secret_shaped_keys_are_redacted(self) -> None:
        scrubbed = scrub_evidence({"client_secret": "abc123", "displayName": "Payroll"})
        assert scrubbed["client_secret"] == REDACTED
        assert scrubbed["displayName"] == "Payroll"

    def test_nested_secrets_are_redacted(self) -> None:
        scrubbed = scrub_evidence({"credential": {"passwordCredentials": [{"secretText": "s"}]}})
        assert scrubbed["credential"]["passwordCredentials"] == REDACTED

    def test_field_name_is_kept(self) -> None:
        """ "There is a secret on this app" is the fact worth reporting."""
        assert "client_secret" in scrub_evidence({"client_secret": "abc"})

    def test_token_and_authorization_are_redacted(self) -> None:
        scrubbed = scrub_evidence({"access_token": "x", "Authorization": "Bearer y"})
        assert scrubbed["access_token"] == REDACTED
        assert scrubbed["Authorization"] == REDACTED

    def test_lists_are_bounded(self) -> None:
        scrubbed = scrub_evidence(list(range(500)))
        assert len(scrubbed) == 51
        assert "more" in scrubbed[-1]

    def test_mappings_are_bounded(self) -> None:
        scrubbed = scrub_evidence({f"k{i}": i for i in range(200)})
        assert "_truncated" in scrubbed

    def test_depth_is_bounded(self) -> None:
        deep: dict = {"a": {}}
        cursor = deep["a"]
        for _ in range(20):
            cursor["a"] = {}
            cursor = cursor["a"]
        assert "truncated" in str(scrub_evidence(deep))

    def test_control_characters_in_values_are_neutralised(self) -> None:
        assert "\n" not in str(scrub_evidence({"note": "a\nb"}))

    def test_booleans_and_numbers_survive(self) -> None:
        assert scrub_evidence({"count": 3, "ok": True, "none": None}) == {
            "count": 3,
            "ok": True,
            "none": None,
        }


class TestEnvVarName:
    def test_url_in_an_env_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment variable"):
            validate_env_var_name("https://hooks.slack.com/services/x", where="notify.slack")

    def test_path_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_env_var_name("/etc/secret", where="x")

    def test_valid_name_passes(self) -> None:
        assert validate_env_var_name("OKTA_API_TOKEN", where="x") == "OKTA_API_TOKEN"

    def test_empty_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_env_var_name("", where="x")


class TestAddressGuard:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "172.16.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:169.254.169.254",
            "2002:a9fe:a9fe::1",
        ],
    )
    def test_non_public_addresses_are_refused(self, address: str) -> None:
        assert not is_public_address(ipaddress.ip_address(address))

    @pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_addresses_pass(self, address: str) -> None:
        assert is_public_address(ipaddress.ip_address(address))


class TestUrlGuard:
    def test_http_is_refused_by_default(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            assert_public_http_url("http://example.com/hook")

    def test_embedded_credentials_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="credentials"):
            assert_http_url("https://user:pass@example.com/", resolve=False)

    def test_literal_private_address_is_refused_even_without_dns(self) -> None:
        with pytest.raises(ValidationError, match="non-public"):
            assert_http_url("https://10.0.0.5/graph", resolve=False)

    def test_metadata_address_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            assert_http_url("https://169.254.169.254/", resolve=False)

    def test_allow_internal_permits_an_internal_host(self) -> None:
        assert assert_http_url("https://10.0.0.5/graph", allow_internal=True) == "https://10.0.0.5/graph"

    def test_shape_only_mode_does_not_resolve(self) -> None:
        assert assert_http_url("https://nonexistent.invalid/x", resolve=False).endswith("/x")

    def test_empty_url_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            assert_http_url("   ")

    def test_missing_host_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="no host"):
            assert_http_url("https:///path", resolve=False)

    def test_file_scheme_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            assert_http_url("file:///etc/passwd", resolve=False)
