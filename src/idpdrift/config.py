"""Configuration loading.

YAML parsed with ``yaml.safe_load`` — never ``load`` — so a config file cannot
instantiate Python objects. Unknown keys are rejected rather than ignored,
because a silently-ignored typo that disables a check is exactly the failure a
security tool must not have.

**No secret is ever stored here.** Every credential is named by the environment
variable that holds it, and :func:`validate_env_var_name` rejects anything URL-
or path-shaped, so pasting a client secret where a variable name belongs fails
loudly at parse time rather than being committed to a repository.

**There is deliberately no way to supply an API path or query from
configuration.** The endpoints each source reads are fixed in the source modules
and reviewed in-tree. A config-injectable path would turn a read-only monitor
into an arbitrary-request primitive holding a directory-wide access token.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity
from .privacy import PrivacyMode
from .severity import RoleTier
from .validation import (
    ValidationError,
    assert_http_url,
    normalize_key,
    safe_text,
    validate_env_var_name,
)

log = logging.getLogger(__name__)

ALL_CHECKS: tuple[str, ...] = (
    "privileged_roles",
    "auth_strength",
    "dormancy",
    "service_principals",
    "oauth_grants",
    "guests",
    "conditional_access",
)

SOURCE_TYPES: tuple[str, ...] = ("entra", "okta", "file")

_MAX_CONFIG_BYTES = 5 * 1024 * 1024
_MAX_LIST_ENTRIES = 20000


def _read_env(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


@dataclass(slots=True)
class EntraSourceConfig:
    """Read-only connection to Microsoft Entra ID through Microsoft Graph.

    The application registration this uses needs only ``.Read.All`` scopes. If a
    deployment finds itself needing a write scope, something is wrong: nothing in
    this tool writes to a tenant.
    """

    tenant_id: str
    client_id: str
    # Holds the NAME of an environment variable, never the secret itself.
    client_secret_env: str = "IDPDRIFT_ENTRA_CLIENT_SECRET"  # noqa: S105
    authority: str = "https://login.microsoftonline.com"
    graph_url: str = "https://graph.microsoft.com"
    allow_internal: bool = False
    page_size: int = 100
    verify_tls: bool = True
    max_detail_lookups: int = 2000

    def client_secret(self) -> str | None:
        return _read_env(self.client_secret_env)


@dataclass(slots=True)
class OktaSourceConfig:
    """Read-only connection to an Okta org."""

    org_url: str
    api_token_env: str = "OKTA_API_TOKEN"  # noqa: S105
    allow_internal: bool = False
    page_size: int = 200
    verify_tls: bool = True
    max_detail_lookups: int = 2000

    def api_token(self) -> str | None:
        return _read_env(self.api_token_env)


@dataclass(slots=True)
class FileSourceConfig:
    """Reader for an exported JSON snapshot.

    Exists so the tool can be evaluated, tested and run in CI without a tenant,
    and so an operator whose directory sits behind a change-controlled export
    process can still use it. The schema is documented in the README.
    """

    path: str
    max_bytes: int = 256 * 1024 * 1024


@dataclass(slots=True)
class SourceConfig:
    type: str = "file"
    entra: EntraSourceConfig | None = None
    okta: OktaSourceConfig | None = None
    file: FileSourceConfig | None = None


@dataclass(slots=True)
class PolicyConfig:
    """What the operator considers acceptable."""

    # Extra role names to treat as privileged, and at what tier. Custom roles
    # cannot be classified by name alone, so a tenant with a powerful custom role
    # names it here rather than having the tool guess.
    privileged_roles: dict[str, RoleTier] = field(default_factory=dict)
    # True when the tenant runs privileged identity management and standing
    # assignments are meant to be the exception. Off by default: on a tenant
    # without PIM every assignment is standing, and reporting all of them says
    # nothing an operator did not already know.
    expect_just_in_time: bool = False
    dormant_days: int = 90
    credential_expiry_days: int = 30
    credential_max_lifetime_days: int = 365
    guest_role_allowance: int = 0
    guest_group_allowance: int = 5
    # Matched against the principal id and the normalised user principal name.
    ignore_principals: tuple[str, ...] = ()
    # Matched against the service principal object id and the application id.
    # Deliberately not the display name: whoever registers an application picks
    # that, so an entry here would let them opt themselves out of the report.
    ignore_applications: tuple[str, ...] = ()
    # Third-party applications already reviewed and accepted, by the same
    # identifiers and for the same reason.
    approved_applications: tuple[str, ...] = ()


@dataclass(slots=True)
class NotifyEmailConfig:
    smtp_host: str = ""
    smtp_port: int = 587
    use_starttls: bool = True
    username_env: str | None = None
    password_env: str | None = None
    from_address: str = ""
    to_addresses: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.smtp_host and self.from_address and self.to_addresses)

    def username(self) -> str | None:
        return _read_env(self.username_env)

    def password(self) -> str | None:
        return _read_env(self.password_env)


@dataclass(slots=True)
class NotifyConfig:
    """Where findings go.

    Destination URLs are read from the *environment*, named here but never stored
    here, so a repository can carry a committed config without carrying a secret.
    """

    slack_webhook_url_env: str | None = None
    webhook_url_env: str | None = None
    email: NotifyEmailConfig = field(default_factory=NotifyEmailConfig)
    min_severity: Severity = Severity.HIGH
    max_findings_per_message: int = 20

    def slack_webhook_url(self) -> str | None:
        return _read_env(self.slack_webhook_url_env)

    def webhook_url(self) -> str | None:
        return _read_env(self.webhook_url_env)


@dataclass(slots=True)
class AIConfig:
    """Optional LLM assistance. See :mod:`idpdrift.ai` for the trust boundary."""

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    summarize: bool = True
    max_items: int = 40

    def api_key(self) -> str | None:
        return _read_env(self.api_key_env)


@dataclass(slots=True)
class Settings:
    fail_on: Severity = Severity.HIGH
    http_timeout: float = 30.0
    max_identities: int = 100000
    checks: tuple[str, ...] = ALL_CHECKS
    state_path: str = ".idpdrift/state.json"
    salt_path: str = ".idpdrift/salt"
    user_agent: str = "idpdrift (+https://github.com/angeldeleon/idpdrift)"


@dataclass(slots=True)
class Config:
    source: SourceConfig
    settings: Settings = field(default_factory=Settings)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    privacy_mode: PrivacyMode = PrivacyMode.PSEUDONYMOUS


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(allowed))})"
        )


def _bounded_int(value: Any, where: str, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be an integer") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bounded_float(value: Any, where: str, low: float, high: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be a number") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{where} must be true or false")
    return value


def _key_list(raw: Any, where: str) -> tuple[str, ...]:
    """Parse a list of names into normalised matching keys."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list")
    if len(raw) > _MAX_LIST_ENTRIES:
        raise ValidationError(f"{where} has {len(raw)} entries; limit is {_MAX_LIST_ENTRIES}")
    keys: list[str] = []
    for item in raw:
        key = normalize_key(item)
        if not key:
            raise ValidationError(f"{where} contains an entry that normalises to nothing: {item!r}")
        if key not in keys:
            keys.append(key)
    return tuple(keys)


# --------------------------------------------------------------------------
# section parsers
# --------------------------------------------------------------------------


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _uuid(value: Any, where: str) -> str:
    text = str(value or "").strip()
    if not _UUID_RE.match(text):
        raise ValidationError(f"{where} must be a GUID, got {value!r}")
    return text


def _parse_entra(raw: Any) -> EntraSourceConfig:
    mapping = _require_mapping(raw, "source.entra")
    _reject_unknown(
        mapping,
        {
            "tenant_id",
            "client_id",
            "client_secret_env",
            "authority",
            "graph_url",
            "allow_internal",
            "page_size",
            "verify_tls",
            "max_detail_lookups",
        },
        "source.entra",
    )
    if not mapping:
        raise ValidationError("source.entra is required when source.type is 'entra'")

    allow_internal = _bool(mapping.get("allow_internal", False), "source.entra.allow_internal")
    if allow_internal:
        log.warning(
            "source.entra.allow_internal is enabled; the Graph and authority URLs are not "
            "checked against public address space"
        )

    verify_tls = _bool(mapping.get("verify_tls", True), "source.entra.verify_tls")
    if not verify_tls:
        # Allowed for a deployment behind an inspecting proxy, but it means the
        # client secret is exposed to whatever terminates the connection, so it
        # is never silent.
        log.warning(
            "source.entra.verify_tls is disabled; the client secret and the access token are "
            "exposed to any on-path attacker. Use a trusted certificate instead."
        )

    config = EntraSourceConfig(
        tenant_id=_uuid(mapping.get("tenant_id"), "source.entra.tenant_id"),
        client_id=_uuid(mapping.get("client_id"), "source.entra.client_id"),
        client_secret_env=validate_env_var_name(
            mapping.get("client_secret_env", "IDPDRIFT_ENTRA_CLIENT_SECRET"),
            where="source.entra.client_secret_env",
        ),
        allow_internal=allow_internal,
        verify_tls=verify_tls,
        page_size=_bounded_int(mapping.get("page_size", 100), "source.entra.page_size", 1, 999),
        max_detail_lookups=_bounded_int(
            mapping.get("max_detail_lookups", 2000), "source.entra.max_detail_lookups", 0, 200000
        ),
    )

    for key in ("authority", "graph_url"):
        if mapping.get(key):
            # Shape only. Resolving here would make `idpdrift validate` require
            # network access; the address check runs at connect time, which is
            # where it counts.
            setattr(
                config,
                key,
                assert_http_url(
                    str(mapping[key]),
                    require_https=True,
                    allow_internal=allow_internal,
                    resolve=False,
                ).rstrip("/"),
            )
    return config


def _parse_okta(raw: Any) -> OktaSourceConfig:
    mapping = _require_mapping(raw, "source.okta")
    _reject_unknown(
        mapping,
        {
            "org_url",
            "api_token_env",
            "allow_internal",
            "page_size",
            "verify_tls",
            "max_detail_lookups",
        },
        "source.okta",
    )
    if not mapping.get("org_url"):
        raise ValidationError("source.okta.org_url is required")

    allow_internal = _bool(mapping.get("allow_internal", False), "source.okta.allow_internal")
    if allow_internal:
        log.warning(
            "source.okta.allow_internal is enabled; the org URL is not checked against public address space"
        )

    verify_tls = _bool(mapping.get("verify_tls", True), "source.okta.verify_tls")
    if not verify_tls:
        log.warning(
            "source.okta.verify_tls is disabled; the API token is exposed to any on-path "
            "attacker. Use a trusted certificate instead."
        )

    return OktaSourceConfig(
        org_url=assert_http_url(
            str(mapping["org_url"]), require_https=True, allow_internal=allow_internal, resolve=False
        ).rstrip("/"),
        api_token_env=validate_env_var_name(
            mapping.get("api_token_env", "OKTA_API_TOKEN"), where="source.okta.api_token_env"
        ),
        allow_internal=allow_internal,
        verify_tls=verify_tls,
        page_size=_bounded_int(mapping.get("page_size", 200), "source.okta.page_size", 1, 200),
        max_detail_lookups=_bounded_int(
            mapping.get("max_detail_lookups", 2000), "source.okta.max_detail_lookups", 0, 200000
        ),
    )


def _parse_source(raw: Any) -> SourceConfig:
    mapping = _require_mapping(raw, "source")
    if not mapping:
        raise ValidationError("config.source is required")
    _reject_unknown(mapping, {"type", "entra", "okta", "file"}, "source")

    source_type = str(mapping.get("type", "file")).strip().lower()
    if source_type not in SOURCE_TYPES:
        raise ValidationError(
            f"source.type {source_type!r} is not supported (expected: {', '.join(SOURCE_TYPES)})"
        )

    config = SourceConfig(type=source_type)

    if source_type == "entra":
        config.entra = _parse_entra(mapping.get("entra"))
    elif source_type == "okta":
        config.okta = _parse_okta(mapping.get("okta"))
    else:
        file_raw = _require_mapping(mapping.get("file"), "source.file")
        _reject_unknown(file_raw, {"path", "max_bytes"}, "source.file")
        if not file_raw.get("path"):
            raise ValidationError("source.file.path is required")
        config.file = FileSourceConfig(
            path=str(file_raw["path"]),
            max_bytes=_bounded_int(
                file_raw.get("max_bytes", 256 * 1024 * 1024),
                "source.file.max_bytes",
                1024,
                4 * 1024 * 1024 * 1024,
            ),
        )

    return config


def _parse_settings(raw: Any) -> Settings:
    mapping = _require_mapping(raw, "settings")
    _reject_unknown(
        mapping,
        {
            "fail_on",
            "http_timeout",
            "max_identities",
            "checks",
            "state_path",
            "salt_path",
            "user_agent",
        },
        "settings",
    )
    settings = Settings()

    if "fail_on" in mapping:
        settings.fail_on = Severity.parse(str(mapping["fail_on"]))
    if "http_timeout" in mapping:
        settings.http_timeout = _bounded_float(mapping["http_timeout"], "settings.http_timeout", 1.0, 300.0)
    if "max_identities" in mapping:
        settings.max_identities = _bounded_int(
            mapping["max_identities"], "settings.max_identities", 1, 2000000
        )
    if "state_path" in mapping:
        settings.state_path = str(mapping["state_path"])
    if "salt_path" in mapping:
        settings.salt_path = str(mapping["salt_path"])
    if "user_agent" in mapping:
        agent = safe_text(mapping["user_agent"], limit=200)
        if not agent:
            raise ValidationError("settings.user_agent must not be empty")
        settings.user_agent = agent

    if "checks" in mapping:
        checks_raw = mapping["checks"]
        if not isinstance(checks_raw, list):
            raise ValidationError("settings.checks must be a list")
        selected: list[str] = []
        for item in checks_raw:
            name = str(item).strip().lower()
            if name not in ALL_CHECKS:
                raise ValidationError(
                    f"settings.checks contains unknown check {item!r} (available: {', '.join(ALL_CHECKS)})"
                )
            if name not in selected:
                selected.append(name)
        if not selected:
            raise ValidationError("settings.checks is empty; omit the key to run all checks")
        settings.checks = tuple(selected)

    return settings


def _parse_privileged_roles(raw: Any) -> dict[str, RoleTier]:
    """Parse ``policy.privileged_roles``.

    Accepts a list of names (all treated as the privileged tier) or a mapping of
    name to tier, because a tenant with a genuinely tenant-admin-equivalent
    custom role needs to be able to say so.
    """
    if raw is None:
        return {}
    tiers = {tier.value: tier for tier in RoleTier}

    if isinstance(raw, list):
        return {
            normalize_key(name): RoleTier.PRIVILEGED for name in _key_list(raw, "policy.privileged_roles")
        }

    if isinstance(raw, dict):
        out: dict[str, RoleTier] = {}
        for name, tier_name in raw.items():
            key = normalize_key(name)
            if not key:
                raise ValidationError(f"policy.privileged_roles has an unusable role name: {name!r}")
            tier_key = str(tier_name).strip().lower()
            if tier_key not in tiers:
                raise ValidationError(
                    f"policy.privileged_roles[{name!r}] is {tier_name!r}; expected one of: "
                    f"{', '.join(sorted(tiers))}"
                )
            out[key] = tiers[tier_key]
        return out

    raise ValidationError("policy.privileged_roles must be a list of names or a mapping of name to tier")


def _parse_policy(raw: Any) -> PolicyConfig:
    mapping = _require_mapping(raw, "policy")
    _reject_unknown(
        mapping,
        {
            "privileged_roles",
            "expect_just_in_time",
            "dormant_days",
            "credential_expiry_days",
            "credential_max_lifetime_days",
            "guest_role_allowance",
            "guest_group_allowance",
            "ignore_principals",
            "ignore_applications",
            "approved_applications",
        },
        "policy",
    )

    policy = PolicyConfig(
        privileged_roles=_parse_privileged_roles(mapping.get("privileged_roles")),
        ignore_principals=_key_list(mapping.get("ignore_principals"), "policy.ignore_principals"),
        ignore_applications=_key_list(mapping.get("ignore_applications"), "policy.ignore_applications"),
        approved_applications=_key_list(mapping.get("approved_applications"), "policy.approved_applications"),
    )

    if "expect_just_in_time" in mapping:
        policy.expect_just_in_time = _bool(mapping["expect_just_in_time"], "policy.expect_just_in_time")
    if "dormant_days" in mapping:
        policy.dormant_days = _bounded_int(mapping["dormant_days"], "policy.dormant_days", 1, 3650)
    if "credential_expiry_days" in mapping:
        policy.credential_expiry_days = _bounded_int(
            mapping["credential_expiry_days"], "policy.credential_expiry_days", 1, 3650
        )
    if "credential_max_lifetime_days" in mapping:
        policy.credential_max_lifetime_days = _bounded_int(
            mapping["credential_max_lifetime_days"], "policy.credential_max_lifetime_days", 1, 36500
        )
    if "guest_role_allowance" in mapping:
        policy.guest_role_allowance = _bounded_int(
            mapping["guest_role_allowance"], "policy.guest_role_allowance", 0, 10000
        )
    if "guest_group_allowance" in mapping:
        policy.guest_group_allowance = _bounded_int(
            mapping["guest_group_allowance"], "policy.guest_group_allowance", 0, 10000
        )

    if policy.credential_expiry_days >= policy.credential_max_lifetime_days:
        raise ValidationError(
            "policy.credential_expiry_days must be shorter than "
            "policy.credential_max_lifetime_days; otherwise every credential is reported twice"
        )

    overlap = set(policy.ignore_applications) & set(policy.approved_applications)
    if overlap:
        raise ValidationError(
            "an application appears in both policy.ignore_applications and "
            f"policy.approved_applications: {', '.join(sorted(overlap))}"
        )

    return policy


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _email_address(value: Any, where: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    # Header-injection guard: a newline in an address splits the message and lets
    # a config add arbitrary headers or recipients.
    if any(c in text for c in "\r\n\t,;<>"):
        raise ValidationError(f"{where} contains an illegal character: {value!r}")
    if len(text) > 254 or not _EMAIL_RE.match(text):
        raise ValidationError(f"{where} is not a valid email address: {value!r}")
    return text


def _parse_email(raw: Any) -> NotifyEmailConfig:
    mapping = _require_mapping(raw, "notify.email")
    _reject_unknown(
        mapping,
        {
            "smtp_host",
            "smtp_port",
            "use_starttls",
            "username_env",
            "password_env",
            "from_address",
            "to_addresses",
        },
        "notify.email",
    )
    if not mapping:
        return NotifyEmailConfig()

    email = NotifyEmailConfig()
    email.smtp_host = safe_text(mapping.get("smtp_host", ""), limit=253)
    if "smtp_port" in mapping:
        email.smtp_port = _bounded_int(mapping["smtp_port"], "notify.email.smtp_port", 1, 65535)
    if "use_starttls" in mapping:
        email.use_starttls = _bool(mapping["use_starttls"], "notify.email.use_starttls")
    if mapping.get("username_env"):
        email.username_env = validate_env_var_name(mapping["username_env"], where="notify.email.username_env")
    if mapping.get("password_env"):
        email.password_env = validate_env_var_name(mapping["password_env"], where="notify.email.password_env")

    email.from_address = _email_address(mapping.get("from_address", ""), "notify.email.from_address")

    to_raw = mapping.get("to_addresses") or []
    if not isinstance(to_raw, list):
        raise ValidationError("notify.email.to_addresses must be a list")
    if len(to_raw) > 50:
        raise ValidationError("notify.email.to_addresses has more than 50 entries")
    email.to_addresses = tuple(
        _email_address(item, "notify.email.to_addresses") for item in to_raw if str(item).strip()
    )

    if email.smtp_host and not (email.from_address and email.to_addresses):
        raise ValidationError(
            "notify.email needs from_address and at least one to_addresses entry when smtp_host is set"
        )
    if email.smtp_host and not email.use_starttls and email.smtp_port != 465:
        log.warning(
            "notify.email.use_starttls is disabled on port %d; credentials and a list of "
            "who administers your tenant will cross the network in the clear",
            email.smtp_port,
        )
    return email


def _parse_notify(raw: Any) -> NotifyConfig:
    mapping = _require_mapping(raw, "notify")
    _reject_unknown(
        mapping,
        {"slack_webhook_url_env", "webhook_url_env", "email", "min_severity", "max_findings_per_message"},
        "notify",
    )

    notify = NotifyConfig()
    for key in ("slack_webhook_url_env", "webhook_url_env"):
        if mapping.get(key):
            setattr(notify, key, validate_env_var_name(mapping[key], where=f"notify.{key}"))

    if "min_severity" in mapping:
        notify.min_severity = Severity.parse(str(mapping["min_severity"]))
    if "max_findings_per_message" in mapping:
        notify.max_findings_per_message = _bounded_int(
            mapping["max_findings_per_message"], "notify.max_findings_per_message", 1, 100
        )
    notify.email = _parse_email(mapping.get("email"))
    return notify


def _parse_ai(raw: Any) -> AIConfig:
    mapping = _require_mapping(raw, "ai")
    _reject_unknown(mapping, {"enabled", "provider", "model", "api_key_env", "summarize", "max_items"}, "ai")
    ai = AIConfig()
    if "enabled" in mapping:
        ai.enabled = _bool(mapping["enabled"], "ai.enabled")
    if "provider" in mapping:
        provider = str(mapping["provider"]).strip().lower()
        if provider != "anthropic":
            raise ValidationError(f"ai.provider {provider!r} is not supported (only 'anthropic')")
        ai.provider = provider
    if "model" in mapping:
        model = safe_text(mapping["model"], limit=100)
        if not model:
            raise ValidationError("ai.model must not be empty")
        ai.model = model
    if "api_key_env" in mapping:
        ai.api_key_env = validate_env_var_name(mapping["api_key_env"], where="ai.api_key_env")
    if "summarize" in mapping:
        ai.summarize = _bool(mapping["summarize"], "ai.summarize")
    if "max_items" in mapping:
        ai.max_items = _bounded_int(mapping["max_items"], "ai.max_items", 1, 200)
    return ai


def _parse_privacy(raw: Any) -> PrivacyMode:
    mapping = _require_mapping(raw, "privacy")
    _reject_unknown(mapping, {"mode"}, "privacy")
    if "mode" not in mapping:
        return PrivacyMode.PSEUDONYMOUS
    mode = PrivacyMode.parse(str(mapping["mode"]))
    if mode is PrivacyMode.IDENTIFIED:
        log.warning(
            "privacy.mode is 'identified': reports will name real accounts. Confirm this is "
            "compatible with your obligations before distributing them."
        )
    return mode


def load_config(path: str | Path) -> Config:
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ValidationError(f"config file not found: {config_path}")

    size = config_path.stat().st_size
    if size > _MAX_CONFIG_BYTES:
        raise ValidationError(f"config file is too large ({size} bytes; limit 5 MiB)")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"config file is not valid YAML: {exc}") from exc

    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    mapping = _require_mapping(raw, "config")
    if not mapping:
        raise ValidationError("config is empty")
    _reject_unknown(mapping, {"source", "settings", "policy", "notify", "ai", "privacy"}, "config")

    return Config(
        source=_parse_source(mapping.get("source")),
        settings=_parse_settings(mapping.get("settings")),
        policy=_parse_policy(mapping.get("policy")),
        notify=_parse_notify(mapping.get("notify")),
        ai=_parse_ai(mapping.get("ai")),
        privacy_mode=_parse_privacy(mapping.get("privacy")),
    )
