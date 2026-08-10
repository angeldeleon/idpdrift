"""Reader for an exported JSON snapshot of a directory.

Three reasons this exists rather than being a test fixture:

* **Evaluation without credentials.** Nobody should have to create an
  application registration with directory-wide read scopes to find out whether a
  tool is worth running.
* **Change-controlled environments.** Plenty of organisations will not let a
  scheduled job hold a directory token, but will happily let an existing,
  reviewed export process drop a file somewhere.
* **Reproducibility.** A finding somebody disputes can be re-derived from the
  exact input that produced it.

The schema is documented in the README. One rule governs how it is read, and it
is the tri-state rule: **an absent top-level key means "not exported", not
"empty"**. A file with no ``policies`` key records ``access_policies`` coverage
as UNKNOWN and the conditional-access check declines to conclude anything; a file
with ``"policies": []`` records the facet as read, and an empty list of policies
is then a fact the check is entitled to report on. Getting that backwards would
make every partial export look like a catastrophically misconfigured tenant.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

from ..config import FileSourceConfig
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
)
from ..validation import safe_text
from .base import SourceError

log = logging.getLogger(__name__)

_READ_CHUNK = 4 * 1024 * 1024

# Which facets a given top-level key is evidence for.
_KEY_FACETS: dict[str, tuple[str, ...]] = {
    "principals": ("principals", "group_membership", "sign_in_activity", "authentication_methods"),
    "role_assignments": ("role_assignments", "role_eligibility"),
    "service_principals": ("service_principals", "application_credentials", "application_permissions"),
    "oauth_grants": ("oauth_grants",),
    "policies": ("access_policies",),
}


class FileSource:
    """Collects identity state from an exported JSON snapshot."""

    name = "file"

    def __init__(self, config: FileSourceConfig, *, max_identities: int = 100000) -> None:
        self.config = config
        self.max_identities = max_identities

    # ------------------------------------------------------------------

    def _read(self) -> bytes:
        """Read the export through a descriptor.

        ``O_NOFOLLOW`` because the export path is frequently a world-writable
        drop directory shared with whatever produces the export, and following a
        symlink from there would let that process aim this reader at any file the
        service account can open. ``O_NONBLOCK`` because a FIFO left at the path
        blocks inside ``os.open`` — before the regular-file check can refuse it —
        and would hang every scheduled run with no timeout and no log line.
        Cleared once the descriptor is known to be a regular file.
        """
        path = Path(self.config.path).expanduser()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError as exc:
            raise SourceError(f"export file not found: {path}") from exc
        except OSError as exc:
            raise SourceError(f"cannot open export file {path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SourceError(f"export path {path} is not a regular file; refusing to read it")
            if info.st_size > self.config.max_bytes:
                raise SourceError(
                    f"export file is {info.st_size} bytes, above the configured max_bytes "
                    f"({self.config.max_bytes}). Raise the limit deliberately if that is expected."
                )
            os.set_blocking(fd, True)

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.config.max_bytes:
                    raise SourceError(f"export file exceeds max_bytes ({self.config.max_bytes})")
                chunks.append(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise SourceError(f"cannot read export file {path}: {exc}") from exc
        finally:
            os.close(fd)

    def collect(self) -> IdentityState:
        raw_bytes = self._read()
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceError(f"export file is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise SourceError("export file must contain a JSON object at the top level")

        state = IdentityState(
            collected_at=safe_text(raw.get("collected_at") or IdentityState.now_iso(), limit=40),
            source=safe_text(raw.get("source") or self.name, limit=32) or self.name,
            tenant=safe_text(raw.get("tenant") or "", limit=253),
        )

        # Coverage first, so a later parse failure cannot leave a facet looking
        # readable when it was not.
        for key, facets in _KEY_FACETS.items():
            present = isinstance(raw.get(key), list)
            for facet in facets:
                state.coverage[facet] = Determination.PRESENT if present else Determination.UNKNOWN

        declared = raw.get("coverage")
        if isinstance(declared, dict):
            # An explicit declaration wins. An export that carried a `principals`
            # list but could not read authentication methods needs a way to say
            # so, and the alternative — inferring it from every principal having
            # a null field — is guesswork.
            for facet, value in declared.items():
                state.coverage[str(facet)] = Determination.parse(value)

        state.principals = self._principals(raw.get("principals"), state)
        # An export that never says what kind of account a row is cannot support
        # a guest finding. Inferring "no guests" from silence would report a
        # partial export as a clean one.
        if "guest_status" not in state.coverage:
            rows = raw.get("principals")
            declares_kind = isinstance(rows, list) and any(
                isinstance(row, dict) and ("kind" in row or "user_type" in row) for row in rows
            )
            state.coverage["guest_status"] = Determination.PRESENT if declares_kind else Determination.UNKNOWN
        state.role_assignments = self._role_assignments(raw.get("role_assignments"), state)
        state.workloads = self._workloads(raw.get("service_principals"), state)
        state.oauth_grants = self._grants(raw.get("oauth_grants"), state)
        state.policies = self._policies(raw.get("policies"), state)

        if not state.principals and not state.workloads:
            state.errors.append(
                "the export contains no principals and no service principals; nothing could be assessed"
            )

        return state

    # ------------------------------------------------------------------

    def _rows(self, raw: Any, key: str, state: IdentityState) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        rows = [row for row in raw if isinstance(row, dict)]
        if len(rows) != len(raw):
            state.errors.append(f"{len(raw) - len(rows)} non-object entry/entries in '{key}' were skipped")
        if len(rows) > self.max_identities:
            state.errors.append(
                f"'{key}' holds {len(rows)} entries, above settings.max_identities "
                f"({self.max_identities}); the scan covers a subset"
            )
            # A truncated read cannot distinguish "absent" from "past the cap",
            # so the facets this key feeds become indeterminate rather than
            # silently short.
            for facet in _KEY_FACETS.get(key, ()):
                state.coverage[facet] = Determination.UNKNOWN
            rows = rows[: self.max_identities]
        return rows

    def _principals(self, raw: Any, state: IdentityState) -> list[Principal]:
        out: list[Principal] = []
        for row in self._rows(raw, "principals", state):
            principal_id = safe_text(row.get("id") or row.get("principal_id") or "", limit=128)
            if not principal_id:
                continue
            kind = PrincipalKind.parse(row.get("kind") or row.get("user_type"))
            out.append(
                Principal(
                    principal_id=principal_id,
                    display=safe_text(row.get("display_name") or row.get("display") or "", limit=200),
                    upn=safe_text(row.get("user_principal_name") or row.get("upn") or "", limit=254),
                    kind=kind,
                    enabled=_tri(row.get("enabled")),
                    last_sign_in=safe_text(row.get("last_sign_in") or "", limit=40),
                    sign_in_known=_tri_known(row, "last_sign_in", state.covers("sign_in_activity")),
                    phishing_resistant=_tri(row.get("phishing_resistant")),
                    second_factor=_tri(row.get("second_factor")),
                    auth_methods=tuple(
                        safe_text(m, limit=64) for m in _as_list(row.get("auth_methods"))[:20]
                    ),
                    group_count=_as_int(row.get("group_count"), 0),
                    group_count_known=Determination.PRESENT
                    if isinstance(row.get("group_count"), int)
                    else Determination.UNKNOWN,
                    created_at=safe_text(row.get("created_at") or "", limit=40),
                )
            )
        return out

    def _role_assignments(self, raw: Any, state: IdentityState) -> list[RoleAssignment]:
        by_id = {p.principal_id: p for p in state.principals}
        out: list[RoleAssignment] = []
        for row in self._rows(raw, "role_assignments", state):
            principal_id = safe_text(row.get("principal_id") or "", limit=128)
            role_name = safe_text(row.get("role_name") or "", limit=200)
            if not principal_id or not role_name:
                continue
            principal = by_id.get(principal_id)
            out.append(
                RoleAssignment(
                    assignment_id=safe_text(row.get("id") or "", limit=128),
                    role_id=safe_text(row.get("role_id") or "", limit=128),
                    role_name=role_name,
                    principal_id=principal_id,
                    principal_display=(
                        principal.display
                        if principal is not None
                        else safe_text(row.get("principal_display") or "", limit=200)
                    ),
                    principal_kind=(
                        principal.kind
                        if principal is not None
                        else PrincipalKind.parse(row.get("principal_kind"))
                    ),
                    scope=safe_text(row.get("scope") or "/", limit=200),
                    standing=_tri(row.get("standing")),
                    assigned_at=safe_text(row.get("assigned_at") or "", limit=40),
                )
            )
        return out

    def _workloads(self, raw: Any, state: IdentityState) -> list[Workload]:
        out: list[Workload] = []
        for row in self._rows(raw, "service_principals", state):
            workload_id = safe_text(row.get("id") or "", limit=128)
            if not workload_id:
                continue
            credentials = tuple(
                Credential(
                    credential_id=safe_text(cred.get("id") or "", limit=64),
                    kind=_credential_kind(cred.get("type")),
                    display=safe_text(cred.get("display_name") or "", limit=120),
                    starts_at=safe_text(cred.get("start") or "", limit=40),
                    expires_at=safe_text(cred.get("expires") or "", limit=40),
                )
                for cred in _as_list(row.get("credentials"))[:200]
                if isinstance(cred, dict)
            )
            permissions = tuple(
                PermissionGrant(
                    permission_id=safe_text(perm.get("id") or "", limit=128),
                    scope=safe_text(perm.get("scope") or "", limit=200),
                    resource=safe_text(perm.get("resource") or "", limit=200),
                    application=str(perm.get("type") or "application").strip().lower() != "delegated",
                    granted_at=safe_text(perm.get("granted_at") or "", limit=40),
                )
                for perm in _as_list(row.get("permissions"))[:500]
                if isinstance(perm, dict) and perm.get("scope")
            )
            out.append(
                Workload(
                    workload_id=workload_id,
                    display=safe_text(row.get("display_name") or row.get("display") or "", limit=200),
                    app_id=safe_text(row.get("app_id") or "", limit=128),
                    third_party=_tri(row.get("third_party")),
                    enabled=_tri(row.get("enabled")),
                    owner_count=_as_int(row.get("owner_count"), 0),
                    credentials=credentials,
                    permissions=permissions,
                )
            )
        return out

    def _grants(self, raw: Any, state: IdentityState) -> list[OAuthGrant]:
        out: list[OAuthGrant] = []
        for row in self._rows(raw, "oauth_grants", state):
            client_id = safe_text(row.get("client_id") or "", limit=128)
            if not client_id:
                continue
            consent = str(row.get("consent_type") or "").strip().lower()
            out.append(
                OAuthGrant(
                    grant_id=safe_text(row.get("id") or "", limit=128),
                    client_id=client_id,
                    client_display=safe_text(
                        row.get("client_display_name") or row.get("client_display") or "", limit=200
                    ),
                    resource=safe_text(row.get("resource") or "", limit=200),
                    scopes=tuple(safe_text(s, limit=120) for s in _as_list(row.get("scopes"))[:100]),
                    tenant_wide=consent in ("allprincipals", "tenant", "tenant_wide", "org"),
                    principal_id=safe_text(row.get("principal_id") or "", limit=128),
                )
            )
        return out

    def _policies(self, raw: Any, state: IdentityState) -> list[AccessPolicy]:
        out: list[AccessPolicy] = []
        for row in self._rows(raw, "policies", state):
            policy_id = safe_text(row.get("id") or "", limit=128)
            if not policy_id:
                continue
            out.append(
                AccessPolicy(
                    policy_id=policy_id,
                    display=safe_text(row.get("display_name") or row.get("display") or "", limit=200),
                    state=_policy_state(row.get("state")),
                    excluded_users=_names(row.get("excluded_users")),
                    excluded_groups=_names(row.get("excluded_groups")),
                    excluded_roles=_names(row.get("excluded_roles")),
                )
            )
        return out


# --------------------------------------------------------------------------


def _tri(value: Any) -> Determination:
    """Map an exported field onto the tri-state.

    ``null`` and a missing key both mean UNKNOWN. That is the entire point: an
    exporter that could not read a field writes ``null``, and reading that as
    ``false`` would invent a finding for every row.
    """
    if isinstance(value, bool):
        return Determination.from_optional(value)
    if value is None:
        return Determination.UNKNOWN
    return Determination.parse(value)


def _tri_known(row: dict[str, Any], key: str, facet: Determination) -> Determination:
    if facet.is_unknown:
        return Determination.UNKNOWN
    if key not in row or row.get(key) is None:
        return Determination.UNKNOWN
    return Determination.PRESENT if row.get(key) else Determination.ABSENT


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _credential_kind(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in ("secret", "password", "client_secret", "passwordcredential"):
        return "secret"
    if text in ("certificate", "cert", "key", "keycredential"):
        return "certificate"
    return "unknown"


def _policy_state(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    if text in ("enabled", "active", "on"):
        return "enabled"
    if text in ("disabled", "inactive", "off"):
        return "disabled"
    if text in ("report_only", "reportonly", "enabledforreportingbutnotenforced", "audit"):
        return "report_only"
    return "unknown"


def _names(value: Any) -> tuple[str, ...]:
    return tuple(sorted({safe_text(item, limit=200) for item in _as_list(value)[:500] if str(item).strip()}))
