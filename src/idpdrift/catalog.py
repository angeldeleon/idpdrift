"""What counts as privileged, and what counts as a high-impact permission.

Two curated tables, and one heuristic that is honest about being one.

Every key is passed through :func:`idpdrift.validation.normalize_key` at import,
so ``Global Administrator``, ``GlobalAdministrator`` and ``global-administrator``
all resolve to the same entry. Providers spell their own role names differently
between APIs, between API versions and between the portal and the wire; a table
that matched only one spelling would read as coverage on the tin and detect
nothing. The CI invariants job asserts that no entry normalises to the empty
string, because such an entry is unreachable and would sit here looking useful.

The tables are deliberately conservative about *tier*, not about membership.
Listing a role is cheap; rating a reports reader as tenant-admin is how a report
gets ignored, and then the genuine Global Administrator grant gets ignored with
it.
"""

from __future__ import annotations

from .models import Determination, PrincipalKind
from .severity import RoleTier
from .validation import normalize_key

# --------------------------------------------------------------------------
# Directory roles
# --------------------------------------------------------------------------

# Microsoft Entra ID built-in directory roles. Names as Microsoft spells them in
# the portal; the normalisation handles the wire spellings.
_ENTRA_ROLES: dict[str, RoleTier] = {
    "Global Administrator": RoleTier.TENANT_ADMIN,
    "Company Administrator": RoleTier.TENANT_ADMIN,  # the legacy wire name for the above
    "Privileged Role Administrator": RoleTier.TENANT_ADMIN,
    "Privileged Authentication Administrator": RoleTier.TENANT_ADMIN,
    "Partner Tier2 Support": RoleTier.TENANT_ADMIN,
    "Application Administrator": RoleTier.PRIVILEGED,
    "Cloud Application Administrator": RoleTier.PRIVILEGED,
    "Hybrid Identity Administrator": RoleTier.PRIVILEGED,
    "Domain Name Administrator": RoleTier.PRIVILEGED,
    "User Administrator": RoleTier.PRIVILEGED,
    "Authentication Administrator": RoleTier.PRIVILEGED,
    "Conditional Access Administrator": RoleTier.PRIVILEGED,
    "Security Administrator": RoleTier.PRIVILEGED,
    "Exchange Administrator": RoleTier.PRIVILEGED,
    "SharePoint Administrator": RoleTier.PRIVILEGED,
    "Helpdesk Administrator": RoleTier.PRIVILEGED,
    "Password Administrator": RoleTier.PRIVILEGED,
    "Directory Writers": RoleTier.PRIVILEGED,
    "Partner Tier1 Support": RoleTier.PRIVILEGED,
    "Groups Administrator": RoleTier.SENSITIVE,
    "Intune Administrator": RoleTier.SENSITIVE,
    "Teams Administrator": RoleTier.SENSITIVE,
    "Billing Administrator": RoleTier.SENSITIVE,
    "Compliance Administrator": RoleTier.SENSITIVE,
    "Security Operator": RoleTier.SENSITIVE,
    "Global Reader": RoleTier.SENSITIVE,
    "Security Reader": RoleTier.SENSITIVE,
    "Reports Reader": RoleTier.STANDARD,
    "Directory Readers": RoleTier.STANDARD,
    "Message Center Reader": RoleTier.STANDARD,
}

# Okta administrator roles.
_OKTA_ROLES: dict[str, RoleTier] = {
    "Super Administrator": RoleTier.TENANT_ADMIN,
    "SUPER_ADMIN": RoleTier.TENANT_ADMIN,
    "Organization Administrator": RoleTier.PRIVILEGED,
    "ORG_ADMIN": RoleTier.PRIVILEGED,
    "Application Administrator": RoleTier.PRIVILEGED,
    "APP_ADMIN": RoleTier.PRIVILEGED,
    "API Access Management Administrator": RoleTier.PRIVILEGED,
    "API_ACCESS_MANAGEMENT_ADMIN": RoleTier.PRIVILEGED,
    "User Administrator": RoleTier.PRIVILEGED,
    "USER_ADMIN": RoleTier.PRIVILEGED,
    "Help Desk Administrator": RoleTier.PRIVILEGED,
    "HELP_DESK_ADMIN": RoleTier.PRIVILEGED,
    "Group Administrator": RoleTier.SENSITIVE,
    "GROUP_ADMIN": RoleTier.SENSITIVE,
    "Group Membership Administrator": RoleTier.SENSITIVE,
    "GROUP_MEMBERSHIP_ADMIN": RoleTier.SENSITIVE,
    "Mobile Administrator": RoleTier.SENSITIVE,
    "MOBILE_ADMIN": RoleTier.SENSITIVE,
    "Report Administrator": RoleTier.STANDARD,
    "REPORT_ADMIN": RoleTier.STANDARD,
    "Read Only Administrator": RoleTier.STANDARD,
    "READ_ONLY_ADMIN": RoleTier.STANDARD,
}

ROLE_TIERS: dict[str, RoleTier] = {
    normalize_key(name): tier for name, tier in {**_ENTRA_ROLES, **_OKTA_ROLES}.items()
}

# Roles at or above this tier are what "privileged" means throughout the tool.
PRIVILEGED_TIERS = frozenset({RoleTier.TENANT_ADMIN, RoleTier.PRIVILEGED})


def role_tier(role_name: str) -> RoleTier:
    """Tier for a role name, defaulting to STANDARD for anything unlisted.

    Defaulting downward is the deliberate choice. A custom role called
    ``Reporting - Finance`` is far more likely to be mundane than to be a
    tenant-admin equivalent, and rating every unrecognised role as privileged
    would put most of a real directory into the report on day one. The cost is
    that a genuinely powerful custom role reads as standard until someone adds
    it, which is why ``policy.privileged_roles`` exists in config.
    """
    return ROLE_TIERS.get(normalize_key(role_name), RoleTier.STANDARD)


# --------------------------------------------------------------------------
# Application permissions
# --------------------------------------------------------------------------

# Application (app-only) permissions that let a workload act across the whole
# tenant with no user present. Value is the sentence that appears in the
# finding, so it says what the permission *does* rather than repeating its name.
_HIGH_IMPACT: dict[str, str] = {
    "RoleManagement.ReadWrite.Directory": (
        "grants and revokes directory roles, so the holder can make itself Global Administrator"
    ),
    "AppRoleAssignment.ReadWrite.All": (
        "assigns application permissions to any application, which is the same escalation one step removed"
    ),
    "Directory.ReadWrite.All": "creates and modifies any directory object, including role-holding accounts",
    "Application.ReadWrite.All": (
        "adds credentials to any application registration, which is persistent access to whatever they hold"
    ),
    "Policy.ReadWrite.ConditionalAccess": "edits the conditional access policies that gate every sign-in",
    "PrivilegedAccess.ReadWrite.AzureADGroup": "activates privileged access group membership",
    "User.ReadWrite.All": "modifies any user, including their authentication methods",
    "Group.ReadWrite.All": "modifies any group, including groups that confer role assignments",
    "GroupMember.ReadWrite.All": "adds any principal to any group, including role-assignable groups",
    "Mail.ReadWrite": "reads and writes every mailbox in the tenant",
    "Mail.Read": "reads every mailbox in the tenant",
    "Mail.Send": "sends mail as any user, which is internal phishing with perfect provenance",
    "MailboxSettings.ReadWrite": "sets mailbox rules and forwarding on any mailbox",
    "Files.ReadWrite.All": "reads and writes every file in OneDrive and SharePoint",
    "Files.Read.All": "reads every file in OneDrive and SharePoint",
    "Sites.FullControl.All": "takes full control of every SharePoint site",
    "Sites.ReadWrite.All": "reads and writes every SharePoint site",
    "Chat.Read.All": "reads every Teams chat in the tenant",
    "DeviceManagementConfiguration.ReadWrite.All": (
        "changes device configuration, which on most estates means running code on managed endpoints"
    ),
    "UserAuthenticationMethod.ReadWrite.All": (
        "registers authentication methods for any user, which is account takeover without a password"
    ),
    # Okta
    "okta.users.manage": "creates and modifies every user, including their credentials",
    "okta.roles.manage": "grants administrator roles, so the holder can make itself a super administrator",
    "okta.apps.manage": "modifies every application integration, including their credentials",
    "okta.groups.manage": "modifies every group, including groups that confer administrator roles",
    "okta.policies.manage": "edits the sign-on policies that gate every authentication",
    "okta.sessions.manage": "creates and revokes sessions for any user",
}

HIGH_IMPACT_SCOPES: dict[str, str] = {normalize_key(scope): why for scope, why in _HIGH_IMPACT.items()}

# Scopes that read a person's correspondence or documents. Reported separately
# because "an application can read all mail" is the sentence that gets an
# incident opened, and it is worth saying even when the scope is delegated.
#
# Every entry has to actually read mail. Okta's `okta.users.read` was on this
# list and reads user *profiles* — name, login, status — which is a directory
# read and not correspondence. It produced a high-severity finding telling the
# reader an integration could read their organisation's mail, on an org where no
# such thing had been granted. A check that is confidently wrong about what a
# scope does is worse than one that stays quiet: it costs an investigation and
# then it costs the reader's trust in the rest of the report.
_MAIL_SCOPES = (
    "Mail.Read",
    "Mail.ReadBasic",
    "Mail.ReadBasic.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.Read",
    "MailboxSettings.ReadWrite",
    "IMAP.AccessAsUser.All",
    "POP.AccessAsUser.All",
)

_FILE_SCOPES = (
    "Files.Read",
    "Files.Read.All",
    "Files.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
)

MAIL_SCOPES: frozenset[str] = frozenset(normalize_key(s) for s in _MAIL_SCOPES)
FILE_SCOPES: frozenset[str] = frozenset(normalize_key(s) for s in _FILE_SCOPES)


def scope_impact(scope: str) -> str | None:
    """Why a scope is high-impact, or ``None`` if it is not on the list."""
    return HIGH_IMPACT_SCOPES.get(normalize_key(scope))


def reads_mail(scope: str) -> bool:
    return normalize_key(scope) in MAIL_SCOPES


def reads_files(scope: str) -> bool:
    return normalize_key(scope) in FILE_SCOPES


# --------------------------------------------------------------------------
# Non-human accounts
# --------------------------------------------------------------------------

# Substrings that suggest an account is a workload rather than a person. This is
# a heuristic and is treated as one: it can only ever produce PRESENT or UNKNOWN,
# never ABSENT, because "this name does not look like a service account" is not
# evidence that a person is behind it. Naming conventions are an organisational
# habit, not a fact the directory records.
_NON_HUMAN_TOKENS = frozenset(
    {
        "svc",
        "service",
        "srv",
        "sa",
        "automation",
        "automated",
        "bot",
        "daemon",
        "sync",
        "connector",
        "integration",
        "pipeline",
        "runner",
        "agent",
        "scanner",
        "backup",
        "noreply",
        "system",
        "api",
        "app",
        "robot",
        "rpa",
    }
)


def looks_non_human(*, kind: PrincipalKind, display: str, upn: str = "") -> Determination:
    """Is this principal a workload rather than a person?

    Returns PRESENT when the directory says so outright, PRESENT when the naming
    convention says so, and UNKNOWN otherwise. It never returns ABSENT: the only
    thing a human-looking name proves is that someone chose a human-looking name,
    and an attacker creating a persistence account will choose one deliberately.

    Callers use this to *raise* attention on an assignment, never to dismiss one.
    """
    if kind in (PrincipalKind.SERVICE_PRINCIPAL, PrincipalKind.SERVICE_ACCOUNT):
        return Determination.PRESENT
    if kind.is_human:
        # The directory has told us this is a person. A naming convention does
        # not get to overrule that.
        return Determination.ABSENT

    # The local part is split out separately because `svc-backup@corp.example`
    # normalises as one run otherwise, and the domain contributes nothing.
    local_part = upn.split("@", 1)[0] if "@" in upn else upn
    tokens = {token for token in normalize_key(f"{display} {local_part}").split() if token}
    if tokens & _NON_HUMAN_TOKENS:
        return Determination.PRESENT
    return Determination.UNKNOWN


# --------------------------------------------------------------------------
# Authentication methods
# --------------------------------------------------------------------------

# Methods bound to an origin, so a reverse proxy sitting between the user and
# the identity provider cannot replay them. This is the only property that
# survives contact with modern phishing kits: everything else on the list below
# is a code the user can be talked into typing into the wrong window.
_PHISHING_RESISTANT = (
    "fido2",
    "fido2SecurityKey",
    "webauthn",
    "u2f",
    "passKeyDeviceBound",
    "passKeyDeviceBoundAuthenticator",
    "passKeyDeviceBoundWindowsHello",
    "windowsHelloForBusiness",
    "smartcard",
    "piv",
    "certificateBasedAuthentication",
    "x509Certificate",
)

# Second factors that are delivered to a phone number or a mailbox. A phone
# number is transferable by anyone who can convince a carrier's retention desk,
# and a mailbox is usually protected by the very account being defended.
_WEAK_METHODS = (
    "sms",
    "mobilePhone",
    "alternateMobilePhone",
    "voiceCall",
    "call",
    "voice",
    "officePhone",
    "email",
    "emailAuthentication",
)

PHISHING_RESISTANT_METHODS: frozenset[str] = frozenset(normalize_key(m) for m in _PHISHING_RESISTANT)
WEAK_METHODS: frozenset[str] = frozenset(normalize_key(m) for m in _WEAK_METHODS)


def is_phishing_resistant(method: str) -> bool:
    return normalize_key(method) in PHISHING_RESISTANT_METHODS


def is_weak_method(method: str) -> bool:
    return normalize_key(method) in WEAK_METHODS
