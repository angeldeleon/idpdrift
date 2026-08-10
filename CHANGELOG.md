# Changelog

Notable changes to idpdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Entra: application permissions were never rated.** `appRoleAssignments`
  names a granted permission by the GUID of the app role, and that GUID was
  recorded as the scope. Every rule downstream matches on the value, so
  `app_permission_high_impact` matched nothing against a real tenant — an
  application holding `Mail.Read` as an app-only permission produced no finding,
  and a drift line named a GUID. The name is now resolved from the resource
  application's published roles, which the service principal walk already
  fetches. A permission that cannot be resolved is reported as indeterminate
  rather than rated on its id.
- **Entra: eligible role assignments read as standing.** The eligibility join
  compared `directoryRole.id` against `roleDefinitionId`; those are different
  GUIDs, so it matched nothing in any tenant. With `policy.expect_just_in_time`
  set, every activated just-in-time assignment was reported as permanent, and
  `role_assignment_elevated` could never fire. The join now uses
  `roleTemplateId`.
- **Entra: `isPasswordlessCapable` is not phishing resistance.** Microsoft
  counts Authenticator passwordless phone sign-in as passwordless, and a push
  approval is relayed by every off-the-shelf phishing proxy. Phishing resistance
  is now derived from `methodsRegistered` against the catalog, so a privileged
  account whose strongest method is a push is reported again.
- **Okta: a locked-out account is not a disabled one.** `LOCKED_OUT` is what a
  mistyped password produces and it clears on unlock, but it was read as
  deactivated — producing `disabled_with_role`, with leaver-process remediation,
  against administrators who were at their desks.
- **`okta.users.read` was classified as a mail scope**, so an integration that
  reads user profiles produced a high-severity finding claiming it could read
  the organisation's correspondence.
- **Allow lists matched attacker-chosen display names.**
  `policy.approved_applications` and `policy.ignore_applications` matched the
  application display name, so registering an application called
  `Atlassian Cloud` removed it from the report *and* from the baseline the drift
  rule reads. Both now match object ids and application ids only.
- **A per-account "could not count groups" read as zero.** `group_membership`
  coverage says the source can count groups in general; whether it returned a
  count for one account is a separate answer. An uncounted account suppressed
  the guest allowance finding and persisted a fabricated zero, so the next run
  reported the guest as having joined every group they were already in.
- **Report files followed a symlink.** A report is the same inventory of
  privileged access the state file is, and it is usually written to a shared
  artefact directory; a symlink at the output path redirected it and had the
  `0600` tightening applied to the attacker's target. The write now uses
  `O_NOFOLLOW` and fails rather than following.
- **Conditional access exclusions carried raw account identifiers** into
  reports, alerts and webhook payloads, contrary to PRIVACY.md. Excluded users
  are pseudonymised like any other account identifier; excluded groups and roles
  stay legible.
- **A scripted credential rotation reported itself twice** — twenty-five
  high-severity lines and then an aggregate line saying it was a rotation. The
  credential drift rule is now either/or, as the role and grant rules already
  were.
- **Slack alerts let a workload name format itself.** A finding's subject is the
  application display name for a workload, and it was interpolated into an
  mrkdwn field where `*RESOLVED*` renders as bold. mrkdwn has no backslash
  escape, so the subject is now emitted inside a code span.
- **The tool's own prose rendered with visible backslashes.** Markdown escaping
  is applied to finding text because that text interpolates directory-chosen
  names; strings such as `account(s)` and parenthesised coverage notes came out
  as `account\(s\)`. Rewritten to avoid the metacharacters.

### Removed

- `catalog.is_privileged_role`, `CheckContext.baseline`, `AccessPolicy.exclusions`
  and two re-exported but unused imports, none of which had a caller.

## [0.1.0] — 2026-08-10

First release.

Reads identity and access state from Microsoft Entra ID, Okta, or an exported
JSON snapshot; compares it against a stored baseline; and reports what changed.
Seven checks covering privileged role assignments, authentication strength,
dormancy, service principal credentials and permissions, OAuth consent grants,
external identities, and conditional access policy. Slack, webhook and email
notification. Markdown, JSON and HTML output. Pseudonymised by default.

Three design decisions are worth naming, because they are what the rest of the
tool is built around and they are the things a fork should not undo:

- **Present, absent, or could-not-determine.** Identity APIs return the same
  shape of answer for "this account has no second factor" and "you may not see
  this account's second factors". Nothing here collapses the second into the
  first: an unreadable facet produces no posture finding, produces an operational
  finding saying so, and is merged over the baseline rather than replacing it.
  `idpdrift coverage` prints what a deployment can actually see.
- **Severity from a table.** Every finding names an issue; the band comes from
  `severity.BASE_SEVERITY` adjusted by role tier and by determination, both
  bounded. Every finding carries a one-line derivation, so a disputed rating can
  be argued about specifically.
- **Credentials redacted where findings are built.** `Finding.__post_init__`
  scrubs secret-shaped keys and `Credential.from_raw` never accepts key material,
  rather than filtering at the four output sinks — because the fifth sink will
  not remember.

See the [README](README.md) for what each check covers and where the known
limitations are, and [PRIVACY.md](PRIVACY.md) for exactly what is collected.

[0.1.0]: https://github.com/angeldeleon/idpdrift/releases/tag/v0.1.0
