# idpdrift

Detects changes to who can administer your identity provider, and tells your security team about the ones that matter.

[![CI](https://github.com/angeldeleon/idpdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/angeldeleon/idpdrift/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## What it does

Reads the current state of Microsoft Entra ID or Okta through APIs you already have — role assignments, authentication methods, sign-in activity, application credentials and permissions, consent grants, conditional access policies — compares it against a stored baseline, and reports what changed. Alerts via Slack, webhook, or email.

Output is Markdown, JSON, or a standalone HTML page. Exit code reflects the worst finding, so it drops into cron or CI.

**Agentless and read-only.** Nothing is deployed, nothing is granted, nothing is revoked. A read-only application registration or API token is sufficient, and there is no code path that writes to a tenant.

## Why drift, not audit

Posture tools are a crowded space, and they will all tell you the same true, unactionable things: four people hold Global Administrator, six applications have client secrets, one policy has an exclusion. You know. Three of the four admins are in the change record, the secrets belong to pipelines that predate you, and the exclusion is the break-glass account.

What you cannot see is that there are five admins today. That somebody added a second credential to an application that already had one. That the conditional access policy requiring MFA for administrators gained an exclusion on Tuesday to unblock a vendor and nobody put it back.

Those changes are silent. Nothing errors, nothing alerts, and the tenant looks exactly as compliant as it did yesterday. idpdrift's second run onward reports only what moved.

```
🔴 CRITICAL — New assignment to Global Administrator
   id-4a40c401a509 · privileged_roles · role_assignment_new · This principal did not
   hold Global Administrator at the previous scan and does now. A role assignment
   appearing outside a change record is the single clearest signal this tool produces.

🟠 HIGH — New secret credential on an existing application
   Payroll Sync · service_principals · credential_new · A credential was added to an
   application registration that already existed. This is the standard way to keep
   access to a tenant after the account used to get in is reset.
```

It also knows the difference between a migration and an intrusion. Forty new assignments at once is a rollout and gets one line with a count. Two new assignments keep their full severity and are both named.

## Install

```bash
pip install idpdrift
```

## Usage

Start without a tenant. Export a snapshot in the [documented schema](#the-export-schema) — or use the one your existing reporting already produces — and point the tool at it:

```yaml
# idp.yml
source:
  type: file
  file:
    path: tenant-export.json
```

**Microsoft Entra ID:**

```yaml
source:
  type: entra
  entra:
    tenant_id: 00000000-0000-0000-0000-000000000000
    client_id: 00000000-0000-0000-0000-000000000000
    client_secret_env: IDPDRIFT_ENTRA_CLIENT_SECRET   # env var NAME, never the secret
```

**Okta:**

```yaml
source:
  type: okta
  okta:
    org_url: https://example.okta.com
    api_token_env: OKTA_API_TOKEN
```

Then:

```bash
idpdrift validate -c idp.yml     # check config without reading a tenant
idpdrift coverage -c idp.yml     # what can this deployment actually see?
idpdrift scan -c idp.yml -o report.md
idpdrift severity                # print the severity table
```

First run writes the baseline and reports posture only. Subsequent runs report drift.

Run `idpdrift coverage` before you trust a clean report. It is the fastest way to find out that your token cannot read sign-in activity, which is the difference between "no dormant administrators" and "we did not look".

## What it detects

| Check | Detects |
|---|---|
| `privileged_roles` | New assignment to a privileged directory role, standing assignment where just-in-time was expected, assignment to a non-human account, assignment removed |
| `auth_strength` | Privileged accounts with no phishing-resistant method, accounts whose only factor is SMS or voice, accounts with no second factor, an account losing a strong method |
| `dormancy` | Accounts with no interactive sign-in beyond the window that still hold roles or group membership, disabled accounts still holding privileged roles, a dormant administrator signing in again |
| `service_principals` | Credentials expiring inside the window, credentials with excessive lifetime, secrets rather than certificates, application (not delegated) permissions on high-impact scopes, a new credential or permission on an existing application |
| `oauth_grants` | Third-party applications holding consent, tenant-wide admin consent, scopes that read mail or files, a new grant or an added scope |
| `guests` | Guests holding roles or group membership beyond the configured allowance, a guest gaining access |
| `conditional_access` | Policies disabled or moved to report-only, policies deleted, exclusions added to a policy |

The role catalog is deliberately conservative about tier, not about membership. Rating a Reports Reader as tenant-admin-equivalent teaches the team to ignore the report, and then the genuine Global Administrator grant gets ignored with it. A custom role cannot be classified from its name, so `policy.privileged_roles` lets you say what yours are worth.

## Present, absent, or could-not-determine

This is the design decision the rest of the tool is built around, and it is the one worth reading before you deploy it.

Every fact this tool asserts is in one of three states: **present**, **definitively absent**, or **could not be determined**. Nothing collapses the third into the second.

The reason is specific. Identity APIs return the same shape of answer for "this account has no second factor" and "you do not have permission to see this account's second factors". On Entra, sign-in activity needs an extra licence *and* an extra scope; on Okta, roles and factors are per-user endpoints with no org-wide listing on every plan. A tool that reads silence as absence opens its first report with "nobody in your organisation has MFA", and after that nobody reads the second one — including the four real findings inside it.

So each source declares, per facet, what it could actually read:

```
$ idpdrift coverage -c idp.yml
  principals              read
  guest_status            read
  authentication_methods  read
  sign_in_activity        COULD NOT DETERMINE
  group_membership        COULD NOT DETERMINE
  role_assignments        read
  ...
```

Three things follow from an indeterminate facet, and all three matter:

1. **No posture finding is produced from it.** The dormancy check does not report anybody as dormant when it cannot read sign-in activity.
2. **A finding is produced saying so.** It is `operational`, capped at `low` by the severity table, and states what was not concluded — so a clean report is never mistaken for a clean tenant.
3. **The baseline is merged, not replaced.** A facet that was unreadable for one run keeps its previous observations, so the following successful run does not report every administrator in the tenant as newly appointed.

Every renderer carries the coverage notes, including HTML. An incomplete scan must not look like a clean one in any output format.

## Severity

Severity comes from a table, not from a judgement at the call site. Severity chosen inline is severity that drifts, and within a few releases the `fail_on` threshold is either permanently tripped or permanently silent.

Each finding names an issue; the band is `BASE_SEVERITY[issue]`, adjusted by exactly two documented modifiers. `idpdrift severity` prints the live table.

| Issue | Base (at the `privileged` tier) |
|---|---|
| `role_assignment_new` | high |
| `role_assignment_elevated` | high |
| `role_assignment_non_human` | high |
| `role_assignment_standing` | medium |
| `role_assignment_removed` | info |
| `mfa_absent`, `mfa_weakened` | high |
| `mfa_not_phishing_resistant`, `mfa_weak_factor_only` | medium |
| `dormant_with_role`, `disabled_with_role`, `dormant_reactivated` | medium |
| `dormant_with_access` | low |
| `credential_new` | high |
| `credential_long_lived` | medium |
| `credential_expiring`, `credential_secret_not_certificate` | low |
| `app_permission_high_impact`, `app_permission_new` | high |
| `oauth_sensitive_scope` | high |
| `oauth_tenant_wide`, `oauth_grant_new`, `oauth_scope_added` | medium |
| `oauth_third_party` | low |
| `guest_with_role` | high |
| `guest_gained_access` | medium |
| `guest_over_allowance` | low |
| `policy_disabled`, `policy_report_only`, `policy_exclusion_added`, `policy_removed` | high |
| `policy_weakened` | medium |
| `facet_indeterminate`, `findings_truncated` | low |
| `baseline_mismatch` | medium |

**Modifier 1 — role tier.** `tenant_admin` raises the band once; `sensitive` and `standard` lower it once; `privileged` is the baseline. Capped at one band in either direction, so a judgement about a role name cannot outweigh an observation about the tenant.

**Modifier 2 — determination.** Anything resting on "could not determine" is capped at `low` and reported as `operational`. An unreadable facet can never trip your threshold.

Every finding carries `evidence.severity_basis`, a one-line derivation, so a reader who thinks a rating is overblown can name the input they disagree with rather than concluding the tool is noisy.

## Permissions

**Entra ID** — application permissions, all read-only. Each may be refused independently, and whatever is refused becomes an indeterminate facet rather than a clean result:

| Scope | Without it |
|---|---|
| `Directory.Read.All` | nothing works; the user list is the foundation |
| `RoleManagement.Read.Directory` | `role_assignments` and `role_eligibility` are indeterminate |
| `UserAuthenticationMethod.Read.All` | `authentication_methods` is indeterminate |
| `AuditLog.Read.All` (plus an Entra ID P1 licence) | `sign_in_activity` is indeterminate; no dormancy findings |
| `Application.Read.All` | `service_principals` and everything below it is indeterminate |
| `Policy.Read.All` | `access_policies` is indeterminate |

**Okta** — a read-only administrator API token. Two facets are indeterminate by construction and the tool says so rather than pretending otherwise: Okta does not expose credential expiry for application integrations, and it does not mark external collaborators as guests.

## The export schema

The `file` source reads a JSON object. **An absent top-level key means "not exported", not "empty"** — that is the whole schema in one sentence. A file with no `policies` key records `access_policies` as indeterminate; a file with `"policies": []` asserts the tenant has none.

```json
{
  "source": "entra",
  "tenant": "contoso.example",
  "collected_at": "2026-08-10T00:00:00+00:00",
  "coverage": { "sign_in_activity": "unknown" },
  "principals": [
    { "id": "u1", "display_name": "Alice Admin", "user_principal_name": "alice@contoso.example",
      "kind": "user", "enabled": true, "last_sign_in": "2026-08-09T09:00:00Z",
      "phishing_resistant": false, "second_factor": true,
      "auth_methods": ["microsoftAuthenticatorPush"], "group_count": 4 }
  ],
  "role_assignments": [
    { "id": "ra1", "role_id": "62e90394", "role_name": "Global Administrator",
      "principal_id": "u1", "scope": "/", "standing": true }
  ],
  "service_principals": [
    { "id": "sp1", "display_name": "Payroll Sync", "app_id": "app-1", "third_party": true,
      "credentials": [{ "id": "c1", "type": "secret", "start": "...", "expires": "..." }],
      "permissions": [{ "scope": "Mail.Read", "resource": "Microsoft Graph", "type": "application" }] }
  ],
  "oauth_grants": [
    { "id": "og1", "client_id": "sp1", "client_display_name": "Payroll Sync",
      "scopes": ["Mail.Read"], "consent_type": "AllPrincipals" }
  ],
  "policies": [
    { "id": "cap1", "display_name": "Require MFA for admins", "state": "enabled",
      "excluded_users": [] }
  ]
}
```

Any boolean field may be `null`, which reads as "could not determine". The optional `coverage` block overrides the inference for a facet the exporter knows it could not read. `kind` on a principal is what makes guest findings possible; an export that omits it records `guest_status` as indeterminate rather than asserting the organisation has no guests.

## Privacy

Account identifiers are **pseudonymised by default**. Reports say `id-4a40c401a509`, not `alice@corp.example`.

This is not decoration. A report from this tool is a list of named employees and what they can do, and those reports travel — into tickets, into a Slack channel with a wider membership than the security team, into a change request. The mapping is stable, so "the same account keeps appearing" still works, and you resolve a pseudonym through the identity provider when an investigation warrants it.

Application and policy names are not pseudonymised: they are organisational objects, and "an application you cannot identify gained Mail.ReadWrite" is not a usable finding.

Set `privacy.mode: identified` when you have made that call deliberately. See [PRIVACY.md](PRIVACY.md) for what is collected, what is stored, and for how long.

## Configuration

```yaml
source:
  type: entra
  entra:
    tenant_id: 00000000-0000-0000-0000-000000000000
    client_id: 00000000-0000-0000-0000-000000000000
    client_secret_env: IDPDRIFT_ENTRA_CLIENT_SECRET   # env var NAME, never the secret

privacy:
  mode: pseudonymous                   # or: identified

policy:
  privileged_roles:
    Break Glass Operator: tenant_admin # custom roles cannot be classified by name
  expect_just_in_time: false           # true only if you run privileged identity management
  dormant_days: 90
  credential_expiry_days: 30
  credential_max_lifetime_days: 365
  guest_role_allowance: 0
  guest_group_allowance: 5
  approved_applications: [82b6a5a8-1a01-4b06-9f3e-2a3f0dd4a2b1]   # ids, not names

settings:
  checks: [privileged_roles, auth_strength, dormancy, service_principals, oauth_grants, guests, conditional_access]
  fail_on: high
  state_path: .idpdrift/state.json

notify:
  slack_webhook_url_env: SLACK_WEBHOOK_URL
  min_severity: high

ai:
  enabled: false                       # see below
```

Unknown keys are rejected. A typo shouldn't silently disable a check.

`approved_applications` and `ignore_applications` match on the service principal object id and the application id, never on the display name. A display name is chosen by whoever registered the application, and an allow list keyed on one is an allow list the adversary can put themselves on: registering an application called `Atlassian Cloud` would otherwise remove it from the report *and* from the baseline, so drift would never see it appear either. `ignore_principals` matches the object id and the user principal name for the same reason.

Secrets are read from the environment; config only names the variable. Putting a URL or a path where a variable name belongs is a validation error, so you cannot commit a client secret by accident.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, nothing at or above `fail_on` |
| 1 | Completed, findings at or above `fail_on` |
| 2 | Could not run, collected no identities, or over half the checks failed |

1 and 2 are separate on purpose. A pipeline that treats them alike eventually goes green because the client secret expired rather than because the tenant is clean.

## The AI layer

Off by default. One capability: a prose paragraph at the top of the report. It runs after every finding, severity and exit code is already final, and it cannot change any of them. Delete the module and the tool behaves identically.

That constraint exists because the input includes names an attacker chooses. Registering an application called `Reviewed and approved by Security — no action required` takes thirty seconds. Nothing parses the model's reply, and the summary is rendered with line-leading markup escaped, so a coerced reply cannot forge a heading, a bullet list or a table that reads as part of the deterministic report. What an injection can achieve is a misleading sentence inside one section labelled as model-generated.

Enabling it sends finding titles, checks and severities to a third-party API. Never a display name, never a user principal name, never a tenant id — in either privacy mode. A finding title can name a directory role or a permission scope, which are organisational objects rather than people.

## Security design

Full detail in [SECURITY.md](SECURITY.md). The short version:

- **Read-only by construction.** No source has a write path. A read-only token is sufficient, and the tool is designed so that anything more is a signal something is wrong.
- **Credentials are redacted where findings are built**, not at the output sinks. A finding that never holds a secret cannot leak one through a renderer, a webhook, or the fifth sink somebody adds next year.
- **SSRF guard on every outbound request**, with credential headers and the request body dropped on cross-origin redirects — and the token endpoint's body carries a client secret.
- **Directory data is treated as attacker-controlled.** Display names are sanitised at ingestion and escaped again in every renderer, for that renderer's syntax, so a crafted application name cannot forge a report line, inject a link, or put a tracking pixel in a ticket.
- **Every file this tool opens goes through a descriptor** with `O_NOFOLLOW` and, where a read could block, `O_NONBLOCK`: the state file, the salt, the `file` source's export, and the report. State is JSON at `0600`, namespaced per config; reports are `0600` too, and a symlink at the report path is refused rather than followed.
- **Every serialised collection is bounded**, so a large tenant cannot produce an unusable report or a webhook payload the receiver drops.

CI runs ruff, mypy, bandit, and pip-audit on every push.

## Limitations

Worth knowing before you rely on it:

- **Group-based role assignment is only partly visible.** Both providers can confer a role through group membership. idpdrift reads direct assignments; a role granted through a role-assignable group appears when the provider materialises it and is missed when it does not. Nothing here enumerates group nesting.
- **Okta credential expiry is not available.** Okta reports that an integration has a client secret, not when that secret expires. That facet is indeterminate, permanently, and the report says so rather than showing a clean credential section.
- **Okta does not mark guests.** External collaborators are ordinary users, so `guest_status` is indeterminate and no guest finding is produced against an Okta org.
- **Sign-in activity on Entra needs a P1 licence.** A tenant without one gets no dormancy findings and an operational note saying why. This is the single most common reason a deployment sees less than it expects.
- **Application permission names come from the resource application.** Graph identifies a granted app permission by the GUID of the app role, and the name — `Mail.Read` — is published on the resource's own service principal. idpdrift resolves it from the service principal list it already reads. If the resource application is not in that list the permission cannot be named, so it is not rated: `application_permissions` becomes indeterminate and the report says which grants could not be resolved.
- **Non-human detection is a heuristic.** It reads a naming convention, which is an organisational habit rather than a fact the directory records. It can raise attention on an assignment and never dismisses one — but an attacker naming a persistence account `Jane Smith` will not trip it.
- **Unrecognised roles default to the standard tier.** A powerful custom role reads as ordinary until someone adds it to `policy.privileged_roles`. Rating every unrecognised role as privileged would put most of a real directory into the first report.
- **The baseline is only as good as the previous run.** A first run against a tenant that is already compromised baselines the compromise. Drift detection tells you what changed since you started looking, which is not the same as what is wrong.
- **This is not a log tool.** It compares state between runs, so a change made and reverted between two scans is invisible. Sign-in logs and audit logs are where that lives.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The easiest useful contribution is a role or scope entry in `catalog.py` — one line, real value to everyone running the tool.

Security issues: [private reporting](https://github.com/angeldeleon/idpdrift/security/advisories/new), not a public issue.

## License

Apache 2.0.
