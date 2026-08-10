# Privacy

idpdrift processes directory data about named employees: who they are, when they last signed in, how they authenticate, and what they can do. In the EU and UK that is personal data under GDPR without qualification — a user principal name is an identifier and frequently a job title in one string — and in several jurisdictions the last-sign-in field in particular is workplace monitoring data before it is a security control.

This document states exactly what the tool collects, what it stores, and for how long, so you can answer those questions without reading the source. If your deployment needs a data protection impact assessment, this is the input for it.

## What is collected

Only what the checks need. `idpdrift coverage -c idp.yml` prints exactly which of these a given deployment could actually read.

| Field | Why |
|---|---|
| Account id, display name, user principal name | Correlating a finding to an account, and resolving a pseudonym when an investigation warrants it |
| Enabled state | A disabled account still holding a privileged role is a finding |
| Last interactive sign-in | Dormancy. This is the field with the strongest workplace-monitoring character; see below |
| Account type (member or guest) | External identities are assessed against a separate allowance |
| Registered authentication methods | The whole authentication-strength check |
| Group membership **count** | How far an account's access reaches. The tool does not collect group names or membership lists |
| Role assignments and their scope | The reason the tool exists |
| Application registrations, their credential metadata and their permissions | Workload identity findings |
| OAuth consent grants and their scopes | Illicit consent detection |
| Conditional access policies and their exclusion lists | Policy posture and drift |

## What is deliberately not collected

There is no code path that reads any of these, and no way to add one through configuration:

- Sign-in logs, audit logs, or any individual sign-in event beyond the single "last sign-in" timestamp
- Mailbox contents, files, chats, or any data an application permission grants access to — the tool reports that a permission exists, never exercises it
- Device inventory, location, IP addresses, or user agents
- Group names or membership lists (only a count per account)
- Credential material of any kind. `Credential.from_raw` never accepts `secretText` or a private key into the object, and Okta's inline `client_secret` is dropped at parse time

The endpoints each source reads are fixed in the source modules and reviewed in-tree. `config.py` has no key that accepts an API path, an endpoint or a query fragment. If a pull request adds an endpoint, it must state what new data it collects and why the finding it enables justifies that collection. That trade is the point of the review.

## Pseudonymisation

**Default mode: `pseudonymous`.** Account identifiers are replaced with stable labels like `id-4a40c401a509` in every report, alert, and webhook payload.

The mechanism is HMAC-SHA256 under a locally generated 32-byte salt:

- **Deterministic**, so drift detection and "the same account keeps appearing" both work.
- **Not reversible** by anyone holding a report but not the salt — which matters, because these reports get pasted into tickets and posted to channels with a wider membership than the security team.
- **Not enumerable**, unlike a plain hash. A directory of ten thousand `firstname.lastname@company.com` addresses is a trivially small space to brute-force a bare SHA-256 over.

The salt is stored beside the state file at mode `0600`. Deleting it makes every previously issued pseudonym permanently unresolvable and resets the baseline — which is the correct behaviour for a "forget this tenant" request.

Application, workload, group and policy names are **not** pseudonymised. They are organisational objects rather than people, and "an application you cannot identify gained Mail.ReadWrite" is not a finding anybody can act on.

A conditional access policy's exclusion list names the accounts exempt from it by directory object id, which *is* an account identifier — one lookup resolves it to a person. Those entries are pseudonymised like any other account identifier, so an exclusion-added finding says which exemption appeared without naming who. Excluded groups and roles stay legible.

**`privacy.mode: identified`** puts real account names in output. It is a deliberate choice with a warning logged every run. Make it knowingly.

Re-identification, when an investigation genuinely warrants it, is done by looking the account up in the identity provider — not by reversing the pseudonym.

## What is stored, and for how long

| Artefact | Contains | Retention |
|---|---|---|
| `state.json` (`0600`) | The previous scan's observations per check, per scope: pseudonymised account labels, role names and tiers, application ids and credential ids, policy states, and exclusion lists with the account entries pseudonymised | Overwritten each run; one snapshot per scope, no history |
| `salt` (`0600`) | The pseudonymisation key | Until deleted |
| Reports | Whatever you configure, written `0600` through a descriptor that refuses to follow a symlink | Yours to manage |

The state file holds exactly one snapshot per scope. Keeping a history of who could administer your tenant over time would be more useful for forensics and is a larger liability, and this tool has no need for it: drift is a comparison between two adjacent runs.

Note what the state file *is*, because it drives the handling advice in [SECURITY.md](SECURITY.md): an inventory of privileged access, including which conditional access policies have exclusions and who is in them. That is a target list.

## Third-party transmission

Nothing leaves your infrastructure except to the identity provider you configured, unless you switch something on.

| Feature | Sends | To | Default |
|---|---|---|---|
| `source: entra` / `source: okta` | Read requests only | Your own tenant's API | **On** — it is the tool |
| `ai.enabled` | Finding titles, check names, issue ids, severities, determinations, and a per-request `identity-N` index — never a display name, a user principal name, or a tenant id. A title can name a directory role or a permission scope, which are organisational objects | Anthropic API | Off |
| `notify.*` | Findings, per your severity threshold | Your webhook, Slack, or SMTP | Off |

The AI layer never receives an identifier of any kind. This holds in `identified` mode too: subjects are replaced with a throwaway `identity-1`, `identity-2` index local to the single request, which lets the model see that two findings concern the same account and nothing more. It is off by default, and enabling it is still a disclosure decision — you are telling a third party how many administrators you have and what is wrong with your tenant.

Notification destinations receive whatever your `min_severity` threshold selects, in pseudonymous form unless you set `identified`. Every payload is bounded, so a large tenant produces a truncated message with an honest total rather than an oversized one the receiver drops.

## Practical guidance

- Run in `pseudonymous` mode unless you have a documented reason not to.
- Keep the state file and salt on a host with restricted access, and back them up as sensitive data.
- Tell your workforce, and be specific about the last-sign-in field. A tool that reports dormant accounts is easy to explain and easy to resent if it is discovered rather than announced; in some jurisdictions the disclosure is not optional, and in Germany it is a works-council matter before it is a technical decision.
- Route findings to a security or identity team, not to account holders. The tool is built that way on purpose: an automated "your account has no second factor" to five hundred people generates helpdesk load, gets filtered, and — for the findings that matter here — tips off the person whose account may already be under someone else's control.
- If your retention policy needs the state file gone, deleting it and the salt removes everything the tool has kept. There is no second copy.

## Questions

If something here is unclear or incomplete for your assessment, open an issue. Getting this document right is more useful than another detection rule.
