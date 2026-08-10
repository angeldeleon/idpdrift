# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability reporting](https://github.com/angeldeleon/idpdrift/security/advisories/new) rather than opening a public issue.

Include affected version, reproduction steps, and impact. I aim to acknowledge within 72 hours and to ship a fix or mitigation plan within 30 days for confirmed issues. Credit in the advisory unless you would rather not be named.

## Threat model

idpdrift runs on a management host holding a credential that can read an entire directory, and it writes a file that is a complete inventory of privileged access in that directory. It also ingests strings chosen by whoever created the objects it reads — which, in the scenario it exists to detect, includes an attacker who has just registered an application or created an account. That shapes what it defends against.

| Threat | Mitigation |
|---|---|
| **Writing to the tenant** | No source has a write path. Every request is a GET, except the OAuth2 token request the client-credentials flow requires. A read-only application registration or API token is sufficient, and the tool is designed so that anything more is a signal something is wrong |
| **Arbitrary request via config** | No config key accepts an API path, an endpoint or a query fragment. The endpoints each source reads are fixed in the source modules and reviewed in-tree; a config-injectable path would turn a read-only monitor into an arbitrary-request primitive holding a directory-wide token |
| **Client secret leakage into the state file, a report, or a webhook** | Redaction happens at the construction boundary, not at the output sinks: `Finding.__post_init__` scrubs secret-shaped keys, and `Credential.from_raw` never accepts key material into the object at all. There are four sinks today and the fifth will not remember to redact, so a finding simply never holds a secret. Okta returns `client_secret` inline on the apps endpoint; it is dropped at parse time |
| **SSRF to cloud metadata or internal services** | Every outbound URL is validated and its host resolved before connecting; loopback, RFC1918, link-local (`169.254.169.254`), CGNAT, reserved, multicast and IPv4-mapped/6to4/NAT64 spellings are refused |
| **SSRF via redirect** | Redirects are followed manually, capped at 3 hops, re-validated at each. `allow_internal` — which exists for a tenant endpoint reached through a proxy — does **not** survive a cross-origin hop, so a compromised or on-path provider cannot redirect the scanner into the rest of the network. Okta's pagination `Link` header goes through the same guard as any other URL |
| **Credential forwarding via redirect** | Credential-bearing headers and the request body are dropped on any cross-origin hop; 301/302/303 downgrade to GET. This covers the form-encoded token request, whose body carries the client secret |
| **Alert and report injection** — a crafted display name forging a finding line, a phishing link, or a tracking pixel in the report an analyst opens | Directory strings are sanitised at ingestion (control characters collapsed, invisible and bidi-override characters dropped, unpaired surrogates replaced, length capped) and escaped again at every renderer, for that renderer's syntax. Markdown link, image and code-span metacharacters are escaped, and a bare URL — which needs none of them, and which most renderers autolink on sight — is quarantined inside a code span, where autolinking does not happen; HTML output is fully entity-escaped; email headers are validated and control characters stripped. Slack is handled structurally rather than by escaping — mrkdwn has no backslash escape, so finding prose is emitted as `plain_text` with `emoji: false`, where no markup is interpreted at all |
| **Name spoofing** — an account whose displayed name is not the name it matches on | Bidi overrides and zero-width characters are stripped, so a name cannot render as one thing and be stored as another. Role and scope matching is NFKC-normalised, CamelCase-split and Unicode-aware, so a fullwidth or non-Latin spelling neither evades the catalog nor disappears from the report |
| **Finding suppression by an attacker-chosen name** | `policy.approved_applications`, `policy.ignore_applications` and `policy.ignore_principals` match on object ids, application ids and user principal names — never on a display name. Suppressing a finding is the most valuable thing an adversary can make this tool do, and a display name is a string they choose; an allow list keyed on one would let anyone who can register an application remove themselves from the report and from the baseline the drift rule reads |
| **Prompt injection via a display name** | The model runs after all findings, severities and the exit code are final and cannot change them. Its output is prose that no code parses. Input is fenced and framed as untrusted. The summary is rendered with line-leading markup escaped, so a coerced reply cannot open a heading, list or table and pass itself off as a section of the deterministic report |
| **Code execution via config** | `yaml.safe_load` only, size-capped, unknown keys rejected |
| **Secret leakage into logs** | Secrets come from the environment, never config. A `*_env` field containing a URL or path is rejected. A logging filter redacts credential-shaped strings — including JWTs, Okta `SSWS` tokens and bearer headers — in messages and in tracebacks; URLs in error messages are truncated to scheme and host, and provider error bodies are never logged because the token endpoint echoes the request |
| **Re-identification of employees** | Pseudonymous by default, including the directory object ids in a conditional access policy's exclusion list — those resolve to a person in one lookup and reach the report, the alert and the webhook through the exclusion-added drift finding. The AI layer receives a per-request `identity-N` index rather than any identifier, in both privacy modes. See [PRIVACY.md](PRIVACY.md) |
| **Salt, state or report theft via symlink** | Every file this tool opens is opened with `O_NOFOLLOW` — the salt, the state file, the `file` source's export path, and the report — on every open and not only on creation, since a link pointing at an *existing* file is the case that matters. Reports count: a report is the same inventory the state file is, and it is usually written into a shared artefact directory on a build agent. `O_NONBLOCK` is set alongside it on the reads: opening a FIFO for reading blocks inside `open()`, before the regular-file check can refuse it, so a named pipe left in the state directory would otherwise hang every run indefinitely rather than failing. Permissions are checked and repaired through the file descriptor, never the path |
| **Resource exhaustion from a hostile or broken provider** | Per-facet item caps, page caps, per-check finding caps, streamed HTTP with an incremental size cap, config and state size caps, bounded evidence structures, bounded serialised output in every renderer and every notification destination |
| **Confidently wrong provider semantics** | A misread API field produces a true-sounding sentence about somebody's access that is not true, and nothing downstream can catch it. The readings that carry weight have a test naming the distinction: `directoryRole.id` against `roleDefinitionId` for eligibility, an `appRoleId` GUID against the permission name the resource publishes, `isPasswordlessCapable` against actual phishing resistance, and an Okta lockout against a deactivated account |
| **False findings from partial data** | The tri-state runs through the whole tool: an unreadable facet produces no posture finding, produces an operational finding saying so, and is merged over the baseline rather than replacing it. A truncated page listing marks its facet indeterminate rather than short. A drift comparison requires a determinate answer on both sides. A baseline sharing no observations with the collection is reported instead of silently producing no drift. Every renderer, including HTML, carries the coverage notes — an incomplete scan must not look like a clean one in any output format |
| **State corruption** | Written atomically: temp file in the same directory, `fchmod 0600`, `fsync`, then `os.replace`. A corrupt file degrades to "no baseline" rather than stopping the job; a symlink or FIFO raises |

### Explicitly out of scope

- **The integrity of the directory's own answers.** idpdrift trusts what Graph and the Okta API return. An attacker with enough privilege to alter those answers has already won, and nothing here changes that. This is a drift detector, not a tamper-evident audit log.
- **Time-of-check/time-of-use on the HTTP client.** DNS can change between validation and connection. The guard raises the bar substantially against accidental and opportunistic SSRF without claiming to be airtight; pinning the resolved address at connect time would close it and is not implemented.
- **Remediation.** The tool detects and reports. It has no capability to revoke a role, delete a credential or disable an account, and adding one would require write privilege on the directory and turn it into an attack path.
- **A compromise that predates the first run.** The first scan baselines whatever is there, including an attacker's persistence. Drift tells you what changed since you started looking.

## Supply chain

- Two runtime dependencies: `PyYAML` and `httpx`. Every dependency is attack surface someone else maintains.
- CI runs `pip-audit` on every push and weekly.
- Workflow `permissions` default to `contents: read`; jobs opt in to more.
- Dependabot is enabled for pip and GitHub Actions.
- Actions are pinned to **full commit SHAs**, with the version tag kept in a trailing comment so Dependabot can still propose updates. A tag is mutable and can be repointed at malicious code by anyone who compromises the action's repository; a SHA cannot.

## Running it safely

- Use a **read-only** application registration or API token. The tool never needs more, and a write scope on this credential is worth more to an attacker than most things on the host.
- Give the host the narrowest network egress you can.
- Store the client secret, API token, webhook URLs and SMTP credentials as environment variables or secrets — never in the config file. The config only names them.
- **Treat `state.json` as sensitive.** It is an inventory of privileged access: who holds which administrative role, which applications can read all mail, and which conditional access policies have exclusions and who is in them. That is a target list, and it is the first thing worth stealing from the host this runs on. It is created `0600` and gitignored; keep it that way, and if you commit it for baseline persistence, use a private repository.
- The same applies to reports. The JSON rendering carries the findings and their evidence; report files are written `0600` rather than at the process umask, and the write refuses to follow a symlink at the output path.
- Leave `verify_tls: true`. Disabling it exposes the client secret and the access token to anyone on-path, and the tool logs a warning every run if you do.
- Keep `ai.enabled: false` unless you have accepted sending finding titles and severities to a third-party API.
- Run `idpdrift coverage` when you deploy, and again after any change to the credential's scopes. A report that says nothing because it could see nothing looks exactly like a clean tenant if you do not check.
