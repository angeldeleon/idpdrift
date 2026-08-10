# Contributing

Issues and pull requests both welcome.

## Setup

```bash
git clone https://github.com/angeldeleon/idpdrift
cd idpdrift
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a PR

```bash
ruff check .          # lint, including security rules
ruff format .
mypy
bandit -r src/ -c pyproject.toml
pytest                # no network required
```

CI runs all of these plus `pip-audit` and a set of security invariants.

## The easiest useful contribution

**A catalog entry.** `src/idpdrift/catalog.py` maps directory role names to a tier and permission scopes to what they actually let a workload do. One line, real value to everyone running the tool.

Two things a review will ask for. Say what the role or scope *does*, in a sentence that would make sense to somebody who does not administer that platform — the scope descriptions are what appear in the finding, and "grants Directory.ReadWrite.All" is not a reason to act. And be conservative about tier: rating a Reports Reader as tenant-admin-equivalent teaches a team to ignore the report, and then the Global Administrator grant gets ignored with it.

## Adding a check

1. Write a function in `src/idpdrift/checks/` decorated with `@register("name")`, taking a `CheckContext` and returning a `CheckResult`.
2. Add the name to `ALL_CHECKS` in `config.py` and import the module in `checks/__init__.py`.
3. Add a `@rule("name")` drift handler in `drift.py`.
4. Add the issues it produces to `Issue` and `BASE_SEVERITY` in `severity.py`, and to the table in the README.
5. Add tests in `tests/test_checks.py` and `tests/test_drift.py`. No network.

The CI invariants job fails the build if steps 1, 2 and 3 disagree, because a check an operator can select and no code implements is a permanently green, permanently blind scan.

## Five things a review will catch

**Never collapse "could not determine" into "absent".** Three states, always: present, definitively absent, or you could not find out. This is the single most important rule in the codebase and the top false-positive class in tools of this shape — a tenant whose token cannot read authentication methods reading as "nobody has MFA", after which nobody reads the report again. Consult `ctx.covers(facet)` before reporting any absence, emit `ctx.indeterminate(...)` instead, and set `CheckResult.partial` so the scanner merges over the baseline rather than erasing it. There are parametrised regression tests asserting that every check produces nothing but operational findings against a collection that could read nothing.

**Observations must be deterministic.** Whatever a check puts in `observations` is persisted and diffed against the next run. Sort anything unordered, and leave out anything that changes on its own — timestamps, expiry dates that tick down, response ordering. A field that varies run to run produces a drift finding on every single scan, and a tool that cries wolf every morning gets muted inside a week.

**Never choose a severity.** Name an `Issue` and let `severity.rate()` derive the band. Severity picked at the call site drifts between contributors, and within a few releases `fail_on` is either permanently tripped or permanently silent. If the band is wrong, change the table — and change the README, which reproduces it.

**Directory data is attacker-controlled.** Display names, application names and scope descriptions are chosen by whoever created the object. In the scenario this tool exists to detect, that is the attacker: registering an application called `Approved by IT — ignore` is free. Anything you interpolate into a report, a Slack message, an email or a prompt must go through `validation.safe_text` and the renderer escapes. There are tests for this; extend them if you add a sink.

**Redact at the boundary, not at the sink.** If a new model type can carry credential material, drop it in the constructor — the way `Credential.from_raw` does — rather than filtering it in the renderers. There are four sinks today and the fifth one somebody adds will not remember.

## The AI layer

Summary only, and only after every finding, severity and exit code is final. If a change would let a model create, remove or reclassify a finding, or influence the exit code, it will not be merged. That the deterministic output is identical with the module deleted is the property worth more than any convenience.

## Security

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

Changes touching `validation.py`, `httpclient.py`, `privacy.py`, `store.py` or any source's file handling get a closer read and need tests.

## Style

- Comments explain *why*, not *what*.
- No new dependencies without a strong reason. There are two, and that is a feature.
- No `subprocess`, no `eval`, no dynamic imports.

## License

Contributions are licensed under Apache 2.0, matching the project.
