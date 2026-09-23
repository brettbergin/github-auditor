# Contributing to github-auditor

The rule set is the product. The most valuable contribution is usually a new
rule: you found a risky GitHub Actions or repository pattern in the wild, and
now every user of the tool can detect it. This guide walks the whole path —
dev setup, the rule contract, registering a rule, writing a fixture-driven
test, and the docs that have to move with it.

## Dev environment

Python 3.10+ (CI tests 3.10, 3.11 and 3.12; mypy and the linters run on 3.12).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

`[dev]` pulls in pytest, pytest-mock, ruff, mypy, bandit and type stubs.

### Checks CI enforces

Every one of these is a separate required job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Run all five before
opening a pull request — they read their configuration from `pyproject.toml`,
so no flags are needed beyond what is shown:

```bash
ruff format --check .        # formatting (CI pins ruff 0.16.5; `ruff format .` to fix)
ruff check .                 # lint: E, F, I, UP, B, SIM; line length 100
mypy                         # strict, incl. disallow_any_explicit; files = src/github_auditor
bandit -c pyproject.toml -r src
pytest                       # testpaths = tests
```

Notes that bite people:

- `mypy` is configured with `files = ["src/github_auditor"]`, so a bare `mypy`
  checks exactly what CI checks. It runs in `strict` mode with
  `disallow_any_explicit = true` — a new rule module must be fully annotated
  and must not spell `Any`. (Only the pydantic-model modules are exempted, via
  a `[[tool.mypy.overrides]]` block; don't add yourself to it for convenience.)
- `ruff format` also formats the Python code blocks inside Markdown files, so
  `README.md` and this file are checked too — a snippet with hand-aligned
  trailing comments fails the formatting job just like a source file would.
- `bandit` excludes `tests/` and only scans `src`.
- The rule engine runs entirely off the cache, so tests need no network and no
  GitHub token.

## How a rule is structured

The contract lives in
[`src/github_auditor/analyze/rules/base.py`](src/github_auditor/analyze/rules/base.py).
`RuleBase` holds the identity every rule declares as classvars:

| Classvar | Meaning |
|----------|---------|
| `id` | Stable identifier, e.g. `GHA009`, `REPO008`, `ACC007`, `ORG007`. Used by `--include`/`--exclude` and by the README tables. |
| `name` | Short kebab-case slug, e.g. `pwn-request`. Also matchable on the CLI. |
| `default_severity` | A `Severity` member (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). Used unless `check` passes an explicit `severity=`. |
| `description` | Why this is a risk, in prose. This is what a reader sees in the report, so explain the attack, not the setting. |
| `remediation` | Optional (defaults to `""`): the concrete fix, ideally naming the GitHub settings path. |

There are two subclasses, and you pick one based on what the check needs to see:

- `Rule` — repository-scoped. Implement
  `check(self, ctx: RepoContext) -> Iterator[Finding]`. `RepoContext` carries
  `org`, `repo` (a `RepoInfo`), `workflows` (parsed workflow YAML),
  `raw_workflows`, `org_info`, `org_runners`, `repo_runners` and `settings`.
  Runs once per repository.
- `OrgRule` — organization-scoped. Implement
  `check(self, ctx: OrgContext) -> Iterator[Finding]`. `OrgContext` carries
  `org`, `org_info` and `settings`. Runs once per audit, and findings are
  attributed to the `ORG_SCOPE` sentinel rather than a repo.

`check` is a generator: `yield` one `Finding` per distinct problem, and yield
nothing for a clean subject. Build findings with the inherited
`self.finding(ctx, ...)` helper rather than constructing `Finding` directly —
it fills in `rule_id`, `rule_name`, `severity`, `description`, `remediation`
and the repo/org attribution for you:

```python
class DangerousThingRule(Rule):
    id = "GHA009"
    name = "dangerous-thing"
    default_severity = Severity.HIGH
    description = "One or two sentences on what an attacker does with this."
    remediation = "The concrete fix."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            if not wf.has_trigger("pull_request_target"):
                continue
            yield self.finding(
                ctx,
                title="Short, specific, one line",
                severity=Severity.CRITICAL,  # optional: overrides default_severity
                location=wf.path,  # where in the repo to look
                evidence="the offending line or setting value",
            )
```

House rules for the checks themselves:

- **Unknown is never a finding.** Posture fields are tri-state: `None` means
  the token could not see the setting (most need org-owner or `admin:org`
  read). Only fire on an explicit bad value — write `if x is False:`, not
  `if not x:`. A limited token must yield a smaller audit, not false positives.
- **Fill in `location` and `evidence`.** They are what makes a finding
  actionable, and tests assert on them.
- **Grade by exploitability** where it differs. Several rules escalate
  severity (e.g. an unpinned action used under `pull_request_target`) or
  de-escalate it (a SHA-pinned external reusable workflow). Pass `severity=`
  per finding for that, and reflect the range in the README table as
  `medium/high`.
- **Dedupe per repo** when the same underlying problem appears in many files;
  see `UnpinnedActionRule` for the pattern (one finding listing every use site,
  with the count in `evidence`).

## Registering a new rule

1. Put the class in the module that matches its subject:
   - `workflow_rules.py` — parsed workflow YAML (`GHA…`)
   - `repo_rules.py` — repository settings and posture (`REPO…`)
   - `access_rules.py` — access, keys, collaborators, scanning (`ACC…`)
   - `org_rules.py` — organization-wide settings (`ORG…`)
2. Import it in
   [`src/github_auditor/analyze/rules/__init__.py`](src/github_auditor/analyze/rules/__init__.py)
   and append it to `ALL_RULES` (for a `Rule`) or `ALL_ORG_RULES` (for an
   `OrgRule`). The engine instantiates straight from those lists, so a rule
   that isn't in one of them never runs.
3. Pick the next free id in its family. `tests/test_engine.py` asserts that all
   ids across `ALL_RULES` and `ALL_ORG_RULES` are unique — and it also asserts
   the registry sizes, so bump those counts in the same change.

## Adding a fixture-driven test

Tests live flat in `tests/`, one module per rule family:
`test_rules_workflow.py`, `test_rules_repo.py`, `test_rules_access.py`,
`test_rules_org.py`. Add your test to the matching one.

For a workflow rule:

1. Drop a minimal workflow YAML in `tests/fixtures/workflows/`, named after the
   pattern it exercises (`unpinned.yml`, `pwn_request_vuln.yml`, …). Keep it as
   small as the rule allows, and add a safe twin (`*_safe.yml`) so you can
   prove the rule does *not* fire on the benign version.
2. Build a context with `make_ctx([...])` from
   [`tests/conftest.py`](tests/conftest.py) — it loads each named fixture,
   parses it, and returns a `RepoContext` with test settings and no token.
3. Run the rule and assert on the findings list — length, `severity`, and the
   text in `title` / `evidence`:

```python
from conftest import make_ctx
from github_auditor.analyze.rules.workflow_rules import DangerousThingRule
from github_auditor.models import Severity


def run_rule(rule, ctx):
    return list(rule.check(ctx))


def test_dangerous_thing_detected():
    findings = run_rule(DangerousThingRule(), make_ctx(["dangerous_thing_vuln.yml"]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "pull_request_target" in findings[0].title


def test_dangerous_thing_safe_twin_clean():
    assert run_rule(DangerousThingRule(), make_ctx(["dangerous_thing_safe.yml"])) == []
```

For repo and access rules there is usually no fixture file: pass a
`make_repo(...)` with the posture fields you care about, plus any extra
`RepoContext` fields as keyword arguments, e.g.
`make_ctx(repo=make_repo(visibility="private"), repo_runners=[...])`. Org rules
build an `OrgContext` directly from an `OrgInfo`; copy `make_org_ctx` in
`tests/test_rules_org.py`.

Cover three cases for anything posture-driven: the bad value fires, the good
value is clean, and `None` (unknown) is clean.

## Keep the README in sync

`README.md` under **What it checks** carries one table per rule family
(organization, workflow, repository, access), each row being ID, severity and a
one-line description. A new rule, a changed `id`, or a changed
`default_severity` must update the matching README row in the same change —
that table is the user-facing rule catalogue, and a mismatch between it and
`ALL_RULES` is treated as a bug. Use `medium/high` style when a rule grades its
severity per finding.

If a rule introduces a new tunable, add it to the **Configuration** table in
`README.md` alongside the `Settings` field in `src/github_auditor/config.py`.

## Pull requests

There is no PR template or CLA — default GitHub flow: fork or branch, push,
open a pull request against `main`, and keep it to one logical change.

- Commit subjects follow the imperative, sentence-case style already in
  `git log` (`Add organization-level posture rules (ORG001-ORG006)`,
  `Dedupe GHA002 findings per unique action per repo`). No prefix convention,
  no trailing period.
- Explain the risk in the PR description: what an attacker does with the
  pattern, and why the severity you chose is the right one. A rule's value is
  its precision, so say what you did to avoid false positives.
- All five CI jobs (ruff format, ruff lint, mypy, bandit, pytest) must be green.

Maintainers: [`RELEASING.md`](RELEASING.md) documents how a version is cut and
published — where the version lives, the tag format, and what happens on a tag
push.
