# github-auditor

[![CI](https://github.com/brettbergin/github-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/brettbergin/github-auditor/actions/workflows/ci.yml)

**Find the repositories that are leaving your GitHub organization at risk.**

Public repos created years ago — still wired to Actions runners, still running unpinned
third-party actions, still granting write tokens to workflows nobody has looked at since
2019 — are how organizations lose PATs, get releases poisoned, and have runners backdoored.
`github-auditor` sweeps an **entire organization** (or user account), caches everything
locally, and tells you exactly which repos put you at risk and why.

## Quick links

- [CI workflow](https://github.com/brettbergin/github-auditor/actions/workflows/ci.yml) — build and test status.
- [Issue tracker](https://github.com/brettbergin/github-auditor/issues) — report a bug or request a rule.
- [CLI reference](docs/CLI.md) — every command flag-by-flag, with defaults, accepted values, sample output per format, and the exit code contract.
- [Rule reference](docs/RULES.md) — every rule's vulnerable pattern, exploit scenario, and fix, one entry per rule id.
- [Changelog](CHANGELOG.md) — what changed between versions, including new rule ids.

- **Fetch** org, repo, workflow, runner, and access data via the GitHub API (PyGithub),
  concurrently and rate-limit aware.
- **Cache** everything in a local SQLite database (SQLAlchemy) with a freshness TTL, so
  re-runs are instant and API-cheap.
- **Deep-scan** optionally clones repos (GitPython, shallow) to read workflow files
  straight from disk.
- **Analyze** with 21 security rules covering the GitHub Actions attack surface and repo
  security posture.
- **Present** results in a rich terminal report (Rich + Typer), or export JSON/CSV.

## Install

```bash
pip install github-auditor        # once published
# or from source:
pip install .
```

Requires Python 3.10+.

## Quick start

```bash
export GITHUB_TOKEN=ghp_...       # a classic PAT or fine-grained token
gha audit your-org                # fetch + analyze + report
```

Typical output: a summary panel, then a table of repositories sorted by risk score with
per-severity counts and letter grades (A–F).

### More commands

```bash
gha fetch your-org --refresh      # (re)populate the cache, no analysis
gha audit your-org --deep         # also clone repos to scan workflow files from disk
gha report your-org --repo your-org/legacy-service   # full findings for one repo
gha repos your-org --sort pushed  # every repo with score/grade/last-push
gha findings your-org --min-severity high --format csv > findings.csv
gha rules                         # list all rules with descriptions
gha cache info                    # what's cached, how fresh
gha cache clear --org your-org    # forget one org (DB + clones)
```

That is one example per command; see the [CLI reference](docs/CLI.md) for every flag, its
default, the accepted `--format`/`--sort`/`--severity` values, and the exit code contract.

### CI usage

```bash
gha audit your-org --fail-on high --format json --output audit.json
```

Exits `1` when any finding at or above the given severity exists.

## What it checks

Each rule id links to its entry in the [rule reference](docs/RULES.md) — the vulnerable
pattern, the attack it enables, and the concrete fix.

<!-- Anchor map, kept in sync with the rule reference (docs/RULES.md):
     ORG001(docs/RULES.md#org001) ORG002(docs/RULES.md#org002) ORG003(docs/RULES.md#org003)
     ORG004(docs/RULES.md#org004) ORG005(docs/RULES.md#org005) ORG006(docs/RULES.md#org006) -->

**Organization rules** — settings that apply to *every* repository underneath them,
including repos created tomorrow. Reported once per audit, above the repo table:

| ID | Severity | Finding |
|----|----------|---------|
| [ORG001](docs/RULES.md#org001) | high | Two-factor authentication not required for members |
| [ORG002](docs/RULES.md#org002) | medium/high | Base member permission is write (or admin) on every repo |
| [ORG003](docs/RULES.md#org003) | high | Fork pull request workflows run without approval |
| [ORG004](docs/RULES.md#org004) | medium | Default `GITHUB_TOKEN` is read-write org-wide |
| [ORG005](docs/RULES.md#org005) | high | Workflows may create and approve pull requests org-wide |
| [ORG006](docs/RULES.md#org006) | medium | Members can create public repositories |

<!-- Anchor map, kept in sync with the rule reference (docs/RULES.md):
     GHA001(docs/RULES.md#gha001) GHA002(docs/RULES.md#gha002) GHA003(docs/RULES.md#gha003)
     GHA004(docs/RULES.md#gha004) GHA005(docs/RULES.md#gha005) GHA006(docs/RULES.md#gha006)
     GHA007(docs/RULES.md#gha007) GHA008(docs/RULES.md#gha008) -->

**Workflow rules** (parsed from workflow YAML):

| ID | Severity | Finding |
|----|----------|---------|
| [GHA001](docs/RULES.md#gha001) | critical | `pull_request_target` workflow checks out the untrusted PR head ("pwn request") |
| [GHA002](docs/RULES.md#gha002) | medium/high | Third-party actions pinned to mutable tags instead of commit SHAs |
| [GHA003](docs/RULES.md#gha003) | high | Reusable workflows called from external owners or unpinned refs |
| [GHA004](docs/RULES.md#gha004) | high | `workflow_run` workflows consuming untrusted artifacts |
| [GHA005](docs/RULES.md#gha005) | critical | Untrusted input (PR titles, branch names, comments…) interpolated into scripts |
| [GHA006](docs/RULES.md#gha006) | medium/high | `write-all` / write-level `GITHUB_TOKEN` permissions |
| [GHA007](docs/RULES.md#gha007) | low | No `permissions:` block at all |
| [GHA008](docs/RULES.md#gha008) | medium | Reusable (`workflow_call`) workflows with write or missing permissions |

<!-- Anchor map, kept in sync with the rule reference (docs/RULES.md):
     REPO001(docs/RULES.md#repo001) REPO002(docs/RULES.md#repo002) REPO003(docs/RULES.md#repo003)
     REPO004(docs/RULES.md#repo004) REPO005(docs/RULES.md#repo005) REPO006(docs/RULES.md#repo006)
     REPO007(docs/RULES.md#repo007) -->

**Repository rules**:

| ID | Severity | Finding |
|----|----------|---------|
| [REPO001](docs/RULES.md#repo001) | critical | Self-hosted runners reachable from a public repo |
| [REPO002](docs/RULES.md#repo002) | high | No branch protection on the default branch |
| [REPO003](docs/RULES.md#repo003) | medium | Weak branch protection (no reviews, force pushes allowed) |
| [REPO004](docs/RULES.md#repo004) | medium/high | Stale repo (no pushes in years) with Actions still enabled |
| [REPO005](docs/RULES.md#repo005) | low | Archived public repo still exposing workflow files |
| [REPO006](docs/RULES.md#repo006) | medium | Default `GITHUB_TOKEN` is read-write |
| [REPO007](docs/RULES.md#repo007) | low | All marketplace actions allowed on a public repo |

<!-- Anchor map, kept in sync with the rule reference (docs/RULES.md):
     ACC001(docs/RULES.md#acc001) ACC002(docs/RULES.md#acc002) ACC003(docs/RULES.md#acc003)
     ACC004(docs/RULES.md#acc004) ACC005(docs/RULES.md#acc005) ACC006(docs/RULES.md#acc006) -->

**Access rules**:

| ID | Severity | Finding |
|----|----------|---------|
| [ACC001](docs/RULES.md#acc001) | high | Deploy keys with write access |
| [ACC002](docs/RULES.md#acc002) | medium/high | Outside collaborators with write/admin |
| [ACC003](docs/RULES.md#acc003) | medium | Secret scanning disabled on a public repo |
| [ACC004](docs/RULES.md#acc004) | low | Push protection disabled |
| [ACC005](docs/RULES.md#acc005) | low | Dependabot alerts disabled |
| [ACC006](docs/RULES.md#acc006) | high | Workflows allowed to create/approve pull requests |

## Token scopes & graceful degradation

Everything the token can't see is treated as **unknown, never as a finding** — a
limited token yields a smaller audit, not false positives.

For full coverage use a token with:

- `repo` — private repos, branch protection, deploy keys, collaborators, Actions settings
- `admin:org` (read) — org-level self-hosted runners, org settings
- `security_events` or repo admin — secret scanning status

An unauthenticated run works too (public data, 60 requests/hour) and is enough to spot
public-facing workflow risks.

## Configuration

All settings come from environment variables (or a local `.env`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `GITHUB_TOKEN` | – | GitHub token (also `GITHUB_AUDITOR_TOKEN`) |
| `GITHUB_AUDITOR_ORG` | – | Default org, so you can omit the CLI argument |
| `GITHUB_AUDITOR_DATA_DIR` | `~/.github-auditor` | Cache DB + clones live here |
| `GITHUB_AUDITOR_CACHE_TTL_HOURS` | `24` | Re-fetch anything older than this (`--refresh` overrides) |
| `GITHUB_AUDITOR_MAX_WORKERS` | `8` | Concurrent repo fetches |
| `GITHUB_AUDITOR_STALE_YEARS` | `2` | Threshold for the stale-repo rule |
| `GITHUB_AUDITOR_TRUSTED_ACTION_OWNERS` | `["actions","github"]` | Owners exempt from SHA-pinning rules |

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The rule engine runs entirely from the cache, so tests exercise rules against fixture
workflow files and mocked API objects — no network needed.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full dev setup, every check CI enforces
(`ruff format --check`, `ruff check`, `mypy`, `bandit`, `pytest`), and the guide to
writing a new rule — the contract, where to register it, how to add a fixture-driven
test, and keeping the rule tables above in sync.

## License

MIT
