# github-auditor

[![CI](https://github.com/brettbergin/github-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/brettbergin/github-auditor/actions/workflows/ci.yml)

**Find the repositories that are leaving your GitHub organization at risk.**

Public repos created years ago — still wired to Actions runners, still running unpinned
third-party actions, still granting write tokens to workflows nobody has looked at since
2019 — are how organizations lose PATs, get releases poisoned, and have runners backdoored.
`github-auditor` sweeps an **entire organization** (or user account), caches everything
locally, and tells you exactly which repos put you at risk and why.

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

### CI usage

```bash
gha audit your-org --fail-on high --format json --output audit.json
```

Exits `1` when any finding at or above the given severity exists.

## What it checks

**Workflow rules** (parsed from workflow YAML):

| ID | Severity | Finding |
|----|----------|---------|
| GHA001 | critical | `pull_request_target` workflow checks out the untrusted PR head ("pwn request") |
| GHA002 | medium/high | Third-party actions pinned to mutable tags instead of commit SHAs |
| GHA003 | high | Reusable workflows called from external owners or unpinned refs |
| GHA004 | high | `workflow_run` workflows consuming untrusted artifacts |
| GHA005 | critical | Untrusted input (PR titles, branch names, comments…) interpolated into scripts |
| GHA006 | medium/high | `write-all` / write-level `GITHUB_TOKEN` permissions |
| GHA007 | low | No `permissions:` block at all |
| GHA008 | medium | Reusable (`workflow_call`) workflows with write or missing permissions |

**Repository rules**:

| ID | Severity | Finding |
|----|----------|---------|
| REPO001 | critical | Self-hosted runners reachable from a public repo |
| REPO002 | high | No branch protection on the default branch |
| REPO003 | medium | Weak branch protection (no reviews, force pushes allowed) |
| REPO004 | medium/high | Stale repo (no pushes in years) with Actions still enabled |
| REPO005 | low | Archived public repo still exposing workflow files |
| REPO006 | medium | Default `GITHUB_TOKEN` is read-write |
| REPO007 | low | All marketplace actions allowed on a public repo |

**Access rules**:

| ID | Severity | Finding |
|----|----------|---------|
| ACC001 | high | Deploy keys with write access |
| ACC002 | medium/high | Outside collaborators with write/admin |
| ACC003 | medium | Secret scanning disabled on a public repo |
| ACC004 | low | Push protection disabled |
| ACC005 | low | Dependabot alerts disabled |
| ACC006 | high | Workflows allowed to create/approve pull requests |

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

## License

MIT
