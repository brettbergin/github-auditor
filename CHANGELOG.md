# Changelog

All notable changes to `github-auditor` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the rule set is the product, rule-level changes are called out by id.
Read them as compatibility notes: a **new rule id** can newly flag repositories
or organizations that previously came back clean, and a **severity change** can
flip the exit code of a pinned `gha audit --fail-on <severity>` in CI.

## [Unreleased]

## [0.1.0] - 2026-08-29

First development version. Not published to PyPI.

### Added

- Analysis engine with 21 repository-scoped security rules covering the GitHub
  Actions attack surface and repository posture: `GHA001`–`GHA008` (pwn
  requests, unpinned actions, external reusable workflows, `workflow_run`
  artifact consumption, untrusted script interpolation, `GITHUB_TOKEN`
  permissions), `REPO001`–`REPO007` (self-hosted runners on public repos,
  branch protection, stale and archived repos, default token permissions,
  marketplace action policy) and `ACC001`–`ACC006` (deploy keys, outside
  collaborators, secret scanning, push protection, Dependabot alerts,
  workflow PR creation/approval).
- Workflow parser for GitHub Actions YAML, feeding the rules a structured view
  of triggers, jobs, steps and permissions.
- SQLite cache layer (SQLAlchemy 2.0) with a freshness TTL, so re-runs are
  local and API-cheap.
- Concurrent fetch layer (PyGithub) for org, repo, workflow, runner and access
  data, rate-limit aware.
- Optional deep scan that shallow-clones repositories (GitPython) to read
  workflow files straight from disk (`--deep`).
- Typer CLI (`gha`) with `audit`, `fetch`, `report`, `repos`, `findings`,
  `rules` and `cache` commands, Rich terminal reporting with risk scores and
  A–F grades, JSON/CSV export, and `--fail-on` for CI gating.
- Test suite: 70 tests across the parser, rules, cache, fetcher and CLI, driven
  by workflow fixtures and requiring no network or GitHub token.
- CI workflow running five required checks — `ruff format --check`,
  `ruff check`, `mypy` (strict), `bandit` and `pytest` — plus a Dependabot
  configuration and a CI status badge.
- Organization-level posture rules `ORG001`–`ORG006`, reported once per audit
  against the organization rather than a repository: 2FA not required
  (`ORG001`), base member permission of write or admin (`ORG002`), fork pull
  request workflows running without approval (`ORG003`), org-wide read-write
  default `GITHUB_TOKEN` (`ORG004`), workflows allowed to create and approve
  pull requests org-wide (`ORG005`), and members able to create public
  repositories (`ORG006`). Each fires only on an explicit bad value, so a token
  that cannot read a setting yields a smaller audit rather than a false
  positive.

### Changed

- `GHA006` (`GITHUB_TOKEN` write permissions) no longer flags least-privilege
  per-job write grants; it reports `write-all` and broad write-level grants
  only. Fewer findings on workflows that already scope their token per job.
- `GHA003` (external reusable workflows) is graded by mutability: a reusable
  workflow from an external owner pinned to a commit SHA is reported as **low**
  severity instead of high, leaving high for mutable refs.
- `GHA002` (unpinned actions) deduplicates findings per unique action per
  repository — one finding per action listing every use site, with the count in
  the evidence — instead of one finding per occurrence.

[Unreleased]: https://github.com/brettbergin/github-auditor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brettbergin/github-auditor/releases/tag/v0.1.0
