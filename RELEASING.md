# Releasing github-auditor

This is how a release is cut today. It is deliberately a description of the
current state of the repository, not an aspiration: the build and the upload
are run by hand from a maintainer's machine, because there is no release
automation in the repository yet. If that changes, change this file in the same
pull request.

## Where the version lives

The single source of truth is the `version` field under `[project]` in
[`pyproject.toml`](pyproject.toml):

```toml
[project]
name = "github-auditor"
version = "0.1.0"
```

Nothing else in the tree hard-codes a version — there is no `__version__`
constant to keep in sync — so bumping that one field is the whole version bump.
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html);
for a rule-set tool the practical reading is:

- **patch** — a fix to an existing rule that does not change which findings a
  clean repository gets, docs, packaging.
- **minor** — new rule ids, new CLI flags, new config settings. A new rule id
  can newly flag an organization that previously came back clean, so it is
  never a patch.
- **major** — a changed or removed rule id, a severity change that can flip the
  exit code of a pinned `gha audit --fail-on <severity>`, a renamed or removed
  CLI flag or config key.

## Cutting a release

1. **Update the changelog.** In [`CHANGELOG.md`](CHANGELOG.md), move everything
   under `## [Unreleased]` into a new heading of the form
   `## [x.y.z] - YYYY-MM-DD` (the release date, ISO 8601), and leave an empty
   `## [Unreleased]` section at the top for the next cycle. Call out new rule
   ids and severity changes explicitly — that is the part users need in order
   to predict what a bump will do to their audit.
2. **Bump the version** in `pyproject.toml` to the same `x.y.z`.
3. **Run the full check suite locally.** These are the same five checks CI
   enforces, and they read their configuration from `pyproject.toml`:

   ```bash
   ruff format --check .
   ruff check .
   mypy
   bandit -c pyproject.toml -r src
   pytest
   ```

4. **Open a pull request** with the changelog and version bump, and merge it
   once CI is green. Releases are cut from `main`.
5. **Tag the merge commit on `main`.** The tag convention is `vX.Y.Z` — a
   leading `v` followed by exactly the version string in `pyproject.toml`, so
   version `0.2.0` is tagged `v0.2.0`. Annotated tags, pushed explicitly:

   ```bash
   git checkout main && git pull
   git tag -a v0.2.0 -m "github-auditor 0.2.0"
   git push origin v0.2.0
   ```

6. **Publish to PyPI manually** — see below.
7. **Create the GitHub release** for the tag, pasting that version's
   `CHANGELOG.md` section as the release notes.

## What CI does, and when

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the only workflow in
the repository. It triggers on exactly two events:

- `push` to the `main` branch
- `pull_request` (any branch)

On either event it runs five independent required jobs: `ruff format --check .`,
`ruff check .`, `mypy` (strict), `bandit -c pyproject.toml -r src`, and `pytest`
across a Python 3.10 / 3.11 / 3.12 matrix. The lint, type and security jobs run
on 3.12 only. The workflow requests `contents: read` and nothing more.

**There is currently no tag-triggered workflow and no automated PyPI publish
step.** Pushing a `vX.Y.Z` tag runs nothing at all: tags are not in the `push`
trigger's branch filter, so CI does not even re-run the test suite for them, and
no job builds a distribution, uploads to PyPI, or creates a GitHub release. The
repository has no PyPI credentials or trusted-publisher configuration. Everything
after the tag push is manual.

## Publishing to PyPI (manual, current process)

Do this from a clean checkout of the tagged commit. The build backend is
hatchling, configured in `pyproject.toml`; `build` and `twine` are *not* part of
the `[dev]` extra, so install them into the release environment yourself.

```bash
git checkout v0.2.0
python3 -m venv .venv-release && source .venv-release/bin/activate
pip install build twine

rm -rf dist/
python -m build              # writes sdist + wheel to dist/
twine check dist/*
twine upload dist/*          # PyPI; prompts for an API token
```

`twine upload` targets PyPI by default. Authenticate with a PyPI API token
(username `__token__`), scoped to the `github-auditor` project once the first
release exists. To rehearse the upload without burning a version number, push to
TestPyPI first:

```bash
twine upload --repository testpypi dist/*
```

PyPI filenames are immutable: a version can be yanked but never re-uploaded, so
if a release is broken, bump the patch version and cut another one rather than
trying to replace it.

## Checklist

- [ ] `CHANGELOG.md`: `[Unreleased]` entries moved under `## [x.y.z] - YYYY-MM-DD`
- [ ] `pyproject.toml`: `[project].version` bumped to `x.y.z`
- [ ] Five checks green locally, and CI green on the pull request
- [ ] Merged to `main`
- [ ] Tag `vX.Y.Z` created and pushed
- [ ] `python -m build` and `twine upload dist/*` run against PyPI
- [ ] GitHub release created for the tag with the changelog section as notes
