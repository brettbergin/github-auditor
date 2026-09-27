# Scheduled deployment

`github-auditor` is built to sweep an entire organization on a recurring basis, but the
example in README.md's **CI usage** section is a single local invocation — it shows the
flags, not the job. This page shows the other half: running `gha audit` as a scheduled
GitHub Actions workflow, so the audit is continuous posture monitoring rather than a
one-off scan somebody remembers to run.

It covers the workflow file itself, the token you give it and how little that token can
get away with, and what to do with the report once the run finishes.

## The workflow

Drop this in the *auditing* repository — the one that owns the schedule — as
`.github/workflows/github-auditor.yml`. It is a complete file: change `your-org` and the
Python version pin, add the secret described under [Token scopes](#token-scopes), and it
runs as written.

```yaml
name: github-auditor

on:
  schedule:
    # Weekly, Monday 06:17 UTC. Off the hour: scheduled runs are queued best-effort and
    # the top of the hour is the busiest slot on GitHub's scheduler.
    - cron: "17 6 * * 1"
  # Manual runs, for testing the workflow and for auditing on demand after an incident.
  workflow_dispatch:

# Read-only at the top level, inherited by every job. The audit talks to the GitHub API
# with its own PAT (GITHUB_AUDITOR_TOKEN); the workflow's own GITHUB_TOKEN only needs to
# read this repository. github-auditor's own GHA006/GHA007/GHA008 rules fire on missing
# or write-level permissions blocks, so this example declares one explicitly.
permissions:
  contents: read

concurrency:
  group: github-auditor-${{ github.workflow }}
  cancel-in-progress: false

env:
  AUDIT_ORG: your-org
  # Cache DB and any clones live here. Default is ~/.github-auditor
  # (GITHUB_AUDITOR_DATA_DIR in README.md's Configuration table); pointing it inside the
  # workspace keeps the path stable and cacheable across runners.
  GITHUB_AUDITOR_DATA_DIR: ${{ github.workspace }}/.github-auditor

jobs:
  audit:
    name: audit
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      # Every action below is pinned to a commit SHA, not a floating tag. actions/* and
      # github/* are exempt from GHA002/GHA003 by default
      # (GITHUB_AUDITOR_TRUSTED_ACTION_OWNERS in README.md's Configuration table), so
      # pinning them is belt-and-braces — but any third-party action you add here is not
      # exempt, and an unpinned one would make this workflow fail the very rules the job
      # is running. Pin everything; the trailing comment keeps the version readable.
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"

      # Persist the cache directory between runs, keyed on the org. Within
      # GITHUB_AUDITOR_CACHE_TTL_HOURS (default 24) a re-run reuses what is already
      # cached instead of re-fetching the whole org over the API, which is what makes a
      # manual re-run, a retried job, and the gate step below cheap. The restore-keys
      # prefix lets a scheduled run start from the previous week's DB and refresh only
      # what the TTL has aged out.
      - name: Restore audit cache
        uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ${{ github.workspace }}/.github-auditor
          key: github-auditor-${{ env.AUDIT_ORG }}-${{ github.run_id }}
          restore-keys: |
            github-auditor-${{ env.AUDIT_ORG }}-

      - name: Install github-auditor
        run: pip install github-auditor

      # Step 1 of 2: produce the report. No --fail-on, so this step is non-gating and
      # exits 0 whatever it finds. Keeping report generation and gating in separate steps
      # means the artifact and the job summary below are still published on a run that
      # the gate turns red — if one step both reported and gated, a failing audit would
      # stop the job before anyone got the report explaining why.
      - name: Audit (report)
        env:
          GITHUB_AUDITOR_TOKEN: ${{ secrets.GITHUB_AUDITOR_TOKEN }}
        run: gha audit "$AUDIT_ORG" --format json --output audit.json

      # Human-readable summary on the run page itself, so the result is visible without
      # downloading anything.
      - name: Write job summary
        if: always()
        run: |
          {
            echo "## github-auditor — $AUDIT_ORG"
            echo
            echo "| Severity | Findings |"
            echo "| --- | --- |"
            jq -r '.severity_totals | to_entries[] | "| \(.key) | \(.value) |"' audit.json
            echo
            echo "### Highest-risk repositories"
            echo
            echo "| Repository | Grade | Score |"
            echo "| --- | --- | --- |"
            jq -r '.repos | sort_by(-.risk_score) | .[:10][]
                   | "| \(.repo.full_name) | \(.grade) | \(.risk_score) |"' audit.json
          } >> "$GITHUB_STEP_SUMMARY"

      # The full machine-readable report, kept for diffing against next week's run.
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: github-auditor-${{ env.AUDIT_ORG }}-${{ github.run_id }}
          path: audit.json
          retention-days: 90

      # Step 2 of 2: the gate. --fail-on high exits 1 when any finding is high or
      # critical, which is what turns the run red and sends the notification. The cache
      # is warm from the report step, so this costs no extra API calls.
      - name: Fail on high or critical findings
        env:
          GITHUB_AUDITOR_TOKEN: ${{ secrets.GITHUB_AUDITOR_TOKEN }}
        run: gha audit "$AUDIT_ORG" --fail-on high
```

A few things worth adjusting rather than copying:

- **Gate severity.** `--fail-on high` is a reasonable starting point; on a large org with
  a backlog it will be red from day one and stop meaning anything. Either start at
  `--fail-on critical` and tighten, or keep the gate step but mark it
  `continue-on-error: true` until the backlog is cleared.
- **Gating without a second audit.** The gate step re-runs `gha audit` against the warm
  cache, which keeps the exit-code contract in one place. If you would rather not run the
  command twice, gate on the report instead — `jq -e '.severity_totals | (.critical +
  .high) == 0' audit.json` — and accept that the threshold now lives in two places.
- **Schedule frequency.** The cache TTL defaults to 24 hours, so anything more frequent
  than daily mostly re-reads the cache and reports the same thing. Weekly plus
  `workflow_dispatch` for incidents is the common shape; add `--refresh` if you want a
  scheduled run to ignore the TTL entirely.
- **Deep scans.** `--deep` clones each repository to read workflow files from disk. It is
  substantially slower and wants a longer `timeout-minutes`, but it is the mode that sees
  workflows the API alone does not surface.

## Token scopes

The audit authenticates with its own credential, read from `GITHUB_TOKEN` or
`GITHUB_AUDITOR_TOKEN` (README.md's Configuration table), and *not* from the workflow's
built-in `GITHUB_TOKEN` — that one is scoped to the repository running the workflow and
cannot see the rest of the org.

Prefer a **fine-grained personal access token** over a classic PAT for a scheduled job:

- A fine-grained token is scoped to a named resource owner and an explicit repository set,
  so it can be granted read-only access to exactly the org being audited. A classic PAT's
  `repo` scope, by contrast, covers every repository the issuing account can reach — the
  audited org, plus every other org and personal repo that account has.
- It carries a mandatory expiration, which puts a hard ceiling on how long a leaked
  secret stays useful.
- Issue it from a dedicated machine/bot account, not from an engineer's personal account.
  An unattended weekly job outliving the person who set it up is the normal case: a
  personal PAT means the audit breaks when they change teams, and keeps working with
  their access when they leave.
- Store it as a repository or organization Actions secret (`secrets.GITHUB_AUDITOR_TOKEN`
  above). An organization secret scoped to selected repositories is the better choice if
  several repositories run audits.

### Scope-to-rule mapping

README.md's **Token scopes & graceful degradation** section is the authority on what a
token needs and on the guarantee that matters here: anything the token cannot see is
treated as unknown, never as a finding, so a narrow token yields a smaller audit rather
than false positives. That means you can grant only what the rules you care about need.
The table maps the three scope groups from that section to the rule families they unlock
and to the nearest fine-grained permission:

| Classic scope | Fine-grained equivalent | Unlocks |
| --- | --- | --- |
| *(none — unauthenticated)* | – | `GHA*` on public repositories only, at 60 requests/hour |
| `repo` | Repository permissions: Metadata: Read, Contents: Read, Administration: Read, Actions: Read | `GHA*` on private repositories, `REPO002`–`REPO007`, `ACC001`, `ACC002`, `ACC006` |
| `admin:org` (read) | Organization permissions: Administration: Read, Members: Read, Self-hosted runners: Read | `ORG001`–`ORG006`, and the org-runner half of `REPO001` |
| `security_events` or repo admin | Repository permissions: Secret scanning alerts: Read, Dependabot alerts: Read, Administration: Read | `ACC003`, `ACC004`, `ACC005` |

Read that as a menu. A workflow-only audit — "are our actions pinned, do our workflows
declare permissions" — needs nothing beyond `Metadata: Read` and `Contents: Read` on the
repositories in scope, and on a public org it needs no token at all. Org posture rules
(`ORG*`) are the ones that genuinely require an org owner to issue the token, because
`admin:org` read is not a permission a member can self-grant; if nobody will issue one,
the audit still runs and simply reports nothing for those six rules.

An unauthenticated run works too: public repositories only, 60 requests/hour, enough to
spot public-facing workflow risks. That is a legitimate way to start — schedule the
workflow with no secret at all, confirm it runs and that the report is being read, then
add a token once somebody is acting on the output.

## When GitHub App auth lands

Everything above depends on a standing PAT sitting in an Actions secret, which is exactly
the class of long-lived, broadly-scoped credential this tool's own rules warn about —
`ACC001` (write deploy keys), `ACC002` (standing outside-collaborator write) and `ORG004`
(permanently read-write workflow tokens) are all the same problem in different places.
A fine-grained token with a short expiration narrows the blast radius; it does not remove
the credential.

[Issue #14](https://github.com/brettbergin/github-auditor/issues/14) tracks GitHub App
authentication. A GitHub App is the right credential for an unattended scheduled run: the
installation is scoped to the org and to a named permission set, it belongs to the
organization rather than to a person, and the workflow exchanges the app's private key for
an installation token that expires in an hour instead of storing a token that is valid
until somebody remembers to rotate it. It also raises the rate limit well above what a
single PAT gets, which matters on a large org.

When #14 ships, GitHub App auth becomes the preferred credential for the workflow on this
page, with the PAT flow kept only for local and ad-hoc runs — and this document should be
updated to show the app installation flow as the default example.
