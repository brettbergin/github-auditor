# CLI reference

`github-auditor` installs two equivalent entry points: `github-auditor` and the short
`gha`. Every example below uses `gha`; the long name behaves identically. The commands
live in
[`src/github_auditor/cli/__init__.py`](../src/github_auditor/cli/__init__.py), which is
the source of truth if this page and the code ever disagree.

Running `gha` with no arguments prints the help and exits.

## Global

```bash
gha --version          # prints "github-auditor <version>" and exits 0
gha --help             # top-level help; `gha <command> --help` for one command
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--version` | off | Print the installed version and exit 0. Eager: it runs before any command. |
| `--help` | – | Show help and exit. Also valid per command. |
| `--install-completion` / `--show-completion` | – | Standard Typer shell-completion helpers. |

### The ORG argument

Every command that touches an organization takes `ORG` as an optional positional
argument. When it is omitted, the value falls back to the `GITHUB_AUDITOR_ORG`
environment variable (read by `Settings`, so a `.env` file in the working directory
works too). If neither is set the command prints
`No organization given. Pass ORG or set GITHUB_AUDITOR_ORG.` and exits with code 2.

```bash
gha audit your-org                       # explicit
GITHUB_AUDITOR_ORG=your-org gha audit    # from the environment
```

A user account works anywhere an organization does; org-scoped rules simply find
nothing to report.

### Severity values

Wherever a severity is accepted — `--min-severity`, `--fail-on`, `--severity` — the
value is matched case-insensitively against the `Severity` enum:

`critical`, `high`, `medium`, `low`, `info`

Anything else prints `Unknown severity '<value>'` with the list of valid choices and
exits with code 2.

## `audit`

Fetch (respecting the cache TTL), analyze, and render a full audit. This is the one
command that both hits the network and produces a report, and the only one that can
exit 1.

```bash
gha audit your-org
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--refresh` | off | Ignore the cache TTL (24h by default) and re-fetch everything from the API. |
| `--deep` | off | After fetching, clone each non-archived repo that has workflows and re-read the workflow files from disk, catching files the API listing misses. |
| `--include-archived` / `--no-archived` | `--include-archived` | Include archived repositories in the fetch and the analysis, or leave them out. |
| `--format`, `-f` | `table` | Output format: `table`, `json`, or `csv`. Any other value renders the table. |
| `--min-severity` | none | Drop findings below this severity from the report before it is rendered. |
| `--rules` | none (all rules) | Comma-separated rule ids or names to run — everything else is skipped. |
| `--exclude-rules` | none | Comma-separated rule ids or names to skip; every other rule runs. |
| `--fail-on` | none | Exit 1 if any finding is at or above this severity. Intended for CI gates. |
| `--output`, `-o` | stdout | Write the report to this file instead of stdout. A short confirmation still goes to stderr. |
| `--db` | `~/.github-auditor/cache.db` | Use a different SQLite cache file (also settable as `GITHUB_AUDITOR_DB_PATH`). |

Examples:

```bash
gha audit your-org --refresh                        # ignore the cache TTL
gha audit your-org --deep                           # clone repos for the workflow read
gha audit your-org --no-archived                    # skip archived repos
gha audit your-org --format json -o audit.json      # machine-readable report to a file
gha audit your-org --min-severity high              # hide medium/low/info findings
gha audit your-org --rules GHA001,GHA002            # only the pwn-request and pinning rules
gha audit your-org --exclude-rules REPO003          # everything except that rule
gha audit your-org --fail-on high                   # CI gate: exit 1 on high or critical
gha audit your-org --db ./audit-cache.db            # keep this run's cache out of $HOME
```

`--rules` and `--exclude-rules` both match on rule id (`GHA001`) or rule name
(`pwn-request`), case-insensitively. `gha rules` lists every id and name.

Both flags select **repository-scoped rules only** (`GHA…`, `REPO…`, `ACC…`). The
organization rules (`ORG…`) always run: `--rules GHA001` still reports every `ORG…`
finding, and `--exclude-rules ORG001` does not suppress it. To drop org findings from
the output, filter them out downstream — they carry `"repo": "<organization>"`. The
`PARSE` info findings for unparseable workflow YAML are likewise always emitted and
cannot be excluded.

Two notes on combining flags:

- `--min-severity` is applied to the report *before* `--fail-on` is evaluated, so a
  `--min-severity` stricter than `--fail-on` hides the very findings the threshold
  would have tripped on. For a CI gate, set `--fail-on` and leave `--min-severity`
  alone.
- Without `GITHUB_TOKEN` the fetch runs unauthenticated (60 requests/hour, public data
  only) and warns on stderr. Posture fields the token cannot see stay unknown, and
  unknown is never a finding.

## `fetch` (alias: `sync`)

Populate the local cache without analyzing anything. Useful when you want to fetch once
with a privileged token and then re-analyze offline with `gha report`, or to warm the
cache before a run.

`sync` is registered as a hidden alias: it does not appear in `gha --help`, but
`gha sync your-org` is accepted and behaves exactly like `gha fetch your-org`.

```bash
gha fetch your-org
gha sync your-org      # identical, hidden alias
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--refresh` | off | Ignore the cache TTL and re-fetch everything from the API. |
| `--deep` | off | Also clone repos with workflows and read their workflow files from disk. |
| `--include-archived` / `--no-archived` | `--include-archived` | Fetch archived repositories, or skip them. |
| `--db` | `~/.github-auditor/cache.db` | Cache database path override. |

Examples:

```bash
gha fetch your-org --refresh                  # force a full re-fetch
gha fetch your-org --deep --no-archived       # clone live repos only
gha fetch your-org --db ./audit-cache.db      # write to a scratch cache
```

`fetch` prints a one-line summary to stderr (repos seen, fetched, fresh in cache,
removed) and reports per-repo fetch errors without failing the run; it produces no
report and no findings, so it never exits 1.

## `report`

Re-analyze whatever is already in the cache and render the report. `report` never
touches the network: it reads the cached repositories, runs every rule over them, and
prints the result. Use it to re-render a different format or a different severity cut
without paying for another fetch.

If the cache holds nothing for the org it prints
`Nothing cached for '<org>'. Run 'gha fetch <org>' first.` and exits with code 2.

```bash
gha report your-org
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--repo` | none (whole org) | Show the full finding detail for one repository instead of the summary table. Matches either the full name (`your-org/api`) or the bare name (`api`). Table format only. |
| `--format`, `-f` | `table` | Output format: `table`, `json`, or `csv`. |
| `--min-severity` | none | Drop findings below this severity before rendering. |
| `--include-archived` / `--no-archived` | `--include-archived` | Include archived repositories in the analysis, or leave them out. |
| `--output`, `-o` | stdout | Write the report to this file instead of stdout. |
| `--db` | `~/.github-auditor/cache.db` | Cache database path override. |

Examples:

```bash
gha report your-org                                  # re-render the cached audit
gha report your-org --repo your-org/deploy-tools     # every finding for one repo
gha report your-org --repo deploy-tools              # bare name works too
gha report your-org --format csv -o findings.csv     # spreadsheet export, no network
gha report your-org --min-severity high              # only high and critical
gha report your-org --no-archived                    # ignore archived repos
gha report your-org --db ./audit-cache.db            # read a scratch cache
```

`--repo` is resolved against the report that was just built, so a name that is not in
the cache prints `Repo '<name>' not found in report.` and exits with code 2. `--repo`
only changes the `table` rendering; with `--format json` or `--format csv` the full
report is emitted regardless.

Unlike `audit`, `report` has no `--fail-on`, so it never exits 1.

## `repos`

List the cached repositories with their risk score, grade and finding count. Like
`report`, it analyzes the cache and never hits the network, and it exits 2 when nothing
is cached for the org. Archived repositories are always included.

```bash
gha repos your-org
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--sort` | `score` | Row order. Accepted values: `score`, `name`, `pushed`. |
| `--db` | `~/.github-auditor/cache.db` | Cache database path override. |

The three `--sort` values:

| Value | Order |
|-------|-------|
| `score` (default) | Highest risk score first, ties broken by repository full name. Any unrecognized value falls back to this. |
| `name` | Alphabetical by full name (`your-org/api` before `your-org/web`). |
| `pushed` | Oldest `pushed_at` first, so the most neglected repositories lead. Repos with no push date sort first. |

Examples:

```bash
gha repos your-org                       # riskiest first (default)
gha repos your-org --sort name           # alphabetical
gha repos your-org --sort pushed         # stalest first
gha repos your-org --db ./audit-cache.db
```

The table columns are Repository, Visibility, Archived, Grade, Score, Findings and Last
push. `repos` has no `--format`: it always prints the table.

## `findings`

Show the findings recorded by the most recent completed audit run for the org, straight
out of the cache. `audit`, `report` and `repos` all record a run when they analyze, so
the newest of those is what `findings` reads.

If the org has no completed audit run at all it prints
`No audit runs cached for '<org>'. Run 'gha audit <org>' first.` and exits with code 2.
An empty result from a run that exists is not an error — it prints `No findings match.`
and exits 0.

```bash
gha findings your-org
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--severity` | none | Exact severity match — `--severity high` shows high findings only, not critical ones. |
| `--min-severity` | none | Threshold match: this severity and everything above it. |
| `--rule` | none | Only findings from this rule id, matched case-insensitively (`GHA001`, `gha001`). |
| `--repo` | none | Only findings for this repository, matched on the exact full name (`your-org/api`). Use `<organization>` for org-scoped findings. |
| `--format`, `-f` | `table` | Output format: `table`, `json`, or `csv`. |
| `--db` | `~/.github-auditor/cache.db` | Cache database path override. |

Examples:

```bash
gha findings your-org                                  # everything from the last run
gha findings your-org --severity critical              # exactly critical
gha findings your-org --min-severity high              # high and critical
gha findings your-org --rule GHA001                    # one rule across the org
gha findings your-org --repo your-org/deploy-tools     # one repository
gha findings your-org --repo '<organization>'          # org-scoped findings only
gha findings your-org --format json | jq '.[].rule_id' # pipe into jq
gha findings your-org --db ./audit-cache.db
```

`--severity` and `--min-severity` can be combined, and both apply; rows come back sorted
by severity (highest first), then repository, then rule id. `--format json` here emits a
flat array of finding objects rather than the full report envelope that
`audit --format json` produces.

## `rules`

Print the full rule catalogue — every organization rule followed by every repository
rule — as an "Available rules" table with ID, Name, Severity and "Checks for"
(the rule's description). This is the authoritative list of the values `--rules`,
`--exclude-rules` and `--rule` accept — bearing in mind that `--rules`/`--exclude-rules`
only take effect for the repository-scoped families, while `findings --rule` matches any
id including `ORG…`.

`rules` takes no options at all: no `ORG`, no `--db`, no `--format`. It needs neither
the cache nor a token.

```bash
gha rules                       # the whole catalogue
gha rules | grep -i runner      # find the rule id you want to exclude
```

## `cache info`

Show what the local cache holds: database path and size, the organizations in it, and
counts of repositories, workflow files, audit runs and findings, plus the newest and
oldest fetch timestamps.

```bash
gha cache info
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--db` | `~/.github-auditor/cache.db` | Inspect a different cache file instead of the default. |

```bash
gha cache info --db ./audit-cache.db     # inspect a scratch cache
```

The command creates the database file if it does not exist yet, so a fresh `cache info`
reports zeros rather than failing.

## `cache clear`

Delete cached API data, and by default the cached git clones `--deep` created too.

```bash
gha cache clear
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--org` | none (everything) | Only clear this organization's cached data and its clone directory. Without it, *all* cached data is removed. |
| `--clones` / `--no-clones` | `--clones` | Also delete cached clones under `~/.github-auditor/clones`, or keep them and clear only the database. |
| `--yes`, `-y` | off | Skip the confirmation prompt. Required for unattended use. |
| `--db` | `~/.github-auditor/cache.db` | Cache database path override. |

Examples:

```bash
gha cache clear                          # prompts: "Clear ALL cached data?"
gha cache clear --org your-org           # prompts: "Clear org 'your-org'?"
gha cache clear --org your-org --yes     # no prompt, for scripts
gha cache clear --no-clones --yes        # drop the database rows, keep the clones
gha cache clear --db ./audit-cache.db -y # clear a scratch cache
```

Without `--yes` the command asks for confirmation and exits 0 if you decline, leaving
the cache untouched. On success it prints what it cleared, and how many clone
directories it removed, to stderr.

## Format values

Three commands take `--format` / `-f`, and they all accept the same three values:

| Command | `--format` values | Default |
|---------|-------------------|---------|
| `audit` | `table`, `json`, `csv` | `table` |
| `report` | `table`, `json`, `csv` | `table` |
| `findings` | `table`, `json`, `csv` | `table` |

`repos`, `rules`, `cache info` and `cache clear` have no `--format`; `fetch`/`sync`
produces no report at all.

An unrecognized `--format` value is not an error: anything that is neither `json` nor
`csv` renders the table.

One command has its own value set instead:

| Command | Flag | Accepted values | Default |
|---------|------|-----------------|---------|
| `repos` | `--sort` | `score`, `name`, `pushed` | `score` |

And severities, accepted by `--min-severity`, `--fail-on` and `--severity`, are
`critical`, `high`, `medium`, `low`, `info` (case-insensitive) — see
[Severity values](#severity-values).

## Sample output

The blocks below are real output from the shapes this CLI renders, for a three-repo org
with one clean repository.

### `--format table`

The default. A summary panel, the organization-wide findings, and the
**Repositories by risk** table — which lists only repositories that have findings, with
a per-severity breakdown across the Crit/High/Med/Low columns:

```text
╭───────────────────────────────────── GitHub Security Audit ──────────────────────────────────────╮
│ Organization: your-org                                                                           │
│ Repositories audited: 3                                                                          │
│ Generated: 2026-09-12 14:03 UTC                                                                  │
│                                                                                                  │
│ CRITICAL: 1   HIGH: 3   MEDIUM: 2   LOW: 1   INFO: 0                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
Organization settings  (1 finding(s) affecting every repository)
└── HIGH  ORG001  Two-factor authentication is not required for members
    ├── two_factor_requirement_enabled = false
    └── fix: Organization settings -> Authentication security: require 2FA.

                                        Repositories by risk
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━┳━━━━━┳━━━━━━━━━━━━┓
┃ Repository              ┃ Visibility  ┃ Grade  ┃  Score ┃  Crit ┃  High ┃ Med ┃ Low ┃ Last push  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━╇━━━━━╇━━━━━━━━━━━━┩
│ your-org/deploy-tools   │ public      │   F    │     79 │     1 │     1 │   1 │   1 │ 2026-09-12 │
│ your-org/legacy-api     │ private     │   D    │     27 │     0 │     1 │   1 │   0 │ 2026-06-02 │
└─────────────────────────┴─────────────┴────────┴────────┴───────┴───────┴─────┴─────┴────────────┘
1 repo(s) with no findings not shown.
```

In a terminal the severities and grades are colour-coded; the colours are dropped when
the output is redirected to a file or a pipe. Terminal width decides the column widths —
when stdout is not a TTY the tables render at 140 columns (120 with `--output`).

### `--format json`

`audit --format json` (and `report --format json`) emits the whole report envelope:
`org`, `generated_at`, a `repos` array with each repository's `repo` object, `findings`,
computed `risk_score` and `grade`, then `org_findings` and the top-level
`severity_totals` map. Repositories with no findings are included, unlike in the table.
The repo objects are abbreviated here — the real payload carries every posture field,
with `null` for anything the token could not see:

```json
{
  "org": "your-org",
  "generated_at": "2026-09-12T14:03:00Z",
  "repos": [
    {
      "repo": {
        "id": 68206,
        "full_name": "your-org/deploy-tools",
        "name": "deploy-tools",
        "org": "your-org",
        "visibility": "public",
        "archived": false,
        "fork": false,
        "default_branch": "main",
        "pushed_at": "2026-09-12T00:00:00Z",
        "html_url": "https://github.com/your-org/deploy-tools",
        "clone_url": "https://github.com/your-org/deploy-tools.git",
        "actions_enabled": true,
        "actions_allowed_actions": "all",
        "default_workflow_permissions": "write",
        "can_approve_pull_request_reviews": null,
        "secret_scanning": null,
        "push_protection": null,
        "dependabot_alerts": true,
        "branch_protection": null,
        "deploy_keys": null,
        "outside_collaborators": null,
        "has_self_hosted_runners": null,
        "fetched_at": "2026-09-12T14:03:00Z"
      },
      "findings": [
        {
          "rule_id": "GHA001",
          "rule_name": "pwn-request",
          "severity": "critical",
          "title": "pull_request_target checks out untrusted PR code",
          "description": "A pull_request_target workflow checks out the PR head and runs it with the base repository's secrets.",
          "remediation": "Split the workflow: build on pull_request, comment on pull_request_target.",
          "repo": "your-org/deploy-tools",
          "location": ".github/workflows/pr.yml",
          "evidence": "ref: ${{ github.event.pull_request.head.sha }}",
          "created_at": "2026-09-12T14:03:00Z"
        }
      ],
      "risk_score": 79,
      "grade": "F"
    },
    {
      "repo": { "full_name": "your-org/docs-site", "visibility": "public", "archived": false },
      "findings": [],
      "risk_score": 0,
      "grade": "A"
    }
  ],
  "org_findings": [
    {
      "rule_id": "ORG001",
      "rule_name": "no-2fa-requirement",
      "severity": "high",
      "title": "Two-factor authentication is not required for members",
      "description": "Without a 2FA requirement a single phished member password is enough to push code.",
      "remediation": "Organization settings -> Authentication security: require 2FA.",
      "repo": "<organization>",
      "location": "settings/security",
      "evidence": "two_factor_requirement_enabled = false",
      "created_at": "2026-09-12T14:03:00Z"
    }
  ],
  "severity_totals": {
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
  }
}
```

Org-scoped findings carry the sentinel `"repo": "<organization>"` instead of a
repository name. `findings --format json` is different: it is a flat array of exactly
these finding objects, with no envelope and no `severity_totals`.

### `--format csv`

One row per finding, org-scoped findings included, with the header row always written
first. The columns are fixed (`CSV_FIELDS` in
[`src/github_auditor/output/export.py`](../src/github_auditor/output/export.py)) and
standard CSV quoting applies to any value containing a comma:

```csv
rule_id,rule_name,severity,repo,title,location,evidence,remediation
GHA001,pwn-request,critical,your-org/deploy-tools,pull_request_target checks out untrusted PR code,.github/workflows/pr.yml,ref: ${{ github.event.pull_request.head.sha }},"Split the workflow: build on pull_request, comment on pull_request_target."
```

The `description` field is not exported to CSV — use `--format json` if you need it.

## Exit codes

The process exit code is the contract CI depends on:

| Code | When |
|------|------|
| 0 | Success. Includes `audit` finding nothing at or above `--fail-on`, and `audit` finding anything at all when `--fail-on` was not given. |
| 1 | `audit` only: at least one finding is at or above the `--fail-on` severity. |
| 2 | Usage or operational error — nothing was audited, or the arguments were wrong. |

**Exit code 0** is the default outcome of every command that completes. Findings alone
do not fail the process; only `--fail-on` turns them into a non-zero exit.

**Exit code 1** is raised by `audit` and by nothing else, after the report has already
been rendered, when `--fail-on` is set and some finding's severity is at or above it.
Severity comparison uses the ranking `critical` > `high` > `medium` > `low` > `info`, so
`--fail-on high` trips on high and critical findings.

**Exit code 2** covers every failure the tool raises itself:

- No organization could be resolved — no `ORG` argument and no `GITHUB_AUDITOR_ORG`.
- An unknown value for `--min-severity`, `--fail-on` or `--severity`.
- An `AuditorError` caught during the fetch stage of `fetch`/`sync` or `audit` —
  authentication failure, rate limiting, or a cache/clone error. The message is printed
  to stderr.
- Nothing usable in the cache for the requested org (for the offline commands), or a
  `--repo` that is not present in the report.

Typer also uses exit code 2 for its own usage errors, such as an unknown flag.

A CI gate therefore looks like this, and distinguishes "findings" from "the audit did
not run":

```bash
gha audit your-org --fail-on high --format json --output audit.json
case $? in
  0) echo "clean below the threshold" ;;
  1) echo "findings at or above high" ;;
  *) echo "the audit failed to run" ;;
esac
```
