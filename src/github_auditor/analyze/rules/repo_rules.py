"""Rules on repository configuration and Actions settings (REPO001–REPO007)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from github_auditor.analyze.rules.base import RepoContext, Rule
from github_auditor.models import Finding, Severity, utcnow

SELF_HOSTED_LABELS = {"self-hosted"}


class PublicSelfHostedRunnerRule(Rule):
    id = "REPO001"
    name = "public-self-hosted-runner"
    default_severity = Severity.CRITICAL
    description = (
        "A public repository can run workflows on a self-hosted runner. Anyone can fork the "
        "repo and open a pull request whose workflow code executes on your infrastructure — "
        "persistent runners can be backdoored, and their network position and cached "
        "credentials stolen."
    )
    remediation = (
        "Never attach self-hosted runners to public repositories. Use GitHub-hosted runners, "
        "or make the repo private, or restrict runner groups to private repos only."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if not ctx.repo.is_public:
            return
        if ctx.repo.has_self_hosted_runners:
            names = ", ".join(r.name for r in ctx.repo_runners) or "unknown"
            yield self.finding(
                ctx,
                title="Public repo has self-hosted runners registered",
                location="settings/actions/runners",
                evidence=f"runners: {names}",
            )
            return
        # No visible registration — fall back to workflows targeting self-hosted labels.
        for wf in ctx.workflows:
            for job in wf.jobs:
                labels = {label.lower() for label in job.runs_on}
                if labels & SELF_HOSTED_LABELS:
                    yield self.finding(
                        ctx,
                        title="Public repo workflow targets self-hosted runners",
                        severity=Severity.HIGH,
                        location=f"{wf.path} § job:{job.id}",
                        evidence=f"runs-on: {job.runs_on}",
                    )


class NoBranchProtectionRule(Rule):
    id = "REPO002"
    name = "no-branch-protection"
    default_severity = Severity.HIGH
    description = (
        "The default branch has no protection rules. A single compromised account or leaked "
        "token can push directly to the branch that releases, workflows, and consumers trust."
    )
    remediation = (
        "Protect the default branch: require pull-request reviews and status checks, and "
        "disallow force pushes."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        bp = ctx.repo.branch_protection
        if bp is None or ctx.repo.archived:
            return
        if not bp.exists:
            yield self.finding(
                ctx,
                title=f"No branch protection on default branch '{ctx.repo.default_branch}'",
                severity=Severity.HIGH if ctx.repo.is_public else Severity.MEDIUM,
                location=f"settings/branches/{ctx.repo.default_branch}",
            )


class WeakBranchProtectionRule(Rule):
    id = "REPO003"
    name = "weak-branch-protection"
    default_severity = Severity.MEDIUM
    description = (
        "Branch protection exists but is weak: no required reviews, or force pushes/deletions "
        "are allowed, which lets history be rewritten out from under signed-off code."
    )
    remediation = (
        "Require at least one review, enable required status checks, and disallow force "
        "pushes and deletions on the default branch."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        bp = ctx.repo.branch_protection
        if bp is None or not bp.exists or ctx.repo.archived:
            return
        weaknesses = []
        if bp.required_reviews == 0:
            weaknesses.append("no required reviews")
        if bp.allow_force_pushes:
            weaknesses.append("force pushes allowed")
        if bp.allow_deletions:
            weaknesses.append("branch deletion allowed")
        if weaknesses:
            yield self.finding(
                ctx,
                title=f"Weak branch protection on '{ctx.repo.default_branch}'",
                location=f"settings/branches/{ctx.repo.default_branch}",
                evidence=", ".join(weaknesses),
            )


class StaleActiveActionsRule(Rule):
    id = "REPO004"
    name = "stale-repo-actions-enabled"
    default_severity = Severity.MEDIUM
    description = (
        "The repository hasn't been pushed to in years, but GitHub Actions is still enabled "
        "with workflow files present. Nobody is watching it, its workflows and pinned "
        "dependencies age into known vulnerabilities, and it remains an active attack surface "
        "for the whole org."
    )
    remediation = (
        "Archive the repository (archiving disables Actions), or disable Actions for it, or "
        "bring its workflows back under maintenance."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        repo = ctx.repo
        if repo.archived or repo.pushed_at is None:
            return
        if repo.actions_enabled is False:
            return
        if not ctx.raw_workflows:
            return
        age = utcnow() - repo.pushed_at
        threshold = timedelta(days=365.25 * ctx.settings.stale_years)
        if age > threshold:
            years = age.days / 365.25
            yield self.finding(
                ctx,
                title=f"Stale repo (last push {years:.1f}y ago) still has Actions workflows",
                severity=Severity.HIGH if repo.is_public else Severity.MEDIUM,
                evidence=f"pushed_at: {repo.pushed_at:%Y-%m-%d}, "
                f"{len(ctx.raw_workflows)} workflow file(s)",
            )


class ArchivedPublicWorkflowsRule(Rule):
    id = "REPO005"
    name = "archived-public-workflows"
    default_severity = Severity.LOW
    description = (
        "An archived public repository still exposes workflow files. Archived workflows don't "
        "run, but they advertise your (dated) CI patterns and become live again the moment "
        "anyone unarchives or forks the repo."
    )
    remediation = "Consider making long-dead archived repos private or deleting them."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.archived and ctx.repo.is_public and ctx.raw_workflows:
            yield self.finding(
                ctx,
                title="Archived public repo still contains workflow files",
                evidence=f"{len(ctx.raw_workflows)} workflow file(s)",
            )


class DefaultTokenWriteRule(Rule):
    id = "REPO006"
    name = "default-token-write"
    default_severity = Severity.MEDIUM
    description = (
        "The repository's default GITHUB_TOKEN permission is read-write, so every workflow "
        "without an explicit permissions block gets a token that can push code and modify "
        "releases."
    )
    remediation = (
        "Set Settings → Actions → General → Workflow permissions to 'Read repository "
        "contents' and grant write per workflow where needed."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.default_workflow_permissions == "write":
            yield self.finding(
                ctx,
                title="Default GITHUB_TOKEN permissions are read-write",
                location="settings/actions",
            )


class ActionsUnrestrictedRule(Rule):
    id = "REPO007"
    name = "actions-unrestricted"
    default_severity = Severity.LOW
    description = (
        "This public repository may run any action from any author. One malicious or "
        "compromised marketplace action away from executing attacker code with your token."
    )
    remediation = (
        "Restrict allowed actions (Settings → Actions → General) to those created by GitHub, "
        "verified creators, or an explicit allow list."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.is_public and ctx.repo.actions_allowed_actions == "all":
            yield self.finding(
                ctx,
                title="All actions are allowed to run",
                location="settings/actions",
            )
