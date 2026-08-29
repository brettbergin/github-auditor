"""Rules on access controls and platform security features (ACC001–ACC006)."""

from __future__ import annotations

from collections.abc import Iterator

from github_auditor.analyze.rules.base import RepoContext, Rule
from github_auditor.models import Finding, Severity

WRITE_PERMISSIONS = {"push", "maintain", "admin"}


class WritableDeployKeyRule(Rule):
    id = "ACC001"
    name = "writable-deploy-key"
    default_severity = Severity.HIGH
    description = (
        "A deploy key with write access exists. Deploy keys don't expire, aren't tied to a "
        "user, bypass branch protection push restrictions in some configurations, and a "
        "leaked one grants silent write access indefinitely."
    )
    remediation = (
        "Make deploy keys read-only wherever possible; rotate and audit any that must write."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.deploy_keys is None:
            return
        for key in ctx.repo.deploy_keys:
            if not key.read_only:
                created = f", created {key.created_at:%Y-%m-%d}" if key.created_at else ""
                yield self.finding(
                    ctx,
                    title=f"Writable deploy key: '{key.title}'",
                    location="settings/keys",
                    evidence=f"key id {key.id}{created}",
                )


class OutsideCollaboratorWriteRule(Rule):
    id = "ACC002"
    name = "outside-collaborator-write"
    default_severity = Severity.MEDIUM
    description = (
        "An outside collaborator (not an org member, so exempt from org policies like 2FA "
        "enforcement and SSO) holds write or admin access to this repository."
    )
    remediation = (
        "Review outside collaborators; convert long-term ones to org members and downgrade "
        "or remove the rest."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.outside_collaborators is None:
            return
        for collab in ctx.repo.outside_collaborators:
            if collab.permission in WRITE_PERMISSIONS:
                yield self.finding(
                    ctx,
                    title=f"Outside collaborator '{collab.login}' has {collab.permission} access",
                    severity=Severity.HIGH if collab.permission == "admin" else Severity.MEDIUM,
                    location="settings/access",
                )


class SecretScanningDisabledRule(Rule):
    id = "ACC003"
    name = "secret-scanning-disabled"
    default_severity = Severity.MEDIUM
    description = (
        "Secret scanning is disabled on this public repository, so leaked tokens and keys in "
        "its history go undetected — and public repo leaks are harvested by bots within "
        "minutes."
    )
    remediation = "Enable secret scanning (free for public repos) under Settings → Security."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.is_public and ctx.repo.secret_scanning is False:
            yield self.finding(
                ctx,
                title="Secret scanning disabled on public repo",
                location="settings/security_analysis",
            )


class PushProtectionDisabledRule(Rule):
    id = "ACC004"
    name = "push-protection-disabled"
    default_severity = Severity.LOW
    description = (
        "Secret scanning push protection is disabled, so secrets are only found after they "
        "have already landed in (public) history."
    )
    remediation = "Enable push protection under Settings → Security → Secret scanning."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.is_public and ctx.repo.push_protection is False:
            yield self.finding(
                ctx,
                title="Secret scanning push protection disabled",
                location="settings/security_analysis",
            )


class DependabotDisabledRule(Rule):
    id = "ACC005"
    name = "dependabot-alerts-disabled"
    default_severity = Severity.LOW
    description = (
        "Dependabot vulnerability alerts are disabled, so known-vulnerable dependencies "
        "(including the actions this repo runs) accumulate silently."
    )
    remediation = "Enable Dependabot alerts under Settings → Security."

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.archived:
            return
        if ctx.repo.dependabot_alerts is False:
            yield self.finding(
                ctx,
                title="Dependabot alerts disabled",
                location="settings/security_analysis",
            )


class ForkPrApprovalRule(Rule):
    id = "ACC006"
    name = "actions-can-approve-prs"
    default_severity = Severity.HIGH
    description = (
        "GitHub Actions workflows are allowed to create and approve pull requests. Combined "
        "with any code-execution bug in a workflow, an attacker can approve and merge their "
        "own changes, defeating required-review branch protection."
    )
    remediation = (
        "Disable 'Allow GitHub Actions to create and approve pull requests' under "
        "Settings → Actions → General."
    )

    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        if ctx.repo.can_approve_pull_request_reviews:
            yield self.finding(
                ctx,
                title="Workflows may create and approve pull requests",
                severity=Severity.HIGH if ctx.repo.is_public else Severity.MEDIUM,
                location="settings/actions",
            )
