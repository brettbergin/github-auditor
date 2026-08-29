"""Organization-wide posture rules (ORG001–ORG006).

These read settings GitHub reports through its organization APIs. One
misconfigured org default applies to every repository underneath it — including
repos created tomorrow — which is why they carry weight despite being few.

Every field is tri-state: ``None`` means the token cannot see the setting (most
require org-owner or ``admin:org`` read), and unknown is never a finding.
"""

from __future__ import annotations

from collections.abc import Iterator

from github_auditor.analyze.rules.base import OrgContext, OrgRule
from github_auditor.models import Finding, Severity

ORG_SETTINGS_PATH = "settings/security"
ORG_ACTIONS_PATH = "settings/actions"
ORG_MEMBER_PRIVILEGES_PATH = "settings/member_privileges"

# Fork-PR approval policies, loosest first. Only requiring approval from every
# outside contributor closes the "stranger runs code in your CI" path.
FORK_PR_POLICIES_WITHOUT_FULL_APPROVAL = {
    "first_time_contributors_new_to_github",
    "first_time_contributors",
}


class TwoFactorNotRequiredRule(OrgRule):
    id = "ORG001"
    name = "org-2fa-not-required"
    default_severity = Severity.HIGH
    description = (
        "The organization does not require two-factor authentication. Any member's password "
        "compromise — credential stuffing, phishing, a reused password in a breach dump — "
        "becomes direct write access to organization repositories with no second factor in "
        "the way. Account takeover is the most common route into a repository, and this one "
        "control blocks the entire class."
    )
    remediation = (
        "Organization Settings → Authentication security → require two-factor authentication "
        "for everyone. Give notice first: enabling it removes members and outside "
        "collaborators who do not yet have 2FA."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        if ctx.org_info.is_user:
            return
        if ctx.org_info.two_factor_requirement_enabled is False:
            yield self.finding(
                ctx,
                title="Two-factor authentication is not required for organization members",
                location=ORG_SETTINGS_PATH,
            )


class BaseMemberPermissionRule(OrgRule):
    id = "ORG002"
    name = "org-base-permission-write"
    default_severity = Severity.MEDIUM
    description = (
        "The organization's base permission grants every member write (or admin) on every "
        "repository. A single compromised member account can push anywhere in the org, and "
        "the blast radius grows automatically with each new hire and each new repo. It also "
        "defeats per-repository access control: team grants become decoration on top of a "
        "floor that already allows writes everywhere."
    )
    remediation = (
        "Organization Settings → Member privileges → Base permissions → set to Read (or No "
        "permission), then grant write through teams on the repositories that need it."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        permission = ctx.org_info.default_repository_permission
        if permission not in ("write", "admin"):
            return
        yield self.finding(
            ctx,
            title=f"Every member has '{permission}' access to every repository",
            # Admin additionally allows disabling branch protection and security
            # features, and deleting repositories outright.
            severity=Severity.HIGH if permission == "admin" else Severity.MEDIUM,
            location=ORG_MEMBER_PRIVILEGES_PATH,
            evidence=f"default_repository_permission: {permission}",
        )


class OrgForkPrApprovalRule(OrgRule):
    id = "ORG003"
    name = "org-fork-pr-no-approval"
    default_severity = Severity.HIGH
    description = (
        "Workflows on pull requests from forks run without maintainer approval. Anyone can "
        "fork a public repo, open a pull request, and cause the organization's CI to execute "
        "their code with no human in the loop — compute abuse and a probing foothold on "
        "GitHub-hosted runners, and arbitrary code execution on org infrastructure wherever a "
        "self-hosted runner is attached."
    )
    remediation = (
        "Organization Settings → Actions → General → Fork pull request workflows → require "
        "approval for all outside collaborators."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        policy = ctx.org_info.fork_pr_approval_policy
        if policy is None or policy not in FORK_PR_POLICIES_WITHOUT_FULL_APPROVAL:
            return
        yield self.finding(
            ctx,
            title="Fork pull request workflows run without approval from all contributors",
            location=ORG_ACTIONS_PATH,
            evidence=f"approval policy: {policy}",
        )


class OrgDefaultTokenWriteRule(OrgRule):
    id = "ORG004"
    name = "org-default-token-write"
    default_severity = Severity.MEDIUM
    description = (
        "The organization's default workflow permission is read/write, so every workflow in "
        "every repo that declares no permissions block receives a token that can push "
        "commits, move tags, and modify releases. This is what makes a missing permissions "
        "block (GHA007) dangerous rather than merely untidy — the two compound."
    )
    remediation = (
        "Organization Settings → Actions → General → Workflow permissions → read repository "
        "contents and packages. Grant write per job in the workflows that need it."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        if ctx.org_info.default_workflow_permissions == "write":
            yield self.finding(
                ctx,
                title="Default GITHUB_TOKEN permissions are read-write org-wide",
                location=ORG_ACTIONS_PATH,
            )


class OrgActionsApprovePrRule(OrgRule):
    id = "ORG005"
    name = "org-actions-can-approve-prs"
    default_severity = Severity.HIGH
    description = (
        "GitHub Actions may create and approve pull requests across the organization. "
        "Combined with any code-execution flaw in a workflow, an attacker can approve and "
        "merge their own changes, defeating required-review branch protection everywhere at "
        "once."
    )
    remediation = (
        "Organization Settings → Actions → General → uncheck 'Allow GitHub Actions to create "
        "and approve pull requests'."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        if ctx.org_info.can_approve_pull_request_reviews:
            yield self.finding(
                ctx,
                title="Workflows may create and approve pull requests org-wide",
                location=ORG_ACTIONS_PATH,
            )


class MembersCanCreatePublicReposRule(OrgRule):
    id = "ORG006"
    name = "org-members-create-public-repos"
    default_severity = Severity.MEDIUM
    description = (
        "Any member can create public repositories. Accidental public exposure of an internal "
        "codebase is a leading source of leaked credentials and proprietary source — one "
        "wrong visibility choice and bots scrape the repo within minutes. This is also how "
        "the aging public repos this tool exists to find enter the organization."
    )
    remediation = (
        "Organization Settings → Member privileges → Repository creation → restrict public "
        "repository creation to owners, or route creation through a request process."
    )

    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        if ctx.org_info.members_can_create_public_repositories:
            yield self.finding(
                ctx,
                title="Organization members can create public repositories",
                location=ORG_MEMBER_PRIVILEGES_PATH,
            )
