from github_auditor.analyze.rules.base import OrgContext
from github_auditor.analyze.rules.org_rules import (
    BaseMemberPermissionRule,
    MembersCanCreatePublicReposRule,
    OrgActionsApprovePrRule,
    OrgDefaultTokenWriteRule,
    OrgForkPrApprovalRule,
    TwoFactorNotRequiredRule,
)
from github_auditor.config import Settings
from github_auditor.models import ORG_SCOPE, OrgInfo, Severity


def make_org_ctx(**overrides) -> OrgContext:
    org_info = OrgInfo(login="testorg", **overrides)
    return OrgContext(
        org="testorg",
        org_info=org_info,
        settings=Settings(github_token=None, _env_file=None),
    )


def run_rule(rule, ctx):
    return list(rule.check(ctx))


def test_two_factor_not_required():
    findings = run_rule(
        TwoFactorNotRequiredRule(), make_org_ctx(two_factor_requirement_enabled=False)
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].is_org_scoped
    assert findings[0].repo == ORG_SCOPE


def test_two_factor_enabled_or_unknown_clean():
    assert (
        run_rule(TwoFactorNotRequiredRule(), make_org_ctx(two_factor_requirement_enabled=True))
        == []
    )
    # Unknown (non-owner token) must never produce a finding.
    assert run_rule(TwoFactorNotRequiredRule(), make_org_ctx()) == []


def test_two_factor_skipped_for_user_accounts():
    ctx = make_org_ctx(is_user=True, two_factor_requirement_enabled=False)
    assert run_rule(TwoFactorNotRequiredRule(), ctx) == []


def test_base_permission_grades_write_vs_admin():
    write = run_rule(
        BaseMemberPermissionRule(), make_org_ctx(default_repository_permission="write")
    )
    assert len(write) == 1
    assert write[0].severity == Severity.MEDIUM

    admin = run_rule(
        BaseMemberPermissionRule(), make_org_ctx(default_repository_permission="admin")
    )
    assert len(admin) == 1
    assert admin[0].severity == Severity.HIGH


def test_base_permission_read_or_unknown_clean():
    for permission in ("read", "none"):
        ctx = make_org_ctx(default_repository_permission=permission)
        assert run_rule(BaseMemberPermissionRule(), ctx) == []
    assert run_rule(BaseMemberPermissionRule(), make_org_ctx()) == []


def test_fork_pr_approval_policy():
    lax = run_rule(
        OrgForkPrApprovalRule(), make_org_ctx(fork_pr_approval_policy="first_time_contributors")
    )
    assert len(lax) == 1
    assert lax[0].severity == Severity.HIGH

    strict = make_org_ctx(fork_pr_approval_policy="all_external_contributors")
    assert run_rule(OrgForkPrApprovalRule(), strict) == []
    assert run_rule(OrgForkPrApprovalRule(), make_org_ctx()) == []


def test_org_default_token_write():
    assert (
        len(
            run_rule(OrgDefaultTokenWriteRule(), make_org_ctx(default_workflow_permissions="write"))
        )
        == 1
    )
    assert (
        run_rule(OrgDefaultTokenWriteRule(), make_org_ctx(default_workflow_permissions="read"))
        == []
    )
    assert run_rule(OrgDefaultTokenWriteRule(), make_org_ctx()) == []


def test_org_actions_can_approve_prs():
    findings = run_rule(
        OrgActionsApprovePrRule(), make_org_ctx(can_approve_pull_request_reviews=True)
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert run_rule(OrgActionsApprovePrRule(), make_org_ctx()) == []


def test_members_can_create_public_repos():
    ctx = make_org_ctx(members_can_create_public_repositories=True)
    assert len(run_rule(MembersCanCreatePublicReposRule(), ctx)) == 1
    off = make_org_ctx(members_can_create_public_repositories=False)
    assert run_rule(MembersCanCreatePublicReposRule(), off) == []
    assert run_rule(MembersCanCreatePublicReposRule(), make_org_ctx()) == []
