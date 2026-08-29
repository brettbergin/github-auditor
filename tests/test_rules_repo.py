from datetime import timedelta

from conftest import make_ctx, make_repo
from github_auditor.analyze.rules.repo_rules import (
    ActionsUnrestrictedRule,
    ArchivedPublicWorkflowsRule,
    DefaultTokenWriteRule,
    NoBranchProtectionRule,
    PublicSelfHostedRunnerRule,
    StaleActiveActionsRule,
    WeakBranchProtectionRule,
)
from github_auditor.models import BranchProtectionInfo, RunnerInfo, Severity, utcnow


def run_rule(rule, ctx):
    return list(rule.check(ctx))


def test_public_self_hosted_runner_registered():
    repo = make_repo(has_self_hosted_runners=True)
    ctx = make_ctx(
        repo=repo,
        repo_runners=[RunnerInfo(name="runner-1", level="repo", repo_full_name=repo.full_name)],
    )
    findings = run_rule(PublicSelfHostedRunnerRule(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_self_hosted_labels_fallback():
    ctx = make_ctx(["self_hosted.yml"], repo=make_repo(has_self_hosted_runners=None))
    findings = run_rule(PublicSelfHostedRunnerRule(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_self_hosted_private_repo_skipped():
    ctx = make_ctx(
        ["self_hosted.yml"], repo=make_repo(visibility="private", has_self_hosted_runners=True)
    )
    assert run_rule(PublicSelfHostedRunnerRule(), ctx) == []


def test_branch_protection_unknown_is_skipped():
    ctx = make_ctx(repo=make_repo(branch_protection=None))
    assert run_rule(NoBranchProtectionRule(), ctx) == []


def test_no_branch_protection():
    ctx = make_ctx(repo=make_repo(branch_protection=BranchProtectionInfo(exists=False)))
    findings = run_rule(NoBranchProtectionRule(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # public repo


def test_weak_branch_protection():
    bp = BranchProtectionInfo(exists=True, required_reviews=0, allow_force_pushes=True)
    findings = run_rule(WeakBranchProtectionRule(), make_ctx(repo=make_repo(branch_protection=bp)))
    assert len(findings) == 1
    assert "no required reviews" in findings[0].evidence
    assert "force pushes allowed" in findings[0].evidence


def test_stale_repo_with_actions():
    old = utcnow() - timedelta(days=365 * 4)
    ctx = make_ctx(["unpinned.yml"], repo=make_repo(pushed_at=old, actions_enabled=True))
    findings = run_rule(StaleActiveActionsRule(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # public

    fresh_ctx = make_ctx(["unpinned.yml"], repo=make_repo(pushed_at=utcnow()))
    assert run_rule(StaleActiveActionsRule(), fresh_ctx) == []


def test_stale_repo_without_workflows_skipped():
    old = utcnow() - timedelta(days=365 * 4)
    ctx = make_ctx(repo=make_repo(pushed_at=old, actions_enabled=True))
    assert run_rule(StaleActiveActionsRule(), ctx) == []


def test_archived_public_workflows():
    ctx = make_ctx(["unpinned.yml"], repo=make_repo(archived=True))
    assert len(run_rule(ArchivedPublicWorkflowsRule(), ctx)) == 1


def test_default_token_write():
    ctx = make_ctx(repo=make_repo(default_workflow_permissions="write"))
    assert len(run_rule(DefaultTokenWriteRule(), ctx)) == 1
    ctx_read = make_ctx(repo=make_repo(default_workflow_permissions="read"))
    assert run_rule(DefaultTokenWriteRule(), ctx_read) == []
    ctx_unknown = make_ctx(repo=make_repo(default_workflow_permissions=None))
    assert run_rule(DefaultTokenWriteRule(), ctx_unknown) == []


def test_actions_unrestricted():
    ctx = make_ctx(repo=make_repo(actions_allowed_actions="all"))
    assert len(run_rule(ActionsUnrestrictedRule(), ctx)) == 1
    ctx2 = make_ctx(repo=make_repo(actions_allowed_actions="selected"))
    assert run_rule(ActionsUnrestrictedRule(), ctx2) == []
