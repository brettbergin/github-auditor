from conftest import make_ctx, make_repo
from github_auditor.analyze.rules.access_rules import (
    DependabotDisabledRule,
    ForkPrApprovalRule,
    OutsideCollaboratorWriteRule,
    PushProtectionDisabledRule,
    SecretScanningDisabledRule,
    WritableDeployKeyRule,
)
from github_auditor.models import CollaboratorInfo, DeployKeyInfo, Severity


def run_rule(rule, ctx):
    return list(rule.check(ctx))


def test_writable_deploy_key():
    keys = [
        DeployKeyInfo(id=1, title="ci-push", read_only=False),
        DeployKeyInfo(id=2, title="readonly", read_only=True),
    ]
    findings = run_rule(WritableDeployKeyRule(), make_ctx(repo=make_repo(deploy_keys=keys)))
    assert len(findings) == 1
    assert "ci-push" in findings[0].title


def test_deploy_keys_unknown_skipped():
    assert run_rule(WritableDeployKeyRule(), make_ctx(repo=make_repo(deploy_keys=None))) == []


def test_outside_collaborator_write():
    collabs = [
        CollaboratorInfo(login="ex-contractor", permission="admin"),
        CollaboratorInfo(login="helper", permission="push"),
        CollaboratorInfo(login="viewer", permission="pull"),
    ]
    findings = run_rule(
        OutsideCollaboratorWriteRule(),
        make_ctx(repo=make_repo(outside_collaborators=collabs)),
    )
    assert len(findings) == 2
    by_login = {f.title: f.severity for f in findings}
    assert any("ex-contractor" in t and s == Severity.HIGH for t, s in by_login.items())
    assert any("helper" in t and s == Severity.MEDIUM for t, s in by_login.items())


def test_secret_scanning_tristate():
    assert (
        len(run_rule(SecretScanningDisabledRule(), make_ctx(repo=make_repo(secret_scanning=False))))
        == 1
    )
    assert (
        run_rule(SecretScanningDisabledRule(), make_ctx(repo=make_repo(secret_scanning=True))) == []
    )
    assert (
        run_rule(SecretScanningDisabledRule(), make_ctx(repo=make_repo(secret_scanning=None))) == []
    )
    # Private repo: rule doesn't apply.
    assert (
        run_rule(
            SecretScanningDisabledRule(),
            make_ctx(repo=make_repo(visibility="private", secret_scanning=False)),
        )
        == []
    )


def test_push_protection():
    assert (
        len(run_rule(PushProtectionDisabledRule(), make_ctx(repo=make_repo(push_protection=False))))
        == 1
    )
    assert (
        run_rule(PushProtectionDisabledRule(), make_ctx(repo=make_repo(push_protection=None))) == []
    )


def test_dependabot():
    assert (
        len(run_rule(DependabotDisabledRule(), make_ctx(repo=make_repo(dependabot_alerts=False))))
        == 1
    )
    assert (
        run_rule(
            DependabotDisabledRule(),
            make_ctx(repo=make_repo(archived=True, dependabot_alerts=False)),
        )
        == []
    )


def test_actions_can_approve_prs():
    findings = run_rule(
        ForkPrApprovalRule(), make_ctx(repo=make_repo(can_approve_pull_request_reviews=True))
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert (
        run_rule(
            ForkPrApprovalRule(), make_ctx(repo=make_repo(can_approve_pull_request_reviews=None))
        )
        == []
    )
