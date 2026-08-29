from datetime import timedelta

from conftest import make_repo
from github_auditor.models import Finding, OrgInfo, RunnerInfo, Severity, WorkflowInfo


def test_repo_roundtrip(store):
    repo = make_repo(id=42, secret_scanning=True, dependabot_alerts=None)
    store.upsert_repo(repo)
    loaded = store.get_repo("testorg/testrepo")
    assert loaded is not None
    assert loaded.id == 42
    assert loaded.secret_scanning is True
    assert loaded.dependabot_alerts is None  # tri-state survives the round trip


def test_upsert_is_idempotent(store):
    repo = make_repo(id=42)
    store.upsert_repo(repo)
    store.upsert_repo(repo.model_copy(update={"visibility": "private"}))
    repos = store.list_repos("testorg")
    assert len(repos) == 1
    assert repos[0].visibility == "private"


def test_list_repos_archived_filter(store):
    store.upsert_repo(make_repo(id=1, full_name="testorg/a", name="a"))
    store.upsert_repo(make_repo(id=2, full_name="testorg/b", name="b", archived=True))
    assert len(store.list_repos("testorg")) == 2
    assert len(store.list_repos("testorg", include_archived=False)) == 1


def test_delete_repos_not_in(store):
    store.upsert_repo(make_repo(id=1, full_name="testorg/a", name="a"))
    store.upsert_repo(make_repo(id=2, full_name="testorg/b", name="b"))
    removed = store.delete_repos_not_in("testorg", keep_ids={1})
    assert removed == 1
    assert [r.full_name for r in store.list_repos("testorg")] == ["testorg/a"]


def test_ttl_freshness(store):
    assert not store.is_fresh("repo_detail", "testorg/a", timedelta(hours=1))
    store.touch("repo_detail", "testorg/a")
    assert store.is_fresh("repo_detail", "testorg/a", timedelta(hours=1))
    assert not store.is_fresh("repo_detail", "testorg/a", timedelta(seconds=-1))


def test_workflows_roundtrip(store):
    repo = make_repo(id=7)
    store.upsert_repo(repo)
    store.upsert_workflows(
        7,
        [
            WorkflowInfo(
                repo_full_name=repo.full_name, path=".github/workflows/ci.yml", content="on: push"
            ),
        ],
    )
    wfs = store.get_workflows(repo.full_name)
    assert len(wfs) == 1
    assert wfs[0].content == "on: push"
    # Re-upsert replaces rather than duplicates.
    store.upsert_workflows(
        7,
        [
            WorkflowInfo(
                repo_full_name=repo.full_name,
                path=".github/workflows/ci.yml",
                content="on: pull_request",
            ),
        ],
    )
    assert [w.content for w in store.get_workflows(repo.full_name)] == ["on: pull_request"]


def test_org_roundtrip(store):
    store.upsert_org(OrgInfo(login="testorg", id=1, two_factor_requirement_enabled=True))
    org = store.get_org("testorg")
    assert org.two_factor_requirement_enabled is True


def test_runners(store):
    store.replace_runners("testorg", [RunnerInfo(name="r1", level="org")], level="org")
    assert [r.name for r in store.get_runners("testorg")] == ["r1"]
    store.replace_runners("testorg", [], level="org")
    assert store.get_runners("testorg") == []


def _finding(repo="testorg/a", rule_id="GHA001", severity=Severity.HIGH):
    return Finding(rule_id=rule_id, rule_name="x", severity=severity, title="t", repo=repo)


def test_findings_query(store):
    run = store.start_audit_run("testorg")
    store.save_findings(
        run,
        [
            _finding(severity=Severity.CRITICAL),
            _finding(rule_id="ACC001", severity=Severity.LOW),
            _finding(repo="testorg/b", rule_id="REPO002", severity=Severity.MEDIUM),
        ],
    )
    store.finish_audit_run(run, repo_count=2, finding_count=3)

    all_f = store.latest_findings("testorg")
    assert len(all_f) == 3
    assert all_f[0].severity == Severity.CRITICAL  # sorted most-severe first
    assert len(store.latest_findings("testorg", severity=Severity.LOW)) == 1
    assert len(store.latest_findings("testorg", min_severity=Severity.MEDIUM)) == 2
    assert len(store.latest_findings("testorg", rule_id="gha001")) == 1
    assert len(store.latest_findings("testorg", repo="testorg/b")) == 1


def test_latest_findings_uses_latest_run(store):
    run1 = store.start_audit_run("testorg")
    store.save_findings(run1, [_finding()])
    store.finish_audit_run(run1, repo_count=1, finding_count=1)
    run2 = store.start_audit_run("testorg")
    store.finish_audit_run(run2, repo_count=1, finding_count=0)
    assert store.latest_findings("testorg") == []


def test_clear_org_scoped(store):
    store.upsert_repo(make_repo(id=1, full_name="testorg/a", name="a"))
    store.upsert_repo(make_repo(id=2, full_name="other/x", name="x", org="other"))
    store.touch("repo_detail", "testorg/a")
    run = store.start_audit_run("testorg")
    store.save_findings(run, [_finding()])
    store.finish_audit_run(run, repo_count=1, finding_count=1)

    store.clear(org="testorg")
    assert store.list_repos("testorg") == []
    assert store.latest_findings("testorg") == []
    assert len(store.list_repos("other")) == 1

    store.clear()
    assert store.list_repos("other") == []


def test_cache_stats(store):
    store.upsert_repo(make_repo(id=1))
    store.upsert_org(OrgInfo(login="testorg"))
    stats = store.cache_stats("db", 0)
    assert stats.repo_count == 1
    assert stats.orgs == ["testorg"]
