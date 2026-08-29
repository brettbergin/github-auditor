from conftest import load_fixture, make_ctx, make_repo
from github_auditor.analyze.engine import RuleEngine, select_rules
from github_auditor.analyze.rules import ALL_RULES
from github_auditor.models import (
    Finding,
    Severity,
    WorkflowInfo,
    risk_grade,
    risk_score,
)


def test_all_rules_have_unique_ids():
    ids = [r.id for r in ALL_RULES]
    assert len(ids) == len(set(ids))
    assert len(ALL_RULES) == 21


def test_select_rules_include_exclude():
    only = select_rules(include=["GHA001", "repo002"])
    assert sorted(r.id for r in only) == ["GHA001", "REPO002"]
    without = select_rules(exclude=["gha001"])
    assert "GHA001" not in [r.id for r in without]


def test_risk_scoring():
    findings = [
        Finding(rule_id="X", rule_name="x", severity=Severity.CRITICAL, title="t", repo="r"),
        Finding(rule_id="Y", rule_name="y", severity=Severity.MEDIUM, title="t", repo="r"),
    ]
    assert risk_score(findings) == 57
    assert risk_score([]) == 0
    assert risk_score(findings * 10) == 100  # capped
    assert risk_grade(0) == "A"
    assert risk_grade(5) == "B"
    assert risk_grade(15) == "C"
    assert risk_grade(35) == "D"
    assert risk_grade(57) == "F"


def test_analyze_repo_runs_all_rules():
    engine = RuleEngine()
    ctx = make_ctx(["pwn_request_vuln.yml", "injection_vuln.yml"])
    findings = engine.analyze_repo(ctx)
    rule_ids = {f.rule_id for f in findings}
    assert "GHA001" in rule_ids
    assert "GHA005" in rule_ids


def test_analyze_org_from_cache(store):
    repo = make_repo(id=1)
    store.upsert_repo(repo)
    store.upsert_workflows(1, [
        WorkflowInfo(repo_full_name=repo.full_name,
                     path=".github/workflows/pwn.yml",
                     content=load_fixture("pwn_request_vuln.yml")),
        WorkflowInfo(repo_full_name=repo.full_name,
                     path=".github/workflows/broken.yml",
                     content="{{not yaml"),
    ])
    engine = RuleEngine()
    report = engine.analyze_org(store, "testorg")
    assert len(report.repos) == 1
    rule_ids = {f.rule_id for f in report.findings}
    assert "GHA001" in rule_ids
    assert "PARSE" in rule_ids  # unparseable workflow surfaced, not swallowed
    # Findings were persisted as the latest run.
    assert store.latest_findings("testorg")
    assert report.sorted_repos()[0].risk_score > 0
