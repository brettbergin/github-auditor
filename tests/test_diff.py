from __future__ import annotations

from github_auditor.analyze.diff import compute_diff, finding_key
from github_auditor.models import ORG_SCOPE, Finding, Severity, total_risk_score


def make_finding(
    rule_id: str = "GHA001",
    repo: str = "testorg/a",
    severity: Severity = Severity.HIGH,
    title: str = "t",
    location: str | None = ".github/workflows/ci.yml",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="x",
        severity=severity,
        title=title,
        repo=repo,
        location=location,
    )


def test_new_and_resolved_findings_are_split():
    stays = make_finding(rule_id="GHA001")
    gone = make_finding(rule_id="GHA002")
    added = make_finding(rule_id="GHA003")

    diff = compute_diff([stays, gone], [stays, added])

    assert [f.rule_id for f in diff.new_findings] == ["GHA003"]
    assert [f.rule_id for f in diff.resolved_findings] == ["GHA002"]


def test_identical_finding_in_both_runs_is_unchanged():
    finding = make_finding()
    # A re-analysis rebuilds findings from scratch, so identity must not depend
    # on object identity or on created_at.
    same = make_finding()

    diff = compute_diff([finding], [same])

    assert diff.new_findings == []
    assert diff.resolved_findings == []


def test_changed_location_is_a_resolved_plus_new_pair():
    before = make_finding(location=".github/workflows/ci.yml")
    after = make_finding(location=".github/workflows/release.yml")

    diff = compute_diff([before], [after])

    assert [f.location for f in diff.new_findings] == [".github/workflows/release.yml"]
    assert [f.location for f in diff.resolved_findings] == [".github/workflows/ci.yml"]


def test_title_identifies_a_finding_without_a_location():
    before = make_finding(location=None, title="Secret scanning disabled")
    after = make_finding(location=None, title="Push protection disabled")

    diff = compute_diff([before], [after])

    assert [f.title for f in diff.new_findings] == ["Push protection disabled"]
    assert [f.title for f in diff.resolved_findings] == ["Secret scanning disabled"]


def test_finding_key_uses_title_only_when_location_is_missing():
    assert finding_key(make_finding(location="wf.yml", title="t")) == (
        "GHA001",
        "testorg/a",
        "wf.yml",
    )
    assert finding_key(make_finding(location=None, title="t")) == ("GHA001", "testorg/a", "t")


def test_findings_are_sorted_most_severe_first():
    low = make_finding(rule_id="REPO001", severity=Severity.LOW, repo="testorg/b")
    critical = make_finding(rule_id="GHA009", severity=Severity.CRITICAL, repo="testorg/z")
    high_a = make_finding(rule_id="GHA002", severity=Severity.HIGH, repo="testorg/a")
    high_b = make_finding(rule_id="GHA001", severity=Severity.HIGH, repo="testorg/b")

    diff = compute_diff([], [low, high_b, critical, high_a])

    assert [f.rule_id for f in diff.new_findings] == ["GHA009", "GHA002", "GHA001", "REPO001"]


def test_scope_deltas_only_cover_scopes_whose_score_moved():
    unchanged = make_finding(rule_id="GHA001", repo="testorg/steady")
    regressed = make_finding(rule_id="GHA002", repo="testorg/worse", severity=Severity.CRITICAL)
    fixed = make_finding(rule_id="GHA003", repo="testorg/better", severity=Severity.HIGH)

    diff = compute_diff([unchanged, fixed], [unchanged, regressed])

    by_scope = {d.scope: d for d in diff.scope_deltas}
    assert "testorg/steady" not in by_scope
    assert by_scope["testorg/worse"].baseline_score == 0
    assert by_scope["testorg/worse"].current_score == 50
    assert by_scope["testorg/worse"].delta == 50
    assert by_scope["testorg/better"].baseline_score == 20
    assert by_scope["testorg/better"].current_score == 0
    assert by_scope["testorg/better"].delta == -20


def test_scope_deltas_sorted_by_absolute_delta_then_name():
    baseline = [make_finding(rule_id="GHA001", repo="testorg/down", severity=Severity.CRITICAL)]
    current = [
        make_finding(rule_id="GHA002", repo="testorg/b-up", severity=Severity.MEDIUM),
        make_finding(rule_id="GHA003", repo="testorg/a-up", severity=Severity.MEDIUM),
    ]

    diff = compute_diff(baseline, current)

    assert [(d.scope, d.delta) for d in diff.scope_deltas] == [
        ("testorg/down", -50),
        ("testorg/a-up", 7),
        ("testorg/b-up", 7),
    ]


def test_org_scoped_findings_get_their_own_scope():
    org_finding = make_finding(rule_id="ORG001", repo=ORG_SCOPE, location=None, title="2FA off")

    diff = compute_diff([], [org_finding])

    assert [d.scope for d in diff.scope_deltas] == [ORG_SCOPE]


def test_totals_match_total_risk_score():
    baseline = [
        make_finding(rule_id="GHA001", repo="testorg/a", severity=Severity.CRITICAL),
        make_finding(rule_id="GHA002", repo="testorg/b", severity=Severity.HIGH),
    ]
    current = [make_finding(rule_id="GHA002", repo="testorg/b", severity=Severity.HIGH)]

    diff = compute_diff(baseline, current)

    assert diff.baseline_total == total_risk_score(baseline) == 70
    assert diff.current_total == total_risk_score(current) == 20
    assert diff.total_delta == -50


def test_empty_runs_diff_to_nothing():
    diff = compute_diff([], [])

    assert diff.new_findings == []
    assert diff.resolved_findings == []
    assert diff.scope_deltas == []
    assert diff.total_delta == 0
