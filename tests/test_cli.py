"""CLI smoke tests via Typer's CliRunner against a temp cache DB."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from conftest import load_fixture, make_repo
from github_auditor.analyze.engine import RuleEngine
from github_auditor.cache import CacheStore, create_db_engine, init_db
from github_auditor.cli import app
from github_auditor.models import Finding, Severity, WorkflowInfo

runner = CliRunner()


@pytest.fixture
def seeded_db(tmp_path):
    db_path = tmp_path / "cache.db"
    engine = create_db_engine(db_path)
    init_db(engine)
    store = CacheStore(engine)
    repo = make_repo(id=1)
    store.upsert_repo(repo)
    store.upsert_workflows(
        1,
        [
            WorkflowInfo(
                repo_full_name=repo.full_name,
                path=".github/workflows/pwn.yml",
                content=load_fixture("pwn_request_vuln.yml"),
            ),
        ],
    )
    RuleEngine().analyze_org(store, "testorg")
    engine.dispose()
    return db_path


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "github-auditor" in result.output


def test_rules_lists_all():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "GHA001" in result.output
    assert "ACC006" in result.output


def test_cache_info(tmp_path):
    result = runner.invoke(app, ["cache", "info", "--db", str(tmp_path / "cache.db")])
    assert result.exit_code == 0
    assert "Repositories" in result.output


def test_findings_json(seeded_db):
    result = runner.invoke(app, ["findings", "testorg", "--db", str(seeded_db), "--format", "json"])
    assert result.exit_code == 0
    findings = json.loads(result.stdout)
    assert any(f["rule_id"] == "GHA001" for f in findings)


def test_findings_filters(seeded_db):
    result = runner.invoke(
        app, ["findings", "testorg", "--db", str(seeded_db), "--rule", "GHA001", "--format", "csv"]
    )
    assert result.exit_code == 0
    assert "GHA001" in result.stdout


def test_report_table(seeded_db):
    result = runner.invoke(app, ["report", "testorg", "--db", str(seeded_db)])
    assert result.exit_code == 0
    assert "testorg/testrepo" in result.output


def test_report_missing_org_errors(tmp_path):
    result = runner.invoke(app, ["report", "nosuchorg", "--db", str(tmp_path / "c.db")])
    assert result.exit_code == 2


def test_repos_table(seeded_db):
    result = runner.invoke(app, ["repos", "testorg", "--db", str(seeded_db)])
    assert result.exit_code == 0
    assert "testorg/testrepo" in result.output


def _finding(rule_id, repo, title, severity=Severity.HIGH, location=None):
    return Finding(
        rule_id=rule_id,
        rule_name="a-rule",
        severity=severity,
        title=title,
        repo=repo,
        location=location,
    )


def _write_run(store, findings, org="testorg"):
    run_id = store.start_audit_run(org)
    store.save_findings(run_id, findings)
    store.finish_audit_run(run_id, repo_count=2, finding_count=len(findings))
    return run_id


@pytest.fixture
def diff_db(tmp_path):
    """Three runs: 'kept' throughout, 'gone' only in the first, 'fresh' only in the last."""
    db_path = tmp_path / "diff.db"
    engine = create_db_engine(db_path)
    init_db(engine)
    store = CacheStore(engine)

    kept = _finding("GHA001", "testorg/a", "kept finding", location=".github/workflows/a.yml")
    gone = _finding("GHA002", "testorg/b", "gone finding", severity=Severity.CRITICAL)
    fresh = _finding("GHA003", "testorg/c", "fresh finding", severity=Severity.MEDIUM)

    run_ids = [
        _write_run(store, [kept, gone]),
        _write_run(store, [kept, gone]),
        _write_run(store, [kept, fresh]),
    ]
    engine.dispose()
    return db_path, run_ids


def test_diff_needs_two_runs(tmp_path):
    db_path = tmp_path / "one.db"
    engine = create_db_engine(db_path)
    init_db(engine)
    _write_run(CacheStore(engine), [_finding("GHA001", "testorg/a", "only finding")])
    engine.dispose()

    result = runner.invoke(app, ["diff", "testorg", "--db", str(db_path)])
    assert result.exit_code == 2
    assert "Need at least two completed audit runs to diff 'testorg'" in result.output


def test_diff_without_runs_errors(tmp_path):
    result = runner.invoke(app, ["diff", "nosuchorg", "--db", str(tmp_path / "empty.db")])
    assert result.exit_code == 2
    assert "No completed audit runs cached for 'nosuchorg'" in result.output


def test_diff_table_lists_new_and_resolved(diff_db):
    db_path, _ = diff_db
    result = runner.invoke(app, ["diff", "testorg", "--db", str(db_path)])
    assert result.exit_code == 0
    out = result.output
    assert "New findings" in out and "Resolved findings" in out
    assert out.index("fresh finding") < out.index("gone finding")
    # The finding present in both runs is neither new nor resolved.
    assert "kept finding" not in out
    assert "Score changes" in out


def test_diff_json(diff_db):
    db_path, run_ids = diff_db
    result = runner.invoke(app, ["diff", "testorg", "--db", str(db_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert {"new_findings", "resolved_findings", "scope_deltas", "total_delta"} <= set(payload)
    assert [f["title"] for f in payload["new_findings"]] == ["fresh finding"]
    assert [f["title"] for f in payload["resolved_findings"]] == ["gone finding"]
    assert payload["baseline_run"]["id"] == run_ids[1]
    assert payload["current_run"]["id"] == run_ids[2]
    scopes = {d["scope"]: d["delta"] for d in payload["scope_deltas"]}
    assert scopes == {"testorg/b": -50, "testorg/c": 7}
    assert payload["total_delta"] == payload["current_total"] - payload["baseline_total"]


def test_diff_since_run_id(diff_db):
    db_path, run_ids = diff_db
    result = runner.invoke(
        app,
        ["diff", "testorg", "--since", str(run_ids[0]), "--db", str(db_path), "--format", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["baseline_run"]["id"] == run_ids[0]
    assert payload["current_run"]["id"] == run_ids[2]
    assert [f["title"] for f in payload["resolved_findings"]] == ["gone finding"]


def test_diff_since_unknown_run_id(diff_db):
    db_path, _ = diff_db
    result = runner.invoke(app, ["diff", "testorg", "--since", "9999", "--db", str(db_path)])
    assert result.exit_code == 2
    assert "Run 9999 not found for 'testorg'" in result.output


def test_diff_since_date_before_any_run(diff_db):
    db_path, _ = diff_db
    result = runner.invoke(app, ["diff", "testorg", "--since", "2000-01-01", "--db", str(db_path)])
    assert result.exit_code == 2
    assert "No completed audit run at or before '2000-01-01' for 'testorg'" in result.output


def test_diff_since_date_picks_earlier_run(diff_db):
    db_path, run_ids = diff_db
    cutoff = datetime.now(timezone.utc) + timedelta(days=1)
    result = runner.invoke(
        app,
        ["diff", "testorg", "--since", cutoff.isoformat(), "--db", str(db_path), "-f", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["baseline_run"]["id"] == run_ids[2]
    assert payload["new_findings"] == [] and payload["resolved_findings"] == []


def test_diff_since_unparseable(diff_db):
    db_path, _ = diff_db
    result = runner.invoke(
        app, ["diff", "testorg", "--since", "last-tuesday", "--db", str(db_path)]
    )
    assert result.exit_code == 2
    assert "Could not parse --since value 'last-tuesday'" in result.output


def test_diff_no_changes(diff_db):
    db_path, run_ids = diff_db
    result = runner.invoke(
        app, ["diff", "testorg", "--since", str(run_ids[1]), "--db", str(db_path)]
    )
    assert result.exit_code == 0
    # Runs 1 and 2 hold identical findings, but run 3 is the current one, so this
    # diff does have changes; the no-change path is run 3 against itself.
    same = runner.invoke(app, ["diff", "testorg", "--since", str(run_ids[2]), "--db", str(db_path)])
    assert same.exit_code == 0
    assert f"No changes between run {run_ids[2]} and run {run_ids[2]}." in same.output


@pytest.fixture
def trend_db(tmp_path):
    """Three finished runs for 'testorg' scoring 50, 70 and 20 in that order."""
    db_path = tmp_path / "trends.db"
    engine = create_db_engine(db_path)
    init_db(engine)
    store = CacheStore(engine)

    def finding(severity, repo="testorg/a"):
        return Finding(
            rule_id="GHA001", rule_name="pwn-request", severity=severity, title="t", repo=repo
        )

    for findings in (
        [finding(Severity.CRITICAL)],
        [finding(Severity.CRITICAL), finding(Severity.HIGH, repo="testorg/b")],
        [finding(Severity.HIGH)],
    ):
        run_id = store.start_audit_run("testorg")
        store.save_findings(run_id, findings)
        store.finish_audit_run(run_id, repo_count=2, finding_count=len(findings))
    engine.dispose()
    return db_path


def test_trends_table_is_chronological(trend_db):
    result = runner.invoke(app, ["trends", "testorg", "--db", str(trend_db)])
    assert result.exit_code == 0
    out = result.output
    assert "Risk score trend for testorg" in out
    # Oldest run first, each row's delta against the row above it (50 -> 70 -> 20).
    assert out.index("+20") < out.index("-50")
    assert out.count("50") >= 1


def test_trends_json(trend_db):
    result = runner.invoke(app, ["trends", "testorg", "--db", str(trend_db), "--format", "json"])
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert [r["risk_score"] for r in rows] == [50, 70, 20]
    assert [r["delta"] for r in rows] == [None, 20, -50]
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows)
    assert set(rows[0]) == {
        "id",
        "started_at",
        "finished_at",
        "repo_count",
        "finding_count",
        "risk_score",
        "delta",
    }
    assert rows[0]["finding_count"] == 1
    assert rows[1]["finding_count"] == 2


def test_trends_limit_keeps_most_recent(trend_db):
    result = runner.invoke(
        app, ["trends", "testorg", "--db", str(trend_db), "--limit", "2", "--format", "json"]
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert [r["risk_score"] for r in rows] == [70, 20]  # the 2 newest, still oldest-first
    assert [r["delta"] for r in rows] == [None, -50]


def test_trends_without_runs_errors(tmp_path):
    result = runner.invoke(app, ["trends", "nosuchorg", "--db", str(tmp_path / "empty.db")])
    assert result.exit_code == 2
    assert "No completed audit runs cached for 'nosuchorg'" in result.output


def test_cache_clear(seeded_db):
    result = runner.invoke(app, ["cache", "clear", "--db", str(seeded_db), "--yes"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["repos", "testorg", "--db", str(seeded_db)])
    assert result.exit_code == 2  # nothing cached anymore
