"""CLI smoke tests via Typer's CliRunner against a temp cache DB."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from conftest import load_fixture, make_repo
from github_auditor.analyze.engine import RuleEngine
from github_auditor.cache import CacheStore, create_db_engine, init_db
from github_auditor.cli import app
from github_auditor.models import WorkflowInfo

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


def test_cache_clear(seeded_db):
    result = runner.invoke(app, ["cache", "clear", "--db", str(seeded_db), "--yes"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["repos", "testorg", "--db", str(seeded_db)])
    assert result.exit_code == 2  # nothing cached anymore
