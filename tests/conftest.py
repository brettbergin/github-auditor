from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool

from github_auditor.analyze.rules.base import RepoContext
from github_auditor.analyze.workflow_parser import parse_workflow
from github_auditor.cache import CacheStore, init_db
from github_auditor.config import Settings
from github_auditor.models import RepoInfo, WorkflowInfo

FIXTURES = Path(__file__).parent / "fixtures" / "workflows"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        github_token=None,
        data_dir=tmp_path,
        _env_file=None,  # keep the developer's real .env out of tests
    )


def make_repo(**overrides) -> RepoInfo:
    defaults = dict(
        id=1,
        full_name="testorg/testrepo",
        name="testrepo",
        org="testorg",
        visibility="public",
        default_branch="main",
    )
    defaults.update(overrides)
    return RepoInfo(**defaults)


def make_ctx(
    workflow_files: list[str] | None = None,
    repo: RepoInfo | None = None,
    settings: Settings | None = None,
    **ctx_overrides,
) -> RepoContext:
    repo = repo or make_repo()
    raw_workflows = []
    parsed = []
    for name in workflow_files or []:
        content = load_fixture(name)
        path = f".github/workflows/{name}"
        raw_workflows.append(
            WorkflowInfo(repo_full_name=repo.full_name, path=path, content=content)
        )
        wf = parse_workflow(content, path)
        assert wf is not None, f"fixture {name} failed to parse"
        parsed.append(wf)
    return RepoContext(
        org=repo.org,
        repo=repo,
        workflows=parsed,
        raw_workflows=raw_workflows,
        settings=settings or Settings(github_token=None, _env_file=None),
        **ctx_overrides,
    )


@pytest.fixture
def store() -> CacheStore:
    from sqlalchemy import create_engine

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(engine)
    return CacheStore(engine)
