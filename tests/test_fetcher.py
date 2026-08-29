"""Fetcher tests against mocked PyGithub objects — no network."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from github.GithubException import GithubException

from github_auditor.fetch.client import GitHubClient
from github_auditor.fetch.fetcher import OrgFetcher


@pytest.fixture
def client(settings):
    c = GitHubClient.__new__(GitHubClient)  # skip __init__: no real Github object needed
    c._settings = settings
    c._log = lambda _m: None
    c.authenticated = False
    c.gh = MagicMock()
    return c


def make_mock_repo(**overrides):
    repo = MagicMock()
    repo.id = overrides.get("id", 1)
    repo.full_name = overrides.get("full_name", "testorg/repo")
    repo.name = overrides.get("name", "repo")
    repo.visibility = overrides.get("visibility", "public")
    repo.private = False
    repo.archived = overrides.get("archived", False)
    repo.fork = False
    repo.default_branch = "main"
    repo.pushed_at = None
    repo.html_url = "https://github.com/testorg/repo"
    repo.clone_url = "https://github.com/testorg/repo.git"
    repo.raw_data = overrides.get("raw_data", {})
    repo.url = "https://api.github.com/repos/testorg/repo"
    return repo


def deny(*_args, **_kwargs):
    raise GithubException(403, {"message": "forbidden"}, None)


def test_optional_maps_403_to_none(client):
    assert client.optional(deny) is None


def test_optional_reraises_500(client):
    def boom():
        raise GithubException(500, {"message": "server error"}, None)

    with pytest.raises(GithubException):
        client.optional(boom)


def test_fetch_repo_details_with_denied_endpoints(client, store, settings):
    """A token that can't see any privileged endpoint yields all-None posture."""
    repo = make_mock_repo()
    repo._requester.requestJsonAndCheck.side_effect = deny
    repo.get_keys.side_effect = deny
    repo.get_collaborators.side_effect = deny
    repo.get_branch.side_effect = deny
    repo.get_vulnerability_alert.side_effect = deny

    fetcher = OrgFetcher(client, store, settings)
    info = fetcher.fetch_repo_details(repo, "testorg")

    assert info.full_name == "testorg/repo"
    assert info.actions_enabled is None
    assert info.default_workflow_permissions is None
    assert info.branch_protection is None
    assert info.deploy_keys is None
    assert info.outside_collaborators is None
    assert info.has_self_hosted_runners is None
    assert info.secret_scanning is None


def test_fetch_repo_details_with_data(client, store, settings):
    repo = make_mock_repo(
        raw_data={
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "disabled"},
            }
        }
    )

    def request_json(method, url):
        if url.endswith("/actions/permissions"):
            return {}, {"enabled": True, "allowed_actions": "all"}
        if url.endswith("/actions/permissions/workflow"):
            return {}, {"default_workflow_permissions": "write",
                        "can_approve_pull_request_reviews": True}
        if url.endswith("/actions/runners"):
            return {}, {"total_count": 1, "runners": [
                {"name": "buildbox", "os": "linux", "status": "online",
                 "labels": [{"name": "self-hosted"}]},
            ]}
        raise GithubException(404, {}, None)

    repo._requester.requestJsonAndCheck.side_effect = request_json
    repo.get_keys.return_value = []
    repo.get_collaborators.return_value = []
    repo.get_vulnerability_alert.return_value = True

    branch = MagicMock()
    branch.get_protection.side_effect = GithubException(404, {}, None)
    repo.get_branch.return_value = branch

    fetcher = OrgFetcher(client, store, settings)
    info = fetcher.fetch_repo_details(repo, "testorg")

    assert info.secret_scanning is True
    assert info.push_protection is False
    assert info.actions_enabled is True
    assert info.actions_allowed_actions == "all"
    assert info.default_workflow_permissions == "write"
    assert info.can_approve_pull_request_reviews is True
    assert info.dependabot_alerts is True
    assert info.deploy_keys == []
    assert info.branch_protection is not None
    assert info.branch_protection.exists is False  # 404 on protection = none configured
    assert info.has_self_hosted_runners is True
    runners = store.get_runners("testorg")
    assert [r.name for r in runners] == ["buildbox"]


def test_fetch_workflows_decodes_content(client, store, settings):
    repo = make_mock_repo()
    entry = MagicMock()
    entry.type = "file"
    entry.path = ".github/workflows/ci.yml"
    entry.decoded_content = b"on: push"
    other = MagicMock()
    other.type = "file"
    other.path = ".github/workflows/README.md"
    repo.get_contents.return_value = [entry, other]

    fetcher = OrgFetcher(client, store, settings)
    workflows = fetcher.fetch_workflows(repo)
    assert len(workflows) == 1
    assert workflows[0].content == "on: push"
    assert workflows[0].source == "api"


def test_sync_skips_fresh_repos(client, store, settings, monkeypatch):
    org = MagicMock(spec=[])  # not an Organization instance → treated as user
    org.login = "testorg"
    org.id = 1
    org.name = "Test Org"
    repo = make_mock_repo()
    org.get_repos = MagicMock(return_value=[repo])
    monkeypatch.setattr(client, "get_org_or_user", lambda _name: org)

    store.touch("repo_detail", repo.full_name)  # already fresh

    called = []
    fetcher = OrgFetcher(client, store, settings)
    monkeypatch.setattr(
        fetcher, "_sync_one_repo", lambda r, o: called.append(r.full_name)
    )

    result = fetcher.sync("testorg")
    assert result.repo_count == 1
    assert result.from_cache == 1
    assert called == []  # fresh repo not re-fetched

    result2 = fetcher.sync("testorg", refresh=True)
    assert result2.fetched == 1
    assert called == [repo.full_name]
