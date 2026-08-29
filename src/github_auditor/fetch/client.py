"""GitHubClient: a thin PyGithub wrapper.

All raw REST calls for endpoints PyGithub lacks first-class support for
(actions permissions, workflow token permissions, repo runners) live here, so
the fetcher stays free of API plumbing. ``optional()`` maps 403/404/410 to
``None``, which the domain models treat as "not visible to this token".
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from github import Auth, Github, GithubRetry
from github.GithubException import (
    GithubException,
    RateLimitExceededException,
    UnknownObjectException,
)
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Repository import Repository

from github_auditor.config import Settings
from github_auditor.exceptions import AuthError, RateLimitError
from github_auditor.models import JSONDict, RunnerInfo

T = TypeVar("T")

NOT_VISIBLE_STATUSES = {403, 404, 410}


@dataclass
class TokenInfo:
    login: str | None
    authenticated: bool
    scopes: list[str]


class GitHubClient:
    def __init__(self, settings: Settings, *, log: Callable[[str], None] | None = None):
        self._settings = settings
        self._log = log or (lambda _msg: None)
        token = settings.token_value()
        auth = Auth.Token(token) if token else None
        self.gh = Github(auth=auth, per_page=100, retry=GithubRetry())
        self.authenticated = auth is not None

    # -- auth / limits -----------------------------------------------------

    def check_token(self) -> TokenInfo:
        if not self.authenticated:
            return TokenInfo(login=None, authenticated=False, scopes=[])
        try:
            user = self.gh.get_user()
            login = user.login
        except GithubException as exc:
            raise AuthError(f"GitHub token rejected: {exc.status} {exc.data}") from exc
        scopes = self.gh.oauth_scopes or []
        return TokenInfo(login=login, authenticated=True, scopes=list(scopes))

    def rate_limit_remaining(self) -> int:
        return self.gh.get_rate_limit().resources.core.remaining

    # -- call guards -------------------------------------------------------

    def guarded(self, fn: Callable[[], T]) -> T:
        """Run an API call; on primary rate-limit exhaustion, wait for reset once."""
        try:
            return fn()
        except RateLimitExceededException as exc:
            reset = self.gh.get_rate_limit().resources.core.reset
            wait = max(0.0, reset.timestamp() - time.time()) + 5
            if wait > 3600:
                raise RateLimitError(
                    f"Rate limit exhausted; reset is {wait / 60:.0f} minutes away."
                ) from exc
            self._log(f"Rate limit hit; sleeping {wait:.0f}s until reset…")
            time.sleep(wait)
            return fn()

    def optional(self, fn: Callable[[], T]) -> T | None:
        """Run an API call; return None when the feature isn't visible to this token."""
        try:
            return self.guarded(fn)
        except GithubException as exc:
            if exc.status in NOT_VISIBLE_STATUSES:
                return None
            raise

    # -- targets -----------------------------------------------------------

    def get_org_or_user(self, name: str) -> Organization | NamedUser:
        try:
            return self.guarded(lambda: self.gh.get_organization(name))
        except UnknownObjectException:
            pass
        except GithubException as exc:
            if exc.status != 403:
                raise
        try:
            return self.guarded(lambda: self.gh.get_user(name))
        except UnknownObjectException as exc:
            raise AuthError(f"No organization or user named '{name}' is visible.") from exc
        except GithubException as exc:
            message = (exc.data or {}).get("message", exc.data)
            raise AuthError(f"Could not look up '{name}': {exc.status} {message}") from exc

    # -- raw endpoints PyGithub doesn't cover well -------------------------

    def _get_json(self, repo: Repository, suffix: str) -> JSONDict | None:
        def call() -> JSONDict:
            _headers, data = repo._requester.requestJsonAndCheck("GET", f"{repo.url}{suffix}")
            return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}

        return self.optional(call)

    def get_actions_permissions(self, repo: Repository) -> JSONDict | None:
        """{enabled: bool, allowed_actions: all|local_only|selected}"""
        return self._get_json(repo, "/actions/permissions")

    def get_workflow_permissions(self, repo: Repository) -> JSONDict | None:
        """{default_workflow_permissions: read|write, can_approve_pull_request_reviews: bool}"""
        return self._get_json(repo, "/actions/permissions/workflow")

    def list_repo_runners(self, repo: Repository) -> list[RunnerInfo] | None:
        data = self._get_json(repo, "/actions/runners")
        if data is None:
            return None
        return _runners_from(data, level="repo", repo_full_name=repo.full_name)

    def _get_org_json(self, org: Organization, suffix: str) -> JSONDict | None:
        def call() -> JSONDict:
            _headers, data = org._requester.requestJsonAndCheck("GET", f"{org.url}{suffix}")
            return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}

        return self.optional(call)

    def list_org_runners(self, org: Organization) -> list[RunnerInfo] | None:
        data = self._get_org_json(org, "/actions/runners")
        if data is None:
            return None
        return _runners_from(data, level="org", repo_full_name=None)

    def get_org_workflow_permissions(self, org: Organization) -> JSONDict | None:
        """{default_workflow_permissions, can_approve_pull_request_reviews} org-wide."""
        return self._get_org_json(org, "/actions/permissions/workflow")

    def get_org_fork_pr_approval_policy(self, org: Organization) -> str | None:
        """Approval policy for workflows on pull requests from forks."""
        data = self._get_org_json(org, "/actions/permissions/fork-pr-contributor-approval")
        if data is None:
            return None
        return _opt_str(data.get("approval_policy"))

    def get_dependabot_alerts_enabled(self, repo: Repository) -> bool | None:
        """204 = enabled, 404 = disabled — distinct from a permissions failure."""
        try:
            return self.guarded(repo.get_vulnerability_alert)
        except GithubException as exc:
            if exc.status in NOT_VISIBLE_STATUSES:
                return None
            raise


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _runners_from(data: JSONDict, *, level: str, repo_full_name: str | None) -> list[RunnerInfo]:
    """Build RunnerInfo models from a /actions/runners payload, narrowing as we go."""
    runners: list[RunnerInfo] = []
    entries = data.get("runners")
    if not isinstance(entries, list):
        return runners
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        labels_raw = entry.get("labels")
        labels = (
            [str(label.get("name", "")) for label in labels_raw if isinstance(label, dict)]
            if isinstance(labels_raw, list)
            else []
        )
        runners.append(
            RunnerInfo(
                name=str(entry.get("name", "")),
                os=_opt_str(entry.get("os")),
                status=_opt_str(entry.get("status")),
                labels=labels,
                level=level,
                repo_full_name=repo_full_name,
            )
        )
    return runners
