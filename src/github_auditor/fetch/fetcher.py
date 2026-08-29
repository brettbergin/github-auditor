"""OrgFetcher: pull an organization's security-relevant data into the cache.

Repo details are fetched concurrently with a thread pool; every privileged
endpoint goes through ``GitHubClient.optional`` so limited tokens degrade to
``None`` ("unknown") instead of failing the sync.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import timedelta

from github.GitBlob import GitBlob
from github.NamedUser import NamedUser
from github.Organization import Organization
from github.Repository import Repository

from github_auditor.cache.store import CacheStore
from github_auditor.config import Settings
from github_auditor.fetch.client import GitHubClient
from github_auditor.models import (
    BranchProtectionInfo,
    CollaboratorInfo,
    DeployKeyInfo,
    OrgInfo,
    RepoInfo,
    WorkflowInfo,
)

WORKFLOW_DIR = ".github/workflows"


@dataclass
class SyncResult:
    org: str
    repo_count: int = 0
    fetched: int = 0
    from_cache: int = 0
    removed: int = 0
    errors: list[str] = field(default_factory=list)


class OrgFetcher:
    def __init__(
        self,
        client: GitHubClient,
        store: CacheStore,
        settings: Settings,
        *,
        on_repo_done: Callable[[str], None] | None = None,
        log: Callable[[str], None] | None = None,
    ):
        self.client = client
        self.store = store
        self.settings = settings
        self._on_repo_done = on_repo_done or (lambda _name: None)
        self._log = log or (lambda _msg: None)

    @property
    def _ttl(self) -> timedelta:
        return timedelta(hours=self.settings.cache_ttl_hours)

    # -- org ---------------------------------------------------------------

    def fetch_org(self, target: Organization | NamedUser) -> OrgInfo:
        is_user = not isinstance(target, Organization)
        info = OrgInfo(
            login=target.login,
            id=target.id,
            name=target.name,
            is_user=is_user,
        )
        if isinstance(target, Organization):
            org_target = target
            info.two_factor_requirement_enabled = self.client.optional(
                lambda: org_target.two_factor_requirement_enabled
            )
            info.default_repository_permission = self.client.optional(
                lambda: org_target.default_repository_permission
            )
        self.store.upsert_org(info)
        return info

    # -- repo details ------------------------------------------------------

    def fetch_repo_details(self, repo: Repository, org_login: str) -> RepoInfo:
        client = self.client
        info = RepoInfo(
            id=repo.id,
            full_name=repo.full_name,
            name=repo.name,
            org=org_login,
            visibility=repo.visibility or ("private" if repo.private else "public"),
            archived=repo.archived,
            fork=repo.fork,
            default_branch=repo.default_branch or "main",
            pushed_at=repo.pushed_at,
            html_url=repo.html_url,
            clone_url=repo.clone_url,
        )

        # security_and_analysis rides on the repo payload itself.
        saa = (repo.raw_data or {}).get("security_and_analysis") or None
        if saa is not None:
            ss = saa.get("secret_scanning") or {}
            pp = saa.get("secret_scanning_push_protection") or {}
            info.secret_scanning = ss.get("status") == "enabled" if ss else None
            info.push_protection = pp.get("status") == "enabled" if pp else None

        info.dependabot_alerts = client.get_dependabot_alerts_enabled(repo)

        perms = client.get_actions_permissions(repo)
        if perms is not None:
            info.actions_enabled = _opt_bool(perms.get("enabled"))
            info.actions_allowed_actions = _opt_str(perms.get("allowed_actions"))

        wf_perms = client.get_workflow_permissions(repo)
        if wf_perms is not None:
            info.default_workflow_permissions = _opt_str(
                wf_perms.get("default_workflow_permissions")
            )
            info.can_approve_pull_request_reviews = _opt_bool(
                wf_perms.get("can_approve_pull_request_reviews")
            )

        info.branch_protection = self._fetch_branch_protection(repo, info.default_branch)

        keys = client.optional(lambda: list(repo.get_keys()))
        if keys is not None:
            info.deploy_keys = [
                DeployKeyInfo(
                    id=k.id,
                    title=k.title or "",
                    read_only=bool(k.read_only),
                    created_at=k.created_at,
                )
                for k in keys
            ]

        collabs = client.optional(lambda: list(repo.get_collaborators(affiliation="outside")))
        if collabs is not None:
            info.outside_collaborators = [
                CollaboratorInfo(
                    login=c.login,
                    permission=self._permission_of(c),
                    affiliation="outside",
                )
                for c in collabs
            ]

        runners = client.list_repo_runners(repo)
        if runners is not None:
            info.has_self_hosted_runners = len(runners) > 0
            self.store.replace_runners(
                org_login, runners, level="repo", repo_full_name=repo.full_name
            )

        return info

    @staticmethod
    def _permission_of(collaborator: NamedUser) -> str:
        perms = collaborator.permissions
        if perms is None:
            return "pull"
        if perms.admin:
            return "admin"
        if getattr(perms, "maintain", False):
            return "maintain"
        if perms.push:
            return "push"
        if getattr(perms, "triage", False):
            return "triage"
        return "pull"

    def _fetch_branch_protection(
        self, repo: Repository, branch_name: str
    ) -> BranchProtectionInfo | None:
        from github.GithubException import GithubException

        def call() -> BranchProtectionInfo:
            branch = repo.get_branch(branch_name)
            try:
                protection = branch.get_protection()
            except GithubException as exc:
                if exc.status == 404:
                    # Distinct from 403: the token can see protection, there just is none.
                    return BranchProtectionInfo(exists=False)
                raise
            reviews = protection.required_pull_request_reviews
            return BranchProtectionInfo(
                exists=True,
                required_reviews=(reviews.required_approving_review_count if reviews else 0),
                required_status_checks=protection.required_status_checks is not None,
                enforce_admins=bool(protection.enforce_admins),
                allow_force_pushes=bool(getattr(protection, "allow_force_pushes", False)),
                allow_deletions=bool(getattr(protection, "allow_deletions", False)),
            )

        return self.client.optional(call)

    # -- workflows ---------------------------------------------------------

    def fetch_workflows(self, repo: Repository) -> list[WorkflowInfo]:
        """List workflow files under .github/workflows and fetch their content."""
        client = self.client
        entries = client.optional(lambda: repo.get_contents(WORKFLOW_DIR))
        if entries is None:
            return []
        if not isinstance(entries, list):
            entries = [entries]

        workflows: list[WorkflowInfo] = []
        for entry in entries:
            if entry.type != "file" or not entry.path.endswith((".yml", ".yaml")):
                continue
            content: str | None = None
            try:
                content = entry.decoded_content.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - content may exceed API size limits
                sha = entry.sha

                def fetch_blob(blob_sha: str = sha) -> GitBlob:
                    return repo.get_git_blob(blob_sha)

                blob = client.optional(fetch_blob)
                if blob is not None and blob.encoding == "base64":
                    content = base64.b64decode(blob.content).decode("utf-8", errors="replace")
            workflows.append(
                WorkflowInfo(
                    repo_full_name=repo.full_name,
                    path=entry.path,
                    name=None,
                    state=None,
                    content=content,
                    source="api",
                )
            )
        return workflows

    # -- sync orchestration ------------------------------------------------

    def _sync_one_repo(self, repo: Repository, org_login: str) -> None:
        info = self.fetch_repo_details(repo, org_login)
        self.store.upsert_repo(info)
        # Archived repos keep their workflow files too — always fetch them.
        self.store.upsert_workflows(info.id, self.fetch_workflows(repo))
        self.store.touch("repo_detail", info.full_name)

    def sync(
        self,
        org: str,
        *,
        refresh: bool = False,
        include_archived: bool = True,
    ) -> SyncResult:
        result = SyncResult(org=org)
        target = self.client.get_org_or_user(org)

        if refresh or not self.store.is_fresh("org", org, self._ttl):
            self.fetch_org(target)
            self.store.touch("org", org)

        repos: list[Repository] = list(
            self.client.guarded(lambda: list(target.get_repos(type="all")))
        )
        # Audit the target's own repos, not forks-of-others noise? Keep all: forks
        # can still hold runners/secrets. Only filter archived when asked.
        if not include_archived:
            repos = [r for r in repos if not r.archived]
        result.repo_count = len(repos)
        result.removed = self.store.delete_repos_not_in(org, {r.id for r in repos})

        # Org-level runners once per sync.
        if isinstance(target, Organization):
            runners = self.client.list_org_runners(target)
            if runners is not None:
                self.store.replace_runners(org, runners, level="org")

        to_fetch = [
            r
            for r in repos
            if refresh or not self.store.is_fresh("repo_detail", r.full_name, self._ttl)
        ]
        result.from_cache = len(repos) - len(to_fetch)

        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as pool:
            futures = {pool.submit(self._sync_one_repo, repo, org): repo for repo in to_fetch}
            for future in as_completed(futures):
                repo = futures[future]
                try:
                    future.result()
                    result.fetched += 1
                except Exception as exc:  # noqa: BLE001 - one bad repo must not kill the sync
                    result.errors.append(f"{repo.full_name}: {exc}")
                    self._log(f"Error fetching {repo.full_name}: {exc}")
                finally:
                    self._on_repo_done(repo.full_name)

        self.store.touch("org_repos", org)
        return result


def _opt_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
