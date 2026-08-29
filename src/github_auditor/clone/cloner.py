"""RepoCloner: shallow local clones for deep workflow scanning.

Tokens are only ever passed to git transiently (embedded in the remote URL for
the duration of a clone/fetch) and are scrubbed from ``.git/config`` right
after, so credentials never persist on disk.
"""

from __future__ import annotations

import shutil
from contextlib import contextmanager
from pathlib import Path

from git import GitCommandError, Repo

from github_auditor.config import Settings
from github_auditor.exceptions import CloneError
from github_auditor.models import RepoInfo, WorkflowInfo

WORKFLOW_DIR = ".github/workflows"


def _with_token(url: str, token: str | None) -> str:
    if token and url.startswith("https://"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


@contextmanager
def _authenticated_remote(repo: Repo, clean_url: str, token: str | None):
    """Temporarily point origin at a token-embedded URL; always restore the clean one."""
    try:
        repo.remotes.origin.set_url(_with_token(clean_url, token))
        yield repo.remotes.origin
    finally:
        repo.remotes.origin.set_url(clean_url)


class RepoCloner:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._clone_dir = settings.effective_clone_dir

    def path_for(self, repo: RepoInfo) -> Path:
        return self._clone_dir / repo.org / repo.name

    def ensure_clone(self, repo: RepoInfo, token: str | None = None) -> Path:
        """Clone (depth=1, single branch) or update an existing clone. Returns its path."""
        if not repo.clone_url:
            raise CloneError(f"{repo.full_name}: no clone URL known")
        path = self.path_for(repo)
        if (path / ".git").exists():
            try:
                self._update(path, repo, token)
                return path
            except GitCommandError:
                shutil.rmtree(path, ignore_errors=True)  # corrupt clone: start over

        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            local = Repo.clone_from(
                _with_token(repo.clone_url, token),
                path,
                depth=self._settings.clone_depth,
                single_branch=True,
                branch=repo.default_branch,
            )
        except GitCommandError as exc:
            raise CloneError(f"{repo.full_name}: clone failed: {exc.stderr}") from exc
        local.remotes.origin.set_url(repo.clone_url)
        return path

    def _update(self, path: Path, repo: RepoInfo, token: str | None) -> None:
        local = Repo(path)
        with _authenticated_remote(local, repo.clone_url or "", token) as origin:
            origin.fetch(depth=self._settings.clone_depth)
        local.git.reset("--hard", f"origin/{repo.default_branch}")

    def read_workflow_files(self, clone_path: Path, repo_full_name: str) -> list[WorkflowInfo]:
        """Read every workflow YAML in the clone (catches files the API listing misses)."""
        wf_dir = clone_path / WORKFLOW_DIR
        if not wf_dir.is_dir():
            return []
        workflows = []
        for file in sorted(wf_dir.iterdir()):
            if file.suffix not in (".yml", ".yaml") or not file.is_file():
                continue
            workflows.append(
                WorkflowInfo(
                    repo_full_name=repo_full_name,
                    path=f"{WORKFLOW_DIR}/{file.name}",
                    content=file.read_text(encoding="utf-8", errors="replace"),
                    source="clone",
                )
            )
        return workflows

    def prune(self, keep: set[str] | None = None) -> int:
        """Delete cached clones (all, or those not in *keep* as 'org/name'). Returns count."""
        if not self._clone_dir.is_dir():
            return 0
        removed = 0
        for org_dir in self._clone_dir.iterdir():
            if not org_dir.is_dir():
                continue
            for repo_dir in org_dir.iterdir():
                full_name = f"{org_dir.name}/{repo_dir.name}"
                if keep is not None and full_name in keep:
                    continue
                shutil.rmtree(repo_dir, ignore_errors=True)
                removed += 1
            if not any(org_dir.iterdir()):
                org_dir.rmdir()
        return removed
