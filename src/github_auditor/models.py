"""Pydantic domain models shared by the fetch, cache, analysis, and output layers.

Security-posture fields on :class:`RepoInfo` are tri-state: ``None`` means the
authenticated token could not see the setting (403/404 from GitHub). Rules must
treat ``None`` as "unknown" and skip, never report a finding from it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TypeAlias

from pydantic import BaseModel, Field

# JSON-shaped payloads (cache rows, raw API data). Values are `object` rather
# than `Any` so every consumer must narrow before use.
JSONDict: TypeAlias = dict[str, object]

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Sentinel used as Finding.repo for findings that belong to the organization
# itself rather than to any one repository.
ORG_SCOPE = "<organization>"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 50, "high": 20, "medium": 7, "low": 2, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self.value)

    @property
    def rich_style(self) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }[self.value]

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BranchProtectionInfo(BaseModel):
    exists: bool
    required_reviews: int = 0
    required_status_checks: bool = False
    enforce_admins: bool = False
    allow_force_pushes: bool = False
    allow_deletions: bool = False


class DeployKeyInfo(BaseModel):
    id: int
    title: str = ""
    read_only: bool = True
    created_at: datetime | None = None


class CollaboratorInfo(BaseModel):
    login: str
    permission: str = "pull"  # admin / maintain / push / triage / pull
    affiliation: str = "outside"


class RunnerInfo(BaseModel):
    name: str
    os: str | None = None
    status: str | None = None
    labels: list[str] = Field(default_factory=list)
    level: str = "repo"  # "org" or "repo"
    repo_full_name: str | None = None


class OrgInfo(BaseModel):
    login: str
    id: int | None = None
    name: str | None = None
    is_user: bool = False  # target is a user account, not an organization

    # Tri-state org posture (None = not visible to this token; most of these
    # require org-owner or admin:org read).
    two_factor_requirement_enabled: bool | None = None
    default_repository_permission: str | None = None  # none / read / write / admin
    members_can_create_public_repositories: bool | None = None
    default_workflow_permissions: str | None = None  # read / write
    can_approve_pull_request_reviews: bool | None = None
    # Fork-PR approval policy, e.g. first_time_contributors_new_to_github /
    # first_time_contributors / all_external_contributors.
    fork_pr_approval_policy: str | None = None
    fetched_at: datetime = Field(default_factory=utcnow)


class WorkflowInfo(BaseModel):
    repo_full_name: str
    path: str
    name: str | None = None
    state: str | None = None  # active / disabled_manually / disabled_inactivity / ...
    content: str | None = None
    source: str = "api"  # "api" or "clone"


class RepoInfo(BaseModel):
    id: int
    full_name: str
    name: str
    org: str
    visibility: str = "public"  # public / private / internal
    archived: bool = False
    fork: bool = False
    default_branch: str = "main"
    pushed_at: datetime | None = None
    html_url: str | None = None
    clone_url: str | None = None

    # Tri-state security posture (None = not visible to this token).
    actions_enabled: bool | None = None
    actions_allowed_actions: str | None = None  # all / local_only / selected
    default_workflow_permissions: str | None = None  # read / write
    can_approve_pull_request_reviews: bool | None = None
    secret_scanning: bool | None = None
    push_protection: bool | None = None
    dependabot_alerts: bool | None = None
    branch_protection: BranchProtectionInfo | None = None
    deploy_keys: list[DeployKeyInfo] | None = None
    outside_collaborators: list[CollaboratorInfo] | None = None
    has_self_hosted_runners: bool | None = None

    fetched_at: datetime = Field(default_factory=utcnow)

    @property
    def is_public(self) -> bool:
        return self.visibility == "public"


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    title: str
    description: str = ""
    remediation: str = ""
    # Repository the finding belongs to. Org-scoped findings (the ORG rules)
    # carry the scope marker below instead of a repository name.
    repo: str = ORG_SCOPE
    location: str | None = None
    evidence: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def is_org_scoped(self) -> bool:
        return self.repo == ORG_SCOPE


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(f.severity.weight for f in findings))


def risk_grade(score: int) -> str:
    if score == 0:
        return "A"
    if score <= 5:
        return "B"
    if score <= 15:
        return "C"
    if score <= 35:
        return "D"
    return "F"


class RepoRiskReport(BaseModel):
    repo: RepoInfo
    findings: list[Finding] = Field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return risk_score(self.findings)

    @property
    def grade(self) -> str:
        return risk_grade(self.risk_score)

    def severity_count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


class AuditReport(BaseModel):
    org: str
    generated_at: datetime = Field(default_factory=utcnow)
    repos: list[RepoRiskReport] = Field(default_factory=list)
    # Findings about the organization itself, which apply to every repo under it.
    org_findings: list[Finding] = Field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return self.org_findings + [f for r in self.repos for f in r.findings]

    @property
    def org_risk_score(self) -> int:
        return risk_score(self.org_findings)

    def severity_totals(self) -> dict[str, int]:
        totals = {s.value: 0 for s in Severity}
        for f in self.findings:
            totals[f.severity.value] += 1
        return totals

    def sorted_repos(self) -> list[RepoRiskReport]:
        return sorted(self.repos, key=lambda r: (-r.risk_score, r.repo.full_name))
