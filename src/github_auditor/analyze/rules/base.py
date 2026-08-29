"""Rule base class and the per-repo context handed to every rule."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from github_auditor.analyze.workflow_parser import ParsedWorkflow
from github_auditor.config import Settings
from github_auditor.models import (
    ORG_SCOPE,
    Finding,
    OrgInfo,
    RepoInfo,
    RunnerInfo,
    Severity,
    WorkflowInfo,
)


@dataclass
class RepoContext:
    org: str
    repo: RepoInfo
    workflows: list[ParsedWorkflow] = field(default_factory=list)
    raw_workflows: list[WorkflowInfo] = field(default_factory=list)
    org_info: OrgInfo | None = None
    org_runners: list[RunnerInfo] = field(default_factory=list)
    repo_runners: list[RunnerInfo] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)


@dataclass
class OrgContext:
    """Organization-wide settings, for rules that audit the org rather than a repo."""

    org: str
    org_info: OrgInfo
    settings: Settings = field(default_factory=Settings)


class RuleBase(ABC):
    """Shared identity for every rule, repo-scoped or org-scoped."""

    id: ClassVar[str]
    name: ClassVar[str]
    default_severity: ClassVar[Severity]
    description: ClassVar[str]
    remediation: ClassVar[str] = ""

    def _finding(
        self,
        repo: str,
        *,
        title: str,
        severity: Severity | None = None,
        description: str | None = None,
        location: str | None = None,
        evidence: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.default_severity,
            title=title,
            description=description if description is not None else self.description,
            remediation=self.remediation,
            repo=repo,
            location=location,
            evidence=evidence,
        )


class Rule(RuleBase):
    """A repository-scoped check. Subclasses yield findings for one repo at a time."""

    @abstractmethod
    def check(self, ctx: RepoContext) -> Iterator[Finding]:
        """Yield findings for this repo. Must treat None posture fields as unknown."""

    def finding(
        self,
        ctx: RepoContext,
        *,
        title: str,
        severity: Severity | None = None,
        description: str | None = None,
        location: str | None = None,
        evidence: str | None = None,
    ) -> Finding:
        return self._finding(
            ctx.repo.full_name,
            title=title,
            severity=severity,
            description=description,
            location=location,
            evidence=evidence,
        )


class OrgRule(RuleBase):
    """An organization-scoped check, run once per audit rather than per repo."""

    @abstractmethod
    def check(self, ctx: OrgContext) -> Iterator[Finding]:
        """Yield org-level findings. Must treat None posture fields as unknown."""

    def finding(
        self,
        ctx: OrgContext,
        *,
        title: str,
        severity: Severity | None = None,
        description: str | None = None,
        location: str | None = None,
        evidence: str | None = None,
    ) -> Finding:
        # repo defaults to the ORG_SCOPE sentinel on Finding.
        return self._finding(
            ORG_SCOPE,
            title=title,
            severity=severity,
            description=description,
            location=location,
            evidence=evidence,
        )
