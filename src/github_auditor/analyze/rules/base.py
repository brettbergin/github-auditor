"""Rule base class and the per-repo context handed to every rule."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import ClassVar

from github_auditor.analyze.workflow_parser import ParsedWorkflow
from github_auditor.config import Settings
from github_auditor.models import Finding, OrgInfo, RepoInfo, RunnerInfo, Severity, WorkflowInfo


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


class Rule(ABC):
    """A single security check. Subclasses yield findings for one repo at a time."""

    id: ClassVar[str]
    name: ClassVar[str]
    default_severity: ClassVar[Severity]
    description: ClassVar[str]
    remediation: ClassVar[str] = ""

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
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=severity or self.default_severity,
            title=title,
            description=description if description is not None else self.description,
            remediation=self.remediation,
            repo=ctx.repo.full_name,
            location=location,
            evidence=evidence,
        )
