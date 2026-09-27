"""Compare two analysis runs' findings.

Pure computation: it takes two lists of :class:`~github_auditor.models.Finding`
(loaded by the caller, e.g. via ``CacheStore.findings_for_run``) and reports what
appeared, what went away, and how each subject's risk score moved. Nothing here
touches the database or the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from github_auditor.models import Finding, risk_score, total_risk_score

# Identity of a finding across runs: the rule that fired, the subject it fired
# on, and where in that subject. Two findings are "the same" only if all three
# match, so a rule that moves to another file reads as one resolved plus one new
# finding rather than an unchanged one.
FindingKey = tuple[str, str, str]


def finding_key(finding: Finding) -> FindingKey:
    """The cross-run identity of a finding: ``(rule_id, repo, location or title)``."""
    return (finding.rule_id, finding.repo, finding.location or finding.title)


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """The severity-desc / repo / rule_id ordering used everywhere else."""
    return sorted(findings, key=lambda f: (-f.severity.rank, f.repo, f.rule_id))


@dataclass
class ScopeDelta:
    """How one subject's risk score moved between two runs."""

    scope: str  # a repository full name, or the ORG_SCOPE sentinel
    baseline_score: int
    current_score: int

    @property
    def delta(self) -> int:
        return self.current_score - self.baseline_score


@dataclass
class RunDiff:
    """What changed between a baseline run and a current one."""

    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    scope_deltas: list[ScopeDelta] = field(default_factory=list)
    baseline_total: int = 0
    current_total: int = 0

    @property
    def total_delta(self) -> int:
        return self.current_total - self.baseline_total


def _by_scope(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.repo, []).append(finding)
    return grouped


def compute_diff(baseline: list[Finding], current: list[Finding]) -> RunDiff:
    """Diff two runs' findings: what is new, what is resolved, how scores moved."""
    baseline_keys = {finding_key(f) for f in baseline}
    current_keys = {finding_key(f) for f in current}

    new_findings = [f for f in current if finding_key(f) not in baseline_keys]
    resolved_findings = [f for f in baseline if finding_key(f) not in current_keys]

    baseline_scopes = _by_scope(baseline)
    current_scopes = _by_scope(current)
    scope_deltas = []
    for scope in baseline_scopes.keys() | current_scopes.keys():
        before = risk_score(baseline_scopes.get(scope, []))
        after = risk_score(current_scopes.get(scope, []))
        if before != after:
            scope_deltas.append(ScopeDelta(scope=scope, baseline_score=before, current_score=after))

    return RunDiff(
        new_findings=_sorted_findings(new_findings),
        resolved_findings=_sorted_findings(resolved_findings),
        scope_deltas=sorted(scope_deltas, key=lambda d: (-abs(d.delta), d.scope)),
        baseline_total=total_risk_score(baseline),
        current_total=total_risk_score(current),
    )
