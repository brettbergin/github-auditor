"""Rule engine: run rules over cached data and produce an AuditReport."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from github_auditor.analyze.rules import ALL_RULES, RepoContext, Rule
from github_auditor.analyze.workflow_parser import ParsedWorkflow, parse_workflow
from github_auditor.cache.store import CacheStore
from github_auditor.config import Settings
from github_auditor.models import (
    AuditReport,
    Finding,
    RepoInfo,
    RepoRiskReport,
    Severity,
)


def select_rules(
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> list[Rule]:
    """Instantiate rules, filtered by rule id or name (case-insensitive)."""
    include_set = {r.lower() for r in include} if include else None
    exclude_set = {r.lower() for r in exclude} if exclude else set()
    selected = []
    for cls in ALL_RULES:
        keys = {cls.id.lower(), cls.name.lower()}
        if include_set is not None and not (keys & include_set):
            continue
        if keys & exclude_set:
            continue
        selected.append(cls())
    return selected


class RuleEngine:
    def __init__(self, rules: Sequence[Rule] | None = None, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.rules: list[Rule] = list(rules) if rules is not None else select_rules()

    def analyze_repo(self, ctx: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check(ctx))
        return findings

    def build_context(
        self,
        repo: RepoInfo,
        store: CacheStore,
        org: str,
    ) -> tuple[RepoContext, list[Finding]]:
        """Load workflows from cache, parse them, and assemble the rule context.

        Returns the context plus any parse-failure findings (unparseable workflow files
        are surfaced as info findings rather than silently skipped).
        """
        raw_workflows = store.get_workflows(repo.full_name)
        parsed: list[ParsedWorkflow] = []
        parse_failures: list[Finding] = []
        for wf in raw_workflows:
            if not wf.content:
                continue
            result = parse_workflow(wf.content, wf.path)
            if result is None:
                parse_failures.append(
                    Finding(
                        rule_id="PARSE",
                        rule_name="unparseable-workflow",
                        severity=Severity.INFO,
                        title=f"Could not parse workflow YAML: {wf.path}",
                        description="The file could not be parsed as workflow YAML and was "
                        "excluded from workflow analysis.",
                        repo=repo.full_name,
                        location=wf.path,
                    )
                )
            else:
                parsed.append(result)

        all_runners = store.get_runners(org)
        ctx = RepoContext(
            org=org,
            repo=repo,
            workflows=parsed,
            raw_workflows=raw_workflows,
            org_info=store.get_org(org),
            org_runners=[r for r in all_runners if r.level == "org"],
            repo_runners=[
                r for r in all_runners
                if r.level == "repo" and r.repo_full_name == repo.full_name
            ],
            settings=self.settings,
        )
        return ctx, parse_failures

    def analyze_org(
        self,
        store: CacheStore,
        org: str,
        *,
        include_archived: bool = True,
        persist: bool = True,
        progress: Callable[[str], None] | None = None,
    ) -> AuditReport:
        """Analyze every cached repo of *org*. Cache-only: never touches the network."""
        repos = store.list_repos(org, include_archived=include_archived)
        report = AuditReport(org=org)
        run_id = store.start_audit_run(org) if persist else None

        for repo in repos:
            if progress is not None:
                progress(repo.full_name)
            ctx, parse_failures = self.build_context(repo, store, org)
            findings = parse_failures + self.analyze_repo(ctx)
            report.repos.append(RepoRiskReport(repo=repo, findings=findings))
            if run_id is not None and findings:
                store.save_findings(run_id, findings)

        if run_id is not None:
            store.finish_audit_run(
                run_id, repo_count=len(repos), finding_count=len(report.findings)
            )
        return report
