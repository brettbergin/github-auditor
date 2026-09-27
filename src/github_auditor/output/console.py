"""Rich renderers for audit results."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from github_auditor.analyze.diff import RunDiff
from github_auditor.analyze.rules.base import RuleBase
from github_auditor.cache.store import AuditRunSummary, CacheStats, TrendRow
from github_auditor.models import AuditReport, Finding, RepoRiskReport, Severity

GRADE_STYLES = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red"}


def severity_text(severity: Severity) -> Text:
    return Text(severity.value.upper(), style=severity.rich_style)


def grade_text(grade: str) -> Text:
    return Text(grade, style=GRADE_STYLES.get(grade, ""))


def make_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def render_org_findings(report: AuditReport, console: Console) -> None:
    """Org-wide findings, shown first: each one applies to every repo below it."""
    if not report.org_findings:
        return
    tree = Tree(
        Text.assemble(
            ("Organization settings", "bold"),
            f"  ({len(report.org_findings)} finding(s) affecting every repository)",
        )
    )
    for f in sorted(report.org_findings, key=lambda f: -f.severity.rank):
        node = tree.add(Text.assemble(severity_text(f.severity), f"  {f.rule_id}  {f.title}"))
        if f.evidence:
            node.add(Text(f.evidence, style="dim italic"))
        if f.remediation:
            node.add(Text(f"fix: {f.remediation}", style="green"))
    console.print(tree)
    console.print()


def render_audit_summary(report: AuditReport, console: Console, *, min_grade: str = "A") -> None:
    totals = report.severity_totals()
    header = Text()
    header.append(f"Organization: {report.org}\n", style="bold")
    header.append(f"Repositories audited: {len(report.repos)}\n")
    header.append(f"Generated: {report.generated_at:%Y-%m-%d %H:%M UTC}\n\n")
    for sev in Severity:
        count = totals[sev.value]
        style = sev.rich_style if count else "dim"
        header.append(f"{sev.value.upper()}: {count}   ", style=style)
    console.print(Panel(header, title="GitHub Security Audit", border_style="blue"))

    render_org_findings(report, console)

    at_risk = [r for r in report.sorted_repos() if r.findings]
    clean = len(report.repos) - len(at_risk)

    if not at_risk:
        console.print("[bold green]Every audited repository came back clean.[/]")
        return

    table = Table(title="Repositories by risk", expand=True)
    table.add_column("Repository", style="bold", no_wrap=True)
    table.add_column("Visibility")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Crit", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Med", justify="right")
    table.add_column("Low", justify="right")
    table.add_column("Last push", no_wrap=True)

    def count_cell(rr: RepoRiskReport, sev: Severity) -> Text:
        n = rr.severity_count(sev)
        return Text(str(n), style=sev.rich_style if n else "dim")

    for rr in at_risk:
        repo = rr.repo
        vis_style = "red" if repo.is_public else "dim"
        table.add_row(
            repo.full_name,
            Text(repo.visibility, style=vis_style),
            grade_text(rr.grade),
            str(rr.risk_score),
            count_cell(rr, Severity.CRITICAL),
            count_cell(rr, Severity.HIGH),
            count_cell(rr, Severity.MEDIUM),
            count_cell(rr, Severity.LOW),
            f"{repo.pushed_at:%Y-%m-%d}" if repo.pushed_at else "-",
        )
    console.print(table)
    if clean:
        console.print(f"[green]{clean} repo(s) with no findings not shown.[/]")


def render_repo_detail(rr: RepoRiskReport, console: Console) -> None:
    repo = rr.repo
    title = Text(repo.full_name, style="bold")
    title.append(f"  [{repo.visibility}]", style="red" if repo.is_public else "dim")
    title.append("  grade ")
    title.append(rr.grade, style=GRADE_STYLES.get(rr.grade, ""))
    title.append(f"  score {rr.risk_score}")
    tree = Tree(title)
    by_rule: dict[str, list[Finding]] = {}
    for f in sorted(rr.findings, key=lambda f: -f.severity.rank):
        by_rule.setdefault(f"{f.rule_id} {f.rule_name}", []).append(f)
    for rule_label, findings in by_rule.items():
        branch = tree.add(Text.assemble(severity_text(findings[0].severity), f"  {rule_label}"))
        for f in findings:
            node = branch.add(f.title)
            if f.location:
                node.add(Text(f"at {f.location}", style="dim"))
            if f.evidence:
                node.add(Text(f.evidence, style="dim italic"))
            if f.remediation:
                node.add(Text(f"fix: {f.remediation}", style="green"))
    console.print(tree)


def render_findings_table(findings: list[Finding], console: Console) -> None:
    if not findings:
        console.print("[green]No findings match.[/]")
        return
    table = Table(expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Repository", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location", overflow="fold")
    for f in findings:
        table.add_row(
            severity_text(f.severity),
            f"{f.rule_id}",
            f.repo,
            f.title,
            f.location or "-",
        )
    console.print(table)
    console.print(f"[dim]{len(findings)} finding(s)[/]")


def render_rules_table(rules: Sequence[RuleBase], console: Console) -> None:
    table = Table(title="Available rules", expand=True)
    table.add_column("ID", no_wrap=True)
    table.add_column("Name", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Checks for")
    for rule in rules:
        table.add_row(
            rule.id,
            rule.name,
            severity_text(rule.default_severity),
            rule.description,
        )
    console.print(table)


def delta_text(delta: int | None) -> Text:
    """A signed score move, green when the score fell; '-' for the first run."""
    if delta is None:
        return Text("-", style="dim")
    style = "green" if delta < 0 else "red" if delta > 0 else "dim"
    return Text(f"{delta:+d}", style=style)


def _run_stamp(run: AuditRunSummary) -> str:
    """When a run finished, or when it started if it somehow has no finish time."""
    when = run.finished_at or run.started_at
    return f"{when:%Y-%m-%d %H:%M UTC}"


def _diff_findings_table(title: str, findings: Sequence[Finding]) -> Table:
    """One side of a run diff, in the same columns as :func:`render_findings_table`."""
    table = Table(title=title, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Repository", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location", overflow="fold")
    for f in findings:
        table.add_row(
            severity_text(f.severity),
            f.rule_id,
            f.repo,
            f.title,
            f.location or "-",
        )
    return table


def render_diff(
    org: str,
    baseline: AuditRunSummary,
    current: AuditRunSummary,
    diff: RunDiff,
    console: Console,
) -> None:
    """What changed between two audit runs: findings gained, findings resolved, scores."""
    if not diff.new_findings and not diff.resolved_findings and not diff.scope_deltas:
        console.print(f"No changes between run {baseline.id} and run {current.id}.")
        return

    header = Text()
    header.append(f"Organization: {org}\n", style="bold")
    header.append(f"Baseline: run {baseline.id} ({_run_stamp(baseline)})\n")
    header.append(f"Current:  run {current.id} ({_run_stamp(current)})\n\n")
    header.append(f"Risk score {diff.baseline_total} -> {diff.current_total}  ")
    header.append(delta_text(diff.total_delta))
    console.print(Panel(header, title="Audit run diff", border_style="blue"))

    if diff.new_findings:
        console.print(_diff_findings_table("New findings", diff.new_findings))
    if diff.resolved_findings:
        console.print(_diff_findings_table("Resolved findings", diff.resolved_findings))

    if diff.scope_deltas:
        table = Table(title="Score changes", expand=True)
        table.add_column("Scope", style="bold", no_wrap=True)
        table.add_column("Baseline", justify="right")
        table.add_column("Current", justify="right")
        table.add_column("Δ", justify="right")
        for scope_delta in diff.scope_deltas:
            table.add_row(
                scope_delta.scope,
                str(scope_delta.baseline_score),
                str(scope_delta.current_score),
                delta_text(scope_delta.delta),
            )
        console.print(table)


def render_trends(org: str, rows: Sequence[TrendRow], console: Console) -> None:
    """Risk score per audit run, oldest first, with the move between runs."""
    table = Table(title=f"Risk score trend for {org}")
    table.add_column("Run ID", justify="right", no_wrap=True)
    table.add_column("Finished", no_wrap=True)
    table.add_column("Repos", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Risk score", justify="right")
    table.add_column("Δ", justify="right")
    for row in rows:
        table.add_row(
            str(row.id),
            f"{row.finished_at:%Y-%m-%d %H:%M UTC}" if row.finished_at else "-",
            str(row.repo_count),
            str(row.finding_count),
            str(row.risk_score),
            delta_text(row.delta),
        )
    console.print(table)


def render_cache_stats(stats: CacheStats, console: Console) -> None:
    table = Table(title="Cache", show_header=False)
    table.add_column("k", style="bold")
    table.add_column("v")
    table.add_row("Database", stats.db_path)
    table.add_row("Size", f"{stats.db_size_bytes / 1024:.1f} KiB")
    table.add_row("Organizations", f"{stats.org_count} ({', '.join(stats.orgs) or '-'})")
    table.add_row("Repositories", str(stats.repo_count))
    table.add_row("Workflow files", str(stats.workflow_count))
    table.add_row("Audit runs", str(stats.audit_run_count))
    table.add_row("Findings (all runs)", str(stats.finding_count))
    if stats.newest_fetch:
        table.add_row("Newest fetch", f"{stats.newest_fetch:%Y-%m-%d %H:%M UTC}")
    if stats.oldest_fetch:
        table.add_row("Oldest fetch", f"{stats.oldest_fetch:%Y-%m-%d %H:%M UTC}")
    console.print(table)
