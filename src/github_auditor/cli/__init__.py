"""Typer CLI for github-auditor (`github-auditor` / `gha`)."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

import github_auditor
from github_auditor.analyze.engine import RuleEngine, select_org_rules, select_rules
from github_auditor.cache import CacheStore, create_db_engine, init_db
from github_auditor.config import Settings
from github_auditor.exceptions import AuditorError
from github_auditor.models import AuditReport, Severity
from github_auditor.output import console as render
from github_auditor.output import export

app = typer.Typer(
    name="github-auditor",
    help="Audit a GitHub organization for repositories that put you at risk.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
cache_app = typer.Typer(help="Inspect or clear the local cache.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")

# When output is piped (not a terminal) Rich falls back to 80 columns, which
# truncates repo names in tables; give redirected output more room instead.
stdout = Console(width=None if sys.stdout.isatty() else 140)
stderr = Console(stderr=True)


@dataclass
class AppContext:
    settings: Settings
    store: CacheStore


def _load_context(db: Path | None = None) -> AppContext:
    settings = Settings()
    if db is not None:
        settings = settings.model_copy(update={"db_path": db})
    engine = create_db_engine(settings.effective_db_path)
    init_db(engine)
    return AppContext(settings=settings, store=CacheStore(engine))


def _resolve_org(org: str | None, settings: Settings) -> str:
    resolved = org or settings.org
    if not resolved:
        stderr.print("[red]No organization given. Pass ORG or set GITHUB_AUDITOR_ORG.[/]")
        raise typer.Exit(code=2)
    return resolved


def _severity_option(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        stderr.print(
            f"[red]Unknown severity '{value}'. "
            f"Choose from: {', '.join(s.value for s in Severity)}[/]"
        )
        raise typer.Exit(code=2) from exc


def _version_callback(value: bool) -> None:
    if value:
        stdout.print(f"github-auditor {github_auditor.__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """github-auditor: find the repos leaving your org at risk."""


def _run_sync(
    ctx: AppContext, org: str, *, refresh: bool, deep: bool, include_archived: bool
) -> None:
    from github_auditor.fetch import GitHubClient, OrgFetcher

    settings = ctx.settings
    if not settings.token_value():
        stderr.print(
            "[yellow]No GITHUB_TOKEN set — running unauthenticated (60 req/hr, "
            "public data only). Set GITHUB_TOKEN for a real audit.[/]"
        )
    client = GitHubClient(settings, log=lambda m: stderr.print(f"[yellow]{m}[/]"))

    with render.make_progress(stderr) as progress:
        task = progress.add_task(f"Fetching {org}", total=None)

        fetcher = OrgFetcher(
            client,
            ctx.store,
            settings,
            on_repo_done=lambda _name: progress.advance(task),
            log=lambda m: stderr.print(f"[yellow]{m}[/]"),
        )
        # SyncResult totals aren't known until repos are listed; run sync and let
        # the progress bar switch from indeterminate once counts are in.
        result = fetcher.sync(org, refresh=refresh, include_archived=include_archived)
        progress.update(task, total=result.repo_count, completed=result.repo_count)

    if deep:
        _deep_scan(ctx, org)

    stderr.print(
        f"Synced [bold]{org}[/]: {result.repo_count} repos "
        f"({result.fetched} fetched, {result.from_cache} fresh in cache"
        + (f", {result.removed} removed" if result.removed else "")
        + ")."
    )
    for error in result.errors:
        stderr.print(f"[red]fetch error:[/] {error}")


def _deep_scan(ctx: AppContext, org: str) -> None:
    """Clone repos with workflows and re-read workflow files from disk."""
    from github_auditor.clone import RepoCloner
    from github_auditor.exceptions import CloneError

    cloner = RepoCloner(ctx.settings)
    token = ctx.settings.token_value()
    repos = [
        r
        for r in ctx.store.list_repos(org)
        if not r.archived and ctx.store.get_workflows(r.full_name)
    ]
    with render.make_progress(stderr) as progress:
        task = progress.add_task("Deep scan (cloning)", total=len(repos))
        for repo in repos:
            try:
                path = cloner.ensure_clone(repo, token)
                workflows = cloner.read_workflow_files(path, repo.full_name)
                if workflows:
                    ctx.store.upsert_workflows(repo.id, workflows)
            except CloneError as exc:
                stderr.print(f"[red]{exc}[/]")
            finally:
                progress.advance(task)


def _analyze(
    ctx: AppContext,
    org: str,
    *,
    include_archived: bool,
    rules: str | None,
    exclude_rules: str | None,
) -> AuditReport:
    selected = select_rules(
        include=rules.split(",") if rules else None,
        exclude=exclude_rules.split(",") if exclude_rules else None,
    )
    engine = RuleEngine(rules=selected, settings=ctx.settings)
    return engine.analyze_org(ctx.store, org, include_archived=include_archived)


def _emit_report(
    report: AuditReport,
    *,
    format: str,
    min_severity: Severity | None,
    output: Path | None,
    detail_repo: str | None = None,
) -> None:
    if min_severity is not None:
        report.org_findings = [f for f in report.org_findings if f.severity >= min_severity]
        for rr in report.repos:
            rr.findings = [f for f in rr.findings if f.severity >= min_severity]

    if format == "json":
        text = export.report_to_json(report)
    elif format == "csv":
        text = export.findings_to_csv(report.findings)
    else:

        def _render_to(target: Console) -> None:
            if detail_repo:
                matches = [
                    r
                    for r in report.repos
                    if r.repo.full_name == detail_repo or r.repo.name == detail_repo
                ]
                if not matches:
                    stderr.print(f"[red]Repo '{detail_repo}' not found in report.[/]")
                    raise typer.Exit(code=2)
                for rr in matches:
                    render.render_repo_detail(rr, target)
            else:
                render.render_audit_summary(report, target)

        if output is None:
            _render_to(stdout)
        else:
            with open(output, "w") as fh:
                _render_to(Console(file=fh, width=120))
            stderr.print(f"Wrote report to {output}")
        return

    if output is not None:
        output.write_text(text)
        stderr.print(f"Wrote {format.upper()} report to {output}")
    else:
        print(text)


@app.command()
def audit(
    org: str = typer.Argument(None, help="Organization (or user) to audit."),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore cache TTL and re-fetch."),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Also clone repos to scan workflow files "
        "from disk (catches files the API listing misses).",
    ),
    include_archived: bool = typer.Option(True, "--include-archived/--no-archived"),
    format: str = typer.Option("table", "--format", "-f", help="table, json, or csv."),
    min_severity: str = typer.Option(None, "--min-severity", help="Hide findings below this."),
    rules: str = typer.Option(None, "--rules", help="Comma-separated rule ids to run."),
    exclude_rules: str = typer.Option(
        None, "--exclude-rules", help="Comma-separated rule ids to skip."
    ),
    fail_on: str = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding is at or above this severity (for CI)."
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Write the report to a file."),
    db: Path = typer.Option(None, "--db", help="Cache database path override."),
) -> None:
    """Fetch (respecting the cache TTL), analyze, and render a full audit."""
    ctx = _load_context(db)
    target = _resolve_org(org, ctx.settings)
    try:
        _run_sync(ctx, target, refresh=refresh, deep=deep, include_archived=include_archived)
    except AuditorError as exc:
        stderr.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    report = _analyze(
        ctx, target, include_archived=include_archived, rules=rules, exclude_rules=exclude_rules
    )
    _emit_report(report, format=format, min_severity=_severity_option(min_severity), output=output)

    threshold = _severity_option(fail_on)
    if threshold is not None and any(f.severity >= threshold for f in report.findings):
        raise typer.Exit(code=1)


@app.command()
def fetch(
    org: str = typer.Argument(None, help="Organization (or user) to fetch."),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore cache TTL and re-fetch."),
    deep: bool = typer.Option(False, "--deep", help="Also clone repos with workflows."),
    include_archived: bool = typer.Option(True, "--include-archived/--no-archived"),
    db: Path = typer.Option(None, "--db", help="Cache database path override."),
) -> None:
    """Populate the local cache without analyzing (alias: sync)."""
    ctx = _load_context(db)
    target = _resolve_org(org, ctx.settings)
    try:
        _run_sync(ctx, target, refresh=refresh, deep=deep, include_archived=include_archived)
    except AuditorError as exc:
        stderr.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc


app.command(name="sync", hidden=True)(fetch)


@app.command()
def report(
    org: str = typer.Argument(None),
    repo: str = typer.Option(None, "--repo", help="Show full detail for one repo."),
    format: str = typer.Option("table", "--format", "-f"),
    min_severity: str = typer.Option(None, "--min-severity"),
    include_archived: bool = typer.Option(True, "--include-archived/--no-archived"),
    output: Path = typer.Option(None, "--output", "-o"),
    db: Path = typer.Option(None, "--db"),
) -> None:
    """Re-analyze cached data and render the report. No network access."""
    ctx = _load_context(db)
    target = _resolve_org(org, ctx.settings)
    if not ctx.store.list_repos(target):
        stderr.print(f"[red]Nothing cached for '{target}'. Run 'gha fetch {target}' first.[/]")
        raise typer.Exit(code=2)
    audit_report = _analyze(
        ctx, target, include_archived=include_archived, rules=None, exclude_rules=None
    )
    _emit_report(
        audit_report,
        format=format,
        min_severity=_severity_option(min_severity),
        output=output,
        detail_repo=repo,
    )


@app.command()
def repos(
    org: str = typer.Argument(None),
    sort: str = typer.Option("score", "--sort", help="score, name, or pushed."),
    db: Path = typer.Option(None, "--db"),
) -> None:
    """List cached repos with their risk scores."""
    from rich.table import Table

    ctx = _load_context(db)
    target = _resolve_org(org, ctx.settings)
    if not ctx.store.list_repos(target):
        stderr.print(f"[red]Nothing cached for '{target}'. Run 'gha fetch {target}' first.[/]")
        raise typer.Exit(code=2)
    audit_report = _analyze(ctx, target, include_archived=True, rules=None, exclude_rules=None)

    rows = audit_report.repos
    if sort == "name":
        rows = sorted(rows, key=lambda r: r.repo.full_name)
    elif sort == "pushed":
        from datetime import datetime, timezone

        epoch = datetime.min.replace(tzinfo=timezone.utc)
        rows = sorted(rows, key=lambda r: r.repo.pushed_at or epoch)
    else:
        rows = audit_report.sorted_repos()

    table = Table(expand=True)
    table.add_column("Repository", style="bold")
    table.add_column("Visibility")
    table.add_column("Archived")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Last push")
    for rr in rows:
        r = rr.repo
        table.add_row(
            r.full_name,
            r.visibility,
            "yes" if r.archived else "",
            render.grade_text(rr.grade),
            str(rr.risk_score),
            str(len(rr.findings)),
            f"{r.pushed_at:%Y-%m-%d}" if r.pushed_at else "-",
        )
    stdout.print(table)


@app.command()
def findings(
    org: str = typer.Argument(None),
    severity: str = typer.Option(None, "--severity", help="Exact severity filter."),
    min_severity: str = typer.Option(None, "--min-severity"),
    rule: str = typer.Option(None, "--rule", help="Filter by rule id (e.g. GHA001)."),
    repo: str = typer.Option(None, "--repo", help="Filter by repo full name."),
    format: str = typer.Option("table", "--format", "-f"),
    db: Path = typer.Option(None, "--db"),
) -> None:
    """Show findings from the latest audit run in the cache."""
    ctx = _load_context(db)
    target = _resolve_org(org, ctx.settings)
    results = ctx.store.latest_findings(
        target,
        severity=_severity_option(severity),
        min_severity=_severity_option(min_severity),
        rule_id=rule,
        repo=repo,
    )
    if not results and ctx.store.latest_run_id(target) is None:
        stderr.print(
            f"[red]No audit runs cached for '{target}'. Run 'gha audit {target}' first.[/]"
        )
        raise typer.Exit(code=2)
    if format == "json":
        print(export.findings_to_json(results))
    elif format == "csv":
        print(export.findings_to_csv(results))
    else:
        render.render_findings_table(results, stdout)


@app.command()
def rules() -> None:
    """List every rule this auditor can run."""
    render.render_rules_table([*select_org_rules(), *select_rules()], stdout)


@cache_app.command("info")
def cache_info(db: Path = typer.Option(None, "--db")) -> None:
    """Show what the local cache holds."""
    ctx = _load_context(db)
    db_path = ctx.settings.effective_db_path
    size = db_path.stat().st_size if db_path.exists() else 0
    stats = ctx.store.cache_stats(str(db_path), size)
    render.render_cache_stats(stats, stdout)


@cache_app.command("clear")
def cache_clear(
    org: str = typer.Option(None, "--org", help="Only clear one org's data."),
    clones: bool = typer.Option(True, "--clones/--no-clones", help="Also delete cached clones."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
    db: Path = typer.Option(None, "--db"),
) -> None:
    """Clear cached API data (and clones)."""
    ctx = _load_context(db)
    scope = f"org '{org}'" if org else "ALL cached data"
    if not yes and not typer.confirm(f"Clear {scope}?"):
        raise typer.Exit()
    ctx.store.clear(org=org)
    removed = 0
    if clones:
        clone_root = ctx.settings.effective_clone_dir
        if org:
            org_dir = clone_root / org
            if org_dir.is_dir():
                removed = sum(1 for d in org_dir.iterdir() if d.is_dir())
                shutil.rmtree(org_dir, ignore_errors=True)
        else:
            from github_auditor.clone import RepoCloner

            removed = RepoCloner(ctx.settings).prune()
    stderr.print(f"Cleared {scope}" + (f"; removed {removed} clone(s)" if removed else "") + ".")
