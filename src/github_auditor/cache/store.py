"""CacheStore: repository-pattern access to the SQLite cache.

Writes are serialized with a lock so the fetcher's thread pool can safely
funnel results into a single SQLite database.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from github_auditor.cache.orm import (
    AuditRunRow,
    FetchMetaRow,
    FindingRow,
    OrgRow,
    RepoRow,
    RunnerRow,
    WorkflowRow,
)
from github_auditor.models import (
    Finding,
    OrgInfo,
    RepoInfo,
    RunnerInfo,
    Severity,
    WorkflowInfo,
    total_risk_score,
    utcnow,
)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; interpret stored naive datetimes as UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _aware_utc(dt: datetime) -> datetime:
    """Non-optional variant of :func:`_aware`, for columns that are never null."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@dataclass
class CacheStats:
    db_path: str
    db_size_bytes: int
    org_count: int = 0
    repo_count: int = 0
    workflow_count: int = 0
    finding_count: int = 0
    audit_run_count: int = 0
    oldest_fetch: datetime | None = None
    newest_fetch: datetime | None = None
    orgs: list[str] = field(default_factory=list)


@dataclass
class AuditRunSummary:
    """One finished analysis run, as history/trend views want to read it."""

    id: int
    started_at: datetime
    finished_at: datetime | None
    repo_count: int
    finding_count: int
    risk_score: int


@dataclass
class TrendRow(AuditRunSummary):
    """A run in a chronological trend view, with the score move from the run before it.

    ``delta`` is None for the first row shown, which has no predecessor to compare
    against.
    """

    delta: int | None = None

    @classmethod
    def from_run(cls, run: AuditRunSummary, delta: int | None) -> TrendRow:
        return cls(
            id=run.id,
            started_at=run.started_at,
            finished_at=run.finished_at,
            repo_count=run.repo_count,
            finding_count=run.finding_count,
            risk_score=run.risk_score,
            delta=delta,
        )


class CacheStore:
    def __init__(self, engine: Engine):
        self._engine = engine
        self._session_factory = sessionmaker(engine, expire_on_commit=False)
        self._write_lock = threading.Lock()

    def _session(self) -> Session:
        return self._session_factory()

    # -- freshness ---------------------------------------------------------

    def is_fresh(self, kind: str, key: str, ttl: timedelta) -> bool:
        with self._session() as session:
            row = session.get(FetchMetaRow, (kind, key))
            if row is None:
                return False
            fetched_at = _aware(row.fetched_at)
            return fetched_at is not None and utcnow() - fetched_at < ttl

    def touch(self, kind: str, key: str) -> None:
        with self._write_lock, self._session() as session:
            row = session.get(FetchMetaRow, (kind, key))
            if row is None:
                row = FetchMetaRow(kind=kind, key=key, fetched_at=utcnow())
                session.add(row)
            else:
                row.fetched_at = utcnow()
            session.commit()

    # -- orgs --------------------------------------------------------------

    def upsert_org(self, org: OrgInfo) -> None:
        with self._write_lock, self._session() as session:
            row = session.get(OrgRow, org.login)
            data = org.model_dump(mode="json")
            if row is None:
                session.add(OrgRow(login=org.login, data=data, fetched_at=utcnow()))
            else:
                row.data = data
                row.fetched_at = utcnow()
            session.commit()

    def get_org(self, login: str) -> OrgInfo | None:
        with self._session() as session:
            row = session.get(OrgRow, login)
            return OrgInfo.model_validate(row.data) if row else None

    # -- repos -------------------------------------------------------------

    def upsert_repo(self, repo: RepoInfo) -> None:
        with self._write_lock, self._session() as session:
            row = session.get(RepoRow, repo.id)
            data = repo.model_dump(mode="json")
            if row is None:
                row = RepoRow(id=repo.id)
                session.add(row)
            row.org_login = repo.org
            row.full_name = repo.full_name
            row.visibility = repo.visibility
            row.archived = repo.archived
            row.pushed_at = repo.pushed_at
            row.data = data
            row.fetched_at = utcnow()
            session.commit()

    def get_repo(self, full_name: str) -> RepoInfo | None:
        with self._session() as session:
            row = session.scalar(select(RepoRow).where(RepoRow.full_name == full_name))
            return RepoInfo.model_validate(row.data) if row else None

    def list_repos(self, org: str, *, include_archived: bool = True) -> list[RepoInfo]:
        with self._session() as session:
            stmt = select(RepoRow).where(RepoRow.org_login == org).order_by(RepoRow.full_name)
            if not include_archived:
                stmt = stmt.where(RepoRow.archived.is_(False))
            return [RepoInfo.model_validate(row.data) for row in session.scalars(stmt)]

    def delete_repos_not_in(self, org: str, keep_ids: set[int]) -> int:
        """Drop cached repos that no longer exist upstream. Returns count removed."""
        with self._write_lock, self._session() as session:
            stmt = select(RepoRow).where(RepoRow.org_login == org)
            stale = [row for row in session.scalars(stmt) if row.id not in keep_ids]
            for row in stale:
                session.delete(row)
            session.commit()
            return len(stale)

    # -- workflows ---------------------------------------------------------

    def upsert_workflows(self, repo_id: int, workflows: list[WorkflowInfo]) -> None:
        with self._write_lock, self._session() as session:
            session.execute(delete(WorkflowRow).where(WorkflowRow.repo_id == repo_id))
            for wf in workflows:
                session.add(
                    WorkflowRow(
                        repo_id=repo_id,
                        path=wf.path,
                        name=wf.name,
                        state=wf.state,
                        content=wf.content,
                        source=wf.source,
                        fetched_at=utcnow(),
                    )
                )
            session.commit()

    def get_workflows(self, repo_full_name: str) -> list[WorkflowInfo]:
        with self._session() as session:
            repo = session.scalar(select(RepoRow).where(RepoRow.full_name == repo_full_name))
            if repo is None:
                return []
            return [
                WorkflowInfo(
                    repo_full_name=repo_full_name,
                    path=row.path,
                    name=row.name,
                    state=row.state,
                    content=row.content,
                    source=row.source,
                )
                for row in repo.workflows
            ]

    # -- runners -----------------------------------------------------------

    def replace_runners(
        self, org: str, runners: list[RunnerInfo], *, level: str, repo_full_name: str | None = None
    ) -> None:
        with self._write_lock, self._session() as session:
            stmt = delete(RunnerRow).where(RunnerRow.org_login == org, RunnerRow.level == level)
            if repo_full_name is not None:
                stmt = stmt.where(RunnerRow.repo_full_name == repo_full_name)
            session.execute(stmt)
            for runner in runners:
                session.add(
                    RunnerRow(
                        org_login=org,
                        level=runner.level,
                        repo_full_name=runner.repo_full_name,
                        data=runner.model_dump(mode="json"),
                        fetched_at=utcnow(),
                    )
                )
            session.commit()

    def get_runners(self, org: str) -> list[RunnerInfo]:
        with self._session() as session:
            stmt = select(RunnerRow).where(RunnerRow.org_login == org)
            return [RunnerInfo.model_validate(row.data) for row in session.scalars(stmt)]

    # -- audit runs / findings ---------------------------------------------

    def start_audit_run(self, org: str) -> int:
        with self._write_lock, self._session() as session:
            run = AuditRunRow(org_login=org, started_at=utcnow(), finished_at=None)
            session.add(run)
            session.commit()
            return run.id

    def finish_audit_run(self, run_id: int, *, repo_count: int, finding_count: int) -> None:
        with self._write_lock, self._session() as session:
            run = session.get(AuditRunRow, run_id)
            if run is not None:
                run.finished_at = utcnow()
                run.repo_count = repo_count
                run.finding_count = finding_count
                session.commit()

    def save_findings(self, run_id: int, findings: list[Finding]) -> None:
        with self._write_lock, self._session() as session:
            for finding in findings:
                session.add(
                    FindingRow(
                        run_id=run_id,
                        repo_full_name=finding.repo,
                        rule_id=finding.rule_id,
                        severity=finding.severity.value,
                        data=finding.model_dump(mode="json"),
                    )
                )
            session.commit()

    def latest_run_id(self, org: str) -> int | None:
        with self._session() as session:
            return session.scalar(
                select(AuditRunRow.id)
                .where(AuditRunRow.org_login == org, AuditRunRow.finished_at.is_not(None))
                .order_by(AuditRunRow.id.desc())
                .limit(1)
            )

    def latest_findings(
        self,
        org: str,
        *,
        min_severity: Severity | None = None,
        severity: Severity | None = None,
        rule_id: str | None = None,
        repo: str | None = None,
    ) -> list[Finding]:
        run_id = self.latest_run_id(org)
        if run_id is None:
            return []
        with self._session() as session:
            stmt = select(FindingRow).where(FindingRow.run_id == run_id)
            if severity is not None:
                stmt = stmt.where(FindingRow.severity == severity.value)
            if rule_id is not None:
                stmt = stmt.where(func.lower(FindingRow.rule_id) == rule_id.lower())
            if repo is not None:
                stmt = stmt.where(FindingRow.repo_full_name == repo)
            findings = [Finding.model_validate(row.data) for row in session.scalars(stmt)]
        if min_severity is not None:
            findings = [f for f in findings if f.severity >= min_severity]
        return sorted(findings, key=lambda f: (-f.severity.rank, f.repo, f.rule_id))

    # -- run history -------------------------------------------------------

    def findings_for_run(self, run_id: int) -> list[Finding]:
        """Every finding saved under one specific run, most-severe first."""
        with self._session() as session:
            stmt = select(FindingRow).where(FindingRow.run_id == run_id)
            findings = [Finding.model_validate(row.data) for row in session.scalars(stmt)]
        return sorted(findings, key=lambda f: (-f.severity.rank, f.repo, f.rule_id))

    def _summarize_run(self, row: AuditRunRow) -> AuditRunSummary:
        return AuditRunSummary(
            id=row.id,
            started_at=_aware_utc(row.started_at),
            finished_at=_aware(row.finished_at),
            repo_count=row.repo_count,
            finding_count=row.finding_count,
            risk_score=total_risk_score(self.findings_for_run(row.id)),
        )

    def list_audit_runs(self, org: str, *, limit: int = 10) -> list[AuditRunSummary]:
        """The org's finished runs, most recent first, at most ``limit`` of them."""
        with self._session() as session:
            rows = list(
                session.scalars(
                    select(AuditRunRow)
                    .where(AuditRunRow.org_login == org, AuditRunRow.finished_at.is_not(None))
                    .order_by(AuditRunRow.id.desc())
                    .limit(limit)
                )
            )
        return [self._summarize_run(row) for row in rows]

    def get_run(self, org: str, run_id: int) -> AuditRunSummary | None:
        """One finished run of this org by id, or None if there is no such run."""
        with self._session() as session:
            row = session.scalar(
                select(AuditRunRow).where(
                    AuditRunRow.id == run_id,
                    AuditRunRow.org_login == org,
                    AuditRunRow.finished_at.is_not(None),
                )
            )
        return self._summarize_run(row) if row is not None else None

    def find_run_before(self, org: str, cutoff: datetime) -> AuditRunSummary | None:
        """The org's most recent finished run that started at or before ``cutoff``."""
        cutoff = _aware_utc(cutoff)
        with self._session() as session:
            rows = session.scalars(
                select(AuditRunRow)
                .where(AuditRunRow.org_login == org, AuditRunRow.finished_at.is_not(None))
                .order_by(AuditRunRow.id.desc())
            )
            match = next((row for row in rows if _aware_utc(row.started_at) <= cutoff), None)
        return self._summarize_run(match) if match is not None else None

    # -- maintenance -------------------------------------------------------

    def cache_stats(self, db_path: str, db_size_bytes: int) -> CacheStats:
        with self._session() as session:
            stats = CacheStats(db_path=db_path, db_size_bytes=db_size_bytes)
            stats.org_count = session.scalar(select(func.count(OrgRow.login))) or 0
            stats.repo_count = session.scalar(select(func.count(RepoRow.id))) or 0
            stats.workflow_count = session.scalar(select(func.count(WorkflowRow.id))) or 0
            stats.finding_count = session.scalar(select(func.count(FindingRow.id))) or 0
            stats.audit_run_count = session.scalar(select(func.count(AuditRunRow.id))) or 0
            stats.oldest_fetch = _aware(session.scalar(select(func.min(FetchMetaRow.fetched_at))))
            stats.newest_fetch = _aware(session.scalar(select(func.max(FetchMetaRow.fetched_at))))
            stats.orgs = list(session.scalars(select(OrgRow.login).order_by(OrgRow.login)))
            return stats

    def clear(self, *, org: str | None = None) -> None:
        with self._write_lock, self._session() as session:
            if org is None:
                for table in (
                    FindingRow,
                    AuditRunRow,
                    WorkflowRow,
                    RunnerRow,
                    RepoRow,
                    OrgRow,
                    FetchMetaRow,
                ):
                    session.execute(delete(table))
            else:
                run_ids = select(AuditRunRow.id).where(AuditRunRow.org_login == org)
                session.execute(delete(FindingRow).where(FindingRow.run_id.in_(run_ids)))
                session.execute(delete(AuditRunRow).where(AuditRunRow.org_login == org))
                repo_ids = select(RepoRow.id).where(RepoRow.org_login == org)
                session.execute(delete(WorkflowRow).where(WorkflowRow.repo_id.in_(repo_ids)))
                session.execute(delete(RunnerRow).where(RunnerRow.org_login == org))
                session.execute(delete(RepoRow).where(RepoRow.org_login == org))
                session.execute(delete(OrgRow).where(OrgRow.login == org))
                session.execute(delete(FetchMetaRow).where(FetchMetaRow.key.startswith(org)))
            session.commit()
