"""SQLAlchemy 2.0 declarative models for the local cache.

Hybrid storage: columns used for filtering/sorting are real columns; the full
Pydantic model dump is stored in a JSON ``data`` column for lossless round-trips.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from github_auditor.models import JSONDict

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    type_annotation_map = {
        JSONDict: JSON,
        datetime: DateTime(timezone=True),
    }


class OrgRow(Base):
    __tablename__ = "orgs"

    login: Mapped[str] = mapped_column(primary_key=True)
    data: Mapped[JSONDict] = mapped_column(JSON)
    fetched_at: Mapped[datetime]


class RepoRow(Base):
    __tablename__ = "repos"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)  # GitHub repo id
    org_login: Mapped[str] = mapped_column(index=True)
    full_name: Mapped[str] = mapped_column(unique=True, index=True)
    visibility: Mapped[str]
    archived: Mapped[bool]
    pushed_at: Mapped[datetime | None]
    data: Mapped[JSONDict] = mapped_column(JSON)
    fetched_at: Mapped[datetime]

    workflows: Mapped[list[WorkflowRow]] = relationship(
        back_populates="repo", cascade="all, delete-orphan"
    )


class WorkflowRow(Base):
    __tablename__ = "workflows"
    __table_args__ = (UniqueConstraint("repo_id", "path"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repos.id", ondelete="CASCADE"), index=True)
    path: Mapped[str]
    name: Mapped[str | None]
    state: Mapped[str | None]
    content: Mapped[str | None]
    source: Mapped[str] = mapped_column(default="api")
    fetched_at: Mapped[datetime]

    repo: Mapped[RepoRow] = relationship(back_populates="workflows")


class RunnerRow(Base):
    __tablename__ = "runners"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    org_login: Mapped[str] = mapped_column(index=True)
    level: Mapped[str]  # org / repo
    repo_full_name: Mapped[str | None] = mapped_column(index=True)
    data: Mapped[JSONDict] = mapped_column(JSON)
    fetched_at: Mapped[datetime]


class AuditRunRow(Base):
    __tablename__ = "audit_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    org_login: Mapped[str] = mapped_column(index=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    repo_count: Mapped[int] = mapped_column(default=0)
    finding_count: Mapped[int] = mapped_column(default=0)

    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("audit_runs.id", ondelete="CASCADE"), index=True)
    repo_full_name: Mapped[str] = mapped_column(index=True)
    rule_id: Mapped[str] = mapped_column(index=True)
    severity: Mapped[str] = mapped_column(index=True)
    data: Mapped[JSONDict] = mapped_column(JSON)

    run: Mapped[AuditRunRow] = relationship(back_populates="findings")


class FetchMetaRow(Base):
    __tablename__ = "fetch_meta"

    kind: Mapped[str] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(primary_key=True)
    fetched_at: Mapped[datetime]
