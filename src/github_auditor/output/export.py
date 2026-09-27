"""Machine-readable exports (JSON / CSV)."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence

from github_auditor.analyze.diff import RunDiff
from github_auditor.cache.store import AuditRunSummary, TrendRow
from github_auditor.models import AuditReport, Finding

CSV_FIELDS = [
    "rule_id",
    "rule_name",
    "severity",
    "repo",
    "title",
    "location",
    "evidence",
    "remediation",
]


def report_to_json(report: AuditReport) -> str:
    payload = report.model_dump(mode="json")
    for repo_report, model in zip(payload["repos"], report.repos, strict=True):
        repo_report["risk_score"] = model.risk_score
        repo_report["grade"] = model.grade
    payload["severity_totals"] = report.severity_totals()
    import json

    return json.dumps(payload, indent=2)


def findings_to_json(findings: list[Finding]) -> str:
    import json

    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)


def diff_to_json(
    org: str, baseline: AuditRunSummary, current: AuditRunSummary, diff: RunDiff
) -> str:
    """Two runs' comparison as JSON: what is new, what is resolved, how scores moved."""
    import json

    def run_payload(run: AuditRunSummary) -> dict[str, str | int | None]:
        return {
            "id": run.id,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        }

    return json.dumps(
        {
            "org": org,
            "baseline_run": run_payload(baseline),
            "current_run": run_payload(current),
            "new_findings": [f.model_dump(mode="json") for f in diff.new_findings],
            "resolved_findings": [f.model_dump(mode="json") for f in diff.resolved_findings],
            "scope_deltas": [
                {
                    "scope": d.scope,
                    "baseline_score": d.baseline_score,
                    "current_score": d.current_score,
                    "delta": d.delta,
                }
                for d in diff.scope_deltas
            ],
            "baseline_total": diff.baseline_total,
            "current_total": diff.current_total,
            "total_delta": diff.total_delta,
        },
        indent=2,
    )


def trends_to_json(rows: Sequence[TrendRow]) -> str:
    """The trend rows as a JSON array, oldest run first, delta null on the first."""
    import json

    return json.dumps(
        [
            {
                "id": row.id,
                "started_at": row.started_at.isoformat(),
                "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                "repo_count": row.repo_count,
                "finding_count": row.finding_count,
                "risk_score": row.risk_score,
                "delta": row.delta,
            }
            for row in rows
        ],
        indent=2,
    )


def findings_to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = f.model_dump(mode="json")
        row["severity"] = f.severity.value
        writer.writerow(row)
    return buf.getvalue()
