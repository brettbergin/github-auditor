"""Machine-readable exports (JSON / CSV)."""

from __future__ import annotations

import csv
import io

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


def findings_to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = f.model_dump(mode="json")
        row["severity"] = f.severity.value
        writer.writerow(row)
    return buf.getvalue()
