"""Parse GitHub Actions workflow YAML into typed models, plus helpers for rules."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import yaml
from pydantic import BaseModel, Field

EXPRESSION_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}", re.DOTALL)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Event contexts an outside contributor controls. Interpolating any of these
# into a shell script enables command injection.
UNTRUSTED_CONTEXT_RES = [
    re.compile(p)
    for p in (
        r"\bgithub\.event\.issue\.title\b",
        r"\bgithub\.event\.issue\.body\b",
        r"\bgithub\.event\.pull_request\.title\b",
        r"\bgithub\.event\.pull_request\.body\b",
        r"\bgithub\.event\.pull_request\.head\.ref\b",
        r"\bgithub\.event\.pull_request\.head\.label\b",
        r"\bgithub\.event\.pull_request\.head\.repo\.default_branch\b",
        r"\bgithub\.event\.comment\.body\b",
        r"\bgithub\.event\.review\.body\b",
        r"\bgithub\.event\.review_comment\.body\b",
        r"\bgithub\.event\.discussion\.title\b",
        r"\bgithub\.event\.discussion\.body\b",
        r"\bgithub\.event\.commits\b",
        r"\bgithub\.event\.head_commit\.message\b",
        r"\bgithub\.event\.head_commit\.author\.(name|email)\b",
        r"\bgithub\.event\.workflow_run\.head_branch\b",
        r"\bgithub\.event\.workflow_run\.head_commit\.message\b",
        r"\bgithub\.head_ref\b",
    )
]


class ParsedStep(BaseModel):
    index: int
    name: str | None = None
    uses: str | None = None
    run: str | None = None
    with_: dict[str, Any] = Field(default_factory=dict)
    env: dict[str, Any] = Field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.uses or f"step[{self.index}]"


class ParsedJob(BaseModel):
    id: str
    runs_on: list[str] = Field(default_factory=list)
    permissions: dict[str, Any] | str | None = None
    uses: str | None = None  # reusable workflow call
    environment: str | None = None
    if_expr: str | None = None
    steps: list[ParsedStep] = Field(default_factory=list)


class ParsedWorkflow(BaseModel):
    path: str
    name: str | None = None
    triggers: dict[str, Any] = Field(default_factory=dict)
    permissions: dict[str, Any] | str | None = None
    jobs: list[ParsedJob] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    def has_trigger(self, *names: str) -> bool:
        return any(n in self.triggers for n in names)


def _normalize_triggers(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        return {value: {}}
    if isinstance(value, list):
        return {str(v): {} for v in value}
    if isinstance(value, dict):
        return {str(k): (v if v is not None else {}) for k, v in value.items()}
    return {}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_runs_on(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, dict):  # {group: ..., labels: [...]}
        labels = value.get("labels", [])
        result = [str(v) for v in (labels if isinstance(labels, list) else [labels])]
        if "group" in value:
            result.append(f"group:{value['group']}")
        return result
    return [str(value)]


def parse_workflow(content: str, path: str) -> ParsedWorkflow | None:
    """Parse workflow YAML. Returns None when the file is not valid workflow YAML."""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None

    # YAML 1.1 parses the bare key `on:` as boolean True.
    triggers_raw = doc.get("on", doc.get(True))

    jobs: list[ParsedJob] = []
    for job_id, job_raw in _as_dict(doc.get("jobs")).items():
        job_dict = _as_dict(job_raw)
        steps: list[ParsedStep] = []
        raw_steps = job_dict.get("steps")
        if isinstance(raw_steps, list):
            for i, step_raw in enumerate(raw_steps):
                step_dict = _as_dict(step_raw)
                run_val = step_dict.get("run")
                steps.append(
                    ParsedStep(
                        index=i,
                        name=step_dict.get("name"),
                        uses=step_dict.get("uses"),
                        run=str(run_val) if run_val is not None else None,
                        with_=_as_dict(step_dict.get("with")),
                        env=_as_dict(step_dict.get("env")),
                    )
                )
        jobs.append(
            ParsedJob(
                id=str(job_id),
                runs_on=_normalize_runs_on(job_dict.get("runs-on")),
                permissions=job_dict.get("permissions"),
                uses=job_dict.get("uses"),
                environment=job_dict.get("environment")
                if isinstance(job_dict.get("environment"), str)
                else _as_dict(job_dict.get("environment")).get("name"),
                if_expr=str(job_dict["if"]) if "if" in job_dict else None,
                steps=steps,
            )
        )

    return ParsedWorkflow(
        path=path,
        name=doc.get("name") if isinstance(doc.get("name"), str) else None,
        triggers=_normalize_triggers(triggers_raw),
        permissions=doc.get("permissions"),
        jobs=jobs,
        raw={str(k): v for k, v in doc.items()},
    )


def iter_expressions(text: str) -> Iterator[str]:
    """Yield the inner expression of every ``${{ ... }}`` in *text*."""
    for match in EXPRESSION_RE.finditer(text):
        yield match.group(1)


def find_untrusted_expressions(text: str) -> list[str]:
    """Return expressions in *text* that reference attacker-controllable context."""
    hits = []
    for expr in iter_expressions(text):
        if any(regex.search(expr) for regex in UNTRUSTED_CONTEXT_RES):
            hits.append(expr)
    return hits


def split_uses(uses: str) -> tuple[str, str | None]:
    """Split a ``uses:`` value into (action path, ref). Ref is None when unpinned."""
    if "@" in uses:
        action, _, ref = uses.rpartition("@")
        return action, ref
    return uses, None


def is_sha_pinned(uses: str) -> bool:
    _, ref = split_uses(uses)
    return ref is not None and bool(SHA_RE.match(ref))


def action_owner(uses: str) -> str | None:
    """Owner of a ``uses:`` target; None for local (./) or docker:// references."""
    if uses.startswith("./") or uses.startswith("docker://"):
        return None
    action, _ = split_uses(uses)
    parts = action.split("/")
    return parts[0] if len(parts) >= 2 else None


def is_local_or_trusted(uses: str, org: str, trusted_owners: list[str]) -> bool:
    if uses.startswith("./"):
        return True
    owner = action_owner(uses)
    if owner is None:
        return False  # docker:// or malformed: not trusted
    trusted = {org.lower(), *(o.lower() for o in trusted_owners)}
    return owner.lower() in trusted


def is_write_permissions(permissions: dict[str, Any] | str | None) -> bool:
    """True when a permissions value grants any write access."""
    if permissions is None:
        return False
    if isinstance(permissions, str):
        return permissions == "write-all"
    return any(v in ("write", "write-all") for v in permissions.values())
