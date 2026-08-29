from github_auditor.analyze.workflow_parser import (
    find_untrusted_expressions,
    is_local_or_trusted,
    is_sha_pinned,
    is_write_permissions,
    parse_workflow,
)


def test_on_boolean_key_quirk():
    wf = parse_workflow("on: push\njobs: {}", "wf.yml")
    assert wf is not None
    assert wf.has_trigger("push")


def test_trigger_forms_normalize():
    for content, expected in [
        ("on: push\njobs: {}", {"push"}),
        ("on: [push, pull_request]\njobs: {}", {"push", "pull_request"}),
        ("on:\n  pull_request_target:\n    types: [opened]\njobs: {}", {"pull_request_target"}),
    ]:
        wf = parse_workflow(content, "wf.yml")
        assert set(wf.triggers) == expected


def test_malformed_yaml_returns_none():
    assert parse_workflow("{{unbalanced", "wf.yml") is None
    assert parse_workflow("- just\n- a list", "wf.yml") is None


def test_jobs_steps_parsed():
    wf = parse_workflow(
        """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: build
        run: make
        env: {FOO: bar}
""",
        "wf.yml",
    )
    job = wf.jobs[0]
    assert job.id == "build"
    assert job.runs_on == ["ubuntu-latest"]
    assert job.steps[0].uses == "actions/checkout@v4"
    assert job.steps[1].run == "make"
    assert job.steps[1].env == {"FOO": "bar"}


def test_runs_on_forms():
    wf = parse_workflow(
        "on: push\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps: []",
        "wf.yml",
    )
    assert wf.jobs[0].runs_on == ["self-hosted", "linux"]


def test_untrusted_expression_detection():
    hits = find_untrusted_expressions('echo "${{ github.event.issue.title }}"')
    assert hits == ["github.event.issue.title"]
    assert find_untrusted_expressions('echo "${{ github.sha }}"') == []
    assert find_untrusted_expressions("plain text") == []


def test_sha_pinning():
    assert is_sha_pinned("a/b@0123456789abcdef0123456789abcdef01234567")
    assert not is_sha_pinned("a/b@v4")
    assert not is_sha_pinned("a/b@main")
    assert not is_sha_pinned("a/b")


def test_trusted_owners():
    trusted = ["actions", "github"]
    assert is_local_or_trusted("./local", "myorg", trusted)
    assert is_local_or_trusted("actions/checkout@v4", "myorg", trusted)
    assert is_local_or_trusted("MyOrg/tool@v1", "myorg", trusted)
    assert not is_local_or_trusted("random/tool@v1", "myorg", trusted)
    assert not is_local_or_trusted("docker://alpine:3", "myorg", trusted)


def test_write_permissions_detection():
    assert is_write_permissions("write-all")
    assert is_write_permissions({"contents": "write"})
    assert not is_write_permissions({"contents": "read"})
    assert not is_write_permissions(None)
    assert not is_write_permissions("read-all")
