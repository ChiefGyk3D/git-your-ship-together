"""lory-audit.yml: the structure it promises and the shell it carries, run against stub responses.

The general rules (pinning, permissions, harden-runner, injection, documented inputs, the egress canary) are held
for every reusable workflow in test_workflows.py and test_egress_canary.py. This file holds what only this workflow
owes: the token reaches one step and never a command line, and every way the call can go wrong fails the job. The
two scripts are extracted from the YAML and run as shipped; `curl` is a stub on PATH, so nothing reaches the network.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "lory-audit.yml"
EXAMPLE = REPO / "examples" / "lory-audit-caller.yml"
PAGE = REPO / "docs" / "wiki" / "Workflow-lory-audit.md"
DOC = yaml.safe_load(WORKFLOW.read_text())
CALL = (DOC.get("on") or DOC.get(True))["workflow_call"]
JOB = DOC["jobs"]["audit"]
STEPS = {s.get("name"): s for s in JOB["steps"]}
CALL_STEP = STEPS["Call the Lory pipeline scan API"]
JUDGE_STEP = STEPS["Judge the Lory response"]
TOKEN = "lory-test-token-0123456789"  # a made-up value, not a credential
URL = "https://lorikeetsecurity.com/talon/api/v1/pipeline/scan"


# --- structure -------------------------------------------------------------------------------------------------


def test_it_is_callable_only_and_reads_contents_only():
    assert list((DOC.get("on") or DOC.get(True)).keys()) == ["workflow_call"]
    assert DOC["permissions"] == {"contents": "read"}
    assert JOB["permissions"] == {"contents": "read"}
    assert list(DOC["jobs"]) == ["audit"]


def test_the_secret_is_required_and_the_input_is_advisory_by_default():
    assert CALL["secrets"]["LORY_PIPELINE_TOKEN"]["required"] is True
    assert list(CALL["secrets"]) == ["LORY_PIPELINE_TOKEN"]
    assert CALL["inputs"]["fail-on-findings"]["default"] is False
    assert CALL["inputs"]["fail-on-findings"]["type"] == "boolean"


def test_no_input_can_redirect_the_token():
    """The URL is fixed. An input for it would let a caller (or a bug) send the bearer token anywhere."""
    assert not [n for n in CALL["inputs"] if "url" in n or "host" in n or "depth" in n]
    assert CALL_STEP["env"]["LORY_API_URL"] == URL


def test_the_token_is_in_exactly_one_step_and_only_through_env():
    text = WORKFLOW.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert code.count("secrets.LORY_PIPELINE_TOKEN") == 1
    assert CALL_STEP["env"]["LORY_PIPELINE_TOKEN"] == "${{ secrets.LORY_PIPELINE_TOKEN }}"
    for name, step in STEPS.items():
        if name == CALL_STEP["name"]:
            continue
        assert "LORY_PIPELINE_TOKEN" not in yaml.safe_dump(step), f"{name} can see the token"
    assert "secrets" not in {k for k in JOB if k != "steps"}


def test_no_run_script_contains_a_template_expression_at_all():
    runs = [s["run"] for s in JOB["steps"] if "run" in s]
    assert len(runs) >= 4
    for body in runs:
        assert "${{" not in body


def test_there_is_no_checkout_and_the_artifact_step_is_pinned():
    uses = [str(s.get("uses", "")) for s in JOB["steps"] if "uses" in s]
    assert not [u for u in uses if u.startswith("actions/checkout@")], "nothing here needs the tree"
    upload = STEPS["Keep the response"]
    assert re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", upload["uses"])
    assert upload["if"] == "${{ always() }}"
    assert upload["with"]["path"] == "${{ runner.temp }}/lory/response.json"


def test_the_call_is_bounded_and_does_not_follow_redirects():
    body = CALL_STEP["run"]
    for flag in ("--fail-with-body", "--max-time", "--max-filesize", "--proto '=https'", "--header @-"):
        assert flag in body, flag
    assert not re.search(r"(^|\s)(-L|--location)(\s|$)", body)
    assert "Authorization: Bearer %s" in body and "set -u -o pipefail" in body


# --- the call step, run against a stub curl --------------------------------------------------------------------

STUB = """#!/usr/bin/env bash
# a stand-in for curl: records its argument vector and header-from-stdin, then replies as told
printf '%s\\n' "$@" >"$STUB_DIR/argv"
cat >"$STUB_DIR/stdin"
if [ -f "$STUB_DIR/body" ]; then cat "$STUB_DIR/body"; fi
exit "${STUB_RC:-0}"
"""


def script(step: dict) -> str:
    return textwrap.dedent(step["run"])


def run_call(tmp_path: Path, body: bytes | None, rc: int = 0, **env):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "curl"
    stub.write_text(STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    stubdir = tmp_path / "stub"
    stubdir.mkdir(exist_ok=True)
    if body is not None:
        (stubdir / "body").write_bytes(body)
    summary = tmp_path / "summary.md"
    summary.write_text("")
    out_dir = tmp_path / "out"
    full = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "STUB_DIR": str(stubdir),
        "STUB_RC": str(rc),
        "GITHUB_STEP_SUMMARY": str(summary),
        "LORY_PIPELINE_TOKEN": TOKEN,
        "LORY_API_URL": URL,
        "LORY_BRANCH": "main; $(touch pwned) `id`",
        "LORY_COMMIT_SHA": "0" * 40,
        "LORY_PR_NUMBER": "0",
        "LORY_MAX_TIME": "60",
        "LORY_MAX_BYTES": "1024",
        "LORY_OUT_DIR": str(out_dir),
        **{k: str(v) for k, v in env.items()},
    }
    done = subprocess.run(
        ["bash", "-c", script(CALL_STEP)], capture_output=True, text=True, timeout=60, env=full, cwd=tmp_path
    )
    return done, summary.read_text(), out_dir / "response.json", stubdir


def test_a_good_call_sends_the_documented_request_and_keeps_the_token_off_the_command_line(tmp_path):
    done, summary, saved, stubdir = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0, done.stdout + done.stderr
    argv = (stubdir / "argv").read_text().splitlines()
    assert TOKEN not in "\n".join(argv)
    assert (stubdir / "stdin").read_text() == f"Authorization: Bearer {TOKEN}\n"
    assert URL in argv and "Content-Type: application/json" in argv
    data = json.loads(argv[argv.index("--data") + 1])
    assert data == {"branch": "main; $(touch pwned) `id`", "commit_sha": "0" * 40, "pr_number": 0}
    assert not (tmp_path / "pwned").exists(), "a hostile ref name must stay data"
    assert saved.read_bytes() == b'{"exit_code": 0}'
    assert TOKEN not in done.stdout + done.stderr + summary


def test_the_token_is_scrubbed_from_the_saved_response(tmp_path):
    done, _, saved, _ = run_call(tmp_path, json.dumps({"exit_code": 0, "echo": TOKEN}).encode())
    assert done.returncode == 0
    assert TOKEN.encode() not in saved.read_bytes() and b"[redacted]" in saved.read_bytes()


@pytest.mark.parametrize(
    "case,body,rc,env,fragment",
    [
        ("http error", b'{"error": "nope"}', 22, {}, "curl exit 22"),
        ("timeout", None, 28, {}, "curl exit 28"),
        ("oversize", b"x" * 5000, 0, {}, "larger than max-response-bytes"),
        ("oversize with a curl error", b"x" * 5000, 63, {}, "larger than max-response-bytes"),
        ("bad timeout input", b"{}", 0, {"LORY_MAX_TIME": "9; reboot"}, "whole number"),
        ("bad cap input", b"{}", 0, {"LORY_MAX_BYTES": ""}, "whole number"),
        ("bad pr number", b"{}", 0, {"LORY_PR_NUMBER": "x"}, "whole number"),
        ("zero cap", b"{}", 0, {"LORY_MAX_BYTES": "0"}, "at least 1"),
        ("empty token", b"{}", 0, {"LORY_PIPELINE_TOKEN": ""}, "secret is empty"),
    ],
)
def test_every_way_the_call_can_fail_fails_the_step(tmp_path, case, body, rc, env, fragment):
    done, summary, _, _ = run_call(tmp_path, body, rc, **env)
    assert done.returncode == 1, f"{case}: {done.stdout}{done.stderr}"
    assert fragment in done.stdout and fragment in summary, case
    assert TOKEN not in done.stdout + done.stderr + summary


def test_a_body_exactly_at_the_cap_is_accepted(tmp_path):
    body = b'{"exit_code": 0, "pad": "' + b"x" * 100 + b'"}'
    done, *_ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body))
    assert done.returncode == 0, done.stdout + done.stderr
    done, *_ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body) - 1)
    assert done.returncode == 1


# --- the judge step -----------------------------------------------------------------------------------------------


def run_judge(tmp_path: Path, content: bytes | None, fail_on: str, cap: int = 1024):
    out_dir = tmp_path / "judge"
    out_dir.mkdir(exist_ok=True)
    if content is not None:
        (out_dir / "response.json").write_bytes(content)
    summary = tmp_path / "judge-summary.md"
    summary.write_text("")
    env = {
        **os.environ,
        "GITHUB_STEP_SUMMARY": str(summary),
        "LORY_OUT_DIR": str(out_dir),
        "LORY_MAX_BYTES": str(cap),
        "FAIL_ON_FINDINGS": fail_on,
    }
    done = subprocess.run(
        ["bash", "-c", script(JUDGE_STEP)], capture_output=True, text=True, timeout=60, env=env, cwd=tmp_path
    )
    return done, summary.read_text()


MALFORMED = [
    ("not json", b"<html>502</html>"),
    ("empty", b""),
    ("json array", b"[0]"),
    ("json null", b"null"),
    ("missing exit_code", b'{"status": "ok"}'),
    ("string exit_code", b'{"exit_code": "0"}'),
    ("float exit_code", b'{"exit_code": 0.0}'),
    ("bool exit_code", b'{"exit_code": false}'),
    ("null exit_code", b'{"exit_code": null}'),
    ("duplicate exit_code", b'{"exit_code": 1, "exit_code": 0}'),
    ("nan", b'{"exit_code": NaN}'),
    ("invalid utf-8", b'{"exit_code": 0, "x": "\xff"}'),
    ("oversize", b'{"exit_code": 0, "pad": "' + b"x" * 2000 + b'"}'),
]


@pytest.mark.parametrize("mode", ["true", "false"])
@pytest.mark.parametrize("case,body", MALFORMED, ids=[c for c, _ in MALFORMED])
def test_a_malformed_response_fails_even_in_advisory_mode(tmp_path, case, body, mode):
    done, summary = run_judge(tmp_path, body, mode)
    assert done.returncode == 1, f"{case}: {done.stdout}{done.stderr}"
    assert "FAILED" in summary and "::error" in done.stdout


def test_a_missing_response_file_fails(tmp_path):
    done, summary = run_judge(tmp_path, None, "false")
    assert done.returncode == 1 and "never a pass" in summary


def test_a_clean_result_passes_in_both_modes(tmp_path):
    for mode in ("true", "false"):
        done, summary = run_judge(tmp_path, b'{"exit_code": 0, "extra": {"anything": [1]}}', mode)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "exit_code 0, pass" in summary


def test_findings_are_advisory_by_default_and_blocking_on_request(tmp_path):
    done, summary = run_judge(tmp_path, b'{"exit_code": 2}', "false")
    assert done.returncode == 0
    assert "::warning" in done.stdout and "exit_code 2" in summary and "advisory" in summary
    done, summary = run_judge(tmp_path, b'{"exit_code": 2}', "true")
    assert done.returncode == 1
    assert "fail-on-findings is true" in summary
    done, _ = run_judge(tmp_path, b'{"exit_code": -1}', "true")
    assert done.returncode == 1


def test_an_unrecognized_mode_value_is_advisory_only_for_findings_never_for_malformed_output(tmp_path):
    """FAIL_ON_FINDINGS comes from a boolean input; anything that is not `true` is advisory for findings only."""
    done, _ = run_judge(tmp_path, b'{"exit_code": 1}', "yes")
    assert done.returncode == 0
    done, _ = run_judge(tmp_path, b"nope", "yes")
    assert done.returncode == 1


def test_the_table_bites(tmp_path, monkeypatch):
    """Falsifiability: with the integer check removed from a copy of the judge, the malformed cases pass."""
    text = JUDGE_STEP["run"]
    mutated = text.replace(
        'if "exit_code" not in doc or isinstance(code, bool) or not isinstance(code, int):', "if False:"
    )
    assert mutated != text
    monkeypatch.setitem(JUDGE_STEP, "run", mutated)
    done, _ = run_judge(tmp_path, b'{"status": "ok"}', "false")
    assert done.returncode == 0, "the mutant should have let a missing exit_code through"


# --- the caller template and the docs ---------------------------------------------------------------------------


def test_the_caller_template_is_scheduled_and_on_demand_never_per_pull_request():
    doc = yaml.safe_load(EXAMPLE.read_text())
    triggers = doc.get("on") or doc.get(True)
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert re.fullmatch(r"\d+ \d+ \d+ \* \*", triggers["schedule"][0]["cron"]), "monthly: a fixed day of the month"
    assert doc["permissions"] == {"contents": "read"}
    (job,) = doc["jobs"].values()
    assert re.search(
        r"uses: ChiefGyk3D/git-your-ship-together/\.github/workflows/lory-audit\.yml@<sha> # vX\.Y\.Z",
        EXAMPLE.read_text(),
    ), "the template pins by commit with a version comment, like every GYST caller"
    assert job["permissions"] == {"contents": "read"}
    assert job["secrets"] == {"LORY_PIPELINE_TOKEN": "${{ secrets.LORY_PIPELINE_TOKEN }}"}
    assert "with" not in job, "the template is advisory by default; blocking is a commented-out choice"


def test_the_page_states_the_limits():
    text = PAGE.read_text().lower()
    for needle in (
        "scheduled and on-demand",
        "not a per-pull-request gate",
        "spike",
        "rate limit",
        "third-party model output",
        "never instructions",
        "fails closed",
        ".lory/config.yml",
    ):
        assert needle in text, f"docs/wiki/Workflow-lory-audit.md does not say {needle!r}"
