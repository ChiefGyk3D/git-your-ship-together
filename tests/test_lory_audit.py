"""lory-audit.yml: the structure it promises and the shell it carries, run against stub responses.

The general rules (pinning, permissions, harden-runner, injection, documented inputs, the egress canary) are held
for every reusable workflow in test_workflows.py and test_egress_canary.py. This file holds what only this workflow
owes: the token reaches one step and never a command line, and every way the call can go wrong fails the job. The
two scripts are extracted from the YAML and run as shipped; `curl` is a stub on PATH, so nothing reaches the network.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import textwrap
import urllib.parse
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
TOKEN = 'lory/te+st=tok"en\\ 0123&456789'  # a made-up value with awkward characters, not a credential
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
    assert upload["with"]["path"] == "${{ runner.temp }}/lory/response.json"


def test_the_raw_response_is_uploaded_only_on_request_from_a_private_repository_for_three_days():
    """Findings are sensitive: an artifact is readable by anyone who can read the repository's artifacts."""
    assert CALL["inputs"]["upload-response"]["default"] is False
    assert CALL["inputs"]["upload-response"]["type"] == "boolean"
    upload = STEPS["Keep the response"]
    condition = upload["if"]
    assert "inputs.upload-response" in condition
    assert "github.event.repository.visibility == 'private'" in condition
    assert "steps.visibility.outputs.private == 'true'" in condition, "the live API lookup must gate the upload"
    assert int(upload["with"]["retention-days"]) <= 3
    assert upload["with"]["if-no-files-found"] == "ignore"
    assert CALL_STEP["env"]["LORY_REPO_VISIBILITY"] == "${{ github.event.repository.visibility }}"
    assert "github.event.repository.private" not in WORKFLOW.read_text(), "the boolean is not what we trust"
    names = [s.get("name") for s in JOB["steps"]]
    assert names.index("Look up the repository visibility now") == names.index("Keep the response") - 1, (
        "the lookup must come immediately before the upload"
    )
    assert CALL_STEP["env"]["LORY_UPLOAD"] == "${{ inputs.upload-response }}"
    assert len([s for s in JOB["steps"] if "upload-artifact" in str(s.get("uses", ""))]) == 1


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
        "LORY_UPLOAD": "false",
        "LORY_REPO_VISIBILITY": "private",
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


def token_part(token: str, offset: int) -> bytes:
    """The base64 characters of `token` that do not depend on its neighbours, when it starts at byte `offset` mod 3."""
    enc = base64.b64encode(b"\0" * offset + token.encode()).rstrip(b"=")
    total = offset + len(token.encode())
    return enc[(offset * 8 + 5) // 6 : len(enc) - (1 if total % 3 else 0)]


PLAIN_FORMS = {
    "raw": lambda t: t,
    "json-escaped": lambda t: json.dumps(t)[1:-1],
    "json-slash-escaped": lambda t: json.dumps(t)[1:-1].replace("/", "\\/"),
    "url-quote": lambda t: urllib.parse.quote(t, safe=""),
    "url-quote-plus": lambda t: urllib.parse.quote_plus(t),
    "url-quote-keeping-slash": lambda t: urllib.parse.quote(t),
    "bearer-header": lambda t: "Bearer " + t,
}


def body_with(text: str) -> bytes:
    # Inserted verbatim: the forms under test are already what a server would have written inside a JSON string.
    return ('{"exit_code": 0, "echo": "' + text + '"}').encode()


def assert_clean(kept: bytes, form: str):
    for name, make in PLAIN_FORMS.items():
        assert make(TOKEN).encode() not in kept, f"{form}: {name} form survived in the saved response"
    for offset in range(3):
        assert token_part(TOKEN, offset) not in kept, f"{form}: base64 (offset {offset}) survived"
        urlsafe = token_part(TOKEN, offset).replace(b"+", b"-").replace(b"/", b"_")
        assert urlsafe not in kept, f"{form}: urlsafe base64 (offset {offset}) survived"


@pytest.mark.parametrize("form", list(PLAIN_FORMS))
def test_the_token_is_scrubbed_from_the_saved_response_in_every_plain_form(tmp_path, form):
    body = body_with("before " + PLAIN_FORMS[form](TOKEN) + " after")
    done, _, saved, _ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body) + 64)
    assert done.returncode == 0, done.stdout + done.stderr
    kept = saved.read_bytes()
    assert b"[redacted]" in kept, form
    assert_clean(kept, form)
    assert TOKEN not in done.stdout + done.stderr


@pytest.mark.parametrize("urlsafe", [False, True], ids=["base64", "base64url"])
@pytest.mark.parametrize("offset", [0, 1, 2])
def test_the_token_is_scrubbed_from_the_saved_response_when_base64_encoded_at_any_alignment(tmp_path, offset, urlsafe):
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    text = encode(b"x" * (30 + offset) + TOKEN.encode() + b"yz").decode()
    assert token_part(TOKEN, offset).replace(b"+", b"-").replace(b"/", b"_") in text.encode() or (
        token_part(TOKEN, offset) in text.encode()
    ), "test setup: this alignment is not in the encoded text"
    body = body_with(text)
    done, _, saved, _ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body) + 64)
    assert done.returncode == 0, done.stdout + done.stderr
    kept = saved.read_bytes()
    assert b"[redacted]" in kept
    assert_clean(kept, f"base64 offset {offset}")


def test_the_response_body_is_never_printed(tmp_path):
    marker = "SENSITIVE-FINDING-TEXT"
    done, summary, _, _ = run_call(tmp_path, json.dumps({"exit_code": 3, "finding": marker}).encode())
    assert done.returncode == 0
    assert marker not in done.stdout + done.stderr + summary
    done, summary, _, _ = run_call(tmp_path, json.dumps({"finding": marker}).encode() + b"x" * 5000)
    assert done.returncode == 1 and marker not in done.stdout + done.stderr + summary


@pytest.mark.parametrize("visibility", ["public", "internal", "", "maybe", "PRIVATE", "private "])
def test_uploading_is_refused_unless_the_visibility_is_exactly_private(tmp_path, visibility):
    done, summary, saved, stubdir = run_call(
        tmp_path, b'{"exit_code": 0}', LORY_UPLOAD="true", LORY_REPO_VISIBILITY=visibility
    )
    assert done.returncode == 1, done.stdout + done.stderr
    assert "upload-response" in done.stdout and "private" in summary
    assert not (stubdir / "argv").exists(), "the API must not be called when the upload is refused"
    assert not saved.exists()


def test_uploading_is_allowed_in_a_private_repository_and_a_public_one_may_run_without_it(tmp_path):
    done, *_ = run_call(tmp_path, b'{"exit_code": 0}', LORY_UPLOAD="true", LORY_REPO_VISIBILITY="private")
    assert done.returncode == 0, done.stdout + done.stderr
    done, *_ = run_call(tmp_path, b'{"exit_code": 0}', LORY_UPLOAD="false", LORY_REPO_VISIBILITY="public")
    assert done.returncode == 0, done.stdout + done.stderr


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


# --- the visibility lookup, run against a stub gh -------------------------------------------------------------

LOOKUP_STEP = STEPS["Look up the repository visibility now"]
GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" >"$STUB_DIR/gh-argv"
printf '%s' "${GH_TOKEN-}" >"$STUB_DIR/gh-token"
if [ "${STUB_RC:-0}" -ne 0 ]; then echo "gh: HTTP 500" >&2; exit "$STUB_RC"; fi
printf '%s\\n' "${STUB_VISIBILITY-}"
"""


def run_lookup(tmp_path: Path, visibility: str | None, rc: int = 0):
    bindir = tmp_path / "ghbin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "gh"
    stub.write_text(GH_STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    stubdir = tmp_path / "ghstub"
    stubdir.mkdir(exist_ok=True)
    out = tmp_path / "github-output"
    out.write_text("")
    summary = tmp_path / "lookup-summary.md"
    summary.write_text("")
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "STUB_DIR": str(stubdir),
        "STUB_RC": str(rc),
        "STUB_VISIBILITY": visibility or "",
        "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(summary),
        "GH_TOKEN": "gh-test-token",
        "LORY_REPOSITORY": "octo/widget",
    }
    done = subprocess.run(
        ["bash", "-c", script(LOOKUP_STEP)], capture_output=True, text=True, timeout=60, env=env, cwd=tmp_path
    )
    return done, out.read_text(), stubdir


def test_the_lookup_asks_the_api_with_the_job_token_and_the_repository_from_env(tmp_path):
    env = LOOKUP_STEP["env"]
    assert env == {"GH_TOKEN": "${{ github.token }}", "LORY_REPOSITORY": "${{ github.repository }}"}
    done, out, stubdir = run_lookup(tmp_path, "private")
    assert done.returncode == 0, done.stdout + done.stderr
    assert (stubdir / "gh-argv").read_text().split() == ["api", "repos/octo/widget", "--jq", ".visibility"]
    assert (stubdir / "gh-token").read_text() == "gh-test-token"
    assert out == "private=true\n"


@pytest.mark.parametrize("visibility", ["public", "internal", "", "Private", "private-ish", "null"])
def test_anything_but_exactly_private_from_the_api_fails_closed(tmp_path, visibility):
    done, out, _ = run_lookup(tmp_path, visibility)
    assert done.returncode == 1, f"{visibility!r}: {done.stdout}{done.stderr}"
    assert "private=true" not in out
    assert "::error" in done.stdout


def test_a_lookup_failure_fails_closed(tmp_path):
    done, out, _ = run_lookup(tmp_path, "private", rc=1)
    assert done.returncode == 1
    assert "private=true" not in out and "::error" in done.stdout


def test_the_api_wins_over_an_event_payload_that_says_private(tmp_path):
    """The payload may be stale (a repository made public after the event was queued); the live answer decides."""
    condition = STEPS["Keep the response"]["if"]
    assert "github.event.repository.visibility == 'private'" in condition  # the payload says private ...
    done, out, _ = run_lookup(tmp_path, "public")  # ... the API says public
    assert done.returncode == 1 and "private=true" not in out
    # With no output from the lookup, the upload condition's second clause cannot hold.
    assert "steps.visibility.outputs.private == 'true'" in condition
    assert STEPS["Look up the repository visibility now"]["id"] == "visibility"


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
        assert re.search(r"at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", summary), "the summary carries a UTC timestamp"


def test_the_judge_never_prints_the_body(tmp_path):
    marker = "SENSITIVE-FINDING-TEXT"
    for mode in ("true", "false"):
        done, summary = run_judge(tmp_path, json.dumps({"exit_code": 4, "finding": marker}).encode(), mode)
        assert marker not in done.stdout + done.stderr + summary
        done, summary = run_judge(tmp_path, ('{"exit_code": "' + marker + '"}').encode(), mode)
        assert done.returncode == 1 and marker not in done.stdout + done.stderr + summary


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
    assert "sensitive" in EXAMPLE.read_text().lower() and "upload-response" in EXAMPLE.read_text()
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
        "sensitive",
        "upload-response",
        "private",
        "three days",
    ):
        assert needle in text, f"docs/wiki/Workflow-lory-audit.md does not say {needle!r}"
