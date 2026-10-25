"""lory-audit.yml: the structure it promises and the shell it carries, run against stub responses.

The general rules (pinning, permissions, harden-runner, injection, documented inputs, the egress canary) are held
for every reusable workflow in test_workflows.py and test_egress_canary.py. This file holds what only this workflow
owes: the token reaches one step and never a command line, the response is never copied anywhere, and every way
the call can go wrong fails the job. The
two scripts are extracted from the YAML and run as shipped; `curl` is a stub on PATH, so nothing reaches the network.
"""

from __future__ import annotations

import json
import os
import re
import shutil
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


def test_findings_are_never_copied_into_github():
    """Findings stay in the vendor portal: no artifact, upload, scrubber, visibility lookup or GitHub token."""
    text = WORKFLOW.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "upload-artifact" not in code and "actions/cache" not in code
    assert "upload-response" not in code and "retention-days" not in code
    assert "gh api" not in code and "GH_TOKEN" not in code and "github.token" not in code
    assert [n for n in STEPS if "Keep" in str(n) or "Look up" in str(n)] == []
    assert "upload-response" not in CALL["inputs"]
    assert [s for s in JOB["steps"] if "upload" in str(s.get("uses", ""))] == []


def test_there_is_no_checkout_and_the_steps_are_the_expected_ones():
    uses = [str(s.get("uses", "")) for s in JOB["steps"] if "uses" in s]
    assert not [u for u in uses if u.startswith("actions/checkout@")], "nothing here needs the tree"
    assert [s.get("name") for s in JOB["steps"] if "name" in s] == [
        "Validate the egress policy inputs (EX-0001)",
        "Egress canary (EX-0001)",
        "Call the Lory pipeline scan API",
        "Judge the Lory response",
    ]
    assert uses == ["step-security/harden-runner@dc2769abcc0fcfbadfc1df54081c1608579ef6b2"]


def test_no_input_can_add_an_endpoint_or_change_where_the_job_may_connect():
    """A caller must not be able to widen the egress allow-list of a job that holds a vendor token."""
    assert sorted(CALL["inputs"]) == [
        "egress-policy",
        "fail-on-findings",
        "max-response-bytes",
        "request-timeout-seconds",
        "timeout-minutes",
    ]
    harden = next(s for s in JOB["steps"] if str(s.get("uses", "")).startswith("step-security/harden-runner@"))
    allowed = harden["with"]["allowed-endpoints"]
    assert "${{" not in allowed, "the allow-list is a literal"
    entries = allowed.split(" ")
    assert entries == sorted(entries) and "lorikeetsecurity.com:443" in entries
    assert all(re.fullmatch(r"[a-z0-9.-]+:\d+", e) for e in entries)
    assert set(entries) == {
        "api.github.com:443",
        "github.com:443",
        "lorikeetsecurity.com:443",
        "results-receiver.actions.githubusercontent.com:443",
    }
    assert JOB["steps"][2]["name"] == "Egress canary (EX-0001)"
    egress = CALL["inputs"]["egress-policy"]
    assert egress["type"] == "string" and egress["default"] == "audit"


def test_the_call_is_bounded_and_does_not_follow_redirects():
    body = CALL_STEP["run"]
    command = re.search(r"curl --disable.*?\"\$LORY_API_URL\"", body, re.S)[0]
    for flag in ("--fail-with-body", "--max-time", "--max-filesize", "--proto '=https'", "--header @-"):
        assert flag in command, flag
    assert not re.search(r"(^|\s)(-L|--location)(\s|$)", command)
    assert not re.search(r"--(proxy|insecure|cacert|netrc|config)\b|(^|\s)(-k|-K|-x)(\s|$)", command)
    assert "Authorization: Bearer %s" in body and "set -u -o pipefail" in body
    assert body.count("curl --disable") == 1


# --- the call step, run against a stub curl --------------------------------------------------------------------

STUB = """#!/usr/bin/env bash
# a stand-in for curl: records its argument vector and header-from-stdin, then replies as told
printf '%s\\n' "$@" >"$STUB_DIR/argv"
env | grep -iE '^(http_proxy|https_proxy|all_proxy|curl_home)=' >"$STUB_DIR/env" || true
{ echo "== curl"; env; } >>"$STUB_DIR/children-env"
cat >"$STUB_DIR/stdin"
if [ -f "$STUB_DIR/body" ]; then cat "$STUB_DIR/body"; fi
# --write-out '\\n%{http_code}': a real curl appends the status after the body, also on an HTTP error
if [ -n "${STUB_STATUS+set}" ]; then printf '\\n%s' "$STUB_STATUS"; fi
exit "${STUB_RC:-0}"
"""


def script(step: dict) -> str:
    return textwrap.dedent(step["run"])


# Every external command the call step may run is wrapped: it records its environment, then runs the real one.
WRAPPED = ["python3", "mktemp", "head", "tail", "wc", "tr", "rm", "stat", "mkdir", "cat", "chmod"]
WRAPPER = """#!/usr/bin/env bash
{ echo "== NAME"; env; } >>"$STUB_DIR/children-env"
exec REAL "$@"
"""


def run_call(tmp_path: Path, body: bytes | None, rc: int = 0, status: str | None = "200", **env):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "curl"
    stub.write_text(STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    for name in WRAPPED:
        wrapper = bindir / name
        wrapper.write_text(WRAPPER.replace("NAME", name).replace("REAL", shutil.which(name) or name))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    stubdir = tmp_path / "stub"
    stubdir.mkdir(exist_ok=True)
    if body is not None:
        (stubdir / "body").write_bytes(body)
    summary = tmp_path / "summary.md"
    summary.write_text("")
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir(exist_ok=True)
    github_output = tmp_path / "github-output"
    github_output.write_text("")
    full = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "STUB_DIR": str(stubdir),
        "STUB_RC": str(rc),
        **({"STUB_STATUS": status} if status is not None else {}),
        "GITHUB_STEP_SUMMARY": str(summary),
        "LORY_PIPELINE_TOKEN": TOKEN,
        "LORY_API_URL": URL,
        "LORY_BRANCH": "main; $(touch pwned) `id`",
        "LORY_COMMIT_SHA": "0" * 40,
        "LORY_PR_NUMBER": "0",
        "LORY_MAX_TIME": "60",
        "LORY_MAX_BYTES": "1024",
        "LORY_TMP": str(runner_temp),
        "GITHUB_OUTPUT": str(github_output),
        **{k: str(v) for k, v in env.items()},
    }
    done = subprocess.run(
        ["bash", "-c", script(CALL_STEP)], capture_output=True, text=True, timeout=60, env=full, cwd=tmp_path
    )
    handed = re.search(r"^dir=(.*)$", github_output.read_text(), re.M)
    saved = Path(handed[1]) / "response.json" if handed else tmp_path / "no-output" / "response.json"
    return done, summary.read_text(), saved, stubdir


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
    assert [p.name for p in saved.parent.iterdir()] == ["response.json"], "no temp files are left behind"


def test_the_response_lives_in_a_private_unique_directory_and_is_handed_over_by_step_output(tmp_path):
    done, _, saved, _ = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0, done.stdout + done.stderr
    rt = tmp_path / "rt"
    (directory,) = list(rt.iterdir())
    assert re.fullmatch(r"lory\.[A-Za-z0-9]{6}", directory.name), "an unpredictable mktemp name, never a fixed one"
    assert saved.parent == directory
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert CALL_STEP["id"] == "call"
    assert JUDGE_STEP["env"]["LORY_DIR"] == "${{ steps.call.outputs.dir }}"
    assert JUDGE_STEP["env"]["LORY_TMP"] == "${{ runner.temp }}"
    assert "mktemp -d" in CALL_STEP["run"] and "umask 077" in CALL_STEP["run"]


def test_a_symlink_at_the_old_fixed_path_is_not_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    rt = tmp_path / "rt"
    rt.mkdir()
    (rt / "lory").symlink_to(victim)
    done, _, saved, _ = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0, done.stdout + done.stderr
    assert list(victim.iterdir()) == [], "nothing may be written through the planted link"
    assert saved.parent != victim and not saved.parent.is_symlink()
    assert (rt / "lory").is_symlink(), "and the link itself is left alone"


def test_a_planted_directory_with_the_same_prefix_is_never_reused(tmp_path):
    rt = tmp_path / "rt"
    rt.mkdir()
    planted = rt / "lory.AAAAAA"
    planted.mkdir()
    done, _, saved, _ = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0
    assert saved.parent != planted and list(planted.iterdir()) == []


def test_the_token_is_in_the_environment_of_no_child_process(tmp_path):
    """The step copies the token into a shell variable and unsets the exported one before it runs any program."""
    done, _, _, stubdir = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0, done.stdout + done.stderr
    recorded = (stubdir / "children-env").read_text()
    names = set(re.findall(r"^== (\S+)$", recorded, re.M))
    assert {"curl", "python3", "mktemp", "head", "wc", "tail"} <= names, names
    assert "LORY_PIPELINE_TOKEN" not in recorded and TOKEN not in recorded
    # ... while the request still carries it, on curl's standard input only.
    assert (stubdir / "stdin").read_text() == f"Authorization: Bearer {TOKEN}\n"
    assert TOKEN not in (stubdir / "argv").read_text()
    script_text = CALL_STEP["run"]
    assert script_text.index("unset LORY_PIPELINE_TOKEN") < script_text.index("python3")
    assert script_text.index("unset LORY_PIPELINE_TOKEN") < script_text.index("mktemp")
    assert script_text.index("unset LORY_PIPELINE_TOKEN") < script_text.index("curl --disable")


def test_curl_ignores_the_users_config_proxies_and_curl_home(tmp_path):
    done, _, _, stubdir = run_call(
        tmp_path,
        b'{"exit_code": 0}',
        http_proxy="http://evil.invalid:3128",
        HTTPS_PROXY="http://evil.invalid:3128",
        all_proxy="socks5://evil.invalid",
        ALL_PROXY="socks5://evil.invalid",
        HTTP_PROXY="http://evil.invalid:3128",
        https_proxy="http://evil.invalid:3128",
        CURL_HOME=str(tmp_path),
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert (stubdir / "env").read_text() == "", "no proxy variable and no CURL_HOME may reach curl"


def test_disable_is_the_first_curl_option(tmp_path):
    """`--disable` must be first or a curlrc could still re-enable redirects, tracing or a proxy."""
    done, _, _, stubdir = run_call(tmp_path, b'{"exit_code": 0}')
    assert done.returncode == 0
    argv = (stubdir / "argv").read_text().splitlines()
    assert argv[0] == "--disable"
    assert argv.count("--disable") == 1
    for flag in ("--write-out", "--fail-with-body", "--max-time"):
        assert flag in argv


def test_the_response_body_is_never_printed(tmp_path):
    marker = "SENSITIVE-FINDING-TEXT"
    done, summary, _, _ = run_call(tmp_path, json.dumps({"exit_code": 3, "finding": marker}).encode())
    assert done.returncode == 0
    assert marker not in done.stdout + done.stderr + summary
    done, summary, _, _ = run_call(tmp_path, json.dumps({"finding": marker}).encode() + b"x" * 5000)
    assert done.returncode == 1 and marker not in done.stdout + done.stderr + summary


@pytest.mark.parametrize(
    "case,body,rc,env,fragment",
    [
        ("http 500", b'{"error": "nope"}', 22, {"status": "500"}, "HTTP status 500"),
        ("http 401", b'{"error": "nope"}', 22, {"status": "401"}, "HTTP status 401"),
        ("timeout", None, 28, {"status": "000"}, "curl exit 28"),
        ("redirect with a valid body", b'{"exit_code": 0}', 0, {"status": "302"}, "HTTP status 302"),
        ("permanent redirect", b'{"exit_code": 0}', 0, {"status": "308"}, "HTTP status 308"),
        ("no content", b"", 0, {"status": "204"}, "HTTP status 204"),
        ("created", b'{"exit_code": 0}', 0, {"status": "201"}, "HTTP status 201"),
        ("missing status", b'{"exit_code": 0}', 0, {"status": None}, "no HTTP status"),
        ("garbage status", b'{"exit_code": 0}', 0, {"status": "2OO"}, "no HTTP status"),
        ("status with a suffix", b'{"exit_code": 0}', 0, {"status": "2000"}, "no HTTP status"),
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
    done, summary, saved, _ = run_call(tmp_path, body, rc, **env)
    assert done.returncode == 1, f"{case}: {done.stdout}{done.stderr}"
    assert fragment in done.stdout and fragment in summary, case
    assert not saved.exists(), f"{case}: a failed call must leave no response file for anything to read"
    assert list((tmp_path / "rt").iterdir()) == [], f"{case}: the private directory must be gone"
    assert TOKEN not in done.stdout + done.stderr + summary


def test_only_exactly_200_passes(tmp_path):
    for status in ("200",):
        done, *_ = run_call(tmp_path, b'{"exit_code": 0}', status=status)
        assert done.returncode == 0, done.stdout + done.stderr
    for status in ("100", "199", "201", "204", "206", "301", "302", "303", "307", "400", "404", "429", "500", "503"):
        done, *_ = run_call(tmp_path, b'{"exit_code": 0}', status=status)
        assert done.returncode == 1, status


def test_a_body_that_ends_in_a_digit_line_is_not_mistaken_for_the_status(tmp_path):
    done, _, saved, _ = run_call(tmp_path, b'{"exit_code": 0}\n404', status="200")
    assert done.returncode == 0 and saved.read_bytes() == b'{"exit_code": 0}\n404'
    done, *_ = run_call(tmp_path, b'{"exit_code": 0}\n200', status="500")
    assert done.returncode == 1


def test_a_body_exactly_at_the_cap_is_accepted(tmp_path):
    body = b'{"exit_code": 0, "pad": "' + b"x" * 100 + b'"}'
    done, *_ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body))
    assert done.returncode == 0, done.stdout + done.stderr
    done, *_ = run_call(tmp_path, body, LORY_MAX_BYTES=len(body) - 1)
    assert done.returncode == 1


# --- the judge step -----------------------------------------------------------------------------------------------


def run_judge(tmp_path: Path, content: bytes | None, fail_on: str, cap: int = 1024, directory: Path | None = None):
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir(exist_ok=True)
    out_dir = directory or runner_temp / "lory.judge1"
    out_dir.mkdir(mode=0o700, exist_ok=True)
    if content is not None:
        (out_dir / "response.json").write_bytes(content)
    summary = tmp_path / "judge-summary.md"
    summary.write_text("")
    env = {
        **os.environ,
        "GITHUB_STEP_SUMMARY": str(summary),
        "LORY_DIR": str(out_dir),
        "LORY_TMP": str(runner_temp),
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


@pytest.mark.parametrize("body", [b'{"exit_code": 0}', b'{"exit_code": 3}', b"not json"])
@pytest.mark.parametrize("mode", ["true", "false"])
def test_the_judge_deletes_the_whole_directory_whatever_it_decides(tmp_path, body, mode):
    run_judge(tmp_path, body, mode)
    assert list((tmp_path / "rt").iterdir()) == []


def test_the_judge_deletes_the_directory_when_the_response_is_missing_too(tmp_path):
    run_judge(tmp_path, None, "false")
    assert list((tmp_path / "rt").iterdir()) == []


def test_the_judge_refuses_a_directory_it_was_not_given_by_the_call_step(tmp_path):
    """A path outside RUNNER_TEMP/lory.XXXXXX, a symlink or an empty value: fail, and delete nothing."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("keep")
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    link = runner_temp / "lory.link00"
    link.symlink_to(outside)
    for case, value in (
        ("outside", str(outside)),
        ("symlink", str(link)),
        ("empty", ""),
        ("parent", str(runner_temp)),
        ("dotdot", f"{runner_temp}/lory.xxxxxx/../../outside"),
        ("nested", f"{runner_temp}/lory.abcdef/sub"),
    ):
        env = {
            **os.environ,
            "GITHUB_STEP_SUMMARY": str(tmp_path / "s.md"),
            "LORY_DIR": value,
            "LORY_TMP": str(runner_temp),
            "LORY_MAX_BYTES": "1024",
            "FAIL_ON_FINDINGS": "false",
        }
        done = subprocess.run(
            ["bash", "-c", script(JUDGE_STEP)], capture_output=True, text=True, timeout=60, env=env, cwd=tmp_path
        )
        assert done.returncode == 1, f"{case}: {done.stdout}{done.stderr}"
        assert "::error" in done.stdout, case
        assert (outside / "precious").read_text() == "keep", f"{case}: the judge deleted something it must not"


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
    assert "vendor portal" in EXAMPLE.read_text().lower()
    assert "upload" not in EXAMPLE.read_text().lower()
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
        "vendor portal",
        "not copied into github",
    ):
        assert needle in text, f"docs/wiki/Workflow-lory-audit.md does not say {needle!r}"
    for gone in ("upload-response", "artifact", "retention"):
        assert gone not in text.replace("no artifact", "").replace("never uploads", ""), f"stale mention of {gone!r}"
