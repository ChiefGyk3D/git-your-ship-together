"""dast.yml: the contract a caller relies on, and its steps run for real.

The steps are lifted out of the workflow and executed under bash the way the
job runs them, with `${{ inputs.x }}` resolved from the declared defaults and
the caller's values, so what is asserted is what the job does and not what its
YAML looks like. Three layers:

* the contract: inputs, permissions per job, the image pinned by digest, no
  caller value interpolated into a script;
* the steps against canned reports (tests/fixtures/dast/*.json are the real
  output of zap-baseline.py 2.17.0 against fixture/dast/server.py, with and
  without its headers): the fail-on threshold, the SARIF, the refusals;
* the live scans, with the real ZAP image against the fixture server, which are
  the proof that the job can go red. They need docker (or a podman that answers
  to it), pull a 1.5 GB image and take two minutes, so they run when DAST_LIVE
  is set, in ci.yml's `dast-live` job; set and without a usable docker they
  FAIL rather than skip, because a skip would hide the one check that matters.
  Locally: DAST_LIVE=1 pytest tests/test_dast.py -k live

Each assertion was broken on purpose once (the threshold inverted, the loopback
check removed, the fixture's headers added to the insecure mode) to confirm it
goes red with a message naming the fix.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_workflows import README, REPO, WORKFLOWS, jobs, load, steps_of, triggers

WORKFLOW = WORKFLOWS / "dast.yml"
FIXTURES = REPO / "tests" / "fixtures" / "dast"
SERVER = REPO / "fixture" / "dast" / "server.py"
IMAGE = re.compile(r"^ghcr\.io/zaproxy/zaproxy:(\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}$")

INPUTS = {
    "target-url": "http://127.0.0.1:8080",
    "ready-path": "/",
    "ready-timeout-seconds": 60,
    "rules-file": "",
    "fail-on": "high",
    "spider-minutes": 1,
    "python-version": "",
    "install-command": "",
    "upload-sarif": True,
    "artifact-name": "zap-reports",
}


def declared() -> dict:
    return triggers(load(WORKFLOW))["workflow_call"]["inputs"]


def step(job: str, fragment: str) -> dict:
    for candidate in steps_of(jobs(load(WORKFLOW))[job]):
        if fragment in str(candidate.get("name", "")):
            return candidate
    raise AssertionError(f"dast.yml job {job!r} has no step named like {fragment!r}")


# --- the contract -----------------------------------------------------------


def test_it_is_callable_and_takes_the_documented_inputs():
    assert "workflow_call" in triggers(load(WORKFLOW))
    for name, default in INPUTS.items():
        assert name in declared(), f"input {name!r} is missing"
        assert declared()[name]["default"] == default, f"{name} default is {declared()[name]['default']!r}"
    start = declared()["start-command"]
    assert start["required"] is True and "default" not in start


def test_every_input_is_in_the_readme_table():
    readme = README.read_text()
    section = readme[readme.index("Inputs of `dast.yml`") :]
    for name in declared():
        assert f"| `{name}` |" in section, f"README's dast.yml table does not list `{name}`"


def test_the_zap_image_is_pinned_by_digest_and_the_tag_is_the_one_documented():
    image = jobs(load(WORKFLOW))["scan"]["env"]["ZAP_IMAGE"]
    match = IMAGE.match(image)
    assert match, f"ZAP_IMAGE {image!r} must be ghcr.io/zaproxy/zaproxy:<x.y.z>@sha256:<digest>, never a moving tag"
    assert f"zaproxy {match[1]}" in WORKFLOW.read_text(), "the comment above ZAP_IMAGE must name the pinned version"


def test_the_job_that_runs_the_callers_service_holds_nothing_but_read():
    scan = jobs(load(WORKFLOW))["scan"]
    assert scan["permissions"] == {"contents": "read"}, "the caller's service runs here; no write, no OIDC token"
    assert "secrets" not in triggers(load(WORKFLOW))["workflow_call"]


def test_the_upload_job_holds_the_one_write_and_runs_none_of_the_callers_code():
    upload = jobs(load(WORKFLOW))["upload"]
    assert upload["permissions"] == {"contents": "read", "security-events": "write"}
    names = [str(s.get("uses", "")) for s in steps_of(upload)]
    assert not any(n.startswith("actions/checkout@") for n in names), "the write must not sit beside a checkout"
    assert not any(s.get("run") for s in steps_of(upload)), "the upload job runs no shell at all"
    sarif = steps_of(upload)[-1]
    assert sarif["uses"].startswith("github/codeql-action/upload-sarif@")
    assert sarif["with"]["category"] == "zap", "the SARIF category is part of the contract"
    cond = str(upload["if"])
    assert "inputs.upload-sarif" in cond and "head.repo.full_name == github.repository" in cond, (
        "a fork's pull request has a read-only token; the upload must be skipped there"
    )
    assert upload["needs"] == "scan"


def test_zap_runs_without_a_token_and_makes_no_unsolicited_requests():
    run = str(step("scan", "Run the ZAP baseline scan")["run"])
    assert '-z "-silent"' in run, "without -silent ZAP calls cfu.zaproxy.org and tel.zaproxy.org"
    assert "GITHUB_TOKEN" not in run and "github.token" not in WORKFLOW.read_text()
    assert "--network host" in run and '"$ZAP_IMAGE"' in run


def test_caller_values_never_reach_the_shell_by_template_expansion():
    for job in jobs(load(WORKFLOW)).values():
        for s in steps_of(job):
            assert "${{" not in str(s.get("run", "")), f"step {s.get('name')!r} expands a template into the script"


# --- running the steps ------------------------------------------------------


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Job:
    """The scan job's steps, run one at a time under bash in a scratch runner temp."""

    def __init__(self, tmp_path: Path, **inputs: object):
        self.tmp = tmp_path
        self.temp = tmp_path / "runner-temp"
        self.temp.mkdir(exist_ok=True)
        self.output = tmp_path / "github-output"
        self.output.touch()
        self.summary = tmp_path / "summary.md"
        self.inputs = {name: spec["default"] for name, spec in declared().items() if "default" in spec}
        self.inputs.update({k.replace("_", "-"): v for k, v in inputs.items()})
        self.groups: list[int] = []

    def resolve(self, template: str) -> str:
        def one(match: re.Match) -> str:
            kind, _, name = match[1].strip().partition(".")
            if kind == "inputs":
                value = self.inputs[name]
                return str(value).lower() if isinstance(value, bool) else str(value)
            if match[1].strip() == "runner.temp":
                return str(self.temp)
            if match[1].strip() == "steps.zap.outputs.exit":
                found = re.findall(r"^exit=(.*)$", self.output.read_text(), re.M)
                return found[-1] if found else ""
            raise AssertionError(f"the test cannot resolve ${{{{ {match[1].strip()} }}}}")

        return re.sub(r"\$\{\{(.*?)\}\}", one, str(template))

    def run(self, fragment: str, timeout: int = 300, job: str = "scan", **extra_env: str):
        spec = step(job, fragment)
        env = {
            **os.environ,
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "ZAP_IMAGE": jobs(load(WORKFLOW))[job]["env"]["ZAP_IMAGE"],
            **{k: self.resolve(v) for k, v in (spec.get("env") or {}).items()},
            **extra_env,
        }
        proc = subprocess.Popen(
            ["bash", "-c", str(spec["run"])],
            cwd=self.tmp,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,  # the service the step starts is left running; one group to end it
        )
        self.groups.append(proc.pid)
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop()
            raise
        return proc.returncode, out

    def stop(self) -> None:
        for group in self.groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.fixture
def job(tmp_path):
    made: list[Job] = []

    def make(**inputs: object) -> Job:
        made.append(Job(tmp_path, **inputs))
        return made[-1]

    yield make
    for j in made:
        j.stop()


def server_command(port: int, *flags: str) -> str:
    return f'"{sys.executable}" "{SERVER}" --port {port} {" ".join(flags)}'


# The input check ------------------------------------------------------------


@pytest.mark.parametrize(
    ("inputs", "message"),
    [
        ({"target_url": "https://example.com"}, "not a loopback"),
        ({"target_url": "http://127.0.0.1.evil.example:8080"}, "not a loopback"),
        ({"target_url": "http://localhost@evil.example:8080"}, "not a loopback"),
        ({"target_url": "http://10.0.0.5:8080"}, "not a loopback"),
        ({"ready_path": "health"}, "must start with /"),
        ({"fail_on": "critical"}, "not one of high, medium"),
        ({"fail_on": ""}, "not one of high, medium"),
        ({"spider_minutes": "1;id"}, "not a whole number"),
        ({"rules_file": "no/such/rules.tsv"}, "not a file"),
    ],
)
def test_a_bad_input_is_refused_before_anything_starts_and_the_message_names_the_fix(job, inputs, message):
    code, out = job(**inputs).run("Check the inputs")
    assert code != 0, f"{inputs} was accepted"
    assert message in out, out


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8080", "http://localhost:3000/", "http://[::1]:8080", "http://127.0.0.1"]
)
@pytest.mark.parametrize("fail_on", ["high", "medium", "low", "informational", "none"])
def test_loopback_urls_and_every_documented_fail_on_are_accepted(job, url, fail_on):
    code, out = job(target_url=url, fail_on=fail_on).run("Check the inputs")
    assert code == 0, out


# Starting the service -------------------------------------------------------


def start(job, command: str, port: int, **extra):
    j = job(start_command=command, target_url=f"http://127.0.0.1:{port}", **extra)
    code, out = j.run("Start the service and wait for it", timeout=60)
    return j, code, out


def test_a_service_that_blocks_is_started_in_the_background_and_waited_for(job):
    port = free_port()
    _, code, out = start(job, server_command(port), port)
    assert code == 0 and "The service answered" in out, out


def test_a_command_that_starts_the_service_itself_and_returns_is_waited_for_too(job):
    port = free_port()
    _, code, out = start(job, server_command(port) + " &", port)
    assert code == 0 and "The service answered" in out, out


def test_a_service_that_dies_fails_at_once_with_the_tail_of_its_output(job):
    port = free_port()
    _, code, out = start(job, "echo 'boom: cannot bind'; exit 3", port, ready_timeout_seconds=30)
    assert code != 0
    assert "exited 3" in out and "boom: cannot bind" in out, out


def test_a_service_that_never_answers_fails_after_the_timeout_and_says_where(job):
    port = free_port()
    _, code, out = start(job, "sleep 30", port, ready_timeout_seconds=2)
    assert code != 0
    assert f"nothing answered at http://127.0.0.1:{port}/ within 2s" in out, out


def test_the_ready_path_is_what_is_requested(job):
    port = free_port()
    _, code, out = start(job, server_command(port), port, ready_path="/about")
    assert code == 0 and f"http://127.0.0.1:{port}/about" in out, out
    _, code, out = start(job, server_command(free_port()), port, ready_path="/missing", ready_timeout_seconds=2)
    assert code != 0, "a 404 on the ready path must not count as ready"


# The report and the threshold ----------------------------------------------


def report(job, canned: str, fail_on: str, zap_exit: str = "0"):
    j = job(fail_on=fail_on)
    zap = j.temp / "zap"
    zap.mkdir()
    shutil.copy(FIXTURES / canned, zap / "report.json")
    j.output.write_text(f"exit={zap_exit}\n")
    code, out = j.run("Report and apply fail-on")
    return j, code, out, zap


@pytest.mark.parametrize(
    ("fail_on", "fails"),
    [("high", False), ("medium", True), ("low", True), ("informational", True), ("none", False)],
)
def test_a_page_without_headers_fails_at_medium_and_below_and_passes_at_high(job, fail_on, fails):
    """The falsifiability of the threshold: the insecure fixture's worst alerts are Medium."""
    _, code, out, _ = report(job, "insecure.json", fail_on)
    assert (code != 0) == fails, f"fail-on {fail_on}: exit {code}\n{out}"
    if fails:
        assert "Content Security Policy (CSP) Header Not Set" in out and "::error::" in out, out


@pytest.mark.parametrize("fail_on", ["high", "medium", "low", "informational", "none"])
def test_a_clean_report_passes_at_every_threshold(job, fail_on):
    _, code, out, _ = report(job, "clean.json", fail_on)
    assert code == 0, out


def test_a_rule_set_to_fail_in_the_rules_file_fails_whatever_fail_on_says(job):
    _, code, out, _ = report(job, "clean.json", "none", zap_exit="1")
    assert code != 0 and "rule set to FAIL" in out, out


def test_the_summary_names_each_alert_and_marks_the_ones_that_fail(job):
    j, _, _, _ = report(job, "insecure.json", "medium")
    summary = j.summary.read_text()
    assert "| Medium (fails) | Content Security Policy (CSP) Header Not Set |" in summary, summary
    assert "| Low | X-Content-Type-Options Header Missing |" in summary, summary


def test_the_sarif_is_valid_enough_for_code_scanning(job):
    j, _, _, zap = report(job, "insecure.json", "none")
    sarif = json.loads((zap / "zap.sarif").read_text())
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "OWASP ZAP" and run["tool"]["driver"]["version"] == "2.17.0"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert run["results"], "an insecure page must produce results"
    levels = set()
    for result in run["results"]:
        assert result["ruleId"] in rules
        levels.add(result["level"])
        assert result["message"]["text"] and result["partialFingerprints"]["zapAlert/v1"]
        for location in result["locations"]:
            physical = location["physicalLocation"]
            assert physical["artifactLocation"]["uri"].startswith("http://127.0.0.1:")
            assert physical["region"]["startLine"] == 1
    assert levels == {"warning", "note"}, "Medium is a warning, Low and Informational are notes"
    csp = rules["10038"]
    assert csp["properties"]["security-severity"] == "5.5" and "external/cwe/cwe-693" in csp["properties"]["tags"]
    assert csp["shortDescription"]["text"].startswith("Content Security Policy")
    assert "<p>" not in csp["fullDescription"]["text"], "ZAP's markup must be stripped"
    assert re.search(r"^sarif=true$", j.output.read_text(), re.M)


def test_a_clean_report_still_writes_a_sarif_so_fixed_findings_close(job):
    """Code scanning closes an alert when the next upload for the category no longer has it."""
    _, code, _, zap = report(job, "clean.json", "high")
    assert code == 0
    sarif = json.loads((zap / "zap.sarif").read_text())
    assert sarif["runs"][0]["results"] == []


# --- the live scans: the real ZAP image, against the fixture server ---------

LIVE = os.environ.get("DAST_LIVE")
live = pytest.mark.skipif(not LIVE, reason="set DAST_LIVE=1 to run the real ZAP image (ci.yml's dast-live job does)")


def docker_usable() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan(job, *server_flags: str, fail_on: str):
    assert docker_usable(), "DAST_LIVE is set and docker is not usable: this job exists to run the real image"
    port = free_port()
    j = job(start_command=server_command(port, *server_flags), target_url=f"http://127.0.0.1:{port}", fail_on=fail_on)
    for fragment in ("Check the inputs", "Start the service and wait for it", "Run the ZAP baseline scan"):
        code, out = j.run(fragment, timeout=420)
        assert code == 0, f"{fragment}:\n{out}"
    return j


@live
def test_live_a_page_with_its_headers_passes_at_low(job):
    j = scan(job, fail_on="low")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, out
    sarif = json.loads((j.temp / "zap" / "zap.sarif").read_text())
    assert [r for r in sarif["runs"][0]["results"] if r["level"] != "note"] == []


@live
def test_live_the_same_page_without_its_headers_fails_at_medium_and_passes_at_high(job):
    j = scan(job, "--insecure", fail_on="medium")
    code, out = j.run("Report and apply fail-on")
    assert code != 0, "a page with no CSP and no anti-clickjacking header passed fail-on: medium\n" + out
    assert "Content Security Policy (CSP) Header Not Set" in out and "Missing Anti-clickjacking Header" in out, out
    j.inputs["fail-on"] = "high"
    code, out = j.run("Report and apply fail-on")
    assert code == 0, "Medium findings must not trip fail-on: high\n" + out
    sarif = json.loads((j.temp / "zap" / "zap.sarif").read_text())
    assert any(r["ruleId"] == "10038" for r in sarif["runs"][0]["results"])
