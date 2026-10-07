"""dast.yml: the contract a caller relies on, and its steps run for real.

The steps are lifted out of the workflow and executed under bash the way the
job runs them, with `${{ inputs.x }}` resolved from the declared defaults and
the caller's values, so what is asserted is what the job does and not what its
YAML looks like. Four layers:

* the contract: inputs, permissions per job, the image pinned by digest, no
  caller value interpolated into a script;
* the steps against canned reports (tests/fixtures/dast/*.json are the real
  output of zap-baseline.py 2.17.0 against fixture/dast/server.py, with and
  without its headers): the fail-on threshold, the SARIF, the refusals;
* the scan step against a fake `docker` on PATH that records its arguments and
  leaves a report: which ZAP script each `scan-type` runs and with which flags,
  since the three scripts take different ones and a wrong flag is a scan that
  silently did less than the caller asked;
* the live scans, with the real ZAP image against the fixture server, which are
  the proof that each scan type can go red for the class of hole it exists to
  find, and passes where it has nothing to find. They need docker (or a podman
  that answers to it), pull a 1.5 GB image and take minutes each, so they run
  when DAST_LIVE is set, in ci.yml's `dast-live` job; set and without a usable
  docker they FAIL rather than skip, because a skip would hide the one check
  that matters. Locally: DAST_LIVE=1 pytest tests/test_dast.py -k live

Each assertion was broken on purpose once (the threshold inverted, the loopback
check removed, the fixture's headers added to the insecure mode) to confirm it
goes red with a message naming the fix.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from test_workflows import README, REPO, WORKFLOWS, jobs, load, steps_of, triggers

WORKFLOW = WORKFLOWS / "dast.yml"
FIXTURES = REPO / "tests" / "fixtures" / "dast"
SERVER = REPO / "fixture" / "dast" / "server.py"
OPENAPI = REPO / "fixture" / "dast" / "openapi.json"
IMAGE = re.compile(r"^ghcr\.io/zaproxy/zaproxy:(\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}$")

INPUTS = {
    "target-url": "http://127.0.0.1:8080",
    "ready-path": "/",
    "ready-timeout-seconds": 60,
    "rules-file": "",
    "fail-on": "high",
    "scan-type": "baseline",
    "spider-minutes": 1,
    "ajax-spider": False,
    "active-scan-minutes": 0,
    "api-definition": "",
    "api-format": "openapi",
    "python-version": "",
    "install-command": "",
    "upload-sarif": True,
    "sarif-category": "zap",
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
    assert sarif["with"]["category"] == "${{ inputs.sarif-category }}", (
        "the category is the caller's: two scans coexist"
    )
    assert declared()["sarif-category"]["default"] == "zap", "the default category `zap` is part of the contract"
    cond = str(upload["if"])
    assert "inputs.upload-sarif" in cond and "head.repo.full_name == github.repository" in cond, (
        "a fork's pull request has a read-only token; the upload must be skipped there"
    )
    assert upload["needs"] == "scan"


def test_zap_runs_without_a_token_and_makes_no_unsolicited_requests():
    run = str(step("scan", "Run the ZAP scan")["run"])
    assert 'zap_options="-silent"' in run and '-z "$zap_options"' in run, (
        "without -silent ZAP calls cfu.zaproxy.org and tel.zaproxy.org, whatever the scan type"
    )
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
        """Run one step. REPO_ROOT in extra_env runs it from the repository, as the job does after checkout."""
        spec = step(job, fragment)
        cwd = extra_env.pop("REPO_ROOT", str(self.tmp))
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
            cwd=cwd,
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
        ({"active_scan_minutes": "5m"}, "not a whole number"),
        ({"rules_file": "no/such/rules.tsv"}, "not a file"),
        ({"scan_type": "active"}, "not one of baseline, full, api"),
        ({"scan_type": ""}, "not one of baseline, full, api"),
        ({"scan_type": "api"}, "api-definition is empty"),
        ({"scan_type": "api", "api_definition": "https://example.com/openapi.json"}, "not a loopback one"),
        ({"scan_type": "api", "api_definition": "http://127.0.0.1.evil.example/openapi.json"}, "not a loopback one"),
        ({"scan_type": "api", "api_definition": "no/such/openapi.yaml"}, "neither a loopback URL nor a file"),
        (
            {"scan_type": "api", "api_definition": "fixture/dast/openapi.json", "api_format": "wsdl"},
            "not one of openapi",
        ),
        (
            {"scan_type": "api", "api_definition": "schema.graphqls", "api_format": "graphql"},
            "loopback URL of the GraphQL",
        ),
        ({"scan_type": "baseline", "api_definition": "fixture/dast/openapi.json"}, "but scan-type is 'baseline'"),
        ({"scan_type": "full", "api_definition": "http://127.0.0.1:8080/openapi.json"}, "but scan-type is 'full'"),
    ],
)
def test_a_bad_input_is_refused_before_anything_starts_and_the_message_names_the_fix(job, inputs, message):
    code, out = job(**inputs).run("Check the inputs", REPO_ROOT=str(REPO))
    assert code != 0, f"{inputs} was accepted"
    assert message in out, out


@pytest.mark.parametrize(
    "inputs",
    [
        {"scan_type": "full"},
        {"scan_type": "full", "ajax_spider": True, "active_scan_minutes": 10},
        {"scan_type": "api", "api_definition": "fixture/dast/openapi.json"},
        {"scan_type": "api", "api_definition": "http://127.0.0.1:8080/openapi.json"},
        {"scan_type": "api", "api_definition": "http://localhost:8080/soap?wsdl", "api_format": "soap"},
        {"scan_type": "api", "api_definition": "http://[::1]:8080/graphql", "api_format": "graphql"},
    ],
)
def test_every_scan_type_with_its_own_inputs_is_accepted(job, inputs):
    code, out = job(**inputs).run("Check the inputs", REPO_ROOT=str(REPO))
    assert code == 0, out


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


# The scan step: which script, which flags -----------------------------------

FAKE_DOCKER = """#!/usr/bin/env bash
# Stands in for docker: records every argument and leaves the report the next step reads.
set -euo pipefail
printf '%s\\n' "$@" > "$RECORD"
for arg in "$@"; do
  case "$arg" in *:/zap/wrk:rw) wrk="${arg%%:/zap/wrk:rw}" ;; esac
done
cp "$CANNED" "$wrk/report.json"
exit "${FAKE_EXIT:-0}"
"""


def scan_step(job, tmp_path, **inputs):
    """Run the scan step with a fake docker first on PATH; returns (exit code, output, docker's arguments)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    record = tmp_path / "docker-args"
    j = job(**inputs)
    code, out = j.run(
        "Run the ZAP scan",
        REPO_ROOT=str(REPO),
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        RECORD=str(record),
        CANNED=str(FIXTURES / "clean.json"),
    )
    args = record.read_text().splitlines() if record.exists() else []
    return j, code, out, args


def after_image(args: list[str]) -> list[str]:
    image = jobs(load(WORKFLOW))["scan"]["env"]["ZAP_IMAGE"]
    assert image in args, f"docker was not given the pinned image: {args}"
    return args[args.index(image) + 1 :]


def flag(args: list[str], name: str) -> str:
    assert name in args, f"{name} is missing from {args}"
    return args[args.index(name) + 1]


def test_the_default_scan_is_the_baseline_with_the_flags_it_always_had(job, tmp_path):
    j, code, out, args = scan_step(job, tmp_path)
    assert code == 0, out
    assert args[:3] == ["run", "--rm", "--network"] and args[3] == "host"
    cmd = after_image(args)
    assert cmd[0] == "zap-baseline.py"
    assert flag(cmd, "-t") == "http://127.0.0.1:8080" and flag(cmd, "-m") == "1"
    assert flag(cmd, "-J") == "report.json" and flag(cmd, "-r") == "report.html" and flag(cmd, "-w") == "report.md"
    assert "-I" in cmd and flag(cmd, "-z") == "-silent"
    assert "-j" not in cmd and "-f" not in cmd and "-O" not in cmd and "-c" not in cmd
    assert re.search(r"^exit=0$", j.output.read_text(), re.M)


def test_the_full_scan_runs_the_full_script_with_the_spider_bound_and_no_active_limit_by_default(job, tmp_path):
    _, code, out, args = scan_step(job, tmp_path, scan_type="full", spider_minutes=3)
    assert code == 0, out
    cmd = after_image(args)
    assert cmd[0] == "zap-full-scan.py"
    assert flag(cmd, "-t") == "http://127.0.0.1:8080" and flag(cmd, "-m") == "3"
    assert flag(cmd, "-z") == "-silent", "active-scan-minutes 0 is ZAP's own no-limit; nothing to pass"
    assert "-j" not in cmd


def test_the_ajax_spider_and_the_active_scan_limit_become_zaps_flags(job, tmp_path):
    _, code, out, args = scan_step(job, tmp_path, scan_type="full", ajax_spider=True, active_scan_minutes=7)
    assert code == 0, out
    cmd = after_image(args)
    assert "-j" in cmd and "--ajax-spider" in cmd, "-j alone picks ZAP's client spider; the input promises the AJAX one"
    assert flag(cmd, "-z") == "-silent -config scanner.maxScanDurationInMins=7"
    _, code, out, args = scan_step(job, tmp_path, scan_type="baseline", ajax_spider=True, active_scan_minutes=7)
    assert code == 0, out
    cmd = after_image(args)
    assert cmd[0] == "zap-baseline.py" and "-j" in cmd
    assert flag(cmd, "-z") == "-silent", "the baseline has no active scan; its limit must not be passed"


def test_the_api_scan_copies_a_repository_definition_in_and_overrides_its_servers_with_the_target(job, tmp_path):
    j, code, out, args = scan_step(
        job, tmp_path, scan_type="api", api_definition="fixture/dast/openapi.json", target_url="http://127.0.0.1:9090"
    )
    assert code == 0, out
    cmd = after_image(args)
    assert cmd[0] == "zap-api-scan.py"
    assert flag(cmd, "-t") == "definition.json", "a file is read from the mounted directory, keeping its extension"
    copied = j.temp / "zap" / "definition.json"
    assert copied.read_bytes() == OPENAPI.read_bytes()
    assert flag(cmd, "-f") == "openapi"
    assert flag(cmd, "-O") == "http://127.0.0.1:9090", (
        "the definition names another host; -O sends the scan to loopback"
    )
    assert "-m" not in cmd and "-j" not in cmd, "the api scan has no spider"
    assert "-I" in cmd and flag(cmd, "-z") == "-silent"


def test_the_api_scan_takes_a_loopback_url_as_the_definition_and_passes_soap_and_graphql_through(job, tmp_path):
    _, code, out, args = scan_step(job, tmp_path, scan_type="api", api_definition="http://127.0.0.1:8080/openapi.json")
    assert code == 0, out
    cmd = after_image(args)
    assert flag(cmd, "-t") == "http://127.0.0.1:8080/openapi.json" and flag(cmd, "-O") == "http://127.0.0.1:8080"
    for fmt, definition in (
        ("soap", "http://127.0.0.1:8080/service?wsdl"),
        ("graphql", "http://127.0.0.1:8080/graphql"),
    ):
        _, code, out, args = scan_step(job, tmp_path, scan_type="api", api_definition=definition, api_format=fmt)
        assert code == 0, out
        cmd = after_image(args)
        assert flag(cmd, "-t") == definition and flag(cmd, "-f") == fmt
        assert "-O" not in cmd, f"-O is the OpenAPI importer's; {fmt} takes the definition's own addresses"


def test_the_rules_file_rides_along_for_every_scan_type(job, tmp_path):
    rules = tmp_path / "rules.tsv"
    rules.write_text("10038\tIGNORE\tCSP is set by the proxy in front of this service\n")
    for scan_type, extra in (("baseline", {}), ("full", {}), ("api", {"api_definition": "fixture/dast/openapi.json"})):
        j, code, out, args = scan_step(job, tmp_path, scan_type=scan_type, rules_file=str(rules), **extra)
        assert code == 0, out
        assert flag(after_image(args), "-c") == "rules.tsv"
        assert (j.temp / "zap" / "rules.tsv").read_text() == rules.read_text()


def test_a_scan_that_leaves_no_report_fails_the_step_naming_the_script(job, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text("#!/usr/bin/env bash\nexit 3\n")
    (bin_dir / "docker").chmod(0o755)
    j = job(scan_type="full")
    code, out = j.run("Run the ZAP scan", REPO_ROOT=str(REPO), PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    assert code != 0
    assert "zap-full-scan.py exited 3 and left no report" in out, out


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
    assert "### ZAP baseline scan" in summary, summary
    assert "| Medium (fails) | Content Security Policy (CSP) Header Not Set |" in summary, summary
    assert "| Low | X-Content-Type-Options Header Missing |" in summary, summary


def test_the_summary_and_the_sarif_say_which_scan_type_ran(job):
    j = job(fail_on="none", scan_type="full")
    zap = j.temp / "zap"
    zap.mkdir()
    shutil.copy(FIXTURES / "insecure.json", zap / "report.json")
    j.output.write_text("exit=0\n")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, out
    assert "### ZAP full scan" in j.summary.read_text()
    sarif = json.loads((zap / "zap.sarif").read_text())
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        assert "zap-full" in rule["properties"]["tags"], (
            "the Security tab must tell a full scan's alert from a baseline's"
        )


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
    assert "zap-baseline" in csp["properties"]["tags"]
    assert csp["shortDescription"]["text"].startswith("Content Security Policy")
    assert "<p>" not in csp["fullDescription"]["text"], "ZAP's markup must be stripped"
    assert re.search(r"^sarif=true$", j.output.read_text(), re.M)


def test_a_clean_report_still_writes_a_sarif_so_fixed_findings_close(job):
    """Code scanning closes an alert when the next upload for the category no longer has it."""
    _, code, _, zap = report(job, "clean.json", "high")
    assert code == 0
    sarif = json.loads((zap / "zap.sarif").read_text())
    assert sarif["runs"][0]["results"] == []


# --- the fixture itself -----------------------------------------------------


def test_the_committed_openapi_definition_is_what_the_fixture_server_serves():
    """fixture/dast/openapi.json is the repository-file form of the definition; the server is the URL form."""
    spec = importlib.util.spec_from_file_location("dast_fixture_server", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert json.loads(OPENAPI.read_text()) == module.OPENAPI, "regenerate fixture/dast/openapi.json from server.OPENAPI"
    assert module.OPENAPI["servers"][0]["url"].endswith(".invalid"), (
        "the definition must name a host that does not exist, so a scan that reaches anything proves the -O override"
    )
    for path in module.OPENAPI["paths"]:
        assert path.startswith("/api/")


def test_the_fixture_escapes_what_it_echoes_unless_told_not_to():
    """The hole the full scan exists to find is opt-in, and the secure mode has the same surface."""
    port = free_port()
    for flags, expected in (((), "&lt;b&gt;x"), (("--vulnerable",), "<b>x")):
        proc = subprocess.Popen([sys.executable, str(SERVER), "--port", str(port), *flags])
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/search?q=%3Cb%3Ex", timeout=1) as resp:
                        body = resp.read().decode()
                        headers = dict(resp.headers)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("the fixture server never answered")
            assert expected in body, body
            assert "Content-Security-Policy" in headers, (
                "--vulnerable keeps the headers; the hole is the only difference"
            )
        finally:
            proc.kill()
            proc.wait()


# --- the live scans: the real ZAP image, against the fixture server ---------

LIVE = os.environ.get("DAST_LIVE")
live = pytest.mark.skipif(not LIVE, reason="set DAST_LIVE=1 to run the real ZAP image (ci.yml's dast-live job does)")


def docker_usable() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan(job, *server_flags: str, fail_on: str, **inputs: object):
    assert docker_usable(), "DAST_LIVE is set and docker is not usable: this job exists to run the real image"
    port = free_port()
    j = job(
        start_command=server_command(port, *server_flags),
        target_url=f"http://127.0.0.1:{port}",
        fail_on=fail_on,
        **inputs,
    )
    for fragment in ("Check the inputs", "Start the service and wait for it", "Run the ZAP scan"):
        code, out = j.run(fragment, timeout=1500, REPO_ROOT=str(REPO))
        assert code == 0, f"{fragment}:\n{out}"
    return j


def alerts_in(j) -> dict[str, str]:
    sarif = json.loads((j.temp / "zap" / "zap.sarif").read_text())
    return {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}


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


XSS = "40012"  # Cross Site Scripting (Reflected), an active rule: High


# Why the full scan exists: the same page passes the baseline at medium and
# fails the full scan at high. Two tests, one page, two scan types.


@live
def test_live_baseline_passes_the_vulnerable_page_because_nothing_in_its_headers_is_wrong(job):
    j = scan(job, "--vulnerable", fail_on="medium")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, "the baseline is passive; a hole in what the server does with input is not its to find\n" + out
    assert XSS not in alerts_in(j)


@live
def test_live_the_full_scan_fails_the_vulnerable_page_at_high_naming_the_xss(job):
    j = scan(job, "--vulnerable", fail_on="high", scan_type="full")
    code, out = j.run("Report and apply fail-on")
    assert code != 0, "a page that reflects its query unescaped passed the full scan at fail-on: high\n" + out
    assert "Cross Site Scripting (Reflected)" in out, out
    assert alerts_in(j)[XSS] == "error"
    assert "### ZAP full scan" in j.summary.read_text()


@live
def test_live_the_full_scan_passes_the_same_page_when_it_escapes_at_medium(job):
    j = scan(job, fail_on="medium", scan_type="full")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, "the full scan found a Medium or worse on the fixture that escapes its output\n" + out
    assert XSS not in alerts_in(j)


@live
def test_live_the_api_scan_imports_the_repository_definition_and_scans_the_loopback_service(job):
    """The definition names https://fixture.invalid; the scan can only find URLs if -O redirected it to loopback."""
    j = scan(job, fail_on="medium", scan_type="api", api_definition="fixture/dast/openapi.json")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, out
    report = json.loads((j.temp / "zap" / "report.json").read_text())
    sites = [site["@name"] for site in report.get("site", [])]
    assert sites and all(s.startswith("http://127.0.0.1:") for s in sites), sites
    assert "### ZAP api scan" in j.summary.read_text()
