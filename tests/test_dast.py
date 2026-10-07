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

import base64
import html
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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from test_workflows import README, REPO, WORKFLOWS, jobs, load, steps_of, triggers

WORKFLOW = WORKFLOWS / "dast.yml"
FIXTURES = REPO / "tests" / "fixtures" / "dast"
SERVER = REPO / "fixture" / "dast" / "server.py"
OPENAPI = REPO / "fixture" / "dast" / "openapi.json"
CONTEXT = REPO / "fixture" / "dast" / "login.context"
CONTEXT_PATH = "fixture/dast/login.context"
CONTEXT_USER = "throwaway"
CONTEXT_PORT = 8080  # the context names the login URL with a port, so the live tests serve the fixture on it
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
    "context-file": "",
    "context-user": "",
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
        ({"context_user": "throwaway"}, "context-user 'throwaway' is set but context-file is empty"),
        ({"scan_type": "full", "context_user": "throwaway"}, "has nobody to sign in as"),
        ({"context_file": "no/such/app.context"}, "context-file 'no/such/app.context' is not a file"),
        ({"context_file": "fixture/dast", "context_user": "throwaway"}, "is not a file in the repository"),
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
        {"context_file": CONTEXT_PATH},
        {"context_file": CONTEXT_PATH, "context_user": "throwaway"},
        {"scan_type": "full", "context_file": CONTEXT_PATH, "context_user": "throwaway"},
        {
            "scan_type": "api",
            "api_definition": "fixture/dast/openapi.json",
            "context_file": CONTEXT_PATH,
            "context_user": "throwaway",
        },
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


def scan_step(job, tmp_path, between=None, **inputs):
    """Run the scan step with a fake docker first on PATH; returns (exit code, output, docker's arguments).

    With a context file the check step runs first, as in the job; `between(job)` runs after it, before the scan."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    record = tmp_path / "docker-args"
    j = job(**inputs)
    if inputs.get("context_file"):
        checked, check_out = j.run("Check the context file", REPO_ROOT=str(REPO))
        assert checked == 0, check_out
    if between:
        between(j)
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


@pytest.mark.parametrize(
    ("scan_type", "script", "extra"),
    [
        ("baseline", "zap-baseline.py", {}),
        ("full", "zap-full-scan.py", {}),
        ("api", "zap-api-scan.py", {"api_definition": "fixture/dast/openapi.json"}),
    ],
)
def test_the_context_and_the_user_become_zaps_n_and_u_for_every_scan_type(job, tmp_path, scan_type, script, extra):
    """All three packaged scripts take -n and -U (read from the pinned image's /zap/*.py), the baseline's too."""
    j, code, out, args = scan_step(
        job, tmp_path, scan_type=scan_type, context_file=CONTEXT_PATH, context_user="throwaway", **extra
    )
    assert code == 0, out
    cmd = after_image(args)
    assert cmd[0] == script
    assert flag(cmd, "-n") == "context.context", "the script reads the context from the mounted directory"
    assert flag(cmd, "-U") == "throwaway"
    assert (j.temp / "zap" / "context.context").read_bytes() == CONTEXT.read_bytes()
    assert (j.temp / "zap" / "context.context").stat().st_mode & 0o004, "the container's user is not the runner's"


def test_a_context_without_a_user_passes_only_n_and_no_context_passes_neither(job, tmp_path):
    _, code, out, args = scan_step(job, tmp_path, scan_type="full", context_file=CONTEXT_PATH)
    assert code == 0, out
    cmd = after_image(args)
    assert flag(cmd, "-n") == "context.context" and "-U" not in cmd
    _, code, out, args = scan_step(job, tmp_path, scan_type="full")
    assert code == 0, out
    cmd = after_image(args)
    assert "-n" not in cmd and "-U" not in cmd


def test_a_user_name_with_shell_characters_reaches_zap_as_one_argument(job, tmp_path):
    name = 'a b"; touch pwned; "$(id)'
    path = context_file(tmp_path, USER_ENTRY, user_entry(name, "throwaway-password"))
    _, code, out, args = scan_step(job, tmp_path, context_file=path, context_user=name)
    assert code == 0, out
    assert flag(after_image(args), "-U") == name
    assert not (tmp_path / "pwned").exists() and not (REPO / "pwned").exists()


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


def test_an_authenticated_scan_says_so_in_the_summary_and_tags_its_alerts(job):
    j = job(fail_on="none", scan_type="full", context_file=CONTEXT_PATH, context_user="throwaway")
    zap = j.temp / "zap"
    zap.mkdir()
    shutil.copy(FIXTURES / "insecure.json", zap / "report.json")
    j.output.write_text("exit=0\n")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, out
    assert "Scanned signed in as a user of `context-file`" in j.summary.read_text()
    sarif = json.loads((zap / "zap.sarif").read_text())
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        assert "zap-authenticated" in rule["properties"]["tags"]


def test_an_anonymous_scan_does_not_claim_to_be_authenticated(job):
    j, _, _, zap = report(job, "insecure.json", "none")
    assert "signed in" not in j.summary.read_text()
    sarif = json.loads((zap / "zap.sarif").read_text())
    assert all("zap-authenticated" not in r["properties"]["tags"] for r in sarif["runs"][0]["tool"]["driver"]["rules"])


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


class Fixture:
    """The fixture server in one mode, on a port, for the duration of a with block."""

    def __init__(self, port: int, *flags: str):
        self.port, self.flags = port, flags

    def __enter__(self):
        self.proc = subprocess.Popen([sys.executable, str(SERVER), "--port", str(self.port), *self.flags])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=1).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise AssertionError("the fixture server never answered")

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait()

    def get(self, path: str, cookie: str = "", data: str | None = None):
        """(status, headers, body), redirects not followed."""

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data.encode() if data is not None else None,
            headers={"Cookie": cookie} if cookie else {},
        )
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read().decode()


GOOD_LOGIN = "username=throwaway&password=throwaway-password"


def test_the_login_mode_hides_an_unescaped_echo_behind_a_form_login_and_leaves_the_public_pages_escaped():
    with Fixture(free_port(), "--login") as server:
        status, headers, _ = server.get("/account")
        assert status == 302 and headers["Location"] == "/login", "an anonymous request must be sent to the login"
        assert server.get("/account/search?q=%3Cb%3Ex")[0] == 302
        assert server.get("/login")[0] == 200
        status, headers, _ = server.get("/login", data="username=throwaway&password=wrong")
        assert status == 401 and "Set-Cookie" not in headers
        status, headers, _ = server.get("/login", data=GOOD_LOGIN)
        assert status == 302 and headers["Location"] == "/account"
        cookie = headers["Set-Cookie"].split(";")[0]
        assert "HttpOnly" in headers["Set-Cookie"]
        status, _, body = server.get("/account", cookie)
        assert status == 200 and "Signed in as throwaway" in body
        status, headers, body = server.get("/account/search?q=%3Cb%3Ex", cookie)
        assert status == 200 and "<b>x" in body, "the hole behind the login echoes q unescaped"
        assert "Content-Security-Policy" in headers
        assert server.get("/account", "fixture_session=forged")[0] == 302, "only a cookie the server issued signs in"
        _, _, body = server.get("/search?q=%3Cb%3Ex")
        assert "&lt;b&gt;x" in body, "the public page stays escaped: only a signed-in scan can find the hole"
        _, _, anonymous_home = server.get("/")
        _, _, signed_in_home = server.get("/", cookie)
        assert "/account" not in anonymous_home and "/account" in signed_in_home
        assert "/login" in anonymous_home


def test_the_login_routes_do_not_exist_without_the_login_flag():
    with Fixture(free_port()) as server:
        for path in ("/login", "/account", "/account/search?q=x"):
            assert server.get(path)[0] == 404, path
        assert server.get("/login", data=GOOD_LOGIN)[0] == 404


def test_the_shipped_context_file_matches_the_fixtures_login():
    """fixture/dast/login.context is what the live tests hand ZAP; it must describe this server's login."""
    import base64
    import xml.etree.ElementTree as ET

    spec = importlib.util.spec_from_file_location("dast_fixture_server", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    context = ET.parse(CONTEXT).getroot().find("context")
    assert context is not None
    user = context.find("users/user").text.split(";")
    assert user[1] == "true" and base64.b64decode(user[2]).decode() == module.LOGIN_USER == CONTEXT_USER
    username, password = (base64.b64decode(part).decode() for part in user[4].split("~")[:2])
    assert (username, password) == (module.LOGIN_USER, module.LOGIN_PASSWORD)
    form = context.find("authentication/form")
    assert form.find("loginurl").text == f"http://127.0.0.1:{CONTEXT_PORT}/login"
    assert form.find("loginbody").text == "username={%username%}&password={%password%}"
    # ZAP checks every response (headers and body) against the logged-out indicator; a hit makes it sign in again.
    # Its first attempt was a logged-in indicator on the account page, which the login's own redirect does not carry,
    # and ZAP counted every sign-in as failed and shut itself down.
    out = re.compile(context.find("authentication/loggedout").text.replace("\\Q", "(?:").replace("\\E", ")"))

    def seen(response: tuple[int, dict, str]) -> bool:
        status, headers, body = response
        return bool(out.search("\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body))

    with Fixture(free_port(), "--login") as server:
        assert seen(server.get("/account")), "a request without a session is the logged-out case"
        assert seen(server.get("/login"))
        assert seen(server.get("/login", data="username=throwaway&password=wrong"))
        signed_in = server.get("/login", data=GOOD_LOGIN)
        assert not seen(signed_in), "the login's own response must not read as logged out"
        cookie = signed_in[1]["Set-Cookie"].split(";")[0]
        for path in ("/", "/account", "/account/search?q=fixture", "/about", "/search?q=x"):
            assert not seen(server.get(path, cookie)), f"{path} signed in must not read as logged out"


# --- the context file: parsed as XML, every URL decoded and loopback, credentials kept out of the output ---------

LOGIN = "<loginurl>http://127.0.0.1:8080/login</loginurl>"
PAGE_URL = "<loginpageurl>http://127.0.0.1:8080/login</loginpageurl>"
UNITS = "<pollunits>REQUESTS</pollunits>"
USER_ENTRY = re.search(r"<user>.*?</user>", CONTEXT.read_text()).group(0)
PASSWORD = "throwaway-password"
USERS_BLOCK = re.search(r"<users>.*?</users>", CONTEXT.read_text(), re.S).group(0)
SCOPE_OK = "http://127\\.0\\.0\\.1:8080/.*"
HOSTILE_HOST = re.compile(r"example\.com|evil\.example|2130706433|0x7f|0177|ffff", re.I)


def context_file(tmp_path: Path, old: str, new: str, head: str = "") -> str:
    text = CONTEXT.read_text()
    assert old in text, f"{old!r} is not in the shipped context"
    path = tmp_path / "variant.context"
    path.write_text(text.replace(old, new, 1).replace("<configuration>", head + "<configuration>", 1))
    return str(path)


def check_context(job, path: str, user: str = "throwaway", **inputs: object):
    return job(context_file=path, context_user=user, **inputs).run("Check the context file", REPO_ROOT=str(REPO))


def runner_unescape(data: str) -> str:
    """What the Actions runner does to a workflow command's data before it uses it."""
    return data.replace("%0D", "\r").replace("%0A", "\n").replace("%25", "%")


def log_without_masks(out: str) -> str:
    """The runner swallows `::add-mask::` lines; they are not part of the log anyone reads."""
    return "\n".join(line for line in out.splitlines() if not line.startswith("::add-mask::"))


def user_entry(name: str, password: str) -> str:
    def b64(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    return f"<user>0;true;{b64(name)};2;{b64(name)}~{b64(password)}~</user>"


OFF_HOST = [
    # CDATA, character references and entities hide a URL from a pattern over the text; the XML is parsed.
    ("cdata", LOGIN, "<loginurl><![CDATA[https://example.com/login]]></loginurl>", "", "<loginurl> is not loopback"),
    ("cdata split", LOGIN, "<loginurl><![CDATA[ht]]>tps://example.com/login</loginurl>", "", "is not loopback"),
    ("decimal char ref", LOGIN, "<loginurl>&#104;ttps://example.com/login</loginurl>", "", "is not loopback"),
    ("hex char ref", LOGIN, "<loginurl>&#x68;ttps://example.com/login</loginurl>", "", "is not loopback"),
    (
        "internal entity",
        LOGIN,
        "<loginurl>&u;</loginurl>",
        '<!DOCTYPE configuration [<!ENTITY u "https://example.com/login">]>',
        "declares a DOCTYPE or an entity",
    ),
    (
        "external entity",
        LOGIN,
        "<loginurl>&u;</loginurl>",
        '<!DOCTYPE configuration [<!ENTITY u SYSTEM "http://example.com/x">]>',
        "declares a DOCTYPE or an entity",
    ),
    ("doctype alone", LOGIN, LOGIN, '<!DOCTYPE configuration SYSTEM "http://example.com/x.dtd">', "DOCTYPE"),
    # Case, host spelling, trailing dots and look-alikes.
    ("mixed-case scheme and host", LOGIN, "<loginurl>HtTpS://ExAmPlE.CoM/login</loginurl>", "", "is not loopback"),
    ("mixed-case look-alike", LOGIN, "<loginurl>http://LocalHost.Evil.Example/login</loginurl>", "", "is not loopback"),
    ("trailing dot", LOGIN, "<loginurl>http://localhost./login</loginurl>", "", "is not loopback"),
    (
        "127.0.0.1 as a subdomain",
        LOGIN,
        "<loginurl>http://127.0.0.1.evil.example/login</loginurl>",
        "",
        "is not loopback",
    ),
    # Numeric forms of an address, which a resolver accepts and a pattern does not see.
    ("decimal IPv4", LOGIN, "<loginurl>http://2130706433/login</loginurl>", "", "is not loopback"),
    ("hex IPv4", LOGIN, "<loginurl>http://0x7f.0.0.1/login</loginurl>", "", "is not loopback"),
    ("octal IPv4", LOGIN, "<loginurl>http://0177.0.0.1/login</loginurl>", "", "is not loopback"),
    ("short IPv4", LOGIN, "<loginurl>http://127.1/login</loginurl>", "", "is not loopback"),
    ("unspecified address", LOGIN, "<loginurl>http://0.0.0.0:8080/login</loginurl>", "", "is not loopback"),
    ("private address", LOGIN, "<loginurl>http://10.0.0.5:8080/login</loginurl>", "", "is not loopback"),
    # IPv6 forms.
    ("IPv4-mapped IPv6", LOGIN, "<loginurl>http://[::ffff:127.0.0.1]:8080/login</loginurl>", "", "is not loopback"),
    ("unspecified IPv6", LOGIN, "<loginurl>http://[::]:8080/login</loginurl>", "", "is not loopback"),
    ("other IPv6", LOGIN, "<loginurl>http://[2001:db8::1]:8080/login</loginurl>", "", "is not loopback"),
    ("IPv6 zone", LOGIN, "<loginurl>http://[::1%25eth0]:8080/login</loginurl>", "", "is not loopback"),
    ("broken IPv6", LOGIN, "<loginurl>http://[::1/login</loginurl>", "", "not a valid URL"),
    # Userinfo and parser-confusion tricks.
    ("userinfo host", LOGIN, "<loginurl>http://127.0.0.1@evil.example/login</loginurl>", "", "user information"),
    ("userinfo port", LOGIN, "<loginurl>http://127.0.0.1:80@evil.example/login</loginurl>", "", "user information"),
    ("fragment trick", LOGIN, "<loginurl>http://evil.example#@127.0.0.1/login</loginurl>", "", "fragment"),
    ("backslash trick", LOGIN, "<loginurl>http://evil.example\\@127.0.0.1/login</loginurl>", "", "backslash"),
    ("whitespace", LOGIN, "<loginurl>http://127.0.0.1:8080/lo gin</loginurl>", "", "whitespace"),
    ("no scheme", LOGIN, "<loginurl>//evil.example/login</loginurl>", "", "absolute http or https"),
    ("other scheme", LOGIN, "<loginurl>ftp://127.0.0.1/login</loginurl>", "", "absolute http or https"),
    # The other URL-bearing elements are held to the same rule.
    ("login page url", PAGE_URL, "<loginpageurl>https://example.com/login</loginpageurl>", "", "<loginpageurl> is not"),
    (
        "poll url",
        UNITS,
        UNITS + "<pollurl>https://example.com/poll</pollurl>",
        "",
        "<pollurl> is not loopback",
    ),
    # Authentication and session kinds the check cannot read are refused, not let through.
    ("http authentication", "<type>2</type>", "<type>3</type>", "", "authentication type 3"),
    ("script authentication", "<type>2</type>", "<type>4</type>", "", "authentication type 4"),
    ("browser authentication", "<type>2</type>", "<type>6</type>", "", "authentication type 6"),
    ("auto-detect authentication", "<type>2</type>", "<type>7</type>", "", "authentication type 7"),
    ("unknown authentication", "<type>2</type>", "<type>99</type>", "", "authentication type 99"),
    ("unreadable authentication", "<type>2</type>", "<type>https://example.com</type>", "", "type unreadable"),
    ("unknown auth element", LOGIN, LOGIN + "<callback>https://example.com</callback>", "", "<callback>"),
    ("unknown form element", LOGIN, LOGIN + "<redirect>https://example.com</redirect>", "", "<redirect>"),
    (
        "duplicate authentication",
        "<forceduser>",
        "<authentication><type>0</type></authentication><forceduser>",
        "",
        "twice",
    ),
    ("script session", "<type>0</type>\n        </session>", "<type>2</type>\n        </session>", "", "session"),
    # Scope: the spider follows links the include regexes allow.
    ("scope everything", SCOPE_OK, ".*", "", "<incregexes>"),
    ("scope look-alike host", SCOPE_OK, "http://127\\.0\\.0\\.1.*", "", "<incregexes>"),
    ("scope other host", SCOPE_OK, "https://example\\.com.*", "", "<incregexes>"),
    # The review's two: an alternation is a second scope, and `:8080.*` also matches http://127.0.0.1:8080@evil/.
    ("scope alternation", SCOPE_OK, "http://127\\.0\\.0\\.1:8080/.*|https?://evil\\.example/.*", "", "<incregexes>"),
    ("scope prefix form", SCOPE_OK, "http://127\\.0\\.0\\.1:8080.*", "", "<incregexes>"),
    ("scope userinfo", SCOPE_OK, "http://127\\.0\\.0\\.1:8080/@evil\\.example/.*", "", "<incregexes>"),
    ("scope group", SCOPE_OK, "(http://127\\.0\\.0\\.1:8080/|https://evil\\.example/).*", "", "<incregexes>"),
    (
        "scope mixed content",
        SCOPE_OK,
        "http://127\\.0\\.0\\.1:8080/<x>|http://evil.example/.*</x>",
        "",
        "child elements",
    ),
    # Mixed content: ZAP reads the element's own text, an XML parser's itertext() joins the children's too.
    (
        "mixed content in a login url",
        LOGIN,
        "<loginurl>http://<x>127.0.0.1:8080/</x>evil.example/login</loginurl>",
        "",
        "child elements",
    ),
    ("mixed content in the type", "<type>2</type>", "<type>2<x>0</x></type>", "", "child elements"),
    ("interpolation", LOGIN, "<loginurl>http://127.0.0.1:8080/${sys:user.name}</loginurl>", "", "dollar-brace"),
    ("no users at all", USERS_BLOCK, "", "", "holds no users"),
    # The user must exist in the context, or the scan is anonymous.
    ("user not in context", "dGhyb3dhd2F5;2;", "bm9ib2R5;2;", "", "not one of the context's users"),
]


@pytest.mark.parametrize(("label", "old", "new", "head", "message"), OFF_HOST, ids=[c[0] for c in OFF_HOST])
def test_a_context_that_could_sign_in_off_host_or_hide_where_is_refused_without_echoing_it(
    job, tmp_path, label, old, new, head, message
):
    code, out = check_context(job, context_file(tmp_path, old, new, head))
    assert code != 0, f"{label} was accepted\n{out}"
    assert message in out, out
    log = log_without_masks(out)
    assert not HOSTILE_HOST.search(log) and "evil" not in log and "example.com" not in log, (
        f"the refusal printed the value it refused:\n{log}"
    )
    assert "Traceback" not in out


ACCEPTED = [
    ("shipped", LOGIN, LOGIN),
    ("mixed-case loopback", LOGIN, "<loginurl>HTTP://LocalHost:8080/login</loginurl>"),
    ("loopback in CDATA", LOGIN, "<loginurl><![CDATA[http://127.0.0.1:8080/login]]></loginurl>"),
    ("loopback with a character reference", LOGIN, "<loginurl>&#104;ttp://127.0.0.1:8080/login</loginurl>"),
    ("any 127/8 address", LOGIN, "<loginurl>http://127.0.0.2:8080/login</loginurl>"),
    ("IPv6 loopback", LOGIN, "<loginurl>http://[::1]:8080/login</loginurl>"),
    ("IPv6 loopback written out", LOGIN, "<loginurl>http://[0:0:0:0:0:0:0:1]:8080/login</loginurl>"),
    ("a harmless query", LOGIN, "<loginurl>http://127.0.0.1:8080/login?next=/account</loginurl>"),
    ("scope: the bare origin", SCOPE_OK, "http://127\\.0\\.0\\.1:8080"),
    ("scope: a path", SCOPE_OK, "^http://localhost:8080/app/v1/.*"),
    ("a poll url on loopback", UNITS, UNITS + "<pollurl>http://localhost:8080/account</pollurl>"),
]


@pytest.mark.parametrize(("label", "old", "new"), ACCEPTED, ids=[c[0] for c in ACCEPTED])
@pytest.mark.parametrize("egress", ["audit", "block"])
def test_a_loopback_context_in_any_spelling_is_accepted_under_either_egress_policy(
    job, tmp_path, label, old, new, egress
):
    """Request-time enforcement is not required: see the wiki. Both policies pass the same static check."""
    code, out = check_context(job, context_file(tmp_path, old, new), egress_policy=egress)
    assert code == 0, f"{label}\n{out}"


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://127.0.0.1:8080/login?u={%username%}&p={%password%}", "{%...%} token"),
        ("http://127.0.0.1:8080/login?u=%7B%25username%25%7D", "{%...%} token"),
        ("http://127.0.0.1:8080/login?password=hunter2hunter2", "named like a credential"),
        ("http://127.0.0.1:8080/login?API_TOKEN=abc", "named like a credential"),
        ("http://127.0.0.1:8080/login?x=throwaway-password", "credential in its query string"),
        ("http://127.0.0.1:8080/login?x=throwaway%2Dpassword", "credential in its query string"),
        ("http://throwaway:throwaway-password@127.0.0.1:8080/login", "user information"),
        ("http://127.0.0.1:8080/throwaway-password/login", "contains a user's credential"),
    ],
)
def test_a_credential_in_a_url_is_refused_and_never_reaches_the_log(job, tmp_path, url, message):
    code, out = check_context(job, context_file(tmp_path, LOGIN, f"<loginurl>{html.escape(url)}</loginurl>"))
    assert code != 0 and message in out, out
    log = log_without_masks(out)
    for secret in (PASSWORD, "hunter2hunter2", "abc", "%7B%25"):
        assert secret not in log, f"the refusal printed {secret!r}:\n{log}"


def test_the_credentials_belong_in_the_post_body_only(job, tmp_path):
    code, out = check_context(job, context_file(tmp_path, "<loginbody>", "<loginbody>token={%password%}&amp;"))
    assert code == 0, "{%username%} and {%password%} are what loginbody is for\n" + out


def test_a_user_the_context_does_not_hold_and_a_credential_too_short_to_redact_are_refused(job, tmp_path):
    code, out = check_context(job, context_file(tmp_path, USER_ENTRY, user_entry("throwaway", "abc")))
    assert code != 0 and "under 4 characters" in out and "abc" not in log_without_masks(out), out
    code, out = check_context(job, context_file(tmp_path, USER_ENTRY, user_entry("throwaway", "two\nlines")))
    assert code != 0 and "line break" in out, out


def test_a_file_that_is_not_utf8_xml_is_refused(job, tmp_path):
    bad = tmp_path / "utf16.context"
    bad.write_bytes(CONTEXT.read_text().encode("utf-16"))
    code, out = check_context(job, str(bad))
    assert code != 0 and "UTF-8" in out, out
    bad.write_text("<configuration><context>")
    code, out = check_context(job, str(bad))
    assert code != 0 and "well-formed" in out, out
    bad.write_text("<configuration></configuration>")
    code, out = check_context(job, str(bad))
    assert code != 0 and "exactly one <context>" in out, out


def test_the_scope_regex_of_the_shipped_context_is_the_anchored_form():
    text = CONTEXT.read_text()
    assert (
        f"<incregexes>{SCOPE_OK}</incregexes>" in text
        and "<incregexes>http://127\\.0\\.0\\.1:8080</incregexes>" in text
    )


def test_zap_is_given_the_bytes_that_were_validated_not_whatever_the_workspace_holds_now(job, tmp_path):
    """The install and start commands run after the check and can write the workspace."""
    path = tmp_path / "app.context"
    path.write_bytes(CONTEXT.read_bytes())

    def rewrite(j):
        path.write_text(CONTEXT.read_text().replace(LOGIN, "<loginurl>https://example.com/login</loginurl>"))

    j, code, out, args = scan_step(job, tmp_path, between=rewrite, context_file=str(path), context_user="throwaway")
    assert code == 0, out
    assert (j.temp / "zap" / "context.context").read_bytes() == CONTEXT.read_bytes()
    assert b"example.com" not in (j.temp / "zap" / "context.context").read_bytes()


def test_a_validated_copy_that_changes_before_the_scan_is_refused(job, tmp_path):
    def tamper(j):
        (j.temp / "zap-context.xml").write_text("<configuration/>")

    _, code, out, args = scan_step(job, tmp_path, between=tamper, context_file=CONTEXT_PATH, context_user="throwaway")
    assert code != 0 and "changed after the check" in out and not args, out


def test_a_password_with_the_runners_escape_sequences_is_masked_as_the_runner_will_read_it(job, tmp_path):
    password = "abc%0Adef%25x"
    j = job(
        context_file=context_file(tmp_path, USER_ENTRY, user_entry("scan-user", password)), context_user="scan-user"
    )
    code, out = j.run("Check the context file", REPO_ROOT=str(REPO))
    assert code == 0, out
    masks = {line.removeprefix("::add-mask::") for line in out.splitlines() if line.startswith("::add-mask::")}
    assert "abc%250Adef%2525x" in masks, masks
    assert password not in masks, "the runner would read %0A as a newline and mask something else"
    for bad in ("two\rlines", "two\nlines"):
        code, out = check_context(job, context_file(tmp_path, USER_ENTRY, user_entry("scan-user", bad)), "scan-user")
        assert code != 0 and "line break" in out, out


# The credentials of the context never reach a log, the summary, the SARIF or an uploaded report -------------


def test_the_context_check_masks_every_shape_of_the_credentials_and_keeps_them_in_a_private_file(job, tmp_path):
    password = "p@ss w/rd&1<x>"
    j = job(
        context_file=context_file(tmp_path, USER_ENTRY, user_entry("scan-user", password)), context_user="scan-user"
    )
    code, out = j.run("Check the context file", REPO_ROOT=str(REPO))
    assert code == 0, out
    masked = {
        runner_unescape(line.removeprefix("::add-mask::"))
        for line in out.splitlines()
        if line.startswith("::add-mask::")
    }
    for form in (
        password,
        urllib.parse.quote(password, safe=""),
        urllib.parse.quote_plus(password),
        html.escape(password),
        base64.b64encode(password.encode()).decode(),
        "scan-user",
    ):
        assert form in masked, f"{form!r} is not masked: {sorted(masked)}"
    redact = j.temp / "zap-redact.json"
    assert redact.exists() and oct(redact.stat().st_mode & 0o777) == "0o600"
    assert password in json.loads(redact.read_text())


def planted_reports(j, secrets: list[str]) -> Path:
    """The canned insecure report with the credentials where a reflecting application would put them."""
    zap = j.temp / "zap"
    zap.mkdir(exist_ok=True)
    report = json.loads((FIXTURES / "insecure.json").read_text())
    instance = report["site"][0]["alerts"][0]["instances"][0]
    password, user = secrets
    instance["uri"] += "?p=" + urllib.parse.quote_plus(password)
    instance["evidence"] = f'<input value="{html.escape(password)}">'
    instance["otherinfo"] = f"posted {user} / {password}"
    instance["attack"] = urllib.parse.quote(password, safe="")
    (zap / "report.json").write_text(json.dumps(report))
    (zap / "report.html").write_text(f"<p>{html.escape(password)} for {user}</p>")
    (zap / "report.md").write_text(f"posted {user} / {password}")
    (zap / "context.context").write_text(CONTEXT.read_text())
    for name in ("report.json", "report.html", "report.md"):
        (zap / name).chmod(0o444)  # the container's user owns the real ones; the runner may only replace them
    j.output.write_text("exit=0\n")
    return zap


def test_the_credentials_in_alert_instances_are_absent_from_the_sarif_the_summary_the_log_and_every_report(
    job, tmp_path
):
    password, user = "p@ss w/rd&1<x>", "scan-user"
    path = context_file(tmp_path, USER_ENTRY, user_entry(user, password))
    j = job(context_file=path, context_user=user, fail_on="none", scan_type="full")
    assert j.run("Check the context file", REPO_ROOT=str(REPO))[0] == 0
    zap = planted_reports(j, [password, user])
    code, out = j.run("Remove the context's credentials")
    assert code == 0, out
    code, report_out = j.run("Report and apply fail-on")
    assert code == 0, report_out
    forms = [
        password,
        urllib.parse.quote(password, safe=""),
        urllib.parse.quote_plus(password),
        html.escape(password),
        user,
    ]
    everything = {
        "stdout": out + report_out,
        "summary": j.summary.read_text(),
        **{name: (zap / name).read_text() for name in ("report.json", "report.html", "report.md", "zap.sarif")},
    }
    for where, text in everything.items():
        for form in forms:
            assert form not in text, f"{form!r} is in the {where}"
    assert "[redacted]" in everything["report.json"] and json.loads(everything["report.json"])
    sarif = json.loads(everything["zap.sarif"])
    assert sarif["runs"][0]["results"], "the SARIF is still a report"
    assert not (zap / "context.context").exists(), "the context holds the credentials, encoded; it is never uploaded"
    assert not (j.temp / "zap-redact.json").exists()


def test_a_credential_equal_to_a_key_of_the_report_cannot_blind_the_gate(job, tmp_path):
    """Redaction is by value: a password `alerts` must not rename the `alerts` key and turn the gate green."""
    password, user = "alerts", "riskcode"
    path = context_file(tmp_path, USER_ENTRY, user_entry(user, password))
    j = job(context_file=path, context_user=user, fail_on="medium", scan_type="full")
    assert j.run("Check the context file", REPO_ROOT=str(REPO))[0] == 0
    zap = planted_reports(j, [password, user])
    assert j.run("Remove the context's credentials")[0] == 0
    report = json.loads((zap / "report.json").read_text())
    assert report["site"][0]["alerts"], "the keys are intact"
    code, out = j.run("Report and apply fail-on")
    assert code != 0 and "Content Security Policy" in out, "the Medium alerts must still fail the gate\n" + out
    assert password not in "".join(report["site"][0]["alerts"][0]["instances"][0].values())


def test_when_the_credentials_cannot_be_removed_the_reports_are_deleted_not_uploaded(job, tmp_path):
    j = job(context_file=CONTEXT_PATH, context_user="throwaway", fail_on="none")
    assert j.run("Check the context file", REPO_ROOT=str(REPO))[0] == 0
    zap = planted_reports(j, [PASSWORD, "throwaway"])
    (j.temp / "zap-redact.json").write_text("not json")
    code, out = j.run("Remove the context's credentials")
    assert code != 0 and "deleted, not uploaded" in out, out
    assert not [p for p in zap.iterdir() if p.name.startswith(("report.", "zap."))], list(zap.iterdir())
    # and with no redaction file at all, the same
    zap = planted_reports(j, [PASSWORD, "throwaway"])
    (j.temp / "zap-redact.json").unlink()
    code, out = j.run("Remove the context's credentials")
    assert code != 0 and not (zap / "report.json").exists(), out


def test_the_scrub_runs_whether_or_not_the_scan_passed_and_only_the_report_files_are_uploaded():
    scan = jobs(load(WORKFLOW))["scan"]
    names = [str(s.get("name", s.get("uses", ""))) for s in steps_of(scan)]
    scrub = names.index("Remove the context's credentials from the reports")
    assert names.index("Run the ZAP scan") < scrub < names.index("Report and apply fail-on")
    spec = steps_of(scan)[scrub]
    assert "always()" in spec["if"] and "context-file" in spec["if"], "a failed scan still leaves reports to upload"
    upload = [s for s in steps_of(scan) if str(s.get("uses", "")).startswith("actions/upload-artifact@")][0]
    uploaded = [Path(line.strip()).name for line in upload["with"]["path"].splitlines() if line.strip()]
    assert sorted(uploaded) == ["report.html", "report.json", "report.md", "zap.sarif"], (
        "anything else in the work directory (the context, the rules, the definition) must not be uploaded"
    )


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


# The login: the same hole, reachable only signed in. Two tests, one fixture, two scans -----------------


def login_scan(job, *server_flags: str, fail_on: str, **inputs: object):
    """scan(), on the port the shipped context names, with the login served."""
    assert docker_usable(), "DAST_LIVE is set and docker is not usable: this job exists to run the real image"
    j = job(
        start_command=server_command(CONTEXT_PORT, "--login", *server_flags),
        target_url=f"http://127.0.0.1:{CONTEXT_PORT}",
        fail_on=fail_on,
        **inputs,
    )
    steps = ["Check the inputs"]
    if inputs.get("context_file"):
        steps.append("Check the context file")
    steps += ["Start the service and wait for it", "Run the ZAP scan"]
    if inputs.get("context_file"):
        steps.append("Remove the context's credentials")
    for fragment in steps:
        code, out = j.run(fragment, timeout=1500, REPO_ROOT=str(REPO))
        assert code == 0, f"{fragment}:\n{out}"
    return j


def alert_urls(j) -> set[str]:
    report = json.loads((j.temp / "zap" / "report.json").read_text())
    return {i["uri"] for site in report["site"] for a in site["alerts"] for i in a.get("instances", [])}


@live
def test_live_the_anonymous_full_scan_passes_a_hole_that_only_a_signed_in_session_reaches(job):
    j = login_scan(job, fail_on="high", scan_type="full")
    code, out = j.run("Report and apply fail-on")
    assert code == 0, "the anonymous full scan found something at High; the hole must sit behind the login\n" + out
    assert XSS not in alerts_in(j)
    assert not any("/account" in u for u in alert_urls(j)), "an anonymous spider must not have reached /account"


@live
def test_live_the_authenticated_full_scan_fails_the_same_service_at_high_naming_the_xss(job):
    j = login_scan(job, fail_on="high", scan_type="full", context_file=CONTEXT_PATH, context_user=CONTEXT_USER)
    code, out = j.run("Report and apply fail-on")
    assert code != 0, "the full scan, signed in, passed a page that reflects its query unescaped\n" + out
    assert "Cross Site Scripting (Reflected)" in out, out
    assert alerts_in(j)[XSS] == "error"
    assert any("/account/search" in u for u in alert_urls(j)), alert_urls(j)
    zap = j.temp / "zap"
    assert not (zap / "context.context").exists(), "the context holds the credentials, encoded; it is not uploaded"
    for name in ("report.json", "report.html", "report.md", "zap.sarif"):
        assert "throwaway-password" not in (zap / name).read_text(), name
    assert "Scanned signed in as a user of `context-file`" in j.summary.read_text()


@live
def test_live_the_baseline_spider_signs_in_too_which_is_why_it_is_not_refused_the_context(job):
    """With the headers off, every page it reaches is an alert: /account only shows up when the spider got in."""
    anonymous = login_scan(job, "--insecure", fail_on="none")
    assert anonymous.run("Report and apply fail-on")[0] == 0
    assert not any("/account" in u for u in alert_urls(anonymous))
    signed_in = login_scan(job, "--insecure", fail_on="none", context_file=CONTEXT_PATH, context_user=CONTEXT_USER)
    assert signed_in.run("Report and apply fail-on")[0] == 0
    assert any("/account" in u for u in alert_urls(signed_in)), alert_urls(signed_in)
