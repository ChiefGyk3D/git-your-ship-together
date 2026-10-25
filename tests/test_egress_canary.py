"""The egress canary (EX-0001): the script's logic, and where the workflows put it.

The script lives in `.github/actions/egress-canary/action.yml` and is inlined, byte for byte, as the
third step of every job that can run harden-runner in `block` (a reusable workflow cannot name the
commit it runs from, so it cannot call the action by path; see docs/wiki/Design-rules.md).

The logic tests source the script up to its entry point (the first `export -f` line), replace the
functions that touch the network with stubs, and run the real `canary_main` under `bash -eo pipefail`,
the shell GitHub gives a `shell: bash` step. A second composite action, `egress-policy-check`, holds the
input validation that precedes the canary; its copies are held identical the same way.
"""

import itertools
import json
import os
import re
import socket
import subprocess
import textwrap
import time
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / ".github" / "actions" / "egress-canary" / "action.yml"
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))
HOSTS = ["github.com", "api.github.com", "results-receiver.actions.githubusercontent.com"]


def canary_script() -> str:
    return yaml.safe_load(ACTION.read_text())["runs"]["steps"][0]["run"]


WATCHDOG = '(sleep 90; kill -TERM -- "-$main"; sleep 2; kill -KILL -- "-$main") >/dev/null 2>&1 &'


def entry_index(lines: list[str]) -> int:
    entry = lines.index("set -m")
    assert lines[entry + 1] == "canary_main &", "canary_main must run as a job of its own process group"
    assert lines[entry + 3] == WATCHDOG, "canary_main must run under a 90 s watchdog that kills the group"
    return entry


def sourceable() -> str:
    lines = canary_script().rstrip("\n").split("\n")
    return "\n".join(lines[: entry_index(lines)]) + "\n"


def full_script(stubs: str = "", deadline: int | None = None) -> str:
    """The script as shipped, with stub functions defined just before the entry point."""
    lines = canary_script().rstrip("\n").split("\n")
    entry = entry_index(lines)
    text = "\n".join(lines[:entry]) + "\n" + textwrap.dedent(stubs) + "\n" + "\n".join(lines[entry:]) + "\n"
    return text if deadline is None else text.replace("sleep 90;", f"sleep {deadline};")


def process_alive(marker: str) -> bool:
    """True when any process has `marker` as an argument (read from /proc, so this test never matches itself)."""
    for entry in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if marker.encode() in entry.read_bytes().split(b"\0"):
                return True
        except OSError:
            continue
    return False


def kill_leftovers(marker: str) -> None:
    """Tidy up after a test whose assertion failed: stop any process that still has `marker` as an argument."""
    for entry in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if marker.encode() in entry.read_bytes().split(b"\0"):
                os.kill(int(entry.parent.name), 9)
        except (OSError, ValueError):
            continue


def wait_gone(marker: str, seconds: float = 4.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not process_alive(marker):
            return True
        time.sleep(0.1)
    return not process_alive(marker)


CHECK = REPO / ".github" / "actions" / "egress-policy-check" / "action.yml"


def check_script() -> str:
    return yaml.safe_load(CHECK.read_text())["runs"]["steps"][0]["run"]


def run_canary(tmp_path, stubs: str, env: dict | None = None):
    summary = tmp_path / "summary.md"
    summary.write_text("")
    script = sourceable() + textwrap.dedent(stubs) + "\nsleep() { :; }\ncanary_main\n"
    full_env = {**os.environ, "GITHUB_STEP_SUMMARY": str(summary), **(env or {})}
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, timeout=60, env=full_env
    )
    return done.returncode, done.stdout + done.stderr, summary.read_text()


# One A record for api.github.com and results-receiver, two for github.com.
RESOLVE = """
canary_resolve() {
  case "$1" in
    github.com) printf '140.82.1.1\\n140.82.1.2\\n' ;;
    api.github.com) echo 140.82.2.1 ;;
    results-receiver.actions.githubusercontent.com) echo 140.82.3.1 ;;
  esac
}
canary_show() { shift; echo "+ $*"; }
"""


def test_a_healthy_runner_passes_quietly(tmp_path):
    code, out, summary = run_canary(tmp_path, RESOLVE + "canary_probe() { return 0; }")
    assert code == 0, out
    assert "all 4 addresses" in out
    assert "diagnostics" not in out and "+ uname" not in out
    assert summary == "", "a healthy run writes no step summary"


def test_one_dropped_address_fails_names_it_and_prints_the_diagnostics(tmp_path):
    stub = RESOLVE + 'canary_probe() { [ "$1" != 140.82.1.2 ]; }'
    code, out, summary = run_canary(tmp_path, stub)
    assert code == 1, out
    assert "egress broken on this runner (known westus2 DNS issue, EX-0001): rerun the job" in out
    assert "github.com 140.82.1.2" in out
    assert "140.82.1.1\n" not in out.split("unreachable addresses")[1].split("::group::")[0]
    for expected in [
        "+ uname -srmo",
        "+ cat /etc/resolv.conf",
        "resolvectl status",
        "ss -lun",
        "+ getent ahostsv4 pipelines.actions.githubusercontent.com",
        "+ curl -sS -o /dev/null -w %{http_code} %{remote_ip} %{time_connect}\\n --max-time 8 https://pipelines.actions.githubusercontent.com",
        *(f"+ getent ahostsv4 {h}" for h in HOSTS),
        *(f"--max-time 8 https://{h}" for h in HOSTS),
    ]:
        assert expected in out, f"diagnostic missing: {expected}"
    assert "-Ivs" not in out and " -v " not in out, "no verbose curl: its output carries request headers"
    assert "uname -a" not in out and "ss -lunp" not in out, "no hostname and no process names in the diagnostics"
    assert "EX-0001" in summary and "github.com 140.82.1.2" in summary
    assert summary.count("\n") == 1, "the step summary is one line"


def test_a_name_that_does_not_resolve_fails(tmp_path):
    stub = (
        RESOLVE + 'canary_resolve() { [ "$1" = github.com ] && echo 140.82.1.1; true; }\ncanary_probe() { return 0; }'
    )
    code, out, summary = run_canary(tmp_path, stub)
    assert code == 1
    assert "api.github.com -" in out and "results-receiver.actions.githubusercontent.com -" in out


def counting_probe(tmp_path, fail_first: int) -> str:
    """A probe that fails its first `fail_first` calls for each address (one counter file per address)."""
    return f"canary_probe() {{ echo x >> {tmp_path}/calls.$1; [ $(wc -l < {tmp_path}/calls.$1) -gt {fail_first} ]; }}"


def calls(tmp_path, address: str) -> int:
    return (tmp_path / f"calls.{address}").read_text().count("x")


def test_a_refusal_is_retried_three_times_before_it_counts(tmp_path):
    code, out, _ = run_canary(tmp_path, RESOLVE + counting_probe(tmp_path, fail_first=3))
    assert code == 0, out
    assert calls(tmp_path, "140.82.2.1") == 4, "three refusals, then the fourth try connects"


def test_an_address_that_never_answers_is_tried_four_times_and_fails(tmp_path):
    code, out, _ = run_canary(tmp_path, RESOLVE + counting_probe(tmp_path, fail_first=10**6))
    assert code == 1, out
    assert calls(tmp_path, "140.82.2.1") == 4, "one try plus three retries, no more"


def test_four_refusals_in_a_row_are_unreachable(tmp_path):
    code, out, _ = run_canary(tmp_path, RESOLVE + counting_probe(tmp_path, fail_first=4))
    assert code == 1, out
    assert "api.github.com 140.82.2.1" in out


def test_all_lookups_are_unioned(tmp_path):
    """A name that answers with a different address on each lookup has every address probed."""
    counter = tmp_path / "n"
    stub = (
        RESOLVE
        + f"""
canary_resolve() {{
  case "$1" in
    github.com) echo "140.82.9.$(( $(wc -l < {counter} 2>/dev/null || echo 0) + 1 ))"; echo x >> {counter} ;;
    api.github.com) echo 140.82.2.1 ;;
    results-receiver.actions.githubusercontent.com) echo 140.82.3.1 ;;
  esac
}}
canary_probe() {{ echo "probe $1" >> {tmp_path}/probes; return 0; }}
"""
    )
    code, out, _ = run_canary(tmp_path, stub)
    assert code == 0, out
    probed = (tmp_path / "probes").read_text().split("\n")
    assert sum(1 for p in probed if p.startswith("probe 140.82.9.")) >= 2, probed


def test_the_real_resolver_keeps_only_stream_lines(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    getent = fake / "getent"
    getent.write_text(
        "#!/bin/sh\n"
        '[ "$1" = ahostsv4 ] || exit 2\n'
        "printf '140.82.1.1 STREAM %s\\n140.82.1.1 DGRAM\\n140.82.1.1 RAW\\n' \"$2\"\n"
    )
    getent.chmod(0o755)
    script = sourceable() + "canary_resolve github.com\n"
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"},
    )
    assert done.stdout == "140.82.1.1\n", done.stdout + done.stderr


def real_probe(addr: str, port: int):
    script = sourceable() + f"PORT={port}\ncanary_probe {addr}\n"
    start = time.monotonic()
    done = subprocess.run(["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, timeout=30)
    return done.returncode, time.monotonic() - start


def test_the_real_probe_connects_to_a_listener_and_fails_on_a_closed_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        assert real_probe("127.0.0.1", listener.getsockname()[1])[0] == 0
        port = listener.getsockname()[1]
    assert real_probe("127.0.0.1", port)[0] != 0, "a closed port must count as unreachable"


def test_the_real_probe_cannot_hang():
    """A black-holed address (TEST-NET-1) is refused, unroutable or silent; none may take over 3 s plus slack."""
    code, elapsed = real_probe("192.0.2.1", 443)
    assert code != 0
    assert elapsed < 6, f"the probe took {elapsed:.1f}s; its own limit is 3s"


def test_the_guard_bites_a_probe_that_always_succeeds_hides_a_dropped_address(tmp_path):
    """Negative case: with the failure counting removed the dropped-address test above would pass."""
    mutated = canary_script().replace('echo "$name $addr" >"$tmp/bad.$n"', "true")
    assert mutated != canary_script()
    lines = mutated.rstrip("\n").split("\n")
    script = (
        "\n".join(lines[: next(i for i, line in enumerate(lines) if line == "canary_main &")])
        + RESOLVE
        + "canary_probe() { return 1; }\nsleep() { :; }\ncanary_main\n"
    )
    done = subprocess.run(["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, (
        "the mutant must let a fully dropped runner through, proving the test above measures something"
    )


# --- where the workflows put it ------------------------------------------------------------------


def run_full(tmp_path, script: str, extra_path: Path | None = None):
    path = f"{extra_path}:{os.environ['PATH']}" if extra_path else os.environ["PATH"]
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "PATH": path, "GITHUB_STEP_SUMMARY": str(tmp_path / "s")},
    )


def test_the_whole_canary_runs_under_a_deadline(tmp_path):
    """The script as shipped, with the deadline cut to 1 s and a resolver that takes 3 s: exit 124 and a message."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "getent").write_text("#!/bin/sh\nsleep 3\n")
    (fake / "getent").chmod(0o755)
    done = run_full(tmp_path, full_script(deadline=1), fake)
    assert done.returncode == 124, done.stdout + done.stderr
    assert "90 s deadline" in done.stdout


def test_a_deadline_kills_the_whole_process_tree(tmp_path):
    """A resolver that leaves a grandchild behind: after the deadline no process of the group remains."""
    try:
        stubs = "canary_resolve() { sleep 4711 & wait; }"
        done = run_full(tmp_path, full_script(stubs, deadline=1))
        assert done.returncode == 124, done.stdout + done.stderr
        assert wait_gone("4711"), "a grandchild of canary_main survived the deadline"
    finally:
        kill_leftovers("4711")


def test_a_normal_finish_leaves_no_stray_process(tmp_path):
    """A probe that backgrounds something and returns: the group is cleaned up when canary_main is done."""
    try:
        stubs = RESOLVE + "canary_probe() { sleep 4712 & return 0; }"
        done = run_full(tmp_path, full_script(stubs))
        assert done.returncode == 0, done.stdout + done.stderr
        assert wait_gone("4712"), "a background child survived a normal finish"
    finally:
        kill_leftovers("4712")


def test_a_normal_finish_does_not_wait_for_the_watchdog(tmp_path):
    start = time.monotonic()
    done = run_full(tmp_path, full_script(RESOLVE + "canary_probe() { return 0; }"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert time.monotonic() - start < 20, "the watchdog's 90 s sleep must be cancelled when the canary is done"
    assert wait_gone("90"), "the watchdog's sleep outlived the step"


def run_check(env: dict[str, str]):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("POLICY_")}
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", check_script()],
        capture_output=True,
        text=True,
        timeout=20,
        env={**clean, **env},
    )


@pytest.mark.parametrize(
    "env",
    [
        {"POLICY_EGRESS_POLICY": "audit"},
        {"POLICY_EGRESS_POLICY": "block"},
        {"POLICY_EGRESS_POLICY": "audit", "POLICY_EGRESS_POLICY_SECRETLESS": "block"},
        {
            "POLICY_EGRESS_POLICY": "block",
            "POLICY_EGRESS_POLICY_SECRETLESS": "audit",
            "POLICY_DISTRO_EGRESS_POLICY": "block",
            "POLICY_SEMGREP_EGRESS_POLICY": "audit",
        },
        {},  # a workflow that declares none of them
    ],
)
def test_the_policy_check_accepts_exact_audit_and_block(env):
    done = run_check(env)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout == ""


HOSTILE = [
    "typo",
    "",
    "Block",
    "AUDIT",
    "audit ",
    " block",
    "audit|audit",
    "audit|block",
    "audit,block",
    "audit\nblock",
    "audit\n",
    "block\n::warning::injected",
    "::error::injected",
    "::set-output name=x::y",
    "'; echo pwned #",
    '"; echo pwned #',
    "$(echo pwned)",
    "`echo pwned`",
    "caf\u00e9 \u202e audit",
    "a" * 2000,
]


@pytest.mark.parametrize("value", HOSTILE, ids=lambda v: repr(v)[:30])
@pytest.mark.parametrize(
    "var,name",
    [
        ("POLICY_EGRESS_POLICY", "egress-policy"),
        ("POLICY_EGRESS_POLICY_SECRETLESS", "egress-policy-secretless"),
        ("POLICY_DISTRO_EGRESS_POLICY", "distro-egress-policy"),
        ("POLICY_SEMGREP_EGRESS_POLICY", "semgrep-egress-policy"),
    ],
)
def test_the_policy_check_rejects_anything_else_and_never_echoes_it(var, name, value):
    done = run_check({var: value})
    out = done.stdout + done.stderr
    assert done.returncode == 1, out
    assert out == (
        f"::error title=egress policy::the {name} input must be exactly 'audit' or 'block' "
        f"(its value is {len(value)} characters long)\n"
    ), "the message is fixed text, the input name and a length; nothing a caller passes appears in it"
    assert "::warning::" not in out and "injected" not in out and "pwned" not in out


def test_the_policy_check_reports_every_bad_input_by_name():
    done = run_check({"POLICY_EGRESS_POLICY": "typo", "POLICY_EGRESS_POLICY_SECRETLESS": "audit|audit"})
    assert done.returncode == 1
    assert "the egress-policy input" in done.stdout and "the egress-policy-secretless input" in done.stdout
    assert done.stdout.count("::error") == 2


CHECK_NAME = "Validate the egress policy inputs (EX-0001)"


def workflow_jobs():
    """Every job that has a harden-runner step, with its steps after the leading policy check (if it has one)."""
    for path in WORKFLOWS:
        doc = yaml.safe_load(path.read_text())
        for name, job in doc["jobs"].items():
            raw = job.get("steps") or []
            steps = raw[1:] if raw and raw[0].get("name") == CHECK_NAME else raw
            if steps and str(steps[0].get("uses", "")).startswith("step-security/harden-runner@"):
                yield path, name, job, steps


def test_the_policy_check_is_the_first_step_of_every_job_that_has_it():
    """It runs before anything consumes a policy, harden-runner included. No step may precede it."""
    seen = 0
    for path in WORKFLOWS:
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            names = [s.get("name") for s in job.get("steps") or []]
            if CHECK_NAME in names:
                seen += 1
                assert names.index(CHECK_NAME) == 0, f"{path.name}:{name}: a step runs before the policy check"
                assert names.count(CHECK_NAME) == 1
    assert seen > 60


def test_every_job_that_can_block_has_the_policy_check_except_the_hardcoded_audit_workflow():
    for path, name, job, _steps in workflow_jobs():
        if path.name in ("ci.yml", "audit.yml"):
            continue
        assert job["steps"][0].get("name") == CHECK_NAME, f"{path.name}:{name}"


def test_something_was_collected():
    assert len(list(workflow_jobs())) > 60


def effective_allow_list(path: Path, expression: str) -> str:
    """The step's allowed-endpoints with each `${{ inputs.X }}` replaced by X's default (a caller's override aside)."""
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return re.sub(r"\$\{\{ inputs\.([\w-]+) \}\}", lambda m: str(inputs[m.group(1)].get("default", "")), expression)


RUNNER_CASES = [
    "ubuntu-latest",
    "ubuntu-24.04-arm",
    "Ubuntu-Latest",
    "windows-latest",
    "macos-26",
    "self-hosted",
    "",
    "linux",
    "ubuntu-latest,self-hosted",
    '["ubuntu-latest"]',
    '["self-hosted","linux"]',
    ["self-hosted", "linux"],
    ["ubuntu-latest"],
    "ubuntu-latest-4-cores",
    "ubuntu-24.04-16core",
    "my-org-large-runner",
    None,
]


def runner_is_hosted(label) -> bool:
    """The oracle for the label check. `contains(fromJSON(list), label)` compares strings case-insensitively, so
    this lowercases both sides on purpose; a non-string (a list or object) never matches."""
    return isinstance(label, str) and label.lower() in {x.lower() for x in hosted_labels()}


POLICY_INPUTS = ("egress-policy", "egress-policy-secretless", "distro-egress-policy", "semgrep-egress-policy")
VALUES = ["audit", "block", "typo", "", "Block", "AUDIT"]
# `runner.environment` is `github-hosted` or `self-hosted` (GitHub Docs, contexts, runner context). Anything else
# must never give audit. GitHub's string comparison is case-insensitive, so the capitalizations below are equal.
ENVIRONMENTS = ["github-hosted", "self-hosted", "", None, "GitHub-Hosted", "GITHUB-HOSTED", "github-hosted ", "hosted"]


def declared_policy_inputs(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return sorted(n for n in inputs if n in POLICY_INPUTS)


RECORD = REPO / "docs" / "security" / "exceptions" / "EX-0001-harden-runner-block-westus2.md"


def hosted_labels() -> list[str]:
    """The ONE list of GitHub-hosted runner labels: the exception record (it cites the GitHub docs page)."""
    text = RECORD.read_text()
    block = text.split("<!-- hosted-runner-labels:begin -->")[1].split("<!-- hosted-runner-labels:end -->")[0]
    labels = [line.strip() for line in block.splitlines() if line.strip() and not line.startswith("```")]
    assert len(labels) >= 15 and len(labels) == len(set(labels))
    return labels


def eq(left, right: str) -> bool:
    """GitHub's `==` on strings is case-insensitive; null (an undefined context value) equals no string."""
    return isinstance(left, str) and left.lower() == right.lower()


def evaluate(expression: str, values: dict[str, str], runner=None, environment="github-hosted", runner_os="Linux"):
    """The expression forms used for a policy: inputs.X, runner.environment, == 'lit' (case-insensitive like
    GitHub's), &&, ||, parentheses, and contains(fromJSON('[...]'), <runner>) against the hosted-label list."""
    body = re.fullmatch(r"\$\{\{ (.*) \}\}", expression).group(1)

    def hosted(m):
        assert json.loads(m.group(1)) == hosted_labels(), (
            "a workflow embeds a hosted-label list that differs from EX-0001"
        )
        return "H(R)"

    body = re.sub(r"contains\(fromJSON\('(\[[^']*\])'\), (?:matrix|inputs)\.runner\)", hosted, body)
    body = re.sub(r"hashFiles\([^)]*\) != ''", "T", body)  # a manifest exists: the cache is wanted
    body = body.replace("runner.environment", "N")
    body = re.sub(r"runner\.os == ('[\w-]*')", r"Q(O, \1)", body)
    body = re.sub(r"inputs\.([\w-]+)", lambda m: f"V[{m.group(1)!r}]", body)
    body = re.sub(r"(V\['[\w-]+'\]|N) == ('[\w-]*')", r"Q(\1, \2)", body)
    py = body.replace("&&", " and ").replace("||", " or ")
    assert re.fullmatch(r"[\sVHRNOQT\[\]'a-zA-Z\-=(),]*", py), f"unexpected syntax in a policy expression: {py}"

    def is_hosted(label):  # a list or other type never matches a label
        return isinstance(label, str) and label.lower() in {x.lower() for x in hosted_labels()}

    env = {"V": values, "H": is_hosted, "R": runner, "N": environment, "O": runner_os, "Q": eq, "T": True}
    return eval(py, {"__builtins__": {}}, env)  # noqa: S307 - our own fixed expression


def test_the_runner_check_follows_the_hosted_list():
    lst = json.dumps(hosted_labels(), separators=(",", ":"))
    expr = (
        "${{ (inputs.a == 'audit' && runner.environment == 'github-hosted' && contains(fromJSON('"
        + lst
        + "'), matrix.runner)) && 'audit' || 'block' }}"
    )
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04") == "audit"
    assert evaluate(expr, {"a": "audit"}, "self-hosted") == "block"
    assert evaluate(expr, {"a": "audit"}, ["ubuntu-24.04"]) == "block"
    assert evaluate(expr, {"a": "block"}, "ubuntu-24.04") == "block"
    # A self-hosted runner can carry a hosted label; the runtime context is what stops it.
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="self-hosted") == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment=None) == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="") == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="GitHub-Hosted") == "audit"  # case-insensitive


def test_the_evaluator_follows_github_semantics():
    audit_or_block = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert evaluate(audit_or_block, {"a": "audit"}) == "audit"
    assert evaluate(audit_or_block, {"a": "typo"}) == "block"
    either = "${{ (inputs.a == 'audit' || inputs.b == 'audit') && 'audit' || 'block' }}"
    assert evaluate(either, {"a": "x", "b": "audit"}) == "audit"


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_every_job_gets_the_policy_check_and_the_canary_right_after_harden_runner(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name == "ci.yml":
        pytest.skip("this repository's own CI is audit by construction, there is nothing to guard")
    hardcoded = policy == "block"  # audit.yml
    offset = 1
    declared = declared_policy_inputs(path)
    if not hardcoded:
        check = job["steps"][0]
        assert check.get("name") == CHECK_NAME, f"{path.name}:{name}: the policy check must be the first step"
        assert check["run"] == check_script(), f"{path.name}:{name} policy check differs from the composite action"
        assert "if" not in check, "the check must run whatever the policy is"
        assert check["env"] == {"POLICY_" + n.upper().replace("-", "_"): f"${{{{ inputs.{n} }}}}" for n in declared}, (
            f"{path.name}:{name}: one environment variable per policy input, never a joined string"
        )
        assert check["working-directory"] == "${{ github.workspace }}" and check["shell"] == "bash"
    canary = steps[offset]
    assert canary.get("name") == "Egress canary (EX-0001)", f"{path.name}:{name} has no canary after the checks"
    assert canary["timeout-minutes"] == 2
    assert canary["shell"] == "bash"
    # A job's defaults.run.working-directory may not exist before checkout (python-package-release `build`).
    assert canary["working-directory"] == "${{ github.workspace }}", (
        f"{path.name}:{name}: canary lacks working-directory"
    )
    assert canary["run"] == canary_script(), f"{path.name}:{name} canary differs from the composite action"
    allowed = effective_allow_list(path, steps[0]["with"]["allowed-endpoints"])
    for host in HOSTS:
        assert f"{host}:443" in allowed.split(), (
            f"{path.name}:{name}: block must allow {host}, the canary connects to it"
        )
    assert "uses" not in canary and "secrets" not in canary["run"].lower()
    if hardcoded:
        assert "if" not in canary
        return
    # One effective policy, written three times: harden-runner, its telemetry switch and the canary's `if`.
    inner = policy[len("${{ ") : -len(" }}")]
    assert steps[0]["with"]["disable-telemetry"] == "${{ (" + inner + ") == 'block' }}"
    assert canary["if"] == "${{ runner.os == 'Linux' && ((" + inner + ") == 'block') }}"
    dynamic = str(job.get("runs-on")) in ("${{ matrix.runner }}", "${{ inputs.runner }}")
    secretless = (path.name, name) not in KEPT_BLOCK
    if secretless and not dynamic:
        assert job["runs-on"].lower() in {x.lower() for x in hosted_labels()}, f"{path.name}:{name}: not a hosted label"
    assert ("contains(fromJSON(" in policy) is (secretless and dynamic), f"{path.name}:{name}: runner check misplaced"
    runners = RUNNER_CASES if dynamic else [None]
    used = sorted(set(re.findall(r"inputs\.([\w-]+)", policy)) - {"runner"})
    assert ("runner.environment == 'github-hosted'" in policy) is secretless, (
        f"{path.name}:{name}: runtime check misplaced"
    )
    for runner in runners:
        for environment in ENVIRONMENTS:
            for combo in itertools.product(VALUES, repeat=len(used)):
                values = dict(zip(used, combo, strict=True))
                result = evaluate(policy, values, runner, environment)
                assert result in ("audit", "block")
                assert evaluate(steps[0]["with"]["disable-telemetry"], values, runner, environment) is (
                    result == "block"
                )
                assert evaluate(canary["if"], values, runner, environment) is (result == "block")
                for other_os in ("macOS", "Windows"):  # `timeout` and `getent` are Linux tools (issue #196)
                    assert evaluate(canary["if"], values, runner, environment, other_os) is False
                wants_audit = any(v.lower() == "audit" for v in values.values())  # GitHub compares case-insensitively
                runtime_hosted = (not secretless) or (environment or "").lower() == "github-hosted"
                label_hosted = (not secretless) or (not dynamic) or runner_is_hosted(runner)
                expected = "audit" if wants_audit and runtime_hosted and label_hosted else "block"
                assert result == expected, (
                    f"{path.name}:{name}: audit needs the input, runner.environment and the label to agree"
                )


def test_the_effective_policy_follows_the_right_inputs():
    """audit only when the input the job answers to equals `audit` (GitHub's `==` ignores case); distro and
    semgrep need either to say so. The exact-string control is the policy check, see the test that pins it."""
    seen = 0
    for path, name, _job, steps in workflow_jobs():
        if path.name in ("ci.yml", "audit.yml"):
            continue
        seen += 1
        used = set(re.findall(r"inputs\.([\w-]+)", steps[0]["with"]["egress-policy"])) - {"runner"}
        if (path.name, name) in KEPT_BLOCK:
            assert used == {"egress-policy"}, f"{path.name}:{name}"
        elif (path.name, name) in {("python-ci.yml", "distro"), ("bash-ci.yml", "distro")}:
            assert used == {"egress-policy-secretless", "distro-egress-policy"}
        elif (path.name, name) == ("security.yml", "semgrep"):
            assert used == {"egress-policy-secretless", "semgrep-egress-policy"}
        else:
            assert used == {"egress-policy-secretless"}, f"{path.name}:{name}"
    assert seen > 60


def test_the_canary_is_never_called_by_path_from_a_workflow():
    """A caller's workspace, not this repository, would resolve `./.github/actions/...`."""
    for path, name, _job, steps in workflow_jobs():
        for step in steps:
            assert "egress-canary" not in str(step.get("uses", "")), f"{path.name}:{name} calls the action by path"


# --- which jobs may follow the secretless input -----------------------------------------------------

# Kept in block on purpose (docs/security/exceptions/EX-0001-harden-runner-block-westus2.md, "Scope").
KEPT_BLOCK = {
    ("artifact-release.yml", "build"),  # builds the file that is signed and published
    ("artifact-release.yml", "publish"),  # contents: write, id-token, attestations
    ("container-release.yml", "plan"),  # its outputs choose the runners and the image name of the privileged build
    ("container-release.yml", "build"),  # packages: write
    ("container-release.yml", "merge"),  # packages: write, id-token, Doppler
    ("dast.yml", "scan"),  # its SARIF artifact is uploaded verbatim by the job that holds security-events: write
    ("dependabot-auto-merge.yml", "auto-merge"),  # contents and pull-requests: write
    ("docs-pages.yml", "build"),  # runs caller code; its artifact is deployed verbatim by `deploy`
    ("docs-pages.yml", "deploy"),  # pages: write, id-token
    ("lory-audit.yml", "audit"),  # LORY_PIPELINE_TOKEN, a third-party bearer token
    ("project-sync.yml", "sync"),  # id-token, Doppler, a GitHub App token
    ("python-ci.yml", "coverage"),  # id-token, Doppler, the Codecov upload
    ("python-ci.yml", "test"),  # its coverage artifact is uploaded to Codecov by `coverage`
    ("python-package-release.yml", "build"),  # builds the distribution that is published
    ("python-package-release.yml", "github-release"),  # contents: write, id-token, attestations
    ("security.yml", "dependency-review"),  # pull-requests: write
    ("security.yml", "snyk"),  # id-token, Doppler, SNYK_TOKEN
    ("security.yml", "scorecard"),  # id-token
    ("tofu-ci.yml", "plan"),  # id-token, Doppler
    ("verify-published.yml", "verify"),  # packages: read; gh attestation verify with the job token
    ("verify-published.yml", "verify-release"),  # gh release download and attestation verify with the job token
    ("wiki-publish.yml", "generate"),  # runs caller code; its artifact is pushed verbatim by `publish`
    ("wiki-publish.yml", "publish"),  # contents: write
}
SECRET_MARKERS = (
    "${{ secrets.",
    "doppler",
    "id-token",
    "DOPPLER",
    "attestations",
    "github.token",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)
TOKEN_KEYS = ("token", "github-token", "password", "registry-password")


def test_the_classification_table_names_real_jobs():
    real = {(path.name, name) for path, name, _, _ in workflow_jobs()}
    assert KEPT_BLOCK <= real, sorted(KEPT_BLOCK - real)


def what_a_job_holds(job: dict) -> list[str]:
    """Everything that disqualifies a job from the secretless input (EX-0001, "Scope")."""
    found = []
    grants = dict(job.get("permissions") or {})
    if grants.pop("contents", "read") != "read":
        found.append("contents write")
    if grants.pop("security-events", "write") != "write":
        found.append("security-events")
    found += [f"{scope}: {level}" for scope, level in grants.items()]
    steps = [s for s in job.get("steps") or [] if s.get("name") != "Egress canary (EX-0001)"]
    text = [yaml.safe_dump(s) for s in steps]
    found += [m for m in SECRET_MARKERS if any(m in t for t in text)]
    # A token handed to an action beyond the default (checkout and harden-runner use the job token themselves).
    found += [f"with.{k}" for s in steps for k in (s.get("with") or {}) if k in TOKEN_KEYS]
    return found


def artifact_feeds_a_privileged_job(path: Path, name: str, kept=None) -> bool:
    """True when a job kept in block needs `name` and downloads an artifact or reads its outputs."""
    kept = KEPT_BLOCK if kept is None else kept
    doc = yaml.safe_load(path.read_text())
    for other, job in doc["jobs"].items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if name not in needs or (path.name, other) not in kept:
            continue
        text = yaml.safe_dump(job)
        if "download-artifact" in text or f"needs.{name}.outputs" in text:
            return True
    return False


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_a_job_follows_the_secretless_input_only_if_it_holds_nothing(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name in ("ci.yml", "audit.yml"):
        pytest.skip("hardcoded policies")
    follows_secretless = "egress-policy-secretless" in policy
    assert follows_secretless == ((path.name, name) not in KEPT_BLOCK), f"{path.name}:{name} is classified differently"
    if follows_secretless:
        assert what_a_job_holds(job) == [], f"{path.name}:{name} holds something and must follow egress-policy"
        assert not artifact_feeds_a_privileged_job(path, name), f"{path.name}:{name} feeds a privileged job"


@pytest.mark.parametrize(
    "job,expected",
    [
        ({"permissions": {"contents": "write"}}, "contents write"),
        ({"permissions": {"contents": "read", "id-token": "write"}}, "id-token: write"),
        ({"permissions": {"contents": "read", "packages": "read"}}, "packages: read"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"T": "${{ secrets.X }}"}}]}, "${{ secrets."),
        ({"permissions": {"contents": "read"}, "steps": [{"run": "doppler run -- true"}]}, "doppler"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"T": "${{ github.token }}"}}]}, "github.token"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"GH_TOKEN": "x"}, "run": "gh x"}]}, "GH_TOKEN"),
        ({"permissions": {"contents": "read"}, "steps": [{"uses": "a/b@1", "with": {"token": "x"}}]}, "with.token"),
    ],
)
def test_the_guard_bites_a_job_that_holds_something(job, expected):
    assert expected in what_a_job_holds(job)


def test_the_artifact_guard_bites(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text(
        "jobs:\n  a:\n    steps: []\n  b:\n    needs: a\n    steps:\n      - uses: actions/download-artifact@1\n"
    )
    assert artifact_feeds_a_privileged_job(wf, "a", kept={("w.yml", "b")})
    assert not artifact_feeds_a_privileged_job(wf, "a", kept=set())
    assert not artifact_feeds_a_privileged_job(wf, "b", kept={("w.yml", "b")})


def test_the_guard_accepts_a_sarif_upload_and_a_read_only_job():
    assert what_a_job_holds({"permissions": {"contents": "read", "security-events": "write"}}) == []
    assert what_a_job_holds({"permissions": {"contents": "read"}, "steps": [{"run": "true"}]}) == []


def test_the_canary_overrides_every_job_default_working_directory_and_shell():
    seen_default = 0
    for path, name, job, steps in workflow_jobs():
        canary = next((s for s in steps if s.get("name") == "Egress canary (EX-0001)"), None)
        if canary is None:
            continue
        run_defaults = (job.get("defaults") or {}).get("run") or {}
        if "working-directory" in run_defaults:
            seen_default += 1
            assert canary.get("working-directory") == "${{ github.workspace }}", f"{path.name}:{name}"
        if "shell" in run_defaults:
            assert canary.get("shell") == "bash", f"{path.name}:{name}"
        top = (yaml.safe_load(path.read_text()).get("defaults") or {}).get("run") or {}
        assert not top, f"{path.name} has workflow-level run defaults; extend this test"
    assert seen_default >= 1, "python-package-release build sets a default working-directory; the guard must see it"


def test_the_action_sets_the_working_directory_too():
    step = yaml.safe_load(ACTION.read_text())["runs"]["steps"][0]
    assert step["working-directory"] == "${{ github.workspace }}" and step["shell"] == "bash"


# --- caches: an audit-mode job neither restores nor saves one --------------------------------------
#
# Code that runs in an audit job can write a poisoned cache that a later block-mode job (possibly one holding
# an OIDC token) restores, in the same run or a later one. setup-python's pip cache key is OS, architecture,
# Python version and a hash of the manifests, with no suffix or namespace option (read at the pinned SHA), so
# the only way to keep audit and block apart is to turn the cache off in a job whose effective policy is audit.
# Tool-download caches (key `tool-*`) stay: every restore is followed by `sha256sum -c`, so a poisoned entry
# cannot pass (tests/test_hygiene.py holds that).


def cache_sites(job: dict):
    """(step name, kind, expression) for every cache a job can restore or save."""
    run_text = "\n".join(str(s.get("run", "")) for s in job.get("steps") or [])
    for step in job.get("steps") or []:
        uses = str(step.get("uses", ""))
        with_ = step.get("with") or {}
        label = step.get("name") or uses
        if uses.startswith("actions/cache"):
            if str(with_.get("key", "")).startswith("tool-") and "sha256sum -c" in run_text:
                yield label, "hash-verified tool cache", None
            else:
                yield label, "actions/cache", step.get("if")
        for key in ("cache", "cache-from", "cache-to"):
            if with_.get(key) not in (None, ""):
                yield label, key, str(with_[key])


def gated_on_block(job: dict, policy: str, expression) -> bool:
    inner = policy[len("${{ ") : -len(" }}")]
    return expression is not None and f"({inner}) == 'block'" in str(expression)


def uncached_problems(path_name: str, job: dict, policy: str) -> list[str]:
    return [
        f"{path_name}: {label} ({kind}) is not off in audit"
        for label, kind, expr in cache_sites(job)
        if kind != "hash-verified tool cache" and not gated_on_block(job, policy, expr)
    ]


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_no_cache_is_used_when_the_job_is_audit(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name in ("ci.yml", "audit.yml"):
        pytest.skip("hardcoded policy")
    assert uncached_problems(f"{path.name}:{name}", job, policy) == []
    used = sorted(set(re.findall(r"inputs\.([\w-]+)", policy)) - {"runner"})
    dynamic = str(job.get("runs-on")) in ("${{ matrix.runner }}", "${{ inputs.runner }}")
    for label, kind, expr in cache_sites(job):
        if kind == "hash-verified tool cache":
            continue
        for runner in RUNNER_CASES if dynamic else [None]:
            for environment in ENVIRONMENTS:
                for combo in itertools.product(VALUES, repeat=len(used)):
                    values = dict(zip(used, combo, strict=True))
                    effective = evaluate(policy, values, runner, environment)
                    if kind == "actions/cache":
                        on = evaluate(expr, values, runner, environment)
                        assert on is (effective == "block"), f"{path.name}:{name}: {label}"
                    elif kind == "cache":
                        got = evaluate(expr, values, runner, environment)
                        assert got == ("pip" if effective == "block" else ""), f"{path.name}:{name}: {label}"
                    else:  # a buildx cache spec: empty unless block
                        assert gated_on_block(job, policy, expr), f"{path.name}:{name}: {label}"


def test_the_cache_guard_bites():
    job = {
        "steps": [
            {"name": "py", "uses": "actions/setup-python@x", "with": {"cache": "pip"}},
            {"name": "buildx", "uses": "docker/build-push-action@x", "with": {"cache-to": "type=gha"}},
            {"name": "dl", "uses": "actions/cache@x", "with": {"key": "arduino-packages-1"}},
            {"name": "tool", "uses": "actions/cache@x", "with": {"key": "tool-x-1"}},
            {"name": "verify", "run": "echo x | sha256sum -c -"},
        ]
    }
    policy = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert len(uncached_problems("w.yml", job, policy)) == 3
    job["steps"][0]["with"]["cache"] = "${{ (inputs.a == 'audit' && 'audit' || 'block') == 'block' && 'pip' || '' }}"
    assert len(uncached_problems("w.yml", job, policy)) == 2


def test_every_cache_site_in_the_workflows_was_seen():
    kinds = {}
    for path, name, job, _steps in workflow_jobs():
        for _label, kind, _expr in cache_sites(job):
            kinds.setdefault(kind, []).append(f"{path.name}:{name}")
    assert len(kinds.get("cache", [])) >= 5 and kinds.get("actions/cache") and kinds.get("cache-from")
    assert kinds.get("hash-verified tool cache"), "the tool caches are the hash-verified exception"


def test_this_repositorys_audit_jobs_use_no_cache_that_the_blocking_audit_workflow_restores():
    """ci.yml jobs are audit by construction and share setup-python's key with audit.yml (block, Doppler)."""
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    seen = 0
    for name, job in doc["jobs"].items():
        steps = job.get("steps") or []
        if steps and str(steps[0].get("uses", "")).startswith("step-security/harden-runner@"):
            assert steps[0]["with"]["egress-policy"] == "audit"
            seen += 1
            assert [label for label, kind, _ in cache_sites(job) if kind != "hash-verified tool cache"] == [], name
    assert seen >= 6


def test_the_expressions_depend_on_the_policy_check_for_exactness():
    """GitHub's `==` and `contains()` compare strings case-insensitively, so an effective-policy expression reads
    `AUDIT` as `audit` and `Block` as `block`. The expressions are therefore NOT the exact-string control. The
    control is the policy check: step 0 of every job that has such an expression, running before anything
    consumes the value, and failing on every value that is not exactly `audit` or `block`.
    """
    jobs_with_expressions = 0
    for path in WORKFLOWS:
        if path.name in ("ci.yml", "audit.yml"):
            continue  # hardcoded policies: no input reaches an expression
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            steps = job.get("steps") or []
            harden = next((s for s in steps if str(s.get("uses", "")).startswith("step-security/harden-runner@")), None)
            if harden is None or "inputs." not in str(harden["with"]["egress-policy"]):
                continue
            jobs_with_expressions += 1
            assert steps[0].get("name") == CHECK_NAME, f"{path.name}:{name}: an expression without the exact check"
            assert steps.index(harden) > 0
    assert jobs_with_expressions > 60
    # The expression alone is case-insensitive (the reason the check exists); the check is exact.
    expression = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert evaluate(expression, {"a": "AUDIT"}) == "audit"
    assert run_check({"POLICY_EGRESS_POLICY": "AUDIT"}).returncode == 1


# --- the canary is Linux-only (issue #196) -----------------------------------------------------------

CANARY_NAME = "Egress canary (EX-0001)"


def canary_steps():
    """Every canary step in every workflow, hardcoded-audit.yml ones included."""
    for path in WORKFLOWS:
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            for step in job.get("steps") or []:
                if step.get("name") == CANARY_NAME:
                    yield path, name, job, step


def linux_gate_problem(job: dict, step: dict) -> str | None:
    """None when the canary cannot run on macOS or Windows (`timeout` and `getent` are missing there): its `if`
    requires `runner.os == 'Linux'`, or the job runs on a fixed ubuntu label."""
    if "runner.os == 'Linux' &&" in str(step.get("if", "")):
        return None
    if re.fullmatch(r"ubuntu-[\w.]+", str(job.get("runs-on"))) and "if" not in step:
        return None  # audit.yml: hardcoded block on a fixed Linux runner
    return "canary can run on a non-Linux runner"


def test_every_canary_runs_only_on_linux():
    seen = 0
    for path, name, job, step in canary_steps():
        seen += 1
        assert linux_gate_problem(job, step) is None, f"{path.name}:{name}: {linux_gate_problem(job, step)}"
    assert seen > 60


def test_the_linux_guard_bites():
    """Mutation: drop the Linux condition from a real canary and the guard must object."""
    dynamic = [(j, s) for _p, _n, j, s in canary_steps() if str(j.get("runs-on")).startswith("${{ ")]
    assert len(dynamic) >= 6, "the matrix-runner jobs (python-ci, bash-ci, container-release, python-fuzz) must be seen"
    for job, step in dynamic:
        assert linux_gate_problem(job, step) is None
        mutated = {**step, "if": step["if"].replace("runner.os == 'Linux' && ", "")}
        assert mutated["if"] != step["if"]
        assert linux_gate_problem(job, mutated) is not None
        assert linux_gate_problem(job, {k: v for k, v in step.items() if k != "if"}) is not None
