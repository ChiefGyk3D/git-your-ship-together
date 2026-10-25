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


def sourceable() -> str:
    lines = canary_script().rstrip("\n").split("\n")
    entry = next(i for i, line in enumerate(lines) if line == "canary_main &")
    assert lines[entry + 2] == '(sleep 90; kill "$main") >/dev/null 2>&1 &', (
        "canary_main must run under a 90 s watchdog"
    )
    return "\n".join(lines[:entry]) + "\n"


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
        "+ uname -a",
        "+ cat /etc/resolv.conf",
        "+ resolvectl status",
        "ss -lunp",
        "+ getent ahostsv4 pipelines.actions.githubusercontent.com",
        "+ curl -sS -o /dev/null -w %{http_code} %{remote_ip} %{time_connect}\\n --max-time 8 https://pipelines.actions.githubusercontent.com",
        *(f"+ getent ahostsv4 {h}" for h in HOSTS),
        *(f"--max-time 8 https://{h}" for h in HOSTS),
    ]:
        assert expected in out, f"diagnostic missing: {expected}"
    assert "-Ivs" not in out and " -v " not in out, "no verbose curl: its output carries request headers"
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


def test_the_whole_canary_runs_under_a_deadline(tmp_path):
    """The script as shipped, with the deadline cut to 1 s and a resolver that takes 3 s: exit 124 and a message."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "getent").write_text("#!/bin/sh\nsleep 3\n")
    (fake / "getent").chmod(0o755)
    script = canary_script().replace("sleep 90;", "sleep 1;")
    assert script != canary_script()
    done = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "GITHUB_STEP_SUMMARY": str(tmp_path / "s")},
    )
    assert done.returncode == 124, done.stdout + done.stderr
    assert "90 s deadline" in done.stdout


@pytest.mark.parametrize(
    "policies,ok",
    [
        ("audit|block", True),
        ("block", True),
        ("audit|audit|block", True),
        ("audit|typo", False),
        ("", False),
        ("block|", False),
        ("Block", False),
        ("audit|block|audit ", False),
    ],
)
def test_the_policy_check_accepts_only_exact_audit_or_block(policies, ok):
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", check_script()],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "POLICIES": policies},
    )
    assert (done.returncode == 0) is ok, done.stdout + done.stderr
    if not ok:
        assert "must be exactly 'audit' or 'block'" in done.stdout


def workflow_jobs():
    for path in WORKFLOWS:
        doc = yaml.safe_load(path.read_text())
        for name, job in doc["jobs"].items():
            steps = job.get("steps") or []
            if steps and str(steps[0].get("uses", "")).startswith("step-security/harden-runner@"):
                yield path, name, job, steps


def test_something_was_collected():
    assert len(list(workflow_jobs())) > 60


def effective_allow_list(path: Path, expression: str) -> str:
    """The step's allowed-endpoints with each `${{ inputs.X }}` replaced by X's default (a caller's override aside)."""
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return re.sub(r"\$\{\{ inputs\.([\w-]+) \}\}", lambda m: str(inputs[m.group(1)].get("default", "")), expression)


POLICY_INPUTS = ("egress-policy", "egress-policy-secretless", "distro-egress-policy", "semgrep-egress-policy")
VALUES = ["audit", "block", "typo", "", "Block"]


def declared_policy_inputs(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return sorted(n for n in inputs if n in POLICY_INPUTS)


def evaluate(expression: str, values: dict[str, str]):
    """The few expression forms used for a policy: inputs.X, == 'lit', &&, ||, parentheses."""
    body = re.fullmatch(r"\$\{\{ (.*) \}\}", expression).group(1)
    py = re.sub(r"inputs\.([\w-]+)", lambda m: f"V[{m.group(1)!r}]", body).replace("&&", " and ").replace("||", " or ")
    assert re.fullmatch(r"[\sV\[\]'a-z\-=()]*", py), f"unexpected syntax in a policy expression: {py}"
    return eval(py, {"__builtins__": {}}, {"V": values})  # noqa: S307 - a fixed expression from our own workflows


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
        check = steps[1]
        assert check.get("name") == "Validate the egress policy inputs (EX-0001)", f"{path.name}:{name}"
        assert check["run"] == check_script(), f"{path.name}:{name} policy check differs from the composite action"
        assert "if" not in check, "the check must run whatever the policy is"
        assert check["env"]["POLICIES"] == "|".join(f"${{{{ inputs.{n} }}}}" for n in declared), f"{path.name}:{name}"
        assert check["working-directory"] == "${{ github.workspace }}" and check["shell"] == "bash"
        offset = 2
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
    assert canary["if"] == "${{ (" + inner + ") == 'block' }}"
    for combo in itertools.product(VALUES, repeat=len(declared)):
        values = dict(zip(declared, combo, strict=True))
        result = evaluate(policy, values)
        assert result in ("audit", "block")
        assert evaluate(steps[0]["with"]["disable-telemetry"], values) is (result == "block")
        assert evaluate(canary["if"], values) is (result == "block")
        used = set(re.findall(r"inputs\.([\w-]+)", policy))
        expected = "audit" if any(values[n] == "audit" for n in used) else "block"
        assert result == expected, f"{path.name}:{name}: audit only on an exact `audit`; anything else fails closed"


def test_the_effective_policy_follows_the_right_inputs():
    """audit only when the input the job answers to says exactly audit; distro and semgrep need either to say audit."""
    seen = 0
    for path, name, _job, steps in workflow_jobs():
        if path.name in ("ci.yml", "audit.yml"):
            continue
        seen += 1
        used = set(re.findall(r"inputs\.([\w-]+)", steps[0]["with"]["egress-policy"]))
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
