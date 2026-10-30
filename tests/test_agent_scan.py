"""agent-scan.yml: optional, advisory scans of agent content with two Cisco AI Defense scanners.

The general rules (pinning, permissions, harden-runner, injection, documented inputs, the lock files) are held for
every reusable workflow in test_workflows.py, test_egress_canary.py and test_tool_locks.py. This file holds what is
particular to this one:

* the structure it promises: off unless a caller names paths, advisory unless a caller names a threshold, static
  engines only, no secret, and the job that reads the repository's content holds no write;
* the scan script it carries, the exact text that ships, run against stand-in scanners and workspaces built on the
  spot, because a gate nobody has seen go red is not known to go red.

The real scanners are not installed in the test job (they are hash-locked into the workflow and installed by it).
The fixture jobs in ci.yml run them for real: the clean fixture must pass `fail-on-severity: info`, the planted one
must produce a critical skill finding and a high MCP finding, and `agent-scan-control` fails when it does not.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "agent-scan.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
FIXTURES = REPO / "fixture" / "agent-scan"
SCAN_JOBS = {"skill-scan": "skill", "mcp-scan": "mcp"}
UPLOAD_JOBS = {"skill-upload": "skill-scan", "mcp-upload": "mcp-scan"}


def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def call() -> dict:
    d = doc()
    return (d.get("on") or d.get(True))["workflow_call"]


def steps(job: str) -> list[dict]:
    return doc()["jobs"][job]["steps"]


def scan_step(job: str) -> dict:
    return next(s for s in steps(job) if s.get("id") == "scan")


def script_of(job: str) -> str:
    match = re.search(r"<<'PY'\n(.*?)\n\s*PY\s*$", scan_step(job)["run"], re.S)
    assert match, f"{job}: the scan step does not carry its script as a quoted heredoc"
    return textwrap.dedent(match.group(1))


# --- structure ---------------------------------------------------------------------------------------------------


def test_there_are_four_jobs_two_that_read_and_two_that_upload():
    assert set(doc()["jobs"]) == set(SCAN_JOBS) | set(UPLOAD_JOBS)


def test_everything_is_off_until_a_caller_names_paths_and_advisory_until_it_names_a_threshold():
    inputs = call()["inputs"]
    assert inputs["skill-paths"]["default"] == ""
    assert inputs["mcp-tool-files"]["default"] == ""
    assert inputs["fail-on-severity"]["default"] == ""
    assert inputs["upload-sarif"]["default"] is True
    assert doc()["jobs"]["skill-scan"]["if"] == "inputs.skill-paths != ''"
    assert doc()["jobs"]["mcp-scan"]["if"] == "inputs.mcp-tool-files != ''"


def test_the_jobs_that_read_the_repository_hold_no_write():
    for job in SCAN_JOBS:
        assert doc()["jobs"][job]["permissions"] == {"contents": "read"}, job


def test_only_the_upload_jobs_hold_the_one_write_and_they_run_nothing_of_the_repository():
    for job, scan in UPLOAD_JOBS.items():
        spec = doc()["jobs"][job]
        assert spec["permissions"] == {"contents": "read", "security-events": "write"}
        assert spec["needs"] == scan
        uses = [str(s.get("uses", "")) for s in steps(job)]
        assert not any(u.startswith("actions/checkout@") for u in uses), "the upload job checks nothing out"
        plain = [s for s in steps(job) if "(EX-0001)" not in s.get("name", "")]
        assert not any("run" in s for s in plain), "only the egress policy check and canary are scripts"
        assert any(u.startswith("actions/download-artifact@") for u in uses)
        assert any(u.startswith("github/codeql-action/upload-sarif@") for u in uses)


def test_the_upload_runs_only_when_the_scan_finished_and_the_token_can_write():
    for job in UPLOAD_JOBS:
        cond = " ".join(str(doc()["jobs"][job]["if"]).split())
        assert "inputs.upload-sarif" in cond
        assert f"needs.{UPLOAD_JOBS[job]}.outputs.sarif == 'true'" in cond
        assert "head.repo.full_name == github.repository" in cond, "a fork's read-only token cannot upload"


def test_no_secret_no_opt_out_and_no_token_in_the_file():
    text = WORKFLOW.read_text()
    assert "secrets" not in call(), "the workflow takes no secret"
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for banned in ("continue-on-error", "secrets.", "DOPPLER", "GITHUB_TOKEN", "github.token"):
        assert banned not in code, f"agent-scan.yml contains {banned!r}"
    # The egress canary (EX-0001) is a shared script with its own `|| true`s, held identical by test_egress_canary.py.
    for job in doc()["jobs"].values():
        for step in job["steps"]:
            if "(EX-0001)" not in step.get("name", ""):
                assert "|| true" not in yaml.safe_dump(step), step.get("name", step.get("uses"))


def test_the_engines_are_static_only_and_the_workflow_says_so():
    text = WORKFLOW.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for flag in ("--use-llm", "--use-virustotal", "--use-aidefense", "--use-osv", "--use-behavioral", "--api-key"):
        assert flag not in code, f"{flag} would leave the static engines"
    assert '"--analyzers",\n        "yara"' in code or '"--analyzers", "yara"' in code
    assert "static engines only" in text.lower()
    assert "no llm" in text.lower() and "no api key" in text.lower()


def test_both_scan_steps_carry_the_same_script_and_pass_only_data_through_env():
    assert script_of("skill-scan") == script_of("mcp-scan")
    for job, kind in SCAN_JOBS.items():
        step = scan_step(job)
        assert step["env"]["KIND"] == kind
        assert "${{" not in step["run"], "inputs reach the script through env, never by expansion"
        assert set(step["env"]) == {"KIND", "TARGETS", "FAIL_ON", "WORKSPACE", "SARIF_OUT"}


def test_the_scan_runs_after_the_install_and_the_artifact_follows_it():
    for job in SCAN_JOBS:
        names = [s.get("name", s.get("uses", "")) for s in steps(job)]
        install = next(i for i, n in enumerate(names) if n.startswith("Install "))
        scan = next(i for i, s in enumerate(steps(job)) if s.get("id") == "scan")
        assert install < scan < len(names) - 1
        last = steps(job)[-1]
        assert last["uses"].startswith("actions/upload-artifact@")
        assert "steps.scan.outputs.sarif == 'true'" in last["if"]


def test_the_category_and_artifact_names_come_from_one_input_and_differ_per_scanner():
    assert "sarif-category" in call()["inputs"]
    names = {}
    for job, scan in UPLOAD_JOBS.items():
        download = next(s for s in steps(job) if str(s.get("uses", "")).startswith("actions/download-artifact@"))
        upload = next(s for s in steps(job) if str(s.get("uses", "")).startswith("github/codeql-action/upload-sarif@"))
        names[job] = (download["with"]["name"], upload["with"]["category"])
        produced = next(s for s in steps(scan) if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
        assert produced["with"]["name"] == download["with"]["name"]
    assert names["skill-upload"] != names["mcp-upload"]


def test_the_workflow_outputs_the_counts_the_fixture_control_reads():
    outputs = call()["outputs"]
    assert set(outputs) == {"skill-findings", "skill-max-severity", "mcp-findings", "mcp-max-severity"}


# --- the fixtures and the CI wiring -----------------------------------------------------------------------------


def test_the_planted_fixtures_hold_what_they_claim_and_the_clean_ones_do_not():
    bad = (FIXTURES / "planted-skill" / "SKILL.md").read_text()
    assert "ignore all previous instructions" in bad.lower()
    assert "| bash" in bad and ".ssh/id_rsa" in bad
    clean = (FIXTURES / "clean-skill" / "SKILL.md").read_text()
    assert "license:" in clean, "a clean skill states its license, or the scanner reports an INFO finding"
    for needle in ("ignore all previous", "| bash", ".ssh", "curl "):
        assert needle not in clean.lower()
    planted = json.loads((FIXTURES / "mcp" / "planted-tools.json").read_text())
    assert "id_rsa" in planted["tools"][0]["description"]
    clean_tools = json.loads((FIXTURES / "mcp" / "clean-tools.json").read_text())
    assert clean_tools["tools"] and "ssh" not in json.dumps(clean_tools).lower()


def test_ci_runs_the_clean_fixture_with_a_threshold_and_the_planted_one_as_advisory_and_checks_it_fired():
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    clean, planted, control = jobs["fixture-agent-scan"], jobs["fixture-agent-scan-planted"], jobs["agent-scan-control"]
    for job in (clean, planted):
        assert job["uses"] == "./.github/workflows/agent-scan.yml"
        # a caller grants what the called workflow declares, even for a job its inputs skip (static check)
        assert job["permissions"] == {"contents": "read", "security-events": "write"}
        assert job["with"]["upload-sarif"] is False, "planted findings must not become alerts on this repository"
        assert job["with"]["egress-policy"] == "block"
    assert clean["with"]["fail-on-severity"] == "info", "zero findings of any severity on the clean fixture"
    assert "fail-on-severity" not in planted["with"], "the planted fixture runs advisory: the job is green"
    assert control["needs"] == "fixture-agent-scan-planted"
    run = " ".join(step["run"] for step in control["steps"] if "run" in step)
    for needle in ("SKILL_MAX", "MCP_MAX", "critical", "high"):
        assert needle in run
    assert "${{" not in run


# --- the script, run as shipped -----------------------------------------------------------------------------------


def stub(path: Path, body: str) -> None:
    path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


SKILL_STUB = """
import json, os, sys
args = sys.argv[1:]
config = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub-config.json")))
with open(config["log"], "a") as log:
    log.write(json.dumps({"argv": args, "env": sorted(os.environ), "cwd": os.getcwd()}) + "\\n")
mode = config["skill_mode"]
out = args[args.index("--output-sarif") + 1]
directory = args[1]
prefix = directory.lstrip("/")
if mode == "crash":
    sys.exit(2)
results = []
if mode in ("critical", "info", "partial"):
    sev = {"critical": "CRITICAL", "info": "INFO", "partial": "LOW"}[mode]
    results.append({
        "ruleId": "YARA_prompt_injection_generic", "level": "error", "message": {"text": "x"},
        "properties": {"severity": sev},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": prefix + "/SKILL.md"},
                                            "region": {"startLine": 3}}}],
    })
with open(out, "w") as f:
    tool = {"driver": {"name": "skill-scanner", "rules": []}}
    json.dump({"version": "2.1.0", "runs": [{"tool": tool, "results": results}]}, f)
if mode == "partial":
    sys.exit(2)
if "--fail-on-severity" in args:
    order = ["info", "low", "medium", "high", "critical"]
    want = order.index(args[args.index("--fail-on-severity") + 1])
    if any(order.index(r["properties"]["severity"].lower()) >= want for r in results):
        sys.exit(1)
"""

MCP_STUB = """
import json, os, sys
args = sys.argv[1:]
config = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub-config.json")))
with open(config["log"], "a") as log:
    log.write(json.dumps({"argv": args, "env": sorted(os.environ), "cwd": os.getcwd()}) + "\\n")
mode = config["mcp_mode"]
tools = json.load(open(args[args.index("--tools") + 1]))["tools"]
if mode == "crash":
    sys.exit(1)
out = []
for t in tools:
    sev = {"high": "HIGH", "medium": "MEDIUM", "safe": "SAFE", "weird": "WEIRD"}.get(mode, "SAFE")
    finding = {"severity": sev, "threat_names": ["PROMPT INJECTION"] if sev != "SAFE" else [], "threat_summary": "s"}
    out.append({"status": "error" if mode == "error" else "completed", "is_safe": sev == "SAFE",
                "findings": {"yara_analyzer": finding}, "tool_name": t["name"], "item_type": "tool"})
if mode == "short":
    out = out[:-1]
if mode == "duplicate":
    out = [out[0]] * len(out)
if mode == "extra":
    out = out + [dict(out[0])]
if mode == "wrong":
    out[-1]["tool_name"] = "not-requested"
print(json.dumps(out))
"""


@pytest.fixture
def bench(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub(bin_dir / "skill-scanner", SKILL_STUB)
    stub(bin_dir / "mcp-scanner", MCP_STUB)
    return tmp_path


def make_skill(root: Path, rel: str, entry: str = "SKILL.md") -> None:
    (root / rel).mkdir(parents=True, exist_ok=True)
    (root / rel / entry).write_text("---\nname: s\n---\n")


def run_script(bench: Path, job: str, targets: str, fail_on: str = "", mode: str | None = None, extra_env=None):
    """Run the shipped script of `job` with stand-in scanners; returns (result, outputs, sarif or None, log lines)."""
    work = bench / "work"
    env = {
        "PATH": f"{bench / 'bin'}:{os.environ['PATH']}",
        "HOME": str(bench),
        "KIND": SCAN_JOBS[job],
        "TARGETS": targets,
        "FAIL_ON": fail_on,
        "WORKSPACE": str(work),
        "SARIF_OUT": str(bench / "out.sarif"),
        "GITHUB_OUTPUT": str(bench / "gh-output"),
        "GITHUB_STEP_SUMMARY": str(bench / "summary.md"),
        # what a real runner step has in its environment; none of it may reach a scanner
        "GITHUB_TOKEN": "ghs_FAKE_TOKEN_VALUE",
        "DOPPLER_TOKEN": "dp.st.FAKE",
        "ACTIONS_RUNTIME_TOKEN": "FAKE_RUNTIME",
    }
    default = {"skill-scan": "critical", "mcp-scan": "high"}[job]
    modes = {"skill_mode": "critical", "mcp_mode": "high", "log": str(bench / "stub.log")}
    modes["skill_mode" if job == "skill-scan" else "mcp_mode"] = mode or default
    (bench / "bin" / "stub-config.json").write_text(json.dumps(modes))
    env.update(extra_env or {})
    result = subprocess.run(
        [sys.executable, "-I", "-c", script_of(job)], cwd=work, env=env, capture_output=True, text=True, check=False
    )
    out = {}
    if (bench / "gh-output").exists():
        out = dict(line.split("=", 1) for line in (bench / "gh-output").read_text().splitlines())
    sarif = json.loads((bench / "out.sarif").read_text()) if (bench / "out.sarif").exists() else None
    log = (
        [json.loads(x) for x in (bench / "stub.log").read_text().splitlines()] if (bench / "stub.log").exists() else []
    )
    return result, out, sarif, log


def test_a_skill_finding_is_reported_and_the_job_stays_green_without_a_threshold(bench):
    make_skill(bench / "work", "skills/one")
    result, out, sarif, log = run_script(bench, "skill-scan", "skills/one")
    assert result.returncode == 0, result.stdout + result.stderr
    assert out == {"findings": "1", "max-severity": "critical", "scanned": "1", "sarif": "true"}
    assert "--fail-on-severity" not in log[0]["argv"], "advisory means the scanner's own gate is off"
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "skills/one/SKILL.md", "the report names the file relative to the repository root"
    assert "critical" in (bench / "summary.md").read_text()


def test_the_threshold_is_applied_to_the_report_and_the_scanner_must_exit_zero(bench):
    make_skill(bench / "work", "skills/one")
    result, out, sarif, log = run_script(bench, "skill-scan", "skills/one", fail_on="high")
    assert result.returncode == 1
    assert "--fail-on-severity" not in log[0]["argv"], "a scanner exit code never stands for a finding"
    assert out["sarif"] == "true", "a finding still produces its report; only a failed scan withholds it"
    assert "at or above high" in result.stdout


def test_a_scanner_that_exits_nonzero_with_a_partial_report_is_an_error_not_a_threshold_trip(bench):
    make_skill(bench / "work", "skills/one")
    result, out, sarif, _ = run_script(bench, "skill-scan", "skills/one", fail_on="high", mode="partial")
    assert result.returncode == 1
    assert out["sarif"] == "false" and sarif is None, "a partial report must never be uploaded"
    assert "at or above" not in result.stdout, "a crash is not a finding"
    assert "exited 2" in result.stdout


def test_a_threshold_above_every_finding_stays_green(bench):
    make_skill(bench / "work", "skills/one")
    result, _, _, _ = run_script(bench, "skill-scan", "skills/one", fail_on="critical", mode="info")
    assert result.returncode == 0, result.stdout


def test_a_clean_skill_passes_the_strictest_threshold(bench):
    make_skill(bench / "work", "skills/one")
    result, out, _, _ = run_script(bench, "skill-scan", "skills/one", fail_on="info", mode="clean")
    assert result.returncode == 0
    assert out["findings"] == "0" and out["max-severity"] == "none"


def test_an_entry_file_is_scanned_through_skill_file_and_a_directory_is_not(bench):
    make_skill(bench / "work", "roles", "implementer.md")
    make_skill(bench / "work", "skills/one")
    result, _, _, log = run_script(bench, "skill-scan", "roles/implementer.md skills/one")
    assert result.returncode == 0, result.stdout + result.stderr
    argvs = [entry["argv"] for entry in log]
    assert any("--skill-file=implementer.md" in a for a in argvs)
    assert sum(any(x.startswith("--skill-file") for x in a) for a in argvs) == 1
    assert len(argvs) == 2, "one invocation per entry file"


def test_globs_expand_inside_the_workspace_and_one_that_matches_nothing_fails(bench):
    make_skill(bench / "work", "roles", "a.md")
    (bench / "work" / "roles" / "b.md").write_text("x")
    result, out, _, log = run_script(bench, "skill-scan", "roles/*.md")
    assert result.returncode == 0 and out["scanned"] == "2" and len(log) == 2
    gone = run_script(bench, "skill-scan", "nothing/*.md")
    assert gone[0].returncode == 1 and "matches nothing" in gone[0].stdout


@pytest.mark.parametrize(
    "target",
    ["../outside", "/etc", "-x", "~/skills", ".git/hooks", "skills/../../x", "skills/.git/x"],
    ids=["dotdot", "absolute", "option", "tilde", "git-dir", "deep-dotdot", "nested-git"],
)
def test_a_path_that_is_not_inside_the_repository_is_refused_and_nothing_runs(bench, target):
    (bench / "work" / ".git" / "hooks").mkdir(parents=True)
    make_skill(bench / "work", "skills/one")
    (bench / "outside").mkdir()
    result, out, sarif, log = run_script(bench, "skill-scan", target)
    assert result.returncode == 1
    assert log == [], "the scanner must never see a refused path"
    assert out.get("sarif") == "false" and sarif is None, "no report is written for a scan that did not happen"


def test_a_symlink_that_leaves_the_repository_is_refused(bench):
    make_skill(bench, "elsewhere/one")
    make_skill(bench / "work", "skills")
    (bench / "work" / "skills" / "link").symlink_to(bench / "elsewhere" / "one")
    result, _, _, log = run_script(bench, "skill-scan", "skills/link")
    assert result.returncode == 1 and log == []
    assert "leads outside the repository" in result.stdout


def test_a_symlink_inside_a_skill_that_leaves_the_repository_is_refused_and_one_inside_is_not(bench):
    make_skill(bench / "work", "skills/one")
    (bench / "secret.txt").write_text("not for the report")
    (bench / "work" / "skills" / "one" / "notes").symlink_to(bench / "secret.txt")
    result, out, sarif, log = run_script(bench, "skill-scan", "skills/one")
    assert result.returncode == 1 and log == [] and sarif is None
    assert "symlink that leaves the repository" in result.stdout
    (bench / "work" / "skills" / "one" / "notes").unlink()
    (bench / "work" / "skills" / "one" / "notes").symlink_to(bench / "work" / "skills" / "one" / "SKILL.md")
    assert run_script(bench, "skill-scan", "skills/one")[0].returncode == 0


def test_a_symlinked_directory_is_never_traversed_when_patterns_are_expanded(bench):
    make_skill(bench, "elsewhere/deep")
    make_skill(bench / "work", "skills/real")
    (bench / "work" / "skills" / "link").symlink_to(bench / "elsewhere", target_is_directory=True)
    (bench / "work" / "inside").symlink_to(bench / "work" / "skills", target_is_directory=True)
    found = run_script(bench, "skill-scan", "**/SKILL.md")
    assert found[0].returncode == 0 and found[1]["scanned"] == "1", found[0].stdout
    assert [e["argv"][1] for e in found[3]] == [str(bench / "work" / "skills" / "real")]
    for pattern in ("skills/link/*", "inside/real", "skills/link/deep"):
        refused = run_script(bench, "skill-scan", pattern)
        assert refused[0].returncode == 1 and "matches nothing" in refused[0].stdout, pattern


def test_expanding_a_pattern_stops_at_the_entry_limit_and_the_depth_limit(bench):
    for n in range(5):
        make_skill(bench / "work", f"many/s{n}")
    limited = script_of("skill-scan").replace("MAX_ENTRIES = 100000", "MAX_ENTRIES = 3")
    assert limited != script_of("skill-scan")
    deep = bench / "work" / "d"
    deep.mkdir()
    for _ in range(40):
        deep = deep / "d"
        deep.mkdir()
    make_skill(deep, "x")
    for text, target, wanted in (
        (limited, "many/*", "too many entries"),
        (script_of("skill-scan"), "**/SKILL.md", "too deep"),
    ):
        env = {"PATH": f"{bench / 'bin'}:{os.environ['PATH']}", "KIND": "skill", "FAIL_ON": "", "TARGETS": target}
        env.update(WORKSPACE=str(bench / "work"), SARIF_OUT=str(bench / "o.sarif"))
        done = subprocess.run(
            [sys.executable, "-I", "-c", text], cwd=bench / "work", env=env, capture_output=True, text=True, check=False
        )
        assert done.returncode == 1 and wanted in done.stdout, (target, done.stdout)


def test_the_scan_jobs_block_egress_unless_the_caller_chooses_audit():
    assert call()["inputs"]["egress-policy"]["default"] == "block"
    assert call()["inputs"]["egress-policy-secretless"]["default"] == "audit", "the upload jobs follow EX-0001"
    for job in SCAN_JOBS:
        policy = doc()["jobs"][job]["steps"][1]["with"]["egress-policy"]
        assert "inputs.egress-policy ==" in policy


def test_whitespace_only_paths_and_a_bad_threshold_fail(bench):
    make_skill(bench / "work", "skills/one")
    empty = run_script(bench, "skill-scan", "  \n ")
    assert empty[0].returncode == 1 and "no paths to scan" in empty[0].stdout
    bad = run_script(bench, "skill-scan", "skills/one", fail_on="urgent")
    assert bad[0].returncode == 1 and "fail-on-severity must be" in bad[0].stdout


def test_a_scanner_that_crashes_fails_the_job_and_uploads_no_report(bench):
    make_skill(bench / "work", "skills/one")
    for fail_on in ("", "high"):
        (bench / "out.sarif").unlink(missing_ok=True)
        result, out, sarif, _ = run_script(bench, "skill-scan", "skills/one", fail_on=fail_on, mode="crash")
        assert result.returncode == 1, fail_on
        assert out["sarif"] == "false" and sarif is None
        assert "did not complete" in (bench / "summary.md").read_text()


def test_no_secret_reaches_a_scanner_and_it_runs_outside_the_repository(bench):
    make_skill(bench / "work", "skills/one")
    (bench / "work" / ".env").write_text("MCP_SCANNER_API_KEY=planted\n")
    run_script(bench, "skill-scan", "skills/one")
    (bench / "work" / "t.json").write_text(json.dumps({"tools": [{"name": "a"}]}))
    run_script(bench, "mcp-scan", "t.json")
    log = [json.loads(x) for x in (bench / "stub.log").read_text().splitlines()]
    assert len(log) == 2
    for entry in log:
        leaked = {"GITHUB_TOKEN", "DOPPLER_TOKEN", "ACTIONS_RUNTIME_TOKEN", "GITHUB_OUTPUT", "KIND", "TARGETS"}
        assert not leaked & set(entry["env"]), sorted(leaked & set(entry["env"]))
        assert "LITELLM_LOCAL_MODEL_COST_MAP" in entry["env"], (
            "the scanner must not fetch a price list over the network"
        )
        assert Path(entry["cwd"]).resolve() != (bench / "work").resolve(), "a .env in the repository is never read"


def test_the_summary_and_the_log_carry_no_text_that_could_start_a_command_or_a_mention(bench):
    make_skill(bench / "work", "skills/@evil`x`|[l](http://a)\nname")
    result, _, _, _ = run_script(bench, "skill-scan", "skills/*")
    text = (bench / "summary.md").read_text() + result.stdout
    for bad in ("@evil", "`x`", "[l](", "\n::"):
        assert bad not in text


def test_a_second_scan_of_the_same_directory_is_reported_once(bench):
    make_skill(bench / "work", "roles", "a.md")
    (bench / "work" / "roles" / "b.md").write_text("x")
    _, out, _, log = run_script(bench, "skill-scan", "roles/a.md roles/b.md")
    assert len(log) == 2 and out["findings"] == "1", "both runs report the same finding; the report holds it once"


# --- MCP ---------------------------------------------------------------------------------------------------------


def tools_file(root: Path, rel="mcp/tools.json", tools=None):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"tools": tools if tools is not None else [{"name": "a"}, {"name": "b"}]}))


def test_an_mcp_finding_is_advisory_by_default_and_the_engine_is_yara_alone(bench):
    tools_file(bench / "work")
    result, out, sarif, log = run_script(bench, "mcp-scan", "mcp/tools.json")
    assert result.returncode == 0, result.stdout
    assert out["findings"] == "2" and out["max-severity"] == "high" and out["sarif"] == "true"
    argv = log[0]["argv"]
    assert argv[argv.index("--analyzers") + 1] == "yara"
    assert "--api-key" not in argv and "--llm-api-key" not in argv
    first = sarif["runs"][0]["results"][0]
    assert first["ruleId"] == "mcp-scanner/prompt-injection" and first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mcp/tools.json"


@pytest.mark.parametrize(
    "threshold,mode,code",
    [("high", "high", 1), ("medium", "high", 1), ("low", "medium", 1), ("info", "medium", 1), ("high", "medium", 0)]
    + [("critical", "high", 0), ("info", "safe", 0), ("low", "safe", 0)],
)
def test_the_threshold_is_applied_to_the_mcp_severity_because_the_scanner_has_no_flag(bench, threshold, mode, code):
    tools_file(bench / "work")
    result, _, _, _ = run_script(bench, "mcp-scan", "mcp/tools.json", fail_on=threshold, mode=mode)
    assert result.returncode == code, result.stdout


@pytest.mark.parametrize("mode", ["crash", "error", "short", "weird", "duplicate", "wrong", "extra"])
def test_an_mcp_scan_that_did_not_cover_every_tool_fails_closed(bench, mode):
    tools_file(bench / "work")
    result, out, sarif, _ = run_script(bench, "mcp-scan", "mcp/tools.json", mode=mode)
    assert result.returncode == 1, result.stdout
    assert out["sarif"] == "false" and sarif is None


def test_tools_that_share_a_name_cannot_be_matched_to_results_and_are_refused(bench):
    tools_file(bench / "work", tools=[{"name": "a"}, {"name": "a"}])
    result, out, sarif, log = run_script(bench, "mcp-scan", "mcp/tools.json")
    assert result.returncode == 1 and log == [] and sarif is None
    assert "more than one tool named" in result.stdout


def test_a_result_for_a_tool_that_was_not_asked_about_is_named_in_the_error(bench):
    tools_file(bench / "work")
    result, _, _, _ = run_script(bench, "mcp-scan", "mcp/tools.json", mode="wrong")
    assert result.returncode == 1
    assert "not-requested" in result.stdout and "no result for" in result.stdout


@pytest.mark.parametrize(
    "body",
    ["not json", "[]", '{"tools": []}', '{"tools": "x"}', '{"tools": [1]}', "[" * 100000],
    ids=["text", "list", "empty", "string", "number", "deeply-nested"],
)
def test_a_file_that_is_not_a_tools_list_is_an_error_and_the_scanner_never_sees_it(bench, body):
    (bench / "work" / "bad.json").write_text(body)
    result, _, _, log = run_script(bench, "mcp-scan", "bad.json")
    assert result.returncode == 1 and log == []
    assert "not an MCP tools list" in result.stdout
