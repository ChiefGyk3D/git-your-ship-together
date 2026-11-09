"""scripts/trivy_sarif_summary.py: what a failed Trivy image scan found, printed from its own SARIF (issue #383).

The script prints the totals by severity and one row per (rule id, file path), and a hint when every secret hit is
under site-packages. It never prints the matched text. Its marked block is inlined, byte for byte, into the
"Summarize a failed Trivy scan" step of container-release.yml (both build jobs); these tests run the script on
fixtures, hold the copies identical, and pin the step so it can never change pass or fail.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from test_container_release_digests import RELEASE
from test_workflows import jobs, load, steps_of

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "trivy_sarif_summary.py"
BEGIN, END = "# BEGIN trivy_sarif_summary", "# END trivy_sarif_summary"
STEP = "Summarize a failed Trivy scan"
HINT = (
    "All secret hits are under site-packages: set skip-secret-scan-in-site-packages: true on this call "
    "to skip secret rules there (CVE scanning stays on)."
)
# Text a real SARIF carries in `message`, `snippet` and `help`: it must never reach the output.
LEAK = "LEAK-SENTINEL-matched-secret-text"

SITE = "opt/venv/lib/python3.14/site-packages/anthropic/types/x.py"
APP = "app/settings.py"


def rule(rule_id: str, kind: str, severity: str, score: str | None = None) -> dict:
    props: dict = {"tags": [kind, "security", severity]}
    if score:
        props["security-severity"] = score
    return {"id": rule_id, "shortDescription": {"text": LEAK}, "help": {"text": LEAK}, "properties": props}


def result(rule_id: str, path: str, level: str = "error") -> dict:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"Artifact: {path}\nMatch: {LEAK}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path, "uriBaseId": "ROOTPATH"},
                    "region": {"startLine": 3, "snippet": {"text": LEAK}},
                }
            }
        ],
    }


def sarif(rules: list[dict], results: list[dict]) -> dict:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "rules": rules}}, "results": results}]}


SECRET = rule("gcp-service-account", "secret", "HIGH", "8.0")
CVE = rule("CVE-2026-0001", "vulnerability", "CRITICAL", "9.8")


def run(tmp_path: Path, doc: object | None, *, raw: str | None = None) -> subprocess.CompletedProcess[str]:
    target = tmp_path / "trivy-results.sarif"
    if raw is not None:
        target.write_text(raw)
    elif doc is not None:
        target.write_text(json.dumps(doc))
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), str(target)], capture_output=True, text=True, check=False, timeout=60
    )


def test_secret_hits_under_site_packages_print_a_table_and_the_hint(tmp_path):
    doc = sarif([SECRET], [result("gcp-service-account", SITE)] * 3 + [result("gcp-service-account", SITE + "2")])
    out = run(tmp_path, doc)
    assert out.returncode == 0
    lines = out.stdout.splitlines()
    assert any("HIGH=4" in ln and "total 4" in ln for ln in lines), out.stdout
    assert any(ln.split()[:4] == ["3", "secret", "HIGH", "gcp-service-account"] and ln.endswith(SITE) for ln in lines)
    assert any(ln.split()[:1] == ["1"] and ln.endswith(SITE + "2") for ln in lines)
    assert lines[-1] == HINT


def test_secret_hits_in_app_code_get_no_hint(tmp_path):
    out = run(tmp_path, sarif([SECRET], [result("gcp-service-account", APP)]))
    assert out.returncode == 0 and APP in out.stdout
    assert "skip-secret-scan-in-site-packages" not in out.stdout


def test_one_secret_hit_outside_site_packages_withholds_the_hint(tmp_path):
    out = run(tmp_path, sarif([SECRET], [result("gcp-service-account", SITE), result("gcp-service-account", APP)]))
    assert SITE in out.stdout and APP in out.stdout
    assert "skip-secret-scan-in-site-packages" not in out.stdout


def test_cve_only_results_get_totals_and_no_hint(tmp_path):
    out = run(tmp_path, sarif([CVE], [result("CVE-2026-0001", "usr/lib/python3.12/site-packages/pkg/mod.py")]))
    assert out.returncode == 0
    assert "CRITICAL=1" in out.stdout and "CVE-2026-0001" in out.stdout and "other" in out.stdout
    assert "skip-secret-scan-in-site-packages" not in out.stdout


def test_secret_rows_come_before_other_rows(tmp_path):
    out = run(tmp_path, sarif([CVE, SECRET], [result("CVE-2026-0001", "lib/a"), result("gcp-service-account", APP)]))
    assert out.stdout.index("gcp-service-account") < out.stdout.index("CVE-2026-0001")


def test_severity_falls_back_to_the_score_then_the_level(tmp_path):
    bare = {"id": "r-score", "properties": {"security-severity": "5.5"}}
    plain = {"id": "r-level"}
    out = run(tmp_path, sarif([bare, plain], [result("r-score", "a"), result("r-level", "b", level="warning")]))
    assert "MEDIUM=2" in out.stdout


@pytest.mark.parametrize(
    ("doc", "raw", "words"),
    [
        (None, None, "no SARIF"),
        (None, "", "could not summarize"),
        (None, "{not json", "could not summarize"),
        (None, "[1, 2]", "not a SARIF object"),
        ({}, None, "No results"),
        ({"runs": []}, None, "No results"),
        ({"runs": [None, {"results": [3, {"ruleId": 7}]}]}, None, "total 1"),
        (sarif([SECRET], []), None, "No results"),
    ],
)
def test_missing_empty_or_odd_files_print_a_line_and_exit_zero(tmp_path, doc, raw, words):
    out = run(tmp_path, doc, raw=raw)
    assert out.returncode == 0, out.stderr
    assert words in out.stdout
    assert "Traceback" not in out.stdout + out.stderr


def test_no_message_snippet_or_help_text_can_appear_in_the_output(tmp_path):
    doc = sarif([SECRET, CVE], [result("gcp-service-account", SITE), result("CVE-2026-0001", APP)])
    assert LEAK in json.dumps(doc)  # the fixture does carry it, in message, snippet, description and help
    out = run(tmp_path, doc)
    assert out.returncode == 0 and "gcp-service-account" in out.stdout
    assert LEAK not in out.stdout + out.stderr
    assert "Match:" not in out.stdout and "Artifact:" not in out.stdout


def test_the_leak_check_bites(tmp_path):
    # a rule id that carries the sentinel is printed (ids are data we show), so the assertion above is not vacuous
    out = run(tmp_path, sarif([], [result(LEAK, APP)]))
    assert LEAK in out.stdout


def test_hostile_ids_and_paths_are_escaped_and_cut(tmp_path):
    evil = "x\n::error::injected\r" + chr(27) + "[31m" + "a" * 500
    out = run(tmp_path, sarif([], [result(evil, evil)]))
    assert out.returncode == 0
    assert not [ln for ln in out.stdout.splitlines() if ln.startswith("::")]
    assert chr(27) not in out.stdout and "\r" not in out.stdout
    assert "\\n::error::injected" in out.stdout and "..." in out.stdout
    assert "a" * 201 not in out.stdout


def test_the_table_is_bounded(tmp_path):
    results = [result("gcp-service-account", f"opt/venv/lib/python3.14/site-packages/p{i}.py") for i in range(120)]
    out = run(tmp_path, sarif([SECRET], results))
    assert len(out.stdout.splitlines()) < 70
    assert "and 70 more (rule, path) pairs" in out.stdout and "total 120" in out.stdout
    assert out.stdout.splitlines()[-1] == HINT  # the hint judges every hit, not only the printed rows


def test_a_directory_is_not_a_sarif(tmp_path):
    out = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), str(tmp_path)], capture_output=True, text=True, check=False, timeout=60
    )
    assert out.returncode == 0 and "no SARIF" in out.stdout


# --- the inlined copies ----------------------------------------------------------------------------------------


def block_of(text: str) -> str:
    lines = textwrap.dedent(text).split("\n")
    return "\n".join(lines[lines.index(BEGIN) : lines.index(END) + 1])


def build_steps() -> list[tuple[str, dict]]:
    doc = load(RELEASE)
    return [(name, s) for name, job in jobs(doc).items() for s in steps_of(job) if s.get("name") == STEP]


def test_the_step_is_in_both_build_jobs():
    assert sorted(name for name, _ in build_steps()) == ["build", "build-local"]


def test_every_inlined_copy_is_byte_identical_to_the_script():
    want = block_of(SCRIPT.read_text())
    assert want.startswith(BEGIN) and want.endswith(END)
    for name, step in build_steps():
        assert block_of(step["run"]) == want, (name, "the inlined copy differs from scripts/trivy_sarif_summary.py")
        assert step["run"].count(BEGIN) == 1


def test_the_copy_check_bites():
    want = block_of(SCRIPT.read_text())
    assert block_of(want.replace("MAX_ROWS = 50", "MAX_ROWS = 51")) != want
    assert want.count("\n") > 50  # a real block, not an empty marker pair


def test_the_step_runs_only_after_a_failure_reads_only_the_sarif_and_cannot_change_the_verdict():
    doc = load(RELEASE)
    seen = 0
    for name, job in jobs(doc).items():
        steps = steps_of(job)
        names = [s.get("name") for s in steps]
        if STEP not in names:
            continue
        seen += 1
        step = steps[names.index(STEP)]
        scan, upload = names.index("Scan the image with Trivy"), names.index("Upload Trivy results to the Security tab")
        assert scan < names.index(STEP) < upload, name
        assert step["if"] == "inputs.trivy && failure()", name
        assert step.get("timeout-minutes") and step["timeout-minutes"] <= 5, name
        assert "continue-on-error" not in step, name  # the script exits 0 itself; no verdict is weakened
        assert "env" not in step and "with" not in step, name
        assert step["run"].split("\n", 1)[0] == "python3 -I - trivy-results.sarif <<'PY'", name
        assert step["run"].rstrip().endswith("\nPY"), name
        for banned in ("docker", "trivy ", "secrets.", "GITHUB_ENV", "exit 1", "http"):
            assert banned not in step["run"], (name, banned)
        assert steps[scan]["with"]["exit-code"] == "${{ inputs.trivy-exit-code }}", name
    assert seen == 2
