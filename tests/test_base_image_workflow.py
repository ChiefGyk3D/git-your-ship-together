"""The compare step of base-image-digest.yml, run for real under bash against a fake docker and a fake trivy.

The step is the networked part around scripts/base_image_digest.py: it resolves today's digest of each tag, scans both
digests, and must fail on a fixable finding and on any lookup or scan it could not finish. A step that passes when it
could not look is the failure these tests exist to catch.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
TEXT = (REPO / ".github" / "workflows" / "base-image-digest.yml").read_text()
STEPS = yaml.safe_load(TEXT)["jobs"]["check"]["steps"]
HELPER_STEP = next(s for s in STEPS if s.get("name") == "Write the helper")
COMPARE = next(s for s in STEPS if "Compare the pinned" in s.get("name", ""))
D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
VULN = {
    "VulnerabilityID": "CVE-2026-0001",
    "PkgName": "libssl3",
    "InstalledVersion": "1",
    "FixedVersion": "2",
    "Severity": "HIGH",
}


def helper_text() -> str:
    """The heredoc body of the step; YAML has already removed the block's indent."""
    return HELPER_STEP["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0] + "\n"


def report(*vulns):
    return json.dumps({"Results": [{"Target": "t", "Vulnerabilities": list(vulns)}] if vulns else []})


def run_step(
    tmp_path: Path, *, current: str, pinned_report: str, current_report: str, trivy_fails: bool = False, exit_code="1"
):
    temp = tmp_path / "runner"
    (temp / "trivy-bin").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # The helper is the workflow's own heredoc, extracted from the step the way the runner would write it.
    (temp / "base_image_digest.py").write_text(helper_text())
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.14-slim@{D1}\n")
    (bindir / "docker").write_text(f'#!/bin/bash\necho \'{{"digest": "{current}"}}\'\n')
    (temp / "trivy-bin" / "trivy").write_text(
        "#!/bin/bash\n"
        + ("exit 3\n" if trivy_fails else "")
        + 'for a in "$@"; do prev="$last"; last="$a"; [ "$prev" = "--output" ] && out="$a"; done\n'
        + f"case \"${{@: -1}}\" in *{D1}) printf '%s' '{pinned_report}' > \"$out\";;"
        + f" *) printf '%s' '{current_report}' > \"$out\";; esac\n"
    )
    for p in (bindir / "docker", temp / "trivy-bin" / "trivy"):
        p.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(temp),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "DOCKERFILE": "Dockerfile",
        "ALLOW_UNPINNED": "false",
        "PLATFORM": "linux/amd64",
        "SEVERITY": "CRITICAL,HIGH",
        "IGNORE_UNFIXED": "true",
        "TRIVYIGNORES": "",
        "EXIT_CODE": exit_code,
    }
    return subprocess.run(
        ["bash", "-c", COMPARE["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


def test_the_helper_the_step_writes_is_the_script(tmp_path):
    assert helper_text() == (REPO / "scripts" / "base_image_digest.py").read_text()


def test_an_unmoved_tag_passes_without_scanning(tmp_path):
    done = run_step(tmp_path, current=D1, pinned_report="{}", current_report="{}", trivy_fails=True)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "the pin is what the tag points to today" in done.stdout


def test_a_moved_tag_that_fixes_a_finding_fails_and_writes_the_summary(tmp_path):
    done = run_step(tmp_path, current=D2, pinned_report=report(VULN), current_report=report())
    assert done.returncode == 1, done.stdout + done.stderr
    assert "CVE-2026-0001" in done.stdout
    assert D2 in (tmp_path / "summary.md").read_text()


def test_report_only_mode_does_not_fail_on_the_same_finding(tmp_path):
    done = run_step(tmp_path, current=D2, pinned_report=report(VULN), current_report=report(), exit_code="0")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "CVE-2026-0001" in done.stdout


def test_a_moved_tag_with_the_same_findings_passes(tmp_path):
    done = run_step(tmp_path, current=D2, pinned_report=report(VULN), current_report=report(VULN))
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("current", ["", "null", "sha256:short"])
def test_a_digest_that_cannot_be_resolved_fails(tmp_path, current):
    done = run_step(tmp_path, current=current, pinned_report=report(VULN), current_report=report())
    assert done.returncode == 1, done.stdout + done.stderr


def test_a_failed_scan_fails_instead_of_reading_as_clean(tmp_path):
    done = run_step(tmp_path, current=D2, pinned_report=report(VULN), current_report=report(), trivy_fails=True)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "Trivy failed" in done.stdout


def test_a_current_report_that_is_not_a_report_fails(tmp_path):
    done = run_step(tmp_path, current=D2, pinned_report=report(VULN), current_report="{}")
    assert done.returncode == 1, done.stdout + done.stderr
