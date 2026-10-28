"""The default distro-setup-command survives a Kali mirror caught mid-sync (issue #228).

The default setup command of bash-ci.yml and python-ci.yml is real shell that runs as root in each image. These tests
pull that text out of the workflow and run it under bash against a fake `apt-get` (fails the first N `update` calls with
the exact error Kali's mirror gave), a fake `sleep` that records the pause, a fake `rm` (the real one would touch the
host's /var/lib/apt/lists), a fake `sed`, and a `grep` that says the image is not Kali or Parrot. Nothing here touches
the network or the host's apt state.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = ["bash-ci.yml", "python-ci.yml"]
ERROR = (
    "E: Failed to fetch http://kali.download/kali/dists/kali-rolling/main/binary-amd64/Packages.gz "
    "File has unexpected size (21787192 != 21783014). Mirror sync in progress?"
)


def default_setup(workflow: str) -> str:
    doc = yaml.safe_load((REPO / ".github" / "workflows" / workflow).read_text())
    triggers = doc.get("on") or doc[True]
    return triggers["workflow_call"]["inputs"]["distro-setup-command"]["default"]


def script(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def run_setup(tmp_path: Path, workflow: str, fail_updates: int):
    """Run the default setup with `update` failing `fail_updates` times; return (CompletedProcess, log lines)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    count = tmp_path / "updates"
    count.write_text("0")
    script(
        bin_dir / "apt-get",
        f"""echo "apt-get $*" >> '{log}'
case " $* " in
  *" update "*)
    n=$(( $(cat '{count}') + 1 )); echo $n > '{count}'
    if [ "$n" -le {fail_updates} ]; then echo '{ERROR}' >&2; exit 100; fi ;;
esac
exit 0
""",
    )
    script(bin_dir / "sleep", f"echo \"sleep $*\" >> '{log}'\n")
    script(bin_dir / "rm", f"echo \"rm $*\" >> '{log}'\n")
    script(bin_dir / "sed", "exit 0\n")
    script(bin_dir / "grep", "exit 1\n")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    proc = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", 'eval "$SETUP"'],
        env={**env, "SETUP": default_setup(workflow)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc, log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_a_healthy_mirror_needs_no_retry(tmp_path, workflow):
    proc, calls = run_setup(tmp_path, workflow, fail_updates=0)
    assert proc.returncode == 0, proc.stderr
    assert [c for c in calls if " update " in c + " "] and sum(" update " in c + " " for c in calls) == 1
    assert not [c for c in calls if c.startswith(("sleep", "rm"))]


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_a_mirror_mid_sync_is_retried_until_it_settles(tmp_path, workflow):
    """Five bad `update` calls in a row (the mirror did not hold for five readings) and a sixth that works."""
    proc, calls = run_setup(tmp_path, workflow, fail_updates=5)
    assert proc.returncode == 0, proc.stderr + "\n".join(calls)
    assert sum(" update " in c + " " for c in calls) == 6
    assert any(" install " in c + " " for c in calls)
    # A stale partial index is never reused, and each pause is bounded.
    assert sum(c.startswith("rm -rf /var/lib/apt/lists/") for c in calls) == 5
    pauses = [int(c.split()[1]) for c in calls if c.startswith("sleep")]
    assert len(pauses) == 5 and all(20 <= p <= 60 for p in pauses), pauses


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_a_mirror_that_never_settles_fails_for_real_with_the_apt_error(tmp_path, workflow):
    proc, calls = run_setup(tmp_path, workflow, fail_updates=99)
    assert proc.returncode != 0
    assert ERROR in proc.stderr
    assert sum(" update " in c + " " for c in calls) == 6
    assert not any(" install " in c + " " for c in calls)
    assert "6 attempts" in proc.stderr
