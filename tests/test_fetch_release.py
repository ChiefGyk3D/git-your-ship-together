"""fetch_release: the one place a workflow downloads a release asset (issue #372).

`scripts/fetch-release.sh` is the source; its marked block is inlined, byte for byte, into every step
that downloads a release asset (a reusable workflow cannot call a file of its own commit). These tests
run the real function against a fake `curl` and a fake `sleep` put first on PATH, and read the
workflows to hold the copies identical and to keep any other step from curling a release URL.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import textwrap
import time
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "fetch-release.sh"
WORKFLOW_FILES = sorted((REPO / ".github" / "workflows").glob("*.yml"))
ACTION_FILES = sorted((REPO / ".github" / "actions").glob("*/action.yml"))
BEGIN, END = "# BEGIN fetch_release", "# END fetch_release"
GOOD = b"payload"
TOKEN = "ghs_SecretTokenValue0123456789"
URL = "https://github.com/acme/tool/releases/download/v1.0.0/tool.tar.gz"


def block_of(text: str) -> str:
    """The marked block of a script, dedented, without the trailing newline."""
    lines = textwrap.dedent(text).split("\n")
    return "\n".join(lines[lines.index(BEGIN) : lines.index(END) + 1])


def source_block() -> str:
    return block_of(SCRIPT.read_text())


def sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


FAKE_CURL = """#!/usr/bin/env bash
# Fake curl: the plan file holds one outcome per call: an HTTP status ("504"), "timeout", or
# "200:<text>". It logs argv and the config read from stdin, and writes the body to -o.
dir=$FAKE_DIR
n=$(( $(cat "$dir/calls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/calls"
{ printf 'call %s:' "$n"; printf ' [%s]' "$@"; echo; } >> "$dir/argv.log"
{ echo "call $n"; cat; } >> "$dir/stdin.log"
plan=$(sed -n "${n}p" "$dir/plan"); [ -n "$plan" ] || plan=$(tail -n 1 "$dir/plan")
out=""; write=""
while [ $# -gt 0 ]; do
  case $1 in -o) out=$2; shift ;; -w) write=$2; shift ;; esac
  shift
done
case $plan in
  timeout) printf '000'; exit 28 ;;
  200:*) printf '%s' "${plan#200:}" > "$out"; printf '200'; exit 0 ;;
  *) printf '%s' "$plan"; exit 22 ;;
esac
"""
FAKE_SLEEP = """#!/usr/bin/env bash
echo "$1" >> "$FAKE_DIR/sleeps"
"""


@pytest.fixture
def box(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("curl", FAKE_CURL), ("sleep", FAKE_SLEEP)):
        p = bin_dir / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "work").mkdir()
    return tmp_path


def run(box, plan, *args, env=None, shell_flags="-eo pipefail", real_sleep=False, body=None):
    """Run the real fetch_release from the source script; return CompletedProcess."""
    (box / "plan").write_text("\n".join(plan) + "\n")
    out = box / "work" / "asset"
    call = body if body is not None else f'fetch_release "{URL}" "{out}" "{sha256(GOOD)}"'
    script = source_block() + "\n" + call + "\n"
    full_env = {
        "PATH": f"{box / 'bin'}{os.pathsep}{os.environ['PATH']}" if not real_sleep else os.environ["PATH"],
        "FAKE_DIR": str(box),
        "HOME": str(box),
        **(env or {}),
    }
    if real_sleep:
        # real sleep, fake curl only
        (box / "bin" / "sleep").unlink()
        full_env["PATH"] = f"{box / 'bin'}{os.pathsep}{os.environ['PATH']}"
    return subprocess.run(
        ["bash", *shell_flags.split(), "-c", script], env=full_env, capture_output=True, text=True, timeout=60
    )


def calls(box) -> int:
    return int((box / "calls").read_text()) if (box / "calls").exists() else 0


def sleeps(box) -> list[int]:
    p = box / "sleeps"
    return [int(x) for x in p.read_text().split()] if p.exists() else []


OK = "200:" + GOOD.decode()


def test_downloads_and_verifies_on_the_first_try(box):
    r = run(box, [OK])
    assert r.returncode == 0, r.stderr
    assert (box / "work" / "asset").read_bytes() == GOOD
    assert calls(box) == 1 and sleeps(box) == []
    assert [p.name for p in (box / "work").iterdir()] == ["asset"], "no temp file left behind"


def test_retries_a_504_then_succeeds(box):
    r = run(box, ["504", "timeout", OK])
    assert r.returncode == 0, r.stderr
    assert calls(box) == 3
    assert len(sleeps(box)) == 2


def test_gives_up_after_exactly_five_tries(box):
    r = run(box, ["504"])
    assert r.returncode != 0
    assert calls(box) == 5, "at most 5 tries"
    assert len(sleeps(box)) == 4
    assert not (box / "work" / "asset").exists()
    assert list((box / "work").iterdir()) == [], "no temp file left behind"
    assert "could not download" in r.stdout and "5 tries" in r.stdout


def test_backoff_is_exponential_with_jitter_and_bounded(box):
    for _ in range(5):  # jitter is random: sample it
        for f in ("calls", "sleeps"):
            (box / f).unlink(missing_ok=True)
        run(box, ["504"])
        got = sleeps(box)
        bases = [2, 4, 8, 16]
        assert len(got) == 4
        for pause, base in zip(got, bases, strict=True):
            assert base <= pause <= base + base // 2, (got, base)
        assert sum(got) < 170, "all the waiting fits the 3 minute budget"


def test_each_try_is_capped_and_the_budget_cannot_be_raised(box):
    run(box, ["504"], env={"FETCH_RELEASE_BUDGET": "99999"})
    caps = [int(m) for m in re.findall(r"\[--max-time\] \[(\d+)\]", (box / "argv.log").read_text())]
    assert len(caps) == 5 and all(0 < c <= 45 for c in caps), caps
    # worst case: five capped tries plus the longest waits is still under the clamp the code enforces
    assert 5 * 45 > 170 and "budget" in source_block() and '"$budget" -gt 170' in source_block()


def test_the_wall_clock_budget_stops_the_loop(box):
    started = time.monotonic()
    r = run(box, ["504"], env={"FETCH_RELEASE_BUDGET": "4", "FETCH_RELEASE_BASE_DELAY": "1"}, real_sleep=True)
    assert r.returncode != 0
    assert calls(box) < 5, "the budget ended it before the fifth try"
    assert time.monotonic() - started < 4 + 3


def test_checksum_mismatch_is_fatal_and_not_retried(box):
    r = run(box, ["200:tampered"])
    assert r.returncode != 0
    assert calls(box) == 1, "a hash mismatch is never retried"
    assert sleeps(box) == []
    assert not (box / "work" / "asset").exists(), "a file that fails the hash is not left in place"
    assert list((box / "work").iterdir()) == []
    assert "SHA-256 mismatch" in r.stdout


@pytest.mark.parametrize("bad", ["", "abc", "z" * 64, "a" * 63, "a" * 65, sha256(GOOD) + " "])
def test_the_checksum_is_mandatory(box, bad):
    out = box / "work" / "asset"
    r = run(box, [OK], body=f'fetch_release "{URL}" "{out}" "{bad}"')
    assert r.returncode != 0
    assert calls(box) == 0, "no download without a well-formed hash"
    assert not out.exists()


def test_a_missing_hash_argument_fails(box):
    r = run(box, [OK], body=f'fetch_release "{URL}" "{box / "work" / "asset"}"')
    assert r.returncode != 0 and calls(box) == 0


def test_an_uppercase_hash_is_accepted(box):
    out = box / "work" / "asset"
    r = run(box, [OK], body=f'fetch_release "{URL}" "{out}" "{sha256(GOOD).upper()}"')
    assert r.returncode == 0 and out.read_bytes() == GOOD


@pytest.mark.parametrize("url", ["http://github.com/a/b", "ftp://github.com/a", "github.com/a/b", ""])
def test_only_https_urls(box, url):
    out = box / "work" / "asset"
    r = run(box, [OK], body=f'fetch_release "{url}" "{out}" "{sha256(GOOD)}"')
    assert r.returncode != 0 and calls(box) == 0


def test_the_token_goes_to_github_com_through_stdin_only(box):
    r = run(box, ["504", OK], env={"FETCH_RELEASE_TOKEN": TOKEN})
    assert r.returncode == 0
    assert f"Authorization: Bearer {TOKEN}" in (box / "stdin.log").read_text()
    assert TOKEN not in (box / "argv.log").read_text(), "the token is never an argument"
    assert TOKEN not in r.stdout + r.stderr


def test_the_token_is_not_sent_to_another_host(box):
    out = box / "work" / "asset"
    body = f'fetch_release "https://example.com/a/releases/download/v1/x" "{out}" "{sha256(GOOD)}"'
    r = run(box, [OK], env={"FETCH_RELEASE_TOKEN": TOKEN}, body=body)
    assert r.returncode == 0
    assert TOKEN not in (box / "stdin.log").read_text() + (box / "argv.log").read_text()


def test_a_look_alike_host_does_not_get_the_token(box):
    out = box / "work" / "asset"
    body = f'fetch_release "https://github.com.evil.example/a/b" "{out}" "{sha256(GOOD)}"'
    run(box, [OK], env={"FETCH_RELEASE_TOKEN": TOKEN}, body=body)
    assert TOKEN not in (box / "stdin.log").read_text()


def test_a_token_with_odd_characters_is_not_put_in_the_config(box):
    run(box, [OK], env={"FETCH_RELEASE_TOKEN": 'x"\nurl = "file:///etc/passwd'})
    assert "passwd" not in (box / "stdin.log").read_text()
    assert "Authorization" not in (box / "stdin.log").read_text()


def test_the_token_is_dropped_after_a_401(box):
    r = run(box, ["401", OK], env={"FETCH_RELEASE_TOKEN": TOKEN})
    assert r.returncode == 0
    first, second = (box / "stdin.log").read_text().split("call 2")
    assert TOKEN in first and TOKEN not in second


def test_the_token_never_appears_in_a_trace(box):
    for plan in (["504", OK], ["504"], ["200:tampered"]):
        for f in ("calls", "sleeps", "argv.log", "stdin.log"):
            (box / f).unlink(missing_ok=True)
        r = run(box, plan, env={"FETCH_RELEASE_TOKEN": TOKEN}, shell_flags="-exo pipefail")
        assert "+ fetch_release" in r.stderr or "fetch_release" in r.stderr, "the trace was on"
        assert TOKEN not in r.stdout + r.stderr, plan


def test_a_trace_is_restored_for_the_caller(box):
    r = run(
        box,
        [OK],
        env={"FETCH_RELEASE_TOKEN": TOKEN},
        shell_flags="-exo pipefail",
        body=(f'fetch_release "{URL}" "{box / "work" / "asset"}" "{sha256(GOOD)}"\necho AFTER_FETCH'),
    )
    assert "+ echo AFTER_FETCH" in r.stderr, "set -x is back on after the call"


def test_a_trace_stays_off_when_it_was_off(box):
    r = run(
        box,
        [OK],
        env={"FETCH_RELEASE_TOKEN": TOKEN},
        body=(f'fetch_release "{URL}" "{box / "work" / "asset"}" "{sha256(GOOD)}"\necho AFTER_FETCH'),
    )
    assert "+ echo" not in r.stderr


def test_curl_is_never_told_to_follow_credentials_or_use_plain_http():
    text = source_block()
    for bad in ("--location-trusted", " -u ", "--user", "--insecure", " -k ", "--proto-default http", "wget"):
        assert bad not in text, bad
    assert "--proto '=https'" in text and "--proto-redir '=https'" in text and "-K -" in text


# ---------------------------------------------------------------- the workflows


def run_texts(path: Path):
    """(step name, run text) for every shell step of a workflow or composite action."""
    doc = yaml.safe_load(path.read_text())
    steps = []
    for job_name, job in (doc.get("jobs") or {}).items():
        steps += [(job_name, s) for s in job.get("steps") or []]
    steps += [("", s) for s in (doc.get("runs") or {}).get("steps") or []]
    return [(s.get("name", "(unnamed)"), s, job_name) for job_name, s in steps if "run" in s]


def release_steps():
    found = []
    for path in [*WORKFLOW_FILES, *ACTION_FILES]:
        for name, step, job_name in run_texts(path):
            if "/releases/download/" in step["run"]:
                found.append((path.name, name, step, job_name))
    return found


def without_helper(run: str) -> str:
    lines = run.split("\n")
    if not any(ln.strip() == BEGIN for ln in lines):
        return run
    b = next(i for i, ln in enumerate(lines) if ln.strip() == BEGIN)
    e = next(i for i, ln in enumerate(lines) if ln.strip() == END)
    return "\n".join(lines[:b] + lines[e + 1 :])


def violations(run: str) -> list[str]:
    """Why a step's script downloads a release asset outside the helper (empty when it does not)."""
    rest = "\n".join(ln for ln in without_helper(run).split("\n") if not ln.lstrip().startswith("#"))
    found = []
    if "/releases/download/" in rest and re.search(r"(?<![\w-])(curl|wget)\s", rest):
        found.append("curl or wget in a step that names a release URL")
    if re.search(r"(?<![\w-])(curl|wget)\s[^\n]*(releases/download|\$url\b|\$\{url\})", rest):
        found.append("curl or wget on a release URL")
    if "/releases/download/" in rest and "fetch_release " not in rest:
        found.append("a release URL with no fetch_release call")
    if re.search(r"(?<![\w-])(curl|wget)\s", rest) and "get.trivy.dev" in rest:
        found.append("an installer script piped from the network")
    return found


def test_the_guard_collected_every_release_download():
    steps = release_steps()
    assert len(steps) >= 14, [(f, n) for f, n, _, _ in steps]
    assert {f for f, _, _, _ in steps} >= {
        "arduino-ci.yml",
        "base-image-digest.yml",
        "bash-ci.yml",
        "container-release.yml",
        "python-package-release.yml",
        "security.yml",
        "tofu-ci.yml",
        "verify-published.yml",
    }


def test_no_workflow_downloads_a_release_outside_the_helper():
    bad = {(f, n): v for f, n, s, _ in release_steps() if (v := violations(s["run"]))}
    assert not bad, bad


def test_the_guard_bites():
    direct = 'set -e\ncurl -sSfL -o x "https://github.com/a/b/releases/download/v1/x"\n'
    via_var = 'url="https://github.com/a/b/releases/download/v1/x"\ncurl -sSfL -o x "$url"\n'
    wgot = "wget https://github.com/a/b/releases/download/v1/x\n"
    inside = f'{BEGIN}\ncurl -sS "$url"\n{END}\n'
    assert violations(direct) and violations(via_var) and violations(wgot)
    assert not violations(inside + 'fetch_release "https://github.com/a/b/releases/download/v1/x" o "$S"\n')
    # a curl hidden inside the marked block does not excuse one outside it
    assert violations(inside + direct)


def test_every_inlined_copy_is_byte_identical_to_the_script():
    want = source_block()
    steps = release_steps()
    for f, name, step, _ in steps:
        lines = step["run"].split("\n")
        assert BEGIN in [ln.strip() for ln in lines], (f, name, "no fetch_release block")
        assert block_of(step["run"]) == want, (f, name, "the inlined copy differs from scripts/fetch-release.sh")
        assert step["run"].count(BEGIN) == 1


def test_the_copy_check_bites():
    step = "    set -e\n" + textwrap.indent(source_block(), "    ") + "\n"
    assert block_of(step) == source_block()
    assert block_of(step.replace("tries=5", "tries=9")) != source_block()


# Jobs that follow `egress-policy-secretless` run harden-runner in audit, so they must hold no token at all
# (tests/test_egress_canary.py). Only a job already kept in block may hand the job token to the helper; the
# secretless ones download anonymously, with the same retries and the same mandatory hash.
TOKEN_JOBS = {("python-package-release.yml", "build"), ("tofu-ci.yml", "plan")}


def test_only_jobs_kept_in_block_hand_the_job_token_to_the_helper():
    from test_egress_canary import KEPT_BLOCK

    assert TOKEN_JOBS <= KEPT_BLOCK
    for f, name, step, job in release_steps():
        token = step.get("env", {}).get("FETCH_RELEASE_TOKEN")
        if (f, job) in TOKEN_JOBS:
            assert token == "${{ github.token }}", (f, job, name)
        else:
            assert token is None, (f, job, name, "a secretless job must hold no token")
            assert (f, job) not in KEPT_BLOCK or (f, job) in TOKEN_JOBS, (f, job, "kept in block: add it to TOKEN_JOBS")
        # the token is read from the environment, never interpolated into the script text
        assert "${{" not in step["run"], (f, name)


def test_every_download_step_keeps_a_fatal_hash_check():
    for f, name, step, _ in release_steps():
        assert re.search(r"sha256sum (--status )?-c -", step["run"]), (f, name)
        assert re.search(r'fetch_release [^\n]*"\$\{\w*SHA256\}"\s*$', without_helper(step["run"]), re.M), (f, name)
        assert "|| true" not in without_helper(step["run"]), (f, name)
        assert step.get("continue-on-error") in (None, False), (f, name)


def test_the_helper_adds_no_egress_host():
    # github.com redirects to release-assets.githubusercontent.com; both were already allowed.
    hosts = set(re.findall(r"https://([a-z0-9.-]+)/", source_block()))
    assert hosts <= {"github.com"}, hosts
