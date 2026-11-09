"""scripts/check_pin_comments.py and pin-comments.yml: a `# vX.Y.Z` comment must name the pinned commit.

The resolver is faked everywhere except one process-level test, which talks to a local fake API server.
Every negative case has a positive twin, and the unverifiable cases (network down, rate limit, garbage) must
never come out green.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_pin_comments.py"
WORKFLOW = REPO / ".github" / "workflows" / "pin-comments.yml"
A = "a" * 40
B = "b" * 40

spec = importlib.util.spec_from_file_location("check_pin_comments", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules["check_pin_comments"] = mod
spec.loader.exec_module(mod)


def write(root: Path, text: str, name=".github/workflows/ci.yml"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def uses(sha=A, comment="# v1.2.3", action="actions/checkout"):
    return f"jobs:\n  a:\n    steps:\n      - uses: {action}@{sha} {comment}\n"


class Fake:
    """A resolver: maps (repo, tag) to a commit, to None (no such tag) or to an exception to raise."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, repo, tag):
        self.calls.append((repo, tag))
        got = self.table.get((repo, tag))
        if isinstance(got, Exception):
            raise got
        return got


def check(root, table, **kw):
    fake = Fake(table)
    return mod.run(root, fake, **kw), fake


def test_a_matching_comment_passes(tmp_path):
    write(tmp_path, uses())
    (problems, notes), fake = check(tmp_path, {("actions/checkout", "v1.2.3"): A})
    assert problems == [] and notes == [] and fake.calls == [("actions/checkout", "v1.2.3")]


def test_a_comment_naming_another_commit_fails_with_both(tmp_path):
    write(tmp_path, uses())
    (problems, _), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): B})
    assert len(problems) == 1 and "mismatch" in problems[0] and A in problems[0] and B in problems[0]


def test_a_tag_that_does_not_exist_fails(tmp_path):
    write(tmp_path, uses())
    (problems, _), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): None})
    assert len(problems) == 1 and "no such tag" in problems[0]


def test_a_missing_version_comment_fails(tmp_path):
    write(tmp_path, uses(comment=""))
    (problems, _), fake = check(tmp_path, {})
    assert len(problems) == 1 and "no version comment" in problems[0] and fake.calls == []


def test_a_comment_that_is_not_a_version_fails(tmp_path):
    write(tmp_path, uses(comment="# latest"))
    (problems, _), _ = check(tmp_path, {})
    assert len(problems) == 1 and "no version comment" in problems[0]


def test_a_trailing_zizmor_suppression_after_the_version_is_fine(tmp_path):
    write(tmp_path, uses(comment="# v1.2.3 zizmor: ignore[x]"))
    (problems, _), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): A})
    assert problems == []


def test_unpinned_local_and_docker_uses_are_not_this_checks_business(tmp_path):
    write(
        tmp_path,
        "jobs:\n  a:\n    uses: ./.github/workflows/x.yml\n  b:\n    steps:\n"
        "      - uses: docker://alpine:3\n      - uses: actions/checkout@v4\n",
    )
    (problems, notes), fake = check(tmp_path, {})
    assert problems == [] and fake.calls == []


def test_subpath_actions_resolve_against_the_owner_repo(tmp_path):
    write(tmp_path, uses(action="github/codeql-action/analyze", comment="# v3"))
    (problems, _), fake = check(tmp_path, {("github/codeql-action", "v3"): A})
    assert problems == [] and fake.calls == [("github/codeql-action", "v3")]


def test_each_repo_and_tag_is_looked_up_once(tmp_path):
    write(tmp_path, uses() + uses())
    write(tmp_path, uses(), ".github/workflows/b.yaml")
    (problems, _), fake = check(tmp_path, {("actions/checkout", "v1.2.3"): A})
    assert problems == [] and len(fake.calls) == 1


def test_composite_actions_are_scanned_too(tmp_path):
    write(tmp_path, uses(sha=B), ".github/actions/x/action.yml")
    (problems, _), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): A})
    assert len(problems) == 1 and "action.yml" in problems[0]


def test_a_commented_out_uses_is_ignored(tmp_path):
    write(tmp_path, "# - uses: actions/checkout@" + B + " # v9\n" + uses())
    (problems, _), fake = check(tmp_path, {("actions/checkout", "v1.2.3"): A})
    assert problems == [] and len(fake.calls) == 1


@pytest.mark.parametrize("err", [TimeoutError("slow"), OSError("down"), ValueError("garbage")])
def test_an_unverifiable_lookup_is_never_green(tmp_path, err):
    write(tmp_path, uses())
    (problems, notes), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): err})
    assert problems == [] and len(notes) == 1 and "unverified" in notes[0]
    assert mod.exit_code(problems, notes, "fail") == 1
    assert mod.exit_code(problems, notes, "warn") == 0  # the loud, explicit opt-out
    assert mod.exit_code([], [], "fail") == 0


def test_a_real_mismatch_still_fails_in_warn_mode(tmp_path):
    write(tmp_path, uses())
    (problems, notes), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): B})
    assert mod.exit_code(problems, notes, "warn") == 1


def test_the_lookup_budget_is_bounded_and_the_rest_reported_unverified(tmp_path):
    body = "".join(uses(action=f"o/r{i}", comment="# v1") for i in range(5))
    write(tmp_path, body)
    (problems, notes), fake = check(tmp_path, {(f"o/r{i}", "v1"): A for i in range(5)}, max_lookups=2)
    assert len(fake.calls) == 2 and len(notes) == 3 and all("budget" in n for n in notes)


def test_the_deadline_stops_the_lookups(tmp_path):
    write(tmp_path, uses())
    (problems, notes), fake = check(tmp_path, {}, deadline=-1.0)
    assert fake.calls == [] and len(notes) == 1 and "unverified" in notes[0]


def test_files_with_no_pinned_uses_are_fine(tmp_path):
    write(tmp_path, "on: push\n")
    (problems, notes), _ = check(tmp_path, {})
    assert problems == [] and notes == []


def test_nothing_to_scan_is_a_failure_not_a_pass(tmp_path):
    (problems, _), _ = check(tmp_path, {})
    assert len(problems) == 1 and "nothing to check" in problems[0]


def test_output_values_cannot_forge_a_workflow_command(tmp_path):
    write(tmp_path, uses(), ".github/workflows/a\n::error::x.yml")
    (problems, _), _ = check(tmp_path, {("actions/checkout", "v1.2.3"): B})
    assert problems and all("\n" not in p for p in problems)


# --- the real resolver against a local fake API ------------------------------------------------


@pytest.fixture
def api():
    answers = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            got = answers.get(self.path)
            if got is None:
                self.send_response(404)
                self.end_headers()
                return
            code, body = got
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", answers
    server.shutdown()
    server.server_close()
    thread.join(5)


def process(root, base, *args):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(root), "--api-base", base, *args],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )


def test_process_passes_on_a_match_and_fails_on_a_mismatch(tmp_path, api):
    base, answers = api
    write(tmp_path, uses())
    answers["/repos/actions/checkout/commits/refs/tags/v1.2.3"] = (200, {"sha": A})
    done = process(tmp_path, base)
    assert done.returncode == 0 and done.stdout.startswith("ok"), done.stdout + done.stderr
    answers["/repos/actions/checkout/commits/refs/tags/v1.2.3"] = (200, {"sha": B})
    done = process(tmp_path, base)
    assert done.returncode == 1 and "FAIL" in done.stdout


def test_process_404_is_a_missing_tag_and_5xx_or_garbage_is_unverified(tmp_path, api):
    base, answers = api
    write(tmp_path, uses())
    done = process(tmp_path, base)  # the fake answers 404
    assert done.returncode == 1 and "no such tag" in done.stdout
    for reply in ((500, {}), (403, {"message": "rate limit"}), (200, b"not json"), (200, {"sha": "zz"})):
        answers["/repos/actions/checkout/commits/refs/tags/v1.2.3"] = reply
        done = process(tmp_path, base)
        assert done.returncode == 1 and "unverified" in done.stdout, (reply, done.stdout)
        assert process(tmp_path, base, "--unverified", "warn").returncode == 0


def test_process_with_the_server_gone_is_unverified_not_green(tmp_path):
    write(tmp_path, uses())
    done = process(tmp_path, "http://127.0.0.1:9")
    assert done.returncode == 1 and "unverified" in done.stdout


# --- the reusable workflow carries this script byte for byte -----------------------------------


def test_the_workflow_inlines_the_script_byte_for_byte():
    text = WORKFLOW.read_text()
    start = text.index("python3 -I - ")
    body = text[text.index("<<'PY'\n", start) + len("<<'PY'\n") :]
    body = body[: body.rindex("\n          PY")]
    inlined = "".join(line[10:] + "\n" if line.strip() else "\n" for line in body.split("\n"))
    assert inlined == SCRIPT.read_text()
