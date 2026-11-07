"""scripts/check_vendored_drift.py and vendored-drift.yml: a vendored file may not drift from its pin.

The script is run as a process (the way the workflow runs it) over lock files written into a temp
directory. Lock files and vendored files are data from the repository under test, so the hostile cases
here are the point: a lock that points outside the root, a symlink, a FIFO, a duplicate key, a value
that tries to forge a log line. Every negative case also has a positive twin, so a check that fails
everything cannot pass this file.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_vendored_drift.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
BODY = b"--brand: #123456;\n"


def sha(data: bytes = BODY) -> str:
    return hashlib.sha256(data).hexdigest()


def lock_doc(**over):
    doc = {
        "vendored": "vendor/tokens.css",
        "sha256": sha(),
        "source": {"repo": "example/brand", "path": "dist/tokens.css", "commit": COMMIT},
    }
    doc.update(over)
    return doc


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "tokens.css").write_bytes(BODY)
    (tmp_path / "vendor" / "tokens.lock.json").write_text(json.dumps(lock_doc()))
    return tmp_path


def run(root: Path, *args: str, locks=("vendor/tokens.lock.json",), timeout=60):
    cmd = [sys.executable, "-I", str(SCRIPT), "--root", str(root)]
    for lock in locks:
        cmd += ["--lock", lock]
    return subprocess.run(
        [*cmd, *args], capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, check=False
    )


def write_lock(tree: Path, doc, name="vendor/tokens.lock.json"):
    text = doc if isinstance(doc, str) else json.dumps(doc)
    (tree / name).write_text(text)


def test_a_matching_pin_passes(tree):
    done = run(tree)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.startswith("ok")


def test_a_changed_vendored_file_fails_and_names_both_hashes(tree):
    (tree / "vendor" / "tokens.css").write_bytes(BODY + b"x")
    done = run(tree)
    assert done.returncode == 1
    assert "hash mismatch" in done.stdout and sha() in done.stdout and sha(BODY + b"x") in done.stdout


def test_no_lock_at_all_fails(tree):
    done = run(tree, locks=())
    assert done.returncode == 1 and "nothing to check" in done.stdout


def test_a_missing_lock_fails(tree):
    done = run(tree, locks=("vendor/nope.json",))
    assert done.returncode == 1 and "cannot read the lock" in done.stdout


def test_a_missing_vendored_file_fails(tree):
    (tree / "vendor" / "tokens.css").unlink()
    done = run(tree)
    assert done.returncode == 1 and "not a regular file" in done.stdout


def test_two_locks_are_both_checked_and_a_repeat_is_refused(tree):
    (tree / "vendor" / "b.css").write_bytes(b"b")
    write_lock(tree, lock_doc(vendored="vendor/b.css", sha256=sha(b"x")), "vendor/b.lock.json")
    done = run(tree, locks=("vendor/tokens.lock.json", "vendor/b.lock.json"))
    assert done.returncode == 1 and "vendor/b.css" in done.stdout and "tokens.css" not in done.stdout
    twice = run(tree, locks=("vendor/tokens.lock.json", "./vendor/tokens.lock.json"))
    assert twice.returncode == 1 and "listed twice" in twice.stdout


# --- hostile lock files -----------------------------------------------------------------------


BAD_LOCKS = {
    "not an object": "[]",
    "not json": "{nope",
    "empty": "",
    "duplicate key": '{"vendored": "vendor/tokens.css", "vendored": "vendor/tokens.css", '
    f'"sha256": "{sha()}", "source": {{"repo": "a/b", "path": "p", "commit": "{COMMIT}"}}}}',
    "uppercase sha": lock_doc(sha256=sha().upper()),
    "short sha": lock_doc(sha256=sha()[:63]),
    "sha with newline": lock_doc(sha256=sha() + "\n"),
    "sha not a string": lock_doc(sha256=12),
    "short commit": lock_doc(source={"repo": "a/b", "path": "p", "commit": COMMIT[:39]}),
    "branch as commit": lock_doc(source={"repo": "a/b", "path": "p", "commit": "main"}),
    "repo without owner": lock_doc(source={"repo": "brand", "path": "p", "commit": COMMIT}),
    "repo with a space": lock_doc(source={"repo": "a b/c", "path": "p", "commit": COMMIT}),
    "source path traversal": lock_doc(source={"repo": "a/b", "path": "../p", "commit": COMMIT}),
    "source missing": {"vendored": "vendor/tokens.css", "sha256": sha()},
    "source not an object": lock_doc(source="a/b"),
    "extra key (a typo for a real one)": lock_doc(sha265=sha()),
    "extra source key": lock_doc(source={"repo": "a/b", "path": "p", "commit": COMMIT, "ref": "main"}),
    "vendored absolute": lock_doc(vendored="/etc/passwd"),
    "vendored traversal": lock_doc(vendored="../outside"),
    "vendored traversal inside": lock_doc(vendored="vendor/../../outside"),
    "vendored backslash": lock_doc(vendored="vendor\\tokens.css"),
    "vendored NUL": lock_doc(vendored="vendor/tokens.css\u0000.png"),
    "vendored empty": lock_doc(vendored=""),
    "vendored a list": lock_doc(vendored=["vendor/tokens.css"]),
    "vendored a directory": lock_doc(vendored="vendor"),
}


@pytest.mark.parametrize("doc", BAD_LOCKS.values(), ids=BAD_LOCKS.keys())
def test_a_malformed_or_hostile_lock_fails_without_a_traceback(tree, doc):
    write_lock(tree, doc)
    done = run(tree)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "FAIL" in done.stdout and "Traceback" not in done.stderr


def test_deeply_nested_json_fails_cleanly(tree):
    write_lock(tree, "[" * 100000 + "]" * 100000)
    done = run(tree)
    assert done.returncode == 1 and "Traceback" not in done.stderr


def test_an_oversize_lock_is_refused_unread(tree):
    write_lock(tree, '{"pad": "' + "a" * (1 << 21) + '"}')
    done = run(tree)
    assert done.returncode == 1 and "larger than" in done.stdout


def test_a_symlink_out_of_the_root_is_refused(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.css"
    outside.write_bytes(BODY)  # the same bytes: only the containment check can fail it
    (tree / "vendor" / "tokens.css").unlink()
    os.symlink(outside, tree / "vendor" / "tokens.css")
    done = run(tree)
    assert done.returncode == 1 and "stays inside the root" in done.stdout


def test_a_symlink_that_stays_inside_the_root_is_followed(tree):
    (tree / "real.css").write_bytes(BODY)
    (tree / "vendor" / "tokens.css").unlink()
    os.symlink(tree / "real.css", tree / "vendor" / "tokens.css")
    assert run(tree).returncode == 0


def test_a_lock_symlinked_out_of_the_root_is_refused(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "x.lock.json"
    outside.write_text(json.dumps(lock_doc()))
    os.symlink(outside, tree / "vendor" / "evil.lock.json")
    done = run(tree, locks=("vendor/evil.lock.json",))
    assert done.returncode == 1 and "stays inside the root" in done.stdout


def test_an_absolute_lock_outside_the_root_is_refused(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "x.lock.json"
    outside.write_text(json.dumps(lock_doc()))
    done = run(tree, locks=(str(outside),))
    assert done.returncode == 1 and "stays inside the root" in done.stdout


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_fifo_as_the_vendored_file_does_not_hang(tree):
    (tree / "vendor" / "tokens.css").unlink()
    os.mkfifo(tree / "vendor" / "tokens.css")
    done = run(tree, timeout=20)
    assert done.returncode == 1 and "not a regular file" in done.stdout


def test_a_value_cannot_forge_a_log_line_or_a_workflow_command(tree):
    evil = "x\n::error::forged\nFAIL fake"
    write_lock(tree, lock_doc(vendored=evil))
    done = run(tree)
    assert done.returncode == 1
    assert all(not line.startswith("::") for line in done.stdout.splitlines())
    assert "\nFAIL fake" not in done.stdout


# --- generator --------------------------------------------------------------------------------


def make_generator(tree: Path, body: str) -> str:
    (tree / "gen.py").write_text(body)
    return f"{sys.executable} gen.py"


def test_a_generator_whose_check_passes_is_accepted_and_is_given_check(tree):
    cmd = make_generator(tree, "import sys; sys.exit(0 if sys.argv[1:] == ['--check'] else 9)")
    done = run(tree, "--generator-command", cmd)
    assert done.returncode == 0, done.stdout
    assert "generator" in done.stdout


def test_a_generator_whose_check_fails_is_drift_and_its_output_is_shown_quoted(tree):
    cmd = make_generator(
        tree, "import sys; print('::error::forged'); print('stale: out.css', file=sys.stderr); sys.exit(1)"
    )
    done = run(tree, "--generator-command", cmd)
    assert done.returncode == 1
    assert "drift: generator --check exited 1" in done.stdout and "stale: out.css" in done.stdout
    assert all(not line.startswith("::") for line in done.stdout.splitlines())


def test_the_pin_and_the_generator_are_both_reported(tree):
    (tree / "vendor" / "tokens.css").write_bytes(b"changed")
    cmd = make_generator(tree, "import sys; sys.exit(1)")
    done = run(tree, "--generator-command", cmd)
    assert "hash mismatch" in done.stdout and "generator --check" in done.stdout


def test_the_generator_runs_without_a_shell(tree):
    marker = tree / "pwned"
    cmd = make_generator(tree, "import sys; sys.exit(0 if sys.argv[1:] == ['--check'] else 1)") + f" ; touch {marker}"
    done = run(tree, "--generator-command", cmd)
    assert not marker.exists()
    assert done.returncode == 1  # gen.py received `;`, `touch` and the path as arguments, and said no


def test_a_missing_generator_fails(tree):
    done = run(tree, "--generator-command", "no-such-generator-binary")
    assert done.returncode == 1 and "could not start" in done.stdout


def test_an_unparsable_generator_command_fails(tree):
    done = run(tree, "--generator-command", "python3 'unterminated")
    assert done.returncode == 1 and "cannot be parsed" in done.stdout


def test_a_blank_generator_command_means_no_generator_and_whitespace_is_refused(tree):
    assert run(tree, "--generator-command", "").returncode == 0
    done = run(tree, "--generator-command", "   ")
    assert done.returncode == 1 and "empty" in done.stdout


def test_the_generator_does_not_inherit_the_environment(tree, monkeypatch):
    monkeypatch.setenv("SECRET_FOR_TEST", "hunter2")
    cmd = make_generator(tree, "import os, sys; sys.exit(1 if 'SECRET_FOR_TEST' in os.environ else 0)")
    assert run(tree, "--generator-command", cmd).returncode == 0


def test_a_bad_root_is_a_usage_error(tmp_path):
    done = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_path / "nope"), "--lock", "x"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 2
