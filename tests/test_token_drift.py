"""scripts/check_token_drift.py and token-drift.yml: a vendored file may not drift from its pin or its source.

The pin checks run the script as a process over lock files in a temp directory; the live checks import it and
point its API host at a fake local server, so nothing here touches the network. Lock files and vendored files
are data from the repository under test, so the hostile cases are the point. Every negative case has a
passing twin, so a check that fails everything cannot pass this file.
"""

from __future__ import annotations

import hashlib
import http.server
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_token_drift.py"
WORKFLOW = REPO / ".github" / "workflows" / "token-drift.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NEWER = "fedcba9876543210fedcba9876543210fedcba98"
BODY = b'{"brand": "#123456"}\n'


def sha(data: bytes = BODY) -> str:
    return hashlib.sha256(data).hexdigest()


def lock_doc(**over):
    doc = {
        "vendored": "vendor/tokens.json",
        "sha256": sha(),
        "source": {"repo": "example/brand", "path": "brand/tokens.json", "commit": COMMIT},
    }
    doc.update(over)
    return doc


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "tokens.json").write_bytes(BODY)
    (tmp_path / "vendor" / "tokens.lock.json").write_text(json.dumps(lock_doc()))
    return tmp_path


def run(root: Path, *args: str, lock="vendor/tokens.lock.json", timeout=60, env=None):
    cmd = [sys.executable, "-I", str(SCRIPT), "--root", str(root)]
    if lock:
        cmd += ["--lock", lock]
    return subprocess.run(
        [*cmd, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        check=False,
        env=env,
    )


def write_lock(tree: Path, doc, name="vendor/tokens.lock.json"):
    (tree / name).write_text(doc if isinstance(doc, str) else json.dumps(doc))


# --- the pin ----------------------------------------------------------------------------------


def test_a_matching_pin_passes(tree):
    done = run(tree)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.startswith("ok")


def test_a_tampered_vendored_file_fails_and_names_the_file_and_both_hashes(tree):
    (tree / "vendor" / "tokens.json").write_bytes(BODY + b" ")
    done = run(tree)
    assert done.returncode == 1
    assert "hash mismatch" in done.stdout and "vendor/tokens.json" in done.stdout
    assert sha() in done.stdout and sha(BODY + b" ") in done.stdout


def test_a_tampered_lock_hash_fails(tree):
    write_lock(tree, lock_doc(sha256=sha(b"other")))
    done = run(tree)
    assert done.returncode == 1 and "hash mismatch" in done.stdout


def test_no_lock_is_a_usage_error_not_a_pass(tree):
    assert run(tree, lock=None).returncode == 2


def test_a_missing_lock_fails(tree):
    done = run(tree, lock="vendor/nope.json")
    assert done.returncode == 1 and "cannot read the lock" in done.stdout


def test_a_missing_vendored_file_fails(tree):
    (tree / "vendor" / "tokens.json").unlink()
    done = run(tree)
    assert done.returncode == 1 and "not a regular file" in done.stdout


def test_an_oversize_vendored_file_is_refused_unread(tree):
    with (tree / "vendor" / "tokens.json").open("wb") as handle:
        handle.truncate((16 << 20) + 1)  # sparse: no disk used
    done = run(tree)
    assert done.returncode == 1 and "larger than" in done.stdout


BAD_LOCKS = {
    "not an object": "[]",
    "not json": "{nope",
    "empty": "",
    "duplicate key": '{"vendored": "a", "vendored": "a", "sha256": "x", "source": {}}',
    "uppercase sha": lock_doc(sha256=sha().upper()),
    "short sha": lock_doc(sha256=sha()[:63]),
    "sha with newline": lock_doc(sha256=sha() + "\n"),
    "short commit": lock_doc(source={"repo": "a/b", "path": "p", "commit": COMMIT[:39]}),
    "branch as commit": lock_doc(source={"repo": "a/b", "path": "p", "commit": "main"}),
    "repo without owner": lock_doc(source={"repo": "brand", "path": "p", "commit": COMMIT}),
    "repo with a space": lock_doc(source={"repo": "a b/c", "path": "p", "commit": COMMIT}),
    "source path traversal": lock_doc(source={"repo": "a/b", "path": "../p", "commit": COMMIT}),
    "source path absolute": lock_doc(source={"repo": "a/b", "path": "/p", "commit": COMMIT}),
    "extra key": lock_doc(sha265=sha()),
    "extra source key": lock_doc(source={"repo": "a/b", "path": "p", "commit": COMMIT, "ref": "main"}),
    "vendored absolute": lock_doc(vendored="/etc/passwd"),
    "vendored traversal": lock_doc(vendored="../outside"),
    "vendored traversal inside": lock_doc(vendored="vendor/../../outside"),
    "vendored backslash": lock_doc(vendored="vendor\\tokens.json"),
    "vendored NUL": lock_doc(vendored="vendor/tokens.json\u0000.png"),
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


def test_a_symlinked_vendored_file_out_of_the_root_is_refused(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.json"
    outside.write_bytes(BODY)  # the same bytes: only the containment check can fail it
    (tree / "vendor" / "tokens.json").unlink()
    os.symlink(outside, tree / "vendor" / "tokens.json")
    done = run(tree)
    assert done.returncode == 1 and "stays inside the root" in done.stdout


def test_a_symlink_that_stays_inside_the_root_is_followed(tree):
    (tree / "real.json").write_bytes(BODY)
    (tree / "vendor" / "tokens.json").unlink()
    os.symlink(tree / "real.json", tree / "vendor" / "tokens.json")
    assert run(tree).returncode == 0


def test_a_lock_symlinked_or_pointed_outside_the_root_is_refused(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "x.lock.json"
    outside.write_text(json.dumps(lock_doc()))
    os.symlink(outside, tree / "vendor" / "evil.lock.json")
    for lock in ("vendor/evil.lock.json", str(outside), "../x.lock.json"):
        done = run(tree, lock=lock)
        assert done.returncode == 1 and "stays inside the root" in done.stdout, lock


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_fifo_as_the_vendored_file_does_not_hang(tree):
    (tree / "vendor" / "tokens.json").unlink()
    os.mkfifo(tree / "vendor" / "tokens.json")
    done = run(tree, timeout=20)
    assert done.returncode == 1 and "not a regular file" in done.stdout


def test_a_value_cannot_forge_a_log_line_or_a_workflow_command(tree):
    write_lock(tree, lock_doc(vendored="x\n::error::forged\nFAIL fake"))
    done = run(tree)
    assert done.returncode == 1
    assert all(not line.startswith("::") for line in done.stdout.splitlines())
    assert "\nFAIL fake" not in done.stdout


def test_a_bad_root_is_a_usage_error(tmp_path):
    done = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(tmp_path / "nope"), "--lock", "x"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 2


# --- the workflow's inputs, asserted against the lock -------------------------------------------


def test_expected_values_that_match_the_lock_pass(tree):
    done = run(
        tree,
        "--expect-vendored",
        "vendor/tokens.json",
        "--expect-source-repo",
        "example/brand",
        "--expect-source-path",
        "brand/tokens.json",
    )
    assert done.returncode == 0, done.stdout


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--expect-vendored", "vendor/other.json"),
        ("--expect-source-repo", "someone/else"),
        ("--expect-source-path", "brand/other.json"),
    ],
)
def test_an_expected_value_the_lock_disagrees_with_fails(tree, flag, value):
    done = run(tree, flag, value)
    assert done.returncode == 1 and "workflow input says" in done.stdout


def test_a_source_ref_without_check_live_is_a_usage_error(tree):
    assert run(tree, "--source-ref", "main").returncode == 2


# --- advisory ---------------------------------------------------------------------------------


def test_advisory_reports_drift_as_a_warning_and_sets_the_output(tree, tmp_path):
    out = tmp_path / "out"
    (tree / "vendor" / "tokens.json").write_bytes(b"changed")
    env = {**os.environ, "GITHUB_OUTPUT": str(out)}
    done = run(tree, "--advisory", env=env)
    assert done.returncode == 0 and "WARN hash mismatch" in done.stdout
    assert out.read_text() == "drifted=true\n"


def test_advisory_with_no_drift_sets_the_output_false(tree, tmp_path):
    out = tmp_path / "out"
    done = run(tree, "--advisory", env={**os.environ, "GITHUB_OUTPUT": str(out)})
    assert done.returncode == 0 and out.read_text() == "drifted=false\n"


def test_advisory_does_not_excuse_a_malformed_lock(tree):
    write_lock(tree, "{nope")
    assert run(tree, "--advisory").returncode == 1


# --- the live check, against a fake api.github.com ----------------------------------------------


def load_module():
    spec = importlib.util.spec_from_file_location("check_token_drift", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeApi:
    """Serves /commits/<ref> and /contents/<path>?ref=<sha> for one repository."""

    def __init__(self, content: bytes, head: str = NEWER):
        self.content, self.head = content, head
        self.requests: list[tuple[str, str, str]] = []  # path, accept, authorization
        self.mode = "ok"
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                api.requests.append((self.path, self.headers.get("Accept", ""), self.headers.get("Authorization", "")))
                if api.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                    self.end_headers()
                    return
                if api.mode == "404":
                    self.send_response(404)
                    self.end_headers()
                    return
                if "/commits/" in self.path:
                    body = (api.head if api.mode != "junk" else "<html>").encode()
                elif "/contents/" in self.path:
                    body = api.content
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"


def live(tree: Path, api: FakeApi, monkeypatch, capsys, *args: str):
    module = load_module()
    monkeypatch.setattr(module, "API", api.url)
    code = module.main(["--root", str(tree), "--lock", "vendor/tokens.lock.json", "--check-live", *args])
    return code, capsys.readouterr().out


def test_live_agreement_passes_and_both_fetches_use_the_one_resolved_commit(tree, monkeypatch, capsys):
    with FakeApi(BODY) as api:
        code, out = live(tree, api, monkeypatch, capsys)
    assert code == 0, out
    assert [p for p, _, _ in api.requests] == [
        "/repos/example/brand/commits/HEAD",
        f"/repos/example/brand/contents/brand/tokens.json?ref={NEWER}",
    ]
    assert f"commit {NEWER} (the lock says {COMMIT})" in out


def test_live_drift_names_the_file_both_hashes_and_the_commit(tree, monkeypatch, capsys):
    with FakeApi(BODY + b"new") as api:
        code, out = live(tree, api, monkeypatch, capsys)
    assert code == 1
    assert "drift:" in out and "brand/tokens.json" in out and NEWER in out
    assert sha() in out and sha(BODY + b"new") in out


def test_a_named_ref_is_resolved_once_quoted_and_used_for_the_file(tree, monkeypatch, capsys):
    with FakeApi(BODY) as api:
        code, _ = live(tree, api, monkeypatch, capsys, "--source-ref", "release/v1")
    assert code == 0
    assert api.requests[0][0] == "/repos/example/brand/commits/release%2Fv1"
    assert api.requests[1][0].endswith(f"?ref={NEWER}")


@pytest.mark.parametrize("ref", ["../x", "a..b", "-x", "/x", "x/", "a//b", "a b", "a;b", "x\n", "$(id)", "a" * 201])
def test_a_hostile_source_ref_is_refused_before_any_request(tree, monkeypatch, capsys, ref):
    with FakeApi(BODY) as api:
        code, out = live(tree, api, monkeypatch, capsys, f"--source-ref={ref}")
    assert code == 1 and "not a plain branch" in out and api.requests == []


@pytest.mark.parametrize("mode", ["redirect", "404", "junk"])
def test_an_unreachable_or_odd_source_fails_closed_not_as_a_pass(tree, monkeypatch, capsys, mode):
    with FakeApi(BODY) as api:
        api.mode = mode
        code, out = live(tree, api, monkeypatch, capsys)
    assert code == 1 and "FAIL" in out


def test_a_redirect_is_never_followed(tree, monkeypatch, capsys):
    with FakeApi(BODY) as api:
        api.mode = "redirect"
        _, out = live(tree, api, monkeypatch, capsys)
    assert "redirects are refused" in out or "HTTP 302" in out
    assert len(api.requests) == 1


def test_the_fetch_stops_reading_at_the_cap(monkeypatch):
    module = load_module()
    monkeypatch.setattr(module, "MAX_BYTES", 10)
    with FakeApi(b"x" * 11) as api:
        monkeypatch.setattr(module, "API", api.url)
        with pytest.raises(module.Error, match="more than 10 bytes"):
            module.api_get("/repos/a/b/contents/c", "application/vnd.github.raw+json", 10)
        assert module.api_get("/repos/a/b/contents/c", "application/vnd.github.raw+json", 11) == b"x" * 11


def test_the_token_is_sent_only_when_set_and_the_host_is_fixed(monkeypatch):
    module = load_module()
    assert module.API == "https://api.github.com"
    with FakeApi(BODY) as api:
        monkeypatch.setattr(module, "API", api.url)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        module.api_get("/repos/a/b/commits/HEAD", "application/vnd.github.sha", 100)
        monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
        module.api_get("/repos/a/b/commits/HEAD", "application/vnd.github.sha", 100)
    assert [auth for _, _, auth in api.requests] == ["", "Bearer t0ken"]


def test_a_wrong_ref_that_resolves_to_a_different_file_is_drift(tree, monkeypatch, capsys):
    """A branch that has moved on and changed the file: the lock no longer equals the source."""
    with FakeApi(b'{"brand": "#654321"}\n') as api:
        code, out = live(tree, api, monkeypatch, capsys, "--source-ref", "next")
    assert code == 1 and "drift:" in out


def test_live_checks_nothing_when_the_pin_check_cannot_run(tree, monkeypatch, capsys):
    write_lock(tree, "{nope")
    with FakeApi(BODY) as api:
        code, _ = live(tree, api, monkeypatch, capsys)
    assert code == 1 and api.requests == []


# --- the workflow -----------------------------------------------------------------------------


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def inlined_script() -> str:
    """The heredoc body of the check step, de-indented."""
    text = WORKFLOW.read_text()
    match = re.search(r"<<'PY'\n(.*?)\n\s*PY\n", text, re.S)
    assert match, "the check step has no PY heredoc"
    lines = match.group(1).split("\n")
    indent = min(len(line) - len(line.lstrip()) for line in lines if line.strip())
    return "\n".join(line[indent:] for line in lines) + "\n"


def test_the_workflow_inlines_the_script_byte_for_byte():
    assert inlined_script() == SCRIPT.read_text()


def test_the_inputs_the_callers_rely_on_exist_with_the_documented_defaults():
    inputs = workflow()[True]["workflow_call"]["inputs"]
    for name in ("lock-file", "vendored-path", "source-repo", "source-path", "source-ref"):
        assert inputs[name]["type"] == "string", name
    assert inputs["source-ref"]["default"] == ""
    assert inputs["check-live"]["type"] == "boolean" and inputs["check-live"]["default"] is False
    assert inputs["advisory"]["default"] is False, "drift must fail the job unless a caller opts out"
    assert inputs["egress-policy"]["default"] == "block"
    assert inputs["lock-file"]["default"] == ""


def test_the_workflow_reads_only_and_writes_no_environment_file():
    text = WORKFLOW.read_text()
    assert workflow()["permissions"] == {"contents": "read"}
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "GITHUB_ENV" not in code and "GITHUB_PATH" not in code
    assert "continue-on-error" not in code
    assert "secrets." not in code


def test_no_input_is_interpolated_into_a_shell_script():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            run_text = step.get("run", "")
            assert "${{ inputs." not in run_text, step.get("name")


def test_the_live_fetch_needs_only_the_api_host_by_default():
    inputs = workflow()[True]["workflow_call"]["inputs"]
    assert inputs["allowed-endpoints"]["default"] == "api.github.com:443 github.com:443"


def test_ci_has_a_passing_fixture_and_planted_fixtures_that_a_control_job_checks():
    ci = yaml.safe_load(CI.read_text())["jobs"]
    for name in ("fixture-token-drift", "fixture-token-drift-live"):
        assert ci[name]["uses"] == "./.github/workflows/token-drift.yml", name
        assert not ci[name]["with"].get("advisory"), "the passing fixtures must fail on drift"
    planted = [n for n in ci if n.startswith("fixture-token-drift-planted")]
    assert len(planted) == 2
    for name in planted:
        assert ci[name]["with"]["advisory"] is True
    assert "token-drift-control" in ci
    control = ci["token-drift-control"]
    assert set(planted) <= set(control["needs"])
    script = "\n".join(str(s.get("run", "")) for s in control["steps"])
    for name in planted:
        assert name in yaml.dump(control["steps"]), name
    assert "true" in script
    gate = ci["ci-green"]["needs"]
    for name in ("fixture-token-drift", "fixture-token-drift-live", "token-drift-control", *planted):
        assert name in gate, name


def test_the_planted_fixtures_really_drift_and_the_good_ones_do_not():
    base = REPO / "fixture" / "token-drift"
    for name, expect in (("ok", 0), ("planted-pin", 1)):
        done = run(REPO, lock=f"fixture/token-drift/{name}/tokens.lock.json")
        assert done.returncode == expect, (name, done.stdout)
    # live fixtures: the vendored file matches its lock in both; only the lock vs the source differs
    for name in ("live", "planted-live"):
        done = run(REPO, lock=f"fixture/token-drift/{name}/tokens.lock.json")
        assert done.returncode == 0, (name, done.stdout)
    assert (base / "live" / "tokens.lock.json").exists()
