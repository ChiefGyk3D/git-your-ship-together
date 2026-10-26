"""wait-ci: the CI watcher (scripts/wait-ci.sh) and the composite action that wraps it.

The script runs for real under bash against a fake `gh` (a Python program driven by a scenario file) with a
fake `sleep` and `date` that move a clock file, so a thirty-minute wait takes milliseconds and every call gh
received is on record. The scenario models the three things the script reads: the pull request head (which can
move after N check polls, or during a merge), the check runs of each commit by SHA (a list of snapshots, one per
poll, the last repeating), and the results of `gh pr merge`.

Every guard has a case that must go red and a control that must stay green, so a guard that bites on
everything, or on nothing, shows. Each core guard (the head pin, the required context, no checks) was also
broken on purpose in the script to confirm these tests go red; the mutations are listed in the pull request.
"""

from __future__ import annotations

import http.server
import inspect
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "wait-ci.sh"
ACTION = REPO / ".github" / "actions" / "wait-ci" / "action.yml"
PAGE = REPO / "docs" / "wiki" / "Action-wait-ci.md"

SLUG = "N0TST/widgets"
REAL_GH = shutil.which("gh")
A = "a" * 40
B = "b" * 40
C = "c" * 40
TOKEN = "ghs_FAKE0TOKEN0VALUE0DO0NOT0PRINT"
US = "\x1f"


def current_head(st):
    head = st["head"]
    for move in st.get("moves", []):
        if st["check_polls"] >= move["after_check_polls"]:
            head = move["head"]
    return head


def github_runs(snapshot, sha):
    # GitHub-shaped check runs; list order is chronological (later is newer). A run is
    # (status, conclusion, name[, app id[, head_sha]]); head_sha defaults to the commit asked about.
    runs = []
    for n, run in enumerate(snapshot):
        status, conclusion, name = run[:3]
        app = run[3] if len(run) > 3 else 15368
        head_sha = run[4] if len(run) > 4 else sha
        runs.append(
            {
                "id": 1000 + n,
                "name": name,
                "head_sha": head_sha,
                "status": status,
                "conclusion": conclusion or None,
                "started_at": f"2026-10-26T00:{n % 60:02d}:00Z",
                "completed_at": None if status != "completed" else f"2026-10-26T01:{n % 60:02d}:00Z",
                "app": {"id": app, "slug": f"app-{app}"},
            }
        )
    return runs


def latest_only(runs):
    # filter=latest: "returns the most recent check runs" (the docs key this on completed_at; an
    # unfinished run has none and is the newest). Grouped here by (name, app), the newest of each.
    # Probed live on 2026-10-26: with filter=latest total_count equals the runs returned (95/95 where
    # filter=all gave 180).
    newest = {}
    for run in runs:
        newest[(run["name"], run["app"]["id"])] = run
    return list(newest.values())


def snapshot_runs(st, sha):
    # One poll of the check-runs endpoint: advance the counters; None while the scenario has the API failing.
    st["check_polls"] += 1
    st["check_shas"].append(sha)
    fails = st.get("check_failures", 0)
    if st["check_polls"] <= fails:
        return None
    snaps = st["checks"].get(sha, [[]])
    idx = min(st["check_polls"] - 1 - fails, len(snaps) - 1)
    return github_runs(snaps[idx], sha)


def shape_runs(st, runs, query):
    # Apply filter=latest, then the scenario's lies: a total_count that is not the runs shown, or a
    # response cut short (the endpoint only shows the 1000 most recent check suites).
    if query.get("filter", ["latest"])[0] == "latest":
        runs = latest_only(runs)
    total = st.get("total_count_override")
    if total is None:
        total = len(runs)
    if st.get("serve_only") is not None:
        runs = runs[: st["serve_only"]]
    return total, runs


def suites_body(st, sha):
    # GET commits/{sha}/check-suites?per_page=1: total_count is every check suite on the ref, also those that
    # hold no runs (probed live on 2026-10-26: 12 suites behind 3 with runs). The scenario can override it
    # with any JSON value, drop it, or make the call fail.
    st["suite_calls"] = st.get("suite_calls", 0) + 1
    if st.get("suites_fail"):
        return None
    if st.get("suites_missing"):
        return {"check_suites": []}
    if "suites" in st:
        return {"total_count": st["suites"], "check_suites": []}
    fails = st.get("check_failures", 0)
    snaps = st["checks"].get(sha, [[]])
    idx = max(0, min(st["check_polls"] - 1 - fails, len(snaps) - 1))
    apps = {run[3] if len(run) > 3 else 15368 for run in snaps[idx]}
    return {"total_count": len(apps), "check_suites": []}


def split_pages(runs, query):
    per_page = max(1, min(int(query.get("per_page", ["30"])[0]), 100))
    return [runs[i : i + per_page] for i in range(0, len(runs), per_page)] or [[]]


FAKE_GH = r"""#!@PYTHON@
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

d = Path(os.environ["FAKE_DIR"])
sf = d / "state.json"
st = json.loads(sf.read_text())
argv = sys.argv[1:]
with open(d / "calls.log", "a") as log:
    log.write(" ".join(argv) + "\n")
tok = os.environ.get("GH_TOKEN", "")


def save():
    sf.write_text(json.dumps(st))


# @HELPERS@

if argv[:1] == ["api"]:
    path = next(a for a in argv[1:] if "/" in a and not a.startswith("-"))
    jq = argv[argv.index("--jq") + 1] if "--jq" in argv else ""
    if "/pulls/" in path:
        st["head_reads"] += 1
        save()
        if st.get("head_read_fails"):
            sys.stderr.write("HTTP 502 for token " + tok + "\n")
            sys.exit(1)
        if st.get("head_warns"):
            sys.stderr.write("warning: a new gh is available\n")
        if st.get("head_garbage"):
            print(st["head_garbage"])
            sys.exit(0)
        print(current_head(st) if jq == ".head.sha" else str(st["merged"]).lower())
        sys.exit(0)
    if "/check-runs" in path:
        url = urlsplit(path)
        sha = url.path.split("/commits/")[1].split("/")[0]
        query = parse_qs(url.query)
        runs = snapshot_runs(st, sha)
        if runs is None:
            save()
            sys.stderr.write("HTTP 500 using " + tok + "\n")
            sys.exit(1)
        total, runs = shape_runs(st, runs, query)
        pages = split_pages(runs, query)
        if "--paginate" not in argv:
            wanted = int(query.get("page", ["1"])[0])
            pages = pages[wanted - 1 : wanted]
        st["pages_served"] = st.get("pages_served", 0) + len(pages)
        save()
        for page in pages:
            body = json.dumps({"total_count": total, "check_runs": page})
            proc = subprocess.run(["jq", "-r", jq], input=body, capture_output=True, text=True)
            if proc.returncode != 0:
                sys.stderr.write("jq: " + proc.stderr)
                sys.exit(1)
            out = proc.stdout
            for old, new in st.get("mangle", []):
                out = out.replace(old, new)
            sys.stdout.write(out)
        sys.exit(0)
    if "/check-suites" in path:
        sha = urlsplit(path).path.split("/commits/")[1].split("/")[0]
        body = suites_body(st, sha)
        save()
        if body is None:
            sys.stderr.write("HTTP 500 using " + tok + "\n")
            sys.exit(1)
        proc = subprocess.run(["jq", "-r", jq], input=json.dumps(body), capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write("jq: " + proc.stderr)
            sys.exit(1)
        sys.stdout.write(proc.stdout)
        sys.exit(0)
    sys.stderr.write("fake gh: unexpected api path " + path + "\n")
    sys.exit(97)

if argv[:2] == ["pr", "merge"]:
    attempt = st["merge_attempts"]
    results = st["merge_results"]
    res = results[min(attempt, len(results) - 1)]
    st["merge_attempts"] = attempt + 1
    if "set_head" in res:
        st["head"] = res["set_head"]
        st["moves"] = []
    if res.get("merged") or (res["rc"] == 0 and not res.get("queued")):
        st["merged"] = True
    save()
    if res["rc"] != 0:
        sys.stderr.write(res.get("err", "merge failed").replace("TOKEN", tok) + "\n")
    sys.exit(res["rc"])

sys.stderr.write("fake gh: unexpected command " + " ".join(argv) + "\n")
sys.exit(98)
"""

FAKE_SLEEP = """#!/bin/sh
echo "$1" >> "$FAKE_DIR/sleeps"
now=$(cat "$FAKE_DIR/clock")
echo $((now + $1)) > "$FAKE_DIR/clock"
"""

FAKE_DATE = """#!/bin/sh
[ "$1" = "+%s" ] || { echo "fake date: unexpected $*" >&2; exit 99; }
cat "$FAKE_DIR/clock"
"""


def ok(name: str, app: int = 15368) -> tuple:
    return ("completed", "success", name, app)


def done(name: str, conclusion: str, app: int = 15368) -> tuple:
    return ("completed", conclusion, name, app)


def running(name: str, app: int = 15368) -> tuple:
    return ("in_progress", "", name, app)


HELPER_SOURCE = "\n\n".join(
    inspect.getsource(f)
    for f in (current_head, github_runs, latest_only, snapshot_runs, shape_runs, suites_body, split_pages)
)


class World:
    def __init__(self, tmp: Path, *, head: str = A, checks=None, engine: str = "jq", cert: Path | None = None, **extra):
        tmp = Path(tempfile.mkdtemp(dir=tmp))
        self.tmp = tmp
        self.engine = engine
        self.cert = cert
        self.server = None
        self.dir = tmp / "fake"
        self.bin = tmp / "bin"
        self.dir.mkdir()
        self.bin.mkdir()
        self.out = tmp / "github_output"
        python = sys.executable
        for name, text in (
            ("gh", FAKE_GH.replace("@PYTHON@", python).replace("# @HELPERS@", HELPER_SOURCE)),
            ("sleep", FAKE_SLEEP),
            ("date", FAKE_DATE),
        ):
            path = self.bin / name
            path.write_text(text)
            path.chmod(0o755)
        (self.dir / "clock").write_text("1000")
        self.state = {
            "head": head,
            "moves": [],
            "merged": False,
            "checks": checks or {},
            "merge_results": [{"rc": 0}],
            "merge_attempts": 0,
            "check_polls": 0,
            "check_shas": [],
            "head_reads": 0,
            **extra,
        }
        self.save()
        if engine == "gh":
            self.start_server()

    def start_server(self) -> None:
        """Serve the scenario over TLS on loopback to the REAL gh, whose embedded gojq then runs the script's --jq."""
        world = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, obj, headers=()):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in headers:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                with open(world.dir / "calls.log", "a") as log:
                    log.write("GET " + self.path + "\n")
                st = world.load()
                url = urlsplit(self.path)
                query = parse_qs(url.query)
                if re.fullmatch(r"/api/v3/repos/[^/]+/[^/]+/pulls/\d+", url.path):
                    st["head_reads"] += 1
                    world.state = st
                    world.save()
                    return self.reply(200, {"head": {"sha": current_head(st)}, "merged": st["merged"]})
                m = re.fullmatch(r"/api/v3/repos/[^/]+/[^/]+/commits/([0-9a-f]+)/check-suites", url.path)
                if m:
                    body = suites_body(st, m.group(1))
                    world.state = st
                    world.save()
                    if body is None:
                        return self.reply(500, {"message": "boom"})
                    return self.reply(200, body)
                m = re.fullmatch(r"/api/v3/repos/[^/]+/[^/]+/commits/([0-9a-f]+)/check-runs", url.path)
                if not m:
                    return self.reply(404, {"message": "Not Found"})
                page = int(query.get("page", ["1"])[0])
                if page == 1:
                    runs = snapshot_runs(st, m.group(1))
                    if runs is None:
                        world.state = st
                        world.save()
                        return self.reply(500, {"message": "boom"})
                    total, runs = shape_runs(st, runs, query)
                    st["cached"] = [total, runs]
                else:
                    total, runs = st["cached"]
                pages = split_pages(runs, query)
                st["pages_served"] = st.get("pages_served", 0) + 1
                world.state = st
                world.save()
                headers = []
                if page < len(pages):
                    q = "&".join(f"{k}={v[0]}" for k, v in query.items() if k != "page")
                    nxt = f"https://localhost:{world.port}{url.path}?{q}&page={page + 1}"
                    headers.append(("Link", f'<{nxt}>; rel="next"'))
                self.reply(200, {"total_count": total, "check_runs": pages[page - 1]}, headers)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert / "cert.pem", self.cert / "key.pem")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()

    def save(self) -> None:
        (self.dir / "state.json").write_text(json.dumps(self.state))

    def load(self) -> dict:
        return json.loads((self.dir / "state.json").read_text())

    def calls(self) -> list[str]:
        path = self.dir / "calls.log"
        return path.read_text().splitlines() if path.exists() else []

    def sleeps(self) -> list[int]:
        path = self.dir / "sleeps"
        return [int(x) for x in path.read_text().split()] if path.exists() else []

    def merges(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("pr merge") or "graphql" in c]

    def outputs(self) -> dict[str, str]:
        if not self.out.exists():
            return {}
        return dict(line.split("=", 1) for line in self.out.read_text().splitlines())

    def env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GH_", "GITHUB_", "INPUT_", "WAIT_CI_"))}
        env.update(
            PATH=f"{self.bin}:{env['PATH']}",
            GH_BIN=str(self.bin / "gh"),
            FAKE_DIR=str(self.dir),
            GH_TOKEN=TOKEN,
            GITHUB_OUTPUT=str(self.out),
        )
        if self.engine == "gh":
            env.pop("GH_TOKEN")
            env.update(
                GH_BIN=REAL_GH,
                GH_HOST=f"localhost:{self.port}",
                GH_ENTERPRISE_TOKEN=TOKEN,
                GH_CONFIG_DIR=str(self.tmp / "ghcfg"),
                SSL_CERT_FILE=str(self.cert / "cert.pem"),
                GH_PROMPT_DISABLED="1",
                GH_NO_UPDATE_NOTIFIER="1",
                NO_PROXY="localhost,127.0.0.1",
            )
        return env

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )


FAST = ("--interval", "10", "--timeout", "300", "--hung-after", "1000")


def shown(p: subprocess.CompletedProcess[str]) -> str:
    return f"exit={p.returncode}\n--stdout--\n{p.stdout}\n--stderr--\n{p.stderr}"


def need(tool: str, found: object) -> None:
    if found:
        return
    message = f"{tool} is required by tests/test_wait_ci.py (see docs/wiki/Action-wait-ci.md, How it is tested)"
    if os.environ.get("CI"):
        pytest.fail(message)
    pytest.skip(message)


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory):
    need("openssl", shutil.which("openssl"))
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(d / "key.pem"),
            "-out",
            str(d / "cert.pem"),
        ]
        + ["-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True,
        capture_output=True,
    )
    return d


# Tests that take `engine` run twice: with the system jq under a fake gh, and with the REAL gh (whose
# embedded gojq evaluates the script's --jq) against a loopback TLS server serving the same scenario.
ENGINES = pytest.mark.parametrize("engine", ["jq", "gh"])


@pytest.fixture
def world(tmp_path, request):
    # The fake gh applies the real --jq expression with the real jq, so the script's parsing is under test.
    need("jq", shutil.which("jq"))
    engine = request.node.callspec.params.get("engine", "jq") if hasattr(request.node, "callspec") else "jq"
    made = []

    def make(**kw):
        if engine == "gh":
            need("gh", REAL_GH)
            kw["cert"] = request.getfixturevalue("tls_cert")
        w = World(tmp_path, engine=engine, **kw)
        made.append(w)
        return w

    yield make
    for w in made:
        w.close()


GATE = [ok("lint"), ok("test"), ok("CI green")]


# --- green and the verified SHA ---------------------------------------------


@ENGINES
def test_green_prints_the_verified_sha_and_exits_zero(world, engine):
    w = world(checks={A: [GATE]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert f"verified {A}" in p.stdout
    assert w.outputs() == {"result": "green", "sha": A, "merged": "false"}
    assert w.merges() == [], "no --merge, no merge"


def test_checks_are_read_for_the_pinned_sha_only(world):
    # The head moves to B after the first poll. Checks for B are green too; with abort the run must
    # still end at the A it pinned (exit 4), and every check call must name A.
    w = world(checks={A: [[running("CI green")]], B: [GATE]}, moves=[{"after_check_polls": 1, "head": B}])
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 4, shown(p)
    assert set(w.load()["check_shas"]) == {A}


def test_sha_without_a_pr_verifies_that_commit(world):
    w = world(checks={A: [GATE]})
    p = w.run("--repo", SLUG, "--sha", A, *FAST)
    assert p.returncode == 0, shown(p)
    assert f"verified {A}" in p.stdout
    assert not [c for c in w.calls() if "/pulls/" in c], "no pull request, no head to read"


def test_sha_that_is_not_the_pr_head_is_head_moved(world):
    w = world(head=B, checks={A: [GATE], B: [GATE]})
    p = w.run("--repo", SLUG, "--pr", "7", "--sha", A, *FAST)
    assert p.returncode == 4, shown(p)
    assert w.load()["check_shas"] == [], "nothing is verified for a commit that is not the head"


# --- a push: abort or reset ---------------------------------------------------


def test_a_push_aborts_with_exit_4_even_when_the_old_commit_is_green(world):
    w = world(checks={A: [GATE]}, moves=[{"after_check_polls": 1, "head": B}], head=A)
    # Poll 1 of A is already green; the head moved right after it, before the merge.
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 4, shown(p)
    assert B in p.stdout and A in p.stdout
    assert w.merges() == [], "an unverified head is never merged"
    assert w.outputs()["result"] == "head-moved"


def test_a_push_while_waiting_aborts(world):
    w = world(checks={A: [[running("CI green")]], B: [GATE]}, moves=[{"after_check_polls": 2, "head": B}])
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 4, shown(p)
    assert "head moved" in p.stdout


def test_on_push_reset_follows_a_push_made_while_waiting(world):
    w = world(
        checks={A: [[running("CI green")], [running("CI green")], GATE], B: [GATE]},
        moves=[{"after_check_polls": 2, "head": B}],
    )
    p = w.run("--repo", SLUG, "--pr", "7", "--on-push", "reset", *FAST)
    assert p.returncode == 0, shown(p)
    assert f"verified {B}" in p.stdout
    assert "resetting" in p.stdout
    assert set(w.load()["check_shas"]) == {A, B}


def test_on_push_reset_keeps_the_total_timeout(world):
    # A push every poll must not extend the wait for ever.
    moves = [{"after_check_polls": n, "head": ("b" if n % 2 else "c") * 40} for n in range(1, 60)]
    w = world(checks={}, moves=moves)
    p = w.run("--repo", SLUG, "--pr", "7", "--on-push", "reset", "--interval", "10", "--timeout", "100")
    assert p.returncode == 2, shown(p)


# --- not green: no checks, missing context, wrong name ------------------------


def test_no_check_runs_at_all_is_not_green(world):
    w = world(checks={A: [[]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "100", "--hung-after", "1000")
    assert p.returncode == 2, shown(p)
    assert "verified" not in p.stdout
    assert w.outputs()["result"] == "timeout"


def test_no_check_runs_with_no_context_required_is_still_not_green(world):
    w = world(checks={A: [[]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--context", "", "--interval", "10", "--timeout", "100")
    assert p.returncode == 2, shown(p)


def test_a_required_context_that_has_not_reported_is_not_green(world):
    # Twenty checks passed, the aggregate gate has not reported (GYST #218).
    others = [ok(f"job {n}") for n in range(20)]
    w = world(checks={A: [others]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "100")
    assert p.returncode == 2, shown(p)
    assert "'CI green' not reported" in p.stdout


def test_the_context_reporting_late_turns_it_green_on_that_poll(world):
    others = [ok(f"job {n}") for n in range(5)]
    w = world(checks={A: [others, others, others + [running("CI green")], others + [ok("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.load()["check_polls"] == 4


@pytest.mark.parametrize(
    "name",
    [
        "CI green (old)",
        "CI green ",
        " CI green",
        "ci green",
        "xCI green",
        "CI greens",
        "CI gree?",
        "CI *",
        "CI green\\",
    ],
)
def test_context_matching_is_exact_no_suffix_case_glob_or_space_tricks(world, name):
    w = world(checks={A: [[ok(name), ok("lint")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, f"{name!r} must not satisfy 'CI green'\n" + shown(p)


def test_a_glob_given_as_the_context_is_literal(world):
    w = world(checks={A: [[ok("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--context", "CI *", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)


def test_an_exact_name_among_lookalikes_is_green(world):
    w = world(checks={A: [[ok("CI green (old)"), ok("ci green"), ok("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)


def test_every_required_context_is_needed(world):
    w = world(checks={A: [[ok("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--context", "CI green", "--context", "Security", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "'Security' not reported" in p.stdout
    w2 = world(checks={A: [[ok("CI green"), ok("Security")]]})
    q = w2.run("--repo", SLUG, "--pr", "7", "--context", "CI green", "--context", "Security", *FAST)
    assert q.returncode == 0, shown(q)


def test_a_context_that_is_skipped_or_neutral_is_not_green(world):
    for conclusion in ("skipped", "neutral"):
        w = world(checks={A: [[ok("lint"), done("CI green", conclusion)]]})
        p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
        assert p.returncode == 2, f"{conclusion}\n" + shown(p)


def test_min_checks_counts_completed_runs(world):
    w = world(checks={A: [[ok("CI green"), running("a"), running("b")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--min-checks", "3", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "1 of 3" in p.stdout
    w2 = world(checks={A: [[ok("CI green"), ok("a"), running("b")]]})
    q = w2.run("--repo", SLUG, "--pr", "7", "--min-checks", "2", *FAST)
    assert q.returncode == 0, shown(q)


def test_a_pending_non_gate_check_does_not_block_a_green_gate(world):
    w = world(checks={A: [[ok("CI green"), running("nightly")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)


# --- who reported the check run ------------------------------------------------------

FOREIGN = 99999


def test_a_same_named_run_from_another_app_is_not_green(world):
    w = world(checks={A: [[ok("lint"), ok("CI green", FOREIGN)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "verified" not in p.stdout
    assert "ignored 1 run(s)" in p.stdout


def test_a_same_named_run_from_the_right_app_is_green(world):
    w = world(checks={A: [[ok("CI green", FOREIGN), ok("CI green"), ok("lint")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)


def test_a_foreign_app_cannot_satisfy_the_gate_while_the_real_one_is_still_running(world):
    w = world(checks={A: [[ok("CI green", FOREIGN), running("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)


def test_a_failed_same_named_run_from_another_app_is_ignored_not_red(world):
    # Documented choice: a foreign run that borrows a required name is ignored in both directions,
    # so it can neither satisfy the gate nor block a gate the right app reported green.
    w = world(checks={A: [[done("CI green", "failure", FOREIGN), ok("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)


def test_a_failed_run_with_another_name_is_red_whatever_its_app(world):
    w = world(checks={A: [[ok("CI green"), done("other", "failure", FOREIGN)]]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 1


def test_app_id_selects_the_expected_app(world):
    w = world(checks={A: [[ok("CI green", FOREIGN)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--app-id", str(FOREIGN), *FAST)
    assert p.returncode == 0, shown(p)


def test_any_app_counts_a_foreign_run_with_a_warning(world):
    w = world(checks={A: [[ok("CI green", FOREIGN)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--any-app", *FAST)
    assert p.returncode == 0, shown(p)
    assert "warning: --any-app" in p.stdout


# --- an explicit --sha is never replaced -------------------------------------------------


@pytest.mark.parametrize("mode", ["abort", "reset"])
def test_a_head_move_with_an_explicit_sha_is_exit_4_in_every_on_push_mode(world, mode):
    w = world(
        checks={A: [[running("CI green")], [running("CI green")], GATE], B: [GATE]},
        moves=[{"after_check_polls": 1, "head": B}],
    )
    p = w.run("--repo", SLUG, "--pr", "7", "--sha", A, "--on-push", mode, "--merge", *FAST)
    assert p.returncode == 4, shown(p)
    assert w.merges() == []
    assert B not in set(w.load()["check_shas"]), "the new head is never even looked at"


@pytest.mark.parametrize("mode", ["abort", "reset"])
def test_a_head_move_between_verify_and_merge_with_an_explicit_sha_is_exit_4(world, mode):
    w = world(checks={A: [GATE], B: [GATE]}, moves=[{"after_check_polls": 1, "head": B}])
    p = w.run("--repo", SLUG, "--pr", "7", "--sha", A, "--on-push", mode, "--merge", *FAST)
    assert p.returncode == 4, shown(p)
    assert w.merges() == []


def test_without_an_explicit_sha_reset_still_follows_the_head(world):
    w = world(
        checks={A: [[running("CI green")], [running("CI green")]], B: [GATE]},
        moves=[{"after_check_polls": 1, "head": B}],
    )
    p = w.run("--repo", SLUG, "--pr", "7", "--on-push", "reset", "--merge", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.merges() == [f"pr merge 7 -R {SLUG} --squash --match-head-commit {B}"]


# --- hostile check run names (the jq / bash boundary) ----------------------------------------

FORGED = "x\ncompleted\x1fsuccess\x1f15368\x1fCI green"
HOSTILE_NAMES = {
    "newline": "x\nfoo",
    "forged line (the reviewer's repro)": FORGED,
    "carriage return": "x\rfoo",
    "US 0x1f": "a\x1fb",
    "tab": "a\tb",
    "NUL": "a\x00b",
    "DEL": "a\x7fb",
    "NEL U+0085": "a\u0085b",
    "line separator U+2028": "a b",
    "paragraph separator U+2029": "a b",
    "trailing newline": "CI green\n",
    "escape": "a\x1b[31mb",
}


# `gh api` rewrites these in the response before --jq runs (observed with gh 2.100.0: ESC becomes "^[", US "^_",
# NUL "^@", NEL "^E"), so through the real gh they arrive as printable text that cannot equal a real name; the
# jq flag still catches them for any other client, and for the characters gh leaves alone.
SANITIZED_BY_GH = {"NUL", "US 0x1f", "escape", "NEL U+0085"}


@pytest.mark.parametrize("label", sorted(HOSTILE_NAMES))
@ENGINES
def test_a_check_run_name_with_a_control_character_is_red_never_green(world, label, engine):
    # Another app (or a job name) can post a check run whose name carries a newline and a forged
    # "completed / success / trusted app / CI green" line. No real CI green run exists here.
    name = HOSTILE_NAMES[label]
    w = world(checks={A: [[ok("lint"), ok(name, 57789)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    if engine == "gh" and label in SANITIZED_BY_GH:
        assert p.returncode in (1, 2), f"{label!r}\n" + shown(p)  # never green: the gate did not report
        assert "verified" not in p.stdout
        assert w.merges() == []
        return
    assert p.returncode == 1, f"{label!r}\n" + shown(p)
    assert "verified" not in p.stdout
    assert "control character" in p.stdout
    assert w.merges() == []
    assert w.outputs()["result"] == "red"


@pytest.mark.parametrize("label", sorted(HOSTILE_NAMES))
@ENGINES
def test_a_hostile_name_is_red_even_when_the_real_gate_is_green(world, label, engine):
    w = world(checks={A: [[ok("CI green"), ok(HOSTILE_NAMES[label], 57789)]]})
    if engine == "gh" and label in SANITIZED_BY_GH:
        # gh already turned the name into harmless printable text; the gate really is green.
        assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0
        return
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 1, f"{label!r}\n" + shown(p)
    assert w.merges() == []


@ENGINES
def test_the_forged_line_cannot_satisfy_a_gate_that_has_not_reported(world, engine):
    # Same forgery, but from a run of the trusted app itself (a job name in this repository).
    w = world(checks={A: [[ok("lint"), ok(FORGED)]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 1, shown(p)


@pytest.mark.parametrize("name", ["CI green ✓", 'say "CI green"', "café \U0001f600 build", "a'b $(touch x) `id`"])
@ENGINES
def test_odd_but_printable_names_are_not_hostile_and_still_match_exactly(world, name, engine):
    w = world(checks={A: [[ok("CI green"), ok(name)]]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0
    w2 = world(checks={A: [[ok(name)]]})
    assert w2.run("--repo", SLUG, "--pr", "7", "--context", name, *FAST).returncode == 0


# --- what the API call asks for, and what comes back ----------------------------------------


def test_the_check_runs_request_asks_for_latest_runs_at_the_maximum_page_size(world):
    w = world(checks={A: [GATE]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0
    request = [c for c in w.calls() if "/check-runs" in c]
    assert request and all("--paginate" in c for c in request)
    assert all("filter=latest" in c and "per_page=100" in c for c in request)


@ENGINES
def test_the_gate_on_the_second_page_is_found(world, engine):
    many = [ok(f"job {n}") for n in range(130)] + [ok("CI green")]
    w = world(checks={A: [many]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.load()["pages_served"] == 2


@ENGINES
def test_a_failure_on_the_second_page_is_red(world, engine):
    many = [ok(f"job {n}") for n in range(130)] + [done("late", "failure"), ok("CI green")]
    w = world(checks={A: [many]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 1


@ENGINES
def test_a_green_rerun_of_a_failed_run_is_green(world, engine):
    w = world(checks={A: [[done("CI green", "failure"), ok("CI green")]]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0


@ENGINES
def test_a_failed_rerun_of_a_green_run_is_red(world, engine):
    w = world(checks={A: [[ok("CI green"), done("CI green", "failure")]]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 1


def test_a_rerun_in_progress_after_a_green_run_is_not_green(world):
    w = world(checks={A: [[ok("CI green"), running("CI green")]]})
    assert w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60").returncode == 2


@ENGINES
def test_a_completed_run_with_a_null_conclusion_is_not_green(world, engine):
    w = world(checks={A: [[("completed", None, "CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)


@ENGINES
def test_a_null_conclusion_while_running_is_pending_then_green(world, engine):
    w = world(checks={A: [[("in_progress", None, "CI green")], GATE]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0


# --- merge: retry only a policy block; a queue is not a merge -------------------------------

POLICY = {
    "rc": 1,
    "err": "X Pull request N0TST/widgets#7 is not mergeable: the base branch policy prohibits the merge.",
}
REQUIRED = {"rc": 1, "err": 'Required status check "CI green" is expected.'}


@pytest.mark.parametrize(
    "err", ["merge conflict: not mergeable", "HTTP 403: Resource not accessible", "Pull request is closed", "boom"]
)
def test_any_other_merge_failure_is_not_retried(world, err):
    w = world(checks={A: [GATE]}, merge_results=[{"rc": 1, "err": err}, {"rc": 0}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retry-delay", "30", *FAST)
    assert p.returncode == 1, shown(p)
    assert len(w.merges()) == 1
    assert w.sleeps() == []
    assert "merge blocked: not a policy block" in p.stdout
    assert w.outputs()["result"] == "merge-blocked"


@pytest.mark.parametrize("block", [POLICY, REQUIRED])
def test_a_policy_or_required_check_block_is_retried(world, block):
    w = world(checks={A: [GATE]}, merge_results=[block, {"rc": 0}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retry-delay", "30", *FAST)
    assert p.returncode == 0, shown(p)
    assert len(w.merges()) == 2 and w.sleeps() == [30]


def test_a_policy_block_that_never_clears_says_so_after_the_bound(world):
    w = world(checks={A: [GATE]}, merge_results=[POLICY])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retries", "1", "--merge-retry-delay", "5", *FAST)
    assert p.returncode == 1, shown(p)
    assert len(w.merges()) == 2
    assert "merge blocked: policy block still in place after 2 attempts" in p.stdout
    assert w.outputs()["sha"] == A and w.outputs()["merged"] == "false"


def test_a_merge_the_api_accepts_but_that_is_queued_is_not_reported_merged(world):
    w = world(checks={A: [GATE]}, merge_results=[{"rc": 0, "queued": True}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 5, shown(p)
    assert "not merged" in p.stdout
    assert w.outputs() == {"result": "queued", "sha": A, "merged": "false"}


# --- the other input boundaries ------------------------------------------------------------------


@pytest.mark.parametrize("garbage", ["not-a-sha", A.upper(), A[:39], A + "0", "a" * 40 + "\n" + "b" * 40])
def test_a_head_that_is_not_a_full_sha_is_refused(world, garbage):
    w = world(checks={A: [GATE]}, head_garbage=garbage)
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 1, shown(p)
    assert "verified" not in p.stdout
    assert w.outputs().get("sha", "") == ""


@pytest.mark.parametrize(
    "repo", ["./widgets", "N0TST/..", "../widgets", "N0TST/.", "N0TST//widgets", "N0TST/widgets/x"]
)
def test_dot_segments_in_the_repo_are_a_usage_error(world, repo):
    w = world(checks={A: [GATE]})
    p = w.run("--repo", repo, "--pr", "7", *FAST)
    assert p.returncode == 64, shown(p)
    assert w.calls() == []


def test_a_zero_interval_is_a_usage_error(world):
    w = world(checks={A: [GATE]})
    assert w.run("--repo", SLUG, "--pr", "7", "--interval", "0").returncode == 64


def test_repeated_gh_errors_back_off_and_the_backoff_is_bounded(world):
    w = world(checks={A: [GATE]}, check_failures=8)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "100000", "--hung-after", "100000")
    assert p.returncode == 0, shown(p)
    assert w.sleeps() == [10, 20, 40, 80, 80, 80, 80, 80]


def test_gh_stderr_is_not_mixed_into_the_data_stream(world):
    # A gh that writes a warning on stderr while succeeding must not corrupt the parsed head.
    w = world(checks={A: [GATE]}, head_warns=True)
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)


# --- numbers: only plain, bounded, base-10 integers ---------------------------------------------

LIMITS = {
    "--min-checks": (1, 100000),
    "--timeout": (1, 604800),
    "--hung-after": (1, 604800),
    "--interval": (1, 3600),
    "--merge-retries": (0, 100),
    "--merge-retry-delay": (0, 3600),
    "--pr": (1, 999999999),
    "--app-id": (1, 999999999),
}
BAD_NUMBERS = [
    "18446744073709551616",  # 2**64: wraps to 0 in a 64-bit comparison
    "9223372036854775808",  # 2**63
    "9223372036854775807",
    "08",  # invalid octal in arithmetic
    "007",
    "+5",
    "-5",
    " 5",
    "5 ",
    "",
    "0x10",
    "1e3",
    "3.0",
    "٣",  # Arabic-Indic digit three
    "５",  # fullwidth digit five
    "1_0",
]


def with_option(option: str, value: str) -> list[str]:
    if option == "--pr":
        return ["--repo", SLUG, "--pr", value]
    return ["--repo", SLUG, "--pr", "7", option, value]


@pytest.mark.parametrize("option", sorted(LIMITS))
@pytest.mark.parametrize("value", BAD_NUMBERS, ids=lambda v: repr(v))
def test_a_number_that_is_not_a_plain_bounded_integer_is_exit_64_naming_the_option(world, option, value):
    w = world(checks={A: [GATE]})
    p = w.run(*with_option(option, value))
    assert p.returncode == 64, shown(p)
    assert option in p.stderr
    assert w.calls() == []


@pytest.mark.parametrize("option", sorted(LIMITS))
def test_each_number_has_a_documented_maximum_and_zero_only_where_it_is_legal(world, option):
    low, high = LIMITS[option]
    w = world(checks={A: [GATE]})
    assert w.run(*with_option(option, str(high + 1))).returncode == 64
    if low > 0:
        assert w.run(*with_option(option, "0")).returncode == 64
    else:
        assert w.run(*with_option(option, "0"), *FAST).returncode == 0
    at_max = w.run(*with_option(option, str(high)), "--timeout", "60", "--interval", "10")
    assert at_max.returncode != 64, shown(at_max)


# --- a response that may not be the whole list ------------------------------------------------------


@ENGINES
def test_a_total_count_larger_than_the_runs_seen_is_not_green(world, engine):
    w = world(checks={A: [GATE]}, total_count_override=5)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "check-run list may be truncated" in p.stdout
    assert "verified" not in p.stdout


@ENGINES
def test_a_list_at_the_one_thousand_cap_is_not_green_even_when_it_is_consistent(world, engine):
    runs = [ok(f"job {n}") for n in range(999)] + [ok("CI green")]
    w = world(checks={A: [runs]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "check-run list may be truncated" in p.stdout


@ENGINES
def test_a_consistent_list_just_under_the_cap_is_green(world, engine):
    runs = [ok(f"job {n}") for n in range(998)] + [ok("CI green")]
    w = world(checks={A: [runs]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.load()["pages_served"] == 10


@ENGINES
def test_a_failure_that_is_visible_is_still_red_when_the_list_may_be_truncated(world, engine):
    w = world(checks={A: [[ok("CI green"), done("lint", "failure")]]}, total_count_override=50)
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 1


@ENGINES
def test_a_run_for_a_different_commit_is_not_green(world, engine):
    w = world(checks={A: [[ok("lint"), ("completed", "success", "CI green", 15368, B)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 1, shown(p)
    assert "head_sha" in p.stdout
    assert w.merges() == []


@ENGINES
def test_runs_for_the_pinned_commit_are_green(world, engine):
    w = world(checks={A: [[("completed", "success", "CI green", 15368, A)]]})
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0


# --- the cap GitHub applies is on check SUITES -----------------------------------------------------------
# "If there are more than 1000 check suites on a single git reference, this endpoint will limit check runs to the
# 1000 most recent check suites" (REST: list check runs for a Git reference). The run count cannot show that.


@ENGINES
@pytest.mark.parametrize("suites", [1000, 1001, 5000])
def test_a_suite_count_at_or_over_the_cap_is_not_green_however_few_runs_show(world, engine, suites):
    # 600 runs, so the run count is nowhere near 1000, yet the suites say the answer may have been cut.
    runs = [ok(f"job {n}") for n in range(599)] + [ok("CI green")]
    w = world(checks={A: [runs]}, suites=suites)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "check-run list may be truncated" in p.stdout
    assert "verified" not in p.stdout


@ENGINES
def test_999_suites_is_under_the_cap_and_green(world, engine):
    w = world(checks={A: [GATE]}, suites=999)
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0


@ENGINES
def test_600_runs_in_400_suites_is_green(world, engine):
    runs = [ok(f"job {n}") for n in range(599)] + [ok("CI green")]
    w = world(checks={A: [runs]}, suites=400)
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.load()["pages_served"] == 6


@ENGINES
@pytest.mark.parametrize("label", ["null", "string", "negative", "float", "huge", "bool"])
def test_an_unreadable_suite_count_is_not_green(world, engine, label):
    value = {"null": None, "string": "7", "negative": -1, "float": 3.5, "huge": 10**12, "bool": True}[label]
    w = world(checks={A: [GATE]}, suites=value)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, f"{label}\n" + shown(p)
    assert "check-run list may be truncated" in p.stdout


@ENGINES
def test_a_missing_suite_count_is_not_green(world, engine):
    w = world(checks={A: [GATE]}, suites_missing=True)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "60")
    assert p.returncode == 2, shown(p)
    assert "check-run list may be truncated" in p.stdout


@ENGINES
def test_a_failing_suite_call_is_not_green_and_backs_off(world, engine):
    w = world(checks={A: [GATE]}, suites_fail=True)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--timeout", "100", "--hung-after", "100000")
    assert p.returncode == 2, shown(p)
    assert "verified" not in p.stdout
    assert w.sleeps()[:3] == [10, 20, 40]


@ENGINES
def test_a_visible_failure_is_still_red_when_the_suite_count_is_over_the_cap(world, engine):
    w = world(checks={A: [[ok("CI green"), done("lint", "failure")]]}, suites=1000)
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 1


@ENGINES
def test_the_suite_count_is_asked_once_per_poll_not_once_per_page(world, engine):
    runs = [ok(f"job {n}") for n in range(299)] + [ok("CI green")]
    snaps = [[running("CI green")] + runs[:250], runs]
    w = world(checks={A: snaps})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    st = w.load()
    assert st["check_polls"] == 2
    assert st["suite_calls"] == st["check_polls"]
    asked = [c for c in w.calls() if "check-suites" in c]
    assert len(asked) == 2 and all("per_page=1" in c for c in asked)


# --- base64 must be canonical ---------------------------------------------------------------------------

SPELLINGS = {
    "bad padding": ("Y29tcGxldGVk", "Y29tcGxldGVk===="),
    "whitespace inside": ("Y29tcGxldGVk", "Y29t cGxldGVk"),
    "newline inside": ("Y29tcGxldGVk", "Y29t\ncGxldGVk"),
    "missing padding": ("Q0kgZ3JlZW4=", "Q0kgZ3JlZW4"),
    "non-zero trailing bits": ("Q0kgZ3JlZW4=", "Q0kgZ3JlZW5="),
    "stray character": ("Y29tcGxldGVk", "Y29tcGxldGVk!"),
}


@pytest.mark.parametrize("label", sorted(SPELLINGS))
def test_a_non_canonical_base64_spelling_is_hostile_not_decoded(world, label):
    w = world(checks={A: [GATE]}, mangle=[list(SPELLINGS[label])])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 1, f"{label}\n" + shown(p)
    assert "verified" not in p.stdout
    assert w.merges() == []


def test_the_mangling_harness_is_neutral_when_the_spelling_is_unchanged(world):
    w = world(checks={A: [GATE]}, mangle=[["Y29tcGxldGVk", "Y29tcGxldGVk"]])
    assert w.run("--repo", SLUG, "--pr", "7", *FAST).returncode == 0


# --- docs hold the limits ------------------------------------------------------------------------------------


def test_the_page_documents_the_numeric_limits_and_the_truncation_rule():
    text = PAGE.read_text()
    for option, (_low, high) in LIMITS.items():
        assert re.search(rf"`{option}`[^\n]*\b{high}\b", text), f"the maximum of {option} is not in the page"
    assert "may be truncated" in text
    assert "1000" in text
    assert "check-suites" in text


# --- red -----------------------------------------------------------------------


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required", "startup_failure"])
def test_a_failed_or_cancelled_gate_is_red(world, conclusion):
    w = world(checks={A: [[ok("lint"), done("CI green", conclusion)]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 1, shown(p)
    assert conclusion in p.stdout
    assert w.outputs()["result"] == "red"


@pytest.mark.parametrize("conclusion", ["failure", "cancelled"])
def test_a_failed_check_is_red_even_when_the_gate_succeeded(world, conclusion):
    w = world(checks={A: [[ok("CI green"), done("deploy preview", conclusion)]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 1, shown(p)
    assert w.merges() == []


def test_red_is_immediate_while_the_gate_is_still_running(world):
    w = world(checks={A: [[running("CI green"), done("lint", "failure")]]})
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 1, shown(p)
    assert w.sleeps() == []


# --- timeout and hung -----------------------------------------------------------


def test_timeout_exits_2_after_the_stated_time(world):
    w = world(checks={A: [[running("CI green")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "30", "--timeout", "100", "--hung-after", "1000")
    assert p.returncode == 2, shown(p)
    assert sum(w.sleeps()) == 120, "polls at 0, 30, 60, 90 and 120 s: the first one at or past 100 s ends it"
    assert w.outputs()["result"] == "timeout"


def test_hung_exits_3_when_nothing_changes(world):
    w = world(checks={A: [[running("CI green"), ok("lint")]]})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--hung-after", "50", "--timeout", "1000")
    assert p.returncode == 3, shown(p)
    assert sum(w.sleeps()) == 50
    assert w.outputs()["result"] == "hung"


def test_progress_resets_the_hung_clock(world):
    # A new check completes every poll; the run is slow but not hung, so only the timeout ends it.
    snaps = [[running("CI green")] + [ok(f"job {n}") for n in range(k)] for k in range(1, 30)]
    w = world(checks={A: snaps})
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--hung-after", "35", "--timeout", "200")
    assert p.returncode == 2, shown(p)


def test_a_failing_api_is_retried_and_eventually_hung_not_green(world):
    w = world(checks={A: [GATE]}, check_failures=1000)
    p = w.run("--repo", SLUG, "--pr", "7", "--interval", "10", "--hung-after", "50", "--timeout", "1000")
    assert p.returncode == 3, shown(p)


def test_a_transient_api_failure_is_retried(world):
    w = world(checks={A: [GATE]}, check_failures=2)
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.load()["check_polls"] == 3


# --- merge ------------------------------------------------------------------------


def test_merge_is_a_squash_pinned_to_the_verified_sha(world):
    w = world(checks={A: [GATE]})
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.merges() == [f"pr merge 7 -R {SLUG} --squash --match-head-commit {A}"]
    assert w.outputs() == {"result": "green", "sha": A, "merged": "true"}
    assert "--admin" not in " ".join(w.merges()) and "--auto" not in " ".join(w.merges())


def test_merge_can_delete_the_branch(world):
    w = world(checks={A: [GATE]})
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--delete-branch", *FAST)
    assert p.returncode == 0, shown(p)
    assert w.merges()[0].endswith(f"--match-head-commit {A} --delete-branch")


def test_merge_retries_a_policy_block_a_bounded_number_of_times(world):
    block = {"rc": 1, "err": "the base branch policy prohibits the merge"}
    w = world(checks={A: [GATE]}, merge_results=[block, block, {"rc": 0}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retry-delay", "30", *FAST)
    assert p.returncode == 0, shown(p)
    assert len(w.merges()) == 3
    assert w.sleeps() == [30, 30]


def test_merge_gives_up_after_the_retry_bound_with_exit_1(world):
    block = {"rc": 1, "err": "the base branch policy prohibits the merge"}
    w = world(checks={A: [GATE]}, merge_results=[block])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retries", "2", "--merge-retry-delay", "5", *FAST)
    assert p.returncode == 1, shown(p)
    assert len(w.merges()) == 3, "one try plus two retries"
    assert "merge blocked" in p.stdout
    assert w.outputs()["merged"] == "false"


def test_zero_merge_retries_means_one_attempt(world):
    w = world(checks={A: [GATE]}, merge_results=[{"rc": 1, "err": "the base branch policy prohibits the merge"}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retries", "0", *FAST)
    assert p.returncode == 1, shown(p)
    assert len(w.merges()) == 1


def test_head_moved_between_the_last_check_and_the_merge_is_exit_4(world):
    # The head moves to B the instant the green poll of A is read: the re-read before merging catches it.
    w = world(checks={A: [GATE]}, moves=[{"after_check_polls": 1, "head": B}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 4, shown(p)
    assert w.merges() == []
    assert "verified" not in p.stdout


def test_head_moved_during_the_merge_is_exit_4_and_not_retried(world):
    w = world(checks={A: [GATE]}, merge_results=[{"rc": 1, "err": "head branch was modified", "set_head": B}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 4, shown(p)
    assert len(w.merges()) == 1


def test_a_merge_that_landed_before_the_error_is_success(world):
    w = world(checks={A: [GATE]}, merge_results=[{"rc": 1, "err": "already merged?", "merged": True}])
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", *FAST)
    assert p.returncode == 0, shown(p)
    assert len(w.merges()) == 1
    assert w.outputs()["merged"] == "true"


# --- secrets and input -----------------------------------------------------------


def test_the_token_is_never_printed(world):
    # The token shows up in the text of failed gh calls and in a failed merge; neither may reach the log.
    w = world(
        checks={A: [GATE]},
        check_failures=1,
        merge_results=[{"rc": 1, "err": "the base branch policy prohibits the merge TOKEN here"}, {"rc": 0}],
    )
    p = w.run("--repo", SLUG, "--pr", "7", "--merge", "--merge-retry-delay", "1", *FAST)
    assert p.returncode == 0, shown(p)
    assert TOKEN not in p.stdout + p.stderr
    assert "prohibits the merge *** here" in p.stdout
    assert TOKEN not in (w.out.read_text() if w.out.exists() else "")


def test_the_token_is_redacted_when_the_head_cannot_be_read(world):
    w = world(checks={A: [GATE]}, head_read_fails=True)
    p = w.run("--repo", SLUG, "--pr", "7", *FAST)
    assert p.returncode == 1, shown(p)
    assert TOKEN not in p.stdout + p.stderr
    assert "***" in p.stdout + p.stderr


@pytest.mark.parametrize(
    "args",
    [
        ["--repo", SLUG],
        ["--repo", "not a slug", "--pr", "1"],
        ["--repo", SLUG, "--sha", "abc123"],
        ["--repo", SLUG, "--sha", A.upper()],
        ["--repo", SLUG, "--pr", "x"],
        ["--repo", SLUG, "--sha", A, "--merge"],
        ["--repo", SLUG, "--pr", "1", "--min-checks", "0"],
        ["--repo", SLUG, "--pr", "1", "--on-push", "ignore"],
        ["--repo", SLUG, "--pr", "1", "--timeout", "-5"],
        ["--repo", SLUG, "--pr", "1", "--interval"],
        ["--repo", SLUG, "--pr", "1", "--bogus", "1"],
        ["--repo", SLUG, "--pr", "1", "--context", "a\nb"],
    ],
)
def test_bad_input_is_exit_64_and_calls_nothing(world, args):
    w = world(checks={A: [GATE]})
    p = w.run(*args)
    assert p.returncode == 64, shown(p)
    assert w.calls() == []


def test_the_script_is_plain_and_does_not_trace_or_eval():
    text = SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"\bset\s+-[a-z]*x", code), "tracing would print the token"
    assert not re.search(r"\beval\b", code)
    assert os.access(SCRIPT, os.X_OK), "scripts/wait-ci.sh must be executable"


# --- the composite action ------------------------------------------------------------


def action() -> dict:
    return yaml.safe_load(ACTION.read_text())


def action_step() -> dict:
    steps = action()["runs"]["steps"]
    assert len(steps) == 1
    return steps[0]


def test_the_action_is_composite_with_one_bash_step_that_never_interpolates_inputs():
    a = action()
    assert a["runs"]["using"] == "composite"
    step = action_step()
    assert step["shell"] == "bash"
    assert "${{" not in step["run"], "inputs reach the script through env, never through the script text"
    for key in ("repo", "pr", "sha", "context", "min-checks", "timeout", "hung-after", "interval", "on-push", "merge"):
        assert key in a["inputs"], key
    assert set(a["outputs"]) == {"result", "sha", "merged"}


def test_the_action_defaults_match_the_documented_ones():
    inputs = action()["inputs"]
    assert inputs["context"]["default"] == "CI green"
    assert inputs["on-push"]["default"] == "abort"
    assert inputs["merge"]["default"] == "false"
    assert inputs["token"]["default"] == "${{ github.token }}"
    for name, spec in inputs.items():
        assert spec.get("description"), f"input {name} needs a description"


def test_the_action_finds_the_script_it_wraps():
    step = action_step()
    assert "GITHUB_ACTION_PATH" in step["run"]
    rel = re.search(r'"\$GITHUB_ACTION_PATH/([^"]+)"', step["run"])
    assert rel, "the step must call the script by its path from the action directory"
    assert (ACTION.parent / rel.group(1)).resolve() == SCRIPT.resolve()


def run_action(w: World, **inputs: str) -> subprocess.CompletedProcess[str]:
    env = w.env()
    env.update({k: v for k, v in action_step().get("env", {}).items() if not v.startswith("${{")})
    mapping = action_step()["env"]
    for var, expr in mapping.items():
        m = re.fullmatch(r"\$\{\{ inputs\.([a-z-]+) \}\}", expr)
        if m:
            name = m.group(1)
            default = action()["inputs"][name].get("default", "")
            value = inputs.get(name, default)
            env[var] = TOKEN if name == "token" else value
    env["GITHUB_ACTION_PATH"] = str(ACTION.parent)
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", action_step()["run"]],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


BASE_INPUTS = {"repo": SLUG, "pr": "7", "interval": "10", "timeout": "300", "hung-after": "1000"}


def test_the_action_runs_the_script_green_and_merges(world):
    w = world(checks={A: [GATE]})
    p = run_action(w, **BASE_INPUTS, merge="true")
    assert p.returncode == 0, shown(p)
    assert w.merges() == [f"pr merge 7 -R {SLUG} --squash --match-head-commit {A}"]
    assert w.outputs()["sha"] == A


def test_the_action_passes_a_nonzero_exit_code_through(world):
    w = world(checks={A: [[ok("lint"), done("CI green", "failure")]]})
    assert run_action(w, **BASE_INPUTS).returncode == 1
    w2 = world(checks={A: [[running("CI green")]]})
    assert run_action(w2, **{**BASE_INPUTS, "timeout": "60"}).returncode == 2
    w3 = world(checks={A: [[running("CI green")]]}, moves=[{"after_check_polls": 2, "head": B}])
    assert run_action(w3, **BASE_INPUTS).returncode == 4


def test_the_action_takes_several_contexts_one_per_line(world):
    w = world(checks={A: [[ok("CI green")]]})
    p = run_action(w, **{**BASE_INPUTS, "context": "CI green\nSecurity", "timeout": "60"})
    assert p.returncode == 2, shown(p)
    assert "'Security' not reported" in p.stdout


def test_a_blank_context_input_means_no_named_gate_but_still_needs_checks(world):
    w = world(checks={A: [[]]})
    assert run_action(w, **{**BASE_INPUTS, "context": "", "timeout": "60"}).returncode == 2
    w2 = world(checks={A: [[ok("lint")]]})
    assert run_action(w2, **{**BASE_INPUTS, "context": ""}).returncode == 0


def test_the_action_rejects_a_merge_value_that_is_not_true_or_false(world):
    w = world(checks={A: [GATE]})
    p = run_action(w, **BASE_INPUTS, merge="yes")
    assert p.returncode == 64, shown(p)
    assert w.calls() == []


# --- docs -------------------------------------------------------------------------------


def test_the_page_documents_every_exit_code_and_input():
    text = PAGE.read_text()
    for code in ("0", "1", "2", "3", "4", "5", "64"):
        assert re.search(rf"^\| `{code}` \|", text, re.M), f"exit code {code} is not in the page's table"
    for name in action()["inputs"]:
        assert f"`{name}`" in text, f"input {name} is not documented"
    assert "tests/test_wait_ci.py" in text


def test_the_script_header_and_page_agree_on_the_exit_codes():
    header = {m.group(1) for m in re.finditer(r"^#\s+(\d+)\s{2,}", SCRIPT.read_text(), re.M)}
    assert header == {"0", "1", "2", "3", "4", "5", "64"}


def test_the_action_is_listed_in_the_readme_and_repository_map():
    assert ".github/actions/wait-ci" in (REPO / "README.md").read_text()
    assert ".github/actions/wait-ci" in (REPO / "docs" / "wiki" / "Repository-map.md").read_text()
    assert "(Action-wait-ci.md)" in (REPO / "docs" / "wiki" / "_Sidebar.md").read_text()


def test_the_changelog_names_the_watcher():
    changelog = (REPO / "CHANGELOG.md").read_text()
    unreleased = changelog.split("## Unreleased", 1)[1].split("\n## ", 1)[0]
    assert "wait-ci" in unreleased and "#223" in unreleased
