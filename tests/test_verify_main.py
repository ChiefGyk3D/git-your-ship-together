"""scripts/verify_main.py and main-verify.yml: main may not sit with its required checks unverified.

The logic runs against a stub with the API's two methods (`get`, `post`) and a fake clock, so nothing here touches
the network or sleeps. Every failing case has a passing twin, so a check that fails everything cannot pass.
"""

from __future__ import annotations

import http.server
import importlib.util
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "verify_main.py"
WORKFLOW = REPO / ".github" / "workflows" / "main-verify.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"

spec = importlib.util.spec_from_file_location("verify_main", SCRIPT)
vm = importlib.util.module_from_spec(spec)
sys.modules["verify_main"] = vm  # dataclasses looks its module up here
spec.loader.exec_module(vm)

SLUG = "example/proj"
HEAD = "a" * 40
OTHER = "b" * 40


def stamp(age_seconds: float) -> str:
    return (datetime.now(UTC) - timedelta(seconds=age_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_doc(name="CI green", status="completed", conclusion="success", app=vm.ACTIONS_APP_ID):
    return {"name": name, "status": status, "conclusion": conclusion, "app": {"id": app}}


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.sleeps += 1


class Stub:
    """GitHub REST for one repository. `runs` maps a context to the list of check runs on HEAD; `after` is a hook
    called with the number of reads so far, so a test can change the world while the script waits."""

    def __init__(self, runs=None, protection="default", age=3600, live=(), head=HEAD, after=None):
        self.runs = {} if runs is None else runs
        self.protection = protection  # "default" | an HTTP status | a dict
        self.age = age
        self.live = list(live)
        self.head = head
        self.after = after
        self.reads = 0
        self.posts = []

    def get(self, path):
        self.reads += 1
        if self.after:
            self.after(self)
        bare = path.split("?")[0]
        if bare == f"/repos/{SLUG}":
            return {"default_branch": "main"}
        if bare == f"/repos/{SLUG}/branches/main":
            return {"commit": {"sha": self.head, "commit": {"committer": {"date": stamp(self.age)}}}}
        if bare == f"/repos/{SLUG}/branches/main/protection/required_status_checks":
            if isinstance(self.protection, int):
                raise vm.ApiError(f"GET {bare} answered HTTP {self.protection}", self.protection)
            if self.protection == "default":
                return {"contexts": ["CI green"], "checks": [{"context": "CI green", "app_id": vm.ACTIONS_APP_ID}]}
            return self.protection
        if bare.startswith(f"/repos/{SLUG}/commits/") and bare.endswith("/check-runs"):
            name = path.split("check_name=")[1].split("&")[0].replace("+", " ")
            sha = bare.split("/")[5]
            return {"check_runs": self.runs.get(name, []) if sha == self.head else []}
        if bare == f"/repos/{SLUG}/actions/workflows/ci.yml/runs":
            return {"workflow_runs": self.live}
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path, body):
        self.posts.append((path, body))
        return {}


def go(phase, api, *extra, clock=None, env_out=None, monkeypatch=None, capsys=None):
    clock = clock or Clock()
    monkeypatch.setenv("GITHUB_REPOSITORY", SLUG)
    if env_out:
        monkeypatch.setenv("GITHUB_OUTPUT", str(env_out))
    else:
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    code = vm.main([phase, *extra], api=api, clock=clock, sleep=clock.sleep)
    return code, capsys.readouterr().out, clock


@pytest.fixture
def run(monkeypatch, capsys, tmp_path):
    out = tmp_path / "out"

    def call(phase, api, *extra, clock=None):
        code, text, clk = go(phase, api, *extra, clock=clock, env_out=out, monkeypatch=monkeypatch, capsys=capsys)
        return code, text, clk, (out.read_text() if out.exists() else "")

    return call


# --- fixture 1: a green head ------------------------------------------------------------------


def test_green_head_is_quiet_and_dispatches_nothing(run):
    api = Stub({"CI green": [run_doc()]})
    code, text, clock, outputs = run("assess", api)
    assert code == 0 and "verdict=green" in outputs and f"sha={HEAD}" in outputs
    assert "::error" not in text and "::warning" not in text
    assert api.posts == [] and clock.sleeps == 0


def test_confirm_on_a_green_head_passes_at_once(run):
    code, text, clock, _ = run("confirm", Stub({"CI green": [run_doc()]}))
    assert code == 0 and clock.sleeps == 0 and "ok   main head" in text


# --- fixture 2: a head with no runs -----------------------------------------------------------


def test_old_head_with_no_runs_asks_for_a_dispatch(run):
    api = Stub({}, age=3600)
    code, text, clock, outputs = run("assess", api)
    assert code == 0 and "verdict=dispatch" in outputs and clock.sleeps == 0


def test_young_head_with_no_runs_waits_out_the_grace_period_then_dispatches(run):
    api = Stub({}, age=200)
    code, _, clock, outputs = run("assess", api, "--grace-seconds", "600", "--poll-seconds", "30")
    assert code == 0 and "verdict=dispatch" in outputs
    assert 360 <= clock.now <= 420, "waits for what is left of the 600 s, not the whole of it and not none"


def test_a_check_that_appears_during_the_grace_period_means_no_dispatch(run):
    runs = {}
    api = Stub(runs, age=100)
    api.after = lambda s: (
        runs.update({"CI green": [run_doc(status="in_progress", conclusion=None)]}) if s.reads > 8 else None
    )
    code, _, _, outputs = run("assess", api)
    assert code == 0 and "verdict=pending" in outputs and api.posts == []


def test_a_queued_ci_run_for_the_head_means_no_second_dispatch(run):
    api = Stub({}, age=3600, live=[{"status": "queued"}])
    code, _, _, outputs = run("assess", api)
    assert code == 0 and "verdict=pending" in outputs


def test_a_finished_ci_run_without_the_check_does_not_hide_the_gap(run):
    api = Stub({}, age=3600, live=[{"status": "completed"}])
    _, _, _, outputs = run("assess", api)
    assert "verdict=dispatch" in outputs


def test_dispatch_posts_the_default_branch_once(run):
    api = Stub({}, age=3600)
    code, text, _, _ = run("dispatch", api, "--sha", HEAD)
    assert code == 0 and api.posts == [(f"/repos/{SLUG}/actions/workflows/ci.yml/dispatches", {"ref": "main"})]
    assert "dispatched ci.yml on main" in text


def test_dispatch_skips_when_main_moved_on(run):
    api = Stub({}, head=OTHER)
    code, text, _, _ = run("dispatch", api, "--sha", HEAD)
    assert code == 0 and api.posts == [] and "moved" in text


def test_confirm_goes_green_once_the_dispatched_run_reports(run):
    runs = {}
    api = Stub(runs)
    api.after = lambda s: runs.update({"CI green": [run_doc()]}) if s.reads > 12 else None
    code, text, clock, _ = run("confirm", api)
    assert code == 0 and clock.sleeps > 0 and "ok   main head" in text


# --- fixture 3: a head with a red run ---------------------------------------------------------


def test_red_required_check_fails_with_counts_and_names(run):
    api = Stub({"CI green": [run_doc(conclusion="failure")]})
    for phase in ("assess", "confirm"):
        code, text, clock, _ = run(phase, api)
        assert code == 1 and clock.sleeps == 0, "a red check fails at once, without waiting"
        assert "::error title=main-verify::" in text
        assert "1 required: 0 green, 1 red, 0 running, 0 missing" in text and '"CI green"' in text
        assert api.posts == []


@pytest.mark.parametrize("conclusion", ["cancelled", "timed_out", "skipped", "neutral", "action_required", None])
def test_anything_but_success_is_red(run, conclusion):
    code, text, _, _ = run("confirm", Stub({"CI green": [run_doc(conclusion=conclusion)]}))
    assert code == 1 and "1 red" in text


def test_a_green_check_from_another_app_does_not_count(run):
    api = Stub({"CI green": [run_doc(app=12345)]})
    code, text, _, _ = run("confirm", api, "--wait-seconds", "60")
    assert code == 1 and "1 missing" in text


def test_only_the_pinned_app_counts_when_the_protection_names_one(run):
    protection = {"checks": [{"context": "CI green", "app_id": 777}], "contexts": ["CI green"]}
    assert run("confirm", Stub({"CI green": [run_doc(app=777)]}, protection=protection))[0] == 0
    assert run("confirm", Stub({"CI green": [run_doc()]}, protection=protection), "--wait-seconds", "30")[0] == 1


# --- fixture 4: required checks unreadable ----------------------------------------------------


@pytest.mark.parametrize("status", [401, 403, 404])
def test_unreadable_protection_falls_back_to_the_list(run, status):
    api = Stub({"CI green": [run_doc()], "Other": [run_doc("Other", conclusion="failure")]}, protection=status)
    code, text, _, _ = run("assess", api)
    assert code == 0 and "fallback list" in text and f"HTTP {status}" in text


def test_fallback_list_is_the_input(run):
    api = Stub({"A": [run_doc("A")], "B": [run_doc("B", conclusion="failure")]}, protection=403)
    code, text, _, _ = run("confirm", api, "--fallback-contexts", "A, B")
    assert code == 1 and "2 required: 1 green, 1 red" in text and '"B"' in text


def test_a_server_error_reading_the_protection_is_not_swallowed(run):
    code, text, _, _ = run("assess", Stub({"CI green": [run_doc()]}, protection=500))
    assert code == 1 and "HTTP 500" in text


def test_protection_with_no_required_checks_uses_the_fallback(run):
    api = Stub({"CI green": [run_doc()]}, protection={"contexts": [], "checks": []})
    code, text, _, _ = run("assess", api)
    assert code == 0 and "requires no status check" in text


def test_every_protection_context_is_required(run):
    protection = {"contexts": ["CI green", "Security"], "checks": []}
    api = Stub({"CI green": [run_doc()]}, protection=protection)
    code, text, _, _ = run("confirm", api, "--wait-seconds", "30")
    assert code == 1 and '"Security"' in text and "1 missing" in text


# --- fixture 5: the bounded wait runs out ------------------------------------------------------


def test_wait_exhausted_fails_loudly_and_stops_polling(run):
    api = Stub({})
    code, text, clock, _ = run("confirm", api, "--wait-seconds", "120", "--poll-seconds", "30")
    assert code == 1 and "::error title=main-verify::" in text
    assert "no completed green required check after 120s" in text and "1 missing" in text
    assert clock.now == 120 and api.reads < 40, "the wait is bounded by the deadline"


def test_a_check_still_running_at_the_deadline_fails(run):
    api = Stub({"CI green": [run_doc(status="in_progress", conclusion=None)]})
    code, text, _, _ = run("confirm", api, "--wait-seconds", "60")
    assert code == 1 and "1 running" in text


def test_the_assess_wait_never_exceeds_the_grace(run):
    code, _, clock, _ = run("assess", Stub({}, age=0), "--grace-seconds", "300")
    assert code == 0 and clock.now <= 330


def test_a_moved_head_is_verified_in_its_own_right(run):
    api = Stub({}, age=100)

    def move(s):
        if s.reads > 6:
            s.head = OTHER
            s.runs = {"CI green": [run_doc()]}

    api.after = move
    code, _, _, outputs = run("assess", api)
    assert code == 0 and f"sha={OTHER}" in outputs and "verdict=green" in outputs


# --- input checks ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["--workflow", "../ci.yml"],
        ["--workflow", "ci.txt"],
        ["--sha", "xyz"],
        ["--poll-seconds", "0"],
        ["--wait-seconds", "999999"],
        ["--grace-seconds", "-1"],
        ["--api-base", "http://example.com"],
        ["--api-base", "ftp://example.com"],
    ],
)
def test_bad_arguments_are_refused_before_any_request(args, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", SLUG)
    with pytest.raises(SystemExit) as exc:
        vm.main(["assess", *args])
    assert exc.value.code == 2


def test_repository_must_be_owner_name(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "nope")
    with pytest.raises(SystemExit):
        vm.main(["assess"], api=Stub())


def test_context_names_cannot_forge_a_workflow_command(run):
    protection = {"contexts": ["x\n::error::forged"], "checks": []}
    code, text, _, _ = run("confirm", Stub({}, protection=protection), "--wait-seconds", "30")
    assert code == 1 and "\n::error::forged" not in text and "\\n::error::forged" in text


# --- the HTTP layer, against a local server ----------------------------------------------------


@pytest.fixture
def server():
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()
            elif self.path == "/denied":
                self.send_response(403)
                self.end_headers()
            else:
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(204)
            self.end_headers()

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def test_http_layer_reads_json_posts_and_reports_status(server):
    base, seen = server
    api = vm.Api(base, "tok")
    assert api.get("/ok") == {"ok": True} and seen[0][1] == "Bearer tok"
    assert api.post("/x", {"a": 1}) == {}
    with pytest.raises(vm.ApiError) as exc:
        api.get("/denied")
    assert exc.value.status == 403


def test_http_layer_refuses_a_redirect(server):
    base, _ = server
    with pytest.raises(vm.ApiError) as exc:
        vm.Api(base, "tok").get("/redirect")
    assert exc.value.status == 302


# --- the workflow ------------------------------------------------------------------------------


def wf():
    return yaml.safe_load(WORKFLOW.read_text())


def on(doc):
    return doc.get("on") or doc.get(True)


def test_triggers_are_push_to_main_a_six_hour_schedule_and_manual():
    trig = on(wf())
    assert trig["push"]["branches"] == ["main"]
    assert trig["schedule"] == [{"cron": "17 */6 * * *"}]
    assert "workflow_dispatch" in trig and "pull_request" not in trig and "pull_request_target" not in trig


def test_ci_can_be_dispatched_and_the_workflow_names_it():
    """The dispatch is useless unless ci.yml still has workflow_dispatch; this is the guard."""
    assert "workflow_dispatch" in on(yaml.safe_load(CI.read_text()))
    text = WORKFLOW.read_text()
    assert 'CI_WORKFLOW: "ci.yml"' in text or "CI_WORKFLOW: ci.yml" in text


def test_only_the_dispatch_job_can_write_and_only_actions():
    doc = wf()
    assert doc["permissions"] == {}
    seen = {}
    for name, job in doc["jobs"].items():
        seen[name] = job["permissions"]
        for scope, level in job["permissions"].items():
            assert level == "read" or (name == "dispatch" and scope == "actions"), (name, scope, level)
    assert seen["dispatch"] == {"contents": "read", "actions": "write"}
    assert seen["assess"]["checks"] == seen["confirm"]["checks"] == "read"


def test_every_job_is_default_branch_only_bounded_and_secretless():
    text = WORKFLOW.read_text()
    assert "secrets." not in text.replace("secrets.GITHUB_TOKEN", "") and "continue-on-error" not in text
    for name, job in wf()["jobs"].items():
        assert "refs/heads/" in job["if"] and "default_branch" in job["if"], name
        assert isinstance(job["timeout-minutes"], int) and job["timeout-minutes"] <= 45, name
        assert job["steps"][0]["uses"].startswith("step-security/harden-runner@"), name
        for step in job["steps"]:
            assert "${{" not in step.get("run", "").replace("${{ env.", ""), (name, "no expression in a script")


def test_the_phases_are_chained_so_a_failed_dispatch_cannot_pass():
    jobs = wf()["jobs"]
    assert jobs["dispatch"]["needs"] == "assess" and "'dispatch'" in jobs["dispatch"]["if"]
    needs = jobs["confirm"]["needs"]
    assert set(needs) == {"assess", "dispatch"}
    cond = jobs["confirm"]["if"]
    assert "always()" in cond and "needs.dispatch.result" in cond and "'green'" in cond


def test_workflow_bounds_match_the_job_timeouts():
    jobs = wf()["jobs"]
    # assess waits at most the 600 s grace, confirm at most its wait, each with room to spare inside the job timeout
    assert jobs["assess"]["timeout-minutes"] * 60 > 600 + 120
    assert jobs["confirm"]["timeout-minutes"] * 60 > 1500 + 120
