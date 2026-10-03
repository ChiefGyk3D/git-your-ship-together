"""The docs-pages and wiki-publish workflows, and the two pull-request checks.

The general rules (pinning, permissions, harden-runner, injection) are held
for every reusable workflow in test_workflows.py. This file holds what is
particular to these: where the write grants sit, what only runs on the default
branch, and, for the wiki, the publish script itself run against a local git
repository, because a script nobody runs is a script nobody tested.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
DEFAULT_BRANCH_ONLY = "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def calls(name: str) -> dict:
    doc = load(name)
    return (doc.get("on") or doc.get(True))["workflow_call"]


def step(job: dict, name_prefix: str) -> dict:
    found = [s for s in job["steps"] if str(s.get("name", "")).startswith(name_prefix)]
    assert len(found) == 1, f"expected exactly one step starting {name_prefix!r}, found {len(found)}"
    return found[0]


# --- docs-pages -------------------------------------------------------------


def test_docs_pages_defaults_are_the_documented_ones():
    inputs = calls("docs-pages.yml")["inputs"]
    assert inputs["build-command"]["default"] == "mkdocs build --strict"
    assert inputs["install-command"]["default"] == 'pip install -e ".[docs]"'
    assert inputs["python-version"]["default"] == "3.11"
    assert inputs["deploy"]["default"] is True


def test_docs_pages_holds_the_pages_writes_on_the_deploy_job_alone():
    jobs = load("docs-pages.yml")["jobs"]
    assert jobs["deploy"]["permissions"] == {"pages": "write", "id-token": "write"}
    assert jobs["build"]["permissions"] == {"contents": "read"}, "the job that runs the caller's build holds no token"
    assert load("docs-pages.yml")["permissions"] == {"contents": "read"}


def test_docs_pages_deploys_only_from_the_default_branch_and_never_from_a_pull_request():
    jobs = load("docs-pages.yml")["jobs"]
    cond = jobs["deploy"]["if"]
    assert "inputs.deploy" in cond and "github.event_name != 'pull_request'" in cond and DEFAULT_BRANCH_ONLY in cond
    upload = step(jobs["build"], "Upload the Pages artifact")
    assert upload["if"] == cond, "the artifact is uploaded exactly when the deploy will run"
    assert jobs["deploy"]["needs"] == "build"
    assert "pull_request" in cond


def test_docs_pages_serialises_deployments_without_cancelling_one():
    deploy = load("docs-pages.yml")["jobs"]["deploy"]
    assert deploy["concurrency"] == {"group": "pages", "cancel-in-progress": False}
    assert deploy["environment"]["name"] == "github-pages"


def test_docs_pages_says_what_to_do_when_pages_is_not_configured():
    deploy = load("docs-pages.yml")["jobs"]["deploy"]
    check = step(deploy, "Check that Pages is set up")
    assert "Source to GitHub Actions" in check["run"] and "/settings/pages" in check["run"]
    assert deploy["steps"].index(check) < len(deploy["steps"]) - 1, "the check runs before deploy-pages"
    assert check["env"]["GH_TOKEN"] == "${{ github.token }}"


# --- wiki-publish -----------------------------------------------------------


def test_wiki_publish_generates_read_only_and_publishes_with_the_only_write():
    jobs = load("wiki-publish.yml")["jobs"]
    assert jobs["generate"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "write"}
    assert jobs["publish"]["needs"] == "generate"
    checkouts = [s for s in jobs["publish"]["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert [s["with"]["repository"] for s in checkouts] == ["${{ github.repository }}.wiki"], (
        "the job holding the write token checks out the wiki and nothing else, and runs none of the caller's code"
    )
    assert "inputs.generate-command" not in str(jobs["publish"])
    assert "inputs.install-command" not in str(jobs["publish"])


def test_wiki_publish_publishes_only_from_the_default_branch_and_never_cancels():
    jobs = load("wiki-publish.yml")["jobs"]
    cond = jobs["publish"]["if"]
    assert "inputs.publish" in cond and "github.event_name != 'pull_request'" in cond and DEFAULT_BRANCH_ONLY in cond
    assert "if" not in jobs["generate"], "generation runs on pull requests so a broken generator fails the review"
    assert jobs["publish"]["concurrency"] == {"group": "wiki", "cancel-in-progress": False}


def test_wiki_publish_generate_command_is_required_and_has_no_default():
    spec = calls("wiki-publish.yml")["inputs"]["generate-command"]
    assert spec["required"] is True and "default" not in spec
    assert calls("wiki-publish.yml")["inputs"]["out-dir"]["default"] == "wiki-out"


def test_wiki_publish_hands_git_no_credential_in_a_variable_header_or_url():
    text = (WORKFLOWS / "wiki-publish.yml").read_text().lower()
    for banned in ("extraheader", "base64", "add-mask", "x-access-token", "@github.com"):
        assert banned not in text, f"wiki-publish.yml mentions {banned!r}"
    publish = load("wiki-publish.yml")["jobs"]["publish"]
    checkout = step(publish, "Check out the wiki")
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["continue-on-error"] is True
    assert checkout["with"]["repository"] == "${{ github.repository }}.wiki"
    assert checkout["with"]["path"] == "wiki"
    assert checkout["with"]["token"] == "${{ github.token }}"
    assert checkout["with"]["persist-credentials"] is True
    assert "TOKEN" not in str([s.get("env") for s in publish["steps"]]), "no step receives the token as a variable"


# The two scripts that follow the wiki checkout, run for real in a scratch
# workspace: the test makes `wiki/` the way the checkout does (a clone), and the
# push goes to a local bare repository, so nothing here touches a network.


@pytest.fixture
def wiki_env(tmp_path: Path):
    job = load("wiki-publish.yml")["jobs"]["publish"]
    guard = step(job, "Check that the wiki exists")["run"]
    publish = step(job, "Replace the wiki")["run"]
    remote = tmp_path / "remote.git"
    seed = tmp_path / "seed"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "master", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "master", str(seed)], check=True)
    (seed / "Old.md").write_text("stale page\n")
    (seed / "Keep.md").write_text("old text\n")
    git = ["git", "-C", str(seed), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "first page"], check=True)
    subprocess.run([*git, "push", "-q", str(remote), "master"], check=True)

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "Keep.md").write_text("new text\n")
    (tree / "Added.md").write_text("added\n")
    workspace = tmp_path / "workspace"

    def run(sha: str, exists: bool = True):
        subprocess.run(["rm", "-rf", str(workspace)], check=True)
        workspace.mkdir()
        if exists:
            subprocess.run(["git", "clone", "-q", str(remote), str(workspace / "wiki")], check=True)
        env = {
            **os.environ,
            "REPO": "owner/repo",
            "SERVER_URL": "https://example.invalid",
            "SOURCE_SHA": sha,
            "TREE": str(tree),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        }
        result = subprocess.run(["bash", "-c", guard], env=env, cwd=workspace, capture_output=True, text=True)
        if result.returncode != 0:
            return result
        return subprocess.run(["bash", "-c", publish], env=env, cwd=workspace, capture_output=True, text=True)

    return run, remote, tree


def remote_files(remote: Path) -> dict[str, str]:
    names = subprocess.run(
        ["git", "-C", str(remote), "ls-tree", "-r", "--name-only", "master"], capture_output=True, text=True, check=True
    ).stdout.split()
    return {
        n: subprocess.run(["git", "-C", str(remote), "show", f"master:{n}"], capture_output=True, text=True).stdout
        for n in names
    }


def remote_log(remote: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(remote), "log", "--format=%an <%ae> %s"], capture_output=True, text=True, check=True
    ).stdout
    return out.strip().splitlines()


def test_publish_replaces_the_wiki_commits_as_the_bot_and_names_the_source(wiki_env):
    run, remote, _ = wiki_env
    result = run("abc1234")
    assert result.returncode == 0, result.stdout + result.stderr
    assert remote_files(remote) == {"Keep.md": "new text\n", "Added.md": "added\n"}, "the stale page must be gone"
    head = remote_log(remote)[0]
    assert head.startswith("github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>")
    assert "abc1234" in head and "owner/repo" in head


def test_publish_pushes_nothing_when_nothing_changed(wiki_env):
    run, remote, _ = wiki_env
    assert run("one").returncode == 0
    before = remote_log(remote)
    second = run("two")
    assert second.returncode == 0 and "already current" in second.stdout
    assert remote_log(remote) == before, "an unchanged tree must not make a commit"


def test_publish_refuses_an_empty_tree_rather_than_emptying_the_wiki(wiki_env):
    run, remote, tree = wiki_env
    for f in tree.iterdir():
        f.unlink()
    before = remote_files(remote)
    result = run("abc")
    assert result.returncode != 0 and "empty" in result.stdout
    assert remote_files(remote) == before


def test_publish_names_the_one_time_step_when_the_wiki_does_not_exist(wiki_env):
    run, _, _ = wiki_env
    result = run("abc", exists=False)
    assert result.returncode != 0
    expected = (
        "The wiki has no first page yet: open https://example.invalid/owner/repo/wiki, "
        "create any page once, then re-run"
    )
    assert expected in result.stdout


# --- the two pull-request checks -------------------------------------------


@pytest.mark.parametrize(
    ("workflow", "fragment_job", "claims_job"),
    [("python-ci.yml", "fragment-check", "commit-claims"), ("bash-ci.yml", "fragment-check", "commit-claims")],
)
def test_the_pull_request_checks_are_opt_in_pr_only_and_hold_the_whole_history(workflow, fragment_job, claims_job):
    doc = load(workflow)
    inputs = calls(workflow)["inputs"]
    for job_name, input_name, env_names in [
        (fragment_job, "fragment-check-command", {"BASE"}),
        (claims_job, "commit-claims-command", {"BASE", "HEAD"}),
    ]:
        assert inputs[input_name]["default"] == "", f"{input_name} must default to skipped"
        job = doc["jobs"][job_name]
        assert job["if"] == f"github.event_name == 'pull_request' && inputs.{input_name} != ''"
        assert job["permissions"] == {"contents": "read"}
        checkout = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")][0]
        assert checkout["with"]["fetch-depth"] == 0
        run_step = job["steps"][-1]
        assert set(run_step["env"]) == {"COMMAND", *env_names}
        assert run_step["env"]["BASE"] == "${{ github.base_ref }}"
        assert run_step["env"]["COMMAND"] == "${{ inputs." + input_name + " }}"
        if "HEAD" in env_names:
            assert run_step["env"]["HEAD"] == "${{ github.event.pull_request.head.sha }}"
        assert job_name in doc["jobs"]["ci-green"]["needs"]
