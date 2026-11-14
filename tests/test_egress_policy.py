"""The egress policy: the exact-string input check, the policy expressions, the defaults, and no canary.

The egress canary (a step that probed GitHub from the runner after harden-runner) was removed on 2026-11-14
(#412): EX-0001 closed on 2026-11-02 and the step outlived it. `test_no_egress_canary_is_left` keeps it out.

`egress-policy-check` is a composite action whose `run:` script is inlined, byte for byte, as the first step of
every job that has a policy input (a reusable workflow cannot name the commit it runs from, so it cannot call the
action by path; see docs/wiki/Design-rules.md). Its copies are held identical here.
"""

import copy
import functools
import itertools
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))


CHECK = REPO / ".github" / "actions" / "egress-policy-check" / "action.yml"


def check_script() -> str:
    return yaml.safe_load(CHECK.read_text())["runs"]["steps"][0]["run"]


def run_check(env: dict[str, str]):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("POLICY_")}
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", check_script()],
        capture_output=True,
        text=True,
        timeout=20,
        env={**clean, **env},
    )


@pytest.mark.parametrize(
    "env",
    [
        {"POLICY_EGRESS_POLICY": "audit"},
        {"POLICY_EGRESS_POLICY": "block"},
        {"POLICY_EGRESS_POLICY": "audit", "POLICY_EGRESS_POLICY_SECRETLESS": "block"},
        {
            "POLICY_EGRESS_POLICY": "block",
            "POLICY_EGRESS_POLICY_SECRETLESS": "audit",
            "POLICY_DISTRO_EGRESS_POLICY": "block",
            "POLICY_SEMGREP_EGRESS_POLICY": "audit",
        },
        {},  # a workflow that declares none of them
    ],
)
def test_the_policy_check_accepts_exact_audit_and_block(env):
    done = run_check(env)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout == ""


HOSTILE = [
    "typo",
    "",
    "Block",
    "AUDIT",
    "audit ",
    " block",
    "audit|audit",
    "audit|block",
    "audit,block",
    "audit\nblock",
    "audit\n",
    "block\n::warning::injected",
    "::error::injected",
    "::set-output name=x::y",
    "'; echo pwned #",
    '"; echo pwned #',
    "$(echo pwned)",
    "`echo pwned`",
    "caf\u00e9 \u202e audit",
    "a" * 2000,
]


@pytest.mark.parametrize("value", HOSTILE, ids=lambda v: repr(v)[:30])
@pytest.mark.parametrize(
    "var,name",
    [
        ("POLICY_EGRESS_POLICY", "egress-policy"),
        ("POLICY_EGRESS_POLICY_SECRETLESS", "egress-policy-secretless"),
        ("POLICY_DISTRO_EGRESS_POLICY", "distro-egress-policy"),
        ("POLICY_SEMGREP_EGRESS_POLICY", "semgrep-egress-policy"),
    ],
)
def test_the_policy_check_rejects_anything_else_and_never_echoes_it(var, name, value):
    done = run_check({var: value})
    out = done.stdout + done.stderr
    assert done.returncode == 1, out
    assert out == (
        f"::error title=egress policy::the {name} input must be exactly 'audit' or 'block' "
        f"(its value is {len(value)} characters long)\n"
    ), "the message is fixed text, the input name and a length; nothing a caller passes appears in it"
    assert "::warning::" not in out and "injected" not in out and "pwned" not in out


def test_the_policy_check_reports_every_bad_input_by_name():
    done = run_check({"POLICY_EGRESS_POLICY": "typo", "POLICY_EGRESS_POLICY_SECRETLESS": "audit|audit"})
    assert done.returncode == 1
    assert "the egress-policy input" in done.stdout and "the egress-policy-secretless input" in done.stdout
    assert done.stdout.count("::error") == 2


CHECK_NAME = "Validate the egress policy inputs"


def workflow_jobs():
    """Every job that has a harden-runner step, with its steps after the leading policy check (if it has one)."""
    for path in WORKFLOWS:
        doc = yaml.safe_load(path.read_text())
        for name, job in doc["jobs"].items():
            raw = job.get("steps") or []
            steps = raw[1:] if raw and raw[0].get("name") == CHECK_NAME else raw
            if steps and str(steps[0].get("uses", "")).startswith("step-security/harden-runner@"):
                yield path, name, job, steps


def test_the_policy_check_is_the_first_step_of_every_job_that_has_it():
    """It runs before anything consumes a policy, harden-runner included. No step may precede it."""
    seen = 0
    for path in WORKFLOWS:
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            names = [s.get("name") for s in job.get("steps") or []]
            if CHECK_NAME in names:
                seen += 1
                assert names.index(CHECK_NAME) == 0, f"{path.name}:{name}: a step runs before the policy check"
                assert names.count(CHECK_NAME) == 1
    assert seen > 60


def test_every_job_that_can_block_has_the_policy_check_except_the_hardcoded_audit_workflow():
    for path, name, job, _steps in workflow_jobs():
        if path.name in ("ci.yml", "audit.yml", "main-verify.yml", "fleet-status.yml"):
            continue
        assert job["steps"][0].get("name") == CHECK_NAME, f"{path.name}:{name}"


def test_something_was_collected():
    assert len(list(workflow_jobs())) > 60


def effective_allow_list(path: Path, expression: str) -> str:
    """The step's allowed-endpoints with each `${{ inputs.X }}` replaced by X's default (a caller's override aside)."""
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return re.sub(r"\$\{\{ inputs\.([\w-]+) \}\}", lambda m: str(inputs[m.group(1)].get("default", "")), expression)


RUNNER_CASES = [
    "ubuntu-latest",
    "ubuntu-24.04-arm",
    "Ubuntu-Latest",
    "windows-latest",
    "macos-26",
    "self-hosted",
    "",
    "linux",
    "ubuntu-latest,self-hosted",
    '["ubuntu-latest"]',
    '["self-hosted","linux"]',
    ["self-hosted", "linux"],
    ["ubuntu-latest"],
    "ubuntu-latest-4-cores",
    "ubuntu-24.04-16core",
    "my-org-large-runner",
    None,
]


def runner_is_hosted(label) -> bool:
    """The oracle for the label check. `contains(fromJSON(list), label)` compares strings case-insensitively, so
    this lowercases both sides on purpose; a non-string (a list or object) never matches."""
    return isinstance(label, str) and label.lower() in {x.lower() for x in hosted_labels()}


POLICY_INPUTS = ("egress-policy", "egress-policy-secretless", "distro-egress-policy", "semgrep-egress-policy")
VALUES = ["audit", "block", "typo", "", "Block", "AUDIT"]
# `runner.environment` is `github-hosted` or `self-hosted` (GitHub Docs, contexts, runner context). Anything else
# must never give audit. GitHub's string comparison is case-insensitive, so the capitalizations below are equal.
ENVIRONMENTS = ["github-hosted", "self-hosted", "", None, "GitHub-Hosted", "GITHUB-HOSTED", "github-hosted ", "hosted"]


def declared_policy_inputs(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text())
    inputs = ((doc.get(True) or doc.get("on")).get("workflow_call") or {}).get("inputs", {})
    return sorted(n for n in inputs if n in POLICY_INPUTS)


RECORD = REPO / "docs" / "security" / "exceptions" / "EX-0001-harden-runner-block-westus2.md"


def hosted_labels() -> list[str]:
    """The ONE list of GitHub-hosted runner labels: the exception record (it cites the GitHub docs page)."""
    text = RECORD.read_text()
    block = text.split("<!-- hosted-runner-labels:begin -->")[1].split("<!-- hosted-runner-labels:end -->")[0]
    labels = [line.strip() for line in block.splitlines() if line.strip() and not line.startswith("```")]
    assert len(labels) >= 15 and len(labels) == len(set(labels))
    return labels


def eq(left, right: str) -> bool:
    """GitHub's `==` on strings is case-insensitive; null (an undefined context value) equals no string."""
    return isinstance(left, str) and left.lower() == right.lower()


def evaluate(expression: str, values: dict[str, str], runner=None, environment="github-hosted", runner_os="Linux"):
    """The expression forms used for a policy: inputs.X, runner.environment, == 'lit' (case-insensitive like
    GitHub's), &&, ||, parentheses, and contains(fromJSON('[...]'), <runner>) against the hosted-label list."""
    body = re.fullmatch(r"\$\{\{ (.*) \}\}", expression).group(1)

    def hosted(m):
        assert json.loads(m.group(1)) == hosted_labels(), (
            "a workflow embeds a hosted-label list that differs from EX-0001"
        )
        return "H(R)"

    body = re.sub(r"contains\(fromJSON\('(\[[^']*\])'\), (?:matrix|inputs)\.runner\)", hosted, body)
    body = re.sub(r"hashFiles\([^)]*\) != ''", "T", body)  # a manifest exists: the cache is wanted
    # parallel-ci.yml: a pin file was named (a needs output is not empty) and the matrix leg asks for the cache
    body = re.sub(r"needs\.[\w.-]+ != ''", "T", body)
    body = re.sub(r"matrix\.(?:pip-cache|tools)", "T", body)
    body = body.replace("runner.environment", "N")
    body = re.sub(r"runner\.os == ('[\w-]*')", r"Q(O, \1)", body)
    body = re.sub(r"inputs\.([\w-]+)", lambda m: f"V[{m.group(1)!r}]", body)
    body = re.sub(r"(V\['[\w-]+'\]|N) == ('[\w-]*')", r"Q(\1, \2)", body)
    py = body.replace("&&", " and ").replace("||", " or ")
    assert re.fullmatch(r"[\sVHRNOQT\[\]'a-zA-Z\-=(),]*", py), f"unexpected syntax in a policy expression: {py}"

    def is_hosted(label):  # a list or other type never matches a label
        return isinstance(label, str) and label.lower() in {x.lower() for x in hosted_labels()}

    env = {"V": values, "H": is_hosted, "R": runner, "N": environment, "O": runner_os, "Q": eq, "T": True}
    return eval(py, {"__builtins__": {}}, env)  # noqa: S307 - our own fixed expression


def test_the_runner_check_follows_the_hosted_list():
    lst = json.dumps(hosted_labels(), separators=(",", ":"))
    expr = (
        "${{ (inputs.a == 'audit' && runner.environment == 'github-hosted' && contains(fromJSON('"
        + lst
        + "'), matrix.runner)) && 'audit' || 'block' }}"
    )
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04") == "audit"
    assert evaluate(expr, {"a": "audit"}, "self-hosted") == "block"
    assert evaluate(expr, {"a": "audit"}, ["ubuntu-24.04"]) == "block"
    assert evaluate(expr, {"a": "block"}, "ubuntu-24.04") == "block"
    # A self-hosted runner can carry a hosted label; the runtime context is what stops it.
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="self-hosted") == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment=None) == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="") == "block"
    assert evaluate(expr, {"a": "audit"}, "ubuntu-24.04", environment="GitHub-Hosted") == "audit"  # case-insensitive


def test_the_evaluator_follows_github_semantics():
    audit_or_block = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert evaluate(audit_or_block, {"a": "audit"}) == "audit"
    assert evaluate(audit_or_block, {"a": "typo"}) == "block"
    either = "${{ (inputs.a == 'audit' || inputs.b == 'audit') && 'audit' || 'block' }}"
    assert evaluate(either, {"a": "x", "b": "audit"}) == "audit"


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_every_job_gets_the_policy_check_before_harden_runner(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name in ("ci.yml", "main-verify.yml"):
        pytest.skip("this repository's own workflows are audit by construction, there is nothing to guard")
    hardcoded = policy == "block"  # audit.yml
    declared = declared_policy_inputs(path)
    if not hardcoded:
        check = job["steps"][0]
        assert check.get("name") == CHECK_NAME, f"{path.name}:{name}: the policy check must be the first step"
        assert check["run"] == check_script(), f"{path.name}:{name} policy check differs from the composite action"
        assert "if" not in check, "the check must run whatever the policy is"
        assert check["env"] == {"POLICY_" + n.upper().replace("-", "_"): f"${{{{ inputs.{n} }}}}" for n in declared}, (
            f"{path.name}:{name}: one environment variable per policy input, never a joined string"
        )
        assert check["working-directory"] == "${{ github.workspace }}" and check["shell"] == "bash"
    if hardcoded:
        return
    # One effective policy, written twice: harden-runner and its telemetry switch.
    inner = policy[len("${{ ") : -len(" }}")]
    assert steps[0]["with"]["disable-telemetry"] == "${{ (" + inner + ") == 'block' }}"
    dynamic = str(job.get("runs-on")) in ("${{ matrix.runner }}", "${{ inputs.runner }}")
    secretless = (path.name, name) not in KEPT_BLOCK
    if secretless and not dynamic:
        assert job["runs-on"].lower() in {x.lower() for x in hosted_labels()}, f"{path.name}:{name}: not a hosted label"
    assert ("contains(fromJSON(" in policy) is (secretless and dynamic), f"{path.name}:{name}: runner check misplaced"
    runners = RUNNER_CASES if dynamic else [None]
    used = sorted(set(re.findall(r"inputs\.([\w-]+)", policy)) - {"runner"})
    assert ("runner.environment == 'github-hosted'" in policy) is secretless, (
        f"{path.name}:{name}: runtime check misplaced"
    )
    for runner in runners:
        for environment in ENVIRONMENTS:
            for combo in itertools.product(VALUES, repeat=len(used)):
                values = dict(zip(used, combo, strict=True))
                result = evaluate(policy, values, runner, environment)
                assert result in ("audit", "block")
                assert evaluate(steps[0]["with"]["disable-telemetry"], values, runner, environment) is (
                    result == "block"
                )
                wants_audit = any(v.lower() == "audit" for v in values.values())  # GitHub compares case-insensitively
                runtime_hosted = (not secretless) or (environment or "").lower() == "github-hosted"
                label_hosted = (not secretless) or (not dynamic) or runner_is_hosted(runner)
                expected = "audit" if wants_audit and runtime_hosted and label_hosted else "block"
                assert result == expected, (
                    f"{path.name}:{name}: audit needs the input, runner.environment and the label to agree"
                )


def test_the_effective_policy_follows_the_right_inputs():
    """audit only when the input the job answers to equals `audit` (GitHub's `==` ignores case); distro and
    semgrep need either to say so. The exact-string control is the policy check, see the test that pins it."""
    seen = 0
    for path, name, _job, steps in workflow_jobs():
        if path.name in ("ci.yml", "audit.yml", "main-verify.yml", "fleet-status.yml"):
            continue
        seen += 1
        used = set(re.findall(r"inputs\.([\w-]+)", steps[0]["with"]["egress-policy"])) - {"runner"}
        if (path.name, name) in KEPT_BLOCK:
            assert used == {"egress-policy"}, f"{path.name}:{name}"
        elif (path.name, name) in {("python-ci.yml", "distro"), ("bash-ci.yml", "distro")}:
            assert used == {"egress-policy-secretless", "distro-egress-policy"}
        elif (path.name, name) == ("security.yml", "semgrep"):
            assert used == {"egress-policy-secretless", "semgrep-egress-policy"}
        else:
            assert used == {"egress-policy-secretless"}, f"{path.name}:{name}"
    assert seen > 60


# --- which jobs may follow the secretless input -----------------------------------------------------

# Kept in block on purpose (docs/security/exceptions/EX-0001-harden-runner-block-westus2.md, "Scope").
KEPT_BLOCK = {
    (
        "agent-scan.yml",
        "skill-scan",
    ),  # its SARIF artifact is uploaded verbatim by the job that holds security-events: write
    ("agent-scan.yml", "mcp-scan"),  # likewise
    ("artifact-release.yml", "build"),  # builds the file that is signed and published
    ("artifact-release.yml", "publish"),  # contents: write, id-token, attestations
    ("container-release.yml", "plan"),  # its outputs choose the runners and the image name of the privileged build
    ("container-release.yml", "build"),  # packages: write
    (
        "container-release.yml",
        "build-local",
    ),  # runs the caller's Dockerfile and test command; keeps the operator's egress policy as `build` does
    ("container-release.yml", "merge"),  # packages: write, id-token, Doppler
    ("dast.yml", "scan"),  # its SARIF artifact is uploaded verbatim by the job that holds security-events: write
    ("dependabot-auto-merge.yml", "auto-merge"),  # contents and pull-requests: write
    ("docs-pages.yml", "build"),  # runs caller code; its artifact is deployed verbatim by `deploy`
    ("docs-pages.yml", "deploy"),  # pages: write, id-token
    ("lory-audit.yml", "audit"),  # LORY_PIPELINE_TOKEN, a third-party bearer token
    ("pin-comments.yml", "pin-comments"),  # the job token goes to the GitHub API lookups
    ("project-sync.yml", "sync"),  # id-token, Doppler, a GitHub App token
    ("repin.yml", "repin"),  # a GitHub App token that can push workflow files and open pull requests
    ("python-ci.yml", "coverage"),  # id-token, Doppler, the Codecov upload
    ("python-package-release.yml", "build"),  # builds the distribution that is published
    ("python-package-release.yml", "github-release"),  # contents: write, id-token, attestations
    ("security.yml", "snyk"),  # id-token, Doppler, SNYK_TOKEN
    ("security.yml", "scorecard"),  # id-token
    ("tofu-ci.yml", "plan"),  # id-token, Doppler
    ("token-drift.yml", "drift"),  # the job token goes to api.github.com for the live check; read-only, no secret
    ("verify-published.yml", "verify"),  # packages: read; gh attestation verify with the job token
    ("verify-published.yml", "verify-release"),  # gh release download and attestation verify with the job token
    ("wiki-publish.yml", "generate"),  # runs caller code; its artifact is pushed verbatim by `publish`
    ("wiki-publish.yml", "publish"),  # contents: write
}
# Documented extensions to "secretless" (EX-0001, "Widening of 2026-10-26", issue #225). Each is pinned exactly:
# the job may hold that and nothing else, so a new grant or secret on it still fails the guard.
ALLOWED_HOLDINGS = {
    # the comment-scoped job token for the PR summary comment; no stored secret, no OIDC, no publish scope
    ("security.yml", "dependency-review"): ["pull-requests: write"],
}
# A job whose artifact is a data report a kept-block job uploads to a third party, never code that is published.
ARTIFACT_TO_PRIVILEGED_OK = {("python-ci.yml", "test")}  # the coverage report that `coverage` sends to Codecov
# Jobs that hold a stored secret, an OIDC token or a publish-capable token: they must stay in block (issue #225).
MUST_STAY_BLOCK = {
    ("python-ci.yml", "coverage"),  # id-token, Doppler, Codecov
    ("security.yml", "snyk"),  # Doppler, SNYK_TOKEN
    ("security.yml", "scorecard"),  # id-token, publishes results
    ("tofu-ci.yml", "plan"),  # id-token, Doppler
    ("container-release.yml", "build"),  # packages: write, id-token, Doppler
    ("container-release.yml", "merge"),  # packages: write, id-token, Doppler
    ("artifact-release.yml", "publish"),  # contents: write, id-token, attestations
    ("python-package-release.yml", "github-release"),  # contents: write, id-token, attestations
    ("docs-pages.yml", "deploy"),  # pages: write, id-token
    ("wiki-publish.yml", "publish"),  # contents: write
    ("project-sync.yml", "sync"),  # GitHub App token, Doppler
    ("repin.yml", "repin"),  # GitHub App token with contents, pull-requests and workflows write
    ("verify-published.yml", "verify"),  # the job token goes to gh attestation verify
    ("verify-published.yml", "verify-release"),  # the job token goes to gh release download
}
# The widening of 2026-10-26: these follow the secretless input although they were in block before.
WIDENED = {("security.yml", "dependency-review"), ("python-ci.yml", "test")}
SECRET_MARKERS = (
    "${{ secrets.",
    "doppler",
    "id-token",
    "DOPPLER",
    "attestations",
    "github.token",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)
TOKEN_KEYS = ("token", "github-token", "password", "registry-password")


def test_the_classification_table_names_real_jobs():
    real = {(path.name, name) for path, name, _, _ in workflow_jobs()}
    assert KEPT_BLOCK <= real, sorted(KEPT_BLOCK - real)


EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
# The `secrets` context in every spelling: secrets.X, secrets['X'], secrets["X"], secrets[expr], toJSON(secrets),
# any whitespace or case; a name that merely contains the word (secretless, my-secrets) does not count.
SECRETS_CONTEXT = re.compile(r"(?<![\w.\-'\"])secrets(?![\w\-])", re.IGNORECASE)
GITHUB_TOKEN_CONTEXT = re.compile(r"github\s*(\.\s*token\b|\[\s*['\"]token['\"]\s*\])", re.IGNORECASE)
# An upstream output that carries a credential (a plain data output, such as a file name, is not one).
NEEDS_OUTPUT = re.compile(
    r"(?<![\w.\-])needs\b[^}]*?(token|secret|password|passwd|credential|apikey|api-key|api_key)", re.IGNORECASE
)
JOB_LEVEL_SECRET_KEYS = ("secrets", "container", "services")


def strings_in(node):
    """Every key and every string value anywhere in a mapping, so no placement is skipped."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from strings_in(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings_in(v)
    elif isinstance(node, str):
        yield node


def what_a_job_holds(job: dict) -> list[str]:
    """Everything that disqualifies a job from the secretless input (EX-0001, "Scope"). Scans the whole job
    mapping (job-level env, with, secrets, container, services, every step), not only the steps."""
    found = []
    grants = dict(job.get("permissions") or {})
    if grants.pop("contents", "read") != "read":
        found.append("contents write")
    if grants.pop("security-events", "write") != "write":
        found.append("security-events")
    found += [f"{scope}: {level}" for scope, level in grants.items()]
    steps = list(job.get("steps") or [])
    scanned = {k: v for k, v in job.items() if k != "steps"}
    scanned["steps"] = steps
    texts = list(strings_in(scanned))
    # `if:` conditions are expressions without the ${{ }} wrapper
    expressions = [e for t in texts for e in EXPRESSION.findall(t)]
    expressions += [str(v) for node in [job, *steps] for v in [node.get("if")] if v is not None]
    if any(SECRETS_CONTEXT.search(e) for e in expressions) or any(k in job for k in JOB_LEVEL_SECRET_KEYS):
        found.append("secrets context")
    if any(GITHUB_TOKEN_CONTEXT.search(e) for e in expressions):
        found.append("github.token")
    if any(NEEDS_OUTPUT.search(e) for e in expressions):
        found.append("needs output")
    dumped = [yaml.safe_dump(scanned)]
    found += [m for m in SECRET_MARKERS if m not in ("${{ secrets.", "github.token") and any(m in t for t in dumped)]
    if "github.token" in dumped[0] and "github.token" not in found:
        found.append("github.token")
    # A token handed to an action beyond the default (checkout and harden-runner use the job token themselves).
    found += [f"with.{k}" for s in steps for k in (s.get("with") or {}) if k in TOKEN_KEYS]
    found += [f"with.{k}" for k in (job.get("with") or {}) if k in TOKEN_KEYS]
    return found


def artifact_feeds_a_privileged_job(path: Path, name: str, kept=None) -> bool:
    """True when a job kept in block needs `name` and downloads an artifact or reads its outputs."""
    kept = KEPT_BLOCK if kept is None else kept
    doc = yaml.safe_load(path.read_text())
    for other, job in doc["jobs"].items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if name not in needs or (path.name, other) not in kept:
            continue
        text = yaml.safe_dump(job)
        if "download-artifact" in text or f"needs.{name}.outputs" in text:
            return True
    return False


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_a_job_follows_the_secretless_input_only_if_it_holds_nothing(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name in ("ci.yml", "audit.yml", "main-verify.yml", "fleet-status.yml"):
        pytest.skip("hardcoded policies")
    follows_secretless = "egress-policy-secretless" in policy
    assert follows_secretless == ((path.name, name) not in KEPT_BLOCK), f"{path.name}:{name} is classified differently"
    if follows_secretless:
        key = (path.name, name)
        assert what_a_job_holds(job) == ALLOWED_HOLDINGS.get(key, []), (
            f"{path.name}:{name} holds something and must follow egress-policy"
        )
        assert key in ARTIFACT_TO_PRIVILEGED_OK or not artifact_feeds_a_privileged_job(path, name), (
            f"{path.name}:{name} feeds a privileged job"
        )


def test_the_widening_of_2026_10_26_is_pinned_both_ways():
    """Issue #225: the two widened jobs follow the secretless input; every job that holds a secret, OIDC or a
    publish-capable token stays in block, and no widened job is also on the must-stay list."""
    policies = {(p.name, n): s[0]["with"]["egress-policy"] for p, n, _j, s in workflow_jobs()}
    for key in sorted(WIDENED):
        assert "egress-policy-secretless" in policies[key], f"{key} must follow egress-policy-secretless"
        assert key not in KEPT_BLOCK
    for key in sorted(MUST_STAY_BLOCK):
        assert key in policies, f"{key} is not a real job"
        assert key in KEPT_BLOCK, f"{key} holds a secret, OIDC or a publish token and must stay in KEPT_BLOCK"
        assert "egress-policy-secretless" not in policies[key], f"{key} must stay in block"
        assert "runner.environment" not in policies[key]
    assert not WIDENED & MUST_STAY_BLOCK


def test_the_widened_jobs_hold_exactly_what_the_record_says():
    by_key = {(p.name, n): j for p, n, j, _s in workflow_jobs()}
    assert what_a_job_holds(by_key[("security.yml", "dependency-review")]) == ["pull-requests: write"]
    assert what_a_job_holds(by_key[("python-ci.yml", "test")]) == []
    # the comment token is the only write scope; nothing else is handed to the review action
    review = yaml.safe_dump(by_key[("security.yml", "dependency-review")])
    for marker in ("secrets.", "id-token", "doppler", "DOPPLER", "repo-token"):
        assert marker not in review


def test_the_extension_tables_do_not_hide_a_new_grant():
    """Negative case: the extension allows exactly one holding on one job and nothing for any other."""
    assert ALLOWED_HOLDINGS == {("security.yml", "dependency-review"): ["pull-requests: write"]}
    widened_job = {"permissions": {"contents": "read", "pull-requests": "write", "id-token": "write"}}
    assert what_a_job_holds(widened_job) != ALLOWED_HOLDINGS[("security.yml", "dependency-review")]
    with_secret = {"permissions": {"contents": "read", "pull-requests": "write"}, "steps": [{"run": "doppler x"}]}
    assert what_a_job_holds(with_secret) != ALLOWED_HOLDINGS[("security.yml", "dependency-review")]
    assert ARTIFACT_TO_PRIVILEGED_OK == {("python-ci.yml", "test")}


def test_the_record_lists_the_widened_jobs_and_the_order():
    text = RECORD.read_text()
    assert "Widening of 2026-10-26" in text and "#225" in text
    relaxed = text.split("Relaxed (policy follows", 1)[1].split("**Kept in `block`**", 1)[0]
    rows = {line.split("|")[1].strip(): line for line in relaxed.splitlines() if line.startswith("| `")}
    assert "`dependency-review`" in rows["`security.yml`"]
    assert "`test`" in rows["`python-ci.yml`"]
    kept = text.split("**Kept in `block`**", 1)[1].split("Ambiguous means", 1)[0]
    assert "`dependency-review`" not in kept
    assert "| `python-ci.yml` | `test` |" not in kept
    assert "| Expires | was 2026-11-07" in text  # the original expiry stays in the history


@pytest.mark.parametrize(
    "job,expected",
    [
        ({"permissions": {"contents": "write"}}, "contents write"),
        ({"permissions": {"contents": "read", "id-token": "write"}}, "id-token: write"),
        ({"permissions": {"contents": "read", "packages": "read"}}, "packages: read"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"T": "${{ secrets.X }}"}}]}, "secrets context"),
        ({"permissions": {"contents": "read"}, "steps": [{"run": "doppler run -- true"}]}, "doppler"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"T": "${{ github.token }}"}}]}, "github.token"),
        ({"permissions": {"contents": "read"}, "steps": [{"env": {"GH_TOKEN": "x"}, "run": "gh x"}]}, "GH_TOKEN"),
        ({"permissions": {"contents": "read"}, "steps": [{"uses": "a/b@1", "with": {"token": "x"}}]}, "with.token"),
    ],
)
def test_the_guard_bites_a_job_that_holds_something(job, expected):
    assert expected in what_a_job_holds(job)


def test_the_artifact_guard_bites(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text(
        "jobs:\n  a:\n    steps: []\n  b:\n    needs: a\n    steps:\n      - uses: actions/download-artifact@1\n"
    )
    assert artifact_feeds_a_privileged_job(wf, "a", kept={("w.yml", "b")})
    assert not artifact_feeds_a_privileged_job(wf, "a", kept=set())
    assert not artifact_feeds_a_privileged_job(wf, "b", kept={("w.yml", "b")})


def test_the_guard_accepts_a_sarif_upload_and_a_read_only_job():
    assert what_a_job_holds({"permissions": {"contents": "read", "security-events": "write"}}) == []
    assert what_a_job_holds({"permissions": {"contents": "read"}, "steps": [{"run": "true"}]}) == []


# --- caches: an audit-mode job neither restores nor saves one --------------------------------------
#
# Code that runs in an audit job can write a poisoned cache that a later block-mode job (possibly one holding
# an OIDC token) restores, in the same run or a later one. setup-python's pip cache key is OS, architecture,
# Python version and a hash of the manifests, with no suffix or namespace option (read at the pinned SHA), so
# the only way to keep audit and block apart is to turn the cache off in a job whose effective policy is audit.
# Tool-download caches (key `tool-*`) stay: every restore is followed by `sha256sum -c`, so a poisoned entry
# cannot pass (tests/test_hygiene.py holds that).


def cache_sites(job: dict):
    """(step name, kind, expression) for every cache a job can restore or save."""
    run_text = "\n".join(str(s.get("run", "")) for s in job.get("steps") or [])
    for step in job.get("steps") or []:
        uses = str(step.get("uses", ""))
        with_ = step.get("with") or {}
        label = step.get("name") or uses
        if uses.startswith("actions/cache"):
            if str(with_.get("key", "")).startswith("tool-") and "sha256sum -c" in run_text:
                yield label, "hash-verified tool cache", None
            else:
                yield label, "actions/cache", step.get("if")
        for key in ("cache", "cache-from", "cache-to"):
            if with_.get(key) not in (None, ""):
                yield label, key, str(with_[key])


def gated_on_block(job: dict, policy: str, expression) -> bool:
    inner = policy[len("${{ ") : -len(" }}")]
    return expression is not None and f"({inner}) == 'block'" in str(expression)


def uncached_problems(path_name: str, job: dict, policy: str) -> list[str]:
    return [
        f"{path_name}: {label} ({kind}) is not off in audit"
        for label, kind, expr in cache_sites(job)
        if kind != "hash-verified tool cache" and not gated_on_block(job, policy, expr)
    ]


@pytest.mark.parametrize("path,name,job,steps", list(workflow_jobs()), ids=lambda v: v if isinstance(v, str) else "")
def test_no_cache_is_used_when_the_job_is_audit(path, name, job, steps):
    policy = steps[0]["with"]["egress-policy"]
    if path.name in ("ci.yml", "audit.yml", "main-verify.yml", "fleet-status.yml"):
        pytest.skip("hardcoded policy")
    assert uncached_problems(f"{path.name}:{name}", job, policy) == []
    used = sorted(set(re.findall(r"inputs\.([\w-]+)", policy)) - {"runner"})
    dynamic = str(job.get("runs-on")) in ("${{ matrix.runner }}", "${{ inputs.runner }}")
    for label, kind, expr in cache_sites(job):
        if kind == "hash-verified tool cache":
            continue
        for runner in RUNNER_CASES if dynamic else [None]:
            for environment in ENVIRONMENTS:
                for combo in itertools.product(VALUES, repeat=len(used)):
                    values = dict(zip(used, combo, strict=True))
                    effective = evaluate(policy, values, runner, environment)
                    if kind == "actions/cache":
                        on = evaluate(expr, values, runner, environment)
                        assert on is (effective == "block"), f"{path.name}:{name}: {label}"
                    elif kind == "cache":
                        got = evaluate(expr, values, runner, environment)
                        assert got == ("pip" if effective == "block" else ""), f"{path.name}:{name}: {label}"
                    else:  # a buildx cache spec: empty unless block
                        assert gated_on_block(job, policy, expr), f"{path.name}:{name}: {label}"


def test_the_cache_guard_bites():
    job = {
        "steps": [
            {"name": "py", "uses": "actions/setup-python@x", "with": {"cache": "pip"}},
            {"name": "buildx", "uses": "docker/build-push-action@x", "with": {"cache-to": "type=gha"}},
            {"name": "dl", "uses": "actions/cache@x", "with": {"key": "arduino-packages-1"}},
            {"name": "tool", "uses": "actions/cache@x", "with": {"key": "tool-x-1"}},
            {"name": "verify", "run": "echo x | sha256sum -c -"},
        ]
    }
    policy = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert len(uncached_problems("w.yml", job, policy)) == 3
    job["steps"][0]["with"]["cache"] = "${{ (inputs.a == 'audit' && 'audit' || 'block') == 'block' && 'pip' || '' }}"
    assert len(uncached_problems("w.yml", job, policy)) == 2


def test_every_cache_site_in_the_workflows_was_seen():
    kinds = {}
    for path, name, job, _steps in workflow_jobs():
        for _label, kind, _expr in cache_sites(job):
            kinds.setdefault(kind, []).append(f"{path.name}:{name}")
    assert len(kinds.get("cache", [])) >= 5 and kinds.get("actions/cache") and kinds.get("cache-from")
    assert kinds.get("hash-verified tool cache"), "the tool caches are the hash-verified exception"


def test_this_repositorys_audit_jobs_use_no_cache_that_the_blocking_audit_workflow_restores():
    """ci.yml jobs are audit by construction and share setup-python's key with audit.yml (block, Doppler)."""
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    seen = 0
    for name, job in doc["jobs"].items():
        steps = job.get("steps") or []
        if steps and str(steps[0].get("uses", "")).startswith("step-security/harden-runner@"):
            assert steps[0]["with"]["egress-policy"] == "audit"
            seen += 1
            assert [label for label, kind, _ in cache_sites(job) if kind != "hash-verified tool cache"] == [], name
    assert seen >= 6


def test_the_expressions_depend_on_the_policy_check_for_exactness():
    """GitHub's `==` and `contains()` compare strings case-insensitively, so an effective-policy expression reads
    `AUDIT` as `audit` and `Block` as `block`. The expressions are therefore NOT the exact-string control. The
    control is the policy check: step 0 of every job that has such an expression, running before anything
    consumes the value, and failing on every value that is not exactly `audit` or `block`.
    """
    jobs_with_expressions = 0
    for path in WORKFLOWS:
        if path.name in ("ci.yml", "audit.yml", "main-verify.yml", "fleet-status.yml"):
            continue  # hardcoded policies: no input reaches an expression
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            steps = job.get("steps") or []
            harden = next((s for s in steps if str(s.get("uses", "")).startswith("step-security/harden-runner@")), None)
            if harden is None or "inputs." not in str(harden["with"]["egress-policy"]):
                continue
            jobs_with_expressions += 1
            assert steps[0].get("name") == CHECK_NAME, f"{path.name}:{name}: an expression without the exact check"
            assert steps.index(harden) > 0
    assert jobs_with_expressions > 60
    # The expression alone is case-insensitive (the reason the check exists); the check is exact.
    expression = "${{ inputs.a == 'audit' && 'audit' || 'block' }}"
    assert evaluate(expression, {"a": "AUDIT"}) == "audit"
    assert run_check({"POLICY_EGRESS_POLICY": "AUDIT"}).returncode == 1


SECRET_SPELLINGS = [
    "${{ secrets.NEW_SECRET }}",
    "${{ secrets['NEW_SECRET'] }}",
    '${{ secrets["NEW_SECRET"] }}',
    "${{ secrets[format('{0}', 'NEW_SECRET')] }}",
    "${{ secrets[inputs.name] }}",
    "${{ toJSON(secrets) }}",
    "${{ toJson( secrets ) }}",
    "${{SECRETS.NEW_SECRET}}",
    "${{   Secrets  [ 'NEW_SECRET' ]   }}",
    "${{ secrets.GITHUB_TOKEN }}",
    "${{ github.token }}",
    "${{ github['token'] }}",
    "${{ GitHub . Token }}",
]


@functools.cache
def _jobs_by_key():
    return {(p.name, n): j for p, n, j, _s in workflow_jobs()}


def widened_job(key):
    return copy.deepcopy(_jobs_by_key()[key])


def place(job, where, value):
    """Add `value` to a job in one placement; the placements are every place a secret can be handed in."""
    last = job["steps"][-1]
    if where == "job-env":
        job.setdefault("env", {})["T"] = value
    elif where == "step-env":
        last.setdefault("env", {})["T"] = value
    elif where == "step-with":
        last.setdefault("with", {})["x"] = value
    elif where == "step-run":
        last["run"] = f"echo {value}"
    elif where == "step-if":
        last["if"] = value
    elif where == "job-if":
        job["if"] = value
    elif where == "job-with":
        job.setdefault("with", {})["x"] = value
    elif where == "job-secrets":
        job["secrets"] = {"T": value}
    elif where == "container":
        job["container"] = {"image": "x", "credentials": {"username": "u", "password": value}}
    elif where == "services":
        job["services"] = {"db": {"image": "x", "credentials": {"username": "u", "password": value}}}
    elif where == "other-key":
        job["outputs"] = {"o": value}
    else:
        raise AssertionError(where)


PLACEMENTS = [
    "job-env", "step-env", "step-with", "step-run", "step-if", "job-if", "job-with", "job-secrets", "container",
    "services", "other-key",
]  # fmt: skip


@pytest.mark.parametrize("key", sorted(WIDENED), ids=lambda k: k[1])
@pytest.mark.parametrize("where", PLACEMENTS)
@pytest.mark.parametrize("spelling", SECRET_SPELLINGS)
def test_a_secret_added_to_a_widened_job_fails_the_guard(key, where, spelling):
    job = widened_job(key)
    baseline = what_a_job_holds(job)
    value = spelling[3:-2].strip() if where in ("step-if", "job-if") else spelling
    place(job, where, value)
    assert what_a_job_holds(job) != baseline, f"{where} {spelling!r} on {key} went unnoticed"


@pytest.mark.parametrize("where", ["job-env", "step-env", "step-run", "step-if"])
def test_a_needs_output_added_to_a_widened_job_fails_the_guard(where):
    job = widened_job(("python-ci.yml", "test"))
    value = "needs.setup.outputs.token" if where == "step-if" else "${{ needs.setup.outputs.token }}"
    place(job, where, value)
    assert "needs output" in what_a_job_holds(job)


def test_the_secrets_guard_does_not_cry_wolf_on_look_alikes():
    job = {"permissions": {"contents": "read"}, "env": {"A": "${{ inputs.egress-policy-secretless }}"}}
    job["steps"] = [{"name": "my-secrets notes", "run": "echo secrets-are-not-here ${{ vars.secretsish }}"}]
    assert what_a_job_holds(job) == []


# --- EX-0001 is closed: the secretless jobs block by default again -----------------------------------


def secretless_defaults() -> dict[str, object]:
    found = {}
    for path in WORKFLOWS:
        triggers = yaml.safe_load(path.read_text()).get(True)  # PyYAML reads the key `on` as True
        call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
        inputs = (call or {}).get("inputs") or {}
        if "egress-policy-secretless" in inputs:
            found[path.name] = inputs["egress-policy-secretless"].get("default")
    return found


def defaults_that_are_not_block(defaults: dict[str, object]) -> list[str]:
    return sorted(name for name, value in defaults.items() if value != "block")


def test_every_secretless_input_defaults_to_block_since_ex_0001_closed():
    defaults = secretless_defaults()
    assert len(defaults) >= 13, f"expected every reusable workflow with the input to be collected: {sorted(defaults)}"
    assert defaults_that_are_not_block(defaults) == []


def test_the_secretless_default_guard_bites():
    assert defaults_that_are_not_block({"a.yml": "block", "b.yml": "audit"}) == ["b.yml"]
    assert defaults_that_are_not_block({"a.yml": None}) == ["a.yml"]
    assert defaults_that_are_not_block({"a.yml": "Block"}) == ["a.yml"]


def test_the_per_job_follow_inputs_still_default_to_block():
    for name, key in (
        ("python-ci.yml", "distro-egress-policy"),
        ("bash-ci.yml", "distro-egress-policy"),
        ("security.yml", "semgrep-egress-policy"),
    ):
        doc = yaml.safe_load((REPO / ".github" / "workflows" / name).read_text())
        assert doc[True]["workflow_call"]["inputs"][key]["default"] == "block", f"{name}:{key}"


def test_the_record_and_the_docs_say_ex_0001_is_closed():
    text = RECORD.read_text()
    assert "| Status | **closed** |" in text and "| Closed | 2026-11-02" in text
    assert "\n## Closure\n" in text
    closure = text.split("\n## Closure\n", 1)[1].split("\n## Why\n", 1)[0]
    for needle in (
        "41490712453",
        "41493344115",
        "41496006377",
        "15 of 15",
        "135 of 135",
        "13 of 13",
        "root cause",
        "egress-policy-secretless: audit",
    ):
        assert needle in closure, needle
    assert "\n## Why\n" in text and "## Exact scope" in text, "the history stays"
    index = (REPO / "docs" / "security" / "exceptions" / "README.md").read_text()
    row = next(line for line in index.splitlines() if line.startswith("| [EX-0001]"))
    assert "closed" in row and "2026-11-02" in row and "active" not in row
    readme = (REPO / "README.md").read_text()
    assert "**Status: closed on 2026-11-02.**" in readme
    wiki = (REPO / "docs" / "wiki" / "Egress-control.md").read_text()
    assert "Closed on 2026-11-02" in wiki and "egress-policy-secretless: audit" in wiki


# --- the egress canary is gone (#412) ---------------------------------------------------------------

ACTIONS = REPO / ".github" / "actions"


# The canary's mechanism, whatever its steps or functions are called: a TCP probe through bash's /dev/tcp and a
# name lookup through `getent ahosts`. No workflow or action here uses either (checked when this guard was written);
# a legitimate future use must be scoped here on purpose, not waved through.
CANARY_MECHANISM = re.compile(r"/dev/tcp/|getent\s+ahosts")


def canary_leftovers(workflows: list[Path], actions: Path) -> list[str]:
    """Every place under .github that still carries an `Egress canary` step, the `canary_probe` function, the
    canary's mechanism (`/dev/tcp/` probes, `getent ahosts` lookups) under any name, or an action directory of that
    name. Loose collection (every yml, every step, the raw text); the assertion is strict."""
    found = []
    for path in sorted([*workflows, *actions.glob("*/action.yml")]):
        text = path.read_text()
        if "canary_probe" in text:
            found.append(f"{path.name}: canary_probe")
        found += [f"{path.name}: network probe {m.group(0)!r}" for m in [CANARY_MECHANISM.search(text)] if m]
        doc = yaml.safe_load(text)
        jobs = (doc.get("jobs") or {}).values() if "jobs" in doc else [doc.get("runs") or {}]
        for job in jobs:
            for step in job.get("steps") or []:
                if str(step.get("name", "")).lower().startswith("egress canary"):
                    found.append(f"{path.name}: step {step['name']!r}")
    found += [f"{d.name}: action directory" for d in actions.glob("*canary*")]
    return found


def test_no_egress_canary_is_left():
    assert len(WORKFLOWS) > 20 and len(list(ACTIONS.glob("*/action.yml"))) >= 4, "the guard collected nothing"
    assert canary_leftovers(WORKFLOWS, ACTIONS) == []


def test_the_canary_guard_bites(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text("jobs:\n  a:\n    steps:\n      - name: Egress canary\n        run: canary_probe() { true; }\n")
    assert canary_leftovers([wf], tmp_path) == ["w.yml: canary_probe", "w.yml: step 'Egress canary'"]
    (tmp_path / "egress-canary").mkdir()
    assert "egress-canary: action directory" in canary_leftovers([], tmp_path)
    (tmp_path / "egress-canary").rmdir()
    ok = tmp_path / "ok.yml"
    ok.write_text("jobs:\n  a:\n    steps:\n      - name: Build\n        run: true\n")
    assert canary_leftovers([ok], tmp_path / "none") == []


def policy_defaults(workflows: list[Path] | None = None) -> dict[tuple[str, str], object]:
    found = {}
    for path in WORKFLOWS if workflows is None else workflows:
        triggers = yaml.safe_load(path.read_text()).get(True)  # PyYAML reads the key `on` as True
        call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
        for key, spec in ((call or {}).get("inputs") or {}).items():
            if key in ("egress-policy", "egress-policy-secretless"):
                found[(path.name, key)] = spec.get("default")
    return found


# The reviewed `egress-policy` default of every reusable workflow that has the input, read from origin/main on
# 2026-11-14. A default is a security decision (a token-bearing job that defaults to audit runs unrestricted), so a
# change is made here, in the same diff, and a reviewer sees it.
EGRESS_POLICY_BASELINE = {
    "agent-scan.yml": "block",
    "arduino-ci.yml": "audit",
    "artifact-release.yml": "audit",
    "base-image-digest.yml": "block",
    "bash-ci.yml": "audit",
    "ci-gate.yml": "block",
    "container-release.yml": "audit",
    "dast.yml": "audit",
    "dependabot-auto-merge.yml": "audit",
    "docs-pages.yml": "audit",
    "lory-audit.yml": "audit",
    "parallel-ci.yml": "block",
    "pin-comments.yml": "block",
    "pr-title-lint.yml": "block",
    "project-sync.yml": "audit",
    "python-ci.yml": "audit",
    "python-docker-release.yml": "audit",
    "python-fuzz.yml": "audit",
    "python-package-release.yml": "audit",
    "repin.yml": "block",
    "security.yml": "audit",
    "threat-model.yml": "audit",
    "tofu-ci.yml": "audit",
    "token-drift.yml": "block",
    "vendored-drift.yml": "block",
    "verify-published.yml": "block",
    "wiki-publish.yml": "audit",
}


def policy_default_problems(defaults: dict[tuple[str, str], object]) -> list[str]:
    problems = []
    plain = {n: v for (n, k), v in defaults.items() if k == "egress-policy"}
    for name, value in sorted(plain.items()):
        if name not in EGRESS_POLICY_BASELINE:
            problems.append(f"{name}: no baseline for its egress-policy default {value!r}; add one deliberately")
        elif value != EGRESS_POLICY_BASELINE[name]:
            want = EGRESS_POLICY_BASELINE[name]
            problems.append(f"{name}: egress-policy defaults to {value!r}, the reviewed baseline is {want!r}")
    problems += [
        f"{n}: in the baseline but has no egress-policy input" for n in sorted(set(EGRESS_POLICY_BASELINE) - set(plain))
    ]
    problems += [
        f"{n}: egress-policy-secretless defaults to {v!r}, it must be 'block' (EX-0001 closed)"
        for (n, k), v in sorted(defaults.items())
        if k == "egress-policy-secretless" and v != "block"
    ]
    return problems


def test_every_egress_policy_default_equals_its_reviewed_baseline():
    defaults = policy_defaults()
    assert len({n for (n, k) in defaults if k == "egress-policy"}) >= 13, "the guard collected too few workflows"
    assert len({n for (n, k) in defaults if k == "egress-policy-secretless"}) >= 13
    assert policy_default_problems(defaults) == []


def test_the_policy_default_guard_bites_on_the_real_workflows(tmp_path):
    """Copy the real workflow text, flip one default from block to audit (and one secretless), run the real checker."""
    for path in WORKFLOWS:
        (tmp_path / path.name).write_text(path.read_text())
    assert policy_default_problems(policy_defaults(sorted(tmp_path.glob("*.yml")))) == []
    pin = tmp_path / "pin-comments.yml"
    text = pin.read_text()
    flipped = re.sub(r"(      egress-policy:\n(?:        .*\n)*?        default: )block", r"\1audit", text, count=1)
    assert flipped != text
    pin.write_text(flipped)
    assert policy_default_problems(policy_defaults(sorted(tmp_path.glob("*.yml")))) == [
        "pin-comments.yml: egress-policy defaults to 'audit', the reviewed baseline is 'block'"
    ]
    (tmp_path / "brand-new.yml").write_text(
        "on:\n  workflow_call:\n    inputs:\n      egress-policy:\n        type: string\n        default: audit\n"
    )
    assert any("no baseline" in p for p in policy_default_problems(policy_defaults(sorted(tmp_path.glob("*.yml")))))
    sec = tmp_path / "security.yml"
    sec.write_text(
        re.sub(
            r"(      egress-policy-secretless:\n(?:        .*\n)*?        default: )block",
            r"\1audit",
            sec.read_text(),
            count=1,
        )
    )
    assert any("secretless" in p for p in policy_default_problems(policy_defaults(sorted(tmp_path.glob("*.yml")))))


def test_every_harden_runner_step_blocks_unless_the_policy_says_exactly_audit():
    """The effective policy of every harden-runner step is `block`, or an expression whose fallback is `block`."""
    seen = 0
    for path, name, _job, steps in workflow_jobs():
        if path.name in ("ci.yml", "main-verify.yml"):
            continue  # this repository's own workflows are audit by construction
        seen += 1
        policy = steps[0]["with"]["egress-policy"]
        assert policy == "block" or policy.endswith("'audit' || 'block' }}"), f"{path.name}:{name}: {policy}"
    assert seen > 60


def test_the_canary_guard_catches_the_mechanism_under_other_names(tmp_path):
    """Copy the real workflows, add the probe under a new step and function name, run the real guard."""
    for path in WORKFLOWS:
        (tmp_path / path.name).write_text(path.read_text())
    copies = sorted(tmp_path.glob("*.yml"))
    assert canary_leftovers(copies, ACTIONS) == []
    target = tmp_path / "pin-comments.yml"
    text = target.read_text()
    marker = "      - uses: actions/checkout"
    probe = (
        "      - name: Runner network health\n"
        "        run: |\n"
        '          probe_endpoint() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/443"; }\n'
        "          getent ahostsv4 github.com\n"
    )
    assert marker in text
    target.write_text(text.replace(marker, probe + marker, 1))
    found = canary_leftovers(copies, ACTIONS)
    assert found == ["pin-comments.yml: network probe '/dev/tcp/'"], found
