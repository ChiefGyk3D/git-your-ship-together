"""The Semgrep job and the licence rule in security.yml.

The general invariants (harden-runner first, pinned actions, timeouts, no
`inputs.*` in run blocks, documented inputs) live in test_workflows.py and
already cover these jobs; this file pins what is specific to them.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
from urllib.request import Request, urlopen

import pytest
import yaml
from test_workflows import README, WORKFLOWS, jobs, load, steps_of, triggers

DOC = load(WORKFLOWS / "security.yml")
INPUTS = triggers(DOC)["workflow_call"]["inputs"]
SEMGREP = jobs(DOC)["semgrep"]
SCAN = next(s for s in steps_of(SEMGREP) if s.get("name") == "Scan (Semgrep)")
DEFAULT_PACKS = sorted(set(re.findall(r"\bp/[\w-]+", SCAN["run"] + INPUTS["semgrep-config"]["default"])))


def test_semgrep_job_exists_and_is_named():
    assert SEMGREP["name"] == "Semgrep"
    assert SEMGREP["if"] == "inputs.semgrep"


def test_semgrep_inputs_and_defaults():
    assert INPUTS["semgrep"]["type"] == "boolean" and INPUTS["semgrep"]["default"] is True
    assert INPUTS["semgrep-config"]["default"] == ""
    assert INPUTS["semgrep-continue-on-error"]["default"] is False
    assert INPUTS["semgrep-egress-policy"]["default"] == "block"
    assert INPUTS["semgrep-allowed-endpoints"]["default"].split(" ")[-1] == "semgrep.dev:443"
    assert INPUTS["semgrep-version"]["default"].count(".") == 2, "pin an exact release"


def test_semgrep_holds_no_id_token_and_no_doppler():
    assert SEMGREP["permissions"] == {"contents": "read", "security-events": "write"}
    text = str(SEMGREP)
    assert "doppler" not in text.lower() and "secrets." not in text


def test_semgrep_uses_its_own_egress_policy():
    first = steps_of(SEMGREP)[0]
    assert first["uses"].startswith("step-security/harden-runner@")
    assert first["with"]["egress-policy"] == "${{ inputs.semgrep-egress-policy }}"
    assert "inputs.semgrep-allowed-endpoints" in first["with"]["allowed-endpoints"]
    assert "inputs.extra-allowed-endpoints" in first["with"]["allowed-endpoints"]
    others = [n for n, j in jobs(DOC).items() if n != "semgrep"]
    for name in others:
        policy = steps_of(jobs(DOC)[name])[0]["with"]["egress-policy"]
        assert policy == "${{ inputs.egress-policy }}", f"{name} must keep the shared egress input"


def test_semgrep_scan_command():
    scan = next(s for s in steps_of(SEMGREP) if s.get("name") == "Scan (Semgrep)")
    run = scan["run"]
    assert "--metrics=off" in run and "--sarif --output semgrep.sarif" in run
    assert '--config "$config"' in run
    assert 'if [ "$CONTINUE" != "true" ]; then args+=(--error); fi' in run
    assert scan["env"]["CONFIGS"] == "${{ inputs.semgrep-config }}"
    install = next(s for s in steps_of(SEMGREP) if s.get("name") == "Install Semgrep")
    assert install["env"]["SEMGREP_VERSION"] == "${{ inputs.semgrep-version }}"
    assert "inputs." not in install["run"]


@pytest.mark.parametrize("python_file", [None, "app.py", "src/app.py"])
@pytest.mark.parametrize("configs", ["", "p/secrets custom.yml"])
@pytest.mark.parametrize("continue_on_error", [False, True])
def test_semgrep_defaults_follow_repository_content(tmp_path, python_file, configs, continue_on_error):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "greet.sh").write_text("#!/bin/sh\nprintf 'hello\\n'\n")
    if python_file:
        path = tmp_path / python_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("print('hello')\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    # An untracked dependency must not turn a shell-only caller into a Python repository.
    (tmp_path / "untracked.py").write_text("print('dependency')\n")
    scan = next(s for s in steps_of(SEMGREP) if s.get("name") == "Scan (Semgrep)")
    capture = tmp_path / "scan-args"
    subprocess.run(
        ["bash", "-c", 'semgrep() { printf "%s\\n" "$@" > "$SCAN_ARGS"; }\n' + scan["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "CONFIGS": configs or INPUTS["semgrep-config"]["default"],
            "CONTINUE": str(continue_on_error).lower(),
            "SCAN_ARGS": str(capture),
        },
        check=True,
    )
    expected_configs = (
        configs.split() if configs else ((["p/python"] if python_file else []) + ["p/github-actions", "p/secrets"])
    )
    args = capture.read_text().splitlines()
    assert args == [
        "scan",
        "--metrics=off",
        "--sarif",
        "--output",
        "semgrep.sarif",
        *(arg for config in expected_configs for arg in ("--config", config)),
        *([] if continue_on_error else ["--error"]),
        ".",
    ]


@pytest.mark.parametrize("pack", DEFAULT_PACKS)
@pytest.mark.skipif(
    os.environ.get("GYST_TEST_SEMGREP_REGISTRY") != "1",
    reason="set GYST_TEST_SEMGREP_REGISTRY=1 to resolve default packs against the live registry",
)
def test_semgrep_default_pack_resolves_in_registry(pack):
    request = Request(f"https://semgrep.dev/c/{pack}", headers={"Accept": "application/json"})
    with urlopen(request, timeout=60) as response:
        config = yaml.safe_load(response.read())
    if "rule_config" in config:
        config = config["rule_config"]
        if isinstance(config, str):
            config = yaml.safe_load(config)
    assert config["rules"], f"{pack}: registry returned no rules"
    assert all({"id", "languages", "message", "severity"} <= rule.keys() for rule in config["rules"]), pack


@pytest.mark.parametrize("format_", ["yaml", "wrapped-yaml", "wrapped-object"])
def test_registry_contract_accepts_supported_response_formats(monkeypatch, format_):
    config = {"rules": [{"id": "example", "languages": ["python"], "message": "example", "severity": "WARNING"}]}
    if format_ == "wrapped-yaml":
        config = {"rule_config": yaml.safe_dump(config)}
    elif format_ == "wrapped-object":
        config = {"rule_config": config}
    body = yaml.safe_dump(config).encode()
    monkeypatch.setattr("test_security_jobs.urlopen", lambda request, timeout: io.BytesIO(body))
    test_semgrep_default_pack_resolves_in_registry("p/python")


def test_semgrep_uploads_sarif_with_its_category_even_after_a_finding():
    upload = next(
        s for s in steps_of(SEMGREP) if str(s.get("uses", "")).startswith("github/codeql-action/upload-sarif@")
    )
    assert upload["with"] == {"sarif_file": "semgrep.sarif", "category": "semgrep"}
    assert "always()" in upload["if"] and "hashFiles('semgrep.sarif')" in upload["if"]


def test_there_is_no_gate_job_for_semgrep_to_join():
    """security.yml has no summary job; callers require the called jobs' own checks. Revisit if one is added."""
    assert not [n for n, j in jobs(DOC).items() if "needs" in j]


def test_dependency_review_carries_the_licence_denylist():
    assert INPUTS["dependency-review-deny-licenses"]["type"] == "string"
    default = INPUTS["dependency-review-deny-licenses"]["default"]
    assert {"AGPL-3.0", "GPL-3.0", "SSPL-1.0"} <= {x.strip() for x in default.split(",")}
    step = next(s for s in steps_of(jobs(DOC)["dependency-review"]) if "dependency-review-action" in str(s.get("uses")))
    assert step["with"]["deny-licenses"] == "${{ inputs.dependency-review-deny-licenses }}"
    assert step["with"]["allow-ghsas"] == "${{ inputs.dependency-review-allow-ghsas }}"
    assert "allow-licenses" not in step["with"], "the action rejects allow-licenses beside deny-licenses"


def test_new_inputs_are_in_the_readme():
    text = README.read_text()
    for name in (
        "semgrep",
        "semgrep-config",
        "semgrep-version",
        "semgrep-continue-on-error",
        "semgrep-egress-policy",
        "dependency-review-deny-licenses",
    ):
        assert f"| `{name}` |" in text, f"{name} is not documented in the README"


GITLEAKS = jobs(DOC)["gitleaks"]


def test_gitleaks_is_a_pinned_binary_not_a_licensed_action():
    # #90: gitleaks-action demands a licence under an organisation.
    assert not any("gitleaks/gitleaks-action" in str(s.get("uses", "")) for s in steps_of(GITLEAKS))
    assert "GITLEAKS_LICENSE" not in (WORKFLOWS / "security.yml").read_text()
    assert "GITLEAKS_LICENSE" not in README.read_text()
    allowed = WORKFLOWS.parent.parent / "baseline" / "selected-actions.json"
    assert "gitleaks/gitleaks-action" not in allowed.read_text()
    # No credential: no OIDC token, no Doppler, no secrets in this job.
    assert GITLEAKS["permissions"] == {"contents": "read", "security-events": "write"}
    text = str(GITLEAKS)
    assert "doppler" not in text.lower() and "secrets." not in text and "id-token" not in text
    install = next(s for s in steps_of(GITLEAKS) if s.get("name", "").startswith("Install gitleaks"))
    assert install["env"] == {
        "GITLEAKS_VERSION": "${{ inputs.gitleaks-version }}",
        "GITLEAKS_SHA256": "${{ inputs.gitleaks-sha256 }}",
    }
    assert re.fullmatch(r"\d+\.\d+\.\d+", INPUTS["gitleaks-version"]["default"])
    assert re.fullmatch(r"[0-9a-f]{64}", INPUTS["gitleaks-sha256"]["default"])
    assert "sha256sum -c" in install["run"]
    assert install["run"].index("sha256sum -c") < install["run"].index("tar ")


def test_gitleaks_scans_full_history_and_uploads_sarif():
    checkout = next(s for s in steps_of(GITLEAKS) if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    scan = next(s for s in steps_of(GITLEAKS) if s.get("name", "").startswith("Scan the full history"))
    assert "--exit-code 1" in scan["run"] and '--log-opts="--all"' in scan["run"]
    assert "--report-format sarif --report-path gitleaks.sarif" in scan["run"]
    upload = next(s for s in steps_of(GITLEAKS) if "upload-sarif" in str(s.get("uses", "")))
    assert upload["with"] == {"sarif_file": "gitleaks.sarif", "category": "gitleaks"}
    assert upload["if"].startswith("always()")


def test_gitleaks_canary_is_wired_before_the_scan():
    names = [s.get("name", "") for s in steps_of(GITLEAKS)]
    canary = next(i for i, n in enumerate(names) if "planted key" in n)
    assert canary < next(i for i, n in enumerate(names) if n.startswith("Scan the full history"))
    run = steps_of(GITLEAKS)[canary]["run"]
    assert '"$status" -ne 1' in run


def test_gitleaks_pinned_release_catches_a_planted_key(tmp_path):
    """Falsifiability, run for real: the pinned archive is fetched, checked
    against the pinned hash, and the canary step's own script must exit 0 (it
    exits 1 when the planted key is NOT caught). Needs the network."""
    import hashlib

    version, sha = INPUTS["gitleaks-version"]["default"], INPUTS["gitleaks-sha256"]["default"]
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz"
    try:
        data = urlopen(Request(url), timeout=60).read()
    except OSError as err:
        pytest.skip(f"no network: {err}")
    assert hashlib.sha256(data).hexdigest() == sha, "the pinned sha256 does not match the release asset"
    import tarfile

    bindir = tmp_path / "bin"
    bindir.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = tar.getmember("gitleaks")
        (bindir / "gitleaks").write_bytes(tar.extractfile(member).read())  # type: ignore[union-attr]
    (bindir / "gitleaks").chmod(0o755)
    canary = next(s for s in steps_of(GITLEAKS) if "planted key" in s.get("name", ""))
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    done = subprocess.run(["bash", "-c", canary["run"]], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
