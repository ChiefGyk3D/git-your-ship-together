"""The `runs-on` input of security.yml and dast.yml (slice 1 of self-hosted runner support).

`runs-on` takes a string, an array or an object, so the input is a JSON string and every job reads it with
`fromJSON(inputs.runs-on)`. The default parses to the label the workflow used before the input existed, so a caller
that does not pass it sees no change. A job that follows the secretless egress input may only reach `audit` on a
GitHub-hosted label (EX-0001); the label check follows the input, see tests/test_egress_policy.py for the oracle.
"""

import json
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
# workflow file -> the label every job used before the input existed
DEFAULTS = {"security.yml": "ubuntu-latest", "dast.yml": "ubuntu-24.04"}
EXPECTED = "${{ fromJSON(inputs.runs-on) }}"


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def test_something_was_collected():
    assert sum(len(load(n)["jobs"]) for n in DEFAULTS) >= 10


@pytest.mark.parametrize("name,label", sorted(DEFAULTS.items()))
def test_the_input_default_parses_to_todays_label(name, label):
    doc = load(name)
    spec = doc[True]["workflow_call"]["inputs"]["runs-on"]
    assert spec["type"] == "string" and spec.get("required") is not True
    assert json.loads(spec["default"]) == label
    assert "JSON" in spec["description"]


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_every_job_uses_the_input(name):
    for job_name, job in load(name)["jobs"].items():
        assert job["runs-on"] == EXPECTED, f"{name}:{job_name}"


def test_the_guard_bites():
    assert {"runs-on": "ubuntu-latest"}["runs-on"] != EXPECTED


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_the_header_documents_harden_runner_on_self_hosted_runners(name):
    head = (WORKFLOWS / name).read_text().split("\nname:")[0].lower()
    assert "self-hosted" in head and "no-op" in head and "2026-11-25" in head and "verified" in head
