"""The fixture image that `fixture verify` and `fixture rescan` check (issues #285, #315, #381).

The image is built from fixture/gyst-fixture/ and published by .github/workflows/fixture-image.yml through this
repository's own container-release.yml. ci.yml reads which image to check from ONE file, fixture/gyst-fixture/DIGEST:
`unpublished` keeps the third-party star-daemon target (the image does not exist before the workflow first runs on
main), a sha256 switches both jobs to gyst-fixture pinned by that digest. These tests hold both states to the rules.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "fixture" / "gyst-fixture"
DIGEST_FILE = SRC / "DIGEST"
WORKFLOW = REPO / ".github" / "workflows" / "fixture-image.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

CI_JOBS = yaml.safe_load(CI.read_text())["jobs"]
IMAGE_JOBS = ("fixture-verify", "fixture-rescan")


def pin_value() -> str:
    return DIGEST_FILE.read_text().strip()


def pin_step() -> dict:
    steps = [s for s in CI_JOBS["fixture-pin"]["steps"] if s.get("id") == "pin"]
    assert len(steps) == 1, "exactly one step reads the pin"
    return steps[0]


def run_pin(tmp_path: Path, content: str):
    """Run the CI job's pin step under bash over a DIGEST file holding `content`; return (result, outputs)."""
    digest = tmp_path / "DIGEST"
    digest.write_text(content)
    out = tmp_path / "out"
    out.write_text("")
    env = {**os.environ, "DIGEST_FILE": str(digest), "GITHUB_OUTPUT": str(out)}
    result = subprocess.run(["bash", "-c", pin_step()["run"]], env=env, capture_output=True, text=True)
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    return result, outputs


def test_the_source_is_one_dockerfile_and_one_copied_file():
    assert sorted(p.name for p in SRC.iterdir()) == ["DIGEST", "Dockerfile", "README.md", "VERSION"]
    lines = [x.strip() for x in (SRC / "Dockerfile").read_text().splitlines() if x.strip() and not x.startswith("#")]
    froms = [x for x in lines if x.startswith("FROM ")]
    assert len(froms) == 1 and re.search(r"@sha256:[0-9a-f]{64}$", froms[0]), "one base, pinned by digest"
    assert len([x for x in lines if x.startswith("COPY ")]) == 1
    assert not [x for x in lines if x.startswith(("RUN ", "ADD ", "ARG ", "ENV "))], "no network or secret at build"
    assert any(re.fullmatch(r"USER [1-9][0-9]*", x) for x in lines), "non-root, numeric"
    assert SEMVER.match((SRC / "VERSION").read_text().strip())


def test_the_pin_file_is_unpublished_or_one_valid_digest():
    text = DIGEST_FILE.read_text()
    assert text.endswith("\n") and text.count("\n") == 1, "one line"
    assert pin_value() == "unpublished" or SHA256.match(pin_value()), pin_value()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "Unpublished",
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
        "sha512:" + "a" * 64,
        "a" * 64,
        "latest",
        "unpublished sha256:" + "a" * 64,
    ],
)
def test_the_pin_step_refuses_anything_else_and_writes_nothing(tmp_path, bad):
    result, outputs = run_pin(tmp_path, bad + "\n")
    assert result.returncode != 0, "a typo must not fall back to the old image"
    assert outputs == {}


def test_a_digest_pins_the_gyst_fixture_image_with_its_own_signer(tmp_path):
    digest = "sha256:" + "ab" * 32
    result, outputs = run_pin(tmp_path, digest + "\n")
    assert result.returncode == 0, result.stderr
    assert outputs["image"] == f"ghcr.io/chiefgyk3d/gyst-fixture@{digest}"
    assert outputs["source-repository"] == "ChiefGyk3D/git-your-ship-together"
    assert "star-daemon" not in "".join(outputs.values()).lower()


def test_unpublished_keeps_the_existing_target_working(tmp_path):
    result, outputs = run_pin(tmp_path, "unpublished\n")
    assert result.returncode == 0, result.stderr
    assert outputs["image"] == "ghcr.io/chiefgyk3d/star-daemon:latest"
    assert outputs["source-repository"] == "ChiefGyk3D/Star-Daemon"
    assert outputs["identity-regexp"] == "^https://github.com/ChiefGyk3D/"


def test_the_fixture_jobs_take_everything_from_the_pin_job_and_name_no_image():
    for name in IMAGE_JOBS:
        job = CI_JOBS[name]
        assert "fixture-pin" in job["needs"]
        for key in ("image", "source-repository", "identity-regexp"):
            assert job["with"][key] == "${{ needs.fixture-pin.outputs." + key + " }}", (name, key)
        assert "star-daemon" not in str(job).lower() and "gyst-fixture" not in str(job)
    assert CI_JOBS["fixture-verify"]["with"]["test-command"] == "${{ needs.fixture-pin.outputs.test-command }}"


def test_star_daemon_appears_in_ci_only_inside_the_unpublished_branch_of_the_pin_step():
    ci_without_pin = {k: v for k, v in CI_JOBS.items() if k != "fixture-pin"}
    assert "star-daemon" not in str(ci_without_pin).lower()
    run = pin_step()["run"]
    published = run.split("elif", 1)[1]
    assert "star-daemon" not in published.lower(), "the published branch names the new image only"
    assert "star-daemon" in run.split("elif", 1)[0]


def test_the_pin_job_is_gated_and_part_of_the_ci_gate():
    gate = next(s for s in CI_JOBS["ci-green"]["steps"] if s.get("name") == "Every job passed")["with"]
    assert "fixture-pin" in CI_JOBS["ci-green"]["needs"]
    for key in ("required-jobs", "skippable-jobs"):
        assert "fixture-pin" in gate[key].split()
    assert CI_JOBS["fixture-pin"]["if"] == CI_JOBS["fixture-verify"]["if"]


def copies_of(value: str, paths: list[Path], pin_file: Path) -> list[str]:
    return [str(p) for p in paths if p != pin_file and p.is_file() and value.encode() in p.read_bytes()]


def test_the_digest_is_written_in_one_place_only():
    """Every tracked file other than the pin file itself must not carry the pinned digest."""
    value = pin_value()
    if value == "unpublished":
        pytest.skip("nothing published yet")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True).stdout
    paths = [REPO / n.decode() for n in out.split(b"\0") if n]
    assert DIGEST_FILE in paths, "something was collected"
    assert copies_of(value, paths, DIGEST_FILE) == []
    assert "gyst-fixture@sha256" not in CI.read_text()


def test_the_one_place_scan_bites(tmp_path):
    value = "sha256:" + "cd" * 32
    pin, copy, clean = tmp_path / "DIGEST", tmp_path / "ci.yml", tmp_path / "ok.yml"
    pin.write_text(value + "\n")
    copy.write_text(f"image: ghcr.io/chiefgyk3d/gyst-fixture@{value}\n")
    clean.write_text("nothing here\n")
    assert copies_of(value, [pin, copy, clean], pin) == [str(copy)]
    assert copies_of(value, [pin, clean], pin) == []


# --- the publishing workflow ---------------------------------------------------------------------------------

WF = yaml.safe_load(WORKFLOW.read_text())
ON = WF.get("on") or WF.get(True)


def test_the_workflow_runs_on_dispatch_and_on_main_pushes_to_the_image_source_only():
    assert set(ON) == {"workflow_dispatch", "push"}
    assert ON["push"]["branches"] == ["main"]
    paths = ON["push"]["paths"]
    assert "fixture/gyst-fixture/**" in paths
    assert "!fixture/gyst-fixture/DIGEST" in paths, "recording the digest must not start another publish"
    assert "workflow_call" not in ON and "pull_request" not in ON and "pull_request_target" not in ON


def test_it_publishes_through_this_repositorys_own_container_release_with_the_narrowest_inputs():
    publish = WF["jobs"]["publish"]
    assert publish["uses"].startswith("./.github/workflows/container-release.yml")
    assert publish["if"] == "github.ref == 'refs/heads/main'"
    with_ = publish["with"]
    assert with_["push"] is True
    assert with_["allowed-publish-events"] == "push,workflow_dispatch"
    assert with_["require-tag-ref"] is False
    assert with_["image-name"] == "gyst-fixture"
    assert with_["dockerfile"] == "fixture/gyst-fixture/Dockerfile" and with_["context"] == "fixture/gyst-fixture"
    for off in ("sign", "sbom", "provenance", "allow-unsigned-publish", "hadolint-continue-on-error"):
        assert off not in with_, f"{off} stays at container-release.yml's default (signed, attested, strict)"
    assert publish["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
        "security-events": "write",
    }
    assert WF["permissions"] == {"contents": "read"}


def test_the_release_path_defaults_stay_strict():
    """This caller opts into publishing from a manual or path trigger; the reusable workflow's defaults stay strict."""
    doc = yaml.safe_load((REPO / ".github/workflows/container-release.yml").read_text())
    inputs = (doc.get("on") or doc[True])["workflow_call"]
    assert inputs["inputs"]["allowed-publish-events"]["default"] == "push"
    assert inputs["inputs"]["require-tag-ref"]["default"] is True


def test_the_version_tag_follows_the_version_file_and_latest_is_kept():
    tags = WF["jobs"]["publish"]["with"]["tags"].split()
    version = (SRC / "VERSION").read_text().strip()
    assert f"type=raw,value={version}" in tags
    assert "type=raw,value=latest" in tags
    assert len([t for t in tags if re.fullmatch(r"type=raw,value=\d+\.\d+\.\d+", t)]) == 1


def test_the_verify_fixture_identity_matches_the_signing_workflow_path():
    """The certificate subject is the reusable workflow that signs (container-release.yml, called from
    fixture-image.yml on main), as container-release.yml documents: `SAN = https://github.com/<repo>/.github/workflows/
    container-release.yml@<ref>`. The regexp the pin step hands to the verify fixture must match that subject on main,
    and nothing else a stranger could produce."""
    published = pin_step()["run"].split("elif", 1)[1]
    raw = re.search(r"echo 'identity-regexp=(.*?)'\n", published).group(1)
    regexp = re.compile(raw)
    base = "https://github.com/ChiefGyk3D/git-your-ship-together/.github/workflows/"
    assert WF["jobs"]["publish"]["uses"].startswith("./.github/workflows/container-release.yml")
    assert regexp.search(base + "container-release.yml@refs/heads/main")
    # negative cases: another repository, another workflow, another ref, a suffix, the caller's own path
    for bad in (
        "https://github.com/ChiefGyk3D/Star-Daemon/.github/workflows/container-release.yml@refs/heads/main",
        "https://github.com/Evil/git-your-ship-together/.github/workflows/container-release.yml@refs/heads/main",
        base + "verify-published.yml@refs/heads/main",
        base + "fixture-image.yml@refs/heads/main",
        base + "container-release.yml@refs/heads/other",
        base + "container-release.yml@refs/heads/main-evil",
        base + "container-releaseXyml@refs/heads/main",
    ):
        assert not regexp.search(bad), bad
    # container-release.yml's own post-signing check (its default) accepts the same subject
    release = yaml.safe_load((REPO / ".github/workflows/container-release.yml").read_text())
    default = (release.get("on") or release[True])["workflow_call"]["inputs"]["signer-identity-regexp"]["default"]
    assert re.search(default, base + "container-release.yml@refs/heads/main")


def test_the_dependabot_config_moves_the_base_pin():
    cfg = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text())
    docker = [u for u in cfg["updates"] if u["package-ecosystem"] == "docker"]
    assert "/fixture/gyst-fixture" in [u["directory"] for u in docker]
