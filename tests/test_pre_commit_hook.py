"""The gitleaks pre-commit hook: one source, the CI pin, and what it does at a keyboard.

`.githooks/pre-commit` is copied byte for byte into adopted repositories by
scripts/new-repo.sh, so it cannot read security.yml at run time; these tests
hold its version and sha256 equal to the `gitleaks-version` and
`gitleaks-sha256` defaults there instead. The behaviour tests run the hook in
a scratch git repository with a planted AWS-shaped key. The ones that need the
pinned binary download it through the hook itself into a temporary cache and
are skipped when that download is impossible (offline); the offline-and-absent
case needs no network and always runs.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / ".githooks" / "pre-commit"
NEW_REPO = REPO / "scripts" / "new-repo.sh"
SECURITY = REPO / ".github" / "workflows" / "security.yml"

# AWS's own documentation key is allowlisted by gitleaks; this shape is not.
# Built at run time so no credential-shaped literal sits in this file for the CI scan to find.
SECRET = "AKIA" + "YVP4CIPPERUWRIOD"
PLANTED = f'key = "{SECRET}"\n'


def hook_constant(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"$', HOOK.read_text(), re.M)
    assert match, f"{name} not found in the hook"
    return match.group(1)


def test_the_hook_pins_the_same_gitleaks_as_security_yml():
    inputs = yaml.safe_load(SECURITY.read_text())[True]["workflow_call"]["inputs"]
    assert hook_constant("GITLEAKS_VERSION") == inputs["gitleaks-version"]["default"], (
        "the hook and security.yml pin different gitleaks versions: change both"
    )
    assert hook_constant("GITLEAKS_SHA256") == inputs["gitleaks-sha256"]["default"], (
        "the hook and security.yml pin different gitleaks hashes: change both"
    )


def test_the_hook_is_executable_and_never_prints_the_finding():
    assert HOOK.stat().st_mode & stat.S_IXUSR
    text = HOOK.read_text()
    assert "--redact" in text and "--pre-commit --staged" in text
    assert "'^(RuleID|File|Line):'" in text, "only the rule, file and line may be printed"


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def scratch(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    return repo


def run_hook(repo: Path, cache: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(HOOK)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GYST_CACHE_DIR": str(cache), **env},
    )


def test_offline_with_no_binary_warns_and_allows(scratch, tmp_path):
    (scratch / "a.env").write_text(PLANTED)
    git(scratch, "add", "a.env")
    result = run_hook(scratch, tmp_path / "cache", GYST_GITLEAKS_URL="file:///nonexistent")
    assert result.returncode == 0
    assert "NOT scanned" in result.stderr


def test_a_download_that_is_not_the_pinned_release_is_refused(scratch, tmp_path):
    served = tmp_path / "served"
    served.mkdir()
    version = hook_constant("GITLEAKS_VERSION")
    (served / f"gitleaks_{version}_linux_x64.tar.gz").write_bytes(b"not gitleaks")
    git(scratch, "add", "-A")
    result = run_hook(scratch, tmp_path / "cache", GYST_GITLEAKS_URL=served.as_uri())
    assert result.returncode == 1
    assert "pinned sha256" in result.stderr
    binaries = [p for p in (tmp_path / "cache").rglob("gitleaks") if p.is_file()]
    assert not binaries, "an unverified download must not leave a binary"


@pytest.fixture(scope="module")
def warm_cache(tmp_path_factory) -> Path:
    """The pinned binary, fetched and verified by the hook itself; skip when offline."""
    cache = tmp_path_factory.mktemp("cache")
    repo = tmp_path_factory.mktemp("warm")
    git(repo, "init", "-q")
    result = run_hook(repo, cache)
    if "NOT scanned" in result.stderr:
        pytest.skip("cannot download the pinned gitleaks release (offline)")
    assert result.returncode == 0, result.stderr
    return cache


def test_a_planted_key_is_refused_naming_rule_and_file_but_not_the_secret(scratch, warm_cache):
    (scratch / "settings.env").write_text(PLANTED)
    git(scratch, "add", "settings.env")
    result = run_hook(scratch, warm_cache)
    assert result.returncode == 1
    assert "aws-access-token" in result.stderr and "settings.env" in result.stderr
    assert SECRET not in result.stdout + result.stderr


def test_a_clean_commit_passes(scratch, warm_cache):
    (scratch / "readme.txt").write_text("nothing to see\n")
    git(scratch, "add", "readme.txt")
    assert run_hook(scratch, warm_cache).returncode == 0


def test_the_repositorys_gitleaks_toml_is_honoured(scratch, warm_cache):
    (scratch / "settings.env").write_text(PLANTED)
    (scratch / ".gitleaks.toml").write_text('[extend]\nuseDefault = true\n[[allowlists]]\npaths = ["settings.env"]\n')
    git(scratch, "add", "-A")
    assert run_hook(scratch, warm_cache).returncode == 0


def test_a_broken_config_refuses_rather_than_skipping_the_scan(scratch, warm_cache):
    (scratch / ".gitleaks.toml").write_text("garbage = [\n")
    git(scratch, "add", "-A")
    result = run_hook(scratch, warm_cache)
    assert result.returncode == 1
    assert "not scanned" in result.stderr


def test_the_hook_blocks_a_real_commit_and_no_verify_passes_it(scratch, warm_cache):
    git(scratch, "config", "core.hooksPath", str(HOOK.parent))
    (scratch / "settings.env").write_text(PLANTED)
    git(scratch, "add", "settings.env")
    env = {**os.environ, "GYST_CACHE_DIR": str(warm_cache)}
    blocked = subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=scratch, env=env, capture_output=True, text=True)
    assert blocked.returncode != 0
    passed = subprocess.run(
        ["git", "commit", "-q", "--no-verify", "-m", "x"], cwd=scratch, env=env, capture_output=True, text=True
    )
    assert passed.returncode == 0


# --- scripts/new-repo.sh writes it ----------------------------------------


def adopt(tmp_path: Path, files: dict[str, str]) -> Path:
    tree = tmp_path / "tree"
    for name, text in files.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text)
    out = tmp_path / "out"
    out.mkdir()
    result = subprocess.run(
        [
            str(NEW_REPO),
            "ChiefGyk3D/example",
            "--dry-run",
            "--path",
            str(tree),
            "--out",
            str(out),
            "--pin",
            "v9.9.9",
            "--sha",
            "d5d9556afeeb06f78419b91ecb5d146e789c6d51",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return out


def test_new_repo_writes_a_byte_identical_executable_hook(tmp_path):
    out = adopt(tmp_path, {"lib/common.sh": "#!/usr/bin/env bash\n  echo hi\n"})
    written = out / ".githooks" / "pre-commit"
    assert written.read_bytes() == HOOK.read_bytes()
    assert written.stat().st_mode & stat.S_IXUSR


def test_new_repo_adds_the_hooks_path_line_to_a_developing_section_once(tmp_path):
    readme = "# T\n\n## Developing\n\nRun the tests.\n"
    out = adopt(tmp_path, {"lib/common.sh": "#!/usr/bin/env bash\n  echo hi\n", "README.md": readme})
    text = (out / "README.md").read_text()
    assert text.count("git config core.hooksPath .githooks") == 1
    assert text.index("## Developing") < text.index("core.hooksPath") < text.index("Run the tests.")


def test_new_repo_leaves_a_readme_with_the_line_or_no_section_alone(tmp_path):
    out = adopt(tmp_path, {"lib/common.sh": "#!/usr/bin/env bash\n  echo hi\n", "README.md": "# T\n\nno section\n"})
    assert not (out / "README.md").exists()
