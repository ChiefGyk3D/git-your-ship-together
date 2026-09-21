#!/usr/bin/env bash
# Adopt a repository into the shared workflows and the baseline, or start a
# new one. Reads the repository as it is, writes the caller workflows from
# what it finds, commits them on a branch, pushes over SSH, opens the pull
# request, applies every BASELINE.md setting through the API, and appends
# the repository to baseline/repos.txt for the audit to confirm.
#
#   scripts/new-repo.sh OWNER/NAME [--path DIR] [--language python|bash]...
#                       [--container|--no-container] [--package|--no-package]
#                       [--pypi] [--doppler-identity UUID] [--pin vX.Y.Z]
#                       [--dry-run --out DIR [--sha SHA]]
#
# What it reads: pyproject.toml, requirements*.txt, ruff and mypy config,
# the Dockerfile, the shell scripts and their indent, a yamllint config, an
# ansible/ directory, and the workflows already there (a PyPI publish step
# there turns PyPI on; the rest are replaced and listed in the pull request).
# What it asks a person for: the Doppler service account and identity, which
# are made in the Doppler dashboard; pass --doppler-identity once you have
# the UUID and the variable is set, or run again with just that flag.
#
# --dry-run writes the files under --out and prints the settings it would
# apply, touching neither GitHub nor the repository's git history. That is
# what tests/test_new_repo.py runs.
#
# Needs: gh (authenticated as the owner), git with SSH push access, python3.
# The gh token does not need the `workflow` scope: workflow files are
# committed locally and pushed over SSH.
set -euo pipefail

SHARED="ChiefGyk3D/git-your-ship-together"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BRANCH="ci/git-your-ship-together"

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

die() {
  echo "error: $*" >&2
  exit 1
}

# ---- arguments -------------------------------------------------------------

repo=""
path=""
out=""
pin=""
sha=""
identity=""
dry_run=false
want_container=""
want_package=""
want_pypi=""
declare -a languages=()

while [ $# -gt 0 ]; do
  case $1 in
    --path)
      path=$2
      shift 2
      ;;
    --out)
      out=$2
      shift 2
      ;;
    --language)
      languages+=("$2")
      shift 2
      ;;
    --container)
      want_container=true
      shift
      ;;
    --no-container)
      want_container=false
      shift
      ;;
    --package)
      want_package=true
      shift
      ;;
    --no-package)
      want_package=false
      shift
      ;;
    --pypi)
      want_pypi=true
      shift
      ;;
    --doppler-identity)
      identity=$2
      shift 2
      ;;
    --pin)
      pin=$2
      shift 2
      ;;
    --sha)
      sha=$2
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    -h | --help) usage ;;
    -*) die "unknown option $1" ;;
    *)
      [ -z "$repo" ] || die "one repository at a time"
      repo=$1
      shift
      ;;
  esac
done
[ -n "$repo" ] || usage
case $repo in */*) ;; *) die "repository must be OWNER/NAME" ;; esac
owner=${repo%%/*}
name=${repo#*/}
if $dry_run; then
  [ -n "$out" ] || die "--dry-run needs --out DIR"
  [ -n "$path" ] || die "--dry-run needs --path DIR, the tree to read"
fi
if [ -n "$identity" ] && ! [[ $identity =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  die "--doppler-identity is not a UUID"
fi

# ---- the pin ---------------------------------------------------------------
# A tag's SHA is not a commit's SHA: an annotated tag points at a tag object,
# and a caller must pin the commit. Dereference.

resolve_pin() {
  if [ -z "$pin" ]; then
    pin=$(gh api "repos/$SHARED/releases/latest" --jq .tag_name)
  fi
  if [ -z "$sha" ]; then
    local type
    type=$(gh api "repos/$SHARED/git/ref/tags/$pin" --jq .object.type)
    sha=$(gh api "repos/$SHARED/git/ref/tags/$pin" --jq .object.sha)
    if [ "$type" = "tag" ]; then
      sha=$(gh api "repos/$SHARED/git/tags/$sha" --jq .object.sha)
    fi
  fi
  [[ $sha =~ ^[0-9a-f]{40}$ ]] || die "pin $pin resolved to '$sha', not a commit SHA"
  [[ $pin =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "pin '$pin' is not a vX.Y.Z tag"
}

# ---- the tree --------------------------------------------------------------

clone_if_needed() {
  if [ -z "$path" ]; then
    path=$(pwd)/$name
    if [ ! -d "$path/.git" ]; then
      echo "cloning git@github.com:$repo.git into $path"
      git clone -q "git@github.com:$repo.git" "$path"
    fi
  fi
  [ -d "$path" ] || die "$path does not exist"
}

has_python=false
has_bash=false
dockerfile=""
package=false
pypi=false
py_versions=""
install_cmd=""
lint_install=""
lint_cmd=""
smoke_cmd=""
shfmt_indent=4
shell_test_hint=""
config_install=""
config_cmd=""
declare -a old_workflows=()
declare -a kept_workflows=()
default_branch="main"

tracked() {
  # Every tracked file, or every file when the tree is not a git checkout.
  if git -C "$path" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$path" ls-files
  else
    (cd "$path" && find . -type f -not -path './.git/*' | sed 's|^\./||')
  fi
}

detect() {
  local files
  files=$(tracked)

  # Python: a project file or a requirements file.
  if [ -f "$path/pyproject.toml" ] || [ -f "$path/requirements.txt" ] || [ -f "$path/setup.py" ]; then
    has_python=true
  fi
  # Shell: a script by name or shebang.
  local f
  while IFS= read -r f; do
    [ -f "$path/$f" ] || continue
    case "$f" in
      *.sh | *.bash)
        has_bash=true
        break
        ;;
    esac
    if head -c 200 "$path/$f" | head -n 1 | grep -Eq '^#!.*\b(ba)?sh\b'; then
      has_bash=true
      break
    fi
  done <<<"$files"
  if [ ${#languages[@]} -gt 0 ]; then
    has_python=false
    has_bash=false
    local l
    for l in "${languages[@]}"; do
      case $l in
        python) has_python=true ;;
        bash | shell) has_bash=true ;;
        *) die "unknown language $l (python, bash)" ;;
      esac
    done
  fi
  $has_python || $has_bash || die "found neither Python nor shell in $path; pass --language"

  # Container: the first Dockerfile in the usual places.
  local d
  for d in Dockerfile docker/Dockerfile Docker/Dockerfile; do
    if [ -f "$path/$d" ]; then
      dockerfile=$d
      break
    fi
  done
  if [ "$want_container" = false ]; then dockerfile=""; fi
  if [ "$want_container" = true ] && [ -z "$dockerfile" ]; then die "--container but no Dockerfile found"; fi

  # Package: a build system in pyproject.toml. PyPI only where a workflow
  # already publishes there; a Trusted Publisher has to exist first.
  if $has_python && [ -f "$path/pyproject.toml" ] && grep -q '^\[build-system\]' "$path/pyproject.toml"; then
    package=true
  fi
  if [ "$want_package" = false ]; then package=false; fi
  if [ "$want_package" = true ]; then package=true; fi
  if [ -d "$path/.github/workflows" ] && grep -rlq 'gh-action-pypi-publish' "$path/.github/workflows" 2>/dev/null; then
    pypi=true
  fi
  if [ "$want_pypi" = true ]; then pypi=true; fi

  if $has_python; then detect_python; fi
  if $has_bash; then detect_bash; fi
  detect_config_lint
  detect_old_workflows
}

detect_python() {
  local pp="$path/pyproject.toml"
  # Versions: the classifiers when present, else from requires-python to 3.13.
  if [ -f "$pp" ]; then
    py_versions=$(
      python3 - "$pp" <<'PY'
import re, sys, tomllib
data = tomllib.load(open(sys.argv[1], "rb"))
project = data.get("project", {})
versions = sorted({m.group(1) for c in project.get("classifiers", []) for m in [re.search(r"Python :: (3\.\d+)$", c)] if m}, key=lambda v: int(v.split(".")[1]))
if not versions:
    m = re.search(r">=\s*3\.(\d+)", project.get("requires-python", ""))
    low = int(m.group(1)) if m else 11
    versions = [f"3.{n}" for n in range(max(low, 9), 14)]
print(", ".join(f'"{v}"' for v in versions))
PY
    )
  fi
  [ -n "$py_versions" ] || py_versions='"3.11", "3.12", "3.13"'

  # Install: a hash-pinned dev lock, a dev extra, or the project itself.
  if [ -f "$path/requirements-dev.txt" ]; then
    if grep -q -- '--hash=sha256:' "$path/requirements-dev.txt"; then
      install_cmd='pip install --require-hashes -r requirements-dev.txt'
    else
      install_cmd='pip install -r requirements-dev.txt'
    fi
    if [ -f "$pp" ]; then install_cmd="$install_cmd"$'\n''pip install --no-deps -e .'; fi
  elif [ -f "$pp" ] && python3 -c 'import sys, tomllib; d = tomllib.load(open(sys.argv[1], "rb")); sys.exit(0 if "dev" in d.get("project", {}).get("optional-dependencies", {}) else 1)' "$pp"; then
    install_cmd='pip install -e ".[dev]"'
  elif [ -f "$path/requirements.txt" ]; then
    install_cmd='pip install -r requirements.txt'$'\n''pip install pytest'
  else
    install_cmd='pip install -e .'$'\n''pip install pytest'
  fi

  # Lint: ruff where it is configured, mypy beside it where it is.
  local ruff=false mypy=false
  if [ -f "$path/ruff.toml" ] || [ -f "$path/.ruff.toml" ] || { [ -f "$pp" ] && grep -q '^\[tool.ruff' "$pp"; }; then ruff=true; fi
  if [ -f "$path/mypy.ini" ] || { [ -f "$pp" ] && grep -q '^\[tool.mypy\]' "$pp"; }; then mypy=true; fi
  if $ruff && $mypy; then
    lint_install="$install_cmd"
    lint_cmd='ruff check .'$'\n''ruff format --check . || echo "::warning title=ruff format::formatting drift (advisory)"'$'\n''mypy'
  elif $ruff; then
    lint_install='pip install ruff'
    lint_cmd='ruff check .'$'\n''ruff format --check . || echo "::warning title=ruff format::formatting drift (advisory)"'
  else
    lint_install='pip install ruff'
    lint_cmd='ruff check .'
  fi

  # Smoke: the first console script, asked for its help.
  if [ -f "$pp" ]; then
    local script
    script=$(python3 -c 'import sys, tomllib; d = tomllib.load(open(sys.argv[1], "rb")); s = d.get("project", {}).get("scripts", {}); print(next(iter(s), ""))' "$pp")
    if [ -n "$script" ]; then smoke_cmd="$script --help"; fi
  fi
}

detect_bash() {
  # The indent the scripts already write: two or four spaces, by majority.
  local two four
  two=$(tracked | grep -E '\.(sh|bash)$' | while IFS= read -r f; do [ -f "$path/$f" ] && grep -cE '^  [^ ]' "$path/$f" || true; done | paste -sd+ | bc 2>/dev/null || echo 0)
  four=$(tracked | grep -E '\.(sh|bash)$' | while IFS= read -r f; do [ -f "$path/$f" ] && grep -cE '^    [^ ]' "$path/$f" || true; done | paste -sd+ | bc 2>/dev/null || echo 0)
  if [ "${two:-0}" -gt "${four:-0}" ]; then shfmt_indent=2; fi
  # A test runner is named, not guessed; say what was seen.
  local runners
  runners=$(tracked | grep -E '^tests?/.*\.(sh|bats)$' | head -5 | paste -sd' ' || true)
  if [ -n "$runners" ]; then shell_test_hint="$runners"; fi
}

detect_config_lint() {
  local parts=()
  if [ -f "$path/.yamllint" ] || [ -f "$path/.yamllint.yml" ] || [ -f "$path/.yamllint.yaml" ]; then
    parts+=("yamllint .")
    config_install="pip install yamllint"
  fi
  if [ -d "$path/ansible" ]; then
    parts+=("cd ansible && ansible-lint")
    config_install="${config_install:+$config_install }\"ansible-core>=2.16\" ansible-lint"
    config_install="pip install ${config_install#pip install }"
  fi
  if [ ${#parts[@]} -gt 0 ]; then
    config_cmd=$(printf '%s\n' "${parts[@]}")
    case $config_install in pip\ install*) ;; *) config_install="pip install $config_install" ;; esac
  fi
}

detect_old_workflows() {
  [ -d "$path/.github/workflows" ] || return 0
  local f base
  for f in "$path"/.github/workflows/*.yml "$path"/.github/workflows/*.yaml; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    case $base in
      ci.yml | security.yml | release.yml | dependabot-auto-merge.yml) old_workflows+=("$base") ;;
      ci.yaml | tests.yml | test.yml | lint.yml | codeql.yml | scorecard.yml | security.yaml | release.yaml | publish.yml | pypi.yml) old_workflows+=("$base") ;;
      *) kept_workflows+=("$base") ;;
    esac
  done
}

# ---- the files -------------------------------------------------------------

indent() {
  # Indent a multi-line value for a YAML block scalar at the given depth.
  local depth=$1
  sed "s/^/$(printf '%*s' "$depth" '')/"
}

uses_line() {
  echo "uses: $SHARED/.github/workflows/$1@$sha # $pin"
}

write_ci() {
  local file="$out/.github/workflows/ci.yml"
  {
    echo "# CI for $name. The jobs live in $SHARED; this file"
    echo "# says only what is specific to this repository."
    echo "name: CI"
    echo
    echo "on:"
    echo "  push:"
    echo "    branches: [$default_branch]"
    echo "  pull_request:"
    echo "  workflow_dispatch:"
    echo
    echo "permissions:"
    echo "  contents: read"
    echo
    echo "concurrency:"
    echo '  group: ${{ github.workflow }}-${{ github.ref }}'
    echo "  cancel-in-progress: true"
    echo
    echo "jobs:"
    if $has_python; then
      echo "  ci:"
      echo "    $(uses_line python-ci.yml)"
      echo "    permissions:"
      echo "      contents: read"
      echo "      id-token: write   # Doppler OIDC (see the shared repository's README)"
      echo "    secrets:"
      echo '      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional Service Token fallback; unset means OIDC only'
      echo "    with:"
      echo "      python-versions: '[$py_versions]'"
      echo "      install-command: |"
      echo "        python -m pip install --upgrade pip"
      indent 8 <<<"$install_cmd"
      echo "      test-command: pytest"
      echo "      lint-install-command: |"
      indent 8 <<<"$lint_install"
      echo "      lint-command: |"
      indent 8 <<<"$lint_cmd"
      if [ -n "$smoke_cmd" ]; then
        echo "      smoke-command: $smoke_cmd"
      fi
      if [ -n "$dockerfile" ]; then
        echo "      dockerfile: $dockerfile"
        echo "      docker-test-command: |"
        echo "        # Replace with a real check of the image; this only proves it is not root."
        echo '        test "$(docker run --rm --entrypoint id "$IMAGE" -u)" != "0"'
      else
        echo "      docker-build: false"
      fi
      echo "      egress-policy: block"
      echo "      doppler-project: ci"
      echo "      doppler-config: ci"
      echo '      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}'
    fi
    if $has_bash; then
      if $has_python; then
        echo
        echo "  shell:"
      else
        echo "  ci:"
      fi
      echo "    $(uses_line bash-ci.yml)"
      echo "    permissions:"
      echo "      contents: read"
      echo "    with:"
      echo "      shfmt-args: -i $shfmt_indent -ci"
      if [ -n "$shell_test_hint" ]; then
        echo "      # Shell tests seen: $shell_test_hint. Name the runner:"
        echo "      # test-command: ./tests/run.sh"
      fi
      if [ -n "$config_cmd" ]; then
        echo "      config-lint-install-command: $config_install"
        echo "      config-lint-command: |"
        indent 8 <<<"$config_cmd"
      fi
      if $has_python; then
        echo "      workflow-lint: false   # the ci job above already lints the workflow files"
      fi
      echo "      egress-policy: block"
    fi
  } >"$file"
}

write_security() {
  local file="$out/.github/workflows/security.yml"
  {
    echo "# CodeQL, gitleaks, a dependency audit and dependency review on pull"
    echo "# requests. The jobs live in $SHARED."
    echo "name: Security"
    echo
    echo "on:"
    echo "  push:"
    echo "    branches: [$default_branch]"
    echo "  pull_request:"
    echo "  schedule:"
    echo "    - cron: '0 6 * * 1'   # weekly, so new advisories surface between commits"
    echo "  workflow_dispatch:"
    echo
    echo "permissions:"
    echo "  contents: read"
    echo
    echo "jobs:"
    echo "  security:"
    echo "    $(uses_line security.yml)"
    echo "    permissions:"
    echo "      contents: read"
    echo "      security-events: write"
    echo "      pull-requests: write"
    echo "      id-token: write"
    echo "    secrets:"
    echo '      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional Service Token fallback; unset means OIDC only'
    echo "    with:"
    if ! $has_python; then
      echo "      codeql-languages: actions   # no Python here; CodeQL fails on a language with no source"
      echo '      pip-audit-requirements: ""'
    elif [ ! -f "$path/requirements.txt" ]; then
      echo '      pip-audit-requirements: ""   # no requirements.txt; add a hash-pinned lock and name it here'
    fi
    echo "      scorecard: true"
    echo "      egress-policy: block"
    echo "      doppler-project: ci"
    echo "      doppler-config: ci"
    echo '      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}'
  } >"$file"
}

write_release() {
  [ -n "$dockerfile" ] || $package || return 0
  local file="$out/.github/workflows/release.yml"
  {
    echo "# Publishes on a version tag. The jobs live in $SHARED."
    echo "name: Release"
    echo
    echo "on:"
    echo "  push:"
    echo "    tags: ['v*']"
    echo "  pull_request:   # builds and checks; never publishes"
    echo "  workflow_dispatch:"
    echo
    echo "permissions:"
    echo "  contents: read"
    echo
    echo "jobs:"
    if $package; then
      echo "  package:"
      echo "    $(uses_line python-package-release.yml)"
      echo "    permissions:"
      echo "      contents: write      # the GitHub release and its assets"
      echo "      id-token: write      # PyPI Trusted Publishing, and build provenance"
      echo "      attestations: write  # the provenance record"
      echo "    with:"
      echo "      publish: \${{ startsWith(github.ref, 'refs/tags/v') }}"
      if $pypi; then
        echo "      pypi: true   # the Trusted Publisher on PyPI names this repository, release.yml and the pypi environment"
      else
        echo "      pypi: false   # turn on once a Trusted Publisher on PyPI names this repository, release.yml and the pypi environment"
      fi
      if [ -n "$smoke_cmd" ]; then
        echo "      smoke-command: $smoke_cmd"
      fi
      if [ -f "$path/CHANGELOG.md" ]; then
        echo '      verify-command: grep -q "^## \[$VERSION\]" CHANGELOG.md'
      fi
      echo "      egress-policy: block"
    fi
    if [ -n "$dockerfile" ]; then
      if $package; then echo; fi
      echo "  container:"
      echo "    $(uses_line python-docker-release.yml)"
      echo "    permissions:"
      echo "      contents: read"
      echo "      packages: write"
      echo "      id-token: write"
      echo "      attestations: write"
      echo "      security-events: write"
      echo "    secrets:"
      echo '      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional Service Token fallback; unset means OIDC only'
      echo "    with:"
      echo "      dockerfile: $dockerfile"
      echo "      push: \${{ startsWith(github.ref, 'refs/tags/v') }}"
      echo "      docker-test-command: |"
      echo "        # Replace with a real check of the image; this only proves it is not root."
      echo '        test "$(docker run --rm --entrypoint id "$IMAGE" -u)" != "0"'
      echo "      egress-policy: block"
      echo "      doppler-project: ci"
      echo "      doppler-config: ci"
      echo '      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}'
    fi
  } >"$file"
}

write_auto_merge() {
  local file="$out/.github/workflows/dependabot-auto-merge.yml"
  {
    echo "# Dependabot's own pull requests, merged once the gate is green. The job"
    echo "# lives in $SHARED; a major bump is still left for a person."
    echo "name: Dependabot auto-merge"
    echo
    echo "on: pull_request"
    echo
    echo "permissions:"
    echo "  contents: read"
    echo
    echo "jobs:"
    echo "  auto-merge:"
    echo "    $(uses_line dependabot-auto-merge.yml)"
    echo "    permissions:"
    echo "      contents: write  # enable auto-merge on the pull request"
    echo "      pull-requests: write  # read its Dependabot metadata"
  } >"$file"
}

write_dependabot() {
  local file="$out/.github/dependabot.yml"
  {
    echo "version: 2"
    echo "updates:"
    if $has_python; then
      echo "  - package-ecosystem: pip"
      echo "    directory: /"
      echo "    schedule:"
      echo "      interval: weekly"
      echo "    # A release that turns out to be malicious is usually pulled within days;"
      echo "    # waiting a week before proposing it costs nothing."
      echo "    cooldown:"
      echo "      default-days: 7"
      echo "    open-pull-requests-limit: 5"
      echo "    groups:"
      echo "      python-dependencies:"
      echo "        patterns: ['*']"
      echo
    fi
    echo "  - package-ecosystem: github-actions"
    echo "    directory: /"
    echo "    schedule:"
    echo "      interval: weekly"
    echo "    cooldown:"
    echo "      default-days: 7"
    if [ -n "$dockerfile" ]; then
      echo
      echo "  - package-ecosystem: docker"
      echo "    directory: /$(dirname "$dockerfile" | sed 's|^\.$||')"
      echo "    schedule:"
      echo "      interval: weekly"
      echo "    cooldown:"
      echo "      default-days: 7"
    fi
  } >"$file"
}

write_files() {
  mkdir -p "$out/.github/workflows"
  write_ci
  write_security
  write_release
  write_auto_merge
  write_dependabot
}

required_checks() {
  # The gates the ci.yml just written produces, as the audit derives them.
  python3 - "$out/.github/workflows/ci.yml" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
job = None; gates = []
for line in text.splitlines():
    m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
    if m: job = m.group(1)
    elif job and re.match(r"^\s+uses:\s*\S+/\.github/workflows/[A-Za-z0-9_-]+-ci\.ya?ml@", line):
        gates.append(f"{job} / CI green")
print("\n".join(gates))
PY
}

# ---- the settings ----------------------------------------------------------

settings_plan() {
  local checks
  checks=$(required_checks | python3 -c 'import json, sys; print(json.dumps([{"context": c} for c in sys.stdin.read().split("\n") if c]))')
  cat <<EOF
gh api -X PUT repos/$repo/branches/$default_branch/protection --input - <<'JSON'
{"required_status_checks": {"strict": false, "checks": $checks},
 "enforce_admins": false,
 "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
 "restrictions": null, "required_linear_history": false,
 "allow_force_pushes": false, "allow_deletions": false, "required_conversation_resolution": false}
JSON
gh api -X PUT repos/$repo/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
gh api -X PUT repos/$repo/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
gh api -X PUT repos/$repo/actions/permissions -F enabled=true -f allowed_actions=selected
gh api -X PUT repos/$repo/actions/permissions/selected-actions --input $HERE/baseline/selected-actions.json
gh api -X PATCH repos/$repo -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
gh api -X PUT repos/$repo/private-vulnerability-reporting
gh api -X PUT repos/$repo/automated-security-fixes
gh api -X PATCH repos/$repo -F allow_auto_merge=true
gh api -X POST repos/$repo/rulesets --input - <<'JSON'
{"name": "Version tags are immutable", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]}
JSON
EOF
  if [ -n "$identity" ]; then
    echo "gh variable set DOPPLER_IDENTITY_ID --repo $repo --body $identity"
  fi
}

apply_settings() {
  echo "applying the baseline to $repo"
  local plan
  plan=$(settings_plan)
  # The tag ruleset is a POST; a second run would add a duplicate.
  if gh api "repos/$repo/rulesets" --jq '.[] | select(.target == "tag") | .id' | grep -q .; then
    plan=$(printf '%s\n' "$plan" | python3 -c '
import sys
text = sys.stdin.read()
start = text.index("gh api -X POST")
end = text.index("JSON\n", start) + 5
print(text[:start] + text[end:], end="")')
    echo "a tag ruleset exists already; not adding another"
  fi
  bash -eo pipefail -c "$plan"
}

# ---- git and the pull request ---------------------------------------------

commit_and_pr() {
  local f
  git -C "$path" fetch -q origin
  git -C "$path" checkout -q -B "$BRANCH" "origin/$default_branch"
  for f in "${old_workflows[@]}"; do
    git -C "$path" rm -q ".github/workflows/$f"
  done
  git -C "$path" add .github
  if git -C "$path" diff --cached --quiet; then
    echo "nothing to commit: the caller files are already in place"
    return 0
  fi
  git -C "$path" commit -q -F - <<EOF
ci: call the shared workflows from $SHARED

Written by scripts/new-repo.sh from what the repository already contains.
The workflows it replaces are listed in the pull request.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
EOF
  git -C "$path" push -q -u origin "$BRANCH"
  local body
  body="$(pr_body)"
  gh pr create --repo "$repo" --head "$BRANCH" --base "$default_branch" \
    --title "ci: call the shared workflows from git-your-ship-together" --body "$body"
}

pr_body() {
  cat <<EOF
Written by \`scripts/new-repo.sh\` in $SHARED, pinned to $pin.

What it found and wrote:

- Languages: $($has_python && echo -n "Python " || true)$($has_bash && echo -n "shell" || true)
- Container release: ${dockerfile:-none}
- Package release: $($package && echo "yes (PyPI: $pypi)" || echo no)
- Required checks: $(required_checks | paste -sd, | sed 's/,/, /g')
$(if [ ${#old_workflows[@]} -gt 0 ]; then echo "- Replaced: ${old_workflows[*]}"; fi)
$(if [ ${#kept_workflows[@]} -gt 0 ]; then echo "- Left alone: ${kept_workflows[*]}"; fi)

Before merging: read the caller files once; every command in them came from what the repository already ran. A \`domain not allowed: <host>\` line in a job log names a host to add to \`extra-allowed-endpoints\`. Branch protection now requires the checks above.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
}

# ---- main ------------------------------------------------------------------

if ! $dry_run; then
  command -v gh >/dev/null || die "gh is needed"
  resolve_pin
  clone_if_needed
  default_branch=$(gh api "repos/$repo" --jq .default_branch)
else
  [ -n "$pin" ] || pin="v0.0.0"
  [ -n "$sha" ] || sha="0000000000000000000000000000000000000000"
fi

detect
echo "repository:   $repo ($default_branch)"
echo "pin:          $pin @ $sha"
echo "languages:    $($has_python && echo -n "python " || true)$($has_bash && echo -n "bash" || true)"
echo "container:    ${dockerfile:-no}"
echo "package:      $package (pypi: $pypi)"
echo "config lint:  ${config_cmd:-no}"
echo "replaces:     ${old_workflows[*]:-nothing}"
echo "leaves alone: ${kept_workflows[*]:-nothing}"

if $dry_run; then
  write_files
  echo
  echo "wrote:"
  (cd "$out" && find .github -type f | sort)
  echo
  echo "would apply:"
  settings_plan
  exit 0
fi

out=$path
write_files
commit_and_pr
apply_settings

repos_file="$HERE/baseline/repos.txt"
if ! grep -qx "$repo" "$repos_file"; then
  echo "$repo" >>"$repos_file"
  echo "appended $repo to baseline/repos.txt; commit that here"
fi

cat <<EOF

Done. What is left is Doppler, made in the dashboard (README, Doppler setup):
  1. Workplace → Team → Service Accounts → create gha-$name, Viewer on
     the ci project's ci environment and nothing else.
  2. On it, add an OIDC identity: issuer https://token.actions.githubusercontent.com,
     subject repo:$repo:ref:refs/heads/$default_branch (and refs/tags/*),
     audience https://github.com/$owner. Copy the UUID.
  3. scripts/new-repo.sh $repo --path $path --doppler-identity <UUID>
Then: python scripts/audit_baseline.py $repo
EOF
