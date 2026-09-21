# Roadmap: what is left, and what the lab could carry

The pipelines, the Doppler design and the baseline are in place; this page is
the list of what would make them better, kept in one place so that nothing
depends on somebody remembering it. Each item says what it is, why, and where
it stands. Move an item to *done* with the pull request that did it; add a new
one with the same three parts.

Status as of 2026-09-21.

## Done

| Item | Where |
|---|---|
| Fixture project: `python-ci.yml` and `python-docker-release.yml` run against a real project from the pull request's own ref, so a change is exercised here before a caller pins it | `fixture/`, `.github/workflows/ci.yml` |
| Hash-pinned Python dependencies in every calling repository: `requirements.in` is the source, `requirements.txt` a universal lock with every hash, installed under `--require-hashes` in CI and the images | one pull request per repository |
| Risk register: an advisory a pipeline ignores is entered with a reason, an owner and an expiry, and the audit fails on one that is not | `baseline/risk-register.yaml`, `risk-exceptions` check |
| Required approval count zero on every repository | `BASELINE.md` §2 |
| Actions settings on every repository (read-only token, all-contributor approval, the actions allow-list) and the audit at zero FAIL, zero UNKNOWN | `BASELINE.md` §5, `baseline/selected-actions.json` |
| harden-runner `block` mode on CI, release and security in every caller, with the measured lists as the workflows' defaults | v1.3.1, `README.md` Egress |
| Snyk and Docker Hub tokens in the shared `ci` config; no GitHub Actions secret left in any repository | `scripts/doppler-ci-set.sh` |
| `v*` tags immutable in all ten repositories: a ruleset forbids deleting, moving and force-pushing them | `BASELINE.md` §2, `tag-ruleset` check |
| Dependabot patch and minor bumps merge themselves once the gate is green | `dependabot-auto-merge.yml`, `auto-merge-enabled` check |
| GitHub Releases with notes for every tag of this repository | the Releases page |
| Scan and test tools out of Boon-Tube-Daemon's runtime requirements, which took nltk out of the image and closed the only risk-register entry | `Boon-Tube-Daemon` deps PR, register now empty |

## Next, cheap

1. **Revoke the tokens the old GitHub secrets held.** The Docker Hub and
   Snyk credentials now in the shared `ci` config were minted fresh, so
   nothing needs rotating. What is unfinished is the other end: deleting a
   GitHub secret does not revoke the token that was in it, so any earlier
   Docker Hub and Snyk token still works for anyone who kept a copy. Revoke
   them at the provider, which leaves exactly one live token per provider and
   makes Doppler's log the whole history of who fetched it.

## Beyond Python: one pattern for every kind of project

Most of this repository already has nothing to do with Python. BASELINE.md,
`scripts/audit_baseline.py`, the Doppler action, `dependabot-auto-merge.yml`,
and the pinning, permission and egress rules with their tests never mention a
language. `python-docker-release.yml` names Python three times: its own file
name, its display name, and two hosts in its egress default that matter only
while a Dockerfile is installing Python packages; it builds whatever the
Dockerfile builds. `security.yml` runs six jobs and exactly one of them,
pip-audit, is Python. What is genuinely Python-shaped is `python-ci.yml` and
the fixture.

So this is not a rewrite. It is a rename, one input, a sibling CI workflow per
language, and a way to start a repository without doing any of it by hand.

The rule that keeps it one pattern rather than several: **every language's CI
workflow ends in a gate job called `CI green`.** Then `ci / CI green` stays
the single required status check in every repository whatever it is written
in, BASELINE.md needs no per-language branch, and the audit keeps asking one
question.

### What was measured before writing any of it (2026-09-21)

The plan above was written from this repository. Before starting on it the
other repositories on the account were read, and the plan changed in five
places.

- **Every real repository is more than one language.** mother-ticker is
  Python, shell and Ansible; Hammunition is Python and shell; Skid-Finder is
  shell, Python and C++; penguin-overlord alone carries 11 shell scripts. "One
  CI workflow per language" therefore needs a rule for a repository that calls
  two, and the audit has to enforce it: today it passes as long as
  `ci / CI green` is among the required checks, so a second gate could be left
  unrequired and nothing would notice. That rule is item 2 and comes first.
- **The demand is adoption, not creation.** No new repository is waiting.
  Nine existing ones run hand-written CI: mother-ticker, hypeman, Hammunition,
  hammunition-hill, the-great-infocon-recovery, Skid-Finder,
  pfsense-siem-stack, siem-docker-stack and Patch-Gremlin, plus
  dell-battery-balance with no CI at all. Two of them pin actions to a moving
  tag. So the bootstrap (item 6) reads what a repository already runs and
  writes the caller files from it; a blank-repository mode is the degenerate
  case.
- **The most duplicated code on the account is a Python package release.**
  typo-sniper, hypeman, hammunition-hill and mother-ticker each hand-roll
  build sdist and wheel, `twine check`, a tag-against-version check and PyPI
  Trusted Publishing. That is item 5, and it pays off before the
  container-release rename, which has no non-Python consumer yet.
- **Item 9's board exists.** Skid-Finder's ESP32 sketch compiles under
  arduino-cli with ESP32 core 3.3.12 as of 2026-09-18. And it is one of three
  file artifacts already built by hand: hammunition-hill produces a `.deb`,
  mother-ticker an offline bundle. One signed-artifact release covers all of
  them (item 8).
- **Item 7's Terraform plan cannot run on a pull request.** typo-sniper's
  modules use the AWS provider and an `aws_region` data source, so `plan`
  needs credentials even with no state. The project also uses OpenTofu.
  The item is rewritten to match.

Two facts the items below rely on: the active `gh` token has `repo`,
`read:org`, `admin:public_key` and `gist` and not `workflow`, so a script
that writes `.github/workflows` commits locally and pushes over SSH, which
is already the configured protocol; and GitHub's documentation on nested
reusable workflows says a `./` reference resolves to the same commit as the
workflow that contains it, nesting is allowed ten deep, and secrets are
passed only one level at a time.

### Costs every new workflow carries

Each item below that adds a workflow also has to pay these, and the plan for
each should say how.

- **A measured egress list.** shellcheck is preinstalled on the runner;
  shfmt, bats, tflint, tofu, Trivy and arduino-cli are all downloaded. A new
  workflow ships with `egress-policy: audit` as its default, runs against its
  fixture, and gets `block` with the measured list as the default in the
  release after, the same way the Python ones did.
- **Actions allow-list entries.** Any new action goes into
  `baseline/selected-actions.json` and is applied to every repository before
  a caller can use it, or the caller's run fails at workflow start.
- **A fixture and the tests.** `tests/test_workflows.py` asserts the exact
  number of callable workflows, tests the `CI green` gate for `python-ci.yml`
  only, and requires every callable workflow to be run from `ci.yml` against
  a fixture. Each new workflow adds a fixture directory: shell scripts for
  bash-ci, a module on a local-only provider for tofu-ci so `plan` runs
  without credentials, the sketch for embedded.
- **Language-neutral `security.yml` defaults.** CodeQL defaults to `python`
  and pip-audit to `requirements.txt`; a shell repository has to override
  both or the jobs fail. Item 4 fixes the defaults at the same time as the
  audit input.

### The items

2. **The composition rule, and the audit that enforces it.** A repository
   calls one shared CI workflow per language it contains, one caller job
   each: `ci:` for the primary language, then `shell:`, `tofu:`, and so on.
   Every one of those jobs reports a `<job> / CI green` check, and every one
   is required. `audit_baseline.py` derives the expected set from the
   caller's `.github/workflows/ci.yml`, every job whose `uses:` names this
   repository, and fails on any of them missing from branch protection. The
   alternative, a `shell-lint` switch inside `python-ci.yml`, is quicker for
   the nine callers and does nothing for the shell-first repositories, so it
   is not taken.
3. **`bash-ci.yml`.** There are 47 shell scripts across the nine calling
   repositories and not one of them is linted by anything today; actionlint
   only reads the `run:` blocks inside workflow files. shellcheck, `shfmt
   --diff`, and a `test-command` input in the same shape as `python-ci.yml`:
   commands as inputs, harden-runner first, a `CI green` gate. No repository
   uses bats; Skid-Finder has twenty `tests/test-*.sh` with its own runner,
   which is what the input is for. Severity is an input defaulting to
   `warning`, which is what Skid-Finder and Patch-Gremlin run, with a
   `continue-on-error` migration input for the two repositories that run at
   `error` today, the way pip-audit was introduced. The workflow fetches
   nothing from Doppler and holds no token: it belongs with
   `dependabot-auto-merge.yml` in the tests, not with the three that fetch.
4. **A dependency audit that is not pip-shaped, and neutral defaults.**
   `security.yml`'s one Python-specific job becomes a command input in the
   same idiom as the CI workflow's, so a Node, Rust or Go repository gets the
   same job with its own tool, and a shell repository turns it off with an
   empty string. The pip-audit defaults stay so nothing changes for the nine.
   At the same time `codeql-languages` gains `actions`, which scans the
   workflow files themselves and applies to every repository whatever it is
   written in.
5. **`python-package-release.yml`.** Build sdist and wheel, `twine check`,
   refuse a tag that disagrees with the packaged version, install the wheel
   and run a caller's smoke command, publish to PyPI through Trusted
   Publishing with PEP 740 attestations, and attach the distribution to the
   GitHub release. Four repositories carry a copy of this by hand today.
6. **A bootstrap that adopts a repository.** `scripts/new-repo.sh
   <owner/name> [language...]` reads the repository as it is: which
   languages it holds, what its existing workflows run, whether it has a
   Dockerfile. It writes the caller workflows and `dependabot.yml` from
   templates for those languages, carrying the commands it found, commits
   them on a branch and pushes over SSH, applies every BASELINE setting
   through the API, and appends to `baseline/repos.txt`, leaving `python
   scripts/audit_baseline.py` to confirm. The Doppler service account and
   identity are created in the dashboard, so the script prints those two
   steps and waits for the UUID; automating them would need a workplace-admin
   Doppler token, which the script should not hold by default. mother-ticker
   is the first repository it adopts, because it exercises three languages
   at once. A blank repository is the same script with nothing to read.
7. **`container-release.yml`.** The release workflow is already language
   agnostic; only its name says otherwise, which is what stops it being used
   for a Go or Rust daemon without explaining the name every time. Add it
   under the honest name and keep `python-docker-release.yml` as a thin
   caller that forwards to it through a local `./` reference, so existing
   pins keep working until callers move. The fixture cannot verify this: its
   own call is local, so it never exercises a `./` reference inside a
   workflow that another repository called at a pinned commit. Verification
   is a branch in one caller pinned to the pull request's SHA, and the thin
   caller has to forward `DOPPLER_TOKEN` explicitly, because secrets do not
   cascade.
8. **`artifact-release.yml`.** For anything that is a file rather than an
   image: a `.deb`, a firmware binary, a bundle, a wheel. Build it with a
   caller's command, sign the blob with cosign, record build provenance,
   and attach it with its checksums and signature to the release. This is
   the same supply-chain story the container release tells, for the three
   repositories that already ship a file by hand.
9. **`tofu-ci.yml`.** On a pull request: `fmt -check`, `validate`, tflint and
   a config scan (Trivy), which is everything that runs without a cloud
   credential. `plan` runs on push to the default branch with a read-only
   role fetched through the Doppler gate, which is the one place the gate
   already allows a secret. Nothing applies from CI at all. The binary is
   OpenTofu, because that is what typo-sniper's examples use; a `binary`
   input allows Terraform for anyone who needs it.
10. **Embedded.** An arduino-cli compile of the sketch, the host-side unit
    tests, and the binary through `artifact-release.yml`. Skid-Finder's
    `nodes/esp32` sketch is the first consumer. PlatformIO is an input away
    when a project uses it.
11. **Ansible and YAML.** mother-ticker runs ansible-lint and yamllint. They
    are a job each in `bash-ci.yml` behind an input, because a repository
    with a playbook has scripts beside it every time, and one caller job is
    simpler than three for a repository that is mostly shell.

The order is the order above: the rule and the audit first because every
later item depends on it, then the workflow with the most consumers, then
the one that retires the most copied code.

## Next, one step deeper

12. **Image hardening across the board.** Every image runs an import check;
   add a non-root check like typo-sniper's to all nine, then a read-only root
   filesystem and dropped capabilities in the compose files, and a
   `chainguard/python` or distroless base to shrink what Trivy has to report.
   Then `trivy-exit-code: "1"` once the images are clean.
13. **`disable-sudo: true` in harden-runner** on jobs that never need it, which
   is most of them. One input per job in the shared workflows.
14. **Signed commits and tags.** The laptop signs with its SSH key now
    (`gpg.format ssh`, commits and tags), the key is registered on GitHub as
    a signing key, and v1.2.0 and the commits since verify as valid. What is
    left is the branch rule, which waits until every place that commits is
    signing: the other machines, and the cloud sessions, which commit
    unsigned today. Then BASELINE.md §7 moves it into the required set.
    Next step of the same experiment: move the signing and authentication
    keys onto hardware, YubiKeys and Immurok, with subkeys per device so a
    lost token revokes one key, not the identity.
15. **A weekly audit run in CI.** `audit_baseline.py` on a schedule here, with
    a fine-grained read-only token held in its own Doppler project and
    identity, never the shared `ci` config, so drift in any repository's
    settings is a red job rather than a thing somebody remembers to check.

## Structural

16. **Move the repositories into a GitHub organization.** Org-level rulesets,
    one allowed-actions policy and required workflows turn the baseline into
    one setting instead of ten repositories times six switches, and the audit
    shrinks to confirming the policy applies. Also the only way to get custom
    secret-scanning patterns for the Doppler and Snyk token shapes.
17. **Feed GitHub and Doppler security events into the Wazuh stack.** The
    JumpCloud-to-Wazuh bridge already has the shape: poll code-scanning,
    secret-scanning and Dependabot alerts plus Actions failures per
    repository, and Doppler's activity log, so a quiet Security tab becomes an
    alert in the place already watched.
18. **A mirror of the repositories somewhere self-controlled.** A push mirror
    to a Gitea in the lab or a nightly bundle to the NAS; today the only copies
    outside GitHub are laptop clones.
19. **Mature the risk register.** Today it is a file, a test and an audit
    check. Next: an expiring entry opens an issue in the repository it names
    (the weekly audit run above can do that), a page generated from the file
    so the current exceptions are readable without opening YAML, and the same
    shape for the other classes of accepted risk (an unpinned base image, a
    tool kept advisory) so that "we decided to live with this" is always a
    register entry and never a comment in a workflow file.

## What the lab could carry

The lab has compute to spare beyond what is planned for it, and CI is where
that pays. The rule that governs all of it: **a self-hosted runner never runs
a pull request.** GitHub's own guidance is that self-hosted runners on public
repositories are unsafe, because a fork's pull request runs the fork's code on
the runner. So every lab runner is ephemeral (one job, then the VM or
container is destroyed), sits in its own network segment with no route to the
rest of the lab, holds no secret beyond the job's OIDC identity, and is
selected only by jobs that run on `push` to the default branch, on a tag or on
a schedule. `pull_request` jobs stay on GitHub-hosted runners. That is the
same trusted-refs rule the Doppler gate already enforces, applied to compute.

20. **Native arm64 image builds.** Today the release workflow builds arm64
    under QEMU, which is slow and means the `docker-test-command` never runs
    on real arm64. An ephemeral runner on an ARM box in the lab (a Pi 5 or an
    ARM server) as a buildx node builds that half natively and runs the image
    check on it. The multi-arch manifest is unchanged; the arm64 layer is
    simply built and tested where it will run.
21. **Ephemeral runners for the heavy scheduled jobs.** The Monday rebuilds,
    Trivy scans and Scorecard runs across nine repositories are pure compute
    on a schedule. actions-runner-controller on the lab's Kubernetes, or a
    `--ephemeral` runner in a throwaway Podman container, takes them off the
    GitHub minutes and off the shared queue. Each job is a fresh runner.
22. **Pull-through caches.** A registry mirror (Zot or Harbor as a proxy cache)
    for `python:*-slim` and the action images, and a PyPI proxy (devpi) for the
    locks. Hash checking still verifies every artifact, so the cache changes
    nothing about trust; it removes egress, makes a rebuild possible with the
    WAN down, and gives one place to see what CI actually downloads.
23. **Consumer-side verification, nightly.** A lab job that does what an
    operator does: pull each published image from GHCR, `cosign verify` it
    against this repository's identity, verify the SBOM attestation, run the
    import check and the healthcheck. The producer already signs; nothing yet
    proves the signatures verify from outside.
24. **The weekly audit and the register's issue-opening** (15, 19) run from a
    lab runner, so the token that reads ten repositories' settings never
    leaves the lab.
25. **Wazuh and the mirror** (17, 18) are lab services by nature; the runners
    above give them a CI-side counterpart, so an event in CI and an event in
    the lab land in the same dashboard.
26. **A staging deploy.** The daemons (Stream-Daemon, Star-Daemon, Boon-Tube,
    penguin-overlord, yomama) publish images that are never started by a
    machine before a human does. A lab runner that starts each new `latest`
    in a staging namespace against test accounts and watches the healthcheck
    for ten minutes is the missing step between "the image built" and "the
    image works".
