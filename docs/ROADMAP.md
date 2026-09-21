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

2. **A bootstrap for a new repository.** This is the item that answers "start
   a project and go". Today a new project means writing three caller files,
   creating a Doppler service account and an OIDC identity, applying eight
   repository settings, and adding a line to `baseline/repos.txt`. A
   `scripts/new-repo.sh <owner/name> <language>` should do all of it: apply
   every BASELINE setting through the API, write the caller workflows from a
   template for that language, set the identity variable, and append to the
   repo list, leaving `python scripts/audit_baseline.py` to confirm. One
   caveat found today: a token needs the `workflow` scope to write files
   under `.github/workflows` through the API, so the script either asks for
   that scope or commits locally and pushes over SSH.
3. **`container-release.yml`.** The release workflow is already language
   agnostic; only its name says otherwise, which is what stops it being used
   for a Go or Rust daemon without explaining the name every time. Add it
   under the honest name and keep `python-docker-release.yml` as a thin
   caller that forwards to it through a local `./` reference, so existing
   pins keep working until callers move. Verify first that a nested local
   reference resolves at the caller's pinned commit, which is the whole point
   of doing it that way.
4. **`bash-ci.yml`.** There are 46 shell scripts across the nine repositories
   and not one of them is linted by anything today. shellcheck, `shfmt
   --diff`, and bats where a repository has tests, in the same shape as
   `python-ci.yml`: commands as inputs, harden-runner first, a `CI green`
   gate. This is the cheapest real coverage win on the list.
5. **`terraform-ci.yml`.** `fmt -check`, `validate`, tflint, a config scan
   (Trivy or Checkov), and `plan` on a pull request. The Doppler gate already
   refuses to fetch secrets on a pull request, which is exactly the right
   default for a plan: it runs without cloud credentials, and nothing applies
   from a pull request ever.
6. **A dependency audit that is not pip-shaped.** `security.yml`'s one
   Python-specific job should become a command input in the same idiom as the
   CI workflow's, so a Node, Rust or Go repository gets the same job with its
   own tool. Keep the pip-audit defaults so nothing here changes.
7. **Embedded, when there is a board to build for.** An ESP32 or PlatformIO
   workflow builds firmware, runs the host-side unit tests, and publishes the
   binary as an attested artifact, which is the same supply-chain story the
   container release already tells. Worth writing when the first project
   exists, not before: a workflow written for hardware nobody has started is
   a guess, and this repository's whole habit is to measure first.

## Next, one step deeper

8. **Image hardening across the board.** Every image runs an import check;
   add a non-root check like typo-sniper's to all nine, then a read-only root
   filesystem and dropped capabilities in the compose files, and a
   `chainguard/python` or distroless base to shrink what Trivy has to report.
   Then `trivy-exit-code: "1"` once the images are clean.
9. **`disable-sudo: true` in harden-runner** on jobs that never need it, which
   is most of them. One input per job in the shared workflows.
10. **Signed commits and tags.** The laptop signs with its SSH key now
    (`gpg.format ssh`, commits and tags), the key is registered on GitHub as
    a signing key, and v1.2.0 and the commits since verify as valid. What is
    left is the branch rule, which waits until every place that commits is
    signing: the other machines, and the cloud sessions, which commit
    unsigned today. Then BASELINE.md §7 moves it into the required set.
    Next step of the same experiment: move the signing and authentication
    keys onto hardware, YubiKeys and Immurok, with subkeys per device so a
    lost token revokes one key, not the identity.
11. **A weekly audit run in CI.** `audit_baseline.py` on a schedule here, with
    a fine-grained read-only token held in its own Doppler project and
    identity, never the shared `ci` config, so drift in any repository's
    settings is a red job rather than a thing somebody remembers to check.

## Structural

12. **Move the repositories into a GitHub organization.** Org-level rulesets,
    one allowed-actions policy and required workflows turn the baseline into
    one setting instead of ten repositories times six switches, and the audit
    shrinks to confirming the policy applies. Also the only way to get custom
    secret-scanning patterns for the Doppler and Snyk token shapes.
13. **Feed GitHub and Doppler security events into the Wazuh stack.** The
    JumpCloud-to-Wazuh bridge already has the shape: poll code-scanning,
    secret-scanning and Dependabot alerts plus Actions failures per
    repository, and Doppler's activity log, so a quiet Security tab becomes an
    alert in the place already watched.
14. **A mirror of the repositories somewhere self-controlled.** A push mirror
    to a Gitea in the lab or a nightly bundle to the NAS; today the only copies
    outside GitHub are laptop clones.
15. **Mature the risk register.** Today it is a file, a test and an audit
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

16. **Native arm64 image builds.** Today the release workflow builds arm64
    under QEMU, which is slow and means the `docker-test-command` never runs
    on real arm64. An ephemeral runner on an ARM box in the lab (a Pi 5 or an
    ARM server) as a buildx node builds that half natively and runs the image
    check on it. The multi-arch manifest is unchanged; the arm64 layer is
    simply built and tested where it will run.
17. **Ephemeral runners for the heavy scheduled jobs.** The Monday rebuilds,
    Trivy scans and Scorecard runs across nine repositories are pure compute
    on a schedule. actions-runner-controller on the lab's Kubernetes, or a
    `--ephemeral` runner in a throwaway Podman container, takes them off the
    GitHub minutes and off the shared queue. Each job is a fresh runner.
18. **Pull-through caches.** A registry mirror (Zot or Harbor as a proxy cache)
    for `python:*-slim` and the action images, and a PyPI proxy (devpi) for the
    locks. Hash checking still verifies every artifact, so the cache changes
    nothing about trust; it removes egress, makes a rebuild possible with the
    WAN down, and gives one place to see what CI actually downloads.
19. **Consumer-side verification, nightly.** A lab job that does what an
    operator does: pull each published image from GHCR, `cosign verify` it
    against this repository's identity, verify the SBOM attestation, run the
    import check and the healthcheck. The producer already signs; nothing yet
    proves the signatures verify from outside.
20. **The weekly audit and the register's issue-opening** (11, 15) run from a
    lab runner, so the token that reads ten repositories' settings never
    leaves the lab.
21. **Wazuh and the mirror** (13, 14) are lab services by nature; the runners
    above give them a CI-side counterpart, so an event in CI and an event in
    the lab land in the same dashboard.
22. **A staging deploy.** The daemons (Stream-Daemon, Star-Daemon, Boon-Tube,
    penguin-overlord, yomama) publish images that are never started by a
    machine before a human does. A lab runner that starts each new `latest`
    in a staging namespace against test accounts and watches the healthcheck
    for ten minutes is the missing step between "the image built" and "the
    image works".
