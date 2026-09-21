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
| Required approval count zero (documented; the setting is applied per repository with the command in BASELINE.md §2) | `BASELINE.md` |

## Next, cheap

1. **Take the scan tools out of the runtime requirements** where they sit
   there (Boon-Tube-Daemon lists `safety`, `bandit`, `ruff` and `pytest` in
   `requirements.txt`, so the image carries them). A `requirements-dev.in`
   like penguin-overlord's keeps them local and closes the nltk exception in
   the register by removing the package from the image.
2. **Rotate the credentials that used to live in GitHub secrets.** Moving a
   token into Doppler does not change the token. Revoke the Docker Hub and
   Snyk tokens at the provider and reissue them into the shared `ci` config
   once; Doppler's log is then the whole history of who fetched them.
3. **Protect the `v*` tags in this repository.** A ruleset that forbids
   updating or deleting tags matching `v*`. Callers pin SHAs, but Dependabot
   follows tags, and a moved tag is the one way a pin comment and its SHA can
   silently disagree. GitHub's immutable releases setting does the same for
   release assets.
4. **Auto-merge Dependabot patch and minor bumps.** With the gate required and
   reviews at zero, `gh pr merge --auto` on Dependabot pull requests lets the
   seven-day cooldown plus a green run do the merging.
5. **GitHub Releases with notes for each tag here.** Dependabot's bump pull
   requests then show the changelog inline, which is what makes a pin bump
   reviewable in ten seconds.
6. **Actions settings and the audit to zero** (BASELINE.md §5): the two
   `gh api` calls per repository, then `python scripts/audit_baseline.py`
   exits 0 with no UNKNOWN.

## Next, one step deeper

7. **Image hardening across the board.** Every image runs an import check;
   add a non-root check like typo-sniper's to all nine, then a read-only root
   filesystem and dropped capabilities in the compose files, and a
   `chainguard/python` or distroless base to shrink what Trivy has to report.
   Then `trivy-exit-code: "1"` once the images are clean.
8. **`disable-sudo: true` in harden-runner** on jobs that never need it, which
   is most of them. One input per job in the shared workflows.
9. **harden-runner `block` mode for `security.yml`** once the Snyk hosts are
   measured (one audit-mode run with the token in).
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
