# Roadmap

**What this is.** What is done, what is open as a measured issue, and what is only an idea,
grouped. The sources are [docs/ROADMAP.md](../ROADMAP.md) (the long-form plan, status of
2026-09-21 plus later notes) and the open issues of 2026-10-05. Where they disagree, the
repository and the issue tracker are right and this page has a bug.

## Done

- Every reusable workflow in the list on the [Home](Home.md) page, each run against `fixture/` from the pull
  request's own ref before any caller pins it.
- The baseline, the weekly audit with its own token and Doppler project, the risk register with
  issue-opening, `scripts/new-repo.sh`.
- Hash-pinned Python dependencies in every calling repository, `block` mode egress with measured
  lists, `v*` tags immutable, Dependabot auto-merge, no GitHub Actions secret left in a calling repository.
- `python-fuzz.yml` (v1.10.0), so OpenSSF Scorecard's Fuzzing check is credited for real Atheris targets.
- hadolint, a non-root check and `trivy-exit-code: "1"` by default in the container release (2026-10-03).
- The gitleaks binary pinned by sha256 in place of the licence-gated action (#90, closed), after the
  Hammunition suite moved into an organization.

## Open, measured issues

Each has a "done when" in its issue.

**Scanning**

- **#83** A Semgrep finding suppressed in source still becomes an open code-scanning alert (not settled; see
  [Security scanning explained](Security-scanning-explained.md)).
- **#87** Scorecard: a `pip install` in `security.yml` is not pinned by hash.
- **#97** A `dast.yml` workflow: OWASP ZAP against a service the caller starts (first caller:
  hammunition-hill). The workflow shipped with the baseline scan and then grew the full (active) and api
  scans, each proved to fail on the fixture; what stays open is the first caller.

**Supply chain and baseline**

- **#99** Attach a CycloneDX and an SPDX SBOM to every package and artifact release, signed with the rest.

## What needs the lab: gaps GitHub-hosted runners cannot close

Everything above runs on GitHub's runners, and most of CI security should: a job that
anyone can reproduce with a fork and no hardware is a job nobody can call special. These
are the gaps that stay open until a self-hosted runner exists, listed so the
[project board](Keeping-a-project-board-current.md) can carry them as issues. The rule from
the long-form roadmap holds for every one: **a self-hosted runner never runs a pull request.**
Ephemeral, segmented, no secret beyond the job's identity, selected only by trusted refs.

| Gap | Why GitHub-hosted cannot do it | What closes it |
|---|---|---|
| **DAST against a deployed environment.** `dast.yml` scans a loopback service the job starts, with no login and no real integrations, because attack traffic at anything else from a shared runner is a liability | A staging deploy needs a network only the lab controls, real credentials for an authenticated ZAP context, and the right to be attacked | A staging namespace in the lab, started from each new image, scanned with a ZAP context file and a user; the staging deploy and the healthcheck below are the same runner |
| **Hardware-in-the-loop for firmware.** `arduino-ci.yml` compiles every sketch and runs host tests; nothing flashes a board | There is no board on a GitHub runner | A runner with the boards on USB, flashing each build and running the on-device tests, on `push` and tags only |
| **Continuous fuzzing with a kept corpus.** `python-fuzz.yml` runs each target for a fixed time from an empty corpus every time | A corpus that grows for weeks needs storage and compute that outlast one job; GitHub's cache is writable from any pull request, so it cannot hold the corpus | A fuzzing runner that keeps the corpus on the NAS and runs the targets nightly, reporting a crash as an issue |
| **A findings aggregator.** Code scanning on a private repository needs GitHub Advanced Security; the ZAP, Trivy, Semgrep and gitleaks SARIF has nowhere to land there, and nothing today reads findings across 23 repositories at once | GitHub's view is per repository and paid for private ones | OWASP DefectDojo (or an equivalent) in the lab taking every SARIF upload, with the dedup and the SLAs per severity in one place |
| **SBOMs that someone reads.** Every release carries a CycloneDX and an SPDX SBOM, signed; nothing watches them after the release for an advisory published later | A new CVE against a shipped dependency is found today only when the next build's audit runs | OWASP Dependency-Track in the lab, fed each release's SBOM, alerting on a new advisory against anything shipped |
| **Runtime egress of the published images.** harden-runner measures what CI reaches; nothing measures what a daemon reaches once it runs | A runner cannot hold an image in a segmented network for an hour and log its connections | The staging deploy's network with egress logging, the product-side counterpart of the `block` allow-lists |
| **Native arm64 builds and tests.** GitHub's hosted arm64 runners now cover the public repositories; a private one still builds arm64 under QEMU | Hosted arm64 is a paid tier for private repositories, and QEMU never runs the image check on real arm64 | An ARM box in the lab as a buildx node, for the private repositories |
| **Scheduled heavy jobs off the shared queue.** The weekly audit, Trivy rebuilds, Scorecard and the 1.5 GB ZAP image pull run on a schedule across every repository | Minutes and queue time, and the audit's token that reads repository settings should not have to leave anywhere | Ephemeral runners for `schedule` jobs; the audit and the register's issue-opening first, since the key that mints their tokens then never leaves the lab |
| **Pull-through caches.** Every job pulls `python:*-slim`, the action images and the ZAP image from the internet | A cache GitHub hosts is writable from a pull request; a mirror is not | Zot or Harbor as a proxy cache and devpi for the locks; hash checking still verifies every artifact |
| **Hardware-backed release signing.** Releases are signed keyless with the job's OIDC identity, which is right for a hosted runner | A hardware key cannot be plugged into a GitHub runner | A signer in the lab for the artifacts that warrant a key a person holds, beside the keyless signature, not instead of it |
| **A SIEM, a mirror.** A quiet Security tab is noticed by nobody; the only copies of the repositories outside GitHub are laptop clones | Both are services, not jobs | Wazuh fed from the code-scanning, secret-scanning and Dependabot APIs and Doppler's activity log; a push mirror to a Gitea in the lab |

Not on the list: Windows and macOS runners (GitHub hosts them), SAST, secrets and dependency
scanning (all done hosted), and anything a pull request must run, which stays hosted by rule.

## Planned, not started

From the long-form roadmap. Treat these as intentions with reasons, not commitments.

- **Image hardening in the callers**: read-only root filesystems, dropped capabilities, a smaller base image.
- **Signed commits and tags as a rule**, once every place that commits signs.
- **Hardware-backed signing keys** with subkeys per device.
- **Feed GitHub and Doppler security events into a SIEM**, so a quiet Security tab becomes an alert somewhere
  already watched.
- **A mirror of the repositories** somewhere self-controlled.
- **Mature the risk register**: a generated page, and the same shape for other accepted risks (an unpinned
  base image, a tool kept advisory).
- **Lab-hosted runners** for heavy scheduled jobs and native arm64 builds, under one rule: a self-hosted runner
  never runs a pull request. Ephemeral, segmented, no secret beyond the job's identity, selected only by trusted
  refs.
- **Pull-through caches** for images and packages (hash checking still verifies every artifact).
- **A staging deploy** that starts each new image and watches its healthcheck, to close the gap between "the image
  built" and "the image works".
- **More languages** behind the same `CI green` gate, so branch protection stays one rule per language.

## Decided against, for now

Moving the repositories into an organization as a way to get org-level rulesets was decided against in 2026-10-03
while the maintainer's own projects stayed under the personal account. The Hammunition suite has since moved
(2026-10-05), which is where the organization issues above came from; the audit remains the enforcement across
both.
