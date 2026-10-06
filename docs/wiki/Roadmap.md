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

**Organizations**

- **#89** The audit cannot read organization-owned repositories; proposed: a GitHub App so no personal
  token remains.
- **#95** The collaborators check calls an organization's owner an outsider with write access.
- **#98** Organization-level checks: two-factor requirement, new-repository defaults, Actions policy.

**Scanning**

- **#83** A Semgrep finding suppressed in source still becomes an open code-scanning alert (not settled; see
  [Security scanning explained](Security-scanning-explained.md)).
- **#87** Scorecard: a `pip install` in `security.yml` is not pinned by hash.
- **#82** `python-fuzz` should pass a libFuzzer `-timeout` so a hang leaves a `timeout-*` artifact.
- **#97** A `dast.yml` workflow: OWASP ZAP baseline against a service the caller starts (first caller:
  hammunition-hill).

**Supply chain and baseline**

- **#99** Attach a CycloneDX and an SPDX SBOM to every package and artifact release, signed with the rest.
- **#79** A `SECURITY.md` template in the baseline, for Scorecard's SecurityPolicy check.
- **#96** `new-repo.sh` should ship a gitleaks pre-commit hook beside the commit-claims hook.
- **#74** A caller that pins job permissions to `contents: read` fails at startup with no check; document the
  `id-token` grant where it bites and lint for it.

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
