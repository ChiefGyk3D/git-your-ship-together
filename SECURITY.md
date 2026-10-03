# Security Policy

## Supported Versions

This repository ships reusable GitHub Actions workflows and a handful of
scripts, consumed by other repositories that pin a tag or `main`. There are no
numbered releases; the workflows at the tip of `main` are the supported set.
Callers pinned to an older commit should update to a current one to pick up
fixes.

## Reporting a Vulnerability

Please report security issues **privately**, not in a public issue.

- Preferred: open a
  [GitHub Security Advisory](https://github.com/ChiefGyk3D/git-your-ship-together/security/advisories/new)
  for this repository. This notifies the maintainer directly and keeps the
  report private until a fix is available.
- If you cannot use GitHub Security Advisories, contact the maintainer through
  the profile at [github.com/ChiefGyk3D](https://github.com/ChiefGyk3D).

Please include:

- The affected workflow, action, or script (file and, if applicable, job/step)
- A description of the issue and its potential impact
- Steps to reproduce, or a minimal example if practical

## What to Expect

This is a small, community-maintained project. There is no formal SLA, but
reports are triaged as soon as practical and a fix or mitigation is
prioritized for anything that could affect a calling repository's secrets,
supply chain, or CI environment. Target timelines: an
acknowledgement within 14 days, and public disclosure once a fix is released or
120 days after the report, whichever comes first, coordinated with the reporter.
Credit is given in the fix's changelog entry
or commit message unless you ask not to be named.

## Scope

In scope: the reusable workflows and composite actions under
`.github/workflows/` and `.github/actions/`, and the scripts under `scripts/`
that those workflows call. The `fixture/` project exists only to exercise the
workflows in this repository's own CI and is not itself a supported artifact.
