# git-your-ship-together

> Reusable workflows. Repeatable builds. Less "what the fuck broke?"

This wiki explains **what** this repository is, **why** it is built the way it
is, and **how** to use it, change it, or learn from it. The repository itself
([README](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md))
is the reference manual: every input of every workflow, every command. The wiki
is the guided tour. It tells you what to read first, what each piece is for,
and what went wrong along the way so you do not repeat it.

## The one-paragraph version

Every project I maintain needs the same things from CI: lint, tests, a container
build, a signed release, security scans, and a way to keep dependencies fresh.
Writing those per repository means ten copies that drift apart, and every fix
has to be made ten times. This repository holds **one copy of each pipeline** as
a [reusable GitHub Actions workflow](Concepts-and-Glossary#reusable-workflow).
Each project calls them with a short YAML file that says only what is specific to
that project. Secrets live in one place ([Doppler](Secrets-and-Doppler)), are
fetched with short-lived identity tokens instead of stored passwords, and are
never handed to code from a pull request.

## Who this is for

| You are... | Start with |
|---|---|
| **Learning CI/CD or supply-chain security** and want a real, working example with the reasoning left in | [Learning Path](Learning-Path), then [Concepts and Glossary](Concepts-and-Glossary) |
| **Using these workflows** in one of my projects or your own | [Calling the Workflows](Calling-the-Workflows), then the [Workflow Catalog](Workflow-Catalog) |
| **Adopting a repository** into the baseline | [Adopting a Repository](Adopting-a-Repository) |
| **Contributing** a change to a workflow | [Contributing and Developing](Contributing-and-Developing) |
| **Debugging a red run** | [Troubleshooting](Troubleshooting) |
| **Just curious why it is built this way** | [Design Rules and Why](Design-Rules-and-Why) |

## What you get from three short YAML files

A project that calls these workflows gets, on every push and pull request:

- **Lint, type check and a test matrix** across Python versions, operating
  systems and Linux distributions ([CI workflows](CI-Workflows)).
- **A container build that is run before it is trusted**, then a multi-arch
  image pushed to GHCR, **signed** with cosign, with an **SBOM** and **SLSA
  provenance** ([Release workflows](Release-Workflows)).
- **Security scans**: CodeQL, gitleaks, dependency audit, dependency review,
  Semgrep, optionally Snyk and OpenSSF Scorecard ([Security workflow](Security-Workflow)).
- **Dependabot bumps that merge themselves** once the gate is green and only up
  to a size you choose ([Automation workflows](Automation-Workflows)).
- **A network allow-list on every job** so a compromised step cannot phone home
  ([Egress Control](Egress-Control)).

And the repository checks itself weekly: an audit confirms every adopted
repository still meets the [baseline](Repository-Baseline).

## Map of the wiki

**Understand it**
- [Learning Path](Learning-Path): a guided reading order with hands-on exercises
- [Concepts and Glossary](Concepts-and-Glossary): OIDC, SHA pinning, SBOM, provenance, and the rest, in plain language
- [Architecture Overview](Architecture-Overview): what a push goes through, and a map of every file
- [Design Rules and Why](Design-Rules-and-Why): the rules, the threat each closes, and the test that enforces it

**Use it**
- [Calling the Workflows](Calling-the-Workflows): the pin, the secrets rule, a complete caller
- [Workflow Catalog](Workflow-Catalog): every workflow at a glance
  - [CI workflows](CI-Workflows), [Release workflows](Release-Workflows), [Security workflow](Security-Workflow), [Automation workflows](Automation-Workflows)
- [Secrets and Doppler](Secrets-and-Doppler): how CI gets credentials without storing them in GitHub
- [Egress Control](Egress-Control): harden-runner, audit mode, block mode
- [Repository Baseline](Repository-Baseline): the settings no YAML can set, and the weekly audit
- [Adopting a Repository](Adopting-a-Repository): `new-repo.sh`, step by step

**Change it**
- [Testing and the Contract](Testing-and-the-Contract): how the tests hold the rules still
- [Contributing and Developing](Contributing-and-Developing): the dev loop, adding a workflow, cutting a release
- [Maintaining This Wiki](Maintaining-This-Wiki): how this wiki stays current

**When things go wrong**
- [Troubleshooting](Troubleshooting): symptom to cause to fix
- [Lessons Learned](Lessons-Learned): the mistakes, kept in on purpose
- [FAQ](FAQ)

## Honest scope

- The workflows that exist today are shaped by the projects that call them
  (mostly Python, plus shell, OpenTofu and Arduino). Most of the *design*
  (baseline, Doppler, pinning, permissions, egress, tests) is language-neutral.
  The [roadmap](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/docs/ROADMAP.md)
  is the list of what is done and what is next.
- This is a small, single-maintainer project. There is no SLA. Security reports
  go through the private channel in
  [SECURITY.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/SECURITY.md).
- Nothing here is a secret. The identifiers, hostnames and tokens that make a
  pipeline run are deliberately absent from this repository and this wiki.

License: MIT.
