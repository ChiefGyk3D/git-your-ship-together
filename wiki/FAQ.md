# FAQ

## What is this, in one sentence?
A set of shared GitHub Actions workflows (CI, releases, security scans, auto-merge...) plus the baseline, audit and tests that keep every
repository using them consistent and hardened. See [Home](Home).

## Is it only for Python?
No. The Python workflows exist because the first projects were Python, but there are also shell, OpenTofu, Arduino and generic file/image
release workflows, and most of the design (baseline, Doppler, pinning, permissions, egress, tests) is language-neutral. See
[Workflow Catalog](Workflow-Catalog).

## Can I use these workflows in my own repository?
Yes, it is MIT licensed. Call them with a pinned SHA ([Calling the Workflows](Calling-the-Workflows)). If you want the whole pattern
(your own baseline, your own Doppler), fork it and change the owner, project names and allow-list ([Adopting a Repository](Adopting-a-Repository)).
Be aware the defaults reflect these projects' choices, e.g. the Doppler project is named `ci`.

## Do I need Doppler?
Not to try it: with no Doppler configured the pipelines still run and steps needing a secret skip (or fail naming the missing one). For real
use it is the design's secret store ([Secrets and Doppler](Secrets-and-Doppler)). OIDC identities need Doppler's Team plan; on the Developer plan
use the Service Token path and accept one static secret per repository.

## Why pin to a SHA instead of `@v1`?
Because a tag can be moved after you reviewed it. A SHA cannot. The version rides in a comment, and Dependabot moves both
([Design Rules and Why](Design-Rules-and-Why)).

## Why not `@main`?
A push here would silently change every caller's pipeline: no pin, no review, no Dependabot PR.

## Why are the Doppler steps copy-pasted into each workflow?
A reusable workflow cannot reference the commit it was loaded from, so referencing the composite action would mean `@main`. The copies are
inlined and a test holds them identical to the action ([Design Rules and Why](Design-Rules-and-Why#the-workflows-never-reference-this-repository-by-branch)).

## Why is the required approval count zero?
On a single-maintainer repository a count of one can never be satisfied (you cannot approve your own PR), so it only teaches overriding as
admin. Zero keeps the PR and the green check required ([Repository Baseline](Repository-Baseline)).

## Why does Snyk only run weekly?
The free plan meters tests per month across the account, and per-push scans in ten repositories burned a month's quota in a day.
`snyk-on: push` restores it ([Security Workflow](Security-Workflow)).

## Why can't a pull request get my secrets?
That is the point. A pull request's code could be anything. Secrets are fetched only on the default branch, a tag, or a schedule, and a fork never
gets an OIDC token at all ([Secrets and Doppler](Secrets-and-Doppler)).

## What is `CI green`?
A gate job that needs every other job in a workflow. Branch protection requires only it, so a job added later is covered automatically
([Concepts and Glossary](Concepts-and-Glossary#ci-green)).

## How do I add a new repository?
`scripts/new-repo.sh OWNER/NAME` ([Adopting a Repository](Adopting-a-Repository)).

## How do I know the repositories still meet the baseline?
The weekly audit ([Repository Baseline](Repository-Baseline#the-weekly-audit)) reports PASS, FAIL or UNKNOWN per check and goes red on any FAIL or UNKNOWN.

## How do I report a security problem?
Privately, through the advisory link in
[SECURITY.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/SECURITY.md). Not a public issue.

## Can I edit this wiki directly?
No: it is regenerated from `wiki/` in the repository and a web edit is overwritten. Open a pull request
([Maintaining This Wiki](Maintaining-This-Wiki)).

## Where do I start if I'm learning?
[Learning Path](Learning-Path).
