# Learning path

You can read this repository as a course in building a hardened CI/CD setup.
Each stage below says what to read, what you should understand afterwards, and
an exercise that makes it stick. Nothing needs an account beyond a free GitHub
one unless noted.

> **Tip:** the repository was written to be read. Comments in the workflow files
> say *why* a line exists, and [Lessons learned](Lessons-learned.md) keeps the
> mistakes in.

## Stage 0: the problem (15 minutes)

**Read:** [Home](Home.md) and the opening of
[docs/DESIGN.md](../../docs/DESIGN.md).

**You should be able to say:** why ten copies of a pipeline drift, why GitHub's
encrypted secrets are hard to audit (they are write-only), and what "a secret
leaving a CI job" means.

**Exercise:** open the Actions tab of any project that calls these workflows
(for example [typo-sniper](https://github.com/ChiefGyk3D/typo-sniper/tree/main/.github/workflows)).
Count how many lines the caller workflows have. Then open
`python-ci.yml` here and count its lines. That ratio is the point of the repository.

## Stage 1: reusable workflows (1 hour)

**Read:** [Glossary](Glossary.md) (reusable workflow,
caller, `workflow_call`), then [Getting started](Getting-started.md).

**You should be able to say:** how a caller passes inputs and secrets, why
secrets are passed by name and never with `secrets: inherit`, and why a caller
pins a commit SHA instead of `@main`.

**Exercise:** in a scratch repository, write a caller for
`bash-ci.yml` (it needs no secrets and no Docker). Pin it to a real commit:

```sh
git ls-remote --tags https://github.com/ChiefGyk3D/git-your-ship-together 'refs/tags/v*'
```

Take the line ending in `^{}` for the tag you want, because that is the
*commit*; the line without it is the tag object. Push, and watch the run.

## Stage 2: threat modelling a pipeline (2 hours)

**Read:** [Design rules](Design-rules.md), then
[Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md).

**You should be able to say:** the three ways a job leaks a secret, which
design rule closes each, and why the job that runs your tests holds no identity
token.

**Exercise:** pick any three rules from the page. For each, write down the
attack it prevents *as a story* (who does what, what they get). Then find the
test that enforces it in
[`tests/test_workflows.py`](../../tests/test_workflows.py)
and break the rule on a branch (remove a `persist-credentials: false`, say).
Run `pytest` and read the failure message. Revert.

## Stage 3: the supply chain of what you ship (2 hours)

**Read:** [Releases and supply chain](Releases-and-supply-chain.md) and the glossary entries for
*cosign*, *SBOM*, *SLSA provenance* and *attestation*.

**You should be able to say:** what a keyless signature proves, what an SBOM is
for, and why verifying from *outside* the producer (`verify-published.yml`)
matters.

**Exercise:** verify a published image the way a consumer would. These
commands are in the README under "Container release":

```sh
cosign verify ghcr.io/chiefgyk3d/typo-sniper:latest \
  --certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/chiefgyk3d/typo-sniper:latest --owner ChiefGyk3D
```

Read the certificate that comes back. Which workflow does it name? Why is it
this repository's workflow and not the calling project's?

## Stage 4: network egress (1 hour)

**Read:** [Egress control](Egress-control.md).

**You should be able to say:** the difference between `audit` and `block`, why
the allow-list is one space-separated line, and how a new dependency announces
itself.

**Exercise:** call a workflow with `egress-policy: audit`, open the run's
summary, and read the list of hosts the job talked to. Switch to `block`, then add
a `curl https://example.com` step and watch it fail with
`domain not allowed`.

## Stage 5: settings no YAML can set (1 hour)

**Read:** [The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).

**You should be able to say:** why a required review count of zero is *more*
secure on a one-person repository than one, what the Actions allow-list adds on
top of SHA pins, and why an audit that cannot check something reports UNKNOWN
instead of PASS.

**Exercise:** run the audit against a repository you own:

```sh
python scripts/audit_baseline.py owner/repo
```

Fix one FAIL using the `gh api` command from BASELINE.md, and run it again.

## Stage 6: tests as a contract (2 hours)

**Read:** [Testing and the contract](Testing-and-the-contract.md).

**You should be able to say:** why structural tests (does the YAML have the
right shape) and dogfooding (run the workflow against a real project) are both
needed, and how a rule becomes a build failure.

**Exercise:** add a new rule. For example, "every reusable workflow has a
`name:` starting with a capital letter". Write the test in `tests/`, watch it
pass or fail honestly, and read how the existing tests are parametrised over the
`REUSABLE` list.

## Stage 7: ship a change (half a day)

**Read:** [Contributing and developing](Contributing-and-developing.md).

**Exercise:** make a small improvement (a docs fix is a fine start), run the
checks locally, open a pull request, and read what the `CI green` gate on this
repository's own pipeline does with it.

## Where to go next

- Build the same pattern for your own repositories: see
  [Adopting GYST in your own project](Adopting-GYST-in-your-own-project.md) and the "Using this for your
  own repositories" section of
  [docs/DESIGN.md](../../docs/DESIGN.md).
- Read the [roadmap](../../docs/ROADMAP.md)
  for what is unfinished; some of it is a good first contribution.
- Look at the other projects that call these workflows; the list is
  [`baseline/repos.txt`](../../baseline/repos.txt).
