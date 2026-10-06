# Adopting GYST in your own project

**What this is.** For someone who is not the maintainer: what to copy, what to change, and
what the path looks like without Doppler. Most of the value is the tests; the workflows are
the part you can call.

## Two ways to use it

**Call it.** Your repository holds callers that `uses:` workflows from this repository, pinned
by commit. You get fixes through Dependabot. The workflows' own defaults name the maintainer in a few
places (the default `identity-regexp` of `verify-published`, the OIDC audience), so most callers pass
those inputs. This is the lightest path and the right one if you trust this repository's pins.

**Fork it.** Fork, change the owner everywhere it appears (the OIDC subject and audience, the
`SHARED` repository in `scripts/new-repo.sh`, `baseline/repos.txt`), and call your own fork. You then own
the pin bumps and the tests. Do this if you want to change what a workflow does.

## What to copy, and what to change

Copy the **tests** whichever way you go. They are what turns "we pin our actions" from a habit into
a build failure. Change:

- The owner in OIDC subjects and audiences, and in the allowed-actions list
  `baseline/selected-actions.json` (it ends in `OWNER/*` so the shared workflows resolve).
- The Doppler project and config names, if you use Doppler.
- `baseline/repos.txt`, to your repositories. A repository not on the list is not covered.
- Docker Hub and Snyk inputs, if you do not use them (both are off by default).

Nothing in the repository is a secret; identifiers, hostnames and tokens that make a pipeline run
are deliberately absent.

## Starting from the helper

```sh
scripts/new-repo.sh YOU/YOUR-REPO --dry-run --path ./your-checkout --out /tmp/preview
```

It writes the callers from what your tree contains and prints the repository settings it would
apply. Read both before running it for real. See [Getting started](Getting-started.md).

## The Doppler-free path

You can use every workflow with no Doppler at all. Leave `doppler-project`, `doppler-config` and
`doppler-identity-id` empty. The Doppler step then prints a notice and exports nothing; steps
that need a secret skip or fail naming it.

- **Nothing needs a secret** in `python-ci`, `bash-ci`, `arduino-ci`, `python-fuzz`, `docs-pages`,
  `wiki-publish`, `dependabot-auto-merge`, `verify-published`, `python-package-release` (PyPI
  Trusted Publishing is its own OIDC) or `artifact-release`.
- **Optional extras that do:** Snyk (`SNYK_TOKEN`) and Docker Hub (`DOCKERHUB_*`). Leave them off,
  or use the service-token path below.
- **Path 2, the service token.** On a Doppler plan without OIDC identities, create a read-only
  service token for one config and store it as the one GitHub secret `DOPPLER_TOKEN`; callers
  pass it by name. It is one static credential per repository, which is the thing the OIDC design
  avoids, so accept that trade knowingly.
- **No Doppler at all but a secret you need:** put it in GitHub's encrypted secrets and read it as an
  environment variable in your own step. You lose the audit log and single rotation point; the rest of the
  gates still apply.

Doppler's service-account identities need the Team or Enterprise plan. See
[Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md) for the model.

## Keep the repository settings too

Workflows are half of it. Apply [BASELINE.md](../../BASELINE.md): branch protection requiring the `CI green`
gates, read-only `GITHUB_TOKEN`, the allowed-actions list, secret scanning and push protection, immutable
tags. `new-repo.sh` applies them; `scripts/audit_baseline.py` checks them. See
[The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).

## This wiki's generator

The wiki you are reading is `docs/wiki/*.md` plus `scripts/gen_wiki.py`, which copies the pages, rewrites
links for the flat wiki, and renders each workflow's inputs, secrets and outputs table from its YAML so the
table cannot drift. `.github/workflows/wiki.yml` calls [wiki-publish](Workflow-wiki-publish.md) to push the
result. The pattern is the same one Hammunition uses; copy it for your own docs.

## Licence

MIT. See [`LICENSE`](../../LICENSE).

## What this refuses to do

It does not hide its own assumptions: the maintainer's owner name, plan tier and accounts are in the
defaults and the baseline, and a fork has to change them. It does not promise the allow-lists fit your
build; they were measured against these callers, and yours will log `domain not allowed` lines of its own.
