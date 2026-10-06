# python-docker-release

**What it does.** The old name of [container-release](Workflow-container-release.md). It is a thin caller that forwards every input, the
secret and the outputs to `container-release.yml` through a `./` reference, which GitHub resolves to the same commit as the
workflow that contains it.

**Why it exists.** The release workflow named Python three times (its file name, its display name, and two egress hosts) while
building whatever the Dockerfile builds. Renaming it would have broken every caller's pin. So the old file stayed and forwards;
a caller pinned to it sees no difference.

## Behaviour

- A test holds the two sets of inputs **identical**, so a new input cannot be added to one and forgotten in the other.
- Secrets do not cascade through nested workflows, so the thin caller forwards `DOPPLER_TOKEN` by name. The fixture reaches
  `container-release.yml` through it, so the nested reference is exercised on every pull request here.
- The signing job's OIDC identity names the innermost workflow, so a `--certificate-identity` written out in full says
  `container-release.yml`; the `--certificate-identity-regexp` form matches either.
- **New callers should use `container-release.yml`.** Move at the next pin bump.

A caller looks exactly like the one on the container-release page, with the old file name in `uses:`.

<!-- inputs -->

## What it refuses to do

It adds nothing of its own: no job, no input and no behaviour that the container release does not have.
