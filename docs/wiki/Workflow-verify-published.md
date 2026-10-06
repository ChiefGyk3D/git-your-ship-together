# verify-published

**What it does.** Verifies a published image from the outside, the way an operator would: `cosign verify` for the signature,
`cosign verify-attestation --type spdxjson` for the SBOM, `gh attestation verify` for provenance, then each platform pulled and
your `test-command` run against it. A final `Verified` job is the gate. It stops at the first failure.

**Why it exists.** The producer signs, attaches an SBOM and records provenance, and nothing proved those verify from outside. A
signature nobody checks is a claim. Run it nightly and a release that stops verifying is a red job, not a surprise.

## Jobs and trust boundaries

`verify` has `contents: read` and `packages: read`. **No secret, no Doppler, no `id-token`.** A verifier that needs a credential is
trusting something. A platform that differs from the runner's (arm64 on the x86 runner) runs under QEMU, set up only then.

## A minimal caller

```yaml
on:
  schedule:
    - cron: "17 5 * * *"
  workflow_dispatch:

jobs:
  verify:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/verify-published.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      packages: read
    with:
      image: ghcr.io/OWNER/IMAGE:latest
      test-command: docker run --rm "$IMAGE" --version
```

A digest is stronger than a tag. The default `identity-regexp` matches any workflow in the maintainer's repositories and so
matches an image from [container-release](Workflow-container-release.md); narrow it to one workflow with a pattern like
`^https://github.com/ChiefGyk3D/git-your-ship-together/\.github/workflows/container-release\.yml@refs/tags/v`. **A fork should
change the default**, which names the maintainer. The allow-list was measured in block mode: this repository's `fixture verify`
job refused GitHub's attestation store until its blob host was added.

<!-- inputs -->

## What it refuses to do

It never holds a credential, never passes when verification failed (the `Verified` job fails unless the verification succeeded), and
never changes anything it verifies.
