# tofu-ci

**What it does.** CI for infrastructure as code (OpenTofu or Terraform): `fmt -check`, `validate` with no backend, tflint and a
Trivy configuration scan on every push and pull request, none of which needs a cloud credential; a **plan** on the default
branch only, with credentials through the Doppler gate; the same **`CI green`** gate. **Nothing applies, ever.**

**Why it exists.** A repository with Terraform wants the checks that need no credential on every pull request and the one that
needs a credential on a trusted ref only. The first consumer's modules use the AWS provider and an `aws_region` data source,
so `plan` cannot run on a pull request even with no state; that measurement rewrote the roadmap item from "plan on pull
requests" to this shape.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `fmt`, `validate`, `tflint`, `trivy`, `workflow-lint` | `contents: read` | No credential. OpenTofu and tflint are downloaded at a pinned version and sha256 |
| `plan` | `contents: read`, `id-token: write` | Runs only on a push to the default branch, a tag or a schedule; fetches the Doppler config's secrets into the environment and runs `plan-command`. The one place in this workflow a secret exists |
| `ci-green` | none | Needs all of the above |

## A minimal caller

```yaml
jobs:
  tofu:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/tofu-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write   # the plan job's Doppler fetch, off pull requests only
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional fallback; unset means OIDC only
    with:
      directories: infra/terraform/examples/ecs-fargate
      plan-command: |
        cd infra/terraform/examples/ecs-fargate
        tofu init -input=false && tofu plan -input=false
      egress-policy: block
      extra-allowed-endpoints: registry.terraform.io:443 sts.amazonaws.com:443
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

`binary: terraform` uses the Terraform the runner image ships instead of downloading OpenTofu. A provider registry or a
cloud API your plan reaches goes in `extra-allowed-endpoints`. A plan that needs a credential means the Doppler `ci`
config (or your own) holds a read-only role for it; the maintainer's first consumer still needed that role in Doppler
before `plan-command` was set.

<!-- inputs -->

## What it refuses to do

It never applies, never plans on a pull request, and never lets a pull request's code run beside the plan's credentials.
