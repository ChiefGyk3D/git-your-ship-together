# arduino-ci

**What it does.** CI for firmware built with `arduino-cli`: arduino-cli at a pinned version and sha256, cores and libraries
pinned by the caller, every sketch compiled for a board with the binaries kept as an artifact, optional host-side tests,
the workflow lint and the **`CI green`** gate. Holds no token.

**Why it exists.** A firmware repository (the first consumer is an ESP32 sensor node) had no CI that could be trusted to build
next year what it builds today. Naming cores and libraries with versions makes the build the same build later. The binaries
reach a release through [artifact-release](Workflow-artifact-release.md), which signs and attests them, using the same compile as
its build command.

## Jobs and trust boundaries

`compile`, `test` (host-side), `workflow-lint` and `ci-green`, each with `contents: read` and nothing more. arduino-cli verifies
each downloaded package against its index checksum before installing it, and the workflow caches the download staging
directory keyed on the arduino-cli version and a hash of `cores`, `additional-urls` and `libraries`.

## A minimal caller

```yaml
jobs:
  firmware:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/arduino-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      sketches: nodes/esp32/skidfinder_node
      fqbn: esp32:esp32:esp32
      cores: esp32:esp32@3.3.12
      additional-urls: https://espressif.github.io/arduino-esp32/package_esp32_index.json
      egress-policy: block
      extra-allowed-endpoints: espressif.github.io:443 dl.espressif.com:443
```

A core from another index adds its hosts to `extra-allowed-endpoints`; the ESP32 core's hosts were added on the first
block-mode run, which is how a new index announces itself.

<!-- inputs -->

## What it refuses to do

It never holds a token, never flashes hardware, and never compiles against an unversioned core.
