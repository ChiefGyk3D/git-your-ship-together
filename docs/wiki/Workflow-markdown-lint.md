# markdown-lint

**What it does.** Runs the standalone rumdl Markdown linter over the files selected by newline-separated globs, then emits at
most 50 GitHub annotations with the file, line, rule id and a short message. It is read-only, holds no secret and is opt-in.

**Why it exists.** Markdown is executable documentation: broken heading structure, malformed lists and other lintable mistakes
make both rendered documentation and assistive navigation worse. A reusable job keeps the linter version, installation and
annotation behavior identical without requiring Node.js or a copied dependency lock in every caller.

## The pinned tool

The workflow downloads rumdl v0.3.2 from its exact GitHub release asset URL with SHA-256
`f527d1374765d826c1627ceab3d1f46e548268731a495b5b12a3af529b3d79e8`. It uses only the shared `fetch_release` helper,
checks the archive again after the helper returns, and extracts the binary under the runner's temporary directory. There is no
floating version and no direct release-asset curl outside the helper.

## Files and configuration

`globs` defaults to `**/*.md`. Each non-empty line is one repository-relative glob; matches are deduplicated and sorted before
they become separate rumdl arguments. Absolute paths, traversal, symbolic links outside the checkout, no patterns, and a set of
patterns that matches no regular file all fail before rumdl runs.

`config` is empty by default. A non-empty value must name a regular file inside the checkout. Empty uses the committed
`.github/rumdl.toml`, copied into the workflow byte for byte:

```toml
[global]
disable = ["MD013", "MD033"]
```

That default is intended to disable line length and allow inline HTML by disabling its rule. This terminal had neither network
access nor a rumdl binary or documentation copy, so the v0.3.2 names `[global].disable`, `MD013` and `MD033` were not verified
against the real release here. The fixture job is the integration check against the downloaded binary.

## Findings and exit behavior

rumdl runs in GitHub output mode. `scripts/run_markdown_lint.py` accepts only annotations with a file, positive line and `MDnnn`
rule id, normalizes their messages to 300 characters, and emits the first 50. The `findings` output counts every finding, including
those omitted from display. `fail-on-findings` defaults to true; false changes finding annotations to warnings and keeps the job
green, but does not excuse invalid input or a rumdl execution/format failure.

## A minimal caller

```yaml
permissions:
  contents: read

jobs:
  markdown:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/markdown-lint.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      globs: |
        README.md
        docs/**/*.md
```

Set `config: .rumdl.toml` to use a repository-owned configuration. Leave `fail-on-findings` at its default in a real gate.

## The fixtures prove it can fail

`ci.yml` runs a short passing document and a planted heading-level jump. The planted call uses `fail-on-findings: false`, and
`markdown-lint-control` fails unless its `findings` output is greater than zero. `tests/test_markdown_lint.py` tests the input and
annotation boundary with a fake executable and no network; it does not claim to run rumdl itself.

<!-- inputs -->

## What it refuses to do

It never installs from a floating version, downloads without a mandatory SHA-256, runs an input through a shell, follows a path
outside the checkout, silently passes with no files, emits more than 50 finding annotations, or writes repository content.
