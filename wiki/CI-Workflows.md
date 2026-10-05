# CI Workflows

One CI workflow per language, all with the same shape and all ending in a
`CI green` gate job. The complete input tables are in the README:
[CI](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#ci),
[Bash CI](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#bash-ci),
[Tofu CI](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#tofu-ci),
[Arduino CI](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#arduino-ci),
[Fuzzing](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#fuzzing-python-code).

**The rule that keeps it one pattern:** every language's CI workflow ends in a job
called `CI green`. Then `ci / CI green` stays the required status check whatever
the language, and the audit keeps asking one question.

## python-ci

`.github/workflows/python-ci.yml`: for Python projects.

| Job | What it does |
|---|---|
| `lint` | ruff (configurable) |
| `typecheck` | Optional: your type checker, only when `typecheck-command` is set |
| `workflow-lint` | actionlint and zizmor over *your* workflow files |
| `test` | Your test command across a matrix of Python versions and runners. **No OIDC token, no write permission.** |
| `distro` | Optional: the tests run inside official images of Debian, Ubuntu, Kali, Parrot, Fedora... |
| `coverage` | Uploads the coverage report to Codecov over OIDC. Separate job, never on a pull request |
| `smoke` | Optional: installs the project and runs a command (e.g. `my-cli --version`) |
| `docker` | Single-arch container build, **then actually run** (`docker-test-command`) before it is trusted |
| `fragment-check`, `commit-claims` | Optional pull-request-only checks (see below) |
| `ci-green` | The gate: needs every other job and fails if any failed |

Ideas worth noticing:

- **Tests and secrets never share a job.** That is why coverage upload is its own job.
  A consequence: coverage appears on Codecov per push to the default branch, not per PR.
- **Operating systems** come in two kinds: GitHub-hosted runners (`runners`:
  Ubuntu, Ubuntu arm64, macOS, Windows) and **other Linux distributions run in
  their official container** (`distros`). The README has a table mapping "I want
  to cover Raspberry Pi OS / Kali / Qubes" to the right image.
- **`coverage-threshold`** fails the test job under a minimum line coverage, read
  from the Cobertura XML.
- **Multiple languages?** Call `python-ci.yml` from a job named `ci:` and
  `bash-ci.yml` from one named `shell:`; require both gates.

## bash-ci

`.github/workflows/bash-ci.yml`: for the shell in a repository, which is nearly
every repository.

- **Scripts are found, not listed:** every tracked file ending `.sh` / `.bash`, or
  whose first line is a `sh`/`bash` shebang, under `paths`.
- **shellcheck and shfmt are downloaded at a pinned version and checked against a
  pinned SHA-256 before they run.** No third-party action joins the allow-list for
  them, and what lints today lints next year.
- Optional: a shell test command (`bats`, a script...), a configuration lint
  (yamllint, ansible-lint), the same `distro` matrix, workflow lint, and the same
  pull-request checks.
- No job holds more than `contents: read`. A lint needs nothing else.

## tofu-ci

`.github/workflows/tofu-ci.yml`: for OpenTofu or Terraform.

- On every PR, **with no cloud credential**: `fmt -check`, `validate` with no
  backend, tflint, and a Trivy configuration scan.
- A **plan** runs only on a push to the default branch, with credentials from the
  [Doppler](Secrets-and-Doppler) config in its environment. This is the one place
  the gate lets a secret exist.
- **Nothing ever applies from CI.**
- OpenTofu and tflint are pinned by version and hash. `binary: terraform` uses the
  runner's own Terraform instead. Several root modules go in `directories`.

## arduino-ci

`.github/workflows/arduino-ci.yml`: for firmware built with arduino-cli.

- arduino-cli is pinned by version and hash. Cores and libraries are named *with
  versions* by the caller, so the build is the same build next year.
- Every sketch is compiled for the board (`fqbn`) and the binaries are kept as an
  artifact. A release signs and attests them through
  [`artifact-release.yml`](Release-Workflows#artifact-release).
- Optional host-side unit tests. No token anywhere.

## python-fuzz

`.github/workflows/python-fuzz.yml`: runs every [Atheris](Concepts-and-Glossary#security-scanning)
fuzz target a repository keeps (default `fuzz/fuzz_*.py`) for a fixed time, fails
on a crash, and uploads the crashing input.

Why it exists: OpenSSF Scorecard's *Fuzzing* check credits a Python repository only
for real Atheris (or OSS-Fuzz, ClusterFuzzLite, OneFuzz) in the tree. This makes
that credit honest. A caller that opts in with no targets **fails**: a missing
directory is a defect, not a skip.

A target must `import atheris`, wrap the imports under test in
`atheris.instrument_imports()`, define `TestOneInput(data: bytes)`, and call
`atheris.Setup` / `atheris.Fuzz()`. It should raise only on a real bug and catch
errors the code under test documents (a parser rejecting bad input). The README has
a complete example and the crash-reproduction command. Add the job to your
`CI green` gate (`needs:`) or run it on a schedule.

## Pull-request checks

`python-ci.yml` and `bash-ci.yml` each take two optional jobs that run on pull
requests only (empty command skips them; both feed the gate when set):

- **`fragment-check-command`** (the `Changelog fragment` job): for repositories that
  keep one changelog *fragment file per change* (`changelog.d/<pr>.<kind>.md`)
  instead of editing `CHANGELOG.md`. Shared-section edits conflict with every other
  PR; a file each does not. Your own script decides what fails.
- **`commit-claims-command`** (the `Commit claims` job): for repositories whose commit
  messages make claims a diff can check ("adds a test", "no functional change").
  Your script compares what each commit says with what it changed.

Both check out full history, hold `contents: read`, and receive `BASE` / `HEAD` as
environment variables. This repository ships neither script; the command *is* the
check.

## Shared habits

Three habits apply to all of them, and tests hold them:

- **`disable-sudo: true`** on every harden-runner step (the only exceptions are jobs
  that run a caller's own install command, which may legitimately say `sudo apt-get`).
- **Downloaded tools are cached *and* still hash-checked** on every run. A cached
  file that fails the hash is thrown away and fetched again.
- **Concurrency belongs to the caller**
  ([why](Design-Rules-and-Why#concurrency-belongs-to-the-caller)).
