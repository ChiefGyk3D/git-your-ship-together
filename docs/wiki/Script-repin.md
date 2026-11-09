# repin

**What it does.** Moves a repository's pins of this repository's reusable workflows to a release. A caller pins
`uses: ChiefGyk3D/git-your-ship-together/.github/workflows/<name>.yml@<40-hex sha> # vX.Y.Z`; a release reaches it only when it
re-pins. `scripts/repin.sh` rewrites the SHA and the version comment, in every workflow and composite action of the repository,
and can open the pull request. It never merges. It is a script; the scheduled form is the reusable workflow [repin](Workflow-repin.md), which runs it.

**Why it exists.** A re-pin is mechanical, the maintainer's rule is that a GYST release moves every caller, and doing it by hand
cost five pull requests in eight days on one repository (issue #310).

## Use

```bash
scripts/repin.sh status ~/src/widgets ~/src/gadgets     # pinned against latest, with ages; exit 10 when a pin is behind
scripts/repin.sh apply --dry-run ~/src/widgets          # print the diff, write nothing
scripts/repin.sh apply ~/src/widgets                    # rewrite in place (the latest release; --to vX.Y.Z picks another)
scripts/repin.sh apply --also-update-literals ~/src/widgets   # and the exact copies of the old SHA outside the workflows (exit 11 without the flag when any remain)
scripts/repin.sh pr ~/src/widgets                       # branch repin/gyst-<tag>, commit, push, open the pull request
scripts/repin.sh pr --watch ~/src/widgets               # and wait for CI on that commit (wait-ci.sh, never --merge)
```

`status` prints, per repository, the latest release with its date and age, then each pinned version with its date, age, and
`BEHIND` or `current`. A comment that names a tag whose commit is not the pinned SHA is flagged `MISMATCH`. It needs `gh` (read
access to this public repository is enough) and GNU `date` and `sed`.

## The rules

- **Pin-only.** The SHA and the `# vX.Y.Z` comment of a `uses:` line are the only bytes that change. Before a file is written
  the old and new text are compared with both fields blanked; any other difference stops the run (exit 4) and writes nothing.
  The pull request body says so and lists the files.
- **All or nothing.** A reference to this repository that is not a canonical pin (a branch, a tag, a SHA with no comment or an odd
  one) stops the run before anything is written (exit 3), as does a downgrade. Other repositories' actions are never touched.
- **The release comes from the API only.** The tag must be `vMAJOR.MINOR.PATCH` and the commit 40 hex characters.
- **One pull request, idempotent.** Branch `repin/gyst-<tag>`; if a pull request from that branch is already open, nothing is
  done. The working tree must be clean.
- **Inputs are not changed under you.** If the new release drops or retypes an input the caller sets, or adds a required input
  (no default) it does not set, the run stops with exit 5 and names them; `--allow-input-changes` overrides, and says so in the
  pull request. A definition it cannot read is a stop. A changed default of an input the caller does not set is a note in the
  pull request.
- **Other copies of the old pin are listed, never silent.** A test that asserts the pin, a script constant or a template can hold
  the old SHA outside the workflows and fail the caller's checks after a re-pin. In a git checkout, after the pins are rewritten
  (and in `status` and `apply --dry-run`), every tracked text file is searched for the old full 40-hex SHA as a whole word, and each
  hit outside the rewritten workflow refs is listed as `path:line`. Binary files, symlinks, untracked files, longer hex strings
  that merely contain the SHA, and release-history files (`CHANGELOG*`, `HISTORY*`, `NEWS*`, `RELEASES*`, `RELEASE_NOTES*`) are
  never hits. `apply` and `pr` exit **11** when copies remain (the pins were rewritten; `pr` opened the workflow-only pull request
  and names the copies in its body).
- **`--also-update-literals`** (`apply`, `pr`) rewrites those exact copies, and a `# vX.Y.Z` comment only where it directly follows
  the SHA (a closing quote may sit between), prints each rewrite, and with `pr` commits those files in the same pull request.
  `--dry-run` prints the diff instead. Pass it on the run that re-pins: once the workflows are current the old SHA is no longer known.
- **A symlinked workflow file is reported and skipped.**
- **A workflow path outside `A-Za-z0-9._/-` is refused** before anything is read.

## Dependabot

[`examples/dependabot-gyst.yml`](../../examples/dependabot-gyst.yml) is a `dependabot.yml` template for a caller: a `gyst` group
for every reference to this repository (all of a caller's workflows move in one pull request), a separate group for every other
action, and a 2-day cooldown. Dependabot moves the SHA and the version comment together, as it does for any pinned action.
Use it, this script, or both: the script covers a repository Dependabot does not.

## How it is tested

`tests/test_repin.py` runs the real script under bash against a fake `gh` (a Python program that answers from a scenario and
records every call) and, for the pull request mode, real git with a local bare repository as the remote. No network. It covers
status and its exit code, the age arithmetic, the mismatch flag, the pin-only rewrite byte for byte, every file kind, idempotence,
dry run, `--to`, the downgrade, every non-canonical reference, hostile tag and commit values from the API, symlinks, the pin-only
check itself (a sed that also edits an input), the branch, commit, push and pull request, a dirty tree, an open pull request, a
current caller, and the Dependabot template.

## What it refuses to do

- It does not merge, enable auto-merge, or approve.
- It does not touch an input, a job, a permission or any line that is not a pin.
- It does not follow a branch or a tag reference, or guess at a malformed pin.
- It does not run in a dirty working tree, or twice for the same release.
