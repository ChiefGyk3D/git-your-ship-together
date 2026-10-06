# python-fuzz

**What it does.** Runs every [Atheris](https://github.com/google/atheris) fuzz target a repository keeps under `fuzz/` for a
fixed time per target, fails the job on a crash and uploads the crashing input. Holds no token.

**Why it exists.** OpenSSF Scorecard's Fuzzing check credits a Python repository for exactly one thing: an `import atheris` in a
`*.py` file in the tree (or OSS-Fuzz, ClusterFuzzLite, OneFuzz). Hypothesis does not count. This workflow makes that credit
honest: the targets actually run, and a crash is a red job. The first rollout (v1.10.0, 2026-10-04) across five repositories
found real defects (parsers that mishandled a bare carriage return, a null YAML key, wrong-shape JSON, an epoch
that hung a C routine), each fixed with a failing test first.

## What a target is

A file under `fuzz-dir` matching `target-glob` (default `fuzz_*.py`, searched recursively), run as
`python <target> -max_total_time=<seconds> -max_len=<max-len> -artifact_prefix=<dir>/ -print_final_stats=1`. It must:

- `import atheris` and wrap the imports of the code under test in `atheris.instrument_imports()`, or it fuzzes blind;
- define `def TestOneInput(data: bytes) -> None`, drawing typed values from `atheris.FuzzedDataProvider(data)`;
- call `atheris.Setup(sys.argv, TestOneInput)` then `atheris.Fuzz()` under `if __name__ == "__main__":`;
- raise only on a real bug. An error the code documents (a parser rejecting bad input) is caught inside the target.

```python
import sys

import atheris

with atheris.instrument_imports():
    from my_pkg.parser import ParseError, parse


def TestOneInput(data: bytes) -> None:
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(1024)
    try:
        parse(text)
    except ParseError:
        pass  # documented rejection, not a bug


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

## Behaviour worth knowing

- **A missing `fuzz/` directory, or one with no match, is a failure, not a skip.** A caller that opts in without targets
  is wrong, and a silent pass would be the thing Scorecard was trying not to credit.
- Every target runs even when an earlier one failed; the job fails if any did. A crash leaves `crash-*` (also `leak-*`,
  `timeout-*`, `oom-*`) files, uploaded as `fuzz-findings` for 30 days. Reproduce with `python fuzz/fuzz_x.py crash-<sha>`.
- **A hang looks different from a crash.** The first hang found (a TLE whose epoch made an SGP4 C routine never return) surfaced
  only as the outer per-target backstop killing the process, with no artifact, because no libFuzzer `-timeout` is passed
  (issue #82, open: a `timeout-per-input` input).
- Atheris is installed from one pinned version under `--require-hashes` with `--only-binary`, so nothing is built on the
  runner. It publishes x86_64 manylinux wheels for CPython 3.12 to 3.14 only, so the default Python is `3.14` and `runner`
  must be x86_64 Linux. A test fails when the workflow's pin and `requirements-dev.in` disagree.
- Add the job to the caller's `CI green` `needs:` (or run it on a schedule) so a crash cannot merge unseen. The Hammunition suite's callers run
  it for 30 seconds on a pull request and 600 seconds weekly.

## A minimal caller

```yaml
jobs:
  fuzz:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-fuzz.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      seconds-per-target: 60
      install-command: pip install -e ".[parse]"   # only when the default is not enough
```

<!-- inputs -->

## What it refuses to do

It never holds a token, never treats a missing target as a pass, and never builds Atheris from source on the runner.
