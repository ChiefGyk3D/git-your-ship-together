# fixture

The smallest Python project that exercises every job of `python-ci.yml` and
`python-docker-release.yml`. `.github/workflows/ci.yml` calls both reusable
workflows against it from the pull request's own ref, so a change to a workflow
runs against a real project before it reaches the repositories that pin a tag.
`security.yml` is dogfooded the same way by `security-self.yml`.

It is not an example to copy; the callers' own `.github/workflows` are. What it
has is one of everything a job needs: a package with a console script (smoke
test), a test (test matrix), a linted tree (lint), a Dockerfile that runs as a
non-root user (build, check, Trivy) and a hash-pinned `requirements.txt`
(install under `--require-hashes`, as the callers do).

`requirements.in` lists the direct dependencies. Regenerate the lock after
editing it:

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras --no-header --output-file requirements.txt requirements.in
```

`tests/test_fixture.py` fails when a line of `requirements.txt` carries no hash.
