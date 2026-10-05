# Adopting a Repository

`scripts/new-repo.sh` adopts an existing repository into the shared workflows and the baseline, or starts a
new one. Source:
[`scripts/new-repo.sh`](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/scripts/new-repo.sh);
its header comment is the up-to-date usage.

```sh
scripts/new-repo.sh OWNER/NAME [--path DIR] [--language python|bash]...
                    [--container|--no-container] [--package|--no-package]
                    [--pypi] [--doppler-identity UUID] [--pin vX.Y.Z]
                    [--dry-run --out DIR [--sha SHA]]
```

## What it does

1. **Reads the repository as it is**: `pyproject.toml`, requirements files, ruff and mypy config, the Dockerfile, the
   shell scripts and their indent style, yamllint config, an `ansible/` directory, and the workflows already there
   (a PyPI publish step turns PyPI on).
2. **Writes the caller workflows from what it found**, one CI job per language, plus security, release (if there is a
   Dockerfile or package) and auto-merge, and a `dependabot.yml`. Existing hand-written CI is replaced and listed in the
   pull request.
3. **Commits on a branch** (`ci/git-your-ship-together`), pushes over SSH (so the `gh` token needs no `workflow` scope)
   and **opens the pull request**.
4. **Applies every BASELINE setting** through the API (branch protection, Actions settings, scanning, tag ruleset...).
5. **Appends the repository to `baseline/repos.txt`** so the weekly audit covers it.

## What it cannot do

**Doppler.** The Service Account and OIDC identity are made in the Doppler dashboard. The script prints those two steps
and takes the UUID back through `--doppler-identity` (it then sets the repository variable). Run it again with just
that flag once you have the UUID.

## Try it safely

```sh
scripts/new-repo.sh OWNER/NAME --dry-run --out /tmp/preview
```

`--dry-run` writes the generated files under `--out` and **prints** the settings it would apply, touching neither
GitHub nor the repository's history. That is exactly what `tests/test_new_repo.py` runs over three synthetic trees.

## After adopting

1. Merge the pull request once its first run is green.
2. Create the Doppler Service Account and identity ([Secrets and Doppler](Secrets-and-Doppler)); pass the UUID back.
3. Delete the repository's old GitHub secrets and rotate the values at the provider.
4. Run the [audit](Repository-Baseline#what-the-audit-checks) until it reports no FAIL and no UNKNOWN:
   ```sh
   python scripts/audit_baseline.py OWNER/NAME
   ```
5. Check the first push to the default branch fetched from Doppler (the audit cannot see Doppler's side).

## Using this for your own repositories (not just mine)

Fork it, or copy the workflow files and the tests. What you will change: the owner in the OIDC subject and audience,
the Doppler project names, `baseline/repos.txt`, `baseline/selected-actions.json`, and the Docker Hub and Snyk inputs if you do not
use them. **Keep the tests.** They are most of the value: they turn "we pin our actions" from a habit into a build failure.
