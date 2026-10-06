# Contributing and developing

Pull requests are welcome; this is a small single-maintainer project with no SLA.
Security problems go through the private channel in
[SECURITY.md](../../SECURITY.md), **not** a public issue.

## The dev loop

```sh
pip install -r requirements-dev.txt
pytest                                                    # the contract
ruff check tests/ scripts/ fixture/ && ruff format --check tests/ fixture/
actionlint                                                # workflow syntax
zizmor --offline .                                        # workflow security
python scripts/gen_wiki.py --check                       # the wiki generates cleanly
```

(`python scripts/audit_baseline.py` needs a token with admin read on the repositories; you rarely need it.)

## Before you open a pull request

- [ ] `pytest` passes. If a test names a fix, apply that fix rather than editing the test to pass.
- [ ] If you **added a reusable workflow**, see the checklist below.
- [ ] If you **changed an input**, its README table row changed too (a test checks).
- [ ] If you **changed behaviour a person reads about**, the **wiki page changed in the same PR** (see
  [Maintaining this wiki](Maintaining-this-wiki.md)).
- [ ] If you **added a third-party action**, `baseline/selected-actions.json` lists it, including any subdirectory form and any
  action *its* `action.yml` calls. Read the action's `action.yml` for nested `uses:`.
- [ ] If you **added a write permission**, `ALLOWED_WRITES` in `tests/test_workflows.py` lists it with a reason.

## Adding a reusable workflow: checklist

1. Start from `contents: read` at the top; give **each job** its own `permissions:`, a `timeout-minutes`, and
   harden-runner as the **first step** (`disable-sudo: true`).
2. Pin every action to a **commit SHA** with a `# vX.Y.Z` comment.
3. Every checkout sets `persist-credentials: false`.
4. Pass anything untrusted (and every caller-supplied command) through `env:`, never `${{ }}` in `run:`.
5. Declare every input with a description and default; add the **README table row**.
6. Add `egress-policy`, `allowed-endpoints` (one sorted line of `host:port`), `extra-allowed-endpoints`, `timeout-minutes`.
7. If it runs the caller's code, give that job **no write token and no OIDC**; put publishing in a separate job.
8. Add it to the `REUSABLE` list in `tests/test_workflows.py` (and `DOPPLER` if it fetches secrets).
9. **Dogfood it**: call it from `ci.yml` against `fixture/` at `./.github/workflows/<name>.yml`, never publishing.
10. Add it to the `CI green` gate's `needs:` in `ci.yml`.
11. Update the README ("What is in the repository"), BASELINE if settings change, the roadmap if it closes an item, and **the wiki**
    ([Which workflow do I need?](Which-workflow-do-I-need.md), that workflow's page, [Repository map](Repository-map.md)).

## Style that matches the repository

- Comments say **why**, not what. The repository is meant to be read.
- Failure messages name the fix.
- Prefer a small test that fails honestly over a long comment.
- "Measured" beats "guessed" for allow-lists and defaults. Say how you measured.

## Releasing a version of this repository

Callers' Dependabot follows the **tags**, so a tag is the release.

```sh
git fetch --tags && git tag -l | sort -V | tail -3   # see what exists BEFORE choosing a number
git tag -a vX.Y.Z <sha> -m "vX.Y.Z: ..."
git push origin vX.Y.Z
```

**Fetch first.** Another session once cut v1.3.0 while this one believed the latest was v1.2.0; the v1.2.1 that followed would have
moved every caller's pin *backwards*, and was deleted and re-cut. Version tags are immutable (a ruleset forbids deleting or moving them),
so a mistaken number is superseded by the next one, not reused. zizmor fails a caller whose `# vX.Y.Z` comment names a tag that does not exist.

## Working in a cloud or automated session

Some contributions are made by automated sessions. The same rules apply, and there is one more: such sessions can commit unsigned,
which is part of why signed commits are not yet required. Develop on the branch you were given and open a draft pull request.
