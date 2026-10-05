## What and why

<!-- What does this change, and why? The "why" is what a reader of the wiki wants most. -->

## Checklist

- [ ] `pytest` passes (a failing test names its fix; apply it rather than editing the test)
- [ ] If an input changed, its README table row changed too
- [ ] **Wiki:** if this changes what a person would read (a workflow, an input, a script, a setting, a rule), the page under `wiki/` is updated in this pull request. `tests/test_wiki.py` fails when something exists that the wiki never mentions, but it cannot tell when a sentence has gone stale.
- [ ] If a write permission or a third-party action was added: `ALLOWED_WRITES` / `baseline/selected-actions.json` updated
