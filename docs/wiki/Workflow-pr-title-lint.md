# pr-title-lint

**What it does.** Fails a pull request when its title is too long or does not fully match a Python regular expression. It
reads the title from the event payload, checks out no repository code and holds no token. Calls made by another event print a
notice and do nothing.

**Why it exists.** A title becomes the squash commit subject and the release history. A local hook cannot govern a title typed
in GitHub, while a reusable check gives every opt-in repository the same visible branch-protection result.

## Default rule

The default accepts 8 to 120 Unicode characters, starts with a common imperative verb, contains no newline and does not end in
a period. Endings such as `(Refs #12)` and `(Closes #12)` are valid. `max-length` is enforced separately and before regular
expression matching.

`pattern` replaces the default and is applied with `re.fullmatch`. `allow-prefixes` is a comma-separated list such as
`release:,chore(deps):`; a matching prefix bypasses the pattern, never the length limit.

## A minimal caller

```yaml
on:
  pull_request:

permissions: {}

jobs:
  title:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/pr-title-lint.yml@<sha> # vX.Y.Z
    permissions: {}
    with:
      allow-prefixes: "release:,chore(deps):"
```

The workflow itself is callable, so GitHub preserves the caller's event. If a caller invokes it from `push`, `schedule` or
`workflow_dispatch`, the job prints a notice and succeeds without inspecting a title.

## Hostile titles and expressions

The title is passed through `PR_TITLE`, never inserted into a shell program. Workflow-command metacharacters and line breaks are
escaped before an annotation prints the title, the broken rule, the fix and character counts.

Length is checked before the regular expression. Python's `re` has no timeout argument, so the Linux job uses the stdlib POSIX
interval timer (`signal.setitimer`) to interrupt `re.fullmatch` after 0.25 seconds. A malformed or timed-out expression is a
configuration error with a clear annotation and no traceback. `scripts/check_pr_title.py` is the local, stdlib-only source;
the workflow carries it byte for byte because a reusable workflow cannot read a file from its own pinned commit.

<!-- inputs -->

## What it refuses to do

It never checks out or runs pull request code, never reads a secret, never interpolates the event title into shell source, never
lets a prefix bypass the length ceiling, and never attempts a regular expression on an overlong title.
