# wiki-publish

**What it does.** Runs a command that generates a wiki tree, then replaces the repository's GitHub wiki with it, as `github-actions[bot]`,
only when something changed, from the default branch only.

**Why it exists.** A wiki written by hand drifts from the code it describes. A wiki that is a generated mirror of something else, usually
the docs, cannot. Every run replaces every page, so a page the generator stops writing disappears. It came from Hammunition's `wiki.yml`,
split into two jobs so the write token is never beside the generator. This wiki is published by it; see
[Adopting GYST in your own project](Adopting-GYST-in-your-own-project.md).

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `generate` | `contents: read` | Runs `install-command` and `generate-command`, keeps the tree as an artifact. Runs on pull requests too, so a broken generator fails review. An empty tree is refused, because publishing it would empty the wiki |
| `publish` | `contents: write` | Checks out only the wiki, runs none of your commands. Default branch only, never a pull request. Fixed concurrency group `wiki`, never cancelled halfway through a push |

The wiki checkout is the one checkout in the repository that keeps its credentials, deliberately: the token reaches git through the clone's
own config, never a shell variable, an argument or a URL. The commit names the source commit; nothing is pushed when the tree is unchanged.

## A minimal caller

```yaml
on:
  push: { branches: [main] }
  workflow_dispatch:

jobs:
  wiki:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/wiki-publish.yml@<sha> # vX.Y.Z
    permissions:
      contents: write   # the publish job only
    with:
      install-command: pip install -e ".[docs]"
      generate-command: python scripts/gen_wiki.py --out "$OUT_DIR" --commit "$SOURCE_SHA"
```

**The owner does one thing once, and GitHub offers it only in the UI.** A wiki's git repository does not exist until its first page is made:
open the repository's Wiki tab, choose "Create the first page", save anything, then re-run. Until then `publish` fails with exactly that
instruction. The wiki feature must also be enabled in the repository's settings.

<!-- inputs -->

## What it refuses to do

It never publishes from a pull request, never publishes an empty tree, never runs your generator beside the write token, and never writes
by hand: every page that is not in the generated tree is removed.
