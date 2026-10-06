# docs-pages

**What it does.** Builds a static documentation site on every pull request and deploys it to GitHub Pages from the default branch only.
Built for MkDocs (`mkdocs build --strict` after `pip install -e ".[docs]"`), but both commands are inputs, so anything that writes a
directory of static files fits: Sphinx, mdBook, a script.

**Why it exists.** A strict build fails a pull request that breaks a link, so it is caught in review and not published as a 404. It was
written from Hammunition's `pages.yml`; the project-specific parts (its site, its extra, its nav) stayed there.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `build` | `contents: read` and no token | Runs your install and build commands. The artifact is uploaded exactly when the deploy will run |
| `deploy` | `pages: write`, `id-token: write` | Default branch only, never a pull request. Runs none of your commands. Fixed concurrency group `pages`: queues behind a running deployment and never cancels one |

## A minimal caller

```yaml
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:

jobs:
  docs:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/docs-pages.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      pages: write      # the deploy job only
      id-token: write   # the deploy job only: Pages verifies it
```

**The owner sets one thing once:** Settings, Pages, Build and deployment, Source: **GitHub Actions**. Until then `deploy` fails with a
message that says so and names the URL; `build` is unaffected. `deploy: false` keeps a repository building only until the setting is made.
The default egress list has not been measured against a caller, which is why the default policy is `audit`.

<!-- inputs -->

## What it refuses to do

It never deploys from a pull request, never lets your build command run beside the Pages write, and never publishes an empty or missing
site directory.
