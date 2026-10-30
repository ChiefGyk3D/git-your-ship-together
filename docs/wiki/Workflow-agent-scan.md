# agent-scan

**What it does.** Scans agent content with two static scanners from Cisco AI Defense: skills (`cisco-ai-skill-scanner`) and MCP tool
definitions (`cisco-ai-mcp-scanner`, `static` mode). It is optional and advisory. Nothing runs until you name paths, and a finding is
reported, not enforced, until you set `fail-on-severity`.

**Why it exists.** A skill, a role file or a tool description is text an agent obeys. A planted "ignore all previous instructions", a
`curl | bash` setup step or a hidden "read your SSH key first" in a tool description is a supply-chain problem that no dependency
scanner sees. These scanners look for exactly those patterns.

## What runs

| Job | Reads | Holds | Does |
|---|---|---|---|
| `skill-scan` | Your repository | `contents: read` | `skill-scanner scan` once per target, SARIF merged into one report |
| `mcp-scan` | Your repository | `contents: read` | `mcp-scanner --analyzers yara static --tools FILE` once per file, SARIF built from its JSON |
| `skill-upload`, `mcp-upload` | One SARIF artifact | `security-events: write` | Upload to code scanning; check nothing out, run nothing of yours |

Static engines only: pattern, YARA and structure checks on files already on the runner. The scan jobs run third-party code beside
your checkout, so `egress-policy` defaults to `block` with an allow-list of the checkout and PyPI hosts; `audit` opts out.
Patterns in `skill-paths` and `mcp-tool-files` are expanded by a bounded walk that never enters a symlinked directory. No LLM engine, no cloud engine, no
VirusTotal, no AI Defense API, no API key, no secret. The scanners run from an empty directory with an environment the script builds,
so a token or a `.env` in your repository never reaches them.

## A minimal caller

```yaml
on:
  push: { branches: [main] }
  pull_request:

jobs:
  agent-scan:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/agent-scan.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write  # granted even with upload-sarif: false
    with:
      skill-paths: |
        .claude/skills/*
        roles/*.md
      mcp-tool-files: mcp/tools-list.json
```

A template is in the repository: [`examples/agent-scan-caller.yml`](../../examples/agent-scan-caller.yml).

<!-- inputs -->

## Advisory, and when it is not

With `fail-on-severity` empty, a finding never fails the job. It lands in the job summary and in code scanning. Set it to `critical`,
`high`, `medium`, `low` or `info` and the job fails on a finding at or above that level:

- The workflow applies the threshold to the severities in the parsed reports. Neither scanner's exit code stands for a finding: the
  skill scanner must exit 0, and a nonzero exit is an error whose partial report is discarded.
- The MCP scanner reports at most `HIGH`, so `critical` never fails an MCP scan.

A scan that could not look at everything is not advisory. A path outside the repository, a pattern that matches nothing, a file that
is not a `{"tools": [...]}` list, two tools with the same name, a scanner that crashed, an MCP result set that is not exactly one
result per tool: each fails the job and uploads no report, so a half-finished scan cannot
close the alerts of the last good one. To keep the check from blocking merges, leave its check out of branch protection.

## Skills, entry files and directories

A directory is scanned as a skill and needs a `SKILL.md`. A file is scanned as the entry file of its directory, one run per file, so
`roles/*.md` works. A run covers the whole directory, so a finding in a sibling file can show under another file's run; the report
holds each finding once.

## What a clean result is worth

The scanners match known-bad patterns. They cannot judge instruction text that is harmful in meaning alone, and a clean scan is not a
safety result. On a repository that is mostly instruction prose, a first trial found nothing above INFO. Use the check to catch the
blunt cases and to notice when a file picks up a pattern it did not have.

## Supply chain and licence

Each scanner is installed from a hash lock inside the workflow (`.github/requirements/cisco-ai-skill-scanner.txt`,
`cisco-ai-mcp-scanner.txt`, written by `scripts/tool_locks.py` from the `.in` files), with `--require-hashes --no-deps
--only-binary=:all:`. The MCP scanner's tree is large (it depends on `litellm` and `fastapi`, which do not run in `static` mode), and
the lock lists all of it. Both packages are Apache-2.0. GitHub shows the skill scanner's licence as unrecognized because its
`LICENSE` file holds only the licence header; its package metadata says Apache-2.0.

## Tested how

`tests/test_agent_scan.py` runs the exact scan script against stand-in scanners and workspaces built on the spot: the threshold, the
refused paths, the crashed scanner, the environment the scanners get. In CI the workflow runs on `fixture/agent-scan`: the clean
files with `fail-on-severity: info`, the planted skill and tool list in advisory mode, and a control job that fails unless the
scanners fired on the planted files.

## What it refuses to do

It runs no LLM engine and calls no cloud engine, VirusTotal or AI Defense API; it takes no secret and no key, writes nothing to your
repository and comments on nothing. It reads no path outside the repository (`..`, an absolute path, a symlink that leaves it, `.git`)
and uploads no report from a scan that did not cover every target. It does not call a repository safe: a clean result means the known
patterns were absent, nothing more.
