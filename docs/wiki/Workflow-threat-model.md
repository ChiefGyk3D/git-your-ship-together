# threat-model

**What it does.** Checks that a repository with AI components keeps an OWASP Threat Dragon model, and that the model moves when the
AI surface moves. It reads the model files and, on a pull request, the list of changed files. It writes nothing and holds only
`contents: read`.

**Why it exists.** A prompt, a tool config or a model integration can change with no one asking whether the threat model still holds.
Process alone loses that. A red check does not. It pairs with the `threat-model` step in
[Scrum Around and Find Out](https://github.com/ChiefGyk3D/scrum-around-and-find-out), which requires the model (or a stated reason
there is none) before AI-facing work is built; this workflow is the half that checks the file.

## The two checks

| Check | When | Fails on |
|---|---|---|
| The model | Every run | Not a v2 model, duplicate ids, a flow to a cell that does not exist, no trust boundary, no flow, no threat, a bad or `TBD` severity, a bad status, `Mitigated` with no mitigation text, a stale `threatTop`; a `required-topics` entry no threat covers; an `Open` threat at or above `fail-on-open-severity` |
| The change | Pull requests, when `ai-paths` is set | A changed file matches `ai-paths`, no changed file matches `model-glob`, and the description has no `threat-model: n/a - <reason>` line |

## A minimal caller

```yaml
on:
  push: { branches: [main] }
  pull_request:

jobs:
  threat-model:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/threat-model.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      ai-paths: |
        prompts/**
        **/mcp*.json
      required-topics: prompt injection, data leakage, tool abuse
```

Author the model in Threat Dragon (the desktop app or the web app), save it as `docs/threat-model/<name>.threat-dragon.json`, and
commit it. The first run tells you what the file still lacks.

<!-- inputs -->

## What it refuses to do

It writes nothing, comments on nothing and holds no secret. It also cannot tell that the model is true of the running system or that an edit to it is a good one. The `n/a` line is written by the
pull request's author, so it is a recorded decision for the reviewer to read, not a control the author cannot bypass. Reading the
model is still a person's job; this makes skipping it visible.

## Why the script is inline

A reusable workflow cannot check out its own repository, so the validator lives in the workflow file. `tests/test_threat_model.py`
extracts that exact text and runs it against models and throwaway git repositories, and a mutation of any rule turns a test red.
