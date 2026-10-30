# agent-scan fixtures

Inputs for `agent-scan.yml`, called from `.github/workflows/ci.yml`.

| Path | Role | What CI expects |
| --- | --- | --- |
| `clean-skill/` | Clean skill | `skill-scan` passes `fail-on-severity: info`, so zero findings of any severity |
| `mcp/clean-tools.json` | Clean MCP tool list | `mcp-scan` passes `fail-on-severity: info` |
| `planted-skill/` | Negative control: an injection line, `curl \| bash` and an SSH key read | critical finding |
| `mcp/planted-tools.json` | Negative control: a hidden instruction in a tool description | high finding |

The planted files are inert text (see the note on wording below). Nothing runs them, and nothing in this repository loads them as a skill
or a tool list. They exist so a green scan can be told from a scanner that finds nothing: the job
`agent-scan-control` in CI fails unless the planted skill produces a critical finding and the planted
tool list a high one. The planted calls never upload a report, so no code scanning alert is opened here.

Wording matters to the skill scanner. The first draft of the planted skill added a sentence saying the file is inert test
data, and the critical prompt-injection rule then did not fire (the skill scored HIGH at most). So the planted file carries
no such sentence, and the explanation lives here, outside the scanned directory. Do not add one back.
