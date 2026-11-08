"""Every expression in a composite action's manifest uses only a context that location can see.

GYST v1.32.0 shipped `.github/actions/ci-gate/action.yml` with a description that read
"`${{ toJSON(needs) }}` of the calling job." A runner evaluates `${{ }}` in the action's metadata when it loads the
manifest, `needs` does not exist there, and the job died in Set up job with
"Unrecognized named-value: needs". actionlint and zizmor do not evaluate action metadata, and no job ran the action,
so nothing caught it. This file is the static half of the fix; the live half is the `fixture-actions` job in ci.yml.

What the documentation gives, read 2026-11-07:

- https://docs.github.com/en/actions/reference/workflows-and-actions/contexts ("Context availability"): `needs` is
  populated only for a job with dependent jobs, the `jobs` context is for reusable workflow outputs only, and "the
  `secrets` context is not available for composite actions".
- https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax: composite actions use the
  `inputs` context; `outputs.<id>.value` takes an expression over `steps`; a step takes any supported context.

GitHub publishes no per-key table for action.yml. So the rules below are the strict reading: anything the
documentation does not allow at a location is refused, and the observed failure fixes the rest (an expression in a
`description` is evaluated at load and sees almost nothing, so none is allowed there). If GitHub documents more, widen
the table here with the page and the date.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
MANIFESTS = sorted((REPO / ".github" / "actions").glob("*/action.yml"))

NEVER = {"needs", "jobs", "secrets", "matrix", "strategy"}  # not defined inside an action at all
STEP_CONTEXTS = {"github", "inputs", "env", "runner", "job", "steps", "vars"}
OUTPUT_CONTEXTS = {"github", "inputs", "env", "runner", "job", "steps"}
DEFAULT_CONTEXTS = {"github"}  # the one the manifests use (`github.token`, `github.repository`)
LITERALS = {"true", "false", "null"}

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
STRING = re.compile(r"'(?:[^']|'')*'")
TOKEN = re.compile(r"(?<![\w.\-])([A-Za-z_][\w\-]*)(\s*\()?")  # a name not after `.`; group 2 set for a function call


def named_values(expression: str) -> set[str]:
    """The context names an expression reads: `toJSON(needs.a.result)` gives {"needs"}."""
    bare = STRING.sub("''", expression)
    return {n for n, call in TOKEN.findall(bare) if not call and n not in LITERALS}


def walk(node, path=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, path + (str(key),))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (index,))
    elif isinstance(node, str):
        yield path, node


def allowed_at(path) -> set[str]:
    if path[:2] == ("runs", "steps"):
        return STEP_CONTEXTS
    if len(path) == 3 and path[0] == "outputs" and path[2] == "value":
        return OUTPUT_CONTEXTS
    if len(path) == 3 and path[0] == "inputs" and path[2] == "default":
        return DEFAULT_CONTEXTS
    return set()  # name, description, author, branding, ...: evaluated at load, nothing to read


def violations(doc) -> list[str]:
    found = []
    for path, text in walk(doc):
        for expression in EXPRESSION.findall(text):
            where = ".".join(str(p) for p in path)
            for name in sorted(named_values(expression)):
                if name in allowed_at(path):
                    continue
                why = "does not exist in an action" if name in NEVER else "is not available at this location"
                found.append(f"{where}: `{name}` {why} (in `${{{{{expression}}}}}`)")
    return found


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.name)
def test_every_manifest_expression_uses_an_available_context(manifest):
    assert violations(yaml.safe_load(manifest.read_text())) == []


def test_there_are_manifests_to_check():
    assert {p.parent.name for p in MANIFESTS} >= {"ci-gate", "classify-changes", "wait-ci"}


# --- the checker itself bites -------------------------------------------------------------------------------


def test_the_v1_32_0_ci_gate_manifest_is_refused():
    doc = {"inputs": {"needs": {"description": "`${{ toJSON(needs) }}` of the calling job.", "required": True}}}
    (found,) = violations(doc)
    assert "inputs.needs.description" in found and "`needs`" in found


@pytest.mark.parametrize(
    ("doc", "name"),
    [
        ({"inputs": {"x": {"default": "${{ toJSON(needs) }}"}}}, "needs"),
        ({"inputs": {"x": {"default": "${{ secrets.TOKEN }}"}}}, "secrets"),
        ({"outputs": {"x": {"value": "${{ jobs.a.outputs.b }}"}}}, "jobs"),
        ({"runs": {"steps": [{"run": "echo ${{ needs.a.result }}"}]}}, "needs"),
        ({"runs": {"steps": [{"env": {"T": "${{ secrets.T }}"}}]}}, "secrets"),
        ({"inputs": {"x": {"default": "${{ inputs.other }}"}}}, "inputs"),
        ({"inputs": {"x": {"default": "${{ format('{0}', needs.a) }}"}}}, "needs"),
        ({"description": "token ${{ github.token }}"}, "github"),
    ],
)
def test_an_unavailable_context_is_refused(doc, name):
    found = violations(doc)
    assert found and all(f"`{name}`" in f for f in found)


def test_available_contexts_pass_and_text_in_strings_is_not_a_context():
    doc = {
        "inputs": {"t": {"default": "${{ github.token }}"}, "r": {"default": "${{ github.repository }}"}},
        "outputs": {"o": {"value": "${{ steps.s.outputs.v }}"}},
        "runs": {
            "steps": [
                {"env": {"A": "${{ inputs.t }}", "B": "${{ github.event.pull_request.number }}"}},
                {"if": "${{ always() && inputs.t != 'needs' }}", "run": "echo ${{ env.X }} ${{ runner.temp }}"},
            ]
        },
    }
    assert violations(doc) == []
