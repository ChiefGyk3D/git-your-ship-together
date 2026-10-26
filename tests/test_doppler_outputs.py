"""The Doppler composite action's `export` and `names` inputs (issue #207), run under bash the way a runner would.

`export: env` (the default) is the old behavior: every secret in the config goes into GITHUB_ENV, so every later
step and every action post-run hook in the job inherits it. `export: outputs` writes nothing to the environment and
returns one masked JSON output the caller hands to individual steps through `env:`. `names` is an allow-list that
narrows either mode.

The validate and fetch steps are extracted from the action as shipped and run with a stub `curl` on PATH, so nothing
reaches the network. Every value here is made up. The decide step (the one inlined byte-identical in five workflows)
is covered by test_doppler_gate.py and test_workflows.py and is deliberately untouched by this feature.
"""

from __future__ import annotations

import json
import os
import select
import stat
import subprocess
import time
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / ".github" / "actions" / "doppler-secrets" / "action.yml"
DOC = yaml.safe_load(ACTION.read_text())
STEPS = DOC["runs"]["steps"]
BY_ID = {s["id"]: s for s in STEPS if "id" in s}

# Made-up values with the characters that break naive writers: quotes, a dollar sign, a backtick, a workflow
# command, a percent escape, a backslash, a carriage return and a multi-line PEM-like block.
PEM = "-----BEGIN FAKE KEY-----\nAAAA\n$(touch /nope)\n`id`\n::error::injected\n-----END FAKE KEY-----\n"
AWKWARD = "p\"q'r $HOME `id` ::error::boom %0A %25 back\\slash"
SECRETS = {
    "PROD_TOKEN": "prod-synthetic-value-111",
    "DEPLOY_KEY": PEM,
    "AWKWARD": AWKWARD,
    "OTHER_NAME": "other-synthetic-value-222",
    "DOPPLER_PROJECT": "demo",
}
ALL = "PROD_TOKEN,DEPLOY_KEY,AWKWARD,OTHER_NAME"  # every secret in SECRETS except Doppler's own labels
ALL_VALUES = {k: v for k, v in SECRETS.items() if not k.startswith("DOPPLER_")}
SENTINELS = ["prod-synthetic-value-111", "other-synthetic-value-222", "AAAA", "boom", "injected"]

STUB = r"""#!/usr/bin/env bash
# A stand-in for curl: answers the three calls the action makes and records how it was called.
{ printf 'ARGS:'; printf ' %q' "$@"; printf '\n'; } >>"$FAKE_LOG"
stdin=""
if [ ! -t 0 ]; then stdin=$(cat); fi
printf 'STDIN:%s\n' "$stdin" >>"$FAKE_LOG"
# NOTE: this stub ignores --max-filesize; the argument's presence is asserted separately, and the real cap is the
# `head -c` in the action, which the oversize tests exercise.
[ -z "${FAKE_MARK:-}" ] || echo "CURL_CALLED" >&2
if [ -n "${TMPDIR:-}" ]; then find "$TMPDIR" -mindepth 1 -printf 'TMP %m %y\n' >>"$FAKE_LOG" 2>/dev/null; fi
if [ -n "${FAKE_CURL_FAIL:-}" ]; then echo "curl: (22) The requested URL returned error: 403" >&2; exit 22; fi
case "$*" in
  *githubusercontent.com*) printf '{"count":1,"value":"fake.jwt.token"}\n' ;;
  *auth/oidc*) printf '{"success":true,"token":"dp.sa.fakeexchange"}\n' ;;
  *config/secrets*) cat "$FAKE_SECRETS"; [ -z "${FAKE_CURL_EXIT_AFTER_BODY:-}" ] || exit "$FAKE_CURL_EXIT_AFTER_BODY" ;;
  *) echo "unexpected curl call: $*" >&2; exit 99 ;;
esac
"""


def shipped(step_id: str) -> str:
    return BY_ID[step_id]["run"]


def doppler_response(values: dict[str, str]) -> str:
    secrets = {
        k: {
            "raw": v,
            "computed": v,
            "computedVisibility": "unmasked" if k.startswith(("DOPPLER_", "UNMASKED_")) else "masked",
        }
        for k, v in values.items()
    }
    return json.dumps({"success": True, "secrets": secrets}, ensure_ascii=False)


class Harness:
    def __init__(self, tmp: Path, values: dict[str, str] | None = None):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        stub = self.bin / "curl"
        stub.write_text(STUB)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.log = tmp / "curl.log"
        self.log.write_text("")
        self.secrets_file = tmp / "secrets.json"
        self.secrets_file.write_bytes(doppler_response(SECRETS if values is None else values).encode())
        self.out = tmp / "github_output"
        self.env_file = tmp / "github_env"
        self.out.write_text("")
        self.env_file.write_text("")

    def env(self, **extra: str) -> dict[str, str]:
        base = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            "FAKE_SECRETS": str(self.secrets_file),
            "GITHUB_OUTPUT": str(self.out),
            "GITHUB_ENV": str(self.env_file),
            "MODE": "token",
            "EXPORT": "outputs",
            "NAMES": "",
            "PROJECT": "demo",
            "CONFIG": "ci",
            "IDENTITY_ID": "",
            "TOKEN": "dp.st.synthetic-service-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/abc/oidc?x=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-request-token",
        }
        base.update(extra)
        return base

    def validate(self, export: str = "outputs", names: str = "") -> tuple[int, str, str]:
        """Run the validate step; return (exit code, normalized names it published, output)."""
        self.out.write_text("")
        proc = subprocess.run(
            ["bash", "-c", shipped("validate")],
            env=self.env(EXPORT=export, NAMES=names),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        got = ""
        for line in self.out.read_text().splitlines():
            if line.startswith("names="):
                got = line.split("=", 1)[1]
        return proc.returncode, got, proc.stdout + proc.stderr

    def fetch(self, export: str = "outputs", names: str = "", **extra: str) -> subprocess.CompletedProcess:
        """Run validate, then the fetch step with what validate published, as the action wires them."""
        code, normalized, out = self.validate(export, names)
        assert code == 0, out
        self.out.write_text("")
        return subprocess.run(
            ["bash", "-c", shipped("select")],
            env=self.env(EXPORT=export, WANT=normalized, **extra),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )

    def outputs(self) -> dict[str, str]:
        return parse_heredocs(self.out.read_text())

    def exported(self) -> dict[str, str]:
        return parse_heredocs(self.env_file.read_text())


def parse_heredocs(text: str) -> dict[str, str]:
    """Parse a GITHUB_OUTPUT / GITHUB_ENV file the way the runner does: NAME<<DELIM, lines, DELIM."""
    result: dict[str, str] = {}
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue
        assert "<<" in line, f"not a heredoc header: {line!r}"
        name, delim = line.split("<<", 1)
        j = i + 1
        body: list[str] = []
        while lines[j] != delim:
            body.append(lines[j])
            j += 1
        result[name] = "\n".join(body)
        i = j + 1
    return result


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


# --- structure: what a caller and the older path see ------------------------------------------------------------


def test_the_new_inputs_exist_with_the_old_behavior_as_default():
    inputs = DOC["inputs"]
    assert inputs["export"]["default"] == "env"
    assert inputs["export"]["required"] is False
    assert inputs["names"]["default"] == ""
    assert inputs["names"]["required"] is False


def test_the_mode_output_is_unchanged_and_secrets_defaults_to_an_empty_object():
    outputs = DOC["outputs"]
    assert outputs["mode"]["value"] == "${{ steps.mode.outputs.mode }}"
    assert outputs["secrets"]["value"] == "${{ steps.select.outputs.secrets || '{}' }}"


def test_the_decide_step_stays_first_and_untouched():
    """It is inlined byte-identical in five workflows; changing it here would drift every copy."""
    assert STEPS[0]["id"] == "mode"
    assert STEPS[0]["name"].startswith("Decide how to authenticate")
    assert "export" not in STEPS[0]["run"].lower()


def test_the_default_env_path_still_uses_the_same_pinned_fetch_action_and_injects():
    """No names + env is the old path: the same two steps, the same pins, inject-env-vars on."""
    fetches = [s for s in STEPS if str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@")]
    assert len(fetches) == 2
    for step in fetches:
        assert step["uses"] == "dopplerhq/secrets-fetch-action@451892f16195f9ac360e1a5bcbf0b5fd0e957534"
        assert step["with"]["inject-env-vars"] is True
        assert "inputs.export == 'env'" in step["if"] and "steps.validate.outputs.names == ''" in step["if"]
    modes = sorted(s["if"] for s in fetches)
    assert any("== 'oidc'" in m for m in modes) and any("== 'token'" in m for m in modes)


def test_the_new_step_runs_only_when_something_is_fetched_and_the_old_path_does_not_cover_it():
    cond = BY_ID["select"]["if"]
    assert "steps.mode.outputs.mode != 'none'" in cond
    assert "inputs.export == 'outputs'" in cond and "steps.validate.outputs.names != ''" in cond


def test_the_validate_step_runs_before_any_fetch_and_always():
    order = [s.get("id") or s.get("name") for s in STEPS]
    assert order.index("mode") < order.index("validate") < order.index("select")
    fetches = [i for i, s in enumerate(STEPS) if str(s.get("uses", "")).startswith("dopplerhq/")]
    assert all(order.index("validate") < i for i in fetches)
    assert "if" not in BY_ID["validate"]


def test_untrusted_input_reaches_the_new_steps_only_through_env():
    for step_id in ("validate", "select"):
        body = BY_ID[step_id]["run"]
        assert "${{" not in body, f"{step_id} interpolates an expression into the script"
        assert BY_ID[step_id]["shell"] == "bash"


# --- export validation -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["env", "outputs"])
def test_the_two_known_export_values_pass(h, value):
    assert h.validate(value, "PROD_TOKEN")[0] == 0


@pytest.mark.parametrize("value", ["", "ENV", "Outputs", "output", "env,outputs", "file", "env\n::error::x", " env"])
def test_any_other_export_value_fails(h, value):
    code, _, out = h.validate(value)
    assert code == 1 and "export must be env or outputs" in out
    assert "::error::x" not in out.replace("::error title=Doppler::", ""), "the bad value must not be echoed"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("A,B", "A,B"),
        ("A B", "A,B"),
        ("A, B ,C", "A,B,C"),
        ("A\nB\n", "A,B"),
        ("  _X1 \t Y_2 ", "_X1,Y_2"),
        ("A,A,B,A", "A,B"),
    ],
)
def test_names_are_split_on_commas_and_whitespace(h, raw, expected):
    code, got, out = h.validate("outputs", raw)
    assert code == 0 and got == expected, out


@pytest.mark.parametrize(
    "raw", ["a_lower", "1STARTS_WITH_DIGIT", "HAS-DASH", "HAS.DOT", "A;B", "$(id)", "A=B", "*", "A,B,x y"]
)
def test_a_malformed_name_fails_without_echoing_it(h, raw):
    code, got, out = h.validate("outputs", raw)
    assert code == 1 and got == "" and "names" in out
    assert raw not in out.replace("^[A-Z_][A-Z0-9_]*$", ""), "the bad entry was echoed"


@pytest.mark.parametrize("raw", [",", " , ,", "\n\n,"])
def test_names_that_hold_only_separators_fail_instead_of_meaning_everything(h, raw):
    """A typo must not widen an allow-list into 'every secret'."""
    code, _, out = h.validate("outputs", raw)
    assert code == 1 and "no names" in out


def test_names_may_be_empty_with_export_env_only(h):
    code, got, out = h.validate("env", "")
    assert code == 0 and got == "", out


def test_outputs_mode_requires_names(h):
    """Omitting the list would return the whole config: the exposure this mode exists to avoid."""
    code, got, out = h.validate("outputs", "")
    assert code == 1 and got == "" and "export: outputs requires names" in out


@pytest.mark.parametrize("raw", ["   ", "\n"])
def test_outputs_mode_with_blank_names_also_fails(h, raw):
    code, got, out = h.validate("outputs", raw)
    assert code == 1 and got == "" and "names" in out


# --- outputs mode: nothing reaches the environment ---------------------------------------------------------------


def test_outputs_mode_writes_nothing_to_github_env(h):
    proc = h.fetch("outputs", ALL)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert h.env_file.read_text() == "", "outputs mode wrote to GITHUB_ENV"
    data = json.loads(h.outputs()["secrets"])
    assert data == ALL_VALUES


def test_outputs_mode_returns_a_single_output(h):
    proc = h.fetch("outputs", ALL)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert list(h.outputs()) == ["secrets"]


def test_the_names_allow_list_exports_only_the_named_secrets_in_outputs_mode(h):
    proc = h.fetch("outputs", "PROD_TOKEN")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(h.outputs()["secrets"]) == {"PROD_TOKEN": "prod-synthetic-value-111"}
    assert h.env_file.read_text() == ""
    # and the values that were not asked for are never masked, announced or printed
    assert "other-synthetic-value-222" not in proc.stdout + proc.stderr


def test_the_names_allow_list_exports_only_the_named_secrets_in_env_mode(h):
    proc = h.fetch("env", "PROD_TOKEN,DEPLOY_KEY")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert h.exported() == {"PROD_TOKEN": "prod-synthetic-value-111", "DEPLOY_KEY": PEM}
    assert "OTHER_NAME" not in h.env_file.read_text()
    assert h.out.read_text() == "", "env mode has nothing to return as an output"


def test_a_named_secret_missing_from_the_config_fails_content_free(h):
    proc = h.fetch("outputs", "PROD_TOKEN,NOT_THERE")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "NOT_THERE" in out and "not in the Doppler config" in out
    for value in SENTINELS:
        assert value not in out, "a secret value reached the failure message"
    assert h.out.read_text() == "" and h.env_file.read_text() == ""


def test_a_missing_name_also_fails_in_env_mode(h):
    proc = h.fetch("env", "NOT_THERE")
    assert proc.returncode == 1 and h.env_file.read_text() == ""


def test_a_failed_api_call_fails_without_a_body_or_a_value(h):
    proc = h.fetch("outputs", "PROD_TOKEN", FAKE_CURL_FAIL="1")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and h.out.read_text() == "" and h.env_file.read_text() == ""
    assert "::error title=Doppler::" in out
    for value in SENTINELS:
        assert value not in out


# --- masking -----------------------------------------------------------------------------------------------------


def test_every_value_is_masked_line_by_line_and_as_a_whole(h):
    proc = h.fetch("outputs", "DEPLOY_KEY,PROD_TOKEN")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    masks = [ln for ln in proc.stdout.splitlines() if ln.startswith("::add-mask::")]
    assert "::add-mask::prod-synthetic-value-111" in masks
    for line in (
        "-----BEGIN FAKE KEY-----",
        "AAAA",
        "$(touch /nope)",
        "`id`",
        "::error::injected",
        "-----END FAKE KEY-----",
    ):
        assert f"::add-mask::{line}" in masks, line
    whole = "::add-mask::" + PEM.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    assert whole in masks, "the multi-line value is not masked as a whole"


def test_a_workflow_command_inside_a_value_cannot_run_as_a_command(h):
    proc = h.fetch("outputs", "DEPLOY_KEY,AWKWARD")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for line in (proc.stdout + proc.stderr).splitlines():
        assert line.startswith("::add-mask::"), f"stdout carries something other than a mask: {line!r}"
    assert "::add-mask::::error::injected" in proc.stdout


def test_percent_escapes_in_a_value_are_escaped_so_the_runner_masks_the_literal_text(h):
    proc = h.fetch("outputs", "AWKWARD")
    assert proc.returncode == 0
    assert "::add-mask::" + AWKWARD.replace("%", "%25") in proc.stdout.splitlines()


def test_the_json_escaped_form_and_the_whole_output_are_masked_too(h):
    proc = h.fetch("outputs", "AWKWARD")
    encoded = json.dumps(AWKWARD)[1:-1].replace("%", "%25")
    assert "::add-mask::" + encoded in proc.stdout.splitlines()
    blob = h.outputs()["secrets"].replace("%", "%25")
    assert "::add-mask::" + blob in proc.stdout.splitlines()


def test_outputs_mode_masks_a_value_even_when_doppler_marks_it_unmasked(tmp_path):
    """The caller extracts the value and passes it on, so a log line from that step must not show it."""
    h2 = Harness(tmp_path, {"UNMASKED_THING": "visible-per-doppler-1", "PROD_TOKEN": "prod-synthetic-value-111"})
    proc = h2.fetch("outputs", "UNMASKED_THING,PROD_TOKEN")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    masks = proc.stdout.splitlines()
    assert "::add-mask::visible-per-doppler-1" in masks
    assert "::add-mask::prod-synthetic-value-111" in masks


def test_env_mode_still_leaves_a_value_doppler_marks_unmasked_readable(tmp_path):
    """Unchanged from the pinned action's behavior: only outputs mode masks everything."""
    h2 = Harness(tmp_path, {"UNMASKED_THING": "visible-per-doppler-1"})
    proc = h2.fetch("env", "UNMASKED_THING")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::add-mask::visible-per-doppler-1" not in proc.stdout.splitlines()
    assert h2.exported() == {"UNMASKED_THING": "visible-per-doppler-1"}


def test_the_doppler_labels_are_never_returned_or_masked_in_outputs_mode(h):
    proc = h.fetch("outputs", ALL)
    assert proc.returncode == 0
    assert "DOPPLER_PROJECT" not in h.outputs()["secrets"]
    assert "::add-mask::demo" not in proc.stdout.splitlines()


@pytest.mark.parametrize("label", ["DOPPLER_PROJECT", "DOPPLER_CONFIG", "DOPPLER_ENVIRONMENT"])
def test_asking_for_a_doppler_label_in_outputs_mode_fails(h, label):
    h.secrets_file.write_bytes(doppler_response({**SECRETS, label: "label-value-xyz"}).encode())
    proc = h.fetch("outputs", f"PROD_TOKEN,{label}")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and label in out and "label-value-xyz" not in out
    assert h.out.read_text() == ""


def test_an_empty_selected_value_fails_closed_in_outputs_mode(tmp_path):
    """Why: a credential that is missing in Doppler must not come back as "" - a downstream step could then fall back
    to anonymous or default authentication without anyone noticing. The message names the secret, never a value."""
    h2 = Harness(tmp_path, {"EMPTY_ONE": "", "FULL": "synthetic-full-value"})
    proc = h2.fetch("outputs", "EMPTY_ONE,FULL")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "EMPTY_ONE" in out and "empty" in out
    assert "synthetic-full-value" not in out
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


def test_an_empty_unselected_value_is_ignored(tmp_path):
    h2 = Harness(tmp_path, {"EMPTY_ONE": "", "FULL": "synthetic-full-value"})
    proc = h2.fetch("outputs", "FULL")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(h2.outputs()["secrets"]) == {"FULL": "synthetic-full-value"}


def test_an_empty_value_is_still_allowed_in_env_mode(tmp_path):
    h2 = Harness(tmp_path, {"EMPTY_ONE": ""})
    assert h2.fetch("env", "EMPTY_ONE").returncode == 0


@pytest.mark.parametrize(
    "value, ok",
    [
        ("~", False),
        ("~~~", False),
        ("~~~~", False),
        ("~~~~~~~", False),  # 7 characters
        ("~~~~~~~~", True),  # 8 characters
        ("true", False),
        ("null", False),
        ("prod", False),
        ("http", False),
        ("2026", False),
        ("\u20ac" * 7, False),  # counted in characters, not bytes
        ("\u20ac" * 8, True),
    ],
)
def test_a_value_under_eight_characters_fails_closed_in_outputs_mode(tmp_path, value, ok):
    """add-mask on a short or common-word value redacts that text from every later log line."""
    h2 = Harness(tmp_path, {"SHORT_ONE": value, "PROD_TOKEN": "prod-synthetic-value-111"})
    proc = h2.fetch("outputs", "SHORT_ONE,PROD_TOKEN")
    out = proc.stdout + proc.stderr
    if ok:
        assert proc.returncode == 0, out
        assert json.loads(h2.outputs()["secrets"])["SHORT_ONE"] == value
    else:
        assert proc.returncode == 1 and "SHORT_ONE" in out and "shorter than 8" in out
        assert value not in out.replace("shorter than 8", "")
        assert "prod-synthetic-value-111" not in out
        assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


def test_a_short_value_is_still_allowed_in_env_mode(tmp_path):
    h2 = Harness(tmp_path, {"SHORT_ONE": "~~"})
    proc = h2.fetch("env", "SHORT_ONE")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert h2.exported() == {"SHORT_ONE": "~~"}


def test_masks_are_printed_before_the_value_is_written_anywhere(tmp_path):
    """GITHUB_OUTPUT is a pipe nobody reads yet: if the script has printed its last mask while the pipe is still
    unopened, the write cannot have happened first."""
    h2 = Harness(tmp_path)
    fifo = tmp_path / "out.fifo"
    os.mkfifo(fifo)
    code, normalized, out = h2.validate("outputs", "PROD_TOKEN,AWKWARD")
    assert code == 0, out
    proc = subprocess.Popen(
        ["bash", "-c", shipped("select")],
        env=h2.env(EXPORT="outputs", WANT=normalized, GITHUB_OUTPUT=str(fifo)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    seen = b""
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline and b"::add-mask::{" not in seen:
            ready, _, _ = select.select([proc.stdout], [], [], 0.2)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    break
                seen += chunk
        assert b"::add-mask::{" in seen, f"the whole-output mask never appeared before the write: {seen!r}"
        assert proc.poll() is None, "the script finished writing before anyone could read the pipe"
        assert b"prod-synthetic-value-111" in seen  # printed only behind ::add-mask::
        with open(fifo, encoding="utf-8") as reader:
            written = reader.read()
        assert "secrets<<" in written and "prod-synthetic-value-111" in written
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()


# --- the JSON and the heredoc ------------------------------------------------------------------------------------


def test_awkward_values_survive_the_json_round_trip_byte_for_byte(h):
    proc = h.fetch("outputs", "DEPLOY_KEY,AWKWARD")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(h.outputs()["secrets"])
    assert data == {"DEPLOY_KEY": PEM, "AWKWARD": AWKWARD}


def test_the_output_is_one_compact_line_between_random_delimiters(h):
    proc = h.fetch("outputs", "DEPLOY_KEY")
    assert proc.returncode == 0
    lines = h.out.read_text().split("\n")
    assert lines[0].startswith("secrets<<") and lines[-1] == "" and lines[-2] == lines[0].split("<<", 1)[1]
    assert len(lines) == 4, "the JSON must be a single line"
    delim = lines[0].split("<<", 1)[1]
    assert delim not in lines[1] and len(delim) >= 16
    assert not any(v in delim for v in ("synthetic", "AAAA", "KEY"))
    first = delim
    h.fetch("outputs", "DEPLOY_KEY")
    assert h.out.read_text().split("\n")[0].split("<<", 1)[1] != first, "the delimiter is not random"


def test_a_value_that_looks_like_a_heredoc_terminator_cannot_end_the_output_early(tmp_path):
    h2 = Harness(tmp_path, {"TRICKY": "EOF\nghadelimiter\nsecrets<<EOF\nEOF"})
    proc = h2.fetch("outputs", "TRICKY")
    assert proc.returncode == 0
    assert json.loads(h2.outputs()["secrets"]) == {"TRICKY": "EOF\nghadelimiter\nsecrets<<EOF\nEOF"}


def test_env_mode_values_with_newlines_and_quotes_are_written_exactly(h):
    proc = h.fetch("env", "DEPLOY_KEY,AWKWARD")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert h.exported() == {"DEPLOY_KEY": PEM, "AWKWARD": AWKWARD}


def test_env_mode_preserves_a_trailing_newline(h):
    proc = h.fetch("env", "DEPLOY_KEY")
    assert proc.returncode == 0
    assert h.exported()["DEPLOY_KEY"].endswith("-----END FAKE KEY-----\n")


def _size_case(tmp_path, value):
    h2 = Harness(tmp_path, {"BIG": value})
    return h2, h2.fetch("outputs", "BIG")


def test_the_old_byte_limit_is_gone_a_600000_character_ascii_value_fails(tmp_path):
    """600,000 ASCII characters are 1.2 MB in UTF-16, over GitHub's 1 MB. The old 1,000,000 byte check passed it."""
    h2, proc = _size_case(tmp_path, "x" * 600_000)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "UTF-16 code units" in out and "names" in out
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""
    assert "xxxxxxxx" not in out, "an oversize value was masked or printed before the size check"


def test_a_value_just_under_the_limit_passes(tmp_path):
    h2, proc = _size_case(tmp_path, "x" * 499_000)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-300:]
    assert json.loads(h2.outputs()["secrets"]) == {"BIG": "x" * 499_000}


def test_the_limit_is_exact_on_the_utf16_unit_count(tmp_path):
    overhead = len('{"BIG":""}')
    _, ok = _size_case(tmp_path, "x" * (500_000 - overhead))
    assert ok.returncode == 0
    (tmp_path / "b").mkdir()
    _, bad = _size_case(tmp_path / "b", "x" * (500_000 - overhead + 1))
    assert bad.returncode == 1


def test_a_bmp_multibyte_value_is_counted_in_utf16_units_not_utf8_bytes(tmp_path):
    """300,000 euro signs are 900,000 UTF-8 bytes but 300,000 UTF-16 units, well under the limit."""
    h2, proc = _size_case(tmp_path, "\u20ac" * 300_000)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-300:]
    assert json.loads(h2.outputs()["secrets"])["BIG"] == "\u20ac" * 300_000


def test_characters_outside_the_bmp_count_as_two_units(tmp_path):
    h2, ok = _size_case(tmp_path, "\U0001f600" * 249_000)  # 498,000 units
    assert ok.returncode == 0, (ok.stdout + ok.stderr)[-300:]
    (tmp_path / "b").mkdir()
    _, bad = _size_case(tmp_path / "b", "\U0001f600" * 251_000)  # 502,000 units
    assert bad.returncode == 1 and "UTF-16" in bad.stdout + bad.stderr


# --- hostile Doppler replies ---------------------------------------------------------------------------------


def _raw_reply(h2, body: bytes):
    h2.secrets_file.write_bytes(body)


def test_malformed_utf8_in_the_reply_fails_closed_before_parsing(tmp_path):
    """jq 1.7 would turn the stray byte into U+FFFD and quietly change the credential."""
    h2 = Harness(tmp_path)
    _raw_reply(
        h2,
        b'{"success":true,"secrets":{"BAD":{"computed":"abc\xffdefghijkl","computedVisibility":"masked"}}}',
    )
    proc = h2.fetch("outputs", "BAD")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "UTF-8" in out and "abcdefghijkl" not in out
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


def test_malformed_utf8_also_fails_in_env_mode(tmp_path):
    h2 = Harness(tmp_path)
    _raw_reply(h2, b'{"secrets":{"BAD":{"computed":"abc\xc3(defghijkl"}}}')
    proc = h2.fetch("env", "BAD")
    assert proc.returncode == 1 and h2.env_file.read_text() == ""


def test_an_oversize_reply_fails_closed_before_any_parsing(tmp_path):
    h2 = Harness(tmp_path, {"BIG": "x" * 4_100_000})
    proc = h2.fetch("outputs", "BIG")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "larger than 4000000 bytes" in out
    assert "xxxxxxxx" not in out and h2.out.read_text() == ""


def test_curl_is_given_a_response_size_cap(h):
    h.fetch("outputs", "PROD_TOKEN")
    args = [ln for ln in h.log.read_text().splitlines() if ln.startswith("ARGS:") and "config/secrets" in ln]
    assert args and all("--max-filesize 4000000" in ln for ln in args)


@pytest.mark.parametrize("mode", ["outputs", "env"])
def test_a_value_holding_a_nul_is_refused_by_name(tmp_path, mode):
    h2 = Harness(tmp_path)
    _raw_reply(h2, b'{"secrets":{"NUL_ONE":{"computed":"abcd\\u0000efghijkl","computedVisibility":"masked"}}}')
    proc = h2.fetch(mode, "NUL_ONE")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "NUL_ONE" in out and "NUL" in out and "abcd" not in out
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


def test_the_utf16_count_edge_between_u_ffff_and_u_10000(tmp_path):
    """U+FFFF is one UTF-16 unit and U+10000 is two. The JSON adds 10 units of overhead."""
    overhead = len('{"BIG":""}')
    _, one = _size_case(tmp_path, "\uffff" * (500_000 - overhead))  # exactly the limit, 1 unit each
    assert one.returncode == 0, (one.stdout + one.stderr)[-300:]
    (tmp_path / "b").mkdir()
    _, two = _size_case(tmp_path / "b", "\U00010000" * ((500_000 - overhead) // 2 + 1))  # one unit over
    assert two.returncode == 1 and "UTF-16" in two.stdout + two.stderr
    (tmp_path / "c").mkdir()
    _, edge = _size_case(tmp_path / "c", "\U00010000" * ((500_000 - overhead) // 2))  # exactly the limit
    assert edge.returncode == 0


# --- both ways in, and what goes on a command line ---------------------------------------------------------------


def test_the_oidc_path_exchanges_the_job_token_and_masks_both_tokens(tmp_path):
    h2 = Harness(tmp_path)
    proc = h2.fetch("outputs", "PROD_TOKEN", MODE="oidc", IDENTITY_ID="00000000-0000-0000-0000-000000000000", TOKEN="")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    log = h2.log.read_text()
    assert "githubusercontent.com" in log and "auth/oidc" in log and "config/secrets" in log
    masks = proc.stdout.splitlines()
    assert "::add-mask::fake.jwt.token" in masks and "::add-mask::dp.sa.fakeexchange" in masks
    assert json.loads(h2.outputs()["secrets"]) == {"PROD_TOKEN": "prod-synthetic-value-111"}


def test_the_oidc_path_fails_clearly_without_an_id_token_grant(tmp_path):
    h2 = Harness(tmp_path)
    proc = h2.fetch(
        "outputs",
        "PROD_TOKEN",
        MODE="oidc",
        IDENTITY_ID="00000000-0000-0000-0000-000000000000",
        ACTIONS_ID_TOKEN_REQUEST_URL="",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="",
    )
    assert proc.returncode == 1 and "id-token: write" in proc.stdout + proc.stderr


def test_the_service_token_path_uses_basic_auth_and_masks_the_token(h):
    proc = h.fetch("outputs", "PROD_TOKEN")
    assert proc.returncode == 0
    assert "::add-mask::dp.st.synthetic-service-token" in proc.stdout.splitlines()
    assert "auth/oidc" not in h.log.read_text()


def test_no_credential_is_ever_on_a_command_line(tmp_path):
    h2 = Harness(tmp_path)
    proc = h2.fetch("outputs", "PROD_TOKEN", MODE="oidc", IDENTITY_ID="00000000-0000-0000-0000-000000000000", TOKEN="")
    assert proc.returncode == 0
    args = [ln for ln in h2.log.read_text().splitlines() if ln.startswith("ARGS:")]
    assert args
    for secret in ("synthetic-request-token", "fake.jwt.token", "dp.sa.fakeexchange", "dp.st.synthetic-service-token"):
        assert not any(secret in ln for ln in args), f"{secret} reached a curl command line"
    (tmp_path / "second").mkdir()
    h3 = Harness(tmp_path / "second")
    proc = h3.fetch("outputs", "PROD_TOKEN")
    assert proc.returncode == 0
    args = [ln for ln in h3.log.read_text().splitlines() if ln.startswith("ARGS:")]
    assert not any("dp.st.synthetic-service-token" in ln for ln in args)


def test_curl_is_locked_to_https_and_does_not_follow_redirects(h):
    h.fetch("outputs", "PROD_TOKEN")
    args = [ln for ln in h.log.read_text().splitlines() if ln.startswith("ARGS:")]
    assert args
    for ln in args:
        assert "--proto =https" in ln or "--proto \\=https" in ln
        assert " -L" not in ln and "--location" not in ln


def test_a_secret_value_is_never_printed_unmasked(h):
    proc = h.fetch("outputs", ALL)
    assert proc.returncode == 0
    for line in (proc.stdout + proc.stderr).splitlines():
        assert line.startswith("::add-mask::")


def test_the_action_text_names_the_trade_off_and_the_waiting_callers():
    text = ACTION.read_text()
    head = text.split("\nname:", 1)[0]
    assert "export: outputs" in head and "names" in head and "post-run" in head
    assert "requires `names`" in head and "authorization boundary" in head and "GITHUB_STEP_SUMMARY" in head
    assert "whole as an env" in head and "job outputs" in head and "steal" in head
    assert "8 characters" in head and "empty" in head
    assert "fromJSON" in head and "no-php-no-cry" in head and "Reach-Around" in head


@pytest.mark.parametrize("path", ["README.md", "docs/wiki/Secrets-Doppler-and-OIDC.md"])
def test_the_docs_state_the_outputs_mode_rules(path):
    text = " ".join((REPO / path).read_text().split())
    assert "Required with `export: outputs`" in text or "**Required with `export: outputs`**" in text
    assert "shorter than 8 characters" in text
    assert "empty" in text and "fails the job" in text
    assert (
        "Never pass `steps.<id>.outputs.secrets` whole" in text
        or "Never** pass `steps.<id>.outputs.secrets` whole" in text
    )
    assert "authorization boundary" in text
    assert "outputs` mode is the form to use for production credentials" in text
    assert "marked unmasked stay unmasked" in text


# --- round 4: one mask function, OIDC request credential, pipeline stages, lossy encodings -----------------------


def test_every_mask_command_goes_through_one_function():
    """Exactly one line of the action prints a mask command, so exactly one line needs a justification."""
    lines = [ln for ln in ACTION.read_text().splitlines() if "::add-mask::" in ln and not ln.lstrip().startswith("#")]
    assert len(lines) == 1, lines
    assert "printf" in lines[0]
    assert shipped("select").count("emit_mask") >= 4


def test_the_mask_function_escapes_a_hostile_value(tmp_path):
    """The escaping that makes the single flagged line safe: remove it and a value starts its own command."""
    hostile = "prefix%0A::error::x\n::stop-commands::x\r::warning::y tail1234"
    h2 = Harness(tmp_path, {"HOSTILE": hostile})
    proc = h2.fetch("outputs", "HOSTILE")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert lines and all(ln.startswith("::add-mask::") for ln in lines), lines
    assert not any(ln.startswith(("::stop-commands::", "::error", "::warning")) for ln in lines)
    whole = hostile.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    assert "::add-mask::" + whole in lines
    assert json.loads(h2.outputs()["secrets"]) == {"HOSTILE": hostile}


def test_the_oidc_request_token_is_masked_before_any_curl_call(tmp_path):
    h2 = Harness(tmp_path)
    code, normalized, out = h2.validate("outputs", "PROD_TOKEN")
    assert code == 0, out
    proc = subprocess.run(
        ["bash", "-c", shipped("select")],
        env=h2.env(
            EXPORT="outputs",
            WANT=normalized,
            MODE="oidc",
            IDENTITY_ID="00000000-0000-0000-0000-000000000000",
            TOKEN="",
            FAKE_MARK="1",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = proc.stdout.splitlines()
    assert proc.returncode == 0, proc.stdout
    assert "::add-mask::synthetic-request-token" in lines
    assert lines.index("::add-mask::synthetic-request-token") < lines.index("CURL_CALLED")


@pytest.mark.parametrize(
    "token",
    ["synthetic-request-token\nX-Evil: 1", "short", "has space in the token 1234", "x" * 9000, 'tok"en-with-quote-123'],
    ids=["newline", "too-short", "space", "too-long", "quote"],
)
def test_a_hostile_oidc_request_token_fails_before_any_curl_call(tmp_path, token):
    h2 = Harness(tmp_path)
    proc = h2.fetch(
        "outputs",
        "PROD_TOKEN",
        MODE="oidc",
        IDENTITY_ID="00000000-0000-0000-0000-000000000000",
        TOKEN="",
        ACTIONS_ID_TOKEN_REQUEST_TOKEN=token,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and ("OIDC request token" in out or "unexpected shape" in out)
    assert "ARGS:" not in h2.log.read_text(), "curl was called with a hostile request token"
    assert "X-Evil" not in out


@pytest.mark.parametrize(
    "url",
    [
        "http://pipelines.actions.githubusercontent.com/abc",
        "https://evil.example/abc",
        "https://actions.githubusercontent.com.evil.example/abc",
        "https://pipelines.actions.githubusercontent.com/abc\nHost: evil",
        "https://user@pipelines.actions.githubusercontent.com/abc",
        "file:///etc/passwd",
    ],
)
def test_a_bad_oidc_request_url_fails_before_any_curl_call(tmp_path, url):
    h2 = Harness(tmp_path)
    proc = h2.fetch(
        "outputs",
        "PROD_TOKEN",
        MODE="oidc",
        IDENTITY_ID="00000000-0000-0000-0000-000000000000",
        TOKEN="",
        ACTIONS_ID_TOKEN_REQUEST_URL=url,
    )
    assert proc.returncode == 1 and "OIDC request URL" in proc.stdout + proc.stderr
    assert "ARGS:" not in h2.log.read_text()


# pipeline stages: 0 request builder (printf), 1 curl, 2 head


def _run_select(h2, extra_env=None, path_prefix=None):
    code, normalized, out = h2.validate("outputs", "PROD_TOKEN")
    assert code == 0, out
    env = h2.env(EXPORT="outputs", WANT=normalized, **(extra_env or {}))
    if path_prefix:
        env["PATH"] = f"{path_prefix}:{env['PATH']}"
    h2.out.write_text("")
    return subprocess.run(
        ["bash", "-c", shipped("select")], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL
    )


def test_a_failing_curl_fails_even_though_a_complete_body_was_written(h):
    proc = _run_select(h, {"FAKE_CURL_EXIT_AFTER_BODY": "7"})
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "at the curl stage" in out
    assert h.out.read_text() == "" and "prod-synthetic-value-111" not in out


def test_a_failing_head_fails_even_though_the_body_parses(tmp_path):
    h2 = Harness(tmp_path)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    (fakebin / "head").write_text("#!/usr/bin/env bash\ncat\nexit 5\n")
    (fakebin / "head").chmod(0o755)
    proc = _run_select(h2, path_prefix=str(fakebin))
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "at the head stage" in out and h2.out.read_text() == ""


def test_a_failing_request_builder_fails_even_though_the_body_parses(tmp_path):
    h2 = Harness(tmp_path)
    rc = tmp_path / "bashenv"
    rc.write_text("printf() { case $1 in 'Authorization: Basic'*) return 3 ;; esac; builtin printf \"$@\"; }\n")
    proc = _run_select(h2, {"BASH_ENV": str(rc)})
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "at the building the request stage" in out and h2.out.read_text() == ""


def test_exactly_the_reply_cap_in_bytes_with_every_stage_clean_passes(tmp_path):
    h2 = Harness(tmp_path)
    body = b'{"secrets":{"PROD_TOKEN":{"computed":"prod-synthetic-value-111","computedVisibility":"masked"}}}'
    h2.secrets_file.write_bytes(body + b" " * (4_000_000 - len(body)))
    proc = _run_select(h2)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-300:]
    h2.secrets_file.write_bytes(body + b" " * (4_000_001 - len(body)))
    over = _run_select(h2)
    assert over.returncode == 1 and "larger than 4000000 bytes" in over.stdout + over.stderr


# lossy encodings


def _body(value_escaped: str) -> bytes:
    return ('{"secrets":{"BAD":{"computed":"' + value_escaped + '","computedVisibility":"masked"}}}').encode()


@pytest.mark.parametrize("mode", ["outputs", "env"])
def test_an_escaped_lone_low_surrogate_is_refused_by_name(tmp_path, mode):
    """The body is pure ASCII so iconv passes it; jq 1.7 would silently rewrite the escape to U+FFFD."""
    h2 = Harness(tmp_path)
    h2.secrets_file.write_bytes(_body("\\udfffABCDEFGH"))
    proc = h2.fetch(mode, "BAD")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1 and "BAD" in out and "U+FFFD" in out and "ABCDEFGH" not in out
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


@pytest.mark.parametrize("mode", ["outputs", "env"])
def test_an_escaped_lone_high_surrogate_still_fails(tmp_path, mode):
    h2 = Harness(tmp_path)
    h2.secrets_file.write_bytes(_body("\\ud800ABCDEFGH"))
    proc = h2.fetch(mode, "BAD")
    assert proc.returncode == 1 and "ABCDEFGH" not in proc.stdout + proc.stderr
    assert h2.out.read_text() == "" and h2.env_file.read_text() == ""


def test_a_valid_surrogate_pair_escape_round_trips_exactly(tmp_path):
    h2 = Harness(tmp_path)
    h2.secrets_file.write_bytes(_body("\\ud83d\\ude00ABCDEFGH"))
    proc = h2.fetch("outputs", "BAD")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(h2.outputs()["secrets"]) == {"BAD": "\U0001f600ABCDEFGH"}
    h3dir = tmp_path / "env"
    h3dir.mkdir()
    h3 = Harness(h3dir)
    h3.secrets_file.write_bytes(_body("\\ud83d\\ude00ABCDEFGH"))
    assert h3.fetch("env", "BAD").returncode == 0
    assert h3.exported() == {"BAD": "\U0001f600ABCDEFGH"}


# the private work directory (names are already limited to ^[A-Z_][A-Z0-9_]*$, so U+FFFD cannot occur in one)


def test_the_work_directory_is_private_and_removed_even_on_failure(tmp_path):
    h2 = Harness(tmp_path)
    tmpdir = tmp_path / "tmpdir"
    tmpdir.mkdir()
    proc = _run_select(h2, {"TMPDIR": str(tmpdir)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    seen = [ln for ln in h2.log.read_text().splitlines() if ln.startswith("TMP ")]
    assert "TMP 700 d" in seen and "TMP 600 f" in seen, seen
    assert list(tmpdir.iterdir()) == []
    h2.secrets_file.write_bytes(_body("\\udfffABCDEFGH"))
    proc = _run_select(h2, {"TMPDIR": str(tmpdir)})
    assert proc.returncode == 1
    assert list(tmpdir.iterdir()) == [], "a failure left the reply on disk"
