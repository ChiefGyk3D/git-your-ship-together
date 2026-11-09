#!/usr/bin/env python3
"""Say what a failed Trivy image scan found, from the SARIF the scan already wrote (issue #383).

container-release.yml runs this in a step that only runs when an earlier step failed, so a red "Scan the image
with Trivy" step comes with a table of what tripped it instead of only the Security tab. It reads the SARIF file
named on the command line and prints:

- the totals by severity,
- one row per (rule id, file path) with its count, secret rules first,
- when every secret-rule hit is under a `site-packages` directory, one line naming the input that skips them.

It prints rule ids and file paths only. The matched text, the message, the snippet and every code region in the
SARIF are never read into the output. Rule ids and paths come from the scanned image, so they are printed
JSON-escaped and cut to 200 characters (a path cannot carry a newline or a workflow command into the log).

It never fails the job: a missing, empty, oversized or malformed file prints one line and exits 0. The scan's own
step decides pass or fail.

The block between BEGIN and END below is inlined, byte for byte, into the diagnostic step of container-release.yml
(a reusable workflow cannot call a file of its own commit). tests/test_trivy_sarif_summary.py holds every copy
identical to this file and runs the function on fixtures.

    python3 -I trivy_sarif_summary.py trivy-results.sarif
"""

# BEGIN trivy_sarif_summary
import json
import os
import re
import sys

MAX_BYTES = 256 * 1024 * 1024
MAX_ROWS = 50
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
LEVELS = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
SITE_PACKAGES = re.compile(r"(^|/)site-packages/")
HINT = (
    "All secret hits are under site-packages: set skip-secret-scan-in-site-packages: true on this call "
    "to skip secret rules there (CVE scanning stays on)."
)


def clean(value, limit=200):
    text = json.dumps(str(value))[1:-1]
    return text if len(text) <= limit else text[: limit - 3] + "..."


def tags_of(rule):
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    tags = props.get("tags") if isinstance(props.get("tags"), list) else []
    return props, [t.lower() for t in tags if isinstance(t, str)]


def severity_of(rule, level):
    props, tags = tags_of(rule)
    for sev in SEVERITIES:
        if sev.lower() in tags:
            return sev
    try:
        score = float(props.get("security-severity"))
    except (TypeError, ValueError):
        return LEVELS.get(level, "UNKNOWN")
    for sev, floor in (("CRITICAL", 9.0), ("HIGH", 7.0), ("MEDIUM", 4.0), ("LOW", 0.1)):
        if score >= floor:
            return sev
    return "UNKNOWN"


def is_secret(rule):
    return "secret" in tags_of(rule)[1]


def location_of(result):
    try:
        return str(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    except (KeyError, IndexError, TypeError):
        return "(no path)"


def summarize(doc):
    """Return (lines, hits) for a parsed SARIF document; hits maps (rule id, path, secret?) to a count."""
    totals = dict.fromkeys(SEVERITIES, 0)
    hits = {}
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver")) or {}
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id) or {}
            sev = severity_of(rule, result.get("level"))
            totals[sev] += 1
            key = (str(rule_id), location_of(result), is_secret(rule), sev)
            hits[key] = hits.get(key, 0) + 1
    lines = ["Trivy scan diagnostic (rule ids and paths only; matched text is never printed)"]
    counts = " ".join(f"{s}={totals[s]}" for s in SEVERITIES)
    lines.append(f"Results by severity: {counts} (total {sum(totals.values())})")
    if not hits:
        lines.append("No results in the SARIF.")
        return lines
    order = sorted(hits.items(), key=lambda kv: (not kv[0][2], SEVERITIES.index(kv[0][3]), -kv[1], kv[0][0], kv[0][1]))
    lines.append(f"{'COUNT':>6}  {'KIND':<6}  {'SEVERITY':<8}  RULE  PATH")
    for (rule_id, path, secret, sev), count in order[:MAX_ROWS]:
        lines.append(f"{count:>6}  {'secret' if secret else 'other':<6}  {sev:<8}  {clean(rule_id)}  {clean(path)}")
    if len(order) > MAX_ROWS:
        lines.append(f"... and {len(order) - MAX_ROWS} more (rule, path) pairs")
    secret_paths = [path for (_, path, secret, _), _ in order if secret]
    if secret_paths and all(SITE_PACKAGES.search(p) for p in secret_paths):
        lines.append(HINT)
    return lines


def main(argv):
    path = argv[0] if argv else "trivy-results.sarif"
    try:
        if not os.path.isfile(path):
            print(f"Trivy scan diagnostic: no SARIF at {clean(path)}; nothing to summarize.")
            return 0
        if os.path.getsize(path) > MAX_BYTES:
            print(f"Trivy scan diagnostic: {clean(path)} is larger than {MAX_BYTES} bytes; not read.")
            return 0
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        if not isinstance(doc, dict):
            print(f"Trivy scan diagnostic: {clean(path)} is not a SARIF object.")
            return 0
        print("\n".join(summarize(doc)))
    except Exception as exc:  # the diagnostic must never change pass or fail
        print(f"Trivy scan diagnostic: could not summarize {clean(path)} ({type(exc).__name__}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
# END trivy_sarif_summary
