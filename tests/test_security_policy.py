"""The caller security policy is copied from one baseline template."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "baseline" / "SECURITY.template.md"
BASELINE = REPO / "BASELINE.md"


def test_security_template_has_repository_specific_fields_and_reporting_terms():
    text = TEMPLATE.read_text()

    for section in ("## Supported Versions", "## Reporting a Vulnerability", "## Scope", "## What to Expect"):
        assert section in text
    assert "<OWNER>/<REPO>" in text
    assert "<version>" in text
    assert "<project-specific scope bullet>" in text
    assert "private vulnerability reporting" in text
    assert "Do not open a public issue" in text
    assert "expected versus" in text and "reproduction steps" in text
    assert "within a week" in text
    assert "fix or written assessment" in text
    assert "There is no bounty" in text
    assert "unless you decline" in text


def test_baseline_tells_callers_to_copy_and_complete_the_template():
    text = " ".join(BASELINE.read_text().split())

    assert "baseline/SECURITY.template.md" in text
    assert "SECURITY.md" in text
    assert "latest tagged release" in text
    assert "project-specific scope" in text
