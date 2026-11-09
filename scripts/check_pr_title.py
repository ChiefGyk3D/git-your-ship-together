#!/usr/bin/env python3
"""Check one pull request title from environment variables.

The title is read from ``PR_TITLE`` so event data never becomes shell source.
``PATTERN`` is matched against the whole title.  Length is checked first, then
the regular expression is evaluated under a POSIX interval timer.  Python's
``re`` module has no timeout argument; ``signal.setitimer`` is the stdlib way
to interrupt a catastrophic match on the Linux runner used by the workflow.
"""

from __future__ import annotations

import os
import re
import signal
import sys

DEFAULT_PATTERN = (
    r"(?=.{8,120}\Z)(?:Add|Adjust|Allow|Avoid|Build|Bump|Change|Clean|Document|Drop|Enable|Enforce|Ensure|"
    r"Expose|Extend|Fix|Handle|Harden|Implement|Improve|Introduce|Make|Move|Prevent|Refactor|Release|Remove|"
    r"Rename|Replace|Require|Restore|Revert|Simplify|Support|Test|Update|Upgrade|Use|Write)\b[^\r\n]*[^.\r\n]\Z"
)
MATCH_TIMEOUT_SECONDS = 0.25


class MatchTimeout(Exception):
    """The configured regular expression did not finish in time."""


def workflow_escape(value: str) -> str:
    """Keep arbitrary event data inside one GitHub workflow-command line."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotation(level: str, message: str) -> None:
    print(f"::{level} title=PR title lint::{workflow_escape(message)}")


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        number = 0
    if number <= 0:
        raise ValueError("max-length must be a positive integer")
    return number


def timed_fullmatch(pattern: re.Pattern[str], title: str) -> bool:
    """Run ``fullmatch`` with a real, interrupting stdlib timeout."""

    def timeout(_signum: int, _frame: object) -> None:
        raise MatchTimeout

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, MATCH_TIMEOUT_SECONDS)
    try:
        return pattern.fullmatch(title) is not None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main() -> int:
    title = os.environ.get("PR_TITLE", "")
    pattern_text = os.environ.get("PATTERN", DEFAULT_PATTERN)
    prefixes_text = os.environ.get("ALLOW_PREFIXES", "")

    try:
        max_length = positive_integer(os.environ.get("MAX_LENGTH", "120"))
    except ValueError as exc:
        annotation("error", f"title={title}; rule=valid configuration; fix={exc}; count={len(title)} characters")
        return 2

    count = len(title)
    if count > max_length:
        remove = count - max_length
        annotation(
            "error",
            f"title={title}; rule=title must be at most {max_length} characters; "
            f"fix=remove at least {remove} characters; count={count} characters",
        )
        return 1

    try:
        pattern = re.compile(pattern_text)
    except re.error as exc:
        annotation(
            "error",
            f"title={title}; rule=pattern must be a valid Python regular expression; "
            f"fix=correct the invalid regular expression ({exc}); count={count} characters",
        )
        return 2

    prefixes = tuple(prefix.strip() for prefix in prefixes_text.split(",") if prefix.strip())
    if prefixes and title.startswith(prefixes):
        annotation(
            "notice",
            f"title={title}; rule=allowed prefix bypasses the pattern; fix=none; count={count} characters",
        )
        return 0

    try:
        matched = timed_fullmatch(pattern, title)
    except MatchTimeout:
        annotation(
            "error",
            f"title={title}; rule=pattern must finish within {MATCH_TIMEOUT_SECONDS:g} seconds; "
            f"fix=replace the regular expression timed out with a linear-time pattern; count={count} characters",
        )
        return 2

    if not matched:
        annotation(
            "error",
            f"title={title}; rule=title must fully match the configured pattern; "
            f"fix=use an imperative title of 8 to {max_length} characters without a trailing period, "
            f"or change the pattern; count={count} characters",
        )
        return 1

    annotation("notice", f"title={title}; rule=title matches; fix=none; count={count} characters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
