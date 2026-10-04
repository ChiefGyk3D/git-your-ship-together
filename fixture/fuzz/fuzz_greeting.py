"""The fixture's Atheris target: the shape python-fuzz.yml documents, for a function that cannot fail.

`.github/workflows/ci.yml` runs it for a few seconds through python-fuzz.yml at the pull request's own ref.
"""

import sys

import atheris

with atheris.instrument_imports():
    from fixture_app import greeting


def TestOneInput(data: bytes) -> None:
    name = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(64)
    assert greeting(name) == f"hello, {name}"


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
