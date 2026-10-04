"""A target that always fails, so the tests can prove python-fuzz.yml's run step goes red.

It lives under tests/, not fixture/, so no workflow ever runs it by accident.
"""

import sys

import atheris


def TestOneInput(data: bytes) -> None:
    raise RuntimeError("deliberate crash: the fuzz step must fail on this")


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
