"""A target that hangs on an empty seed or zero byte, so libFuzzer saves a timeout input."""

import sys

import atheris


def TestOneInput(data: bytes) -> None:
    if not data or data[0] == 0:
        while True:
            pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
