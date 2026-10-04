"""A target that cannot fail, for the tests of python-fuzz.yml's run step."""

import sys

import atheris


def TestOneInput(data: bytes) -> None:
    atheris.FuzzedDataProvider(data).ConsumeBytes(8)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
