"""A program small enough to be obviously correct, with a CLI the smoke test and the image check can run."""

import argparse
import sys

__version__ = "0.1.0"


def greeting(name: str) -> str:
    return f"hello, {name}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fixture-app")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("name", nargs="?", default="world")
    args = parser.parse_args(argv)
    print(greeting(args.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
