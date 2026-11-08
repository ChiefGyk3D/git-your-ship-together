"""Stand-in generator for the vendored-drift dogfood job: derives tokens.generated.txt from tokens.css.

`gen_tokens.py` writes the output; `gen_tokens.py --check` exits 1 when the committed output differs.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def render() -> str:
    return (HERE / "tokens.css").read_text(encoding="utf-8").upper()


def main(argv: list[str]) -> int:
    out = HERE / "tokens.generated.txt"
    if argv == ["--check"]:
        if out.read_text(encoding="utf-8") != render():
            print("tokens.generated.txt is stale; run gen_tokens.py")
            return 1
        return 0
    out.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
