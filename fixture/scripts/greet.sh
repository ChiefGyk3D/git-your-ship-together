#!/usr/bin/env bash
# The fixture's one shell script: enough for shellcheck, shfmt and a test to
# have something to hold. Prints a greeting; `--version` prints the version.
set -euo pipefail

VERSION="0.1.0"

usage() {
  echo "usage: $0 [--version] [NAME]" >&2
}

main() {
  local name="world"
  case "${1:-}" in
    --version)
      echo "greet $VERSION"
      return 0
      ;;
    -h | --help)
      usage
      return 0
      ;;
    -*)
      usage
      return 2
      ;;
    ?*)
      name=$1
      ;;
  esac
  printf 'hello, %s\n' "$name"
}

main "$@"
