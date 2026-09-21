#!/usr/bin/env bash
# Tests for scripts/greet.sh, in plain bash so the fixture needs no test
# framework. Each check prints what it asserts; the first failure exits.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
greet="$here/../scripts/greet.sh"

check() {
  local want=$1 got=$2 what=$3
  if [ "$want" = "$got" ]; then
    echo "ok: $what"
  else
    echo "FAIL: $what: want '$want', got '$got'" >&2
    exit 1
  fi
}

check "hello, world" "$("$greet")" "default greeting"
check "hello, ci" "$("$greet" ci)" "named greeting"
check "greet 0.1.0" "$("$greet" --version)" "version"
if "$greet" --bogus 2>/dev/null; then
  echo "FAIL: an unknown flag should fail" >&2
  exit 1
fi
echo "ok: unknown flag rejected"
