#!/usr/bin/env bash
# Put one CI credential into the `ci` config of several Doppler projects.
# The value is typed once with echo off; it never appears on a command line,
# in shell history, or in this script's output.
#
#   scripts/doppler-ci-set.sh SNYK_TOKEN stream-daemon boon-tube-daemon
#
# Set DOPPLER_CI_CONFIG to target a config other than `ci`.
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 NAME PROJECT [PROJECT...]" >&2
  exit 2
fi
name=$1
shift
case $name in
  [A-Z_][A-Z0-9_]*) ;;
  *) echo "not a secret name: $name" >&2; exit 2 ;;
esac
config=${DOPPLER_CI_CONFIG:-ci}

read -rs -p "$name (input hidden): " value
echo >&2
if [ -z "$value" ]; then
  echo "empty value, nothing set" >&2
  exit 1
fi
read -rs -p "$name again to confirm: " again
echo >&2
if [ "$value" != "$again" ]; then
  echo "values differ, nothing set" >&2
  exit 1
fi

status=0
for project in "$@"; do
  # `doppler secrets set` prints the new value back in a table; drop that.
  if printf '%s' "$value" | doppler secrets set "$name" --project "$project" --config "$config" >/dev/null; then
    echo "set $name in $project/$config"
  else
    echo "FAILED $name in $project/$config" >&2
    status=1
  fi
done
exit "$status"
