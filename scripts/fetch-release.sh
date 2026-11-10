#!/usr/bin/env bash
# Download one release asset, verify its SHA-256, and retry a flaky download (issue #372).
#
# On 2026-11-09 a GitHub incident made anonymous downloads time out (HTTP 504, curl exit 22) and every
# plain `curl -sSfL` tool install in these workflows failed on the first try. This is the one helper they
# all call now. The block between BEGIN and END below is inlined, byte for byte, into every workflow step
# that downloads a release asset (a reusable workflow cannot name the commit it runs from, so it cannot
# call this file by path; see docs/wiki/Design-rules.md). tests/test_fetch_release.py holds every copy
# identical to this file and runs the real function against a fake curl.
#
#   fetch_release URL OUTFILE SHA256
#
# - The SHA-256 is mandatory (64 hex digits) and fatal: a missing or malformed hash, or a download whose
#   hash differs, fails at once, is never retried, and leaves no OUTFILE. The bytes are written to a
#   temporary file beside OUTFILE and moved into place only after the hash matches.
# - The job token, when the step passes it as FETCH_RELEASE_TOKEN, is sent on https://github.com/ URLs only (authenticated traffic is
#   not in the anonymous-traffic pool that timed out). curl drops it on the redirect to
#   release-assets.githubusercontent.com. It goes in through a curl config on stdin, so it is in no
#   argument list, and tracing (`set -x`) is switched off while it is in a variable. A 401 or 403 drops it
#   for the remaining tries.
# - At most 5 tries; between them exponential backoff with jitter (2 s, 4 s, 8 s, 16 s, each plus up to
#   half again); each try is capped at 45 s and the whole call at 170 s, so it never runs 3 minutes.
#   FETCH_RELEASE_BUDGET (seconds, at most 170) and FETCH_RELEASE_BASE_DELAY exist for the tests only.
#
# BEGIN fetch_release
fetch_release() {
  local xt=0 rc
  case $- in *x*) xt=1 ;; esac
  set +x
  if _fetch_release "$@"; then rc=0; else rc=$?; fi
  if [ "$xt" = 1 ]; then set -x; fi
  return "$rc"
}
_fetch_release() {
  local url=${1:-} out=${2:-} want=${3:-} token=${FETCH_RELEASE_TOKEN:-}
  local tries=5 budget=${FETCH_RELEASE_BUDGET:-170} delay=${FETCH_RELEASE_BASE_DELAY:-2}
  local start=$SECONDS n=0 left cap pause step tmp code rc have
  case $url in https://?*) ;; *)
    echo "::error title=fetch_release::the URL must start with https://"
    return 2
    ;;
  esac
  if [ -z "$out" ]; then
    echo "::error title=fetch_release::no output file given"
    return 2
  fi
  case $want in *[!0-9a-fA-F]*) want="" ;; esac
  if [ "${#want}" -ne 64 ]; then
    echo "::error title=fetch_release::a SHA-256 of exactly 64 hex digits is required for $url"
    return 2
  fi
  case $budget in '' | *[!0-9]*) budget=170 ;; esac
  case $delay in '' | *[!0-9]*) delay=2 ;; esac
  if [ "$budget" -gt 170 ]; then budget=170; fi
  case $url in https://github.com/*) ;; *) token="" ;; esac
  case $token in *[!A-Za-z0-9_.-]*) token="" ;; esac
  tmp=$(mktemp "${out}.XXXXXX") || return 1
  step=$delay
  while [ "$n" -lt "$tries" ]; do
    n=$((n + 1))
    left=$((budget - (SECONDS - start)))
    if [ "$left" -lt 1 ]; then break; fi
    cap=$((left < 45 ? left : 45))
    if [ -n "$token" ]; then have="header = \"Authorization: Bearer ${token}\""; else have="# anonymous"; fi
    if code=$(printf '%s\n' "$have" | curl -q -sSfL --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time "$cap" -K - -w '%{http_code}' -o "$tmp" "$url"); then
      rc=0
    else
      rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
      have=$(sha256sum "$tmp" | cut -d' ' -f1)
      if [ "$have" != "$(printf '%s' "$want" | tr 'A-F' 'a-f')" ]; then
        rm -f "$tmp"
        echo "::error title=fetch_release::SHA-256 mismatch for $url: expected $want, got $have"
        return 1
      fi
      mv -f "$tmp" "$out"
      return 0
    fi
    echo "fetch_release: attempt $n of $tries failed for $url (curl exit $rc, HTTP ${code:-none})" >&2
    case $code in 401 | 403) token="" ;; esac
    if [ "$n" -ge "$tries" ]; then break; fi
    pause=$((step + RANDOM % (step / 2 + 1)))
    left=$((budget - (SECONDS - start)))
    if [ "$pause" -ge "$left" ]; then break; fi
    echo "fetch_release: waiting ${pause}s before the next try" >&2
    sleep "$pause"
    step=$((step * 2))
  done
  rm -f "$tmp"
  echo "::error title=fetch_release::could not download $url after $n tries (last curl exit ${rc:-none}); nothing was written to the output file"
  return 1
}
# END fetch_release
