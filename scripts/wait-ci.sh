#!/usr/bin/env bash
# wait-ci.sh: wait for CI on ONE commit, then optionally squash-merge exactly that commit.
#
# The watcher every repository and every monitor agent calls instead of a hand-written
# mergeStateStatus loop (which reported CLEAN or completed falsely five times on 2026-10-25).
# Its rules, each held by tests/test_wait_ci.py:
#
#   * The head SHA is pinned at the start and every verdict is about THAT commit, never a branch.
#   * Green needs ALL of: every required context (exact name, default "CI green") reported on the
#     pinned SHA and concluded success; at least --min-checks check runs completed; and no run
#     failed, was cancelled, timed out or needs action. No check runs at all is NOT green, and a
#     context that has not reported yet is NOT green (the aggregate-gate race seen on GYST #218).
#   * The gate is not the only check (issue #259). Every OTHER check run on the pinned SHA must also be
#     completed without failure, timeout, cancellation, action-required, startup failure or stale
#     (success, skipped and neutral pass). One that is queued or in progress is waited for (bounded by
#     --timeout and --hung-after); one that failed ends the wait with exit 6. A gate that failed is still
#     exit 1. --allow-red NAME (repeatable, empty by default) lets a named non-gate check be red; it is a
#     recorded exception and needs --allow-red-reason TEXT, which is printed. A gate name cannot be allowed.
#   * A late check cannot be seen before it exists. Two answers: --require-check NAME (repeatable) names a check
#     that must exist from the expected app and succeed, so a workflow that starts late is waited for (a
#     missing one ends in exit 2, never green); and success is returned only after two consecutive polls, one
#     --interval apart, read the identical set of check runs (id, status, conclusion, app, name). A name that
#     appears between the polls restarts the wait. A run named like the gate from another app is not the gate;
#     it is judged as an other check (unless --any-app). Without a required name nothing can prove that a
#     check which never appears does not exist: branch protection is the real control for that.
#   * The list of check runs must be whole. The endpoint shows at most the 1000 most recent check
#     suites of a ref, so the script asks for the suite count (GET .../check-suites, once per poll) and
#     is NOT green when it is 1000 or more or cannot be read as a plain integer. It also keeps the
#     check-runs total_count and is not green when that exceeds the runs actually seen or reaches 1000
#     ("check-run list may be truncated": it waits, so the end is exit 2 or 3). A failure that is
#     visible is still red. Every run must also carry the pinned commit as its head_sha, else red.
#   * The list must also hold still. Pages are requested one by one (page=1, 2, ... at most 12) from an
#     offset-paged collection that can change between requests, so a read is accepted only when every
#     page reports the same total_count, no run id repeats, and the distinct ids equal total_count
#     exactly; the suite count is read before AND after the run pages and the two must be equal; and
#     before it can be called green the whole read is made a second time and must show the same
#     (id, status, conclusion) set and the same suite counts. Anything else waits.
#   * A required context counts only when the check run was reported by the expected GitHub App
#     (--app-id, default 15368, GitHub Actions). A same-named run from any other app is ignored:
#     it is neither green nor red, so another app cannot satisfy or block the gate by copying the name.
#     --any-app turns that off (with a warning). Merge safety still also needs branch protection or a
#     ruleset that pins the required check to an app; this script is a second lock, not the first.
#   * A push (the head moves) aborts with exit 4, or with --on-push reset re-pins to the new head
#     and starts over (the total timeout is NOT reset, so the wait stays bounded). When the caller
#     gave --sha, ANY head move is exit 4 whatever --on-push says: an explicit SHA is never replaced.
#   * A check run whose NAME contains a control character (U+0000-U+001F, U+007F, U+0085, U+2028,
#     U+2029) is an error: red, never green. Names cross from jq to bash base64-encoded, so no name
#     can add a line or a field to what bash parses (a forged "completed / success / CI green" line).
#   * --merge squash-merges with --match-head-commit <verified sha>. Only a policy block (the base
#     branch policy, a required check not yet satisfied) is retried, a bounded number of times;
#     any other failure is exit 1 at once. The head is re-read after the last check and again when
#     a merge fails, so a push between the check and the merge is exit 4, never a merge of unverified
#     code. A merge gh accepts but that leaves the pull request open (a merge queue, auto-merge) is
#     exit 5, never reported as merged.
#   * What this script cannot do (issue #263): the check state is not atomic with the merge call. Between the last
#     read and the moment GitHub processes `gh pr merge`, a check can still turn red or appear. The script re-reads
#     the check runs and suite counts before EVERY merge attempt, first and retries alike, and aborts with exit 6
#     on any change; that narrows the window, it does not close it. The only atomic guarantee is GitHub-enforced
#     required status checks (branch protection or a ruleset) or a merge queue. This script is the second line.
#     Before merging it reads the base branch's rules and warns loudly when none cover the required contexts;
#     --require-protection makes that an error (exit 1).
#   * It prints the SHA it verified. It never prints a token (output from gh is redacted).
#
# Exit codes:
#   0   green (and merged, when --merge was given; or the PR was already merged at the verified SHA)
#   1   red: a check failed or was cancelled, or a check run name holds a control character; also
#       --merge could not merge ("merge blocked": a non-policy failure, or a policy block that
#       outlasted the retries) and an unreadable or malformed head
#   2   timeout: --timeout seconds passed without a verdict
#   3   hung: no check changed state for --hung-after seconds
#   4   head moved: the pull request head is no longer the pinned SHA
#   5   queued: the merge was accepted and the pull request, read back, is positively not merged yet at the
#       verified head (merge queue or auto-merge); a pull request that cannot be read back is exit 1
#   6   other checks red: the gate did not fail, but another check run on the pinned SHA failed, was
#       cancelled, timed out, needed action, failed to start or went stale (and is not in --allow-red)
#   64  usage error (bad flag or value); nothing was waited on
#
# Numbers are plain base-10 integers, no sign, space or leading zero (0 only where it is legal), and
# bounded; anything else is exit 64 naming the option:
#   --pr 1..999999999  --app-id 1..999999999  --min-checks 1..100000  --timeout 1..604800
#   --hung-after 1..604800  --interval 1..3600  --merge-retries 0..100  --merge-retry-delay 0..3600
#
# Usage:
#   wait-ci.sh --repo OWNER/REPO (--pr N | --sha SHA) [options]
#
# Options (defaults in brackets):
#   --repo OWNER/REPO       repository [$GITHUB_REPOSITORY]
#   --pr N                  pull request to watch; its head is pinned and re-read, and --merge needs it
#   --sha SHA               commit to verify; with --pr it must equal the head, else exit 4
#   --context NAME          required check run name, exact match; repeatable ["CI green"]; '' for none
#   --require-check NAME    a further required check run (exact name, expected app); repeatable [none]
#   --allow-red NAME[@APP]  a non-gate check run that may be red, exact name; repeatable [none]. A recorded
#                           exception, never a default; needs --allow-red-reason. @APP is the reporting app's
#                           slug (lowercase letters, digits, hyphens) and then both must match; a bare NAME
#                           matches that name from any app
#   --allow-red-reason TEXT why those checks may be red (one line); printed with the exception
#   --min-checks N          check runs that must be complete [1]
#   --timeout S             total seconds to wait [1800]
#   --hung-after S          seconds without any check changing before exit 3 [600]
#   --interval S            seconds between polls, at least 1 [20]; repeated gh errors back off to 8x
#   --app-id N              GitHub App id whose check runs may satisfy a context [15368]
#   --any-app               accept a same-named run from any app (prints a warning)
#   --on-push abort|reset   what a moved head does [abort]; reset is ignored when --sha is given
#   --merge                 squash-merge the verified SHA once green (needs --pr)
#   --delete-branch         with --merge, delete the head branch
#   --require-protection    with --merge, exit 1 unless the base branch has GitHub-enforced required status checks
#                           (branch protection or a ruleset) covering every required context, or a merge queue;
#                           without it a missing one is a loud warning
#   --merge-retries N       retries after a policy-blocked merge attempt [5]
#   --merge-retry-delay S   seconds between merge attempts [30]
#
# Environment: GH_TOKEN (read by gh; checks: read and pull-requests: read, plus contents: write and
# pull-requests: write for --merge), GH_BIN (the gh command, default gh; tests point it at a fake),
# GITHUB_OUTPUT (when set, result, sha and merged are appended for a composite action).
set -euo pipefail
# Byte-wise matching: [0-9] means the ASCII digits, never another script's.
export LC_ALL=C

gh_bin="${GH_BIN:-gh}"
repo="${GITHUB_REPOSITORY:-}"
pr=""
want_sha=""
contexts=()
contexts_given=0
required=()
allowed=()
allowed_names=()
allowed_apps=()
allow_reason=""
min_checks=1
timeout_s=1800
hung_after=600
interval=20
on_push=abort
merge=0
delete_branch=0
merge_retries=5
merge_retry_delay=30
app_id=15368
any_app=0
require_protection=0

result="usage"
verified=""
merged="false"

emit_outputs() {
  [[ -n "${GITHUB_OUTPUT:-}" ]] || return 0
  {
    echo "result=${result}"
    echo "sha=${verified}"
    echo "merged=${merged}"
  } >>"$GITHUB_OUTPUT"
}
errfile=""
on_exit() {
  [[ -z "$errfile" ]] || rm -f "$errfile"
  emit_outputs
}
trap on_exit EXIT

say() { printf 'wait-ci: %s\n' "$*"; }
die_usage() {
  printf 'wait-ci: usage: %s\n' "$*" >&2
  exit 64
}

# Replace every credential value in a string. Fixed-string replacement, never a regex built from it.
redact() {
  local text="$1" secret
  for secret in "${GH_TOKEN:-}" "${GITHUB_TOKEN:-}"; do
    [[ -n "$secret" ]] && text="${text//"$secret"/***}"
  done
  printf '%s' "$text"
}

now() { date +%s; }
nap() { sleep "$1"; }

# A control character (C0, DEL, NEL, line and paragraph separator) must never reach a log line.
has_ctrl() {
  [[ "$1" == *[[:cntrl:]]* || "$1" == *$'\xc2\x85'* || "$1" == *$'\xe2\x80\xa8'* || "$1" == *$'\xe2\x80\xa9'* ]] && return 0
  has_bidi "$1"
}
# Bidirectional formatting characters (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) can reorder what a
# reader sees in a log line: refused like a control character.
has_bidi() {
  local c
  for c in $'\xd8\x9c' $'\xe2\x80\x8e' $'\xe2\x80\x8f' $'\xe2\x80\xaa' $'\xe2\x80\xab' $'\xe2\x80\xac' \
    $'\xe2\x80\xad' $'\xe2\x80\xae' $'\xe2\x81\xa6' $'\xe2\x81\xa7' $'\xe2\x81\xa8' $'\xe2\x81\xa9'; do
    [[ "$1" == *"$c"* ]] && return 0
  done
  return 1
}

need_value() { [[ $# -ge 2 ]] || die_usage "$1 needs a value"; }
# need_num OPTION VALUE MIN MAX: a plain base-10 integer in range, else exit 64. The pattern admits at most
# nine digits and no leading zero, so no later arithmetic can wrap, read an octal or see a sign.
need_num() {
  [[ "$2" =~ ^(0|[1-9][0-9]{0,8})$ ]] ||
    die_usage "$1 must be a plain whole number: digits only, no sign or spaces, no leading zero, at most 999999999 (got '$2')"
  (($((10#$2)) >= $3 && $((10#$2)) <= $4)) || die_usage "$1 must be between $3 and $4 (got '$2')"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --merge)
      merge=1
      shift
      continue
      ;;
    --delete-branch)
      delete_branch=1
      shift
      continue
      ;;
    --any-app)
      any_app=1
      shift
      continue
      ;;
    --require-protection)
      require_protection=1
      shift
      continue
      ;;
  esac
  need_value "$@"
  case "$1" in
    --repo) repo="$2" ;;
    --pr) pr="$2" ;;
    --sha) want_sha="$2" ;;
    --context)
      contexts_given=1
      [[ -z "$2" ]] || contexts+=("$2")
      ;;
    --require-check)
      [[ -n "$2" ]] || die_usage "--require-check needs a check name"
      required+=("$2")
      ;;
    --allow-red)
      [[ -n "$2" ]] || die_usage "--allow-red needs a check name"
      allowed+=("$2")
      ;;
    --allow-red-reason) allow_reason="$2" ;;
    --min-checks) min_checks="$2" ;;
    --timeout) timeout_s="$2" ;;
    --hung-after) hung_after="$2" ;;
    --interval) interval="$2" ;;
    --on-push) on_push="$2" ;;
    --app-id) app_id="$2" ;;
    --merge-retries) merge_retries="$2" ;;
    --merge-retry-delay) merge_retry_delay="$2" ;;
    *) die_usage "unknown option '$1'" ;;
  esac
  shift 2
done

if [[ $contexts_given -eq 0 ]]; then
  contexts=("CI green")
fi
# --require-check names are further required contexts: each must exist, from the expected app, and succeed.
contexts+=("${required[@]}")

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die_usage "--repo must be OWNER/REPO (got '${repo}')"
case "${repo%%/*}" in . | ..) die_usage "--repo owner must not be . or .." ;; esac
case "${repo##*/}" in . | ..) die_usage "--repo name must not be . or .." ;; esac
if [[ -n "$pr" ]]; then
  need_num --pr "$pr" 1 999999999
  pr=$((10#$pr))
fi
[[ -n "$pr" || -n "$want_sha" ]] || die_usage "give --pr N or --sha SHA"
if [[ -n "$want_sha" ]]; then
  [[ "$want_sha" =~ ^[0-9a-f]{40}$ ]] || die_usage "--sha must be a full 40-character lowercase commit SHA (got '${want_sha}')"
fi
need_num --min-checks "$min_checks" 1 100000
need_num --timeout "$timeout_s" 1 604800
need_num --hung-after "$hung_after" 1 604800
need_num --interval "$interval" 1 3600
need_num --app-id "$app_id" 1 999999999
need_num --merge-retries "$merge_retries" 0 100
need_num --merge-retry-delay "$merge_retry_delay" 0 3600
min_checks=$((10#$min_checks))
timeout_s=$((10#$timeout_s))
hung_after=$((10#$hung_after))
interval=$((10#$interval))
app_id=$((10#$app_id))
merge_retries=$((10#$merge_retries))
merge_retry_delay=$((10#$merge_retry_delay))
case "$on_push" in
  abort | reset) ;;
  *) die_usage "--on-push must be abort or reset (got '${on_push}')" ;;
esac
if [[ $merge -eq 1 && -z "$pr" ]]; then die_usage "--merge needs --pr"; fi
for c in "${contexts[@]}"; do
  if has_ctrl "$c"; then die_usage "a --context or --require-check name must not hold a control character"; fi
done

for c in "${allowed[@]}"; do
  if has_ctrl "$c"; then die_usage "an --allow-red name must not hold a control character"; fi
  # NAME@APP scopes the exception to the check run reported by the app with that slug; a bare NAME matches the
  # name from any app.
  name="$c"
  app=""
  if [[ "$c" =~ ^(.+)@([a-z0-9][a-z0-9-]*)$ ]]; then
    name="${BASH_REMATCH[1]}"
    app="${BASH_REMATCH[2]}"
  fi
  allowed_names+=("$name")
  allowed_apps+=("$app")
  for g in "${contexts[@]}"; do
    [[ "$name" != "$g" ]] || die_usage "--allow-red '${c}' is a required context; the gate cannot be allowed to fail"
  done
done
if [[ ${#allowed[@]} -gt 0 ]]; then
  [[ -n "${allow_reason//[[:space:]]/}" ]] || die_usage "--allow-red is a recorded exception and needs --allow-red-reason TEXT"
  if has_ctrl "$allow_reason"; then die_usage "--allow-red-reason must be one line without control characters"; fi
elif [[ -n "$allow_reason" ]]; then
  die_usage "--allow-red-reason without --allow-red"
fi
if has_ctrl "$allow_reason"; then die_usage "--allow-red-reason must be one line without control characters"; fi

errfile="$(mktemp)"

# gh with stdout and stderr kept apart. A failure is reported as one redacted line; a token never
# reaches the log.
gh_try() {
  local out first
  if out="$("$gh_bin" "$@" 2>"$errfile")"; then
    printf '%s' "$out"
    return 0
  fi
  first="$(grep -m1 . "$errfile" || true)"
  say "gh call failed: $(redact "$first")" >&2
  return 1
}

# The state of the pull request from ONE response: merged, head.sha and merge_commit_sha are read together,
# so a merge can be attributed to the head it merged and not to a head read a moment earlier. Every value is
# validated (a full SHA, a boolean); a response with more than one line is refused.
PR_MERGED=""
PR_HEAD=""
PR_MERGE_SHA=""
PR_BASE=""
pr_state() {
  local out
  out="$(gh_try api "repos/${repo}/pulls/${pr}" \
    --jq '[(.merged | tostring), (.head.sha // "" | tostring), (.merge_commit_sha // "" | tostring), (.base.ref // "" | tostring)] | join("\u001f")')" || return 1
  PR_MERGED=""
  PR_BASE=""
  PR_HEAD=""
  PR_MERGE_SHA=""
  if [[ "$out" == *$'\n'* ]]; then
    say "the API returned a malformed pull request state for ${repo}#${pr}" >&2
    return 1
  fi
  IFS=$'\x1f' read -r PR_MERGED PR_HEAD PR_MERGE_SHA PR_BASE <<<"$out"
  [[ "$PR_BASE" =~ ^[A-Za-z0-9._/-]{1,200}$ ]] || PR_BASE=""
  if [[ "$PR_MERGED" != true && "$PR_MERGED" != false ]] || [[ ! "$PR_HEAD" =~ ^[0-9a-f]{40}$ ]] ||
    [[ -n "$PR_MERGE_SHA" && ! "$PR_MERGE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    say "the API returned something that is not a pull request state with a full commit SHA for ${repo}#${pr}" >&2
    return 1
  fi
}
# A commit SHA from the API is used (and written to GITHUB_OUTPUT) only when it is 40 hex digits.
pr_head() {
  pr_state || return 1
  printf '%s' "$PR_HEAD"
}

# One page of the check runs of a commit as lines, every free-text value crossing as base64 so a hostile
# value (a name with a newline or the field separator in it) cannot add a line or a field. Fields are split
# by \x1f.
#   T <total_count>                                                       once per page
#   R <id> <status> <conclusion> <app id> <hostile> <head_sha> <app slug> <name>   once per run
# The run id is plain digits (or "bad"), checked again in bash. hostile is 1 when the name holds a control
# character, DEL, NEL or a Unicode line or paragraph separator (NUL included).
check_page() {
  gh_try api "repos/${repo}/commits/${1}/check-runs?per_page=100&filter=latest&page=${2}" \
    --jq '(["T", ((.total_count // -1) | tostring | @base64)] | join("\u001f")), (.check_runs[] | ["R", (.id | if type == "number" and . == floor and . >= 0 and . < 1000000000000000 then tostring else "bad" end), (.status // "" | tostring | @base64), (.conclusion // "" | tostring | @base64), ((.app.id // 0) | tostring | @base64), (.name // "" | tostring | if explode | any(. < 32 or . == 127 or . == 133 or . == 1564 or . == 8206 or . == 8207 or . == 8232 or . == 8233 or (. >= 8234 and . <= 8238) or (. >= 8294 and . <= 8297)) then "1" else "0" end), (.head_sha // "" | tostring | @base64), ((.app.slug // "") | tostring | @base64), (.name // "" | tostring | @base64)] | join("\u001f"))'
}

# The number of CHECK SUITES on a commit, from a call of its own (one per poll). GitHub's cap is on suites:
# "If there are more than 1000 check suites on a single git reference, this endpoint will limit check runs to
# the 1000 most recent check suites" (REST, list check runs for a Git reference), and a truncated answer can hold
# far fewer than 1000 runs, so the run count cannot show it. GET .../check-suites returns total_count, an
# integer, for every suite on the ref (also those without runs). Anything that is not a plain integer is
# "unreadable", never zero.
suite_count() {
  local n
  n="$(gh_try api "repos/${repo}/commits/${1}/check-suites?per_page=1" \
    --jq '.total_count | if type == "number" and . == floor and . >= 0 and . < 1000000000 then tostring else "bad" end')" || return 1
  [[ "$n" =~ ^(0|[1-9][0-9]{0,8})$ ]] || return 1
  printf '%s' "$n"
}

# Canonical base64 only. The pattern is the exact shape including the rule that the unused trailing bits
# are zero (the last character before "==" is one of A Q g w, before "=" one of A E I M Q U Y c g k o s w
# 0 4 8), so a value has exactly one spelling and equality of encodings is equality of values.
B64_RE='^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$'
enc() { printf '%s' "$1" | base64 | tr -d '\n'; }

# Strict decode, for the few values read as data (a count): the shape, a decode that succeeds, and a
# re-encode equal to the input. The decoded value is left in B64_VALUE.
b64_strict() {
  local dec
  [[ "$1" =~ $B64_RE ]] || return 1
  dec="$(printf '%s' "$1" | base64 -d 2>/dev/null)" || return 1
  [[ "$(enc "$dec")" == "$1" ]] || return 1
  B64_VALUE="$dec"
}

# A name for a message, only ever for a run that is already known to be safe to print.
dec_display() {
  local d
  d="$(printf '%s' "$1" | base64 -d 2>/dev/null | tr -d '\000-\037\177')" || d=""
  if has_bidi "$d"; then d="<name with bidirectional control characters>"; fi
  printf '%s' "${d:-unnamed}"
}

# A fingerprint of a read: the sorted (id, status, conclusion, app, name) of every run, in their encoded form.
fingerprint() {
  local kind f1 f2 f3 f4 f5 f6 f7 f8 rest out=""
  while IFS=$'\x1f' read -r kind f1 f2 f3 f4 f5 f6 f7 f8 rest; do
    if [[ "$kind" == R ]]; then out+="${f1} ${f2} ${f3} ${f4} ${f8}"$'\n'; fi
  done <<<"$1"
  printf '%s' "$out" | LC_ALL=C sort
}

# One complete read of a commit: the suite count, then the run pages one by one, then the suite count again.
# Sets W_A (suites before), W_LINES (every page), W_B (suites after). Returns 1 when a call failed, 2 when the
# list needs more pages than it is allowed to. W_SUITE_FAILED is 1 when a suite call failed.
MAX_RUN_PAGES=12
W_A=""
W_B=""
W_LINES=""
W_SUITE_FAILED=0
read_world() {
  local sha="$1" page=1 chunk first rest total_seen accumulated=0 n_r want
  W_A=""
  W_B=""
  W_LINES=""
  W_SUITE_FAILED=0
  if ! W_A="$(suite_count "$sha")"; then
    W_A=""
    W_SUITE_FAILED=1
  fi
  while :; do
    chunk="$(check_page "$sha" "$page")" || return 1
    W_LINES+="${chunk}"$'\n'
    n_r="$(grep -c $'^R\x1f' <<<"$chunk" || true)"
    accumulated=$((accumulated + n_r))
    if [[ $n_r -lt 100 ]]; then break; fi
    first="${chunk%%$'\n'*}"
    IFS=$'\x1f' read -r total_seen want rest <<<"$first"
    if [[ "$total_seen" == T ]] && b64_strict "$want" && [[ "$B64_VALUE" =~ ^(0|[1-9][0-9]{0,8})$ ]] &&
      [[ $accumulated -ge $((10#$B64_VALUE)) ]]; then
      break
    fi
    if [[ $page -ge $MAX_RUN_PAGES ]]; then return 2; fi
    page=$((page + 1))
  done
  if ! W_B="$(suite_count "$sha")"; then
    W_B=""
    W_SUITE_FAILED=1
  fi
}

pin=""
if [[ -n "$pr" ]]; then
  pin="$(pr_head)" || {
    say "cannot read the head of ${repo}#${pr}"
    result="error"
    exit 1
  }
  if [[ -n "$want_sha" && "$pin" != "$want_sha" ]]; then
    say "head moved: ${repo}#${pr} is at ${pin}, expected ${want_sha}"
    result="head-moved"
    exit 4
  fi
else
  pin="$want_sha"
fi
if [[ $any_app -eq 1 ]]; then
  say "warning: --any-app: a check run of any app with a required name counts; rely on branch protection pinning the app"
fi
say "pinned ${pin} (${repo}${pr:+#$pr}); gate: ${contexts[*]:-any checks}; min checks ${min_checks}"
if [[ ${#allowed[@]} -gt 0 ]]; then
  say "warning: recorded exception: these check runs may be red: $(printf "'%s' " "${allowed[@]}")(reason: ${allow_reason}); a bare name matches any app"
fi

start="$(now)"
last_change="$start"
last_sig=""
polls=0
fails=0

# Values are compared in their encoded form, which is canonical and so unique: no per-run decoding.
B_COMPLETED="$(enc completed)"
B_SUCCESS="$(enc success)"
B_APP="$(enc "$app_id")"
declare -A BAD_CONCLUSION=()
for c in failure cancelled timed_out action_required startup_failure stale; do
  BAD_CONCLUSION["$(enc "$c")"]="$c"
done
B_NEUTRAL="$(enc neutral)"
B_SKIPPED="$(enc skipped)"
context_enc=()
for c in "${contexts[@]}"; do
  context_enc+=("$(enc "$c")")
done
allowed_enc=()
allowed_app_enc=()
for i in "${!allowed_names[@]}"; do
  allowed_enc+=("$(enc "${allowed_names[$i]}")")
  if [[ -n "${allowed_apps[$i]}" ]]; then allowed_app_enc+=("$(enc "${allowed_apps[$i]}")"); else allowed_app_enc+=(""); fi
done

is_context_enc() {
  local e
  for e in "${context_enc[@]}"; do
    [[ "$1" == "$e" ]] && return 0
  done
  return 1
}

# is_allowed_enc NAME_ENC SLUG_ENC: the name matches an --allow-red entry and, when that entry carries @APP, the
# reporting app's slug matches too. A bare name matches the name from any app.
is_allowed_enc() {
  local i
  for i in "${!allowed_enc[@]}"; do
    [[ "$1" == "${allowed_enc[$i]}" ]] || continue
    if [[ -z "${allowed_app_enc[$i]}" || "$2" == "${allowed_app_enc[$i]}" ]]; then return 0; fi
  done
  return 1
}

# Truncation: the endpoint lists at most the 1000 most recent check suites of a ref. The suite count (read
# before and after the run pages into $suites_a and $suites_b, empty when unreadable) is the signal that cap
# applies to; the two must be readable, equal and under the cap. The run-count checks stay as extra guards.
SUITE_CAP=1000
RUN_LIST_CAP=1000

# Sets verdict (green|red|pending) and detail for the lines passed in, using $suites_a and $suites_b.
evaluate() {
  local lines="$1" kind f1 f2 f3 f4 f5 f6 f7 f8 i b_pin first_count=""
  foreign=0
  hostile=0
  local runs_seen=0 count_lines=0 count_missing=0 count_mismatch=0 dups=0 total_count=0
  local total=0 complete=0 bad=0 badname="" seen_ok seen_any
  local other_bad=0 other_badname="" other_open=0 other_openname="" allowed_bad=0 is_ctx
  local -A ctx_seen=() ctx_ok=() ctx_open=() seen_id=()
  b_pin="$(enc "$pin")"
  while IFS=$'\x1f' read -r kind f1 f2 f3 f4 f5 f6 f7 f8; do
    [[ -n "$kind$f1$f2$f3$f4$f5$f6$f7$f8" ]] || continue
    if [[ "$kind" == T ]]; then
      if [[ -n "$f2$f3$f4$f5$f6$f7$f8" ]] || ! b64_strict "$f1" || [[ ! "$B64_VALUE" =~ ^(-1|0|[1-9][0-9]{0,8})$ ]]; then
        hostile=$((hostile + 1))
        continue
      fi
      count_lines=$((count_lines + 1))
      if [[ "$B64_VALUE" == -1 ]]; then
        count_missing=1
      else
        # Every page of one read must report the same total_count.
        if [[ -z "$first_count" ]]; then
          first_count="$B64_VALUE"
        elif [[ "$B64_VALUE" != "$first_count" ]]; then
          count_mismatch=1
        fi
        if [[ $((10#$B64_VALUE)) -gt $total_count ]]; then total_count=$((10#$B64_VALUE)); fi
      fi
      continue
    fi
    if [[ "$kind" != R ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    runs_seen=$((runs_seen + 1))
    # The run id: plain digits, and never twice in one read.
    if [[ ! "$f1" =~ ^(0|[1-9][0-9]{0,14})$ ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    if [[ -n "${seen_id[$f1]:-}" ]]; then
      dups=$((dups + 1))
    else
      seen_id[$f1]=1
    fi
    # Anything that is not exactly the shape jq emits, a name that jq flagged, or a run for another
    # commit is hostile.
    if [[ ! "$f5" =~ ^0$ || ! "$f2" =~ $B64_RE || ! "$f3" =~ $B64_RE || ! "$f4" =~ $B64_RE || ! "$f6" =~ $B64_RE ||
      ! "$f7" =~ $B64_RE || ! "$f8" =~ $B64_RE || "$f6" != "$b_pin" ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    # A run that carries a required name but comes from another app is NOT the gate: it cannot satisfy it, and it
    # is judged like any other check (red blocks with exit 6, open is waited for), unless --any-app.
    total=$((total + 1))
    is_ctx=0
    if is_context_enc "$f8"; then
      if [[ $any_app -eq 1 || "$f4" == "$B_APP" ]]; then
        is_ctx=1
      else
        foreign=$((foreign + 1))
      fi
    fi
    if [[ "$f2" == "$B_COMPLETED" ]]; then
      complete=$((complete + 1))
      if [[ -n "$f3" && -n "${BAD_CONCLUSION[$f3]:-}" ]]; then
        if [[ $is_ctx -eq 1 ]]; then
          bad=$((bad + 1))
          badname="${badname:-$(dec_display "$f8") (${BAD_CONCLUSION[$f3]})}"
        elif is_allowed_enc "$f8" "$f7"; then
          allowed_bad=$((allowed_bad + 1))
        else
          other_bad=$((other_bad + 1))
          other_badname="${other_badname:-$(dec_display "$f8") (${BAD_CONCLUSION[$f3]})}"
        fi
      elif [[ $is_ctx -eq 0 && "$f3" != "$B_SUCCESS" && "$f3" != "$B_NEUTRAL" && "$f3" != "$B_SKIPPED" ]]; then
        # Completed but with no usable conclusion: not a pass, so it is waited for like an open run.
        other_open=$((other_open + 1))
        other_openname="${other_openname:-$(dec_display "$f8")}"
      fi
    elif [[ $is_ctx -eq 0 ]]; then
      other_open=$((other_open + 1))
      other_openname="${other_openname:-$(dec_display "$f8")}"
    fi
    for i in "${!contexts[@]}"; do
      [[ $is_ctx -eq 1 && "$f8" == "${context_enc[$i]}" ]] || continue
      ctx_seen[$i]=1
      if [[ "$f2" != "$B_COMPLETED" ]]; then
        ctx_open[$i]=1
      elif [[ "$f3" != "$B_SUCCESS" ]]; then
        ctx_ok[$i]=bad
      elif [[ "${ctx_ok[$i]:-}" != bad ]]; then
        ctx_ok[$i]=ok
      fi
    done
  done <<<"$lines"

  verdict=pending
  if [[ $hostile -gt 0 ]]; then
    verdict=red
    detail="${hostile} check run(s) on ${pin} with a control character in the name, a head_sha other than the pinned commit or malformed fields; refusing (possible forgery)"
    return 0
  fi
  # A read that contradicts itself is not a snapshot: pages that disagree on total_count, a run id that
  # appears twice, or more runs than total_count (the collection moved between page requests).
  if [[ $count_mismatch -eq 1 || $dups -gt 0 || $runs_seen -gt $total_count ]] && [[ $count_lines -gt 0 && $count_missing -eq 0 ]]; then
    detail="check-run list changed while it was read (${count_lines} pages, total_count ${total_count}, ${runs_seen} runs seen, ${dups} repeated ids); waiting for a stable snapshot"
    return 0
  fi
  if [[ $foreign -gt 0 ]]; then
    say "${foreign} run(s) named like a required check come from an app other than ${app_id}: they do not count as the gate and are judged as other checks"
  fi
  if [[ $bad -gt 0 ]]; then
    verdict=red
    detail="${badname} on ${pin}"
    return 0
  fi
  if [[ $other_bad -gt 0 ]]; then
    verdict=other-red
    detail="another check run is red, not only the gate: ${other_badname} on ${pin}"
    return 0
  fi
  if [[ -n "$suites_a" && -n "$suites_b" && "$suites_a" != "$suites_b" ]]; then
    detail="check-run list may be truncated (check suite count changed while reading (${suites_a} then ${suites_b})); not trusting it"
    return 0
  fi
  if [[ -z "$suites_a" || -z "$suites_b" || ${suites_a:-0} -ge $SUITE_CAP || $count_lines -eq 0 || $count_missing -eq 1 ||
    $total_count -gt $runs_seen || $total_count -ge $RUN_LIST_CAP ]]; then
    detail="check-run list may be truncated (${suites_a:-unreadable} then ${suites_b:-unreadable} check suites, cap ${SUITE_CAP}; total_count ${total_count}, ${runs_seen} runs seen); not trusting it"
    return 0
  fi
  if [[ $total -eq 0 ]]; then
    detail="no check runs on ${pin} yet"
    return 0
  fi
  seen_ok=1
  seen_any=""
  for i in "${!contexts[@]}"; do
    if [[ -z "${ctx_seen[$i]:-}" ]]; then
      seen_ok=0
      seen_any="${seen_any}'${contexts[$i]}' not reported; "
    elif [[ -n "${ctx_open[$i]:-}" || "${ctx_ok[$i]:-}" != ok ]]; then
      seen_ok=0
      seen_any="${seen_any}'${contexts[$i]}' not finished; "
    fi
  done
  if [[ $seen_ok -eq 0 ]]; then
    detail="${seen_any}${complete}/${total} runs complete"
    return 0
  fi
  if [[ $complete -lt $min_checks ]]; then
    detail="${complete} of ${min_checks} required check runs complete"
    return 0
  fi
  if [[ $other_open -gt 0 ]]; then
    detail="gate satisfied, waiting for ${other_open} other check run(s) to finish (first: ${other_openname}); ${complete}/${total} runs complete"
    return 0
  fi
  verdict=green
  detail="${complete}/${total} runs complete, gate satisfied, no other check red"
  if [[ $allowed_bad -gt 0 ]]; then detail+=" (${allowed_bad} allowed red)"; fi
}

verdict=pending
detail=""
settle_fp=""
settled_a=""
settled_b=""
suites_a=""
suites_b=""
while :; do
  polls=$((polls + 1))
  t="$(now)"

  # The head first: a push makes everything below about a stale commit.
  poll_failed=0
  if [[ -n "$pr" ]]; then
    if cur="$(pr_head)"; then
      if [[ "$cur" != "$pin" ]]; then
        if [[ "$on_push" == abort || -n "$want_sha" ]]; then
          say "head moved: ${repo}#${pr} was ${pin}, now ${cur}"
          result="head-moved"
          exit 4
        fi
        say "head moved: ${pin} -> ${cur}; resetting (the total timeout keeps running)"
        pin="$cur"
        settle_fp=""
        last_sig=""
        last_change="$t"
      fi
    else
      poll_failed=1
    fi
  fi

  rc=0
  read_world "$pin" || rc=$?
  if [[ $rc -eq 0 ]]; then
    suites_a="$W_A"
    suites_b="$W_B"
    if [[ $W_SUITE_FAILED -eq 1 ]]; then poll_failed=1; fi
    evaluate "$W_LINES"
    sig="$(printf '%s\n' "$pin" "suites=${suites_a}/${suites_b}" "$W_LINES" | LC_ALL=C sort | cksum)"
    if [[ "$verdict" == green ]]; then
      # Green is only believed after a second, complete read shows the same runs and suite counts.
      fp_first="$(fingerprint "$W_LINES")"
      a_first="$W_A"
      b_first="$W_B"
      rc=0
      read_world "$pin" || rc=$?
      if [[ $rc -ne 0 ]]; then
        verdict=pending
        detail="the confirming read failed, will retry"
        poll_failed=1
      else
        suites_a="$W_A"
        suites_b="$W_B"
        if [[ $W_SUITE_FAILED -eq 1 ]]; then poll_failed=1; fi
        evaluate "$W_LINES"
        if [[ "$verdict" == green ]] &&
          [[ "$(fingerprint "$W_LINES")" != "$fp_first" || "$W_A" != "$a_first" || "$W_B" != "$b_first" ]]; then
          verdict=pending
          detail="check runs or suite counts changed between two reads; waiting for a stable snapshot"
        fi
      fi
    fi
    # Settle rule: a green read is believed only when the previous poll, one interval earlier, read the identical set
    # of check runs (id, status, conclusion, app, name). A check that appears between two polls changes the set and
    # restarts the wait; it is then judged like every other check.
    if [[ "$verdict" == green ]]; then
      fp_now="$(fingerprint "$W_LINES")"
      settled_a="$W_A"
      settled_b="$W_B"
      if [[ -z "$settle_fp" || "$settle_fp" != "$fp_now" ]]; then
        settle_fp="$fp_now"
        verdict=pending
        detail="settling: the check list must read identical twice, one interval apart, before it counts"
      fi
    else
      settle_fp=""
    fi
  elif [[ $rc -eq 2 ]]; then
    verdict=pending
    detail="check-run list may be truncated (more than ${MAX_RUN_PAGES} pages of check runs); not trusting it"
    sig="$last_sig"
    poll_failed=1
    settle_fp=""
  else
    verdict=pending
    detail="the check-runs call failed, will retry"
    sig="$last_sig"
    poll_failed=1
  fi

  if [[ "$sig" != "$last_sig" ]]; then
    last_sig="$sig"
    last_change="$t"
  fi
  say "poll ${polls}: ${verdict}: ${detail}"

  if [[ "$verdict" == red ]]; then
    say "red: ${detail}"
    result="red"
    exit 1
  fi
  if [[ "$verdict" == other-red ]]; then
    say "other checks red: ${detail}"
    result="other-red"
    exit 6
  fi
  if [[ "$verdict" == green ]]; then
    break
  fi
  if ((t - start >= timeout_s)); then
    say "timeout: no verdict for ${pin} after ${timeout_s} s (${detail})"
    result="timeout"
    exit 2
  fi
  if ((t - last_change >= hung_after)); then
    say "hung: nothing changed on ${pin} for ${hung_after} s (${detail})"
    result="hung"
    exit 3
  fi
  # Repeated gh errors back off (x2 each, at most x8) so a failing API is not hammered.
  if [[ $poll_failed -eq 1 ]]; then
    fails=$((fails + 1))
  else
    fails=0
  fi
  backoff=1
  if [[ $fails -gt 1 ]]; then backoff=$((1 << (fails > 4 ? 3 : fails - 1))); fi
  nap $((interval * backoff))
done

# Green on $pin. Re-read the head once more: a push after the last poll must not be merged.
if [[ -n "$pr" ]]; then
  # Not in a command substitution: the base branch it reads (for the protection check) must survive.
  if ! pr_state; then
    say "cannot re-read the head of ${repo}#${pr} after the checks; not trusting ${pin}"
    result="error"
    exit 1
  fi
  cur="$PR_HEAD"
  if [[ "$cur" != "$pin" ]]; then
    say "head moved after the last check: ${pin} -> ${cur}; nothing merged"
    result="head-moved"
    exit 4
  fi
fi

verified="$pin"
# Backstop for the loop's rule: an explicit --sha is the only commit that may be reported or merged.
if [[ -n "$want_sha" && "$verified" != "$want_sha" ]]; then
  verified=""
  say "verified commit is not the requested ${want_sha}; nothing merged"
  result="head-moved"
  exit 4
fi
say "verified ${verified}: green"

if [[ $merge -eq 0 ]]; then
  result="green"
  exit 0
fi

# What GitHub itself enforces on the base branch. The merge call is not atomic with the checks read above, so
# GitHub-enforced required status checks (branch protection or a ruleset) or a merge queue are the real lock.
# Sets PROT to covered, partial, none or unreadable. Context names cross as base64.
PROT=unreadable
PROT_MISSING=""
read_protection() {
  local base="$PR_BASE" rules classic line have_queue=0 got=0 n ctx
  local -A have=() anyapp=()
  PROT=unreadable
  PROT_MISSING=""
  [[ -n "$base" ]] || return 0
  if rules="$("$gh_bin" api "repos/${repo}/rules/branches/${base}" --jq '.[] | select(.type == "merge_queue" or .type == "required_status_checks") | if .type == "merge_queue" then "Q" else ((.parameters.required_status_checks // [])[] | "C " + ((.context // "") | tostring | @base64) + " " + (if .integration_id == null or .integration_id == -1 then "any" else (.integration_id | tostring) end)) end' 2>/dev/null)"; then
    got=1
  else
    rules=""
  fi
  if classic="$("$gh_bin" api "repos/${repo}/branches/${base}/protection/required_status_checks" --jq '(if ((.checks // []) | length) > 0 then .checks else (.contexts // [] | map({context: ., app_id: null})) end)[] | "C " + ((.context // "" | tostring) | @base64) + " " + (if .app_id == null or .app_id == -1 then "any" else (.app_id | tostring) end)' 2>/dev/null)"; then
    got=1
  else
    classic=""
  fi
  [[ $got -eq 1 ]] || return 0
  while IFS= read -r line; do
    if [[ "$line" == Q ]]; then
      have_queue=1
    elif [[ "$line" == "C "* ]]; then
      line="${line#C }"
      have["$line"]=1
      anyapp["${line%% *}"]=1
    fi
  done <<<"${rules}"$'\n'"${classic}"
  if [[ $have_queue -eq 1 ]]; then
    PROT=covered
    return 0
  fi
  if [[ ${#have[@]} -eq 0 ]]; then
    PROT=none
    return 0
  fi
  PROT=covered
  for ctx in "${contexts[@]}"; do
    n="$(enc "$ctx")"
    # A requirement counts when it names the app whose check run this script evaluates (--app-id), or names no app
    # at all (GitHub then accepts the name from any app, which includes that one), or --any-app was given.
    if [[ -z "${have["$n any"]:-}" && -z "${have["$n ${app_id}"]:-}" && ($any_app -eq 0 || -z "${anyapp[$n]:-}") ]]; then
      PROT=partial
      PROT_MISSING="${PROT_MISSING}'${ctx}' "
    fi
  done
}
check_protection() {
  read_protection
  case "$PROT" in
    covered) say "base branch ${PR_BASE}: GitHub enforces the required checks (or a merge queue); this script is the second line" ;;
    partial) say "WARNING: base branch ${PR_BASE} has required status checks, but none cover: ${PROT_MISSING}" ;;
    none) say "WARNING: base branch ${PR_BASE} has no required status checks and no merge queue; nothing GitHub enforces stops a check that turns red at merge time" ;;
    *) say "WARNING: could not read the required status checks of the base branch; assume GitHub enforces none" ;;
  esac
  if [[ "$PROT" != covered && $require_protection -eq 1 ]]; then
    say "--require-protection: the base branch does not enforce the required checks; nothing merged"
    result="error"
    exit 1
  fi
}
check_protection

# Merge-time recheck, run before EVERY merge attempt (the first and each retry): read the check runs on the pinned
# head again and apply the same all-green rule. A check that is new, open or red since the settled poll aborts;
# nothing is merged.
merge_recheck() {
  local rc=0
  read_world "$pin" || rc=$?
  if [[ $rc -ne 0 ]]; then
    say "cannot re-read the check runs of ${pin} right before the merge; nothing merged"
    result="error"
    exit 1
  fi
  suites_a="$W_A"
  suites_b="$W_B"
  if [[ $W_SUITE_FAILED -eq 1 || "$W_A" != "$settled_a" || "$W_B" != "$settled_b" ]]; then
    say "the check suites changed or could not be read right before the merge; nothing merged"
    result="other-red"
    exit 6
  fi
  evaluate "$W_LINES"
  if [[ "$verdict" == red ]]; then
    say "red right before the merge: ${detail}"
    result="red"
    exit 1
  fi
  if [[ "$verdict" != green || "$(fingerprint "$W_LINES")" != "$settle_fp" ]]; then
    say "the check runs changed right before the merge (${detail}); nothing merged"
    result="other-red"
    exit 6
  fi
}

# What gh says when a branch policy, not the code, is what stands in the way. Everything else
# (a conflict, a closed pull request, a 403) is not retried. Messages seen in the maintainer's merge
# logs (GYST #218 and another repository): "the base branch policy prohibits the merge"; GitHub's
# wording for a missing required check: "Required status check ... is expected".
is_policy_block() {
  local m="${1,,}"
  [[ "$m" == *"base branch policy prohibits"* || "$m" == *"required status check"* ]]
}

# The pull request reads as merged (from one response): that is the verified commit's merge only when the head
# in that same response is the verified commit.
attribute_merge() {
  if [[ "$PR_HEAD" == "$verified" ]]; then
    merged="true"
    result="green"
    say "$1"
    exit 0
  fi
  say "${repo}#${pr} was merged at a different head (${PR_HEAD}, not the verified ${verified}); nothing is attributed to the verified commit"
  result="head-moved"
  exit 4
}

# After a merge call the pull request must be readable: an unreadable state (HTTP error, rate limit, malformed
# or invalid response) says nothing about whether it merged, so it is an error, never queued, merged or moved.
state_unreadable() {
  say "could not read the pull request after the merge call (${repo}#${pr}); the outcome is unknown, so it is reported neither as merged nor as queued"
  result="error"
  exit 1
}

attempt=0
last_err=""
while :; do
  attempt=$((attempt + 1))
  merge_recheck
  args=(pr merge "$pr" -R "$repo" --squash --match-head-commit "$verified")
  [[ $delete_branch -eq 1 ]] && args+=(--delete-branch)
  if "$gh_bin" "${args[@]}" >/dev/null 2>"$errfile"; then
    # gh can accept a merge that is only queued (merge queue, auto-merge), or that another push turned into
    # the merge of a different head: confirm from ONE response before reporting anything.
    if ! pr_state; then state_unreadable; fi
    if [[ "$PR_MERGED" == true ]]; then
      attribute_merge "merged ${repo}#${pr} (squash) at ${verified}"
    fi
    if [[ "$PR_HEAD" != "$verified" ]]; then
      say "head moved: ${repo}#${pr} is not merged and its head is ${PR_HEAD}, not the verified ${verified}"
      result="head-moved"
      exit 4
    fi
    # Only here, with merged=false observed at the verified head, is the merge known to be queued.
    result="queued"
    say "the merge of ${repo}#${pr} was accepted but the pull request is not merged (merge queue or auto-merge?); not reporting it as merged"
    exit 5
  fi
  full_err="$(redact "$(cat "$errfile")")"
  last_err="$(redact "$(grep -m1 . "$errfile" || true)")"
  say "merge attempt ${attempt} failed: ${last_err}"

  # Why did it fail: a push, a merge that landed anyway, or a block that may clear? One response answers
  # both questions (merged and head), so a merge is never tied to a head read earlier.
  if ! pr_state; then state_unreadable; fi
  if [[ "$PR_MERGED" == true ]]; then
    attribute_merge "${repo}#${pr} is already merged at ${verified}"
  fi
  if [[ "$PR_HEAD" != "$verified" ]]; then
    say "head moved before the merge: ${verified} -> ${PR_HEAD}; nothing merged"
    result="head-moved"
    exit 4
  fi
  if ! is_policy_block "$full_err"; then
    say "merge blocked: not a policy block, so it is not retried"
    result="merge-blocked"
    exit 1
  fi
  if [[ $attempt -gt $merge_retries ]]; then
    say "merge blocked: policy block still in place after ${attempt} attempts"
    result="merge-blocked"
    exit 1
  fi
  nap "$merge_retry_delay"
done
