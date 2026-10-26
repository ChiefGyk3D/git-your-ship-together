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
#   5   queued: the merge was accepted but the pull request is not merged yet (merge queue or auto-merge)
#   64  usage error (bad flag or value); nothing was waited on
#
# Usage:
#   wait-ci.sh --repo OWNER/REPO (--pr N | --sha SHA) [options]
#
# Options (defaults in brackets):
#   --repo OWNER/REPO       repository [$GITHUB_REPOSITORY]
#   --pr N                  pull request to watch; its head is pinned and re-read, and --merge needs it
#   --sha SHA               commit to verify; with --pr it must equal the head, else exit 4
#   --context NAME          required check run name, exact match; repeatable ["CI green"]; '' for none
#   --min-checks N          check runs that must be complete [1]
#   --timeout S             total seconds to wait [1800]
#   --hung-after S          seconds without any check changing before exit 3 [600]
#   --interval S            seconds between polls, at least 1 [20]; repeated gh errors back off to 8x
#   --app-id N              GitHub App id whose check runs may satisfy a context [15368]
#   --any-app               accept a same-named run from any app (prints a warning)
#   --on-push abort|reset   what a moved head does [abort]; reset is ignored when --sha is given
#   --merge                 squash-merge the verified SHA once green (needs --pr)
#   --delete-branch         with --merge, delete the head branch
#   --merge-retries N       retries after a policy-blocked merge attempt [5]
#   --merge-retry-delay S   seconds between merge attempts [30]
#
# Environment: GH_TOKEN (read by gh; checks: read and pull-requests: read, plus contents: write and
# pull-requests: write for --merge), GH_BIN (the gh command, default gh; tests point it at a fake),
# GITHUB_OUTPUT (when set, result, sha and merged are appended for a composite action).
set -euo pipefail

gh_bin="${GH_BIN:-gh}"
repo="${GITHUB_REPOSITORY:-}"
pr=""
want_sha=""
contexts=()
contexts_given=0
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

need_value() { [[ $# -ge 2 ]] || die_usage "$1 needs a value"; }
need_int() { [[ "$2" =~ ^[0-9]+$ ]] || die_usage "$1 must be a whole number (got '$2')"; }

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

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die_usage "--repo must be OWNER/REPO (got '${repo}')"
case "${repo%%/*}" in . | ..) die_usage "--repo owner must not be . or .." ;; esac
case "${repo##*/}" in . | ..) die_usage "--repo name must not be . or .." ;; esac
if [[ -n "$pr" ]]; then need_int --pr "$pr"; fi
[[ -n "$pr" || -n "$want_sha" ]] || die_usage "give --pr N or --sha SHA"
if [[ -n "$want_sha" ]]; then
  [[ "$want_sha" =~ ^[0-9a-f]{40}$ ]] || die_usage "--sha must be a full 40-character lowercase commit SHA (got '${want_sha}')"
fi
need_int --min-checks "$min_checks"
need_int --timeout "$timeout_s"
need_int --hung-after "$hung_after"
need_int --interval "$interval"
[[ "$interval" -ge 1 ]] || die_usage "--interval must be at least 1 second"
need_int --app-id "$app_id"
need_int --merge-retries "$merge_retries"
need_int --merge-retry-delay "$merge_retry_delay"
[[ "$min_checks" -ge 1 ]] || die_usage "--min-checks must be at least 1: no check runs is never green"
case "$on_push" in
  abort | reset) ;;
  *) die_usage "--on-push must be abort or reset (got '${on_push}')" ;;
esac
if [[ $merge -eq 1 && -z "$pr" ]]; then die_usage "--merge needs --pr"; fi
for c in "${contexts[@]}"; do
  case "$c" in
    *$'\n'*) die_usage "a --context must be one line" ;;
  esac
done

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

# A commit SHA from the API is used (and written to GITHUB_OUTPUT) only when it is 40 hex digits.
pr_head() {
  local h
  h="$(gh_try api "repos/${repo}/pulls/${pr}" --jq '.head.sha')" || return 1
  if [[ ! "$h" =~ ^[0-9a-f]{40}$ ]]; then
    say "the API returned something that is not a full commit SHA for ${repo}#${pr}" >&2
    return 1
  fi
  printf '%s' "$h"
}
pr_merged() { gh_try api "repos/${repo}/pulls/${pr}" --jq '.merged'; }

# One line per check run on a commit. Every field crosses as base64, so a hostile value (a name with
# a newline or the field separator in it) cannot add a line or a field: the line is five fields split
# by \x1f: status, conclusion, app id, hostile flag (1 when the name holds a control character, a
# DEL, NEL or a Unicode line or paragraph separator, NUL included), and the name.
check_lines() {
  gh_try api --paginate "repos/${repo}/commits/${1}/check-runs?per_page=100&filter=latest" \
    --jq '.check_runs[] | [(.status // "" | tostring | @base64), (.conclusion // "" | tostring | @base64), ((.app.id // 0) | tostring | @base64), (.name // "" | tostring | if explode | any(. < 32 or . == 127 or . == 133 or . == 8232 or . == 8233) then "1" else "0" end), (.name // "" | tostring | @base64)] | join("\u001f")'
}

b64d() { printf '%s' "$1" | base64 -d 2>/dev/null || true; }

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

start="$(now)"
last_change="$start"
last_sig=""
polls=0
fails=0

is_context() {
  local c
  for c in "${contexts[@]}"; do
    [[ "$1" == "$c" ]] && return 0
  done
  return 1
}

# Sets verdict (green|red|pending) and detail for the lines passed in.
evaluate() {
  local lines="$1" status conclusion app name c b_status b_conclusion b_app hostile_flag b_name
  foreign=0
  hostile=0
  local total=0 complete=0 bad=0 badname="" seen_ok seen_any
  local -A ctx_seen=() ctx_ok=() ctx_open=()
  while IFS=$'\x1f' read -r b_status b_conclusion b_app hostile_flag b_name; do
    [[ -n "$b_status$b_conclusion$b_app$hostile_flag$b_name" ]] || continue
    # Anything that is not exactly the shape jq emits is treated like a hostile name.
    if [[ ! "$hostile_flag" =~ ^[01]$ || ! "$b_status" =~ ^[A-Za-z0-9+/]*=*$ || ! "$b_conclusion" =~ ^[A-Za-z0-9+/]*=*$ ||
      ! "$b_app" =~ ^[A-Za-z0-9+/]*=*$ || ! "$b_name" =~ ^[A-Za-z0-9+/]*=*$ ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    if [[ "$hostile_flag" == 1 ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    status="$(b64d "$b_status")"
    conclusion="$(b64d "$b_conclusion")"
    app="$(b64d "$b_app")"
    name="$(b64d "$b_name")"
    if [[ ! "$status" =~ ^[a-z_]*$ || ! "$conclusion" =~ ^[a-z_]*$ || ! "$app" =~ ^[0-9]+$ || "$name" =~ [[:cntrl:]] ]]; then
      hostile=$((hostile + 1))
      continue
    fi
    # A run that carries a required name but comes from another app is ignored altogether.
    if [[ $any_app -eq 0 && "$app" != "$app_id" ]] && is_context "$name"; then
      foreign=$((foreign + 1))
      continue
    fi
    total=$((total + 1))
    if [[ "$status" == completed ]]; then
      complete=$((complete + 1))
      case "$conclusion" in
        failure | cancelled | timed_out | action_required | startup_failure | stale)
          bad=$((bad + 1))
          badname="${badname:-${name} (${conclusion})}"
          ;;
      esac
    fi
    for c in "${contexts[@]}"; do
      [[ "$name" == "$c" ]] || continue
      ctx_seen["$c"]=1
      if [[ "$status" != completed ]]; then
        ctx_open["$c"]=1
      elif [[ "$conclusion" != success ]]; then
        ctx_ok["$c"]=bad
      elif [[ "${ctx_ok[$c]:-}" != bad ]]; then
        ctx_ok["$c"]=ok
      fi
    done
  done <<<"$lines"

  verdict=pending
  if [[ $hostile -gt 0 ]]; then
    verdict=red
    detail="${hostile} check run(s) on ${pin} with a control character in the name or malformed fields; refusing (possible forgery)"
    return 0
  fi
  if [[ $foreign -gt 0 ]]; then
    say "ignored ${foreign} run(s) named like a required check from an app other than ${app_id}"
  fi
  if [[ $bad -gt 0 ]]; then
    verdict=red
    detail="${badname} on ${pin}"
    return 0
  fi
  if [[ $total -eq 0 ]]; then
    detail="no check runs on ${pin} yet"
    return 0
  fi
  seen_ok=1
  seen_any=""
  for c in "${contexts[@]}"; do
    if [[ -z "${ctx_seen[$c]:-}" ]]; then
      seen_ok=0
      seen_any="${seen_any}'${c}' not reported; "
    elif [[ -n "${ctx_open[$c]:-}" || "${ctx_ok[$c]:-}" != ok ]]; then
      seen_ok=0
      seen_any="${seen_any}'${c}' not finished; "
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
  verdict=green
  detail="${complete}/${total} runs complete, gate satisfied"
}

verdict=pending
detail=""
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
        last_sig=""
        last_change="$t"
      fi
    else
      poll_failed=1
    fi
  fi

  lines=""
  if lines="$(check_lines "$pin")"; then
    evaluate "$lines"
    sig="$(printf '%s\n' "$pin" "$lines" | LC_ALL=C sort | cksum)"
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
  if ! cur="$(pr_head)"; then
    say "cannot re-read the head of ${repo}#${pr} after the checks; not trusting ${pin}"
    result="error"
    exit 1
  fi
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

# What gh says when a branch policy, not the code, is what stands in the way. Everything else
# (a conflict, a closed pull request, a 403) is not retried. Messages seen in the maintainer's merge
# logs (GYST #218 and another repository): "the base branch policy prohibits the merge"; GitHub's
# wording for a missing required check: "Required status check ... is expected".
is_policy_block() {
  local m="${1,,}"
  [[ "$m" == *"base branch policy prohibits"* || "$m" == *"required status check"* ]]
}

attempt=0
last_err=""
while :; do
  attempt=$((attempt + 1))
  args=(pr merge "$pr" -R "$repo" --squash --match-head-commit "$verified")
  [[ $delete_branch -eq 1 ]] && args+=(--delete-branch)
  if "$gh_bin" "${args[@]}" >/dev/null 2>"$errfile"; then
    # gh can accept a merge that is only queued (merge queue, auto-merge): confirm before reporting it.
    if [[ "$(pr_merged || true)" == true ]]; then
      merged="true"
      result="green"
      say "merged ${repo}#${pr} (squash) at ${verified}"
      exit 0
    fi
    result="queued"
    say "the merge of ${repo}#${pr} was accepted but the pull request is not merged (merge queue or auto-merge?); not reporting it as merged"
    exit 5
  fi
  full_err="$(redact "$(cat "$errfile")")"
  last_err="$(redact "$(grep -m1 . "$errfile" || true)")"
  say "merge attempt ${attempt} failed: ${last_err}"

  # Why did it fail: a push, a merge that landed anyway, or a block that may clear?
  if cur="$(pr_head)" && [[ "$cur" != "$verified" ]]; then
    say "head moved before the merge: ${verified} -> ${cur}; nothing merged"
    result="head-moved"
    exit 4
  fi
  if [[ "$(pr_merged || true)" == true ]]; then
    merged="true"
    result="green"
    say "${repo}#${pr} is already merged at ${verified}"
    exit 0
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
