#!/usr/bin/env bash
# repin.sh: move a repository's pins of this repository's reusable workflows to a release.
#
# A caller pins `uses: ChiefGyk3D/git-your-ship-together/<path>@<40 hex> # vX.Y.Z`. A release reaches a caller
# only when the caller re-pins, and a re-pin is mechanical: the SHA of the release's commit and the version in
# the comment, nothing else. This script does exactly that, for one or many repositories, and can open the pull
# request. It never merges.
#
# Rules, each held by tests/test_repin.py:
#
#   * Pin-only. A pin line changes in two fields, the 40-hex SHA and the `# vX.Y.Z` comment. Before a file is
#     written, the old and new text are compared with both fields blanked out; any other difference stops the
#     run (exit 4) and writes nothing. Other repositories' actions, comments and every other byte are untouched.
#   * All or nothing. A reference to this repository that is not a canonical pin (a branch, a tag, a SHA with no
#     or an odd version comment) stops the run before anything is written (exit 3); so does a downgrade.
#   * Inputs are not changed under a caller: if the new release drops or retypes an input the caller sets, or adds a
#     required input it does not set, the run stops (exit 5) and lists them. --allow-input-changes overrides.
#   * The release is read from the GitHub API only: the tag name must be vMAJOR.MINOR.PATCH and the commit a
#     full 40-hex SHA, or the run stops. Nothing else is fetched, and no value from the API reaches a shell.
#   * A symlinked workflow file is reported and skipped, never followed.
#   * `pr` never merges and never enables auto-merge. `--watch` only waits (scripts/wait-ci.sh without --merge).
#
# Usage:
#   repin.sh status DIR...                       pinned against latest, with ages, per repository
#   repin.sh apply [--to TAG] [--dry-run] [--allow-input-changes] DIR    rewrite the pins in DIR (default: the latest release)
#   repin.sh pr [--to TAG] [--base BRANCH] [--watch] [--allow-input-changes] DIR
#                                                apply on a branch repin/gyst-<tag>, push, open a pull request
#
# Files read: DIR/.github/workflows/*.yml and *.yaml, DIR/.github/actions/*/action.yml and *.yaml.
# Exit codes: 0 done or nothing to do (status: every pin is current); 10 status found a pin behind;
#   3 refused (see the message); 5 an input the caller uses changed; 4 the pin-only check failed; 64 bad usage; 1 anything else (no release, gh error).
# Environment: GH_BIN (the gh command, default gh; tests point it at a fake), REPIN_NOW (an ISO time standing
#   in for now, tests only). GNU date and sed are required.
set -euo pipefail
export LC_ALL=C

SRC=ChiefGyk3D/git-your-ship-together
gh_bin="${GH_BIN:-gh}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

PIN_ERE='uses:[[:space:]]*ChiefGyk3D/git-your-ship-together/[A-Za-z0-9_./-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*$'
REF_ERE='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*ChiefGyk3D/git-your-ship-together/'
TAG_ERE='^v[0-9]+\.[0-9]+\.[0-9]+$'
SHA_ERE='^[0-9a-f]{40}$'

# Every temporary file or directory is registered here and removed on any exit.
TMPS=()
trap 'rm -rf -- "${TMPS[@]}"' EXIT
# mktmp NAME [mktemp args]: sets the variable NAME to a new temporary path (not in a subshell, so it registers).
mktmp() {
  local p
  p=$(mktemp "${@:2}") || exit 1
  TMPS+=("$p")
  printf -v "$1" '%s' "$p"
}

die() {
  local rc=$1
  shift
  echo "repin: $*" >&2
  exit "$rc"
}

usage() {
  sed -n '/^# Usage:/,/^# Files read/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

now_epoch() { date -u -d "${REPIN_NOW:-now}" +%s; }
epoch() { date -u -d "$1" +%s; }
days_old() { echo $((($(now_epoch) - $(epoch "$1")) / 86400)); }

declare -A TAG_SHA TAG_DATE

# tag_info TAG: fills TAG_SHA and TAG_DATE from the API, after checking both.
tag_info() {
  local tag=$1 line sha date
  [[ $tag =~ $TAG_ERE ]] || die 1 "refusing a release tag that is not vMAJOR.MINOR.PATCH: $(printf '%q' "$tag")"
  [ -n "${TAG_SHA[$tag]:-}" ] && return 0
  line=$("$gh_bin" api "repos/$SRC/commits/$tag" --jq '[.sha, .commit.committer.date] | @tsv') ||
    die 1 "no commit for $tag in $SRC"
  IFS=$'\t' read -r sha date <<<"$line"
  [[ $sha =~ $SHA_ERE ]] || die 1 "the API gave $tag a commit that is not 40 hex characters"
  [[ $date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] || die 1 "the API gave $tag a date that is not an ISO timestamp"
  TAG_SHA[$tag]=$sha
  TAG_DATE[$tag]=$date
}

latest_tag() {
  local tag
  tag=$("$gh_bin" api "repos/$SRC/releases/latest" --jq .tag_name) || die 1 "cannot read the latest release of $SRC"
  [[ $tag =~ $TAG_ERE ]] || die 1 "the latest release tag is not vMAJOR.MINOR.PATCH: $(printf '%q' "$tag")"
  printf '%s\n' "$tag"
}

# check_names DIR: refuse any workflow or action path (below DIR) outside [A-Za-z0-9._/-]. Run in the main shell
# before anything else reads the files, because a file name is data and must never become part of a program.
check_names() {
  local dir=$1 f rel
  for f in "$dir"/.github/workflows/* "$dir"/.github/actions/*/*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    rel=${f#"$dir"/}
    [[ $rel =~ ^[A-Za-z0-9._/-]+$ ]] || die 3 "refusing a workflow path with characters outside A-Za-z0-9._/-: $(printf '%q' "$rel")"
  done
}

# files_of DIR: the workflow and action files, one per line; a symlink is reported and left out.
files_of() {
  local dir=$1 f
  for f in "$dir"/.github/workflows/*.yml "$dir"/.github/workflows/*.yaml "$dir"/.github/actions/*/action.yml "$dir"/.github/actions/*/action.yaml; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ -L "$f" ]; then
      echo "repin: skipping a symlink, never followed: $f" >&2
      continue
    fi
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}

# non_canonical DIR: lines naming this repository that are not canonical pins, as `file:line: text`.
non_canonical() {
  local f
  while IFS= read -r f; do
    { grep -nE "$REF_ERE" "$f" || true; } | { grep -vE "$PIN_ERE" || true; } | F="$f" awk '{ print ENVIRON["F"] ":" $0 }'
  done < <(files_of "$1")
}

# pins DIR: `file<TAB>line<TAB>sha<TAB>tag<TAB>path` for each canonical pin (path: what follows the repository name).
pins() {
  local f
  while IFS= read -r f; do
    { grep -nE "^[[:space:]]*(-[[:space:]]+)?$PIN_ERE" "$f" || true; } |
      sed -E 's|^([0-9]+):.*git-your-ship-together/([A-Za-z0-9_./-]+)@([0-9a-f]{40})[[:space:]]+#[[:space:]]*(v[0-9]+\.[0-9]+\.[0-9]+).*$|\1\t\3\t\4\t\2|' |
      F="$f" awk -F'\t' '{ print ENVIRON["F"] "\t" $1 "\t" $2 "\t" $3 "\t" $4 }'
  done < <(files_of "$1")
}

# norm FILE: the file with each pin's SHA and version blanked, to prove a rewrite changed nothing else.
norm() {
  sed -E 's#(uses:[[:space:]]*ChiefGyk3D/git-your-ship-together/[A-Za-z0-9_./-]+@)[0-9a-f]{40}([[:space:]]+\#[[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+#\1PIN\2VER#' "$1"
}

# tag_known TAG: success when the release exists (fills the caches); never exits.
tag_known() {
  (tag_info "$1") >/dev/null 2>&1 || return 1
  tag_info "$1"
}

# --- the input check ---------------------------------------------------------------------------------------------
# A re-pin must not change what a caller passes. For each pin that moves, the called workflow (or composite action)
# is read at the old and at the new commit, and the inputs it declares are compared with the `with:` keys the caller
# sets. Refused (exit 5): a key the caller sets that the new release no longer declares or whose type changed, and a
# new required input (no default) the caller does not set. Only noted, in the pull request: a default that changed
# for an input the caller does not set. A definition that cannot be read or parsed is refused, never skipped.
# The parser reads the layout this repository's workflows use (one scalar per line, or a block scalar), not all YAML.

# inputs_of FILE: name, type, default and required of each declared input, separated by the control character
# 0x1f (not a tab, because `read` merges a run of tabs and would lose an empty field).
inputs_of() {
  awk '
    function ind(s) { match(s, /^ */); return RLENGTH }
    function flush() { if (cur != "") print cur "\037" ty "\037" df "\037" rq; cur = ""; ty = df = rq = "" }
    function clean(v) { sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2); return v }
    /^[ \t]*(#|$)/ { next }
    {
      i = ind($0)
      if (blk != "") {
        if (i > bi) { acc = acc " " clean($0); next }
        if (blk == "default") df = clean(acc)
        blk = ""
      }
      if (mode == 2 && i <= ii) { flush(); mode = (i > wc ? 1 : 0); ni = -1; ci = -1 }
      if (mode == 1 && i <= wc) mode = 0
      if (mode == 0 && $0 ~ /^ *workflow_call:/) { wc = i; mode = 1; next }
      if (mode == 0 && $0 ~ /^inputs:/) { wc = -1; ii = 0; mode = 2; ni = -1; ci = -1; next }
      if (mode == 1 && $0 ~ /^ *inputs:/) { ii = i; mode = 2; ni = -1; ci = -1; next }
      if (mode != 2) next
      if (ni < 0) ni = i
      if (i == ni && match($0, /^ *[A-Za-z0-9_-]+:/)) {
        flush()
        cur = $0; sub(/^ */, "", cur); sub(/:.*$/, "", cur); ci = -1
        next
      }
      if (i > ni) {
        if (ci < 0) ci = i
        if (i == ci && match($0, /^ *(type|default|required):/)) {
          k = $0; sub(/^ */, "", k); sub(/:.*$/, "", k)
          v = $0; sub(/^[^:]*:/, "", v); v = clean(v)
          if (v ~ /^[|>][-+]?$/) { blk = k; bi = i; acc = ""; next }
          if (k == "type") ty = v; else if (k == "default") df = v; else rq = v
        }
      }
    }
    END { if (blk == "default") df = clean(acc); flush() }
  ' "$1"
}

# with_keys FILE LINE: the keys of the `with:` block that belongs to the `uses:` on LINE (same job or step).
with_keys() {
  awk -v L="$2" '
    function ind(s) { match(s, /^ */); return RLENGTH }
    function skip(s) { return s ~ /^[ \t]*(#|$)/ }
    { lines[NR] = $0 }
    END {
      P = index(lines[L], "uses:") - 1
      a = L
      while (a > 1 && (skip(lines[a - 1]) || ind(lines[a - 1]) >= P)) a--
      b = L
      while (b < NR && (skip(lines[b + 1]) || ind(lines[b + 1]) >= P)) b++
      for (n = a; n <= b; n++) if (!skip(lines[n]) && ind(lines[n]) == P && lines[n] ~ /^ *with:[ \t]*$/) { w = n; break }
      if (!w) exit
      ci = -1
      for (n = w + 1; n <= b; n++) {
        if (skip(lines[n])) continue
        i = ind(lines[n])
        if (i <= P) break
        if (ci < 0) ci = i
        if (i == ci && match(lines[n], /^ *[A-Za-z0-9_-]+:/)) { k = lines[n]; sub(/^ */, "", k); sub(/:.*$/, "", k); print k }
      }
    }
  ' "$1"
}

# fetch_def PATH SHA OUTFILE: the declaration file of a called workflow or action at a commit.
fetch_def() {
  local p=$1 sha=$2 out=$3
  case $p in *.yml | *.yaml) ;; *) p="$p/action.yml" ;; esac
  case $p in *..* | /*) return 1 ;; esac
  # ref rides in the query string: -f would make gh send a POST, which the contents endpoint rejects.
  "$gh_bin" api "repos/$SRC/contents/$p?ref=$sha" -H 'Accept: application/vnd.github.raw' >"$out" 2>/dev/null
}

# check_inputs DIR TAG ALLOW NOTES: exit 5 on a refused change unless ALLOW is 1; appends the findings to NOTES.
check_inputs() {
  local dir=$1 tag=$2 allow=$3 notes=$4 newsha=${TAG_SHA[$2]} file line sha otag path
  local oldf newf problems=0 name used
  declare -A odef ndef
  mktmp oldf
  mktmp newf
  while IFS=$'\t' read -r file line sha otag path; do
    [ "$sha" != "$newsha" ] || continue
    if ! fetch_def "$path" "$sha" "$oldf" || ! fetch_def "$path" "$newsha" "$newf"; then
      echo "repin: cannot read $path at the old pin ($otag) or at $tag, so its inputs cannot be compared ($file:$line)" >&2
      problems=1
      continue
    fi
    odef=() ndef=() used=" "
    while IFS=$'\037' read -r name ty df rq; do odef[$name]="$ty|$df|$rq"; done < <(inputs_of "$oldf")
    while IFS=$'\037' read -r name ty df rq; do ndef[$name]="$ty|$df|$rq"; done < <(inputs_of "$newf")
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      used="$used$name "
      if [ -z "${ndef[$name]:-}" ] && [ -z "${odef[$name]:-}" ]; then continue; fi
      if [ -z "${ndef[$name]:-}" ]; then
        echo "repin: $file:$line $path: input $name is set by the caller but $tag no longer declares it" >&2
        problems=1
      elif [ -n "${odef[$name]:-}" ] && [ "${odef[$name]%%|*}" != "${ndef[$name]%%|*}" ]; then
        echo "repin: $file:$line $path: input $name changed type from '${odef[$name]%%|*}' to '${ndef[$name]%%|*}' in $tag" >&2
        problems=1
      fi
    done < <(with_keys "$file" "$line")
    for name in "${!ndef[@]}"; do
      case $used in *" $name "*) continue ;; esac
      IFS='|' read -r _ ndf nrq <<<"${ndef[$name]}"
      IFS='|' read -r _ odf orq <<<"${odef[$name]:-||}"
      if [ "$nrq" = true ] && [ -z "$ndf" ] && { [ -z "${odef[$name]:-}" ] || [ "$orq" != true ]; }; then
        echo "repin: $file:$line $path: $tag adds the required input $name, which the caller does not set" >&2
        problems=1
      elif [ -n "${odef[$name]:-}" ] && [ "$odf" != "$ndf" ]; then
        echo "- \`$path\`: the default of \`$name\` (not set by this caller) changed from \`$odf\` to \`$ndf\`" >>"$notes"
      fi
    done
  done < <(pins "$dir")
  if [ "$problems" = 1 ]; then
    if [ "$allow" = 1 ]; then
      echo "repin: input changes listed above were allowed with --allow-input-changes" >&2
      echo "- input changes were allowed by the operator (--allow-input-changes); read the run log" >>"$notes"
    else
      die 5 "the new release changes inputs this caller uses (listed above); nothing was written. Read the changelog, adjust the caller, or pass --allow-input-changes"
    fi
  fi
}

cmd_status() {
  [ $# -ge 1 ] || usage
  local dir latest behind=0 refused=0 list tag n sha note
  latest=$(latest_tag)
  tag_info "$latest"
  for dir in "$@"; do
    [ -d "$dir/.github" ] || die 64 "not a repository with a .github directory: $dir"
    check_names "$dir"
    if [ -n "$(non_canonical "$dir")" ]; then
      echo "$dir: references to $SRC that are not canonical pins:"
      non_canonical "$dir" | sed 's/^/  /'
      refused=1
    fi
    list=$(pins "$dir")
    if [ -z "$list" ]; then
      echo "$dir: no GYST pins"
      continue
    fi
    echo "$dir: latest $latest (${TAG_DATE[$latest]%%T*}, $(days_old "${TAG_DATE[$latest]}") days old)"
    while IFS= read -r tag; do
      n=$(printf '%s\n' "$list" | awk -F'\t' -v t="$tag" '$4 == t' | wc -l)
      sha=$(printf '%s\n' "$list" | awk -F'\t' -v t="$tag" '$4 == t { print $3; exit }')
      note=""
      if tag_known "$tag"; then
        [ "${TAG_SHA[$tag]}" = "$sha" ] || note=" MISMATCH: the comment says $tag but that tag is ${TAG_SHA[$tag]:0:12} and the pin is ${sha:0:12}"
        printf '  %s x%s (%s, %s days old)' "$tag" "$n" "${TAG_DATE[$tag]%%T*}" "$(days_old "${TAG_DATE[$tag]}")"
      else
        printf '  %s x%s (no such release)' "$tag" "$n"
        note=" MISMATCH: no release of that name"
      fi
      if [ "$tag" = "$latest" ]; then
        [ -n "$note" ] && echo "$note" || echo " current"
      else
        behind=1
        echo " BEHIND$note"
      fi
    done < <(printf '%s\n' "$list" | awk -F'\t' '{ print $4 }' | sort -uV)
  done
  [ "$refused" = 0 ] || return 3
  [ "$behind" = 0 ] || return 10
}

# rewrite DIR TAG DRY LIST [ALLOW [NOTES]]: rewrite (or, when DRY is 1, only print the diff of) the pins of DIR to TAG. The
# changed files are written to the file LIST, one per line.
rewrite() {
  local dir=$1 tag=$2 dry=$3 list=$4 allow=${5:-0} notes=${6:-/dev/null} sha tmp f old n=0 i
  : >"$list"
  tag_info "$tag"
  sha=${TAG_SHA[$tag]}
  if [ -n "$(non_canonical "$dir")" ]; then
    echo "repin: these references to $SRC are not canonical pins (SHA plus # vX.Y.Z); fix them by hand first, nothing was written:" >&2
    non_canonical "$dir" | sed 's/^/  /' >&2
    exit 3
  fi
  while IFS=$'\t' read -r _ _ _ old _; do
    [ "$(printf '%s\n%s\n' "$old" "$tag" | sort -V | tail -1)" = "$tag" ] ||
      die 3 "refusing a downgrade: a pin says $old and the target is $tag (nothing was written)"
  done < <(pins "$dir")
  check_inputs "$dir" "$tag" "$allow" "$notes"
  mktmp tmp -d
  : >"$tmp/changed"
  while IFS= read -r f; do
    n=$((n + 1))
    sed -E "s#(uses:[[:space:]]*ChiefGyk3D/git-your-ship-together/[A-Za-z0-9_./-]+@)[0-9a-f]{40}([[:space:]]+\#[[:space:]]*)v[0-9]+\.[0-9]+\.[0-9]+#\1$sha\2$tag#" "$f" >"$tmp/$n.new"
    cmp -s "$f" "$tmp/$n.new" && continue
    cmp -s <(norm "$f") <(norm "$tmp/$n.new") || die 4 "the rewrite of $f changed more than the pin; nothing was written"
    printf '%s\t%s\n' "$n" "$f" >>"$tmp/changed"
  done < <(files_of "$dir")
  while IFS=$'\t' read -r i f; do
    if [ "$dry" = 1 ]; then
      diff -u "$f" "$tmp/$i.new" || true
    else
      cat "$tmp/$i.new" >"$f"
    fi
    printf '%s\n' "$f" >>"$list"
  done <"$tmp/changed"
}

cmd_apply() {
  local to="" dry=0 allow=0 dir="" changed list
  while [ $# -gt 0 ]; do
    case $1 in
      --to)
        [ $# -ge 2 ] || usage
        to=$2
        shift 2
        ;;
      --dry-run)
        dry=1
        shift
        ;;
      --allow-input-changes)
        allow=1
        shift
        ;;
      -*) usage ;;
      *)
        [ -z "$dir" ] || usage
        dir=$1
        shift
        ;;
    esac
  done
  [ -n "$dir" ] || usage
  [ -d "$dir/.github" ] || die 64 "not a repository with a .github directory: $dir"
  check_names "$dir"
  [ -n "$to" ] || to=$(latest_tag)
  mktmp list
  rewrite "$dir" "$to" "$dry" "$list" "$allow"
  changed=$(cat "$list")
  if [ -z "$changed" ]; then
    echo "up to date: every pin in $dir is already $to"
  elif [ "$dry" = 1 ]; then
    echo "dry run: $(printf '%s\n' "$changed" | wc -l) file(s) would change to $to; nothing written"
  else
    echo "re-pinned to $to:"
    printf '%s\n' "$changed" | sed 's/^/  /'
  fi
}

cmd_pr() {
  local to="" base="" watch=0 allow=0 dir="" start branch open changed list notes body f count url
  local -a files=()
  while [ $# -gt 0 ]; do
    case $1 in
      --to)
        [ $# -ge 2 ] || usage
        to=$2
        shift 2
        ;;
      --base)
        [ $# -ge 2 ] || usage
        base=$2
        shift 2
        ;;
      --watch)
        watch=1
        shift
        ;;
      --allow-input-changes)
        allow=1
        shift
        ;;
      -*) usage ;;
      *)
        [ -z "$dir" ] || usage
        dir=$1
        shift
        ;;
    esac
  done
  [ -n "$dir" ] || usage
  [ -d "$dir/.github" ] || die 64 "not a repository with a .github directory: $dir"
  check_names "$dir"
  [ -n "$to" ] || to=$(latest_tag)
  tag_info "$to"
  branch="repin/gyst-$to"
  start=$(git -C "$dir" symbolic-ref --short HEAD) || die 3 "$dir is not on a branch"
  [ -n "$base" ] || base=$start
  [ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ] || die 3 "the working tree of $dir is not clean; commit or stash first"
  open=$(cd "$dir" && "$gh_bin" pr list --head "$branch" --state open --json number --jq '.[0].number // empty')
  if [ -n "$open" ]; then
    echo "a pull request for $branch is already open (#$open); nothing to do"
    return 0
  fi
  mktmp list
  mktmp notes
  rewrite "$dir" "$to" 0 "$list" "$allow" "$notes"
  changed=$(cat "$list")
  if [ -z "$changed" ]; then
    echo "up to date: every pin in $dir is already $to"
    return 0
  fi
  while IFS= read -r f; do files+=("${f#"$dir"/}"); done <<<"$changed"
  count=$(git -C "$dir" diff --numstat -- "${files[@]}" | awk '{ n += $1 } END { print n + 0 }')
  mktmp body
  {
    echo "Pin-only re-pin of the reusable workflows from \`$SRC\` to \`$to\`."
    echo
    echo "It changes the pin SHA and the \`# vX.Y.Z\` comment on $count line(s) in ${#files[@]} file(s), and nothing else:"
    echo
    printf -- '- `%s`\n' "${files[@]}"
    echo
    echo "- Release: https://github.com/$SRC/releases/tag/$to"
    echo "- Changelog: https://github.com/$SRC/blob/$to/CHANGELOG.md"
    echo
    if [ -s "$notes" ]; then
      echo "Notes for the reviewer (not blockers):"
      echo
      cat "$notes"
      echo
    fi
    echo "Opened by \`scripts/repin.sh\`. It does not merge; read the changelog entries since the old pin, then merge once CI is green."
  } >"$body"
  git -C "$dir" switch -q -c "$branch"
  git -C "$dir" add -- "${files[@]}"
  git -C "$dir" commit -q -m "Re-pin git-your-ship-together to $to" -m "Pin-only: the commit SHA and the version comment of each reference, nothing else."
  git -C "$dir" push -q origin "$branch"
  url=$(cd "$dir" && "$gh_bin" pr create --base "$base" --head "$branch" --title "Re-pin git-your-ship-together to $to" --body-file "$body")
  echo "opened $url"
  git -C "$dir" switch -q "$start"
  if [ "$watch" = 1 ]; then
    bash "$here/wait-ci.sh" --repo "$(cd "$dir" && "$gh_bin" repo view --json nameWithOwner --jq .nameWithOwner)" \
      --pr "${url##*/}" --sha "$(git -C "$dir" rev-parse "$branch")"
  fi
}

[ $# -ge 1 ] || usage
sub=$1
shift
case $sub in
  status) cmd_status "$@" ;;
  apply) cmd_apply "$@" ;;
  pr) cmd_pr "$@" ;;
  *) usage ;;
esac
