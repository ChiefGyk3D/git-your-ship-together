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
#   * Other copies of the old pin are never silent. After the pins are rewritten (and in `status` and `--dry-run`), the
#     tracked files of a git checkout are searched for the old full 40-hex SHA as a whole word, and every hit outside
#     the rewritten workflow refs is listed as path:line (a test that asserts the pin, a script constant, a template).
#     `--also-update-literals` rewrites those exact copies too (and a `# vX.Y.Z` comment that directly follows the SHA (a closing quote may sit between),
#     nothing else), prints each rewrite, and never touches a binary file, a symlink, an untracked file, a longer hex
#     string that merely contains the SHA, or a release-history file (CHANGELOG*, HISTORY*, NEWS*, RELEASES*, RELEASE_NOTES*).
#     Without the flag the pins are rewritten, the copies are only listed, and the run exits 11.
#   * `pr` never merges and never enables auto-merge. `--watch` only waits (scripts/wait-ci.sh without --merge).
#
# Usage:
#   repin.sh status DIR...                       pinned against latest, with ages, per repository
#   repin.sh apply [--to TAG] [--dry-run] [--allow-input-changes] [--also-update-literals] DIR    rewrite the pins in DIR (default: the latest release)
#   repin.sh pr [--to TAG] [--base BRANCH] [--watch] [--allow-input-changes] [--also-update-literals] DIR
#                                                apply on a branch repin/gyst-<tag>, push, open a pull request
#
# Files read: DIR/.github/workflows/*.yml and *.yaml, DIR/.github/actions/*/action.yml and *.yaml.
# Exit codes: 0 done or nothing to do (status: every pin is current); 10 status found a pin behind;
#   3 refused (see the message); 5 an input the caller uses changed; 4 the pin-only check failed; 64 bad usage; 1 anything else (no release, gh error);
#   11 apply or pr rewrote the pins but literal copies of the old SHA remain outside the workflows (listed; rerun with --also-update-literals).
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

# --- other copies of the old pin ---------------------------------------------------------------------------------
# A pin can live outside the workflows too: a test that asserts it, a script constant, a template. A re-pin that
# leaves them behind fails the caller's own checks. These helpers find and (only on request) rewrite the exact copies.

# history_file PATH: success for a release-history file, whose old SHAs are a record and never rewritten.
history_file() {
  local base=${1##*/}
  base=${base^^}
  case $base in CHANGELOG* | HISTORY* | NEWS* | RELEASES* | RELEASE_NOTES* | RELEASE-NOTES*) return 0 ;; esac
  return 1
}

# literal_scan DIR NEWSHA OUT: for each pinned SHA other than NEWSHA, the tracked text files of DIR (a git checkout;
# any other directory is skipped) that hold it as a whole word, outside the canonical workflow pin lines, as
# `sha<TAB>tag<TAB>path<TAB>line` in OUT. Binary files (git grep -I), symlinks, untracked files and history files are
# left out; history files are noted on stdout.
#
# A file name is data. Only names made of [A-Za-z0-9._/-] (what check_names allows for workflow paths) are listed,
# rewritten or echoed anywhere; any other name is skipped and only counted in UNSAFE (a count, never the name).
UNSAFE=0
declare -A UNSAFE_SEEN
literal_scan() {
  local dir=$1 newsha=$2 out=$3 file line sha tag f n
  declare -A old pinned
  : >"$out"
  UNSAFE=0
  UNSAFE_SEEN=()
  git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  while IFS=$'\t' read -r file line sha tag _; do
    pinned["${file#"$dir"/}:$line"]=1
    [ "$sha" = "$newsha" ] || old[$sha]=$tag
  done < <(pins "$dir")
  for sha in "${!old[@]}"; do
    tag=${old[$sha]}
    while IFS= read -r -d '' f; do
      if ! [[ $f =~ ^[A-Za-z0-9._/-]+$ ]]; then
        UNSAFE_SEEN[$f]=1
        UNSAFE=${#UNSAFE_SEEN[@]}
        continue
      fi
      [ -L "$dir/$f" ] && continue
      while IFS=: read -r n _; do
        [ -z "${pinned["$f:$n"]:-}" ] || continue
        if history_file "$f"; then
          echo "left alone (release history): $f:$n"
          continue
        fi
        printf '%s\t%s\t%s\t%s\n' "$sha" "$tag" "$f" "$n" >>"$out"
      done < <(grep -n -I -w -F -e "$sha" -- "$dir/$f" || true)
    done < <(git -C "$dir" grep -z -l -I -w -F -e "$sha" || true)
  done
  sort -t$'\t' -k3,3 -k4,4n -o "$out" "$out"
}

# literal_lines HITS: the hits as `  path:line (sha12, tag)`.
literal_lines() {
  awk -F'\t' '{ printf "  %s:%s (%s, %s)\n", $3, $4, substr($1, 1, 12), $2 }' "$1"
}

# literal_unsafe_note: how many files with unsafe names were skipped, as a count only; nothing when none.
literal_unsafe_note() {
  [ "$UNSAFE" -gt 0 ] || return 0
  echo "$UNSAFE file(s) with unsafe names skipped (not listed, not rewritten; fix them by hand)"
}

# literal_report HITS: the hits, then the skipped count; prints nothing when there is neither.
literal_report() {
  if [ -s "$1" ]; then
    echo "copies of the old pin outside the workflow refs ($(wc -l <"$1")):"
    literal_lines "$1"
  fi
  literal_unsafe_note
}

# literal_rewrite DIR NEWSHA NEWTAG HITS DRY LIST: rewrite (DRY=1: only print the diff of) the exact copies named in
# HITS; the changed paths (relative to DIR) go to the file LIST. A copy is the whole-word old SHA; the `# vX.Y.Z`
# comment is changed only where it directly follows that SHA.
literal_rewrite() {
  local dir=$1 newsha=$2 newtag=$3 hits=$4 dry=$5 list=$6 tmp f sha tag etag n=0 before after verb
  local -a exprs
  : >"$list"
  mktmp tmp -d
  verb=rewrote
  [ "$dry" = 1 ] && verb="would rewrite"
  while IFS= read -r f; do
    exprs=()
    while IFS=$'\t' read -r sha tag; do
      etag=${tag//./\\.}
      exprs+=(-e "s/\\b$sha\\b([\"']?[[:space:]]+#[[:space:]]*)$etag(\\.([^0-9]|\$)|[^0-9A-Za-z.]|\$)/$newsha\\1$newtag\\2/g" -e "s/\\b$sha\\b/$newsha/g")
    done < <(F="$f" awk -F'\t' '$3 == ENVIRON["F"] { print $1 "\t" $2 }' "$hits" | sort -u)
    [ "${#exprs[@]}" -gt 0 ] || continue
    n=$((n + 1))
    sed -E "${exprs[@]}" -- "$dir/$f" >"$tmp/$n.new"
    cmp -s "$dir/$f" "$tmp/$n.new" && continue
    before=$(wc -l <"$dir/$f")
    after=$(wc -l <"$tmp/$n.new")
    [ "$before" = "$after" ] || die 4 "the rewrite of $f changed its line count; nothing more was written"
    if [ "$dry" = 1 ]; then
      diff -u "$dir/$f" "$tmp/$n.new" || true
    else
      cat "$tmp/$n.new" >"$dir/$f"
    fi
    F="$f" awk -F'\t' -v v="$verb" -v n="$newtag" \
      '$3 == ENVIRON["F"] { printf "%s %s:%s (%s -> %s)\n", v, $3, $4, substr($1, 1, 12), n }' "$hits" | sort -u
    printf '%s\n' "$f" >>"$list"
  done < <(cut -f3 "$hits" | sort -u)
}

cmd_status() {
  [ $# -ge 1 ] || usage
  local dir latest behind=0 refused=0 list tag n sha note lits
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
    mktmp lits
    literal_scan "$dir" "${TAG_SHA[$latest]}" "$lits"
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
    literal_report "$lits"
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
  local to="" dry=0 allow=0 lit=0 dir="" changed list lits lchanged lrc=0
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
      --also-update-literals)
        lit=1
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
  mktmp list
  mktmp lits
  mktmp lchanged
  literal_scan "$dir" "${TAG_SHA[$to]}" "$lits"
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
  if [ -s "$lits" ] || [ "$UNSAFE" -gt 0 ]; then
    if [ "$lit" = 1 ]; then
      [ ! -s "$lits" ] || literal_rewrite "$dir" "${TAG_SHA[$to]}" "$to" "$lits" "$dry" "$lchanged"
      literal_unsafe_note
    else
      literal_report "$lits"
      echo "these copies were not changed; rerun with --also-update-literals to rewrite them"
    fi
    # exit 11: copies of the old SHA remain (all of them without the flag; the unsafe-named ones with it)
    if [ "$lit" != 1 ] || [ "$UNSAFE" -gt 0 ]; then lrc=11; fi
  fi
  return "$lrc"
}

cmd_pr() {
  local to="" base="" watch=0 allow=0 lit=0 dir="" start branch open changed list notes body f count url lits lchanged lrc=0
  local -a files=() lfiles=()
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
      --also-update-literals)
        lit=1
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
  mktmp lits
  mktmp lchanged
  literal_scan "$dir" "${TAG_SHA[$to]}" "$lits"
  rewrite "$dir" "$to" 0 "$list" "$allow" "$notes"
  changed=$(cat "$list")
  if [ -z "$changed" ]; then
    echo "up to date: every pin in $dir is already $to"
    return 0
  fi
  while IFS= read -r f; do files+=("${f#"$dir"/}"); done <<<"$changed"
  count=$(git -C "$dir" diff --numstat -- "${files[@]}" | awk '{ n += $1 } END { print n + 0 }')
  if [ "$lit" = 1 ] && [ -s "$lits" ]; then
    literal_rewrite "$dir" "${TAG_SHA[$to]}" "$to" "$lits" 0 "$lchanged"
    while IFS= read -r f; do lfiles+=("$f"); done <"$lchanged"
  fi
  if [ -s "$lits" ] || [ "$UNSAFE" -gt 0 ]; then
    literal_unsafe_note
    if [ "$lit" != 1 ] || [ "$UNSAFE" -gt 0 ]; then lrc=11; fi
  fi
  mktmp body
  {
    echo "Pin-only re-pin of the reusable workflows from \`$SRC\` to \`$to\`."
    echo
    echo "It changes the pin SHA and the \`# vX.Y.Z\` comment on $count line(s) in ${#files[@]} file(s), and nothing else:"
    echo
    printf -- '- `%s`\n' "${files[@]}"
    echo
    if [ "${#lfiles[@]}" -gt 0 ]; then
      echo "With \`--also-update-literals\` it also rewrote exact copies of the old pin SHA (and a \`# vX.Y.Z\` comment directly after it) outside the workflows:"
      echo
      printf -- "- \`%s\`\n" "${lfiles[@]}"
      echo
    elif [ -s "$lits" ]; then
      echo "Copies of the old pin SHA remain outside the workflows and were NOT changed (rerun with \`--also-update-literals\`); this pull request's checks may fail on them:"
      echo
      literal_lines "$lits" | sed 's/^  /- /'
      echo
    fi
    if [ "$UNSAFE" -gt 0 ]; then
      echo "- $(literal_unsafe_note)"
      echo
    fi
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
  git -C "$dir" add -- "${files[@]}" "${lfiles[@]}"
  git -C "$dir" commit -q -m "Re-pin git-your-ship-together to $to" -m "Pin-only: the commit SHA and the version comment of each reference, nothing else.${lfiles[*]:+ Plus exact copies of the old SHA in: ${lfiles[*]}.}"
  git -C "$dir" push -q origin "$branch"
  url=$(cd "$dir" && "$gh_bin" pr create --base "$base" --head "$branch" --title "Re-pin git-your-ship-together to $to" --body-file "$body")
  echo "opened $url"
  git -C "$dir" switch -q "$start"
  if [ "$watch" = 1 ]; then
    bash "$here/wait-ci.sh" --repo "$(cd "$dir" && "$gh_bin" repo view --json nameWithOwner --jq .nameWithOwner)" \
      --pr "${url##*/}" --sha "$(git -C "$dir" rev-parse "$branch")"
  fi
  return "$lrc"
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
