#!/usr/bin/env bash
# port_upstream.sh -- port new upstream commits onto this (unrelated-history) repo.
# For each upstream commit after .upstream-sync, oldest first: format-patch, run it
# through scripts/rebrand_filter.sh --patch, git am -3. Failures are recorded, not fatal.
# Writes the PR body to $PORT_BODY (default port_body.md) and prints PORTED=<n> FAILED=<n>.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/kksimp/Mac.apk.git}"
BODY="${PORT_BODY:-port_body.md}"
# Files we deleted on purpose; patches touching only these are skipped.
SKIP_RE='^(CLA\.md|COMMERCIAL\.md|TRADEMARKS\.md|signatures/.*|\.github/workflows/cla\.yml)$'

last="$(tr -d '[:space:]' < .upstream-sync)"
git fetch --quiet --filter=blob:none "$UPSTREAM_URL" main:refs/upstream/main || { echo "fetch failed"; exit 1; }
head_sha="$(git rev-parse refs/upstream/main)"
ported=(); failed=(); skipped=()
tmp="$(mktemp)"

for sha in $(git rev-list --reverse --no-merges "$last..$head_sha"); do
  subj="$(git log -1 --format=%s "$sha")"
  keep=0
  while IFS= read -r f; do [[ "$f" =~ $SKIP_RE ]] || keep=1; done < <(git diff-tree --no-commit-id --name-only -r "$sha")
  if [ "$keep" = 0 ]; then skipped+=("${sha:0:10} $subj"); continue; fi
  git format-patch -1 --stdout "$sha" | scripts/rebrand_filter.sh --patch > "$tmp"
  if git am -3 --quiet < "$tmp" 2>/dev/null; then
    ported+=("${sha:0:10} $subj")
  else
    git am --abort 2>/dev/null || true
    failed+=("${sha:0:10} $subj")
  fi
done
rm -f "$tmp"

if [ "$head_sha" != "$last" ]; then echo "$head_sha" > .upstream-sync; fi
{
  echo "Automated port of upstream commits ($last..$head_sha), rebranded."
  echo; echo "### Ported (${#ported[@]})"; for l in "${ported[@]}"; do echo "- $l"; done
  echo; echo "### Needs manual port (${#failed[@]})"; for l in "${failed[@]}"; do echo "- $l"; done
  echo; echo "### Skipped, only touch removed files (${#skipped[@]})"; for l in "${skipped[@]}"; do echo "- $l"; done
} > "$BODY"
echo "PORTED=${#ported[@]} FAILED=${#failed[@]} SKIPPED=${#skipped[@]} HEAD=$head_sha"
