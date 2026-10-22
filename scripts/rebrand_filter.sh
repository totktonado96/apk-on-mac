#!/usr/bin/env bash
# rebrand_filter.sh -- the single rename transform (upstream name -> Apk on Mac).
#   rebrand_filter.sh FILE...     rewrite text files in place
#   rebrand_filter.sh --patch     filter a git format-patch from stdin to stdout
#   rebrand_filter.sh             filter stdin to stdout
# Never touches com.macapk, MACAPK_ or macapk-* (internal identifiers).
# Patterns use [x] classes so this file does not match (or rewrite) itself.
set -euo pipefail
PERL_SRC='
  s{[k]ksimp/Mac\.apk(?:-Releases)?}{totktonado96/apk-on-mac}g;
  s{https?://github\.com/[k]ksimp/dex2jvm}{the dex2jvm project}g;
  s{[K]aleb\@[v]oltare\.us}{https://t.me/baha_kabulov}gi;
  s{Mac\.apk\.app}{Apk on Mac.app}g;
  s{Mac\.apk}{Apk on Mac}g;
  s{org\.macapk\.}{io.github.totktonado96.apkonmac.}g;
  s{[K]aleb Simpson / [V]oltare}{the Apk on Mac maintainers}g;
  s{[K]aleb Simpson}{the Apk on Mac maintainers}g;
  s{\b[V]oltare\b}{ApkOnMac}g;
  s{\b[v]oltare\b}{apkonmac}g;
  s{\b[k]ksimp\b}{totktonado96}g;
'
PATCH_HDR='s{^From: .*$}{From: Apk on Mac <noreply\@users.noreply.github.com>} if $. == 2;'
case "${1:-}" in
  --patch) perl -pe "$PATCH_HDR $PERL_SRC" ;;
  "") perl -pe "$PERL_SRC" ;;
  *)
    files=()
    for f in "$@"; do
      case "$f" in */LICENSE|LICENSE|*THIRD_PARTY_NOTICES.txt|*rebrand_filter.sh) continue;; esac
      files+=("$f")
    done
    [ ${#files[@]} -eq 0 ] || perl -i -pe "$PERL_SRC" "${files[@]}" ;;
esac
