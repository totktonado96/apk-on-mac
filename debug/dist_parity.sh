#!/bin/bash
# Prove the release bundle and the dev bundle are the SAME product.
#
# Why: on 2026-08-21 an audit of the two pipelines found the release path
# (a) signed the runtime with an entitlements file lacking custom-x18-abi-toggle,
# (b) jlinked its own JRE without jdk.management (=> every release silently
#     reports 4 GiB of RAM), and
# (c) created Contents/Frameworks that the runtime-staging payload never copied,
#     so an INSTALLED app died at the first java.desktop touch while the control
#     panel launched fine.
# All three were SILENT. This script is the standing check that they stay fixed.
#
# Usage: debug/dist_parity.sh [dev-app] [dist-app]
set -uo pipefail
DEV="${1:-/Applications/Apk on Mac.app}"
DIST="${2:-build/dist/Apk on Mac.app}"
rc=0
say() { printf '%s\n' "$*"; }
[ -d "$DEV" ]  || { say "SKIP: no dev bundle at $DEV"; exit 0; }
[ -d "$DIST" ] || { say "SKIP: no dist bundle at $DIST (run scripts/build_dist.sh)"; exit 0; }

# `./CodeResources` (loose in Contents/, DER, not the _CodeSignature seal) is the
# STAPLED NOTARIZATION TICKET. It exists only on a notarized build and is absent
# from the dev bundle this diffs against, so it is an expected extra -- not a
# divergence. Before 2026-08-23 it failed this check on every notarized release.
say "== (a) file-set parity (expected extras: _CodeSignature, Frameworks, staple ticket) =="
d=$(diff <(cd "$DEV/Contents" && find . -type f | sort) \
         <(cd "$DIST/Contents" && find . -type f | sort) \
    | grep -vE '_CodeSignature|/Frameworks/|^> \./CodeResources$' | grep -E '^[<>]' || true)
[ -z "$d" ] && say "  ok" || { say "$d" | head -20; rc=1; }

say "== (b) JRE module parity (jdk.management is the load-bearing one) =="
for b in "$DEV" "$DIST"; do
  grep -q "jdk.management" "$b/Contents/Resources/jre/release" 2>/dev/null \
    && say "  ok   jdk.management in $b" || { say "  FAIL missing jdk.management in $b"; rc=1; }
done

say "== (c) every Mach-O in the dist bundle is signed =="
# ⚠ THIS CHECK WAS INVERTED until 2026-08-23. It grepped `codesign -dv` output
# for the literal "Signature=", which matches ONLY the ad-hoc spelling
# (`Signature=adhoc`). A real Developer ID signature prints `Signature size=NNNN`,
# which does not contain that substring -- so the gate passed ad-hoc builds and
# reported EVERY properly signed binary in a release build as UNSIGNED. Measured:
# `grep -c "Signature="` is 0 on a binary that `codesign --verify --strict` calls
# valid, and the script contradicted itself by calling macapk-runtime UNSIGNED
# four lines before reporting its entitlements ok.
# Ask codesign for a verdict instead of pattern-matching its prose.
u=$(find "$DIST/Contents" -type f -exec sh -c \
  'file -b "$1" 2>/dev/null | grep -q "^Mach-O" || exit 0
   codesign --verify --strict "$1" >/dev/null 2>&1 || echo "  UNSIGNED: $1"' _ {} \; )
[ -z "$u" ] && say "  ok" || { say "$u"; rc=1; }

say "== (d) entitlement parity on the binaries that run guest code =="
for rel in Resources/macapk-runtime bin/macapk-elfexec; do
  [ -f "$DIST/Contents/$rel" ] || continue
  "$(dirname "$0")/entitlements_check.sh" "$DIST/Contents/$rel" >/dev/null 2>&1 \
    && say "  ok   $rel" || { say "  FAIL $rel is missing entitlements"; rc=1; }
done

say "== (e) every @rpath dep resolves under a STAGED-ROOT view (the Frameworks trap) =="
say "  (staging copies only RuntimeInstall.payload + payloadDirs, NOT the whole bundle)"
STAGE=$(mktemp -d)
for d in Resources/jre Resources/tools Frameworks lib/java_base_patch lib/jdk_unsupported_patch; do
  [ -d "$DIST/Contents/$d" ] && ditto "$DIST/Contents/$d" "$STAGE/$d" 2>/dev/null
done
miss=$(find "$STAGE" -name '*.dylib' -exec sh -c \
  'otool -L "$1" 2>/dev/null | grep -oE "@rpath/[^ ]+" | while read -r r; do
     n=${r#@rpath/}
     find "'"$STAGE"'" -name "$n" -print -quit 2>/dev/null | grep -q . || echo "  UNRESOLVABLE $n <- $1"
   done' _ {} \; | sort -u)
rm -rf "$STAGE"
[ -z "$miss" ] && say "  ok" || { say "$miss" | head -10; rc=1; }

[ $rc -eq 0 ] && say "DIST PARITY OK" || say "DIST PARITY FAILED -- see above"
exit $rc
