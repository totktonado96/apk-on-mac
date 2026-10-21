#!/usr/bin/env bash
# scripts/promote_app.sh <src-app> [canonical-app]
#
# Atomically install a freshly built Mac.apk.app over the ONE canonical copy,
# then make it the only one the machine can resolve.
#
# WHY THIS IS ITS OWN FILE (2026-08-19). This block used to live inline in
# scripts/rebuild_and_run.sh and had exactly ONE caller, so scripts/build_launcher.sh
# -- which builds the three Swift execution surfaces and nothing else -- had no
# way to promote at all. Its last two lines said "Built: build/Mac.apk.app" and
# "Run with: open build/Mac.apk.app", and CLAUDE.md's own step-by-step recipe
# tells the reader to run exactly that sequence. The result is that
# /Applications/Mac.apk.app keeps serving the PREVIOUSLY promoted Swift binaries
# while the developer looks at a different bundle, with no signal anywhere.
# Measured on this machine 2026-08-19: the canonical app's MacApk and
# macapk-installhelper both carried build 260819.0937 while the repo's last
# launcher build was 260819.0956.
#
# Copy-pasting the promote into a second script is the drift this extraction
# exists to remove, and the reason is specific: the trap-vs-$ASIDE ordering
# below is subtle enough that a divergent second copy would eventually delete
# someone's only good bundle. One implementation, two callers -- the same move
# runtime/scripts/build_ids.py already made for the build digests.
#
# Steps, in order:
#   1. precheck the canonical PARENT is writable (fail before doing any work)
#   2. ditto a full copy to a staging dir NEXT TO the target (same volume, so
#      the swap is a rename, not a copy)
#   3. move the old bundle aside, move the new one in, restore on failure
#   4. delete the source copy so exactly one Mac.apk is resolvable
#      (--keep-source opts out)
#   5. lsregister -f the canonical path and UNREGISTER every other
#      org.macapk.launcher registration
#   6. restage the per-app stub into every installed app bundle
#
# It does NOT stage the shared runtime. Both CALLERS do, immediately after
# this returns, via scripts/stage_shared_runtime.sh -- the one implementation
# of "what is the machine's shared runtime". Until 2026-08-19 only
# rebuild_and_run.sh did, so build_launcher.sh --promote left every installed
# app executing an older runtime; if you add a THIRD caller of this script, it
# must stage too or it reintroduces that split.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

KEEP_SOURCE=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --keep-source) KEEP_SOURCE=1 ;;
        -*) echo "Unknown flag: $a (only --keep-source)" >&2; exit 2 ;;
        *) ARGS+=("$a") ;;
    esac
done

SRC_APP="${ARGS[0]:-$PROJECT_DIR/build/Mac.apk.app}"
CANONICAL="${ARGS[1]:-${MACAPK_CANONICAL_APP:-/Applications/Mac.apk.app}}"
CANON_PARENT="$(dirname "$CANONICAL")"

if [ ! -d "$SRC_APP" ]; then
    echo "ERROR: $SRC_APP does not exist; nothing to promote." >&2
    exit 1
fi
if [ ! -w "$CANON_PARENT" ]; then
    echo "ERROR: $CANON_PARENT is not writable, so $SRC_APP could not be" >&2
    echo "promoted to $CANONICAL. Fix permissions, or set" >&2
    echo "MACAPK_CANONICAL_APP to a writable location." >&2
    exit 1
fi

# ---- the install guard (2026-10-07) -----------------------------------------
# Every write to the installed app goes through scripts/install_guard.sh: one
# machine-wide install lock that says who holds it (re-entrant, so the callers
# that already took it -- rebuild_and_run.sh, build_launcher.sh --promote -- pass
# straight through), and a refusal to install a tree that lacks what is already
# installed. That refusal is the guard against what happened on 2026-10-07, when
# a clone at v1.0.1733 overwrote an installed v1.0.1736. MACAPK_FORCE_INSTALL=1
# overrides it; MACAPK_INSTALL_LOCK_TIMEOUT bounds the wait (0 = refuse if busy).
. "$SCRIPT_DIR/install_guard.sh"
SRC_TREE="$(git -C "$(dirname "$SRC_APP")" rev-parse --show-toplevel 2>/dev/null || echo "$PROJECT_DIR")"
IG_TREE="$SRC_TREE" ig_lock_acquire "promote_app.sh -> $CANONICAL" || exit 75
trap 'ig_lock_release' EXIT
ig_check_contains "$SRC_TREE" "$CANONICAL" || exit 3

BUILD_ID="$(strings -a "$SRC_APP/Contents/MacOS/MacApk" 2>/dev/null \
    | grep -oE '^[0-9]{6}\.[0-9]{4}-[0-9a-f]{7,}(\+dirty)?$' | sort -u | head -n 1)"
echo "==> Promoting ${BUILD_ID:-unknown build} to $CANONICAL ..."

# Atomic promote: stage a full copy NEXT TO the target (same volume, so
# mv is a rename), swap old out / new in, delete the old copy last. If
# the swap fails the old bundle is restored and we exit nonzero: the
# previous good runtime staying in place is correct, a half-copied
# bundle is not.
STAGING="$CANON_PARENT/.Mac.apk.app.staging.$$"
ASIDE="$CANON_PARENT/.Mac.apk.app.previous.$$"
rm -rf "$STAGING" "$ASIDE"
# ⚠ The trap must NEVER be able to delete $ASIDE while $ASIDE is the only
# surviving copy of the previous good runtime. Between the mv at "park the
# old bundle" and a successful restore, $ASIDE IS that only copy -- so the
# trap only ever cleans $STAGING, and $ASIDE is removed explicitly, once,
# after the new bundle is provably in place.
trap 'rm -rf "$STAGING"; ig_lock_release' EXIT
ditto "$SRC_APP" "$STAGING"
if [ -d "$CANONICAL" ]; then
    mv "$CANONICAL" "$ASIDE"
fi
if ! mv "$STAGING" "$CANONICAL"; then
    echo "ERROR: promote failed; restoring previous $CANONICAL." >&2
    if [ -d "$ASIDE" ] && ! mv "$ASIDE" "$CANONICAL"; then
        # Both moves failed. Do not delete anything: say exactly where the
        # previous runtime is so it can be recovered by hand.
        echo "ERROR: could not restore either. Your previous Mac.apk is intact at:" >&2
        echo "         $ASIDE" >&2
        echo "       Move it back to $CANONICAL manually." >&2
    fi
    exit 1
fi
rm -rf "$ASIDE"
ig_record_install "$SRC_TREE" "$CANONICAL" "promote_app.sh${MACAPK_INSTALL_VIA:+ via $MACAPK_INSTALL_VIA}"

# Exactly ONE resolvable Mac.apk: drop the repo copy we just promoted
# (build_dist.sh recreates it from source when it needs one), then prune
# every LaunchServices registration for our bundle id that is not the
# canonical path. Two of those once pointed at deleted trees (an old
# build/dist and the pre-rename MacDroid checkout); anything resolving
# by bundle id with duplicates present is rolling dice.
if [ "$KEEP_SOURCE" -eq 0 ]; then
    rm -rf "$SRC_APP"
else
    echo "==> --keep-source: leaving $SRC_APP in place (two bundles now resolve)."
fi
if [ -x "$LSREGISTER" ]; then
    echo "==> Refreshing LaunchServices registrations..."
    "$LSREGISTER" -f "$CANONICAL" 2>/dev/null || true
    # Enumerate registered paths claiming org.macapk.launcher and
    # unregister all but the canonical. The dump costs a few seconds,
    # which is nothing next to the build.
    "$LSREGISTER" -dump 2>/dev/null | awk '
        /^-+$/ { if (id && p) print p; p = ""; id = 0; next }
        /^[[:space:]]*path:/ {
            sub(/^[[:space:]]*path:[[:space:]]*/, "");
            sub(/ \(0x[0-9a-f]+\)[[:space:]]*$/, "");
            p = $0
        }
        /^[[:space:]]*identifier:/ {
            if ($0 ~ /org\.macapk\.launcher([[:space:]]|\(|$)/) id = 1
        }
        END { if (id && p) print p }
    ' | while IFS= read -r reg; do
        [ "$reg" = "$CANONICAL" ] && continue
        [ "$KEEP_SOURCE" -eq 1 ] && [ "$reg" = "$SRC_APP" ] && continue
        [ -n "$reg" ] || continue
        echo "    unregistering stale LS entry: $reg"
        "$LSREGISTER" -u "$reg" 2>/dev/null || true
    done || true
else
    echo "==> NOTE: lsregister not found at the usual path; skipped LS pruning."
fi

# Per-app launcher bundles (the thin per-app .apps that exec the shared
# runtime). They embed no runtime, no jars and no translator, so promoting
# the canonical app updates all of that for every one of them atomically --
# but the STUB BINARY is the exception this comment used to miss. Each
# bundle carries its own copy at Contents/MacOS/<CFBundleExecutable>
# (BundleGenerator.finalize renames it with the bundle), frozen at install
# time, so a stub change reached only apps installed AFTERWARDS.
#
# MEASURED 2026-08-12 (v1.0.962): 10 of the 11 installed bundles on this
# machine were running a stub 17 hours older than the template, while the
# comment here asserted there was "nothing to refresh BY CONSTRUCTION".
#
# ⚠ MACAPK_CANONICAL_APP is EXPORTED for this call on purpose. restage_app_stubs.sh
# resolves its template from that variable, and this script takes the canonical
# path as an ARGUMENT -- so without the export, promoting to a non-default
# location would push /Applications/Mac.apk.app's stub into every installed
# bundle, i.e. a template from a bundle we did not just build. Two sources of
# truth for "which app is canonical" is exactly the divergence this extraction
# exists to remove.
PROMOTE_RC=0
if [ -x "$PROJECT_DIR/scripts/restage_app_stubs.sh" ]; then
    echo ""
    echo "==> Restaging the per-app stub into installed bundles..."
    if ! MACAPK_CANONICAL_APP="$CANONICAL" "$PROJECT_DIR/scripts/restage_app_stubs.sh"; then
        echo "^^ some bundles could not be restaged; they will run the OLD stub."
        PROMOTE_RC=1
    fi
fi

echo ""
echo "==> Promoted: $CANONICAL (${BUILD_ID:-unknown build})"
exit "$PROMOTE_RC"
