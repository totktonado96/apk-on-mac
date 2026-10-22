#!/usr/bin/env bash
# rebuild_and_run.sh -- THE owner's one command. After it finishes, nothing
# stale can be running anywhere on this machine.
#
#   1. Kills any running Apk on Mac processes.
#   2. Wipes runtime/build, runtime/translator/build, build/Apk on Mac.app and
#      rebuilds everything from source.
#   3. PROMOTES the fresh bundle to the ONE canonical installed app
#      (default /Applications/Apk on Mac.app, override MACAPK_CANONICAL_APP),
#      atomically: stage a copy next to the target, swap by rename, restore
#      the old bundle if the swap fails. Never copies over a live bundle in
#      place (macOS caches code signatures by inode; an in-place overwrite of
#      executed signed code can crash with "Code Signature Invalid" until
#      reboot -- see the staging note in runtime/scripts/build.sh).
#   4. Removes the repo's build/Apk on Mac.app after a successful promote and
#      prunes stale LaunchServices registrations, so exactly ONE Apk on Mac is
#      resolvable (lsregister -dump showed THREE io.github.totktonado96.apkonmac.launcher
#      registrations on this machine, two pointing at deleted paths).
#   5. STAGES the shared runtime -- the copy every installed app actually
#      EXECUTES -- from the bundle just promoted. See the block at the site
#      for why the build has to own this and why it shells out to
#      macapk-installhelper rather than copying anything itself.
#   6. Prints the freshness report (debug/staleness.sh) so "it is fresh" is
#      something the machine SAYS, not something you hope.
#
# What it deliberately does NOT do:
#   * It does NOT touch ~/Documents/android/data/data by default. That tree
#     interleaves ~8 GB of regenerable cache with ~8 GB of irreplaceable app
#     saves, and the owner chose per-subsystem stamping (JAVA_ID/NATIVE_ID in
#     runtime/build/build-id.txt) over wipe-on-rebuild: only artifacts whose
#     actual producer changed get regenerated, on their next launch.
#   * --fresh-caches is the explicit escape hatch: it deletes ONLY the five
#     named regenerable cache items per app dir (listed below at the site),
#     never an app dir itself and never files/ databases/ shared_prefs/
#     cache/ services_root/. Until the runtime consumes build-id.txt, this
#     is also the only way to force old caches cold.
#   * thirdparty/angle/ is never rebuilt (vendored, expensive).
#
# Flags:
#   --fresh-caches   invalidate the per-app regenerable caches (see above)
#   --no-promote     build only; leave the canonical app untouched (for a
#                    deliberate A/B against an older installed build)
#   --promote        promote even from a CLONE (see below)
#
# INSTALLS ARE GUARDED (2026-10-07, scripts/install_guard.sh). In a clone of the
# primary checkout this script builds WITHOUT promoting unless --promote is
# given, and does not kill running Apk on Mac processes (other sessions' runs).
# Every promote holds the machine-wide install lock, and is REFUSED -- before
# anything is killed or wiped -- when this tree lacks commits that are already
# installed (an older clone, or one missing another session's test install).
# MACAPK_FORCE_INSTALL=1 overrides; `scripts/install_guard.sh status` says who
# installed what, and who holds the lock.
#
# HISTORY NOTE: this script wiped <repo>/cache/apps as its "start fresh" step
# for ~800 versions. That directory has been EMPTY since v1.0.130 moved the
# cache under the android root -- the wipe was a no-op and the freshness it
# promised did not exist. The promote + build-id design above replaces it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CANONICAL="${MACAPK_CANONICAL_APP:-/Applications/Apk on Mac.app}"
SRC_APP="$PROJECT_DIR/build/Apk on Mac.app"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

FRESH_CACHES=0
NO_PROMOTE=0
PROMOTE_FLAG=0
# Set by the runtime-staging step below. The script exits nonzero on it so a
# stale staged runtime can never be mistaken for a clean build.
STAGE_FAILED=0
for a in "$@"; do
    case "$a" in
        --fresh-caches) FRESH_CACHES=1 ;;
        --no-promote)   NO_PROMOTE=1 ;;
        --promote)      PROMOTE_FLAG=1 ;;
        *) echo "Unknown arg: $a (flags: --fresh-caches, --no-promote, --promote)" >&2; exit 2 ;;
    esac
done
if [ "$NO_PROMOTE" -eq 1 ] && [ "$PROMOTE_FLAG" -eq 1 ]; then
    echo "ERROR: --promote and --no-promote contradict each other." >&2
    exit 2
fi

. "$SCRIPT_DIR/install_guard.sh"
IS_PRIMARY=1
ig_is_primary "$PROJECT_DIR" || IS_PRIMARY=0
if [ "$IS_PRIMARY" -eq 0 ] && [ "$NO_PROMOTE" -eq 0 ] && [ "$PROMOTE_FLAG" -eq 0 ]; then
    NO_PROMOTE=1
    echo "==> This is a clone of the primary checkout, so building WITHOUT promoting."
    echo "    Pass --promote to install this tree over $CANONICAL."
fi
if [ "$NO_PROMOTE" -eq 0 ]; then
    # Refuse BEFORE killing anything or wiping the build: a refused promote
    # must cost nothing.
    ig_check_contains "$PROJECT_DIR" "$CANONICAL" || exit 3
    case "$(ig_lock_status_line)" in
        HELD*) echo "==> NOTE: install lock $(ig_lock_status_line); the promote will wait for it." ;;
    esac
fi

# Fail EARLY if we will not be able to promote, so the owner does not wait
# out a full build to learn /Applications is not writable.
CANON_PARENT="$(dirname "$CANONICAL")"
if [ "$NO_PROMOTE" -eq 0 ] && [ ! -w "$CANON_PARENT" ]; then
    echo "ERROR: $CANON_PARENT is not writable, so the build could not be" >&2
    echo "promoted to $CANONICAL. Fix permissions, or set" >&2
    echo "MACAPK_CANONICAL_APP to a writable location, or pass --no-promote." >&2
    exit 1
fi

if [ "$IS_PRIMARY" -eq 0 ] && [ "$NO_PROMOTE" -eq 1 ]; then
    # A clone that is not installing has no business killing the apps other
    # sessions (or the owner) are running from the installed runtime.
    echo "==> Clone build, not promoting: leaving running Apk on Mac processes alone."
else
echo "==> Killing any running Apk on Mac processes..."
# Kill the GUI app (any copy: repo, canonical, stray) and any orphan runtime
# children. `|| true` so the script does not fail when nothing is running.
pkill -x MacApk         2>/dev/null || true
pkill -x macapk-runtime 2>/dev/null || true
# ⚠ AN INSTALLED APP IS NOT NAMED macapk-runtime (found 2026-10-07). Its stub
# execs the shared runtime through a symlink in its own bundle,
# <App>.app/Contents/MacOS/.<App name> -> <staged runtime>/Resources/macapk-runtime,
# so the process is named ".Plague Inc." and `pkill -x macapk-runtime` never
# matched it: a Plague Inc. started before the v1.0.1737 install kept running
# the OLD runtime through it. Match those by what their executable link points
# at. MACAPK_STAGED_RUNTIME_DIR exists only so the installguard gate can aim
# this at a scratch runtime instead of the machine's.
STAGED_RT="${MACAPK_STAGED_RUNTIME_DIR:-$HOME/Library/Application Support/Apk on Mac/runtime}"
for pid in $(pgrep -f -- '--android-root' 2>/dev/null || true); do
    exe="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
    case "$exe" in */Contents/MacOS/.*) ;; *) continue ;; esac
    case "$(readlink "$exe" 2>/dev/null)" in
        "$STAGED_RT"/*)
            echo "    stopping installed app pid $pid ($(basename "$exe" | sed 's/^\.//'))"
            kill -TERM "$pid" 2>/dev/null || true ;;
    esac
done
# Give the OS a moment to release file locks on the .app bundle.
sleep 0.3
fi

if [ "$FRESH_CACHES" -eq 1 ]; then
    # Explicit, surgical cache invalidation. Deletes EXACTLY these five items
    # per app dir under <android-root>/data/data, nothing else:
    #     .source-mtime            the extraction stamp; deleting it makes
    #                              CacheIsFresh() report stale, so the next
    #                              launch re-converts DEX (apk_unpacker.cpp)
    #     classes.jar              converted DEX (regenerated by the above)
    #     classes.unverified.txt   dexconv sidecar derived from classes.jar
    #     _apkt/                   pre-1590 apktool resource decode (never
    #                              regenerated; the warm path reclaims it too)
    #     lib_native/              translated dylibs -- MUST be deleted
    #                              explicitly because AppClassLoader's cache
    #                              is existence-based, so nothing else ever
    #                              invalidates it
    # It NEVER deletes an app dir, and never touches files/, databases/,
    # shared_prefs/, cache/, services_root/, base.apk, dexopt/, meta.json,
    # icon.png or anything extracted from the APK: those are either the
    # user's saves or keyed correctly on the APK already.
    DATA_ROOT="${MACAPK_ANDROID_ROOT:-$HOME/Documents/android}/data/data"
    case "$DATA_ROOT" in
        */data/data) ;;
        *) echo "ERROR: refusing --fresh-caches: unexpected data root '$DATA_ROOT'" >&2; exit 1 ;;
    esac
    if [ -d "$DATA_ROOT" ]; then
        echo "==> Invalidating per-app regenerable caches under $DATA_ROOT ..."
        reclaimed_kb=0
        touched=0
        for appdir in "$DATA_ROOT"/*/; do
            appdir="${appdir%/}"
            [ -d "$appdir" ] || continue
            # Only dirs carrying OUR cache markers; anything else is not ours.
            if [ ! -f "$appdir/.source-mtime" ] && [ ! -f "$appdir/classes.jar" ] \
               && [ ! -d "$appdir/_apkt" ] && [ ! -d "$appdir/lib_native" ]; then
                continue
            fi
            for item in .source-mtime classes.jar classes.unverified.txt _apkt lib_native; do
                t="$appdir/$item"
                [ -e "$t" ] || continue
                kb="$(du -sk "$t" 2>/dev/null | awk '{print $1}' || true)"
                reclaimed_kb=$((reclaimed_kb + ${kb:-0}))
                echo "    rm $t"
                rm -rf "$t"
            done
            touched=$((touched + 1))
        done
        echo "==> Invalidated caches in $touched app dir(s), ~$((reclaimed_kb / 1024)) MB freed."
        echo "    (App saves untouched. Each app re-converts on its next launch.)"
    else
        echo "==> --fresh-caches: no app cache root at $DATA_ROOT; nothing to do."
    fi
fi

echo "==> Wiping runtime build dirs..."
# Two separate cmake projects each cache the source path in their
# CMakeCache.txt; if the repo gets moved or renamed, that cache goes
# stale and cmake errors out with "current cache dir does not match
# source dir." Always wipe both so a rebuild after a rename Just Works.
#
# build-id.txt survives the wipe on purpose: build.sh only rewrites it when
# the identity actually CHANGES, so its mtime means "last real change".
# Losing it here would give every clean rebuild a fresh mtime and make
# debug/staleness.sh over-flag all per-app caches as predating the identity
# even when the jars are entry-identical.
BUILD_ID_STASH=""
if [ -f "$PROJECT_DIR/runtime/build/build-id.txt" ]; then
    BUILD_ID_STASH="$(mktemp -t macapk_build_id)"
    cp -p "$PROJECT_DIR/runtime/build/build-id.txt" "$BUILD_ID_STASH"
fi
rm -rf "$PROJECT_DIR/runtime/build"
rm -rf "$PROJECT_DIR/runtime/translator/build"
if [ -n "$BUILD_ID_STASH" ] && [ -f "$BUILD_ID_STASH" ]; then
    mkdir -p "$PROJECT_DIR/runtime/build"
    cp -p "$BUILD_ID_STASH" "$PROJECT_DIR/runtime/build/build-id.txt"
    rm -f "$BUILD_ID_STASH"
fi

echo "==> Wiping launcher .app bundle..."
rm -rf "$SRC_APP"

# Legacy pre-v1.0.130 cache location. Kept in existence only so old
# references never hit a missing dir; real caches live under the android
# root and are keyed per Contract 3 (build-id.txt).
mkdir -p "$PROJECT_DIR/cache/apps"

echo "==> Building runtime..."
# The full-bundle promote below replaces the canonical app wholesale, so
# build.sh's incremental per-file payload sync would be redundant work here.
MACAPK_NO_BUNDLE_SYNC=1 "$PROJECT_DIR/runtime/scripts/build.sh"

echo "==> Building launcher..."
MACAPK_NO_BUNDLE_SYNC=1 "$SCRIPT_DIR/build_launcher.sh"
[ -d "$SRC_APP" ] || { echo "ERROR: $SRC_APP was not produced; not promoting." >&2; exit 1; }

# Carry the build identity into the bundle if build_launcher.sh has not been
# taught to (belt and suspenders; the runtime and debug/staleness.sh read it at
# Contents/Resources/build-id.txt, i.e. <runtime-bin-dir>/build-id.txt --
# v1.0.1019 moved it out of Contents/, where a loose file cannot be sealed and
# failed `codesign --verify --deep --strict`).
if [ ! -f "$SRC_APP/Contents/Resources/build-id.txt" ] \
   && [ -f "$PROJECT_DIR/runtime/build/build-id.txt" ]; then
    ditto "$PROJECT_DIR/runtime/build/build-id.txt" "$SRC_APP/Contents/Resources/build-id.txt"
fi

# Read the build ID we just stamped in. If a launcher shows a DIFFERENT id
# when it opens, you are looking at a copy this script did not install --
# the LaunchServices pruning below exists to make that impossible.
BUILD_ID="$(grep -E 'static let id' "$PROJECT_DIR/launcher/BuildInfo.generated.swift" \
            | sed -E 's/.*"([^"]+)".*/\1/' || echo unknown)"

# Open the GUI without this shell's harness settings (2026-10-19). `open` hands
# the caller's environment to the app, and the launcher passes its own to every
# app it opens: an install run from a test shell with MACAPK_NO_ACTIVATE=1
# exported left the owner's control panel opening every app behind his windows.
open_gui() {
    env -u MACAPK_NO_ACTIVATE -u MACAPK_PAUSE_WHEN_HIDDEN -u MACAPK_INSTALL_LOCK_HELD \
        -u MACAPK_INJECT_FILE -u MACAPK_DEBUG_HOSTKEY_FILE -u MACAPK_RECORD_INPUT \
        -u MACAPK_EXTERNAL_URLS open "$@"
}
if [ "$NO_PROMOTE" -eq 1 ]; then
    echo ""
    echo "==> --no-promote: leaving $CANONICAL untouched."
    echo "==> --no-promote: NOT staging the shared runtime either. Installed"
    echo "    apps keep executing whatever is already staged, which is the"
    echo "    point of this flag -- but it means an app launched now is NOT"
    echo "    running the build you just made."
    echo "==> Opening $SRC_APP (build $BUILD_ID)..."
    open_gui "$SRC_APP"
else
    # The promote is scripts/promote_app.sh -- atomic stage/swap/restore,
    # LaunchServices pruning, and the per-app stub restage. It used to be
    # inline here, which meant scripts/build_launcher.sh (the script that
    # builds the three Swift execution surfaces) had no promote path at all
    # and left /Applications/Apk on Mac.app serving the previous GUI, install
    # helper and app-stub template with no signal anywhere. Extracted
    # 2026-08-19 so both callers run ONE implementation; the trap-only-cleans-
    # $STAGING ordering in there is subtle enough that a second copy would
    # eventually delete someone's only good bundle.
    # Hold the install lock across BOTH the promote and the staging below, so
    # no other installer can land between them (promote_app.sh and
    # stage_shared_runtime.sh see the marker and pass straight through).
    # promote_app.sh re-checks this tree against what is installed under it.
    IG_TREE="$PROJECT_DIR" ig_lock_acquire "rebuild_and_run.sh promote + stage" || exit 75
    trap 'ig_lock_release' EXIT
    PROMOTE_RC=0
    MACAPK_CANONICAL_APP="$CANONICAL" MACAPK_INSTALL_VIA=rebuild_and_run.sh \
        "$SCRIPT_DIR/promote_app.sh" "$SRC_APP" "$CANONICAL" || PROMOTE_RC=$?
    if [ "$PROMOTE_RC" -eq 3 ] || [ "$PROMOTE_RC" -eq 75 ]; then
        # The install guard refused (this tree lacks what is installed) or
        # the lock wait timed out. Nothing was installed; say so and stop.
        echo "ERROR: not promoted (install guard, see above). $CANONICAL is unchanged;" >&2
        echo "       the fresh build is still at $SRC_APP." >&2
        exit "$PROMOTE_RC"
    fi
    if [ "$PROMOTE_RC" -ne 0 ]; then
        # promote_app.sh already printed what failed and, on a swap failure,
        # where the previous bundle is. A restage failure is nonfatal (those
        # bundles run the old stub); a promote failure is not.
        if [ ! -d "$CANONICAL" ]; then
            echo "ERROR: $CANONICAL is not in place; aborting." >&2
            exit 1
        fi
        echo "^^ promote reported a problem (see above); continuing so the"
        echo "   runtime-staging step below still runs."
    fi

    # ---- Stage the SHARED RUNTIME (the copy installed apps execute) -------
    #
    # An installed app executes ~/Library/Application Support/Apk on Mac/runtime,
    # NOT anything in this repo and NOT the copy inside Apk on Mac.app, so a
    # promote that skips this leaves every installed app on the previous
    # build. Whoever promotes, stages.
    # ONE implementation, shared with scripts/build_launcher.sh --promote.
    # The long WHY (and the bug this closes) lives in that script's header.
    if ! "$SCRIPT_DIR/stage_shared_runtime.sh" "$CANONICAL"; then
        STAGE_FAILED=1
    fi
    ig_lock_release

    echo ""
    echo "==> Opening $CANONICAL (build $BUILD_ID)..."
    open_gui "$CANONICAL"
fi

echo ""
if [ -f "$PROJECT_DIR/runtime/build/build-id.txt" ]; then
    echo "Build identity: $(tr '\n' ' ' < "$PROJECT_DIR/runtime/build/build-id.txt")"
fi
echo "Done. Launcher header should read: build $BUILD_ID"
echo ""

# The closing freshness report: the machine SAYS everything is consistent
# (or names precisely what is not). Nonzero here means an execution surface
# is stale, which after a successful promote would be a bug worth reading.
if [ -x "$PROJECT_DIR/debug/staleness.sh" ]; then
    echo "==> Freshness report (debug/staleness.sh):"
    "$PROJECT_DIR/debug/staleness.sh" || \
        echo "^^ STALENESS REPORTED ABOVE -- read it before trusting any run."
fi

# A build that promoted but could not stage is NOT a successful build, because
# the thing installed apps execute is still the old one. Exit nonzero so a
# harness that chains off this script stops instead of measuring old code.
if [ "$STAGE_FAILED" -ne 0 ]; then
    echo ""
    echo "ERROR: the build and promote succeeded but the SHARED RUNTIME was not" >&2
    echo "       staged (details above). Installed apps still execute the" >&2
    echo "       previous build. Exiting nonzero on purpose." >&2
    exit 1
fi
