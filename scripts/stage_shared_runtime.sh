#!/usr/bin/env bash
# stage_shared_runtime.sh -- install the SHARED RUNTIME (the copy every
# installed app actually EXECUTES) from an already-promoted Mac.apk bundle.
#
# Usage: scripts/stage_shared_runtime.sh <canonical-app-path>
# Exit 0 = staged (or deliberately not staged because the user uninstalled it).
# Exit 1 = FAILED; installed apps still execute the previous build.
#
# WHY THIS IS A SCRIPT AND NOT INLINE IN A PROMOTER: there are TWO promoters --
# scripts/rebuild_and_run.sh and scripts/build_launcher.sh --promote -- and
# until 2026-08-19 only the first of them staged. The second promoted the
# canonical app and left every installed app executing an OLDER runtime, with
# debug/staleness.sh reporting the split correctly and nothing acting on it.
# That was hit twice in one day. Duplicating the logic into the second promoter
# would have created a SECOND, divergent answer to "what is the machine's
# shared runtime", which is the same class of bug; so both now call this.
#
# WHY A BUILD CANNOT DO THIS: an installed app's Contents/MacOS/<exec> is a
# SYMLINK to
#     ~/Library/Application Support/Mac.apk/runtime/Resources/macapk-runtime
# (RuntimeInstall.stagedRoot), never to anything in this repo and never to the
# copy inside Mac.apk.app. runtime/scripts/build.sh does not stage it directly,
# so it has no business deciding what the machine's ONE shared runtime is.
# Whoever promotes, stages.
# ⚠ CORRECTED 2026-10-07: this used to say build.sh "does not promote". It DOES
# mirror its payload into the canonical app (its "Keep live launcher bundles'
# runtime payload current" block), and the next app launch restages the shared
# runtime from there, so in effect it installs. Since 2026-10-07 that mirror
# runs only from the primary checkout, under scripts/install_guard.sh.
#
# THE ORIGINAL BUG THIS CLOSES (measured 2026-08-19): nothing on any build path
# wrote the staged root. Its only automatic refresh was
# RuntimeInstall.ensureStaged(), whose ONE caller is the per-app stub
# (AppStubMain.swift) -- so the staged runtime only caught up when a guest app
# happened to launch. The control panel does NOT self-heal at startup despite
# ensureStaged's own docstring having claimed it did. Concretely: v1.0.998 was
# promoted around 00:44, no guest app launched between 00:29 and 09:22, and the
# staged root held v1.0.997 the entire time. Every measurement taken through an
# app bundle in that window was of old code, and debug/staleness.sh said FRESH
# throughout because it models the canonical app, not the staged copy.
#
# It shells out to macapk-installhelper rather than copying anything itself:
# the helper is a headless CLI over RuntimeInstall, which resolves its install
# SOURCE from its own path, swaps atomically by rename, restores the previous
# tree if the swap fails, and re-verifies the landed tree against the source.
# Invoking the copy INSIDE the bundle just promoted is what makes "newest
# version always wins" true by construction rather than by hope. A `ditto` here
# would be that second divergent answer again.
set -uo pipefail

CANONICAL="${1:-}"
if [ -z "$CANONICAL" ]; then
    echo "usage: $(basename "$0") <canonical-app-path>" >&2
    exit 2
fi

# Writing the staged runtime is an install, so it holds the machine-wide install
# lock (scripts/install_guard.sh). Re-entrant: when a promoter already holds it,
# this passes straight through. Nothing to check against what is installed here:
# the source is the canonical app, which its promoter already checked.
. "$(dirname "$0")/install_guard.sh"
ig_lock_acquire "stage_shared_runtime.sh" || exit 75
trap 'ig_lock_release' EXIT

echo ""
echo "==> Staging the shared runtime from $CANONICAL ..."
HELPER="$CANONICAL/Contents/bin/macapk-installhelper"

if [ ! -x "$HELPER" ]; then
    echo "ERROR: $HELPER is missing or not executable." >&2
    echo "       The shared runtime was NOT re-staged, so every installed app" >&2
    echo "       keeps executing the PREVIOUS build until one of them is" >&2
    echo "       launched. Check scripts/build_launcher.sh." >&2
    exit 1
fi

if "$HELPER" runtime-status --json 2>/dev/null | grep -q '"removedByUser":"true"'; then
    # Not a failure: the user pressed Runtime: Uninstall, and a build silently
    # undoing that would make the button meaningless. Say it loudly instead,
    # because until it is reinstalled no app can launch.
    echo "==> NOTE: the shared runtime is UNINSTALLED (Runtime: Uninstall was pressed)."
    echo "    Not re-staging it. Installed apps cannot launch until you open"
    echo "    Mac.apk and choose Runtime: Install."
    exit 0
fi

if ! "$HELPER" runtime-install; then
    echo "ERROR: staging the shared runtime FAILED (see the message above)." >&2
    echo "       Installed apps keep executing the PREVIOUS build. Do not" >&2
    echo "       trust any measurement taken through an app bundle until this" >&2
    echo "       is fixed; '$HELPER runtime-install' reproduces it." >&2
    exit 1
fi

# Do NOT trust the exit code alone. Re-ask for the state, which recomputes
# RuntimeInstall.state() -- staged payload compared file by file against what
# the bundle ships -- and refuse to call this staged unless it says installed
# AND not stale.
RT_STATUS="$("$HELPER" runtime-status --json 2>/dev/null || true)"
case "$RT_STATUS" in
    *'"installed":"true"'*)
        case "$RT_STATUS" in
            *'"stale":"false"'*)
                echo "    staged: $(printf '%s' "$RT_STATUS" \
                    | sed -E 's/.*"buildId":"([^"]*)".*/\1/')"
                ;;
            *)
                echo "ERROR: the runtime staged but still reports STALE:" >&2
                echo "       $RT_STATUS" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "ERROR: runtime-install reported success but the runtime is not" >&2
        echo "       installed. Raw status: $RT_STATUS" >&2
        exit 1
        ;;
esac
