#!/usr/bin/env bash
# scripts/install_guard.sh -- the ONE gate in front of everything that writes the
# machine's INSTALLED Mac.apk: the canonical app (/Applications/Mac.apk.app, or
# MACAPK_CANONICAL_APP), the shared staged runtime every installed app executes
# (~/Library/Application Support/Mac.apk/runtime), and the per-app stubs.
#
# WHY (2026-10-07). Several sessions build in their own clones of this repo at
# once. At 02:41 UTC one of them ran runtime/scripts/build.sh in a clone sitting
# at v1.0.1733; build.sh's payload sync mirrored that clone's jars, runtime and
# bionic shim into /Applications/Mac.apk.app, and the next app launch staged
# them as the shared runtime. That silently undid v1.0.1735 and v1.0.1736 on the
# owner's machine until main was re-promoted 24 minutes later. Nothing refused,
# nothing said who had installed what, and the only guard was the coordinator
# handing out an "install slot" by chat message.
#
# Three rules, enforced here so every installer gets the same answer:
#   1. A build in a CLONE never installs by itself. build.sh mirrors into the
#      canonical app only from the PRIMARY checkout (ig_is_primary) or when
#      MACAPK_BUNDLE_SYNC=1 asks for it; rebuild_and_run.sh in a clone builds
#      without promoting unless given --promote.
#   2. Every install holds ONE machine-wide install lock (ig_lock_acquire) that
#      records who holds it. A second installer waits its turn, then proceeds;
#      MACAPK_INSTALL_LOCK_TIMEOUT=0 makes it refuse instead of waiting.
#   3. An install REFUSES a tree that does not contain what is already installed
#      (ig_check_contains): an older checkout, or one that lacks commits another
#      session installed for a test. MACAPK_FORCE_INSTALL=1 overrides, and should
#      only be used with the owner's (or that installer's) OK.
#
# Every successful install is recorded (commit, VERSION, tree, who, when) so the
# next installer -- and anyone asking "what is installed right now?" -- can see it.
#
# CLI:
#   scripts/install_guard.sh status             lock holder, installed build, primary checkout
#   scripts/install_guard.sh check [tree]       would an install from <tree> be allowed? (0 yes, 3 no)
#   scripts/install_guard.sh history [N]        the last N installs (default 15)
#   scripts/install_guard.sh set-primary [tree] mark <tree> (default: this repo) as the checkout
#                                               whose build.sh may mirror into the installed app
#   scripts/install_guard.sh run <cmd...>       run <cmd> holding the install lock
#
# Sourced (scripts/promote_app.sh, stage_shared_runtime.sh, rebuild_and_run.sh,
# build_launcher.sh, runtime/scripts/build.sh):
#   ig_lock_acquire <label> [timeout-s]   0 = held (re-entrant for child scripts), 75 = timed out
#   ig_lock_release                       drops the lock iff this process took it
#   ig_check_contains <tree> <canonical>  0 = ok to install, 3 = refused (reason on stderr)
#   ig_record_install <tree> <canonical> <label>
#   ig_is_primary <tree>                  0 = primary checkout, 1 = a clone
#
# State (override for tests):
#   MACAPK_INSTALL_LOCKDIR    default /tmp/macapk-install.lock (same mkdir pattern as
#                             debug/applock.sh; a dead holder's lock is reaped)
#   MACAPK_INSTALL_STATE_DIR  default ~/Library/Application Support/Mac.apk-dev
#                             (installed*.env, install-history.log, primary-checkout)
#
# This lock is NOT debug/applock.sh's machine lock and does not replace it: that one
# serialises builds/stages into runtime/build and timing-sensitive app runs inside
# ONE checkout; this one serialises writes to what the whole machine executes.

IG_LOCKDIR="${MACAPK_INSTALL_LOCKDIR:-/tmp/macapk-install.lock}"
IG_STATE="${MACAPK_INSTALL_STATE_DIR:-$HOME/Library/Application Support/Mac.apk-dev}"
IG_DEFAULT_CANONICAL="/Applications/Mac.apk.app"
IG_LOCK_OWNED=0

ig_say() { echo "[install-guard] $*" >&2; }

# Real path of a tree's top level (clones are compared by path).
ig_toplevel() {
    local t
    t="$(git -C "$1" rev-parse --show-toplevel 2>/dev/null)" || t="$1"
    (cd "$t" 2>/dev/null && pwd -P) || echo "$t"
}

ig_record_file() {  # $1 = canonical app path
    local c="${1:-$IG_DEFAULT_CANONICAL}"
    if [ "$c" = "$IG_DEFAULT_CANONICAL" ]; then
        echo "$IG_STATE/installed.env"
    else
        # A test promote to a scratch location must never stand in for /Applications.
        echo "$IG_STATE/installed-$(printf '%s' "$c" | shasum | cut -c1-12).env"
    fi
}

ig_whoami() {
    local tree="$1" br
    br="$(git -C "$tree" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
    echo "${MACAPK_AGENT:+$MACAPK_AGENT }$(basename "$(ig_toplevel "$tree")")@$br pid $$"
}

# ---- primary checkout vs clone ---------------------------------------------
# The primary checkout is the one recorded in $IG_STATE/primary-checkout
# (`install_guard.sh set-primary`). With no record, a checkout cloned from
# another checkout on this disk (origin is a local path) is a clone, and
# anything else -- a contributor's one GitHub checkout -- is primary, which
# keeps build.sh's sync working for a single-checkout setup.
ig_is_primary() {
    local top url
    top="$(ig_toplevel "$1")"
    if [ -s "$IG_STATE/primary-checkout" ]; then
        [ "$(cat "$IG_STATE/primary-checkout")" = "$top" ]
        return
    fi
    url="$(git -C "$top" remote get-url origin 2>/dev/null || true)"
    case "$url" in
        /*|file://*|./*|../*) return 1 ;;
    esac
    return 0
}

ig_primary_desc() {
    if [ -s "$IG_STATE/primary-checkout" ]; then
        cat "$IG_STATE/primary-checkout"
    else
        echo "(not recorded; any checkout whose origin is not a local path)"
    fi
}

# ---- the lock ----------------------------------------------------------------
ig_lock_status_line() {
    if [ -d "$IG_LOCKDIR" ]; then
        local owner started now pid
        owner="$(cat "$IG_LOCKDIR/owner" 2>/dev/null || echo '?')"
        started="$(cat "$IG_LOCKDIR/started" 2>/dev/null || echo 0)"
        pid="$(cat "$IG_LOCKDIR/pid" 2>/dev/null || true)"
        now="$(date +%s)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "STALE (left by $owner, whose pid $pid is gone; the next installer reaps it)"
            return 0
        fi
        echo "HELD by $owner, doing $(cat "$IG_LOCKDIR/what" 2>/dev/null || echo '?') (for $((now - ${started:-0}))s)"
    else
        echo "FREE"
    fi
}

ig_lock_acquire() {
    local what="${1:-install}" wait_max="${2:-${MACAPK_INSTALL_LOCK_TIMEOUT:-1800}}"
    local waited=0 holder started meta_missing=0 tree
    # Re-entrant: a child of the holder (rebuild_and_run.sh -> promote_app.sh ->
    # stage_shared_runtime.sh) sees the holder's marker and proceeds. The marker
    # names the holder pid, and only counts while that pid still owns the lock.
    if [ -n "${MACAPK_INSTALL_LOCK_HELD:-}" ] \
       && [ "${MACAPK_INSTALL_LOCK_HELD%%:*}" = "$IG_LOCKDIR" ]; then
        holder="${MACAPK_INSTALL_LOCK_HELD##*:}"
        if [ "$(cat "$IG_LOCKDIR/pid" 2>/dev/null)" = "$holder" ] && kill -0 "$holder" 2>/dev/null; then
            return 0
        fi
    fi
    tree="$(ig_toplevel "${IG_TREE:-$PWD}")"
    while :; do
        if mkdir "$IG_LOCKDIR" 2>/dev/null; then
            echo "$(ig_whoami "$tree")" > "$IG_LOCKDIR/owner"
            echo "$what"                > "$IG_LOCKDIR/what"
            echo "$tree"                > "$IG_LOCKDIR/tree"
            date +%s                    > "$IG_LOCKDIR/started"
            echo $$                     > "$IG_LOCKDIR/pid"
            IG_LOCK_OWNED=1
            export MACAPK_INSTALL_LOCK_HELD="$IG_LOCKDIR:$$"
            return 0
        fi
        holder="$(cat "$IG_LOCKDIR/pid" 2>/dev/null || true)"
        started="$(cat "$IG_LOCKDIR/started" 2>/dev/null || true)"
        # mkdir and the metadata writes are not one step: a lock with no pid yet
        # is FRESH, not abandoned (debug/applock.sh learned this the hard way).
        # Only after ~15s without metadata is it treated as orphaned.
        if [ -z "$holder" ] || [ -z "$started" ]; then
            meta_missing=$((meta_missing + 1))
            if [ "$meta_missing" -ge 15 ]; then
                ig_say "reaping an install lock that never got an owner"
                rm -rf "$IG_LOCKDIR"; meta_missing=0
            fi
            sleep 1; waited=$((waited + 1))
        elif ! kill -0 "$holder" 2>/dev/null; then
            ig_say "reaping a stale install lock (holder pid $holder is gone: $(cat "$IG_LOCKDIR/owner" 2>/dev/null))"
            rm -rf "$IG_LOCKDIR"
            sleep 1; waited=$((waited + 1))
        else
            meta_missing=0
            if [ "$waited" -ge "$wait_max" ]; then
                ig_say "install lock still $(ig_lock_status_line)"
                ig_say "gave up after ${waited}s; nothing was installed. Retry once it is free"
                ig_say "(scripts/install_guard.sh status), or raise MACAPK_INSTALL_LOCK_TIMEOUT."
                return 75
            fi
            [ $((waited % 60)) -eq 0 ] && ig_say "waiting: install lock $(ig_lock_status_line)"
            sleep 5; waited=$((waited + 5))
        fi
    done
}

ig_lock_release() {
    if [ "$IG_LOCK_OWNED" = 1 ] && [ "$(cat "$IG_LOCKDIR/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$IG_LOCKDIR"
    fi
    IG_LOCK_OWNED=0
    return 0
}

# ---- what is installed --------------------------------------------------------
# Loads IG_I_* from the install record, or, before any record exists, from the
# BuildInfo stamp linked into the canonical MacApk ("yymmdd.HHMM-<hash>[+dirty]").
ig_load_installed() {
    local canonical="$1" rec stamp
    IG_I_COMMIT=""; IG_I_DIRTY=""; IG_I_VERSION=""; IG_I_TREE=""; IG_I_BRANCH=""
    IG_I_BY=""; IG_I_WHAT=""; IG_I_AT=""; IG_I_SOURCE=""; IG_I_BASE=""; IG_I_PATCHES=""
    rec="$(ig_record_file "$canonical")"
    if [ -f "$rec" ]; then
        IG_I_COMMIT="$(sed -n 's/^COMMIT=//p' "$rec")"
        IG_I_DIRTY="$(sed -n 's/^DIRTY=//p' "$rec")"
        IG_I_VERSION="$(sed -n 's/^VERSION=//p' "$rec")"
        IG_I_TREE="$(sed -n 's/^TREE=//p' "$rec")"
        IG_I_BRANCH="$(sed -n 's/^BRANCH=//p' "$rec")"
        IG_I_BY="$(sed -n 's/^BY=//p' "$rec")"
        IG_I_WHAT="$(sed -n 's/^WHAT=//p' "$rec")"
        IG_I_AT="$(sed -n 's/^AT=//p' "$rec")"
        IG_I_BASE="$(sed -n 's/^BASE=//p' "$rec")"
        IG_I_PATCHES="$(sed -n 's/^PATCH=//p' "$rec")"
        IG_I_SOURCE="record"
    elif [ -x "$canonical/Contents/MacOS/MacApk" ]; then
        stamp="$(strings -a "$canonical/Contents/MacOS/MacApk" 2>/dev/null \
            | grep -oE '^[0-9]{6}\.[0-9]{4}-[0-9a-f]{7,}(\+dirty)?$' | sort -u | head -n 1)"
        if [ -n "$stamp" ]; then
            IG_I_COMMIT="${stamp#*-}"; IG_I_COMMIT="${IG_I_COMMIT%+dirty}"
            case "$stamp" in *+dirty) IG_I_DIRTY=1 ;; *) IG_I_DIRTY=0 ;; esac
            IG_I_SOURCE="launcher stamp $stamp"
        fi
    fi
    [ -n "$IG_I_COMMIT" ]
}

ig_installed_desc() {
    local s="${IG_I_COMMIT:0:10}"
    [ "$IG_I_DIRTY" = 1 ] && s="$s+dirty"
    [ -n "$IG_I_VERSION" ] && s="v$IG_I_VERSION ($s)"
    [ -n "$IG_I_TREE" ] && s="$s from $IG_I_TREE${IG_I_BRANCH:+ [$IG_I_BRANCH]}"
    [ -n "$IG_I_BY" ] && s="$s by $IG_I_BY"
    [ -n "$IG_I_AT" ] && s="$s at $(date -r "$IG_I_AT" '+%Y-%m-%d %H:%M' 2>/dev/null)"
    [ "$IG_I_SOURCE" != "record" ] && s="$s (from the $IG_I_SOURCE; no install record yet)"
    echo "$s"
}

# git in <tree>, also able to read objects from the tree the installed build came
# from -- so a commit made only in another clone can still be compared, without
# fetching anything into <tree>.
ig_git() {
    local tree="$1"; shift
    local alt="" src="$IG_I_TREE"
    # No record yet (bootstrapped from the launcher stamp): the primary checkout
    # is the likeliest place that commit lives.
    [ -z "$src" ] && [ -s "$IG_STATE/primary-checkout" ] && src="$(cat "$IG_STATE/primary-checkout")"
    if [ -n "$src" ] && [ -d "$src" ]; then
        alt="$(git -C "$src" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)/objects"
        [ -d "$alt" ] || alt=""
    fi
    if [ -n "$alt" ]; then
        GIT_ALTERNATE_OBJECT_DIRECTORIES="$alt" git -C "$tree" "$@"
    else
        git -C "$tree" "$@"
    fi
}

ig_check_contains() {
    local tree="$1" canonical="${2:-$IG_DEFAULT_CANONICAL}" head missing n ver
    local IG_MISSING_DESCRIBED=0
    [ -d "$canonical" ] || return 0          # nothing installed: nothing to protect
    ig_load_installed "$canonical" || {
        ig_say "NOTE: cannot tell which commit $canonical was built from; not checking."
        return 0
    }
    head="$(git -C "$tree" rev-parse HEAD 2>/dev/null)" || {
        ig_say "NOTE: $tree is not a git checkout; cannot check it against the installed build."
        return 0
    }
    ver="$(cat "$tree/VERSION" 2>/dev/null || echo '?')"
    if ig_git "$tree" merge-base --is-ancestor "$IG_I_COMMIT" HEAD 2>/dev/null; then
        return 0
    fi
    if ig_git "$tree" cat-file -e "$IG_I_COMMIT^{commit}" 2>/dev/null; then
        # Not an ancestor -- but the same changes may have landed under other
        # hashes (rebased or cherry-picked into main). `git cherry` marks a
        # commit '-' when an equivalent patch is already in HEAD.
        missing="$(ig_git "$tree" cherry HEAD "$IG_I_COMMIT" 2>/dev/null | sed -n 's/^+ //p')"
        [ -z "$missing" ] && return 0
        n="$(printf '%s\n' "$missing" | wc -l | tr -d ' ')"
    elif [ -n "$IG_I_BASE" ] && git -C "$tree" merge-base --is-ancestor "$IG_I_BASE" HEAD 2>/dev/null; then
        # The installed commit is gone (its clone was cleaned up) or was never
        # here, but the record kept the upstream commit it was built on (BASE)
        # and a patch-id per commit on top of it. If this tree contains BASE
        # and an equivalent of every one of those patches -- e.g. the lane's
        # work landed on main via rebase or `git apply` -- it contains the
        # install.
        local have pid
        have="$(git -C "$tree" log -p --no-merges "$IG_I_BASE..HEAD" 2>/dev/null \
                | git patch-id --stable 2>/dev/null | cut -d' ' -f1)"
        missing=""
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            pid="${line%% *}"
            printf '%s\n' "$have" | grep -qx "$pid" || missing="$missing${missing:+
}${line#* }"
        done <<< "$IG_I_PATCHES"
        [ -z "$missing" ] && return 0
        n="$(printf '%s\n' "$missing" | wc -l | tr -d ' ')"
        IG_MISSING_DESCRIBED=1
    else
        missing=""; n="?"
    fi
    if [ "${MACAPK_FORCE_INSTALL:-0}" = 1 ]; then
        ig_say "MACAPK_FORCE_INSTALL=1: replacing the installed $(ig_installed_desc)"
        ig_say "  with $(ig_toplevel "$tree") at ${head:0:10} (v$ver), which lacks $n of its commit(s)."
        return 0
    fi
    ig_say "REFUSED: this would replace the installed build with an older or diverged one."
    ig_say "  installed: $(ig_installed_desc)"
    ig_say "  this tree: $(ig_toplevel "$tree") at ${head:0:10} (v$ver)"
    if [ -n "$missing" ] && [ "${IG_MISSING_DESCRIBED:-0}" = 1 ]; then
        ig_say "  missing here ($n commit(s), matched by patch, not hash):"
        printf '%s\n' "$missing" | head -n 8 | while read -r c; do
            ig_say "    $(printf '%s' "${c:0:10}${c:40}" | cut -c1-110)"
        done
    elif [ -n "$missing" ]; then
        ig_say "  missing here ($n commit(s)):"
        printf '%s\n' "$missing" | head -n 8 | while read -r c; do
            ig_say "    $(ig_git "$tree" log -1 --format='%h %s' "$c" 2>/dev/null | cut -c1-110)"
        done
    elif [ -n "$IG_I_TREE" ] && [ ! -d "$IG_I_TREE" ]; then
        ig_say "  the installed commit came from $IG_I_TREE, which no longer exists, and this tree"
        ig_say "  does not contain it. If that build is no longer wanted, the override below is the answer."
    else
        ig_say "  the installed commit is not known to this tree at all (fetch or rebase onto main)."
    fi
    ig_say "  Fix: rebase/merge onto what is installed (usually: git pull origin main), then retry."
    ig_say "  Override, only with the owner's or that installer's OK: MACAPK_FORCE_INSTALL=1"
    return 3
}

ig_record_install() {
    local tree="$1" canonical="${2:-$IG_DEFAULT_CANONICAL}" what="${3:-install}"
    local top rec tmp commit dirty=0 ver br now up base="" patches=""
    top="$(ig_toplevel "$tree")"
    commit="$(git -C "$top" rev-parse HEAD 2>/dev/null || echo unknown)"
    [ -n "$(git -C "$top" status --porcelain --untracked-files=no 2>/dev/null)" ] && dirty=1
    ver="$(cat "$top/VERSION" 2>/dev/null || echo '?')"
    br="$(git -C "$top" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
    now="$(date +%s)"
    # BASE = the upstream commit this build sits on, PATCH = a patch-id per
    # commit on top of it, so a later check can still recognise this install
    # once the clone is deleted or its commits land on main under other hashes.
    up="$(git -C "$top" rev-parse --verify -q '@{upstream}' 2>/dev/null \
          || git -C "$top" rev-parse --verify -q origin/main 2>/dev/null || true)"
    if [ -n "$up" ]; then
        base="$(git -C "$top" merge-base HEAD "$up" 2>/dev/null || true)"
        if [ -n "$base" ] && [ "$(git -C "$top" rev-list --count "$base..HEAD" 2>/dev/null || echo 999)" -le 100 ]; then
            patches="$(git -C "$top" log -p --no-merges --reverse "$base..HEAD" 2>/dev/null \
                       | git patch-id --stable 2>/dev/null \
                       | while read -r pid sha; do
                             echo "PATCH=$pid $sha $(git -C "$top" log -1 --format=%s "$sha" | cut -c1-100)"
                         done)"
        else
            base=""
        fi
    fi
    mkdir -p "$IG_STATE" 2>/dev/null || { ig_say "WARN: cannot create $IG_STATE; install not recorded"; return 0; }
    rec="$(ig_record_file "$canonical")"
    tmp="$rec.tmp.$$"
    {
        echo "COMMIT=$commit"
        echo "DIRTY=$dirty"
        echo "VERSION=$ver"
        echo "TREE=$top"
        echo "BRANCH=$br"
        echo "BY=$(ig_whoami "$top")"
        echo "WHAT=$what"
        echo "AT=$now"
        echo "CANONICAL=$canonical"
        [ -n "$base" ] && echo "BASE=$base"
        [ -n "$patches" ] && printf '%s\n' "$patches"
        true   # the group's status must not be the last [ test ]'s
    } > "$tmp" && mv -f "$tmp" "$rec" || ig_say "WARN: could not write $rec; this install is NOT recorded"
    printf '%s\tv%s\t%s%s\t%s\t%s\t%s\t%s\n' \
        "$(date -r "$now" '+%Y-%m-%dT%H:%M:%S%z')" "$ver" "${commit:0:10}" \
        "$([ "$dirty" = 1 ] && echo +dirty)" "$top" "$br" "$what" "$canonical" \
        >> "$IG_STATE/install-history.log"
    ig_say "recorded install: v$ver ${commit:0:10}$([ "$dirty" = 1 ] && echo +dirty) from $top [$br] ($what)"
}

# ---- CLI ---------------------------------------------------------------------
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -uo pipefail
    IG_HERE="$(cd "$(dirname "$0")/.." && pwd)"
    CANON="${MACAPK_CANONICAL_APP:-$IG_DEFAULT_CANONICAL}"
    cmd="${1:-status}"; shift || true
    case "$cmd" in
        status)
            echo "install lock:      $(ig_lock_status_line)"
            if ig_load_installed "$CANON"; then
                echo "installed:         $(ig_installed_desc)"
            else
                echo "installed:         $([ -d "$CANON" ] && echo "unknown build at $CANON" || echo "nothing at $CANON")"
            fi
            echo "primary checkout:  $(ig_primary_desc)"
            if ig_is_primary "$IG_HERE"; then
                echo "this checkout:     $IG_HERE (primary: build.sh mirrors into the installed app)"
            else
                echo "this checkout:     $IG_HERE (a clone: build.sh leaves the installed app alone)"
            fi
            ;;
        check)
            t="${1:-$IG_HERE}"
            if ig_check_contains "$t" "$CANON"; then
                echo "OK: $(ig_toplevel "$t") contains the installed build; an install from it is allowed."
                exit 0
            fi
            exit 3
            ;;
        history)
            tail -n "${1:-15}" "$IG_STATE/install-history.log" 2>/dev/null || echo "(no installs recorded yet)"
            ;;
        set-primary)
            t="$(ig_toplevel "${1:-$IG_HERE}")"
            mkdir -p "$IG_STATE" && echo "$t" > "$IG_STATE/primary-checkout"
            echo "primary checkout: $t"
            ;;
        run)
            [ $# -gt 0 ] || { echo "usage: $0 run <cmd...>" >&2; exit 2; }
            ig_lock_acquire "$(basename "$1")" || exit $?
            # The child runs in the background and we `wait` for it, because
            # bash defers a trap until a FOREGROUND child returns: a holder
            # killed mid-install would otherwise keep the lock until its child
            # finished. A signal kills the child, releases, and EXITS (a trap
            # that does not exit resumes the script; see debug/applock.sh).
            child=""
            trap 'ig_lock_release' EXIT
            trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; ig_lock_release; exit 130' INT
            trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; ig_lock_release; exit 143' TERM
            "$@" &
            child=$!
            wait "$child"
            ;;
        *)
            echo "usage: $0 status | check [tree] | history [N] | set-primary [tree] | run <cmd...>" >&2
            exit 2
            ;;
    esac
fi
