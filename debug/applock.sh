#!/usr/bin/env bash
# debug/applock.sh — serialize EXCLUSIVE machine operations across concurrent
# Claude sessions / fan-out agents working in this ONE checkout.
#
# WHY: a cmake build and an app launch both want exclusive access to the same
# resources (runtime/build/**, runtime/build/bin/macapk-runtime, the GPU, the
# window server, the shared ~/Documents/android cache). Two agents doing either
# at once produces corrupt builds, cross-contaminated logs, and bogus render
# verdicts. Anything that BUILDS or RUNS the runtime must go through here.
#
# Reading files, grepping, disassembling, and static analysis do NOT need it.
#
# Usage:
#   debug/applock.sh <command...>            # run under the lock (waits its turn)
#   debug/applock.sh --timeout 1800 <cmd...> # max seconds to WAIT for the lock
#   debug/applock.sh --status                # who holds it / how long
#
# Exit codes: the command's own, or 75 (EX_TEMPFAIL) if the wait timed out.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# ---- WHAT ACTUALLY NEEDS THIS LOCK (clarified v1.0.837) --------------------
# The hazard is SHARED MUTABLE STATE, and there are exactly two pieces of it:
#
#   1. STAGING -- the `cp`/`mv` into `runtime/build/bin/` or `runtime/build/lib/`.
#      Swapping a binary or jar under a run in flight splits a measurement in two
#      and makes it uninterpretable. Three sweeps were corrupted this way on
#      2026-07-29.
#   2. RUNNING an app, when the verdict is TIMING-dependent (fps, frame pacing,
#      input latency, "renders then freezes"). Plain "does it draw" verdicts were
#      authorised to run 2-3 concurrent by the owner on 2026-07-29.
#
# COMPILING AND LINKING DO **NOT** NEED THIS LOCK. `cmake --build` writes into
# `runtime/translator/build/` or `runtime/build/native/` -- private directories that
# no sweep and no other lane reads. Only the SEPARATE `cp` afterwards is dangerous.
# Wrapping the whole build was over-broad: `scripts/sweep.sh` now holds the lock for
# its entire ~30 min duration, so a lane that wrapped its BUILD blocked for up to an
# hour to protect state its build never touched. One lane burned ~25 minutes of a
# night's runway that way.
#
# So: **wrap the STAGE, not the build.**
#     cmake --build runtime/translator/build --target macapk-bionic-shim -j8   # no lock
#     debug/applock.sh --timeout 3600 cp ... runtime/build/bin/                # lock
# A single-TU `-fsyntax-only` check is free and needs no lock at all.
#
# ---- IF YOU ONLY NEED TO *READ* A STAGED BINARY: SNAPSHOT, DO NOT HOLD -------
# Added 2026-07-30 after a fleet analysis job held this lock for ~30 minutes with
# `--timeout 12000` while never launching a single app. Its only claim on shared
# state was that it READ `runtime/build/bin/libmacapk-bionic-shim.dylib` and did
# not want a concurrent stage to swap it mid-scan. That is a real hazard, and an
# exclusive hold on the whole machine is the wrong instrument for it: three lanes
# queued behind a job that needed one consistent FILE, not one idle GPU.
#
# The right shape is to take a consistent COPY under a short lock, release, and
# analyse the copy:
#
#     debug/applock.sh --timeout 600 cp runtime/build/bin/<artifact> /tmp/snap.dylib
#     ... long analysis reads /tmp/snap.dylib, NO lock held ...
#
# Seconds instead of hours, and the RESULT IS STRONGER: it is pinned to one known
# binary rather than to whatever happened to be staged as the scan rolled through.
# A long analysis that holds the lock is silently measuring a moving target the
# moment anyone stages, which is the very thing it took the lock to prevent.
#
# Rule of thumb: hold the lock for as long as you are WRITING shared state or
# running a timing-sensitive app, and no longer. If your job's own header says it
# does not run anything, it should not be holding this for more than a copy.
LOCKDIR="${MACAPK_LOCKDIR:-/tmp/macapk-machine.lock}"
QDIR="${LOCKDIR}.q"

# ---- FIFO FAIRNESS (added v1.0.838) ----------------------------------------
# WHY. Acquisition used to be a bare `mkdir` spin polled every 5s. That is a
# RACE, not a queue: whoever happens to call mkdir first after a release wins,
# regardless of how long anyone has waited. It was survivable while holders were
# short. It stopped being survivable once scripts/sweep.sh and
# debug/parallel_render.sh started holding the lock for their WHOLE run (30-60
# min, deliberately, so a mid-run stage cannot split a measurement) -- a lane
# doing single-app window captures then loses the race indefinitely against
# lanes doing multi-app batches.
#
# MEASURED: one lane waited 27 minutes of a 40-minute timeout without ever
# starting, and a second waited 19, while batch holders cycled. That is my own
# interlock starving the work it was meant to protect.
#
# Fix: a ticket queue. On arrival a waiter drops <epoch>.<pid> into QDIR; it may
# only attempt mkdir when it is the OLDEST live entry. Stale tickets (dead pid)
# are reaped, so a killed waiter cannot wedge the queue. Ordering is by arrival,
# so a long batch hold delays everyone once instead of starving one lane forever.
mkdir -p "$QDIR" 2>/dev/null
TICKET="$QDIR/$(date +%s).$$"
: > "$TICKET"
cleanup_ticket() { rm -f "$TICKET" 2>/dev/null; }
# ---- A SIGNAL TRAP MUST EXIT. -----------------------------------------------
# `trap handler EXIT INT TERM` looks like "clean up and die" and is NOT: for a
# SIGNAL, bash runs the handler and then RESUMES the script. So a waiter caught
# by SIGTERM deleted its own queue ticket and KEPT WAITING -- alive but
# ticketless, which under the FIFO means `queue_head_is_me` can never be true
# again, so it can never acquire and simply burns its whole timeout. It also
# could not be stopped by an ordinary `kill`; only `kill -9` worked.
# MEASURED 2026-07-30: two such waiters (59706, 73063) survived their own kill
# and held all 10 lanes at `--status FREE` with 6 tickets queued.
# Reproduced directly: SIGTERM -> "process SURVIVED and is still running,
# ticket deleted". Signal traps therefore exit explicitly, with the conventional
# 128+signo status so callers can still tell how it died.
trap 'cleanup_ticket' EXIT
trap 'cleanup_ticket; exit 130' INT
trap 'cleanup_ticket; exit 143' TERM
# ⚠ TERMINATION IS NOT INSTANT, and a check that ignores this will lie. Bash
# defers a trap until the command it is currently waiting on returns, and this
# loop's longest wait is `sleep 5`. So a killer that sends SIGTERM and checks
# 2 seconds later still sees the process alive and concludes the trap is broken
# -- which is exactly what my first verification of this fix reported. Allow >5s
# before deciding a waiter ignored a signal, or use `kill -9` if you need it gone
# now (at the cost of leaving its ticket behind for the dead-pid reaper).

# Reap tickets whose owner is gone, then report whether WE are at the head.
queue_head_is_me() {
  local f pid head=""
  for f in "$QDIR"/*; do
    [ -e "$f" ] || continue
    pid="${f##*.}"
    if ! kill -0 "$pid" 2>/dev/null; then rm -f "$f" 2>/dev/null; continue; fi
    if [ -z "$head" ] || [ "$(basename "$f")" \< "$(basename "$head")" ]; then head="$f"; fi
  done
  [ "$head" = "$TICKET" ]
}
WAIT_MAX=2400          # default: wait up to 40 min for a turn
STALE_AFTER=2700       # a lock older than 45 min is assumed abandoned

if [ "${1:-}" = "--status" ]; then
  if [ -d "$LOCKDIR" ]; then
    owner=$(cat "$LOCKDIR/owner" 2>/dev/null || echo "?")
    started=$(cat "$LOCKDIR/started" 2>/dev/null || echo 0)
    now=$(date +%s)
    echo "HELD by: $owner (for $((now - started))s)"
  else
    echo "FREE"
  fi
  exit 0
fi

if [ "${1:-}" = "--timeout" ]; then WAIT_MAX="$2"; shift 2; fi
[ $# -gt 0 ] || { echo "usage: debug/applock.sh [--timeout N] <command...>" >&2; exit 2; }

OWNER="${MACAPK_AGENT:-$$}:$(basename "$1")"
acquired=0
waited=0
meta_missing=0          # consecutive polls where LOCKDIR existed with no metadata
META_GRACE_POLLS=15     # ~15s before believing a metadata-less lock is orphaned
while [ $waited -lt "$WAIT_MAX" ]; do
  # mkdir is atomic on every POSIX fs -- the classic lock primitive that,
  # unlike flock(1), actually ships on macOS.
  if queue_head_is_me && mkdir "$LOCKDIR" 2>/dev/null; then
    echo "$OWNER"      > "$LOCKDIR/owner"
    date +%s           > "$LOCKDIR/started"
    echo $$            > "$LOCKDIR/pid"
    acquired=1
    break
  fi
  # Reap an abandoned lock: holder process gone, or older than STALE_AFTER.
  holder=$(cat "$LOCKDIR/pid" 2>/dev/null || echo "")
  started=$(cat "$LOCKDIR/started" 2>/dev/null || echo "")
  now=$(date +%s)
  # RACE GUARD (2026-07-30). `mkdir` is atomic but owner/started/pid are written a
  # few instructions LATER, so there is a brief window where LOCKDIR exists with NO
  # metadata. The old test read started="" -> $((now - )) == now -> "older than
  # STALE_AFTER" -> rm -rf a lock that had JUST been legitimately acquired.
  # The FIFO ticket queue made this pathological: a waiter that is not the queue
  # head skips the mkdir arm entirely, falls straight through to here, reaps, and
  # `continue`s WITHOUT sleeping -- a tight loop that destroys the head's lock over
  # and over. Measured 2026-07-30 under 10 lanes: a reap storm in the log and THREE
  # macapk-runtime processes running concurrently, i.e. the interlock was inverted
  # into a no-op and every window-capture verdict taken then was contaminated.
  # So: treat absent metadata as FRESH, and only reap it once it has stayed absent
  # for META_GRACE_POLLS polls (that still covers a lane killed between the mkdir
  # and the echoes).
  if [ -z "$started" ]; then
    meta_missing=$((meta_missing + 1))
    if [ "$meta_missing" -lt "$META_GRACE_POLLS" ]; then
      sleep 1; waited=$((waited + 1)); continue
    fi
    started=0
  else
    meta_missing=0
  fi
  # ONLY THE QUEUE HEAD MAY REAP (2026-07-30). A non-head waiter reaping is both
  # useless -- it cannot take the lock this pass anyway, the mkdir arm above is
  # gated on queue_head_is_me -- and actively destructive: it deletes the current
  # holder's LOCKDIR and then `continue`s WITHOUT sleeping, so it spins. Measured
  # on this box under 10 lanes: 3,901 reaps from a SINGLE waiter in ~2 minutes,
  # 5 macapk-runtime processes alive at once, and a holder that logged
  # "line 110: /tmp/macapk-machine.lock/pid: No such file or directory" because
  # its LOCKDIR was deleted between its own mkdir and its own metadata writes --
  # after which it ran its command believing it held a lock it did not.
  # Letting only the head reap keeps abandoned locks recoverable (the head always
  # arrives eventually) while removing the stampede entirely.
  if queue_head_is_me \
     && { { [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; } \
          || [ $((now - started)) -gt $STALE_AFTER ]; }; then
    echo "[applock] reaping stale lock (owner=$(cat "$LOCKDIR/owner" 2>/dev/null))" >&2
    rm -rf "$LOCKDIR"
    # Never respin without yielding: a reap that races another lane's fresh mkdir
    # must not become a tight loop.
    sleep 1; waited=$((waited + 1))
    continue
  fi
  [ $((waited % 60)) -eq 0 ] && \
    echo "[applock] waiting for $(cat "$LOCKDIR/owner" 2>/dev/null) (${waited}s)" >&2
  sleep 5; waited=$((waited + 5))
done

if [ "$acquired" != 1 ]; then
  echo "[applock] TIMEOUT after ${WAIT_MAX}s; holder=$(cat "$LOCKDIR/owner" 2>/dev/null)" >&2
  exit 75
fi

# NOTE: this trap REPLACES any earlier one, so it must ALSO drop our queue
# ticket. An earlier version set a ticket-only trap above and had it silently
# overwritten here, leaking a ticket per invocation -- caught by a smoke test
# that showed 2 leftover tickets. Self-healing (dead-pid tickets are reaped)
# but wrong, and it would have made the queue look longer than it is.
cleanup() { rm -rf "$LOCKDIR"; cleanup_ticket; }
# Same rule as the ticket trap above, and it matters MORE here: a HOLDER that
# caught SIGTERM would run cleanup (releasing LOCKDIR) and then carry on running
# its command with the lock already released -- i.e. an unprotected run that
# still believes it is protected, while another lane legitimately acquires.
# Both handlers are idempotent (`rm -rf`/`rm -f`), so the EXIT trap firing after
# an explicit exit is harmless.
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Run the child, then REPORT ITS EXIT STATUS ON STDERR before exiting with it.
#
# WHY THE ECHO EXISTS (added v1.0.837). applock already propagated the status
# correctly -- `"$@"` as the last command makes it the script's status. The trap is
# on the CALLER side: `debug/applock.sh ... | tail` makes `$?` the status of TAIL,
# not of applock, so a failing build reports success. That has now bitten twice in
# one night, in two different shapes:
#   * `applock.sh ... | tail` -> a shim build reported "exit 0" while it had failed
#     to compile; only the stale .dylib mtime revealed it.
#   * `javac ... | grep error; echo $?` -> echoed GREP's status, reported success
#     while javac was failing with 2 errors, and the stale jar then silently
#     measured the OLD code, so a real fix looked like it did nothing.
# Same family as the documented `cmd | grep ... && cp` stale-staging trap.
#
# A caller can still get this wrong, so applock now says so out loud on stderr,
# which survives a stdout pipe. If you see this line, the child FAILED regardless
# of what `$?` told you. (Prefer redirecting to a file and checking `$?` directly,
# or `set -o pipefail`.)
# ---- MAKE HOLDING THE LOCK OBSERVABLE TO DESCENDANTS (2026-07-30) ----------
# Scripts that self-lock (scripts/sweep.sh, debug/parallel_render.sh,
# debug/build_java_only.sh) re-exec themselves under this script unless they can
# see that the lock is already held. Until now applock exported NOTHING, so the
# documented call shape `debug/applock.sh debug/build_java_only.sh` made the
# child re-exec into a SECOND applock that waited on the lock ITS OWN PARENT
# held -- a self-deadlock that wedged the machine for ~14 minutes and queued
# every other lane behind it:
#   43760  bash applock.sh --timeout 5400 build_java_only.sh   <- HOLDS the lock
#   98082  bash applock.sh --timeout 3600 build_java_only.sh   <- waits for 43760
# The child's log filled with "[applock] waiting for 43760:build_java_only.sh".
#
# The old contract was "a caller who already holds the lock must set the marker
# himself", which nothing communicated and nothing enforced -- the same class of
# bug as the signal traps above. Exporting it here makes BOTH call shapes correct:
# wrap-it-yourself, and let-it-self-lock.
export MACAPK_APPLOCK_HELD=1

# ---- HOLD THE DISPLAY AWAKE FOR THE LIFE OF THE LOCK ------------------------
# Every measurement in this project renders through an MTKView, and A SLEEPING
# DISPLAY STOPS ITS DISPLAY LINK: `drawInMTKView` never fires, EGL never
# initializes, the GL thread never starts, and the guest's main thread idles
# forever on an empty MessageQueue. The app is perfectly healthy and every
# capture reads zero.
#
# Measured 2026-08-23. The display slept at 18:46:27 and poisoned everything
# after it. TWO independent lanes lost hours to it on the same evening:
#   * a sweep lane spent SEVEN diagnostic runs -- flake-repeat, two source
#     reverts, a cache wipe, a feature-gate bisect, a thread dump, and a full
#     `git stash` clean-tree test -- each of which "confirmed" a regression that
#     did not exist, because each also ran against a dark display;
#   * a Canvas-capture lane got `NO_CAPTURE` on every app with neither
#     `macapkDrawFrame fire #1` nor `skip #1`, which reads exactly like a
#     catastrophic render regression, and nearly filed it as one.
# Controlled A/B, identical binary+jar+data: display OFF 0/3 rendered and
# `fire=0`; display ON 6/6 at ~59fps and `fire=8`.
#
# It belongs HERE rather than in any one harness because EVERY machine-bound
# job comes through this lock -- sweep.sh, recap_mac.sh, recap_fleet.sh,
# rendercheck.sh, fwprobe, and whatever gets written next. A grep on
# 2026-08-23 found ZERO defenses against this anywhere in debug/ or scripts/.
#
# `-d` prevents DISPLAY sleep only: not idle sleep, not the user's own lock, and
# not their screensaver choice. `-w $$` ties it to this process, so it dies with
# the lock even on a signal path -- no stray assertion outliving the run.
# Opt out with MACAPK_NO_CAFFEINATE=1.
if [ -z "${MACAPK_NO_CAFFEINATE:-}" ] && command -v caffeinate >/dev/null 2>&1; then
  caffeinate -d -w $$ &
fi

"$@"
__rc=$?
if [ "$__rc" -ne 0 ]; then
  echo "[applock] *** CHILD EXITED $__rc *** ($*)" >&2
  echo "[applock] if your \$? said 0, you piped applock's stdout -- \$? was the pipe's" >&2
fi
exit $__rc
