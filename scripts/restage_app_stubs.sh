#!/usr/bin/env bash
# scripts/restage_app_stubs.sh -- push the current per-app stub template into
# every ALREADY-INSTALLED app bundle.
#
# WHY THIS EXISTS (measured 2026-08-12, v1.0.962). Each installed <Label>.app
# carries its OWN copy of the stub, renamed to the bundle's CFBundleExecutable
# (BundleGenerator.finalize step 3: "the executable must be renamed with the
# bundle"). That copy is frozen at install time. Nothing refreshed it, so a stub
# change reached only apps installed AFTER the change -- on this machine the 11
# installed bundles were running a stub 17 hours older than the template.
#
# scripts/rebuild_and_run.sh used to state the opposite in a comment: that
# per-app bundles have "nothing to refresh BY CONSTRUCTION" because they "embed
# no runtime, no jars and no translator". True for those three; the stub binary
# itself was the exception nobody listed. That comment also named the fix --
# "WHEN THAT CHANGES ... restage those files here, with ditto" -- which is this
# script, now called from that spot.
#
# v1.0.1592: the PRODUCT does this itself now -- `StubRefresh` in
# launcher/InstallCore.swift: every stub compares itself with the installed
# Mac.apk's template on launch and re-executes the fresh copy when it differs,
# `RuntimeInstall.install` refreshes every installed bundle right after a
# runtime (re)stage, and the control panel sweeps once per session. This script
# stays as the developer's immediate, whole-machine restage after a promote
# (and as the oracle a fresh mechanism is checked against: same md5 test).
#
# Usage:
#   scripts/restage_app_stubs.sh [--template <path>] [--dry-run]
#
# Exit: 0 if every bundle is current (or was made current), 1 on a real failure.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

TEMPLATE=""
DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --template) TEMPLATE="$2"; shift 2 ;;
        --dry-run)  DRY=1; shift ;;
        *) echo "Unknown arg: $1 (flags: --template <path>, --dry-run)" >&2; exit 2 ;;
    esac
done

# Resolve the template. The canonical app is the promoted one and therefore the
# one whose stub matches the runtime every installed app will exec, so it wins
# over the repo copy (which rebuild_and_run.sh deletes after promoting anyway).
if [ -z "$TEMPLATE" ]; then
    for cand in \
        "${MACAPK_CANONICAL_APP:-/Applications/Mac.apk.app}/Contents/Resources/appstub/MacApkAppStub" \
        "build/Mac.apk.app/Contents/Resources/appstub/MacApkAppStub"
    do
        [ -f "$cand" ] && { TEMPLATE="$cand"; break; }
    done
fi
if [ ! -f "$TEMPLATE" ]; then
    echo "restage_app_stubs: no stub template found (looked in the canonical app" >&2
    echo "  and build/Mac.apk.app). Build the launcher first." >&2
    exit 1
fi
WANT="$(md5 -q "$TEMPLATE")"
echo "==> Stub template: $TEMPLATE ($WANT)"

REG="$HOME/Library/Application Support/Mac.apk/installed_apps.json"
if [ ! -f "$REG" ]; then
    echo "    no installed-apps registry at $REG; nothing to restage."
    exit 0
fi

# The registry is the authoritative list of installed bundles; CFBundleExecutable
# inside each one is the authoritative name of its stub copy. Deriving the name
# from the bundle's filename instead would break the moment a label and its
# executable disagree, which finalize's rename path explicitly allows.
BUNDLES="$(python3 - "$REG" <<'PY'
import json, sys, os, plistlib
try:
    apps = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("registry unreadable: %s\n" % e); sys.exit(0)
if isinstance(apps, dict):
    apps = apps.get("apps", [])
import subprocess
def read_plist(path):
    # plistlib is a STRICT XML parser. Bundles generated between 2026-08-24 and
    # v1.0.1584 carry an XML comment with a bare `--` inside (not well-formed;
    # CoreFoundation tolerates it), and plistlib raised ExpatError on every one
    # of them -- so this script silently SKIPPED Minecraft, Instagram, Aurora,
    # Efteling and camtest for weeks while debug/staleness.sh reported "all
    # installed bundles carry the current template". Parse the way macOS does
    # when plistlib cannot; a bundle is only ever skipped OUT LOUD below.
    try:
        return plistlib.load(open(path, "rb"))
    except Exception:
        pass
    out = subprocess.run(["plutil", "-convert", "json", "-o", "-", path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "plutil failed")
    return json.loads(out.stdout)
for a in apps:
    # "ok" is the v1 registry's spelling of installed; a removed row's bundle
    # is gone by definition and everything else (installing/broken) is a row
    # whose bundle may be half-built.
    if not isinstance(a, dict) or a.get("state") not in (None, "installed", "ok"):
        continue
    b = a.get("bundlePath")
    if not b or not os.path.isdir(b):
        continue
    pl = os.path.join(b, "Contents", "Info.plist")
    try:
        exe = read_plist(pl).get("CFBundleExecutable")
    except Exception as e:
        sys.stderr.write("    SKIPPED  %s -- Info.plist unreadable (%s): %s\n"
                         % (a.get("label") or b, e, pl))
        continue
    if exe:
        print("%s\t%s" % (os.path.join(b, "Contents", "MacOS", exe), a.get("label") or b))
PY
)"

[ -z "$BUNDLES" ] && { echo "    no installed bundles found."; exit 0; }

rc=0; updated=0; current=0
while IFS=$'\t' read -r exe label; do
    [ -z "$exe" ] && continue
    if [ ! -f "$exe" ]; then
        echo "    MISSING  $label -- no stub at $exe (bundle damaged; reinstall it)"
        rc=1; continue
    fi
    have="$(md5 -q "$exe")"
    if [ "$have" = "$WANT" ]; then
        current=$((current+1)); continue
    fi
    if [ "$DRY" = "1" ]; then
        echo "    STALE    $label ($have)"
        updated=$((updated+1)); continue
    fi
    # temp + mv, never a write-in-place: replacing the file of a RUNNING app
    # in place is ETXTBSY, while an atomic rename swaps the directory entry and
    # leaves the running process on its old inode. Also means an interrupted
    # copy can never leave a half-written, unlaunchable stub.
    #
    # No codesign here, by contract: the template was ad-hoc signed as a
    # standalone file at build time and ditto preserves that signature.
    # Generated bundles are NEVER signed as bundles (AppStubMain.swift's
    # SIGNING MODEL note) -- signing one would seal it and app data written
    # under Contents/android/ would break the seal.
    tmp="$(dirname "$exe")/.restage.$$"
    if ditto "$TEMPLATE" "$tmp" 2>/dev/null && mv -f "$tmp" "$exe"; then
        echo "    UPDATED  $label ($have -> $WANT)"
        updated=$((updated+1))
    else
        rm -f "$tmp"
        echo "    FAILED   $label -- could not replace $exe" >&2
        rc=1
    fi
done <<< "$BUNDLES"

echo "==> $updated updated, $current already current."
exit $rc
