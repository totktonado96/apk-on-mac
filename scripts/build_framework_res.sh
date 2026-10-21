#!/usr/bin/env bash
# build_framework_res.sh
#
# Builds Android's platform resource table (framework-res.apk) from AOSP
# source (frameworks/base/core/res, Apache-2.0) with the standalone aapt2
# from the SDK build-tools already vendored under android-emulator/. This
# is the SHIPPABLE replacement for the two tables we must not ship:
#   - apktool's bundled ~/Library/apktool/framework/1.apk (API 36, wrong
#     level for the API-30 oracle, and not ours to redistribute), and
#   - the Google-built framework-res.apk extracted from the emulator
#     system image by debug/extract_fw_res.py (right level, but a Google
#     binary that must never enter the repo).
#
# Output: thirdparty/framework-res/framework-res-api<LEVEL>.apk (~48 MB,
# gitignored like every other locally-built thirdparty artifact). Point
# the runtime at it with MACAPK_FW_RES_APK=<path> (see
# ResourceIndex.macapkFrameworkTable).
#
# One-time cost, same category as scripts/build_angle.sh but far cheaper:
# a ~20 MB source tarball fetch plus ~30 s of aapt2. Verified 2026-08-08
# against the Google-built API-30 table: 9,194/11,190 entries semantically
# identical (references compared by name); the residue is 6 Google-internal
# emulator-image patches, pseudolocale coverage, and product filtering.
# With --reference-apk supplied, resource IDS also match: 11,188/11,189
# (the one exception is a bool the android-11.0.0_r48 tag itself pins
# differently from Google's shipped build).
#
# Soong is NOT required. The Android.bp for framework-res declares only
# three aapt2 flags (--private-symbols com.android.internal,
# --no-auto-version, --auto-add-overlay); Soong's only other contributions
# are the min/target sdk version (without which <adaptive-icon> refuses to
# link) and platform signing, which is irrelevant here because the runtime
# only reads resources.arsc out of the zip and never verifies a signature.
#
# Usage:
#   scripts/build_framework_res.sh                # API 30 (the oracle level)
#   scripts/build_framework_res.sh --api 34 --tag android-14.0.0_r1
#   # THE SHIPPED TABLE (v1.0.1589): API 36 with apktool's ids as stable-ids,
#   # so names/ids agree with the decoded text tree:
#   AAPT2=<apktool's prebuilt/macosx/aapt2> scripts/build_framework_res.sh \
#       --api 36 --tag android-16.0.0_r2 --version-name 16 \
#       --reference-apk runtime/build/bin/tools/framework-res.apk
#   scripts/build_framework_res.sh --reference-apk /tmp/framework-res-api30.apk
#
# --reference-apk <apk>: OPTIONAL. A framework-res.apk whose resource-id
#   assignment we should reproduce (aapt2 --stable-ids), typically the one
#   extract_fw_res.py pulls from the local emulator image. PUBLIC ids are
#   already pinned by AOSP's own public.xml either way; the reference only
#   adds INTERNAL-id equality, which the answer-probe golden needs on
#   internally-terminated chains (res=0x0106xxxx and friends). The
#   reference apk is consumed locally and nothing derived from a Google
#   binary is written into the repo by default.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PROJECT_DIR/thirdparty/framework-res"

# Pinned AOSP tag the default build comes from. android-11.0.0_r48 is an
# Android 11 (API 30) release tag, matching both the fwprobe golden AVD and
# the fleet's pixel-reference emulator (the only system image on this box).
API_LEVEL=30
AOSP_TAG="android-11.0.0_r48"
VERSION_NAME="11"
REFERENCE_APK=""
STABLE_IDS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --api)            API_LEVEL="$2"; shift 2 ;;
        --tag)            AOSP_TAG="$2"; shift 2 ;;
        --version-name)   VERSION_NAME="$2"; shift 2 ;;
        --reference-apk)  REFERENCE_APK="$2"; shift 2 ;;
        --stable-ids)     STABLE_IDS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# aapt2: prefer the SDK build-tools already vendored for the emulator
# oracle; allow AAPT2=<path> override for a fresh machine.
AAPT2="${AAPT2:-}"
if [ -z "$AAPT2" ]; then
    for bt in "$PROJECT_DIR"/android-emulator/android-sdk/build-tools/*/aapt2; do
        [ -x "$bt" ] && AAPT2="$bt"
    done
fi
# The SDK was deleted from this machine on 2026-08-31 (CLAUDE.md); the
# Homebrew apktool keg ships a macOS aapt2 (2.20) inside its jar, which is
# what built the shipped API-36 apk (v1.0.1589). Extracted on demand.
if [ -z "$AAPT2" ]; then
    KEG_JAR="$(ls -t /opt/homebrew/Cellar/apktool/*/libexec/apktool_*.jar 2>/dev/null | head -1)"
    if [ -n "$KEG_JAR" ] && unzip -l "$KEG_JAR" 2>/dev/null | grep -q "prebuilt/macosx/aapt2"; then
        mkdir -p "$OUT_DIR/aapt2"
        unzip -p "$KEG_JAR" prebuilt/macosx/aapt2 > "$OUT_DIR/aapt2/aapt2" && chmod +x "$OUT_DIR/aapt2/aapt2" \
            && AAPT2="$OUT_DIR/aapt2/aapt2" && echo "aapt2: extracted from $KEG_JAR"
    fi
fi
[ -n "$AAPT2" ] && [ -x "$AAPT2" ] || {
    echo "no aapt2 found; brew install apktool (its jar carries one), install SDK build-tools, or set AAPT2=<path>" >&2; exit 2; }

WORK="$OUT_DIR/work-$AOSP_TAG"
mkdir -p "$WORK"
TARBALL="$WORK/core-res.tar.gz"
SRC="$WORK/src"

# [1/4] fetch the core/res subtree only (googlesource serves per-directory
# archives, so this is ~20 MB instead of a multi-GB frameworks/base clone).
if [ ! -f "$SRC/AndroidManifest.xml" ]; then
    echo "[1/4] fetching frameworks/base/core/res @ $AOSP_TAG ..."
    curl -sSL -o "$TARBALL" \
        "https://android.googlesource.com/platform/frameworks/base/+archive/refs/tags/$AOSP_TAG/core/res.tar.gz"
    mkdir -p "$SRC"
    tar -xzf "$TARBALL" -C "$SRC"
    [ -f "$SRC/MODULE_LICENSE_APACHE2" ] || {
        echo "archive did not unpack to a core/res tree (no MODULE_LICENSE_APACHE2)" >&2; exit 1; }
else
    echo "[1/4] source cached: $SRC"
fi

# Android 15+ sources carry aconfig `android:featureFlag` alternatives -- on
# resources (android-16.0.0_r2: one, the appwidget corner radius) and on the
# manifest's permission/feature declarations (40 more) -- and aapt2 refuses
# both compile and link without a value for every flag named. A flag only
# selects between two shipped alternatives; the values that matter to a
# RESOURCE table read by Mac.apk are none of them (the manifest ones gate
# platform permissions our own PackageManager answers). Every flag found in
# the tree is set to its RELEASED state (:ro=true) unless FEATURE_FLAGS
# overrides the whole list ("a=true,b:ro=false").
if [ -z "${FEATURE_FLAGS:-}" ]; then
    FEATURE_FLAGS="$(grep -rhoE 'featureFlag="!?[^"]+"' "$SRC/AndroidManifest.xml" "$SRC/res" 2>/dev/null \
        | sed -E 's/featureFlag="!?//; s/"$//' | sort -u | sed 's/$/:ro=true/' | paste -sd, -)"
    [ -n "$FEATURE_FLAGS" ] && echo "    feature flags: $(echo "$FEATURE_FLAGS" | tr ',' '\n' | wc -l | tr -d ' ') (all :ro=true)"
fi

# [2/4] compile. --pseudo-localize matches the shipped table's en-XA/ar-XB
# pseudolocale coverage (Google builds framework-res with it).
COMPILED="$WORK/compiled.zip"
if [ ! -f "$COMPILED" ] || [ "$SRC/AndroidManifest.xml" -nt "$COMPILED" ]; then
    echo "[2/4] aapt2 compile (~25 s) ..."
    "$AAPT2" compile --dir "$SRC/res" --pseudo-localize \
        ${FEATURE_FLAGS:+--feature-flags "$FEATURE_FLAGS"} -o "$COMPILED"
else
    echo "[2/4] compiled cache: $COMPILED"
fi

# Optional stable-ids map from a reference apk. aapt2's own dump provides
# the name->id table; no other tool touches the reference binary.
if [ -n "$REFERENCE_APK" ] && [ -z "$STABLE_IDS" ]; then
    echo "[3/4] deriving stable-ids from $REFERENCE_APK ..."
    STABLE_IDS="$WORK/stable-ids.txt"
    "$AAPT2" dump resources "$REFERENCE_APK" 2>/dev/null | python3 -c '
import re, sys
seen = {}
for line in sys.stdin:
    r = re.match(r"\s*resource (0x01[0-9a-f]{6}) ((?:[\w.+-]+)/(?:[\w.+-]+))(\s|$)", line)
    if r and r.group(2) not in seen:
        seen[r.group(2)] = r.group(1)
for k, v in sorted(seen.items()):
    print("android:%s = %s" % (k, v))
' > "$STABLE_IDS"
    echo "    $(wc -l < "$STABLE_IDS" | tr -d ' ') ids"
else
    echo "[3/4] stable-ids: ${STABLE_IDS:-none (self-assigned internal ids)}"
fi

# [4/4] link. Flags are frameworks/base/core/res/Android.bp verbatim plus
# the min/target sdk that Soong derives from the platform level. The tag
# and the shipped image can disagree on a public-group pin (seen once at
# android-11.0.0_r48); when a reference map collides with the tag's own
# public.xml, the tag wins and the colliding map line is dropped, loudly.
APK="$OUT_DIR/framework-res-api$API_LEVEL.apk"
link_once() {
    "$AAPT2" link -o "$APK" \
        ${FEATURE_FLAGS:+--feature-flags "$FEATURE_FLAGS"} \
        --manifest "$SRC/AndroidManifest.xml" \
        -A "$SRC/assets" \
        --private-symbols com.android.internal \
        --no-auto-version \
        --auto-add-overlay \
        --min-sdk-version "$API_LEVEL" --target-sdk-version "$API_LEVEL" \
        --version-code "$API_LEVEL" --version-name "$VERSION_NAME" \
        ${STABLE_IDS:+--stable-ids "$STABLE_IDS"} \
        "$COMPILED" 2> "$WORK/link.err"
}
echo "[4/4] aapt2 link ..."
for round in 1 2 3 4 5 6 7 8; do
    if link_once; then
        echo "    linked (round $round)"
        break
    fi
    if [ -z "$STABLE_IDS" ]; then
        echo "link failed:" >&2; cat "$WORK/link.err" >&2; exit 1
    fi
    dropped=""
    for name in $(grep -o "already assigned to android:[A-Za-z0-9_./+-]*[A-Za-z0-9_]" \
                    "$WORK/link.err" | sed 's/.*android://' | sort -u); do
        echo "    NOTE: tag public.xml disagrees with reference on '$name'; tag wins" >&2
        grep -v "^android:$name = " "$STABLE_IDS" > "$STABLE_IDS.t" && mv "$STABLE_IDS.t" "$STABLE_IDS"
        dropped=1
    done
    if [ -z "$dropped" ]; then
        echo "link failed (not an id collision):" >&2; cat "$WORK/link.err" >&2; exit 1
    fi
done
[ -f "$APK" ] || { echo "link never succeeded" >&2; exit 1; }

# aapt2 STORES resources.arsc uncompressed (a device mmaps it); our readers
# inflate through java.util.zip / libz, so deflating it costs nothing at
# run time and takes ~40 MB off the shipped bundle (52 MB -> ~9 MB for the
# API-36 table). Repacked in place; everything else keeps aapt2's choice.
if command -v zip >/dev/null 2>&1; then
    ( cd "$WORK" && rm -rf repack && mkdir repack && cd repack \
        && unzip -q "$APK" resources.arsc \
        && zip -q -d "$APK" resources.arsc \
        && zip -q -9 "$APK" resources.arsc ) && echo "    resources.arsc deflated in place"
fi

echo
echo "built: $APK ($(du -h "$APK" | cut -f1 | tr -d ' '))"
echo "source: AOSP $AOSP_TAG frameworks/base/core/res (Apache-2.0)"
echo "use:    MACAPK_FW_RES_APK=$APK"
