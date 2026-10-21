#!/usr/bin/env bash
# stage_framework_res.sh <tools_dir>
#
# Stages the platform resource apk the runtime resolves `@android:` references
# against, as <tools_dir>/framework-res.apk. main.cpp defaults MACAPK_FW_RES_APK
# to <binary_dir>/tools/framework-res.apk (binary_dir = Contents/Resources for
# the bundled macapk-runtime, runtime/build/bin in the dev tree), so every
# launch path -- repo binary, installed stub, GUI -- resolves against ONE table
# instead of "whatever the cwd offered"
# (docs/resources-in-place-gap-assessment_2026-09-20.md FINDING 1). It lives
# under Resources/tools, a staged payload DIRECTORY (InstallCore.swift
# payloadDirs), so the shared runtime carries it without a manifest change.
#
# v1.0.1590 (Phase 5 step 9): this file used to be stage_apktool.sh and bundled
# apktool.jar as well. apktool is no longer run by the runtime -- resources,
# the manifest and the launcher icon are read from the installed apk set in
# place (ResourceIndex / ArscReader / BinaryXmlParser / apk_unpacker.cpp's
# binary readers) -- so nothing of it ships any more. That also removes the
# notarization hazard its prebuilt/macosx/aapt2 Mach-O carried (2026-08-21).
#
# SOURCE: the FULL platform apk built from AOSP by scripts/build_framework_res.sh
# (thirdparty/framework-res/framework-res-api36.apk, android-16.0.0_r2,
# Apache-2.0, ~22 MB): the resource TABLE plus every framework FILE resource
# (res/color selectors, drawables, layouts, animators). A table-only stand-in
# (apktool's prebuilt/android-framework.jar) names
# `@android:color/text_color_secondary` but cannot serve
# res/color/text_color_secondary.xml, and a Material NavigationView that asks
# for it fails to construct (newpipe went blank on the table-only run,
# 78 -> 7%), so the stand-in is refused unless MACAPK_ALLOW_TABLE_ONLY_FW=1.
# The build is one-time and local, like ANGLE (~1 minute; aapt2 out of the
# Homebrew apktool keg, one ~23 MB fetch from googlesource).

set -euo pipefail

DEST="${1:?usage: stage_framework_res.sh <tools_dir>}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
FULL_FW_APK="$REPO/thirdparty/framework-res/framework-res-api36.apk"

mkdir -p "$DEST"
if [ -f "$FULL_FW_APK" ]; then
    cp -f "$FULL_FW_APK" "$DEST/framework-res.apk"
    echo "  Staged $DEST/framework-res.apk (FULL API-36 platform apk from AOSP, $(du -h "$DEST/framework-res.apk" | cut -f1))"
    exit 0
fi

if [ "${MACAPK_ALLOW_TABLE_ONLY_FW:-0}" != 1 ]; then
    echo "  ERROR: $FULL_FW_APK is not built; refusing to ship the TABLE-ONLY platform table" >&2
    echo "         (framework file resources such as res/color selectors would be missing)." >&2
    echo "         Build it once: scripts/build_framework_res.sh --api 36 --tag android-16.0.0_r2 --version-name 16" >&2
    echo "         or set MACAPK_ALLOW_TABLE_ONLY_FW=1 to ship the stand-in deliberately." >&2
    exit 1
fi
APKTOOL_JAR_SRC="$(ls -t /opt/homebrew/Cellar/apktool/*/libexec/apktool_*.jar 2>/dev/null | head -1)"
if [ -z "$APKTOOL_JAR_SRC" ] || [ ! -f "$APKTOOL_JAR_SRC" ]; then
    echo "  ERROR: no full platform apk and no apktool keg to extract the table-only stand-in from." >&2
    exit 1
fi
unzip -p "$APKTOOL_JAR_SRC" prebuilt/android-framework.jar > "$DEST/framework-res.apk.tmp" \
  && mv -f "$DEST/framework-res.apk.tmp" "$DEST/framework-res.apk" \
  || { rm -f "$DEST/framework-res.apk.tmp"; echo "  ERROR: could not extract the framework table" >&2; exit 1; }
echo "  WARN: MACAPK_ALLOW_TABLE_ONLY_FW=1 -- staged the TABLE-ONLY platform table (no framework file resources)" >&2
echo "  Staged $DEST/framework-res.apk (API-36 platform TABLE ONLY, $(du -h "$DEST/framework-res.apk" | cut -f1))"
