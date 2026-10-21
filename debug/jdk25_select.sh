#!/bin/bash
# jdk25_select.sh -- the ONE JDK setting for Mac.apk, and the only place that turns it
# into a JDK home. Sourced by runtime/scripts/build.sh, debug/build_java_only.sh,
# scripts/stage_jre.sh and scripts/check-requirements.sh; run directly, it prints the
# resolved home (or, with --feature <home>, that home's feature release).
#
#   MACAPK_JDK       feature release to build, bundle and link: "21" or "25".
#                    Unset = MACAPK_JDK_DEFAULT below.
#   MACAPK_JDK_HOME  an explicit home. Accepted only if its release file names the
#                    selected feature, so a stale export cannot silently win.
#   JAVA_HOME        LEGACY: honoured exactly as before (unvalidated) ONLY while
#                    MACAPK_JDK is unset, so the default path is the pre-change one.
#
# WHY A RESOLVER AND NOT A PATH. Homebrew's opt/openjdk@NN links are versioned by
# FORMULA, not by the JDK inside them, and they drift. Measured on this box
# 2026-09-26: opt/openjdk@25 -> Cellar/openjdk/26.0.1, while the genuine 25.0.2 sits in
# Cellar/openjdk/25.0.2 as an old keg of the plain `openjdk` formula. Retargeting a
# hardcoded "@21" to "@25" would therefore build against JDK 26 with no warning. So a
# candidate is accepted only when <home>/release says JAVA_VERSION="<feature>.*"; the
# path is a hint, the release file is the fact.
#
# WHY opt/openjdk@21 IS TRIED FIRST FOR 21. The dev binary records libjvm's install
# name at link time, and scripts/relink_bundle_deps.sh rewrites exactly that literal
# (/opt/homebrew/opt/openjdk@21/.../lib/server) to @rpath when it packages a bundle.
# Resolving 21 to a Cellar path would leave the bundle pointing at Homebrew with no
# error (install_name_tool -change of a path that is not there is a silent no-op).
#
# THE JDK IS A BUILD-TIME CHOICE. macapk-runtime LINKS libjvm (runtime/CMakeLists.txt),
# so MACAPK_JDK picks what gets compiled, linked and jlinked. At run time
# runtime/src/jvm_loader.cpp only reads the linked libjvm's release file (dladdr) and
# warns if MACAPK_JDK names a different feature. Flipping the default is ONE edit:
# MACAPK_JDK_DEFAULT below. Design + measurements: docs/jdk25-move-and-aot-cache_2026-09-26.md
#
# bash 3.2 compatible (macOS /bin/bash): no arrays of arrays, no mapfile.

MACAPK_JDK_DEFAULT=21

# <home> -> JAVA_VERSION from <home>/release ("" when absent).
macapk_jdk_version() {
    # Always status 0: consumers run under `set -euo pipefail`, and a legacy JAVA_HOME
    # with no release file (the bare opt/openjdk@21 symlink dir has none) must not abort them.
    sed -n 's/^JAVA_VERSION="\([^"]*\)".*/\1/p' "$1/release" 2>/dev/null | head -1 || true
}

# <home> -> feature release (the part before the first dot), "" when unknown.
macapk_jdk_feature() {
    local v
    v="$(macapk_jdk_version "$1")"
    echo "${v%%.*}"
}

# The feature the ONE setting selects.
macapk_jdk_selected() {
    echo "${MACAPK_JDK:-$MACAPK_JDK_DEFAULT}"
}

# <feature> -> candidate homes, preferred first, one per line (unvalidated).
macapk_jdk_candidates() {
    local f="$1" b="${HOMEBREW_PREFIX:-/opt/homebrew}"
    echo "$b/opt/openjdk@$f/libexec/openjdk.jdk/Contents/Home"
    /usr/libexec/java_home -v "$f" 2>/dev/null
    # Versioned formula kegs, then kegs of the plain `openjdk` formula (where 25.0.2
    # lives on this box), newest patch first.
    ls -d "$b"/Cellar/openjdk@"$f"/"$f"*/libexec/openjdk.jdk/Contents/Home 2>/dev/null | sort -rV
    ls -d "$b"/Cellar/openjdk/"$f".*/libexec/openjdk.jdk/Contents/Home \
          "$b"/Cellar/openjdk/"$f"/libexec/openjdk.jdk/Contents/Home 2>/dev/null | sort -rV
    # Vendor installs (Temurin, Zulu, Oracle ...), system-wide then per-user.
    ls -d /Library/Java/JavaVirtualMachines/*/Contents/Home \
          "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home 2>/dev/null | sort -rV
}

# [feature] -> prints the JDK home to use; rc 1 (and a reason on stderr) if none.
macapk_jdk_home() {
    local f="${1:-}"
    if [ -z "$f" ]; then
        if [ -z "${MACAPK_JDK:-}" ] && [ -n "${JAVA_HOME:-}" ]; then
            # Legacy, byte-for-byte the pre-change behaviour of every consumer:
            # an exported JAVA_HOME wins while nobody has asked for a feature.
            echo "$JAVA_HOME"
            return 0
        fi
        f="$(macapk_jdk_selected)"
    fi
    case "$f" in
        ''|*[!0-9]*) echo "jdk_select: MACAPK_JDK='$f' is not a feature release number (21, 25)" >&2; return 1 ;;
    esac
    if [ -n "${MACAPK_JDK_HOME:-}" ]; then
        if [ "$(macapk_jdk_feature "$MACAPK_JDK_HOME")" = "$f" ] && [ -x "$MACAPK_JDK_HOME/bin/java" ]; then
            echo "$MACAPK_JDK_HOME"
            return 0
        fi
        echo "jdk_select: MACAPK_JDK_HOME=$MACAPK_JDK_HOME is JDK '$(macapk_jdk_version "$MACAPK_JDK_HOME")', not $f -- ignored" >&2
    fi
    local c seen=""
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        case " $seen " in *" $c "*) continue ;; esac
        seen="$seen $c"
        if [ "$(macapk_jdk_feature "$c")" = "$f" ] && [ -x "$c/bin/java" ]; then
            echo "$c"
            return 0
        fi
    done <<EOF
$(macapk_jdk_candidates "$f")
EOF
    echo "jdk_select: no JDK $f found (checked opt/openjdk@$f, java_home -v $f, Cellar kegs, /Library/Java). Every candidate is validated by its release file, so opt/openjdk@$f resolving to another feature does not count." >&2
    return 1
}

# Where build.sh takes a patch module's SOURCES from: the base dir holds copies of JDK
# 21 classes (runtime/java_base_patch = SimpleDateFormat, FileReader,
# jdk.internal.reflect.Reflection), and a JDK class copy is only valid on the JDK it was
# copied from -- measured: the 21 copies do not compile against 25, and loaded into a 25
# JVM they break System.load (NoSuchMethodError on Reflection.ensureNativeAccess) and the
# CLDR provider. So feature N uses <base>_jdkN when it exists, else <base>.
# <rt_dir> <base-name> <feature> -> dir
macapk_jdk_patch_src() {
    if [ "$3" != "21" ] && [ -d "$1/${2}_jdk$3" ]; then echo "$1/${2}_jdk$3"; else echo "$1/$2"; fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        --feature) macapk_jdk_feature "${2:?usage: jdk25_select.sh --feature <home>}" ;;
        --candidates) macapk_jdk_candidates "${2:-$(macapk_jdk_selected)}" ;;
        -h|--help) sed -n '2,33p' "$0" ;;
        *) macapk_jdk_home "${1:-}" ;;
    esac
fi
