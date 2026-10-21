#!/bin/bash
# debug/staleness.sh -- is anything on this machine running stale Mac.apk code?
#
# One line per artifact, ~1s total, cheap enough for every session start
# (scripts/doctor.sh runs it) and printed by scripts/rebuild_and_run.sh as its
# closing report. It exists because every prior staleness incident (the
# nine-days-stale bundle runtime that nearly wasted the owner's camera test,
# the stale classes.jar false PASS on Signal, the poisoned lib_native cache)
# had the same shape: NEW code, OLD artifact, GREEN result -- and no tool
# whose job was to say so.
#
# What it checks:
#   1. STAGED vs BUILT      cmake outputs newer than runtime/build/bin copies
#                           (someone built without staging)
#   2. STAGED vs SOURCE     .java newer than the framework jar; .cpp newer
#                           than the staged binaries (edited without building)
#   3. build-id.txt         recomputes every id from the staged artifacts and
#                           compares (catches staging that bypassed
#                           runtime/scripts/build.sh)
#   4. BUNDLES              dev build/Mac.apk.app and the canonical installed
#                           app vs the repo: build-id string compare, runtime
#                           binary __TEXT compare, AND the three SWIFT
#                           execution surfaces (Contents/MacOS/MacApk, the GUI;
#                           Contents/bin/macapk-installhelper, every headless
#                           install; Contents/Resources/appstub/MacApkAppStub,
#                           the template every installed app's Dock icon execs)
#   5. PER-APP STUBS        each installed <Label>.app carries its OWN frozen
#                           copy of the stub at Contents/MacOS/<exec>; compared
#                           to the canonical template BY CONTENT
#   6. SHARED RUNTIME       the copy installed apps actually EXECUTE, at
#                           ~/Library/Application Support/Mac.apk/runtime --
#                           asked of macapk-installhelper, never recomputed here
#   7. PER-APP CACHES       cached classes.jar carrying a JAVA_ID that no
#                           longer matches (third field of .source-mtime),
#                           lib_native dylibs whose <dylib>.nativeid sidecar no
#                           longer matches, or -- when neither stamp exists --
#                           artifacts older than the last build-identity change
#                           (build-id.txt's mtime; build.sh only rewrites it
#                           when the ids actually change)
#
# ⚠ WHAT THIS TOOL DOES NOT COVER, stated so a green line is not read as more
# than it is (the defect this whole file exists to catch is an instrument
# reporting the GOOD verdict over a surface it never looked at):
#   * Resources/jre (~160 MB) and Resources/tools are compared by NOTHING here;
#     the shared-runtime arm delegates that judgement to RuntimeInstall.state(),
#     whose own header documents the same hole for --patch-module BODIES.
#   * NATIVE_ID does not cover macapk-runtime itself, so a main.cpp edit moves
#     no build id -- which is exactly why check 2 compares macapk-runtime
#     against its CMake source list by mtime, and why the bundle arm compares
#     __TEXT rather than trusting build-id.txt alone.
#   * Nothing here judges the CONTENT of an app's own data.
#   * ENTITLEMENTS are not looked at anywhere in this file. A runtime re-signed
#     with the wrong plist stays byte-fresh by every check above while x18
#     preservation and the mic/camera grants silently vanish;
#     debug/entitlements_check.sh is the tool that asks, and
#     debug/dist_parity.sh applies it to a release bundle.
#
# Exit codes:
#   0  execution surfaces fresh (per-app cache notes may still print)
#   1  an EXECUTION SURFACE is stale (staged/bundle/canonical) -- fix by
#      running runtime/scripts/build.sh or scripts/rebuild_and_run.sh
#   2  (--strict only) surfaces fresh but per-app caches predate the current
#      build identity
#
# Flags: --quiet (one summary line), --strict (see above)
#
# The digests are NOT reimplemented here. They live in ONE place,
# runtime/scripts/build_ids.py, which runtime/scripts/build.sh also calls --
# this file used to carry its own inline-python copy under a "keep in sync"
# comment, which is a divergence waiting to happen and whose failure mode is a
# loud FALSE "build-id.txt does not match" right after a clean build.
#
# ⚠ Only JAVA_ID and NATIVE_ID are CACHE KEYS. JAVA_ID = f(CONVERTER_ID,
# FRAMEWORK_ID) covers exactly the two things that can invalidate a converted
# classes.jar (the converter's bytecode, and the framework's CLASS SHAPE);
# JARS_ID is the full-jar-content digest and is DIAGNOSTIC ONLY -- it moves on
# every framework method-body edit, which is exactly what must NOT re-convert
# the fleet. So a JARS_ID mismatch with everything else matching means "these
# jars were not staged by this build.sh run", not "the caches are stale".
#
# ⚠ CORRECTED 2026-08-12. Check 2 used to compare macapk-translator and
# libmacapk-bionic-shim.dylib against "every file under runtime/translator/src
# except bionic_shim*" / "every bionic_shim* file" -- filename globs, not the
# real per-target source lists. runtime/translator/src/ holds THREE targets'
# sources in one flat directory (translator, shim, macapk-elfexec) plus a
# cmake-less standalone test file; runtime/src/ holds TWO (macapk-runtime,
# macapk-app-stub). The glob approach both flagged a binary stale for a file
# that doesn't compile into it (editing the shim-only arm64_native.cpp read
# "bin/macapk-translator predates edited translator source") AND, the mirror
# bug, left a real dependency invisible to its own target's check
# (arm64_native.cpp and media_ndk.cpp were absent from the shim's OWN
# 'bionic_shim*' glob, and runtime/translator/include/ was never scanned by
# anything). Check 2 now derives each target's real source list from the
# CMakeLists.txt files themselves (cmake_block_sources / cmake_var_sources,
# defined below) instead of a hand-maintained filename pattern -- see the
# derivation block right above the "== Mac.apk staleness ==" banner.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/runtime/build"
BIN="$BUILD/bin"
LIB="$BUILD/lib"
NATIVE_BUILD="$BUILD/native"
TR_BUILD="$REPO/runtime/translator/build"
DEV_APP="$REPO/build/Mac.apk.app"
CANONICAL="${MACAPK_CANONICAL_APP:-/Applications/Mac.apk.app}"
DATA_ROOT="${AB_SCRATCH_ROOT:-${MACAPK_ANDROID_ROOT:-$HOME/Library/Caches/MacApk/scratch}}/android/data/data"

QUIET=0; STRICT=0
for a in "$@"; do
    case "$a" in
        --quiet)  QUIET=1 ;;
        --strict) STRICT=1 ;;
        *) echo "Unknown arg: $a (flags: --quiet, --strict)" >&2; exit 3 ;;
    esac
done

SURFACE_STALE=0
CACHE_STALE=0
say()   { [ "$QUIET" -eq 1 ] || printf '  %s\n' "$1"; }
fresh() { say "$(printf '\033[32mFRESH\033[0m %s' "$1")"; }
stale() { say "$(printf '\033[31mSTALE\033[0m %s' "$1")"; SURFACE_STALE=1; }
note()  { say "$(printf '\033[33mNOTE\033[0m  %s' "$1")"; }

# The single implementation of Contract 3's digests (see the header). Prints
# the same KEY=value lines build.sh writes into build-id.txt.
BUILD_IDS_PY="$REPO/runtime/scripts/build_ids.py"
recompute_ids() {
    [ -f "$BUILD_IDS_PY" ] || return 1
    /usr/bin/python3 "$BUILD_IDS_PY" --lib-dir "$LIB" --bin-dir "$BIN" \
        --java-home "${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}" \
        2>/dev/null
}
# value_of <KEY> <blob>  -- one value out of a KEY=value block
value_of() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

# ---- per-target source-file derivation (build-system-driven) --------------
# ⚠ CORRECTED 2026-08-12. runtime/translator/src/ holds the sources of THREE
# separate cmake targets (macapk-translator, libmacapk-bionic-shim.dylib,
# macapk-elfexec) in one flat directory, plus a cmake-less standalone test
# file (arm32rc/a64_emit_test.cpp -- built only by debug/a64_emit_verify.sh,
# never part of any staged artifact). runtime/src/ holds TWO (macapk-runtime,
# macapk-app-stub). A check that treats "every source under the shared
# directory" as belonging to one target either flags a file that doesn't even
# compile into it (false STALE) or -- the mirror failure, and the one this
# tool's whole job is to catch -- silently omits a real dependency from the
# target it actually belongs to (false FRESH). This file had BOTH bugs at
# once: editing runtime/translator/src/arm64_native.cpp (a shim-only source)
# flagged bin/macapk-translator stale, while arm64_native.cpp and
# media_ndk.cpp edits were INVISIBLE to the shim's own check below it --
# wrong artifact accused, real artifact unwatched, in the same two lines.
# runtime/src/app_native_stub.cpp (macapk-app-stub-only) had the same
# false-STALE-on-macapk-runtime bug, and runtime/translator/include/ (six
# translator-exclusive headers) and runtime/thirdparty/stb_vorbis.c (a real
# macapk-runtime source) were not scanned by ANYTHING.
#
# Fix: read the actual add_executable()/add_library() source lists straight
# out of the CMakeLists.txt files instead of a hand-maintained shadow list
# that silently drifts the next time a file moves between targets -- which is
# exactly how the bug above happened. Two small extractors cover the two
# idioms this repo's CMakeLists.txt files use:
#
#   cmake_block_sources <file> <target>  -- sources listed directly inside
#       add_executable(<target> ...) / add_library(<target> ...), e.g. all
#       three targets in runtime/translator/CMakeLists.txt and macapk-app-stub
#       in runtime/CMakeLists.txt.
#   cmake_var_sources <file> <var>       -- sources collected into a
#       set(<var> ...) list and extended by list(APPEND <var> ...), e.g.
#       runtime/CMakeLists.txt's MACAPK_RUNTIME_SOURCES (macapk-runtime's
#       sources are NOT listed inline in its add_executable() call).
#
# Neither is a general CMake parser -- both assume one source token per line
# and no nested parens in the block, true of every target in this repo today
# (hand-verified against both CMakeLists.txt files, including a full
# every-extracted-path-exists-on-disk pass). If that ever stops holding for a
# given block, the capture just truncates at the first ')' rather than
# hanging -- which is why every call site is wrapped in assert_sources()
# rather than trusted blind: a parser that silently mis-reads a block after a
# future CMakeLists.txt edit is exactly the kind of drift this fix exists to
# stop, so a bad read must NOTE loudly, never pass through quietly.
cmake_block_sources() {
    awk -v target="$2" '
        BEGIN { capturing = 0 }
        {
            line = $0
            sub(/#.*/, "", line)
            if (!capturing) {
                idx = index(line, "add_executable(" target)
                keylen = length("add_executable(" target)
                if (idx == 0) {
                    idx = index(line, "add_library(" target)
                    keylen = length("add_library(" target)
                }
                if (idx == 0) next
                # guard against "target" being a prefix of a longer name
                delim = substr(line, idx + keylen, 1)
                if (delim != "" && delim != ")" && delim != " " && delim != "\t") next
                capturing = 1
                line = substr(line, idx + keylen)
            }
            if ((p = index(line, ")")) > 0) { content = substr(line, 1, p - 1); capturing = 0 }
            else { content = line }
            n = split(content, toks, /[ \t]+/)
            for (i = 1; i <= n; i++) {
                t = toks[i]
                if (t == "") continue
                if (t ~ /^(SHARED|STATIC|MODULE|OBJECT|INTERFACE|IMPORTED|GLOBAL|ALIAS)$/) continue
                print t
            }
        }' "$1" 2>/dev/null
}
cmake_var_sources() {
    awk -v var="$2" '
        BEGIN { capturing = 0 }
        {
            line = $0
            sub(/#.*/, "", line)
            if (!capturing) {
                idx = index(line, "set(" var)
                keylen = length("set(" var)
                if (idx == 0) {
                    idx = index(line, "list(APPEND " var)
                    keylen = length("list(APPEND " var)
                }
                if (idx == 0) next
                delim = substr(line, idx + keylen, 1)
                if (delim != "" && delim != ")" && delim != " " && delim != "\t") next
                capturing = 1
                line = substr(line, idx + keylen)
            }
            if ((p = index(line, ")")) > 0) { content = substr(line, 1, p - 1); capturing = 0 }
            else { content = line }
            n = split(content, toks, /[ \t]+/)
            for (i = 1; i <= n; i++) { if (toks[i] != "") print toks[i] }
        }' "$1" 2>/dev/null
}
# assert_sources <label> <base_dir> <raw list> -- filters a derived source
# list down to entries that exist on disk, NOTEing (not silently dropping)
# anything that doesn't: a parser that mistook a comment or a CMake keyword
# for a filename is exactly the drift this exists to catch. Empty input (the
# trigger phrase never matched -- e.g. a target got renamed) also NOTEs
# loudly rather than letting the caller silently compare against zero files
# and report a meaningless FRESH.
assert_sources() {
    local label="$1" base="$2" raw="$3" rel ok=""
    if [ -z "$raw" ]; then
        note "could not find $label's source list in its CMakeLists.txt (target renamed, or the parser needs updating) -- skipping its freshness check"
        return 0
    fi
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        if [ -f "$base/$rel" ]; then
            ok="$ok
$rel"
        else
            note "$label's CMakeLists.txt lists '$rel' but $base/$rel does not exist -- source-list parser likely drifted"
        fi
    done <<< "$raw"
    printf '%s' "$ok"
}
# ---- per-target SWIFT source derivation (build-script-driven) -------------
# Same principle as the CMake extractors above, applied to the OTHER build
# system in this repo. scripts/build_launcher.sh runs THREE swiftc invocations
# producing three separate execution surfaces, and until 2026-08-19 no
# freshness check in this file touched any of them -- so editing
# launcher/InstallCore.swift (198 KB, on ALL THREE link lines) moved no
# staleness signal at all, while the GUI, every headless install and every
# installed app's Dock icon kept running the previous build.
#
# The source lists are PARSED OUT OF build_launcher.sh rather than copied here,
# for the reason the CMake block above spells out at length: a hand-maintained
# shadow list silently omits a real dependency the first time a link line
# changes, and its failure mode is a false FRESH. Each swiftc block has the
# shape
#     swiftc \
#         ...flags... \
#         -o "<output>" \
#         "$LAUNCHER_DIR/A.swift" \
#         "$BUILD_INFO_SWIFT"
# so: find the line carrying the -o token, then collect the $LAUNCHER_DIR /
# $BUILD_INFO_SWIFT tokens from there until a line that does not continue.
BUILD_LAUNCHER_SH="$REPO/scripts/build_launcher.sh"
swift_target_sources() {  # swift_target_sources <output-token>
    awk -v want="$1" '
        BEGIN { capturing = 0 }
        {
            line = $0
            sub(/#.*/, "", line)
            if (!capturing) {
                if (index(line, "-o \"" want "\"") == 0) next
                capturing = 1
            }
            # LAUNCHER_DIR sources
            rest = line
            while ((i = index(rest, "$LAUNCHER_DIR/")) > 0) {
                rest = substr(rest, i + length("$LAUNCHER_DIR/"))
                j = index(rest, "\"")
                if (j > 0) print substr(rest, 1, j - 1)
            }
            if (index(line, "$BUILD_INFO_SWIFT") > 0) print "BuildInfo.generated.swift"
            # a line that does not end in a continuation ends the block
            if (line !~ /\\[ \t]*$/) { capturing = 0 }
        }' "$BUILD_LAUNCHER_SH" 2>/dev/null
}
GUI_SWIFT_SRCS="$(assert_sources "Contents/MacOS/MacApk" "$REPO/launcher" \
    "$(swift_target_sources '$MACOS_DIR/MacApk')")"
STUB_SWIFT_SRCS="$(assert_sources "Resources/appstub/MacApkAppStub" "$REPO/launcher" \
    "$(swift_target_sources '$RESOURCES_DIR/appstub/MacApkAppStub')")"
HELPER_SWIFT_SRCS="$(assert_sources "Contents/bin/macapk-installhelper" "$REPO/launcher" \
    "$(swift_target_sources '$CONTENTS/bin/macapk-installhelper')")"
# The repo's current launcher build stamp, the same sed scripts/rebuild_and_run.sh
# uses. Empty when the launcher has never been built here.
REPO_BUILD_INFO="$REPO/launcher/BuildInfo.generated.swift"
REPO_SWIFT_ID=""
[ -f "$REPO_BUILD_INFO" ] && REPO_SWIFT_ID="$(grep -E 'static let id' "$REPO_BUILD_INFO" \
    | sed -E 's/.*"([^"]+)".*/\1/' | head -n 1)"

TRANSLATOR_CMAKE="$REPO/runtime/translator/CMakeLists.txt"
RUNTIME_CMAKE="$REPO/runtime/CMakeLists.txt"
TRANSLATOR_SRCS="$(assert_sources macapk-translator "$REPO/runtime/translator" \
    "$(cmake_block_sources "$TRANSLATOR_CMAKE" macapk-translator)")"
SHIM_SRCS="$(assert_sources libmacapk-bionic-shim.dylib "$REPO/runtime/translator" \
    "$(cmake_block_sources "$TRANSLATOR_CMAKE" macapk-bionic-shim)")"
ELFEXEC_SRCS="$(assert_sources macapk-elfexec "$REPO/runtime/translator" \
    "$(cmake_block_sources "$TRANSLATOR_CMAKE" macapk-elfexec)")"
RUNTIME_SRCS="$(assert_sources macapk-runtime "$REPO/runtime" \
    "$(cmake_var_sources "$RUNTIME_CMAKE" MACAPK_RUNTIME_SOURCES)")"
APPSTUB_SRCS="$(assert_sources libmacapk-app-stub.dylib "$REPO/runtime" \
    "$(cmake_block_sources "$RUNTIME_CMAKE" macapk-app-stub)")"

# target_newer_source <artifact> <src_list> <base_dir> [<hdr_dir>...] -- first
# path (repo-relative) newer than <artifact>: checked against the exact
# CMake-derived <src_list> (one <base_dir>-relative path per line, from
# assert_sources above) plus every *.h/*.hpp under each <hdr_dir> (searched
# recursively -- only ever passed a directory already hand-verified exclusive
# to this target; see call sites). Prints nothing and returns 1 if nothing is
# newer.
target_newer_source() {
    local artifact="$1" src_list="$2" base_dir="$3"; shift 3
    local rel f hdr_dir hit base_rel="${base_dir#$REPO/}"
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        f="$base_dir/$rel"
        if [ -f "$f" ] && [ "$f" -nt "$artifact" ]; then printf '%s/%s\n' "$base_rel" "$rel"; return 0; fi
    done <<< "$src_list"
    for hdr_dir in "$@"; do
        [ -d "$hdr_dir" ] || continue
        hit="$(find "$hdr_dir" \( -name '*.h' -o -name '*.hpp' \) -newer "$artifact" -print 2>/dev/null | head -n 1)"
        [ -n "$hit" ] && { printf '%s\n' "${hit#$REPO/}"; return 0; }
    done
    return 1
}

[ "$QUIET" -eq 1 ] || echo "== Mac.apk staleness =="

# ---- 1. staged vs built ----------------------------------------------------
if [ ! -x "$BIN/macapk-runtime" ]; then
    note "runtime not built/staged yet (runtime/scripts/build.sh); nothing to judge"
else
    if [ -f "$NATIVE_BUILD/macapk-runtime" ] && [ "$NATIVE_BUILD/macapk-runtime" -nt "$BIN/macapk-runtime" ]; then
        stale "bin/macapk-runtime older than the cmake output (built but never staged; rerun runtime/scripts/build.sh)"
    else
        fresh "bin/macapk-runtime is the newest built runtime"
    fi
    for t in macapk-translator libmacapk-bionic-shim.dylib macapk-elfexec; do
        if [ -f "$TR_BUILD/$t" ] && [ -f "$BIN/$t" ] && [ "$TR_BUILD/$t" -nt "$BIN/$t" ]; then
            stale "bin/$t older than the translator build output (built but never staged)"
        fi
    done
    if [ -f "$NATIVE_BUILD/libmacapk-app-stub.dylib" ] && [ -f "$BIN/libmacapk-app-stub.dylib" ] \
       && [ "$NATIVE_BUILD/libmacapk-app-stub.dylib" -nt "$BIN/libmacapk-app-stub.dylib" ]; then
        stale "bin/libmacapk-app-stub.dylib older than the cmake output (built but never staged)"
    fi

    # ---- 2. staged vs source ----------------------------------------------
    if [ -f "$LIB/android-framework.jar" ]; then
        NEWER_JAVA="$(find "$REPO/runtime/java" -name '*.java' ! -path '* [2-9].java' \
                        -newer "$LIB/android-framework.jar" -print 2>/dev/null | head -n 1)"
        if [ -n "$NEWER_JAVA" ]; then
            stale "android-framework.jar predates edited Java source (e.g. ${NEWER_JAVA#$REPO/})"
        else
            fresh "framework jars newer than every .java source"
        fi
    fi
    # ⚠ Every row below compares a binary against EXACTLY the sources its own
    # cmake target lists (TRANSLATOR_SRCS/SHIM_SRCS/RUNTIME_SRCS/etc, derived
    # above from the CMakeLists.txt files themselves, plus the header
    # directories hand-verified exclusive to each target) -- never "every file
    # under the shared src/ directory". A freshness tool that cries wolf on a
    # file that doesn't even compile into the binary is worse than none,
    # because it trains you to ignore the one time it's right; a freshness
    # tool that misses a real dependency is worse still, because it's the
    # exact "NEW code, OLD artifact, GREEN result" failure this script exists
    # to catch. See the derivation block above the "== Mac.apk staleness =="
    # banner for the incident (arm64_native.cpp) that made both mistakes at
    # once, in these same two rows.
    if [ -f "$BIN/macapk-runtime" ]; then
        NEWER_RT="$(target_newer_source "$BIN/macapk-runtime" "$RUNTIME_SRCS" "$REPO/runtime" \
                        "$REPO/runtime/src" "$REPO/runtime/include")"
        if [ -n "$NEWER_RT" ]; then
            stale "bin/macapk-runtime predates edited runtime source (e.g. $NEWER_RT)"
        else
            fresh "bin/macapk-runtime newer than every runtime source"
        fi
    fi
    if [ -f "$BIN/libmacapk-app-stub.dylib" ]; then
        NEWER_AS="$(target_newer_source "$BIN/libmacapk-app-stub.dylib" "$APPSTUB_SRCS" "$REPO/runtime")"
        if [ -n "$NEWER_AS" ]; then
            stale "bin/libmacapk-app-stub.dylib predates edited source (e.g. $NEWER_AS)"
        else
            fresh "bin/libmacapk-app-stub.dylib newer than its own source"
        fi
    fi
    if [ -f "$BIN/macapk-translator" ]; then
        NEWER_TR="$(target_newer_source "$BIN/macapk-translator" "$TRANSLATOR_SRCS" "$REPO/runtime/translator" \
                        "$REPO/runtime/translator/include" "$REPO/runtime/translator/src/arm32rc")"
        if [ -n "$NEWER_TR" ]; then
            stale "bin/macapk-translator predates edited translator source (e.g. $NEWER_TR)"
        else
            fresh "bin/macapk-translator newer than its own sources"
        fi
    fi
    if [ -f "$BIN/libmacapk-bionic-shim.dylib" ]; then
        NEWER_SH="$(target_newer_source "$BIN/libmacapk-bionic-shim.dylib" "$SHIM_SRCS" "$REPO/runtime/translator")"
        if [ -n "$NEWER_SH" ]; then
            stale "bin/libmacapk-bionic-shim.dylib predates edited shim source (e.g. $NEWER_SH)"
        else
            fresh "bin/libmacapk-bionic-shim.dylib newer than its own sources"
        fi
    fi
    if [ -f "$BIN/macapk-elfexec" ]; then
        NEWER_EX="$(target_newer_source "$BIN/macapk-elfexec" "$ELFEXEC_SRCS" "$REPO/runtime/translator")"
        if [ -n "$NEWER_EX" ]; then
            stale "bin/macapk-elfexec predates edited source (e.g. $NEWER_EX)"
        else
            fresh "bin/macapk-elfexec newer than its own source"
        fi
    fi

    # ---- 3. build-id.txt describes the staged artifacts --------------------
    if [ -f "$BUILD/build-id.txt" ]; then
        WANT_BLOB="$(recompute_ids)"
        if [ -z "$WANT_BLOB" ]; then
            note "cannot recompute build identity ($BUILD_IDS_PY missing or failed) -- skipping check 3"
        else
            HAVE_BLOB="$(cat "$BUILD/build-id.txt")"
            MISMATCH=""
            for k in CONVERTER_ID FRAMEWORK_ID JAVA_ID JARS_ID NATIVE_ID; do
                w="$(value_of "$k" "$WANT_BLOB")"
                h="$(value_of "$k" "$HAVE_BLOB")"
                # A key the recorded file does not carry at all predates the
                # split; report it as such rather than as a mismatch.
                if [ -z "$h" ]; then
                    MISMATCH="$MISMATCH $k=(absent,want $w)"
                elif [ "$w" != "$h" ]; then
                    MISMATCH="$MISMATCH $k=(recorded $h, actual $w)"
                fi
            done
            if [ -z "$MISMATCH" ]; then
                fresh "build-id.txt matches staged artifacts (JAVA_ID=$(value_of JAVA_ID "$HAVE_BLOB") NATIVE_ID=$(value_of NATIVE_ID "$HAVE_BLOB"))"
            else
                stale "build-id.txt does NOT match staged artifacts --$MISMATCH -- artifacts were staged without runtime/scripts/build.sh; rerun it"
            fi
        fi
    else
        stale "no $BUILD/build-id.txt -- staged tree predates the identity stamp; rerun runtime/scripts/build.sh"
    fi

    # ---- 4. bundles vs repo -------------------------------------------------
    check_bundle() {  # $1 = bundle path, $2 = short label
        local app="$1" label="$2" c bid cbid
        c="$app/Contents"
        [ -d "$c" ] || return 0
        # v1.0.1019: the bundled copy moved from Contents/ to Contents/Resources/
        # so `codesign --verify --deep --strict` can seal the bundle (a plain file
        # loose in Contents/ cannot be signed and fails the seal). Check the new
        # location first and fall back, so this reports correctly against a
        # bundle staged by either vintage rather than shouting "missing".
        cbid="$c/Resources/build-id.txt"; [ -f "$cbid" ] || cbid="$c/build-id.txt"
        if [ -f "$cbid" ] && [ -f "$BUILD/build-id.txt" ]; then
            if cmp -s "$cbid" "$BUILD/build-id.txt"; then
                fresh "$label carries the current build identity"
            else
                bid="$(tr '\n' ' ' < "$cbid")"
                stale "$label has a DIFFERENT build identity ($bid) -- rebuild or resync it"
            fi
        else
            note "$label has no build-id.txt (predates the identity stamp; runtime/scripts/build.sh syncs one in)"
        fi
        # ⚠ A BYTE COMPARISON HERE IS WRONG AS OF v1.0.981, and saying so matters
        # because CLAUDE.md tells every session to trust this tool before a sweep.
        #
        # The bundled copy is DELIBERATELY not byte-identical any more:
        # scripts/relink_bundle_deps.sh rewrites its absolute Homebrew paths to
        # @rpath (so the bundle is self-contained and can be copied to another
        # Mac) and then re-signs it. install_name_tool rewrites LOAD COMMANDS and
        # codesign appends a signature -- neither touches __TEXT. So md5 must
        # differ, by construction, on every correct build.
        #
        # Left as a byte compare this printed a PERMANENT false STALE, which is
        # worse than no check at all: it trains readers to ignore the one
        # instrument that exists to catch the real hazard (2026-08-10, the GUI
        # and the harnesses running different code while sharing one cache).
        #
        # So compare the EXECUTABLE CODE instead -- __TEXT is what actually
        # decides "is the GUI running the code I just built". A genuine
        # stale bundle differs there; a correctly relinked one does not.
        if [ -f "$c/Resources/macapk-runtime" ] && [ -f "$BIN/macapk-runtime" ]; then
            _text_hash() {
                otool -s __TEXT __text "$1" 2>/dev/null | tail -n +3 \
                    | awk '{$1=""; print}' | shasum | cut -d' ' -f1
            }
            _c_text="$(_text_hash "$c/Resources/macapk-runtime")"
            _r_text="$(_text_hash "$BIN/macapk-runtime")"
            if [ -z "$_c_text" ] || [ -z "$_r_text" ]; then
                note "$label runtime binary: could not read __TEXT (otool failed); skipping the code comparison"
            elif [ "$_c_text" = "$_r_text" ]; then
                if [ "$(md5 -q "$c/Resources/macapk-runtime")" = "$(md5 -q "$BIN/macapk-runtime")" ]; then
                    fresh "$label runtime binary is byte-identical to the repo's"
                else
                    fresh "$label runtime binary has the same __TEXT as the repo's (differs only by the expected @rpath relink + re-sign)"
                fi
            else
                stale "$label runtime binary CODE DIFFERS from the repo's (the GUI would test different code than the harnesses)"
            fi
        fi

        # ---- the THREE SWIFT EXECUTION SURFACES ---------------------------
        # Added 2026-08-19. Until now this function inspected Contents/build-id.txt
        # and Contents/Resources/macapk-runtime and NOTHING ELSE, while reporting a
        # verdict every caller reads as "this bundle is fresh". The three Swift
        # binaries are execution surfaces in exactly the sense that matters:
        #   MacOS/MacApk                     the GUI the owner clicks
        #   bin/macapk-installhelper         every headless install, and the
        #                                    authority on the shared runtime
        #   Resources/appstub/MacApkAppStub  the template every installed app's
        #                                    Dock icon is a copy of
        # None of them is covered by build-id.txt: build_ids.py's five digests
        # cover the converter, the framework jar SHAPE, the translator and the
        # shim. So editing launcher/InstallCore.swift -- 198 KB, on all three
        # link lines -- moved no freshness signal anywhere.
        #
        # ⚠ CONTENT, NOT MTIME, for the cross-binary comparison. ditto and
        # copyfile(COPYFILE_ALL) preserve the SOURCE's mtime, so a promoted
        # bundle's binaries carry the mtimes of the build that made them and an
        # mtime comparison between two bundles is meaningless. The embedded
        # BuildInfo stamp is the honest instrument: scripts/build_launcher.sh
        # generates launcher/BuildInfo.generated.swift fresh on every run and
        # links it into MacApk and macapk-installhelper, so both carry the id of
        # the build that produced them, recoverable with `strings`.
        # MacApkAppStub deliberately does NOT link it (it would need a second
        # @main-free source set), so the stub is judged by source mtime only --
        # and that limit is printed rather than papered over.
        _swift_id() {  # embedded BuildInfo stamp of a Swift binary, or empty
            strings -a "$1" 2>/dev/null \
                | grep -oE '^[0-9]{6}\.[0-9]{4}-[0-9a-f]{7,}(\+dirty)?$' | sort -u
        }
        local gui="$c/MacOS/MacApk"
        local helper="$c/bin/macapk-installhelper"
        local stub="$c/Resources/appstub/MacApkAppStub"
        if [ ! -f "$gui" ]; then
            note "$label has no Contents/MacOS/MacApk -- not a launcher bundle; skipped the Swift surface checks"
        else
            # (a) a MISSING surface in a real launcher bundle is stale, not skip:
            # an absent installhelper means every headless install falls back to
            # a path this tool then says nothing about.
            local missing=""
            [ -f "$helper" ] || missing="$missing bin/macapk-installhelper"
            [ -f "$stub" ]   || missing="$missing Resources/appstub/MacApkAppStub"
            if [ -n "$missing" ]; then
                stale "$label is MISSING Swift execution surface(s):$missing -- rebuild with scripts/build_launcher.sh and promote"
            fi

            # (b) cross-surface identity: the two id-carrying binaries must have
            # come from the SAME build_launcher.sh run. A mismatch here means a
            # partial copy landed in the bundle and is never acceptable.
            local gid hid n_gid n_hid
            gid="$(_swift_id "$gui")";    n_gid="$(printf '%s' "$gid" | grep -c . )"
            hid="$(_swift_id "$helper")"; n_hid="$(printf '%s' "$hid" | grep -c . )"
            if [ "$n_gid" -gt 1 ] || [ "$n_hid" -gt 1 ]; then
                note "$label carries MORE THAN ONE BuildInfo stamp (MacApk='$(echo $gid)' installhelper='$(echo $hid)') -- the extractor needs narrowing; not judging identity"
            elif [ -z "$gid" ]; then
                note "$label MacOS/MacApk carries no readable BuildInfo stamp (strings found none) -- cannot judge Swift identity"
            elif [ -f "$helper" ] && [ -z "$hid" ]; then
                note "$label bin/macapk-installhelper carries no readable BuildInfo stamp -- cannot judge Swift identity"
            elif [ -f "$helper" ] && [ "$gid" != "$hid" ]; then
                stale "$label Swift surfaces came from DIFFERENT builds (MacApk=$gid installhelper=$hid) -- the GUI and every headless install are running different code"
            elif [ -n "$REPO_SWIFT_ID" ] && [ "$gid" != "$REPO_SWIFT_ID" ]; then
                # Not STALE on its own: the id moves on every build_launcher.sh
                # run because it embeds a timestamp, so an unpromoted rebuild
                # with NO source change would otherwise cry wolf forever. Say
                # exactly what is true -- this bundle is not from the last
                # launcher build -- and let the source arm below decide whether
                # the CODE actually differs.
                note "$label Swift surfaces are from build $gid, but the repo's last launcher build was $REPO_SWIFT_ID (not promoted; scripts/build_launcher.sh --promote)"
            else
                fresh "$label Swift surfaces carry the current launcher build ($gid)"
            fi

            # (c) source freshness, per target, against build_launcher.sh's own
            # link lines. This is the arm that answers "is the CODE different",
            # and it is why the id mismatch above is only a note.
            local bin_path label_rel newer
            for pair in \
                "$gui:GUI (MacOS/MacApk):$GUI_SWIFT_SRCS" \
                "$helper:installhelper (bin/macapk-installhelper):$HELPER_SWIFT_SRCS" \
                "$stub:app-stub template (Resources/appstub/MacApkAppStub):$STUB_SWIFT_SRCS"; do
                bin_path="${pair%%:*}"; local rest="${pair#*:}"
                label_rel="${rest%%:*}"; local srcs="${rest#*:}"
                [ -f "$bin_path" ] || continue
                newer="$(target_newer_source "$bin_path" "$srcs" "$REPO/launcher")"
                if [ -n "$newer" ]; then
                    if [ "$newer" = "launcher/BuildInfo.generated.swift" ]; then
                        note "$label $label_rel predates only the regenerated build stamp (launcher/BuildInfo.generated.swift) -- no Swift source changed; promote to make the displayed id match"
                    else
                        stale "$label $label_rel predates edited launcher source (e.g. $newer) -- rebuild with scripts/build_launcher.sh and promote"
                    fi
                fi
            done
        fi
    }
    check_bundle "$DEV_APP" "dev bundle (build/Mac.apk.app)"
    check_bundle "$CANONICAL" "canonical app ($CANONICAL)"
    if [ ! -d "$DEV_APP" ] && [ ! -d "$CANONICAL" ]; then
        note "no launcher bundle anywhere (scripts/rebuild_and_run.sh builds + promotes one)"
    elif [ -d "$DEV_APP" ] && [ -d "$CANONICAL" ]; then
        note "TWO launcher bundles exist (dev + canonical) -- scripts/rebuild_and_run.sh promotes and removes the dev copy"
    fi
fi

# ---- 5. per-app stubs (what an installed app's Dock icon actually execs) ----
# Each installed <Label>.app carries its OWN copy of the stub template at
# Contents/MacOS/<CFBundleExecutable>, frozen at install time
# (BundleGenerator.finalize renames the executable with the bundle). MEASURED
# 2026-08-12 (v1.0.962): 10 of 11 installed bundles were running a stub 17 hours
# older than the template while scripts/rebuild_and_run.sh's comment asserted
# there was nothing to refresh "BY CONSTRUCTION". scripts/restage_app_stubs.sh
# was written to fix that, and rebuild_and_run calls it -- but nothing WATCHES
# the surface, so between promotes it is unjudged.
#
# ⚠ CONTENT, NOT MTIME, and this is not a style preference. Measured
# 2026-08-19: all 12 installed stubs read 08-19 00:44 against a template of
# 08-19 09:15 and every one was byte-identical (md5 03eb0f8c...). ditto
# preserves the SOURCE's mtime, so an mtime check here would have shipped 12
# false STALE on its first run -- the same failure that forced the __TEXT
# rewrite in check_bundle above.
#
# The comparison is NOT reimplemented here. scripts/restage_app_stubs.sh
# already enumerates the registry, resolves each bundle's CFBundleExecutable
# from its own Info.plist, and md5-compares against the template; --dry-run
# does exactly that and writes nothing. One implementation, two callers.
check_app_stubs() {
    local sc="$REPO/scripts/restage_app_stubs.sh" out rc n_stale
    if [ ! -x "$sc" ]; then
        note "scripts/restage_app_stubs.sh missing -- per-app stub freshness NOT judged"
        return 0
    fi
    out="$(bash "$sc" --dry-run 2>&1)"; rc=$?
    case "$out" in
        *"no stub template found"*)
            note "no stub template in the canonical app -- per-app stub freshness NOT judged (build the launcher)"
            return 0 ;;
        *"no installed-apps registry"*|*"no installed bundles found"*)
            note "no installed app bundles on this machine -- nothing to judge"
            return 0 ;;
    esac
    # "==> N updated, M already current." -- under --dry-run N is the count that
    # WOULD be replaced, i.e. the number running an old stub.
    n_stale="$(printf '%s\n' "$out" | sed -n 's/^==> \([0-9]*\) updated.*/\1/p' | head -n 1)"
    if [ -z "$n_stale" ]; then
        note "could not read scripts/restage_app_stubs.sh --dry-run's summary line -- per-app stub freshness NOT judged (its output format changed?)"
        return 0
    fi
    if printf '%s\n' "$out" | grep -q '^    MISSING '; then
        stale "installed app bundle(s) have NO stub binary at all: $(printf '%s\n' "$out" | sed -n 's/^    MISSING  *//p' | tr '\n' ' ')-- reinstall them"
    fi
    if [ "$n_stale" -gt 0 ]; then
        stale "$n_stale installed app bundle(s) run an OLD per-app stub (e.g. $(printf '%s\n' "$out" | sed -n 's/^    STALE  *//p' | head -n 3 | tr '\n' ' ')) -- fix with scripts/restage_app_stubs.sh"
    elif [ "$rc" -eq 0 ]; then
        local n_ok
        n_ok="$(printf '%s\n' "$out" | sed -n 's/^==> [0-9]* updated, \([0-9]*\) already current.*/\1/p' | head -n 1)"
        fresh "per-app stubs: all installed bundles carry the current template (${n_ok:-?} bundle(s))"
    fi
}

# ---- 6. the SHARED RUNTIME (the copy installed apps actually EXECUTE) -------
# An installed app's Contents/MacOS/<exec> is a symlink into
# ~/Library/Application Support/Mac.apk/runtime (RuntimeInstall.stagedRoot) --
# never into this repo and never into Mac.apk.app. MEASURED 2026-08-19: nothing
# on any build path wrote that root; its only automatic refresh was a guest app
# launching. v1.0.998 was promoted at ~00:44 and the staged root still held
# v1.0.997 at 09:15, while THIS SCRIPT said FRESH throughout -- because it
# modelled the canonical app and not the copy that runs.
#
# NOT REIMPLEMENTED HERE, deliberately. RuntimeInstall.state() compares the
# staged payload against the bundle file by file (size, mtime) -- the only
# signal that can see a main.cpp edit, since NATIVE_ID does not cover
# macapk-runtime -- and macapk-installhelper is a headless CLI over exactly that
# function. A second answer computed in shell here is the divergence this whole
# file exists to prevent, so we ASK the one implementation.
check_staged_runtime() {
    local helper="$CANONICAL/Contents/bin/macapk-installhelper" js
    if [ ! -x "$helper" ]; then
        note "no macapk-installhelper in the canonical app -- the SHARED RUNTIME (what installed apps execute) is NOT judged"
        return 0
    fi
    js="$("$helper" runtime-status --json 2>/dev/null)"
    if [ -z "$js" ]; then
        note "macapk-installhelper runtime-status produced no output -- the shared runtime is NOT judged"
        return 0
    fi
    case "$js" in
        *'"removedByUser":"true"'*)
            # A deliberate user action (Runtime: Uninstall), not staleness.
            note "the shared runtime is UNINSTALLED (Runtime: Uninstall was pressed) -- installed apps cannot launch until you reinstall it from Mac.apk"
            return 0 ;;
    esac
    case "$js" in
        *'"installed":"false"'*)
            stale "the SHARED RUNTIME is not installed -- every installed app would fail to launch; run scripts/rebuild_and_run.sh (or Mac.apk > Runtime: Install)"
            return 0 ;;
    esac
    case "$js" in
        *'"stale":"true"'*)
            stale "the SHARED RUNTIME is STALE ($(printf '%s' "$js" | sed -E 's/.*"summary":"([^"]*)".*/\1/')) -- installed apps are executing an OLDER build than $CANONICAL ships; run scripts/rebuild_and_run.sh"
            return 0 ;;
        *'"stale":"false"'*)
            fresh "shared runtime matches the canonical app ($(printf '%s' "$js" | sed -E 's/.*"buildId":"[^"]*JAVA_ID=([0-9a-f]*).*/JAVA_ID=\1/'))"
            return 0 ;;
    esac
    note "could not read \"stale\" out of macapk-installhelper runtime-status --json -- the shared runtime is NOT judged (raw: $js)"
}

check_app_stubs
check_staged_runtime

# ---- 5. per-app caches ------------------------------------------------------
# ⚠ TWO trees, not one. The split layout (apk_unpacker.h) puts the REGENERABLE
# half -- classes.jar, _apkt, lib_native, .source-mtime -- under
# <root>/.macapk/code/<pkg>_<ver>/, while <root>/data/data/<pkg>_<ver>/ is the
# app's own data. Installs predating the split still keep their artifacts in
# data/data, and on this machine BOTH are populated (10 code dirs + 59 data
# dirs carrying a classes.jar as of 2026-08-11), so scanning only data/data --
# which this check used to do -- silently ignored every post-split install.
CODE_ROOT="${AB_SCRATCH_ROOT:-${MACAPK_ANDROID_ROOT:-$HOME/Library/Caches/MacApk/scratch}}/android/.macapk/code"
if { [ -d "$DATA_ROOT" ] || [ -d "$CODE_ROOT" ]; } && [ -f "$BUILD/build-id.txt" ]; then
    CUR_J="$(sed -n 's/^JAVA_ID=//p'   "$BUILD/build-id.txt")"
    CUR_N="$(sed -n 's/^NATIVE_ID=//p' "$BUILD/build-id.txt")"
    apps_total=0; jar_old=0; dylib_old=0; id_mismatch=0; examples=""; ex_n=0
    for appdir in "$CODE_ROOT"/*/ "$DATA_ROOT"/*/; do
        appdir="${appdir%/}"
        [ -d "$appdir" ] || continue                      # unmatched glob
        [ -f "$appdir/classes.jar" ] || [ -d "$appdir/lib_native" ] || continue
        apps_total=$((apps_total + 1))
        this_stale=0
        # .source-mtime is "<apk mtime> <abi selector> <JAVA_ID>" -- three
        # WHITESPACE-SEPARATED fields, no key names (apk_unpacker.cpp
        # WriteStamp). This used to look for a literal "JAVA_ID=" and so never
        # matched, which quietly demoted every app to the mtime heuristic
        # below and made a recorded-id mismatch unreportable.
        rec=""
        [ -f "$appdir/.source-mtime" ] && rec="$(awk '{print $3; exit}' "$appdir/.source-mtime" 2>/dev/null)"
        if [ -n "$rec" ] && [ "$rec" != "?" ]; then
            [ "$rec" = "$CUR_J" ] || { id_mismatch=$((id_mismatch + 1)); this_stale=1; }
        elif [ -f "$appdir/classes.jar" ] && [ "$BUILD/build-id.txt" -nt "$appdir/classes.jar" ]; then
            # No usable stamp: build-id.txt's mtime only moves when the identity
            # actually changes, so a jar older than it was converted by a
            # previous framework/converter.
            jar_old=$((jar_old + 1)); this_stale=1
        fi
        if [ -d "$appdir/lib_native" ]; then
            # AppClassLoader.writeNativeIdStamp writes "<dylib>.nativeid"
            # containing the bare NATIVE_ID (no key name). The old code looked
            # for "*.stamp" files holding "NATIVE_ID=", which the runtime has
            # never written, so this branch was dead too.
            if compgen -G "$appdir/lib_native/*.nativeid" >/dev/null 2>&1; then
                for s in "$appdir"/lib_native/*.nativeid; do
                    if [ "$(tr -d ' \n' < "$s")" != "$CUR_N" ]; then
                        id_mismatch=$((id_mismatch + 1)); this_stale=1; break
                    fi
                done
            else
                old_dylib="$(find "$appdir/lib_native" -name '*.dylib' \
                                ! -newer "$BUILD/build-id.txt" -print 2>/dev/null | head -n 1)"
                [ -n "$old_dylib" ] && { dylib_old=$((dylib_old + 1)); this_stale=1; }
            fi
        fi
        if [ "$this_stale" -eq 1 ] && [ "$ex_n" -lt 3 ]; then
            examples="$examples$(basename "$appdir"),"
            ex_n=$((ex_n + 1))
        fi
    done
    if [ $((jar_old + dylib_old + id_mismatch)) -gt 0 ]; then
        CACHE_STALE=1
        note "per-app caches: of $apps_total cached app(s), $jar_old classes.jar and $dylib_old lib_native predate the current build identity, $id_mismatch carry a mismatched recorded id (e.g. ${examples%,})"
        note "  they re-convert on next launch; scripts/rebuild_and_run.sh --fresh-caches invalidates them up front (app data untouched)"
    else
        fresh "per-app caches: none predate the current build identity ($apps_total cached app(s))"
    fi
fi

# ---- summary ---------------------------------------------------------------
if [ "$SURFACE_STALE" -eq 1 ]; then
    SUMMARY="STALE execution surface(s) found -- rebuild before trusting any run"
elif [ "$CACHE_STALE" -eq 1 ]; then
    SUMMARY="execution surfaces fresh; some per-app caches predate the current build identity"
else
    SUMMARY="everything fresh"
fi
if [ "$QUIET" -eq 1 ]; then echo "$SUMMARY"; else echo "== $SUMMARY =="; fi
[ "$SURFACE_STALE" -eq 1 ] && exit 1
[ "$STRICT" -eq 1 ] && [ "$CACHE_STALE" -eq 1 ] && exit 2
exit 0
