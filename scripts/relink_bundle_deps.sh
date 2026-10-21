#!/usr/bin/env bash
# relink_bundle_deps.sh <contents_dir> <project_dir>
#
# Makes the runtime binaries inside a built Mac.apk.app bundle independent
# of Homebrew, so the bundle still runs on a clean Mac with none of it
# installed (no /opt/homebrew at all) and still runs after being copied
# somewhere else (no absolute build-machine paths baked in). Companion to
# stage_angle_vulkan.sh, which already does the identical job for ANGLE's
# Vulkan loader + MoltenVK -- this covers the three Homebrew-linked
# dependencies that script doesn't touch (measured via `otool -L` over
# every Mach-O in the bundle, 2026-08-14):
#   Contents/bin/libmacapk-bionic-shim.dylib -> libcapstone.5 + libpng16.16
#   Contents/bin/macapk-translator           -> libcapstone.5
#   Contents/Resources/macapk-runtime        -> libjvm.dylib + libjli.dylib
#
# (libMoltenVK.dylib's LC_ID_DYLIB was ALSO suspected external -- a raw
# `otool -L` on a fat/universal binary prints one un-indented "<path>
# (architecture X):" header PER SLICE, and libMoltenVK.dylib ships
# x86_64+arm64, so a quick read of the output makes the second slice's
# header look like a dependency line. `otool -D` (which prints only the
# LC_ID_DYLIB, no header ambiguity) shows it is already `@rpath/
# libMoltenVK.dylib` for both slices -- stage_angle_vulkan.sh already
# fixes this (commit b87272d). Not touched here; do not "fix" it again.)
#
# For each real gap: copy the Homebrew dylib into the bundle, `-id
# @rpath/<name>` the copy, `-change <abs-path> @rpath/<name>` on every
# dependent, and make sure the dependent's LC_RPATH set actually resolves
# to where the copy lives -- CHECKED with `otool -l`, never assumed. That
# check matters: the three binaries below turned out to have three
# DIFFERENT rpath starting states when actually measured, not the
# uniform state a guess would produce --
#   libmacapk-bionic-shim.dylib:  already has @loader_path (added earlier
#                                  for its ANGLE cross-refs) -- reused, no
#                                  new rpath needed.
#   macapk-translator:            had ONLY the dead absolute Homebrew
#                                  capstone rpath -- needed @loader_path
#                                  added from scratch.
#   macapk-runtime:                had @executable_path, but that resolves
#                                  to Resources/ itself, not Resources/
#                                  jre/lib/... where the JVM libs live --
#                                  needed two NEW rpath entries.
#
# libjvm.dylib/libjli.dylib are NOT copied standalone here -- they come
# from whatever JRE stage_jre.sh already staged at Contents/Resources/jre/.
# HotSpot's own bootstrap needs the WHOLE jlink output tree (lib/modules,
# lib/tzdb.dat, etc), not just the two dylibs the linker happens to
# reference; hand-copying only those two would relink cleanly and then
# fail at JNI_CreateJavaVM. This script must run AFTER stage_jre.sh.
#
# Re-signing: the capstone/libpng copies and the shim/translator get a
# PLAIN ad-hoc re-sign, matching stage_angle_vulkan.sh's own pattern for
# ANGLE/MoltenVK -- `codesign -dv` on the pre-existing binaries shows only
# "adhoc,linker-signed" (the bare signature the linker attaches with no
# explicit codesign step; no entitlements involved). macapk-runtime is
# different and needs the FULL treatment: runtime/CMakeLists.txt's own
# default (x18-entitlement) POST_BUILD step signs it with `--options
# runtime --entitlements runtime/scripts/jit-entitlements.plist`, which
# carries JIT (com.apple.security.cs.allow-jit / allow-unsigned-executable-
# memory, for V8/cohtml), x18 preservation (com.apple.security.custom-x18-
# abi-toggle, for guest ARM64 code that uses x18 as a GPR) and mic/camera
# access. install_name_tool invalidates whatever signature is present, so
# re-signing macapk-runtime plain ad-hoc here would silently strip all
# four -- exactly the class of regression this project has sunk the most
# investigation effort into (see CLAUDE.md's x18 notes and
# docs/x18-custom-abi-toggle-entitlement_2026-07-14.md). Measured before
# writing this: `codesign -dv --entitlements -` on the built
# macapk-runtime shows exactly those five keys; this script re-applies the
# same flags rather than guessing at them.

set -euo pipefail

CONTENTS="${1:?usage: relink_bundle_deps.sh <contents_dir> <project_dir>}"
PROJECT_DIR="${2:?usage: relink_bundle_deps.sh <contents_dir> <project_dir>}"

BIN_DIR="$CONTENTS/bin"
RES_DIR="$CONTENTS/Resources"
JRE_DIR="$RES_DIR/jre"
ENTITLEMENTS="$PROJECT_DIR/runtime/scripts/jit-entitlements.plist"

# Homebrew source dylibs (dev-machine paths -- same hardcoded-prefix
# convention runtime/CMakeLists.txt's JAVA_HOME default and
# runtime/translator/CMakeLists.txt's CAPSTONE_ROOT/LIBPNG_ROOT already
# use for locating build-time deps; this is the same lookup, just done at
# packaging time instead of compile time).
CAPSTONE_SRC="/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib"
LIBPNG_SRC="/opt/homebrew/opt/libpng/lib/libpng16.16.dylib"
# (The JDK's libjvm/libjli are NOT hardcoded here any more: section 4 reads the names
# the runtime actually recorded, because they depend on which JDK the ONE setting
# selected -- MACAPK_JDK, debug/jdk25_select.sh.)

has_rpath() {  # has_rpath <binary> <path>
    # EXACT match on the rpath value, not a substring grep: LC_RPATH
    # entries can be prefixes of one another (this binary carries both
    # "@executable_path/jre/lib" and "@executable_path/jre/lib/server"),
    # and a plain `grep -q "$2"` against the raw otool -l block matches
    # the longer one whenever $2 is the shorter prefix -- which silently
    # skipped adding "@executable_path/jre/lib" entirely (it looked
    # "already present" because "/server" contains it as a substring),
    # and left libjli.dylib unresolvable: `dyld: Library not loaded:
    # @rpath/libjli.dylib ... tried: .../jre/lib/server/libjli.dylib (no
    # such file)` with no attempt at .../jre/lib/libjli.dylib at all.
    # Caught by the clean-env launch test, not by otool -L (a missing
    # rpath doesn't show up as an external absolute path -- it shows up
    # as dyld refusing to launch the binary at all).
    otool -l "$1" | awk '
        /cmd LC_RPATH/ { want=1; next }
        want && /^ *path / {
            sub(/^ *path /, ""); sub(/ \(offset [0-9]+\)$/, "");
            print; want=0
        }' | grep -qxF -- "$2"
}
add_rpath_if_missing() {  # add_rpath_if_missing <binary> <path>
    has_rpath "$1" "$2" || install_name_tool -add_rpath "$2" "$1"
}
delete_rpath_if_present() {  # delete_rpath_if_present <binary> <path>
    has_rpath "$1" "$2" && install_name_tool -delete_rpath "$2" "$1" 2>/dev/null || true
}
# Drop the ad-hoc signature BEFORE any install_name_tool edit. Every such edit
# on a signed binary prints "changes being made to the file will invalidate the
# code signature", and each of these binaries is unconditionally re-signed a few
# lines later -- so the warnings were noise about something already handled, and
# noise that trains you to skim past a real signing failure. Removing the
# signature we are about to replace kills them at the source instead of
# filtering the text and hoping the re-sign still happens. Same idiom the
# libcapstone/libpng blocks below already used.
unsign_before_edit() {  # unsign_before_edit <binary>
    codesign --remove-signature "$1" 2>/dev/null || true
}
resign_plain() {  # resign_plain <binary> <label>
    if codesign --force --sign - --timestamp=none "$1" 2>/dev/null \
       && codesign --verify --strict "$1" 2>/dev/null; then
        echo "  [relink] re-signed $2 (ad-hoc)"
    else
        # Loud on purpose: we suppressed the invalidation warnings above, so a
        # failed re-sign must not also be quiet.
        echo "  [relink] WARN: could not re-sign (or could not verify) $2" >&2
    fi
}

# ---- 1. capstone + libpng: copy into Contents/bin/, next to both
# dependents (the shim needs both; the translator needs capstone only) --
if [ -f "$CAPSTONE_SRC" ]; then
    cp -f "$CAPSTONE_SRC" "$BIN_DIR/libcapstone.5.dylib"
    codesign --remove-signature "$BIN_DIR/libcapstone.5.dylib" 2>/dev/null || true
    install_name_tool -id "@rpath/libcapstone.5.dylib" "$BIN_DIR/libcapstone.5.dylib"
    resign_plain "$BIN_DIR/libcapstone.5.dylib" "bin/libcapstone.5.dylib"
    echo "  Staged bin/libcapstone.5.dylib: $(du -h "$BIN_DIR/libcapstone.5.dylib" | cut -f1)"
else
    echo "  WARN: $CAPSTONE_SRC not found; macapk-translator / the bionic shim will stay Homebrew-linked for capstone." >&2
fi
if [ -f "$LIBPNG_SRC" ]; then
    cp -f "$LIBPNG_SRC" "$BIN_DIR/libpng16.16.dylib"
    codesign --remove-signature "$BIN_DIR/libpng16.16.dylib" 2>/dev/null || true
    install_name_tool -id "@rpath/libpng16.16.dylib" "$BIN_DIR/libpng16.16.dylib"
    resign_plain "$BIN_DIR/libpng16.16.dylib" "bin/libpng16.16.dylib"
    echo "  Staged bin/libpng16.16.dylib: $(du -h "$BIN_DIR/libpng16.16.dylib" | cut -f1)"
else
    echo "  WARN: $LIBPNG_SRC not found; the bionic shim will stay Homebrew-linked for PNG decode." >&2
fi

# ---- 2. libmacapk-bionic-shim.dylib -------------------------------------
SHIM="$BIN_DIR/libmacapk-bionic-shim.dylib"
if [ -f "$SHIM" ]; then
    unsign_before_edit "$SHIM"
    add_rpath_if_missing "$SHIM" "@loader_path"
    # ANGLE (libGLESv2/libEGL, both `@rpath/` hard dependencies of the shim)
    # lives in Resources/ next to macapk-runtime, NOT next to the shim in bin/.
    # Inside the runtime process that never mattered: dyld also searches the
    # MAIN EXECUTABLE's LC_RPATH (@executable_path = Resources/), so the shim
    # bound the copy the runtime had already loaded. But the shim is ALSO
    # dlopen'd by a SEPARATE process -- macapk-elfexec, the stand-in an app
    # forks for an APK-shipped native executable (runtime/src/apk_native_exec.cpp)
    # -- whose executable lives in the app's lib dir, so neither rpath reached
    # Resources/ and every such exec died 126 ("Library not loaded:
    # @rpath/libGLESv2.dylib") on an installed app while working from the dev
    # tree, where all three sit in runtime/build/bin/. Measured 2026-09-29 on
    # Puzzles (every "new game" failed with "error 126"). This rpath makes the
    # shim's dependencies resolve from its OWN load commands in the bundle and
    # in the staged runtime (same bin/ + Resources/ sibling layout); in the dev
    # tree it names a directory that does not exist and is skipped.
    # Gate: debug/elfexec_shimload_gate.sh.
    add_rpath_if_missing "$SHIM" "@loader_path/../Resources"
    [ -f "$BIN_DIR/libcapstone.5.dylib" ] && install_name_tool -change \
        "$CAPSTONE_SRC" "@rpath/libcapstone.5.dylib" "$SHIM"
    [ -f "$BIN_DIR/libpng16.16.dylib" ] && install_name_tool -change \
        "$LIBPNG_SRC" "@rpath/libpng16.16.dylib" "$SHIM"
    delete_rpath_if_present "$SHIM" "/opt/homebrew/opt/capstone/lib"
    delete_rpath_if_present "$SHIM" "/opt/homebrew/opt/libpng/lib"
    resign_plain "$SHIM" "bin/libmacapk-bionic-shim.dylib"
fi

# ---- 3. macapk-translator ------------------------------------------------
XLAT="$BIN_DIR/macapk-translator"
if [ -f "$XLAT" ]; then
    unsign_before_edit "$XLAT"
    add_rpath_if_missing "$XLAT" "@loader_path"
    [ -f "$BIN_DIR/libcapstone.5.dylib" ] && install_name_tool -change \
        "$CAPSTONE_SRC" "@rpath/libcapstone.5.dylib" "$XLAT"
    delete_rpath_if_present "$XLAT" "/opt/homebrew/opt/capstone/lib"
    resign_plain "$XLAT" "bin/macapk-translator"
fi

# ---- 4. macapk-runtime: point at the JRE stage_jre.sh already staged at
# Resources/jre/. ----------------------------------------------------------
RUNTIME_BIN="$RES_DIR/macapk-runtime"
if [ -f "$RUNTIME_BIN" ] && [ -f "$JRE_DIR/lib/server/libjvm.dylib" ]; then
    # Drop the ad-hoc signature FIRST, same idiom as the libcapstone/libpng
    # blocks above. Every install_name_tool edit below otherwise prints
    # "changes being made to the file will invalidate the code signature",
    # four times, on a binary we unconditionally re-sign ~10 lines later --
    # so the warnings were noise about something already handled, and noise
    # that trains you to skim past a real signing failure. Removing the
    # signature we are about to replace makes them go away at the source
    # rather than filtering the text and hoping the re-sign still happens.
    codesign --remove-signature "$RUNTIME_BIN" 2>/dev/null || true

    add_rpath_if_missing "$RUNTIME_BIN" "@executable_path/jre/lib/server"
    add_rpath_if_missing "$RUNTIME_BIN" "@executable_path/jre/lib"
    # The libjvm/libjli the runtime was LINKED against, read from the binary instead of
    # assumed. This used to be the literal /opt/homebrew/opt/openjdk@21/... path, which
    # is only what a default JDK 21 build records: a MACAPK_JDK=25 build records the
    # Cellar path runtime/CMakeLists.txt pins, and a 21 resolved from java_home records
    # whatever that JDK names itself. `install_name_tool -change` of a name the binary
    # does not carry is a SILENT no-op, so the bundle would have shipped pointing at the
    # build Mac's JDK. docs/jdk25-move-and-aot-cache_2026-09-26.md section 2.
    OLD_JVM="$(otool -L "$RUNTIME_BIN" | awk '/libjvm\.dylib/{print $1; exit}')"
    OLD_JLI="$(otool -L "$RUNTIME_BIN" | awk '/libjli\.dylib/{print $1; exit}')"
    [ -n "$OLD_JVM" ] && install_name_tool -change "$OLD_JVM" "@rpath/libjvm.dylib" "$RUNTIME_BIN"
    [ -n "$OLD_JLI" ] && install_name_tool -change "$OLD_JLI" "@rpath/libjli.dylib" "$RUNTIME_BIN"
    # Drop every ABSOLUTE LC_RPATH that holds a libjvm/libjli (the linked JDK's lib dirs,
    # from CMake's BUILD_RPATH), whichever JDK that was. Left in, it sits AHEAD of
    # @executable_path/jre/... in the search order, so on the build Mac @rpath/libjvm
    # would still bind the JDK's copy rather than the bundle's. Collected first, then
    # deleted, so otool never reads a file install_name_tool is rewriting.
    JDK_RPATHS="$(otool -l "$RUNTIME_BIN" | awk '
        /cmd LC_RPATH/ { want=1; next }
        want && /^ *path / { sub(/^ *path /, ""); sub(/ \(offset [0-9]+\)$/, ""); print; want=0 }')"
    while IFS= read -r rp; do
        case "$rp" in
            /*) if [ -f "$rp/libjvm.dylib" ] || [ -f "$rp/libjli.dylib" ]; then
                    delete_rpath_if_present "$RUNTIME_BIN" "$rp"
                fi ;;
        esac
    done <<EOF_RPATHS
$JDK_RPATHS
EOF_RPATHS
    # Loud instead of silent: an absolute libjvm/libjli left here boots only on this Mac.
    if otool -L "$RUNTIME_BIN" | awk 'NR > 1 {print $1}' | grep -Eq '^/.*/lib(jvm|jli)\.dylib$'; then
        echo "  [relink] ERROR: Resources/macapk-runtime still links an absolute JDK library:" >&2
        otool -L "$RUNTIME_BIN" | grep -E 'lib(jvm|jli)\.dylib' >&2
        exit 1
    fi

    if [ -f "$ENTITLEMENTS" ]; then
        codesign --force --options runtime --sign - \
            --entitlements "$ENTITLEMENTS" "$RUNTIME_BIN"
        # Now that the warnings are gone, ASSERT what they were warning about.
        # Silencing a signature warning without checking the signature is how
        # a broken re-sign ships quietly; this makes the failure loud instead.
        if ! codesign --verify --strict "$RUNTIME_BIN" 2>/dev/null; then
            echo "  [relink] ERROR: macapk-runtime failed codesign --verify after re-signing." >&2
            exit 1
        fi
        echo "  [relink] re-signed Resources/macapk-runtime (--options runtime + jit-entitlements.plist)"
    else
        echo "  [relink] ERROR: $ENTITLEMENTS not found -- macapk-runtime was relinked but" >&2
        echo "           NOT re-signed with entitlements. JIT/x18/mic/camera would be broken." >&2
        exit 1
    fi
else
    echo "  WARN: Resources/macapk-runtime or Resources/jre/lib/server/libjvm.dylib missing;" >&2
    echo "        skipping the JVM relink (the runtime would fail to boot on a clean Mac)." >&2
    echo "        Run stage_jre.sh before relink_bundle_deps.sh." >&2
fi

echo "  relink_bundle_deps.sh done"
