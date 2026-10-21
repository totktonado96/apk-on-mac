#!/usr/bin/env bash
# stage_angle_vulkan.sh <angle_lib_dir> <dest_dir>
#
# Stages the ANGLE Vulkan-backend runtime dylibs next to the Mac.apk runtime
# binary and rewrites their install names to @rpath form so dyld resolves them
# via the runtime's @executable_path rpath. This is the Vulkan complement to the
# libGLESv2/libEGL staging that runtime/CMakeLists.txt already does for the Metal
# backend; it runs as a POST_BUILD step and is a NO-OP on a Metal-only ANGLE
# build (libvulkan.dylib absent).
#
# Robustness: we do NOT hardcode ANGLE's chosen install_name for the Vulkan
# loader (it varies by ANGLE config: "@rpath/libvulkan.dylib", "./libvulkan.dylib",
# a versioned SONAME, or an absolute build path). Instead we discover each
# ANGLE-internal reference with `otool -L` and rewrite it to the @rpath form.
#
# Files staged (each optional):
#   libvulkan.dylib    ANGLE's bundled Vulkan-Loader (linked by libGLESv2's
#                      Vulkan backend); finds the ICD via VK_ICD_FILENAMES.
#   libMoltenVK.dylib  the Vulkan ICD (Vulkan-over-Metal). dlopen'd by the loader
#                      via MoltenVK_icd.json's "./libMoltenVK.dylib", resolved
#                      relative to the manifest -- so its own id is not
#                      load-bearing, but we @rpath it anyway for cleanliness.
#   MoltenVK_icd.json  the ICD manifest the runtime points VK_ICD_FILENAMES at.

set -euo pipefail

SRC="${1:?usage: stage_angle_vulkan.sh <angle_lib_dir> <dest_dir>}"
DEST="${2:?usage: stage_angle_vulkan.sh <angle_lib_dir> <dest_dir>}"

# Nothing to do unless this ANGLE build produced a Vulkan loader.
if [ ! -f "$SRC/libvulkan.dylib" ]; then
    echo "  [stage-vulkan] no libvulkan.dylib in $SRC (Metal-only build); skipping"
    exit 0
fi

# Copy the dylibs + manifest that exist.
for f in libvulkan.dylib libMoltenVK.dylib MoltenVK_icd.json; do
    if [ -f "$SRC/$f" ]; then
        cp -f "$SRC/$f" "$DEST/$f"
        echo "  [stage-vulkan] staged $f"
    fi
done

# Strip any inherited code signature BEFORE rewriting install names. MoltenVK
# ships signed and is a fat binary, so install_name_tool would otherwise warn
# "changes ... will invalidate the code signature" once per architecture per
# invocation. Stripping first makes the rewrite clean; we re-sign ad-hoc at the
# end of this script, so the staged dylibs still end up validly signed.
for f in libvulkan.dylib libMoltenVK.dylib; do
    [ -f "$DEST/$f" ] && codesign --remove-signature "$DEST/$f" 2>/dev/null || true
done

# Give the staged dylibs @rpath ids.
[ -f "$DEST/libvulkan.dylib" ]   && install_name_tool -id "@rpath/libvulkan.dylib"   "$DEST/libvulkan.dylib"
[ -f "$DEST/libMoltenVK.dylib" ] && install_name_tool -id "@rpath/libMoltenVK.dylib" "$DEST/libMoltenVK.dylib"

# Rewrite every ANGLE-internal dependent reference (libGLESv2/libEGL/libvulkan/
# libMoltenVK, in any name form) to @rpath in each staged dylib that might link
# them. libGLESv2's Vulkan backend links libvulkan; that is the critical fixup.
rewrite_refs() {
    local dylib="$1"
    [ -f "$dylib" ] || return 0
    # Skip the id line (first otool -L line); rewrite each dependency whose
    # basename is one of our ANGLE dylibs.
    otool -L "$dylib" | tail -n +2 | awk '{print $1}' | while read -r ref; do
        [ -n "$ref" ] || continue
        local base
        base="$(basename "$ref")"
        case "$base" in
            libGLESv2.dylib|libEGL.dylib|libvulkan.dylib|libMoltenVK.dylib)
                if [ "$ref" != "@rpath/$base" ]; then
                    install_name_tool -change "$ref" "@rpath/$base" "$dylib"
                    echo "  [stage-vulkan] $(basename "$dylib"): $ref -> @rpath/$base"
                fi
                ;;
        esac
    done
}

rewrite_refs "$DEST/libGLESv2.dylib"
rewrite_refs "$DEST/libEGL.dylib"
rewrite_refs "$DEST/libvulkan.dylib"
rewrite_refs "$DEST/libMoltenVK.dylib"

# install_name_tool invalidates any existing code signature (MoltenVK ships
# signed, and it is a fat binary so the linker warns per-architecture). Re-sign
# ad-hoc so the staged dylibs carry a VALID signature -- otherwise the loader can
# refuse them on hardened/notarized configurations. Matches the ad-hoc signing the
# runtime binary itself uses. `--force` replaces, `-s -` is ad-hoc.
for f in libvulkan.dylib libMoltenVK.dylib; do
    if [ -f "$DEST/$f" ]; then
        codesign --force --sign - --timestamp=none "$DEST/$f" 2>/dev/null \
            && echo "  [stage-vulkan] re-signed $f (ad-hoc)" \
            || echo "  [stage-vulkan] WARN: could not re-sign $f"
    fi
done

echo "  [stage-vulkan] done"
