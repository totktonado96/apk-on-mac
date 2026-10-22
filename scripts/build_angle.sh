#!/usr/bin/env bash
# build_angle.sh
#
# Builds ANGLE (Google's GLES->{Vulkan,Metal,D3D} translator) into
# libGLESv2.dylib + libEGL.dylib that we link from the Apk on Mac runtime.
#
# Output: thirdparty/angle/out/Release/{libGLESv2.dylib, libEGL.dylib}
# First build is ~30-60 minutes on an M-series Mac. Subsequent rebuilds
# (after Apk on Mac edits to the Apk on Mac side, not ANGLE itself) are no-op
# because gn/ninja are incremental and ANGLE source hasn't changed.
#
# Why not just download a prebuilt: Google does not ship ANGLE prebuilts
# for general consumption. Browsers like Chrome bundle their own static
# copy; we build once from source.
#
# Disk model (v1.0.200): we DELETED the 25 GB source checkout and keep only
# the two prebuilt dylibs + the include/ headers + license files under
# thirdparty/angle/. That is everything the Apk on Mac runtime links and
# compiles against. This script re-fetches the full source on demand (when
# thirdparty/angle/.git is absent) so a rebuild is always possible, and it
# pins the exact upstream commit those kept dylibs came from so the rebuild
# is byte-reproducible. The 25 GB never needs to live on disk except during
# an intentional ANGLE rebuild.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANGLE_DIR="$PROJECT_DIR/thirdparty/angle"
DEPOT_TOOLS_DIR="$PROJECT_DIR/thirdparty/depot_tools"

# Pinned upstream ANGLE commit the kept prebuilt dylibs were built from.
# Keeping this lets build_angle.sh deterministically reproduce the exact
# libEGL/libGLESv2 we ship. Bump it (and rebuild) to move ANGLE forward.
ANGLE_PINNED_COMMIT="e44b533ccb2b98efb2e7e04560c747116c789939"

# Auto-clone the toolchain on first run so a fresh checkout can build
# without manual setup steps. Both ANGLE and depot_tools are large (~25 GB
# and ~660 MB respectively) and gitignored on our side.
if [ ! -d "$DEPOT_TOOLS_DIR/.git" ]; then
    echo "==> Cloning depot_tools into $DEPOT_TOOLS_DIR (~660 MB)..."
    git clone --depth=1 \
        https://chromium.googlesource.com/chromium/tools/depot_tools.git \
        "$DEPOT_TOOLS_DIR"
fi
if [ ! -x "$DEPOT_TOOLS_DIR/gn" ]; then
    echo "ERROR: depot_tools at $DEPOT_TOOLS_DIR is incomplete" >&2
    exit 1
fi
if [ ! -d "$ANGLE_DIR/.git" ]; then
    echo "==> Cloning ANGLE into $ANGLE_DIR (~25 GB after gclient sync)..."
    git clone https://chromium.googlesource.com/angle/angle "$ANGLE_DIR"
    # Pin to the exact upstream commit the kept prebuilt dylibs came from so
    # a rebuild reproduces byte-compatible libEGL/libGLESv2. DEPS at this
    # commit drives the matching gclient sync below.
    echo "==> Checking out pinned ANGLE commit $ANGLE_PINNED_COMMIT..."
    git -C "$ANGLE_DIR" checkout --quiet "$ANGLE_PINNED_COMMIT"
    echo "==> Running gclient sync (this is the slow step)..."
    (cd "$ANGLE_DIR" \
        && PATH="$DEPOT_TOOLS_DIR:$PATH" python3 scripts/bootstrap.py \
        && PATH="$DEPOT_TOOLS_DIR:$PATH" gclient sync)
fi
if [ ! -f "$ANGLE_DIR/BUILD.gn" ]; then
    echo "ERROR: ANGLE source incomplete at $ANGLE_DIR" >&2
    echo "       Try removing the directory and re-running this script." >&2
    exit 1
fi
# Metal Toolchain check. xcodebuild ships it as a separate downloadable
# component; ANGLE's Metal backend compiles .metal shaders with the `metal`
# tool at build time, which needs that component. IMPORTANT: `xcrun --find
# metal` succeeds even when the component is UNINSTALLED (it finds the
# frontend stub in XcodeDefault.xctoolchain), so it is NOT a valid check --
# it let a broken build through once (Xcode 26.5.1 reset the component and
# the compile failed on the first .metal file after a full 25 GB sync). Use
# `xcrun metal --version`, which actually exercises the tool and fails with
# "missing Metal Toolchain" when the component is not installed.
if ! xcrun metal --version >/dev/null 2>&1; then
    echo "ERROR: Metal Toolchain not installed (component uninstalled)." >&2
    echo "       Check: xcodebuild -showComponent MetalToolchain" >&2
    echo "       Install once: xcodebuild -downloadComponent MetalToolchain" >&2
    echo "       Then re-run this script (the ANGLE source + sync are kept," >&2
    echo "       so it resumes straight to the compile)." >&2
    exit 1
fi

# Apk on Mac ANGLE-source patches (v1.0.604). These modify upstream ANGLE and MUST
# be re-applied after any fresh clone (the disk model deletes the 25GB checkout
# and re-clones on demand, which would drop them). Each is applied idempotently:
# `git apply --check` succeeds only if the patch is NOT yet applied.
#   0001 es3-provoking-gate      MACAPK_ANGLE_ALLOW_ES3_NO_PROVOKING diagnostic
#                                (off by default; fallback for a MoltenVK without
#                                VK_EXT_provoking_vertex -- the private-API build
#                                makes it unnecessary).
#   0002 nv-image-formats        accept GL_NV_image_formats R8/R16/RG8/... in
#                                glBindImageTexture validation (real Android +
#                                MoltenVK support them). AOSP-faithful; safe (only
#                                GLES-3.1 engines hit it). NOTE: this was NOT the
#                                Minecraft black-render fix (RenderDragon merely
#                                PROBES these formats) -- it is a correctness
#                                improvement kept on its own merit.
#   0003 present-into-embedder-  when the embedder hands ANGLE-Vulkan a CAMetalLayer
#        metal-layer             (Apk on Mac's g_unity_layer), present into it DIRECTLY
#                                instead of creating + addSublayer:ing a private child
#                                layer. The child path runs on the caller's thread
#                                (the guest RENDER thread for a native-EGL engine);
#                                off-main-thread CALayer mutations are not reliably
#                                committed to the render server, so MoltenVK presented
#                                into a layer that never reached the screen -> BLACK
#                                window despite a correctly rendered swapchain image.
#                                THIS was the Minecraft-Bedrock visible-menu fix
#                                (v1.0.606). Vulkan-path only; NSView / plain-CALayer
#                                embedders take the unchanged child-layer path.
#   0004 metal-wide-lines        Metal backend draws glLineWidth > 1 (2026-09-26).
#                                Upstream advertises GL_ALIASED_LINE_WIDTH_RANGE [1,1]
#                                and ignores the width, so a 3 px outline drew 1 px
#                                (retrowars, HCR 1.68.1). DisplayMtl asks a real render
#                                encoder for the private setLineWidth: (the call
#                                MoltenVK makes for vkCmdSetLineWidth) and then
#                                advertises [1,8], MoltenVK's own range; ContextMtl
#                                forwards the clamped width; the RenderCommandEncoder
#                                encodes it only for draws that rasterize lines. Kill
#                                switch: MACAPK_ANGLE_WIDE_LINES=0 restores [1,1] with no
#                                private call and no output. Any other fallback to
#                                [1,1] prints one "[macapk-angle] wide GL lines off"
#                                line to stderr naming why (no device, probe failed,
#                                encoder lacks setLineWidth:), so the runtime log tells
#                                the cases apart. It changes mtl_command_buffer.h, so every
#                                Metal TU recompiles; a partial relink of old objects
#                                draws NOTHING (GL_OUT_OF_MEMORY), measured. Gate:
#                                debug/gl_linewidth_probe.sh; it FAILs (STALE) when
#                                this patch is in the tree but the built libGLESv2
#                                lacks it, since the loop below only WARNs on a patch
#                                that does not apply. Driver shape measured on M2
#                                (AGXG14G) only: run the gate on other GPU families.
#                                Research: docs/angle-metal-wide-lines_2026-09-26.md.
PATCH_DIR="$PROJECT_DIR/thirdparty/angle-patches"
if [ -d "$PATCH_DIR" ]; then
    for p in "$PATCH_DIR"/*.patch; do
        [ -f "$p" ] || continue
        if git -C "$ANGLE_DIR" apply --check "$p" >/dev/null 2>&1; then
            git -C "$ANGLE_DIR" apply "$p" && echo "==> applied ANGLE patch $(basename "$p")"
        else
            # already applied (reverse-check) or does not apply -- report which.
            if git -C "$ANGLE_DIR" apply --reverse --check "$p" >/dev/null 2>&1; then
                echo "==> ANGLE patch $(basename "$p") already applied"
            else
                echo "WARNING: ANGLE patch $(basename "$p") does not apply cleanly" >&2
            fi
        fi
    done
fi

# depot_tools must come first on PATH so gn / ninja / autoninja resolve
# to the bundled versions, not whatever stray copy may be on the system.
export PATH="$DEPOT_TOOLS_DIR:$PATH"

cd "$ANGLE_DIR"

# Args:
#   is_debug=false                 release build (smaller, faster)
#   target_cpu                     match host arch
#   angle_enable_metal=true        Metal backend (default for GLES 2.0/3.0 engines:
#                                  cocos2d-x, Unity, AndEngine, libGDX -- unchanged).
#   angle_enable_vulkan=true       Vulkan backend (v1.0.603): the ONLY way to give an
#                                  APK a real GLES 3.1 context on macOS. Apple's system
#                                  GL tops out at a 3.0-equivalent feature level and
#                                  ANGLE's Metal backend has no GLES 3.1 support (it
#                                  targets WebGL/3.0), so RenderDragon-class engines
#                                  (Minecraft Bedrock) that REQUIRE GLES 3.1 (compute
#                                  shaders, image load/store, SSBO) get a broken/absent
#                                  render path and draw nothing. ANGLE-Vulkan on top of
#                                  MoltenVK provides certified GLES 3.1 on Apple Silicon
#                                  (confirmed: "OpenGL ES 3.1.0 (ANGLE ...) / ANGLE
#                                  (Apple, Vulkan 1.2.x (Apple M-series), MoltenVK)").
#                                  Both backends live in the SAME libGLESv2/libEGL; the
#                                  runtime selects per-run via ANGLE_DEFAULT_PLATFORM
#                                  (default = metal; MACAPK_ANGLE_BACKEND=vulkan flips it).
#   angle_use_custom_libvulkan=true   build ANGLE's own Vulkan-Loader (libvulkan.dylib)
#                                  from third_party/vulkan-loader (pulled by gclient
#                                  sync). The loader finds the ICD via VK_ICD_FILENAMES.
#   angle_shared_libvulkan=true    link the loader as a shared dylib (shipped alongside).
#   angle_enable_swiftshader=false we use MoltenVK (hardware Metal) as the ICD, not the
#                                  SwiftShader software rasterizer -- skipping it saves a
#                                  very large chunk of build time + disk.
#   angle_enable_gl=false          we don't need the desktop-GL backend
#   angle_enable_d3d11/9=false     not on macOS
#   angle_enable_vulkan_validation_layers=false  release: no validation overhead
#   angle_build_tests=false        skip the test apps (saves ~10 min)
#   angle_build_all=false          don't build samples
#   use_custom_libcxx=false        use the system libc++ so symbols are
#                                  ABI-compatible with our runtime binary
#
# MoltenVK: DEPS does NOT pull MoltenVK (only the Vulkan-Loader/Headers/Tools), so we
# stage it ourselves after the build (STAGE step below) from the copy that ships with
# the Android SDK emulator, and emit a MoltenVK_icd.json the loader reads.
ARCH="$(uname -m)"
case "$ARCH" in
    arm64) TARGET_CPU=arm64 ;;
    x86_64) TARGET_CPU=x64 ;;
    *) echo "Unsupported arch $ARCH" >&2; exit 1 ;;
esac

OUT_DIR="out/Release"
echo "[1/3] gn gen $OUT_DIR (target_cpu=$TARGET_CPU, Metal+Vulkan)..."
gn gen "$OUT_DIR" --args="
    is_debug=false
    target_cpu=\"$TARGET_CPU\"
    angle_enable_metal=true
    angle_enable_vulkan=true
    angle_use_custom_libvulkan=true
    angle_shared_libvulkan=true
    angle_enable_swiftshader=false
    angle_enable_gl=false
    angle_enable_wgpu=false
    angle_enable_d3d11=false
    angle_enable_d3d9=false
    angle_enable_vulkan_validation_layers=false
    angle_build_tests=false
    angle_build_all=false
    enable_rust=false
    use_custom_libcxx=false
    treat_warnings_as_errors=false
"
# Note (v1.0.603): angle_enable_wgpu=false + enable_rust=false let us DELETE the
# largest unused gclient deps (third_party/{llvm ~7GB, SwiftShader ~2.4GB,
# dawn ~2GB, rust-toolchain ~1.3GB, catapult, vulkan-validation-layers}) to fit
# the checkout on a near-full disk -- we build only libGLESv2/libEGL/libvulkan
# and none of those deps are in that target graph. angle_enable_wgpu=false stops
# BUILD.gn importing third_party/dawn; enable_rust=false stops rust-toolchain
# reads (we still keep the small third_party/rust for its .gni imports).

# autoninja parallelizes correctly for the host. -j defaults to ncores+2.
# Targets: libGLESv2 + libEGL (the GLES/EGL front end, now with the Vulkan
# backend compiled in) and libvulkan (ANGLE's bundled Vulkan-Loader, which
# the front end dlopens/links to reach MoltenVK).
echo "[2/3] autoninja libGLESv2 libEGL (this is the long step)..."
autoninja -C "$OUT_DIR" libGLESv2 libEGL
# libvulkan = ANGLE's bundled Vulkan-Loader. Depending on ANGLE's config it is
# either a transitive dependency of libGLESv2's Vulkan backend (already built
# above) or a separately nameable target. Build it explicitly if the target
# name resolves; otherwise rely on the transitive build. Non-fatal either way
# so a target-name mismatch cannot fail the whole build.
autoninja -C "$OUT_DIR" libvulkan 2>/dev/null \
    || echo "    note: 'libvulkan' not a direct target; using transitive build"

# STAGE MoltenVK as the Vulkan ICD. The ANGLE loader we just built needs an ICD
# to reach the GPU; on macOS that is MoltenVK (Vulkan-over-Metal). We copy the
# universal (incl. arm64) MoltenVK that ships with the Android SDK emulator and
# write an ICD manifest next to the dylibs. The runtime points VK_ICD_FILENAMES
# at this manifest (see main.cpp / launcher) so no system Vulkan SDK is required.
echo "[3/3] stage MoltenVK ICD..."
# Prefer, in order: (1) a Apk on Mac-built MoltenVK WITH provoking-vertex support
# (thirdparty/MoltenVK-build/... built with MVK_USE_METAL_PRIVATE_API=1 -- this
# is the one that lets ANGLE expose GLES 3.1), (2) the Homebrew molten-vk 1.4.1
# (modern but no provoking-vertex), (3) the Android SDK emulator's ancient copy
# (last resort). The emulator MoltenVK (0.2.2208) is too old -- ANGLE caps at
# ES2 with it. See docs/angle-vulkan-moltenvk-gles31-macos_2026-07-09.md.
MOLTENVK_SRC=""
for cand in \
    "$PROJECT_DIR/thirdparty/MoltenVK-build/Package/Release/MoltenVK/dynamic/dylib/macOS/libMoltenVK.dylib" \
    "/opt/homebrew/opt/molten-vk/lib/libMoltenVK.dylib" \
    "$PROJECT_DIR/android-emulator/android-sdk/emulator/lib64/vulkan/libMoltenVK.dylib"; do
    if [ -f "$cand" ]; then MOLTENVK_SRC="$cand"; break; fi
done
echo "    MoltenVK source: $MOLTENVK_SRC"
if [ -n "$MOLTENVK_SRC" ] && [ -f "$MOLTENVK_SRC" ]; then
    cp -f "$MOLTENVK_SRC" "$OUT_DIR/libMoltenVK.dylib"
    cat > "$OUT_DIR/MoltenVK_icd.json" <<'ICD'
{
    "file_format_version": "1.0.0",
    "ICD": {
        "library_path": "./libMoltenVK.dylib",
        "api_version": "1.2.0"
    }
}
ICD
    echo "    staged $OUT_DIR/libMoltenVK.dylib + MoltenVK_icd.json"
else
    echo "    WARNING: MoltenVK not found at $MOLTENVK_SRC -- Vulkan backend will"     >&2
    echo "             fail to find an ICD. Provide a MoltenVK dylib + icd.json."      >&2
fi

echo ""
echo "Built: $ANGLE_DIR/$OUT_DIR/libGLESv2.dylib"
echo "       $ANGLE_DIR/$OUT_DIR/libEGL.dylib"
echo "       $ANGLE_DIR/$OUT_DIR/libvulkan.dylib (loader)"
echo "       $ANGLE_DIR/$OUT_DIR/libMoltenVK.dylib (ICD) + MoltenVK_icd.json"
ls -lh "$OUT_DIR"/libGLESv2.dylib "$OUT_DIR"/libEGL.dylib \
       "$OUT_DIR"/libvulkan.dylib "$OUT_DIR"/libMoltenVK.dylib 2>/dev/null || true

# Keep the COMMITTED binaries (thirdparty/angle-prebuilt) in step with this build
# (v1.0.1650, owner: upload the compiled binaries, never the ~25 GB source tree).
"$PROJECT_DIR/scripts/refresh_angle_prebuilt.sh"
