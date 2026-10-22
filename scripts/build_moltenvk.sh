#!/usr/bin/env bash
# build_moltenvk.sh -- rebuild the MoltenVK Vulkan ICD with Apk on Mac's patches and
# stage it where scripts/build_angle.sh and runtime/scripts/build.sh pick it up.
#
# WHY THIS EXISTS. The MoltenVK in thirdparty/MoltenVK-build (gitignored, pinned at
# KhronosGroup/MoltenVK 973bb08) was built BY HAND on 2026-07-09 with
# MVK_USE_METAL_PRIVATE_API=1 -- the flag that gives ANGLE provoking-vertex support
# and therefore GLES 3.1 (docs/angle-vulkan-moltenvk-gles31-macos_2026-07-09.md).
# Nothing recorded how, and on 2026-09-22 it needed a patch: SPIRV-Cross (vendored
# inside MoltenVK) emits an invalid Metal fragment struct for a fragment-output
# ARRAY that straddles MoltenVK's enable_frag_output_mask, which blanked Temple
# Run 2 on the Vulkan path. So the patches live in the repo
# (thirdparty/moltenvk-patches/) and this script applies them and rebuilds.
#
# WHAT IT DOES, idempotently:
#   1. For each thirdparty/moltenvk-patches/NNNN-spirv-cross-*.patch: apply it in
#      External/SPIRV-Cross and COMMIT it. It must be committed, because
#      fetchDependencies runs `git checkout --force <pinned sha>`, which would
#      silently discard an uncommitted patch.
#   2. Pin that commit in ExternalRevisions/SPIRV-Cross_repo_revision and commit
#      the MoltenVK checkout too. MoltenVK derives pipelineCacheUUID from its OWN
#      git HEAD (MVKDevice.mm), and ANGLE keys its caches on that UUID, so moving
#      the HEAD is what stops a cache from serving Metal source compiled by the
#      unpatched converter.
#   3. ./fetchDependencies --macos, then make macos MVK_USE_METAL_PRIVATE_API=1.
#   4. Copy libMoltenVK.dylib into thirdparty/angle/out/Release/, where
#      runtime/scripts/build.sh stages it from (scripts/stage_angle_vulkan.sh).
#
#   (2026-10-06) MoltenVK's OWN source patches, NNNN-moltenvk-*.patch, are applied to
#   the MoltenVK checkout and deliberately NOT committed: they change no Metal source
#   the converter emits, so the HEAD -- and pipelineCacheUUID with it -- must stay put,
#   or every app's saved VkPipelineCache would be thrown away on the next launch.
#   0002 compiles a pipeline cache's shader libraries on all cores (a cold macOS Metal
#   cache kept Asphalt Legends on its logo for ~9 min; ~35 s with it).
#   Xcode 27 refuses MoltenVK's 11.0 deployment target, so the build passes 12.0.
#   With no local ANGLE build (thirdparty/angle/ absent), the dylib is staged straight
#   into thirdparty/angle-prebuilt/lib and PROVENANCE.txt's MoltenVK lines refreshed.
#
# After it: runtime/scripts/build.sh, then scripts/build_launcher.sh --promote.
# Verify: strings runtime/build/bin/libMoltenVK.dylib must no longer show the old
# MoltenVK sha, and debug/vkprobe.c must still report provoking_vertex=1 (without
# it ANGLE drops Minecraft to ES2).
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MVK="$PROJECT_DIR/thirdparty/MoltenVK-build"
PATCHES="$PROJECT_DIR/thirdparty/moltenvk-patches"
ANGLE_OUT="$PROJECT_DIR/thirdparty/angle/out/Release"

[ -d "$MVK/.git" ] || { echo "no MoltenVK checkout at $MVK (git clone https://github.com/KhronosGroup/MoltenVK.git there, then git checkout 973bb08)" >&2; exit 2; }
SPC="$MVK/External/SPIRV-Cross"
[ -d "$SPC/.git" ] || { echo "no SPIRV-Cross checkout at $SPC -- run ./fetchDependencies --macos in $MVK once first" >&2; exit 2; }

gitc() { git -c user.name="Apk on Mac build" -c user.email="build@macapk.invalid" "$@"; }

# 1. SPIRV-Cross patches: apply + commit, or recognise as already applied.
changed=0
for p in "$PATCHES"/*-spirv-cross-*.patch; do
    [ -f "$p" ] || continue
    if git -C "$SPC" apply --check "$p" >/dev/null 2>&1; then
        git -C "$SPC" apply "$p"
        git -C "$SPC" add -A
        gitc -C "$SPC" commit -q -m "Apk on Mac: $(basename "$p" .patch)"
        echo "==> applied + committed $(basename "$p") in SPIRV-Cross"
        changed=1
    elif git -C "$SPC" apply --reverse --check "$p" >/dev/null 2>&1; then
        echo "==> $(basename "$p") already applied"
    else
        echo "ERROR: $(basename "$p") does not apply to SPIRV-Cross $(git -C "$SPC" rev-parse --short HEAD)" >&2
        exit 1
    fi
done

# 2. Pin the patched SPIRV-Cross in MoltenVK and commit that, so the MoltenVK HEAD
#    (and with it pipelineCacheUUID) moves.
SPC_SHA="$(git -C "$SPC" rev-parse HEAD)"
REV="$MVK/ExternalRevisions/SPIRV-Cross_repo_revision"
if [ "$(tr -d ' \n' < "$REV")" != "$SPC_SHA" ]; then
    printf '%s\n' "$SPC_SHA" > "$REV"
    gitc -C "$MVK" add ExternalRevisions/SPIRV-Cross_repo_revision
    gitc -C "$MVK" commit -q -m "Apk on Mac: pin patched SPIRV-Cross $SPC_SHA"
    echo "==> MoltenVK now pins SPIRV-Cross $SPC_SHA (MoltenVK HEAD $(git -C "$MVK" rev-parse --short HEAD))"
    changed=1
fi

# 2b. MoltenVK source patches: apply, never commit (see the header).
for p in "$PATCHES"/*-moltenvk-*.patch; do
    [ -f "$p" ] || continue
    if git -C "$MVK" apply --check "$p" >/dev/null 2>&1; then
        git -C "$MVK" apply "$p"
        echo "==> applied $(basename "$p") to MoltenVK (uncommitted; HEAD stays $(git -C "$MVK" rev-parse --short HEAD))"
    elif git -C "$MVK" apply --reverse --check "$p" >/dev/null 2>&1; then
        echo "==> $(basename "$p") already applied"
    else
        echo "ERROR: $(basename "$p") does not apply to MoltenVK $(git -C "$MVK" rev-parse --short HEAD)" >&2
        exit 1
    fi
done

# 3. Build. (make macos == this xcodebuild line, plus the 12.0 deployment target.)
cd "$MVK"
./fetchDependencies --macos
set -o pipefail
xcodebuild build -project MoltenVKPackaging.xcodeproj -scheme "MoltenVK Package (macOS only)" \
    -destination "generic/platform=macOS" \
    GCC_PREPROCESSOR_DEFINITIONS='${inherited} MVK_USE_METAL_PRIVATE_API=1' \
    MACOSX_DEPLOYMENT_TARGET=12.0 -quiet

# 4. Stage.
OUT="$MVK/Package/Release/MoltenVK/dynamic/dylib/macOS/libMoltenVK.dylib"
[ -f "$OUT" ] || { echo "build produced no $OUT" >&2; exit 1; }
if [ -d "$ANGLE_OUT" ]; then
    cp -f "$OUT" "$ANGLE_OUT/libMoltenVK.dylib"
    echo "==> staged $ANGLE_OUT/libMoltenVK.dylib (md5 $(md5 -q "$OUT"))"
    # Keep the COMMITTED binaries (thirdparty/angle-prebuilt) in step (v1.0.1650).
    "$PROJECT_DIR/scripts/refresh_angle_prebuilt.sh"
else
    PRE="$PROJECT_DIR/thirdparty/angle-prebuilt"
    cp -p "$OUT" "$PRE/lib/libMoltenVK.dylib"
    python3 - "$PRE/PROVENANCE.txt" "$PROJECT_DIR" "$(md5 -q "$OUT")" <<'PYEOF'
import hashlib, glob, os, sys
prov, root, md5 = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(prov).read().splitlines()
patches = []
for p in sorted(glob.glob(os.path.join(root, "thirdparty/moltenvk-patches/*.patch"))):
    patches.append("patch             %s  %s" % (hashlib.md5(open(p, "rb").read()).hexdigest(),
                                                 os.path.relpath(p, root)))
out, put = [], False
for l in lines:
    if l.startswith("patch") and "thirdparty/moltenvk-patches/" in l:
        if not put: out += patches; put = True
        continue
    if l.startswith("binary") and l.endswith("lib/libMoltenVK.dylib"):
        l = "binary            %s  lib/libMoltenVK.dylib" % md5
    out.append(l)
if not put:
    i = max(k for k, l in enumerate(out) if l.startswith("patch")) + 1
    out[i:i] = patches
open(prov, "w").write("\n".join(out) + "\n")
PYEOF
    echo "==> staged $PRE/lib/libMoltenVK.dylib (md5 $(md5 -q "$OUT")); PROVENANCE.txt updated"
fi
echo "    next: runtime/scripts/build.sh && scripts/build_launcher.sh --promote"
