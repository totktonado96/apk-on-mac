// gles_bridge.cpp -- placeholder.
//
// The real ANGLE/EGL plumbing already lives in runtime/src/angle_glue.cpp.
// We will hoist that into runtime (or factor it into a shared static
// lib) once the JNI surface stabilizes. For now this file just keeps
// the v2 launcher linkable.

#include "macapk/gles_bridge.h"

#include <cstdio>

namespace macapk {

bool GlesInit(void* /*metal_layer*/, int /*width_px*/, int /*height_px*/) {
    std::fprintf(stderr, "[macapk] GlesInit: stub (renderer not wired yet)\n");
    return true;
}

void GlesBeginFrame() {}
void GlesEndFrame()   {}

}  // namespace macapk
