// gles_bridge.h
//
// Stub declarations for the GLES → ANGLE/Metal bridge. The real
// implementation lives in src/angle_glue.cpp; this header is the API
// surface the JNI side calls into.

#pragma once

namespace macapk {

// Initialize EGL on top of a Metal-backed CALayer. Width/height are
// drawable PIXELS (already retina-scaled). Idempotent.
bool GlesInit(void* metal_layer, int width_px, int height_px);

// Begin/end a frame: makeCurrent + swapBuffers in ANGLE terms.
void GlesBeginFrame();
void GlesEndFrame();

}  // namespace macapk
