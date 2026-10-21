// sv_layer_policy.h -- the PURE decisions behind MACAPK_SV_LAYER_AT_CREATE
// (2026-09-27, engine-hook lane "unity-nativeegl-layer-pacing").
//
// WHAT AOSP DOES. SurfaceView.updateSurface creates the layer and its
// BufferQueue (createBlastSurfaceControls, copySurface) BEFORE it calls
// surfaceCreated, so every SurfaceView's window exists before the app is told
// about it, whatever will later produce into it. ANativeWindow_fromSurface
// (native_window_jni.cpp) is then a pure lookup of Surface.mNativeObject: it
// creates nothing and works on any thread. A layer nobody has queued a buffer
// into draws nothing.
//
// WHAT WE DID. Our window object did not exist until a producer asked for it,
// so it was created three different ways: pre-created at the first frame only
// when an image whose soname contains "libunity" had loaded (v1.0.162, keyed on
// the ENGINE), on demand when ANativeWindow_fromSurface ran on the main thread
// (v1.0.572), and through a 2 s bounded main-thread hand-off when it did not
// (2026-07-30, SDL). Default ON, the layer is now created (hidden, unpublished)
// at a render view's surface creation for every app, and fromSurface only
// publishes it. =0 restores all three old paths byte for byte.
//
// Table-tested by debug/geh_unity-nativeegl-layer-pacing_gate.sh, which
// compiles THIS header, so keep it free of ObjC and of any runtime state.
// Ref: docs/unity-nativeegl-layer-precreate-retired_2026-09-27.md.
#pragma once

extern "C++" {
namespace macapk {

// Default ON; any value starting with '0' turns it off (the convention the
// sibling vk_window_surface_policy.h uses).
inline bool sv_layer_at_create_env_on(const char* v) {
    return !(v != nullptr && v[0] == '0');
}

// The v1.0.162 Unity pre-create in drawInMTKView. Under =0 this is exactly the
// old condition (libunity loaded && no layer yet); default ON it never runs.
inline bool sv_unity_precreate_wanted(bool gate_on, bool unity_app,
                                      bool have_layer) {
    return !gate_on && unity_app && !have_layer;
}

// What drawInMTKView does, right before a view's FIRST macapkSurfaceChanged.
enum class SvAtCreate { kNone, kCreate, kPlace };
inline SvAtCreate sv_at_create_action(bool gate_on, bool published,
                                      bool have_pending) {
    if (!gate_on || published) return SvAtCreate::kNone;
    return have_pending ? SvAtCreate::kPlace : SvAtCreate::kCreate;
}

// What CocoaEnsureNativeEglLayer (ANativeWindow_fromSurface's backend) does.
//   kLegacy          gate off: the pre-change body, untouched
//   kReturnPublished the window already exists and is published: look it up
//   kPublishPending  publish the layer made at surface creation (any thread,
//                    no CALayer mutation off-main, no wait)
//   kLegacyFallback  gate on but no surface was ever created: say so loudly,
//                    then run the pre-change body so nothing that worked breaks
enum class SvFromSurface { kLegacy, kReturnPublished, kPublishPending,
                           kLegacyFallback };
inline SvFromSurface sv_fromsurface_action(bool gate_on, bool published,
                                           bool have_pending) {
    if (!gate_on) return SvFromSurface::kLegacy;
    if (published) return SvFromSurface::kReturnPublished;
    if (have_pending) return SvFromSurface::kPublishPending;
    return SvFromSurface::kLegacyFallback;
}

}  // namespace macapk
}  // extern "C++"
