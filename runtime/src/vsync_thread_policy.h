// vsync_thread_policy.h -- who ticks the display vsync this frame: the dedicated
// vsync thread (MACAPK_VSYNC_THREAD, default ON) or the AppKit main thread?
//
// Pure functions of plain values, so the offline gate (debug/vsync_thread_gate.sh)
// compiles and exercises the exact decision cocoa_bridge.mm runs, against the REAL
// Java vsync registry block from native_methods.cpp, without a window or a launch.
//
// AOSP: vsync comes from SurfaceFlinger and is delivered to each
// DisplayEventReceiver on the Looper it was created with ("@param looper The
// looper to use when invoking callbacks", frameworks/base core/java/android/view/
// DisplayEventReceiver.java:105-108 (aosp-mirror master)). A busy UI thread delays its own frame only.
// Apk on Mac generated every vsync inside drawInMTKView on the main thread, so a
// main-thread stall withheld vsync from every paced guest thread.
// docs/subway-frame-hitches_2026-09-28.md.
#pragma once

#include <cstring>

namespace macapk {

// MACAPK_VSYNC_THREAD: default ON; exactly "0" is the old path.
inline bool vsync_thread_env_on(const char* v) {
    return !(v != nullptr && std::strcmp(v, "0") == 0);
}

// The hand-over window: the vsync thread owns the tick while its last callback is
// younger than this many drive periods. Three periods (50 ms at 60 Hz) rides out a
// late callback or two without the main thread double-ticking, and still hands
// the tick back quickly when the link stops (window on no display, link paused).
constexpr double kVsyncThreadStalePeriods = 3.0;

// drawInMTKView's question. enabled = vsync_thread_env_on(getenv); drain_present =
// the shim exports __macapk_arm64_choreographer_run_ready (without it the main
// thread's own AChoreographer callbacks could not run once the fire moved off it);
// beat = CACurrentMediaTime of the vsync thread's last callback (0 = never);
// now = this frame's CACurrentMediaTime; period = 1 / drive rate.
// true = the vsync thread ticks, the main thread must NOT; false = tick here.
inline bool vsync_thread_owns_tick(bool enabled, bool drain_present, double beat,
                                   double now, double period) {
    if (!enabled || !drain_present) return false;
    return beat > 0.0 && (now - beat) < kVsyncThreadStalePeriods * period;
}

}  // namespace macapk
