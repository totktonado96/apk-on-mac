// vk_window_surface_policy.h -- does the guest's native eglCreateWindowSurface
// get the WINDOW surface it asked for, or the v612 offscreen-decouple pbuffer?
//
// Pure functions of three environment strings, so the offline gate
// (debug/geh_offscreen-decouple-present_gate.sh) can compile and table-test the
// exact code the shim runs, without a runtime launch.
//
// AOSP: eglCreateWindowSurface returns a WINDOW surface for a valid
// ANativeWindow and sets swap interval 1 on it
// (frameworks/native/opengl/libs/EGL/egl_platform_entries.cpp,
// eglCreateWindowSurfaceTmpl: window->setSwapInterval(window, 1)). With the
// ANGLE Vulkan backend that surface is WindowSurfaceVk over a VkSwapchain, and
// the producer's only wait is BufferQueueProducer::waitForFreeSlotThenRelock,
// woken by the consumer releasing a buffer. Our window arm is the same
// architecture: ANGLE WindowSurfaceVkMac -> MoltenVK VkSwapchain -> the guest's
// dedicated CAMetalLayer (ANGLE patch 0003). Android never substitutes a
// pbuffer, so the default (MACAPK_VK_WINDOW_SURFACE unset or anything not
// starting with '0') is the window surface.
//
// MACAPK_VK_WINDOW_SURFACE=0 restores the v612 decision VERBATIM:
// macapk_decouple_legacy below is the pre-2026-09-27 lambda, byte for byte in
// behaviour (MACAPK_NO_DECOUPLE set -> window; else pbuffer iff
// ANGLE_DEFAULT_PLATFORM == "vulkan"). So under =0, MACAPK_NO_DECOUPLE keeps
// its old meaning as the opt-out alias. Evidence and the measured A/B:
// docs/offscreen-decouple-present-retired_2026-09-27.md.
#pragma once

#include <cstring>

// extern "C++": harmless at file scope (where bionic_shim.cpp includes it, in
// its top-of-file include block) and keeps the header safe if it is ever
// included inside an extern "C" region.
extern "C++" {
namespace macapk {

// "=0" for a default-ON MACAPK_* gate: the value starts with '0'.
inline bool vk_window_surface_env_off(const char* v) {
    return v != nullptr && v[0] == '0';
}

// The pre-change (v612 .. v1.0.1655) decision, unchanged. Returns true when the
// guest's window surface is REPLACED by the offscreen-decouple pbuffer.
inline bool macapk_decouple_legacy(const char* no_decouple, const char* platform) {
    if (no_decouple) return false;  // opt-out escape hatch
    return platform != nullptr && std::strcmp(platform, "vulkan") == 0;
}

// The current decision. Default: never substitute (the guest keeps its window
// surface). MACAPK_VK_WINDOW_SURFACE=0: the legacy decision.
inline bool macapk_decouple_wanted(const char* vk_window_surface,
                                   const char* no_decouple,
                                   const char* platform) {
    if (vk_window_surface_env_off(vk_window_surface))
        return macapk_decouple_legacy(no_decouple, platform);
    return false;
}

// Whether the shim prints its once-per-process "VULKAN window surface" line:
// only where the gate CHANGED the outcome (the legacy rule would have
// substituted the pbuffer and the current rule does not). Never true under =0,
// so the =0 arm's stderr is exactly the pre-change stderr. A pure function so
// the gate's B4 row can table-test it instead of trusting a source pattern.
inline bool macapk_vk_window_arm_note(const char* vk_window_surface,
                                      const char* no_decouple,
                                      const char* platform) {
    return !macapk_decouple_wanted(vk_window_surface, no_decouple, platform) &&
           macapk_decouple_legacy(no_decouple, platform);
}

}  // namespace macapk
}  // extern "C++"
