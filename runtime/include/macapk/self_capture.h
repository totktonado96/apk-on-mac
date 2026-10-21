// self_capture.h -- capture the frame WE present, without any macOS permission.
//
// Why this exists: every visual render verdict used to route through
// `screencapture`, which needs the Screen Recording TCC grant. That grant is
// attached to the app hosting the shell, and under Claude Code that is a
// version-numbered helper bundle (~/Library/Application Support/Claude/
// claude-code/<VERSION>/claude.app) that is replaced on every auto-update, so
// the grant silently lapses. A denied capture writes nothing, the color count
// reads 0, and a rendering app is scored a STALL -- that exact failure wasted a
// session on 2026-07-20 (Current_State v660) and again on 2026-07-22.
//
// A process needs NO permission to read back its own rendered content, so the
// runtime dumps its own presented frame instead. FOUR capture sources, because
// there are four present paths and no single one covers the fleet:
//   1. the GL path      -- glReadPixels of FBO 0 in AngleEndFrame, taken
//                          BEFORE eglSwapBuffers (the backbuffer is undefined
//                          after the swap).
//   2. the canvas path   -- the ARGB image CocoaPresentBitmap composites, for
//                          pure-Java / Compose / Canvas apps whose pixels never
//                          touch FBO 0.
//   3. the decouple path -- CocoaDecouplePresentTick already holds the exact
//                          RGBA bytes it is about to present for native-EGL
//                          Vulkan guests.
//   4. the LAYER path (v1.0.835) -- a blit-readback of the CAMetalDrawable a
//                          guest just presented, taken from the
//                          -[CAMetalLayer nextDrawable] swizzle. This is the
//                          UNIVERSAL source and the reason the other three are
//                          now cross-checks rather than the whole instrument.
//
// WHY THE LAYER SOURCE EXISTS (measured 2026-07-29). Sources 1-3 all sit on a
// path the FRAMEWORK drives. A guest that drives its own EGL surface --
// ANativeWindow_fromSurface -> eglCreateWindowSurface -> its own
// eglSwapBuffers, on its own render thread -- runs through NONE of them, so a
// capture request produced no file at all and every caller fell back to
// `screencapture`, which needs the Screen Recording grant and (when the window
// id lookup misses) returns the whole desktop. Smash Hit, an app that renders
// and is playable, was scored 0 that way; Crossy Road's framework GL context is
// released outright, so its gl source is an artifact of a path nobody watches.
// But the guest cannot escape ONE fact: it presents into a CAMetalLayer, and
// -[CAMetalLayer nextDrawable] is the only way to get a drawable out of one. So
// swizzling that single AppKit-side method sees the presented pixels of EVERY
// engine -- ANGLE-Metal, ANGLE-Vulkan/MoltenVK, libunity's own layer, and the
// framework's angleLayer -- with no engine sniffing and no per-APK code.
// Mechanics: on a capture request the swizzle retains the drawable it just
// vended, and on the NEXT acquire (or from the main-thread poll if the guest
// went idle) blits its texture into a shared-storage texture and reads it back.
// Retaining the drawable is what keeps the content valid; it costs one pool slot
// for one frame, and only while a request is outstanding.
//
// Protocol (so an already-running app can be captured on demand, with no env
// var chosen at launch time): a caller touches the request file, and the next
// presented frame is written to the output PNG and the request consumed.
//   request: /tmp/macapk_capture_req_<pid>
//   output:  /tmp/macapk_capture_<pid>_<source>.png
//            (source = gl | canvas | dc | layer | layer2 | composite)
//   done:    /tmp/macapk_capture_<pid>.done           (lists the sources written)
// The caller scores every file produced and takes the richest -- which also
// reports WHICH path carries the content, the render-vs-composite bisect.
//
// THE COMPOSITE SOURCE (v1.0.1036). Every source above is a single surface,
// and "the richest single source" is NOT what the user sees -- a video app's
// richest source was the isolated video plane (291k colours, ZERO UI), and the
// canvas overlay vs the guest's EGL layer differ in zPosition and frame, which
// a per-layer read discards. `composite` is ONE image of the actual screen:
// the render view's sublayer tree blended in zPosition order at each layer's
// real frame, honouring hidden/opacity/opaque. CAMetalLayer pixels come from a
// persistent per-layer store fed by the layer-source readbacks; CALayer
// CGImage contents (canvas / dialog overlays) draw directly. Built on the main
// thread near the end of the capture window, after the per-layer sources have
// refreshed the store. Judge "what does the user see" on `composite`; keep
// using the per-layer sources to attribute WHICH surface carries content.
//
// IDLE APPS (v1.0.835). The capture used to piggyback strictly on the NEXT
// present, so a static menu that never repaints produced nothing and the caller
// timed out. Frozen Bubble proved it: `canvas 76549` on one run and NO source at
// all on another, same build, minutes apart. Every source that can cheaply
// retain its last frame now does (canvas keeps the ARGB bytes it last
// composited; dc keeps the last published slot; layer keeps the last vended
// drawable), and a MAIN-THREAD poll in drawInMTKView -- which ticks regardless
// of whether the guest draws -- serves those retained frames. The gl source
// cannot join: a per-frame glReadPixels is not affordable, and it needs the
// guest's context current on the guest's thread.
//
// A READER MUST WAIT FOR THE .done MARKER, not for "a png appeared" and not
// for the total byte count to stop growing. The sources sit at different
// points inside a frame -- canvas mid-frame, gl at end-of-frame -- so they can
// be a whole frame apart, and on a loaded box a frame can be over a second.
// Both guesses settle in that gap, score the small canvas file alone, and
// report a rendering app as blank; that is the hcr181 false REGRESS that was
// misread as an arm32rc codegen regression (v1.0.803). The marker is published
// only once every source that claimed a slot has finished renaming its PNG.
// Use debug/capture_wait.sh rather than reimplementing the wait.
// debug/rendercheck.sh drives this and falls back to screencapture.
//
// Cost when idle: one throttled stat() per few frames. Opt out with
// MACAPK_SELF_CAPTURE=0.
#pragma once

#include <cstdint>

namespace macapk {

// True at most once per request PER SOURCE. The first caller to see the request
// file opens a short capture WINDOW (and consumes the request); every present
// path that fires inside that window captures once, into its own file. This
// matters because the GL path runs even for apps whose pixels never reach FBO 0
// -- a single shared slot let the GL hook win the race and write a black frame
// for a Canvas app that was rendering fine. `tag` names the source ("gl",
// "canvas", "dc") and selects the output file. Safe to call from any thread.
bool SelfCaptureRequested(const char* tag);

// Would the "gl" source capture on the NEXT drawn frame -- a capture window is
// open and "gl" has not claimed its slot, or a request file is waiting? A pure
// peek (it claims nothing and consumes no request). Read on a tick the Java
// GLSurfaceView would otherwise withhold (RENDERMODE_WHEN_DIRTY), so an
// instrument gets a REAL frame instead of a readback of a framebuffer nothing was
// drawn to. Safe to call from any thread.
bool SelfCaptureGlWanted();

// Write RGBA8 pixels to the request's output PNG. `bottom_up` flips rows (both
// of our sources are GL-origin readbacks; PNG rows run top-down). Alpha is
// deliberately DROPPED -- a glReadPixels alpha of 0 would otherwise produce a
// fully transparent PNG, which the scorer (debug/richcheck.swift skips
// non-opaque pixels) would read as an empty frame.
void SelfCaptureWriteRGBA(const uint8_t* rgba, int width, int height,
                          bool bottom_up, const char* tag);

// Canvas path: takes an already-built CGImageRef (as void* to keep this header
// free of CoreGraphics). Used by CocoaPresentBitmap.
void SelfCaptureWriteCGImageForCanvas(void* cgImage, const char* tag);

// ---------------------------------------------------------------------------
// STRUCTURE SCORING (v1.0.835) -- the second half of the instrument.
//
// Why a pixel count is not enough, measured 2026-07-29 and believed twice
// before that: ViewCanvasDriver prints `present WxH nonzero=A/B opaque=O
// drawn=D`, and a HIGH `drawn` proves nothing because it counts a flat
// background fill. Sgt Puzzles read drawn=1478592 -- 100% of the window --
// while a window capture of the same run scored SPARSE with 4 of 16 grid cells
// occupied; Calculator read drawn=752968 on one run and 3227 on another and its
// window is chrome-only. A LOW drawn is still conclusive; a high one is noise.
//
// debug/richcheck.swift already computes the statistics that DO separate a real
// frame from a flat fill (modal-colour share, coverage, edge density, occupied
// cells of a 4x4 grid). Computing them HERE, over pixels the runtime already
// holds, makes a run self-verifying: the verdict lands in the log with no
// capture request, no PNG, no `swift` invocation, and therefore no race and no
// concurrency failure. The thresholds deliberately MATCH richcheck.swift so its
// fleet calibration carries over unchanged.
//
// `stride` is bytes per row; `bgra` selects channel order (Metal drawables and
// Android ARGB_8888-on-little-endian are BGRA, GL readbacks are RGBA). Rows are
// assumed top-down -- flip before calling if the source is GL-origin. Alpha is
// ignored: unlike a window capture there is no rounded corner or drop shadow to
// exclude, and a GL readback's alpha is routinely 0.
//
// Cost: two passes over the frame plus a 2 MB scratch bitset, ~5 ms for
// 808x1796 and ~20 ms for 3244x1796. Callers on a per-frame path must throttle
// (SelfCaptureScorePeriod() is the shared cadence, MACAPK_FRAME_SCORE_EVERY).
void SelfCaptureScoreFrame(const uint8_t* px, int width, int height, int stride,
                           bool bgra, const char* tag);

// Presents between periodic score lines on a per-frame path. 0 disables.
unsigned SelfCaptureScorePeriod();

// Serve any retained last-frame snapshots for a pending capture request, and
// finish a layer readback whose guest went idle. MUST be called from the main
// thread on a path that ticks even when the guest never draws (drawInMTKView).
void SelfCapturePollFromMainThread();

}  // namespace macapk
