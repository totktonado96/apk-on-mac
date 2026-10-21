// camera_capture.h -- native macOS camera capture for Mac.apk.
//
// This is the layer BELOW android.hardware.camera2: a plain C surface over an
// AVFoundation AVCaptureSession, implemented in runtime/src/camera_capture.mm.
// The camera2 Java implementation (CameraManager / CameraDevice /
// CameraCaptureSession / ImageReader) binds onto it through the JNI seam in
// runtime/java/com/macapk/loader/CameraBridge.java. Nothing in this header
// knows anything about camera2 types, and nothing here is app-specific.
//
// WHY A C SURFACE AND NOT OBJC IN THE HEADER: native_methods.cpp and other
// plain-C++ TUs include this; keeping ObjC out of the header means they do not
// need to be compiled as ObjC++. Same convention as media_video.mm's
// macapk_vd_* core.
//
// ---------------------------------------------------------------------------
// THREADING
// ---------------------------------------------------------------------------
// AVFoundation delivers sample buffers on a private serial dispatch queue, not
// the main thread. Every function here is callable from any thread; the
// implementation guards the shared frame slot with a mutex. Enumeration
// (macapk_cam_device_count / _device_info / _format_count / _format_info) does
// NOT require camera authorization and does NOT start a session, so it is safe
// to call at any time, including from a headless run -- see PERMISSIONS below.
//
// ---------------------------------------------------------------------------
// PERMISSIONS (macOS TCC)
// ---------------------------------------------------------------------------
// Verified empirically on macOS 26 (2026-08-10) with an isolated probe:
//   * Device DISCOVERY and format enumeration work with authorizationStatus ==
//     NotDetermined, from a bare binary with NO bundle Info.plist. No prompt is
//     raised and the process is not killed. So a headless
//     `runtime/build/bin/macapk-runtime` run can still answer "what cameras
//     exist" identically to a bundled run.
//   * Only creating an AVCaptureDeviceInput / starting the session touches the
//     protected resource, and THAT is what raises the TCC prompt. A process
//     that reaches that point with no NSCameraUsageDescription in its bundle
//     Info.plist is SIGKILLed by TCC -- not denied, killed.
// The launcher bundle already declares NSCameraUsageDescription
// (launcher/Info.plist), and the runtime is a child of that bundle, so the
// bundled path is safe. A HEADLESS run started from a terminal is attributed to
// the terminal instead, so the outcome there depends on the terminal's own TCC
// state. That is why macapk_cam_open() is the gate: everything cheap and safe
// happens before it, and it fails cleanly rather than hanging.
//
// ---------------------------------------------------------------------------
// PIXEL FORMAT -- read this before touching the conversion site
// ---------------------------------------------------------------------------
// The full layout mapping (Android YUV_420_888 <-> CVPixelBuffer NV12) is
// documented at the conversion site in camera_capture.mm. The short version:
// we ask AVFoundation for '420f' (kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
// a 2-plane NV12 buffer, and expose it to Java as the 3 planes YUV_420_888
// requires by pointing the U and V planes at the SAME interleaved chroma plane
// with pixelStride 2 and a one-byte offset between them. No pixel conversion
// and no copy: the plane descriptors do the work.

#ifndef MACAPK_CAMERA_CAPTURE_H
#define MACAPK_CAMERA_CAPTURE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Constants mirrored from AOSP. Values pinned from source, not guessed.
// ---------------------------------------------------------------------------

// android.graphics.ImageFormat. YUV_420_888 = 0x23 and JPEG = 0x100, verified
// against AOSP graphics/java/android/graphics/ImageFormat.java.
enum {
    MACAPK_CAM_FMT_YUV_420_888 = 0x23,
    MACAPK_CAM_FMT_JPEG        = 0x100,
};

// android.hardware.camera2.CameraMetadata LENS_FACING_*. A MacBook's built-in
// camera points at the user, so it is FRONT; anything else we treat as
// EXTERNAL, which is what Android reports for a USB/UVC camera.
enum {
    MACAPK_CAM_FACING_FRONT    = 0,
    MACAPK_CAM_FACING_BACK     = 1,
    MACAPK_CAM_FACING_EXTERNAL = 2,
};

// Mirrors AVAuthorizationStatus so the Java side can report it without an ObjC
// dependency. The numeric values are AVFoundation's, not ours.
enum {
    MACAPK_CAM_AUTH_NOT_DETERMINED = 0,
    MACAPK_CAM_AUTH_RESTRICTED     = 1,
    MACAPK_CAM_AUTH_DENIED         = 2,
    MACAPK_CAM_AUTH_AUTHORIZED     = 3,
};

// Max planes we ever describe. YUV_420_888 is exactly 3.
#define MACAPK_CAM_MAX_PLANES 3

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// One capture device. `id` is AVFoundation's uniqueID, which is stable across
// runs for a built-in camera, so camera2 can use it as its camera id string.
typedef struct {
    char    id[128];
    char    name[128];
    int32_t facing;              // MACAPK_CAM_FACING_*
    int32_t sensorOrientation;   // degrees; always 0 on a Mac (no rotating sensor)
    int32_t formatCount;
} MacapkCamDeviceInfo;

// One (resolution, frame-rate range) the device advertises.
typedef struct {
    int32_t width;
    int32_t height;
    double  minFps;
    double  maxFps;
} MacapkCamFormat;

// Number of video capture devices. 0 when there is no camera OR when access is
// denied -- see macapk_cam_auth_status() to tell those apart. Never blocks.
int  macapk_cam_device_count(void);

// Fill `out` for device `index`. false if the index is out of range.
bool macapk_cam_device_info(int index, MacapkCamDeviceInfo* out);

// Formats advertised by device `index`.
int  macapk_cam_format_count(int index);
bool macapk_cam_format_info(int index, int formatIndex, MacapkCamFormat* out);

// Current TCC authorization: MACAPK_CAM_AUTH_*. Does not prompt.
int  macapk_cam_auth_status(void);

// Ask for authorization. NON-BLOCKING: it kicks off the async system prompt and
// returns immediately, because the AVFoundation completion handler runs on an
// arbitrary queue and blocking a Java thread on it would deadlock an app that
// called this from its UI thread. Poll macapk_cam_auth_status() for the result.
void macapk_cam_request_auth(void);

// ---------------------------------------------------------------------------
// Capture session
// ---------------------------------------------------------------------------

typedef struct MacapkCamSession MacapkCamSession;

// Open device `index`. This is the call that touches the protected resource, so
// it is the one that can raise the TCC prompt. Returns NULL when the device does
// not exist, access is denied, or AVFoundation refuses the input. Never hangs.
MacapkCamSession* macapk_cam_open(int index);

// Request a capture size and frame rate. Picks the advertised format whose area
// is closest to width*height and clamps fps into that format's supported range.
// Call before macapk_cam_start(). Returns false if the session is invalid.
bool macapk_cam_configure(MacapkCamSession* s, int width, int height, int fps);

// Actual negotiated geometry, valid after configure(). The app asked for a size;
// these are what it is going to get, and camera2 must report THESE.
int  macapk_cam_width(MacapkCamSession* s);
int  macapk_cam_height(MacapkCamSession* s);

bool macapk_cam_start(MacapkCamSession* s);
void macapk_cam_stop(MacapkCamSession* s);
void macapk_cam_close(MacapkCamSession* s);

// Total frames delivered by AVFoundation since start, including ones dropped
// because the consumer did not drain in time. A frame counter that advances is
// the only honest proof that capture is live.
int64_t macapk_cam_frames_delivered(MacapkCamSession* s);

// ---------------------------------------------------------------------------
// Frame handoff -- mirrors ImageReader.acquireLatestImage() / Image.close()
// ---------------------------------------------------------------------------
//
// One frame, described as camera2 describes it. The pointers are valid only
// between a successful macapk_cam_acquire() and the matching
// macapk_cam_release(): acquire locks the CVPixelBuffer's base address and
// release unlocks it. Holding one across frames is what Android's Image does,
// and forgetting to release is what stalls a real camera2 pipeline too.
typedef struct {
    int32_t  width;
    int32_t  height;
    int32_t  planeCount;                          // 3 for YUV_420_888
    int64_t  timestampNs;                         // CMSampleBuffer PTS, nanoseconds
    int64_t  frameNumber;
    uint8_t* planeData[MACAPK_CAM_MAX_PLANES];
    int32_t  planeSize[MACAPK_CAM_MAX_PLANES];    // bytes reachable from planeData
    int32_t  rowStride[MACAPK_CAM_MAX_PLANES];    // Plane.getRowStride()
    int32_t  pixelStride[MACAPK_CAM_MAX_PLANES];  // Plane.getPixelStride()
} MacapkCamFrame;

// Take the most recent frame, dropping any older undrained one -- the same
// "latest wins" policy as ImageReader.acquireLatestImage(), and the reason the
// session sets alwaysDiscardsLateVideoFrames. false when no frame has arrived
// yet or one is already held.
bool macapk_cam_acquire(MacapkCamSession* s, MacapkCamFrame* out);

// Release the frame taken by acquire(). Safe to call when nothing is held.
void macapk_cam_release(MacapkCamSession* s);

// ---------------------------------------------------------------------------
// Newest-frame RGBA copy -- the SurfaceTexture consumer path
// ---------------------------------------------------------------------------
//
// A SurfaceTexture consumer (TextureView preview, a GL renderer, WebRTC's
// SurfaceTextureHelper) needs the frame as an RGBA texture image, not as YUV
// planes. The conversion happens HERE, in native code, because this is where
// the CVPixelBuffer's row strides are still authoritative: a row offset must
// come from CVPixelBufferGetBytesPerRowOfPlane, never from the width
// (CoreVideo pads -- a 65-wide plane gets row stride 128).
//
// These functions read from a session-held reference to the NEWEST delivered
// frame that is INDEPENDENT of the acquire()/release() slot above, so a
// SurfaceTexture latch never steals a frame from an ImageReader in the same
// session and never blocks on one being held. "Latch the most recent frame"
// is exactly GLConsumer's updateTexImage contract.
//
// Row order: dst row 0 is the TOP image row, matching Android's buffer memory
// layout ("(0, 0) is the top-left corner", GLConsumer.cpp), which is why the
// transform matrix camera2 hands to SurfaceTexture consumers is AOSP's
// mtxFlipV.

// Presentation timestamp (ns) of the newest delivered frame, 0 when none has
// arrived. Advances with every delivery; cheap enough to poll.
int64_t macapk_cam_latest_timestamp(MacapkCamSession* s);

// Convert the newest frame to RGBA8888, byte order R,G,B,A in memory, rows
// tightly packed (row stride = width * 4). Returns the frame's PTS in ns
// (clamped to >= 1 so 0 always means failure); 0 when no frame has arrived or
// dstCapBytes < width * height * 4. outDims[0]/[1] are set to the frame's
// width/height whenever a frame exists, including on the too-small failure, so
// a caller can size its buffer and retry.
int64_t macapk_cam_copy_latest_rgba(MacapkCamSession* s, uint8_t* dst,
                                    int64_t dstCapBytes, int32_t outDims[2]);

// Same conversion, packed as 0xAARRGGBB ints (android.graphics.Bitmap /
// Canvas ARGB order, A always 0xFF). dstCapPixels is in PIXELS.
int64_t macapk_cam_copy_latest_argb(MacapkCamSession* s, uint32_t* dst,
                                    int64_t dstCapPixels, int32_t outDims[2]);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // MACAPK_CAMERA_CAPTURE_H
