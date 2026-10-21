// video_vp8_decode.mm -- real VP8 VIDEO decode backend for android.media.
// MediaCodec, backed by libvpx (BSD-3-Clause, WebM project), software-only.
//
// WHY THIS FILE EXISTS INSTEAD OF EXTENDING video_toolbox.mm.
// video_toolbox.mm's own header (and its kMimeTable comment) already states
// the fact this file exists to answer: "VP8 has no VideoToolbox decoder at
// any tier on any macOS version (no kCMVideoCodecType_VP8 constant exists in
// CMFormatDescription.h -- checked); it is out of scope for this file by
// construction and is expected to be served by a software (libvpx) path
// elsewhere, reported honestly as non-hardware." This is that path. Per
// CLAUDE.md's decision ladder (macOS native, then clean 3rd-party, then
// build it ourselves): rung 1 (VideoToolbox) is empty for VP8, so this is
// rung 2 -- libvpx is a clean, permissively-licensed (BSD-3) third-party
// decoder, the same bar thirdparty/bionic_translation (GPL-3, deliberately
// left UNLINKED) is held to and clears.
//
// WHY WEBRTC CARES: Android's CDD mandates VP8 decode on any device that
// does video, and WebRTC negotiates VP8 as its baseline codec -- every
// video-calling app falls back to it when nothing else is offered. This
// unlocks that category, not one app; see docs/voip-video-calling-
// viability_2026-08-10.md, which already found Signal/Telegram both ship
// libvpx VP8/VP9 *inside their own .so* for the case where MediaCodec can't
// help them -- this file is what lets MediaCodec help them instead.
//
// ENGINE CONTRACT -- matches video_toolbox.mm's macapk_vtb_* shape on
// purpose (open/decode/poll/render/release/frame_copy_bgra/flush/close/
// width/height), so a caller does not need a different calling convention
// per codec, only a different function to call. Concretely:
//   * macapk_vp8_open/_decode/_poll/_flush/_close/_width/_height/_probe_mime
//     are NEW (this file), because they touch the vpx_codec_ctx_t handle.
//   * macapk_vp8_render_frame calls the SAME CocoaPresentVideoFrame
//     (cocoa_bridge.mm) entry point video_toolbox.mm's macapk_vtb_render_
//     frame calls -- frames reach the screen through the identical,
//     already-proven present path (CocoaPresentVideoFrame -> macapk_vd_
//     present_to_layer, media_video.mm), not a second path invented here.
//   * macapk_vp8_release_frame / macapk_vp8_frame_copy_bgra are trivial,
//     generic CoreVideo operations (CFRelease / lock+memcpy+unlock) that do
//     not touch anything codec-specific, so they are reimplemented here
//     (a few lines each) rather than reaching into video_toolbox.mm -- this
//     keeps this file independently buildable/linkable and, more
//     importantly, avoids a build-order/ownership dependency on a file a
//     sibling lane owns concurrently. The two implementations operate on
//     byte-identical buffer shapes (packed 32BGRA, IOSurface-backed,
//     Metal-compatible CVPixelBufferRef -- see CreateBgraPixelBuffer below,
//     whose attribute dictionary matches media_video.mm's vd_make_session
//     verbatim) by construction, so a caller cannot tell them apart.
//
// WHAT THE JAVA/JNI SIDE STILL NEEDS (NOT done in this file -- NativeMedia.
// java, MediaCodec.java and native_methods.cpp are owned by sibling lanes /
// the orchestrator; this file only exposes the native surface for them to
// bind). See the exact wiring at the bottom of this file, past the JNI
// method table.
//
// SCOPE: clear (unencrypted) decode only, matching every other decode
// backend in this tree (CLAUDE.md: no DRM circumvention). VP8 carries no
// Android codec-specific-data (csd-0/csd-1): unlike AVC/HEVC, MediaFormat
// defines no out-of-band parameter-set convention for VP8/VP9 (AOSP
// frameworks/base MediaFormat.java's csd table lists none for
// video/x-vnd.on2.vp8) -- every access unit is a complete, self-describing
// VP8 frame, and libvpx's own bitstream parser reads width/height/keyframe-
// ness directly out of the frame's 3/10-byte uncompressed header. The
// csd0/csd1 parameters below exist only for call-shape parity with
// macapk_vtb_open and are accepted-but-unused.
//
// CITATIONS (verified against this machine's Homebrew libvpx 1.16.0, the
// same package manager + pin-to-local-headers convention runtime/CMakeLists
// .txt already uses for capstone/libpng/openjdk):
//   vpx/vpx_decoder.h  -- vpx_codec_dec_init/_decode/_get_frame, the
//     iterator contract ("Iterates over a list of the frames available for
//     display ... valid upon completion of vpx_codec_decode ... until the
//     next call"), vpx_codec_dec_cfg_t.
//   vpx/vp8dx.h        -- vpx_codec_vp8_dx() (the VP8 decoder algorithm
//     interface getter; this file does not use the deprecated
//     vpx_codec_vp8_dx_algo extern directly, matching the header's own
//     "\deprecated ... prefer vpx_codec_vp8_dx()" note).
//   vpx/vpx_image.h    -- vpx_image_t (planes[]/stride[]/d_w/d_h/x_chroma_
//     shift/y_chroma_shift/cs/range), VPX_IMG_FMT_I420 (VP8's only output
//     format: 8-bit, 4:2:0, no alpha -- confirmed by the format enum having
//     no VP8-specific alternative and by libvpx shipping no VP8 high-
//     bitdepth or 4:2:2/4:4:4 path).
//   vpx/vpx_codec.h    -- vpx_codec_ctx_t/_err_t/_err_to_string/_destroy.
// YUV(BT.601/BT.709, studio/full range) -> RGB matrix verified against
// Chromium's libyuv (BSD-3, the reference implementation WebRTC's own VP8
// pipeline uses for this exact conversion), source/row_common.cc:
// kYuvI601Constants/kYuvJPEGConstants/kYuvH709Constants/kYuvF709Constants --
// see the CoeffsFor() comment below for the exact values quoted from there.
//
// Refs: docs/video-decode-backend_2026-06-21.md (the VideoToolbox pipeline
// this file's frames plug into), docs/voip-video-calling-viability_2026-08-
// 10.md (why VP8 unlocks WebRTC-class apps), video_toolbox.mm (the sibling
// engine this file's contract mirrors).

#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8dx.h>
#include <jni.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <string>

// Defined in cocoa_bridge.mm; the SAME present entry point video_toolbox.mm
// calls (see the file header). Declared extern here rather than pulled from
// a shared header, matching the existing forward-declare-across-.mm-files
// convention already used throughout runtime/src (e.g. video_toolbox.mm's
// own extern declarations of macapk_vd_present_create/_to_layer).
extern "C" void CocoaPresentVideoFrame(void* pixbuf, int width, int height);

namespace {

const char* const kVp8Mime = "video/x-vnd.on2.vp8";  // AOSP MediaFormat.MIMETYPE_VIDEO_VP8

// MediaCodec.BUFFER_FLAG_END_OF_STREAM, mirrored the same way video_toolbox
// .mm's kFlagEndOfStream is (that file has no Java import either; the value
// is a stable part of the public AOSP API).
constexpr int kFlagEndOfStream = 4;

inline uint8_t Clamp255(float v) {
    if (v < 0.0f) return 0;
    if (v > 255.0f) return 255;
    return (uint8_t)(v + 0.5f);
}

// YUV -> RGB conversion coefficients. VP8 streams rarely signal a colorspace
// (vpx_image_t::cs comes back VPX_CS_UNKNOWN for the overwhelming majority
// of real VP8 content, which predates widespread BT.709 signaling), so the
// fallback -- and the one every other field in this table backs up -- is
// BT.601 studio range, the historical SD/WebM default. Values quoted
// verbatim from Chromium's libyuv, source/row_common.cc (BSD-3):
//   kYuvI601Constants (BT.601 studio): UB "round(2.018*64)", UG "round(0.391
//     *64)", VG "round(0.813*64)", VR "round(1.596*64)".
//   kYuvJPEGConstants  (BT.601 full):  UB "round(1.77200*64)", UG "round(
//     0.34414*64)", VG "round(0.71414*64)", VR "round(1.40200*64)".
//   kYuvH709Constants  (BT.709 studio): UB "round(2.112*64)", UG "round(0.213
//     *64)", VG "round(0.533*64)", VR "round(1.793*64)".
//   kYuvF709Constants  (BT.709 full):  UB "round(1.8556*64)", UG "round(
//     0.18732*64)", VG "round(0.46812*64)", VR "round(1.5748*64)".
// (UB/VR here are this file's kb/kr; UG/VG are kgU/kgV.) Studio-range Y is
// rescaled from [16,235] to [0,255] via (Y-16)*255/219, the standard BT.601/
// 709 studio-to-full luma stretch.
struct YuvCoeffs {
    float kr;      // R += kr   * (V - 128)
    float kgU;     // G -= kgU  * (U - 128)
    float kgV;     // G -= kgV  * (V - 128)
    float kb;      // B += kb   * (U - 128)
    float yOff;    // Y' = (Y - yOff) * yScale
    float yScale;
};

const YuvCoeffs kBt601Studio = {1.596f,  0.391f,   0.813f,   2.018f,  16.0f, 255.0f / 219.0f};
const YuvCoeffs kBt601Full   = {1.402f,  0.34414f, 0.71414f, 1.772f,   0.0f, 1.0f};
const YuvCoeffs kBt709Studio = {1.793f,  0.213f,   0.533f,   2.112f,  16.0f, 255.0f / 219.0f};
const YuvCoeffs kBt709Full   = {1.5748f, 0.18732f, 0.46812f, 1.8556f,  0.0f, 1.0f};

const YuvCoeffs& CoeffsFor(vpx_color_space_t cs, vpx_color_range_t range) {
    bool full = (range == VPX_CR_FULL_RANGE);
    bool bt709 = (cs == VPX_CS_BT_709);
    if (bt709) return full ? kBt709Full : kBt709Studio;
    return full ? kBt601Full : kBt601Studio;  // also the VPX_CS_UNKNOWN fallback
}

// Allocates a fresh CVPixelBufferRef shaped exactly like media_video.mm's
// vd_make_session destination attrs (kCVPixelFormatType_32BGRA + Metal-
// compatible + IOSurface-backed), which is what macapk_vd_present_to_layer's
// CVMetalTextureCacheCreateTextureFromImage requires (verified by reading
// that function in media_video.mm: it binds MTLPixelFormatBGRA8Unorm off
// CVPixelBufferGetWidth/Height with no format conversion of its own -- the
// buffer we hand it must already be exactly this shape). Without the
// IOSurface-properties key, CVPixelBufferCreate happily returns a buffer
// that CVMetalTextureCacheCreateTextureFromImage silently fails on, so this
// is not a cosmetic detail.
CVPixelBufferRef CreateBgraPixelBuffer(int width, int height) {
    if (width <= 0 || height <= 0) return nullptr;
    @autoreleasepool {
        NSDictionary* attrs = @{
            (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
            (id)kCVPixelBufferMetalCompatibilityKey: @YES,
            (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
        };
        CVPixelBufferRef pb = nullptr;
        CVReturn r = CVPixelBufferCreate(kCFAllocatorDefault, (size_t)width, (size_t)height,
                                         kCVPixelFormatType_32BGRA,
                                         (__bridge CFDictionaryRef)attrs, &pb);
        if (r != kCVReturnSuccess || !pb) {
            std::fprintf(stderr, "[video-vp8] CVPixelBufferCreate(%dx%d) failed: %d\n",
                        width, height, (int)r);
            return nullptr;
        }
        return pb;
    }
}

// Converts a decoded I420 vpx_image_t into an already-allocated BGRA
// CVPixelBufferRef of the SAME (d_w, d_h) dimensions. Uses img->d_w/d_h (the
// bitstream-signaled DISPLAY size) rather than img->w/h (the macroblock-
// aligned STORAGE size, which libvpx internally pads up to a multiple of
// 16) -- planes are walked by stride, so only the loop bounds need to be the
// display size, never the storage size.
void I420ToBgraInto(const vpx_image_t* img, CVPixelBufferRef pb) {
    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t* dst = (uint8_t*)CVPixelBufferGetBaseAddress(pb);
    size_t dstStride = CVPixelBufferGetBytesPerRow(pb);
    size_t w = CVPixelBufferGetWidth(pb);
    size_t h = CVPixelBufferGetHeight(pb);
    if (!dst) { CVPixelBufferUnlockBaseAddress(pb, 0); return; }

    const uint8_t* yPlane = img->planes[VPX_PLANE_Y];
    const uint8_t* uPlane = img->planes[VPX_PLANE_U];
    const uint8_t* vPlane = img->planes[VPX_PLANE_V];
    size_t yStride = (size_t)img->stride[VPX_PLANE_Y];
    size_t uStride = (size_t)img->stride[VPX_PLANE_U];
    size_t vStride = (size_t)img->stride[VPX_PLANE_V];
    unsigned xShift = img->x_chroma_shift;
    unsigned yShift = img->y_chroma_shift;
    const YuvCoeffs& c = CoeffsFor(img->cs, img->range);

    for (size_t row = 0; row < h; row++) {
        const uint8_t* ySrc = yPlane + row * yStride;
        const uint8_t* uSrc = uPlane + (row >> yShift) * uStride;
        const uint8_t* vSrc = vPlane + (row >> yShift) * vStride;
        uint8_t* dstRow = dst + row * dstStride;
        for (size_t col = 0; col < w; col++) {
            float Y = (float)ySrc[col];
            float U = (float)uSrc[col >> xShift];
            float V = (float)vSrc[col >> xShift];
            float yv = (Y - c.yOff) * c.yScale;
            float r = yv + c.kr  * (V - 128.0f);
            float g = yv - c.kgU * (U - 128.0f) - c.kgV * (V - 128.0f);
            float b = yv + c.kb  * (U - 128.0f);
            // kCVPixelFormatType_32BGRA byte order: B, G, R, A (matches
            // video_toolbox.mm's destination format and its WriteBgraPng's
            // kCGBitmapByteOrder32Little + kCGImageAlphaNoneSkipFirst pairing).
            uint8_t* px = dstRow + col * 4;
            px[0] = Clamp255(b);
            px[1] = Clamp255(g);
            px[2] = Clamp255(r);
            px[3] = 255;
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
}

struct Vp8Decoder {
    vpx_codec_ctx_t ctx;
    bool ctxOk = false;
    int width = 0, height = 0;   // last known DISPLAY dims; 0 until the first keyframe decodes

    // Unlike VideoToolbox (video_toolbox.mm's VtDecoder), there is no async
    // callback thread here: vpx_codec_decode() is a synchronous, single-
    // threaded call-and-return (cfg.threads=1 below), and vpx_codec_get_
    // frame() drains whatever it produced before decode() returns. So there
    // is no in-flight-frame-vs-flush race to guard with a generation counter
    // the way VtDecoder needs one -- outQ only ever holds frames that are
    // already fully decoded and waiting to be polled.
    std::mutex mu;
    struct OutFrame { CVPixelBufferRef pb; int64_t ptsUs; int flags; };
    std::deque<OutFrame> outQ;
};

bool InitCtx(Vp8Decoder* d, int widthHint, int heightHint) {
    vpx_codec_dec_cfg_t cfg = {};
    cfg.threads = 1;
    cfg.w = widthHint > 0 ? (unsigned)widthHint : 0;
    cfg.h = heightHint > 0 ? (unsigned)heightHint : 0;
    vpx_codec_err_t e = vpx_codec_dec_init(&d->ctx, vpx_codec_vp8_dx(), &cfg, 0);
    if (e != VPX_CODEC_OK) {
        std::fprintf(stderr, "[video-vp8] vpx_codec_dec_init failed: %s\n",
                    vpx_codec_err_to_string(e));
        return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// C ABI (macapk_vp8_*), mirroring video_toolbox.mm's macapk_vtb_* naming and
// signatures (see the file header for exactly which functions are new here
// vs. reused-by-construction).
// ---------------------------------------------------------------------------

extern "C" {

// Always 1 for the VP8 mime (libvpx is statically linked in, always
// present), 0 for anything else. *outHw is always 0: this is a software-only
// decoder and says so honestly, per the project's contract that
// nativeVideoIsHardware() must never claim hardware it didn't measure.
int macapk_vp8_probe_mime(const char* mimeC, int* outHw) {
    if (outHw) *outHw = 0;
    std::string mime = mimeC ? mimeC : "";
    return mime == kVp8Mime ? 1 : 0;
}

// csd0/csd0Len/csd1/csd1Len are accepted for call-shape parity with
// macapk_vtb_open but unused -- VP8 has no codec-specific-data convention
// (see the file header). width/height are hints from the app's MediaFormat;
// the authoritative size comes from the first decoded keyframe's vpx_image_t
// ::d_w/d_h (macapk_vp8_width/_height report whichever is known so far).
void* macapk_vp8_open(const char* mimeC, int width, int height,
                      const uint8_t* /*csd0*/, int /*csd0Len*/,
                      const uint8_t* /*csd1*/, int /*csd1Len*/,
                      int /*wantSurface*/, int* outHw) {
    std::string mime = mimeC ? mimeC : "";
    if (mime != kVp8Mime) {
        std::fprintf(stderr, "[video-vp8] open: unsupported mime '%s' (this engine only "
                    "handles %s)\n", mime.c_str(), kVp8Mime);
        return nullptr;
    }
    Vp8Decoder* d = new Vp8Decoder();
    if (!InitCtx(d, width, height)) {
        delete d;
        return nullptr;
    }
    d->ctxOk = true;
    d->width  = width  > 0 ? width  : 0;
    d->height = height > 0 ? height : 0;
    if (outHw) *outHw = 0;
    std::fprintf(stderr, "[video-vp8] open: mime=%s %dx%d (hint; confirmed at first "
                "keyframe) hw=no (software libvpx)\n", mime.c_str(), d->width, d->height);
    return d;
}

// Feeds one complete VP8 access unit (the app's demuxer hands MediaCodec one
// full frame per queueInputBuffer call; there is no fragment/partition
// convention in play here). Synchronous: any frame(s) vpx_codec_get_frame()
// yields are converted and enqueued before this returns, but the CALLER
// contract still matches macapk_vtb_decode's fire-and-forget shape (poll
// separately) so a caller can treat both engines identically.
int macapk_vp8_decode(void* h, const uint8_t* au, int auLen, int64_t ptsUs, int eos) {
    Vp8Decoder* d = (Vp8Decoder*)h;
    if (!d || !d->ctxOk) return -1;
    if (au && auLen > 0) {
        vpx_codec_err_t e = vpx_codec_decode(&d->ctx, au, (unsigned int)auLen, nullptr, 0);
        if (e != VPX_CODEC_OK) {
            // AOSP/MediaCodec's contract for a bad access unit is to keep the
            // session alive (the stream may self-heal at the next keyframe),
            // not tear it down -- log and continue, matching how a dropped/
            // corrupt frame is handled on real hardware decoders too.
            const char* detail = vpx_codec_error_detail(&d->ctx);
            std::fprintf(stderr, "[video-vp8] decode: vpx_codec_decode failed: %s (%s)\n",
                        vpx_codec_err_to_string(e), detail ? detail : "no detail");
        } else {
            vpx_codec_iter_t iter = nullptr;
            const vpx_image_t* img;
            while ((img = vpx_codec_get_frame(&d->ctx, &iter)) != nullptr) {
                if (img->fmt != VPX_IMG_FMT_I420) {
                    std::fprintf(stderr, "[video-vp8] decode: unexpected image format 0x%x "
                                "(VP8 should only ever produce I420); dropping frame\n",
                                (unsigned)img->fmt);
                    continue;
                }
                CVPixelBufferRef pb = CreateBgraPixelBuffer((int)img->d_w, (int)img->d_h);
                if (!pb) continue;
                I420ToBgraInto(img, pb);
                d->width  = (int)img->d_w;
                d->height = (int)img->d_h;
                std::lock_guard<std::mutex> lk(d->mu);
                d->outQ.push_back({pb, ptsUs, 0});
            }
        }
    }
    if (eos) {
        std::lock_guard<std::mutex> lk(d->mu);
        d->outQ.push_back({nullptr, -1, kFlagEndOfStream});
    }
    return 0;
}

// Pops the oldest ready frame. Returns 1 and fills the out-params if one was
// available, 0 if the queue is empty (TRY_AGAIN), -1 if `h` is invalid. Same
// shape as macapk_vtb_poll.
int macapk_vp8_poll(void* h, void** outPixbuf, int64_t* outPtsUs, int* outFlags) {
    Vp8Decoder* d = (Vp8Decoder*)h;
    if (!d) return -1;
    std::lock_guard<std::mutex> lk(d->mu);
    if (d->outQ.empty()) return 0;
    Vp8Decoder::OutFrame f = d->outQ.front();
    d->outQ.pop_front();
    if (outPixbuf) *outPixbuf = f.pb;
    if (outPtsUs)  *outPtsUs  = f.ptsUs;
    if (outFlags)  *outFlags  = f.flags;
    return 1;
}

// releaseOutputBuffer(index, render=true): hand the frame to the screen.
// Delegates to the SAME CocoaPresentVideoFrame video_toolbox.mm's
// macapk_vtb_render_frame calls -- see the file header for why this is not
// a second present path.
void macapk_vp8_render_frame(void* pixbuf, int width, int height) {
    if (!pixbuf) return;
    CocoaPresentVideoFrame(pixbuf, width, height);
}

// releaseOutputBuffer(index, render=false), or post-render cleanup: return
// the frame's native memory. MUST be called exactly once per frame
// macapk_vp8_poll ever returned, render or not, matching macapk_vtb_release_
// frame's contract (and AOSP's own "call ... with render set to false to
// simply return the buffer to the codec").
void macapk_vp8_release_frame(void* pixbuf) {
    if (pixbuf) CFRelease((CVPixelBufferRef)pixbuf);
}

// Best-effort raw-pixel readout for the no-Surface decode path (MediaCodec.
// getOutputImage), byte-for-byte the same operation as macapk_vtb_frame_
// copy_bgra (packed 32BGRA, caller-owned buffer, {width,height,stride} out).
int macapk_vp8_frame_copy_bgra(void* pixbuf, uint8_t* outBuf, int outCap,
                               int* outW, int* outH, int* outStride) {
    CVPixelBufferRef pb = (CVPixelBufferRef)pixbuf;
    if (!pb || !outBuf) return -1;
    CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    size_t w = CVPixelBufferGetWidth(pb);
    size_t h = CVPixelBufferGetHeight(pb);
    size_t stride = CVPixelBufferGetBytesPerRow(pb);
    const uint8_t* base = (const uint8_t*)CVPixelBufferGetBaseAddress(pb);
    size_t need = stride * h;
    if (!base || (size_t)outCap < need) {
        CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
        return -2;
    }
    std::memcpy(outBuf, base, need);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    if (outW) *outW = (int)w;
    if (outH) *outH = (int)h;
    if (outStride) *outStride = (int)stride;
    return 0;
}

// flush(): AOSP "all output buffers are immediately revoked at the point of
// the flush" -- drains outQ (releasing native memory), same as macapk_vtb_
// flush. libvpx exposes no explicit "reset reference frames in place" call,
// so this also destroys and reinitializes the decoder context: that is the
// only way to GUARANTEE no stale last/golden/altref reference frame survives
// the flush (an in-place "just forget the queue" would leave libvpx's
// internal reference buffers pointing at pre-flush pixels, which is wrong
// regardless of whether a real app happens to always feed a keyframe next).
void macapk_vp8_flush(void* h) {
    Vp8Decoder* d = (Vp8Decoder*)h;
    if (!d) return;
    {
        std::lock_guard<std::mutex> lk(d->mu);
        while (!d->outQ.empty()) {
            if (d->outQ.front().pb) CFRelease(d->outQ.front().pb);
            d->outQ.pop_front();
        }
    }
    if (d->ctxOk) {
        vpx_codec_destroy(&d->ctx);
        d->ctxOk = InitCtx(d, d->width, d->height);
        if (!d->ctxOk) {
            std::fprintf(stderr, "[video-vp8] flush: decoder re-init failed; "
                        "this handle will now fail every decode() call\n");
        }
    }
}

void macapk_vp8_close(void* h) {
    Vp8Decoder* d = (Vp8Decoder*)h;
    if (!d) return;
    if (d->ctxOk) vpx_codec_destroy(&d->ctx);
    {
        std::lock_guard<std::mutex> lk(d->mu);
        while (!d->outQ.empty()) {
            if (d->outQ.front().pb) CFRelease(d->outQ.front().pb);
            d->outQ.pop_front();
        }
    }
    delete d;
}

int macapk_vp8_width(void* h)  { Vp8Decoder* d = (Vp8Decoder*)h; return d ? d->width  : 0; }
int macapk_vp8_height(void* h) { Vp8Decoder* d = (Vp8Decoder*)h; return d ? d->height : 0; }

}  // extern "C"

// ---------------------------------------------------------------------------
// JNI surface (com.macapk.loader.NativeMedia's video-side native methods,
// the VP8-specific slice). Not registered from this file -- see the wiring
// note at the very bottom. No JNIEXPORT/JNICALL decoration, matching video_
// toolbox.mm's / media_decode.mm's style in this same package (never auto-
// resolved; only ever reached through an explicit RegisterNatives call).
//
// Only open/decode/poll/flush/close get NEW native methods here.
// render/releaseFrame/frameBgra are deliberately NOT duplicated: a VP8-
// decoded frame is a CVPixelBufferRef of the exact same shape a VideoToolbox
// -decoded frame is, so the EXISTING nativeVidRender/nativeVidReleaseFrame/
// nativeVidFrameBgra (video_toolbox.mm, already registered) work unchanged
// on a VP8 frame handle. That is the entire point of matching the engine
// contract: the sibling lane's MediaCodec.java only needs to branch on mime
// for the FIVE calls below, not all eight.
// ---------------------------------------------------------------------------

extern "C" {

jlong Java_com_macapk_loader_NativeMedia_nativeVp8Open(JNIEnv* env, jclass, jstring jmime,
                                                        jint width, jint height,
                                                        jbyteArray jcsd0, jbyteArray jcsd1,
                                                        jboolean wantSurface) {
    if (!jmime) return 0;
    const char* mime = env->GetStringUTFChars(jmime, nullptr);
    // csd is read for call-shape parity with nativeVidOpen even though VP8
    // never uses it (see the file header) -- so a caller that always passes
    // whatever csd it has on hand (null for VP8 in practice) needs no
    // special-casing at the call site either.
    std::string csd0, csd1;
    if (jcsd0) {
        jsize n = env->GetArrayLength(jcsd0);
        csd0.resize((size_t)n);
        if (n > 0) env->GetByteArrayRegion(jcsd0, 0, n, (jbyte*)csd0.data());
    }
    if (jcsd1) {
        jsize n = env->GetArrayLength(jcsd1);
        csd1.resize((size_t)n);
        if (n > 0) env->GetByteArrayRegion(jcsd1, 0, n, (jbyte*)csd1.data());
    }
    int hw = 0;
    void* h = macapk_vp8_open(mime, width, height,
                              csd0.empty() ? nullptr : (const uint8_t*)csd0.data(), (int)csd0.size(),
                              csd1.empty() ? nullptr : (const uint8_t*)csd1.data(), (int)csd1.size(),
                              wantSurface ? 1 : 0, &hw);
    env->ReleaseStringUTFChars(jmime, mime);
    return (jlong)(uintptr_t)h;
}

jint Java_com_macapk_loader_NativeMedia_nativeVp8Decode(JNIEnv* env, jclass, jlong h,
                                                         jbyteArray jau, jlong ptsUs, jboolean eos) {
    std::string au;
    if (jau) {
        jsize n = env->GetArrayLength(jau);
        au.resize((size_t)n);
        if (n > 0) env->GetByteArrayRegion(jau, 0, n, (jbyte*)au.data());
    }
    return macapk_vp8_decode((void*)(uintptr_t)h, au.empty() ? nullptr : (const uint8_t*)au.data(),
                             (int)au.size(), ptsUs, eos ? 1 : 0);
}

jlongArray Java_com_macapk_loader_NativeMedia_nativeVp8Poll(JNIEnv* env, jclass, jlong h) {
    void* pb = nullptr;
    int64_t pts = 0;
    int flags = 0;
    int got = macapk_vp8_poll((void*)(uintptr_t)h, &pb, &pts, &flags);
    if (got <= 0) return nullptr;
    jlongArray arr = env->NewLongArray(3);
    jlong vals[3] = { (jlong)(uintptr_t)pb, (jlong)pts, (jlong)flags };
    env->SetLongArrayRegion(arr, 0, 3, vals);
    return arr;
}

void Java_com_macapk_loader_NativeMedia_nativeVp8Flush(JNIEnv*, jclass, jlong h) {
    macapk_vp8_flush((void*)(uintptr_t)h);
}

void Java_com_macapk_loader_NativeMedia_nativeVp8Close(JNIEnv*, jclass, jlong h) {
    macapk_vp8_close((void*)(uintptr_t)h);
}

}  // extern "C"

namespace macapk { namespace video_vp8 {

static const JNINativeMethod kNativeVp8Methods[] = {
    {(char*)"nativeVp8Open",   (char*)"(Ljava/lang/String;II[B[BZ)J",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp8Open},
    {(char*)"nativeVp8Decode", (char*)"(J[BJZ)I",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp8Decode},
    {(char*)"nativeVp8Poll",   (char*)"(J)[J",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp8Poll},
    {(char*)"nativeVp8Flush",  (char*)"(J)V",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp8Flush},
    {(char*)"nativeVp8Close",  (char*)"(J)V",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp8Close},
};

// Ready to wire in, not yet called from anywhere (see the wiring note
// below) -- native_methods.cpp is a shared registration point other
// concurrent lanes also touch, so it is deliberately left out of this
// file's ownership rather than risking a collision. Callable exactly like
// video::RegisterNativeVideoMethods once that one line is added.
void RegisterNativeVp8Methods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/NativeMedia");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(NativeMedia) failed (vp8)\n");
        env->ExceptionClear();
        return;
    }
    int count = sizeof(kNativeVp8Methods) / sizeof(kNativeVp8Methods[0]);
    if (env->RegisterNatives(cls, kNativeVp8Methods, count) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(NativeMedia vp8) failed\n");
        env->ExceptionClear();
    } else {
        std::fprintf(stderr, "[I] NativeMedia: registered %d VP8 methods (libvpx)\n", count);
    }
    env->DeleteLocalRef(cls);
}

}}  // namespace macapk::video_vp8

// ---------------------------------------------------------------------------
// WIRING -- STATUS AS OF 2026-08-17 (was "WIRING STILL NEEDED" when this
// file shipped at v1.0.984; updated in place rather than left to rot, per
// this project's stale-comment lessons -- see MediaCodecList.java's own
// 2026-08-17 correction for what happens when a note like this one is not
// revisited).
//
// 1. runtime/src/native_methods.cpp -- DONE (2026-08-17, the VP9 session).
//    The forward decl + RegisterAllNativeMethods call this section used to
//    specify were STILL MISSING when that session started -- confirmed by
//    grepping this file for "vp8" (zero hits) before the fix -- meaning
//    every VP8 open() call had been hitting UnsatisfiedLinkError (caught by
//    safeVp8Open's LinkageError guard, below) since v1.0.984 shipped. Now
//    landed, alongside the identical registration for video_vp9_decode.mm.
//
// 2. runtime/java/com/macapk/loader/NativeMedia.java -- DONE (v1.0.986):
//    nativeVp8Open/_Decode/_Poll/_Flush/_Close are real declarations there
//    now, exactly the shape this section used to specify.
//
// 3. runtime/java/android/media/MediaCodec.java -- DONE (v1.0.986): isVp8(),
//    MIME_VP8, isVideoMimeSupported's VP8 branch, safeVp8Open(), and the
//    dispatch ternary at every call site (open/decode/poll/flush/close) are
//    all real, matching this section's original sketch closely (safeVp8Open
//    additionally catches LinkageError, anticipating item 1's gap before it
//    was known to be live -- see that method's own doc).
//
// 4. MediaCodecList advertising -- DONE (2026-08-17), but NOT via the path
//    this section originally sketched (editing video_toolbox.mm's
//    nativeVideoSupportedMimes()/nativeVideoIsHardware() to special-case
//    kVp8Mime). That file is a concurrently-owned, frequently-touched
//    lane boundary in this project's fan-out model, and folding a
//    statically-linked-therefore-unconditional fact into a function whose
//    whole contract is "answers from a live per-host VideoToolbox probe"
//    would have made that contract a lie for two mimes. Instead:
//    runtime/java/android/media/MediaCodecList.java gained a SEPARATE
//    HostCodecProvider, LibvpxDecoders, registered alongside
//    VideoToolboxDecoders -- same registry, same seam, zero edits to
//    video_toolbox.mm. See that provider's own doc comment.
// ---------------------------------------------------------------------------
