// video_vp9_decode.mm -- real VP9 VIDEO decode backend for android.media.
// MediaCodec, backed by libvpx (BSD-3-Clause, WebM project), software-only.
//
// WHY THIS FILE EXISTS INSTEAD OF EXTENDING video_toolbox.mm.
// video_toolbox.mm's own header states the finding this file answers:
// VP9/AV1 were probed on this host (Apple M2, macOS 26.5.2) and BOTH come
// back OSStatus -12906 (kVTCouldNotFindVideoDecoderErr) even when fed a
// real, byte-verified config record -- see docs/videotoolbox-probe-audit_
// 2026-08-16.md section 3. -12906 means "no decoder component registered
// at all", the diagnostic signature of genuine absence, not the "config was
// inadequate" probe bug HEVC/MPEG-4 Part 2 turned out to be (their -12909
// flipped to noErr once given real parameter sets; VP9/AV1's -12906 did not
// budge). So rung 1 of CLAUDE.md's decision ladder (route to macOS native)
// is exhausted for VP9, honestly. This file is rung 2: libvpx is a clean,
// permissively-licensed (BSD-3) third-party decoder -- the SAME static
// archive video_vp8_decode.mm (v1.0.984) already links into this exact
// target, so this is not a new dependency, only a new source file plus one
// new CMakeLists.txt line reusing an existing link.
//
// WHY YOUTUBE CARES: YouTube's DASH manifests have served VP9 as the
// standard adaptive-bitrate video codec since ~2016 -- broader coverage
// across resolutions and videos than AV1, which YouTube reserves more
// selectively (see this session's docs/vp9-av1-decision_2026-08-17.md for
// the specific evidence from this task). Landing VP9 is therefore the
// single highest-value codec gap for "does a YouTube video actually play".
//
// ENGINE CONTRACT -- matches video_toolbox.mm's macapk_vtb_* shape AND
// video_vp8_decode.mm's macapk_vp8_* shape on purpose (open/decode/poll/
// render/release/frame_copy_bgra/flush/close/width/height), so a caller
// does not need a third calling convention, only a third function to call.
// Concretely, this file is close to a structural clone of video_vp8_decode
// .mm with three substantive differences, each cited below at its site:
//   1. vpx_codec_vp9_dx() instead of vpx_codec_vp8_dx() (same header,
//      vpx/vp8dx.h -- verified locally: "WebM VP8/VP9 Decoder", both
//      interfaces declared in the one file).
//   2. VP9 CAN carry an optional csd-0 (AOSP's own CSD table, see below);
//      VP8 has NO row in that table at all. Still safe to accept-but-ignore
//      for the same reason VP8 is: libvpx's own bitstream parser reads
//      width/height/profile/bit-depth/color-config directly out of each
//      frame's uncompressed header, so no out-of-band config is REQUIRED to
//      decode correctly, and AOSP marks the VP9 row "(optional)" for
//      exactly that reason.
//   3. VP9 profiles 1-3 can emit 4:2:2/4:4:4 chroma or 10/12-bit samples
//      (VPX_IMG_FMT_I422/I444/I440 and their *16 high-bitdepth variants,
//      vpx/vpx_image.h). This file decodes profile 0 (8-bit, 4:2:0, I420)
//      -- the overwhelming majority of real-world VP9 web content,
//      including YouTube SDR up to 4K -- and, matching this project's "no
//      comfortable lies" rule, LOGS AND SKIPS any frame libvpx hands back
//      in a different format rather than reinterpreting its bytes as I420
//      (which would silently corrupt colour/geometry). See the format
//      check in macapk_vp9_decode below. HDR (profile 2, 10-bit 4:2:0) is
//      a named, not a hidden, gap.
//   * macapk_vp9_render_frame calls the SAME CocoaPresentVideoFrame
//     (cocoa_bridge.mm) entry point video_toolbox.mm's and video_vp8_decode
//     .mm's render functions call -- one present path for every engine.
//   * macapk_vp9_release_frame / macapk_vp9_frame_copy_bgra are the same
//     trivial generic CoreVideo operations video_vp8_decode.mm reimplements
//     locally (not shared via a header) -- see that file's header for why:
//     independent buildability/linkability, no build-order dependency on a
//     concurrently-owned file. Same reasoning applies here.
//
// CODEC-SPECIFIC DATA (verified, not assumed -- AOSP frameworks/base media/
// java/android/media/MediaCodec.java class javadoc, the "Codec-specific
// Data" table, fetched 2026-08-17 from
// raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/master/
// media/java/android/media/MediaCodec.java, lines ~495-510 at fetch time):
//   | Format | CSD buffer #0                                  |
//   | VP9    | VP9 CodecPrivate Data (optional)                |
//   | AV1    | AV1 AV1CodecConfigurationRecord Data (optional) |
// -- both marked "(optional)", unlike AAC/MPEG-4/H.264/H.265 (mandatory,
// unmarked) or VP8 (no row at all: no CSD concept exists for it). The VP9
// CodecPrivate format (http://wiki.webmproject.org/vp9-codecprivate) is a
// small profile/level/bit-depth/chroma-subsampling/colour descriptor,
// distinct from the ISOBMFF "vpcC" box a real MP4 demuxer would also
// produce, but this file needs neither: see point 2 above. csd0/csd1
// parameters below exist only for call-shape parity with macapk_vtb_open
// and macapk_vp8_open, and are accepted-but-unused, exactly like VP8's.
//
// MID-STREAM RESOLUTION CHANGE: AOSP's own javadoc ("For decoders that
// support and are configured for adaptive playback") names VP8 and VP9
// together as the two non-AVC/HEVC formats that support changing picture
// size mid-stream by feeding the new keyframe as a plain (non-CSD-flagged)
// input buffer. This file's macapk_vp9_decode already handles that for
// free, the same way video_vp8_decode.mm's does: width/height are re-read
// from EVERY decoded frame's vpx_image_t::d_w/d_h, not cached from open().
//
// CITATIONS (verified against this machine's Homebrew libvpx 1.16.0, same
// package + pin-to-local-headers convention as video_vp8_decode.mm):
//   vpx/vpx_decoder.h -- vpx_codec_dec_init/_decode/_get_frame, the
//     iterator contract, vpx_codec_dec_cfg_t. Identical API surface VP8
//     uses; VP9 is a sibling algorithm behind the same vpx_codec_ctx_t.
//   vpx/vp8dx.h       -- vpx_codec_vp9_dx() (declared in this file despite
//     its VP8-suggesting name -- the header's own \defgroup says "WebM
//     VP8/VP9 Decoder"; confirmed via `nm` on this machine's libvpx.a that
//     _vpx_codec_vp9_dx is a real defined symbol in the same archive VP8
//     links, vp9_dx_iface.c.o).
//   vpx/vpx_image.h   -- VPX_IMG_FMT_I420/I422/I444/I440 and their
//     VPX_IMG_FMT_HIGHBITDEPTH (0x800) variants -- the profile-dependent
//     output shapes point 3 above guards against.
//   vpx/vpx_codec.h   -- vpx_codec_ctx_t/_err_t/_err_to_string/_destroy.
// YUV -> RGB matrix: same CoeffsFor table video_vp8_decode.mm verified
// against Chromium's libyuv (source/row_common.cc, BSD-3) -- VP9 signals
// colour space/range explicitly more often than VP8 (its uncompressed
// header carries a real color_config section per the VP9 bitstream spec),
// but VPX_CS_UNKNOWN still falls back to the same BT.601 studio default,
// and VPX_CS_BT_2020 (wide-gamut, paired with high-bitdepth in practice) is
// not in the table -- a named simplification, not a silent one: BT.2020
// content only reaches this file if it were also 8-bit 4:2:0 I420, which
// the VP9 spec does not produce (BT.2020 is profile 2/3 territory, already
// excluded by point 3 above), so the gap is currently unreachable rather
// than merely undocumented.
//
// Refs: video_vp8_decode.mm (the sibling engine this file's contract and
// most of its implementation mirrors), docs/videotoolbox-probe-audit_2026-
// 08-16.md (the VP9/AV1-on-this-host finding), docs/vp9-av1-decision_2026-
// 08-17.md (this session's YouTube-reachability evidence + the AV1/dav1d
// assessment).

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
// and video_vp8_decode.mm call (see the file header). Declared extern here
// rather than pulled from a shared header, matching both siblings'
// forward-declare-across-.mm-files convention.
extern "C" void CocoaPresentVideoFrame(void* pixbuf, int width, int height);

namespace {

const char* const kVp9Mime = "video/x-vnd.on2.vp9";  // AOSP MediaFormat.MIMETYPE_VIDEO_VP9

// MediaCodec.BUFFER_FLAG_END_OF_STREAM, mirrored the same un-imported way
// video_toolbox.mm's kFlagEndOfStream and video_vp8_decode.mm's are.
constexpr int kFlagEndOfStream = 4;

inline uint8_t Clamp255(float v) {
    if (v < 0.0f) return 0;
    if (v > 255.0f) return 255;
    return (uint8_t)(v + 0.5f);
}

// YUV -> RGB conversion coefficients -- byte-for-byte the same table
// video_vp8_decode.mm verified against Chromium's libyuv (source/
// row_common.cc, BSD-3): kYuvI601Constants/kYuvJPEGConstants/
// kYuvH709Constants/kYuvF709Constants. See this file's header for why
// VPX_CS_BT_2020 is not (and cannot currently be) reached here.
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
    return full ? kBt601Full : kBt601Studio;  // also the VPX_CS_UNKNOWN / VPX_CS_BT_2020 fallback
}

// Same shape as video_vp8_decode.mm's CreateBgraPixelBuffer -- see that
// file's comment for why the IOSurface-properties key is load-bearing
// (CVMetalTextureCacheCreateTextureFromImage silently fails without it).
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
            std::fprintf(stderr, "[video-vp9] CVPixelBufferCreate(%dx%d) failed: %d\n",
                        width, height, (int)r);
            return nullptr;
        }
        return pb;
    }
}

// Converts a decoded 8-bit I420 vpx_image_t into an already-allocated BGRA
// CVPixelBufferRef of the SAME (d_w, d_h) dimensions. Uses img->d_w/d_h
// (the bitstream-signaled DISPLAY size) rather than img->w/h (the
// macroblock-aligned STORAGE size) -- same reasoning as video_vp8_decode
// .mm's I420ToBgraInto, which this is a straight copy of (VP9's I420
// output is byte-for-byte the same planar layout VP8 produces; only the
// bitstream that got us here differs). Caller (macapk_vp9_decode) has
// already verified img->fmt == VPX_IMG_FMT_I420 before calling this.
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
            // kCVPixelFormatType_32BGRA byte order: B, G, R, A -- matches
            // video_toolbox.mm's and video_vp8_decode.mm's destination.
            uint8_t* px = dstRow + col * 4;
            px[0] = Clamp255(b);
            px[1] = Clamp255(g);
            px[2] = Clamp255(r);
            px[3] = 255;
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
}

struct Vp9Decoder {
    vpx_codec_ctx_t ctx;
    bool ctxOk = false;
    int width = 0, height = 0;   // last known DISPLAY dims; 0 until the first keyframe decodes

    // Same reasoning as video_vp8_decode.mm's Vp8Decoder: vpx_codec_decode()
    // is synchronous single-threaded (cfg.threads=1 below) and
    // vpx_codec_get_frame() drains everything produced before decode()
    // returns, so outQ only ever holds fully-decoded frames -- no
    // generation counter needed the way VtDecoder's async callback path
    // needs one.
    std::mutex mu;
    struct OutFrame { CVPixelBufferRef pb; int64_t ptsUs; int flags; };
    std::deque<OutFrame> outQ;
};

bool InitCtx(Vp9Decoder* d, int widthHint, int heightHint) {
    vpx_codec_dec_cfg_t cfg = {};
    cfg.threads = 1;
    cfg.w = widthHint > 0 ? (unsigned)widthHint : 0;
    cfg.h = heightHint > 0 ? (unsigned)heightHint : 0;
    vpx_codec_err_t e = vpx_codec_dec_init(&d->ctx, vpx_codec_vp9_dx(), &cfg, 0);
    if (e != VPX_CODEC_OK) {
        std::fprintf(stderr, "[video-vp9] vpx_codec_dec_init failed: %s\n",
                    vpx_codec_err_to_string(e));
        return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// C ABI (macapk_vp9_*), mirroring video_toolbox.mm's macapk_vtb_* and
// video_vp8_decode.mm's macapk_vp8_* naming and signatures.
// ---------------------------------------------------------------------------

extern "C" {

// Always 1 for the VP9 mime (libvpx is statically linked in, always
// present), 0 for anything else. *outHw is always 0: software-only decode,
// reported honestly (same contract as macapk_vp8_probe_mime).
int macapk_vp9_probe_mime(const char* mimeC, int* outHw) {
    if (outHw) *outHw = 0;
    std::string mime = mimeC ? mimeC : "";
    return mime == kVp9Mime ? 1 : 0;
}

// csd0/csd0Len/csd1/csd1Len are accepted for call-shape parity but unused --
// VP9's csd-0 (WebM CodecPrivate) is optional per AOSP's own CSD table and
// unnecessary for decode (see the file header, point 2). width/height are
// hints from the app's MediaFormat; the authoritative size comes from the
// first decoded keyframe's vpx_image_t::d_w/d_h (macapk_vp9_width/_height
// report whichever is known so far), exactly as VP8's open() documents.
void* macapk_vp9_open(const char* mimeC, int width, int height,
                      const uint8_t* /*csd0*/, int /*csd0Len*/,
                      const uint8_t* /*csd1*/, int /*csd1Len*/,
                      int /*wantSurface*/, int* outHw) {
    std::string mime = mimeC ? mimeC : "";
    if (mime != kVp9Mime) {
        std::fprintf(stderr, "[video-vp9] open: unsupported mime '%s' (this engine only "
                    "handles %s)\n", mime.c_str(), kVp9Mime);
        return nullptr;
    }
    Vp9Decoder* d = new Vp9Decoder();
    if (!InitCtx(d, width, height)) {
        delete d;
        return nullptr;
    }
    d->ctxOk = true;
    d->width  = width  > 0 ? width  : 0;
    d->height = height > 0 ? height : 0;
    if (outHw) *outHw = 0;
    std::fprintf(stderr, "[video-vp9] open: mime=%s %dx%d (hint; confirmed at first "
                "keyframe) hw=no (software libvpx)\n", mime.c_str(), d->width, d->height);
    return d;
}

// Feeds one complete VP9 access unit. A VP9 "superframe" (multiple coded
// frames -- typically a hidden alt-ref plus a show_existing_frame reference
// to it -- packed behind one trailing superframe index) is still exactly
// ONE access unit per the container conventions MediaCodec.queueInputBuffer
// receives from (ISOBMFF/WebM demux one sample per call); libvpx's VP9
// decoder parses the superframe index internally and vpx_codec_get_frame's
// iterator yields however many SHOWABLE frames resulted, so no special
// handling is needed here beyond the same decode-then-drain loop VP8 uses.
int macapk_vp9_decode(void* h, const uint8_t* au, int auLen, int64_t ptsUs, int eos) {
    Vp9Decoder* d = (Vp9Decoder*)h;
    if (!d || !d->ctxOk) return -1;
    if (au && auLen > 0) {
        vpx_codec_err_t e = vpx_codec_decode(&d->ctx, au, (unsigned int)auLen, nullptr, 0);
        if (e != VPX_CODEC_OK) {
            // AOSP/MediaCodec's contract for a bad access unit is to keep
            // the session alive (matching video_vp8_decode.mm's identical
            // reasoning) -- log and continue rather than tear down.
            const char* detail = vpx_codec_error_detail(&d->ctx);
            std::fprintf(stderr, "[video-vp9] decode: vpx_codec_decode failed: %s (%s)\n",
                        vpx_codec_err_to_string(e), detail ? detail : "no detail");
        } else {
            vpx_codec_iter_t iter = nullptr;
            const vpx_image_t* img;
            while ((img = vpx_codec_get_frame(&d->ctx, &iter)) != nullptr) {
                // Profile 0 (8-bit 4:2:0) only -- see the file header, point
                // 3. VP9 profiles 1-3 (4:2:2/4:4:4 chroma, or 10/12-bit via
                // VPX_IMG_FMT_HIGHBITDEPTH) are LOGGED AND SKIPPED rather
                // than reinterpreted as I420, which would silently corrupt
                // colour and geometry -- a named gap, not a hidden one, per
                // this project's no-comfortable-lies rule.
                if (img->fmt != VPX_IMG_FMT_I420) {
                    std::fprintf(stderr, "[video-vp9] decode: unsupported image format 0x%x "
                                "(this engine decodes VP9 profile 0 / I420 only -- "
                                "profiles 1-3 [4:2:2, 4:4:4, 10/12-bit] are a known gap); "
                                "dropping frame\n", (unsigned)img->fmt);
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

// Pops the oldest ready frame. Same contract as macapk_vp8_poll /
// macapk_vtb_poll: 1 + out-params filled if one was available, 0 if the
// queue is empty (TRY_AGAIN), -1 if `h` is invalid.
int macapk_vp9_poll(void* h, void** outPixbuf, int64_t* outPtsUs, int* outFlags) {
    Vp9Decoder* d = (Vp9Decoder*)h;
    if (!d) return -1;
    std::lock_guard<std::mutex> lk(d->mu);
    if (d->outQ.empty()) return 0;
    Vp9Decoder::OutFrame f = d->outQ.front();
    d->outQ.pop_front();
    if (outPixbuf) *outPixbuf = f.pb;
    if (outPtsUs)  *outPtsUs  = f.ptsUs;
    if (outFlags)  *outFlags  = f.flags;
    return 1;
}

// releaseOutputBuffer(index, render=true): delegates to the SAME
// CocoaPresentVideoFrame video_toolbox.mm's and video_vp8_decode.mm's
// render functions call -- one present path for every engine (see header).
void macapk_vp9_render_frame(void* pixbuf, int width, int height) {
    if (!pixbuf) return;
    CocoaPresentVideoFrame(pixbuf, width, height);
}

// releaseOutputBuffer(index, render=false), or post-render cleanup. MUST be
// called exactly once per frame macapk_vp9_poll ever returned.
void macapk_vp9_release_frame(void* pixbuf) {
    if (pixbuf) CFRelease((CVPixelBufferRef)pixbuf);
}

// Best-effort raw-pixel readout for the no-Surface decode path (MediaCodec.
// getOutputImage), byte-for-byte the same operation as macapk_vp8_frame_
// copy_bgra / macapk_vtb_frame_copy_bgra.
int macapk_vp9_frame_copy_bgra(void* pixbuf, uint8_t* outBuf, int outCap,
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

// flush(): drains outQ and destroys+reinitializes the decoder context, same
// reasoning as macapk_vp8_flush (libvpx exposes no in-place "forget
// reference frames" call, so reinit is the only way to guarantee no stale
// last/golden/altref frame survives).
void macapk_vp9_flush(void* h) {
    Vp9Decoder* d = (Vp9Decoder*)h;
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
            std::fprintf(stderr, "[video-vp9] flush: decoder re-init failed; "
                        "this handle will now fail every decode() call\n");
        }
    }
}

void macapk_vp9_close(void* h) {
    Vp9Decoder* d = (Vp9Decoder*)h;
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

int macapk_vp9_width(void* h)  { Vp9Decoder* d = (Vp9Decoder*)h; return d ? d->width  : 0; }
int macapk_vp9_height(void* h) { Vp9Decoder* d = (Vp9Decoder*)h; return d ? d->height : 0; }

}  // extern "C"

// ---------------------------------------------------------------------------
// JNI surface (com.macapk.loader.NativeMedia's video-side native methods,
// the VP9-specific slice). No JNIEXPORT/JNICALL decoration, matching video_
// toolbox.mm's / video_vp8_decode.mm's style in this same package -- never
// auto-resolved, only ever reached through RegisterNativeVp9Methods below.
//
// Only open/decode/poll/flush/close get NEW native methods here.
// render/releaseFrame/frameBgra are deliberately NOT duplicated: a VP9-
// decoded frame is a CVPixelBufferRef of the exact same shape a VideoToolbox-
// or VP8-decoded frame is (see CreateBgraPixelBuffer above), so the EXISTING
// nativeVidRender/nativeVidReleaseFrame/nativeVidFrameBgra work unchanged.
// ---------------------------------------------------------------------------

extern "C" {

jlong Java_com_macapk_loader_NativeMedia_nativeVp9Open(JNIEnv* env, jclass, jstring jmime,
                                                        jint width, jint height,
                                                        jbyteArray jcsd0, jbyteArray jcsd1,
                                                        jboolean wantSurface) {
    if (!jmime) return 0;
    const char* mime = env->GetStringUTFChars(jmime, nullptr);
    // csd is read for call-shape parity with nativeVidOpen/nativeVp8Open
    // even though this engine never uses it (see the file header, point 2)
    // -- so a caller that always passes whatever csd it has on hand needs
    // no special-casing at the call site.
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
    void* h = macapk_vp9_open(mime, width, height,
                              csd0.empty() ? nullptr : (const uint8_t*)csd0.data(), (int)csd0.size(),
                              csd1.empty() ? nullptr : (const uint8_t*)csd1.data(), (int)csd1.size(),
                              wantSurface ? 1 : 0, &hw);
    env->ReleaseStringUTFChars(jmime, mime);
    return (jlong)(uintptr_t)h;
}

jint Java_com_macapk_loader_NativeMedia_nativeVp9Decode(JNIEnv* env, jclass, jlong h,
                                                         jbyteArray jau, jlong ptsUs, jboolean eos) {
    std::string au;
    if (jau) {
        jsize n = env->GetArrayLength(jau);
        au.resize((size_t)n);
        if (n > 0) env->GetByteArrayRegion(jau, 0, n, (jbyte*)au.data());
    }
    return macapk_vp9_decode((void*)(uintptr_t)h, au.empty() ? nullptr : (const uint8_t*)au.data(),
                             (int)au.size(), ptsUs, eos ? 1 : 0);
}

jlongArray Java_com_macapk_loader_NativeMedia_nativeVp9Poll(JNIEnv* env, jclass, jlong h) {
    void* pb = nullptr;
    int64_t pts = 0;
    int flags = 0;
    int got = macapk_vp9_poll((void*)(uintptr_t)h, &pb, &pts, &flags);
    if (got <= 0) return nullptr;
    jlongArray arr = env->NewLongArray(3);
    jlong vals[3] = { (jlong)(uintptr_t)pb, (jlong)pts, (jlong)flags };
    env->SetLongArrayRegion(arr, 0, 3, vals);
    return arr;
}

void Java_com_macapk_loader_NativeMedia_nativeVp9Flush(JNIEnv*, jclass, jlong h) {
    macapk_vp9_flush((void*)(uintptr_t)h);
}

void Java_com_macapk_loader_NativeMedia_nativeVp9Close(JNIEnv*, jclass, jlong h) {
    macapk_vp9_close((void*)(uintptr_t)h);
}

}  // extern "C"

namespace macapk { namespace video_vp9 {

static const JNINativeMethod kNativeVp9Methods[] = {
    {(char*)"nativeVp9Open",   (char*)"(Ljava/lang/String;II[B[BZ)J",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp9Open},
    {(char*)"nativeVp9Decode", (char*)"(J[BJZ)I",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp9Decode},
    {(char*)"nativeVp9Poll",   (char*)"(J)[J",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp9Poll},
    {(char*)"nativeVp9Flush",  (char*)"(J)V",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp9Flush},
    {(char*)"nativeVp9Close",  (char*)"(J)V",
     (void*)Java_com_macapk_loader_NativeMedia_nativeVp9Close},
};

// Called from native_methods.cpp::RegisterAllNativeMethods, right next to
// video_vp8::RegisterNativeVp8Methods -- both landed together this session
// (unlike VP8's original landing, where this call was deferred to a
// concurrently-routed change; see native_methods.cpp for the fix to VP8's
// registration too, found while wiring this one in).
void RegisterNativeVp9Methods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/NativeMedia");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(NativeMedia) failed (vp9)\n");
        env->ExceptionClear();
        return;
    }
    int count = sizeof(kNativeVp9Methods) / sizeof(kNativeVp9Methods[0]);
    if (env->RegisterNatives(cls, kNativeVp9Methods, count) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(NativeMedia vp9) failed\n");
        env->ExceptionClear();
    } else {
        std::fprintf(stderr, "[I] NativeMedia: registered %d VP9 methods (libvpx)\n", count);
    }
    env->DeleteLocalRef(cls);
}

}}  // namespace macapk::video_vp9
