// media_video.mm -- real VIDEO decode backend (item 3b): H.264/HEVC -> BGRA
// CVPixelBuffer via AVFoundation (demux) + VideoToolbox (decode), plus the
// CVPixelBuffer -> Metal texture -> CAMetalLayer present path.
//
// Pairs with the audio core (media_decode.mm, macapk_md_*). This file is the
// macapk_vd_* C core, reached by the NDK AMediaCodec video path (media_ndk.cpp)
// via dlsym(RTLD_DEFAULT) -- the same bridge macapk_md_* / macapk_audio_* use.
//
//   * Demux:  AVURLAsset -> AVAssetReader -> AVAssetReaderTrackOutput(nil) ->
//             copyNextSampleBuffer  (compressed AVCC access units, passthrough)
//   * Decode: VTDecompressionSessionCreate(track CMVideoFormatDescription, dest
//             attrs = 32BGRA + MetalCompatibility + IOSurface) ->
//             VTDecompressionSessionDecodeFrame (SYNC: decodeFlags 0, the C
//             output callback fires before DecodeFrame returns) -> CVPixelBuffer.
//   * Present (separate, gated): CVMetalTextureCacheCreateTextureFromImage ->
//             full-screen render pass into a CAMetalLayer's drawable.
//
// Contracts pinned verbatim from the local Xcode SDK headers (VTDecompressionSession.h,
// CMFormatDescription.h, CMSampleBuffer.h, CVPixelBuffer.h, CVMetalTextureCache.h,
// AVAssetReader*.h) -- see docs/video-decode-backend_2026-06-21.md.
//
// SCOPE/LIMITS (first cut): file/path input (setDataSourceFd -> temp file, like
// 3a); sync decode in DECODE order (fine for baseline/no-B-frame; B-frame
// reordering is a follow-on); video track only (audio stays on macapk_md_*).

#import <AVFoundation/AVFoundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <atomic>
#include <vector>

namespace {

struct VideoDecoder {
    AVAssetReader*            reader  = nil;
    AVAssetReaderTrackOutput* output  = nil;
    CMVideoFormatDescriptionRef fmt   = nullptr;   // owned by the track; not retained separately
    VTDecompressionSessionRef session = nullptr;
    int      width = 0, height = 0, codec = 0;      // codec: 1=H264, 2=HEVC, 0=other
    double   frameRateHint = 0;
    // The most recent decoded frame, stashed by the SYNC output callback.
    CVPixelBufferRef lastFrame = nullptr;
    int64_t  lastPtsUs = -1;
    bool     eos = false;
};

// SYNC output callback: decodeFlags==0 makes this fire before DecodeFrame returns,
// so stashing into the decoder is race-free for the pull model.
void vd_output_cb(void* refcon, void* /*srcFrameRefCon*/, OSStatus status,
                  VTDecodeInfoFlags /*flags*/, CVImageBufferRef img,
                  CMTime pts, CMTime /*dur*/) {
    VideoDecoder* d = (VideoDecoder*)refcon;
    if (status == noErr && img) {
        if (d->lastFrame) CFRelease(d->lastFrame);
        d->lastFrame = (CVPixelBufferRef)CFRetain(img);   // hold past the callback
        d->lastPtsUs = CMTIME_IS_VALID(pts)
            ? (int64_t)llround(CMTimeGetSeconds(pts) * 1.0e6) : -1;
    }
}

bool vd_make_session(VideoDecoder* d) {
    NSDictionary* destAttrs = @{
        (id)kCVPixelBufferPixelFormatTypeKey   : @(kCVPixelFormatType_32BGRA),
        (id)kCVPixelBufferMetalCompatibilityKey: @YES,
        (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    VTDecompressionOutputCallbackRecord cb = { vd_output_cb, d };
    OSStatus s = VTDecompressionSessionCreate(
        kCFAllocatorDefault, d->fmt, /*decoderSpec*/ nullptr,
        (__bridge CFDictionaryRef)destAttrs, &cb, &d->session);
    if (s != noErr || !d->session) {
        std::fprintf(stderr, "[video] VTDecompressionSessionCreate failed: %d\n", (int)s);
        return false;
    }
    return true;
}

}  // namespace

extern "C" {

void* macapk_vd_open(const char* path) {
    if (!path || !*path) return nullptr;
    @autoreleasepool {
        NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
        if (!url) return nullptr;
        AVURLAsset* asset = [AVURLAsset URLAssetWithURL:url options:nil];
        // macOS 15 deprecated the synchronous -tracksWithMediaType:; use the
        // modern async loader and block this (already-synchronous) open path
        // on a semaphore. The completion fires on AVFoundation's own internal
        // queue, not the calling thread, so the wait cannot self-deadlock.
        __block NSArray<AVAssetTrack*>* vtracks = nil;
        dispatch_semaphore_t vd_sem = dispatch_semaphore_create(0);
        [asset loadTracksWithMediaType:AVMediaTypeVideo
                     completionHandler:^(NSArray<AVAssetTrack*>* tracks,
                                         NSError* loadErr) {
            if (!loadErr) vtracks = tracks;
            dispatch_semaphore_signal(vd_sem);
        }];
        dispatch_semaphore_wait(vd_sem, DISPATCH_TIME_FOREVER);
        if (vtracks.count == 0) return nullptr;
        AVAssetTrack* track = vtracks[0];

        NSError* err = nil;
        AVAssetReader* reader = [[AVAssetReader alloc] initWithAsset:asset error:&err];
        if (!reader) { std::fprintf(stderr, "[video] AVAssetReader init failed: %s\n", err.localizedDescription.UTF8String); return nullptr; }
        // outputSettings:nil == compressed AVCC passthrough (directly VT-decodable).
        AVAssetReaderTrackOutput* out =
            [AVAssetReaderTrackOutput assetReaderTrackOutputWithTrack:track outputSettings:nil];
        out.alwaysCopiesSampleData = NO;
        if (![reader canAddOutput:out]) return nullptr;
        [reader addOutput:out];
        if (![reader startReading]) {
            std::fprintf(stderr, "[video] startReading failed: %s\n", reader.error.localizedDescription.UTF8String);
            return nullptr;
        }

        NSArray* fds = track.formatDescriptions;
        if (fds.count == 0) return nullptr;
        CMVideoFormatDescriptionRef fmt = (__bridge CMVideoFormatDescriptionRef)fds[0];

        VideoDecoder* d = new VideoDecoder();
        d->reader = reader; d->output = out;
        d->fmt = (CMVideoFormatDescriptionRef)CFRetain(fmt);
        FourCharCode sub = CMFormatDescriptionGetMediaSubType(fmt);
        d->codec = (sub == kCMVideoCodecType_H264) ? 1
                 : (sub == kCMVideoCodecType_HEVC || sub == kCMVideoCodecType_HEVCWithAlpha) ? 2 : 0;
        CMVideoDimensions dim = CMVideoFormatDescriptionGetDimensions(fmt);
        d->width = dim.width; d->height = dim.height;
        d->frameRateHint = track.nominalFrameRate;
        if (!vd_make_session(d)) { CFRelease(d->fmt); delete d; return nullptr; }
        std::fprintf(stderr, "[video] open: %dx%d codec=%s fps~%.1f\n",
                     d->width, d->height, d->codec==1?"H264":d->codec==2?"HEVC":"other", d->frameRateHint);
        return d;
    }
}

int macapk_vd_width(void* h)  { VideoDecoder* d=(VideoDecoder*)h; return d?d->width:0; }
int macapk_vd_height(void* h) { VideoDecoder* d=(VideoDecoder*)h; return d?d->height:0; }
int macapk_vd_codec(void* h)  { VideoDecoder* d=(VideoDecoder*)h; return d?d->codec:0; }

// Decode the next frame. Returns a RETAINED CVPixelBufferRef (BGRA, as void*),
// or null at EOS / error. Caller must macapk_vd_release_frame() it.
void* macapk_vd_next_frame(void* h, int64_t* outPtsUs) {
    VideoDecoder* d = (VideoDecoder*)h;
    if (!d || !d->session || d->eos) return nullptr;
    @autoreleasepool {
        for (;;) {
            CMSampleBufferRef sample = [d->output copyNextSampleBuffer];
            if (!sample) { d->eos = true; return nullptr; }   // end of range
            if (CMSampleBufferGetNumSamples(sample) == 0) { CFRelease(sample); continue; } // marker-only, skip
            if (d->lastFrame) { CFRelease(d->lastFrame); d->lastFrame = nullptr; }
            VTDecodeInfoFlags info = 0;
            OSStatus s = VTDecompressionSessionDecodeFrame(
                d->session, sample, /*decodeFlags=0 -> SYNC*/ 0, /*srcFrameRefCon*/ nullptr, &info);
            CFRelease(sample);
            if (s != noErr) { std::fprintf(stderr, "[video] DecodeFrame err %d\n", (int)s); continue; }
            if (d->lastFrame) {                 // callback delivered a frame
                if (outPtsUs) *outPtsUs = d->lastPtsUs;
                CVPixelBufferRef f = d->lastFrame;
                d->lastFrame = nullptr;          // hand ownership to the caller
                return f;
            }
            // No frame this AU (e.g. dropped/interrupted) -> try the next.
        }
    }
}

void macapk_vd_release_frame(void* pixbuf) { if (pixbuf) CFRelease((CVPixelBufferRef)pixbuf); }

void macapk_vd_close(void* h) {
    VideoDecoder* d = (VideoDecoder*)h; if (!d) return;
    if (d->lastFrame) CFRelease(d->lastFrame);
    if (d->session) { VTDecompressionSessionWaitForAsynchronousFrames(d->session); VTDecompressionSessionInvalidate(d->session); CFRelease(d->session); }
    if (d->fmt) CFRelease(d->fmt);
    d->reader = nil; d->output = nil;   // ARC releases
    delete d;
}

// --- Probe (item-3b validation): decode every frame, return the count + dims +
// codec + the mean abs luma delta between consecutive frames (proves real,
// varied content -- not a static/black no-op). Self-contained; no window/Metal.
int macapk_vd_probe(const char* path, int* outW, int* outH, int* outCodec, double* outMeanAbsDelta) {
    void* h = macapk_vd_open(path);
    if (!h) return -1;
    VideoDecoder* d = (VideoDecoder*)h;
    if (outW) *outW = d->width; if (outH) *outH = d->height; if (outCodec) *outCodec = d->codec;
    int frames = 0;
    double sumDelta = 0; long deltaSamples = 0;
    std::vector<uint8_t> prev;
    for (;;) {
        int64_t pts = -1;
        CVPixelBufferRef f = (CVPixelBufferRef)macapk_vd_next_frame(h, &pts);
        if (!f) break;
        frames++;
        CVPixelBufferLockBaseAddress(f, kCVPixelBufferLock_ReadOnly);
        size_t w = CVPixelBufferGetWidth(f), ht = CVPixelBufferGetHeight(f);
        size_t bpr = CVPixelBufferGetBytesPerRow(f);
        const uint8_t* base = (const uint8_t*)CVPixelBufferGetBaseAddress(f);
        // Sample the green channel of a coarse grid (BGRA: G at byte +1) to keep it cheap.
        std::vector<uint8_t> cur; cur.reserve(64*64);
        if (base && w && ht) {
            for (size_t y = 0; y < ht; y += (ht/64 ? ht/64 : 1))
                for (size_t x = 0; x < w; x += (w/64 ? w/64 : 1))
                    cur.push_back(base[y*bpr + x*4 + 1]);
        }
        CVPixelBufferUnlockBaseAddress(f, kCVPixelBufferLock_ReadOnly);
        macapk_vd_release_frame(f);
        if (!prev.empty() && prev.size() == cur.size()) {
            for (size_t i = 0; i < cur.size(); i++) { sumDelta += std::abs((int)cur[i] - (int)prev[i]); deltaSamples++; }
        }
        prev.swap(cur);
    }
    macapk_vd_close(h);
    if (outMeanAbsDelta) *outMeanAbsDelta = (deltaSamples > 0) ? (sumDelta / deltaSamples) : 0.0;
    return frames;
}

}  // extern "C"

// ===================== Compositing / present (CVPixelBuffer -> MTLTexture ->
// CAMetalLayer) ==============================================================
namespace {

// Full-screen-triangle blit: vertex emits a covering triangle (no vertex
// buffer); fragment samples the decoded BGRA texture. Y is flipped in the
// vertex UV so VideoToolbox's top-left-origin frame lands upright. A render
// pass (not a blit) so arbitrary decoded WxH scales onto the target.
static const char* kBlitMSL = R"MSL(
#include <metal_stdlib>
using namespace metal;
struct VOut { float4 pos [[position]]; float2 uv; };
vertex VOut macapk_vd_vmain(uint vid [[vertex_id]]) {
    float2 p[3] = { float2(-1.0,-1.0), float2(3.0,-1.0), float2(-1.0,3.0) };
    VOut o; o.pos = float4(p[vid], 0.0, 1.0);
    o.uv = float2((p[vid].x + 1.0) * 0.5, 1.0 - (p[vid].y + 1.0) * 0.5);
    return o;
}
fragment float4 macapk_vd_fmain(VOut in [[stage_in]], texture2d<float> tex [[texture(0)]]) {
    constexpr sampler s(filter::linear, address::clamp_to_edge);
    return tex.sample(s, in.uv);
}
)MSL";

struct VideoPresenter {
    id<MTLDevice>              device   = nil;
    id<MTLCommandQueue>        queue    = nil;
    id<MTLRenderPipelineState> pso      = nil;   // BGRA8Unorm color target
    CVMetalTextureCacheRef     cache    = nullptr;
};

// Build a presenter for a given MTLDevice (pipeline color format BGRA8Unorm,
// matching both a CAMetalLayer drawable and our offscreen test texture).
static VideoPresenter* vd_presenter_create(id<MTLDevice> dev) {
    if (!dev) return nullptr;
    VideoPresenter* p = new VideoPresenter();
    p->device = dev;
    p->queue  = [dev newCommandQueue];
    NSError* err = nil;
    id<MTLLibrary> lib = [dev newLibraryWithSource:[NSString stringWithUTF8String:kBlitMSL]
                                           options:nil error:&err];
    if (!lib) { std::fprintf(stderr, "[video] blit MSL compile failed: %s\n", err.localizedDescription.UTF8String); delete p; return nullptr; }
    MTLRenderPipelineDescriptor* rpd = [[MTLRenderPipelineDescriptor alloc] init];
    rpd.vertexFunction   = [lib newFunctionWithName:@"macapk_vd_vmain"];
    rpd.fragmentFunction = [lib newFunctionWithName:@"macapk_vd_fmain"];
    rpd.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    p->pso = [dev newRenderPipelineStateWithDescriptor:rpd error:&err];
    if (!p->pso) { std::fprintf(stderr, "[video] blit PSO failed: %s\n", err.localizedDescription.UTF8String); delete p; return nullptr; }
    CVReturn r = CVMetalTextureCacheCreate(kCFAllocatorDefault, nullptr, dev, nullptr, &p->cache);
    if (r != kCVReturnSuccess || !p->cache) { std::fprintf(stderr, "[video] CVMetalTextureCacheCreate failed: %d\n", (int)r); delete p; return nullptr; }
    return p;
}

// Encode the decoded frame -> a render pass into `dst`. Holds the CVPixelBuffer +
// the CVMetalTexture alive until the GPU completes (per the CVMetalTexture retain
// contract). Returns false if the source texture couldn't be bound.
static bool vd_encode_blit(VideoPresenter* p, CVPixelBufferRef pb,
                           id<MTLTexture> dst, id<MTLCommandBuffer> cb) {
    CVMetalTextureRef cvtex = nullptr;
    CVReturn r = CVMetalTextureCacheCreateTextureFromImage(
        kCFAllocatorDefault, p->cache, pb, nullptr, MTLPixelFormatBGRA8Unorm,
        CVPixelBufferGetWidth(pb), CVPixelBufferGetHeight(pb), 0, &cvtex);
    if (r != kCVReturnSuccess || !cvtex) return false;
    id<MTLTexture> src = CVMetalTextureGetTexture(cvtex);
    if (!src) { CFRelease(cvtex); return false; }
    MTLRenderPassDescriptor* rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture     = dst;
    rp.colorAttachments[0].loadAction  = MTLLoadActionDontCare;   // we cover every texel
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rp];
    [enc setRenderPipelineState:p->pso];
    [enc setFragmentTexture:src atIndex:0];
    [enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    [enc endEncoding];
    CVPixelBufferRef pbHold = (CVPixelBufferRef)CFRetain(pb);
    [cb addCompletedHandler:^(id<MTLCommandBuffer>) { CFRelease(cvtex); CFRelease(pbHold); }];
    return true;
}

}  // namespace

extern "C" {

// Create a presenter bound to a MTLDevice (void* = id<MTLDevice>); pass null to
// use the system default device. Returns a VideoPresenter* (void*) or null.
void* macapk_vd_present_create(void* mtlDevice) {
    @autoreleasepool {
        id<MTLDevice> dev = mtlDevice ? (__bridge id<MTLDevice>)mtlDevice : MTLCreateSystemDefaultDevice();
        return vd_presenter_create(dev);
    }
}
void macapk_vd_present_destroy(void* presenter) {
    VideoPresenter* p = (VideoPresenter*)presenter; if (!p) return;
    if (p->cache) CFRelease(p->cache);
    p->device = nil; p->queue = nil; p->pso = nil;
    delete p;
}

// Present a decoded CVPixelBuffer onto a CAMetalLayer (void* = CAMetalLayer*).
// Acquires nextDrawable, renders the frame, presents, commits. Returns 0 on
// success, -1 if the drawable/texture was unavailable (skip frame, never crash).
int macapk_vd_present_to_layer(void* presenter, void* caMetalLayer, void* pixbuf) {
    VideoPresenter* p = (VideoPresenter*)presenter;
    CAMetalLayer* layer = (__bridge CAMetalLayer*)caMetalLayer;
    CVPixelBufferRef pb = (CVPixelBufferRef)pixbuf;
    static std::atomic<int> dbg{0};
    int cnt = dbg.fetch_add(1);
    bool log = cnt < 6;
    if (!p || !layer || !pb) { if (log) std::fprintf(stderr, "[video] present: null arg p=%p layer=%p pb=%p\n", presenter, caMetalLayer, pixbuf); return -1; }
    @autoreleasepool {
        if (!layer.device) layer.device = p->device;
        id<CAMetalDrawable> drawable = [layer nextDrawable];
        if (!drawable) { if (log) std::fprintf(stderr, "[video] present: nextDrawable nil (dev=%p dsz=%gx%g)\n", (void*)layer.device, layer.drawableSize.width, layer.drawableSize.height); return -1; }
        id<MTLCommandBuffer> cb = [p->queue commandBuffer];
        if (!vd_encode_blit(p, pb, drawable.texture, cb)) { if (log) std::fprintf(stderr, "[video] present: encode_blit failed\n"); return -1; }
        [cb presentDrawable:drawable];
        [cb commit];
        CVMetalTextureCacheFlush(p->cache, 0);
        if (log) std::fprintf(stderr, "[video] present: OK #%d (%zux%zu -> drawable %gx%g)\n", cnt, CVPixelBufferGetWidth(pb), CVPixelBufferGetHeight(pb), layer.drawableSize.width, layer.drawableSize.height);
        return 0;
    }
}

// Render a decoded frame into an offscreen BGRA texture and read back the mean
// luma (item-3b compositing validation, no window). Returns mean luma (0..255),
// or -1 on failure. Proves the CVMetalTextureCache + render-pass pipeline emits
// the decoded pixels.
double macapk_vd_selftest_compositing(const char* path) {
    @autoreleasepool {
        void* h = macapk_vd_open(path);
        if (!h) return -1;
        int64_t pts = -1;
        CVPixelBufferRef f = (CVPixelBufferRef)macapk_vd_next_frame(h, &pts);
        if (!f) { macapk_vd_close(h); return -1; }
        int w = (int)CVPixelBufferGetWidth(f), ht = (int)CVPixelBufferGetHeight(f);
        VideoPresenter* p = vd_presenter_create(MTLCreateSystemDefaultDevice());
        if (!p) { macapk_vd_release_frame(f); macapk_vd_close(h); return -1; }
        MTLTextureDescriptor* td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                                                                     width:w height:ht mipmapped:NO];
        td.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
        id<MTLTexture> dst = [p->device newTextureWithDescriptor:td];
        id<MTLCommandBuffer> cb = [p->queue commandBuffer];
        bool ok = vd_encode_blit(p, f, dst, cb);
        [cb commit];
        [cb waitUntilCompleted];
        double meanLuma = -1;
        if (ok) {
            std::vector<uint8_t> px((size_t)w * ht * 4);
            [dst getBytes:px.data() bytesPerRow:(NSUInteger)w * 4
               fromRegion:MTLRegionMake2D(0, 0, w, ht) mipmapLevel:0];
            double sum = 0;
            for (int i = 0; i < w * ht; i++) {
                // BGRA -> luma ~ 0.114B + 0.587G + 0.299R
                sum += 0.114 * px[i*4+0] + 0.587 * px[i*4+1] + 0.299 * px[i*4+2];
            }
            meanLuma = sum / (w * ht);
        }
        macapk_vd_release_frame(f);
        macapk_vd_present_destroy(p);
        macapk_vd_close(h);
        std::fprintf(stderr, "[video] compositing self-test %s: %dx%d meanLuma=%.1f -> %s\n",
                     path, w, ht, meanLuma, (meanLuma > 0) ? "PASS" : "FAIL");
        return meanLuma;
    }
}

}  // extern "C"
