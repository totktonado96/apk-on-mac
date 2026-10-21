// video_caps_probe.mm -- the HOST-PROBED MediaCodecInfo profile/level table
// for the VideoToolbox video decoders (AVC, HEVC).
//
// WHY THIS EXISTS. MediaCodecList.VideoToolboxDecoders used to register every
// VT codec with an EMPTY CodecCapabilities.profileLevels. That is not a
// neutral answer: ExoPlayer's MediaCodecInfo.isCodecProfileAndLevelSupported
// walks profileLevels looking for (profile == stream profile && level >=
// stream level) and logs "NoSupport [codec.profileLevel, avc1.4d401f, ...]"
// when nothing matches -- an empty table matches NOTHING. Every real AVC/HEVC
// format therefore came back FORMAT_EXCEEDS_CAPABILITIES, and
// DefaultTrackSelector, when every track exceeds capabilities, prefers the
// LOWEST quality (its quality ordering is reversed outside renderer
// capabilities): NewPipe's live kiosk played at 144p. Real Android never
// ships an empty table for a video decoder: Codec2InfoBuilder (frameworks/av
// media/codec2/sfplugin/Codec2InfoBuilder.cpp, addSupportedProfileLevels)
// asks the component, for EACH profile it accepts, for its supported levels
// and adds ONE (profile, highest level) pair:
//     C2Value::Primitive level = levelQuery[0].values.values.back();
//     ...
//     caps->addProfileLevel((uint32_t)sdkProfile, (uint32_t)sdkLevel);
//
// HOW THE ANSWER IS OBTAINED -- a real DECODE, never a guessed table and never
// a bare session create. VideoToolbox has no "which profiles/levels do you
// decode" query. Standing up a VTDecompressionSession for a parameter set is
// NOT an answer either: measured on the 2026-09-30 host
// (docs/vt-profile-level-probe_2026-09-30.md), VTDecompressionSessionCreate
// ACCEPTS hand-built SPSs for AVC High 4:2:2 and High 4:4:4 at 8K, which it
// cannot be relied on to decode, so session creation proves nothing about a
// profile. What this file does instead, per (profile, frame size):
//   1. ENCODE one real mid-grey IDR frame of that profile at that size with
//      VideoToolbox's own encoder (VTCompressionSession, ProfileLevel =
//      kVTProfileLevel_<codec>_<profile>_AutoLevel), and check from the
//      encoded SPS that the encoder really emitted that profile;
//   2. DECODE it through a VTDecompressionSession built exactly like the one
//      real playback builds (video_toolbox.mm CreateSessionInternal: same
//      decoder specification, same 32BGRA Metal-compatible destination), and
//      require a noErr callback with an image whose centre pixel is the grey
//      that went in.
// Only a frame that round-trips counts. A profile the host ENCODER cannot
// produce (AVC High10 / High 4:2:2 / High 4:4:4, HEVC Main Still) is not
// claimed: an untested capability is not advertised. One deliberate
// qualification: AVC Baseline is claimed the way every Android AVC decoder
// claims it (media3 maps profile_idc 66 to AVCProfileBaseline whatever the
// constraint flags, and Android lists Baseline on every AVC decoder), while
// only its CONSTRAINED subset is exercised -- Apple's Baseline encoder never
// emits FMO / ASO / redundant slices. (AOSP itself treats AVC
// Extended/High422/High444 as "Unsupported profile" in
// MediaCodecInfo.VideoCapabilities.applyLevelLimits.)
//
// WHAT A LEVEL MEANS HERE, honestly. A level bounds frame size (MaxFS),
// throughput (MaxMBPS) and bitrate. One decoded frame proves only the frame
// size. Several levels share one MaxFS (AVC 5.1/5.2 and 6/6.1/6.2; HEVC
// 4/4.1, 5/5.1/5.2 and 6/6.1/6.2) and differ only in rate, so per profile we
// report the LOWEST level of the largest MaxFS group that decoded -- the most
// one decode proves -- walking the groups from the largest down and stopping
// at the first that round-trips (a decoder that decodes a frame decodes every
// smaller one). HEVC is reported at MAIN tier: tier differs only in bitrate.
//
// HDR: no HDR profile (HEVCProfileMain10HDR10, ...) is ever advertised.
// Codec2InfoBuilder lists those only with an HDR display path end to end;
// ours decodes into 8-bit BGRA and composites SDR, so an HDR stream would
// play with wrong colours -- the app must pick the SDR rendition. 10-bit SDR
// (HEVC Main10) IS advertised when it round-trips: VT converts it to BGRA.
//
// COST: one encode + one decode per trial, lazily, once per mime per process
// (MediaCodecList caches). MACAPK_VTCAPS_TRACE=1 prints every trial.
//
// This file is deliberately free of JNI and of the rest of video_toolbox.mm so
// the offline gate debug/vtcaps_gate.sh can compile it standalone and run the
// real probe on the host.

#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {

bool g_trace = false;

// Android CodecProfileLevel constants, verbatim from frameworks/base
// media/java/android/media/MediaCodecInfo.java.
enum : int {
    AVCProfileBaseline = 0x01, AVCProfileMain = 0x02, AVCProfileExtended = 0x04,
    AVCProfileHigh = 0x08, AVCProfileConstrainedBaseline = 0x10000,
    AVCProfileConstrainedHigh = 0x80000,
    HEVCProfileMain = 0x01, HEVCProfileMain10 = 0x02,
};

// A level group: the Android constant of the LOWEST level sharing this MaxFS,
// and the MaxFS in the codec's block unit. AVC: macroblocks, the FS column of
// AOSP MediaCodecInfo.VideoCapabilities.applyLevelLimits (AVC branch) = H.264
// Table A-1. HEVC: luma samples, the FS column of the HEVC branch = H.265
// Table A.8. Listed LARGEST first (the probe walks down).
struct LevelGroup { int android; long maxFs; const char* name; };
const LevelGroup kAvcGroups[] = {
    { 0x20000, 139264, "6" },     // 6, 6.1, 6.2
    { 0x8000,  36864,  "5.1" },   // 5.1, 5.2
    { 0x4000,  22080,  "5" },
    { 0x2000,  8704,   "4.2" },
    { 0x800,   8192,   "4" },     // 4, 4.1
    { 0x400,   5120,   "3.2" },
    { 0x200,   3600,   "3.1" },
    { 0x80,    1620,   "2.2" },   // 2.2, 3
    { 0x40,    792,    "2.1" },
    { 0x4,     396,    "1.1" },   // 1.1, 1.2, 1.3, 2
    { 0x1,     99,     "1" },
};
const LevelGroup kHevcGroups[] = {   // MAIN-tier constants
    { 0x100000, 35651584, "6" },      // 6, 6.1, 6.2
    { 0x4000,   8912896,  "5" },      // 5, 5.1, 5.2
    { 0x400,    2228224,  "4" },      // 4, 4.1
    { 0x100,    983040,   "3.1" },
    { 0x40,     552960,   "3" },
    { 0x10,     245760,   "2.1" },
    { 0x4,      122880,   "2" },
    { 0x1,      36864,    "1" },
};

// The largest ~16:9 frame, in whole `unit`-pixel blocks, whose block count
// (unit == 16: macroblocks) or luma-sample count (unit == 8, HEVC: 8x8 cells
// of 64 samples) stays within MaxFS.
void FrameFor(long maxFs, int unit, int* w, int* h) {
    long cells = (unit == 16) ? maxFs : maxFs / 64;
    int wc = (int)std::floor(std::sqrt((double)cells * 16.0 / 9.0));
    if (wc < 1) wc = 1;
    int hc = (int)(cells / wc);
    if (hc < 1) hc = 1;
    *w = wc * unit;
    *h = hc * unit;
}

struct ProfileSpec {
    int android;
    CMVideoCodecType codec;
    CFStringRef vtProfile;      // kVTProfileLevel_* AutoLevel
    bool tenBit;
    int wantIdc;                // profile_idc the encoded SPS must carry
    uint8_t wantConstraintMask; // AVC constraint_set flags that must be SET
    const char* name;
};

// ---------------------------------------------------------------------------
// Encode one grey IDR frame.
// ---------------------------------------------------------------------------
struct EncOut { CMSampleBufferRef sb = nullptr; OSStatus status = 0; };

void EncCallback(void* refcon, void*, OSStatus status, VTEncodeInfoFlags, CMSampleBufferRef sb) {
    EncOut* o = (EncOut*)refcon;
    o->status = status;
    if (status == noErr && sb && !o->sb) { CFRetain(sb); o->sb = sb; }
}

CVPixelBufferRef MakeGreyFrame(int w, int h, bool tenBit) {
    OSType fmt = tenBit ? kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange
                        : kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
    NSDictionary* attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    CVPixelBufferRef pb = nullptr;
    if (CVPixelBufferCreate(kCFAllocatorDefault, (size_t)w, (size_t)h, fmt,
                            (__bridge CFDictionaryRef)attrs, &pb) != kCVReturnSuccess || !pb) {
        return nullptr;
    }
    CVPixelBufferLockBaseAddress(pb, 0);
    for (size_t plane = 0; plane < 2; plane++) {
        uint8_t* base = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, plane);
        size_t stride = CVPixelBufferGetBytesPerRowOfPlane(pb, plane);
        size_t rows = CVPixelBufferGetHeightOfPlane(pb, plane);
        if (!base) continue;
        if (!tenBit) {
            std::memset(base, 128, stride * rows);   // Y = Cb = Cr = 128: mid grey
        } else {
            // 10 bits in the MSBs of each 16-bit sample: 512 << 6.
            for (size_t r = 0; r < rows; r++) {
                uint16_t* row = (uint16_t*)(base + r * stride);
                for (size_t i = 0; i < stride / 2; i++) row[i] = (uint16_t)(512u << 6);
            }
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    return pb;
}

CMSampleBufferRef EncodeGrey(const ProfileSpec& p, int w, int h, bool hwOnly, OSStatus* outStatus) {
    @autoreleasepool {
        EncOut out;
        VTCompressionSessionRef enc = nullptr;
        // hwOnly: see ProbeProfiles. The hardware encoder refuses a size it
        // cannot do in ~1 ms (-12903 kVTCouldNotFindVideoEncoderErr), where
        // the software fallback spends ~0.5 s encoding an 8K frame whose
        // decode would then be refused for not being hardware anyway.
        NSDictionary* encSpec = hwOnly
            ? @{ (id)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @YES }
            : nil;
        OSStatus s = VTCompressionSessionCreate(kCFAllocatorDefault, w, h, p.codec,
                                                (__bridge CFDictionaryRef)encSpec,
                                                nullptr, nullptr, EncCallback, &out, &enc);
        if (s != noErr || !enc) { *outStatus = s; return nullptr; }
        VTSessionSetProperty(enc, kVTCompressionPropertyKey_ProfileLevel, p.vtProfile);
        VTSessionSetProperty(enc, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
        VTSessionSetProperty(enc, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
        VTSessionSetProperty(enc, kVTCompressionPropertyKey_MaxKeyFrameInterval, (__bridge CFNumberRef)@1);
        s = VTCompressionSessionPrepareToEncodeFrames(enc);
        CVPixelBufferRef pb = (s == noErr) ? MakeGreyFrame(w, h, p.tenBit) : nullptr;
        if (pb) {
            NSDictionary* opts = @{ (id)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES };
            s = VTCompressionSessionEncodeFrame(enc, pb, CMTimeMake(0, 30), kCMTimeInvalid,
                                                (__bridge CFDictionaryRef)opts, nullptr, nullptr);
            if (s == noErr) s = VTCompressionSessionCompleteFrames(enc, kCMTimeInvalid);
            CVPixelBufferRelease(pb);
        } else if (s == noErr) {
            s = -1;
        }
        VTCompressionSessionInvalidate(enc);
        CFRelease(enc);
        if (s == noErr && out.status != noErr) s = out.status;
        *outStatus = s;
        if (s != noErr && out.sb) { CFRelease(out.sb); out.sb = nullptr; }
        return out.sb;
    }
}

// ---------------------------------------------------------------------------
// Check the encoder really produced the requested profile (read back from
// the encoded parameter sets, ITU-T H.264 7.3.2.1.1 / H.265 7.3.3).
// ---------------------------------------------------------------------------
std::vector<uint8_t> StripEpb(const uint8_t* p, size_t n) {
    std::vector<uint8_t> out;
    int zeros = 0;
    for (size_t i = 0; i < n; i++) {
        if (zeros >= 2 && p[i] == 3) { zeros = 0; continue; }
        out.push_back(p[i]);
        zeros = (p[i] == 0) ? zeros + 1 : 0;
    }
    return out;
}

bool EncodedProfileMatches(const ProfileSpec& p, CMFormatDescriptionRef fmt, int* outIdc, int* outLevelIdc) {
    *outIdc = -1; *outLevelIdc = -1;
    size_t count = 0;
    if (p.codec == kCMVideoCodecType_H264) {
        const uint8_t* sps = nullptr; size_t n = 0;
        if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 0, &sps, &n, &count, nullptr) != noErr
                || !sps || n < 4) return false;
        std::vector<uint8_t> r = StripEpb(sps + 1, n - 1);   // after the 1-byte NAL header
        if (r.size() < 3) return false;
        *outIdc = r[0];
        *outLevelIdc = r[2];
        return r[0] == p.wantIdc && (r[1] & p.wantConstraintMask) == p.wantConstraintMask;
    }
    if (p.codec == kCMVideoCodecType_HEVC) {
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, nullptr, nullptr, &count, nullptr) != noErr)
            return false;
        for (size_t i = 0; i < count; i++) {
            const uint8_t* ps = nullptr; size_t n = 0;
            if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, i, &ps, &n, nullptr, nullptr) != noErr
                    || !ps || n < 3) continue;
            if (((ps[0] >> 1) & 0x3F) != 33) continue;         // SPS
            std::vector<uint8_t> r = StripEpb(ps + 2, n - 2);  // after the 2-byte NAL header
            // byte 0: vps_id(4) max_sub_layers_minus1(3) nesting(1); byte 1:
            // profile_space(2) tier(1) profile_idc(5); general_level_idc is
            // the last byte of the 96-bit PTL = byte 12.
            if (r.size() < 13) return false;
            *outIdc = r[1] & 0x1F;
            *outLevelIdc = r[12];
            return *outIdc == p.wantIdc;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Decode it through a session shaped like real playback's.
// ---------------------------------------------------------------------------
struct DecOut { OSStatus status = 1; bool gotImage = false; int b = -1, g = -1, r = -1; };

void DecCallback(void* refcon, void*, OSStatus status, VTDecodeInfoFlags,
                 CVImageBufferRef img, CMTime, CMTime) {
    DecOut* o = (DecOut*)refcon;
    o->status = status;
    if (status != noErr || !img) return;
    o->gotImage = true;
    CVPixelBufferRef pb = (CVPixelBufferRef)img;
    if (CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) return;
    uint8_t* base = (uint8_t*)CVPixelBufferGetBaseAddress(pb);
    size_t stride = CVPixelBufferGetBytesPerRow(pb);
    size_t w = CVPixelBufferGetWidth(pb), h = CVPixelBufferGetHeight(pb);
    if (base && w && h) {
        const uint8_t* px = base + (h / 2) * stride + (w / 2) * 4;   // 32BGRA
        o->b = px[0]; o->g = px[1]; o->r = px[2];
    }
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
}

bool DecodeGrey(CMSampleBufferRef sb, OSStatus* outStatus, bool* outHw, DecOut* outPx) {
    @autoreleasepool {
        CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sb);
        NSDictionary* decoderSpec = @{
            (id)kVTVideoDecoderSpecification_EnableHardwareAcceleratedVideoDecoder: @YES,
        };
        NSDictionary* destAttrs = @{
            (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
            (id)kCVPixelBufferMetalCompatibilityKey: @YES,
            (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
        };
        DecOut o;
        VTDecompressionOutputCallbackRecord rec = { DecCallback, &o };
        VTDecompressionSessionRef dec = nullptr;
        OSStatus s = VTDecompressionSessionCreate(kCFAllocatorDefault, (CMVideoFormatDescriptionRef)fmt,
                                                  (__bridge CFDictionaryRef)decoderSpec,
                                                  (__bridge CFDictionaryRef)destAttrs, &rec, &dec);
        if (s != noErr || !dec) { *outStatus = s; return false; }
        CFBooleanRef hwFlag = nullptr;
        if (VTSessionCopyProperty(dec, kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder,
                                  kCFAllocatorDefault, &hwFlag) == noErr && hwFlag) {
            *outHw = CFBooleanGetValue(hwFlag);
            CFRelease(hwFlag);
        }
        VTDecodeInfoFlags info = 0;
        s = VTDecompressionSessionDecodeFrame(dec, sb, 0, nullptr, &info);
        if (s == noErr) s = VTDecompressionSessionWaitForAsynchronousFrames(dec);
        VTDecompressionSessionInvalidate(dec);
        CFRelease(dec);
        if (s == noErr) s = o.status;
        *outStatus = s;
        *outPx = o;
        if (s != noErr || !o.gotImage) return false;
        // The encoder was fed Y'CbCr (128,128,128) video range: a neutral grey
        // that converts to about 130 in each 8-bit channel. A decoder that
        // "succeeds" into garbage (or black) is not a decoder for this profile.
        auto near = [](int v) { return v >= 110 && v <= 150; };
        return near(o.b) && near(o.g) && near(o.r)
               && std::abs(o.b - o.g) <= 8 && std::abs(o.g - o.r) <= 8;
    }
}

struct Result { std::vector<int> pairs; int maxW = 0; int maxH = 0; long maxBlocks = 0; };

// One profile's answer: the level group that round-tripped (or -1) and the
// frame that proved it.
struct ProfileAnswer { int group = -1; int w = 0, h = 0; };

// Walks the MaxFS groups LARGEST first and stops at the first frame that
// round-trips. When the host has a HARDWARE decoder for the codec
// (VTIsHardwareDecodeSupported), the table describes THAT decoder -- the
// MediaCodecInfo entry is advertised isHardwareAccelerated -- so a trial
// counts only if the decode really ran in hardware (measured: VT decodes 8K
// AVC too, but only by falling back to software; a real Android device lists
// its hardware AVC decoder at the hardware's limit and the software one as a
// separate codec). A PROFILE-MISMATCH (the encoder emitted another profile,
// e.g. it has no Extended-profile encoder and emits High) jumps straight to
// the smallest group; a mismatch there too means the profile cannot be
// produced on this host, so it is not claimed.
ProfileAnswer ProbeOne(const ProfileSpec& p, const LevelGroup* groups, size_t nGroups, int unit) {
    ProfileAnswer a;
    bool hwOnly = VTIsHardwareDecodeSupported(p.codec);
    for (size_t gi = 0; gi < nGroups; gi++) {
        int w = 0, h = 0;
        FrameFor(groups[gi].maxFs, unit, &w, &h);
        auto t0 = std::chrono::steady_clock::now();
        OSStatus es = 0, ds = 0;
        int idc = -1, lvl = -1;
        bool hw = false, profileOk = false, ok = false;
        DecOut px;
        CMSampleBufferRef sb = EncodeGrey(p, w, h, hwOnly, &es);
        if (sb) {
            profileOk = EncodedProfileMatches(p, CMSampleBufferGetFormatDescription(sb), &idc, &lvl);
            if (profileOk) ok = DecodeGrey(sb, &ds, &hw, &px) && (hw || !hwOnly);
            CFRelease(sb);
        }
        long ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0).count();
        if (g_trace) {
            std::fprintf(stderr,
                "[vtcaps] %s %-19s L%-3s %5dx%-5d enc=%d sps_idc=%d level_idc=%d%s dec=%d px=%d,%d,%d %s -> %s (%ld ms)\n",
                p.codec == kCMVideoCodecType_H264 ? "avc " : "hevc", p.name, groups[gi].name, w, h,
                (int)es, idc, lvl, (sb && !profileOk) ? " PROFILE-MISMATCH" : "", (int)ds,
                px.b, px.g, px.r, hw ? "hw" : "sw", ok ? "DECODED" : "no", ms);
        }
        if (ok) { a.group = (int)gi; a.w = w; a.h = h; break; }
        if (sb && !profileOk) {
            if (gi + 1 >= nGroups) break;   // mismatched at the smallest: give up
            gi = nGroups - 2;               // loop ++ lands on the smallest group
        }
    }
    return a;
}

// Profiles are independent, so they are probed on parallel threads (VT
// sessions are thread-safe); the answer is assembled in the spec order so it
// does not depend on scheduling.
void ProbeProfiles(const ProfileSpec* specs, size_t nSpecs, const LevelGroup* groups, size_t nGroups,
                   int unit, Result& res) {
    std::vector<ProfileAnswer> answers(nSpecs);
    std::vector<std::thread> threads;
    for (size_t si = 0; si < nSpecs; si++) {
        threads.emplace_back([&, si]() { answers[si] = ProbeOne(specs[si], groups, nGroups, unit); });
    }
    for (auto& t : threads) t.join();
    for (size_t si = 0; si < nSpecs; si++) {
        const ProfileAnswer& a = answers[si];
        if (a.group < 0) continue;
        res.pairs.push_back(specs[si].android);
        res.pairs.push_back(groups[a.group].android);
        // Size claims come from what DECODED: the widest / tallest frame and
        // the largest macroblock count of any profile.
        if (a.w > res.maxW) res.maxW = a.w;
        if (a.h > res.maxH) res.maxH = a.h;
        long mbs = (long)((a.w + 15) / 16) * ((a.h + 15) / 16);
        if (mbs > res.maxBlocks) res.maxBlocks = mbs;
    }
}

Result ProbeAvc() {
    // constraint_set1 marks Constrained Baseline, constraint_set4+5 Constrained
    // High (H.264 A.2.1.1 / A.2.4.2); constraint byte bit 7 = set0 ... bit 2 = set5.
    static const ProfileSpec specs[] = {
        { AVCProfileConstrainedBaseline, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel, false, 66, 0x40, "ConstrainedBaseline" },
        { AVCProfileBaseline, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_Baseline_AutoLevel, false, 66, 0x00, "Baseline" },
        { AVCProfileMain, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_Main_AutoLevel, false, 77, 0x00, "Main" },
        { AVCProfileExtended, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_Extended_AutoLevel, false, 88, 0x00, "Extended" },
        { AVCProfileHigh, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_High_AutoLevel, false, 100, 0x00, "High" },
        { AVCProfileConstrainedHigh, kCMVideoCodecType_H264,
          kVTProfileLevel_H264_ConstrainedHigh_AutoLevel, false, 100, 0x0C, "ConstrainedHigh" },
    };
    Result r;
    ProbeProfiles(specs, sizeof(specs) / sizeof(specs[0]), kAvcGroups,
                  sizeof(kAvcGroups) / sizeof(kAvcGroups[0]), 16, r);
    return r;
}

Result ProbeHevc() {
    static const ProfileSpec specs[] = {
        { HEVCProfileMain, kCMVideoCodecType_HEVC,
          kVTProfileLevel_HEVC_Main_AutoLevel, false, 1, 0, "Main" },
        { HEVCProfileMain10, kCMVideoCodecType_HEVC,
          kVTProfileLevel_HEVC_Main10_AutoLevel, true, 2, 0, "Main10" },
    };
    Result r;
    ProbeProfiles(specs, sizeof(specs) / sizeof(specs[0]), kHevcGroups,
                  sizeof(kHevcGroups) / sizeof(kHevcGroups[0]), 8, r);
    return r;
}

}  // namespace

extern "C" {

// Probes `mime` on this host. Writes [maxWidth, maxHeight, maxMacroblocks,
// nPairs, profile0, level0, profile1, level1, ...] (Android CodecProfileLevel
// constants) into `out` (capacity `cap` ints) and returns the number of ints
// written. 0 means "no per-profile probe exists for this mime" (the caller
// keeps its profile-less entry), -1 means `cap` was too small. A probe that
// ran and decoded nothing returns 4 with nPairs == 0.
int macapk_vtcaps_probe(const char* mime, int* out, int cap) {
    const char* t = std::getenv("MACAPK_VTCAPS_TRACE");
    g_trace = (t && *t && std::strcmp(t, "0") != 0);
    if (!mime || !out) return 0;
    Result r;
    if (std::strcmp(mime, "video/avc") == 0) r = ProbeAvc();
    else if (std::strcmp(mime, "video/hevc") == 0) r = ProbeHevc();
    else return 0;
    int need = 4 + (int)r.pairs.size();
    if (cap < need) return -1;
    out[0] = r.maxW;
    out[1] = r.maxH;
    out[2] = (int)r.maxBlocks;
    out[3] = (int)(r.pairs.size() / 2);
    for (size_t i = 0; i < r.pairs.size(); i++) out[4 + i] = r.pairs[i];
    return need;
}

}  // extern "C"
