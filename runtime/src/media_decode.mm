// media_decode.mm -- real audio DECODE backend for android.media.MediaExtractor
// + MediaCodec, backing the JVM-side stubs with macOS AudioToolbox.
//
// The android.media.* Java surface + state machines, plus PCM OUTPUT (AudioTrack
// /SoundPool/MediaPlayer via audio_backend.mm, OpenSL ES + AAudio via the bionic
// shim) were already real. The gap was DECODE: turning compressed bytes
// (AAC/MP3) into PCM. This file fills it for AUDIO:
//
//   * Demuxer  (backs MediaExtractor): AudioToolbox AudioFile -- open a
//     container, read its COMPRESSED audio access units one at a time + the
//     format (sample rate / channels / the AAC magic cookie aka esds == the
//     Android MediaFormat csd-0).
//   * Decoder  (backs MediaCodec):     AudioToolbox AudioConverter -- decode
//     those compressed access units into interleaved signed-16 PCM.
//
// Both live in AudioToolbox (already linked; no new frameworks). The
// MediaExtractor/MediaCodec buffer-index protocol is implemented in Java
// (MediaExtractor.java / MediaCodec.java); this file is the codec core + the
// NativeMedia JNI surface.
//
// Verbatim-pinned contracts (see docs note + the workflow contract report):
//   AudioFileOpenURL / AudioFileGetProperty(kAudioFilePropertyDataFormat,
//     kAudioFilePropertyMagicCookieData, kAudioFilePropertyPacketSizeUpperBound)
//     / AudioFileReadPacketData -- AudioToolbox/AudioFile.h.
//   AudioConverterNew / AudioConverterSetProperty(
//     kAudioConverterDecompressionMagicCookie) / AudioConverterFillComplexBuffer
//     / AudioConverterReset / AudioConverterDispose -- AudioToolbox/AudioConverter.h.
//   AudioStreamBasicDescription / AudioStreamPacketDescription --
//     CoreAudioTypes/CoreAudioBaseTypes.h.
// Refs: developer.apple.com/documentation/audiotoolbox (AudioFile / AudioConverter),
//   Apple QA1318 (magic-cookie hand-off from the file to the decoder).

#include <AudioToolbox/AudioToolbox.h>
#include <CoreFoundation/CoreFoundation.h>
#include <jni.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <deque>

namespace {

// ===================== Demuxer (backs MediaExtractor) =====================

struct Demuxer {
    AudioFileID                 file = nullptr;
    AudioStreamBasicDescription asbd = {};
    std::vector<uint8_t>        cookie;        // esds / AudioSpecificConfig (csd-0); empty for ADTS/MP3
    SInt64                      nextPacket = 0; // read cursor (packet index)
    UInt32                      maxPacketSize = 0;
    UInt64                      packetCount = 0;
    // Pre-read "current" access unit -- MediaExtractor reads the CURRENT sample
    // (readSampleData/getSampleTime) and advance() moves to the next.
    std::vector<uint8_t>        curData;
    SInt64                      curPtsUs = -1;
    bool                        curValid = false;
};

// PTS (microseconds) of the packet at index `pkt`. (AAC: 1024 frames/pkt;
// MP3: 1152.) frames -> us via the sample rate.
static inline SInt64 md_pts_us(const Demuxer* d, SInt64 pkt) {
    double frames = (double)pkt * (double)d->asbd.mFramesPerPacket;
    if (d->asbd.mSampleRate <= 0) return -1;
    return (SInt64)llround(frames * 1.0e6 / d->asbd.mSampleRate);
}

// Read ONE compressed access unit at the cursor into d->curData; advances the
// cursor. Sets curValid=false at EOF.
static void md_fill_current(Demuxer* d) {
    d->curValid = false;
    if (!d->file || d->maxPacketSize == 0) return;
    std::vector<uint8_t> buf(d->maxPacketSize);
    AudioStreamPacketDescription pkt = {};
    UInt32 numBytes   = d->maxPacketSize;
    UInt32 numPackets = 1;
    OSStatus s = AudioFileReadPacketData(
        d->file, false, &numBytes, &pkt, d->nextPacket, &numPackets, buf.data());
    if (s == kAudioFileEndOfFileError || (s == noErr && numPackets == 0)) return; // EOF
    if (s != noErr) return;
    d->curData.assign(buf.data() + pkt.mStartOffset,
                      buf.data() + pkt.mStartOffset + pkt.mDataByteSize);
    d->curPtsUs = md_pts_us(d, d->nextPacket);
    d->nextPacket += numPackets;
    d->curValid = true;
}

}  // namespace

extern "C" {

void* macapk_md_demux_open(const char* path) {
    if (!path || !*path) return nullptr;
    Demuxer* d = new Demuxer();
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        nullptr, (const UInt8*)path, (CFIndex)strlen(path), false);
    if (!url) { delete d; return nullptr; }
    OSStatus s = AudioFileOpenURL(url, kAudioFileReadPermission, 0, &d->file);
    CFRelease(url);
    if (s != noErr || !d->file) { delete d; return nullptr; }

    UInt32 sz = sizeof(d->asbd);
    if (AudioFileGetProperty(d->file, kAudioFilePropertyDataFormat, &sz, &d->asbd) != noErr) {
        AudioFileClose(d->file); delete d; return nullptr;
    }
    // Magic cookie (csd-0). Absent for raw ADTS/MP3 -> empty, which is fine.
    UInt32 ck = 0, writable = 0;
    if (AudioFileGetPropertyInfo(d->file, kAudioFilePropertyMagicCookieData, &ck, &writable) == noErr
        && ck > 0) {
        d->cookie.resize(ck);
        AudioFileGetProperty(d->file, kAudioFilePropertyMagicCookieData, &ck, d->cookie.data());
        d->cookie.resize(ck);
    }
    UInt32 ubsz = sizeof(d->maxPacketSize);
    if (AudioFileGetProperty(d->file, kAudioFilePropertyPacketSizeUpperBound, &ubsz, &d->maxPacketSize) != noErr
        || d->maxPacketSize == 0) {
        d->maxPacketSize = 8192;  // generous fallback for AAC/MP3
    }
    UInt32 pcsz = sizeof(d->packetCount);
    AudioFileGetProperty(d->file, kAudioFilePropertyAudioDataPacketCount, &pcsz, &d->packetCount);

    md_fill_current(d);  // pre-read the first access unit
    std::fprintf(stderr,
        "[media] demux open: %g Hz, %u ch, fmt=0x%08x, %llu packets, maxpkt=%u, cookie=%zu B\n",
        d->asbd.mSampleRate, (unsigned)d->asbd.mChannelsPerFrame,
        (unsigned)d->asbd.mFormatID, (unsigned long long)d->packetCount,
        (unsigned)d->maxPacketSize, d->cookie.size());
    return d;
}

// 1 if an audio track was found, else 0. (AudioFile exposes a single audio
// stream; container video tracks are not handled by this audio path.)
int macapk_md_demux_track_count(void* h) {
    Demuxer* d = (Demuxer*)h;
    return (d && d->asbd.mSampleRate > 0 && d->asbd.mChannelsPerFrame > 0) ? 1 : 0;
}
int macapk_md_demux_sample_rate(void* h) { Demuxer* d=(Demuxer*)h; return d?(int)d->asbd.mSampleRate:0; }
int macapk_md_demux_channels(void* h)    { Demuxer* d=(Demuxer*)h; return d?(int)d->asbd.mChannelsPerFrame:0; }
// 1=AAC ('aac '), 2=MP3 ('.mp3'), 0=other.
int macapk_md_demux_format_id(void* h) {
    Demuxer* d=(Demuxer*)h; if (!d) return 0;
    if (d->asbd.mFormatID == kAudioFormatMPEG4AAC || d->asbd.mFormatID == kAudioFormatMPEG4AAC_HE) return 1;
    if (d->asbd.mFormatID == kAudioFormatMPEGLayer3) return 2;
    return 0;
}
int64_t macapk_md_demux_duration_us(void* h) {
    Demuxer* d=(Demuxer*)h; if (!d || d->asbd.mSampleRate<=0) return -1;
    double frames = (double)d->packetCount * (double)d->asbd.mFramesPerPacket;
    return (int64_t)llround(frames * 1.0e6 / d->asbd.mSampleRate);
}
int macapk_md_demux_csd0_size(void* h) { Demuxer* d=(Demuxer*)h; return d?(int)d->cookie.size():0; }
int macapk_md_demux_csd0(void* h, void* out, int cap) {
    Demuxer* d=(Demuxer*)h; if (!d) return 0;
    int n = (int)d->cookie.size();
    if (out && cap >= n && n > 0) std::memcpy(out, d->cookie.data(), n);
    return n;
}
int macapk_md_demux_current_size(void* h) { Demuxer* d=(Demuxer*)h; return (d&&d->curValid)?(int)d->curData.size():-1; }
// Copies the current access unit into out(cap); returns its size, or -1 at EOS.
int macapk_md_demux_current(void* h, void* out, int cap) {
    Demuxer* d=(Demuxer*)h; if (!d || !d->curValid) return -1;
    int n = (int)d->curData.size();
    if (out && cap >= n) std::memcpy(out, d->curData.data(), n);
    return n;
}
int64_t macapk_md_demux_sample_time(void* h) { Demuxer* d=(Demuxer*)h; return (d&&d->curValid)?d->curPtsUs:-1; }
// Advance to the next access unit; returns 1 if a new current is available, 0 at EOS.
int macapk_md_demux_advance(void* h) { Demuxer* d=(Demuxer*)h; if(!d) return 0; md_fill_current(d); return d->curValid?1:0; }
void macapk_md_demux_seek(void* h, int64_t us) {
    Demuxer* d=(Demuxer*)h; if(!d || d->asbd.mSampleRate<=0) return;
    double pkt = ((double)us * 1.0e-6) * d->asbd.mSampleRate / (double)d->asbd.mFramesPerPacket;
    SInt64 p = (SInt64)llround(pkt); if (p<0) p=0;
    d->nextPacket = p;
    md_fill_current(d);
}
void macapk_md_demux_close(void* h) {
    Demuxer* d=(Demuxer*)h; if(!d) return;
    if (d->file) AudioFileClose(d->file);
    delete d;
}

// ===================== Decoder (backs MediaCodec) =====================
//
// Widened 2026-08-16 from AAC/MP3-only to every audio format this host's
// AudioToolbox reports it can decode (measured, not assumed -- see
// docs/audiotoolbox-codec-widening_2026-08-16.md for the full
// kAudioFormatProperty_DecodeFormatIDs list and per-format citations) plus
// Vorbis via a vendored software decoder (audio_vorbis_decode.mm), which
// AudioToolbox does not support at all.
//
// formatId is the contract with MediaCodec.java's configure(), which maps
// MediaFormat.KEY_MIME to this integer before calling NativeMedia.
// nativeDecOpen (MediaCodec.java is owned by a different lane; see the
// report for the exact mime -> formatId table it needs to grow into):
//   1  audio/mp4a-latm  AAC LC/HE/HEv2/LD/ELD, self-selected by the
//                       AudioSpecificConfig in the magic cookie   -- existing
//   2  audio/mpeg       MP3                                       -- existing
//   3  audio/opus       kAudioFormatOpus
//   4  audio/flac       kAudioFormatFLAC
//   5  audio/alac       kAudioFormatAppleLossless
//   6  audio/ac3        kAudioFormatAC3
//   7  audio/eac3       kAudioFormatEnhancedAC3
//   8  audio/3gpp       kAudioFormatAMR     (AMR-NB, fixed 8 kHz mono)
//   9  audio/amr-wb     kAudioFormatAMR_WB  (fixed 16 kHz mono)
//   10 audio/g711-alaw  kAudioFormatALaw
//   11 audio/g711-mlaw  kAudioFormatULaw
//   12 audio/raw        PCM passthrough -- bypasses AudioConverter entirely
//   13 audio/vorbis     NOT an AudioConverter format -- see
//                       audio_vorbis_decode.mm for why and how

}  // extern "C"

namespace {

// Sentinel OSStatus the input proc returns when the FIFO is empty mid-stream
// (not EOS): "no data right now", keeps the converter alive (vs noErr+0=EOS).
static const OSStatus kMacApkNoDataNow = (OSStatus)0x6d747279;  // 'mtry'

struct Decoder {
    AudioConverterRef conv = nullptr;
    int sampleRate = 0, channels = 0, formatId = 0;
    // Input FIFO of compressed access units fed via macapk_md_dec_decode. The
    // input callback pulls from here; an empty FIFO that is NOT at EOS returns
    // 0 packets for THIS fill (the converter retains its state for the next
    // call -- standard streaming-decode pattern).
    std::deque<std::vector<uint8_t>> fifo;
    // The access unit currently handed to the converter. It MUST stay alive
    // until the input proc is called AGAIN (Apple: "do not free or alter this
    // buffer until called again") -- the converter reads it after the proc
    // returns. So we keep it here instead of popping inside the proc.
    std::vector<uint8_t> inflight;
    AudioStreamPacketDescription curDesc = {};
    bool eos = false;

    // Byte-constant-bitrate input formats (ALaw/ULaw): the fixed byte size
    // of one decoder packet, so md_input_proc can let AudioConverter compute
    // the packet count itself instead of asserting "this whole access unit
    // is exactly one packet" -- which would be wrong the moment an AU is
    // more than one sample long (Apple's docs: CBR formats do not need
    // explicit packet descriptions). 0 = not CBR, use the existing
    // whole-AU-is-one-packet path every other format here relies on.
    int cbrBytesPerPacket = 0;

    // Non-AudioConverter engines dispatch through these instead of `conv`;
    // exactly one of {conv, vorbisEngine, rawPassthrough} is live per
    // instance (see macapk_md_dec_decode/out_sample_rate/out_channels/close).
    void* vorbisEngine = nullptr;   // formatId==13: an audio_vorbis_dec_* handle
    bool  rawPassthrough = false;   // formatId==12: audio/raw, memcpy through

    // Opus only: samples still to discard from the FRONT of decoder output
    // (RFC 6716 sec 2 / RFC 7845 sec 4.2 pre-skip). Parsed directly from the
    // raw OpusHead (csd-0 bytes[10..11], LE u16) at open time -- see
    // macapk_md_dec_open. The header always carries this value, so Opus
    // decodes correctly with ZERO MediaCodec.java change beyond the mime ->
    // formatId table entry; AOSP's csd-1 override is not honored (rare in
    // practice -- see the report).
    int opusPreSkipRemaining = 0;
};

// Input proc: hand the converter ONE access unit from the FIFO per call; set
// *ioNumberDataPackets=0 when the FIFO is empty (end of input for this fill).
static OSStatus md_input_proc(AudioConverterRef, UInt32* ioNumberDataPackets,
                              AudioBufferList* ioData,
                              AudioStreamPacketDescription* __nullable* __nullable outPktDesc,
                              void* inUserData) {
    Decoder* dec = (Decoder*)inUserData;
    if (dec->fifo.empty()) {
        *ioNumberDataPackets = 0;
        if (outPktDesc) *outPktDesc = nullptr;
        // FIFO empty: at real EOS return noErr+0 packets (the converter then
        // flushes + ends). MID-STREAM (more packets coming later) we must NOT
        // return noErr+0 -- that permanently EOSes the converter. Returning a
        // non-zero status signals "no data right now"; FillComplexBuffer returns
        // it with the partial output, and the converter stays usable for the
        // next call (standard streaming-decode pattern).
        return dec->eos ? noErr : (OSStatus)kMacApkNoDataNow;
    }
    // Move the front packet into `inflight` so it stays alive after we return
    // (the converter reads mData post-return). The PREVIOUS inflight is freed
    // here, which is safe: this proc is only re-entered once the converter has
    // finished with the packet handed out last time.
    dec->inflight = std::move(dec->fifo.front());
    dec->fifo.pop_front();
    ioData->mNumberBuffers = 1;
    ioData->mBuffers[0].mNumberChannels = 0;       // ignored for compressed input
    ioData->mBuffers[0].mDataByteSize = (UInt32)dec->inflight.size();
    ioData->mBuffers[0].mData = dec->inflight.data();
    if (dec->cbrBytesPerPacket > 0) {
        if (outPktDesc) *outPktDesc = nullptr;
        *ioNumberDataPackets = (UInt32)(dec->inflight.size() / (size_t)dec->cbrBytesPerPacket);
    } else {
        if (outPktDesc) {
            dec->curDesc.mStartOffset = 0;
            dec->curDesc.mVariableFramesInPacket = 0;   // whole AU == one packet
            dec->curDesc.mDataByteSize = (UInt32)dec->inflight.size();
            *outPktDesc = &dec->curDesc;
        }
        *ioNumberDataPackets = 1;
    }
    return noErr;
}

// For formatId==13 (Vorbis) ONLY: MediaCodec.java packs csd-0 (identification
// header) and csd-1 (setup header) into one blob as
// [u32 LE len0][bytes0][u32 LE len1][bytes1] before calling nativeDecOpen,
// since Vorbis needs both headers and the existing native method keeps its
// signature (one byte[]) unchanged. Every other formatId keeps today's
// plain, unprefixed csd0 passthrough -- see the report for the exact
// MediaCodec.java diff (this file does not own that source).
static bool parse_vorbis_combined_csd(const uint8_t* blob, int blobLen,
                                      std::vector<uint8_t>* idHdr,
                                      std::vector<uint8_t>* setupHdr) {
    if (!blob || blobLen < 4) return false;
    auto rd32 = [](const uint8_t* p) -> uint32_t {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    };
    int off = 0;
    uint32_t len0 = rd32(blob + off); off += 4;
    if (off + (int)len0 > blobLen) return false;
    idHdr->assign(blob + off, blob + off + len0); off += (int)len0;
    if (off + 4 > blobLen) return false;
    uint32_t len1 = rd32(blob + off); off += 4;
    if (off + (int)len1 > blobLen) return false;
    setupHdr->assign(blob + off, blob + off + len1);
    return true;
}

}  // namespace

// audio_vorbis_decode.mm (same executable target, see runtime/CMakeLists.txt;
// forward-declared rather than a header, matching this file's own style for
// the vendored decoders -- audio_backend.mm does the same for
// stb_vorbis_decode_memory).
extern "C" {
void* macapk_vorbis_dec_open(const void* idHdr, int idLen, const void* setupHdr,
                             int setupLen, int* outSampleRate, int* outChannels);
int   macapk_vorbis_dec_decode(void* h, const void* au, int auLen, int eos, void* out, int cap);
int   macapk_vorbis_dec_out_sample_rate(void* h);
int   macapk_vorbis_dec_out_channels(void* h);
void  macapk_vorbis_dec_close(void* h);
}

extern "C" {

void* macapk_md_dec_open(int formatId, int sampleRate, int channels,
                         const void* csd0, int csd0Len) {
    if (sampleRate <= 0 || channels <= 0) return nullptr;

    // ---- Vorbis: not an AudioConverter format at all (macOS AudioToolbox
    // has no public Vorbis decoder -- see audio_vorbis_decode.mm). ----
    if (formatId == 13) {
        std::vector<uint8_t> idHdr, setupHdr;
        if (!parse_vorbis_combined_csd((const uint8_t*)csd0, csd0Len, &idHdr, &setupHdr)) {
            std::fprintf(stderr, "[media] vorbis: malformed combined csd (len=%d)\n", csd0Len);
            return nullptr;
        }
        int outSr = 0, outCh = 0;
        void* v = macapk_vorbis_dec_open(idHdr.data(), (int)idHdr.size(),
                                         setupHdr.data(), (int)setupHdr.size(),
                                         &outSr, &outCh);
        if (!v) return nullptr;
        Decoder* dec = new Decoder();
        dec->vorbisEngine = v;
        dec->formatId = formatId;
        dec->sampleRate = outSr;
        dec->channels = outCh;
        return dec;
    }

    // ---- audio/raw: already PCM, no converter needed. ----
    if (formatId == 12) {
        Decoder* dec = new Decoder();
        dec->rawPassthrough = true;
        dec->formatId = formatId;
        dec->sampleRate = sampleRate;
        dec->channels = channels;
        return dec;
    }

    AudioStreamBasicDescription in = {};
    in.mSampleRate = sampleRate;
    in.mChannelsPerFrame = channels;
    bool wantsCookie = false;
    int cbrBpp = 0;

    switch (formatId) {
        case 2:  // audio/mpeg (MP3)
            in.mFormatID = kAudioFormatMPEGLayer3; in.mFramesPerPacket = 1152;
            break;
        case 3:  // audio/opus -- always operates at 48 kHz internally
                 // (RFC 6716 sec 2); the ID header's own sample-rate field
                 // is informational only per that same spec, so the caller's
                 // declared rate is intentionally NOT used here.
            in.mFormatID = kAudioFormatOpus; in.mSampleRate = 48000; in.mFramesPerPacket = 0;
            break;
        case 4:  // audio/flac -- see flacCookie below for why this is NOT a
                 // verbatim csd-0 passthrough like AAC/ALAC.
            in.mFormatID = kAudioFormatFLAC; wantsCookie = true;
            // AudioConverterNew for kAudioFormatFLAC fails outright (generic
            // 'what'/kAudioConverterErr_UnspecifiedError) unless
            // mFramesPerPacket is the stream's real block size -- unlike
            // every other compressed format here, FLAC does NOT tolerate 0
            // (VBR/unknown) even though md_input_proc already supplies a
            // correct per-AU packet description generically. Confirmed by
            // opening the same file through AudioFile (kAudioFilePropertyDataFormat)
            // as an oracle: it reports mFramesPerPacket=4608 for a stream
            // whose STREAMINFO min_blocksize is also 4608 -- so read it
            // straight out of csd-0 (FLAC spec: min_blocksize is the first
            // 16 bits of STREAMINFO, i.e. csd-0 bytes[8..9] once the 4-byte
            // "fLaC" marker and 4-byte metadata-block header are skipped).
            if (csd0 && csd0Len >= 10) {
                const uint8_t* h3 = (const uint8_t*)csd0;
                in.mFramesPerPacket = ((UInt32)h3[8] << 8) | (UInt32)h3[9];
            }
            break;
        case 5:  // audio/alac -- cookie = csd-0 verbatim (24- or 48-byte
                 // ALACSpecificConfig[+ALACChannelLayoutInfo]; Apple's own
                 // ALACMagicCookieDescription.txt, macosforge/alac, "the
                 // magic cookie is opaque and should be presented to the
                 // decoder exactly as vended by the encoder").
            in.mFormatID = kAudioFormatAppleLossless; in.mFramesPerPacket = 4096; wantsCookie = true;
            break;
        case 6:  // audio/ac3 -- self-describing sync frames (ATSC A/52
                 // bsi header), no cookie.
            in.mFormatID = kAudioFormatAC3; in.mFramesPerPacket = 1536;
            break;
        case 7:  // audio/eac3 -- frame size varies with sub-block count;
                 // rely on the per-AU packet description md_input_proc
                 // already supplies generically, same as FLAC/Opus.
            in.mFormatID = kAudioFormatEnhancedAC3; in.mFramesPerPacket = 0;
            break;
        case 8:  // audio/3gpp (AMR-NB) -- spec-fixed 8 kHz mono, 20 ms/frame
                 // (3GPP TS 26.101); one Android AU is one frame, matching
                 // the generic per-AU-is-one-packet path (frame BYTE size
                 // still varies with the codec mode, so this is not the
                 // byte-CBR case below).
            in.mFormatID = kAudioFormatAMR; in.mSampleRate = 8000; in.mChannelsPerFrame = 1;
            in.mFramesPerPacket = 160;
            break;
        case 9:  // audio/amr-wb -- spec-fixed 16 kHz mono, 20 ms/frame
                 // (3GPP TS 26.201).
            in.mFormatID = kAudioFormatAMR_WB; in.mSampleRate = 16000; in.mChannelsPerFrame = 1;
            in.mFramesPerPacket = 320;
            break;
        case 10: // audio/g711-alaw -- true byte-CBR: 1 byte/channel/frame.
            in.mFormatID = kAudioFormatALaw; in.mFramesPerPacket = 1;
            in.mBytesPerPacket = (UInt32)channels; cbrBpp = channels;
            break;
        case 11: // audio/g711-mlaw
            in.mFormatID = kAudioFormatULaw; in.mFramesPerPacket = 1;
            in.mBytesPerPacket = (UInt32)channels; cbrBpp = channels;
            break;
        case 1:  // audio/mp4a-latm (AAC) -- the converter self-selects
                 // LC/HE/HEv2/LD/ELD from the AudioSpecificConfig in the
                 // magic cookie.
            in.mFormatID = kAudioFormatMPEG4AAC; in.mFramesPerPacket = 1024; wantsCookie = true;
            break;
        default:
            std::fprintf(stderr, "[media] dec_open: unsupported formatId=%d\n", formatId);
            return nullptr;
    }
    // Every other per-packet byte/frame field stays 0 (VBR, unknown);
    // md_input_proc already supplies a correct per-AU
    // AudioStreamPacketDescription generically, which is all any of the
    // non-CBR formats above need (this is exactly the pattern the existing
    // AAC/MP3 code already relied on -- it generalizes as-is).

    AudioStreamBasicDescription out = {};
    out.mSampleRate = in.mSampleRate;            // the (possibly spec-
                                                  // corrected) input rate
                                                  // above, never the raw
                                                  // caller-supplied one.
    out.mFormatID = kAudioFormatLinearPCM;
    out.mFormatFlags = kLinearPCMFormatFlagIsSignedInteger | kLinearPCMFormatFlagIsPacked;
    out.mBitsPerChannel = 16;
    out.mChannelsPerFrame = in.mChannelsPerFrame;
    out.mFramesPerPacket = 1;
    out.mBytesPerFrame = 2 * out.mChannelsPerFrame;
    out.mBytesPerPacket = out.mBytesPerFrame;

    AudioConverterRef conv = nullptr;
    OSStatus s = AudioConverterNew(&in, &out, &conv);
    if (s != noErr || !conv) {
        std::fprintf(stderr, "[media] AudioConverterNew failed for formatId=%d: %d\n",
                     formatId, (int)s);
        return nullptr;
    }
    // Magic cookie. AAC (AudioSpecificConfig) and ALAC (ALACSpecificConfig)
    // take csd-0 verbatim -- Android's csd-0 IS the exact byte layout
    // AudioToolbox's magic-cookie property expects for those two, matching
    // how the existing AAC path already worked. MP3/Opus/AC3/EAC3/AMR/ALaw/
    // ULaw take no cookie at all (self-describing bitstream or fixed ASBD).
    //
    // FLAC is the one exception: Android's csd-0 is "fLaC"+STREAMINFO (the
    // raw on-disk .flac file header shape, per AOSP's own CSD table), but
    // AudioConverterSetProperty(kAudioConverterDecompressionMagicCookie)
    // for kAudioFormatFLAC wants Apple's ISOBMFF-derived "dfLa" box shape
    // instead: a 4-byte big-endian total-size prefix, the 4-byte 'dfLa'
    // fourcc, a 4-byte ISO fullbox version/flags (0), then the SAME
    // metadata-block-header+STREAMINFO bytes csd-0 already carries after
    // its own 4-byte "fLaC" marker. Confirmed by opening the same file
    // through AudioFile and reading kAudioFilePropertyMagicCookieData as an
    // oracle: the bytes it returns are byte-for-byte this transform of the
    // csd-0 Android supplies, and AudioConverterSetProperty accepts it
    // (rejects the untransformed csd-0 with a hard AudioConverterNew
    // failure before we would even reach this call).
    std::vector<uint8_t> flacCookie;
    const void* cookiePtr = csd0;
    int cookieLen = csd0Len;
    if (formatId == 4 && csd0 && csd0Len > 4) {
        const uint8_t* c = (const uint8_t*)csd0;
        uint32_t rest = (uint32_t)(csd0Len - 4);      // everything after "fLaC"
        uint32_t total = 4 + 4 + 4 + rest;
        flacCookie.push_back((uint8_t)(total >> 24)); flacCookie.push_back((uint8_t)(total >> 16));
        flacCookie.push_back((uint8_t)(total >> 8));  flacCookie.push_back((uint8_t)total);
        flacCookie.push_back('d'); flacCookie.push_back('f'); flacCookie.push_back('L'); flacCookie.push_back('a');
        flacCookie.push_back(0); flacCookie.push_back(0); flacCookie.push_back(0); flacCookie.push_back(0);
        flacCookie.insert(flacCookie.end(), c + 4, c + csd0Len);
        cookiePtr = flacCookie.data();
        cookieLen = (int)flacCookie.size();
    }
    if (wantsCookie && cookiePtr && cookieLen > 0) {
        s = AudioConverterSetProperty(conv, kAudioConverterDecompressionMagicCookie,
                                      (UInt32)cookieLen, cookiePtr);
        if (s != noErr)
            std::fprintf(stderr, "[media] set magic cookie failed (formatId=%d): %d (continuing)\n",
                         formatId, (int)s);
    }
    Decoder* dec = new Decoder();
    dec->conv = conv;
    dec->sampleRate = (int)out.mSampleRate;
    dec->channels = (int)out.mChannelsPerFrame;
    dec->formatId = formatId;
    dec->cbrBytesPerPacket = cbrBpp;

    if (formatId == 3 && csd0 && csd0Len >= 12) {
        const uint8_t* opusHdr = (const uint8_t*)csd0;
        dec->opusPreSkipRemaining = (int)opusHdr[10] | ((int)opusHdr[11] << 8);
    }
    return dec;
}

// Feed ONE compressed access unit (au/auLen; may be empty when eos) and drain
// the PCM the converter produces, into out(cap). Returns PCM bytes written
// (>=0; may be 0 due to decoder priming), or -1 on a hard error.
int macapk_md_dec_decode(void* h, const void* au, int auLen, int eos, void* out, int cap) {
    Decoder* dec = (Decoder*)h;
    if (!dec) return -1;

    if (dec->vorbisEngine)
        return macapk_vorbis_dec_decode(dec->vorbisEngine, au, auLen, eos, out, cap);

    if (dec->rawPassthrough) {
        // audio/raw: the "compressed" access unit already IS S16LE PCM.
        if (!au || auLen <= 0) return 0;
        int n = auLen < cap ? auLen : cap;
        std::memcpy(out, au, (size_t)n);
        return n;
    }

    if (!dec->conv) return -1;
    if (au && auLen > 0)
        dec->fifo.emplace_back((const uint8_t*)au, (const uint8_t*)au + auLen);
    if (eos) dec->eos = true;

    int16_t* dst = (int16_t*)out;
    int capFrames = cap / (int)(2 * dec->channels);
    int producedFrames = 0;

    // Pull until the converter stops producing (FIFO drained for this call).
    while (producedFrames < capFrames) {
        UInt32 want = (UInt32)(capFrames - producedFrames);
        AudioBufferList abl;
        abl.mNumberBuffers = 1;
        abl.mBuffers[0].mNumberChannels = dec->channels;
        abl.mBuffers[0].mData = dst + (size_t)producedFrames * dec->channels;
        abl.mBuffers[0].mDataByteSize = want * (UInt32)(2 * dec->channels);  // reset EVERY call
        UInt32 gotPackets = want;  // PCM: 1 packet == 1 frame
        OSStatus s = AudioConverterFillComplexBuffer(dec->conv, md_input_proc, dec, &gotPackets, &abl, nullptr);
        producedFrames += (int)gotPackets;
        if (s == kMacApkNoDataNow) break;   // input drained mid-stream; converter still alive
        if (s != noErr && s != kAudioFileEndOfFileError) break;  // real error
        if (gotPackets == 0) break;         // EOS fully drained
    }

    // Opus pre-skip trim: drop leading encoder-priming samples from the
    // FRONT of decoder output, across as many calls as it takes (pre_skip
    // is typically a few hundred samples, well under one decoded frame).
    if (dec->opusPreSkipRemaining > 0 && producedFrames > 0) {
        int drop = dec->opusPreSkipRemaining < producedFrames ? dec->opusPreSkipRemaining : producedFrames;
        int keep = producedFrames - drop;
        if (keep > 0)
            std::memmove(dst, dst + (size_t)drop * dec->channels,
                        (size_t)keep * dec->channels * sizeof(int16_t));
        producedFrames = keep;
        dec->opusPreSkipRemaining -= drop;
    }
    return producedFrames * (int)(2 * dec->channels);
}

int macapk_md_dec_out_sample_rate(void* h) {
    Decoder* d = (Decoder*)h;
    if (!d) return 0;
    if (d->vorbisEngine) return macapk_vorbis_dec_out_sample_rate(d->vorbisEngine);
    return d->sampleRate;
}
int macapk_md_dec_out_channels(void* h) {
    Decoder* d = (Decoder*)h;
    if (!d) return 0;
    if (d->vorbisEngine) return macapk_vorbis_dec_out_channels(d->vorbisEngine);
    return d->channels;
}
void macapk_md_dec_close(void* h) {
    Decoder* d = (Decoder*)h;
    if (!d) return;
    if (d->vorbisEngine) macapk_vorbis_dec_close(d->vorbisEngine);
    if (d->conv) AudioConverterDispose(d->conv);
    delete d;
}

}  // extern "C"

// ===================== NativeMedia JNI surface =====================
// Mirrors the audio_backend.mm pattern: own JNINativeMethod[] table + a
// RegisterNativeMediaMethods(JNIEnv*) registrar called from
// native_methods.cpp::RegisterAllNativeMethods at boot.

namespace macapk { namespace media {

extern "C" {

jlong Java_com_macapk_loader_NativeMedia_nativeDemuxOpen(JNIEnv* env, jclass, jstring jpath) {
    if (!jpath) return 0;
    const char* p = env->GetStringUTFChars(jpath, nullptr);
    void* h = macapk_md_demux_open(p);
    env->ReleaseStringUTFChars(jpath, p);
    return (jlong)(uintptr_t)h;
}
jint  Java_com_macapk_loader_NativeMedia_nativeDemuxTrackCount(JNIEnv*, jclass, jlong h) { return macapk_md_demux_track_count((void*)(uintptr_t)h); }
jint  Java_com_macapk_loader_NativeMedia_nativeDemuxSampleRate(JNIEnv*, jclass, jlong h) { return macapk_md_demux_sample_rate((void*)(uintptr_t)h); }
jint  Java_com_macapk_loader_NativeMedia_nativeDemuxChannels(JNIEnv*, jclass, jlong h)   { return macapk_md_demux_channels((void*)(uintptr_t)h); }
jint  Java_com_macapk_loader_NativeMedia_nativeDemuxFormatId(JNIEnv*, jclass, jlong h)   { return macapk_md_demux_format_id((void*)(uintptr_t)h); }
jlong Java_com_macapk_loader_NativeMedia_nativeDemuxDurationUs(JNIEnv*, jclass, jlong h) { return macapk_md_demux_duration_us((void*)(uintptr_t)h); }
jbyteArray Java_com_macapk_loader_NativeMedia_nativeDemuxCsd0(JNIEnv* env, jclass, jlong h) {
    int n = macapk_md_demux_csd0_size((void*)(uintptr_t)h);
    if (n <= 0) return nullptr;
    jbyteArray arr = env->NewByteArray(n);
    std::vector<uint8_t> tmp(n);
    macapk_md_demux_csd0((void*)(uintptr_t)h, tmp.data(), n);
    env->SetByteArrayRegion(arr, 0, n, (const jbyte*)tmp.data());
    return arr;
}
jbyteArray Java_com_macapk_loader_NativeMedia_nativeDemuxCurrent(JNIEnv* env, jclass, jlong h) {
    int n = macapk_md_demux_current_size((void*)(uintptr_t)h);
    if (n < 0) return nullptr;
    jbyteArray arr = env->NewByteArray(n);
    if (n > 0) {
        std::vector<uint8_t> tmp(n);
        macapk_md_demux_current((void*)(uintptr_t)h, tmp.data(), n);
        env->SetByteArrayRegion(arr, 0, n, (const jbyte*)tmp.data());
    }
    return arr;
}
jlong Java_com_macapk_loader_NativeMedia_nativeDemuxSampleTime(JNIEnv*, jclass, jlong h) { return macapk_md_demux_sample_time((void*)(uintptr_t)h); }
jint  Java_com_macapk_loader_NativeMedia_nativeDemuxAdvance(JNIEnv*, jclass, jlong h)    { return macapk_md_demux_advance((void*)(uintptr_t)h); }
void  Java_com_macapk_loader_NativeMedia_nativeDemuxSeek(JNIEnv*, jclass, jlong h, jlong us) { macapk_md_demux_seek((void*)(uintptr_t)h, us); }
void  Java_com_macapk_loader_NativeMedia_nativeDemuxClose(JNIEnv*, jclass, jlong h)      { macapk_md_demux_close((void*)(uintptr_t)h); }

jlong Java_com_macapk_loader_NativeMedia_nativeDecOpen(JNIEnv* env, jclass, jint fmt, jint sr, jint ch, jbyteArray csd0) {
    std::vector<uint8_t> c;
    if (csd0) { jsize n = env->GetArrayLength(csd0); c.resize(n); env->GetByteArrayRegion(csd0, 0, n, (jbyte*)c.data()); }
    void* h = macapk_md_dec_open(fmt, sr, ch, c.empty()?nullptr:c.data(), (int)c.size());
    return (jlong)(uintptr_t)h;
}
// Decode one AU (au may be null when eos); returns the PCM bytes, or null on error.
jbyteArray Java_com_macapk_loader_NativeMedia_nativeDecDecode(JNIEnv* env, jclass, jlong h, jbyteArray au, jboolean eos) {
    std::vector<uint8_t> in;
    if (au) { jsize n = env->GetArrayLength(au); in.resize(n); env->GetByteArrayRegion(au, 0, n, (jbyte*)in.data()); }
    int ch = macapk_md_dec_out_channels((void*)(uintptr_t)h);
    if (ch <= 0) return nullptr;
    // One AAC packet -> up to ~2 * 1024 frames after priming; be generous.
    int cap = (int)((in.size() / 1) + 16384) * 2 * ch + 4096;
    std::vector<uint8_t> out(cap);
    int got = macapk_md_dec_decode((void*)(uintptr_t)h, in.empty()?nullptr:in.data(), (int)in.size(),
                                   eos?1:0, out.data(), cap);
    if (got < 0) return nullptr;
    jbyteArray arr = env->NewByteArray(got);
    if (got > 0) env->SetByteArrayRegion(arr, 0, got, (const jbyte*)out.data());
    return arr;
}
jint  Java_com_macapk_loader_NativeMedia_nativeDecOutSampleRate(JNIEnv*, jclass, jlong h) { return macapk_md_dec_out_sample_rate((void*)(uintptr_t)h); }
jint  Java_com_macapk_loader_NativeMedia_nativeDecOutChannels(JNIEnv*, jclass, jlong h)   { return macapk_md_dec_out_channels((void*)(uintptr_t)h); }
void  Java_com_macapk_loader_NativeMedia_nativeDecClose(JNIEnv*, jclass, jlong h)         { macapk_md_dec_close((void*)(uintptr_t)h); }

}  // extern "C"

static const JNINativeMethod kNativeMediaMethods[] = {
    {(char*)"nativeDemuxOpen",       (char*)"(Ljava/lang/String;)J", (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxOpen},
    {(char*)"nativeDemuxTrackCount", (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxTrackCount},
    {(char*)"nativeDemuxSampleRate", (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxSampleRate},
    {(char*)"nativeDemuxChannels",   (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxChannels},
    {(char*)"nativeDemuxFormatId",   (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxFormatId},
    {(char*)"nativeDemuxDurationUs", (char*)"(J)J",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxDurationUs},
    {(char*)"nativeDemuxCsd0",       (char*)"(J)[B", (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxCsd0},
    {(char*)"nativeDemuxCurrent",    (char*)"(J)[B", (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxCurrent},
    {(char*)"nativeDemuxSampleTime", (char*)"(J)J",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxSampleTime},
    {(char*)"nativeDemuxAdvance",    (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxAdvance},
    {(char*)"nativeDemuxSeek",       (char*)"(JJ)V", (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxSeek},
    {(char*)"nativeDemuxClose",      (char*)"(J)V",  (void*)Java_com_macapk_loader_NativeMedia_nativeDemuxClose},
    {(char*)"nativeDecOpen",         (char*)"(III[B)J", (void*)Java_com_macapk_loader_NativeMedia_nativeDecOpen},
    {(char*)"nativeDecDecode",       (char*)"(J[BZ)[B",  (void*)Java_com_macapk_loader_NativeMedia_nativeDecDecode},
    {(char*)"nativeDecOutSampleRate",(char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDecOutSampleRate},
    {(char*)"nativeDecOutChannels",  (char*)"(J)I",  (void*)Java_com_macapk_loader_NativeMedia_nativeDecOutChannels},
    {(char*)"nativeDecClose",        (char*)"(J)V",  (void*)Java_com_macapk_loader_NativeMedia_nativeDecClose},
};

// Called from native_methods.cpp::RegisterAllNativeMethods at boot.
void RegisterNativeMediaMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/NativeMedia");
    if (!cls) { std::fprintf(stderr, "[macapk] FindClass(NativeMedia) failed\n"); env->ExceptionClear(); return; }
    int count = sizeof(kNativeMediaMethods) / sizeof(kNativeMediaMethods[0]);
    if (env->RegisterNatives(cls, kNativeMediaMethods, count) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(NativeMedia) failed\n"); env->ExceptionClear();
    } else {
        std::fprintf(stderr, "[I] NativeMedia: registered %d methods\n", count);
    }
    env->DeleteLocalRef(cls);
}

}}  // namespace macapk::media
