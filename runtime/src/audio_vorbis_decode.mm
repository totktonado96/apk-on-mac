// audio_vorbis_decode.mm -- Ogg Vorbis DECODE backend for android.media.
// MediaCodec ("audio/vorbis"), reusing the stb_vorbis decoder already
// vendored at runtime/thirdparty/stb_vorbis.c (public domain) for the
// SoundPool/MediaPlayer clip path in audio_backend.mm.
//
// WHY THIS FILE EXISTS: macOS AudioToolbox has no public Vorbis decoder.
// AudioFormatGetProperty(kAudioFormatProperty_DecodeFormatIDs) on this host
// (macOS 26.5.2) DOES list a raw 'vorb' AudioFormatID, but there is no
// public kAudioFormatVorbis constant anywhere in the CoreAudioTypes SDK
// header (CoreAudioBaseTypes.h enumerates every other id this file uses --
// 'opus', 'ac-3', 'ec-3', 'samr', 'sawb', 'flac', 'alac' all have named
// constants; 'vorb' has none), and AudioConverterNew(kAudioFormatID='vorb')
// is therefore not a documented, callable contract -- it is very likely an
// internal/reserved id, not a third-party decode path. Per the owner's
// explicit ruling (2026-08-16, relayed in-session): ship Vorbis via a
// vendored software decoder instead of leaving the gap or guessing at an
// undocumented AudioConverter format id. See docs/audiotoolbox-codec-
// widening_2026-08-16.md for the measured DecodeFormatIDs list and the
// citation trail.
//
// WHY stb_vorbis INSTEAD OF FRESH libogg+libvorbis: stb_vorbis.c is already
// vendored, already statically linked into this exact executable target
// (runtime/CMakeLists.txt MACAPK_RUNTIME_SOURCES), and is public-domain --
// at least as license-clean as the BSD-3 the owner asked for, with zero new
// build-system surface (no new dylib, so scripts/relink_bundle_deps.sh /
// audit_bundle_deps.sh / launcher/InstallCore.swift's payload list need no
// changes at all -- it was already a self-contained static object in the
// one binary before this file existed). Pulling in libogg+libvorbis fresh
// would mean vendoring, building, and bundling a second, larger Vorbis
// decoder alongside a public-domain one already proven in this codebase's
// own SoundPool/MediaPlayer path (decode_clip() in audio_backend.mm) for
// no fidelity gain -- both are complete, spec-conformant Vorbis-I decoders.
//
// THE ARCHITECTURAL WRINKLE: stb_vorbis is an OGG-CONTAINER decoder (see
// start_decoder() in stb_vorbis.c: start_page(), PAGEFLAG_first_page,
// per-page segment/lacing tables, a CRC32-checked page header). It has no
// "decode this bare Vorbis packet" entry point -- everything is driven by
// its own internal Ogg page/segment reader. But Android's MediaCodec
// convention (frameworks/base media/java/android/media/MediaCodec.java,
// "Codec-specific Data" table: VORBIS csd-0 = Identification header,
// csd-1 = Setup header) hands us BARE, already Ogg-unwrapped packets: the
// platform's own extractor already did the Ogg demuxing upstream. So this
// file's real job is a small OGG PAGE ENCODER: wrap each bare packet (the
// two csd header packets once at open, then one packet per queued access
// unit) into a minimal, spec-valid, single-packet-per-page Ogg bitstream
// on the fly, and feed that synthetic stream to stb_vorbis's own pushdata
// API, which already knows how to parse a real Ogg stream. This is pure
// black-box use of stb_vorbis's PUBLIC API (stb_vorbis_open_pushdata /
// stb_vorbis_decode_frame_pushdata / stb_vorbis_get_info / stb_vorbis_close,
// forward-declared extern "C" below exactly like audio_backend.mm already
// forward-declares stb_vorbis_decode_memory for the same vendored file --
// no header include, matching that established idiom); it does not touch
// stb_vorbis.c's internals.
//
// Ogg page format (RFC 3533 section 6) + the CRC32 algorithm (section 5,
// polynomial 0x04c11db7, non-reflected, table-driven) are reimplemented
// here directly from the public spec -- not copied from stb_vorbis.c or
// any other project, since it is the standard on-disk format every Ogg
// writer must produce identically.
//
// Android's csd convention has no comment-header packet (it is metadata
// the decoder never needs), but stb_vorbis's start_decoder() unconditionally
// requires a well-formed second page whose packet begins with the Vorbis
// comment-header type byte 3 the six-byte "vorbis" signature, a vendor
// string and a comment count -- so this file synthesizes the minimal
// spec-valid EMPTY comment packet (vendor_length=0, comment_count=0)
// between the identification and setup packets.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <vector>

// ---- stb_vorbis pushdata API (runtime/thirdparty/stb_vorbis.c, public
// domain). Forward-declared here rather than included, matching the exact
// pattern audio_backend.mm already uses for stb_vorbis_decode_memory: the
// vendored file is a plain-C translation unit built directly into this
// same executable target (see runtime/CMakeLists.txt), so its symbols are
// C-linked and reachable from here with a matching extern "C" prototype. ----
extern "C" {
typedef struct stb_vorbis stb_vorbis;
typedef struct {
    unsigned int sample_rate;
    int channels;
    unsigned int setup_memory_required;
    unsigned int setup_temp_memory_required;
    unsigned int temp_memory_required;
    int max_frame_size;
} stb_vorbis_info;

stb_vorbis* stb_vorbis_open_pushdata(
    const unsigned char* datablock, int datablock_length_in_bytes,
    int* datablock_memory_consumed_in_bytes, int* error, const void* alloc_buffer);
int stb_vorbis_decode_frame_pushdata(
    stb_vorbis* f, const unsigned char* datablock, int datablock_length_in_bytes,
    int* channels, float*** output, int* samples);
stb_vorbis_info stb_vorbis_get_info(stb_vorbis* f);
int  stb_vorbis_get_error(stb_vorbis* f);
void stb_vorbis_close(stb_vorbis* f);
}  // extern "C"

namespace {

// ===================== Ogg CRC32 (RFC 3533 section 5) =====================
// Table-driven, non-reflected, polynomial 0x04c11db7, computed over the
// whole page with the 4-byte checksum field itself zeroed. Independently
// implemented from the public spec (the same algorithm every Ogg encoder
// must use to interoperate; not vendor code).
uint32_t g_ogg_crc_table[256];
bool     g_ogg_crc_ready = false;

void ogg_crc32_init() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t s = i << 24;
        for (int k = 0; k < 8; k++)
            s = (s << 1) ^ ((s & 0x80000000u) ? 0x04c11db7u : 0u);
        g_ogg_crc_table[i] = s;
    }
    g_ogg_crc_ready = true;
}
uint32_t ogg_crc32(const uint8_t* data, size_t len) {
    if (!g_ogg_crc_ready) ogg_crc32_init();
    uint32_t crc = 0;
    for (size_t i = 0; i < len; i++)
        crc = (crc << 8) ^ g_ogg_crc_table[((crc >> 24) ^ data[i]) & 0xffu];
    return crc;
}

inline void put_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
inline void put_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

// ===================== Minimal single-packet-per-page Ogg writer ==========
// Appends one packet to `out` as one or more Ogg pages (RFC 3533 section 6
// lacing: a packet longer than 255*255=65025 bytes spans multiple
// continuation pages; every packet this file ever emits -- a Vorbis ID
// header, a synthesized empty comment header, a setup header, or one audio
// frame -- is far smaller than that in practice, but the continuation path
// is still implemented so a pathological setup header cannot silently
// truncate).
struct OggPageWriter {
    uint32_t serial = 0x4d41504bu;  // 'MAPK', arbitrary but constant per stream
    int32_t  seq = 0;

    void appendPacket(std::vector<uint8_t>& out, const uint8_t* data, size_t len,
                       bool bos, bool eos) {
        size_t off = 0;
        bool firstIter = true;
        do {
            size_t chunk = len - off;
            bool continues = chunk > 65025;
            if (continues) chunk = 65025;

            std::vector<uint8_t> segs;
            size_t remaining = chunk;
            while (remaining >= 255) { segs.push_back(255); remaining -= 255; }
            if (!continues) segs.push_back((uint8_t)remaining);  // terminal lace

            uint8_t hdr[27] = {0};
            hdr[0]='O'; hdr[1]='g'; hdr[2]='g'; hdr[3]='S';
            hdr[4] = 0;  // stream_structure_version
            uint8_t type = 0;
            if (!firstIter)        type |= 0x01;  // continued packet
            if (bos && firstIter)  type |= 0x02;  // beginning of stream
            if (eos && !continues) type |= 0x04;  // end of stream
            hdr[5] = type;
            // Granule position: -1 while a packet is mid-continuation (no
            // packet completes on this page), 0 once it does. Decode-only
            // use never seeks, so an exact running sample count is not
            // required for correctness here.
            uint64_t gp = continues ? UINT64_C(0xFFFFFFFFFFFFFFFF) : 0;
            put_le64(hdr + 6, gp);
            put_le32(hdr + 14, serial);
            put_le32(hdr + 18, (uint32_t)seq);
            put_le32(hdr + 22, 0);  // checksum placeholder, patched below
            hdr[26] = (uint8_t)segs.size();
            seq++;

            size_t pageStart = out.size();
            out.insert(out.end(), hdr, hdr + 27);
            out.insert(out.end(), segs.begin(), segs.end());
            out.insert(out.end(), data + off, data + off + chunk);
            uint32_t crc = ogg_crc32(out.data() + pageStart, out.size() - pageStart);
            put_le32(out.data() + pageStart + 22, crc);

            off += chunk;
            firstIter = false;
        } while (off < len);
        if (len == 0) {
            // Zero-length packet (not expected for any packet this file
            // emits, but handled so a degenerate input cannot wedge the
            // writer): a single page with one zero-length lace.
            uint8_t hdr[28] = {0};
            hdr[0]='O'; hdr[1]='g'; hdr[2]='g'; hdr[3]='S';
            uint8_t type = 0;
            if (bos) type |= 0x02;
            if (eos) type |= 0x04;
            hdr[5] = type;
            put_le64(hdr + 6, 0);
            put_le32(hdr + 14, serial);
            put_le32(hdr + 18, (uint32_t)seq++);
            put_le32(hdr + 22, 0);
            hdr[26] = 1; hdr[27] = 0;
            size_t pageStart = out.size();
            out.insert(out.end(), hdr, hdr + 28);
            uint32_t crc = ogg_crc32(out.data() + pageStart, out.size() - pageStart);
            put_le32(out.data() + pageStart + 22, crc);
        }
    }
};

struct VorbisEngine {
    stb_vorbis*   v = nullptr;
    OggPageWriter writer;
    std::vector<uint8_t> pending;   // synthesized Ogg bytes not yet consumed
    std::vector<float>   carry;     // decoded samples (interleaved) not yet
                                     // drained into a caller buffer -- see
                                     // the "ran out of room" path in decode()
    int sampleRate = 0;
    int channels = 0;
};

inline int16_t clampf2s16(float x) {
    if (x > 1.0f) x = 1.0f;
    if (x < -1.0f) x = -1.0f;
    return (int16_t)lrintf(x * 32767.0f);
}

}  // namespace

extern "C" {

// Opens a Vorbis decoder from Android's two-packet csd convention
// (csd-0 = identification header, csd-1 = setup header; see the file
// header comment for why the comment packet in between is synthesized).
// Returns an opaque handle, or nullptr on failure (also logs the stb_vorbis
// error code so a real parse failure is visible rather than silent).
void* macapk_vorbis_dec_open(const void* idHdr, int idLen,
                             const void* setupHdr, int setupLen,
                             int* outSampleRate, int* outChannels) {
    if (!idHdr || idLen <= 0 || !setupHdr || setupLen <= 0) {
        std::fprintf(stderr, "[vorbis] open: missing id/setup header (id=%d setup=%d)\n",
                     idLen, setupLen);
        return nullptr;
    }
    VorbisEngine* e = new VorbisEngine();

    e->writer.appendPacket(e->pending, (const uint8_t*)idHdr, (size_t)idLen,
                            /*bos=*/true, /*eos=*/false);

    // Minimal spec-valid empty Vorbis comment packet: type=3, "vorbis"
    // validation string, vendor_length=0 (LE32), comment_count=0 (LE32),
    // framing bit set. See stb_vorbis.c start_decoder()'s second-packet
    // parse: it reads exactly this shape (packet type, 6-byte signature,
    // vendor length + bytes, comment count + per-comment length + bytes,
    // then a trailing framing byte with bit0 set).
    uint8_t comment[16] = {
        0x03, 'v','o','r','b','i','s',
        0,0,0,0,   // vendor_length = 0 (LE32)
        0,0,0,0,   // comment_list_length = 0 (LE32)
        0x01       // framing bit
    };
    e->writer.appendPacket(e->pending, comment, sizeof(comment), false, false);

    e->writer.appendPacket(e->pending, (const uint8_t*)setupHdr, (size_t)setupLen,
                            false, false);

    int consumed = 0, err = 0;
    e->v = stb_vorbis_open_pushdata(e->pending.data(), (int)e->pending.size(),
                                    &consumed, &err, nullptr);
    if (!e->v) {
        std::fprintf(stderr, "[vorbis] open_pushdata failed, stb_vorbis error=%d\n", err);
        delete e;
        return nullptr;
    }
    e->pending.erase(e->pending.begin(), e->pending.begin() + consumed);

    stb_vorbis_info info = stb_vorbis_get_info(e->v);
    e->sampleRate = (int)info.sample_rate;
    e->channels   = info.channels;
    if (e->channels <= 0) {
        std::fprintf(stderr, "[vorbis] open: bad channel count %d\n", e->channels);
        stb_vorbis_close(e->v);
        delete e;
        return nullptr;
    }
    if (outSampleRate) *outSampleRate = e->sampleRate;
    if (outChannels)   *outChannels   = e->channels;
    return e;
}

// Feed ONE raw Vorbis audio packet (au may be empty at eos) and drain
// decoded S16 interleaved PCM into out(cap). Mirrors macapk_md_dec_decode's
// contract exactly (media_decode.mm dispatches to this function by format
// id) so the two engines are interchangeable from the caller's point of
// view: returns PCM bytes written (>=0), or -1 on a hard error.
int macapk_vorbis_dec_decode(void* h, const void* au, int auLen, int eos,
                             void* out, int cap) {
    VorbisEngine* e = (VorbisEngine*)h;
    if (!e || !e->v || e->channels <= 0) return -1;

    if (au && auLen > 0) {
        e->writer.appendPacket(e->pending, (const uint8_t*)au, (size_t)auLen,
                               false, eos != 0);
    }

    int16_t* dst = (int16_t*)out;
    int capFrames = cap / (int)(2 * e->channels);
    int produced = 0;

    // Drain any samples stranded by a previous call whose output did not
    // fit the caller's buffer (see the tail of the loop below) before
    // asking stb_vorbis for more -- its output pointers are transient and
    // would otherwise be lost the moment we call it again.
    if (!e->carry.empty()) {
        int carryFrames = (int)(e->carry.size() / (size_t)e->channels);
        int take = carryFrames < capFrames ? carryFrames : capFrames;
        for (int i = 0; i < take * e->channels; i++) dst[i] = clampf2s16(e->carry[i]);
        produced += take;
        if (take < carryFrames)
            e->carry.erase(e->carry.begin(), e->carry.begin() + (size_t)take * e->channels);
        else
            e->carry.clear();
    }

    while (produced < capFrames && !e->pending.empty()) {
        int channels = 0; float** outputs = nullptr; int samples = 0;
        int used = stb_vorbis_decode_frame_pushdata(
            e->v, e->pending.data(), (int)e->pending.size(),
            &channels, &outputs, &samples);
        if (used == 0 && samples == 0) break;  // truly need more input
        e->pending.erase(e->pending.begin(), e->pending.begin() + used);
        if (samples <= 0) continue;            // priming frame or resync; keep going

        int room = capFrames - produced;
        int take = samples < room ? samples : room;
        for (int f = 0; f < take; f++)
            for (int c = 0; c < e->channels; c++)
                dst[(size_t)(produced + f) * e->channels + c] = clampf2s16(outputs[c][f]);
        produced += take;

        if (take < samples) {
            // Caller's buffer filled mid-frame: stash the remainder rather
            // than drop it (outputs[][] is only valid until the next
            // decode call, so this copy must happen now).
            for (int f = take; f < samples; f++)
                for (int c = 0; c < e->channels; c++)
                    e->carry.push_back(outputs[c][f]);
            break;
        }
    }
    return produced * (int)(2 * e->channels);
}

int  macapk_vorbis_dec_out_sample_rate(void* h) { VorbisEngine* e=(VorbisEngine*)h; return e?e->sampleRate:0; }
int  macapk_vorbis_dec_out_channels(void* h)    { VorbisEngine* e=(VorbisEngine*)h; return e?e->channels:0; }

void macapk_vorbis_dec_close(void* h) {
    VorbisEngine* e = (VorbisEngine*)h;
    if (!e) return;
    if (e->v) stb_vorbis_close(e->v);
    delete e;
}

}  // extern "C"
