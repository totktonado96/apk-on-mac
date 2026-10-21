// media_ndk.cpp -- NDK AMediaExtractor / AMediaCodec / AMediaFormat (libmediandk)
// backed by the runtime's real AUDIO decode core (runtime/src/media_decode.mm's
// macapk_md_* C entry points), item 3a.
//
// Native engines (Unity VideoPlayer, ExoPlayer-native, movie-texture code: Subway
// Surfers / Temple Run 2 / Among Us) import the full NDK media surface. Before
// v1.0.482 the macapk_md_* audio core did not exist, so these were honest no-op
// SENTINELS in bionic_shim.cpp ("graceful no-codec degrade"). Now that the audio
// core exists + is validated (AAC/MP3 -> S16 PCM via AudioToolbox), this file
// repoints AMedia* (AUDIO) onto it:
//   AMediaExtractor_* -> macapk_md_demux_*   (read-current / explicit-advance)
//   AMediaCodec_*  (audio mime) -> macapk_md_dec_*  (sync dequeue/queue protocol)
//   AMediaFormat   -> a real key/value bag
// VIDEO mimes stay on the graceful no-codec degrade until 3b (VideoToolbox).
//
// Bridge: the macapk_md_* symbols live in the runtime EXECUTABLE (not this shim
// dylib); we reach them with dlsym(RTLD_DEFAULT, ...) -- the exact pattern the
// OpenSL/AAudio output shims use for macapk_audio_* (bionic_shim.cpp). The 19
// macapk_md_* symbols are exported `T` from the runtime; if the bridge is somehow
// unavailable we fall back to the old graceful degrade (0 tracks / unsupported).
//
// Contracts pinned verbatim (AOSP frameworks/av/media/ndk, refs/heads/main):
//   docs/ndk-amedia-repoint-contract_2026-06-21.md. media_status_t = int (4B).
//   AMediaCodecBufferInfo = {int32 offset; int32 size; int64 presentationTimeUs;
//   uint32 flags;} (24B, pts@8, flags@16). dequeue funcs return ssize_t index or
//   a NEGATIVE INFO_* code (-1 TRY_AGAIN / -2 FORMAT_CHANGED / -3 BUFFERS_CHANGED),
//   NOT a media_status_t. AAC = "audio/mp4a-latm", MP3 = "audio/mpeg".

#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cmath>
#include <cctype>

// ----- NDK constants (verbatim values; see docs note) -----------------------
namespace {
constexpr int kAMEDIA_OK                 = 0;
constexpr int kAMEDIA_ERR_UNSUPPORTED    = -10002;
constexpr int kAMEDIA_ERR_INVALID_OBJECT = -10003;
constexpr int kAMEDIA_ERR_INVALID_PARAM  = -10004;
// ssize_t dequeue status codes (NOT media_status_t)
constexpr int kINFO_TRY_AGAIN_LATER      = -1;
constexpr int kINFO_OUTPUT_FORMAT_CHANGED= -2;
constexpr uint32_t kBUFFER_FLAG_EOS      = 4;
constexpr uint32_t kSAMPLE_FLAG_SYNC     = 1;
constexpr int kNBUF = 8;                  // input + output buffer slots
constexpr size_t kInCap  = 256 * 1024;    // input buffer capacity (> any AAC/MP3 AU)
constexpr size_t kDecCap = 256 * 1024;    // per-decode PCM scratch
// Sanity cap on how many bytes we will materialize to a temp file for the
// fd / custom-data-source paths (the audio core opens a PATH, not a stream).
constexpr int64_t kMaxSrcBytes = 256LL << 20;

// AMediaCodecBufferInfo: 24B, must match the NDK layout exactly (the guest
// passes a pointer; dequeueOutputBuffer fills it). Verified vs NdkMediaCodec.h.
struct AMediaCodecBufferInfo {
    int32_t  offset;
    int32_t  size;
    int64_t  presentationTimeUs;
    uint32_t flags;
};
static_assert(sizeof(AMediaCodecBufferInfo) == 24, "AMediaCodecBufferInfo must be 24B");

// ----- bridge to the runtime's macapk_md_* core (dlsym RTLD_DEFAULT) ---------
struct MdApi {
    void*   (*demux_open)(const char*)              = nullptr;
    int     (*demux_track_count)(void*)             = nullptr;
    int     (*demux_sample_rate)(void*)             = nullptr;
    int     (*demux_channels)(void*)                = nullptr;
    int     (*demux_format_id)(void*)               = nullptr;
    int64_t (*demux_duration_us)(void*)             = nullptr;
    int     (*demux_csd0_size)(void*)               = nullptr;
    int     (*demux_csd0)(void*, void*, int)        = nullptr;
    int     (*demux_current_size)(void*)            = nullptr;
    int     (*demux_current)(void*, void*, int)     = nullptr;
    int64_t (*demux_sample_time)(void*)             = nullptr;
    int     (*demux_advance)(void*)                 = nullptr;
    void    (*demux_seek)(void*, int64_t)           = nullptr;
    void    (*demux_close)(void*)                   = nullptr;
    void*   (*dec_open)(int,int,int,const void*,int)= nullptr;
    int     (*dec_decode)(void*,const void*,int,int,void*,int) = nullptr;
    int     (*dec_out_sample_rate)(void*)           = nullptr;
    int     (*dec_out_channels)(void*)              = nullptr;
    void    (*dec_close)(void*)                     = nullptr;
    bool ok = false;
};
MdApi g_md;
std::once_flag g_md_once;
void md_load() {
#define MD_LD(field, sym) g_md.field = (decltype(g_md.field))dlsym(RTLD_DEFAULT, sym)
    MD_LD(demux_open,        "macapk_md_demux_open");
    MD_LD(demux_track_count, "macapk_md_demux_track_count");
    MD_LD(demux_sample_rate, "macapk_md_demux_sample_rate");
    MD_LD(demux_channels,    "macapk_md_demux_channels");
    MD_LD(demux_format_id,   "macapk_md_demux_format_id");
    MD_LD(demux_duration_us, "macapk_md_demux_duration_us");
    MD_LD(demux_csd0_size,   "macapk_md_demux_csd0_size");
    MD_LD(demux_csd0,        "macapk_md_demux_csd0");
    MD_LD(demux_current_size,"macapk_md_demux_current_size");
    MD_LD(demux_current,     "macapk_md_demux_current");
    MD_LD(demux_sample_time, "macapk_md_demux_sample_time");
    MD_LD(demux_advance,     "macapk_md_demux_advance");
    MD_LD(demux_seek,        "macapk_md_demux_seek");
    MD_LD(demux_close,       "macapk_md_demux_close");
    MD_LD(dec_open,          "macapk_md_dec_open");
    MD_LD(dec_decode,        "macapk_md_dec_decode");
    MD_LD(dec_out_sample_rate,"macapk_md_dec_out_sample_rate");
    MD_LD(dec_out_channels,  "macapk_md_dec_out_channels");
    MD_LD(dec_close,         "macapk_md_dec_close");
#undef MD_LD
    g_md.ok = g_md.demux_open && g_md.demux_track_count && g_md.demux_current
           && g_md.demux_advance && g_md.demux_close && g_md.dec_open
           && g_md.dec_decode && g_md.dec_close;
    if (!g_md.ok)
        std::fprintf(stderr,
            "[amedia] macapk_md_* bridge unavailable -> graceful no-codec degrade\n");
    else
        std::fprintf(stderr, "[amedia] NDK media repointed onto macapk_md_* audio core\n");
}
MdApi* md() { std::call_once(g_md_once, md_load); return g_md.ok ? &g_md : nullptr; }

// ----- objects --------------------------------------------------------------
constexpr uint32_t kFmtMagic = 0x414d4654; // 'AMFT'
constexpr uint32_t kExtMagic = 0x414d4558; // 'AMEX'
constexpr uint32_t kCodMagic = 0x414d4344; // 'AMCD'

struct AmFormat {
    uint32_t magic = kFmtMagic;
    std::map<std::string, int32_t>              i32;
    std::map<std::string, int64_t>              i64;
    std::map<std::string, float>                f32;
    std::map<std::string, std::string>          str;
    std::map<std::string, std::vector<uint8_t>> buf;
    std::string toStr;   // backing storage for toString()'s const char*
};

// AMediaDataSource (API 28). AOSP shape, verbatim from
// frameworks/av/media/ndk/NdkMediaDataSource.cpp `struct AMediaDataSource`:
//   { void *userdata; AMediaDataSourceReadAt readAt; AMediaDataSourceGetSize
//     getSize; AMediaDataSourceClose close; AMediaDataSourceGetAvailableSize
//     getAvailableSize; sp<DataSource> mImpl; uint32_t mFlags; }
// The guest only ever holds an opaque AMediaDataSource*, so the callback
// quintuple is the entire observable surface; mImpl/mFlags exist solely for
// AMediaDataSource_newUri (the HTTP source), which we do not provide.
//
// off64_t is int64_t on EVERY Bionic ABI, so the callback signatures below use
// int64_t rather than a host type. Bionic bionic/libc/include/sys/types.h:
//   LP64:  `typedef int64_t off_t; typedef off_t loff_t; typedef loff_t off64_t;`
//   ILP32: `typedef __kernel_loff_t loff_t; typedef loff_t off64_t;` (long long)
// Darwin has no off64_t at all (sys/_types/_off_t.h: `typedef __darwin_off_t
// off_t;` == __int64_t), so int64_t is the exact 8-byte value the guest passes.
constexpr uint32_t kDsMagic = 0x414d4453; // 'AMDS'
typedef ssize_t (*AmdsReadAt)(void* userdata, int64_t offset, void* buffer, size_t size);
typedef ssize_t (*AmdsGetSize)(void* userdata);
typedef void    (*AmdsClose)(void* userdata);
typedef ssize_t (*AmdsGetAvailableSize)(void* userdata, int64_t offset);

struct AmDataSource {
    uint32_t             magic            = kDsMagic;
    void*                userdata         = nullptr;
    AmdsReadAt           readAt           = nullptr;
    AmdsGetSize          getSize          = nullptr;
    AmdsClose            close            = nullptr;
    AmdsGetAvailableSize getAvailableSize = nullptr;
};

struct AmExtractor {
    uint32_t magic = kExtMagic;
    void*       demux = nullptr;     // macapk_md_demux handle
    std::string tmpPath;             // temp file for setDataSourceFd (unlink on delete)
};

struct AmOut { std::vector<uint8_t> pcm; int64_t pts = 0; uint32_t flags = 0; };

struct AmCodec {
    uint32_t magic = kCodMagic;
    bool audio = false;              // backed by macapk_md_dec
    int  fmtId = 0;                  // 1=AAC, 2=MP3
    std::string mime;
    void* dec = nullptr;             // macapk_md_dec handle (after configure)
    int  sr = 0, ch = 0;
    std::vector<uint8_t> csd0;
    bool started = false, eos = false, formatSent = false;
    std::mutex mu;
    std::vector<uint8_t> inBuf[kNBUF];
    bool inBusy[kNBUF] = {false};
    std::vector<uint8_t> outBuf[kNBUF];
    size_t outLen[kNBUF] = {0};
    bool outBusy[kNBUF] = {false};
    std::deque<AmOut> outQ;
    std::vector<uint8_t> scratch;    // PCM scratch for dec_decode
};

inline AmFormat*    asFmt(void* p) { return (p && reinterpret_cast<AmFormat*>(p)->magic    == kFmtMagic) ? reinterpret_cast<AmFormat*>(p)    : nullptr; }
inline AmExtractor* asExt(void* p) { return (p && reinterpret_cast<AmExtractor*>(p)->magic == kExtMagic) ? reinterpret_cast<AmExtractor*>(p) : nullptr; }
inline AmCodec*     asCod(void* p) { return (p && reinterpret_cast<AmCodec*>(p)->magic     == kCodMagic) ? reinterpret_cast<AmCodec*>(p)     : nullptr; }
inline AmDataSource* asDs(void* p) { return (p && reinterpret_cast<AmDataSource*>(p)->magic == kDsMagic) ? reinterpret_cast<AmDataSource*>(p) : nullptr; }

inline int  mimeFmtId(const char* mime) {
    if (!mime) return 0;
    if (!std::strcmp(mime, "audio/mp4a-latm")) return 1; // AAC
    if (!std::strcmp(mime, "audio/mpeg"))      return 2; // MP3
    return 0;
}
inline const char* fmtIdMime(int id) { return id == 1 ? "audio/mp4a-latm" : id == 2 ? "audio/mpeg" : "audio/unknown"; }
// Infer a codec mime from a component name (createCodecByName). Best-effort.
inline int nameFmtId(const char* name) {
    if (!name) return 0;
    std::string n(name); for (auto& c : n) c = (char)tolower(c);
    if (n.find("aac") != std::string::npos) return 1;
    if (n.find("mp3") != std::string::npos || n.find("mpeg") != std::string::npos) return 2;
    return 0;
}
}  // namespace

// ============================ AMediaFormat ==================================
extern "C" void* __macapk_arm64_AMediaFormat_new(void) { return new AmFormat(); }
extern "C" int   __macapk_arm64_AMediaFormat_delete(void* f) { delete asFmt(f); return kAMEDIA_OK; }

extern "C" bool __macapk_arm64_AMediaFormat_getInt32(void* f, const char* name, int32_t* out) {
    AmFormat* m = asFmt(f); if (!m || !name || !out) return false;
    auto it = m->i32.find(name); if (it == m->i32.end()) return false;
    *out = it->second; return true;
}
extern "C" bool __macapk_arm64_AMediaFormat_getInt64(void* f, const char* name, int64_t* out) {
    AmFormat* m = asFmt(f); if (!m || !name || !out) return false;
    auto it = m->i64.find(name); if (it == m->i64.end()) return false;
    *out = it->second; return true;
}
extern "C" bool __macapk_arm64_AMediaFormat_getFloat(void* f, const char* name, float* out) {
    AmFormat* m = asFmt(f); if (!m || !name || !out) return false;
    auto it = m->f32.find(name); if (it == m->f32.end()) return false;
    *out = it->second; return true;
}
extern "C" bool __macapk_arm64_AMediaFormat_getSize(void* f, const char* name, size_t* out) {
    AmFormat* m = asFmt(f); if (!m || !name || !out) return false;
    auto it = m->buf.find(name); if (it == m->buf.end()) return false;
    *out = it->second.size(); return true;
}
extern "C" bool __macapk_arm64_AMediaFormat_getBuffer(void* f, const char* name, void** data, size_t* size) {
    AmFormat* m = asFmt(f); if (!m || !name || !data || !size) return false;
    auto it = m->buf.find(name); if (it == m->buf.end() || it->second.empty()) return false;
    *data = it->second.data(); *size = it->second.size(); return true;
}
extern "C" bool __macapk_arm64_AMediaFormat_getString(void* f, const char* name, const char** out) {
    AmFormat* m = asFmt(f); if (!m || !name || !out) return false;
    auto it = m->str.find(name); if (it == m->str.end()) return false;
    *out = it->second.c_str(); return true;
}
extern "C" void __macapk_arm64_AMediaFormat_setInt32(void* f, const char* name, int32_t v) { AmFormat* m = asFmt(f); if (m && name) m->i32[name] = v; }
extern "C" void __macapk_arm64_AMediaFormat_setInt64(void* f, const char* name, int64_t v) { AmFormat* m = asFmt(f); if (m && name) m->i64[name] = v; }
extern "C" void __macapk_arm64_AMediaFormat_setFloat(void* f, const char* name, float v)   { AmFormat* m = asFmt(f); if (m && name) m->f32[name] = v; }
extern "C" void __macapk_arm64_AMediaFormat_setString(void* f, const char* name, const char* v) { AmFormat* m = asFmt(f); if (m && name && v) m->str[name] = v; }
extern "C" void __macapk_arm64_AMediaFormat_setBuffer(void* f, const char* name, const void* data, size_t size) {
    AmFormat* m = asFmt(f); if (!m || !name) return;
    auto& b = m->buf[name]; b.assign((const uint8_t*)data, (const uint8_t*)data + (data ? size : 0));
}
extern "C" const char* __macapk_arm64_AMediaFormat_toString(void* f) {
    AmFormat* m = asFmt(f); if (!m) return "";
    m->toStr.clear();
    for (auto& kv : m->str) { m->toStr += kv.first; m->toStr += "=string("; m->toStr += kv.second; m->toStr += ") "; }
    for (auto& kv : m->i32) { m->toStr += kv.first; m->toStr += "=int32(" + std::to_string(kv.second) + ") "; }
    for (auto& kv : m->i64) { m->toStr += kv.first; m->toStr += "=int64(" + std::to_string(kv.second) + ") "; }
    for (auto& kv : m->buf) { m->toStr += kv.first; m->toStr += "=buffer(" + std::to_string(kv.second.size()) + "B) "; }
    return m->toStr.c_str();
}

// ============================ AMediaDataSource ==============================
// Contract: media/ndk/include/media/NdkMediaDataSource.h (new/delete/
// setUserdata/setReadAt/setGetSize/setClose = API 28; close +
// setGetAvailableSize = API 29) with bodies from NdkMediaDataSource.cpp.
// AOSP's setters are bare field stores and _delete is a bare `delete` that does
// NOT invoke the close callback (confirmed in NdkMediaDataSource.cpp's
// AMediaDataSource_delete and in ~NdkDataSource, which only forwards to it) --
// so an app that wants its close callback run must call AMediaDataSource_close.
// Our only addition is the magic/NULL guard every object in this file carries,
// because a stale pointer out of guest code must not fault inside the shim.
extern "C" void* __macapk_arm64_AMediaDataSource_new(void) { return new AmDataSource(); }
extern "C" void  __macapk_arm64_AMediaDataSource_delete(void* d) { delete asDs(d); }
extern "C" void  __macapk_arm64_AMediaDataSource_setUserdata(void* d, void* userdata) { if (AmDataSource* s = asDs(d)) s->userdata = userdata; }
extern "C" void  __macapk_arm64_AMediaDataSource_setReadAt(void* d, AmdsReadAt cb)   { if (AmDataSource* s = asDs(d)) s->readAt  = cb; }
extern "C" void  __macapk_arm64_AMediaDataSource_setGetSize(void* d, AmdsGetSize cb) { if (AmDataSource* s = asDs(d)) s->getSize = cb; }
extern "C" void  __macapk_arm64_AMediaDataSource_setClose(void* d, AmdsClose cb)     { if (AmDataSource* s = asDs(d)) s->close   = cb; }
extern "C" void  __macapk_arm64_AMediaDataSource_setGetAvailableSize(void* d, AmdsGetAvailableSize cb) { if (AmDataSource* s = asDs(d)) s->getAvailableSize = cb; }
// AOSP is `return mSource->close(mSource->userdata);` with no guard at all, so
// a source whose close callback was never set faults there. We use the same
// close!=NULL && userdata!=NULL pair NdkDataSource::close() itself checks.
extern "C" void  __macapk_arm64_AMediaDataSource_close(void* d) {
    AmDataSource* s = asDs(d);
    if (s && s->close && s->userdata) s->close(s->userdata);
}

// ============================ AMediaExtractor ===============================
extern "C" void* __macapk_arm64_AMediaExtractor_new(void) { return new AmExtractor(); }

static void ext_close_demux(AmExtractor* e) {
    if (e->demux) { if (MdApi* m = md()) m->demux_close(e->demux); e->demux = nullptr; }
    if (!e->tmpPath.empty()) { ::unlink(e->tmpPath.c_str()); e->tmpPath.clear(); }
}
extern "C" int __macapk_arm64_AMediaExtractor_delete(void* x) {
    AmExtractor* e = asExt(x); if (!e) return kAMEDIA_OK;
    ext_close_demux(e); delete e; return kAMEDIA_OK;
}
extern "C" int __macapk_arm64_AMediaExtractor_setDataSource(void* x, const char* loc) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !m || !loc) return kAMEDIA_ERR_UNSUPPORTED;
    ext_close_demux(e);
    e->demux = m->demux_open(loc);
    if (!e->demux || m->demux_track_count(e->demux) <= 0) {
        if (e->demux) { m->demux_close(e->demux); e->demux = nullptr; }
        return kAMEDIA_ERR_UNSUPPORTED;   // unsupported container -> 0 tracks, graceful
    }
    return kAMEDIA_OK;
}
// Read the [offset, offset+length) region of `fd` into a temp file (the audio
// core opens a PATH), then demux it. Common for APK-packed media assets.
extern "C" int __macapk_arm64_AMediaExtractor_setDataSourceFd(void* x, int fd, int64_t offset, int64_t length) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !m) return kAMEDIA_ERR_UNSUPPORTED;
    if (fd < 0) return kAMEDIA_ERR_INVALID_PARAM;
    struct stat st; int64_t fsz = (::fstat(fd, &st) == 0) ? (int64_t)st.st_size : 0;
    if (length <= 0 || (fsz && offset + length > fsz)) length = (fsz > offset) ? fsz - offset : 0;
    if (length <= 0 || length > kMaxSrcBytes) return kAMEDIA_ERR_UNSUPPORTED;   // sanity cap
    char tmpl[] = "/tmp/macapk_amedia_XXXXXX";
    int tfd = ::mkstemp(tmpl);
    if (tfd < 0) return kAMEDIA_ERR_UNSUPPORTED;
    std::vector<uint8_t> buf(64 * 1024);
    int64_t remaining = length, pos = offset; bool okcopy = true;
    while (remaining > 0) {
        size_t want = (size_t)std::min<int64_t>(remaining, (int64_t)buf.size());
        ssize_t r = ::pread(fd, buf.data(), want, (off_t)pos);
        if (r <= 0) { okcopy = (remaining != length); break; }   // partial-but-some is OK
        if (::write(tfd, buf.data(), (size_t)r) != r) { okcopy = false; break; }
        pos += r; remaining -= r;
    }
    ::close(tfd);
    if (!okcopy) { ::unlink(tmpl); return kAMEDIA_ERR_UNSUPPORTED; }
    ext_close_demux(e);
    e->demux = m->demux_open(tmpl);
    if (!e->demux || m->demux_track_count(e->demux) <= 0) {
        if (e->demux) { m->demux_close(e->demux); e->demux = nullptr; }
        ::unlink(tmpl); return kAMEDIA_ERR_UNSUPPORTED;
    }
    e->tmpPath = tmpl;   // keep alive while demuxing; unlinked on delete
    return kAMEDIA_OK;
}
// AMediaExtractor_setDataSourceCustom (API 28), NdkMediaExtractor.cpp:
//   `return translate_error(mData->mImpl->setDataSource(new NdkDataSource(src)));`
// NdkDataSource's constructor COPIES userdata + the callbacks out of `src` into
// a fresh AMediaDataSource, so the extractor never aliases the caller's object:
// the app may delete its AMediaDataSource the moment this returns. We copy the
// same way (here, by consuming the callbacks before returning).
//
// AOSP then reads LAZILY -- stagefright calls NdkDataSource::readAt as it
// parses. Our audio core (macapk_md_demux_open) opens a PATH through
// AudioToolbox AudioFileOpenURL, so the bytes have to be on disk before the
// demuxer can look at them. We therefore pull the source's whole readable range
// through the app's OWN readAt callback into a temp file and demux that. Every
// byte still comes from the app (a decrypt-on-read, in-memory, or APK-packed
// source stays correct); the divergence is WHEN the reads happen, the same
// trade setDataSourceFd already makes above. True streaming needs
// macapk_md_demux to grow an AudioFileOpenWithCallbacks variant in
// runtime/src/media_decode.mm.
extern "C" int __macapk_arm64_AMediaExtractor_setDataSourceCustom(void* x, void* srcVoid) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !m) return kAMEDIA_ERR_UNSUPPORTED;
    AmDataSource* s = asDs(srcVoid);
    if (!s) return kAMEDIA_ERR_INVALID_PARAM;
    // NdkDataSource::readAt returns -1 unless BOTH readAt and userdata are set,
    // and getSize returns NO_INIT under the same pair. Mirror that: such a
    // source can never yield a byte, so there is nothing to open.
    if (!s->readAt || !s->userdata) return kAMEDIA_ERR_UNSUPPORTED;

    // AMediaDataSourceGetSize: "Return the size of data source in bytes, or -1
    // if the size is unknown." Unknown size just means we read until EOS.
    int64_t known = s->getSize ? (int64_t)s->getSize(s->userdata) : -1;
    if (known > kMaxSrcBytes) return kAMEDIA_ERR_UNSUPPORTED;

    char tmpl[] = "/tmp/macapk_amedia_XXXXXX";
    int tfd = ::mkstemp(tmpl);
    if (tfd < 0) return kAMEDIA_ERR_UNSUPPORTED;
    std::vector<uint8_t> buf(64 * 1024);
    int64_t pos = 0; bool okcopy = true;
    for (;;) {
        int64_t want = (int64_t)buf.size();
        if (known >= 0) want = std::min<int64_t>(want, known - pos);
        if (want <= 0) break;                       // reached the declared size
        // AMediaDataSourceReadAt: "write up to `size` bytes into `buffer`, and
        // return the number of bytes written ... Return -1 to indicate that end
        // of stream is reached." A short read is legal and NOT end of stream.
        ssize_t r = s->readAt(s->userdata, pos, buf.data(), (size_t)want);
        if (r <= 0) break;                          // -1 = EOS; 0 = nothing more
        if (r > want) { okcopy = false; break; }    // callback overran our buffer
        if (::write(tfd, buf.data(), (size_t)r) != r) { okcopy = false; break; }
        pos += r;
        if (pos > kMaxSrcBytes) { okcopy = false; break; }
    }
    ::close(tfd);
    if (!okcopy || pos <= 0) { ::unlink(tmpl); return kAMEDIA_ERR_UNSUPPORTED; }
    ext_close_demux(e);
    e->demux = m->demux_open(tmpl);
    if (!e->demux || m->demux_track_count(e->demux) <= 0) {
        if (e->demux) { m->demux_close(e->demux); e->demux = nullptr; }
        ::unlink(tmpl); return kAMEDIA_ERR_UNSUPPORTED;
    }
    e->tmpPath = tmpl;   // keep alive while demuxing; unlinked on delete
    return kAMEDIA_OK;
}
extern "C" size_t __macapk_arm64_AMediaExtractor_getTrackCount(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    return (e && e->demux && m) ? (size_t)m->demux_track_count(e->demux) : 0;
}
extern "C" void* __macapk_arm64_AMediaExtractor_getTrackFormat(void* x, size_t idx) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    AmFormat* f = new AmFormat();
    if (e && e->demux && m && idx == 0) {
        int id = m->demux_format_id(e->demux);
        f->str["mime"]          = fmtIdMime(id);
        f->i32["sample-rate"]   = m->demux_sample_rate(e->demux);
        f->i32["channel-count"] = m->demux_channels(e->demux);
        f->i64["durationUs"]    = m->demux_duration_us(e->demux);
        f->i32["max-input-size"]= (int32_t)kInCap;
        int cs = m->demux_csd0_size(e->demux);
        if (cs > 0) { std::vector<uint8_t> c(cs); m->demux_csd0(e->demux, c.data(), cs); f->buf["csd-0"] = std::move(c); }
    }
    return f;
}
extern "C" int  __macapk_arm64_AMediaExtractor_selectTrack(void* x, size_t)   { return asExt(x) ? kAMEDIA_OK : kAMEDIA_ERR_INVALID_OBJECT; }
extern "C" int  __macapk_arm64_AMediaExtractor_unselectTrack(void* x, size_t) { return asExt(x) ? kAMEDIA_OK : kAMEDIA_ERR_INVALID_OBJECT; }
extern "C" int  __macapk_arm64_AMediaExtractor_seekTo(void* x, int64_t us, int /*mode*/) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (e && e->demux && m) { m->demux_seek(e->demux, us); return kAMEDIA_OK; }
    return kAMEDIA_ERR_UNSUPPORTED;
}
extern "C" bool __macapk_arm64_AMediaExtractor_advance(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    return (e && e->demux && m) ? (m->demux_advance(e->demux) != 0) : false;
}
extern "C" ssize_t __macapk_arm64_AMediaExtractor_readSampleData(void* x, uint8_t* buffer, size_t cap) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !e->demux || !m) return -1;
    return (ssize_t)m->demux_current(e->demux, buffer, (int)cap);   // -1 at EOS
}
extern "C" ssize_t __macapk_arm64_AMediaExtractor_getSampleSize(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !e->demux || !m) return -1;
    return (ssize_t)m->demux_current_size(e->demux);
}
extern "C" int64_t __macapk_arm64_AMediaExtractor_getSampleTime(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !e->demux || !m) return -1;
    return m->demux_sample_time(e->demux);
}
extern "C" uint32_t __macapk_arm64_AMediaExtractor_getSampleFlags(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !e->demux || !m) return (uint32_t)-1;
    return (m->demux_current_size(e->demux) >= 0) ? kSAMPLE_FLAG_SYNC : 0; // audio AUs are sync
}
extern "C" int __macapk_arm64_AMediaExtractor_getSampleTrackIndex(void* x) {
    AmExtractor* e = asExt(x); MdApi* m = md();
    if (!e || !e->demux || !m) return -1;
    return (m->demux_current_size(e->demux) >= 0) ? 0 : -1;
}

// ============================ AMediaCodec ===================================
extern "C" void* __macapk_arm64_AMediaCodec_createDecoderByType(const char* mime) {
    AmCodec* c = new AmCodec();
    c->fmtId = mimeFmtId(mime); c->audio = (c->fmtId != 0); if (mime) c->mime = mime;
    return c;
}
extern "C" void* __macapk_arm64_AMediaCodec_createCodecByName(const char* name) {
    AmCodec* c = new AmCodec();
    c->fmtId = nameFmtId(name); c->audio = (c->fmtId != 0); if (name) c->mime = fmtIdMime(c->fmtId);
    return c;
}
extern "C" int __macapk_arm64_AMediaCodec_delete(void* h) {
    AmCodec* c = asCod(h); if (!c) return kAMEDIA_OK;
    if (c->dec) { if (MdApi* m = md()) m->dec_close(c->dec); c->dec = nullptr; }
    delete c; return kAMEDIA_OK;
}
extern "C" int __macapk_arm64_AMediaCodec_configure(void* h, const void* fmt, void* /*surface*/, void* /*crypto*/, uint32_t /*flags*/) {
    AmCodec* c = asCod(h); MdApi* m = md();
    if (!c) return kAMEDIA_ERR_INVALID_OBJECT;
    if (!c->audio || !m) return kAMEDIA_ERR_UNSUPPORTED;   // VIDEO / no bridge -> graceful no-codec
    AmFormat* f = asFmt(const_cast<void*>(fmt));
    if (f) {
        auto si = f->i32.find("sample-rate");   if (si != f->i32.end()) c->sr = si->second;
        auto ci = f->i32.find("channel-count"); if (ci != f->i32.end()) c->ch = ci->second;
        auto bi = f->buf.find("csd-0");         if (bi != f->buf.end()) c->csd0 = bi->second;
        auto mi = f->str.find("mime"); if (mi != f->str.end()) { int id = mimeFmtId(mi->second.c_str()); if (id) c->fmtId = id; }
    }
    if (c->sr <= 0 || c->ch <= 0) return kAMEDIA_ERR_UNSUPPORTED;
    c->dec = m->dec_open(c->fmtId, c->sr, c->ch, c->csd0.empty() ? nullptr : c->csd0.data(), (int)c->csd0.size());
    if (!c->dec) return kAMEDIA_ERR_UNSUPPORTED;
    c->scratch.resize(kDecCap);
    return kAMEDIA_OK;
}
extern "C" int __macapk_arm64_AMediaCodec_start(void* h) {
    AmCodec* c = asCod(h); if (!c) return kAMEDIA_ERR_INVALID_OBJECT;
    if (!c->dec) return kAMEDIA_ERR_UNSUPPORTED;   // video / unconfigured
    c->started = true; return kAMEDIA_OK;
}
extern "C" int __macapk_arm64_AMediaCodec_stop(void* h) { AmCodec* c = asCod(h); if (c) c->started = false; return kAMEDIA_OK; }
extern "C" int __macapk_arm64_AMediaCodec_flush(void* h) {
    AmCodec* c = asCod(h); if (!c) return kAMEDIA_OK;
    std::lock_guard<std::mutex> lk(c->mu);
    c->outQ.clear(); c->eos = false;
    for (int i = 0; i < kNBUF; i++) { c->inBusy[i] = false; c->outBusy[i] = false; c->outLen[i] = 0; }
    return kAMEDIA_OK;   // NOTE: the underlying decoder keeps its state (no dec_reset in the C core yet)
}
extern "C" ssize_t __macapk_arm64_AMediaCodec_dequeueInputBuffer(void* h, int64_t /*timeoutUs*/) {
    AmCodec* c = asCod(h); if (!c || !c->dec) return kINFO_TRY_AGAIN_LATER;
    std::lock_guard<std::mutex> lk(c->mu);
    for (int i = 0; i < kNBUF; i++) if (!c->inBusy[i]) {
        if (c->inBuf[i].size() < kInCap) c->inBuf[i].resize(kInCap);
        c->inBusy[i] = true; return i;
    }
    return kINFO_TRY_AGAIN_LATER;
}
extern "C" uint8_t* __macapk_arm64_AMediaCodec_getInputBuffer(void* h, size_t idx, size_t* out_size) {
    AmCodec* c = asCod(h); if (!c || idx >= (size_t)kNBUF) { if (out_size) *out_size = 0; return nullptr; }
    if (c->inBuf[idx].size() < kInCap) c->inBuf[idx].resize(kInCap);
    if (out_size) *out_size = c->inBuf[idx].size();
    return c->inBuf[idx].data();
}
extern "C" int __macapk_arm64_AMediaCodec_queueInputBuffer(void* h, size_t idx, int64_t offset, size_t size, uint64_t time, uint32_t flags) {
    AmCodec* c = asCod(h); MdApi* m = md();
    if (!c || !c->dec || !m || idx >= (size_t)kNBUF) return kAMEDIA_ERR_INVALID_OBJECT;
    std::lock_guard<std::mutex> lk(c->mu);
    const uint8_t* au = c->inBuf[idx].data() + offset;
    bool isEos = (flags & kBUFFER_FLAG_EOS) != 0;
    if (size > 0) {
        int n = m->dec_decode(c->dec, au, (int)size, isEos ? 1 : 0, c->scratch.data(), (int)c->scratch.size());
        if (n > 0) c->outQ.push_back(AmOut{ std::vector<uint8_t>(c->scratch.data(), c->scratch.data() + n), (int64_t)time, 0 });
    }
    c->inBusy[idx] = false;
    if (isEos) {
        c->eos = true;
        // Drain any PCM the decoder still holds (priming/flush), then a 0-byte EOS marker.
        for (;;) {
            int n = m->dec_decode(c->dec, nullptr, 0, 1, c->scratch.data(), (int)c->scratch.size());
            if (n <= 0) break;
            c->outQ.push_back(AmOut{ std::vector<uint8_t>(c->scratch.data(), c->scratch.data() + n), (int64_t)time, 0 });
        }
        c->outQ.push_back(AmOut{ {}, (int64_t)time, kBUFFER_FLAG_EOS });
    }
    return kAMEDIA_OK;
}
extern "C" ssize_t __macapk_arm64_AMediaCodec_dequeueOutputBuffer(void* h, void* infoVoid, int64_t /*timeoutUs*/) {
    AmCodec* c = asCod(h); if (!c || !c->dec) return kINFO_TRY_AGAIN_LATER;
    AMediaCodecBufferInfo* info = reinterpret_cast<AMediaCodecBufferInfo*>(infoVoid);
    std::lock_guard<std::mutex> lk(c->mu);
    if (!c->formatSent) { c->formatSent = true; return kINFO_OUTPUT_FORMAT_CHANGED; }
    if (c->outQ.empty()) return kINFO_TRY_AGAIN_LATER;
    int slot = -1; for (int i = 0; i < kNBUF; i++) if (!c->outBusy[i]) { slot = i; break; }
    if (slot < 0) return kINFO_TRY_AGAIN_LATER;   // all output buffers held; release some
    AmOut out = std::move(c->outQ.front()); c->outQ.pop_front();
    c->outBuf[slot] = std::move(out.pcm);
    c->outLen[slot] = c->outBuf[slot].size();
    c->outBusy[slot] = true;
    if (info) { info->offset = 0; info->size = (int32_t)c->outLen[slot]; info->presentationTimeUs = out.pts; info->flags = out.flags; }
    return slot;
}
extern "C" uint8_t* __macapk_arm64_AMediaCodec_getOutputBuffer(void* h, size_t idx, size_t* out_size) {
    AmCodec* c = asCod(h); if (!c || idx >= (size_t)kNBUF || !c->outBusy[idx]) { if (out_size) *out_size = 0; return nullptr; }
    if (out_size) *out_size = c->outLen[idx];
    return c->outBuf[idx].empty() ? (uint8_t*)c->outBuf[idx].data() : c->outBuf[idx].data();
}
extern "C" int __macapk_arm64_AMediaCodec_releaseOutputBuffer(void* h, size_t idx, bool /*render*/) {
    AmCodec* c = asCod(h); if (!c || idx >= (size_t)kNBUF) return kAMEDIA_ERR_INVALID_OBJECT;
    std::lock_guard<std::mutex> lk(c->mu);
    c->outBusy[idx] = false; c->outLen[idx] = 0; c->outBuf[idx].clear();
    return kAMEDIA_OK;
}
extern "C" int __macapk_arm64_AMediaCodec_releaseOutputBufferAtTime(void* h, size_t idx, int64_t /*ts*/) {
    return __macapk_arm64_AMediaCodec_releaseOutputBuffer(h, idx, false);
}
extern "C" void* __macapk_arm64_AMediaCodec_getOutputFormat(void* h) {
    AmCodec* c = asCod(h); AmFormat* f = new AmFormat();
    if (c) {
        f->str["mime"]          = "audio/raw";
        f->i32["sample-rate"]   = c->sr;
        f->i32["channel-count"] = c->ch;
        f->i32["pcm-encoding"]  = 2;   // AudioFormat.ENCODING_PCM_16BIT
    }
    return f;
}
extern "C" void* __macapk_arm64_AMediaCodec_getInputFormat(void* h) {
    AmCodec* c = asCod(h); AmFormat* f = new AmFormat();
    if (c) { f->str["mime"] = c->mime.empty() ? fmtIdMime(c->fmtId) : c->mime; f->i32["sample-rate"] = c->sr; f->i32["channel-count"] = c->ch; }
    return f;
}

// ===== AMEDIAFORMAT_KEY_* DATA globals (const char*; the loader resolves the =====
// guest's data import to the ADDRESS of these). Canonical strings (NdkMediaFormat.cpp).
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_MIME          = "mime";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_WIDTH         = "width";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_HEIGHT        = "height";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_STRIDE        = "stride";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_DURATION      = "durationUs";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_FRAME_RATE    = "frame-rate";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_SAMPLE_RATE   = "sample-rate";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_CHANNEL_COUNT = "channel-count";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_COLOR_FORMAT  = "color-format";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_LANGUAGE      = "language";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_CSD_0         = "csd-0";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_MAX_INPUT_SIZE= "max-input-size";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_BIT_RATE      = "bitrate";
// A DATA import the loader cannot resolve is left NULL (it does not trap the
// way an unresolved JUMP_SLOT does), and every AMediaFormat_get*/set* above
// short-circuits on name==nullptr -- so a missing key here is a SILENT metadata
// loss, not a crash. ROTATION in particular is what tells a player a portrait
// recording must be rotated for display, and ENCODER_DELAY/ENCODER_PADDING are
// the gapless-playback trim points (they are only meaningful as a pair).
// Values verbatim from NdkMediaFormat.cpp; note ROTATION is "rotation-degrees",
// NOT "rotation".
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_COLOR_RANGE     = "color-range";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_COLOR_STANDARD  = "color-standard";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_COLOR_TRANSFER  = "color-transfer";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_ENCODER_DELAY   = "encoder-delay";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_ENCODER_PADDING = "encoder-padding";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_ROTATION        = "rotation-degrees";
extern "C" const char* __macapk_arm64_AMEDIAFORMAT_KEY_SLICE_HEIGHT    = "slice-height";

// ===== Native self-test (item 3a validation) ================================
// Drives the AMedia* C API above on `path` exactly as an NDK decode loop would,
// returns total decoded PCM frames (>0 = real audio), or -1 on failure. Reached
// from the runtime via dlsym when MACAPK_AMEDIA_SELFTEST=1; also linked into
// debug/amedia_test.mm for a standalone unit test.
extern "C" int64_t __macapk_arm64_amedia_selftest(const char* path) {
    void* ex = __macapk_arm64_AMediaExtractor_new();
    if (__macapk_arm64_AMediaExtractor_setDataSource(ex, path) != kAMEDIA_OK) {
        std::fprintf(stderr, "[amedia-selftest] setDataSource failed: %s\n", path);
        __macapk_arm64_AMediaExtractor_delete(ex); return -1;
    }
    if (__macapk_arm64_AMediaExtractor_getTrackCount(ex) < 1) { __macapk_arm64_AMediaExtractor_delete(ex); return -1; }
    void* fmt = __macapk_arm64_AMediaExtractor_getTrackFormat(ex, 0);
    const char* mimeC = nullptr; __macapk_arm64_AMediaFormat_getString(fmt, "mime", &mimeC);
    // Copy out of the AmFormat -- it is deleted before the final log line, so a
    // borrowed const char* would dangle (use-after-free).
    std::string mime = mimeC ? mimeC : "audio/mp4a-latm";
    int32_t sr = 0, ch = 0; __macapk_arm64_AMediaFormat_getInt32(fmt, "sample-rate", &sr);
    __macapk_arm64_AMediaFormat_getInt32(fmt, "channel-count", &ch);
    __macapk_arm64_AMediaExtractor_selectTrack(ex, 0);
    void* cod = __macapk_arm64_AMediaCodec_createDecoderByType(mime.c_str());
    if (__macapk_arm64_AMediaCodec_configure(cod, fmt, nullptr, nullptr, 0) != kAMEDIA_OK
        || __macapk_arm64_AMediaCodec_start(cod) != kAMEDIA_OK) {
        std::fprintf(stderr, "[amedia-selftest] configure/start failed (mime=%s sr=%d ch=%d)\n", mime.c_str(), sr, ch);
        __macapk_arm64_AMediaFormat_delete(fmt); __macapk_arm64_AMediaCodec_delete(cod);
        __macapk_arm64_AMediaExtractor_delete(ex); return -1;
    }
    int64_t totalBytes = 0; double sumsq = 0; bool sawEos = false; int guard = 0;
    bool inputDone = false;
    while (!sawEos && guard++ < 1000000) {
        if (!inputDone) {
            ssize_t ii = __macapk_arm64_AMediaCodec_dequeueInputBuffer(cod, 0);
            if (ii >= 0) {
                size_t cap = 0; uint8_t* ib = __macapk_arm64_AMediaCodec_getInputBuffer(cod, (size_t)ii, &cap);
                ssize_t n = __macapk_arm64_AMediaExtractor_readSampleData(ex, ib, cap);
                if (n < 0) { __macapk_arm64_AMediaCodec_queueInputBuffer(cod, (size_t)ii, 0, 0, 0, kBUFFER_FLAG_EOS); inputDone = true; }
                else {
                    int64_t pts = __macapk_arm64_AMediaExtractor_getSampleTime(ex);
                    __macapk_arm64_AMediaCodec_queueInputBuffer(cod, (size_t)ii, 0, (size_t)n, (uint64_t)pts, 0);
                    __macapk_arm64_AMediaExtractor_advance(ex);
                }
            }
        }
        AMediaCodecBufferInfo bi{};
        ssize_t oi = __macapk_arm64_AMediaCodec_dequeueOutputBuffer(cod, &bi, 0);
        if (oi >= 0) {
            if (bi.size > 0) {
                size_t osz = 0; uint8_t* ob = __macapk_arm64_AMediaCodec_getOutputBuffer(cod, (size_t)oi, &osz);
                const int16_t* s = reinterpret_cast<const int16_t*>(ob);
                size_t ns = osz / 2; for (size_t i = 0; i < ns; i++) { double v = s[i]; sumsq += v * v; }
                totalBytes += (int64_t)osz;
            }
            if (bi.flags & kBUFFER_FLAG_EOS) sawEos = true;
            __macapk_arm64_AMediaCodec_releaseOutputBuffer(cod, (size_t)oi, false);
        }
    }
    __macapk_arm64_AMediaFormat_delete(fmt);
    __macapk_arm64_AMediaCodec_delete(cod);
    __macapk_arm64_AMediaExtractor_delete(ex);
    int frames = (ch > 0) ? (int)(totalBytes / (2 * ch)) : 0;
    double rms = (totalBytes >= 2) ? std::sqrt(sumsq / (totalBytes / 2.0)) : 0.0;
    std::fprintf(stderr, "[amedia-selftest] mime=%s sr=%d ch=%d -> %lld PCM bytes (%d frames) rms=%.1f %s\n",
                 mime.c_str(), sr, ch, (long long)totalBytes, frames, rms,
                 (totalBytes > 0 && rms > 0) ? "PASS" : "FAIL");
    return (totalBytes > 0 && rms > 0) ? (int64_t)frames : -1;
}
