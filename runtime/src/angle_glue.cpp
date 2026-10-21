// angle_glue.cpp
//
// Implementation of the ANGLE bridge. See angle_glue.h for design.
//
// This file owns the framework's EGL display/surface/context and the per-frame
// begin/end/resize/finish plumbing that cocoa_bridge.mm drives. It links
// libEGL / libGLESv2 directly. It does NOT forward the app's GLES calls: the
// android.opengl.GLES20 JNI entries in native_methods.cpp call ANGLE directly,
// the way AOSP's android_opengl_GLES20.cpp calls the driver, and nothing here
// is injected into the app's draw stream (the pre-HotSpot AngleDrawArrays /
// AngleUseProgram wrapper family and its MVP hook were retired 2026-09-27, see
// docs/andengine-projectionmatrix-mvp-retired_2026-09-27.md).

#ifdef MACAPK_HAS_ANGLE

#include "angle_glue.h"
#include "macapk/self_capture.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <jni.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <filesystem>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Tiny logger so this translation unit doesn't drag in a wider
// dependency tree. Prints to stderr.
namespace { struct LogShim {
    static void Info(const std::string& m)  { std::fprintf(stderr, "[I] angle: %s\n", m.c_str()); }
    static void Error(const std::string& m) { std::fprintf(stderr, "[E] angle: %s\n", m.c_str()); }
}; }

namespace macapk {

namespace {

// Mirrors the EGL display/surface/context once. ANGLE's EGL implementation
// supports multiple displays but our v0.5 has a single MTKView, so a single
// triplet is enough. v0.6 will multiplex when multiple Activities open
// simultaneously.
EGLDisplay g_display = EGL_NO_DISPLAY;
EGLSurface g_surface = EGL_NO_SURFACE;
EGLContext g_context = EGL_NO_CONTEXT;
bool       g_initialized = false;
// Remember which CAMetalLayer the current surface is bound to, so a
// re-init request that hands us a DIFFERENT layer (e.g. the user's
// Activity replaced the placeholder MTKView with its own GLSurfaceView's
// MTKView) tears down the stale surface + binds the new one. Without this
// guard, AngleInit early-returned `true` and we kept rendering into the
// detached layer => game rendered black on the visible MTKView (Flappy /
// F-Droid v1.0.77 regression after the placeholder MTKView added an
// initial ANGLE binding).
void*      g_bound_layer = nullptr;
// Logical (point) dimensions passed to AngleInit — the game's coordinate space.
int        g_init_width  = 0;
int        g_init_height = 0;

bool MakeCurrent() {
    if (!g_initialized) return false;
    return eglMakeCurrent(g_display, g_surface, g_surface, g_context) == EGL_TRUE;
}

// ---------------------------------------------------------------------------
// ANGLE shader / pipeline blob cache (EGL_ANDROID_blob_cache)
//
// Without this, every launch re-translates every GLSL shader and re-links
// every program from scratch. ANGLE has a persistence hook for exactly this,
// but it is inert until the embedder supplies storage: eglSetBlobCacheFuncsANDROID
// hands ANGLE a set/get pair, and from then on glLinkProgram consults it
// transparently (libANGLE/Program.cpp Program::link -> MemoryProgramCache::getProgram
// -> BlobCache::get). The app needs no glProgramBinary call and no code change --
// the whole mechanism lives below the GLES API.
//
// Contract notes, from the ANGLE source we build against
// (thirdparty/angle @ e44b533ccb2b, libANGLE/BlobCache.cpp:85-126) --
// these are the parts that are easy to get wrong:
//
//   * GET IS CALLED TWICE PER LOOKUP. First with value=nullptr/valueSize=0
//     purely to learn the size, then again with a buffer of exactly the size
//     the first call reported. BOTH calls must return the FULL stored blob
//     size. Returning bytes-copied (0) on the probe turns every lookup into a
//     miss; returning a different number on the second call makes ANGLE
//     discard the hit ("Binary blob no longer available in cache"). So the
//     probe has to be cheap -- it runs on every link, hit or miss -- which is
//     why it is a stat() and not a read().
//   * THREAD SAFETY IS OURS. ANGLE serializes callbacks per EGLDisplay under a
//     non-recursive mutex, but that mutex does not span the two get() calls
//     and there is one per display. More importantly, a callback must NEVER
//     re-enter ANGLE (instant self-deadlock), so everything below is plain
//     POSIX file I/O plus atomics. Vulkan additionally invokes set() from a
//     worker thread, not the GL thread.
//   * WRITES MUST BE ATOMIC. A torn blob is not merely a cache miss: ANGLE's
//     Vulkan pipeline-cache reader calls FATAL() on a CRC mismatch
//     (vk_renderer.cpp:1757), so a half-written file could abort the NEXT
//     launch. Hence temp-file + rename(), which is atomic on APFS.
//   * WE DO NOT NEED TO VERSION FOR CORRECTNESS. ANGLE mixes its own
//     serialization-format hash, the GLES version and GL_RENDERER into the key
//     (MemoryProgramCache.cpp:91-99) and re-checks the format hash inside the
//     payload on load (Program.cpp:2275-2295), rejecting a mismatch by falling
//     back to a full link. The per-build subdirectory below is for HYGIENE:
//     ANGLE never garbage-collects, so without it the entries from every past
//     ANGLE build would accumulate on disk forever.
//   * ONE-SHOT PER DISPLAY. A second eglSetBlobCacheFuncsANDROID on the same
//     display raises EGL_BAD_PARAMETER (validationEGL.cpp:5590), and the call
//     must happen after eglInitialize or it raises EGL_NOT_INITIALIZED.
//
// MEASURED RESULT (2026-07-25, v761 host) -- READ BEFORE ASSUMING THIS IS A WIN.
// The mechanism verifiably works: warm runs report a 100% hit rate, blobs
// round-trip, and ANGLE accepts them (a rejected blob would show up as an
// immediate re-store of the same key, which never happens). But the
// first-frame TIME did not measurably improve on any app reachable from this
// display. Geometry Dash Lite (9 cached programs, 26 KB), 8 cold + 8 warm
// interleaved runs: cold-first ordering showed warm 33 ms faster, but the
// REVERSED ordering (warm first) inverted that to 4 ms slower, so the apparent
// win was run order, not the cache. Pooled delta 14 ms against a 27 ms sd =
// noise. OpenGD (4 programs) showed ~0 either way. The reason is simply that
// cocos-family shaders are tiny -- 3 KB of program binary is not expensive to
// recompile, and the gzip inflate on the read side costs about as much.
//
// The apps that WOULD benefit -- RenderDragon/MCPE, Unity -- drive EGL
// natively and therefore live on the OTHER EGLDisplay, created in
// translator/src/bionic_shim.cpp, which this hook does not reach. See
// macapk_angle_install_blob_cache at the bottom of this file for the one-line
// wiring that would extend it there; that, not this call site, is where the
// shader-recompile cost the cache was built for actually lives.
//
// Off switch: MACAPK_ANGLE_BLOB_CACHE=0. Storage location override:
// MACAPK_ANGLE_BLOB_DIR. Size budget: MACAPK_ANGLE_BLOB_MAX_MB (default 256).
// Per-blob logging: MACAPK_ANGLE_BLOB_TRACE=1.
// ---------------------------------------------------------------------------

// Absolute path of the per-ANGLE-build cache directory. EMPTY means the cache
// is disabled, and every callback below turns into a no-op / miss.
std::string g_blob_dir;
uint64_t    g_blob_budget_bytes = 0;   // 0 = unlimited
bool        g_blob_trace        = false;

std::atomic<uint64_t> g_blob_probe{0};        // lookups ANGLE performed
std::atomic<uint64_t> g_blob_hit{0};          // ... that we served
std::atomic<uint64_t> g_blob_miss{0};
std::atomic<uint64_t> g_blob_hit_bytes{0};
std::atomic<uint64_t> g_blob_store{0};        // blobs ANGLE handed us
std::atomic<uint64_t> g_blob_store_bytes{0};
std::atomic<uint64_t> g_blob_store_skipped{0};// refused: over budget / I/O error
std::atomic<uint64_t> g_blob_dir_bytes{0};    // running on-disk total
std::atomic<uint64_t> g_blob_seq{0};          // temp-file uniquifier

// Wall-clock reference for the cold-vs-warm first-frame measurement.
std::chrono::steady_clock::time_point g_egl_init_time;
bool                  g_egl_init_time_set = false;
std::atomic<bool>     g_first_frame_logged{false};

// key (16 raw bytes in this ANGLE build: XXH3-128, angletypes.h:1368) ->
// "<hex>.blob". Hex because the key is arbitrary binary, not printable.
bool BlobPathFor(const void* key, EGLsizeiANDROID key_size, std::string* out) {
    if (g_blob_dir.empty() || key == nullptr) return false;
    // Defensive: the key length is a compile-time constant in ANGLE, so
    // anything wild means we are being called through a mismatched ABI.
    if (key_size <= 0 || key_size > 128) return false;
    static const char kHex[] = "0123456789abcdef";
    const uint8_t* k = static_cast<const uint8_t*>(key);
    std::string name;
    name.reserve(static_cast<size_t>(key_size) * 2 + 5);
    for (EGLsizeiANDROID i = 0; i < key_size; ++i) {
        name.push_back(kHex[k[i] >> 4]);
        name.push_back(kHex[k[i] & 0x0f]);
    }
    name += ".blob";
    out->assign(g_blob_dir).append("/").append(name);
    return true;
}

bool WriteAll(int fd, const uint8_t* p, size_t left) {
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

bool ReadAll(int fd, uint8_t* p, size_t left) {
    while (left > 0) {
        ssize_t n = ::read(fd, p, left);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

// EGLSetBlobFuncANDROID. Called by ANGLE after a successful shader
// translate / program link, and (Vulkan) with pipeline-cache chunks.
void BlobCacheSet(const void* key, EGLsizeiANDROID key_size,
                  const void* value, EGLsizeiANDROID value_size) {
    std::string path;
    if (!BlobPathFor(key, key_size, &path)) return;
    if (value == nullptr || value_size <= 0) return;

    if (g_blob_budget_bytes != 0 &&
        g_blob_dir_bytes.load(std::memory_order_relaxed)
            + static_cast<uint64_t>(value_size) > g_blob_budget_bytes) {
        // Stop growing rather than evict: ANGLE re-links whatever we decline,
        // so the only cost is the compile we would have saved. An LRU here
        // would need its own metadata and locking for a case that a sane
        // budget never reaches.
        if (g_blob_store_skipped.fetch_add(1, std::memory_order_relaxed) == 0) {
            LogShim::Info("blob cache: budget reached ("
                          + std::to_string(g_blob_budget_bytes >> 20)
                          + " MB); no longer storing new blobs");
        }
        return;
    }

    // Atomic publish: a reader either sees the previous file or the complete
    // new one, never a prefix. See the FATAL() note in the header comment.
    std::string tmp = path + ".tmp."
                    + std::to_string(static_cast<unsigned>(::getpid())) + "."
                    + std::to_string(g_blob_seq.fetch_add(1, std::memory_order_relaxed));
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        g_blob_store_skipped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    bool ok = WriteAll(fd, static_cast<const uint8_t*>(value),
                       static_cast<size_t>(value_size));
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        g_blob_store_skipped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_blob_store.fetch_add(1, std::memory_order_relaxed);
    g_blob_store_bytes.fetch_add(static_cast<uint64_t>(value_size),
                                 std::memory_order_relaxed);
    g_blob_dir_bytes.fetch_add(static_cast<uint64_t>(value_size),
                               std::memory_order_relaxed);
    if (g_blob_trace) {
        LogShim::Info("blob set " + path.substr(path.rfind('/') + 1) + " "
                      + std::to_string(static_cast<long long>(value_size)) + " B");
    }
}

// EGLGetBlobFuncANDROID. Returns the FULL size of the stored blob (0 = absent)
// on BOTH the probe and the fetch call -- see the header comment.
EGLsizeiANDROID BlobCacheGet(const void* key, EGLsizeiANDROID key_size,
                             void* value, EGLsizeiANDROID value_size) {
    std::string path;
    if (!BlobPathFor(key, key_size, &path)) return 0;

    const bool is_probe = (value == nullptr || value_size <= 0);
    struct stat st;
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        if (is_probe) g_blob_miss.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    EGLsizeiANDROID full = static_cast<EGLsizeiANDROID>(st.st_size);
    if (is_probe) {
        g_blob_probe.fetch_add(1, std::memory_order_relaxed);
        return full;   // report the size; copy nothing
    }
    if (value_size < full) {
        // Per EGL_ANDROID_blob_cache: when the caller's buffer is too small,
        // write nothing but still report the real size. ANGLE never hits this
        // (it always passes back exactly what the probe returned) -- it would
        // only fire if the file changed between the two calls.
        return full;
    }
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    bool ok = ReadAll(fd, static_cast<uint8_t*>(value), static_cast<size_t>(full));
    ::close(fd);
    if (!ok) return 0;
    g_blob_hit.fetch_add(1, std::memory_order_relaxed);
    g_blob_hit_bytes.fetch_add(static_cast<uint64_t>(full), std::memory_order_relaxed);
    if (g_blob_trace) {
        LogShim::Info("blob hit " + path.substr(path.rfind('/') + 1) + " "
                      + std::to_string(static_cast<long long>(full)) + " B");
    }
    return full;
}

void BlobCacheLogSummary(const char* when) {
    if (g_blob_dir.empty()) return;
    uint64_t hit  = g_blob_hit.load(std::memory_order_relaxed);
    uint64_t miss = g_blob_miss.load(std::memory_order_relaxed);
    uint64_t look = hit + miss;
    std::fprintf(stderr,
        "[I] angle: blob cache (%s): %llu lookups -> %llu hit / %llu miss (%.0f%% hit), "
        "%llu stored (%llu KB), %llu KB served, %llu skipped, dir=%llu KB\n",
        when,
        (unsigned long long)look,
        (unsigned long long)hit,
        (unsigned long long)miss,
        look ? 100.0 * double(hit) / double(look) : 0.0,
        (unsigned long long)g_blob_store.load(std::memory_order_relaxed),
        (unsigned long long)(g_blob_store_bytes.load(std::memory_order_relaxed) >> 10),
        (unsigned long long)(g_blob_hit_bytes.load(std::memory_order_relaxed) >> 10),
        (unsigned long long)g_blob_store_skipped.load(std::memory_order_relaxed),
        (unsigned long long)(g_blob_dir_bytes.load(std::memory_order_relaxed) >> 10));
    std::fflush(stderr);
}

// Install on one EGLDisplay. Idempotent per display (a second call on the same
// display is an EGL_BAD_PARAMETER), and safe to call for several displays.
void InstallBlobCache(EGLDisplay dpy) {
    namespace fs = std::filesystem;
    static std::mutex s_mu;
    static std::vector<EGLDisplay> s_done;
    std::lock_guard<std::mutex> lock(s_mu);
    for (EGLDisplay d : s_done) if (d == dpy) return;
    s_done.push_back(dpy);

    if (const char* off = std::getenv("MACAPK_ANGLE_BLOB_CACHE");
        off && off[0] == '0' && off[1] == '\0') {
        LogShim::Info("blob cache: disabled via MACAPK_ANGLE_BLOB_CACHE=0");
        return;
    }
    g_blob_trace = [] {
        const char* t = std::getenv("MACAPK_ANGLE_BLOB_TRACE");
        return t && t[0] == '1';
    }();

    // Where to put it. MACAPK_APP_CACHE_DIR is the runtime's own cache root
    // (<android-root>/data/data, set in main.cpp); a dot-prefixed subdir there
    // cannot collide with a package directory because package names never
    // start with '.'. Deliberately SHARED across apps rather than per-package:
    // ANGLE's keys are content-addressed (shader source + GL_RENDERER + its
    // own format hash), so two apps compiling the same shader legitimately
    // reuse one entry, and ANGLE's built-in blit/clear shaders are shared by
    // every app on the machine.
    std::string root;
    if (const char* d = std::getenv("MACAPK_ANGLE_BLOB_DIR"); d && *d) {
        root = d;
    } else if (const char* c = std::getenv("MACAPK_APP_CACHE_DIR"); c && *c) {
        root = std::string(c) + "/.angle_blob";
    } else {
        LogShim::Info("blob cache: no MACAPK_APP_CACHE_DIR; not enabling");
        return;
    }

    // Per-ANGLE-build subdirectory. EGL_VERSION carries ANGLE's version +
    // commit hash, so a rebuilt/replaced ANGLE lands in a fresh directory and
    // the previous one gets pruned below. Correctness does not depend on this
    // (ANGLE validates its own blobs); disk hygiene does.
    uint64_t h = 1469598103934665603ull;   // FNV-1a offset basis
    auto mix = [&h](const char* s) {
        for (const char* p = s; p && *p; ++p) {
            h ^= static_cast<uint8_t>(*p);
            h *= 1099511628211ull;
        }
    };
    mix(eglQueryString(dpy, EGL_VERSION));
    mix("|");
    mix(eglQueryString(dpy, EGL_VENDOR));
    char tag[24];
    std::snprintf(tag, sizeof(tag), "%016llx", (unsigned long long)h);

    std::error_code ec;
    fs::path dir = fs::path(root) / tag;
    fs::create_directories(dir, ec);
    if (ec) {
        LogShim::Error("blob cache: cannot create " + dir.string() + ": " + ec.message());
        return;
    }
    // Prune directories from other ANGLE builds, and total up our own.
    // Wrapped because directory_iterator's INCREMENT throws even when the
    // constructor took an error_code, and this runs on the render-init path
    // where an escaping exception would take down the app over a cache.
    uint64_t on_disk = 0, entries = 0;
    try {
        for (const auto& e : fs::directory_iterator(root, ec)) {
            if (ec) break;
            if (e.is_directory(ec) && e.path().filename() != tag) {
                fs::remove_all(e.path(), ec);
                ec.clear();
            }
        }
        ec.clear();
        for (const auto& e : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            if (!e.is_regular_file(ec)) continue;
            auto sz = e.file_size(ec);
            if (!ec) { on_disk += sz; ++entries; }
            ec.clear();
        }
    } catch (const std::exception& ex) {
        LogShim::Info(std::string("blob cache: scan skipped (") + ex.what() + ")");
    }
    ec.clear();
    g_blob_dir_bytes.store(on_disk, std::memory_order_relaxed);

    uint64_t max_mb = 256;
    if (const char* m = std::getenv("MACAPK_ANGLE_BLOB_MAX_MB"); m && *m) {
        char* end = nullptr;
        unsigned long v = std::strtoul(m, &end, 10);
        if (end != m) max_mb = v;            // 0 = unlimited
    }
    g_blob_budget_bytes = max_mb * 1024ull * 1024ull;

    auto proc = eglGetProcAddress("eglSetBlobCacheFuncsANDROID");
    if (proc == nullptr) {
        LogShim::Error("blob cache: eglSetBlobCacheFuncsANDROID not exported by this ANGLE");
        return;
    }
    g_blob_dir = dir.string();
    eglGetError();   // clear any stale error so the check below is about us
    reinterpret_cast<PFNEGLSETBLOBCACHEFUNCSANDROIDPROC>(proc)(
        dpy, &BlobCacheSet, &BlobCacheGet);
    EGLint err = eglGetError();
    if (err != EGL_SUCCESS) {
        // The call returns void, so eglGetError is the only signal.
        g_blob_dir.clear();
        LogShim::Error("blob cache: eglSetBlobCacheFuncsANDROID failed: 0x"
                       + std::to_string(err));
        return;
    }
    LogShim::Info("blob cache: enabled at " + g_blob_dir + " ("
                  + std::to_string(entries) + " entries, "
                  + std::to_string(on_disk >> 10) + " KB warm, budget "
                  + (max_mb ? std::to_string(max_mb) + " MB" : std::string("unlimited"))
                  + ")");
    static std::once_flag s_atexit;
    std::call_once(s_atexit, [] {
        // Deterministic final tally even when AngleFinish never runs (the
        // usual case: the app is killed rather than shut down cleanly).
        std::atexit([] { BlobCacheLogSummary("exit"); });
    });
}

}  // namespace

// Forwarder so the extern "C" entry point at the bottom of this file can reach
// the anonymous-namespace implementation. Takes void* rather than EGLDisplay so
// callers need no EGL headers.
void InstallBlobCacheForDisplay(void* dpy) {
    InstallBlobCache(static_cast<EGLDisplay>(dpy));
}

bool AngleInit(void* metal_layer, int width, int height) {
    // v1.0.78 rebind-fast-path: if we're already initialized AND the
    // caller hands us a different CAMetalLayer (typical Activity-swap
    // sequence: placeholder MTKView -> user's GLSurfaceView MTKView),
    // destroy the stale window surface, create a fresh one for the new
    // layer, keep the EGLContext/EGLDisplay (these are layer-independent
    // ANGLE-internal handles). Without this, a stale g_surface pointed at
    // a CAMetalLayer no longer in the on-screen view tree -- every
    // eglSwapBuffers presented to nothing visible -> black on the user's
    // GLSurfaceView.
    if (g_initialized) {
        if (metal_layer == g_bound_layer) return true;
        LogShim::Info("AngleInit: rebinding to new metal_layer "
                      + std::to_string((uintptr_t)metal_layer));
        if (g_surface != EGL_NO_SURFACE) {
            eglMakeCurrent(g_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            eglDestroySurface(g_display, g_surface);
            g_surface = EGL_NO_SURFACE;
        }
        EGLint config_attribs[] = {
            EGL_RED_SIZE,     8,
            EGL_GREEN_SIZE,   8,
            EGL_BLUE_SIZE,    8,
            EGL_ALPHA_SIZE,   8,
            EGL_DEPTH_SIZE,   24,
            EGL_STENCIL_SIZE, 0,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_SURFACE_TYPE,    EGL_WINDOW_BIT,
            EGL_NONE
        };
        EGLConfig config;
        EGLint num_configs = 0;
        if (!eglChooseConfig(g_display, config_attribs, &config, 1, &num_configs)
            || num_configs == 0) {
            LogShim::Error("AngleInit rebind: eglChooseConfig failed");
            return false;
        }
        g_surface = eglCreateWindowSurface(g_display, config,
            reinterpret_cast<EGLNativeWindowType>(metal_layer), nullptr);
        if (g_surface == EGL_NO_SURFACE) {
            LogShim::Error("AngleInit rebind: eglCreateWindowSurface failed: 0x"
                           + std::to_string(eglGetError()));
            return false;
        }
        if (eglMakeCurrent(g_display, g_surface, g_surface, g_context) != EGL_TRUE) {
            LogShim::Error("AngleInit rebind: eglMakeCurrent failed: 0x"
                           + std::to_string(eglGetError()));
            return false;
        }
        g_bound_layer = metal_layer;
        g_init_width  = width;
        g_init_height = height;
        return true;
    }
    g_init_width  = width;
    g_init_height = height;

    // Use ANGLE's Metal backend explicitly. Without the platform attrib
    // ANGLE may pick its default (could be GL on macOS, which we disabled
    // at build time anyway). We still pass it for clarity.
    EGLAttrib display_attribs[] = {
        EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_METAL_ANGLE,
        EGL_NONE
    };
    g_display = eglGetPlatformDisplay(EGL_PLATFORM_ANGLE_ANGLE,
                                       reinterpret_cast<void*>(EGL_DEFAULT_DISPLAY),
                                       display_attribs);
    if (g_display == EGL_NO_DISPLAY) {
        LogShim::Error(
            "eglGetPlatformDisplay failed");
        return false;
    }
    EGLint major = 0, minor = 0;
    if (!eglInitialize(g_display, &major, &minor)) {
        LogShim::Error(
            "eglInitialize failed: 0x" + std::to_string(eglGetError()));
        return false;
    }
    LogShim::Info(
        "EGL initialized: " + std::to_string(major) + "." + std::to_string(minor));

    // Persist translated shaders / linked programs across launches. Must come
    // after eglInitialize (EGL_NOT_INITIALIZED otherwise) and before the first
    // glLinkProgram, or the programs linked in between are never cached.
    g_egl_init_time     = std::chrono::steady_clock::now();
    g_egl_init_time_set = true;
    InstallBlobCache(g_display);

    // Pick a config: 8/8/8/8 RGBA, 24-bit depth, no stencil. Matches what
    // AndEngine asks for in its EGLConfigChooser.
    EGLint config_attribs[] = {
        EGL_RED_SIZE,     8,
        EGL_GREEN_SIZE,   8,
        EGL_BLUE_SIZE,    8,
        EGL_ALPHA_SIZE,   8,
        EGL_DEPTH_SIZE,   24,
        EGL_STENCIL_SIZE, 0,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_SURFACE_TYPE,    EGL_WINDOW_BIT,
        EGL_NONE
    };
    EGLConfig config;
    EGLint num_configs = 0;
    if (!eglChooseConfig(g_display, config_attribs, &config, 1, &num_configs)
        || num_configs == 0) {
        LogShim::Error( "eglChooseConfig failed");
        return false;
    }

    // Window surface bound to the CAMetalLayer. ANGLE's Metal backend
    // accepts an id<CAMetalLayer> as the EGLNativeWindowType.
    g_surface = eglCreateWindowSurface(g_display, config,
        reinterpret_cast<EGLNativeWindowType>(metal_layer), nullptr);
    if (g_surface == EGL_NO_SURFACE) {
        LogShim::Error(
            "eglCreateWindowSurface failed: 0x" + std::to_string(eglGetError()));
        return false;
    }

    // ES1 apps need an ES1 CONTEXT. ANGLE gates every ES1 entry point on
    // `context->getClientVersion() < ES_2_0` and otherwise returns
    // GL_INVALID_OPERATION without doing anything, so asking for 2
    // unconditionally makes the entire fixed-function pipeline a silent
    // no-op (v1.0.784). main.cpp sets MACAPK_GLES1_CONTEXT from an
    // imported-symbol scan of the guest libs; the two context types are
    // mutually exclusive, so this cannot be a runtime fallback.
    const char* es1env = std::getenv("MACAPK_GLES1_CONTEXT");
    const EGLint want_client_version = (es1env && es1env[0] == '1') ? 1 : 2;
    EGLint context_attribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, want_client_version,
        EGL_NONE
    };
    LogShim::Info("EGL context client version: " +
                  std::to_string(want_client_version));
    g_context = eglCreateContext(g_display, config, EGL_NO_CONTEXT, context_attribs);
    if (g_context == EGL_NO_CONTEXT) {
        LogShim::Error(
            "eglCreateContext failed: 0x" + std::to_string(eglGetError()));
        return false;
    }

    if (!eglMakeCurrent(g_display, g_surface, g_surface, g_context)) {
        LogShim::Error(
            "eglMakeCurrent failed: 0x" + std::to_string(eglGetError()));
        return false;
    }

    g_initialized = true;
    g_bound_layer = metal_layer;

    // MACAPK_GL_DEFAULTS (default ON; =0 restores the legacy marker state
    // below, byte for byte, as a labelled bisect gate for every GL app).
    //
    // A freshly created GLES context must present the SPEC's initial state,
    // because apps rely on it without ever setting it. Khronos OpenGL ES 3.0.6
    // spec, section 6.2 state tables:
    //   Table 6.11 Pixel Operations: BLEND  IsEnabled  FALSE  (4.1.7)
    //                                BLEND_SRC_RGB/ALPHA  ONE,
    //                                BLEND_DST_RGB/ALPHA  ZERO (4.1.7)
    //   Table 6.12 Framebuffer Control: COLOR_CLEAR_VALUE  0.0,0.0,0.0,0.0 (4.2.3)
    // and the ES 3.0 reference pages: glClearColor "The initial values are
    // all 0."; glEnable "The initial value for each capability with the
    // exception of GL_DITHER is GL_FALSE."; glBlendFunc sfactor GL_ONE,
    // dfactor GL_ZERO. The ES 2.0 reference pages for glClearColor and
    // glEnable carry the same two sentences word for word. Texture unit 0
    // starts bound to the default texture 0, and no texture object exists
    // until the app creates one.
    //
    // Before this gate the context was born with three debugging-era
    // markers from the v0.6 Flappy bring-up (commit 04add6aa, 2026-05-05),
    // when the Java frame loop was only partly wired: a 1x1 white texture
    // occupying name 1 and left bound, a sky-blue clear colour, and blending
    // pre-enabled. Each one is a lie to a real app:
    //   * ShatteredPD never calls glClearColor (its only glClear* reference
    //     is glClear in com.watabou.noosa.Game), so the gaps between its
    //     transparent title layers cleared to our blue, 17-23% of the frame,
    //     where a device shows black (fleet A/B, 2026-09-25).
    //   * The blend preset was never needed. AndEngine's GLState
    //     (org.andengine.opengl.util.e in Flappy's classes.jar) shadows the
    //     blend enable in a boolean that starts false (field u), but
    //     EngineRenderer.onSurfaceCreated (org.andengine.opengl.view.g,
    //     bci 74-99) calls GLState reset, then disableDepthTest, then
    //     enableBlend, which stores u=true and issues glEnable(GL_BLEND)
    //     itself. Its blend-func cache (fields p,q) starts at -1 in both the
    //     constructor and reset, so glBlendFunc is always issued too. So the
    //     shadow and GL agree before the first draw under either initial
    //     state, the old justification ("AndEngine doesn't always call
    //     glEnable(GL_BLEND)") is refuted by AndEngine's own bytecode, and
    //     Flappy is expected to be pixel-identical (use it as a control, not
    //     as the expected change). cocos2d-x v2 (ccGLStateCache.cpp
    //     SetBlending) and libGDX (SpriteBatch.flush) likewise
    //     glEnable/glDisable GL_BLEND themselves, as every correct GLES app
    //     must.
    //   * The white texture made an unbound sampler read white instead of
    //     the incomplete-texture black a device returns, and (ANGLE hands
    //     out the lowest unused name) shifted every texture name the app got
    //     by one.
    // Nothing of ours draws through this context (the canvas tier presents
    // through its own CALayer, and no Java framework class issues GL), so
    // there is no internal consumer of any of the three; state is also per
    // context, so native-EGL engines (bionic_shim's display) never saw them.
    static const bool kGlDefaults = [] {
        const char* e = std::getenv("MACAPK_GL_DEFAULTS");
        return !(e && e[0] == '0' && e[1] == '\0');
    }();
    LogShim::Info(kGlDefaults
        ? "initial context state: GLES spec defaults (MACAPK_GL_DEFAULTS)"
        : "initial context state: LEGACY markers (MACAPK_GL_DEFAULTS=0: "
          "white tex 1 bound, sky-blue clear, GL_BLEND on)");

    // LEGACY (MACAPK_GL_DEFAULTS=0 only): a 1x1 white texture at name 1.
    if (!kGlDefaults) {
        GLuint tex = 0;
        glGenTextures(1, &tex);
        glBindTexture(GL_TEXTURE_2D, tex);
        uint8_t white[] = {255, 255, 255, 255};
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, white);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        LogShim::Info(
            "default white 1x1 texture created: id=" + std::to_string(tex));
    }

    const GLubyte* renderer = glGetString(GL_RENDERER);
    LogShim::Info(
        std::string("ANGLE active: GL_RENDERER=")
        + (renderer ? reinterpret_cast<const char*>(renderer) : "?"));
    // MACAPK_TRACE_GL_EXT=1 dumps the context's advertised extension string.
    //
    // WHY THIS EXISTS: an app whose shader does
    // `#extension GL_OES_EGL_image_external : require` fails to COMPILE when
    // the context does not advertise that extension, and the only symptom is
    // ANGLE's translator saying "extension is not supported" -- with no way to
    // tell whether the extension is absent from the BACKEND or merely not
    // exposed on the context we asked for. TIC-80 hits exactly that (2026-08-27
    // full-fleet census), and ANGLE's own libGLESv2 does ship the extension, so
    // the question is which of the two it is. Nothing in this tree ever
    // queried GL_EXTENSIONS, so there was no way to answer it from a log.
    //
    // Off by default: the string is long and this runs per context.
    if (std::getenv("MACAPK_TRACE_GL_EXT")) {
        const GLubyte* exts = glGetString(GL_EXTENSIONS);
        LogShim::Info(std::string("GL_EXTENSIONS=")
                      + (exts ? reinterpret_cast<const char*>(exts) : "?"));
    }
    // Equal to the spec's initial viewport (the surface size at first
    // MakeCurrent), so this is not a departure from the defaults.
    glViewport(0, 0, width, height);
    if (!kGlDefaults) {
        // LEGACY (MACAPK_GL_DEFAULTS=0 only), kept verbatim for the A/B.
        // The sky-blue clear was a "the ANGLE present works" marker from
        // bring-up; the blend preset assumed AndEngine omitted
        // glEnable(GL_BLEND). Both are refuted in the gate comment above
        // (AndEngine enables blend itself in onSurfaceCreated).
        glClearColor(0.45f, 0.65f, 0.95f, 1.0f);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    }
    // With the gate ON nothing is set: the context already holds the spec
    // defaults, and writing them explicitly would only hide a future
    // regression in ANGLE's own initial state from debug/gldefaults_gate.sh.
    return true;
}

void* AngleBoundLayer() { return g_bound_layer; }

// MACAPK_GLSV_RENDER_MODE: set between Begin and End of ONE tick by the Java
// GLSurfaceView (NativeCocoa.beginWithheldTick) when it withholds that tick.
static std::atomic<bool> g_frame_withheld{false};
void AngleMarkFrameWithheld(bool withheld) {
    g_frame_withheld.store(withheld, std::memory_order_release);
}

void AngleBeginFrame() {
    if (!g_initialized) return;
    g_frame_withheld.store(false, std::memory_order_release);   // per-tick state
    static int s_begin_call_count = 0;
    bool ok = MakeCurrent();
    if (++s_begin_call_count <= 3 || (s_begin_call_count % 600) == 0) {
        uint64_t tid = 0; pthread_threadid_np(nullptr, &tid);
        EGLContext curC = eglGetCurrentContext();
        std::fprintf(stderr,
            "[I] angle: AngleBeginFrame call #%d tid=%llu makeCurrent=%d ctx=%p\n",
            s_begin_call_count, tid, (int)ok, (void*)curC);
        std::fflush(stderr);
    }
}

// Optional debug frame dump: when MACAPK_DEBUG_DUMPFRAME is set,
// glReadPixels the contents at the specified frame(s) and write a raw
// PPM (P6) file to /tmp/macapk_frame_<N>.ppm. The value is a comma-
// separated list of frame numbers, e.g. `MACAPK_DEBUG_DUMPFRAME=60,300,1800`
// dumps frames 60, 300, and 1800 in a single run. The single-number
// form (`MACAPK_DEBUG_DUMPFRAME=300`) is still accepted. PPM files
// convert to PNG with `sips -s format png input.ppm --out out.png`.
// Intended for headless visual diagnosis when screen capture isn't
// available (sandboxed shell, no Accessibility permission, etc.).
void AngleEndFrame() {
    if (!g_initialized) return;
    static int s_end_call_count = 0;
    if (++s_end_call_count <= 3 || (s_end_call_count % 600) == 0) {
        std::fprintf(stderr,
            "[I] angle: AngleEndFrame call #%d (g_init=%d, surface=%p)\n",
            s_end_call_count, (int)g_initialized, (void*)g_surface);
        std::fflush(stderr);
    }
    // First-frame latency, measured from eglInitialize. This is the number the
    // blob cache is supposed to move: on a warm run the shader translate +
    // link work between init and first present is served from disk instead of
    // recompiled. Logged once per run so a cold/warm A/B is a single grep.
    if (!g_first_frame_logged.exchange(true, std::memory_order_relaxed)
        && g_egl_init_time_set) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - g_egl_init_time).count();
        std::fprintf(stderr,
            "[I] angle: first frame presented %lld ms after EGL init\n",
            (long long)ms);
        std::fflush(stderr);
        BlobCacheLogSummary("first-frame");
    }
    static const std::vector<int> dump_targets = [](){
        std::vector<int> v;
        const char* s = std::getenv("MACAPK_DEBUG_DUMPFRAME");
        std::fprintf(stderr, "[I] angle: DUMPFRAME env=%s\n",
                     s ? s : "<unset>");
        std::fflush(stderr);
        if (!s || !*s) return v;
        const char* p = s;
        while (*p) {
            char* end = nullptr;
            long val = std::strtol(p, &end, 10);
            if (end == p) break;
            if (val > 0) v.push_back(static_cast<int>(val));
            p = end;
            while (*p == ',' || *p == ' ') ++p;
        }
        std::fprintf(stderr, "[I] angle: parsed %zu dump targets\n", v.size());
        std::fflush(stderr);
        return v;
    }();
    static std::atomic<int> g_frame_counter{0};
    // A tick the Java GLSurfaceView withheld (RENDERMODE_WHEN_DIRTY, nothing
    // requested) drew nothing: no frame number, no dump, no self-capture. The
    // swap below still runs (it commits the command buffer AngleBeginFrame
    // opened); with no drawable obtained it presents nothing.
    const bool withheld = g_frame_withheld.exchange(false, std::memory_order_acq_rel);
    int n = withheld ? -1 : g_frame_counter.fetch_add(1, std::memory_order_relaxed);
    bool is_dump_frame = false;
    for (int t : dump_targets) { if (t == n) { is_dump_frame = true; break; } }
    if (is_dump_frame) {
        std::fprintf(stderr, "[I] angle: DUMP TRIGGERED at n=%d\n", n);
        // Confirm context is current on this thread; also check thread id.
        EGLContext curC = eglGetCurrentContext();
        EGLSurface curS = eglGetCurrentSurface(EGL_DRAW);
        uint64_t tid = 0; pthread_threadid_np(nullptr, &tid);
        GLenum err = glGetError();
        std::fprintf(stderr,
            "[I] angle: dump-frame state tid=%llu ctx=%p surf=%p glErr=0x%x\n",
            tid, (void*)curC, (void*)curS, err);
        std::fflush(stderr);
        // v1.0.64 diag: also dump FBO + read-buffer + clear-color
        // + scissor + colormask state so we can root-cause "engine
        // makes lots of GL calls but framebuffer reads back as all
        // zeros" cases. The common offenders are:
        //   - non-default FBO bound (engine drew elsewhere)
        //   - color mask all-false (drew but writes suppressed)
        //   - scissor enabled with empty rect (no fragments)
        //   - clear color != 0 but draw calls don't produce frags
        // GLES2 only exposes a single read+draw binding via the
        // GL_FRAMEBUFFER_BINDING get-arg. The GLES3
        // GL_{DRAW,READ}_FRAMEBUFFER_BINDING split is unavailable
        // in the GLES2 headers ANGLE ships with us, so we report
        // the one combined value.
        GLint fbo_bind = -1;
        GLfloat clear_col[4] = {-1, -1, -1, -1};
        GLboolean color_mask[4] = {0, 0, 0, 0};
        GLint scissor_box[4] = {0, 0, 0, 0};
        GLboolean scissor_on = false;
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &fbo_bind);
        glGetFloatv(GL_COLOR_CLEAR_VALUE, clear_col);
        glGetBooleanv(GL_COLOR_WRITEMASK, color_mask);
        glGetIntegerv(GL_SCISSOR_BOX, scissor_box);
        scissor_on = glIsEnabled(GL_SCISSOR_TEST);
        std::fprintf(stderr,
            "[I] angle: dump-frame fbo=%d  "
            "clearCol=(%.2f,%.2f,%.2f,%.2f)  "
            "colorMask=(%d,%d,%d,%d)  "
            "scissor=%s rect=(%d,%d,%d,%d)\n",
            fbo_bind,
            clear_col[0], clear_col[1], clear_col[2], clear_col[3],
            (int)color_mask[0], (int)color_mask[1],
            (int)color_mask[2], (int)color_mask[3],
            scissor_on ? "on" : "off",
            scissor_box[0], scissor_box[1],
            scissor_box[2], scissor_box[3]);
        std::fflush(stderr);
        // If a non-default FBO is bound, force the binding back to
        // 0 so the readback samples the same surface that ends up
        // on screen. Restore the original binding after.
        GLint saved_fbo = fbo_bind;
        if (fbo_bind != 0) {
            std::fprintf(stderr,
                "[I] angle: dump rebinding FBO 0 (was %d)\n",
                fbo_bind);
            glBindFramebuffer(GL_FRAMEBUFFER, 0);
        }
        // Force a viewport read with a fallback to drawable-size.
        GLint vp[4] = {0,0,0,0};
        glGetIntegerv(GL_VIEWPORT, vp);
        int x = vp[0], y = vp[1], w = vp[2], h = vp[3];
        std::fprintf(stderr, "[I] angle: viewport read x=%d y=%d w=%d h=%d\n", x, y, w, h);
        if (w == 0 || h == 0) {
            w = g_init_width;
            h = g_init_height;
            std::fprintf(stderr, "[I] angle: viewport fallback %dx%d\n", w, h);
        }
        std::fflush(stderr);
        if (w > 0 && h > 0 && w <= 8192 && h <= 8192) {
            std::vector<uint8_t> rgba(static_cast<size_t>(w) * h * 4);
            glReadPixels(x, y, w, h, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
            char path[256];
            std::snprintf(path, sizeof(path),
                          "/tmp/macapk_frame_%d.ppm", n);
            FILE* f = std::fopen(path, "wb");
            if (f) {
                std::fprintf(f, "P6\n%d %d\n255\n", w, h);
                // Vertically flip (GL origin is bottom-left, PPM is
                // top-left) and drop alpha to make a 3-byte RGB row.
                std::vector<uint8_t> row(static_cast<size_t>(w) * 3);
                for (int yy = h - 1; yy >= 0; --yy) {
                    const uint8_t* src = &rgba[static_cast<size_t>(yy) * w * 4];
                    for (int xx = 0; xx < w; ++xx) {
                        row[xx*3 + 0] = src[xx*4 + 0]; // R
                        row[xx*3 + 1] = src[xx*4 + 1]; // G
                        row[xx*3 + 2] = src[xx*4 + 2]; // B
                    }
                    std::fwrite(row.data(), 1, row.size(), f);
                }
                std::fclose(f);
                // v1.0.64 diag: report quick byte stats on the
                // pixel data we just read. nonzero=0 means pure
                // black; mean<5 means very dark; high
                // unique_bytes means real content.
                size_t total = rgba.size();
                size_t nonzero = 0;
                uint64_t sum = 0;
                uint8_t seen_set[32] = {0};
                int unique_bytes = 0;
                for (size_t i = 0; i < total; ++i) {
                    uint8_t v = rgba[i];
                    if (v != 0) ++nonzero;
                    sum += v;
                    int bit = v >> 3;
                    if (!(seen_set[bit >> 3] & (1u << (bit & 7)))) {
                        seen_set[bit >> 3] |= (1u << (bit & 7));
                        ++unique_bytes;
                    }
                }
                double mean = total ? double(sum) / double(total) : 0;
                double nz_pct = total ? 100.0 * double(nonzero)
                                          / double(total) : 0;
                std::fprintf(stderr,
                    "[I] cocoa_v2: dumped frame #%d to %s "
                    "(viewport=%d,%d %dx%d) "
                    "[stats: nonzero=%.1f%% mean=%.1f uniq=%d]\n",
                    n, path, x, y, w, h,
                    nz_pct, mean, unique_bytes);
            } else {
                std::fprintf(stderr,
                    "[E] cocoa_v2: failed to open %s for frame dump\n",
                    path);
            }
        }
        // Restore any non-default FBO we rebound above so the
        // engine's next-frame state is untouched.
        if (saved_fbo != 0) {
            glBindFramebuffer(GL_FRAMEBUFFER, saved_fbo);
        }
    }
    // Self-capture (v1.0.675, permission-free -- see macapk/self_capture.h).
    // Must run BEFORE eglSwapBuffers: the backbuffer is undefined after the
    // swap. Unlike MACAPK_DEBUG_DUMPFRAME above, this fires on demand for an
    // ALREADY-RUNNING app instead of at frame numbers fixed before launch.
    if (!withheld && macapk::SelfCaptureRequested("gl")) {
        GLint fbo_bind = 0, vp[4] = {0, 0, 0, 0};
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &fbo_bind);
        glGetIntegerv(GL_VIEWPORT, vp);
        // Read what actually reaches the screen: rebind FBO 0 if the engine
        // left another target bound, then restore it so the next frame's state
        // is untouched.
        if (fbo_bind != 0) glBindFramebuffer(GL_FRAMEBUFFER, 0);
        // SIZE: ask the SURFACE, not the viewport (v1.0.835). Reading vp[2]/vp[3]
        // was a real undercount, not a cosmetic one: the viewport is whatever the
        // engine last set, and a deferred/post-processed engine leaves it sized to
        // its LAST offscreen target rather than to the window. glReadPixels then
        // returns that small rect anchored at the bottom-left corner of FBO 0, so a
        // fully-rendered frame came back as a corner crop -- measured 2026-07-29 as
        // unciv scoring ~8,500 colours on this source against 24,869-26,283 for a
        // window capture of the same run. Note that undercount is ABI-INDEPENDENT:
        // it is the engine's present path, nothing to do with the translator tier.
        // eglQuerySurface is the authoritative answer (ANGLE reports the drawable's
        // pixel size); viewport, then the AngleInit dims, remain fallbacks.
        EGLint sw = 0, sh = 0;
        if (g_surface != EGL_NO_SURFACE) {
            if (eglQuerySurface(g_display, g_surface, EGL_WIDTH,  &sw) != EGL_TRUE) sw = 0;
            if (eglQuerySurface(g_display, g_surface, EGL_HEIGHT, &sh) != EGL_TRUE) sh = 0;
        }
        int w = sw > 0 ? sw : (vp[2] > 0 ? vp[2] : g_init_width);
        int h = sh > 0 ? sh : (vp[3] > 0 ? vp[3] : g_init_height);
        if (w > 0 && h > 0 && w <= 8192 && h <= 8192) {
            // Say when the two disagree, so a future reader can tell a genuinely
            // blank frame from a source that was looking at the wrong rectangle.
            if ((vp[2] > 0 && vp[2] != w) || (vp[3] > 0 && vp[3] != h)) {
                std::fprintf(stderr,
                    "[self-capture] gl: reading surface %dx%d (engine viewport is "
                    "%dx%d -- viewport would have cropped the frame)\n",
                    w, h, vp[2], vp[3]);
                std::fflush(stderr);
            }
            std::vector<uint8_t> rgba((size_t)w * h * 4);
            glReadPixels(0, 0, w, h, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
            macapk::SelfCaptureWriteRGBA(rgba.data(), w, h, /*bottom_up=*/true, "gl");
        }
        if (fbo_bind != 0) glBindFramebuffer(GL_FRAMEBUFFER, (GLuint)fbo_bind);
    }
    eglSwapBuffers(g_display, g_surface);
}

void AngleFinish() {
    if (!g_initialized) return;
    if (MakeCurrent()) {
        // glFinish -> ANGLE ContextMtl::finishCommandBuffer: commit the current
        // command buffer AND waitUntilCompleted. This makes our serial
        // completable and pops it off the per-display shared FIFO
        // (mMetalCmdBuffers), so a native-EGL engine sharing the display's
        // CommandQueue never blocks on a stranded framework buffer.
        glFinish();
    }
    // Release the framework context from this (main) thread: with no surface/
    // context current, ANGLE cannot lazily begin another (uncommitted) command
    // buffer for it and re-strand the shared FIFO.
    eglMakeCurrent(g_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    std::fprintf(stderr,
        "[I] angle: AngleFinish -- framework context drained + released\n");
    std::fflush(stderr);
    BlobCacheLogSummary("finish");
}

void AngleResize(int width, int height) {
    if (!g_initialized) return;
    if (MakeCurrent()) glViewport(0, 0, width, height);
}

}  // namespace macapk

// Blob-cache installer for EGLDisplays this file does not own.
//
// EGL_ANDROID_blob_cache is per-EGLDisplay, and Mac.apk creates TWO displays:
// the framework one above (GLSurfaceView / Java GLES -> cocoa_bridge ->
// AngleInit), and a second one inside the Bionic shim for apps that drive EGL
// natively (__macapk_arm64_eglGetDisplay in translator/src/bionic_shim.cpp,
// which is also where MACAPK_ANGLE_BACKEND=vulkan selects the Vulkan backend).
// The AGDK/GameActivity engines -- RenderDragon/MCPE, Unity -- go through that
// second display, so they get NO caching from the call above.
//
// Wiring that up is a one-liner in the shim's eglInitialize wrapper:
//
//     using Fn = void (*)(void*);
//     if (auto f = (Fn)dlsym(RTLD_DEFAULT, "macapk_angle_install_blob_cache"))
//         f(dpy);   // after real eglInitialize() succeeds
//
// It lives here rather than there because all the contract knowledge (the
// double get(), the atomic write, the FATAL-on-corrupt-pipeline-cache hazard)
// is here, and duplicating it in the shim would mean two implementations to
// keep correct.
extern "C" void macapk_angle_install_blob_cache(void* egl_display) {
    if (egl_display == nullptr) return;
    macapk::InstallBlobCacheForDisplay(egl_display);
}

// ---------------------------------------------------------------------------
// A SurfaceView GL thread's WINDOW surface, for the javax EGL10 facade
// (MACAPK_GL_SURVIVOR_CONTEXT, 2026-09-26; docs/openttd-survivor-gl-context_
// 2026-09-26.md).
//
// On Android, eglCreateWindowSurface(dpy, cfg, surfaceHolder, attribs) from
// Java reaches the driver with the SurfaceView's ANativeWindow
// (frameworks/base android14-release, EGLImpl.java:87-101 ->
// com_google_android_gles_jni_EGLImpl.cpp jni_eglCreateWindowSurface
// :257-282: android_view_Surface_getNativeWindow, then eglCreateWindowSurface
// with window.get()). Our SurfaceView's "native window" is the dedicated
// CAMetalLayer that cocoa_bridge.mm makes for exactly this purpose --
// CocoaEnsureNativeEglLayer, the layer ANativeWindow_fromSurface hands NDK
// engines (Unity, AGDK, SDL2) -- and ANGLE's Metal backend takes a CALayer as
// its EGLNativeWindowType (DisplayMtl::isValidNativeWindow). So the Java path
// makes the SAME window the NDK path makes, then tells the runtime a guest
// window is live (CocoaNoteNativeEglSurfaceLive: the empty framework
// angleLayer stops compositing over it), as
// __macapk_arm64_egl_create_window_surface_bridge does.
//
// Only MacApkEGL10's promoted-survivor path calls this (a SurfaceView GL thread
// that survived the legacy refusal: pelya's libsdl-android fork, OpenTTD).
// A null display is the Java side's capability probe: return null, touch
// nothing.
//
// debug/glsurvivor_gate.sh compiles the lines between the two marker lines
// VERBATIM against real ANGLE, so the gate tests this code, not a copy. Keep
// the block self-contained (jni.h, EGL/egl.h, cstdio, cstdint, vector).
// >>> GLSURVIVOR-GATE-BEGIN
extern "C" void* CocoaEnsureNativeEglLayer(int* outW, int* outH);
extern "C" void  CocoaNoteNativeEglSurfaceLive(void);

namespace macapk {
namespace glsurvivor {

// android.opengl.EGLObjectHandle.getNativeHandle() of a boxed EGL handle.
static void* HandleOf(JNIEnv* env, jobject o) {
    if (!o) return nullptr;
    jclass c = env->FindClass("android/opengl/EGLObjectHandle");
    jmethodID m = c ? env->GetMethodID(c, "getNativeHandle", "()J") : nullptr;
    jlong h = m ? env->CallLongMethod(o, m) : 0;
    if (c) env->DeleteLocalRef(c);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<intptr_t>(h));
}

static jobject JNICALL CreateSurfaceViewWindow(JNIEnv* env, jclass,
                                               jobject dpy, jobject cfg, jintArray attribs) {
    if (!dpy || !cfg) return nullptr;
    EGLDisplay d = static_cast<EGLDisplay>(HandleOf(env, dpy));
    EGLConfig c = static_cast<EGLConfig>(HandleOf(env, cfg));
    if (!d || !c) return nullptr;
    int lw = 0, lh = 0;
    void* layer = CocoaEnsureNativeEglLayer(&lw, &lh);
    if (!layer) {
        std::fprintf(stderr, "[E] angle: SurfaceView window: no native-EGL layer "
                             "(no render view yet) -> EGL_NO_SURFACE\n");
        std::fflush(stderr);
        return nullptr;
    }
    // The Java side has already applied jni_eglCreateWindowSurface's
    // validAttribList (null, or ending in EGL_NONE); copy, do not pin, since
    // EGL runs arbitrary work before it reads the list.
    std::vector<EGLint> al;
    if (attribs) {
        jsize n = env->GetArrayLength(attribs);
        al.resize(static_cast<size_t>(n));
        if (n > 0) env->GetIntArrayRegion(attribs, 0, n, al.data());
    }
    EGLSurface s = eglCreateWindowSurface(d, c, reinterpret_cast<EGLNativeWindowType>(layer),
                                          attribs ? al.data() : nullptr);
    if (s == EGL_NO_SURFACE) {
        std::fprintf(stderr, "[E] angle: SurfaceView window: eglCreateWindowSurface on "
                             "layer %p (%dx%d) failed: 0x%x\n", layer, lw, lh, eglGetError());
        std::fflush(stderr);
        return nullptr;
    }
    CocoaNoteNativeEglSurfaceLive();
    std::fprintf(stderr, "[I] angle: SurfaceView window: EGLSurface %p on native-EGL "
                         "layer %p (%dx%d), thread-owned (javax EGL10)\n", s, layer, lw, lh);
    std::fflush(stderr);
    jclass sc = env->FindClass("android/opengl/EGLSurface");
    jmethodID ctor = sc ? env->GetMethodID(sc, "<init>", "(J)V") : nullptr;
    jobject boxed = ctor ? env->NewObject(sc, ctor,
                                          static_cast<jlong>(reinterpret_cast<intptr_t>(s)))
                         : nullptr;
    if (sc) env->DeleteLocalRef(sc);
    if (!boxed) {
        // Cannot hand it back: do not leak a window nobody can destroy.
        if (env->ExceptionCheck()) env->ExceptionClear();
        eglDestroySurface(d, s);
        return nullptr;
    }
    return boxed;
}

static const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeCreateSurfaceViewWindow"),
     const_cast<char*>("(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;[I)"
                       "Landroid/opengl/EGLSurface;"),
     reinterpret_cast<void*>(CreateSurfaceViewWindow)},
};

}  // namespace glsurvivor

// Registers MacApkEGL10.nativeCreateSurfaceViewWindow. Soft-fails: a framework
// jar without the declaration keeps the survivor on the legacy refusal (the
// Java side probes for the method), so a miss must not abort boot.
void RegisterAngleGlueNatives(JNIEnv* env) {
    jclass c = env->FindClass("javax/microedition/khronos/egl/MacApkEGL10");
    if (!c) {
        env->ExceptionClear();
        std::fprintf(stderr, "[E] angle: MacApkEGL10 not found; SurfaceView window "
                             "bridge unbound\n");
        return;
    }
    if (env->RegisterNatives(c, glsurvivor::kMethods,
                             sizeof(glsurvivor::kMethods) / sizeof(glsurvivor::kMethods[0]))
            != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[E] angle: RegisterNatives(MacApkEGL10) failed; SurfaceView "
                             "window bridge unbound\n");
    }
    env->DeleteLocalRef(c);
}

}  // namespace macapk
// <<< GLSURVIVOR-GATE-END

#endif  // MACAPK_HAS_ANGLE
