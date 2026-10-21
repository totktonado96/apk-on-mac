// jit_wx_guard.cpp -- keep HotSpot's JIT write mode across libjvm's dyld calls.
// The why is in include/macapk/jit_wx_guard.h and
// docs/macos27-tpro-jit-wx-reset_2026-10-19.md; in short, on macOS 27 with
// hardware TPRO on, dyld leaves the calling thread in EXECUTE mode after
// dlopen, while HotSpot still believes it is in WRITE mode.

#include "macapk/jit_wx_guard.h"

#include "../thirdparty/fishhook.h"

#include <dlfcn.h>
#include <jni.h>
#include <mach-o/dyld.h>
#include <pthread.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

// Per-thread record of the mode HotSpot last asked for. pthread TSD rather
// than thread_local: a C++ thread_local's first touch on a thread goes through
// dyld's TLV setup, which is one more dyld path that can rewrite the register.
pthread_key_t g_mode_key;
constexpr uintptr_t kModeWrite = 1;
constexpr uintptr_t kModeExec = 2;

bool g_restore = true;
bool g_simulate = false;

// dyld's dlopen resolves @rpath / @loader_path against the CALLER's image. Our
// wrapper is the caller now, so pass an address inside libjvm through
// dlopen_from (libdyld SPI since macOS 12) to keep libjvm's own resolution.
using DlopenFromFn = void* (*)(const char*, int, void*);
DlopenFromFn g_dlopen_from = nullptr;
void* g_jvm_addr = nullptr;

std::atomic<unsigned> g_dyld_calls{0};
std::atomic<unsigned> g_wx_requests{0};
std::atomic<unsigned> g_reasserts{0};

inline void AfterDyldCall() {
    g_dyld_calls.fetch_add(1, std::memory_order_relaxed);
    if (g_simulate) pthread_jit_write_protect_np(1);
    if (g_restore &&
        reinterpret_cast<uintptr_t>(pthread_getspecific(g_mode_key)) == kModeWrite) {
        pthread_jit_write_protect_np(0);
        g_reasserts.fetch_add(1, std::memory_order_relaxed);
    }
}

extern "C" {

// HotSpot's os::current_thread_enable_wx is the only libjvm caller.
static void WxWriteProtect(int enabled) {
    g_wx_requests.fetch_add(1, std::memory_order_relaxed);
    pthread_setspecific(g_mode_key, reinterpret_cast<void*>(enabled ? kModeExec : kModeWrite));
    pthread_jit_write_protect_np(enabled);
}

static void* WxDlopen(const char* path, int mode) {
    void* r = g_dlopen_from ? g_dlopen_from(path, mode, g_jvm_addr) : dlopen(path, mode);
    AfterDyldCall();
    return r;
}

// libjvm passes RTLD_DEFAULT or a handle (measured on 21.0.11: no RTLD_NEXT or
// RTLD_SELF, the two handles whose meaning depends on the caller).
static void* WxDlsym(void* handle, const char* sym) {
    void* r = dlsym(handle, sym);
    AfterDyldCall();
    return r;
}

static int WxDladdr(const void* addr, Dl_info* info) {
    int r = dladdr(addr, info);
    AfterDyldCall();
    return r;
}

static int WxDlclose(void* handle) {
    int r = dlclose(handle);
    AfterDyldCall();
    return r;
}

static char* WxDlerror() {
    char* r = dlerror();
    AfterDyldCall();
    return r;
}

static uint32_t WxDyldImageCount() {
    uint32_t r = _dyld_image_count();
    AfterDyldCall();
    return r;
}

static const char* WxDyldGetImageName(uint32_t i) {
    const char* r = _dyld_get_image_name(i);
    AfterDyldCall();
    return r;
}

static const struct mach_header* WxDyldGetImageHeader(uint32_t i) {
    const struct mach_header* r = _dyld_get_image_header(i);
    AfterDyldCall();
    return r;
}

}  // extern "C"

bool EnvIs(const char* name, const char* value) {
    const char* v = std::getenv(name);
    return v && std::strcmp(v, value) == 0;
}

}  // namespace

namespace macapk {

void InstallJvmJitWxGuard() {
    static bool done = false;
    if (done) return;
    done = true;

    if (EnvIs("MACAPK_JIT_WX_GUARD", "0") && !EnvIs("MACAPK_JIT_WX_SIMULATE_RESET", "1")) {
        std::fprintf(stderr, "[jitwx] guard off (MACAPK_JIT_WX_GUARD=0)\n");
        return;
    }
    if (!pthread_jit_write_protect_supported_np()) return;
    g_restore = !EnvIs("MACAPK_JIT_WX_GUARD", "0");
    g_simulate = EnvIs("MACAPK_JIT_WX_SIMULATE_RESET", "1");

    // libjvm is linked at launch, so JNI_CreateJavaVM names its image.
    Dl_info info{};
    if (!dladdr(reinterpret_cast<const void*>(&JNI_CreateJavaVM), &info) || !info.dli_fbase) {
        std::fprintf(stderr, "[jitwx] libjvm image not found; guard not installed\n");
        return;
    }
    intptr_t slide = 0;
    bool found = false;
    for (uint32_t i = 0, n = _dyld_image_count(); i < n; ++i) {
        if (_dyld_get_image_header(i) == info.dli_fbase) {
            slide = _dyld_get_image_vmaddr_slide(i);
            found = true;
            break;
        }
    }
    if (!found) {
        std::fprintf(stderr, "[jitwx] libjvm slide not found; guard not installed\n");
        return;
    }
    if (pthread_key_create(&g_mode_key, nullptr) != 0) {
        std::fprintf(stderr, "[jitwx] pthread_key_create failed; guard not installed\n");
        return;
    }
    g_dlopen_from = reinterpret_cast<DlopenFromFn>(dlsym(RTLD_DEFAULT, "dlopen_from"));
    g_jvm_addr = reinterpret_cast<void*>(&JNI_CreateJavaVM);

    static struct rebinding rb[] = {
        {"pthread_jit_write_protect_np", reinterpret_cast<void*>(&WxWriteProtect), nullptr},
        {"dlopen",                       reinterpret_cast<void*>(&WxDlopen), nullptr},
        {"dlsym",                        reinterpret_cast<void*>(&WxDlsym), nullptr},
        {"dladdr",                       reinterpret_cast<void*>(&WxDladdr), nullptr},
        {"dlclose",                      reinterpret_cast<void*>(&WxDlclose), nullptr},
        {"dlerror",                      reinterpret_cast<void*>(&WxDlerror), nullptr},
        {"_dyld_image_count",            reinterpret_cast<void*>(&WxDyldImageCount), nullptr},
        {"_dyld_get_image_name",         reinterpret_cast<void*>(&WxDyldGetImageName), nullptr},
        {"_dyld_get_image_header",       reinterpret_cast<void*>(&WxDyldGetImageHeader), nullptr},
    };
    if (rebind_symbols_image(info.dli_fbase, slide, rb, sizeof(rb) / sizeof(rb[0])) != 0) {
        std::fprintf(stderr, "[jitwx] rebind failed; guard not installed\n");
        return;
    }
    std::fprintf(stderr, "[jitwx] guard installed on %s%s%s\n",
                 info.dli_fname ? info.dli_fname : "libjvm",
                 g_restore ? "" : " (restore OFF)",
                 g_simulate ? " (simulating the TPRO reset)" : "");
}

void LogJvmJitWxGuardStats() {
    std::fprintf(stderr, "[jitwx] stats: dyld calls=%u wx switches=%u write re-asserts=%u\n",
                 g_dyld_calls.load(), g_wx_requests.load(), g_reasserts.load());
}

}  // namespace macapk
