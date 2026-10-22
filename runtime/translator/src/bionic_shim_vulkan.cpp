// bionic_shim_vulkan.cpp -- the guest's libvulkan.so: Android's Vulkan API,
// served by MoltenVK (Vulkan over Metal), for apps that require Vulkan.
//
// WHY THIS FILE EXISTS
// --------------------
// Until 2026-10-05 a guest dlopen("libvulkan.so") always answered NULL ("we have
// no Vulkan backend"), so every engine fell back to GLES. Asphalt Legends
// (Gameloft, uses-feature android.hardware.vulkan.version) has no GLES path: its
// renderer list comes only from vkEnumeratePhysicalDevices, an empty list makes
// its init return false, and its app thread then calls GameActivity_finish -- the
// owner saw the Gameloft splash, then a black window. Play only installs such an
// app on a device with Vulkan, so the faithful answer is a working Vulkan.
//
// macOS has Vulkan through MoltenVK, which Apk on Mac already ships for ANGLE's
// Vulkan backend (libMoltenVK.dylib next to the runtime, MoltenVK_icd.json).
// This TU hands the guest MoltenVK's own entry points and translates only the
// Android-specific window-system piece (the decision ladder's rung 1: route to
// what the host already has).
//
// WHAT IT TRANSLATES (everything else is MoltenVK's function, verbatim)
// ----------------------------------------------------------------------
//   - VK_KHR_android_surface. Android's instance surface extension; MoltenVK has
//     VK_EXT_metal_surface instead. vkEnumerateInstanceExtensionProperties lists
//     VK_KHR_android_surface in place of the Apple surface extensions,
//     vkCreateInstance enables VK_EXT_metal_surface where the guest asked for
//     VK_KHR_android_surface, and vkCreateAndroidSurfaceKHR creates a Metal
//     surface on the CAMetalLayer behind the guest's ANativeWindow (the layer
//     ANativeWindow_fromSurface answered with, __macapk_native_window_layer).
//     VkAndroidSurfaceCreateInfoKHR and VkMetalSurfaceCreateInfoEXT have the same
//     shape (sType, pNext, flags, then the one pointer).
//   - VK_KHR_portability_subset. The spec requires a device that advertises it
//     to have it enabled (VUID-VkDeviceCreateInfo-pProperties-04451); an Android
//     engine never asks for it, so vkCreateDevice adds it.
//   - vkGetInstanceProcAddr returns these wrappers for their names, so an engine
//     that resolves everything through it (Asphalt dlsyms only the five global
//     commands) gets the same translation.
//
// ABI: Vulkan has no variadic and no by-value struct parameters, and the Apple
// arm64 calling convention differs from AAPCS64 only for stack-passed arguments
// smaller than 8 bytes that sit next to each other. No command MoltenVK
// implements passes two such arguments on the stack (vkCmdPipelineBarrier and
// vkCmdWaitEvents place a uint32 then a pointer, which both ABIs lay out at the
// same offsets), so MoltenVK's entry points are called directly.
//
// POLICY (MACAPK_GUEST_VULKAN): "auto" (default) exposes Vulkan to an app whose
// manifest REQUIRES android.hardware.vulkan.* -- Boot sets the JVM system
// property macapk.guestVulkan from the manifest -- and keeps answering NULL for
// every other app, which then keeps the GLES path it has today. "1" exposes it
// to every app, "0" to none. A DEVIATION, on purpose: a real Vulkan device
// exposes it to all apps, and Unity and others would switch to it. That switch
// waits for a fleet measurement of this path; the gate is how it gets one.
//
// WHY A SEPARATE TU: bionic_shim.cpp is shared by many lanes. The cross-TU
// dependencies are __macapk_native_window_layer (bionic_shim.cpp) and the two
// entry points below, which bionic_shim.cpp's dlopen/dlsym call.

#include <jni.h>

#include <dlfcn.h>
#include <libgen.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

extern "C" void* __macapk_native_window_layer(void* window);

namespace {

// ---- The handful of Vulkan types this file touches (vulkan_core.h) ----------
typedef int32_t  VkResult;
typedef uint32_t VkFlags;
typedef void*    VkInstance;
typedef void*    VkPhysicalDevice;
typedef void*    VkDevice;
typedef uint64_t VkSurfaceKHR;
typedef void (*PFN_vkVoidFunction)(void);

constexpr VkResult VK_SUCCESS = 0;
constexpr VkResult VK_INCOMPLETE = 5;
constexpr VkResult VK_ERROR_INITIALIZATION_FAILED = -3;
constexpr VkResult VK_ERROR_LAYER_NOT_PRESENT = -6;
constexpr VkResult VK_ERROR_EXTENSION_NOT_PRESENT = -7;
constexpr int32_t VK_STRUCTURE_TYPE_METAL_SURFACE_CREATE_INFO_EXT = 1000217000;
constexpr uint32_t VK_MAX_EXTENSION_NAME_SIZE = 256;

struct VkExtensionProperties {
    char     extensionName[VK_MAX_EXTENSION_NAME_SIZE];
    uint32_t specVersion;
};
struct VkInstanceCreateInfo {
    int32_t            sType;
    const void*        pNext;
    VkFlags            flags;
    const void*        pApplicationInfo;
    uint32_t           enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t           enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
};
struct VkDeviceCreateInfo {
    int32_t            sType;
    const void*        pNext;
    VkFlags            flags;
    uint32_t           queueCreateInfoCount;
    const void*        pQueueCreateInfos;
    uint32_t           enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t           enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
    const void*        pEnabledFeatures;
};
struct VkAndroidSurfaceCreateInfoKHR {
    int32_t     sType;
    const void* pNext;
    VkFlags     flags;
    void*       window;          // ANativeWindow*
};
struct VkMetalSurfaceCreateInfoEXT {
    int32_t     sType;
    const void* pNext;
    VkFlags     flags;
    const void* pLayer;          // const CAMetalLayer*
};

typedef PFN_vkVoidFunction (*PFN_GetInstanceProcAddr)(VkInstance, const char*);
typedef VkResult (*PFN_EnumerateInstanceExtensionProperties)(
    const char*, uint32_t*, VkExtensionProperties*);
typedef VkResult (*PFN_CreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef VkResult (*PFN_CreateMetalSurfaceEXT)(VkInstance, const VkMetalSurfaceCreateInfoEXT*,
                                              const void*, VkSurfaceKHR*);
typedef VkResult (*PFN_EnumerateDeviceExtensionProperties)(
    VkPhysicalDevice, const char*, uint32_t*, VkExtensionProperties*);
typedef VkResult (*PFN_CreateDevice)(VkPhysicalDevice, const VkDeviceCreateInfo*,
                                     const void*, VkDevice*);

constexpr const char* kAndroidSurface = "VK_KHR_android_surface";
constexpr uint32_t kAndroidSurfaceSpec = 6;
constexpr const char* kMetalSurface = "VK_EXT_metal_surface";
constexpr const char* kPortabilitySubset = "VK_KHR_portability_subset";

// Apple-only instance extensions an Android app could never see listed.
bool apple_only_instance_ext(const char* n) {
    return std::strcmp(n, kMetalSurface) == 0
        || std::strcmp(n, "VK_MVK_macos_surface") == 0
        || std::strcmp(n, "VK_MVK_ios_surface") == 0
        || std::strcmp(n, "VK_KHR_portability_enumeration") == 0;
}

// ---- MoltenVK --------------------------------------------------------------
void* g_mvk = nullptr;
PFN_GetInstanceProcAddr g_gipa = nullptr;

// libMoltenVK.dylib sits next to MoltenVK_icd.json, whose path main.cpp exports
// as VK_DRIVER_FILES / VK_ICD_FILENAMES for ANGLE's loader before any guest
// runs. The same ICD therefore serves ANGLE and the guest.
void* open_moltenvk() {
    std::vector<std::string> tries;
    for (const char* var : {"VK_DRIVER_FILES", "VK_ICD_FILENAMES"}) {
        const char* v = std::getenv(var);
        if (!v || !*v) continue;
        std::string p(v);
        size_t colon = p.find(':');
        if (colon != std::string::npos) p.resize(colon);
        size_t slash = p.rfind('/');
        if (slash != std::string::npos) tries.push_back(p.substr(0, slash) + "/libMoltenVK.dylib");
    }
    Dl_info di{};
    if (dladdr(reinterpret_cast<void*>(&open_moltenvk), &di) && di.dli_fname) {
        std::string p(di.dli_fname);
        size_t slash = p.rfind('/');
        if (slash != std::string::npos) tries.push_back(p.substr(0, slash) + "/libMoltenVK.dylib");
    }
    tries.push_back("libMoltenVK.dylib");
    for (const std::string& p : tries) {
        if (void* h = dlopen(p.c_str(), RTLD_NOW | RTLD_LOCAL)) {
            std::fprintf(stderr, "[guest-vulkan] MoltenVK: %s\n", p.c_str());
            return h;
        }
    }
    std::fprintf(stderr, "[guest-vulkan] MoltenVK not found (%s)\n", dlerror());
    return nullptr;
}

bool load() {
    static std::once_flag once;
    std::call_once(once, [] {
        g_mvk = open_moltenvk();
        if (g_mvk)
            g_gipa = reinterpret_cast<PFN_GetInstanceProcAddr>(
                dlsym(g_mvk, "vkGetInstanceProcAddr"));
    });
    return g_gipa != nullptr;
}

template <typename F> F gipa(VkInstance inst, const char* name) {
    return reinterpret_cast<F>(g_gipa(inst, name));
}

// ---- The policy ------------------------------------------------------------
// The JVM system property Boot sets from the manifest ("1" when the app
// requires Vulkan). Read through the created JavaVM, from whatever thread asks.
bool app_requires_vulkan() {
    using GetVMs = jint (*)(JavaVM**, jsize, jsize*);
    auto get_vms = reinterpret_cast<GetVMs>(dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    JavaVM* vm = nullptr; jsize n = 0;
    if (!get_vms || get_vms(&vm, 1, &n) != JNI_OK || n < 1 || !vm) return false;
    JNIEnv* env = nullptr;
    bool attached = false;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) return false;
        attached = true;
    }
    bool yes = false;
    if (env && !env->ExceptionCheck()) {
        jclass sys = env->FindClass("java/lang/System");
        jmethodID gp = sys ? env->GetStaticMethodID(sys, "getProperty",
                                 "(Ljava/lang/String;)Ljava/lang/String;") : nullptr;
        jstring key = gp ? env->NewStringUTF("macapk.guestVulkan") : nullptr;
        jstring val = key ? static_cast<jstring>(env->CallStaticObjectMethod(sys, gp, key)) : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (val) {
            const char* s = env->GetStringUTFChars(val, nullptr);
            yes = s && s[0] == '1';
            if (s) env->ReleaseStringUTFChars(val, s);
            env->DeleteLocalRef(val);
        }
        if (key) env->DeleteLocalRef(key);
        if (sys) env->DeleteLocalRef(sys);
    }
    if (attached) vm->DetachCurrentThread();
    return yes;
}

bool guest_vulkan_enabled() {
    static const int on = [] {
        const char* e = std::getenv("MACAPK_GUEST_VULKAN");
        int r;
        if (e && e[0] == '0') r = 0;
        else if (e && e[0] == '1') r = 1;
        else r = app_requires_vulkan() ? 1 : 0;
        std::fprintf(stderr, "[guest-vulkan] MACAPK_GUEST_VULKAN=%s -> %s\n",
                     e ? e : "auto", r ? "Vulkan for this app (MoltenVK)"
                                       : "no Vulkan (the app does not require it)");
        return r;
    }();
    return on != 0;
}

// ---- The translated commands -----------------------------------------------
VkResult vk_EnumerateInstanceExtensionProperties(const char* layer, uint32_t* count,
                                                 VkExtensionProperties* props) {
    auto real = reinterpret_cast<PFN_EnumerateInstanceExtensionProperties>(
        dlsym(g_mvk, "vkEnumerateInstanceExtensionProperties"));
    if (!real || !count) return VK_ERROR_INITIALIZATION_FAILED;
    if (layer) return real(layer, count, props);   // MoltenVK has no layers
    uint32_t n = 0;
    VkResult r = real(nullptr, &n, nullptr);
    if (r != VK_SUCCESS) return r;
    std::vector<VkExtensionProperties> all(n);
    r = real(nullptr, &n, all.data());
    if (r < 0) return r;
    all.resize(n);
    std::vector<VkExtensionProperties> out;
    bool has_metal = false;
    for (const VkExtensionProperties& e : all) {
        if (std::strcmp(e.extensionName, kMetalSurface) == 0) has_metal = true;
        if (!apple_only_instance_ext(e.extensionName)) out.push_back(e);
    }
    if (has_metal) {
        VkExtensionProperties a{};
        std::strncpy(a.extensionName, kAndroidSurface, VK_MAX_EXTENSION_NAME_SIZE - 1);
        a.specVersion = kAndroidSurfaceSpec;
        out.push_back(a);
    }
    // The two-call idiom: report the full count, fill up to the caller's.
    if (!props) { *count = static_cast<uint32_t>(out.size()); return VK_SUCCESS; }
    uint32_t k = *count < out.size() ? *count : static_cast<uint32_t>(out.size());
    for (uint32_t i = 0; i < k; ++i) props[i] = out[i];
    *count = k;
    return k < out.size() ? VK_INCOMPLETE : VK_SUCCESS;
}

VkResult vk_CreateInstance(const VkInstanceCreateInfo* ci, const void* alloc, VkInstance* out) {
    auto real = reinterpret_cast<PFN_CreateInstance>(dlsym(g_mvk, "vkCreateInstance"));
    if (!real || !ci) return VK_ERROR_INITIALIZATION_FAILED;
    std::vector<const char*> exts;
    bool want_metal = false;
    for (uint32_t i = 0; i < ci->enabledExtensionCount; ++i) {
        const char* n = ci->ppEnabledExtensionNames[i];
        if (n && std::strcmp(n, kAndroidSurface) == 0) { want_metal = true; continue; }
        exts.push_back(n);
    }
    if (want_metal) exts.push_back(kMetalSurface);
    VkInstanceCreateInfo c = *ci;
    c.enabledExtensionCount = static_cast<uint32_t>(exts.size());
    c.ppEnabledExtensionNames = exts.empty() ? nullptr : exts.data();
    VkResult r = real(&c, alloc, out);
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1) < 4) {
        std::fprintf(stderr, "[guest-vulkan] vkCreateInstance: %u extension(s)%s, %u layer(s) -> %d\n",
                     c.enabledExtensionCount, want_metal ? " (android_surface -> metal_surface)" : "",
                     c.enabledLayerCount, r);
    }
    return r;
}

VkResult vk_CreateAndroidSurfaceKHR(VkInstance inst, const VkAndroidSurfaceCreateInfoKHR* ci,
                                    const void* alloc, VkSurfaceKHR* out) {
    if (!ci || !out) return VK_ERROR_INITIALIZATION_FAILED;
    void* layer = __macapk_native_window_layer(ci->window);
    auto create = gipa<PFN_CreateMetalSurfaceEXT>(inst, "vkCreateMetalSurfaceEXT");
    VkResult r = VK_ERROR_INITIALIZATION_FAILED;
    if (layer && create) {
        VkMetalSurfaceCreateInfoEXT m{};
        m.sType = VK_STRUCTURE_TYPE_METAL_SURFACE_CREATE_INFO_EXT;
        m.pNext = nullptr;
        m.flags = 0;
        m.pLayer = layer;
        r = create(inst, &m, alloc, out);
    }
    std::fprintf(stderr, "[guest-vulkan] vkCreateAndroidSurfaceKHR(window=%p) -> CAMetalLayer %p -> %d\n",
                 ci->window, layer, r);
    return r;
}

VkResult vk_CreateDevice(VkPhysicalDevice pd, const VkDeviceCreateInfo* ci,
                         const void* alloc, VkDevice* out) {
    auto real = gipa<PFN_CreateDevice>(nullptr, "vkCreateDevice");
    if (!real) real = reinterpret_cast<PFN_CreateDevice>(dlsym(g_mvk, "vkCreateDevice"));
    if (!real || !ci) return VK_ERROR_INITIALIZATION_FAILED;
    auto enum_dev = reinterpret_cast<PFN_EnumerateDeviceExtensionProperties>(
        dlsym(g_mvk, "vkEnumerateDeviceExtensionProperties"));
    bool advertised = false;
    if (enum_dev) {
        uint32_t n = 0;
        if (enum_dev(pd, nullptr, &n, nullptr) == VK_SUCCESS && n) {
            std::vector<VkExtensionProperties> all(n);
            if (enum_dev(pd, nullptr, &n, all.data()) >= 0)
                for (uint32_t i = 0; i < n; ++i)
                    if (std::strcmp(all[i].extensionName, kPortabilitySubset) == 0) advertised = true;
        }
    }
    std::vector<const char*> exts(ci->ppEnabledExtensionNames,
                                  ci->ppEnabledExtensionNames + ci->enabledExtensionCount);
    bool present = false;
    for (const char* n : exts) if (n && std::strcmp(n, kPortabilitySubset) == 0) present = true;
    if (advertised && !present) exts.push_back(kPortabilitySubset);
    VkDeviceCreateInfo c = *ci;
    c.enabledExtensionCount = static_cast<uint32_t>(exts.size());
    c.ppEnabledExtensionNames = exts.empty() ? nullptr : exts.data();
    VkResult r = real(pd, &c, alloc, out);
    std::fprintf(stderr, "[guest-vulkan] vkCreateDevice: %u extension(s)%s -> %d\n",
                 c.enabledExtensionCount, advertised && !present ? " (+portability_subset)" : "", r);
    return r;
}

PFN_vkVoidFunction translated(const char* name) {
    if (!name) return nullptr;
    if (std::strcmp(name, "vkEnumerateInstanceExtensionProperties") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(&vk_EnumerateInstanceExtensionProperties);
    if (std::strcmp(name, "vkCreateInstance") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(&vk_CreateInstance);
    if (std::strcmp(name, "vkCreateAndroidSurfaceKHR") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(&vk_CreateAndroidSurfaceKHR);
    if (std::strcmp(name, "vkCreateDevice") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(&vk_CreateDevice);
    return nullptr;
}

PFN_vkVoidFunction vk_GetInstanceProcAddr(VkInstance inst, const char* name) {
    if (PFN_vkVoidFunction f = translated(name)) return f;
    if (name && std::strcmp(name, "vkGetInstanceProcAddr") == 0)
        return reinterpret_cast<PFN_vkVoidFunction>(&vk_GetInstanceProcAddr);
    return g_gipa(inst, name);
}

}  // namespace

// dlopen("libvulkan.so"): true when this app gets Vulkan (and MoltenVK loaded).
extern "C" bool __macapk_guest_vulkan_available() {
    return guest_vulkan_enabled() && load();
}

// dlsym(<libvulkan.so handle>, name) and an imported vk* symbol: the translated
// command, else MoltenVK's own export (the global and core commands), else what
// vkGetInstanceProcAddr(NULL, name) answers.
extern "C" void* __macapk_guest_vulkan_symbol(const char* name) {
    if (!name || !__macapk_guest_vulkan_available()) return nullptr;
    void* p = reinterpret_cast<void*>(vk_GetInstanceProcAddr(nullptr, name));
    if (!p) p = dlsym(g_mvk, name);
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1) < 12)
        std::fprintf(stderr, "[guest-vulkan] dlsym(libvulkan.so, %s) -> %p\n", name, p);
    return p;
}
