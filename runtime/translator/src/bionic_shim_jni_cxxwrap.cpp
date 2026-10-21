// bionic_shim_jni_cxxwrap.cpp -- the `_JNIEnv::Call*Method(..., ...)` C++
// wrapper overrides, with float/double variadic arguments.
//
// ---------------------------------------------------------------------------
// WHAT THESE ARE
// ---------------------------------------------------------------------------
// NDK toolchains can emit jni.h's C++ convenience wrappers out of line, as weak
// exports such as `_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz`
// (`_JNIEnv::CallStaticVoidMethod(jclass, jmethodID, ...)`). The library then
// calls its own wrapper through the PLT, so the call is an import, and
// Image::resolve_external binds `__macapk_arm64_<name>` in preference to the
// library's own body. Six of these names have an override here (the six that
// used to live in bionic_shim.cpp, see its "_JNIEnv::Call*Method variadic ABI
// bridge" note). Every other wrapper name keeps the library's own body, which
// does va_start and calls functions->Call*MethodV -- the slot
// MACAPK_BIONIC_JNI_BRIDGE in bionic_shim.cpp already repacks by signature.
//
// ---------------------------------------------------------------------------
// THE BUG (Plague Inc. 1.24.4, 2026-10-07)
// ---------------------------------------------------------------------------
// The old overrides packed x3..x7 into a jvalue[] and called the *A* slot. That
// is right only while every variadic argument is GP-sized. An AAPCS64 caller
// passes a float/double variadic in d0..d7 (C promotes float to double), so
// for a (F)V method the JVM read the jvalue built from x3 -- whatever pointer
// the caller last left there. libPlagueIncAndroidNative.so,
// SoundMgr::SetGlobalMusicVolume(float) at +0x5da2f0:
//
//     fcvt d0, s8          ; the volume, promoted to double
//     ldr  x1, [x21]       ; jclass NewMusic
//     mov  x0, x19 ; mov x2, x20
//     bl   _JNIEnv::CallStaticVoidMethod(jclass, jmethodID, ...)@plt
//
// and the run log showed `NewMusic: Java::SetGlobalMusicVolume(-22753243561984)`
// (bits 0xd5a58d38, the low half of a pointer). NewMusic multiplies that into
// MediaPlayer.setVolume, so the music played at full-scale clipping whatever
// the player's volume. SoundMgr::SetGlobalSoundVolume (+0x5da418) has the
// same shape.
//
// ---------------------------------------------------------------------------
// THE FIX
// ---------------------------------------------------------------------------
// Do what the library's own wrapper does: va_start. Each override captures
// x3..x7 and q0..q7 into an AAPCS64 va_list in its own frame and hands it to a
// C worker, which repacks through bionic_shim.cpp's signature-aware
// bionic_repack_args (the same one the V bridge and the bare-ellipsis bridge
// use; it resolves 'F'/'D' parameters by reflection and reads them from the VR
// save area) and calls the *A* slot. All-GP signatures pack exactly as before.
//
// No caller test is needed (unlike bionic_shim_jni_bare.cpp, whose vtable
// slots are global): these names are reached only through a guest import, so
// the caller is always AAPCS64.
//
// The va_list layout is the one bionic_shim_jni_bare.cpp's banner derives from
// clang's own codegen: { __stack, __gr_top, __vr_top, __gr_offs, __vr_offs },
// three named GP args so __gr_offs = -(8-3)*8 = -40, no named FP arg so
// __vr_offs = -128.
//
// Frame (256 bytes, sp 16-aligned for the inner bl):
//   [sp+0x00 .. 0x7F]  VR save area, q0..q7      -> __vr_top = sp+0x80
//   [sp+0x80 .. 0x9F]  the va_list
//   [sp+0xC0 .. 0xCF]  saved x29, x30
//   [sp+0xD8 .. 0xFF]  GP save area, x3..x7      -> __gr_top = sp+0x100
// The GP area ENDS at the incoming sp, so x3..x7 are contiguous with the
// caller's stack-spilled arguments. That is the old overrides' jvalue[] layout
// (their 2026-09-18 stack-spill fix), which MACAPK_JNI_CXXWRAP_TYPED=0 passes
// to the *A* slot unchanged to restore the pre-change behaviour exactly.
// x0..x2 are never touched before the bl, so env/receiver/methodID pass
// straight through.
//
// GATE: MACAPK_JNI_CXXWRAP_TYPED (default ON; =0 is the pre-change GP-only
// pack). Offline gate: debug/jni_cxxwrap_fp_gate.sh.

#include <jni.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Exported from bionic_shim.cpp (one copy of the repack logic).
extern "C" void __macapk_jni_bare_repack(JNIEnv* env, jobject obj_or_cls,
                                         int is_jclass, int is_static,
                                         jmethodID mid, void* ap,
                                         jvalue* out, size_t cap);
extern "C" size_t __macapk_jni_bare_argc(JNIEnv* env, jobject obj_or_cls,
                                         int is_jclass, int is_static,
                                         jmethodID mid);
extern "C" void __macapk_jni_bare_null_recv_log(const char* which);

namespace {
struct CxxwrapVaList {
    void* stack;
    void* gr_top;
    void* vr_top;
    int   gr_offs;
    int   vr_offs;
};

bool cxxwrap_typed() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_JNI_CXXWRAP_TYPED");
        bool v = !(e && e[0] == '0');
        if (!v)
            std::fprintf(stderr,
                "[jni-cxxwrap] MACAPK_JNI_CXXWRAP_TYPED=0: _JNIEnv::Call*Method "
                "overrides pack x3..x7 only; float/double arguments read "
                "garbage\n");
        return v;
    }();
    return on;
}
}  // namespace

// NAME, return type, receiver type, IS_JCLASS, IS_STATIC, mangled wrapper name.
#define MACAPK_JNI_CXXWRAP_SLOTS(X)                                              \
    X(CallObjectMethod      , jobject , jobject, false, false,                   \
      _ZN7_JNIEnv16CallObjectMethodEP8_jobjectP10_jmethodIDz)                    \
    X(CallVoidMethod        , void    , jobject, false, false,                   \
      _ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz)                      \
    X(CallStaticObjectMethod, jobject , jclass , true , true ,                   \
      _ZN7_JNIEnv22CallStaticObjectMethodEP7_jclassP10_jmethodIDz)               \
    X(CallStaticVoidMethod  , void    , jclass , true , true ,                   \
      _ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz)                 \
    X(CallBooleanMethod     , jboolean, jobject, false, false,                   \
      _ZN7_JNIEnv17CallBooleanMethodEP8_jobjectP10_jmethodIDz)                   \
    X(CallIntMethod         , jint    , jobject, false, false,                   \
      _ZN7_JNIEnv13CallIntMethodEP8_jobjectP10_jmethodIDz)

#define MACAPK_JNI_CXXWRAP_WORKER(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC, MANGLED) \
    extern "C" RET macapk_jni_cxxwrap_worker_ ## NAME(                         \
            JNIEnv* env, OBJTYPE o, jmethodID mid, void* ap) {                 \
        CxxwrapVaList* v = static_cast<CxxwrapVaList*>(ap);                    \
        if (!cxxwrap_typed())                                                  \
            return env->functions->NAME ## A(env, o, mid,                      \
                reinterpret_cast<const jvalue*>(                               \
                    static_cast<char*>(v->gr_top) + v->gr_offs));              \
        if (!(IS_JCLASS) && !o) {                                              \
            __macapk_jni_bare_null_recv_log(#NAME);                            \
            return (RET)0;                                                     \
        }                                                                      \
        /* Sized from the signature: the *A* slot reads as many entries as     \
         * the method declares. */                                             \
        jvalue argv_inline[16];                                                \
        std::vector<jvalue> argv_heap;                                         \
        jvalue* argv = argv_inline;                                            \
        size_t cap = 16;                                                       \
        size_t argc = __macapk_jni_bare_argc(env, reinterpret_cast<jobject>(o),\
                          (IS_JCLASS) ? 1 : 0, (IS_STATIC) ? 1 : 0, mid);      \
        if (argc > cap) { argv_heap.assign(argc, jvalue{});                    \
                          argv = argv_heap.data(); cap = argc; }               \
        std::memset(argv, 0, cap * sizeof(jvalue));                            \
        __macapk_jni_bare_repack(env, reinterpret_cast<jobject>(o),            \
                                 (IS_JCLASS) ? 1 : 0, (IS_STATIC) ? 1 : 0,     \
                                 mid, ap, argv, cap);                          \
        return env->functions->NAME ## A(env, o, mid, argv);                   \
    }
MACAPK_JNI_CXXWRAP_SLOTS(MACAPK_JNI_CXXWRAP_WORKER)
#undef MACAPK_JNI_CXXWRAP_WORKER

#define MACAPK_JNI_CXXWRAP_TRAMP(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC, MANGLED) \
    extern "C" __attribute__((naked))                                          \
    RET __macapk_arm64_ ## MANGLED(JNIEnv*, OBJTYPE, jmethodID, ...) {         \
        __asm__ volatile(                                                      \
            "sub  sp, sp, #0x100\n"                                            \
            "stp  x29, x30, [sp, #0xC0]\n"                                     \
            "add  x29, sp, #0xC0\n"                                            \
            "stp  q0, q1, [sp, #0x00]\n"                                       \
            "stp  q2, q3, [sp, #0x20]\n"                                       \
            "stp  q4, q5, [sp, #0x40]\n"                                       \
            "stp  q6, q7, [sp, #0x60]\n"                                       \
            "stp  x3, x4, [sp, #0xD8]\n"                                       \
            "stp  x5, x6, [sp, #0xE8]\n"                                       \
            "str  x7,     [sp, #0xF8]\n"  /* x7 ends at the incoming sp */     \
            "add  x8, sp, #0x100\n"       /* __stack = __gr_top = incoming sp*/\
            "stp  x8, x8, [sp, #0x80]\n"                                       \
            "add  x8, sp, #0x80\n"        /* __vr_top = end of q0..q7      */  \
            "mov  x9, #-40\n"             /* __gr_offs = -40  (bits 0..31) */  \
            "movk x9, #0xff80, lsl #32\n" /* __vr_offs = -128 (bits 32..63)*/  \
            "stp  x8, x9, [sp, #0x90]\n"                                       \
            "add  x3, sp, #0x80\n"        /* x0..x2 untouched: env, o, mid */  \
            "bl   _macapk_jni_cxxwrap_worker_" #NAME "\n"                      \
            "ldp  x29, x30, [sp, #0xC0]\n"                                     \
            "add  sp, sp, #0x100\n"                                            \
            "ret\n"                                                            \
        );                                                                     \
    }
MACAPK_JNI_CXXWRAP_SLOTS(MACAPK_JNI_CXXWRAP_TRAMP)
#undef MACAPK_JNI_CXXWRAP_TRAMP
