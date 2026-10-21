// bionic_shim_jni_bare.cpp -- the BARE-ELLIPSIS half of the Bionic va_list
// JNI bridge.
//
// ---------------------------------------------------------------------------
// THE BUG (measured at the instruction level, 2026-07-29)
// ---------------------------------------------------------------------------
// `JNINativeInterface` carries THREE forms of every Call<Type>Method:
//
//     jobject (*CallObjectMethod )(JNIEnv*, jobject, jmethodID, ...);      <-- BARE
//     jobject (*CallObjectMethodV)(JNIEnv*, jobject, jmethodID, va_list);
//     jobject (*CallObjectMethodA)(JNIEnv*, jobject, jmethodID, const jvalue*);
//
// bionic_shim.cpp's `__macapk_install_jni_bionic_variadic_bridge` patches only
// the 21 `...V` slots. That is correct for C++ guests, because jni.h's C++
// convenience wrapper `_JNIEnv::CallObjectMethod(...)` does its own `va_start`
// and calls `functions->CallObjectMethodV`. But a PLAIN-C guest writes
// `(*env)->CallObjectMethod(env, obj, mid, ...)`, which compiles to an indirect
// call straight through the BARE field -- and that field still holds HotSpot's
// own `jni_CallObjectMethod`, compiled by Apple clang.
//
// Apple arm64 and AAPCS64 disagree about variadic argument passing, and it is
// not a subtle disagreement. Compiling the same source both ways:
//
//   void probe(void* env, void* obj, void* mid, ...);
//   probe(a, b, c, 0x11, 0x22, 4.5);
//
//   AAPCS64  (--target=aarch64-linux-android, i.e. every guest .so):
//       mov w0,#1  mov w1,#2  mov w2,#3
//       mov w3,#17          <-- 0x11 in x3
//       mov w4,#34          <-- 0x22 in x4
//       fmov d0,#4.5        <-- 4.5  in d0
//       b probe             (NOTHING on the stack)
//
//   Apple arm64 (-arch arm64, i.e. HotSpot's jni_CallObjectMethod):
//       mov w0,#1  mov w1,#2  mov w2,#3
//       str x9,[sp]         <-- 0x11 at sp+0
//       stp x8,x10,[sp,#8]  <-- 0x22 at sp+8, 4.5 at sp+16
//       bl _probe           (NOTHING in x3..x7 / v0..v7)
//
// and the callee side matches: Apple's `va_start` is `x8 = incoming sp` and
// `sizeof(va_list) == 8` (a plain char*), while AAPCS64's `va_start` spills
// x3..x7 + q0..q7 into save areas and builds a 32-byte descriptor.
//
// So a Bionic guest leaves its arguments in x3.. / d0.. and HotSpot reads the
// guest's own stack frame instead -- whatever spill slot or string buffer
// happened to be at [sp]. Measured symptom: `si_addr=0x6f7400666e6f6336`,
// which is the ASCII bytes ".conf\0to" being dereferenced as an oop.
//
// This is why every SDL app in the corpus crashed: libSDL2.so / libSDL3.so
// contain ZERO `_ZN7_JNIEnv*` symbols, so they take the plain-C path, and
// name-based import shimming can never reach a call that has no import to
// resolve. Only patching the vtable reaches it.
//   Rocks'n'Diamonds (SDL2): bare CallObjectMethod     -> AssetManager.openFd
//   Pekka Kana 2     (SDL2): bare CallStaticVoidMethod -> SDLActivity.setOrientation
//   Anarch RE        (SDL3): bare CallStaticVoidMethod -> (same shape)
// Full evidence: docs/newapk-bringup_2026-07-29.md section 2, and
// docs/arm32-variadic-jni-coverage_2026-07-28.md section 4 predicted it.
//
// ---------------------------------------------------------------------------
// THE FIX
// ---------------------------------------------------------------------------
// One naked-asm trampoline per bare slot. It captures the incoming AAPCS64
// argument-register state, asks `caller_is_bionic(lr)` who called, and then:
//
//   * HOST caller  -> restores every register AND sp exactly, then `br`s to
//     HotSpot's saved original slot. A perfect tail call: the host's stack
//     arguments are still at [sp] where its `va_start` will look, and lr still
//     holds the host's return address, so HotSpot returns straight to it. We
//     must keep this path byte-exact because the patched vtable is GLOBAL --
//     libjvm's own plain-C callers go through the same slot.
//
//   * BIONIC caller -> synthesises a real AAPCS64 va_list over the captured
//     registers and calls a C worker, which reuses bionic_shim.cpp's existing,
//     already-tested `bionic_repack_args` (signature-aware: it resolves the
//     callee's real parameter types by JNI reflection so float/double land in
//     the right jvalue slots) and forwards to the `...A` variant.
//
// The va_list layout is not guessed. Compiling the JNI shape itself
// (`void probe(void* env, void* obj, void* mid, ...)`) for
// --target=aarch64-linux-android emits exactly:
//
//       sub  sp, sp, #224
//       stp  x3, x4, [x29,#-72]     \
//       stp  x5, x6, [x29,#-56]      >  GP save area = x3..x7 ONLY, 40 bytes
//       stur x7,     [x29,#-40]     /   (the 3 named args are NOT saved)
//       stp  q0, q1, [sp]           \
//       stp  q2, q3, [sp,#32]        >  VR save area = q0..q7, 128 bytes
//       stp  q4, q5, [sp,#64]        /
//       stp  q6, q7, [sp,#96]       /
//       sub  x9, x29, #72
//       add  x1, x9, #40            <-- __gr_top  = GP base + 40 (its END)
//       mov  x9, sp
//       add  x2, x9, #128           <-- __vr_top  = VR base + 128 (its END)
//       add  x8, x29, #16           <-- __stack   = the INCOMING sp
//       mov  x8, #-40                   __gr_offs = -40
//       movk x8, #65408, lsl #32        __vr_offs = -128  (0xff80 == -128)
//
// which is the struct `bionic_shim.cpp:33784` already models:
//     { void* stack; void* gr_top; void* vr_top; int gr_offs; int vr_offs; }
// and matches clang's own codegen contract in
// clang/lib/CodeGen/Targets/AArch64.cpp EmitAAPCSVAArg:
//   "// 3 is the field number of __gr_offs" / "reg_top_index = 1"  (__gr_top)
//   "// 4 is the field number of __vr_offs" / "reg_top_index = 2"  (__vr_top)
//   BaseAddr = reg_top + reg_offs; offsets are NEGATIVE while registers
//   remain (`UsingStack = ICmpSGE(reg_offs, 0)`); GP step 8, FP step 16;
//   the overflow path reads field 0 (__stack) in 8-byte multiples.
// The three named args (env, obj, mid) consume x0..x2, so the first variadic
// argument is x3 => gr_offs = -(8-3)*8 = -40, and no named FP arg exists so
// vr_offs = -(8-0)*16 = -128. Those two constants are the whole ABI contract.
//
// ---------------------------------------------------------------------------
// WHY A SEPARATE TRANSLATION UNIT
// ---------------------------------------------------------------------------
// bionic_shim.cpp is 37k lines and concurrently edited. Same rationale (and
// same pattern) as bionic_shim_signal.cpp and bionic_shim_arm32.cpp. The three
// pieces this TU needs from bionic_shim.cpp's anonymous namespace are exported
// there as `__macapk_jni_bare_*` thunks rather than duplicated here, so there
// is exactly ONE copy of the repack logic.
//
// GATE: MACAPK_JNI_BARE_BRIDGE=1. Default OFF. The blast radius is the JNI
// vtable that EVERY Stage-6 guest sees, so the default flip is a separate,
// swept decision -- not this file's to make.

#include <vector>
#include <jni.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

// --- Exported from bionic_shim.cpp (see the block after its anonymous
// --- namespace closes). Declared, never defined, here.
//
// __macapk_jni_bare_is_bionic_caller(ra):
//   `!macapk_bridge_passthrough() && caller_is_bionic(ra)`. The passthrough
//   fold matters: with MACAPK_BIONIC_JNI_PASSTHROUGH=1 every caller is treated
//   as a host caller, so the bare slots become byte-exact tail calls to
//   HotSpot and the whole bridge is isolated out of the picture -- the same
//   diagnostic the V slots already honour. Returns int (not bool) so the
//   naked-asm `cbz w0` test is unambiguous.
extern "C" int  __macapk_jni_bare_is_bionic_caller(const void* ra);
extern "C" void __macapk_jni_bare_repack(JNIEnv* env, jobject obj_or_cls,
                                         int is_jclass, int is_static,
                                         jmethodID mid, void* ap,
                                         jvalue* out, size_t cap);
extern "C" size_t __macapk_jni_bare_argc(JNIEnv* env, jobject obj_or_cls,
                                         int is_jclass, int is_static,
                                         jmethodID mid);
extern "C" void __macapk_jni_bare_null_recv_log(const char* which);

// ---------------------------------------------------------------------------
// The slot table. Every list below is generated from this one X-macro so a
// slot cannot be half-wired (declared but not installed, installed but not
// repacked, ...). Fields: NAME, return type, receiver type, IS_JCLASS
// (the receiver already IS the class -- static calls and NewObject),
// IS_STATIC (fed to ToReflectedMethod; constructors need false).
//
// This is the SAME 21 names bionic_shim.cpp:34179-34199 bridges on the V
// side, deliberately: any slot bridged there but not here would still be an
// ABI hole for plain-C guests, and vice versa.
// ---------------------------------------------------------------------------
#define MACAPK_JNI_BARE_SLOTS(X)                                     \
    X(CallVoidMethod         , void    , jobject, false, false)      \
    X(CallStaticVoidMethod   , void    , jclass , true , true )      \
    X(CallObjectMethod       , jobject , jobject, false, false)      \
    X(CallStaticObjectMethod , jobject , jclass , true , true )      \
    X(CallIntMethod          , jint    , jobject, false, false)      \
    X(CallStaticIntMethod    , jint    , jclass , true , true )      \
    X(CallBooleanMethod      , jboolean, jobject, false, false)      \
    X(CallStaticBooleanMethod, jboolean, jclass , true , true )      \
    X(CallLongMethod         , jlong   , jobject, false, false)      \
    X(CallStaticLongMethod   , jlong   , jclass , true , true )      \
    X(NewObject              , jobject , jclass , true , false)      \
    X(CallByteMethod         , jbyte   , jobject, false, false)      \
    X(CallStaticByteMethod   , jbyte   , jclass , true , true )      \
    X(CallCharMethod         , jchar   , jobject, false, false)      \
    X(CallStaticCharMethod   , jchar   , jclass , true , true )      \
    X(CallShortMethod        , jshort  , jobject, false, false)      \
    X(CallStaticShortMethod  , jshort  , jclass , true , true )      \
    X(CallFloatMethod        , jfloat  , jobject, false, false)      \
    X(CallStaticFloatMethod  , jfloat  , jclass , true , true )      \
    X(CallDoubleMethod       , jdouble , jobject, false, false)      \
    X(CallStaticDoubleMethod , jdouble , jclass , true , true )

// HotSpot's original BARE slot, saved at install time. The naked trampolines
// load these by symbol name, so they must have C linkage and external
// visibility. void* rather than the real function type because the asm only
// ever `br`s to them.
#define MACAPK_JNI_BARE_ORIG(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC) \
    extern "C" void* g_macapk_jni_bare_orig_ ## NAME = nullptr;
MACAPK_JNI_BARE_SLOTS(MACAPK_JNI_BARE_ORIG)
#undef MACAPK_JNI_BARE_ORIG

// The `...A` variant, captured at install time. Read once instead of chasing
// env->functions on every call, and typed per slot so the forward is checked.
#define MACAPK_JNI_BARE_ASLOT(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC) \
    static RET (*g_macapk_jni_bare_A_ ## NAME)(                          \
        JNIEnv*, OBJTYPE, jmethodID, const jvalue*) = nullptr;
MACAPK_JNI_BARE_SLOTS(MACAPK_JNI_BARE_ASLOT)
#undef MACAPK_JNI_BARE_ASLOT

// ---------------------------------------------------------------------------
// The C worker. Entered ONLY on the bionic path (the trampoline already
// decided), so there is no caller test here -- `ap` is always a real AAPCS64
// va_list built by our own prologue.
// ---------------------------------------------------------------------------
#define MACAPK_JNI_BARE_WORKER(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC)   \
    extern "C" RET macapk_jni_bare_worker_ ## NAME(                        \
            JNIEnv* env, OBJTYPE o, jmethodID mid, void* ap) {             \
        /* Same JNI-UB degradation the V bridge applies: a non-static      \
         * Call<Type>Method on a NULL receiver would have HotSpot deref a  \
         * NULL oop and kill the whole JVM. Recoverable zero instead. */   \
        if (!(IS_JCLASS) && !o) {                                          \
            __macapk_jni_bare_null_recv_log(#NAME);                        \
            return (RET)0;                                                 \
        }                                                                  \
        if (!g_macapk_jni_bare_A_ ## NAME) return (RET)0;                  \
        /* Sized from the SIGNATURE, not fixed at 16 -- HotSpot's *A        \
         * variant reads as many slots as the signature declares, so a       \
         * fixed buffer runs off the end for a >16-argument method. */       \
        jvalue argv_inline[16];                                            \
        std::vector<jvalue> argv_heap;                                     \
        jvalue* argv = argv_inline;                                        \
        size_t cap = 16;                                                   \
        size_t argc = __macapk_jni_bare_argc(env,                          \
                          reinterpret_cast<jobject>(o),                    \
                          (IS_JCLASS) ? 1 : 0, (IS_STATIC) ? 1 : 0, mid);  \
        if (argc > cap) { argv_heap.assign(argc, jvalue{});                \
                          argv = argv_heap.data(); cap = argc; }           \
        std::memset(argv, 0, cap * sizeof(jvalue));                        \
        __macapk_jni_bare_repack(env, reinterpret_cast<jobject>(o),         \
                                 (IS_JCLASS) ? 1 : 0, (IS_STATIC) ? 1 : 0, \
                                 mid, ap, argv, cap);                      \
        return g_macapk_jni_bare_A_ ## NAME(env, o, mid, argv);            \
    }
MACAPK_JNI_BARE_SLOTS(MACAPK_JNI_BARE_WORKER)
#undef MACAPK_JNI_BARE_WORKER

// ---------------------------------------------------------------------------
// The naked trampolines.
//
// Frame (256 bytes; sp stays 16-aligned so the inner `bl`s are ABI-legal):
//   [sp+0x00 .. 0x7F]  VR save area, q0..q7      -> __vr_top = sp+0x80
//   [sp+0x80 .. 0xA7]  GP save area, x3..x7      -> __gr_top = sp+0xA8
//   [sp+0xA8 .. 0xAF]  pad (keeps the va_list 16-aligned)
//   [sp+0xB0 .. 0xCF]  BionicVaListJNI
//                        +0x00 __stack  +0x08 __gr_top  +0x10 __vr_top
//                        +0x18 __gr_offs (int)  +0x1C __vr_offs (int)
//   [sp+0xD0 .. 0xE7]  parked x0, x1, x2 (env, receiver, methodID)
//   [sp+0xF0 .. 0xFF]  saved x29, x30
//
// Placing the VR area FIRST makes __vr_top and the GP area base the same
// address (sp+0x80), which is why the two `add`s below look redundant.
//
// x16/x17 are the only scratch used after sp is restored on the host path;
// both are IP0/IP1 (inter-procedure scratch), never argument registers, so
// clobbering them cannot disturb a passthrough.
// ---------------------------------------------------------------------------
#define MACAPK_JNI_BARE_TRAMP(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC)      \
    extern "C" __attribute__((naked))                                        \
    RET macapk_jni_bare_ ## NAME(JNIEnv*, OBJTYPE, jmethodID, ...) {         \
        __asm__ volatile(                                                    \
            "sub  sp, sp, #0x100\n"                                          \
            "stp  x29, x30, [sp, #0xF0]\n"                                   \
            "add  x29, sp, #0xF0\n"       /* real frame chain for backtrace */\
            /* Capture the whole incoming AAPCS64 variadic register state    \
             * BEFORE anything can clobber it. Meaningless for a host        \
             * caller, but we restore it verbatim on that path.  */          \
            "stp  q0, q1, [sp, #0x00]\n"                                     \
            "stp  q2, q3, [sp, #0x20]\n"                                     \
            "stp  q4, q5, [sp, #0x40]\n"                                     \
            "stp  q6, q7, [sp, #0x60]\n"                                     \
            "stp  x3, x4, [sp, #0x80]\n"                                     \
            "stp  x5, x6, [sp, #0x90]\n"                                     \
            "str  x7,     [sp, #0xA0]\n"                                     \
            "stp  x0, x1, [sp, #0xD0]\n"                                     \
            "str  x2,     [sp, #0xE0]\n"                                     \
            /* Who called us? x30 is still the caller's return address. */    \
            "mov  x0, x30\n"                                                 \
            "bl   ___macapk_jni_bare_is_bionic_caller\n"                     \
            "cbz  w0, Lmjb_" #NAME "_host\n"                                 \
            /* ---- BIONIC: synthesise the AAPCS64 va_list ---------------- */\
            "add  x8, sp, #0x100\n"       /* __stack  = the incoming sp    */\
            "add  x9, sp, #0xA8\n"        /* __gr_top = end of x3..x7      */\
            "stp  x8, x9, [sp, #0xB0]\n"                                     \
            "add  x8, sp, #0x80\n"        /* __vr_top = end of q0..q7      */\
            "mov  x9, #-40\n"             /* __gr_offs = -40  (bits 0..31) */\
            "movk x9, #0xff80, lsl #32\n" /* __vr_offs = -128 (bits 32..63)*/\
            "stp  x8, x9, [sp, #0xC0]\n"                                     \
            "ldp  x0, x1, [sp, #0xD0]\n"                                     \
            "ldr  x2,     [sp, #0xE0]\n"                                     \
            "add  x3, sp, #0xB0\n"                                           \
            "bl   _macapk_jni_bare_worker_" #NAME "\n"                       \
            /* the worker's result is already in x0 / d0 / s0 */             \
            "ldp  x29, x30, [sp, #0xF0]\n"                                   \
            "add  sp, sp, #0x100\n"                                          \
            "ret\n"                                                          \
            /* ---- HOST: byte-exact tail call to HotSpot ----------------- */\
            "Lmjb_" #NAME "_host:\n"                                         \
            "ldp  q0, q1, [sp, #0x00]\n"                                     \
            "ldp  q2, q3, [sp, #0x20]\n"                                     \
            "ldp  q4, q5, [sp, #0x40]\n"                                     \
            "ldp  q6, q7, [sp, #0x60]\n"                                     \
            "ldp  x3, x4, [sp, #0x80]\n"                                     \
            "ldp  x5, x6, [sp, #0x90]\n"                                     \
            "ldr  x7,     [sp, #0xA0]\n"                                     \
            "ldp  x0, x1, [sp, #0xD0]\n"                                     \
            "ldr  x2,     [sp, #0xE0]\n"                                     \
            "ldp  x29, x30, [sp, #0xF0]\n"                                   \
            "add  sp, sp, #0x100\n"        /* the host's stack args are now  \
                                            * at [sp] again, untouched     */\
            "adrp x16, _g_macapk_jni_bare_orig_" #NAME "@PAGE\n"             \
            "ldr  x16, [x16, _g_macapk_jni_bare_orig_" #NAME "@PAGEOFF]\n"   \
            "br   x16\n"                                                     \
        );                                                                   \
    }
MACAPK_JNI_BARE_SLOTS(MACAPK_JNI_BARE_TRAMP)
#undef MACAPK_JNI_BARE_TRAMP

// ---------------------------------------------------------------------------
// Install. Called from the tail of bionic_shim.cpp's
// __macapk_install_jni_bionic_variadic_bridge, which means (a) the `...V` and
// `...A` originals are already saved there, and (b) the vtable page is ALREADY
// mprotect'd RW and deliberately left that way (see the JFR-atomic comment at
// that site), so we need no mprotect of our own.
// ---------------------------------------------------------------------------
extern "C" void __macapk_install_jni_bare_ellipsis_bridge(void* vtable_p) {
    if (!vtable_p) return;
    // DEFAULT ON since v1.0.840. This was opt-in, and opt-in meant three corpus
    // apps (Pekka Kana 2, TIC-80, Anarch) rendered ONLY when someone remembered
    // to set the flag -- they have never worked on the shipping path, and every
    // verdict that put them on the RENDERS list was taken with it forced on.
    //
    // The gate is now an INVERSION, not a default change: the escape hatch
    // survives as MACAPK_JNI_BARE_BRIDGE=0.
    //
    // Why this is safe rather than merely desirable:
    //   * a full protected sweep with it ON came back PASS=10 REGRESS=0 XFAIL=2
    //     XPASS=0, and that sweep genuinely EXERCISES the bare slots -- subway
    //     passed while carrying 5 bare-slot-exposed libs (libmain.so and both
    //     libcrashlytics*.so are pure C, 0 mangled symbols), and gdlite carries
    //     libfmod.so likewise.
    //   * fleet exposure is mainstream, not a games edge case: 33 of 47 arm64
    //     JNI-touching libs have no `_ZN7_JNIEnv` reference at all, and 19 libs
    //     across 12 apps are pure C and therefore MUST use the bare slots --
    //     including AndroidX's own libandroidx.graphics.path.so (7 apps) and
    //     Firebase Crashlytics (3 apps).
    //   * our own side never touches these slots: native_methods.cpp has 9
    //     `env->Call...` and ZERO `(*env)->Call...`; bionic_shim.cpp has 15 and
    //     ZERO. So flipping cannot change any Mac.apk-originated call.
    const char* e = std::getenv("MACAPK_JNI_BARE_BRIDGE");
    if (e && e[0] == '0') {
        std::fprintf(stderr,
            "[jni-bare-bridge] DISABLED by MACAPK_JNI_BARE_BRIDGE=0. "
            "Plain-C guests calling the bare-ellipsis Call*Method slots will read "
            "their variadic args from the wrong place (Apple ABI puts them on "
            "the stack, AAPCS64 leaves them in x3..x7/v0..v7).\n");
        return;
    }
    JNINativeInterface_* vt = static_cast<JNINativeInterface_*>(vtable_p);
    int n = 0;
#define MACAPK_JNI_BARE_INSTALL(NAME, RET, OBJTYPE, IS_JCLASS, IS_STATIC) \
    g_macapk_jni_bare_A_ ## NAME    = vt->NAME ## A;                      \
    g_macapk_jni_bare_orig_ ## NAME = reinterpret_cast<void*>(vt->NAME);  \
    vt->NAME = &macapk_jni_bare_ ## NAME;                                 \
    ++n;
    MACAPK_JNI_BARE_SLOTS(MACAPK_JNI_BARE_INSTALL)
#undef MACAPK_JNI_BARE_INSTALL
    std::fprintf(stderr,
        "[jni-bare-bridge] installed: %d bare-ellipsis slots patched on "
        "vtable %p (plain-C guest JNI upcalls now read their variadic args "
        "from x3..x7/v0..v7 per AAPCS64)\n", n, vtable_p);
}

// ---------------------------------------------------------------------------
// Stage-6 Bionic stdio gaps found in libtic80.so by MACAPK_UNRESOLVED_CONTINUE.
// Unshimmed, each bound to the panic stub and RETURNED 0 -- a silent short
// read / short write / NULL file handle with no error anywhere, which is the
// canonical "missing shims are silent killers" shape. These live here rather
// than in bionic_shim.cpp only to keep that file's concurrent diff small; they
// are ordinary Stage-6 shims and `Image::resolve_external` finds them by name
// (`__macapk_arm64_<name>`) with no allowlist entry needed.
// ---------------------------------------------------------------------------

// fopen64 -- Bionic libc/stdio/stdio.cpp:269 is literally
//     __strong_alias(fopen64, fopen);
// i.e. a second exported symbol for the same function, declared in
// libc/include/stdio.h:275 as
//     FILE* fopen64(const char* __path, const char* __mode) __INTRODUCED_IN(24);
// On LP64 off_t is already 64-bit so there is no large-file behaviour to
// reproduce. macOS libSystem has no `fopen64` at all, so nothing masks the gap.
//
// It must delegate to __macapk_arm64_fopen, NOT to ::fopen, so it inherits the
// Android-path remap (/data/data/<pkg>/..., /sdcard/... -> ${android_root})
// and the write-mode parent-dir-create retry. Same reason
// __macapk_arm64_freopen64 delegates to __macapk_arm64_freopen.
extern "C" FILE* __macapk_arm64_fopen(const char* path, const char* mode);
extern "C" FILE* __macapk_arm64_fopen64(const char* path, const char* mode) {
    return __macapk_arm64_fopen(path, mode);
}

// <mntent.h> -- setmntent / getmntent_r / getmntent / endmntent / hasmntopt.
// macOS has none of them (it uses getmntinfo/getfsent), and VLC's libvlc.so
// imports setmntent, getmntent_r and endmntent STRONG-undefined, so they bound
// to the abort stub: once VLC's onboarding was saved its startup reached them
// and every launch died rc=134 (docs/hard-fixes-catalog.md, "missing shims").
//
// Bionic's struct, bionic/libc/include/mntent.h (same layout as glibc's):
//     struct mntent { char* mnt_fsname; char* mnt_dir; char* mnt_type;
//                     char* mnt_opts; int mnt_freq; int mnt_passno; };
// = 4 pointers + 2 ints = 40 bytes on LP64. Spelled out here rather than taken
// from a host header because macOS has no <mntent.h> to take it from.
//
// The bodies follow bionic/libc/bionic/mntent.cpp line for line: setmntent is
// fopen, endmntent fcloses and ALWAYS returns 1, and getmntent_r splits each
// line with the same sscanf (fields stay NUL-terminated inside the caller's
// buffer; Bionic does not decode \040-style escapes, so neither do we). The
// fopen is OUR fopen shim, so "/proc/mounts" reaches the mount-table synth
// (bionic_shim.cpp macapk_arm64_mounts_path) instead of the host's missing /proc.
struct macapk_bionic_mntent {
    char* mnt_fsname;
    char* mnt_dir;
    char* mnt_type;
    char* mnt_opts;
    int   mnt_freq;
    int   mnt_passno;
};
static_assert(sizeof(macapk_bionic_mntent) == 40, "Bionic LP64 struct mntent is 40 bytes");
static_assert(offsetof(macapk_bionic_mntent, mnt_freq) == 32, "mnt_freq at +32");

extern "C" FILE* __macapk_arm64_setmntent(const char* path, const char* mode) {
    return __macapk_arm64_fopen(path, mode);
}

extern "C" int __macapk_arm64_endmntent(FILE* fp) {
    if (fp != nullptr) fclose(fp);
    return 1;
}

extern "C" macapk_bionic_mntent* __macapk_arm64_getmntent_r(FILE* fp,
                                                           macapk_bionic_mntent* e,
                                                           char* buf, int buf_len) {
    if (!fp || !e || !buf || buf_len <= 0) return nullptr;
    memset(e, 0, sizeof(*e));
    while (fgets(buf, buf_len, fp) != nullptr) {
        // Entries look like "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0".
        int fsname0, fsname1, dir0, dir1, type0, type1, opts0, opts1;
        if (sscanf(buf, " %n%*s%n %n%*s%n %n%*s%n %n%*s%n %d %d",
                   &fsname0, &fsname1, &dir0, &dir1, &type0, &type1,
                   &opts0, &opts1, &e->mnt_freq, &e->mnt_passno) == 2) {
            e->mnt_fsname = &buf[fsname0]; buf[fsname1] = '\0';
            e->mnt_dir    = &buf[dir0];    buf[dir1]    = '\0';
            e->mnt_type   = &buf[type0];   buf[type1]   = '\0';
            e->mnt_opts   = &buf[opts0];   buf[opts1]   = '\0';
            return e;
        }
    }
    return nullptr;
}

// Bionic keeps getmntent's result in per-thread TLS (bionic_tls::mntent_buf /
// mntent_strings[BUFSIZ]); thread_local gives the same per-thread lifetime.
extern "C" macapk_bionic_mntent* __macapk_arm64_getmntent(FILE* fp) {
    static thread_local macapk_bionic_mntent t_ent;
    static thread_local char t_strings[1024];   // Bionic: BUFSIZ, which is 1024 there
    return __macapk_arm64_getmntent_r(fp, &t_ent, t_strings, sizeof(t_strings));
}

extern "C" char* __macapk_arm64_hasmntopt(const macapk_bionic_mntent* mnt,
                                          const char* opt) {
    if (!mnt || !mnt->mnt_opts || !opt) return nullptr;
    char* token = mnt->mnt_opts;
    char* const end = mnt->mnt_opts + strlen(mnt->mnt_opts);
    const size_t optLen = strlen(opt);
    while (token) {
        char* const tokenEnd = token + optLen;
        if (tokenEnd > end) break;
        if (memcmp(token, opt, optLen) == 0 &&
            (*tokenEnd == '\0' || *tokenEnd == ',' || *tokenEnd == '=')) {
            return token;
        }
        token = strchr(token, ',');
        if (token) token++;
    }
    return nullptr;
}

// The rest of VLC's libvlc.so STRONG-undefined set (v1.0.1666 log: tdestroy,
// accept4, vmsplice, sched_setscheduler). With the mntent family shimmed, the
// same saved-onboarding launch got one step further and aborted on tdestroy
// (libvlc.so+0xe068e0, inside var_Destroy). None of the four is in libSystem.

// tdestroy -- GNU <search.h>, in Bionic since API 16 (bionic/libc/bionic/
// tdestroy.cpp: post-order llink, rlink, destroy_func(key), free(node)). The guest's
// tsearch/tfind/tdelete bind to libSystem's, so the nodes are libSystem's
// node_t -- `{ char* key; struct node *llink, *rlink; }` per the macOS SDK
// <search.h> _SEARCH_PRIVATE block, the same first three fields as Bionic's --
// malloc()ed, so free() is the right release.
namespace {
struct macapk_tnode { void* key; macapk_tnode* llink; macapk_tnode* rlink; };
}
extern "C" void __macapk_arm64_tdestroy(void* root, void (*destroy_func)(void*)) {
    macapk_tnode* n = static_cast<macapk_tnode*>(root);
    if (n == nullptr) return;
    if (n->llink) __macapk_arm64_tdestroy(n->llink, destroy_func);
    if (n->rlink) __macapk_arm64_tdestroy(n->rlink, destroy_func);
    if (destroy_func) (*destroy_func)(n->key);
    free(n);
}

// accept4(fd, addr, len, flags) -- accept() plus SOCK_NONBLOCK (Linux 04000)
// and SOCK_CLOEXEC (Linux 02000000) on the new fd; any other flag bit is
// EINVAL (net/socket.c __sys_accept4_file). Delegates to our accept shim for
// the sockaddr and errno translation. Darwin has no accept4, so the flags are
// applied right after the accept rather than atomically with it; the only
// observable gap is an exec racing in between on another thread.
extern "C" int __macapk_arm64_accept(int fd, struct sockaddr* addr, socklen_t* len);
extern "C" int __macapk_arm64_accept4(int fd, struct sockaddr* addr,
                                      socklen_t* len, int flags) {
    constexpr int kLinuxNonblock = 04000, kLinuxCloexec = 02000000;
    if (flags & ~(kLinuxNonblock | kLinuxCloexec)) { errno = EINVAL; return -1; }
    const int nfd = __macapk_arm64_accept(fd, addr, len);
    if (nfd < 0) return nfd;                       // errno already Linux-numbered
    if ((flags & kLinuxCloexec) && fcntl(nfd, F_SETFD, FD_CLOEXEC) != 0) {
        const int e = errno; close(nfd); errno = e; return -1;
    }
    if (flags & kLinuxNonblock) {
        const int fl = fcntl(nfd, F_GETFL);
        if (fl < 0 || fcntl(nfd, F_SETFL, fl | O_NONBLOCK) != 0) {
            const int e = errno; close(nfd); errno = e; return -1;
        }
    }
    return nfd;
}

// vmsplice(fd, iov, nr_segs, flags) -- Linux-only: "splice user pages into a
// pipe". For the write direction (fd is a pipe's write end, the only use the
// corpus has: VLC's HTTP prefetch, libvlc.so+0x10fee44, with SPLICE_F_GIFT) the
// observable effect is exactly writev() of the same iovecs into the pipe;
// SPLICE_F_GIFT is a hint about page ownership, not a change in the bytes.
// SPLICE_F_NONBLOCK (2) makes the call non-blocking without touching the fd's
// own O_NONBLOCK, which we reproduce with a zero-timeout poll. A non-pipe fd is
// EBADF, as fs/splice.c answers. Errno values: EAGAIN is 11 on Linux and 35 on
// Darwin; every other one writev can produce here (EBADF, EFAULT, EINTR,
// EINVAL, EPIPE) has the same number on both.
extern "C" ssize_t __macapk_arm64_vmsplice(int fd, const struct iovec* iov,
                                           unsigned long nr_segs, unsigned int flags) {
    constexpr unsigned kSpliceNonblock = 0x02;
    constexpr int kLinuxEAGAIN = 11;
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;            // EBADF: same number
    if (!S_ISFIFO(st.st_mode)) { errno = EBADF; return -1; }
    if (flags & kSpliceNonblock) {
        struct pollfd p = { fd, POLLOUT, 0 };
        const int r = poll(&p, 1, 0);
        if (r == 0) { errno = kLinuxEAGAIN; return -1; }
        if (r < 0) return -1;
    }
    const ssize_t n = writev(fd, iov, static_cast<int>(nr_segs));
    if (n < 0 && errno == EAGAIN) errno = kLinuxEAGAIN;
    return n;
}

// sched_setscheduler(pid, policy, param) -- Darwin has no POSIX scheduling-
// class call. Answer what Android answers an APP: its threads run without
// CAP_SYS_NICE and with RLIMIT_RTPRIO 0, so SCHED_FIFO (1) / SCHED_RR (2) are
// EPERM; SCHED_OTHER (0) / SCHED_BATCH (3) / SCHED_IDLE (5) are allowed and need
// sched_priority 0 (else EINVAL); any other policy is EINVAL
// (kernel/sched/core.c __sched_setscheduler). SCHED_RESET_ON_FORK
// (0x40000000) may be OR'ed in. Like our sched_setparam, the non-realtime case
// changes nothing on the host: Linux gives those policies their priority via
// nice, not sched_priority. VLC (libvlc.so+0x1a0ee0c) expects the EPERM case
// and moves on.
extern "C" int __macapk_arm64_sched_getparam(pid_t pid, void* bionic_param);
extern "C" int __macapk_arm64_sched_setscheduler(pid_t pid, int policy,
                                                 const void* bionic_param) {
    constexpr int kLinuxESRCH = 3, kLinuxEPERM = 1;
    if (!bionic_param || pid < 0) { errno = EINVAL; return -1; }
    int prio = 0;
    std::memcpy(&prio, bionic_param, sizeof(int));  // Bionic sched_param is 4 bytes
    if (pid != 0) {
        int cur = 0;   // our sched_getparam answers ESRCH for a tid we do not know
        if (__macapk_arm64_sched_getparam(pid, &cur) != 0) { errno = kLinuxESRCH; return -1; }
    }
    switch (policy & ~0x40000000) {
        case 0: case 3: case 5:
            if (prio != 0) { errno = EINVAL; return -1; }
            return 0;
        case 1: case 2:
            if (prio < 1 || prio > 99) { errno = EINVAL; return -1; }
            errno = kLinuxEPERM;
            return -1;
        default:
            errno = EINVAL;
            return -1;
    }
}

// __fwrite_chk / __fread_chk -- Bionic FORTIFY wrappers, Android-only symbols
// (absent from macOS libSystem). Prototypes verbatim from
// bionic/libc/include/bits/fortify/stdio.h:36-37:
//     size_t __fread_chk (void*       , size_t, size_t, FILE*, size_t);
//     size_t __fwrite_chk(const void* , size_t, size_t, FILE*, size_t);
// The trailing size_t is the compiler-supplied destination-buffer size; note
// it comes AFTER the FILE*, unlike glibc's _chk convention.
//
// bionic/libc/bionic/fortify.cpp:105-119 checks `size * count > buf_size`
// (via __builtin_umull_overflow then __check_buffer_access) and calls
// __fortify_fatal() == abort() on violation. We follow this shim file's
// established lenient policy (see the "_chk tail" banner in bionic_shim.cpp):
// forward to the plain libc routine, because the guest already validated its
// buffers at compile time and a benign over-read must not take down boot.
extern "C" size_t __macapk_arm64___fwrite_chk(const void* buf, size_t size,
                                             size_t count, FILE* stream,
                                             size_t /*buf_size*/) {
    if (!stream) return 0;
    return std::fwrite(buf, size, count, stream);
}
extern "C" size_t __macapk_arm64___fread_chk(void* buf, size_t size,
                                            size_t count, FILE* stream,
                                            size_t /*buf_size*/) {
    if (!stream) return 0;
    return std::fread(buf, size, count, stream);
}

// ===========================================================================
// GetFieldID: Android private-field-name aliases (v1.0.838)
// ===========================================================================
// THE GENERAL PROBLEM
// -------------------
// Mac.apk reimplements `android.*` but NOT `java.*` -- java.* comes from the
// host OpenJDK 21. Android's java.* is libcore, a FORK of OpenJDK, and libcore
// has renamed some PRIVATE fields relative to upstream. A public API is a
// contract; a private field name is not, so nothing forced the two to agree.
//
// That is invisible to Java guest code (which cannot see a private field of a
// bootclasspath class) but NOT to native guest code, which reaches in by name:
//
//     jclass   fdc = (*env)->FindClass (env, "java/io/FileDescriptor");
//     jfieldID f   = (*env)->GetFieldID(env, fdc, "descriptor", "I");
//     int      fd  = (*env)->GetIntField(env, fdObject, f);   // f is NULL!
//
// The failure is SILENT and then corrupting, which is why it costs a whole
// debugging session every time: GetFieldID returns NULL and throws
// NoSuchFieldError, but a guest that skips the check (they nearly all do --
// this field has existed since Android 1.0) passes NULL to GetIntField, which
// the JNI spec leaves UNDEFINED. HotSpot reads whatever the NULL fieldID
// decodes to, the guest gets a garbage int, and the symptom surfaces far away
// as a bad fd (Rocks'n'Diamonds: `IMG_Load` -> "Unsupported image format",
// because SDL dup()'d a garbage descriptor and read nothing).
//
// THE FIX SHAPE
// -------------
// A data-driven alias table consulted ONLY on the miss path. Zero behaviour
// change when the lookup succeeds (the overwhelmingly common case): we do not
// touch the fast path at all. On a miss we verify the class IDENTITY (not just
// its name) and the type SIGNATURE before retrying under the OpenJDK name, so
// an unrelated class with a coincidentally-named missing field can never be
// silently redirected.
//
// You cannot solve this with a subclass or a framework shadow: `java.io.
// FileDescriptor` is `public final`, and java.* is owned by the boot loader.
// Interception at the JNI vtable is the only layer that reaches it.
//
// THE TABLE. Every row needs BOTH sides cited -- AOSP for the Android name,
// `javap -p` on this host's OpenJDK 21 for the host name. Do not add a row you
// cannot cite; an uncited row is a guess that corrupts a field access.
//
//  [1] java/io/FileDescriptor  "descriptor" -> "fd"   (I)
//      ANDROID: libcore/ojluni/src/main/java/java/io/FileDescriptor.java
//        (android.googlesource.com/platform/libcore, refs/heads/main), the
//        field block of `public final class FileDescriptor`, verbatim:
//            // Android-changed: Renamed fd to descriptor.
//            // Renaming is to avoid issues with JNI/reflection fetching the
//            // descriptor value.
//            private int descriptor;
//        (AOSP renamed it *specifically* to break reflective access, which is
//        exactly the access native guests perform.)
//      OPENJDK: `javap -p java.io.FileDescriptor` on openjdk 21.0.11 ->
//            private int fd;
//        (also java/io/FileDescriptor.java upstream, unchanged since JDK 1.0)
//      Both are `int`, so the "I" signature is identical on both sides and the
//      alias is type-exact.
//      GUEST EVIDENCE (measured): `strings lib/arm64-v8a/libSDL2.so` from
//      org.artsoft.rocksndiamonds_4020200 emits, consecutively,
//        getAssets / ()Landroid/content/res/AssetManager;
//        openFd   / (Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;
//        getStartOffset / getDeclaredLength
//        getFileDescriptor / ()Ljava/io/FileDescriptor;
//        descriptor
//      i.e. SDL's Android_JNI_FileOpen asset path, ending in this GetFieldID.
//      Fleet scan of all 51 APKs in ../Apks for the exact string "descriptor"
//      in a guest .so: 6 hit (rocksndiamonds, org.videolan.vlc,
//      org.thoughtcrime.securesms, org.fossify.gallery, de.danoeh.antennapod,
//      minecraft-mod-menus) -- media/ffmpeg-shaped libraries, not just SDL.
//
// AUDITED AND DELIBERATELY ABSENT
// -------------------------------
//  * java/nio/Buffer -- checked because native code loves to read the direct
//    address without GetDirectBufferAddress. AOSP ojluni Buffer.java declares
//    `mark`/`position`/`limit`/`capacity`/`address` with the SAME names as
//    `javap -p java.nio.Buffer` on OpenJDK 21, so no alias is needed. Its one
//    extra field, `final int _elementSizeShift` ("Android-added: ... for
//    NIOAccess class and framework native code"), has NO OpenJDK counterpart
//    at all -- an alias cannot express that, and inventing one would hand the
//    guest a wrong value. Left to fail loudly instead.
//
// DISCOVERY, not guesswork, is how the next row gets added: macapk_field_alias
// LOGS every unresolved GetFieldID with the owning class's real name, so the
// next instance of this bug names itself in the log on the first run instead
// of costing another session. Same rationale as the v1.0.572
// `log_methodid_miss` guard for methods.
namespace {

struct MacApkFieldAlias {
    const char* clazz;    // JNI internal name of the owning class
    const char* android;  // the name Android's libcore uses (what guests ask)
    const char* openjdk;  // the name this host's OpenJDK uses
    const char* sig;      // JNI type signature; must be identical on both
    jclass      cached;   // lazily-resolved global ref, for identity checks
};

MacApkFieldAlias g_field_aliases[] = {
    { "java/io/FileDescriptor", "descriptor", "fd", "I", nullptr },
};

// Report an unresolved field so the NEXT occurrence of this bug class is
// self-naming. Rate-limited. Must be called with the pending NoSuchFieldError
// already cleared (JNI calls with an exception pending are undefined).
void log_fieldid_miss(JNIEnv* env, jclass c, const char* which,
                      const char* n, const char* s) {
    static std::atomic<int> k{0};
    if (k.fetch_add(1) >= 40) return;
    char owner[256];
    std::snprintf(owner, sizeof(owner), "%s", "?");
    jclass cc = env->GetObjectClass(c);           // -> java.lang.Class
    if (cc) {
        jmethodID gn = env->GetMethodID(cc, "getName", "()Ljava/lang/String;");
        if (gn) {
            jstring js = static_cast<jstring>(env->CallObjectMethod(c, gn));
            if (js) {
                const char* u = env->GetStringUTFChars(js, nullptr);
                if (u) {
                    std::snprintf(owner, sizeof(owner), "%s", u);
                    env->ReleaseStringUTFChars(js, u);
                }
                env->DeleteLocalRef(js);
            }
        }
        env->DeleteLocalRef(cc);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    std::fprintf(stderr,
        "[jni-guard] %s MISS: %s.\"%s\" sig=\"%s\" -> NULL (field not present "
        "on this host's class; a guest that skips the NULL check will read "
        "GARBAGE from GetXxxField)\n",
        which, owner, n ? n : "?", s ? s : "?");
    std::fflush(stderr);
}

}  // namespace

// Called from bionic_shim.cpp's Get{,Static}FieldID guards, ONLY after the
// real lookup has already returned NULL. `orig` is that same original slot,
// passed in rather than re-entered through the (patched) vtable so there is no
// recursion and the static/instance choice needs no branch here.
//
// Contract, exactly:
//   * returns non-NULL and leaves NO pending exception -> an alias resolved;
//   * returns NULL and leaves the caller's ORIGINAL pending exception intact
//     -> nothing matched, behaviour is byte-identical to not having this hook.
extern "C" jfieldID __macapk_jni_field_alias(
        JNIEnv* env, jclass c, const char* name, const char* sig,
        jfieldID (*orig)(JNIEnv*, jclass, const char*, const char*),
        const char* which) {
    if (!env || !c || !name || !sig || !orig) return nullptr;

    // The failed lookup left NoSuchFieldError pending. Every JNI call below
    // needs a clean state, so stash it and restore on the no-match path.
    jthrowable pending = env->ExceptionOccurred();
    if (pending) env->ExceptionClear();

    jfieldID resolved = nullptr;
    for (MacApkFieldAlias& a : g_field_aliases) {
        if (std::strcmp(name, a.android) != 0) continue;
        if (std::strcmp(sig,  a.sig)     != 0) continue;
        if (!a.cached) {
            jclass lc = env->FindClass(a.clazz);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (!lc) continue;
            a.cached = static_cast<jclass>(env->NewGlobalRef(lc));
            env->DeleteLocalRef(lc);
            if (!a.cached) continue;
        }
        // Identity, not name equality: a same-named class from a different
        // loader is a DIFFERENT class and must not be aliased.
        if (!env->IsSameObject(c, a.cached)) continue;
        resolved = orig(env, c, a.openjdk, a.sig);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (resolved) {
            static std::atomic<int> once{0};
            if (once.fetch_add(1) < 8) {
                std::fprintf(stderr,
                    "[jni-fieldalias] %s(%s, \"%s\", \"%s\") -> host field "
                    "\"%s\" (Android libcore renamed it; OpenJDK 21 kept the "
                    "upstream name)\n",
                    which, a.clazz, a.android, a.sig, a.openjdk);
                std::fflush(stderr);
            }
            break;
        }
    }

    if (resolved) {
        if (pending) env->DeleteLocalRef(pending);
        return resolved;   // exception state intentionally left CLEAR
    }
    log_fieldid_miss(env, c, which, name, sig);
    if (pending) {
        env->Throw(pending);          // restore the caller's original error
        env->DeleteLocalRef(pending);
    }
    return nullptr;
}

// ===========================================================================
// FindClass-miss recall: name the class in the NULL-jclass GetMethodID /
// GetFieldID / GetStaticMethodID / GetStaticFieldID diagnostic (v1.0.839)
// ===========================================================================
// THE BUG
// -------
// bionic_shim.cpp's `log_null_jclass_guard` (called from all four
// Get{,Static}{Method,Field}ID guards whenever the caller passes a NULL
// jclass) already explains WHY the crash was avoided, but not WHICH class
// the guest actually wanted -- and that is the single most useful fact for
// this bug class, because the guest already told us: a NULL jclass reaching
// this framework almost always traces back to an unchecked
// `env->FindClass(name)` a few lines up, on the SAME thread. FindClass
// returned NULL (NoClassDefFoundError, silently swallowed by the guest), and
// the guest pressed on with the NULL result instead of checking it.
//
// Measured example (org.thoughtcrime.securesms, 2026-07-29): Stage-6 loads
// libsignal's native lib fine (599 exports, 13318 FDEs, init_array ran),
// then libsignal's Rust JNI init does exactly this shape -- find a class,
// ignore the NULL, ask it for a method -- and our guard logs:
//     [jni-guard] GetMethodID(NULL jclass, "getName", "()Ljava/lang/String;")
//         -> NULL (missing class; would have crashed the JVM)
// which says a class went missing but not WHICH ONE, so the diagnosis
// dead-ends exactly where the most useful fact would be.
//
// THE FIX SHAPE
// -------------
// A per-thread "last FindClass argument that returned NULL" recall cell.
// bionic_shim.cpp's `macapk_jni_FindClass_guard` already knows, at its own
// final-miss log site (next to its `log_findclass_throwable(env, t, "->
// NULL, threw", name)` call), that `name` just failed to resolve; it only
// needs to hand that string to `__macapk_jni_note_findclass_miss` before
// falling through to its existing `return c;` (still NULL, behaviour
// unchanged). `log_null_jclass_guard` then reads it back with
// `__macapk_jni_last_findclass_miss` and appends it to the same printf.
// Both ends are deliberately trivial -- no JNI calls, no allocation, no
// exception-state interaction -- so neither can introduce a new failure mode
// into guard code that exists specifically to survive guest bugs.
//
// This TU cannot wire the two call sites itself (both live in
// bionic_shim.cpp, a file this lane does not own during the speed run); the
// exact diff for that side is reported alongside this change rather than
// applied here.
//
// PER-THREAD, NOT GLOBAL
// -----------------------
// JNI calls arrive from many threads at once (this file's own bare-ellipsis
// bridge exists because engines make JNI calls from arbitrary native
// threads). A single global "last miss" cell would race and misattribute:
// thread A's FindClass miss could be overwritten by thread B's before
// thread A reaches its own GetMethodID call. `thread_local` gives every
// thread its own cell with no lock and no cross-thread interference,
// matching how the guest itself experiences the bug (one thread, FindClass
// then GetMethodID, back to back).
//
// WHY THIS DOES NOT NEED TO BE PROVABLY CAUSAL
// -----------------------------------------------
// This recalls "the most recent miss on this thread," not a proven link to
// the specific NULL-jclass call that follows -- a thread that does an
// unrelated successful FindClass in between will not clear the cell (the
// setter only fires on a miss, never on a hit), so a stale name could in
// principle be reported. That tradeoff is deliberate: on real guest bugs the
// miss and the resulting NULL-jclass call are essentially always adjacent
// (the guest skipped exactly one NULL check), and a slightly-stale hint is
// still far more useful than no name at all. The log wording says "most
// recent FindClass miss on this thread," not "the class this call wanted,"
// so it cannot be over-read as a certainty.
//
// ZERO-COST ON THE SUCCESS PATH
// ------------------------------
// Both functions are reachable ONLY from call sites that already handle a
// NULL class: the note call belongs inside the `!c` branch of the FindClass
// guard, and the recall call belongs inside the `!c` branch of the Get*ID
// guards. A jclass lookup that succeeds -- the overwhelming common case --
// never executes a single instruction added here.
namespace {
// 255 chars + NUL, matching the `owner[256]` scratch-buffer convention this
// file already uses for class names in `log_fieldid_miss` above. Fixed-size
// and thread_local: no allocation, no lock, and every thread gets its own
// zero-initialized copy on first touch.
thread_local char g_last_findclass_miss[256] = "";
}  // namespace

// Called from bionic_shim.cpp's FindClass guard, ONLY on its final NULL
// return (after the app-classloader fallback has also failed). Overwrites
// this thread's recall cell; never fails, never touches JNI state.
extern "C" void __macapk_jni_note_findclass_miss(const char* name) {
    std::snprintf(g_last_findclass_miss, sizeof(g_last_findclass_miss),
                  "%s", name ? name : "?");
}

// Called from bionic_shim.cpp's `log_null_jclass_guard`, ONLY after it has
// already decided the caller passed a NULL jclass. "(none)" (never a legal
// JNI class name) means this thread has not recorded a FindClass miss yet.
extern "C" const char* __macapk_jni_last_findclass_miss(void) {
    return g_last_findclass_miss[0] ? g_last_findclass_miss : "(none)";
}
