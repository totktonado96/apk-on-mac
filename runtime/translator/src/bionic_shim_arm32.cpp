// bionic_shim_arm32.cpp -- ARM32-lifted-tier ("__macapk_shim_*") twins for a
// batch of NDK/Bionic functions whose Stage-6 ("__macapk_arm64_*") host
// implementation already exists in bionic_shim.cpp, but which had NO
// ARM32-lifted counterpart -- so an ARM32 guest's PLT import for any of them
// fell through to a silent panic stub returning 0. See:
//   docs/arm32-shim-parity-audit_2026-07-28.md      (lane A: the parity gap,
//     501 __macapk_arm64_* symbols with no __macapk_shim_* twin, ranked list)
//   docs/arm32-wrong-abi-bare-resolve_2026-07-28.md (lane N: the sibling
//     "bare-resolves-to-the-WRONG-abi-host-function" bug class + the tooling)
//   docs/arm32-shim-bulk-bridge_2026-07-28.md       (this lane's deliverable:
//     what got picked, why, and the exact main.cpp diff needed)
//
// WHY A SEPARATE FILE: bionic_shim.cpp (39k+ lines) was being actively edited
// by another lane concurrently with this batch landing. Rather than collide
// on that file, every shim below lives here and is added to the SAME
// `macapk-bionic-shim` CMake target (see CMakeLists.txt) so it links into
// the one shim dylib the translator already dlopens.
//
// COORDINATION NOTE (read before adding anything to this file): this
// fleet moves fast. Two OTHER lanes landed overlapping work on the SAME
// symbol-parity gap while this file was being researched/written:
//   - lane N landed 14 names DIRECTLY in bionic_shim.cpp: gettid, prctl,
//     __assert2, __system_property_get, __open_2, __FD_SET_chk,
//     __FD_ISSET_chk, __FD_CLR_chk, __fgets_chk, __strncpy_chk2,
//     __read_chk, __write_chk, epoll_create1, sched_getscheduler, eventfd,
//     __ctype_get_mb_cur_max, android_set_abort_message.
//   - lane INFRA landed dl_unwind_find_exidx (a REAL per-image exidx
//     registry, not a stub) in the new src/bionic_shim_signal.cpp.
// This file originally drafted its OWN versions of all 17 before that
// landed; they were removed here to avoid a duplicate-symbol link error
// the moment both TUs compile into the same target. If you are re-deriving
// this file's scope from an older doc/handoff, grep bionic_shim.cpp AND
// bionic_shim_signal.cpp for `__macapk_shim_<name>(` BEFORE adding a name
// here -- this exact collision is why.
//
// DELIBERATE DUPLICATION (do not "clean up" without reading this first):
// A handful of tiny helpers that bionic_shim.cpp keeps `static`/file-local
// (gptr(), the LiftedArmFn typedef) are copied here verbatim rather than
// hoisted into a shared header, per the boss's explicit instruction: a 3-line
// helper duplicated across two TUs today is fine and avoids touching another
// lane's file mid-flight; unify into a shared macapk/bionic_shim_common.h
// later. Do NOT delete the duplicate without confirming bionic_shim.cpp's
// own copy still matches (both derive g_guest_base the same way, via the
// EXPORTED __macapk_get_guest_base() accessor -- see below).
//
// EVERYTHING here is a BRIDGE to an existing, already-correct
// __macapk_arm64_* implementation wherever the underlying logic is
// architecture-agnostic once pointers are translated (the large majority).
// A few names have NO valid bridge because the ARM32 tier's representation
// of the relevant object genuinely differs from Stage-6's (the guest stack
// ARENA vs a real host call stack for pthread_getattr_np; a raw guest vaddr
// chain for __pthread_cleanup_push/pop where Stage-6 uses real host
// pointers; a SEPARATE semaphore registry for sem_timedwait) -- those are
// implemented fresh, with the ABI/struct research cited inline.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <ctime>
#include <unistd.h>
#include <sys/mman.h>

// =============================================================================
// Deliberately-duplicated tiny helpers (see file banner).
// =============================================================================

// Exported by bionic_shim.cpp (nm -gU confirms ___macapk_get_guest_base is a
// live "T" symbol in the currently-staged libmacapk-bionic-shim.dylib). It
// call_once-initializes the guest arena on first use, so calling it from this
// TU is exactly as safe as bionic_shim.cpp's own gptr() calling it via
// std::call_once(g_guest_base_once, allocate_guest_memory) -- we just reach
// the SAME allocation through the public accessor instead of the file-local
// std::once_flag, which we cannot see from here.
extern "C" void* __macapk_get_guest_base(void);

// Mirrors bionic_shim.cpp's own gptr() (its comment: "Force-allocate the
// guest memory region if no translated dylib has triggered it yet... Routing
// every gptr() through call_once forces the region to exist before any shim
// can dereference a guest address"). __macapk_get_guest_base() already does
// that call_once internally, so this is the same guarantee via the exported
// entry point.
static inline char* gptr(uint32_t a) {
    if (!a) return nullptr;
    return reinterpret_cast<char*>(
        static_cast<uint8_t*>(__macapk_get_guest_base()) + a);
}

// JNI-style opaque-handle table (FILE*, jclass, EGLDisplay, ANativeWindow*,
// AConfiguration*, ...) -- already exported, non-static, used throughout
// bionic_shim.cpp for exactly this "host object, guest holds an opaque
// 32-bit token" shape. Declared here so this TU can reuse the SAME table
// (not a parallel one) for the AConfiguration / slCreateEngine /
// __system_property_find bridges below.
extern "C" uint32_t __macapk_jni_make_handle(void* real_ptr);
extern "C" void*    __macapk_jni_resolve_handle(uint32_t h);
extern "C" void      __macapk_jni_release_handle(uint32_t h);

// The ARM32 "host calls into recompiled ARM32 guest code" primitive, already
// exported and exercised by pthread_once/pthread_create/qsort/
// __cxa_thread_atexit_impl. Needed by __pthread_cleanup_pop below (its
// `routine` argument is a GUEST CODE ADDRESS, not a host-callable function
// pointer -- see the long comment there).
using LiftedArmFn = int32_t (*)(uint32_t, uint32_t, uint32_t, uint32_t,
                                 uint32_t);
extern "C" void*   __macapk_resolve_function(uint32_t vaddr);
extern "C" int32_t __macapk_invoke_safe(LiftedArmFn fn, uint32_t r0,
                                         uint32_t r1, uint32_t r2,
                                         uint32_t r3, uint32_t sp);
extern "C" uint32_t __macapk_alloc_thread_stack(void);

// Already-exported ARM32-tier shims this file bridges to (rather than
// duplicating their logic). Both pre-date this file (neither is part of the
// 17-name overlap noted above).
extern "C" uint32_t __macapk_shim_pthread_self(uint32_t, uint32_t, uint32_t,
                                                uint32_t);
extern "C" uint32_t __macapk_shim_sem_trywait(uint32_t, uint32_t, uint32_t,
                                               uint32_t);

// =============================================================================
// __macapk_arm64_* twin prototypes this file bridges to.
//
// Every prototype below is re-declared here using PLAIN standard types
// (void*, size_t, int32_t, ...) rather than bionic_shim.cpp's own
// anonymous-namespace types (e.g. its file-local `MacApkAConfig`), because
// those types have internal linkage and are not nameable outside that TU.
// This is safe: extern "C" linkage is determined by the mangled NAME only,
// and a pointer is ABI-identical regardless of which C++ type name spells it
// in a given TU. Each declaration below was checked against the actual
// definition in bionic_shim.cpp (grep the name there to re-verify if this
// file next needs an update -- line numbers are not cited because another
// lane is actively appending to that file and they shift).
// =============================================================================
extern "C" {

void*       __macapk_arm64___system_property_find(const char* name);
int         __macapk_arm64___system_property_foreach(
                void (*propfn)(const void* pi, void* cookie), void* cookie);
int         __macapk_arm64___system_property_read(void* pi, char* name,
                                                   char* value);
int         __macapk_arm64_epoll_ctl(int epfd, int op, int fd, void* evp);
int         __macapk_arm64_epoll_wait(int epfd, void* evp, int maxevents,
                                       int timeout_ms);
int         __macapk_arm64_ftruncate64(int fd, int64_t length);
int64_t     __macapk_arm64_pread64(int fd, void* buf, size_t count,
                                    int64_t offset);
int64_t     __macapk_arm64_lseek64(int fd, int64_t offset, int whence);
void*       __macapk_arm64_mmap64(void* addr, size_t length, int prot,
                                   int flags, int fd, int64_t offset);
int         __macapk_arm64_sched_getparam(int pid, void* bionic_param);
int         __macapk_arm64_sched_getaffinity(int pid, size_t set_size,
                                              void* set);
int         __macapk_arm64_sched_setaffinity(int pid, size_t set_size,
                                              const void* set);
// SLuint32/SLresult are both `unsigned int` in the OpenSL ES standard;
// declared with plain uint32_t here to avoid pulling in <SLES/OpenSLES.h>
// for two typedefs (ABI-identical either way).
uint32_t    __macapk_arm64_slCreateEngine(void** pEngine, uint32_t numOptions,
                                           const void* options,
                                           uint32_t numInterfaces,
                                           const void* pInterfaceIds,
                                           const void* pInterfaceRequired);
void*       __macapk_arm64_memalign(size_t alignment, size_t size);
// pthread_condattr_setclock's real body (bionic_shim.cpp) does
// `reinterpret_cast<int32_t*>(attr_in)` and bit-manipulates a single word --
// declaring the param as int32_t* directly (rather than pthread_condattr_t*)
// avoids a <pthread.h> dependency and matches what the twin actually does.
int         __macapk_arm64_pthread_condattr_setclock(int32_t* attr_in,
                                                      int clock_id);
int         __macapk_arm64_inotify_init(void);
int         __macapk_arm64_inotify_add_watch(int fd, const char* path,
                                              uint32_t mask);
ssize_t     __macapk_arm64___pread_chk(int fd, void* buf, size_t count,
                                        int32_t offset, size_t buf_size);
ssize_t     __macapk_arm64___pwrite_chk(int fd, const void* buf, size_t count,
                                         int32_t offset, size_t buf_size);
// AConfiguration_* -- the real pointee type (MacApkAConfig) is anonymous-
// namespace/private to bionic_shim.cpp; every function here only ever
// receives back a pointer it got from AConfiguration_new, so `void*` is a
// completely opaque, ABI-safe stand-in (never dereferenced by name here).
void*       __macapk_arm64_AConfiguration_new(void);
void        __macapk_arm64_AConfiguration_delete(void* c);
void        __macapk_arm64_AConfiguration_fromAssetManager(void* out,
                                                            void* am);
void        __macapk_arm64_AConfiguration_getCountry(void* c, char* out);
void        __macapk_arm64_AConfiguration_getLanguage(void* c, char* out);

}  // extern "C" (twin prototypes)

// =============================================================================
// This file's own ARM32-lifted-tier shims ("__macapk_shim_*").
//
// Calling convention recap (main.cpp, kPointerAwareImports comment): every
// shim takes the standard ARM32 4-register quad (a=r0, b=r1, c=r2, d=r3) and
// returns a single i32 (r0). A name ALSO listed in kPointerAwareWideImports
// gets a 5th `sp` parameter (the lifted guest stack pointer) so the shim can
// read stack-spilled arguments 5+ via gptr(sp + N*4) -- see the AAPCS32
// citations below for exactly which of these functions need it and why.
// =============================================================================
extern "C" {

// ---------------------------------------------------------------------------
// Section 1: scalar / single-buffer graceful bridges.
// ---------------------------------------------------------------------------

// __system_property_find(name): bridging (rather than hardcoding "always 0"
// ourselves) means this inherits the twin's behaviour automatically, which is
// exactly what happened: this comment used to say "the twin always returns
// nullptr (no property store to search)" and that has been FALSE since the
// real property store landed 2026-08-21 (see bionic_shim.cpp, "the property
// store"). Java fills the table before any guest code runs and the twin now
// answers real values. The handle-boxing below is what makes a non-null result
// usable: prop_info* is an opaque HOST pointer and the guest is 32-bit, so it
// cannot hold one; __macapk_jni_make_handle boxes it into a 32-bit token the
// guest only ever hands back to __system_property_read / _foreach.
uint32_t __macapk_shim___system_property_find(uint32_t name_addr, uint32_t,
                                               uint32_t, uint32_t) {
    if (!name_addr) return 0;
    void* pi = __macapk_arm64___system_property_find(gptr(name_addr));
    return pi ? __macapk_jni_make_handle(pi) : 0;
}
// __system_property_read(pi, name, value): pi is whatever
// __system_property_find handed back (a handle, or 0 in the always-not-found
// case above), so resolve it before forwarding.
uint32_t __macapk_shim___system_property_read(uint32_t pi_h,
                                               uint32_t name_addr,
                                               uint32_t value_addr,
                                               uint32_t) {
    void* pi = pi_h ? __macapk_jni_resolve_handle(pi_h) : nullptr;
    int r = __macapk_arm64___system_property_read(
        pi, name_addr ? gptr(name_addr) : nullptr,
        value_addr ? gptr(value_addr) : nullptr);
    return static_cast<uint32_t>(r);
}

// __system_property_foreach(callback, cookie): the ARM32 twin of the arm64
// walk in bionic_shim.cpp. Two translations are needed and neither is optional.
//
// (1) THE CALLBACK IS GUEST CODE. It arrives as a 32-bit guest vaddr, not a
//     host function pointer, so it goes through the same resolve+invoke_safe
//     path every other guest-callback shim in this file uses
//     (__macapk_resolve_function then __macapk_invoke_safe on a freshly
//     allocated guest stack, so a faulting callback recovers instead of
//     killing the process, and so the callback cannot stomp the suspended
//     caller's live guest frame). This is the qsort comparator pattern.
//
// (2) THE prop_info HANDLE MUST BE BOXED. The arm64 twin hands out an interned
//     KEY, a 64-bit host pointer. A 32-bit guest cannot hold one, so each is
//     boxed with __macapk_jni_make_handle exactly as _find above does, and
//     _read above resolves it back. The guest therefore sees a handle from
//     foreach that is interchangeable with one from _find, which is the
//     property Bionic's contract requires.
//
// The walk itself is NOT duplicated: this forwards to the arm64 twin with a
// host thunk, so there is one implementation of the store traversal and one
// place where the locking argument has to be right.
uint32_t __macapk_shim___system_property_foreach(uint32_t cb_vaddr,
                                                  uint32_t cookie,
                                                  uint32_t, uint32_t) {
    if (!cb_vaddr) return static_cast<uint32_t>(-1);
    void* host_fn = __macapk_resolve_function(cb_vaddr);
    if (!host_fn) {
        std::fprintf(stderr,
            "[macapk-shim] __system_property_foreach: unresolved callback "
            "vaddr=0x%x -- reporting failure rather than skipping the walk "
            "silently\n", cb_vaddr);
        std::fflush(stderr);
        return static_cast<uint32_t>(-1);
    }
    struct Ctx { void* host_fn; uint32_t cookie; } ctx{host_fn, cookie};
    auto thunk = [](const void* pi, void* c) {
        Ctx* x = static_cast<Ctx*>(c);
        uint32_t h = __macapk_jni_make_handle(const_cast<void*>(pi));
        uint32_t sp = __macapk_alloc_thread_stack();
        __macapk_invoke_safe(reinterpret_cast<LiftedArmFn>(x->host_fn),
                             h, x->cookie, 0, 0, sp);
    };
    return static_cast<uint32_t>(
        __macapk_arm64___system_property_foreach(thunk, &ctx));
}

// epoll_ctl(epfd, op, fd, event): struct epoll_event on Bionic ARM32 is
// `{ uint32_t events; /*4 pad*/ epoll_data_t data; }` = 16 bytes -- verified
// (bionic/libc/kernel/uapi/linux/eventpoll.h: EPOLL_PACKED is empty except
// on __x86_64__, so ARM gets the naturally-aligned layout; AAPCS32 gives a
// __u64 union member 8-byte alignment same as AAPCS64, so the padding after
// `events` is identical). This is BIT-IDENTICAL to the Stage-6 twin's own
// `macapk_epoll_event` (bionic_shim.cpp, same citation, same struct) --
// unlike most of this file, no ARM32-specific struct is needed here, only
// the pointer translation.
uint32_t __macapk_shim_epoll_ctl(uint32_t epfd, uint32_t op, uint32_t fd,
                                  uint32_t evp_addr) {
    void* evp = evp_addr ? gptr(evp_addr) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_epoll_ctl(
        static_cast<int>(epfd), static_cast<int>(op), static_cast<int>(fd),
        evp));
}
// epoll_wait(epfd, events, maxevents, timeout_ms): `events` is a contiguous
// array of the SAME 16-byte struct above; base-pointer translation is
// sufficient (no per-element marshalling needed).
uint32_t __macapk_shim_epoll_wait(uint32_t epfd, uint32_t evp_addr,
                                   uint32_t maxevents, uint32_t timeout_ms) {
    void* evp = evp_addr ? gptr(evp_addr) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_epoll_wait(
        static_cast<int>(epfd), evp, static_cast<int>(maxevents),
        static_cast<int>(timeout_ms)));
}

// ftruncate64(int fd, off64_t length): AAPCS32 Stage C (ARM-software/abi-aa
// aapcs32.rst, Rule C.3: "If the argument requires double-word alignment
// (8-byte), the NCRN is rounded up to the next even register number") --
// fd consumes r0 (NCRN 0->1); the 8-byte `length` needs an EVEN register, so
// NCRN rounds 1->2 and length occupies r2:r3 (lo, hi). r1 is left as padding
// -- NOT length's low word. Fits entirely in registers (no stack/wide shim
// needed), but note the (a, b, c, d) mapping is (fd, PAD, length_lo,
// length_hi), NOT (fd, length_lo, length_hi, PAD).
uint32_t __macapk_shim_ftruncate64(uint32_t fd, uint32_t /*pad_r1*/,
                                    uint32_t length_lo, uint32_t length_hi) {
    int64_t length = static_cast<int64_t>(
        (static_cast<uint64_t>(length_hi) << 32) | length_lo);
    return static_cast<uint32_t>(
        __macapk_arm64_ftruncate64(static_cast<int>(fd), length));
}

// sched_getparam(pid, param) / sched_getaffinity / sched_setaffinity: bridge
// directly. The twin's own body already does the "pid==0 => self, else
// resolve via the tid registry, else report the Android-normal default /
// ESRCH" dance internally (bionic_shim.cpp's macapk_lookup_guest_tid,
// file-local and not reachable from this TU) -- there is nothing left for
// this shim to decide; it only has to translate the pointer.
uint32_t __macapk_shim_sched_getparam(uint32_t pid, uint32_t param_addr,
                                      uint32_t, uint32_t) {
    if (!param_addr) { errno = 14; return static_cast<uint32_t>(-1); }  // EFAULT
    int r = __macapk_arm64_sched_getparam(static_cast<int>(pid),
                                          gptr(param_addr));
    return static_cast<uint32_t>(r);
}
uint32_t __macapk_shim_sched_getaffinity(uint32_t pid, uint32_t set_size,
                                         uint32_t set_addr, uint32_t) {
    void* set = set_addr ? gptr(set_addr) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_sched_getaffinity(
        static_cast<int>(pid), static_cast<size_t>(set_size), set));
}
uint32_t __macapk_shim_sched_setaffinity(uint32_t pid, uint32_t set_size,
                                         uint32_t set_addr, uint32_t) {
    const void* set = set_addr ? gptr(set_addr) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_sched_setaffinity(
        static_cast<int>(pid), static_cast<size_t>(set_size), set));
}

// slCreateEngine(pEngine, numOptions, options, numInterfaces, pInterfaceIds,
// pInterfaceRequired): the twin only ever touches `pEngine` (allocates a
// real SLObj* and writes it through the out-param; every other argument is
// accepted and ignored) -- confirmed by reading its body, so this shim only
// needs to marshal pEngine and can ignore the guest's b/c/d entirely (no
// wide/stack-spill shape needed -- the ignored args never even need to be
// read off the stack).
// `pEngine` is an OUT-POINTER TO AN OPAQUE HANDLE: the twin writes a real
// 8-byte host pointer through it, which cannot be stored directly into the
// guest's 4-byte slot, so we capture it in a local host variable, box it via
// the existing JNI handle table, and write only the resulting 4-byte handle
// into guest memory (the same pattern __macapk_shim_eglCreateContext uses
// for its own out-pointer-to-opaque-object return).
uint32_t __macapk_shim_slCreateEngine(uint32_t pEngine_addr, uint32_t,
                                      uint32_t, uint32_t) {
    if (!pEngine_addr) return static_cast<uint32_t>(-1);  // SL_RESULT_PARAMETER_INVALID
    void* host_engine = nullptr;
    uint32_t r = __macapk_arm64_slCreateEngine(
        &host_engine, 0, nullptr, 0, nullptr, nullptr);
    if (r == 0 && host_engine) {
        uint32_t h = __macapk_jni_make_handle(host_engine);
        std::memcpy(gptr(pEngine_addr), &h, sizeof(h));
    }
    return r;
}

// memalign(alignment, size): both args plain size_t, no pointer args. The
// twin returns a REAL HOST pointer (Stage-6 guest pointers ARE host
// pointers); for ARM32 we must convert that back into a guest-relative
// offset, exactly like __macapk_shim_mmap already does for mmap's result.
uint32_t __macapk_shim_memalign(uint32_t alignment, uint32_t size, uint32_t,
                                 uint32_t) {
    void* p = __macapk_arm64_memalign(static_cast<size_t>(alignment),
                                      static_cast<size_t>(size));
    if (!p) return 0;
    uint8_t* base = static_cast<uint8_t*>(__macapk_get_guest_base());
    intptr_t off = static_cast<uint8_t*>(p) - base;
    if (off < 0 || off > 0xFFFFFFFFLL) {
        // Host allocator handed back memory outside the guest's 32-bit
        // window (should not happen in practice -- the twin's allocator has
        // no reason to prefer a far address -- but a guest can't address it
        // either way, so fail rather than hand back a truncated pointer).
        return 0;
    }
    return static_cast<uint32_t>(off);
}

// pthread_condattr_setclock(attr, clock_id): the twin's ENTIRE body is
// `int32_t* attr = reinterpret_cast<int32_t*>(attr_in); atomic bit-test/set
// on *attr` -- no host-object table, no OS call. Since the ARM32 tier's
// pthread_condattr_t is ALSO just a raw guest int32 word (its own
// __macapk_shim_pthread_condattr_init/_destroy already treat it that way,
// as a no-op that leaves the guest word untouched), the twin's logic is
// architecture-agnostic bit manipulation on whatever memory the pointer
// resolves to -- bridging via gptr() carries the EXACT same semantics
// across tiers, not merely a close approximation.
uint32_t __macapk_shim_pthread_condattr_setclock(uint32_t attr_addr,
                                                  uint32_t clock_id, uint32_t,
                                                  uint32_t) {
    int32_t* attr = attr_addr
        ? reinterpret_cast<int32_t*>(gptr(attr_addr)) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_pthread_condattr_setclock(
        attr, static_cast<int>(clock_id)));
}

// inotify_init() / inotify_add_watch(fd, path, mask): Darwin has no inotify;
// the twin returns -1/ENOSYS so callers take their documented graceful
// degrade path (see the long comment on the twin in bionic_shim.cpp --
// Firebase's messaging watch-thread in particular).
uint32_t __macapk_shim_inotify_init(uint32_t, uint32_t, uint32_t, uint32_t) {
    return static_cast<uint32_t>(__macapk_arm64_inotify_init());
}
uint32_t __macapk_shim_inotify_add_watch(uint32_t fd, uint32_t path_addr,
                                         uint32_t mask, uint32_t) {
    const char* path = path_addr ? gptr(path_addr) : nullptr;
    return static_cast<uint32_t>(__macapk_arm64_inotify_add_watch(
        static_cast<int>(fd), path, static_cast<uint32_t>(mask)));
}

// ---------------------------------------------------------------------------
// Section 2: AConfiguration_* (android/configuration.h). SmashHit reads the
// device configuration to pick asset variants / set up input. The twin's
// AConfiguration* is an opaque host struct (anonymous-namespace
// MacApkAConfig in bionic_shim.cpp) -- box/unbox it through the SAME JNI
// handle table already used throughout that file for exactly this
// "host object, guest holds an opaque token" shape (e.g. ANativeWindow*,
// EGLDisplay). AConfiguration_fromAssetManager's second argument
// (AAssetManager*) is read by NEITHER the guest caller's expectations NOR
// the twin's own body (`void* /*am*/` -- confirmed unused by reading it), so
// it is deliberately never resolved here either.
// ---------------------------------------------------------------------------
uint32_t __macapk_shim_AConfiguration_new(uint32_t, uint32_t, uint32_t,
                                          uint32_t) {
    void* c = __macapk_arm64_AConfiguration_new();
    return c ? __macapk_jni_make_handle(c) : 0;
}
uint32_t __macapk_shim_AConfiguration_delete(uint32_t handle, uint32_t,
                                             uint32_t, uint32_t) {
    if (!handle) return 0;
    void* c = __macapk_jni_resolve_handle(handle);
    if (c) __macapk_arm64_AConfiguration_delete(c);
    __macapk_jni_release_handle(handle);
    return 0;
}
uint32_t __macapk_shim_AConfiguration_fromAssetManager(uint32_t handle,
                                                       uint32_t /*am_h*/,
                                                       uint32_t, uint32_t) {
    void* c = handle ? __macapk_jni_resolve_handle(handle) : nullptr;
    if (c) __macapk_arm64_AConfiguration_fromAssetManager(c, nullptr);
    return 0;
}
uint32_t __macapk_shim_AConfiguration_getCountry(uint32_t handle,
                                                 uint32_t out_addr, uint32_t,
                                                 uint32_t) {
    void* c = handle ? __macapk_jni_resolve_handle(handle) : nullptr;
    char* out = out_addr ? gptr(out_addr) : nullptr;
    if (c && out) __macapk_arm64_AConfiguration_getCountry(c, out);
    return 0;
}
uint32_t __macapk_shim_AConfiguration_getLanguage(uint32_t handle,
                                                  uint32_t out_addr, uint32_t,
                                                  uint32_t) {
    void* c = handle ? __macapk_jni_resolve_handle(handle) : nullptr;
    char* out = out_addr ? gptr(out_addr) : nullptr;
    if (c && out) __macapk_arm64_AConfiguration_getLanguage(c, out);
    return 0;
}

// ---------------------------------------------------------------------------
// Section 3: __cmsg_nxthdr -- FRESH ARM32-specific implementation, NOT a
// bridge to the Stage-6 twin.
//
// The Stage-6 twin's BionicMsghdr/BionicCmsghdr structs (bionic_shim.cpp)
// are the arm64/LP64-compiled byte layout (56/16 bytes, 8-byte CMSG_ALIGN).
// Bionic's OWN source (bionic/libc/include/sys/socket.h, fetched this
// session) declares msg_iovlen/msg_controllen/cmsg_len as `size_t` with NO
// __LP64__ branch in the header text -- meaning the ACTUAL byte layout
// differs by architecture purely through size_t/pointer width. On ARM32
// (ILP32, size_t/pointers = 4 bytes):
//   struct msghdr { void* msg_name;        // +0  (4, GUEST vaddr)
//                   socklen_t msg_namelen; // +4  (4)
//                   struct iovec* msg_iov; // +8  (4, GUEST vaddr)
//                   size_t msg_iovlen;     // +12 (4)
//                   void* msg_control;     // +16 (4, GUEST vaddr)
//                   size_t msg_controllen; // +20 (4)
//                   int msg_flags; }       // +24 (4)            = 28 bytes
//   struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; }
//                                                                 = 12 bytes
//   CMSG_ALIGN(n) = (n + sizeof(long)-1) & ~(sizeof(long)-1); Bionic ARM32
//   `long` is 4 bytes (NOT 8, unlike the arm64/LP64 twin), so alignment
//   rounds to 4-byte boundaries here, not 8.
// msg_control (and the cmsg chain itself) are GUEST addresses living in
// GUEST memory, so pointer arithmetic below stays entirely in guest-vaddr
// space; the result is likewise a guest vaddr (or 0), never boxed as a
// handle -- it is not a new host allocation, just an offset into a buffer
// the guest already owns and can dereference itself via its own compiled
// loads.
// ---------------------------------------------------------------------------
namespace {
struct Arm32Msghdr {
    uint32_t msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control,
             msg_controllen, msg_flags;
};
static_assert(sizeof(Arm32Msghdr) == 28, "ARM32 Bionic msghdr is 28 bytes");
struct Arm32Cmsghdr {
    uint32_t cmsg_len;
    int32_t  cmsg_level;
    int32_t  cmsg_type;
};
static_assert(sizeof(Arm32Cmsghdr) == 12, "ARM32 Bionic cmsghdr is 12 bytes");
inline uint32_t arm32_cmsg_align(uint32_t len) {
    return (len + 3u) & ~3u;   // sizeof(long) == 4 on ARM32, not 8
}
}  // namespace

uint32_t __macapk_shim___cmsg_nxthdr(uint32_t msg_addr, uint32_t cmsg_addr,
                                     uint32_t, uint32_t) {
    if (!msg_addr || !cmsg_addr) return 0;
    auto* msg  = reinterpret_cast<Arm32Msghdr*>(gptr(msg_addr));
    auto* cmsg = reinterpret_cast<Arm32Cmsghdr*>(gptr(cmsg_addr));
    if (cmsg->cmsg_len < sizeof(Arm32Cmsghdr)) return 0;
    uint32_t base = msg->msg_control;
    uint32_t end  = base + msg->msg_controllen;
    uint32_t next = cmsg_addr + arm32_cmsg_align(cmsg->cmsg_len);
    if (static_cast<uint64_t>(next) + sizeof(Arm32Cmsghdr) >
        static_cast<uint64_t>(end)) {
        return 0;
    }
    auto* ncm = reinterpret_cast<Arm32Cmsghdr*>(gptr(next));
    if (static_cast<uint64_t>(next) + arm32_cmsg_align(ncm->cmsg_len) >
        static_cast<uint64_t>(end)) {
        return 0;
    }
    return next;
}

// ---------------------------------------------------------------------------
// Section 4: __pthread_cleanup_push / __pthread_cleanup_pop -- FRESH
// ARM32-specific implementation (guest-vaddr chain), NOT a bridge.
//
// Bionic's macro (bionic/libc/include/pthread.h) is fully opaque to the
// guest: `{ __pthread_cleanup_t local; __pthread_cleanup_push_internal(
// &local, routine, arg); ...; __pthread_cleanup_pop_internal(&local,
// execute); }` -- nothing but push/pop ever touches `local`'s bytes, so we
// are free to choose ANY internal layout, as long as it fits within
// `sizeof(__pthread_cleanup_t)` the ARM32 compiler assumed when it
// stack-allocated `local` (real Bionic struct: 3 pointers -- prev, routine,
// arg -- so 12 bytes on ILP32, matching the Stage-6 twin's own MacApkCleanup
// which uses the SAME 3-pointer shape sized for LP64/24 bytes).
//
// The critical difference from the Stage-6 twin: `routine` is a GUEST CODE
// ADDRESS (a function pointer into the ARM32 .text), NOT a host-callable
// arm64 function pointer -- the exact same hazard __cxa_thread_atexit_impl
// had (see docs/arm32-wrong-abi-bare-resolve_2026-07-28.md), fixed there via
// __macapk_resolve_function + __macapk_invoke_safe. Reused verbatim here:
// `local` lives in GUEST memory (the guest's own stack arena), so the
// push/pop chain is tracked via guest vaddrs in a thread_local head pointer,
// not host pointers.
// ---------------------------------------------------------------------------
namespace {
struct Arm32Cleanup {
    uint32_t prev;      // +0, guest vaddr of the enclosing cleanup frame (0 = none)
    uint32_t routine;   // +4, GUEST CODE vaddr -- resolve before calling
    uint32_t arg;       // +8, guest vaddr passed to routine
};
static_assert(sizeof(Arm32Cleanup) == 12,
              "ARM32 Bionic __pthread_cleanup_t is 3 pointers = 12 bytes");
static thread_local uint32_t t_arm32_cleanup_head = 0;
}  // namespace

uint32_t __macapk_shim___pthread_cleanup_push(uint32_t c_addr,
                                              uint32_t routine_vaddr,
                                              uint32_t arg_vaddr, uint32_t) {
    if (!c_addr) return 0;
    auto* c = reinterpret_cast<Arm32Cleanup*>(gptr(c_addr));
    c->prev    = t_arm32_cleanup_head;
    c->routine = routine_vaddr;
    c->arg     = arg_vaddr;
    t_arm32_cleanup_head = c_addr;
    return 0;
}
uint32_t __macapk_shim___pthread_cleanup_pop(uint32_t c_addr, uint32_t execute,
                                             uint32_t, uint32_t) {
    if (!c_addr) return 0;
    auto* c = reinterpret_cast<Arm32Cleanup*>(gptr(c_addr));
    t_arm32_cleanup_head = c->prev;
    if (execute && c->routine) {
        void* host_fn = __macapk_resolve_function(c->routine);
        if (host_fn) {
            uint32_t sp = __macapk_alloc_thread_stack();
            __macapk_invoke_safe(reinterpret_cast<LiftedArmFn>(host_fn),
                                 c->arg, 0, 0, 0, sp);
        } else {
            static std::atomic<int> logged{0};
            if (logged.fetch_add(1, std::memory_order_relaxed) == 0) {
                std::fprintf(stderr,
                    "[bionic-shim-arm32] __pthread_cleanup_pop: unresolved "
                    "routine vaddr=0x%x -- cleanup handler DROPPED (logged "
                    "once)\n", c->routine);
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Section 5: __pread_chk / __pwrite_chk -- FORTIFY checked positional I/O.
//
// Signatures verified against bionic/libc/include/bits/fortify/unistd.h
// (fetched this session):
//   ssize_t __pread_chk(int, void*, size_t, off_t, size_t);   -- 5 args,
//     PLAIN (32-bit) off_t here -- distinct from __pread64_chk's off64_t,
//     which this file does not implement (not in the target list, and would
//     need the same register-pair-splitting care as pread64 below).
//   ssize_t __pwrite_chk(int, const void*, size_t, off_t, size_t); -- 5 args,
//     same off_t note.
// All 4 of (fd, buf, count, offset) are PLAIN 4-byte values (off_t is
// 32-bit here, unlike off64_t's pread64/lseek64/mmap64 -- no AAPCS32
// alignment-skip applies), so they fit exactly in r0-r3 and only the 5th
// (buf_size) spills to the stack with NO padding gap: these two need
// kPointerAwareWideImports.
// ---------------------------------------------------------------------------
uint32_t __macapk_shim___pread_chk(uint32_t fd, uint32_t buf_addr,
                                   uint32_t count, uint32_t offset,
                                   uint32_t sp) {
    void* buf = buf_addr ? gptr(buf_addr) : nullptr;
    uint32_t buf_size = sp
        ? *reinterpret_cast<const uint32_t*>(gptr(sp)) : 0;
    return static_cast<uint32_t>(__macapk_arm64___pread_chk(
        static_cast<int>(fd), buf, static_cast<size_t>(count),
        static_cast<int32_t>(offset), static_cast<size_t>(buf_size)));
}
uint32_t __macapk_shim___pwrite_chk(uint32_t fd, uint32_t buf_addr,
                                    uint32_t count, uint32_t offset,
                                    uint32_t sp) {
    const void* buf = buf_addr ? gptr(buf_addr) : nullptr;
    uint32_t buf_size = sp
        ? *reinterpret_cast<const uint32_t*>(gptr(sp)) : 0;
    return static_cast<uint32_t>(__macapk_arm64___pwrite_chk(
        static_cast<int>(fd), buf, static_cast<size_t>(count),
        static_cast<int32_t>(offset), static_cast<size_t>(buf_size)));
}

// ---------------------------------------------------------------------------
// Section 6: pread64 / lseek64 / mmap64 -- the off64_t-taking LFS family.
// WIDE shims; the exact register/stack layout below was derived from
// ARM-software/abi-aa's aapcs32.rst (fetched this session) and
// cross-checked against this codebase's own EXISTING distinction between
// plain `mmap`'s 32-bit off_t (sp+4, no alignment skip -- see
// __macapk_shim_mmap) and the *64 family's mandatory 64-bit off64_t:
//
//   Rule C.3: "If the argument requires double-word alignment (8-byte), the
//   NCRN is rounded up to the next even register number."
//   Rule C.7: "If the argument required double-word alignment (8-byte), then
//   the NSAA is rounded up to the next double-word address."
//   (a double-word/8-byte argument that does not fit ENTIRELY within the
//   registers remaining after this rounding is placed ENTIRELY on the stack,
//   not split across the last register and the stack -- confirmed via the
//   same source, Rule C.5's split case only applies to arguments LARGER than
//   one register-pair, which none of these are.)
//
// Empirical cross-check attempted (not just spec-reading): disassembled
// libcrashlytics-common.so (Smash Hit) and libunity.so (Subway), both of
// which import all three symbols -- found ZERO direct `bl` call sites to
// any of them in ~3.2M lines of combined disassembly (both binaries appear
// to reach them only through an internal function-pointer table, e.g. a
// portable-I/O abstraction layer, not a literal PLT branch), so a live
// register-dump cross-check was not achievable in this session. Flagged as
// a NEXT item (docs/arm32-shim-bulk-bridge_2026-07-28.md) -- if either
// function misbehaves, debug/arm32rc_replay.py (Unicorn ground truth) is
// the way to confirm/refute this derivation empirically.
// ---------------------------------------------------------------------------

// pread64(fd, buf, count, offset64): fd=r0, buf=r1, count=r2 (NCRN->3); the
// 8-byte offset64 needs an even register, NCRN=3 is odd so it rounds to 4
// (exhausted) -- offset64 goes ENTIRELY to the stack (sp+0=lo, sp+4=hi); r3
// is left unused. WIDE shim: (a=fd, b=buf, c=count, d=UNUSED, sp).
uint32_t __macapk_shim_pread64(uint32_t fd, uint32_t buf_addr, uint32_t count,
                               uint32_t /*pad_r3*/, uint32_t sp) {
    void* buf = buf_addr ? gptr(buf_addr) : nullptr;
    uint32_t off_lo = 0, off_hi = 0;
    if (sp) {
        off_lo = *reinterpret_cast<const uint32_t*>(gptr(sp));
        off_hi = *reinterpret_cast<const uint32_t*>(gptr(sp + 4));
    }
    int64_t offset = static_cast<int64_t>(
        (static_cast<uint64_t>(off_hi) << 32) | off_lo);
    int64_t r = __macapk_arm64_pread64(static_cast<int>(fd), buf,
                                       static_cast<size_t>(count), offset);
    return static_cast<uint32_t>(r);   // ssize_t narrowed like every other
                                        // i32-returning shim in this family
}

// lseek64(fd, offset64, whence): fd=r0 (NCRN->1); offset64 needs even reg,
// NCRN=1 is odd so it rounds to 2 -- offset64=r2:r3 (NCRN->4); whence
// (plain int) is exhausted -- goes to the STACK at sp+0. WIDE shim:
// (a=fd, b=UNUSED, c=offset_lo, d=offset_hi, sp) -> whence=*(i32*)gptr(sp).
uint32_t __macapk_shim_lseek64(uint32_t fd, uint32_t /*pad_r1*/,
                               uint32_t offset_lo, uint32_t offset_hi,
                               uint32_t sp) {
    int64_t offset = static_cast<int64_t>(
        (static_cast<uint64_t>(offset_hi) << 32) | offset_lo);
    int32_t whence = sp
        ? static_cast<int32_t>(*reinterpret_cast<const uint32_t*>(gptr(sp)))
        : 0;
    int64_t r = __macapk_arm64_lseek64(static_cast<int>(fd), offset, whence);
    return static_cast<uint32_t>(r);
}

// mmap64(addr, length, prot, flags, fd, offset64): addr=r0,length=r1,
// prot=r2,flags=r3 (NCRN->4, exhausted BEFORE offset64 is even considered).
// fd (plain int) is exhausted -- STACK at sp+0. offset64 needs 8-byte stack
// alignment (Rule C.7): NSAA after fd is sp+4, rounds up to sp+8. So:
// fd@sp+0, offset_lo@sp+8, offset_hi@sp+12. WIDE shim:
// (a=addr, b=length, c=prot, d=flags, sp).
//
// Bridges to __macapk_arm64_mmap64 (which itself forwards to the
// Bionic-aware __macapk_arm64_mmap, handling Linux->Darwin MAP_*/PROT_*
// flag translation and the Unity anonymous-mmap special case) rather than
// mirroring __macapk_shim_mmap's simpler direct-::mmap() call, so ARM32
// gets the SAME, more correct flag handling Stage-6 already has. The
// returned HOST pointer is converted back to a guest-relative offset
// exactly like __macapk_shim_mmap already does for plain mmap.
uint32_t __macapk_shim_mmap64(uint32_t addr, uint32_t len, uint32_t prot,
                              uint32_t flags, uint32_t sp) {
    uint32_t fd = 0, off_lo = 0, off_hi = 0;
    if (sp) {
        fd     = *reinterpret_cast<const uint32_t*>(gptr(sp));
        off_lo = *reinterpret_cast<const uint32_t*>(gptr(sp + 8));
        off_hi = *reinterpret_cast<const uint32_t*>(gptr(sp + 12));
    }
    int64_t offset = static_cast<int64_t>(
        (static_cast<uint64_t>(off_hi) << 32) | off_lo);
    void* host_addr = addr ? static_cast<void*>(gptr(addr)) : nullptr;
    void* result = __macapk_arm64_mmap64(
        host_addr, static_cast<size_t>(len), static_cast<int>(prot),
        static_cast<int>(flags), static_cast<int>(fd), offset);
    if (result == MAP_FAILED) return static_cast<uint32_t>(-1);
    uint8_t* base = static_cast<uint8_t*>(__macapk_get_guest_base());
    intptr_t off_from_base = static_cast<uint8_t*>(result) - base;
    if (off_from_base < 0 || off_from_base > 0xFFFFFFFFLL) {
        ::munmap(result, static_cast<size_t>(len));
        return static_cast<uint32_t>(-1);
    }
    return static_cast<uint32_t>(off_from_base);
}

// ---------------------------------------------------------------------------
// Section 7: sem_timedwait -- composition over the ALREADY-EXPORTED
// __macapk_shim_sem_trywait, not a bridge to the Stage-6 twin.
//
// The Stage-6 twin (`int __macapk_arm64_sem_timedwait(int32_t* sem, const
// void* abs_timeout)`) assumes Bionic's sem_t IS a raw int32 counter at a
// real host address -- true on Stage-6 (guest pointers = host pointers),
// but WRONG for ARM32, where sem_init/_post/_wait/_trywait already maintain
// a SEPARATE SimSemaphore registry (bionic_shim.cpp, keyed by guest
// address, file-local/static) that this TU cannot reach without either a
// parallel (and UNSAFE -- see below) registry or a one-line export from
// bionic_shim.cpp. Per the boss's instructions, that diff is reported
// rather than made (see docs/arm32-shim-bulk-bridge_2026-07-28.md) rather
// than either (a) touching bionic_shim.cpp, or (b) inventing a SECOND,
// disjoint semaphore registry that would silently desynchronize from the
// real one the instant an app mixes sem_init/sem_post (existing shims) with
// sem_timedwait (a parallel implementation) on the SAME guest sem_t* --
// exactly the kind of silent-corruption bug this whole audit exists to stop.
//
// Instead: sem_timedwait is built by POLLING the existing, already-correct
// __macapk_shim_sem_trywait (which DOES touch the real registry) at a 1ms
// interval until it succeeds or the deadline passes. This is a genuine,
// correct composition (not a stub) -- coarser-grained than a real
// futex/condvar wait, but behaviorally faithful, and it can never
// desynchronize from sem_init/post/wait's state since it calls through the
// exact same entry point they do.
//
// struct timespec layout: Bionic ARM32 is `{int32_t tv_sec; int32_t
// tv_nsec}` (8 bytes) -- this is not a fresh derivation, it is the SAME
// layout this file's own clock_gettime/nanosleep shims already use and
// document ("Bionic 32-bit ts is {int32_t tv_sec; int32_t tv_nsec}"),
// reused here for consistency rather than re-fetched.
// ---------------------------------------------------------------------------
uint32_t __macapk_shim_sem_timedwait(uint32_t sem_addr, uint32_t abstime_addr,
                                     uint32_t, uint32_t) {
    if (!sem_addr) { errno = 22; return static_cast<uint32_t>(-1); }  // EINVAL
    if (!abstime_addr) {
        // No deadline given is technically invalid per POSIX; degrade to a
        // single trywait attempt through the real registry rather than
        // blocking forever from a shim with no timeout to honor.
        return __macapk_shim_sem_trywait(sem_addr, 0, 0, 0);
    }
    int32_t sec = 0, nsec = 0;
    std::memcpy(&sec,  gptr(abstime_addr),     sizeof(sec));
    std::memcpy(&nsec, gptr(abstime_addr + 4), sizeof(nsec));
    for (;;) {
        uint32_t r = __macapk_shim_sem_trywait(sem_addr, 0, 0, 0);
        if (r == 0) return 0;
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);   // sem_timedwait is
                                                // CLOCK_REALTIME-based (POSIX)
        if (now.tv_sec > sec || (now.tv_sec == sec && now.tv_nsec >= nsec)) {
            errno = 110;   // ETIMEDOUT (Bionic/Linux value; Darwin's is 60)
            return static_cast<uint32_t>(-1);
        }
        usleep(1000);   // 1ms poll tick
    }
}

// ---------------------------------------------------------------------------
// Section 8: pthread_getattr_np -- FRESH ARM32-specific implementation, NOT
// a bridge to the Stage-6 twin.
//
// The Stage-6 twin reports the CALLING THREAD'S REAL HOST STACK bounds
// (pthread_get_stackaddr_np/pthread_get_stacksize_np) -- correct there
// because Stage-6 IS the host thread executing real arm64 instructions. On
// the ARM32 tier this would be SEMANTICALLY WRONG: lifted ARM32 code's own
// `[sp, #imm]` loads/stores address a DEDICATED per-thread GUEST STACK
// ARENA slot (kThreadStackBase..+kMaxThreads*kThreadStackSlot, allocated by
// the already-exported __macapk_alloc_thread_stack -- see bionic_shim.cpp
// "Thread stack region"), completely separate from the real host call stack
// the compiled arm64 lifted-function bodies use for their OWN C++ frames.
// A conservative GC (bdwgc/Boehm, the documented real-world caller per the
// twin's own comment) that walks [stack_base, stack_base+stack_size)
// looking for guest-heap-shaped root pointers needs the GUEST ARENA range,
// not the host range -- reporting the host range would make the scan look
// at memory that never holds a guest value at all.
//
// Real Bionic ARM32 pthread_attr_t (fetched this session,
// bionic/libc/include/bits/pthread_types.h, ILP32 branch -- NOTE: no
// __reserved[16] tail, unlike the LP64 branch the Stage-6 twin mirrors):
//   typedef struct {
//     uint32_t flags;          // +0
//     void*    stack_base;     // +4  (4 bytes on ILP32 -- a GUEST vaddr here)
//     size_t   stack_size;     // +8
//     size_t   guard_size;     // +12
//     int32_t  sched_policy;   // +16
//     int32_t  sched_priority; // +20
//   } pthread_attr_t;                                        // 24 bytes
//
// Self-thread detection: bridges to the already-exported
// __macapk_shim_pthread_self (which hashes the host pthread_t down to a
// uint32 token) rather than reimplementing that hash -- if the guest's
// `thread` argument doesn't match "my own" token, there is no way to reach
// ANOTHER thread's slot index from this TU (t_thread_slot_idx is
// thread_local and file-private to bionic_shim.cpp), so that case is a
// loud, honest ESRCH rather than a fabricated range. This mirrors
// sched_getparam/getscheduler's OWN degrade path for an unresolvable pid.
// ---------------------------------------------------------------------------
namespace {
struct Arm32PthreadAttr {
    uint32_t flags;
    uint32_t stack_base;
    uint32_t stack_size;
    uint32_t guard_size;
    int32_t  sched_policy;
    int32_t  sched_priority;
};
static_assert(sizeof(Arm32PthreadAttr) == 24,
              "ARM32 Bionic pthread_attr_t is 24 bytes (no __reserved tail)");
// Mirrors bionic_shim.cpp's own kThreadStackSlot (its "Thread stack region"
// section: "constexpr uint32_t kThreadStackSlot = 0x00100000; // 1 MiB per
// thread"). Duplicated here (see file banner) rather than exported, since
// it is a compile-time constant with no linkable symbol to declare extern.
constexpr uint32_t kArm32ThreadStackSlot = 0x00100000;
// Matches __macapk_alloc_thread_stack's own "-16 safety margin" (its
// comment: "Top-of-stack: top of the slot, minus a 16-byte safety margin").
constexpr uint32_t kArm32ThreadStackTopMargin = 16;
}  // namespace

uint32_t __macapk_shim_pthread_getattr_np(uint32_t thread, uint32_t attr_addr,
                                          uint32_t, uint32_t) {
    if (!attr_addr) return 22;   // EINVAL
    uint32_t self_token = __macapk_shim_pthread_self(0, 0, 0, 0);
    if (thread != 0 && thread != self_token) {
        static std::atomic<int> logged{0};
        if (logged.fetch_add(1, std::memory_order_relaxed) == 0) {
            std::fprintf(stderr,
                "[bionic-shim-arm32] pthread_getattr_np: cross-thread query "
                "(thread=0x%x, self=0x%x) not supported on the ARM32 tier "
                "yet (the per-thread guest-stack-slot registry is "
                "thread_local + file-private to bionic_shim.cpp) -- "
                "returning ESRCH, logged once\n", thread, self_token);
        }
        return 3;   // ESRCH
    }
    // Self case: this call happens ON the thread being asked about (a shim
    // call IS that guest thread's own lifted code calling out), so
    // __macapk_alloc_thread_stack() returns exactly the right slot.
    uint32_t top = __macapk_alloc_thread_stack();
    uint32_t base = top + kArm32ThreadStackTopMargin - kArm32ThreadStackSlot;
    auto* a = reinterpret_cast<Arm32PthreadAttr*>(gptr(attr_addr));
    a->flags          = 0;
    a->stack_base     = base;
    a->stack_size     = kArm32ThreadStackSlot;
    a->guard_size     = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));
    a->sched_policy   = 0;
    a->sched_priority = 0;
    return 0;
}

}  // extern "C" (this file's own shims)

// =============================================================================
// _Znaj -- CORRECTED v1.0.833. This block previously said "NO SHIM NEEDED.
// Verified, not merely assumed", on the grounds that elf_reader.cpp rewrites
// EVERY operator-new import to the canonical "_Znwj" before resolution. That
// reading covered only one branch of the code.
//
// The rewrite (elf_reader.cpp:388-394) is inside the `else if` arm that
// handles a .rel.plt JUMP_SLOT naming a DEFINED-LOCAL symbol -- an
// intra-module PIC call. Genuine UNDEFINED imports take the other path and
// keep their own names, so a guest that imports `_Znaj` from outside really
// does arrive here as "_Znaj".
//
// Caught by measurement rather than by reading: running the translator over
// the ARM32 fleet, Bouncy's libgdx-box2d.so reported `_Znaj` resolving
// NOWHERE (3 bl sites) -> panic stub -> every `new[]` returning NULL.
// __macapk_shim__Znaj (plus _Znam/_Znwm/_ZdaPv) now live in bionic_shim.cpp
// next to _Znwj/_ZdlPv.
//
// The general lesson, worth more than the fix: "grep found the rewrite" is
// not the same as "the rewrite is reachable on this path".
// =============================================================================
