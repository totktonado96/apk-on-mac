// bionic_shim_signal.cpp -- ARM32-lifted-path infrastructure for two
// genuinely MISSING subsystems, not per-app shims:
//
//   1. dl_unwind_find_exidx -- lets libgcc/libunwind find the
//      .ARM.exidx table for the loaded image containing a given PC.
//      Without it, ARM32 C++ throw/catch cannot work at all. Smash
//      Hit and others hit this (16+ unresolved-call sites).
//   2. signal()/sigaction() -- registration bookkeeping for POSIX
//      signal handlers, engineered so that an ARM32 guest's raw
//      32-bit code address for a handler is NEVER handed to the host
//      kernel as a real function pointer (today, with no shim for
//      either name, that is exactly what happens: main.cpp's
//      resolve_import() finds a real `signal`/`sigaction` symbol via
//      dlsym(RTLD_DEFAULT) in the TRANSLATOR process -- both are
//      always present via libSystem -- and binds the guest import
//      RAW to it. See docs/arm32-signal-unwind_2026-07-28.md for the
//      full trace of that bug).
//
// Full citations, the Bionic-vs-Darwin layout tables, what is
// implemented for real vs. deliberately left LOUD-but-unimplemented,
// and the exact diffs needed in elf_reader.cpp / main.cpp /
// arm32rc_driver.cpp to wire the exidx registration through, all live
// in docs/arm32-signal-unwind_2026-07-28.md. Read that before touching
// this file.
//
// Ownership note (2026-07-28 multi-lane session): bionic_shim.cpp and
// bionic_shim_arm32.cpp are owned by other concurrent lanes and are
// NOT touched by this file. This TU is fully self-contained except for
// one blessed cross-TU call, __macapk_get_guest_base(), which every
// translated dylib's constructor already calls (see
// arm32rc_driver.cpp's module-constructor emission) and which
// bionic_shim.cpp exports with C linkage today -- that is the ONLY
// dependency this file takes on the other TU. Small helpers (gptr and
// friends) are DELIBERATELY DUPLICATED here rather than shared via a
// new header, per this session's lane-ownership split: bionic_shim.cpp
// is being actively edited by another lane and a shared-header
// refactor mid-flight would be a collision hazard for no benefit (both
// copies call the same __macapk_get_guest_base() accessor, so they
// cannot disagree on the arena base itself).
//
// C++17. No em dashes (project convention).

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#include <signal.h>   // host (Darwin) sigaction/sigemptyset/SIG*/SA_*

// Exported by bionic_shim.cpp (see that file's allocate_guest_memory /
// g_guest_base). This is a stable, already-load-bearing entry point --
// every translated ARM32 dylib's module constructor calls it (see
// arm32rc_driver.cpp: `call("__macapk_get_guest_base");`) -- so
// depending on it here does not create any new coupling beyond what
// already exists fleet-wide.
extern "C" void* __macapk_get_guest_base(void);

namespace {

// ---- guest pointer helpers (deliberate duplicate of bionic_shim.cpp's
// file-local `gptr`, ~line 10192; see the file header comment above for
// why this is not shared via a header in this session). ----------------
inline uint8_t* guest_base() {
    return static_cast<uint8_t*>(__macapk_get_guest_base());
}
inline void* gptr(uint32_t guest_addr) {
    uint8_t* base = guest_base();
    if (!base || !guest_addr) return nullptr;
    return base + guest_addr;
}
inline uint32_t read_u32(uint32_t guest_addr) {
    uint32_t v = 0;
    if (void* p = gptr(guest_addr)) std::memcpy(&v, p, sizeof(v));
    return v;
}
inline void write_u32(uint32_t guest_addr, uint32_t v) {
    if (void* p = gptr(guest_addr)) std::memcpy(p, &v, sizeof(v));
}

}  // namespace

// =====================================================================
// Part 1: dl_unwind_find_exidx
// =====================================================================
//
// Contract, verified verbatim from AOSP bionic (fetched 2026-07-28):
//
//   libc/include/link.h (linker/linker.h private twin has an
//   identically-shaped `do_dl_unwind_find_exidx`):
//     typedef uintptr_t _Unwind_Ptr;
//     _Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr, int* _Nonnull);
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/include/link.h
//
//   linker/linker.cpp (guarded #if defined(__arm__)):
//     // For a given PC, find the .so that it belongs to.
//     // Returns the base address of the .ARM.exidx section
//     // for that .so, and the number of 8-byte entries
//     // in that section (via *pcount).
//     //
//     // Intended to be called by libc's __gnu_Unwind_Find_exidx().
//     _Unwind_Ptr do_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
//       if (soinfo* si = find_containing_library((void*)pc)) {
//         *pcount = si->ARM_exidx_count;
//         return (_Unwind_Ptr)si->ARM_exidx;
//       }
//       *pcount = 0;
//       return 0;
//     }
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/linker/linker.cpp
//
//   linker/linker_phdr.cpp (how si->ARM_exidx / ARM_exidx_count are
//   populated ONCE per loaded solib, at load time, from the PT_ARM_EXIDX
//   program header):
//     int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table,
//                                   size_t phdr_count, ElfW(Addr) load_bias,
//                                   ElfW(Addr)** arm_exidx, size_t* arm_exidx_count) {
//       for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
//         if (phdr->p_type != PT_ARM_EXIDX) continue;
//         *arm_exidx = (ElfW(Addr)*)(load_bias + phdr->p_vaddr);
//         *arm_exidx_count = phdr->p_memsz / 8;
//         return 0;
//       }
//       *arm_exidx = nullptr; *arm_exidx_count = 0;
//       return -1;
//     }
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/linker/linker_phdr.cpp
//
//   linker.cpp find_containing_library (how "which .so" is decided --
//   a coarse [si->base, si->base+si->size) check, THEN a per-PT_LOAD
//   refinement using `vaddr = address - si->load_bias` against each
//   PT_LOAD's own [p_vaddr, p_vaddr+p_memsz)):
//     soinfo* find_containing_library(const void* p) {
//       ElfW(Addr) address = (ElfW(Addr))untag_address(p);
//       for (soinfo* si = solist_get_head(); si; si = si->next) {
//         if (address < si->base || address - si->base >= si->size) continue;
//         ElfW(Addr) vaddr = address - si->load_bias;
//         for (size_t i = 0; i != si->phnum; ++i) {
//           const ElfW(Phdr)* phdr = &si->phdr[i];
//           if (phdr->p_type != PT_LOAD) continue;
//           if (vaddr >= phdr->p_vaddr && vaddr < phdr->p_vaddr + phdr->p_memsz)
//             return si;
//         }
//       }
//       ...
//     }
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/linker/linker.cpp
//
// KEY FACTS this implementation rests on:
//   - `pc` is a real, already-relocated runtime address: what this
//     codebase's RAW-vs-BIASED terminology (docs/hard-fixes-catalog.md,
//     "RAW vs BIASED guest addresses") calls BIASED. Bionic's own
//     `find_containing_library` un-biases internally
//     (`vaddr = address - si->load_bias`) before comparing against the
//     ELF's own RAW PT_LOAD bounds -- so the per-segment ranges THIS
//     file registers are RAW, and lookup adds the load_bias back on,
//     mirroring that exactly (see ExidxRange below: biased_lo/hi are
//     precomputed once at registration time instead of un-biasing pc on
//     every lookup, which is equivalent and cheaper).
//   - The returned exidx base is ALSO biased (`load_bias + p_vaddr`).
//   - "count" is ENTRIES, not bytes: sh_size/8 (8 bytes per exidx
//     entry: a PREL31-encoded function offset + an inline/extab-
//     pointing word). elf_reader.cpp's own exidx parsing already uses
//     this exact division (see its "exidx VALIDATION set" block).
//   - Not-found returns 0 / *pcount=0. This file matches that exactly.
//   - Real Bionic sources the table from the PT_ARM_EXIDX PROGRAM
//     HEADER. Our translator (elf_reader.cpp) currently locates the
//     same bytes via the SHT_ARM_EXIDX SECTION header instead (see
//     elf_reader.cpp's existing `find_section(0x70000001u)` /
//     find_section_by_name(".ARM.exidx") calls, used today for
//     exidx_fn_starts discovery). For any conformant linker output the
//     section and the segment describe the identical bytes, so this is
//     an equivalent source, not a divergent one -- but see OPEN
//     QUESTIONS in the docs note for the stripped-section-headers edge
//     case where only the phdr survives.
//
// WHAT THIS FILE DOES vs. WHAT MUST BE PLUMBED FROM ELSEWHERE:
//   This file owns the RUNTIME registry (__macapk_register_exidx) and
//   the guest-facing shim (__macapk_shim_dl_unwind_find_exidx). It does
//   NOT read ELF files -- elf_reader.cpp already parses the exidx
//   section for its own purposes and needs two new Elf32Image fields
//   (exidx_raw_base / exidx_raw_count) plus arm32rc_driver.cpp's
//   module-constructor emission loop needs ONE more call alongside its
//   existing __macapk_register_segment call. See "PROPOSED DIFF" in
//   docs/arm32-signal-unwind_2026-07-28.md for the exact lines --
//   elf_reader.cpp and main.cpp are owned by another lane this session
//   and are not edited here.

namespace {

struct ExidxRange {
    uint32_t biased_lo = 0;          // seg_raw_lo + load_bias
    uint32_t biased_hi = 0;          // seg_raw_hi + load_bias
    uint32_t exidx_biased_base = 0;  // 0 if this image has no .ARM.exidx
    uint32_t exidx_count = 0;        // entries, not bytes
};

std::mutex g_exidx_mtx;
std::vector<ExidxRange> g_exidx_ranges;

}  // namespace

// Proposed call site: arm32rc_driver.cpp's module-constructor emission
// loop, once per PT_LOAD segment, immediately alongside the existing
// `__macapk_register_segment(seg.vaddr + opts.load_bias, ...)` call
// (see that loop over `img.loadable`). `seg_raw_lo`/`seg_raw_hi` are
// that SAME segment's RAW (pre-bias) [vaddr, vaddr+bytes.size()) --
// elf_reader.cpp already sizes CodeSegment::bytes to the full mapped
// extent (arm32rc_driver.cpp's existing register_segment call passes
// seg.bytes.size() for BOTH n_bytes and mem_size, confirming this).
// `exidx_raw_base`/`exidx_count` are the WHOLE IMAGE's .ARM.exidx
// bounds (the same two values, computed once, repeated for every
// segment of one image -- cheap, and keeps this a single call shape
// with no separate "once per image" bookkeeping in the emitter).
// `exidx_raw_base == 0` means "this image has no .ARM.exidx" (a
// stripped or -fno-unwind-tables build); callers should pass count 0
// too in that case, and this function will store 0 regardless.
extern "C" void __macapk_register_exidx(uint32_t load_bias,
                                         uint32_t seg_raw_lo,
                                         uint32_t seg_raw_hi,
                                         uint32_t exidx_raw_base,
                                         uint32_t exidx_count) {
    ExidxRange r;
    r.biased_lo = seg_raw_lo + load_bias;
    r.biased_hi = seg_raw_hi + load_bias;
    r.exidx_biased_base = exidx_raw_base ? (exidx_raw_base + load_bias) : 0;
    r.exidx_count = exidx_raw_base ? exidx_count : 0;
    std::lock_guard<std::mutex> g(g_exidx_mtx);
    g_exidx_ranges.push_back(r);
    if (std::getenv("MACAPK_TRACE_EXIDX")) {
        std::fprintf(stderr,
            "[exidx] register range=[0x%x,0x%x) load_bias=0x%x "
            "exidx_base=0x%x count=%u\n",
            r.biased_lo, r.biased_hi, load_bias, r.exidx_biased_base,
            r.exidx_count);
    }
}

// dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) -- see the file-
// header citation block above for the full contract. r0 = pc (a
// BIASED guest value, compared only, never dereferenced by us), r1 =
// pcount (a GUEST pointer -- the reason this name belongs in
// kPointerAwareImports despite pc itself being a plain value arg). 2
// real args, well under the 4-register AAPCS32 limit, so this does NOT
// need kPointerAwareWideImports.
extern "C" uint32_t __macapk_shim_dl_unwind_find_exidx(uint32_t pc,
                                                        uint32_t pcount_addr,
                                                        uint32_t /*r2*/,
                                                        uint32_t /*r3*/,
                                                        uint32_t /*sp*/) {
    uint32_t found_base = 0;
    uint32_t found_count = 0;
    {
        std::lock_guard<std::mutex> g(g_exidx_mtx);
        for (const ExidxRange& r : g_exidx_ranges) {
            if (pc >= r.biased_lo && pc < r.biased_hi) {
                found_base = r.exidx_biased_base;
                found_count = r.exidx_count;
                break;
            }
        }
    }
    if (pcount_addr) write_u32(pcount_addr, found_count);
    if (std::getenv("MACAPK_TRACE_EXIDX")) {
        static std::atomic<int> n{0};
        if (n.fetch_add(1) < 4096) {
            std::fprintf(stderr,
                "[exidx] dl_unwind_find_exidx(pc=0x%x) -> base=0x%x count=%u%s\n",
                pc, found_base, found_count,
                found_base ? "" : " (NOT FOUND)");
        }
    }
    return found_base;
}

// =====================================================================
// Part 2: signal() / sigaction() -- ARM32 (ILP32) Bionic ABI
// =====================================================================
//
// THE BUG THIS REPLACES: with no shim for either name, main.cpp's
// arm32rc resolve_import() callback checks kPointerAwareImports (does
// not contain "signal"/"sigaction"), then falls through to
// `dlsym(RTLD_DEFAULT, nm.c_str())` -- which succeeds, because the
// TRANSLATOR process itself links libSystem and always has a real
// `signal`/`sigaction` symbol. The guest import therefore binds
// straight to the HOST's signal()/sigaction(), and the guest's own
// 32-bit ARM code address for a handler gets stored as a literal
// function pointer in the HOST's real sigaction table. On real
// delivery, the host kernel would call that address as if it were a
// callable arm64 host function -- a wild jump, not a graceful no-op.
// Every function below exists so that NEITHER name ever reaches that
// bare dlsym/RTLD_DEFAULT fallback again.
//
// ---- Bionic ARM32 (ILP32) struct sigaction, verified byte-for-byte -
// AOSP libc/include/bits/signal_types.h (fetched verbatim 2026-07-28),
// the #else (ILP32) branch:
//
//   struct sigaction {
//     union {
//       sighandler_t sa_handler;
//       void (*sa_sigaction)(int, struct siginfo*, void*);
//     };
//     sigset_t sa_mask;
//     int sa_flags;
//     void (*sa_restorer)(void);
//   };
//
// and libc/kernel/uapi/asm-arm/asm/signal.h (the ARM-ARCH-SPECIFIC
// kernel uapi header -- this is the one that actually applies to
// __arm__ builds, NOT the generic asm-generic/signal.h's 2-word/8-byte
// sigset_t, which is a DIFFERENT, newer type for architectures/ABIs
// that route through the 64-signal-capable rt_* syscalls by default):
//
//   typedef unsigned long sigset_t;
//
// i.e. ARM32 sigset_t is ONE 4-byte word (confirmed independently by
// bits/signal_types.h's own comment: "the ILP32 sigset_t is only 32
// bits, so we need a 64-bit sigset64_t" for real-time-signal support).
// So on ARM32 every field of struct sigaction is exactly 4 bytes:
//   offset 0:  sa_handler / sa_sigaction (union, one slot)
//   offset 4:  sa_mask     (sigset_t, 4 bytes)
//   offset 8:  sa_flags    (int)
//   offset 12: sa_restorer (function pointer)
// Total 16 bytes. This matches the kernel's own raw
// `struct __kernel_sigaction` in the SAME arm asm/signal.h file
// (handler union, sigset_t sa_mask, unsigned long sa_flags,
// sa_restorer -- identical field order), so the two independent
// sources agree.
//
// Sources (fetched verbatim 2026-07-28):
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/include/bits/signal_types.h
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/kernel/uapi/asm-arm/asm/signal.h
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/kernel/uapi/asm-generic/signal-defs.h
//   https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/bionic/signal.cpp
// Darwin side read directly from this host's own SDK (more
// authoritative than any mirror for "what this binary actually runs
// against"):
//   /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/sys/signal.h
//
// Darwin struct sigaction (arm64 host, read verbatim from the header
// above):
//   struct sigaction {
//     union __sigaction_u __sigaction_u;  // 8 bytes (LP64 fnptr)
//     sigset_t sa_mask;                   // 4 bytes (__uint32_t)
//     int sa_flags;                       // 4 bytes
//   };                                     // = 16 bytes, no restorer field
//
// ---- Signal NUMBERS differ between Bionic/Linux and Darwin from 7
// onward -- THE load-bearing fact this file exists to get right ------
//   signal        Bionic/Linux (verified)   Darwin (verified, read
//                 asm-arm/asm/signal.h       directly from sys/signal.h)
//   SIGHUP            1                         1
//   SIGINT            2                         2
//   SIGQUIT           3                         3
//   SIGILL            4                         4
//   SIGTRAP           5                         5
//   SIGABRT           6                         6
//   SIGBUS            7                        10   <-- DIFFERS
//   SIGFPE            8                         8
//   SIGKILL           9                         9
//   SIGUSR1          10                        30   <-- DIFFERS
//   SIGSEGV          11                        11
//   SIGUSR2          12                        31   <-- DIFFERS
//   SIGPIPE          13                        13
//   SIGALRM          14                        14
//   SIGTERM          15                        15
//   SIGSTKFLT        16                     (none, Linux-only)
//   SIGCHLD          17                        20   <-- DIFFERS
//   SIGCONT          18                        19   <-- DIFFERS
//   SIGSTOP          19                        17   <-- DIFFERS
//   SIGTSTP          20                        18   <-- DIFFERS
//   SIGTTIN          21                        21
//   SIGTTOU          22                        22
//   SIGURG           23                        16   <-- DIFFERS
//   SIGXCPU          24                        24
//   SIGXFSZ          25                        25
//   SIGVTALRM        26                        26
//   SIGPROF          27                        27
//   SIGWINCH         28                        28
//   SIGIO/SIGPOLL    29                        23   <-- DIFFERS
//   SIGPWR           30                     (none, Linux-only)
//   SIGSYS           31                        12   <-- DIFFERS
// A raw passthrough of the signal NUMBER (not just the struct) is
// therefore wrong for 11 of these 31 signals. See "OBSERVATION" in
// docs/arm32-signal-unwind_2026-07-28.md: the EXISTING Stage-6 twin,
// __macapk_arm64_sigaction in bionic_shim.cpp, does not translate the
// incoming `sig` number at all before comparing it against host SIG*
// macros or calling the real host sigaction() -- for the 6 signals its
// own refusal list checks, only SIGBUS actually differs (7 vs 10),
// which is presumably why this has not yet surfaced as an observed
// failure. This file translates every signal number explicitly.
//
// ---- SA_* flag bits, verified against AOSP -------------------------
// libc/kernel/uapi/asm-generic/signal-defs.h (ARM32's own
// asm-arm/asm/signal.h #includes this for the SA_* bits; it overrides
// only SA_RESTORER/SA_THIRTYTWO, which are kernel/libc-syscall-internal
// and never touched by userspace sigaction() callers, so they are
// irrelevant here):
//   SA_NOCLDSTOP 0x00000001   SA_NOCLDWAIT 0x00000002
//   SA_SIGINFO   0x00000004   SA_ONSTACK   0x08000000
//   SA_RESTART   0x10000000   SA_NODEFER   0x40000000
//   SA_RESETHAND 0x80000000
// These values independently CROSS-CHECK against the existing Stage-6
// bionic_to_mac_sa_flags()/mac_to_bionic_sa_flags() in bionic_shim.cpp
// (same numbers, re-derived here from AOSP source rather than copied,
// per the file-local-duplicate convention this session uses).
//
// SIG_DFL/SIG_IGN/SIG_ERR are numerically 0/1/-1 on BOTH platforms
// (Bionic asm-generic/signal-defs.h: "#define SIG_DFL
// ((__sighandler_t) 0)" etc.; Darwin sys/signal.h: "#define SIG_DFL
// (void (*)(int))0" etc.) -- the only sentinels this file ever
// forwards to a real host sigaction() call (see do_sigaction below),
// so no translation table is needed for them, just shared constants.
//
// ---- What this file does NOT do, and why (read before extending) ---
// It does NOT deliver a real OS signal into recompiled/lifted ARM32
// guest code, for two compounding reasons:
//   1. The six signals Mac.apk's OWN runtime (bionic_shim.cpp's crash-
//      recovery net) and/or the embedded JVM already own -- SIGSEGV,
//      SIGBUS, SIGABRT, SIGFPE, SIGILL, SIGTRAP, matching the EXISTING
//      Stage-6 __macapk_arm64_sigaction refusal list exactly, so the
//      two tiers behave identically -- must not have their host
//      disposition touched at all. HotSpot relies on SIGSEGV/SIGILL
//      for implicit null-check/safepoint traps; bionic_shim.cpp's own
//      g_old_segv_sa/g_old_bus_sa/g_old_ill_sa/g_old_sys_sa chain is
//      the runtime's sigsetjmp-based crash-recovery net
//      (__macapk_invoke_safe). A guest handler that displaced either
//      would break the exact safety net the whole fleet depends on.
//   2. For every OTHER signal, actually CALLING a guest handler
//      requires a coherent virtual ARM32 register snapshot (r0-r12,
//      sp, lr, pc, cpsr) at the moment of an ASYNCHRONOUS interrupt --
//      which, unlike a synchronous fault (SEGV/ILL/etc. at a known
//      lifted instruction boundary), can land literally anywhere,
//      INCLUDING inside a real host library call made on the guest's
//      behalf via a __macapk_shim_<name> (e.g. mid-memcpy, mid-read()).
//      At that instant there is no "guest PC" to report at all -- the
//      host is transiently running real Darwin code with no
//      corresponding ARM32 program counter. The arm32rc recompiler
//      pins guest r0-r14 onto FIXED host registers during a lifted
//      function body (regmap.h/guest_state.h), which is promising for
//      the "interrupted inside recompiled guest code" case, but
//      solving the general case (any interruption point, including
//      inside a host library frame) needs either (a) a documented
//      "safe point" protocol the recompiler emits so a signal can only
//      ever be considered delivered at those points (deferred,
//      trampoline-style delivery), or (b) full register-pinning
//      knowledge threaded through the signal path -- neither exists
//      yet. Shipping a naive live trampoline now would recreate
//      exactly the "hand a wild address to the kernel" landmine this
//      file was written to remove, just one layer further in.
// Given that, sigaction()/signal() registrations ARE fully and
// correctly bookkept (oldact queries, repeated toggles, and the
// SIG_DFL/SIG_IGN dispositions are all faithfully honoured -- SIG_IGN
// specifically is wired to a REAL host sigaction() call when the
// signal is not one of the six protected ones, since no guest code is
// ever entered for SIG_DFL/SIG_IGN so none of the problems above
// apply). A real function-pointer handler on a non-protected signal is
// recorded (so the guest's own bookkeeping stays correct) and loudly
// logged as NOT wired to live delivery, once per signal, rather than
// silently pretending. This is the "refuse loudly rather than pretend"
// outcome the owning task brief explicitly sanctions when true
// delivery is not yet safe.

namespace {

// ---- Bionic ARM32 signal numbers (verified, see citation block
// above) -----------------------------------------------------------
enum BionicSig : int {
    kBIONIC_SIGHUP = 1,     kBIONIC_SIGINT = 2,     kBIONIC_SIGQUIT = 3,
    kBIONIC_SIGILL = 4,     kBIONIC_SIGTRAP = 5,    kBIONIC_SIGABRT = 6,
    kBIONIC_SIGBUS = 7,     kBIONIC_SIGFPE = 8,     kBIONIC_SIGKILL = 9,
    kBIONIC_SIGUSR1 = 10,   kBIONIC_SIGSEGV = 11,   kBIONIC_SIGUSR2 = 12,
    kBIONIC_SIGPIPE = 13,   kBIONIC_SIGALRM = 14,   kBIONIC_SIGTERM = 15,
    kBIONIC_SIGSTKFLT = 16, kBIONIC_SIGCHLD = 17,   kBIONIC_SIGCONT = 18,
    kBIONIC_SIGSTOP = 19,   kBIONIC_SIGTSTP = 20,   kBIONIC_SIGTTIN = 21,
    kBIONIC_SIGTTOU = 22,   kBIONIC_SIGURG = 23,    kBIONIC_SIGXCPU = 24,
    kBIONIC_SIGXFSZ = 25,   kBIONIC_SIGVTALRM = 26, kBIONIC_SIGPROF = 27,
    kBIONIC_SIGWINCH = 28,  kBIONIC_SIGIO = 29,     kBIONIC_SIGPWR = 30,
    kBIONIC_SIGSYS = 31,
    kBIONIC_NSIG = 32,
};

// Bionic(ARM32) signal number -> Darwin signal number, or 0 when there
// is no faithful Darwin equivalent (SIGSTKFLT/SIGPWR are Linux-only
// and have no BSD/Darwin analogue at all).
int bionic_to_darwin_signum(int b) {
    switch (b) {
        case kBIONIC_SIGHUP:    return SIGHUP;
        case kBIONIC_SIGINT:    return SIGINT;
        case kBIONIC_SIGQUIT:   return SIGQUIT;
        case kBIONIC_SIGILL:    return SIGILL;
        case kBIONIC_SIGTRAP:   return SIGTRAP;
        case kBIONIC_SIGABRT:   return SIGABRT;
        case kBIONIC_SIGBUS:    return SIGBUS;     // 7  -> 10
        case kBIONIC_SIGFPE:    return SIGFPE;
        case kBIONIC_SIGKILL:   return SIGKILL;
        case kBIONIC_SIGUSR1:   return SIGUSR1;    // 10 -> 30
        case kBIONIC_SIGSEGV:   return SIGSEGV;
        case kBIONIC_SIGUSR2:   return SIGUSR2;    // 12 -> 31
        case kBIONIC_SIGPIPE:   return SIGPIPE;
        case kBIONIC_SIGALRM:   return SIGALRM;
        case kBIONIC_SIGTERM:   return SIGTERM;
        case kBIONIC_SIGSTKFLT: return 0;          // no Darwin equivalent
        case kBIONIC_SIGCHLD:   return SIGCHLD;    // 17 -> 20
        case kBIONIC_SIGCONT:   return SIGCONT;    // 18 -> 19
        case kBIONIC_SIGSTOP:   return SIGSTOP;    // 19 -> 17
        case kBIONIC_SIGTSTP:   return SIGTSTP;    // 20 -> 18
        case kBIONIC_SIGTTIN:   return SIGTTIN;
        case kBIONIC_SIGTTOU:   return SIGTTOU;
        case kBIONIC_SIGURG:    return SIGURG;     // 23 -> 16
        case kBIONIC_SIGXCPU:   return SIGXCPU;
        case kBIONIC_SIGXFSZ:   return SIGXFSZ;
        case kBIONIC_SIGVTALRM: return SIGVTALRM;
        case kBIONIC_SIGPROF:   return SIGPROF;
        case kBIONIC_SIGWINCH:  return SIGWINCH;
        case kBIONIC_SIGIO:     return SIGIO;      // 29 -> 23
        case kBIONIC_SIGPWR:    return 0;          // no Darwin equivalent
        case kBIONIC_SIGSYS:    return SIGSYS;     // 31 -> 12
        default:                return 0;
    }
}

// Signals Mac.apk's own runtime (crash-recovery net) and/or the
// embedded JVM already own. Deliberately matches the existing Stage-6
// __macapk_arm64_sigaction refusal list in bionic_shim.cpp (grep
// "Runtime-owned fatal signals" there) so the two tiers agree from the
// app's point of view. Expressed in BIONIC numbering, checked BEFORE
// any Darwin translation -- see the "OBSERVATION" section in
// docs/arm32-signal-unwind_2026-07-28.md for why the Stage-6 twin
// checking in the OTHER order is a latent (if narrow) mismatch.
bool is_runtime_owned_signal(int bionic_sig) {
    switch (bionic_sig) {
        case kBIONIC_SIGSEGV:
        case kBIONIC_SIGBUS:
        case kBIONIC_SIGABRT:
        case kBIONIC_SIGFPE:
        case kBIONIC_SIGILL:
        case kBIONIC_SIGTRAP:
            return true;
        default:
            return false;
    }
}

bool keep_app_crashhandler() {
    // Same two kill-switches as the Stage-6 twin, honoured here too so
    // a diagnostic session can toggle both tiers consistently with one
    // env var.
    return std::getenv("MACAPK_KEEP_APP_CRASHHANDLER") != nullptr ||
           std::getenv("MACAPK_UNITY_KEEP_CRASHHANDLER") != nullptr;
}

// ARM32 (ILP32) struct sigaction field offsets -- see the citation
// block above. All four fields are 4 bytes; total 16 bytes.
constexpr uint32_t kSaHandlerOff  = 0;
constexpr uint32_t kSaMaskOff     = 4;
constexpr uint32_t kSaFlagsOff    = 8;
constexpr uint32_t kSaRestorerOff = 12;

// Bionic SA_* flag bits (verified, see citation block above).
constexpr uint32_t kBionicSA_NOCLDSTOP = 0x00000001u;
constexpr uint32_t kBionicSA_NOCLDWAIT = 0x00000002u;
constexpr uint32_t kBionicSA_SIGINFO   = 0x00000004u;
constexpr uint32_t kBionicSA_ONSTACK   = 0x08000000u;
constexpr uint32_t kBionicSA_RESTART   = 0x10000000u;
constexpr uint32_t kBionicSA_NODEFER   = 0x40000000u;
constexpr uint32_t kBionicSA_RESETHAND = 0x80000000u;

// SIG_DFL/SIG_IGN/SIG_ERR: numerically identical sentinels on Bionic
// and Darwin (see citation block above), so no translation needed.
constexpr uint32_t kSIG_DFL = 0u;
constexpr uint32_t kSIG_IGN = 1u;
constexpr uint32_t kSIG_ERR = 0xffffffffu;

struct GuestSigEntry {
    bool     ever_set = false;    // false = "never touched; Bionic default"
    uint32_t handler  = kSIG_DFL; // guest code addr, or SIG_DFL/SIG_IGN
    uint32_t mask     = 0;        // raw Bionic-numbered bit-per-signal
                                   // (bit N-1 = signal N); see Part 3.
                                   // Never forwarded to the real host
                                   // kernel (see do_sigaction), so this
                                   // only has to be self-consistent
                                   // with Part 3's reader/writer, not
                                   // bit-identical to Darwin's sigset_t.
    uint32_t flags    = 0;        // raw Bionic sa_flags
    uint32_t restorer = 0;        // opaque passthrough, never interpreted
};

std::mutex g_sig_mtx;
std::array<GuestSigEntry, kBIONIC_NSIG> g_sig_table;  // index 1..31 used

// Shared install/query core for both __macapk_shim_sigaction and
// __macapk_shim_signal, so the two can never disagree. Returns 0 on
// success, -1 with errno set to a Bionic-compatible value on failure
// (readable back by the guest via the ALREADY-shimmed __errno()).
int do_sigaction(int bionic_sig, const GuestSigEntry* new_entry,
                  GuestSigEntry* out_old) {
    if (bionic_sig <= 0 || bionic_sig >= kBIONIC_NSIG) {
        errno = EINVAL;
        return -1;
    }
    if (new_entry && (bionic_sig == kBIONIC_SIGKILL ||
                       bionic_sig == kBIONIC_SIGSTOP)) {
        errno = EINVAL;  // uncatchable on every POSIX kernel; match it.
        return -1;
    }

    std::lock_guard<std::mutex> g(g_sig_mtx);
    GuestSigEntry& cur = g_sig_table[static_cast<size_t>(bionic_sig)];
    if (out_old) *out_old = cur;

    if (!new_entry) return 0;  // pure query (act == NULL)

    cur = *new_entry;
    cur.ever_set = true;

    if (is_runtime_owned_signal(bionic_sig) && !keep_app_crashhandler()) {
        // Recorded above so oldact/query semantics stay faithful; the
        // HOST disposition is deliberately left untouched -- see the
        // Part 2 header comment's "what this file does NOT do" section.
        static std::atomic<int> logged{0};
        if (logged.fetch_add(1) < 16) {
            std::fprintf(stderr,
                "[arm32-sig] guest sigaction(sig=%d) recorded but NOT wired "
                "to the host: this signal is owned by Mac.apk's own "
                "crash-recovery net / the embedded JVM (see "
                "docs/arm32-signal-unwind_2026-07-28.md). Set "
                "MACAPK_KEEP_APP_CRASHHANDLER=1 to override for diagnostics "
                "(may break the runtime's own recovery net).\n",
                bionic_sig);
        }
        return 0;
    }

    const int darwin_sig = bionic_to_darwin_signum(bionic_sig);
    if (darwin_sig == 0) {
        static std::atomic<int> logged{0};
        if (logged.fetch_add(1) < 16) {
            std::fprintf(stderr,
                "[arm32-sig] guest sigaction(sig=%d) recorded but NOT wired: "
                "no Darwin equivalent exists for this Linux-only signal.\n",
                bionic_sig);
        }
        return 0;
    }

    if (new_entry->handler == kSIG_DFL || new_entry->handler == kSIG_IGN) {
        // The one disposition that is genuinely safe to apply for
        // real: no guest code is ever entered, so none of the
        // "which virtual register snapshot" problems in the Part 2
        // header comment apply. Applied with an EMPTY host mask --
        // sa_mask only matters while a real handler runs, and none
        // does here.
        struct sigaction host_sa {};
        host_sa.sa_handler = reinterpret_cast<void (*)(int)>(
            static_cast<intptr_t>(new_entry->handler));
        host_sa.sa_flags = 0;
        sigemptyset(&host_sa.sa_mask);
        struct sigaction host_old {};
        int rc = ::sigaction(darwin_sig, &host_sa, &host_old);
        if (rc != 0) {
            static std::atomic<int> logged{0};
            if (logged.fetch_add(1) < 16) {
                std::fprintf(stderr,
                    "[arm32-sig] host sigaction(darwin_sig=%d) for guest "
                    "sig=%d (SIG_DFL/SIG_IGN) failed: errno=%d\n",
                    darwin_sig, bionic_sig, errno);
            }
        }
        return 0;
    }

    // A real guest function-pointer handler on a signal Mac.apk does
    // NOT already own. Registration is recorded (above) so the guest's
    // own bookkeeping (repeated sigaction() calls, oldact queries)
    // stays faithful, but delivery-into-guest-code is deliberately NOT
    // wired up -- see the Part 2 header comment's "what this file does
    // NOT do, and why" section for the full reasoning. The guest sees
    // a successful registration (matching Bionic's own sigaction()
    // return contract exactly), which is honest about the ABI/protocol
    // but not about whether the handler will ever actually run.
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1) < 16) {
        std::fprintf(stderr,
            "[arm32-sig] guest sigaction(sig=%d, handler=0x%x) recorded but "
            "NOT delivered: async delivery into recompiled ARM32 guest code "
            "is not implemented (see docs/arm32-signal-unwind_2026-07-28.md, "
            "\"what this file does NOT do\"). The registration itself is "
            "correct; the handler will not run on a real signal.\n",
            bionic_sig, new_entry->handler);
    }
    return 0;
}

}  // namespace

// sigaction(int sig, const struct sigaction* act, struct sigaction* oldact)
// r0=sig, r1=act (guest ptr or 0), r2=oldact (guest ptr or 0). 3 real
// args; well under the kPointerAwareWideImports threshold.
extern "C" uint32_t __macapk_shim_sigaction(uint32_t sig, uint32_t act_addr,
                                             uint32_t oldact_addr,
                                             uint32_t /*r3*/,
                                             uint32_t /*sp*/) {
    GuestSigEntry new_entry;
    bool have_new = false;
    if (act_addr) {
        new_entry.handler  = read_u32(act_addr + kSaHandlerOff);
        new_entry.mask     = read_u32(act_addr + kSaMaskOff);
        new_entry.flags    = read_u32(act_addr + kSaFlagsOff);
        new_entry.restorer = read_u32(act_addr + kSaRestorerOff);
        have_new = true;
    }
    GuestSigEntry old_entry;
    int rc = do_sigaction(static_cast<int>(sig),
                           have_new ? &new_entry : nullptr, &old_entry);
    if (rc == 0 && oldact_addr) {
        write_u32(oldact_addr + kSaHandlerOff,  old_entry.handler);
        write_u32(oldact_addr + kSaMaskOff,     old_entry.mask);
        write_u32(oldact_addr + kSaFlagsOff,    old_entry.flags);
        write_u32(oldact_addr + kSaRestorerOff, old_entry.restorer);
    }
    return static_cast<uint32_t>(rc);
}

// signal(int sig, sighandler_t handler) -> returns the OLD handler, or
// SIG_ERR. Mirrors Bionic's OWN signal.cpp exactly (fetched verbatim
// 2026-07-28,
// https://raw.githubusercontent.com/aosp-mirror/platform_bionic/main/libc/bionic/signal.cpp):
//
//   sighandler_t signal(int sig, sighandler_t handler) {
//     return _signal(sig, handler, SA_RESTART);
//   }
//   __LIBC_HIDDEN__ sighandler_t _signal(int sig, sighandler_t handler,
//                                         int flags) {
//     struct sigaction64 sa = { .sa_handler = handler, .sa_flags = flags };
//     return (sigaction64(sig, &sa, &sa) == -1) ? SIG_ERR : sa.sa_handler;
//   }
//
// i.e. flags=SA_RESTART, mask=EMPTY, and the return value is whatever
// handler was installed BEFORE this call. Routed through the SAME
// do_sigaction() used by __macapk_shim_sigaction so the two can never
// disagree (Bionic's own signal() is sigaction64-based internally, but
// that is a libc implementation detail invisible to the guest: the
// guest's compiled code imports the SYMBOL "signal", which is exactly
// what this shim answers).
extern "C" uint32_t __macapk_shim_signal(uint32_t sig, uint32_t handler,
                                          uint32_t /*r2*/, uint32_t /*r3*/,
                                          uint32_t /*sp*/) {
    GuestSigEntry new_entry;
    new_entry.handler  = handler;
    new_entry.mask     = 0;
    new_entry.flags    = kBionicSA_RESTART;
    new_entry.restorer = 0;
    GuestSigEntry old_entry;
    int rc = do_sigaction(static_cast<int>(sig), &new_entry, &old_entry);
    if (rc != 0) return kSIG_ERR;
    return old_entry.ever_set ? old_entry.handler : kSIG_DFL;
}

// =====================================================================
// Part 3: sigemptyset/sigfillset/sigaddset/sigdelset/sigismember
// =====================================================================
//
// Direct support infrastructure for sigaction(): a guest that builds
// its sa_mask via these before calling sigaction() would otherwise ALSO
// hit the exact same "unlisted import binds RAW to a host function
// that dereferences a guest pointer" bug (the generic
// kPointerAwareImports gap, not a signal-specific one) -- these five
// all take a `sigset_t*` that is a 32-bit guest vaddr, and none of them
// are shimmed today.
//
// Bit convention: bit (signo-1) of the 32-bit guest sigset_t represents
// signal `signo` (valid range 1..31). This file NEVER forwards these
// bits to the real host kernel (do_sigaction only ever installs
// SIG_DFL/SIG_IGN for real, and those need no mask -- see Part 2's
// header comment), so this convention only has to be self-consistent
// with the reader/writer below, not bit-identical to what Darwin's own
// sigset_t layout would imply.
namespace {
constexpr uint32_t kSigfillsetValue = 0x7fffffffu;  // bits for signals 1..31
}  // namespace

extern "C" uint32_t __macapk_shim_sigemptyset(uint32_t set_addr, uint32_t,
                                               uint32_t, uint32_t, uint32_t) {
    if (!set_addr) { errno = EINVAL; return kSIG_ERR; }
    write_u32(set_addr, 0);
    return 0;
}
extern "C" uint32_t __macapk_shim_sigfillset(uint32_t set_addr, uint32_t,
                                              uint32_t, uint32_t, uint32_t) {
    if (!set_addr) { errno = EINVAL; return kSIG_ERR; }
    write_u32(set_addr, kSigfillsetValue);
    return 0;
}
extern "C" uint32_t __macapk_shim_sigaddset(uint32_t set_addr, uint32_t signo,
                                             uint32_t, uint32_t, uint32_t) {
    if (!set_addr || signo < 1 || signo >= kBIONIC_NSIG) {
        errno = EINVAL;
        return kSIG_ERR;
    }
    uint32_t v = read_u32(set_addr);
    v |= (1u << (signo - 1));
    write_u32(set_addr, v);
    return 0;
}
extern "C" uint32_t __macapk_shim_sigdelset(uint32_t set_addr, uint32_t signo,
                                             uint32_t, uint32_t, uint32_t) {
    if (!set_addr || signo < 1 || signo >= kBIONIC_NSIG) {
        errno = EINVAL;
        return kSIG_ERR;
    }
    uint32_t v = read_u32(set_addr);
    v &= ~(1u << (signo - 1));
    write_u32(set_addr, v);
    return 0;
}
extern "C" uint32_t __macapk_shim_sigismember(uint32_t set_addr, uint32_t signo,
                                              uint32_t, uint32_t, uint32_t) {
    if (!set_addr || signo < 1 || signo >= kBIONIC_NSIG) {
        errno = EINVAL;
        return kSIG_ERR;
    }
    uint32_t v = read_u32(set_addr);
    return (v & (1u << (signo - 1))) ? 1u : 0u;
}
