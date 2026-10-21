// arm32_discovery.h -- the OUTPUT TYPE of ARM32 function discovery.
//
// WHY THIS EXISTS (read before changing the shape):
//
// `Arm32Lifter::lifted_address_map()` currently means TWO different things
// at once: "discovery found a function at this address" AND "a body was
// emitted for this address". Those diverge for exactly the addresses that
// main.cpp special-cases, and there are 91 of them in HCR 1.8.1:
//
//     69  ARM long-call veneers
//     15  exception-runtime overrides (__cxa_throw, __cxa_rethrow,
//         _Unwind_*, _ZSt9terminatev, __gnu_Unwind_*)
//      3  __cxa_guard_acquire / _release / _abort
//      2  __aeabi_idiv0 / __aeabi_ldiv0
//      2  pure-thrower helpers
//      1  __dynamic_cast        1  fullPathFromRelativePath
//      1  CCImage::_initWithPngData
//
// Since 2026-09-26 three of those are bisect arms only: fullPathFromRelativePath
// (MACAPK_COCOS_OWN_FULLPATH=0), __dynamic_cast
// (MACAPK_ARM32_GUEST_DYNAMIC_CAST=0) and the pure-thrower helpers
// (MACAPK_ARM32_THROW_HELPERS_RUN=0). By default the guest's own body is
// translated for each, as a device runs it. The census above is the ORIGINAL
// one; HCR 1.8.1's --emit-discovery sidecar from the 2026-09-27 tree has 86
// non-Translate rows by default (69 Veneer, 16 OverrideShim = 12 exception
// runtime + 3 __cxa_guard + _initWithPngData, 1 OverrideConst __aeabi_ldiv0)
// and 87 with MACAPK_ARM32_GUEST_DYNAMIC_CAST=0.
//
// Each of those calls `register_lifted_function(addr, name)` and then
// CONTINUES without lifting, because the incumbent substitutes a host shim
// for the guest's real body. A consumer that sees only "this address is a
// function" therefore translates the guest bytes where the incumbent
// replaces them. That is not a style problem: the guest `__cxa_throw` run
// on the host unwinder is a SIGABRT or an infinite self-recursion, and the
// guest guard path never fires `pthread_mutex_lock` so every cocos
// singleton's vptr stays unwritten. 410 call sites in HCR. (The guest
// `__dynamic_cast` used to be listed as returning garbage non-NULL so
// cocos2d-x skipped `onEnter`. That was the deleted LLVM lifter; arm32rc's
// translation of it matches the guest bytes on an ARMv7 CPU exactly,
// measured 2026-09-26, so it is translated by default now.)
//
// Worse, it silently invalidates MEASUREMENT: an A/B between the two
// pipelines that does not carry disposition is comparing two different
// programs, which is how "HCR renders 0 frames on the recompiler" became
// an uninterpretable result.
//
// So discovery gets a real output type, and the emitter behind it becomes
// swappable. This is deliberately NOT a refactor of arm32_lifter.cpp: that
// file stays exactly as it is and simply stops being the only description
// of what discovery decided. See docs/arm32rc-integration_2026-07-25.md.
//
// OWNERSHIP: this header is the contract between the producer
// (runtime/translator/src/main.cpp) and the consumers (the arm32rc driver,
// and in time the LLVM emitter). Neither side may change it unilaterally.
//
// C++17. No em dashes (project convention).

#ifndef MACAPK_TRANSLATOR_ARM32_DISCOVERY_H_
#define MACAPK_TRANSLATOR_ARM32_DISCOVERY_H_

#include <cstdint>
#include <string>
#include <vector>

namespace macapk::translator {

// What discovery decided should happen at this address.
enum class Disposition : uint8_t {
    // Translate the guest bytes normally. The common case.
    Translate,

    // Do NOT translate. Emit a body that forwards to `override_symbol`,
    // a host symbol with the same (r0,r1,r2,r3,guest_sp) -> r0 shape.
    // Covers the exception runtime, the __cxa_guard family, __dynamic_cast
    // (bisect arm only, MACAPK_ARM32_GUEST_DYNAMIC_CAST=0),
    // fullPathFromRelativePath (bisect arm only, MACAPK_COCOS_OWN_FULLPATH=0)
    // and _initWithPngData.
    OverrideShim,

    // Do NOT translate. Emit a body that returns `override_const`.
    // Covers __aeabi_idiv0 / __aeabi_ldiv0 (INT_MAX, because ARM raises
    // SIGFPE where the host SDIV quietly returns 0) and the pure-thrower
    // helpers (0, because the generic siglongjmp would unwind PAST the
    // caller's post-throw fall-through).
    OverrideConst,

    // Do NOT translate. An ARM long-call veneer: dispatch indirectly to
    // `veneer_target`, which discovery has already seeded as its own
    // function. 69 of these in HCR, all variant B (`bx r12`).
    Veneer,
};

struct DiscoveredFunction {
    uint32_t    vaddr = 0;        // guest entry, bit 0 already cleared
    uint32_t    size = 0;         // bytes to decode; see the note below
    bool        is_thumb = false;
    std::string symbol;           // e.g. "__macapk_synth_0001a2b4"

    Disposition disposition = Disposition::Translate;
    std::string override_symbol;  // OverrideShim
    int32_t     override_const = 0;   // OverrideConst
    uint32_t    veneer_target = 0;    // Veneer, guest vaddr

    // True when `symbol` is a JNI entry point (Java_* or JNI_OnLoad). The
    // consumer must then export an AAPCS64 thunk under `symbol` and the
    // recompiled body under "__macapk_arm32_" + symbol.
    bool        is_jni_export = false;

    // `size` MUST come from the incumbent's `next_real_function_start`
    // rule, which walks PAST bogus intervening starts (the v1.0.57 fix),
    // and MUST be clipped to the containing SECTION end, not the PT_LOAD
    // end. Getting either wrong is not cosmetic:
    //   - raw next-start gave 21 Jetpack Joyride functions a 2-byte size,
    //     so cs_disasm returned 0 and the driver dropped them entirely,
    //     sending every caller to the panic helper;
    //   - PT_LOAD clipping made the LAST function swallow 351 KB of
    //     .rodata, which the translator then decoded as ARM and EMITTED
    //     (87,751 phantom instructions, ~1 MB of output, and 86.8% of the
    //     apparent "unsupported instruction" histogram).
};

}  // namespace macapk::translator

#endif  // MACAPK_TRANSLATOR_ARM32_DISCOVERY_H_
