// regmap.h -- guest ARM32 register  ->  host Apple-arm64 register map
// for the direct recompiler ("arm32rc").
//
// The LLVM lifter could afford to be sloppy here: it emitted a
// per-function `alloca [16 x i32]` virtual register file and let
// mem2reg / SROA / the register allocator turn it into real registers.
// The direct recompiler has NO optimizer behind it, so whatever this
// file says is literally what the CPU executes. A guest register that
// is not pinned costs a load and a store on every instruction that
// touches it.
//
// Rationale, citations and the full prologue / epilogue listings live
// in docs/arm32-recompiler-design_2026-07-25.md. The short version of
// the central idea:
//
//     AAPCS32 callee-saved guest registers are mapped onto AAPCS64
//     callee-saved host registers, and AAPCS32 caller-saved guest
//     registers onto AAPCS64 caller-saved host registers.
//
// so guest preservation rules are enforced by the host ABI for free,
// including across calls into clang-compiled shim code.
//
// C++17. No em dashes (project convention).

#ifndef MACAPK_ARM32RC_REGMAP_H
#define MACAPK_ARM32RC_REGMAP_H

#include <cstdint>

#include "guest_state.h"

namespace macapk::arm32rc {

// =====================================================================
// Host register names
// =====================================================================
//
// Encoding value == the 5-bit register field in an AArch64 instruction,
// so an emitter can cast straight to the encoding. Register 31 is SP or
// XZR depending on the instruction form, which is why both names exist
// with the same numeric value.

enum class HostGpr : uint8_t {
    X0 = 0,  X1,  X2,  X3,  X4,  X5,  X6,  X7,
    X8,      X9,  X10, X11, X12, X13, X14, X15,
    X16,     X17, X18, X19, X20, X21, X22, X23,
    X24,     X25, X26, X27, X28, X29, X30,
    ZR   = 31,
    SP   = 31,
    kNone = 0xff,
};

enum class HostVec : uint8_t {
    V0 = 0,  V1,  V2,  V3,  V4,  V5,  V6,  V7,
    V8,      V9,  V10, V11, V12, V13, V14, V15,
    V16,     V17, V18, V19, V20, V21, V22, V23,
    V24,     V25, V26, V27, V28, V29, V30, V31,
    kNone = 0xff,
};

constexpr uint8_t enc(HostGpr r) { return static_cast<uint8_t>(r); }
constexpr uint8_t enc(HostVec r) { return static_cast<uint8_t>(r); }

// =====================================================================
// Reserved host registers
// =====================================================================

// x18. Apple, "Writing ARM64 code for Apple platforms", section
// "Respect the purpose of specific CPU registers":
//     "The platforms reserve register x18. Don't use this register."
//
// This project has fought x18 for months on the STAGE 6 path, where the
// guest's own arm64 bytes use x18 as a scratch register and have to be
// statically rewritten at load time (see
// docs/x18-scan-redundancy-crash-rate-ab_2026-07-24.md: turning the scan
// off is a 100% deterministic crash for Among Us, so the kernel
// preserve_x18 entitlement does NOT make the rewrite redundant).
//
// The ARM32 recompiler is IMMUNE to that entire bug class by
// construction, because WE choose every host register and simply never
// choose x18. That immunity is a design property worth protecting: the
// static_assert at the bottom of this header fails the build if any
// mapping ever lands on x18.
constexpr HostGpr kHostReservedPlatform = HostGpr::X18;

// x29 / x30. Apple, same page:
//     "The frame pointer register (x29) must always address a valid
//      frame record."
// Maintaining the frame chain is not optional for us for a second
// reason: the project's crash triage leans on `sample <pid>` and on
// macOS .ips DiagnosticReports backtraces (see the macapk-re skill).
// Recompiled frames only appear in those backtraces if x29 chains.
constexpr HostGpr kHostFramePointer = HostGpr::X29;
constexpr HostGpr kHostLinkRegister = HostGpr::X30;

// x16 / x17. AAPCS64 Table 2 calls these IP0 and IP1, "intra-procedure-
// call temporary register (can be used by call veneers and PLT code)".
// A long-range branch veneer inserted by the linker will clobber them,
// so they are usable as scratch ONLY inside a window with no call and
// no branch that could be veneered.
constexpr HostGpr kHostIp0 = HostGpr::X16;
constexpr HostGpr kHostIp1 = HostGpr::X17;

// x28 holds the base of the 4 GiB guest memory arena
// (__macapk_get_guest_base()). Pinned because EVERY guest load and
// store needs it: with the base in a register, a guest address becomes
// a host pointer in one instruction, `add xT, x28, wA, uxtw`.
// x28 is AAPCS64 callee-saved, so it survives every shim call untouched.
constexpr HostGpr kHostGuestBase = HostGpr::X28;

// Size of that arena, mirroring `kGuestMemSize` in
// runtime/translator/src/bionic_shim.cpp (allocate_guest_memory). It is
// stated here because it is LOAD-BEARING for the addressing mode, not
// merely informative: `[X28, Waddr, UXTW]` can reach exactly the byte
// range [base, base + 2^32), so the fold is in-bounds by construction
// only while the arena spans the WHOLE 32-bit space. Shrink it and every
// single-instruction guest access becomes a potential escape. See THE
// 2^32 WRAP INVARIANT in xlat_mem.h, where that is static_asserted.
constexpr uint64_t kGuestArenaBytes = 1ull << 32;

// =====================================================================
// The guest GPR map
// =====================================================================
//
//   guest        host    why
//   -----        ----    ---------------------------------------------
//   r0 - r3      x0-x3   AAPCS32 argument/result registers land on the
//                        AAPCS64 argument/result registers, so a guest
//                        BL to a recompiled function or to a
//                        __macapk_shim_* needs ZERO argument shuffling,
//                        and the guest r0 result is already the host
//                        return register.
//   r4 - r11     x19-x26 AAPCS32 variable (callee-saved) registers land
//                        on AAPCS64 callee-saved registers. Preserved
//                        across a call automatically, including by
//                        clang-compiled shims.
//   r12 (IP)     x9      AAPCS32 "intra-procedure-call scratch" lands
//                        on an AAPCS64 caller-saved register, so a call
//                        clobbering it is CORRECT.
//   r13 (SP)     x27     Callee-saved on both sides. Holds a 32-bit
//                        GUEST vaddr, zero-extended. It is NOT the host
//                        stack pointer; see below.
//   r14 (LR)     x10     Caller-saved on both sides; a guest BL
//                        overwrites it, which a host bl mirrors.
//   r15 (PC)     none    Translate-time constant, materialized inline.
//                        See guest_state.h section 2.
//
// THE GUEST STACK IS DATA. Guest SP points into the guest memory arena;
// the host SP points at the real thread stack. They never alias and
// they have different alignment rules: AAPCS32 requires "SP mod 8 = 0"
// at a public interface, while Apple requires "The stack pointer on
// Apple platforms follows the ARM64 standard ABI and requires 16-byte
// alignment". Because guest pushes only ever move x27, the guest can
// never break the host's 16-byte invariant. Any host SP adjustment the
// emitter makes must still be a multiple of 16.

constexpr HostGpr kGuestGprHome[kNumGuestGpr] = {
    /* r0  */ HostGpr::X0,
    /* r1  */ HostGpr::X1,
    /* r2  */ HostGpr::X2,
    /* r3  */ HostGpr::X3,
    /* r4  */ HostGpr::X19,
    /* r5  */ HostGpr::X20,
    /* r6  */ HostGpr::X21,
    /* r7  */ HostGpr::X22,
    /* r8  */ HostGpr::X23,
    /* r9  */ HostGpr::X24,
    /* r10 */ HostGpr::X25,
    /* r11 */ HostGpr::X26,
    /* r12 */ HostGpr::X9,
    /* r13 */ HostGpr::X27,
    /* r14 */ HostGpr::X10,
    /* r15 */ HostGpr::kNone,
};

constexpr HostGpr kHostGuestSp = kGuestGprHome[kSP];

// Host register for a guest GPR. Returns kNone only for r15.
constexpr HostGpr host_gpr_for_guest(int guest_reg) {
    return (guest_reg >= 0 && guest_reg < kNumGuestGpr)
             ? kGuestGprHome[guest_reg]
             : HostGpr::kNone;
}

// Reverse map, for tracing and for the disassembly comments the emitter
// writes next to each instruction. Returns -1 when the host register
// does not hold guest state.
int guest_for_host_gpr(HostGpr h);

// True when a guest register's home survives a host `bl` for free.
constexpr bool guest_gpr_survives_call(int guest_reg) {
    return guest_gpr_is_callee_saved(guest_reg);
}

// =====================================================================
// Scratch pools
// =====================================================================
//
// General scratch: caller-saved host registers not used for guest
// state. x4 additionally carries the incoming guest-SP argument, so it
// only joins the pool after the prologue has consumed it.
//
// NOT in the pool: x16 / x17 (veneer hazard, see above), x18
// (forbidden), x28 / x29 / x30 (reserved).
constexpr HostGpr kScratchGpr[] = {
    HostGpr::X4,  HostGpr::X5,  HostGpr::X6,  HostGpr::X7,
    HostGpr::X8,  HostGpr::X11, HostGpr::X12, HostGpr::X13,
    HostGpr::X14, HostGpr::X15,
};
constexpr int kNumScratchGpr = static_cast<int>(sizeof(kScratchGpr) / sizeof(kScratchGpr[0]));

// Vector scratch. v8-v15 are DELIBERATELY excluded: AAPCS64 makes only
// their low 64 bits callee-saved ("Only the bottom 64 bits of each
// value stored in v8-v15 need to be Callee-saved"), so touching them
// would force save/restore code in every prologue. Because the guest
// VFP bank is memory-homed in GuestState, we never need them.
constexpr HostVec kScratchVec[] = {
    HostVec::V0,  HostVec::V1,  HostVec::V2,  HostVec::V3,
    HostVec::V4,  HostVec::V5,  HostVec::V6,  HostVec::V7,
    HostVec::V16, HostVec::V17, HostVec::V18, HostVec::V19,
    HostVec::V20, HostVec::V21, HostVec::V22, HostVec::V23,
    HostVec::V24, HostVec::V25, HostVec::V26, HostVec::V27,
    HostVec::V28, HostVec::V29, HostVec::V30, HostVec::V31,
};
constexpr int kNumScratchVec = static_cast<int>(sizeof(kScratchVec) / sizeof(kScratchVec[0]));

// Classification helpers, implemented in regmap.cpp.
bool host_gpr_is_reserved(HostGpr h);        // x18 / x28 / x29 / x30
bool host_gpr_is_guest_home(HostGpr h);      // holds a pinned guest GPR
bool host_gpr_is_scratch(HostGpr h);         // in kScratchGpr
bool host_gpr_is_caller_saved(HostGpr h);    // clobbered by a host bl
bool host_vec_is_scratch(HostVec v);

// Tiny bitmask allocator for the per-instruction scratch registers an
// emitter needs. Deliberately NOT a register allocator: scratch never
// lives across an instruction boundary, so acquire / release always
// nest inside one guest instruction's lowering.
class ScratchSet {
  public:
    ScratchSet() = default;

    // Returns HostGpr::kNone when the pool is exhausted, which is a
    // translator bug rather than a runtime condition: no single ARM32
    // instruction needs ten scratch registers.
    HostGpr acquire();
    HostVec acquire_vec();
    void    release(HostGpr h);
    void    release(HostVec v);
    void    release_all();

    // Marks a register as unavailable for the rest of this
    // instruction's lowering, e.g. because it aliases an operand.
    void    reserve(HostGpr h);

  private:
    uint32_t gpr_taken_ = 0;   // bit i == kScratchGpr[i] is taken
    uint32_t vec_taken_ = 0;
};

// =====================================================================
// Frame layout
// =====================================================================
//
// Parity convention. Saves the ten callee-saved registers this design
// can touch, plus the frame record. 96 bytes keeps SP 16-byte aligned.
//
//     stp x29, x30, [sp, #-96]!
//     mov x29, sp                  ; Apple: x29 must address a valid
//     stp x19, x20, [sp, #16]      ;        frame record
//     stp x21, x22, [sp, #32]
//     stp x23, x24, [sp, #48]
//     stp x25, x26, [sp, #64]
//     stp x27, x28, [sp, #80]
//
// Pinned convention. Guest state is already live in the caller's
// registers, so a non-leaf body only needs the frame record:
//
//     stp x29, x30, [sp, #-16]!
//     mov x29, sp
//
// A leaf body (no call of any kind, and no host SP adjustment) may skip
// even that and spill into the red zone instead. Apple: "The ARM64 red
// zone consists of the 128 bytes immediately below the stack pointer",
// with the caveat that a recursive function must build a real frame.
constexpr int32_t kParityFrameSize = 96;
constexpr int32_t kParityOffFpLr   = 0;
constexpr int32_t kParityOffX19X20 = 16;
constexpr int32_t kParityOffX21X22 = 32;
constexpr int32_t kParityOffX23X24 = 48;
constexpr int32_t kParityOffX25X26 = 64;
constexpr int32_t kParityOffX27X28 = 80;

constexpr int32_t kPinnedFrameSize = 16;
constexpr int32_t kRedZoneBytes    = 128;

static_assert(kParityFrameSize % 16 == 0, "Apple arm64 requires SP mod 16 == 0");
static_assert(kPinnedFrameSize % 16 == 0, "Apple arm64 requires SP mod 16 == 0");

// Symbol naming. The AAPCS64-conforming entry keeps the existing
// `synth_<hex>` name so main.cpp's __macapk_target_<hex> aliasing, the
// in-image function-pointer LUT and every existing diagnostic keep
// working unchanged. Under the Pinned convention the entry becomes a
// thin wrapper around a second symbol carrying the same body with the
// pinned contract.
//   synth_<hex>          AAPCS64 conforming, callable from C
//   synth_<hex>$rcfast   pinned contract, callable only from
//                        recompiled code
const char* recompiled_entry_suffix();   // "" for the C-visible entry
const char* recompiled_fast_suffix();    // "$rcfast"

// =====================================================================
// Self-check
// =====================================================================
//
// Call once at translator start-up. Verifies the invariants that the
// static_asserts below cannot express (uniqueness of the map, agreement
// between the forward and reverse map, pool disjointness) and returns
// false with a diagnostic on stderr if any of them is violated.
bool regmap_self_test();

// Human-readable name, for the `; guest r4` style comments the emitter
// writes into its optional disassembly listing.
const char* host_gpr_name(HostGpr h);
const char* host_vec_name(HostVec v);
const char* guest_gpr_name(int guest_reg);

// =====================================================================
// Build-time invariants
// =====================================================================

namespace detail {
constexpr bool map_avoids(HostGpr forbidden) {
    for (int i = 0; i < kNumGuestGpr; ++i)
        if (kGuestGprHome[i] == forbidden) return false;
    return true;
}
constexpr bool roles_agree() {
    // Every AAPCS32 callee-saved guest register must land on an AAPCS64
    // callee-saved host register (x19-x28), and every caller-saved one
    // must NOT. This is the property the whole design rests on.
    for (int i = 0; i < kNumGuestGpr; ++i) {
        if (kGuestGprHome[i] == HostGpr::kNone) continue;
        const uint8_t h = static_cast<uint8_t>(kGuestGprHome[i]);
        const bool host_callee_saved = (h >= 19 && h <= 28);
        if (guest_gpr_is_callee_saved(i) != host_callee_saved) return false;
    }
    return true;
}
constexpr bool map_is_injective() {
    for (int i = 0; i < kNumGuestGpr; ++i) {
        if (kGuestGprHome[i] == HostGpr::kNone) continue;
        for (int j = i + 1; j < kNumGuestGpr; ++j)
            if (kGuestGprHome[i] == kGuestGprHome[j]) return false;
    }
    return true;
}
constexpr bool scratch_is_disjoint() {
    for (int s = 0; s < kNumScratchGpr; ++s) {
        if (kScratchGpr[s] == kHostGuestBase)     return false;
        if (kScratchGpr[s] == kHostFramePointer)  return false;
        if (kScratchGpr[s] == kHostLinkRegister)  return false;
        if (kScratchGpr[s] == kHostReservedPlatform) return false;
        if (kScratchGpr[s] == kHostIp0 || kScratchGpr[s] == kHostIp1) return false;
        for (int i = 0; i < kNumGuestGpr; ++i)
            if (kGuestGprHome[i] == kScratchGpr[s]) return false;
    }
    return true;
}
}  // namespace detail

// The x18 guard. If a future edit ever maps a guest register onto x18,
// the build fails here rather than the app crashing on a thread that
// happened not to run macapk_enable_x18_preservation().
static_assert(detail::map_avoids(HostGpr::X18),
              "x18 is platform-reserved on Apple arm64 and must never hold guest state");
static_assert(detail::map_avoids(HostGpr::X28),
              "x28 holds the guest memory base");
static_assert(detail::map_avoids(HostGpr::X29),
              "x29 is the frame pointer and must address a valid frame record");
static_assert(detail::map_avoids(HostGpr::X30),
              "x30 is the host link register");
static_assert(detail::map_avoids(HostGpr::X16) && detail::map_avoids(HostGpr::X17),
              "x16/x17 are IP0/IP1 and may be clobbered by linker veneers");
static_assert(detail::roles_agree(),
              "AAPCS32 and AAPCS64 preservation classes must line up");
static_assert(detail::map_is_injective(),
              "two guest registers may not share a host register");
static_assert(detail::scratch_is_disjoint(),
              "the scratch pool overlaps a pinned or reserved register");
static_assert(kGuestGprHome[kR0] == HostGpr::X0 && kGuestGprHome[kR1] == HostGpr::X1 &&
              kGuestGprHome[kR2] == HostGpr::X2 && kGuestGprHome[kR3] == HostGpr::X3,
              "r0-r3 must sit on x0-x3 so guest and host argument passing coincide");

}  // namespace macapk::arm32rc

#endif  // MACAPK_ARM32RC_REGMAP_H
