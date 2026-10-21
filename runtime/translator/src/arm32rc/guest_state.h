// guest_state.h -- the ARM32 guest machine-state model for the direct
// ARM32 -> arm64 recompiler ("arm32rc").
//
// This header is the SINGLE SOURCE OF TRUTH for what "the guest CPU"
// is, where each piece of it lives at run time, and which host
// instruction sequence is allowed to touch it. Every other arm32rc
// translation unit (ALU lowering, memory lowering, branch lowering,
// the Mach-O emitter) must agree with this file or the produced code
// is silently wrong.
//
// Companion documents (read both before changing anything here):
//   docs/arm32-recompiler-design_2026-07-25.md   -- the WHY, with citations
//   runtime/translator/src/arm32rc/regmap.h      -- the host register map
//
// Terminology used throughout:
//   guest vaddr  = a 32-bit address as the ARM32 ELF sees it
//   host pointer = a 64-bit darwin pointer = guest_base + guest vaddr
//   pinned       = permanently resident in a host register
//   homed        = permanently resident in GuestState memory
//
// C++17. No em dashes (project convention).

#ifndef MACAPK_ARM32RC_GUEST_STATE_H
#define MACAPK_ARM32RC_GUEST_STATE_H

#include <cstddef>
#include <cstdint>

namespace macapk::arm32rc {

// =====================================================================
// 1. Guest register numbering
// =====================================================================
//
// Index order matches arm32_lifter.cpp's arm_reg_idx() exactly (r0..r12,
// then SP=13, LR=14, PC=15) so the two translators can share discovery
// data, traces and test vectors without a translation table.

enum GuestGpr : int {
    kR0 = 0,  kR1,  kR2,  kR3,  kR4,  kR5,  kR6,  kR7,
    kR8,      kR9,  kR10, kR11, kR12,
    kSP  = 13,   // r13
    kLR  = 14,   // r14
    kPC  = 15,   // r15
    kNumGuestGpr = 16,
};

// AAPCS32 role of each core register. Source: Arm "Procedure Call
// Standard for the Arm Architecture" (AAPCS32), Table "Core registers
// and AAPCS usage": r0-r3 "Argument / result / scratch register";
// r4-r8, r10, r11 variable registers (callee-saved); r9 "Platform
// register or Variable-register 6" (Android/Linux EABI treats it as a
// plain variable register); r12 "Intra-Procedure-call scratch
// register"; r13 "The Stack Pointer"; r14 "The Link Register"; r15
// "The Program Counter".
//
// This is load-bearing for the register map: a guest register that is
// callee-saved under AAPCS32 is given a host register that is
// callee-saved under AAPCS64, so preservation across a call is free
// and automatic (including across a call into a clang-compiled shim).
enum class GuestGprRole : uint8_t {
    ArgResultScratch,  // r0-r3   -- caller-saved
    Variable,          // r4-r11  -- callee-saved
    IntraProcScratch,  // r12     -- caller-saved
    StackPointer,      // r13     -- callee-saved
    LinkRegister,      // r14     -- caller-saved (clobbered by BL)
    ProgramCounter,    // r15     -- never lives in a register; see below
};

constexpr GuestGprRole guest_gpr_role(int r) {
    return (r <= kR3)  ? GuestGprRole::ArgResultScratch
         : (r <= kR11) ? GuestGprRole::Variable
         : (r == kR12) ? GuestGprRole::IntraProcScratch
         : (r == kSP)  ? GuestGprRole::StackPointer
         : (r == kLR)  ? GuestGprRole::LinkRegister
                       : GuestGprRole::ProgramCounter;
}

// True when the register must survive a guest BL per AAPCS32.
constexpr bool guest_gpr_is_callee_saved(int r) {
    return (r >= kR4 && r <= kR11) || r == kSP;
}

// =====================================================================
// 2. R15 / PC is never a register
// =====================================================================
//
// The recompiler is ahead-of-time, so every instruction's PC is a
// translate-time constant. R15 is therefore materialized inline as an
// immediate, never stored.
//
// ARM ARM (Arm A32/T32 Instruction Set Architecture, "Pseudocode
// description of operations on the AArch32 general-purpose registers
// and the PC"): a read of R15 returns the address of the current
// instruction plus 8 in A32 state and plus 4 in T32 state. A
// PC-relative literal load additionally word-aligns that value
// (Align(PC, 4)).
//
// WARNING (carried over from the LLVM lifter, v1.0.520 / v1.0.521):
// the aligned-vs-unaligned choice for a data-processing SOURCE read of
// R15 is NOT uniform across NDK eras. GD Lite's cocos2d-x PIC needs the
// ALIGNED value; HCR's libxml2 PIC needs the UNALIGNED value, from the
// same instruction form. arm32_lifter.cpp discriminates per PIC
// sequence (it looks for the `ldr rN, [pc, #imm]; add rN, pc` pair).
// That discrimination MUST be ported; a blanket rule regressed both
// apps. See arm32_lifter.cpp:find_pc_literal_for().

constexpr uint32_t guest_pc_value(uint32_t insn_vaddr, bool thumb) {
    return insn_vaddr + (thumb ? 4u : 8u);
}
constexpr uint32_t guest_pc_literal_base(uint32_t insn_vaddr, bool thumb) {
    return guest_pc_value(insn_vaddr, thumb) & ~3u;
}

// =====================================================================
// 3. Instruction set state (A32 / T32) and interworking
// =====================================================================
//
// Because we recompile ahead of time, a guest function is decoded in
// exactly one instruction set; mode is a static property of the
// function, not dynamic state. The only place mode matters at run time
// is an INDIRECT branch, where the low bit of the target selects it.
//
// ARM ARM, aarch32/functions/registers/BXWritePC:
//     BXWritePC(bits(32) address_in, BranchType branch_type)
//         bits(32) address = address_in;
//         if address<0> == '1' then
//              SelectInstrSet(InstrSet_T32);
//              address<0> = '0';
//         else
//              SelectInstrSet(InstrSet_A32);
//              ...
//
// Consequence for the dispatcher: a guest function POINTER carries the
// Thumb bit, so every vaddr used as a branch/call target must be masked
// with ~1 before it is looked up, and the Thumb bit must be re-applied
// when a function address is materialized as DATA (so that guest code
// which stores a pointer and later BXes it round-trips correctly).

enum class InstrSet : uint8_t { A32 = 0, T32 = 1 };

constexpr uint32_t guest_code_ptr(uint32_t vaddr, InstrSet set) {
    return (vaddr & ~1u) | (set == InstrSet::T32 ? 1u : 0u);
}
constexpr uint32_t guest_branch_target(uint32_t ptr) { return ptr & ~1u; }
constexpr InstrSet guest_branch_mode(uint32_t ptr) {
    return (ptr & 1u) ? InstrSet::T32 : InstrSet::A32;
}

// =====================================================================
// 4. Condition flags
// =====================================================================
//
// Bit positions are deliberately chosen to match the AArch64 NZCV
// system register, so a packed guest flag word can be installed with a
// bare `msr NZCV, x` and read back with `mrs x, NZCV` -- no shuffling.

constexpr uint32_t kFlagN = 1u << 31;
constexpr uint32_t kFlagZ = 1u << 30;
constexpr uint32_t kFlagC = 1u << 29;
constexpr uint32_t kFlagV = 1u << 28;
constexpr uint32_t kFlagNZ   = kFlagN | kFlagZ;
constexpr uint32_t kFlagCV   = kFlagC | kFlagV;
constexpr uint32_t kFlagNZCV = kFlagNZ | kFlagCV;

// How an ARM32 instruction updates APSR.{N,Z,C,V}. The lowering agent
// selects a code sequence purely from this enum; see
// docs/arm32-recompiler-design_2026-07-25.md section "Flag lowering
// cookbook" for the exact instruction sequence per policy.
//
// Every value below is pinned to ARM ARM pseudocode; the citation is in
// the comment. Do not add a value without one.
enum class FlagPolicy : uint8_t {
    // No S suffix / no flag write at all.
    kNone = 0,

    // ADDS / SUBS / RSBS / ADCS / SBCS / RSCS / CMP / CMN / NEGS.
    // ARM ARM: `(result, nzcv) = AddWithCarry(R[n], NOT(imm32), '1');
    //           PSTATE.<N,Z,C,V> = nzcv;`  (SUB, SUBS (immediate))
    // AddWithCarry lives in shared/functions/integer/AddWithCarry, i.e.
    // it is SHARED between AArch32 and AArch64, so the host's
    // adds/subs/adcs/sbcs/cmp/cmn produce bit-identical N, Z, C and V
    // (including "C = NOT borrow" on subtract). Lowering is 1:1 with
    // ZERO overhead, and this is the single most common flag producer.
    kArithNZCV,

    // ANDS / ORRS / EORS / BICS / ORNS / TST / TEQ / MVNS / MOVS and the
    // shift aliases LSLS / LSRS / ASRS / RORS / RRXS, in the forms where
    // the second operand carries NO shifter carry-out (register with no
    // shift, or an immediate whose expansion left the carry alone).
    // ARM ARM AND, ANDS (immediate):
    //           PSTATE.N = result<31>;
    //           PSTATE.Z = IsZeroBit(result);
    //           PSTATE.C = carry;            // == carry_in here
    //           // PSTATE.V unchanged
    // A64 ANDS is NOT a substitute: it force-clears C and V.
    kLogicNZ_CVKeep,

    // Same family, but the operand DID produce a shifter carry-out
    // (register with a shift, or a rotated immediate). N, Z from the
    // result; C from Shift_C / A32ExpandImm_C / T32ExpandImm_C; V
    // unchanged.
    // ARM ARM AND, ANDS (register):
    //           (shifted, carry) = Shift_C(R[m], shift_t, shift_n, PSTATE.C);
    //           ... PSTATE.C = carry;  // PSTATE.V unchanged
    kLogicNZ_CShift,

    // MULS / MLAS / and the other 32-bit multiply forms.
    // ARM ARM MUL, MULS:
    //           PSTATE.N = result<31>;
    //           PSTATE.Z = IsZeroBit(result<31:0>);
    //           // PSTATE.C, PSTATE.V unchanged
    kMulNZ,

    // SMULLS / UMULLS / SMLALS / UMLALS: N, Z from the 64-bit result,
    // C and V unchanged.
    kMulLongNZ,

    // VCMP / VCMPE. These write FPSCR.{N,Z,C,V}, a bank that is
    // SEPARATE from APSR. `VMRS APSR_nzcv, FPSCR` is what copies it
    // across. Keeping the two banks separate is load-bearing: a
    // predicated integer instruction sitting between a VCMP and its
    // VMRS must still see the INTEGER flags. cocos2d-x v2's
    // CCNode::nodeToParentTransform hits exactly this pattern and
    // breaks anchor-point handling for every CCLayer if the banks are
    // merged. (Same finding as arm32_lifter.cpp's fpscr_* allocas.)
    kFpcmpNZCV,

    // Parallel add/sub (SADD16 / UADD8 / SASX / ...): writes APSR.GE
    // per byte lane, leaves NZCV alone. Read back by SEL.
    kGeLanes,

    // QADD / QDADD / SSAT / USAT / SMLA*: sets the STICKY APSR.Q, never
    // clears it. Only MSR can clear Q.
    kQSticky,
};

// =====================================================================
// 5. GuestState -- everything that is NOT pinned in a host register
// =====================================================================
//
// Contents and rationale:
//
//   d[32]   The VFP / NEON bank. Homed in MEMORY rather than pinned in
//           host v-registers ON PURPOSE. ARM32 aliases three widths
//           over the same bits: s2n / s2n+1 are the low / high halves
//           of dn, and qn is the 128-bit pair (d2n, d2n+1). AArch64 has
//           no register whose two halves are two other architectural
//           registers, so any pinned mapping has to synthesize one of
//           the three views with ins/mov sequences and keep them
//           coherent. A contiguous little-endian array makes all three
//           views EXACT and FREE:
//                 s_n  == reinterpret_cast<uint32_t*>(d)[n]
//                 d_n  == d[n]
//                 q_n  == the 16 bytes at &d[2*n]
//           so `ldr q0, [xSTATE, #(16*n)]` loads exactly guest qn.
//           Cost: two loads plus a store per VFP op. Recovered later by
//           the OPTIONAL block-local cache described in the design doc
//           (cache d0..d31 in v0-v7 / v16-v31 inside one basic block;
//           flush before every call, every q-width access and every
//           block terminator).
//           A second, free benefit: a clang-compiled shim cannot
//           disturb the bank at all, so the guest's VFP state survives
//           every host call with no save/restore.
//
//   fpscr   Full FPSCR. Only NZCV (bits 31..28) and the rounding /
//           flush-to-zero control bits are modelled. VCMP writes here;
//           VMRS APSR_nzcv, FPSCR reads here.
//
//   nzcv    Spill home for APSR.{N,Z,C,V}. The LIVE copy normally sits
//           in the host's real PSTATE.NZCV (see the design doc); this
//           field is only written when the flags must survive something
//           that clobbers PSTATE (a call into a clang-compiled shim,
//           the fcmp inside a VCMP lowering, a host->guest boundary).
//
//   ge/q    APSR.GE[3:0] (bits 3..0 of apsr_ge) and the sticky APSR.Q.
//           Rare enough that memory homing costs nothing measurable.
//
//   r[16]   Spill home for the pinned GPRs. Not used on the fast path.
//           It exists so that (a) the host->guest boundary trampoline
//           has somewhere to marshal, (b) MACAPK_RC_TRACE can dump a
//           full register snapshot at an arbitrary instruction, and
//           (c) a future signal handler can present guest context.
//
//   magic   Tripwire. GuestState sits at the BOTTOM of the thread's
//           guest stack slot and the guest stack grows DOWN toward it,
//           so a guest stack overflow lands here first. A corrupted
//           magic is a far better diagnostic than silently scribbling
//           on the neighbouring thread's stack.
//
// The struct lives INSIDE guest memory (see section 6) so it is
// reachable from the two registers we already pin, with no third
// pinned register and no change to the shim layer.

struct alignas(16) GuestState {
    uint64_t d[32];             // +0x000 .. +0x0ff  VFP / NEON bank
    uint32_t fpscr;             // +0x100
    uint32_t nzcv;              // +0x104  packed APSR NZCV (kFlag* layout)
    uint32_t apsr_ge;           // +0x108  GE[3:0] in bits 3..0
    uint32_t apsr_q;            // +0x10c  sticky saturation flag
    uint32_t r[kNumGuestGpr];   // +0x110 .. +0x14f  GPR spill home
    uint32_t magic;             // +0x150  kGuestStateMagic
    uint32_t instr_set;         // +0x154  InstrSet of the running frame
    uint32_t trace_vaddr;       // +0x158  last translated vaddr (tracing)
    uint32_t reentry_depth;     // +0x15c  host->guest nesting level
    uint64_t scratch[8];        // +0x160 .. +0x19f  emitter spill slots
    uint64_t reserved[12];      // +0x1a0 .. +0x1ff  pad to 512 bytes
};

constexpr uint32_t kGuestStateMagic = 0x52433332u;   // "RC32" little-endian

// Compile-time offsets for the instruction emitter. NEVER hardcode a
// literal in an emitter; use these so a layout change is caught here.
constexpr uint32_t kOffD        = static_cast<uint32_t>(offsetof(GuestState, d));
constexpr uint32_t kOffFpscr    = static_cast<uint32_t>(offsetof(GuestState, fpscr));
constexpr uint32_t kOffNzcv     = static_cast<uint32_t>(offsetof(GuestState, nzcv));
constexpr uint32_t kOffApsrGe   = static_cast<uint32_t>(offsetof(GuestState, apsr_ge));
constexpr uint32_t kOffApsrQ    = static_cast<uint32_t>(offsetof(GuestState, apsr_q));
constexpr uint32_t kOffR        = static_cast<uint32_t>(offsetof(GuestState, r));
constexpr uint32_t kOffMagic    = static_cast<uint32_t>(offsetof(GuestState, magic));
constexpr uint32_t kOffInstrSet = static_cast<uint32_t>(offsetof(GuestState, instr_set));
constexpr uint32_t kOffTrace    = static_cast<uint32_t>(offsetof(GuestState, trace_vaddr));
constexpr uint32_t kOffScratch  = static_cast<uint32_t>(offsetof(GuestState, scratch));

// Byte offset of guest dN / sN / qN inside GuestState.
constexpr uint32_t guest_d_offset(int n) { return kOffD + 8u * static_cast<uint32_t>(n); }
constexpr uint32_t guest_s_offset(int n) { return kOffD + 4u * static_cast<uint32_t>(n); }
constexpr uint32_t guest_q_offset(int n) { return kOffD + 16u * static_cast<uint32_t>(n); }
constexpr uint32_t guest_r_offset(int n) { return kOffR + 4u * static_cast<uint32_t>(n); }

static_assert(sizeof(GuestState) == 512, "GuestState must stay 512 bytes");
static_assert(kOffD == 0, "d[] must start at offset 0 so q/d/s views alias exactly");
static_assert(kOffFpscr == 0x100, "GuestState layout drifted");
static_assert(kOffNzcv  == 0x104, "GuestState layout drifted");
static_assert(kOffR     == 0x110, "GuestState layout drifted");
// Every emitter offset must fit the unsigned-12-bit scaled immediate of
// the AArch64 LDR/STR forms so no scratch register is needed to reach a
// field. 512 bytes is comfortably inside the smallest (byte) form.
static_assert(sizeof(GuestState) <= 4096, "GuestState must stay ldr-immediate reachable");

// =====================================================================
// 6. Where GuestState lives, and how the emitter reaches it
// =====================================================================
//
// The shim already partitions guest memory into one 1 MiB stack slot
// per thread. The stack is handed out at the TOP of the slot and grows
// down, so the BOTTOM of the slot is unused address space that is
// already per-thread, already inside guest memory, and already
// allocated. GuestState goes there.
//
// That buys the property that makes the whole register map work: the
// state pointer is derivable from two registers we pin anyway, in two
// instructions and with no memory access:
//
//     and  w<tmp>, w<guestSP>, #0xfff00000     ; slot base (guest vaddr)
//     add  x<tmp>, x<guestBase>, x<tmp>        ; host pointer to GuestState
//
// 0xfff00000 is a valid AArch64 32-bit logical immediate (12 ones then
// 20 zeros), and the W-form AND zero-extends, so the ADD needs no UXTW.
//
// MIRRORED CONSTANTS. The three values below are copies of
// runtime/translator/src/bionic_shim.cpp's kThreadStackBase /
// kThreadStackSlot / kMaxThreads. They are duplicated rather than
// included because bionic_shim.cpp is a .cpp with no header. If the
// shim ever changes them, arm32rc_verify_stack_geometry() below must be
// called with the shim's live values at translator start-up so the
// mismatch is a loud failure instead of silent memory corruption.
constexpr uint32_t kThreadStackBase = 0x3E000000u;   // 992 MiB
constexpr uint32_t kThreadStackSlot = 0x00100000u;   // 1 MiB per thread
constexpr uint32_t kMaxThreads      = 32u;

// The bottom of each slot is reserved so a modest guest stack overflow
// hits GuestState (detectable via `magic`) instead of the neighbouring
// thread's live stack.
constexpr uint32_t kGuestStateReserve = 4096u;
constexpr uint32_t kSlotBaseMask      = ~(kThreadStackSlot - 1u);   // 0xfff00000

static_assert((kThreadStackBase & (kThreadStackSlot - 1u)) == 0,
              "kThreadStackBase must be slot-aligned or the AND trick is wrong");
static_assert(kGuestStateReserve >= sizeof(GuestState),
              "reserve must cover GuestState");

// Guest vaddr of the GuestState belonging to whichever thread owns `sp`.
constexpr uint32_t guest_state_vaddr_for_sp(uint32_t guest_sp) {
    return guest_sp & kSlotBaseMask;
}
constexpr uint32_t guest_state_vaddr_for_slot(uint32_t slot_idx) {
    return kThreadStackBase + slot_idx * kThreadStackSlot;
}

// Call once at translator start-up with the shim's live geometry.
// Returns false when the mirrored constants above have drifted.
bool arm32rc_verify_stack_geometry(uint32_t shim_stack_base,
                                   uint32_t shim_stack_slot,
                                   uint32_t shim_max_threads);

// =====================================================================
// 7. The host-visible entry signature
// =====================================================================
//
// Byte-for-byte the shape bionic_shim.cpp already uses:
//
//     using LiftedArmFn = int32_t(*)(uint32_t, uint32_t, uint32_t,
//                                    uint32_t, uint32_t);
//     int32_t __macapk_invoke_safe(LiftedArmFn fn, r0, r1, r2, r3, sp);
//     int32_t __macapk_indirect_call(target, r0, r1, r2, r3, sp, from);
//     uint32_t __macapk_shim_<name>(r0, r1, r2, r3, sp);
//
// so the recompiler drops in under the EXISTING shim, dispatcher and
// JNI-thunk layer with no change to bionic_shim.cpp.
//
// One deliberate widening: a recompiled function returns uint64_t
// carrying (guest r1 << 32) | guest r0. Existing C callers declare the
// return as int32_t and therefore read w0 == guest r0, which is exactly
// today's behaviour, so the change is binary compatible in both
// directions. What it buys is that AAPCS32's double-word return in
// r0:r1 finally works: `long long`, soft-float `double`, and
// __aeabi_idivmod (quotient in r0, remainder in r1) all round-trip
// without the soft_float_double_plt_ special case that
// arm32_lifter.cpp / main.cpp carry today.
using RecompiledFn = uint64_t (*)(uint32_t r0, uint32_t r1,
                                  uint32_t r2, uint32_t r3,
                                  uint32_t guest_sp);

constexpr uint64_t pack_return(uint32_t r0, uint32_t r1) {
    return (static_cast<uint64_t>(r1) << 32) | r0;
}
constexpr uint32_t return_r0(uint64_t v) { return static_cast<uint32_t>(v); }
constexpr uint32_t return_r1(uint64_t v) { return static_cast<uint32_t>(v >> 32); }

// =====================================================================
// 8. Calling convention selection
// =====================================================================
//
// Two conventions, both specified, staged in this order. See the design
// doc for the full prologue / epilogue listings.
//
//   Parity  Every recompiled function is a fully AAPCS64-conforming
//           host function: it saves and restores x19-x28, zeroes guest
//           r4-r11 on entry, and loads the guest base from a module
//           global. Semantics are IDENTICAL to today's LLVM lifter (a
//           fresh register file per function, r0-r3 in, r0 out, SP
//           threaded through the 5th argument), so a bring-up
//           regression can be bisected against the existing pipeline
//           one function at a time. Costs about 25 extra instructions
//           per call.
//
//   Pinned  Guest r4-r11 and the guest SP stay live in host
//           callee-saved registers ACROSS calls, so a recompiled ->
//           recompiled call needs no marshalling whatsoever and a
//           recompiled -> shim call needs one `mov w4, w<guestSP>`.
//           This is both faster and strictly MORE faithful than Parity:
//           on real ARM a callee does see the caller's r4-r11, whereas
//           the Parity model (and today's lifter) hands it zeroes.
//           Requires the dual-entry scheme in the design doc.
enum class Convention : uint8_t { kParity = 0, kPinned = 1 };

}  // namespace macapk::arm32rc

#endif  // MACAPK_ARM32RC_GUEST_STATE_H
