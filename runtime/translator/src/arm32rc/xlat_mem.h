// xlat_mem.h -- direct ARM32/Thumb -> arm64 recompiler: the MEMORY-ACCESS
// translation stage.
//
// Owns:
//   LDR / STR / LDRB / STRB / LDRH / STRH / LDRSB / LDRSH in every addressing
//   mode (immediate offset, register offset, scaled register offset,
//   pre-indexed, post-indexed, writeback) plus the unprivileged T-suffixed
//   twins; LDRD / STRD; LDM / STM in all four modes (IA / IB / DA / DB) with
//   writeback and the `^` user-mode-register form, and the PUSH / POP aliases;
//   the exclusive family (LDREX.. / STREX.. / LDAEX.. / STLEX..) and the
//   ordered LDA / STL; the barriers DMB / DSB / ISB / CLREX; the deprecated
//   SWP / SWPB; and the prefetch hints PLD / PLDW / PLI.
//
// It also hosts the small shared helpers that xlat_simd.cpp needs (effective
// address, predication guard, guest-state pointer, PC value), so there is
// exactly one implementation of each.
//
// =====================================================================
//  THE MEMORY MODEL
// =====================================================================
//
// regmap.h pins the guest-memory arena base in x28 (kHostGuestBase) and every
// guest GPR r0..r14 in a host register (kGuestGprHome); r15 is a translate-time
// constant. A guest 32-bit address therefore becomes a host access in ONE
// instruction, because A64's register-offset addressing mode can do the
// zero-extend for free:
//
//     LDR Wt, [X28, Waddr, UXTW]      // ARM ARM, LDR (register)
//
// so a typical `ldr r0, [r1, #8]` is two instructions (fold the displacement,
// then access) against the ~8 IR operations the LLVM lifter needed.
//
// Multi-register forms (LDM/STM/LDRD/STRD and the SIMD structure loads)
// materialise the host pointer once with
//
//     ADD Xp, X28, Waddr, UXTW
//
// and then use scaled immediate offsets, which is one host instruction per
// transferred register.
//
// =====================================================================
//  THE 2^32 WRAP INVARIANT (read before touching any addressing mode)
// =====================================================================
//
// NEVER FOLD TWO GUEST REGISTERS INTO ONE A64 ADDRESSING MODE. Flatten
// every guest term into ONE 32-bit W value first, then let exactly one
// UXTW do the extension. That is what `GuestAddrW` below encodes, and it
// is the reason this recompiler needs none of the recovery machinery its
// academic predecessor did.
//
// AArch32 address arithmetic WRAPS at 2^32; A64's does not. MAMBO-X64
// (Amanieu d'Antras et al., "Low Overhead Dynamic Binary Translation on
// ARM", PLDI 2017, section 3.3 "Speculative Address Generation") states
// the hazard exactly:
//
//     "For example, consider the instruction LDR R0, [R1, R2]: if R1 has
//      the value 0xffff0000 and R2 has the value 0x40000 then, on
//      AArch32, adding these two registers together in an address
//      calculation will wrap around the 32-bit address space and result
//      in the address 0x30000. Naively translating this instruction to
//      the closest AArch64 equivalent (LDR W0, [X1, X2]) will not
//      overflow the 64-bit address width and will instead result in the
//      address 0x100030000, which is outside the 32-bit address space."
//
// MAMBO-X64 pays a real price for that: it SPECULATES that the sum does
// not overflow, reserves the first 12 GB of virtual memory so a
// mis-speculation lands on reserved pages instead of live data, catches
// the SIGSEGV, blacklists the load, invalidates the fragment and
// re-translates it with a separate ADD. We need none of that, because we
// never speculate: `mem_effective_addr` and `plan_address` sum every
// guest term with W-form (sf == 0) ADD/SUB, which truncates to 32 bits
// by definition, and the single surviving W value is what gets folded.
// A wrapped guest address stays wrapped.
//
// WHY UXTW AND NOT MAMBO'S SXTW. MAMBO uses `LDR W0, [X1, W2, SXTW]`,
// and sign extension is right FOR THEM because their guest occupies host
// addresses 0 .. 4 GB directly (paper Figure 1), so X1 is a real guest
// base pointer and W2 is a signed offset from it. Our arena base is a
// PINNED NON-ZERO host pointer in x28 and the W we fold is the WHOLE
// guest address, not an offset within an object. SXTW of any guest
// address with bit 31 set (0x80000000 and up, which is ordinary ARM32
// user space) would subtract up to 2 GiB from the arena base and land
// outside it. UXTW is therefore not a preference, it is the only correct
// extension here. xlat_mem.cpp static_asserts both the extend constant
// and the arena span that makes the fold in-bounds.
//
// EVERY SITE THAT NAMES THE ARENA BASE, exhaustively (audited 2026-07-26;
// all single-fold, all UXTW):
//   xlat_mem.cpp  emit_host_ptr        ADD Xp, X28, Waddr, UXTW
//                 emit_guest_ldst      LDR/STR Wt, [X28, Waddr, UXTW]
//                 emit_guest_fp_ldst   LDR/STR St|Dt, [X28, Waddr, UXTW]
//                 emit_guest_state_ptr ADD Xp, X28, Xmasked (the mask is
//                                      a W-form AND, so it zero-extends)
//   xlat_core.cpp BufSink::load_guest_u32 / load_guest_zx /
//                 emit_guest_state_ptr_into -- the table-branch and
//                 GuestState paths, same shapes, commented at each site.
// Outside xlat_mem.cpp there is deliberately no way to NAME x28 from this
// header: `guest_base_reg()` is private to xlat_mem.cpp so that a raw
// `ldst_reg(..., guest_base_reg(), second_guest_reg, ...)` cannot be
// written. Adding a new arena-addressing emitter means adding a choke
// point here, which is where this comment will be read.
//
// `debug/arm32rc_wrap_invariant_test.sh` is the executable half of that
// claim: it tries to write the MAMBO mistake four different ways and
// fails the run if any of them still compiles (plus a control that must).
// It is -fsyntax-only, so it needs no applock and no build tree.
//
// THE ONE RESIDUAL, stated so it is not rediscovered as a surprise. The
// multi-word forms (LDRD/STRD, LDM/STM, VLDM/VSTM, the NEON structure
// loads) materialise ONE host pointer and then walk it with scaled
// immediate offsets, so the +0..+128 byte walk happens in the HOST
// 64-bit domain and does not wrap. A guest LDM whose first address is
// within 128 bytes of 0xffffffff would, on real ARM32, wrap to 0; here
// it walks past the end of the arena. This is the same corner MAMBO-X64
// handles for its immediate-offset form with a guard page ("By reserving
// a guard page at the end of the address space, MAMBO-X64 ensures that
// out-of-bounds accesses from immediate offset addressing will raise a
// SIGSEGV"), and the same fix applies: a PROT_NONE page after the arena
// in bionic_shim.cpp's allocate_guest_memory would turn a silent escape
// into a deterministic fault. Not done here because that file is not
// this one's to change. Doing it in the guest domain instead (one W-form
// ADD per transferred register) was rejected: it doubles the cost of the
// single hottest instruction family in ARM code (every prologue is a
// PUSH, every epilogue a POP) to cover a corner no Android mapping can
// reach, since Bionic never returns allocations near the top of the
// 32-bit space.
//
// UNALIGNED ACCESS. Android runs ARM32 userspace with SCTLR.A == 0 and
// SCTLR.U == 1, so LDR/STR/LDRH/STRH permit unaligned addresses (DDI 0406C.d
// A3.2.1). A64 permits the same for Normal memory, so the single-register
// accesses pass through with no fix-up. The forms that are NOT
// unaligned-tolerant on ARM32 (the exclusives, which require natural
// alignment) are equally intolerant on A64, so the fault behaviour matches
// for free. LDM / STM / LDRD / STRD are word-alignment-required on ARM32 and
// are lowered here to sequences of 32-bit accesses, which is strictly more
// permissive and can therefore never introduce a fault the guest would not
// have taken.
//
// CONDITION CODES. Per xlat_core.h assumption A3 the guest APSR.NZCV lives in
// the host PSTATE.NZCV between instructions. Everything this stage emits is a
// NON-flag-setting form (ADD/SUB, never ADDS/SUBS), so a predicated access can
// evaluate its condition against live guest flags. A predicated access is
// guarded by a real forward branch (`B.<inverse> skip`), reproducing DDI
// 0406C.d A8.3 exactly: a failed predicate performs NO memory access and NO
// base writeback, which is what makes `cmp r1,#0 ; ldrne r0,[r1]` safe when
// r1 is NULL. (The LLVM lifter had to reach the same conclusion the hard way;
// see arm32_lifter.cpp's pred_guard_begin comments.)
//
// PC AS AN OPERAND. `LDR Rt, [PC, #imm]` (compiler constant pools) reads PC as
// insn_addr + 8 in A32 and + 4 in T32, aligned DOWN to 4 for the literal forms
// (DDI 0406C.d A5.1.2). Reading PC as a plain data operand is NOT aligned
// down. Both rules are implemented here and match XlatCore::pc_value_for().
//
// No em dashes (project convention). C++17, -Wall -Wextra clean.

#ifndef MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_MEM_H_
#define MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_MEM_H_

#include <vector>
#include <capstone/capstone.h>

#include <cstdint>
#include <functional>
#include <string>

#include "a64_emit.h"
#include "guest_state.h"
#include "regmap.h"

namespace macapk {
namespace arm32rc {

// ---------------------------------------------------------------------
// Per-instruction translation context
// ---------------------------------------------------------------------
//
// Scratch policy. regmap.h's contract is that scratch registers never live
// across a guest-instruction boundary, so this stage simply names the ones it
// uses instead of running an allocator. The defaults are drawn from
// regmap.h's kScratchGpr / kScratchVec:
//
//   tmp[0..3]  x11, x12, x13, x14   (caller-saved, never a guest home,
//                                    never x16/x17 so no veneer hazard)
//   vtmp0..7   v0 .. v7             EIGHT CONSECUTIVE scratch vector
//                                    registers. Consecutive matters: A64's
//                                    LD3/LD4/ST3/ST4 structure forms can only
//                                    name consecutive V registers, and the
//                                    de-interleaving VLD3/VLD4 lowering in
//                                    xlat_simd.cpp depends on having four in
//                                    a row.
//
// A caller that wants different registers just overwrites the fields.
struct XlatMemCtx {
    a64::A64Buf* buf = nullptr;

    // Word offsets of `bl __macapk_trace_store` sites the module builder must
    // bind. Only populated when MACAPK_ARM32RC_TRACE_STORES is set at
    // translate time; null (and unused) otherwise.
    std::vector<uint32_t>* trace_store_sites = nullptr;

    // Guest vaddr and instruction set of the instruction being translated.
    uint32_t insn_addr = 0;
    bool is_thumb = false;
    // Per-image load bias applied to PC-derived absolute constants, matching
    // XlatCore::pc_value_for().
    uint32_t load_bias = 0;

    unsigned tmp[4] = {
        static_cast<unsigned>(HostGpr::X11), static_cast<unsigned>(HostGpr::X12),
        static_cast<unsigned>(HostGpr::X13), static_cast<unsigned>(HostGpr::X14),
    };
    // First of eight consecutive scratch vector registers.
    unsigned vtmp0 = static_cast<unsigned>(HostVec::V0);

    // Non-fatal diagnostics (a `^` LDM translated as the ordinary form, a
    // stubbed instruction). Optional.
    std::function<void(const std::string&)> warn;

    unsigned vtmp(unsigned i) const { return vtmp0 + i; }
};

struct XlatResult {
    bool handled = false;
    // Guest PC was written (LDR pc,[..] / POP {..,pc} / LDM {..,pc}). The new
    // guest PC is zero-extended in host register `pc_reg`; the driver must
    // consume it immediately as the first action of its dispatch sequence,
    // because `pc_reg` is a scratch register.
    bool wrote_pc = false;
    unsigned pc_reg = 0;
    // The PC write came off the guest stack, i.e. this is a function return
    // rather than a computed jump.
    bool is_return = false;
    // A CONDITIONAL PC write (`pop{cc} {..,pc}`, `ldr{cc} pc,[..]`) leaves its
    // "condition false, skip the body" label UNBOUND, and the driver must bind
    // it AFTER it has emitted the terminator.
    //
    // Binding it here, where the body ends, is wrong and silently so: the
    // driver appends the epilogue + `ret` (or a dispatch) immediately after,
    // so the condition-false path -- which must FALL THROUGH to the next guest
    // instruction -- lands on the terminator instead and leaves the function.
    //
    // That is not theoretical. `pop{hs} {r3,r4,r5,pc}` is the standard ARM
    // conditional return, and cocos2d-x's ccArrayEnsureExtraCapacity is
    //     cmp   r2, r3
    //     pophs {r3,r4,r5,pc}          @ big enough -> return
    //     ...call ccArrayDoubleCapacity @ too small -> grow
    // With the label bound early, "too small" returned instead of growing, so
    // the array NEVER resized and every subsequent ccArrayAppendObject wrote
    // one slot past its allocation. On the bump heap that walked straight into
    // the next live object and smashed a vptr -- which surfaced hundreds of
    // instructions later as an indirect call through a garbage vtable slot.
    // (HCR 1.8.1, 2026-07-28.)
    bool     has_pending_skip = false;
    a64::Label pending_skip{};
};

// ---------------------------------------------------------------------
// Shared helpers (xlat_simd.cpp uses all of these)
// ---------------------------------------------------------------------

// Capstone's arm_cc is 1-based over the A32 condition encodings, and the A32
// and A64 4-bit condition fields are identical (DDI 0406C.d Table A8-1 vs
// DDI 0487 Table C1-1), so the mapping is "subtract one".
a64::Cond cond_of(arm_cc cc);
bool cc_is_always(arm_cc cc);

// Capstone ARM register enum -> guest register number 0..15, or -1.
int arm_core_idx(unsigned reg);

// Host register holding guest core register `r`. Valid for r0..r14 only; r15
// has no home (regmap.h kGuestGprHome) and must go through pc_value().
inline unsigned host_reg(int r) {
    return static_cast<unsigned>(enc(host_gpr_for_guest(r)));
}

// ---------------------------------------------------------------------
// GuestAddrW -- a host W register holding a FULLY FLATTENED 32-bit guest
// address, i.e. every guest term already summed with W-form arithmetic so
// the value is correct MODULO 2^32.
// ---------------------------------------------------------------------
//
// This type exists so THE 2^32 WRAP INVARIANT above is checked by the
// compiler instead of by review. It is a distinct type, not an alias, so
// a bare register number will not convert: the four arena-addressing
// emitters below accept only this, and none of them has a slot for a
// SECOND register to fold. That makes MAMBO-X64's `LDR W0, [X1, X2]`
// mistake inexpressible rather than merely absent.
//
// Producing one is the deliberate act, and `guest_addr_w()` is the only
// way to do it. Its precondition, which the caller is asserting: the
// register was written by W-form (sf == 0) arithmetic, so it already
// carries the wrapped result.
struct GuestAddrW {
    unsigned w = 0;
};
inline GuestAddrW guest_addr_w(unsigned w) { return GuestAddrW{w}; }

// The value an A32/T32 read of R15 yields at `cx.insn_addr`: +8 (A32) or +4
// (T32), word-aligned when `aligned` (the literal-pool and ADR-alias forms
// need Align(PC,4) per A5.1.2), plus the per-image load bias.
uint32_t pc_value(const XlatMemCtx& cx, bool aligned);

// Predication guard. Emits `B.<inverse cc> skip` and returns a token;
// pred_end binds the label. Emits nothing when the condition is AL.
struct PredScope {
    a64::Label skip;
    bool active = false;
};
PredScope pred_begin(XlatMemCtx& cx, arm_cc cc);
void pred_end(XlatMemCtx& cx, PredScope& s);

// wd = wn + imm (signed) using the cheapest ADD/SUB encoding; `tmp` is
// clobbered only when the immediate needs materialising, and must differ
// from `wd`. Never touches PSTATE.
void emit_add_imm32(XlatMemCtx& cx, unsigned wd, unsigned wn, int32_t imm,
                    unsigned tmp);

// ---------------------------------------------------------------------
// The arena-addressing choke points. THESE ARE THE ONLY FUNCTIONS THAT
// NAME x28. Every one takes exactly one GuestAddrW and hardcodes UXTW.
// See THE 2^32 WRAP INVARIANT at the top of this file before adding a
// fifth, and do not give any of them a second address operand.
// ---------------------------------------------------------------------

// Xdst = host pointer for a flattened guest address.
//     ADD Xdst, X28, Waddr, UXTW
// Used by the multi-word forms, which then walk Xdst with scaled
// immediate offsets; see the residual note in the invariant block.
void emit_host_ptr(XlatMemCtx& cx, unsigned xdst, GuestAddrW addr);

// One integer transfer against the arena, in ONE host instruction.
//     <LDR|STR>{B,H} Wt, [X28, Waddr, UXTW]
// `size` is kSizeB / kSizeH / kSizeW / kSizeX and `opc` is the ldst_reg
// opcode (kOpcStore / kOpcLoadZ / kOpcLoadSignedW, or 2 for PRFM, whose
// prefetch operation rides in the Rt field).
void emit_guest_ldst(XlatMemCtx& cx, unsigned size, unsigned opc,
                     unsigned rt, GuestAddrW addr);

// The scalar FP twin, for VLDR / VSTR.
//     <LDR|STR> <St|Dt>, [X28, Waddr, UXTW]
void emit_guest_fp_ldst(XlatMemCtx& cx, unsigned size, bool is_load,
                        unsigned vt, GuestAddrW addr);

// Xdst = pointer to this thread's GuestState. Two instructions, no memory
// access, exactly as specified in guest_state.h section 6:
//     AND Wdst, W<guestSP>, #0xfff00000     ; slot base (guest vaddr)
//     ADD Xdst, X<guestBase>, Xdst          ; host pointer
// The W-form AND zero-extends, so the ADD needs no UXTW.
void emit_guest_state_ptr(XlatMemCtx& cx, unsigned xdst);

// Effective-address computation for an ARM_OP_MEM operand. Returns the host
// register holding the 32-bit guest address; that is `tmp` unless the operand
// was a bare `[Rn]`, in which case it is Rn's home register (read-only).
//
// The result is a GuestAddrW, not a register number, because this function
// is one of the two FLATTENERS: base, index, shift and displacement are all
// summed here with W-form arithmetic, which is what makes the single UXTW
// fold at the access site safe (THE 2^32 WRAP INVARIANT).
struct AddrVal {
    GuestAddrW reg;
    bool ok = false;
};
// `ignore_disp` skips mem.disp. NEON `[Rn:align]` operands report the
// alignment qualifier there and it must NOT be added to the address; that is
// the same trap arm32_lifter.cpp documents at compute_mem_addr.
AddrVal mem_effective_addr(XlatMemCtx& cx, const cs_arm_op& op,
                           bool ignore_disp, unsigned tmp);

// Validate an addressing-mode operand shape BEFORE emitting anything, so a
// predication guard is never left open on a bail-out. `mem_idx` is the index
// of the ARM_OP_MEM operand.
bool addr_shape_ok(const cs_arm& d, int mem_idx);
// Index of the first ARM_OP_MEM operand, or -1.
int find_mem_operand(const cs_arm& d);

// Apply an A32 shifted-operand (LSL/LSR/ASR/ROR/RRX, immediate amounts only)
// to `wsrc`, writing `wdst`. `tmp` is used by RRX and must differ from both.
bool emit_apply_shift(XlatMemCtx& cx, const cs_arm_op& op, unsigned wsrc,
                      unsigned wdst, unsigned tmp);

void warn(XlatMemCtx& cx, const std::string& msg);

// ---------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------

// True when `id` belongs to this stage, so the driver can dispatch without a
// trial translation.
bool is_mem_insn(unsigned id);

// Translate one instruction. Returns false (and emits nothing, or nothing
// observable) when the instruction is not owned here or its operand shape is
// not recognised.
bool translate_mem(XlatMemCtx& cx, const cs_insn* in, XlatResult* result);

}  // namespace arm32rc
}  // namespace macapk

#endif  // MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_MEM_H_
