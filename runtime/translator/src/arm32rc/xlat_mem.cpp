// xlat_mem.cpp -- direct ARM32/Thumb -> arm64 recompiler: memory-access
// translation. See xlat_mem.h for the model and the addressing rules.
//
// No em dashes (project convention). C++17, -Wall -Wextra clean.

#include "xlat_mem.h"

#include <algorithm>
#include <vector>

namespace macapk {
namespace arm32rc {

// Declared in xlat_core.h, forward-declared rather than included: that
// header declares its own `Label`, `Cond` and `cc_is_always` in this same
// namespace, and this file's `using namespace a64` makes all three
// ambiguous the moment both are visible. The refusal-trace entry point is
// the whole surface needed here.
void rc_stub_trace(uint32_t vaddr, bool thumb, const cs_insn* in,
                   const char* stage, const char* reason);

using namespace a64;  // NOLINT(build/namespaces) -- encoder vocabulary

// =====================================================================
//  THE 2^32 WRAP INVARIANT, asserted (see xlat_mem.h for the full
//  argument and the MAMBO-X64 3.3 citation)
// =====================================================================
//
// Three properties make `[X28, Waddr, UXTW]` correct AND in-bounds. All
// three are compile-time checkable, so none of them can rot silently.
static_assert(a64::ExtUXTW == 2u,
              "the arena fold must ZERO-extend a 32-bit W value. ExtUXTW "
              "moved, so every ldst_reg/add_ext in this file now names a "
              "different extend. See THE 2^32 WRAP INVARIANT in xlat_mem.h.");
static_assert((a64::ExtUXTW & 4u) == 0u && (a64::ExtSXTW & 4u) != 0u,
              "bit 2 of A64's extend field is the SIGNED flag. MAMBO-X64 3.3 "
              "uses SXTW because its guest occupies host addresses 0..4GB, so "
              "its base register is a real pointer and the W operand is a "
              "signed offset. Ours is a PINNED NON-ZERO arena base and the W "
              "is the whole guest address, so SXTW would put every address "
              ">= 0x80000000 up to 2 GiB BELOW the arena.");
static_assert(kGuestArenaBytes == (1ull << 32) &&
                  (kGuestArenaBytes - 1ull) == 0xFFFFFFFFull,
              "the single-register fold is in-bounds by construction ONLY "
              "because every value a W register can hold is a valid arena "
              "offset. Shrink the arena and `[X28, Waddr, UXTW]` can leave "
              "it. Keep this in step with kGuestMemSize in bionic_shim.cpp.");

namespace {

inline void put(XlatMemCtx& cx, uint32_t w) { cx.buf->put(w); }

// The arena base register. DELIBERATELY NOT EXPORTED from xlat_mem.h: if
// no other translation unit can name x28, no other translation unit can
// write an addressing mode that folds a second guest register alongside
// it. The three choke points below are the only callers.
inline unsigned guest_base_reg() {
    return static_cast<unsigned>(enc(kHostGuestBase));
}

// Why the last refusal happened, for MACAPK_ARM32RC_STUB_TRACE. A
// handler that returns false emits nothing observable, so without this
// the only evidence a memory instruction was dropped is a per-mnemonic
// tally in the driver's summary, which cannot distinguish "the operand
// shape is one we do not recognise" from "the encoding is architecturally
// UNPREDICTABLE and refusing is correct". That distinction is the whole
// point of the coverage exercise.
thread_local const char* g_mem_refuse = nullptr;

inline bool refuse(const char* why) { g_mem_refuse = why; return false; }

// Access-size selector for the integer load/store encoders.
unsigned size_of_bits(int bits) {
    return bits == 8 ? kSizeB : bits == 16 ? kSizeH : kSizeW;
}

// `opc` for ldst_uimm / ldst_reg with V == 0.
constexpr unsigned kOpcStore = 0u;
constexpr unsigned kOpcLoadZ = 1u;
constexpr unsigned kOpcLoadSignedW = 3u;  // sign-extend into a W register

bool is_core_reg(const cs_arm_op& op) {
    return op.type == ARM_OP_REG && arm_core_idx(op.reg) >= 0;
}

// Shift forms this stage can lower without touching PSTATE. Register-amount
// shifts are deliberately excluded: A32 memory index operands are imm5-shifted
// only (DDI 0406C.d A5.3), so they cannot reach here, and their >= 32
// saturation semantics (trap T2 in xlat_core.h) need a fixup sequence that
// belongs to the core.
bool shift_shape_ok(const cs_arm_op& op) {
    switch (op.shift.type) {
        case ARM_SFT_INVALID:
        case ARM_SFT_LSL:
        case ARM_SFT_LSR:
        case ARM_SFT_ASR:
        case ARM_SFT_ROR:
        case ARM_SFT_RRX:
            return true;
        default:
            return false;
    }
}

}  // namespace

// ==================================================================
// Shared helpers
// ==================================================================

int arm_core_idx(unsigned reg) {
    switch (reg) {
        case ARM_REG_R0:  return 0;
        case ARM_REG_R1:  return 1;
        case ARM_REG_R2:  return 2;
        case ARM_REG_R3:  return 3;
        case ARM_REG_R4:  return 4;
        case ARM_REG_R5:  return 5;
        case ARM_REG_R6:  return 6;
        case ARM_REG_R7:  return 7;
        case ARM_REG_R8:  return 8;
        case ARM_REG_R9:  return 9;
        case ARM_REG_R10: return 10;
        case ARM_REG_R11: return 11;
        case ARM_REG_R12: return 12;
        case ARM_REG_SP:  return 13;
        case ARM_REG_LR:  return 14;
        case ARM_REG_PC:  return 15;
        default:          return -1;
    }
}

bool cc_is_always(arm_cc cc) {
    return cc == ARM_CC_AL || cc == ARM_CC_INVALID;
}

Cond cond_of(arm_cc cc) {
    return static_cast<Cond>((static_cast<unsigned>(cc) - 1u) & 15u);
}

void warn(XlatMemCtx& cx, const std::string& msg) {
    if (cx.warn) cx.warn(msg);
}

uint32_t pc_value(const XlatMemCtx& cx, bool aligned) {
    uint32_t pc = cx.insn_addr + (cx.is_thumb ? 4u : 8u);
    if (aligned) pc &= ~3u;
    return pc + cx.load_bias;
}

PredScope pred_begin(XlatMemCtx& cx, arm_cc cc) {
    PredScope s;
    if (cc_is_always(cc)) return s;
    s.skip = cx.buf->new_label();
    s.active = true;
    // Branch AROUND the body when the guest condition is FALSE.
    cx.buf->b_cond(invert_cond(cond_of(cc)), s.skip);
    return s;
}

void pred_end(XlatMemCtx& cx, PredScope& s) {
    if (!s.active) return;
    cx.buf->bind(s.skip);
    s.active = false;
}

void emit_add_imm32(XlatMemCtx& cx, unsigned wd, unsigned wn, int32_t imm,
                    unsigned tmp) {
    if (imm == 0) {
        if (wd != wn) put(cx, mov_reg(false, wd, wn));
        return;
    }
    const bool sub = imm < 0;
    // 64-bit magnitude so INT32_MIN does not overflow.
    const uint64_t mag = sub ? (0ull - static_cast<int64_t>(imm))
                             : static_cast<uint64_t>(imm);
    if (mag < 4096) {
        put(cx, sub ? sub_imm(false, wd, wn, static_cast<uint32_t>(mag))
                    : add_imm(false, wd, wn, static_cast<uint32_t>(mag)));
        return;
    }
    if ((mag & 0xFFFull) == 0 && (mag >> 12) < 4096) {
        const uint32_t hi = static_cast<uint32_t>(mag >> 12);
        put(cx, sub ? sub_imm(false, wd, wn, hi, true)
                    : add_imm(false, wd, wn, hi, true));
        return;
    }
    if (mag < (1ull << 24)) {
        const uint32_t hi = static_cast<uint32_t>(mag >> 12);
        const uint32_t lo = static_cast<uint32_t>(mag & 0xFFFu);
        put(cx, sub ? sub_imm(false, wd, wn, hi, true)
                    : add_imm(false, wd, wn, hi, true));
        put(cx, sub ? sub_imm(false, wd, wd, lo) : add_imm(false, wd, wd, lo));
        return;
    }
    cx.buf->mov_imm(false, tmp, static_cast<uint32_t>(imm));
    put(cx, add_reg(false, wd, wn, tmp));
}

// The three arena-addressing choke points. Each folds EXACTLY ONE
// already-flattened 32-bit guest address, with the extend hardcoded to
// UXTW. Neither the base nor the extend is a parameter, so a caller
// cannot ask for a second guest register or for sign extension.
void emit_host_ptr(XlatMemCtx& cx, unsigned xdst, GuestAddrW addr) {
    put(cx, add_ext(true, xdst, guest_base_reg(), addr.w, ExtUXTW, 0));
}

// True when the translate-time env gate for the per-store watchpoint is on.
// Read once; the shim is additionally a run-time no-op unless MACAPK_WATCH_ADDR
// or MACAPK_WATCH_INDIRECT is set.
bool trace_stores_on(const XlatMemCtx& cx) {
    static const bool on =
        std::getenv("MACAPK_ARM32RC_TRACE_STORES") != nullptr;
    return on && cx.trace_store_sites != nullptr;
}

// MACAPK_ARM32RC_TRACE_STORES=multi restricts instrumentation to the MULTI-WORD
// shapes (STRD and non-SP STM), leaving single-word STR alone.
//
// This exists because instrumenting everything is too slow to be useful: single
// word STR is ~45,000 sites in HCR and dominates the cost, and with every shape
// traced the app cannot reach native init inside a 420-second window, so the
// watchpoint reports "no stores" for a bug it never got close to. Silence from
// an un-armed watch reads exactly like silence from an innocent instruction,
// which is how three consecutive catch attempts produced a zero that meant
// nothing. Tracing only the multi-word shapes costs a small fraction of the
// sites and keeps the app fast enough to actually reach the corruption.
bool trace_single_word_stores(const XlatMemCtx& cx) {
    static const bool multi_only = []() {
        const char* e = std::getenv("MACAPK_ARM32RC_TRACE_STORES");
        return e && e[0] == 'm';
    }();
    return trace_stores_on(cx) && !multi_only;
}

// Emit `__macapk_trace_store(waddr, wval, insn_addr)`.
//
// Factored out of emit_guest_ldst so the MULTI-WORD stores can use it too.
// Before this, the watchpoint covered ONLY single-word STR through
// emit_guest_ldst, which made it blind to STRD / STM / NEON VST -- every shape
// that goes through emit_host_ptr. That blind spot cost a whole HCR debugging
// session: the watch reported zero stores to an address that demonstrably WAS
// being overwritten, which reads as "nothing wrote here" when it actually meant
// "the writer is a width I do not instrument".
//
// waddr must be a W register holding the already-flattened guest address, and
// it may be x16 itself (the mov is then a harmless no-op). x16/x17 are clobbered.
void emit_trace_store_call(XlatMemCtx& cx, unsigned waddr, unsigned wval) {
    // Capture the two live values into x16/x17 BEFORE spilling. Safe because
    // no branch (and therefore no linker veneer, AAPCS64 Table 2) sits between
    // here and their use -- the same argument emit_dispatch relies on.
    put(cx, mov_reg(false, 16, waddr));
    put(cx, mov_reg(false, 17, wval));
    // Spill EVERY caller-saved GPR the callee may destroy: AAPCS64 makes
    // x0-x17 all caller-saved, and `__macapk_trace_store` is an ordinary C
    // function that can clobber x9-x15 at will.
    //
    // x0-x7 alone is NOT enough, and the comment that used to sit here claiming
    // "the scratch pool starts at x4" was wrong: XlatMemCtx::tmp is
    // {X11, X12, X13, X14} (xlat_mem.h). The single-store caller got away with
    // it because nothing read the scratch pool after the call, but the
    // multi-word callers keep the materialised host pointer (tmp[2]) and the
    // lowest-address register (tmp[0]) live ACROSS it, so an x0-x7-only spill
    // let the callee eat them and turned every later word of an STM into a
    // store through garbage. That crashed as SIGILL.
    //
    // x18 is never touched (platform register), and x19-x28 -- which hold the
    // guest base and guest SP -- are callee-saved, so the callee preserves them.
    cx.buf->put(stp(true, 0, 1, kSP, -128, Index::PreIndex));
    cx.buf->put(stp(true, 2, 3, kSP, 16));
    cx.buf->put(stp(true, 4, 5, kSP, 32));
    cx.buf->put(stp(true, 6, 7, kSP, 48));
    cx.buf->put(stp(true, 8, 9, kSP, 64));
    cx.buf->put(stp(true, 10, 11, kSP, 80));
    cx.buf->put(stp(true, 12, 13, kSP, 96));
    cx.buf->put(stp(true, 14, 15, kSP, 112));
    put(cx, mov_reg(false, 0, 16));
    put(cx, mov_reg(false, 1, 17));
    cx.buf->mov_imm(false, 2, cx.insn_addr);
    cx.trace_store_sites->push_back(
        static_cast<uint32_t>(cx.buf->size_words()));
    cx.buf->put(bl(0));
    cx.buf->put(ldp(true, 14, 15, kSP, 112));
    cx.buf->put(ldp(true, 12, 13, kSP, 96));
    cx.buf->put(ldp(true, 10, 11, kSP, 80));
    cx.buf->put(ldp(true, 8, 9, kSP, 64));
    cx.buf->put(ldp(true, 6, 7, kSP, 48));
    cx.buf->put(ldp(true, 4, 5, kSP, 32));
    cx.buf->put(ldp(true, 2, 3, kSP, 16));
    cx.buf->put(ldp(true, 0, 1, kSP, 128, Index::PostIndex));
}

void emit_guest_ldst(XlatMemCtx& cx, unsigned size, unsigned opc,
                     unsigned rt, GuestAddrW addr) {
    // `scaled` MUST stay false: addr.w is already a BYTE address, and the
    // scaled form would multiply it by the access size.
    put(cx, ldst_reg(size, false, opc, rt, guest_base_reg(), addr.w,
                     ExtUXTW, /*scaled=*/false));

    // MACAPK_ARM32RC_TRACE_STORES=1: call __macapk_trace_store(addr, val, pc)
    // after every 32-bit guest store.
    //
    // The shim has had this per-store watchpoint since the bug-2 hunt, but
    // only the LLVM lifter ever emitted the call (arm32_lifter.cpp
    // ::emit_str_size), so on arm32rc it was dead. It is the only tool that
    // answers "which guest instruction wrote this word", which is exactly the
    // open question on HCR: CCApplication's ctor demonstrably runs with the
    // right `this` and its vptr store is byte-correct, yet by drawScene the
    // object's vptr has become a heap address. Per-function replay cannot see
    // an inter-procedural wild store, and the capture harness only samples at
    // function ENTRY.
    //
    // Diagnostic only, off unless the env var is set at TRANSLATE time; the
    // shim is additionally a no-op unless MACAPK_WATCH_ADDR is set at RUN
    // time. Cost when enabled is a call per 32-bit store, which is why it is
    // not on by default.
    // Byte and halfword stores are traced too: a vptr can be smashed by a
    // narrow store just as easily as by a word one, and the shim's window test
    // already tolerates unaligned targets.
    if (!trace_single_word_stores(cx) || opc != kOpcStore) return;
    emit_trace_store_call(cx, addr.w, rt);
}

void emit_guest_fp_ldst(XlatMemCtx& cx, unsigned size, bool is_load,
                        unsigned vt, GuestAddrW addr) {
    put(cx, fp_ldst_reg(size, is_load, vt, guest_base_reg(), addr.w,
                        ExtUXTW, /*scaled=*/false));
}

void emit_guest_state_ptr(XlatMemCtx& cx, unsigned xdst) {
    // guest_state.h section 6. kSlotBaseMask (0xfff00000) is a legal A64
    // 32-bit logical immediate (12 ones then 20 zeros); the encoding is
    // computed once rather than hard-coded so a change to the slot geometry
    // cannot silently produce a wrong mask.
    static uint32_t mask_field = 0;
    static bool mask_ok = encode_logical_imm(kSlotBaseMask, false, &mask_field);
    if (mask_ok) {
        put(cx, and_imm(false, xdst, host_reg(kSP), mask_field));
    } else {
        cx.buf->mov_imm(false, xdst, kSlotBaseMask);
        put(cx, and_reg(false, xdst, host_reg(kSP), xdst));
    }
    // The X-form ADD below has no UXTW because it does not need one: both
    // branches above write xdst with a W-form (sf == 0) instruction, which
    // zero-extends into the full X register per DDI 0487's "the upper 32
    // bits of the destination register are set to zero" rule. That is the
    // same 2^32 truncation UXTW would perform, just already done, so this
    // site still folds exactly one 32-bit value into the arena base.
    put(cx, add_reg(true, xdst, guest_base_reg(), xdst));
}

bool emit_apply_shift(XlatMemCtx& cx, const cs_arm_op& op, unsigned wsrc,
                      unsigned wdst, unsigned tmp) {
    const arm_shifter st = op.shift.type;
    if (st == ARM_SFT_INVALID) {
        if (wdst != wsrc) put(cx, mov_reg(false, wdst, wsrc));
        return true;
    }
    if (!shift_shape_ok(op)) return false;
    const unsigned n = op.shift.value;
    switch (st) {
        case ARM_SFT_LSL:
            if (n == 0) {
                if (wdst != wsrc) put(cx, mov_reg(false, wdst, wsrc));
            } else if (n < 32) {
                put(cx, lsl_imm(false, wdst, wsrc, n));
            } else {
                put(cx, mov_reg(false, wdst, kZR));
            }
            return true;
        case ARM_SFT_LSR:
            // DecodeImmShift (DDI 0406C.d A8.4.3): LSR #0 in the encoding
            // means LSR #32, which Capstone reports as 32. Everything shifts
            // out either way.
            if (n == 0 || n >= 32) put(cx, mov_reg(false, wdst, kZR));
            else                   put(cx, lsr_imm(false, wdst, wsrc, n));
            return true;
        case ARM_SFT_ASR:
            // ASR #0 encodes ASR #32, whose result is the sign bit replicated,
            // which ASR #31 produces.
            put(cx, asr_imm(false, wdst, wsrc, (n == 0 || n >= 32) ? 31u : n));
            return true;
        case ARM_SFT_ROR:
            if (n == 0) {
                if (wdst != wsrc) put(cx, mov_reg(false, wdst, wsrc));
            } else {
                put(cx, ror_imm(false, wdst, wsrc, n & 31u));
            }
            return true;
        case ARM_SFT_RRX:
            // RRX: result = (C << 31) | (value >> 1). Reading C without
            // disturbing PSTATE means MRS plus a bitfield extract; C is NZCV
            // bit 29 (kFlagC in guest_state.h uses the same bit positions on
            // purpose).
            if (tmp == wdst || tmp == wsrc) return false;
            put(cx, mrs(tmp, kSR_NZCV));
            put(cx, ubfx(false, tmp, tmp, 29, 1));
            put(cx, lsr_imm(false, wdst, wsrc, 1));
            put(cx, orr_reg(false, wdst, wdst, tmp, ShiftLSL, 31));
            return true;
        default:
            return false;
    }
}

int find_mem_operand(const cs_arm& d) {
    for (int i = 0; i < d.op_count; ++i)
        if (d.operands[i].type == ARM_OP_MEM) return i;
    return -1;
}

bool addr_shape_ok(const cs_arm& d, int mem_idx) {
    if (mem_idx < 0 || mem_idx >= d.op_count)
        return refuse("no memory operand at the expected index");
    const cs_arm_op& mem = d.operands[mem_idx];
    if (mem.type != ARM_OP_MEM)
        return refuse("addressing operand is not ARM_OP_MEM");
    if (arm_core_idx(mem.mem.base) < 0)
        return refuse("address base is not a core register r0..r15");
    if (mem.mem.index != ARM_REG_INVALID) {
        if (arm_core_idx(mem.mem.index) < 0)
            return refuse("address index is not a core register r0..r15");
        if (!shift_shape_ok(mem))
            return refuse("address index uses a register-amount shift");
    }
    if (d.op_count == mem_idx + 2) {  // 3-operand post-index shape
        const cs_arm_op& off = d.operands[mem_idx + 1];
        if (off.type == ARM_OP_IMM) return true;
        if (off.type != ARM_OP_REG)
            return refuse("post-index offset is neither imm nor reg");
        if (arm_core_idx(off.reg) < 0)
            return refuse("post-index offset register is not r0..r15");
        if (!shift_shape_ok(off))
            return refuse("post-index offset uses a register-amount shift");
    }
    return true;
}

AddrVal mem_effective_addr(XlatMemCtx& cx, const cs_arm_op& op,
                           bool ignore_disp, unsigned tmp) {
    AddrVal out;
    const int rbase = arm_core_idx(op.mem.base);
    if (rbase < 0) return out;

    const int32_t disp = ignore_disp ? 0 : static_cast<int32_t>(op.mem.disp);
    const bool has_index = (op.mem.index != ARM_REG_INVALID);

    // `cur` tracks where the running address lives. It starts in the base
    // register's home (no copy needed, since every addition below can name a
    // separate destination) and only moves into `tmp` once something is
    // actually added.
    //
    // EVERY accumulation below is W-form (sf == 0), which is what makes this
    // function a FLATTENER: base + shifted index + displacement is summed
    // modulo 2^32 exactly as AArch32 would, so the single value handed back
    // is already wrapped and one UXTW at the access site is sufficient. Do
    // not "optimise" any of these into 64-bit arithmetic or into a second
    // operand of the access itself. See THE 2^32 WRAP INVARIANT in
    // xlat_mem.h and MAMBO-X64 PLDI 2017 section 3.3.
    unsigned cur;
    if (rbase == 15) {
        // PC-relative literal. With no index register (the only shape a
        // compiler constant pool emits) the whole address folds to a
        // constant.
        const uint32_t base_addr = pc_value(cx, /*aligned=*/true);
        if (!has_index) {
            cx.buf->mov_imm(false, tmp,
                            base_addr + static_cast<uint32_t>(disp));
            out.reg = guest_addr_w(tmp);
            out.ok = true;
            return out;
        }
        cx.buf->mov_imm(false, tmp, base_addr);
        cur = tmp;
    } else {
        cur = host_reg(rbase);
        if (!has_index && disp == 0) {
            out.reg = guest_addr_w(cur);
            out.ok = true;
            return out;
        }
    }

    if (has_index) {
        const int ri = arm_core_idx(op.mem.index);
        if (ri < 0) return out;
        unsigned idx = host_reg(ri);
        if (op.shift.type != ARM_SFT_INVALID) {
            // The shifted index needs a register that is not the running
            // base; `tmp` is free unless the base already occupies it.
            const unsigned itmp =
                (cur == tmp) ? ((tmp == cx.tmp[1]) ? cx.tmp[2] : cx.tmp[1])
                             : tmp;
            if (!emit_apply_shift(cx, op, idx, itmp, cx.tmp[3])) return out;
            idx = itmp;
        }
        // Capstone reports `[Rn, -Rm]` either as scale == -1 or via
        // op.subtracted depending on version; honour both. Getting the sign
        // wrong is off-by-2*index on every access (the bug arm32_lifter.cpp
        // documents at compute_mem_addr).
        const bool subtract = (op.mem.scale == -1) || op.subtracted;
        put(cx, subtract ? sub_reg(false, tmp, cur, idx)
                         : add_reg(false, tmp, cur, idx));
        cur = tmp;
    }
    if (disp != 0) {
        emit_add_imm32(cx, tmp, cur, disp, cx.tmp[3]);
        cur = tmp;
    }
    out.reg = guest_addr_w(cur);
    out.ok = true;
    return out;
}

// ==================================================================
// Instruction translation
// ==================================================================

namespace {

// Address plan for the single- and double-register forms.
//
// Capstone reports `LDR Rt, [Rn], #imm` / `[Rn], Rm{,shift}` as
// op_count == mem_idx + 2, with operands[mem_idx] carrying only the base and
// operands[mem_idx + 1] carrying the post-increment. The `post_index` flag is
// not reliable across Capstone builds for every variant, so the operand count
// is the discriminator; that is the same rule arm32_lifter.cpp settled on
// after debugging against real binaries.
struct AddrPlan {
    // The flattened access address. Typed, so it can only reach an
    // arena-addressing choke point (THE 2^32 WRAP INVARIANT in xlat_mem.h).
    GuestAddrW access_w;
    unsigned wb_w = 0;      // host reg with the base writeback value
    bool has_wb = false;
    int base_r = -1;
    bool ok = false;
};

AddrPlan plan_address(XlatMemCtx& cx, const cs_insn* in, int mem_idx,
                      unsigned addr_tmp, unsigned wb_tmp) {
    const cs_arm& d = in->detail->arm;
    AddrPlan p;
    const cs_arm_op& mem = d.operands[mem_idx];
    p.base_r = arm_core_idx(mem.mem.base);
    const bool post3 = (d.op_count == mem_idx + 2);

    if (post3) {
        // A post-indexed access writes its base back, and the base here is
        // PC. DDI 0406C.d A8.6.59 (LDR immediate, A1) makes the
        // post-indexed / writeback forms with Rn == PC UNPREDICTABLE
        // ("if wback && n == t then UNPREDICTABLE" plus the PC-base rule),
        // so there is no defined behaviour to emit.
        if (p.base_r < 0 || p.base_r == 15) {
            refuse("post-indexed access with a PC or non-core base "
                   "(UNPREDICTABLE)");
            return p;
        }
        // Post-indexed: the ACCESS uses the original base, so it can name the
        // base's home register directly. The increment is also computed from
        // the original base, and the writeback is committed only after the
        // access, so no copy of the base is needed anywhere.
        const unsigned wbase = host_reg(p.base_r);
        p.access_w = guest_addr_w(wbase);
        const cs_arm_op& off = d.operands[mem_idx + 1];
        if (off.type == ARM_OP_IMM) {
            const int32_t inc = off.subtracted
                                    ? -static_cast<int32_t>(off.imm)
                                    : static_cast<int32_t>(off.imm);
            emit_add_imm32(cx, wb_tmp, wbase, inc, cx.tmp[3]);
        } else if (off.type == ARM_OP_REG) {
            const int ri = arm_core_idx(off.reg);
            if (ri < 0) { refuse("post-index register not r0..r15"); return p; }
            unsigned iv = host_reg(ri);
            if (off.shift.type != ARM_SFT_INVALID) {
                if (!emit_apply_shift(cx, off, iv, addr_tmp, cx.tmp[3])) {
                    refuse("post-index shift form not lowerable here");
                    return p;
                }
                iv = addr_tmp;
            }
            put(cx, off.subtracted ? sub_reg(false, wb_tmp, wbase, iv)
                                   : add_reg(false, wb_tmp, wbase, iv));
        } else {
            refuse("post-index operand is neither imm nor reg");
            return p;
        }
        p.wb_w = wb_tmp;
        p.has_wb = true;
        p.ok = true;
        return p;
    }

    const AddrVal a = mem_effective_addr(cx, mem, /*ignore_disp=*/false,
                                         addr_tmp);
    if (!a.ok) return p;
    p.access_w = a.reg;
    // Pre-indexed writeback stores the fully-computed access address.
    if (d.writeback && p.base_r >= 0 && p.base_r != 15) {
        p.wb_w = a.reg.w;
        p.has_wb = true;
    }
    p.ok = true;
    return p;
}

// LDR / LDRB / LDRH / LDRSB / LDRSH / STR / STRB / STRH plus the unprivileged
// T-suffixed twins. Mac.apk has a single privilege level, so LDRT/STRT
// translate identically to LDR/STR (the same choice arm32_lifter.cpp made).
bool xlat_ldst_single(XlatMemCtx& cx, const cs_insn* in, int bits,
                      bool is_load, bool sign_ext, XlatResult* res) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2 && d.op_count != 3)
        return refuse("single load/store op_count outside 2..3");
    if (!is_core_reg(d.operands[0]))
        return refuse("Rt is not a core register r0..r15");
    if (!addr_shape_ok(d, 1)) return false;
    const int rt = arm_core_idx(d.operands[0].reg);

    PredScope g = pred_begin(cx, d.cc);
    const AddrPlan p = plan_address(cx, in, 1, cx.tmp[0], cx.tmp[1]);
    if (!p.ok) { pred_end(cx, g); return false; }

    const unsigned sz = size_of_bits(bits);
    const unsigned opc =
        is_load ? (sign_ext ? kOpcLoadSignedW : kOpcLoadZ) : kOpcStore;

    if (is_load) {
        const unsigned dst = (rt == 15) ? cx.tmp[2] : host_reg(rt);
        emit_guest_ldst(cx, sz, opc, dst, p.access_w);
        // Writeback lands after the load: when Rt == Rn the architecture calls
        // the result UNPREDICTABLE, and letting the writeback win is the same
        // choice arm32_lifter.cpp made.
        if (p.has_wb) put(cx, mov_reg(false, host_reg(p.base_r), p.wb_w));
        if (rt == 15 && res) {
            res->wrote_pc = true;
            res->pc_reg = dst;
            res->is_return = (p.base_r == kSP);
            // Same deferral as the LDM path: a conditional `ldr pc,[..]` must
            // fall through to the next guest instruction when the condition
            // is false, so its skip label cannot be bound before the driver
            // emits the terminator.
            if (g.active) {
                res->has_pending_skip = true;
                res->pending_skip = g.skip;
                g.active = false;
            }
        }
    } else {
        // STR with Rt == PC is UNPREDICTABLE on ARMv7; PC+8 (the value the
        // STM form is required to store, DDI 0406C.d A8.8.199) is the
        // conventional choice.
        unsigned src;
        if (rt == 15) {
            src = cx.tmp[2];
            cx.buf->mov_imm(false, src, pc_value(cx, /*aligned=*/false));
        } else {
            src = host_reg(rt);
        }
        emit_guest_ldst(cx, sz, kOpcStore, src, p.access_w);
        if (p.has_wb) put(cx, mov_reg(false, host_reg(p.base_r), p.wb_w));
    }

    pred_end(cx, g);
    return true;
}

// LDRD / STRD. Lowered to two 32-bit accesses rather than LDP/STP: ARMv7
// requires only word alignment for these and they are explicitly NOT
// single-copy atomic (DDI 0406C.d A3.5.3), so a pair of word accesses is
// faithful and sidesteps LDP's scaled-offset constraints. Rt takes the low
// word and Rt2 the high word (little-endian).
bool xlat_ldrd_strd(XlatMemCtx& cx, const cs_insn* in, bool is_load) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3 && d.op_count != 4)
        return refuse("LDRD/STRD op_count outside 3..4");
    if (!is_core_reg(d.operands[0]) || !is_core_reg(d.operands[1]))
        return false;
    if (!addr_shape_ok(d, 2)) return false;
    const int rlo = arm_core_idx(d.operands[0].reg);
    const int rhi = arm_core_idx(d.operands[1].reg);
    // DDI 0406C.d A8.6.66 LDRD (immediate): "if t == 15 || t2 == 15 then
    // UNPREDICTABLE". There is no defined behaviour for a PC-targeted
    // doubleword transfer, so refusing is the correct answer.
    if (rlo == 15 || rhi == 15)
        return refuse("LDRD/STRD naming PC (UNPREDICTABLE)");

    PredScope g = pred_begin(cx, d.cc);
    const AddrPlan p = plan_address(cx, in, 2, cx.tmp[0], cx.tmp[1]);
    if (!p.ok) { pred_end(cx, g); return false; }

    const unsigned xp = cx.tmp[2];
    emit_host_ptr(cx, xp, p.access_w);
    if (is_load) {
        put(cx, ldr(false, host_reg(rlo), xp, 0));
        put(cx, ldr(false, host_reg(rhi), xp, 4));
    } else {
        put(cx, str(false, host_reg(rlo), xp, 0));
        put(cx, str(false, host_reg(rhi), xp, 4));
        if (trace_stores_on(cx)) {
            // Same reconstruction as the STM path: p.access_w is the guest
            // address of the low word, and the high word sits at +4.
            emit_trace_store_call(cx, p.access_w.w, host_reg(rlo));
            emit_add_imm32(cx, 16, p.access_w.w, 4, 17);
            emit_trace_store_call(cx, 16, host_reg(rhi));
        }
    }
    if (p.has_wb) put(cx, mov_reg(false, host_reg(p.base_r), p.wb_w));
    pred_end(cx, g);
    return true;
}

// ------------------------------------------------------------------
// LDM / STM / PUSH / POP.
//
// The ordering rule (DDI 0406C.d A8.8.115 and the LDM/STM family generally):
// "the lowest-numbered register is loaded from or stored to the lowest memory
// address", and it holds for ALL four addressing modes. The mode only chooses
// the START address:
//
//     IA : lowest = Rn                 writeback Rn + 4n
//     IB : lowest = Rn + 4             writeback Rn + 4n
//     DA : lowest = Rn - 4(n-1)        writeback Rn - 4n
//     DB : lowest = Rn - 4n            writeback Rn - 4n
//
// So: compute the lowest address once, materialise one host pointer, then walk
// the SORTED register list with scaled immediate offsets, one host instruction
// per guest register. The list is sorted here rather than trusted from
// Capstone because that ordering invariant is the whole correctness argument.
// ------------------------------------------------------------------
bool xlat_ldm_stm(XlatMemCtx& cx, const cs_insn* in, bool is_load,
                  int direction, int pre, int base_override,
                  bool implicit_writeback, XlatResult* res) {
    const cs_arm& d = in->detail->arm;
    int first_list = 0;
    int base_r = base_override;
    if (base_r < 0) {
        if (d.op_count < 2 || !is_core_reg(d.operands[0]))
            return refuse("LDM/STM base operand is not a core register");
        base_r = arm_core_idx(d.operands[0].reg);
        first_list = 1;
    }
    // DDI 0406C.d A8.6.53 LDM/LDMIA: "if n == 15 ... then UNPREDICTABLE".
    if (base_r < 0 || base_r == 15)
        return refuse("LDM/STM with a PC or non-core base (UNPREDICTABLE)");

    std::vector<int> regs;
    regs.reserve(16);
    for (int i = first_list; i < d.op_count; ++i) {
        if (!is_core_reg(d.operands[i]))
            return refuse("LDM/STM register list holds a non-core register");
        regs.push_back(arm_core_idx(d.operands[i].reg));
    }
    if (regs.empty())
        return refuse("LDM/STM with an empty register list (UNPREDICTABLE)");
    std::sort(regs.begin(), regs.end());
    const int n = static_cast<int>(regs.size());

    if (d.usermode) {
        // LDM/STM (User registers) and LDM (exception return) are privileged.
        // At PL0, where every Android .so runs, they are UNPREDICTABLE
        // (DDI 0406C.d B9.3.5 / B9.3.6). Mac.apk models a single privilege
        // level with no banked registers, so the faithful lowering of what the
        // guest can actually reach is the ordinary form. Recorded rather than
        // silently accepted.
        warn(cx, "LDM/STM with ^ (user-mode registers) is UNPREDICTABLE at "
                 "PL0; translated as the ordinary form");
    }

    const bool writeback = d.writeback || implicit_writeback;
    const unsigned wbase = host_reg(base_r);

    PredScope g = pred_begin(cx, d.cc);

    // Both the lowest accessed address and the writeback value are defined in
    // terms of the ORIGINAL base, and for LDM the base register may itself be
    // overwritten by a load, so both are computed up front and the writeback
    // is committed at the end. For the DB modes the two are the same value
    // (lowest = base - 4n = writeback), which covers every PUSH.
    const int32_t low_off = (direction > 0) ? (pre ? 4 : 0)
                                            : (pre ? (-4 * n) : (-4 * (n - 1)));
    const int32_t wb_off = direction * 4 * n;
    const unsigned wlow = cx.tmp[0];
    emit_add_imm32(cx, wlow, wbase, low_off, cx.tmp[3]);
    unsigned wwb = wlow;
    if (writeback && wb_off != low_off) {
        wwb = cx.tmp[1];
        emit_add_imm32(cx, wwb, wbase, wb_off, cx.tmp[3]);
    }

    const unsigned xp = cx.tmp[2];
    // wlow was written by emit_add_imm32, i.e. W-form arithmetic, so it is
    // already the 2^32-wrapped lowest address.
    emit_host_ptr(cx, xp, guest_addr_w(wlow));

    bool wrote_pc = false;
    unsigned pc_reg = 0;
    for (int i = 0; i < n; ++i) {
        const int r = regs[i];
        const uint64_t off = static_cast<uint64_t>(4 * i);
        if (is_load) {
            // r15 lands in a scratch and is reported to the driver, which
            // turns it into the block terminator.
            const unsigned dst = (r == 15) ? cx.tmp[3] : host_reg(r);
            put(cx, ldr(false, dst, xp, off));
            if (r == 15) { wrote_pc = true; pc_reg = dst; }
        } else {
            unsigned src;
            if (r == 15) {
                // DDI 0406C.d A8.8.199: for STM the value stored for PC is
                // implementation defined, and ARMv7 requires PC+8.
                src = cx.tmp[3];
                cx.buf->mov_imm(false, src, pc_value(cx, /*aligned=*/false));
            } else {
                src = host_reg(r);
            }
            put(cx, str(false, src, xp, off));
            // SP-based STM is deliberately NOT traced. Every guest function
            // prologue is a `push`, so tracing those puts a host call plus a
            // 128-byte frame at every single function entry: it exhausted the
            // host stack inside an already-deep recursion and killed the run
            // with a guard-page fault before the app even finished booting.
            // The cost is nothing in practice, because a push writes near the
            // guest SP (0x3e2xxxxx) while the corruption this watchpoint hunts
            // lands on a heap object (0x2000xxxx). Widen this if a stack object
            // ever turns out to be the victim.
            if (trace_stores_on(cx) && base_r != kSP) {
                // The watchpoint wants the GUEST address, but this loop walks a
                // materialised HOST pointer, so reconstruct it as wlow + off.
                // wlow (tmp[0]) and xp (tmp[2]) are x11/x13, which
                // emit_trace_store_call spills and restores, so they survive.
                emit_add_imm32(cx, 16, wlow, static_cast<int32_t>(off), 17);
                emit_trace_store_call(cx, 16, src);
            }
        }
    }

    if (writeback) put(cx, mov_reg(false, wbase, wwb));

    if (wrote_pc && res) {
        res->wrote_pc = true;
        res->pc_reg = pc_reg;
        res->is_return = (base_r == kSP);
        // Hand the still-unbound skip label to the driver: it must land AFTER
        // the terminator, not here. See XlatResult::has_pending_skip.
        if (g.active) {
            res->has_pending_skip = true;
            res->pending_skip = g.skip;
            g.active = false;              // do not bind it below
        }
    }
    pred_end(cx, g);
    return true;
}

// ------------------------------------------------------------------
// Exclusives and ordered accesses.
//
// ARM32 LDREX/STREX map 1:1 onto A64 LDXR/STXR (and LDAEX/STLEX onto
// LDAXR/STLXR): the exclusive monitor, the reservation granule and the
// "STREX writes 0 on success" convention are identical. This is a real
// upgrade over the LLVM lifter, which degraded STREX to a plain store that
// always reported success and therefore could not express a CAS retry loop at
// all (arm32_lifter.cpp emit_strex).
//
// A64's exclusives take a bare `[Xn]` with no offset form, so the guest
// address is materialised into a host pointer first.
// ------------------------------------------------------------------
bool xlat_exclusive(XlatMemCtx& cx, const cs_insn* in, int bits,
                    bool is_load, bool pair, bool ordered) {
    const cs_arm& d = in->detail->arm;
    const unsigned sz = size_of_bits(bits);

    const int mem_idx = find_mem_operand(d);
    if (!addr_shape_ok(d, mem_idx)) return false;
    // Validate every register operand before emitting anything.
    const int need = is_load ? (pair ? 2 : 1) : (pair ? 3 : 2);
    if (mem_idx < need)
        return refuse("exclusive access operand layout not recognised");
    for (int i = 0; i < need; ++i) {
        if (!is_core_reg(d.operands[i]))
            return refuse("exclusive access operand is not a core register");
        // DDI 0406C.d A8.6.76 LDREX / A8.6.202 STREX both say
        // "if d == 15 || t == 15 || n == 15 then UNPREDICTABLE".
        if (arm_core_idx(d.operands[i].reg) == 15)
            return refuse("exclusive access naming PC (UNPREDICTABLE)");
    }

    PredScope g = pred_begin(cx, d.cc);
    const AddrVal a = mem_effective_addr(cx, d.operands[mem_idx], false,
                                         cx.tmp[0]);
    if (!a.ok) { pred_end(cx, g); return false; }
    const unsigned xp = cx.tmp[1];
    emit_host_ptr(cx, xp, a.reg);

    if (is_load) {
        const unsigned rt = host_reg(arm_core_idx(d.operands[0].reg));
        if (pair) {
            // LDXP Wt, Wt2, [Xn] reads Wt from [Xn] and Wt2 from [Xn+4],
            // which is exactly LDREXD's little-endian low/high split.
            const unsigned rt2 = host_reg(arm_core_idx(d.operands[1].reg));
            put(cx, ordered ? ldaxp(false, rt, rt2, xp)
                            : ldxp(false, rt, rt2, xp));
        } else if (bits == 8) {
            put(cx, ordered ? ldaxrb(rt, xp) : ldxrb(rt, xp));
        } else if (bits == 16) {
            put(cx, ordered ? ldaxrh(rt, xp) : ldxrh(rt, xp));
        } else {
            put(cx, ordered ? ldaxr(false, rt, xp) : ldxr(false, rt, xp));
        }
    } else {
        const int rd = arm_core_idx(d.operands[0].reg);
        const unsigned rt = host_reg(arm_core_idx(d.operands[1].reg));
        // The status register must differ from the data and address registers
        // (CONSTRAINED UNPREDICTABLE otherwise), so it goes to a scratch and
        // is copied to Rd afterwards.
        const unsigned ws = cx.tmp[0];
        if (pair) {
            const unsigned rt2 = host_reg(arm_core_idx(d.operands[2].reg));
            put(cx, ordered ? stlxp(false, ws, rt, rt2, xp)
                            : stxp(false, ws, rt, rt2, xp));
        } else if (bits == 8) {
            put(cx, ordered ? stlxrb(ws, rt, xp) : stxrb(ws, rt, xp));
        } else if (bits == 16) {
            put(cx, ordered ? stlxrh(ws, rt, xp) : stxrh(ws, rt, xp));
        } else {
            put(cx, ordered ? stlxr(false, ws, rt, xp)
                            : stxr(false, ws, rt, xp));
        }
        put(cx, mov_reg(false, host_reg(rd), ws));
    }
    pred_end(cx, g);
    (void)sz;
    return true;
}

// LDA / LDAB / LDAH / STL / STLB / STLH: acquire / release with no exclusive
// monitor, i.e. A64's LDAR / STLR. Encoded through ldst_excl with o2 = 1,
// o0 = 1 and Rs / Rt2 tied to ZR, which is what the manual's diagram requires.
bool xlat_acq_rel(XlatMemCtx& cx, const cs_insn* in, int bits, bool is_load) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count < 2 || !is_core_reg(d.operands[0]))
        return refuse("LDA/STL Rt is not a core register");
    if (!addr_shape_ok(d, 1)) return false;
    const int rt = arm_core_idx(d.operands[0].reg);
    if (rt == 15) return refuse("LDA/STL naming PC (UNPREDICTABLE)");
    const unsigned sz = size_of_bits(bits);

    PredScope g = pred_begin(cx, d.cc);
    const AddrVal a = mem_effective_addr(cx, d.operands[1], false, cx.tmp[0]);
    if (!a.ok) { pred_end(cx, g); return false; }
    const unsigned xp = cx.tmp[1];
    emit_host_ptr(cx, xp, a.reg);
    put(cx, ldst_excl(sz, /*o2=*/true, is_load, /*pair=*/false, /*o0=*/true,
                      kZR, kZR, xp, host_reg(rt)));
    pred_end(cx, g);
    return true;
}

// SWP / SWPB. Deprecated in ARMv6 but present in the old .so files this
// translator still has to handle. Atomically loads [Rn] into Rt and stores Rt2
// to [Rn]. A64 has no single-instruction equivalent without FEAT_LSE, so this
// is the classic LDXR/STXR retry loop, which is correct on every A64 and
// preserves SWP's atomicity.
bool xlat_swp(XlatMemCtx& cx, const cs_insn* in, int bits) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return refuse("SWP/SWPB needs 3 operands");
    if (!is_core_reg(d.operands[0]) || !is_core_reg(d.operands[1]))
        return false;
    if (!addr_shape_ok(d, 2)) return false;
    const int rt = arm_core_idx(d.operands[0].reg);
    const int rt2 = arm_core_idx(d.operands[1].reg);
    // DDI 0406C.d A8.6.722 SWP/SWPB: "if t == 15 || t2 == 15 || n == 15
    // ... then UNPREDICTABLE".
    if (rt == 15 || rt2 == 15)
        return refuse("SWP/SWPB naming PC (UNPREDICTABLE)");

    PredScope g = pred_begin(cx, d.cc);
    const AddrVal a = mem_effective_addr(cx, d.operands[2], false, cx.tmp[0]);
    if (!a.ok) { pred_end(cx, g); return false; }
    const unsigned xp = cx.tmp[1];
    emit_host_ptr(cx, xp, a.reg);

    // Capture the value to store BEFORE the loop: Rt and Rt2 are frequently
    // the same guest register (`swp r0, r0, [r1]` is the canonical idiom), and
    // the loop overwrites Rt.
    const unsigned wval = cx.tmp[0];
    put(cx, mov_reg(false, wval, host_reg(rt2)));

    const unsigned wold = cx.tmp[2];
    const unsigned wstat = cx.tmp[3];
    Label loop = cx.buf->new_label();
    cx.buf->bind(loop);
    if (bits == 8) {
        put(cx, ldxrb(wold, xp));
        put(cx, stxrb(wstat, wval, xp));
    } else {
        put(cx, ldxr(false, wold, xp));
        put(cx, stxr(false, wstat, wval, xp));
    }
    cx.buf->cbnz(false, wstat, loop);
    // SWPB zero-extends the loaded byte into Rt, which LDXRB already does.
    put(cx, mov_reg(false, host_reg(rt), wold));
    pred_end(cx, g);
    return true;
}

// PLD / PLDW / PLI. A64's PRFM has a matching extended-register form and a
// prefetch has no architectural effect, so a mistranslation here can only cost
// performance. prfop: PLDL1KEEP = 0b00000, PLIL1KEEP = 0b01000,
// PSTL1KEEP = 0b10000 ("prepare for store", which is what PLDW means).
bool xlat_prefetch(XlatMemCtx& cx, const cs_insn* in, unsigned prfop) {
    const cs_arm& d = in->detail->arm;
    const int mem_idx = find_mem_operand(d);
    if (!addr_shape_ok(d, mem_idx)) {
        // `pld [label]` and any shape we cannot address: dropping a prefetch
        // hint is always architecturally safe.
        put(cx, nop());
        return true;
    }
    PredScope g = pred_begin(cx, d.cc);
    const AddrVal a = mem_effective_addr(cx, d.operands[mem_idx], false,
                                         cx.tmp[0]);
    if (!a.ok) { pred_end(cx, g); return false; }
    // PRFM shares the load/store register-offset encoding with size = 11,
    // V = 0, opc = 10, and the prefetch operation in the Rt field.
    emit_guest_ldst(cx, kSizeX, 2u, prfop, a.reg);
    pred_end(cx, g);
    return true;
}

// Capstone's arm_mem_barrier enum is the architectural option value PLUS ONE
// (ARM_MB_ISH == 12 encodes option 0b1011), and A64 reuses the identical CRm
// option encoding, so the option passes straight through.
unsigned barrier_crm(const cs_arm& d) {
    const int mb = static_cast<int>(d.mem_barrier);
    if (mb <= 0) return 15u;  // SY when Capstone reports no option
    return static_cast<unsigned>(mb - 1) & 15u;
}

}  // namespace

// ==================================================================

bool is_mem_insn(unsigned id) {
    switch (id) {
        case ARM_INS_LDR: case ARM_INS_LDRB: case ARM_INS_LDRH:
        case ARM_INS_LDRSB: case ARM_INS_LDRSH:
        case ARM_INS_LDRT: case ARM_INS_LDRBT: case ARM_INS_LDRHT:
        case ARM_INS_LDRSBT: case ARM_INS_LDRSHT:
        case ARM_INS_STR: case ARM_INS_STRB: case ARM_INS_STRH:
        case ARM_INS_STRT: case ARM_INS_STRBT: case ARM_INS_STRHT:
        case ARM_INS_LDRD: case ARM_INS_STRD:
        case ARM_INS_LDM: case ARM_INS_LDMDA: case ARM_INS_LDMDB:
        case ARM_INS_LDMIB:
        case ARM_INS_STM: case ARM_INS_STMDA: case ARM_INS_STMDB:
        case ARM_INS_STMIB:
        case ARM_INS_PUSH: case ARM_INS_POP:
        case ARM_INS_LDREX: case ARM_INS_LDREXB: case ARM_INS_LDREXH:
        case ARM_INS_LDREXD:
        case ARM_INS_STREX: case ARM_INS_STREXB: case ARM_INS_STREXH:
        case ARM_INS_STREXD:
        case ARM_INS_LDAEX: case ARM_INS_LDAEXB: case ARM_INS_LDAEXH:
        case ARM_INS_LDAEXD:
        case ARM_INS_STLEX: case ARM_INS_STLEXB: case ARM_INS_STLEXH:
        case ARM_INS_STLEXD:
        case ARM_INS_LDA: case ARM_INS_LDAB: case ARM_INS_LDAH:
        case ARM_INS_STL: case ARM_INS_STLB: case ARM_INS_STLH:
        case ARM_INS_CLREX:
        case ARM_INS_DMB: case ARM_INS_DSB: case ARM_INS_ISB:
        case ARM_INS_SWP: case ARM_INS_SWPB:
        case ARM_INS_PLD: case ARM_INS_PLDW: case ARM_INS_PLI:
            return true;
        default:
            return false;
    }
}

bool translate_mem(XlatMemCtx& cx, const cs_insn* in, XlatResult* result) {
    if (result) *result = XlatResult{};
    if (!in || !in->detail || !cx.buf) return false;
    if (!is_mem_insn(in->id)) return false;

    const cs_arm& d = in->detail->arm;
    bool ok = false;
    g_mem_refuse = nullptr;

    switch (in->id) {
        // ---- single-register load / store -------------------------
        case ARM_INS_LDR: case ARM_INS_LDRT:
            ok = xlat_ldst_single(cx, in, 32, true, false, result); break;
        case ARM_INS_LDRB: case ARM_INS_LDRBT:
            ok = xlat_ldst_single(cx, in, 8, true, false, result); break;
        case ARM_INS_LDRH: case ARM_INS_LDRHT:
            ok = xlat_ldst_single(cx, in, 16, true, false, result); break;
        case ARM_INS_LDRSB: case ARM_INS_LDRSBT:
            ok = xlat_ldst_single(cx, in, 8, true, true, result); break;
        case ARM_INS_LDRSH: case ARM_INS_LDRSHT:
            ok = xlat_ldst_single(cx, in, 16, true, true, result); break;
        case ARM_INS_STR: case ARM_INS_STRT:
            ok = xlat_ldst_single(cx, in, 32, false, false, result); break;
        case ARM_INS_STRB: case ARM_INS_STRBT:
            ok = xlat_ldst_single(cx, in, 8, false, false, result); break;
        case ARM_INS_STRH: case ARM_INS_STRHT:
            ok = xlat_ldst_single(cx, in, 16, false, false, result); break;

        case ARM_INS_LDRD: ok = xlat_ldrd_strd(cx, in, true); break;
        case ARM_INS_STRD: ok = xlat_ldrd_strd(cx, in, false); break;

        // ---- multi-register load / store --------------------------
        case ARM_INS_LDM:
            ok = xlat_ldm_stm(cx, in, true, +1, 0, -1, false, result); break;
        case ARM_INS_LDMIB:
            ok = xlat_ldm_stm(cx, in, true, +1, 1, -1, false, result); break;
        case ARM_INS_LDMDA:
            ok = xlat_ldm_stm(cx, in, true, -1, 0, -1, false, result); break;
        case ARM_INS_LDMDB:
            ok = xlat_ldm_stm(cx, in, true, -1, 1, -1, false, result); break;
        case ARM_INS_STM:
            ok = xlat_ldm_stm(cx, in, false, +1, 0, -1, false, result); break;
        case ARM_INS_STMIB:
            ok = xlat_ldm_stm(cx, in, false, +1, 1, -1, false, result); break;
        case ARM_INS_STMDA:
            ok = xlat_ldm_stm(cx, in, false, -1, 0, -1, false, result); break;
        case ARM_INS_STMDB:
            ok = xlat_ldm_stm(cx, in, false, -1, 1, -1, false, result); break;
        // POP {..} == LDMIA SP!, {..} and PUSH {..} == STMDB SP!, {..}.
        // Capstone reports these with the register list only, so the base
        // (guest SP) and the writeback are supplied here.
        case ARM_INS_POP:
            ok = xlat_ldm_stm(cx, in, true, +1, 0, kSP, true, result); break;
        case ARM_INS_PUSH:
            ok = xlat_ldm_stm(cx, in, false, -1, 1, kSP, true, result); break;

        // ---- exclusives and ordered accesses ----------------------
        case ARM_INS_LDREX:
            ok = xlat_exclusive(cx, in, 32, true, false, false); break;
        case ARM_INS_LDREXB:
            ok = xlat_exclusive(cx, in, 8, true, false, false); break;
        case ARM_INS_LDREXH:
            ok = xlat_exclusive(cx, in, 16, true, false, false); break;
        case ARM_INS_LDREXD:
            ok = xlat_exclusive(cx, in, 32, true, true, false); break;
        case ARM_INS_STREX:
            ok = xlat_exclusive(cx, in, 32, false, false, false); break;
        case ARM_INS_STREXB:
            ok = xlat_exclusive(cx, in, 8, false, false, false); break;
        case ARM_INS_STREXH:
            ok = xlat_exclusive(cx, in, 16, false, false, false); break;
        case ARM_INS_STREXD:
            ok = xlat_exclusive(cx, in, 32, false, true, false); break;
        case ARM_INS_LDAEX:
            ok = xlat_exclusive(cx, in, 32, true, false, true); break;
        case ARM_INS_LDAEXB:
            ok = xlat_exclusive(cx, in, 8, true, false, true); break;
        case ARM_INS_LDAEXH:
            ok = xlat_exclusive(cx, in, 16, true, false, true); break;
        case ARM_INS_LDAEXD:
            ok = xlat_exclusive(cx, in, 32, true, true, true); break;
        case ARM_INS_STLEX:
            ok = xlat_exclusive(cx, in, 32, false, false, true); break;
        case ARM_INS_STLEXB:
            ok = xlat_exclusive(cx, in, 8, false, false, true); break;
        case ARM_INS_STLEXH:
            ok = xlat_exclusive(cx, in, 16, false, false, true); break;
        case ARM_INS_STLEXD:
            ok = xlat_exclusive(cx, in, 32, false, true, true); break;
        case ARM_INS_LDA:  ok = xlat_acq_rel(cx, in, 32, true); break;
        case ARM_INS_LDAB: ok = xlat_acq_rel(cx, in, 8, true); break;
        case ARM_INS_LDAH: ok = xlat_acq_rel(cx, in, 16, true); break;
        case ARM_INS_STL:  ok = xlat_acq_rel(cx, in, 32, false); break;
        case ARM_INS_STLB: ok = xlat_acq_rel(cx, in, 8, false); break;
        case ARM_INS_STLH: ok = xlat_acq_rel(cx, in, 16, false); break;

        // ---- barriers ---------------------------------------------
        case ARM_INS_CLREX: put(cx, clrex()); ok = true; break;
        case ARM_INS_DSB:   put(cx, dsb(barrier_crm(d))); ok = true; break;
        case ARM_INS_DMB:   put(cx, dmb(barrier_crm(d))); ok = true; break;
        case ARM_INS_ISB:   put(cx, isb(barrier_crm(d))); ok = true; break;

        // ---- deprecated swap --------------------------------------
        case ARM_INS_SWP:  ok = xlat_swp(cx, in, 32); break;
        case ARM_INS_SWPB: ok = xlat_swp(cx, in, 8); break;

        // ---- prefetch hints ---------------------------------------
        case ARM_INS_PLD:  ok = xlat_prefetch(cx, in, 0x00); break;
        case ARM_INS_PLDW: ok = xlat_prefetch(cx, in, 0x10); break;
        case ARM_INS_PLI:  ok = xlat_prefetch(cx, in, 0x08); break;

        default:
            return false;
    }

    if (!ok)
        rc_stub_trace(cx.insn_addr, cx.is_thumb, in, "mem-refuse",
                      g_mem_refuse);
    if (result) result->handled = ok;
    return ok;
}

}  // namespace arm32rc
}  // namespace macapk
