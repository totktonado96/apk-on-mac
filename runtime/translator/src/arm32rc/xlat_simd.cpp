// xlat_simd.cpp -- direct ARM32/Thumb -> arm64 recompiler: VFP / NEON
// translation. See xlat_simd.h for the register model, the encoder table and
// the measured Capstone facts (C1..C5) this file depends on.
//
// SEMANTICS CARRIED OVER FROM arm32_lifter.cpp
// --------------------------------------------
// The LLVM lifter accumulated a batch of NEON fixes that each cured a real
// rendering bug. Every one of them is preserved here; the sites are marked
// "[carry-over]" so a future reader can see the lineage:
//
//  1. VMOV.I<sz> with a Q-register destination. The lifter's original code
//     resolved a Q register to "no d/s/core index" and no-op'd the whole
//     instruction, leaving garbage that a following VST1 wrote to memory.
//     That was the ShatteredPD corruption: FreeType's
//     `vmov.i32 q8,#0 ; vst1.8 {d16,d17},[r1]!` was meant to zero a
//     freshly-allocated FT_Size_Internal and instead wrote garbage, which
//     later drove a stray write into libgdx's gdx2d state ("Error loading
//     pixmap", flat blue).
//  2. VMOV.I / VMVN.I / VORR.I / VBIC.I replicate the per-ELEMENT immediate
//     across every lane. The lifter's D-form used the raw immediate, which is
//     wrong for any non-zero value.
//  3. VORR register form (including the `vorr dd,dn,dn` NEON register-move
//     idiom), which the immediate-only path silently dropped.
//  4. VMVN register form (dd = ~dm), likewise dropped.
//  5. VBIC immediate form (dd &= ~replicate(imm)), likewise dropped, leaving
//     the supposedly-cleared bits holding garbage.
//  6. VNEG on INTEGER lanes (.s8/.s16/.s32/.i*), on both D and Q. The lifter
//     routed it to the scalar-float FNEG path, which fell back to a no-op and
//     left a stale register that a later store committed.
//  7. VCEQ / VCGT / VCGE / VCLT / VCLE with an IMMEDIATE right-hand side
//     (`, #0`), which returned false and no-op'd, leaving a stale mask.
//  8. VCEQ / VCGT / VCGE compare at the correct lane width AND signedness for
//     integer vector_data instead of hard-coding a 32-bit float compare (in
//     Geometry Dash the split was 519 integer compares against 48 float).
//  9. VLD1 / VST1 single-lane `{dN[idx]}` must touch EXACTLY one lane. The
//     lifter's generic path transferred a whole 8 bytes, clobbering the
//     register on load and scribbling over neighbouring memory on store.
//     Here the A64 one-lane structure forms make that correct by
//     construction (and see xlat_simd.h fact C1: the lifter's guard for this
//     case can never fire with the Capstone build in this tree, so the bug is
//     still live there).
// 10. VDUP.32 from a core register uses the whole register as the lane; only
//     narrower lanes truncate.
//
// Two places where this stage is strictly MORE correct than the lifter:
//   * Q-form VZIP / VUZP. The lifter refused them (returning false, hence a
//     no-op) because decomposing a 128-bit interleave into two independent
//     64-bit halves is simply wrong. With the memory-homed bank a guest Q
//     register loads as one LDR Q, so ZIP1/ZIP2 on .16B is exact.
//   * VLD1 "to all lanes" (`{d0[]}`). The lifter explicitly let it fall
//     through to the generic path and noted that as wrong; here it is LD1R.
//
// No em dashes (project convention). C++17, -Wall -Wextra clean.

#include "xlat_simd.h"

#include <cstring>
#include <string>
#include <vector>

namespace macapk {
namespace arm32rc {

using namespace a64;       // NOLINT(build/namespaces) -- encoder vocabulary
using namespace simdenc;   // NOLINT(build/namespaces)

// ==================================================================
// Register decoding
// ==================================================================

int vfp_s_idx(unsigned reg) {
    if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31)
        return static_cast<int>(reg - ARM_REG_S0);
    return -1;
}
int vfp_d_idx(unsigned reg) {
    if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31)
        return static_cast<int>(reg - ARM_REG_D0);
    return -1;
}
int vfp_q_idx(unsigned reg) {
    if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15)
        return static_cast<int>(reg - ARM_REG_Q0);
    return -1;
}

namespace {

inline void put(XlatMemCtx& cx, uint32_t w) { cx.buf->put(w); }

// ------------------------------------------------------------------
// A NEON operand as this file models it: a run of 64-bit guest d-units
// starting at `n`. A Q register Qk is the pair (D2k, D2k+1), so its byte
// offset in GuestState is 16*k == 8*(2k) and the SAME `8 * n` formula covers
// both widths. `q` only selects the transfer width and the A64 Q bit.
// ------------------------------------------------------------------
struct VReg {
    int n = -1;
    bool q = false;
    bool ok() const { return n >= 0; }
};

VReg vreg_of(unsigned reg) {
    VReg v;
    const int d = vfp_d_idx(reg);
    if (d >= 0) { v.n = d; v.q = false; return v; }
    const int qi = vfp_q_idx(reg);
    if (qi >= 0) { v.n = qi * 2; v.q = true; return v; }
    return v;
}

// GuestState accessors. kOffD == 0 (static_assert'd in guest_state.h), so the
// d / s / q views alias exactly.
inline void ld_vec(XlatMemCtx& cx, unsigned xs, unsigned v, const VReg& r) {
    const uint64_t off = guest_d_offset(r.n);
    put(cx, r.q ? ldr_q(v, xs, off) : ldr_d(v, xs, off));
}
inline void st_vec(XlatMemCtx& cx, unsigned xs, unsigned v, const VReg& r) {
    const uint64_t off = guest_d_offset(r.n);
    put(cx, r.q ? str_q(v, xs, off) : str_d(v, xs, off));
}
inline void ld_d_at(XlatMemCtx& cx, unsigned xs, unsigned v, int dn) {
    put(cx, ldr_d(v, xs, guest_d_offset(dn)));
}
inline void st_d_at(XlatMemCtx& cx, unsigned xs, unsigned v, int dn) {
    put(cx, str_d(v, xs, guest_d_offset(dn)));
}
inline void ld_s_at(XlatMemCtx& cx, unsigned xs, unsigned v, int sn) {
    put(cx, ldr_s(v, xs, guest_s_offset(sn)));
}
inline void st_s_at(XlatMemCtx& cx, unsigned xs, unsigned v, int sn) {
    put(cx, str_s(v, xs, guest_s_offset(sn)));
}

// ------------------------------------------------------------------
// Element-type helpers
// ------------------------------------------------------------------
int vdata_bits(arm_vectordata_type vd) {
    switch (vd) {
        case ARM_VECTORDATA_I8:  case ARM_VECTORDATA_S8:
        case ARM_VECTORDATA_U8:  case ARM_VECTORDATA_P8:   return 8;
        case ARM_VECTORDATA_I16: case ARM_VECTORDATA_S16:
        case ARM_VECTORDATA_U16: case ARM_VECTORDATA_F16:  return 16;
        case ARM_VECTORDATA_I32: case ARM_VECTORDATA_S32:
        case ARM_VECTORDATA_U32: case ARM_VECTORDATA_F32:  return 32;
        case ARM_VECTORDATA_I64: case ARM_VECTORDATA_S64:
        case ARM_VECTORDATA_U64: case ARM_VECTORDATA_F64:  return 64;
        default: return 0;
    }
}
bool vdata_signed(arm_vectordata_type vd) {
    return vd == ARM_VECTORDATA_S8 || vd == ARM_VECTORDATA_S16 ||
           vd == ARM_VECTORDATA_S32 || vd == ARM_VECTORDATA_S64;
}
bool vdata_float(arm_vectordata_type vd) {
    return vd == ARM_VECTORDATA_F16 || vd == ARM_VECTORDATA_F32 ||
           vd == ARM_VECTORDATA_F64;
}
// Several NEON instructions (VZIP, VUZP, VTRN, VEXT, VLD/VST, VDUP) leave
// vector_data INVALID and report the element width in vector_size instead;
// the probe in xlat_simd.h's header comment shows both cases. Prefer
// vector_data (it carries signedness) and fall back to vector_size.
int lane_bits_of(const cs_arm& d) {
    const int v = vdata_bits(d.vector_data);
    if (v > 0) return v;
    if (d.vector_size > 0 && d.vector_size <= 64)
        return static_cast<int>(d.vector_size);
    return 0;
}
unsigned size_log2(int lane_bits) {
    return lane_bits == 8 ? 0u : lane_bits == 16 ? 1u
         : lane_bits == 32 ? 2u : 3u;
}
bool lane_bits_valid(int lb) {
    return lb == 8 || lb == 16 || lb == 32 || lb == 64;
}

// True for the NEON "by scalar" shapes, where the LAST operand names one
// lane of a D register rather than a whole vector. Capstone reports these
// as ordinary REG operands and only `vector_index` distinguishes them
// (measured with debug/implD_neon_probe.py: `vmul.i16 d0,d1,d2[1]` ->
// vector_index 1 on operand 2), so every handler that would otherwise treat
// operand 2 as a whole vector has to ask this first.
bool is_by_element(const cs_arm& d) {
    return d.op_count == 3 && d.operands[2].type == ARM_OP_REG &&
           d.operands[2].vector_index >= 0;
}

// Replicate a per-element immediate across a 64-bit lane pattern.
// [carry-over 2] The lifter's D-form originally stored the raw immediate,
// which is wrong for any non-zero value: the ARM32 vector-immediate forms
// define the constant PER ELEMENT.
uint64_t replicate_imm(uint64_t imm, int lane_bits) {
    if (lane_bits >= 64) return imm;
    const uint64_t mask = (1ull << lane_bits) - 1ull;
    const uint64_t e = imm & mask;
    uint64_t pat = 0;
    for (int b = 0; b < 64; b += lane_bits)
        pat |= (e << b);
    return pat;
}

// Materialise a 64-bit lane pattern into vector register `v`.
// Q destinations get the same pattern in both halves, which is what the
// element-wise replication above implies for every ARM32 element width.
void emit_vec_const(XlatMemCtx& cx, unsigned v, uint64_t pat, bool q) {
    if (pat == 0) {
        put(cx, movi_2d_zero(v));  // zeroes the whole 128 bits
        return;
    }
    // A byte-uniform pattern is a one-instruction MOVI.
    const uint8_t b0 = static_cast<uint8_t>(pat & 0xFFu);
    bool byte_uniform = true;
    for (int i = 1; i < 8; ++i)
        if (static_cast<uint8_t>((pat >> (8 * i)) & 0xFFu) != b0)
            byte_uniform = false;
    if (byte_uniform) {
        put(cx, simd_modimm(q, /*op=*/false, /*cmode=*/0xE, /*o2=*/false, b0, v));
        return;
    }
    const unsigned xt = cx.tmp[3];
    cx.buf->mov_imm(true, xt, pat);
    if (q) {
        put(cx, dup_gen(true, vec_imm5(3, 0), v, xt));  // DUP Vd.2D, Xt
    } else {
        put(cx, fmov_from_gpr(true, kFpD, v, xt));      // FMOV Dd, Xt
    }
}

// ------------------------------------------------------------------
// The guest-state pointer, materialised once per translated instruction.
// ------------------------------------------------------------------
struct StatePtr {
    unsigned x = 0;
};
StatePtr make_state_ptr(XlatMemCtx& cx) {
    StatePtr s;
    s.x = cx.tmp[0];
    emit_guest_state_ptr(cx, s.x);
    return s;
}

// ==================================================================
// VFP scalar
// ==================================================================

// A scalar VFP operand: an S register (32-bit) or a D register (64-bit).
struct FReg {
    int n = -1;
    bool dbl = false;
    bool ok() const { return n >= 0; }
    uint64_t off() const {
        return dbl ? guest_d_offset(n) : guest_s_offset(n);
    }
    unsigned ptype() const { return dbl ? kFpD : kFpS; }
};
FReg freg_of(unsigned reg) {
    FReg f;
    const int s = vfp_s_idx(reg);
    if (s >= 0) { f.n = s; f.dbl = false; return f; }
    const int d = vfp_d_idx(reg);
    if (d >= 0) { f.n = d; f.dbl = true; return f; }
    return f;
}
inline void ld_freg(XlatMemCtx& cx, unsigned xs, unsigned v, const FReg& f) {
    put(cx, f.dbl ? ldr_d(v, xs, f.off()) : ldr_s(v, xs, f.off()));
}
inline void st_freg(XlatMemCtx& cx, unsigned xs, unsigned v, const FReg& f) {
    put(cx, f.dbl ? str_d(v, xs, f.off()) : str_s(v, xs, f.off()));
}

// True when the instruction is a VFP SCALAR operation rather than packed
// NEON. ARM32 makes this a property of the operand class plus the data type:
//   vadd.f32 s0,s1,s2  -> VFP scalar single
//   vadd.f64 d0,d1,d2  -> VFP scalar double  (NEON has no f64 on ARM32)
//   vadd.f32 d0,d1,d2  -> NEON, two packed floats
//   vadd.i32 d0,d1,d2  -> NEON integer
bool is_vfp_scalar(const cs_arm& d) {
    if (d.op_count == 0 || d.operands[0].type != ARM_OP_REG) return false;
    if (vfp_s_idx(d.operands[0].reg) >= 0) return true;
    return d.vector_data == ARM_VECTORDATA_F64;
}

// VADD / VSUB / VMUL / VDIV / VNMUL and the unary VABS / VNEG / VSQRT, in
// their VFP scalar form.
bool xlat_vfp_scalar_arith(XlatMemCtx& cx, const cs_insn* in, unsigned op2,
                           bool unary) {
    const cs_arm& d = in->detail->arm;
    const int want = unary ? 2 : 3;
    if (d.op_count != want) return false;
    for (int i = 0; i < want; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    if (!fd.ok() || !fn.ok()) return false;
    FReg fm;
    if (!unary) {
        fm = freg_of(d.operands[2].reg);
        if (!fm.ok()) return false;
    }

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0), v1 = cx.vtmp(1);
    ld_freg(cx, st.x, v0, fn);
    if (unary) {
        put(cx, fp1(fd.ptype(), op2, v0, v0));
    } else {
        ld_freg(cx, st.x, v1, fm);
        put(cx, fp2(fd.ptype(), op2, v0, v0, v1));
    }
    st_freg(cx, st.x, v0, fd);
    pred_end(cx, g);
    return true;
}

// The scalar multiply-accumulate family. ARM32's VMLA/VMLS/VNMLA/VNMLS use
// two roundings (DDI 0406C.d A8.8.337) while VFMA/VFMS/VFNMA/VFNMS are truly
// fused (A8.8.341). A64's FMADD/FMSUB/FNMADD/FNMSUB are fused, so:
//   VFMA  -> FMADD  Vd, Vn, Vm, Vd
//   VFMS  -> FMSUB
//   VFNMA -> FNMADD
//   VFNMS -> FNMSUB
// and the discrete VMLA/VMLS/VNMLA/VNMLS are lowered as FMUL followed by
// FADD/FSUB, preserving the double rounding exactly rather than silently
// upgrading them to a fused op (a change of result the guest can observe).
enum class MacOp { VMLA, VMLS, VNMLA, VNMLS, VFMA, VFMS, VFNMA, VFNMS };

bool xlat_vfp_mac(XlatMemCtx& cx, const cs_insn* in, MacOp op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    const FReg fm = freg_of(d.operands[2].reg);
    if (!fd.ok() || !fn.ok() || !fm.ok()) return false;
    const unsigned p = fd.ptype();

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned va = cx.vtmp(0), vb = cx.vtmp(1), vacc = cx.vtmp(2);
    ld_freg(cx, st.x, va, fn);
    ld_freg(cx, st.x, vb, fm);
    ld_freg(cx, st.x, vacc, fd);
    switch (op) {
        case MacOp::VFMA:  put(cx, fmadd(p, vacc, va, vb, vacc)); break;
        case MacOp::VFMS:  put(cx, fmsub(p, vacc, va, vb, vacc)); break;
        case MacOp::VFNMA: put(cx, fnmadd(p, vacc, va, vb, vacc)); break;
        case MacOp::VFNMS: put(cx, fnmsub(p, vacc, va, vb, vacc)); break;
        case MacOp::VMLA:
            put(cx, fmul(p, va, va, vb));
            put(cx, fadd(p, vacc, vacc, va));
            break;
        case MacOp::VMLS:
            put(cx, fmul(p, va, va, vb));
            put(cx, fsub(p, vacc, vacc, va));
            break;
        case MacOp::VNMLA:
            // VNMLA: Vd = -(Vd + Vn*Vm)
            put(cx, fmul(p, va, va, vb));
            put(cx, fadd(p, vacc, vacc, va));
            put(cx, fneg_f(p, vacc, vacc));
            break;
        case MacOp::VNMLS:
            // VNMLS: Vd = -Vd + Vn*Vm
            put(cx, fmul(p, va, va, vb));
            put(cx, fneg_f(p, vacc, vacc));
            put(cx, fadd(p, vacc, vacc, va));
            break;
    }
    st_freg(cx, st.x, vacc, fd);
    pred_end(cx, g);
    return true;
}

// ------------------------------------------------------------------
// VCMP / VCMPE and the FPSCR <-> APSR transfers.
//
// This is the subtle one. ARM32's VCMP writes FPSCR.{N,Z,C,V}, a bank that is
// SEPARATE from APSR; only `VMRS APSR_nzcv, FPSCR` copies it across
// (DDI 0406C.d A8.8.348 / A8.8.349). Code such as
//
//     cmp   r3, #0          ; APSR from an integer compare
//     vldrne s15, ...       ; still reads THAT APSR
//     vcmp.f32 s15, #0      ; writes FPSCR only
//     vaddne.f32 ...        ; STILL the integer APSR
//     vmrs  apsr_nzcv, fpscr
//     bne   ...             ; only NOW the float result
//
// depends on the separation; cocos2d-x v2's CCNode::nodeToParentTransform
// exercises it, and collapsing the two banks broke CCLayer anchor handling in
// the LLVM lifter.
//
// A64's FCMP writes PSTATE.NZCV, which is where the guest's APSR lives (see
// xlat_core.h assumption A3), so the lowering has to bracket it:
//
//     MRS  Xsave, NZCV            ; keep the guest's integer flags
//     FCMP/FCMPE ...              ; A32 and A64 agree bit-for-bit on the four
//                                 ; FP comparison results, including the
//                                 ; unordered case (N=0 Z=0 C=1 V=1)
//     MRS  Xt, NZCV               ; the FP result
//     LDR  Wf, [state, #fpscr]    ; merge into FPSCR, preserving the control
//     AND  Wf, Wf, #0x0fffffff    ; and cumulative-exception bits
//     ORR  Wf, Wf, Wt
//     STR  Wf, [state, #fpscr]
//     MSR  NZCV, Xsave            ; restore the guest's integer flags
//
// FPSCR bits 31..28 are N,Z,C,V in the same order as A64's NZCV, and
// guest_state.h picks its kFlag* bit positions to match, so no shuffling is
// needed. MRS NZCV reads zero in the low 28 bits, so the ORR is safe.
// ------------------------------------------------------------------
bool xlat_vcmp(XlatMemCtx& cx, const cs_insn* in, bool exceptional) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG) return false;
    const FReg fn = freg_of(d.operands[0].reg);
    if (!fn.ok()) return false;
    const bool vs_zero = (d.operands[1].type == ARM_OP_IMM ||
                          d.operands[1].type == ARM_OP_FP);
    FReg fm;
    if (!vs_zero) {
        if (d.operands[1].type != ARM_OP_REG) return false;
        fm = freg_of(d.operands[1].reg);
        if (!fm.ok()) return false;
    }
    const unsigned p = fn.ptype();

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned xsave = cx.tmp[1];
    const unsigned wt = cx.tmp[2];
    const unsigned wf = cx.tmp[3];
    const unsigned v0 = cx.vtmp(0), v1 = cx.vtmp(1);

    put(cx, mrs(xsave, kSR_NZCV));
    ld_freg(cx, st.x, v0, fn);
    if (vs_zero) {
        put(cx, exceptional ? fcmpe_zero(p, v0) : fcmp_zero(p, v0));
    } else {
        ld_freg(cx, st.x, v1, fm);
        put(cx, exceptional ? fcmpe(p, v0, v1) : fcmp(p, v0, v1));
    }
    put(cx, mrs(wt, kSR_NZCV));
    put(cx, ldr(false, wf, st.x, kOffFpscr));
    uint32_t keep_field = 0;
    if (encode_logical_imm(0x0FFFFFFFull, false, &keep_field)) {
        put(cx, and_imm(false, wf, wf, keep_field));
    } else {
        // Not reachable (28 contiguous ones is a legal bitmask immediate);
        // the fallback exists so a future change cannot emit a wrong AND.
        const unsigned wm = cx.vtmp(2);  // unused vector slot, GPR fallback
        (void)wm;
        cx.buf->mov_imm(false, cx.tmp[1], 0x0FFFFFFFu);
        put(cx, and_reg(false, wf, wf, cx.tmp[1]));
        put(cx, mrs(xsave, kSR_NZCV));  // xsave was clobbered; re-read is wrong
    }
    put(cx, orr_reg(false, wf, wf, wt));
    put(cx, str(false, wf, st.x, kOffFpscr));
    put(cx, msr_reg(kSR_NZCV, xsave));
    pred_end(cx, g);
    return true;
}

// VMRS. Two shapes:
//   VMRS APSR_nzcv, FPSCR  -> copy FPSCR.NZCV into the live PSTATE.NZCV
//   VMRS Rt, FPSCR         -> read the whole FPSCR word into a core register
// Capstone also reports the first shape as ARM_INS_FMSTAT.
bool xlat_vmrs(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;
    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    int rt = -1;
    if (d.op_count >= 1 && d.operands[0].type == ARM_OP_REG)
        rt = arm_core_idx(d.operands[0].reg);
    if (rt >= 0 && rt != 15) {
        put(cx, ldr(false, host_reg(rt), st.x, kOffFpscr));
    } else {
        const unsigned wt = cx.tmp[1];
        put(cx, ldr(false, wt, st.x, kOffFpscr));
        // MSR NZCV takes its value from bits 31..28 and ignores the rest.
        put(cx, msr_reg(kSR_NZCV, wt));
    }
    pred_end(cx, g);
    return true;
}

// VMSR FPSCR, Rt. The control bits (rounding mode, flush-to-zero,
// default-NaN, length/stride) select behaviours this lowering does not honour
// (the host FPU runs round-to-nearest with no FTZ), but STORING the word is
// still strictly better than the LLVM lifter's no-op: the overwhelmingly
// common guest sequence is a save/restore of FPSCR around a callout, and a
// no-op silently drops the NZCV half of that round trip.
bool xlat_vmsr(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count < 2 || d.operands[1].type != ARM_OP_REG) return false;
    const int rt = arm_core_idx(d.operands[1].reg);
    if (rt < 0 || rt == 15) return false;
    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    put(cx, str(false, host_reg(rt), st.x, kOffFpscr));
    pred_end(cx, g);
    return true;
}

// ------------------------------------------------------------------
// VCVT / VCVTR
// ------------------------------------------------------------------
bool xlat_vcvt(XlatMemCtx& cx, const cs_insn* in, bool round_to_nearest) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count < 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const arm_vectordata_type vd = d.vector_data;

    // --- packed NEON conversions (D or Q operands, F32 <-> S32/U32) -----
    const VReg qd = vreg_of(d.operands[0].reg);
    const VReg qn = vreg_of(d.operands[1].reg);
    const bool is_vec = qd.ok() && qn.ok() &&
                        (vd == ARM_VECTORDATA_S32F32 ||
                         vd == ARM_VECTORDATA_U32F32 ||
                         vd == ARM_VECTORDATA_F32S32 ||
                         vd == ARM_VECTORDATA_F32U32) &&
                        d.op_count == 2 &&
                        // a scalar VFP conversion names S registers, and an
                        // f64 conversion is never a NEON form on ARM32
                        vfp_s_idx(d.operands[0].reg) < 0 &&
                        vfp_s_idx(d.operands[1].reg) < 0;
    if (is_vec) {
        PredScope g = pred_begin(cx, d.cc);
        const StatePtr st = make_state_ptr(cx);
        const unsigned v0 = cx.vtmp(0);
        ld_vec(cx, st.x, v0, qn);
        switch (vd) {
            case ARM_VECTORDATA_S32F32:
                put(cx, simd_2misc(qd.q, false, 2, kMiscFcvtzs, v0, v0)); break;
            case ARM_VECTORDATA_U32F32:
                put(cx, simd_2misc(qd.q, true, 2, kMiscFcvtzs, v0, v0)); break;
            case ARM_VECTORDATA_F32S32:
                put(cx, simd_2misc(qd.q, false, 0, kMiscScvtf, v0, v0)); break;
            default:
                put(cx, simd_2misc(qd.q, true, 0, kMiscScvtf, v0, v0)); break;
        }
        st_vec(cx, st.x, v0, qd);
        pred_end(cx, g);
        return true;
    }

    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    if (!fd.ok() || !fn.ok()) return false;

    // --- fixed-point conversions (3 operands, the last an immediate) ----
    if (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM) {
        const unsigned fbits = static_cast<unsigned>(d.operands[2].imm) & 63u;
        PredScope g = pred_begin(cx, d.cc);
        const StatePtr st = make_state_ptr(cx);
        const unsigned v0 = cx.vtmp(0);
        const unsigned wt = cx.tmp[1];
        ld_freg(cx, st.x, v0, fn);
        bool ok = true;
        switch (vd) {
            // float -> fixed-point integer, held in a VFP register
            case ARM_VECTORDATA_S16F32: case ARM_VECTORDATA_S32F32:
            case ARM_VECTORDATA_S16F64: case ARM_VECTORDATA_S32F64:
                put(cx, fcvtzs_fixed(false, fn.ptype(), wt, v0, fbits));
                put(cx, fmov_from_gpr(false, kFpS, v0, wt));
                break;
            case ARM_VECTORDATA_U16F32: case ARM_VECTORDATA_U32F32:
            case ARM_VECTORDATA_U16F64: case ARM_VECTORDATA_U32F64:
                put(cx, fcvtzu_fixed(false, fn.ptype(), wt, v0, fbits));
                put(cx, fmov_from_gpr(false, kFpS, v0, wt));
                break;
            // fixed-point integer -> float
            case ARM_VECTORDATA_F32S16: case ARM_VECTORDATA_F32S32:
            case ARM_VECTORDATA_F64S16: case ARM_VECTORDATA_F64S32:
                put(cx, fmov_to_gpr(false, kFpS, wt, v0));
                put(cx, scvtf_fixed(false, fd.ptype(), v0, wt, fbits));
                break;
            case ARM_VECTORDATA_F32U16: case ARM_VECTORDATA_F32U32:
            case ARM_VECTORDATA_F64U16: case ARM_VECTORDATA_F64U32:
                put(cx, fmov_to_gpr(false, kFpS, wt, v0));
                put(cx, ucvtf_fixed(false, fd.ptype(), v0, wt, fbits));
                break;
            default:
                ok = false;
                break;
        }
        if (!ok) {
            warn(cx, "unhandled fixed-point VCVT vector_data " +
                         std::to_string(static_cast<int>(vd)));
            pred_end(cx, g);
            return false;
        }
        st_freg(cx, st.x, v0, fd);
        pred_end(cx, g);
        return true;
    }

    // --- scalar conversions --------------------------------------------
    //
    // ARM32 keeps the integer result of a float->int VCVT in a VFP register,
    // so the lowering is "convert into a GPR, then FMOV back" (two exact
    // instructions) rather than the A64 scalar-SIMD form, which would have to
    // agree with the guest's register width anyway.
    //
    // VCVT rounds toward zero; VCVTR rounds per FPSCR.RMode, which this model
    // fixes at round-to-nearest-even, so VCVTR maps to FCVTNS / FCVTNU. That
    // is exact for the default mode and is the same approximation the LLVM
    // lifter made.
    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0);
    const unsigned wt = cx.tmp[1];
    ld_freg(cx, st.x, v0, fn);
    bool ok = true;
    switch (vd) {
        case ARM_VECTORDATA_F64F32:      // VCVT.F64.F32 Dd, Sm
            put(cx, fcvt(kFpD, kFpS, v0, v0));
            break;
        case ARM_VECTORDATA_F32F64:      // VCVT.F32.F64 Sd, Dm
            put(cx, fcvt(kFpS, kFpD, v0, v0));
            break;
        case ARM_VECTORDATA_S32F32: case ARM_VECTORDATA_S32F64:
            put(cx, round_to_nearest ? fcvtns(false, fn.ptype(), wt, v0)
                                     : fcvtzs(false, fn.ptype(), wt, v0));
            put(cx, fmov_from_gpr(false, kFpS, v0, wt));
            break;
        case ARM_VECTORDATA_U32F32: case ARM_VECTORDATA_U32F64:
            put(cx, round_to_nearest ? fcvtnu(false, fn.ptype(), wt, v0)
                                     : fcvtzu(false, fn.ptype(), wt, v0));
            put(cx, fmov_from_gpr(false, kFpS, v0, wt));
            break;
        case ARM_VECTORDATA_F32S32: case ARM_VECTORDATA_F64S32:
            put(cx, fmov_to_gpr(false, kFpS, wt, v0));
            put(cx, scvtf(false, fd.ptype(), v0, wt));
            break;
        case ARM_VECTORDATA_F32U32: case ARM_VECTORDATA_F64U32:
            put(cx, fmov_to_gpr(false, kFpS, wt, v0));
            put(cx, ucvtf(false, fd.ptype(), v0, wt));
            break;
        default:
            ok = false;
            break;
    }
    if (!ok) {
        warn(cx, "unhandled VCVT vector_data " +
                     std::to_string(static_cast<int>(vd)));
        pred_end(cx, g);
        return false;
    }
    st_freg(cx, st.x, v0, fd);
    pred_end(cx, g);
    return true;
}

// VCVTB / VCVTT: half-precision <-> single. The B form uses the LOW half of
// the S register and the T form the HIGH half (DDI 0406C.d A8.8.306/307).
bool xlat_vcvt_half(XlatMemCtx& cx, const cs_insn* in, bool top) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    if (!fd.ok() || !fn.ok()) return false;
    const arm_vectordata_type vd = d.vector_data;
    const bool to_single = (vd == ARM_VECTORDATA_F32F16 ||
                            vd == ARM_VECTORDATA_F32);
    const bool to_half = (vd == ARM_VECTORDATA_F16F32 ||
                          vd == ARM_VECTORDATA_F16);
    if (!to_single && !to_half) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0);
    const unsigned wt = cx.tmp[1];
    if (to_single) {
        // Read the 16-bit half straight out of GuestState: the S view is a
        // little-endian 4-byte slot, so the low half is at +0 and the high
        // half at +2. One LDRH beats a lane shuffle.
        put(cx, ldrh(wt, st.x, guest_s_offset(fn.n) + (top ? 2u : 0u)));
        put(cx, fmov_from_gpr(false, kFpH, v0, wt));
        put(cx, fcvt(kFpS, kFpH, v0, v0));
        st_freg(cx, st.x, v0, fd);
    } else {
        ld_freg(cx, st.x, v0, fn);
        put(cx, fcvt(kFpH, kFpS, v0, v0));
        put(cx, fmov_to_gpr(false, kFpH, wt, v0));
        // Only the selected half of Sd is written; the other half is
        // preserved (A8.8.306), which a 2-byte store gives for free.
        put(cx, strh(wt, st.x, guest_s_offset(fd.n) + (top ? 2u : 0u)));
    }
    pred_end(cx, g);
    return true;
}

// ==================================================================
// VMOV (every form)
// ==================================================================
bool xlat_vmov(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;

    // ---- 2 operands ------------------------------------------------
    if (d.op_count == 2) {
        const cs_arm_op& o0 = d.operands[0];
        const cs_arm_op& o1 = d.operands[1];
        if (o0.type != ARM_OP_REG) return false;

        // FCONSTS / FCONSTD: `vmov.f32 s1, #1.5`. Capstone hands back the
        // expanded value in op.fp (fact C5). Materialise the bit pattern.
        if (o1.type == ARM_OP_FP) {
            // VMOV.F32 Dd|Qd, #imm is the NEON vector form: the
            // single-precision constant is replicated into every 32-bit lane
            // (DDI 0406C.d A8.8.339). It is distinguished from the scalar
            // double form by the data type, since a D register is a legal
            // destination for both.
            const VReg vd = vreg_of(o0.reg);
            const bool neon_fp_imm =
                vd.ok() && vfp_s_idx(o0.reg) < 0 &&
                d.vector_data != ARM_VECTORDATA_F64;
            if (neon_fp_imm) {
                uint32_t bits;
                const float fv = static_cast<float>(o1.fp);
                std::memcpy(&bits, &fv, sizeof(bits));
                const uint64_t pat = replicate_imm(bits, 32);
                PredScope pg = pred_begin(cx, d.cc);
                const StatePtr pst = make_state_ptr(cx);
                emit_vec_const(cx, cx.vtmp(0), pat, vd.q);
                st_vec(cx, pst.x, cx.vtmp(0), vd);
                pred_end(cx, pg);
                return true;
            }
            const FReg fd = freg_of(o0.reg);
            if (!fd.ok()) return false;
            PredScope g = pred_begin(cx, d.cc);
            const StatePtr st = make_state_ptr(cx);
            if (fd.dbl) {
                uint64_t bits;
                const double dv = o1.fp;
                std::memcpy(&bits, &dv, sizeof(bits));
                cx.buf->mov_imm(true, cx.tmp[1], bits);
                put(cx, str(true, cx.tmp[1], st.x, fd.off()));
            } else {
                uint32_t bits;
                const float fv = static_cast<float>(o1.fp);
                std::memcpy(&bits, &fv, sizeof(bits));
                cx.buf->mov_imm(false, cx.tmp[1], bits);
                put(cx, str(false, cx.tmp[1], st.x, fd.off()));
            }
            pred_end(cx, g);
            return true;
        }

        // VMOV.I<sz> Dd|Qd, #imm -- the NEON vector-immediate form.
        // [carry-over 1 + 2] A Q destination must work, and the immediate is
        // PER ELEMENT and replicated across the lanes.
        if (o1.type == ARM_OP_IMM) {
            const VReg vd = vreg_of(o0.reg);
            if (!vd.ok()) return false;
            int lb = vdata_bits(d.vector_data);
            if (lb == 0) lb = 32;
            const uint64_t pat =
                replicate_imm(static_cast<uint64_t>(o1.imm), lb);
            PredScope g = pred_begin(cx, d.cc);
            const StatePtr st = make_state_ptr(cx);
            emit_vec_const(cx, cx.vtmp(0), pat, vd.q);
            st_vec(cx, st.x, cx.vtmp(0), vd);
            pred_end(cx, g);
            return true;
        }

        if (o1.type != ARM_OP_REG) return false;

        const int r0_core = arm_core_idx(o0.reg);
        const int r1_core = arm_core_idx(o1.reg);
        const int d0 = vfp_d_idx(o0.reg);
        const int d1 = vfp_d_idx(o1.reg);
        const int s0 = vfp_s_idx(o0.reg);
        const int s1 = vfp_s_idx(o1.reg);

        // VMOV.<sz> Rt, Dn[lane] -- lane EXTRACT.
        // Because the bank is a little-endian byte array, lane k of Dn lives
        // at kOffD + 8*n + k*(sz/8) and a plain sized load does the whole job,
        // sign-extension included.
        if (r0_core >= 0 && d1 >= 0 && o1.vector_index >= 0) {
            if (r0_core == 15) return false;
            int lb = vdata_bits(d.vector_data);
            if (lb == 0 && d.vector_size > 0) lb = static_cast<int>(d.vector_size);
            if (lb == 0) lb = 32;
            if (!lane_bits_valid(lb) || lb == 64) return false;
            const bool sgn = vdata_signed(d.vector_data);
            const uint64_t off = guest_d_offset(d1) +
                static_cast<uint64_t>(o1.vector_index) *
                    static_cast<uint64_t>(lb / 8);
            PredScope g = pred_begin(cx, d.cc);
            const StatePtr st = make_state_ptr(cx);
            const unsigned wt = host_reg(r0_core);
            if (lb == 8)       put(cx, sgn ? ldrsb(false, wt, st.x, off)
                                           : ldrb(wt, st.x, off));
            else if (lb == 16) put(cx, sgn ? ldrsh(false, wt, st.x, off)
                                           : ldrh(wt, st.x, off));
            else               put(cx, ldr(false, wt, st.x, off));
            pred_end(cx, g);
            return true;
        }

        // VMOV.<sz> Dd[lane], Rt -- lane INSERT (Capstone reports this as
        // FMDHR / FMDLR, routed here; fact C5). A sized store writes exactly
        // the lane and leaves the rest of Dd alone.
        if (d0 >= 0 && r1_core >= 0 && o0.vector_index >= 0) {
            if (r1_core == 15) return false;
            int lb = vdata_bits(d.vector_data);
            if (lb == 0 && d.vector_size > 0) lb = static_cast<int>(d.vector_size);
            if (lb == 0) lb = 32;
            if (!lane_bits_valid(lb) || lb == 64) return false;
            const uint64_t off = guest_d_offset(d0) +
                static_cast<uint64_t>(o0.vector_index) *
                    static_cast<uint64_t>(lb / 8);
            PredScope g = pred_begin(cx, d.cc);
            const StatePtr st = make_state_ptr(cx);
            const unsigned wt = host_reg(r1_core);
            if (lb == 8)       put(cx, strb(wt, st.x, off));
            else if (lb == 16) put(cx, strh(wt, st.x, off));
            else               put(cx, str(false, wt, st.x, off));
            pred_end(cx, g);
            return true;
        }

        // Register-to-register and the GP <-> FP transfers. Each is a single
        // load or store against the bank.
        PredScope g = pred_begin(cx, d.cc);
        const StatePtr st = make_state_ptr(cx);
        bool ok = true;
        if (s0 >= 0 && r1_core >= 0 && r1_core != 15) {
            put(cx, str(false, host_reg(r1_core), st.x, guest_s_offset(s0)));
        } else if (r0_core >= 0 && r0_core != 15 && s1 >= 0) {
            put(cx, ldr(false, host_reg(r0_core), st.x, guest_s_offset(s1)));
        } else if (s0 >= 0 && s1 >= 0) {
            ld_s_at(cx, st.x, cx.vtmp(0), s1);
            st_s_at(cx, st.x, cx.vtmp(0), s0);
        } else if (d0 >= 0 && d1 >= 0) {
            ld_d_at(cx, st.x, cx.vtmp(0), d1);
            st_d_at(cx, st.x, cx.vtmp(0), d0);
        } else {
            const VReg va = vreg_of(o0.reg), vb = vreg_of(o1.reg);
            if (va.ok() && vb.ok()) {
                ld_vec(cx, st.x, cx.vtmp(0), vb);
                st_vec(cx, st.x, cx.vtmp(0), va);
            } else {
                ok = false;
            }
        }
        pred_end(cx, g);
        return ok;
    }

    // ---- 3 operands: VMOV Dd, Rlo, Rhi  /  VMOV Rlo, Rhi, Dn --------
    if (d.op_count == 3) {
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        const int dd = vfp_d_idx(d.operands[0].reg);
        const int dn = vfp_d_idx(d.operands[2].reg);
        const int r0 = arm_core_idx(d.operands[0].reg);
        const int r1 = arm_core_idx(d.operands[1].reg);
        const int r2 = arm_core_idx(d.operands[2].reg);
        PredScope g = pred_begin(cx, d.cc);
        const StatePtr st = make_state_ptr(cx);
        bool ok = true;
        if (dd >= 0 && r1 >= 0 && r1 != 15 && r2 >= 0 && r2 != 15) {
            put(cx, str(false, host_reg(r1), st.x, guest_d_offset(dd)));
            put(cx, str(false, host_reg(r2), st.x, guest_d_offset(dd) + 4));
        } else if (dn >= 0 && r0 >= 0 && r0 != 15 && r1 >= 0 && r1 != 15) {
            put(cx, ldr(false, host_reg(r0), st.x, guest_d_offset(dn)));
            put(cx, ldr(false, host_reg(r1), st.x, guest_d_offset(dn) + 4));
        } else {
            ok = false;
        }
        pred_end(cx, g);
        return ok;
    }

    // ---- 4 operands: the S-register-pair transfers ------------------
    //   VMOV Sm, Sm1, Rt, Rt2   /   VMOV Rt, Rt2, Sm, Sm1
    if (d.op_count == 4) {
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        const int sa = vfp_s_idx(d.operands[0].reg);
        const int sb = vfp_s_idx(d.operands[1].reg);
        const int sc = vfp_s_idx(d.operands[2].reg);
        const int sd = vfp_s_idx(d.operands[3].reg);
        const int ra = arm_core_idx(d.operands[0].reg);
        const int rb = arm_core_idx(d.operands[1].reg);
        const int rc = arm_core_idx(d.operands[2].reg);
        const int rd = arm_core_idx(d.operands[3].reg);
        PredScope g = pred_begin(cx, d.cc);
        const StatePtr st = make_state_ptr(cx);
        bool ok = true;
        if (sa >= 0 && sb >= 0 && rc >= 0 && rc != 15 && rd >= 0 && rd != 15) {
            put(cx, str(false, host_reg(rc), st.x, guest_s_offset(sa)));
            put(cx, str(false, host_reg(rd), st.x, guest_s_offset(sb)));
        } else if (ra >= 0 && ra != 15 && rb >= 0 && rb != 15 &&
                   sc >= 0 && sd >= 0) {
            put(cx, ldr(false, host_reg(ra), st.x, guest_s_offset(sc)));
            put(cx, ldr(false, host_reg(rb), st.x, guest_s_offset(sd)));
        } else {
            ok = false;
        }
        pred_end(cx, g);
        return ok;
    }

    return false;
}

// ==================================================================
// VLDR / VSTR
// ==================================================================
bool xlat_vldr_vstr(XlatMemCtx& cx, const cs_insn* in, bool is_load) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG) return false;
    if (!addr_shape_ok(d, 1)) return false;
    const FReg f = freg_of(d.operands[0].reg);
    if (!f.ok()) return false;
    const unsigned vsize = f.dbl ? kSizeX : kSizeW;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const AddrVal a = mem_effective_addr(cx, d.operands[1], /*ignore_disp=*/false,
                                         cx.tmp[1]);
    if (!a.ok) { pred_end(cx, g); return false; }
    const unsigned v0 = cx.vtmp(0);
    // One flattened guest address, folded once with UXTW by the shared
    // choke point. See THE 2^32 WRAP INVARIANT in xlat_mem.h.
    if (is_load) {
        emit_guest_fp_ldst(cx, vsize, /*is_load=*/true, v0, a.reg);
        st_freg(cx, st.x, v0, f);
    } else {
        ld_freg(cx, st.x, v0, f);
        emit_guest_fp_ldst(cx, vsize, /*is_load=*/false, v0, a.reg);
    }
    pred_end(cx, g);
    return true;
}

// ==================================================================
// VLDM / VSTM / VPUSH / VPOP / FLDMIAX / FSTMIAX
//
// Same "lowest register at the lowest address" rule as the integer LDM/STM
// family. VLDMIA / VSTMIA start at the base; VLDMDB / VSTMDB start at
// base - total and leave the base there on writeback. VPUSH is VSTMDB SP!
// and VPOP is VLDMIA SP!.
//
// `extra_bytes` covers the VFPv1 legacy FSTMIAX / FLDMIAX / FSTMDBX /
// FLDMDBX forms, whose encoded imm8 is `2*regs + 1` rather than `2*regs`
// (verified: `fstmiax r0,{d0-d15}` assembles to 0xec800b21, imm8 == 0x21 ==
// 33 == 2*16 + 1). DDI 0406C.d A8.8.412's VSTM pseudocode transfers exactly
// `regs` doublewords and then advances the base by ZeroExtend(imm8:'00'),
// i.e. 8*regs + 4, so the extra word is reserved space that the architecture
// never writes. That is why the register loop below is unchanged and only
// the writeback distance grows.
//
// The incumbent no-ops this whole family on the theory that it only appears
// as misdecoded data. It does not: `__gnu_Unwind_Save_VFP` at 0x29086c in
// HCR and 0x41a8xx in JJ is `fstmiax r0,{d0-d15}; bx lr`, a live two-
// instruction function, and rc_cov.py scores one live site in each.
// ==================================================================
bool xlat_vldm_vstm(XlatMemCtx& cx, const cs_insn* in, bool is_load,
                    bool decrement, int base_override,
                    bool implicit_writeback, int extra_bytes) {
    const cs_arm& d = in->detail->arm;
    int first = 0;
    int base_r = base_override;
    if (base_r < 0) {
        if (d.op_count < 2 || d.operands[0].type != ARM_OP_REG) return false;
        base_r = arm_core_idx(d.operands[0].reg);
        first = 1;
    }
    if (base_r < 0 || base_r == 15) return false;

    std::vector<int> regs;
    bool dbl = false;
    for (int i = first; i < d.op_count; ++i) {
        if (d.operands[i].type != ARM_OP_REG) return false;
        const int dn = vfp_d_idx(d.operands[i].reg);
        const int sn = vfp_s_idx(d.operands[i].reg);
        if (i == first) dbl = (dn >= 0);
        if (dbl) {
            if (dn < 0) return false;   // a list is uniformly D or uniformly S
            regs.push_back(dn);
        } else {
            if (sn < 0) return false;
            regs.push_back(sn);
        }
    }
    if (regs.empty()) return false;
    const int n = static_cast<int>(regs.size());
    const int slot = dbl ? 8 : 4;
    const int total = slot * n + extra_bytes;
    const bool writeback = d.writeback || implicit_writeback;
    const unsigned wbase = host_reg(base_r);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned wlow = cx.tmp[1];
    emit_add_imm32(cx, wlow, wbase, decrement ? -total : 0, cx.tmp[3]);
    const unsigned xp = cx.tmp[2];
    // wlow came from W-form arithmetic, so it is already 2^32-wrapped.
    emit_host_ptr(cx, xp, guest_addr_w(wlow));

    const unsigned v0 = cx.vtmp(0);
    for (int i = 0; i < n; ++i) {
        const uint64_t off = static_cast<uint64_t>(slot * i);
        if (is_load) {
            put(cx, dbl ? ldr_d(v0, xp, off) : ldr_s(v0, xp, off));
            if (dbl) st_d_at(cx, st.x, v0, regs[i]);
            else     st_s_at(cx, st.x, v0, regs[i]);
        } else {
            if (dbl) ld_d_at(cx, st.x, v0, regs[i]);
            else     ld_s_at(cx, st.x, v0, regs[i]);
            put(cx, dbl ? str_d(v0, xp, off) : str_s(v0, xp, off));
        }
    }
    if (writeback) {
        // IA leaves the base past the block; DB leaves it at the lowest
        // address, which is exactly `wlow`.
        if (decrement) put(cx, mov_reg(false, wbase, wlow));
        else           emit_add_imm32(cx, wbase, wbase, total, cx.tmp[3]);
    }
    pred_end(cx, g);
    return true;
}

// ==================================================================
// NEON data processing
// ==================================================================

// Three-register-same shapes, integer or float, selected from vector_data.
// [carry-over 8] Integer vector_data routes to the integer opcode at the
// correct lane width and signedness; the LLVM lifter originally hard-coded a
// 32-bit float compare for every VCEQ/VCGT/VCGE.
enum class V3 { ADD, SUB, MUL, MLA, MLS, MIN, MAX,
                CEQ, CGT, CGE, TST, SHL,
                AND, ORR, EOR, BIC, ORN, BSL, BIT, BIF,
                // Added by the coverage pass. Everything below is a
                // three-register-same-arrangement shape, so it shares this
                // function's lane-width decode and, critically, its
                // 64-bit-lane-D -> A64-SCALAR-group routing.
                QADD, QSUB, HADD, HSUB, RHADD, ABD, ABA,
                QSHL, QRSHL, RSHL, PADD, PMAX, PMIN,
                QDMULH, QRDMULH, ACGE, ACGT, RECPS, RSQRTS };

bool xlat_neon_3same(XlatMemCtx& cx, const cs_insn* in, V3 op, bool swap_ops) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    VReg vn = vreg_of(d.operands[1].reg);
    VReg vm = vreg_of(d.operands[2].reg);
    if (!vd.ok() || !vn.ok() || !vm.ok()) return false;
    // VCLT / VCLE have no A64 register form; they are the GT / GE compare
    // with the operands exchanged (a < b == b > a).
    if (swap_ops) { const VReg t = vn; vn = vm; vm = t; }

    const bool flt = vdata_float(d.vector_data);
    int lb = lane_bits_of(d);
    if (lb == 0) lb = flt ? 32 : 32;
    if (!lane_bits_valid(lb)) return false;
    const unsigned sz = size_log2(lb);
    const bool sgn = vdata_signed(d.vector_data);
    const bool q = vd.q;

    // ARM32's 64-bit-lane D-register forms (`vadd.i64 d0,d1,d2`) are A64
    // SCALAR operations: the vector group leaves size == 11 with Q == 0
    // UNDEFINED. The logical ops are exempt because their `size` field is an
    // operation selector, not a lane width. See xlat_simd.h simd_3same_scalar.
    const bool scalar_d = (!q && lb == 64);
    auto emit3 = [&](bool u, unsigned size, unsigned opcode, unsigned rd,
                     unsigned rn, unsigned rm) {
        return scalar_d ? simd_3same_scalar(u, size, opcode, rd, rn, rm)
                        : simd_3same(q, u, size, opcode, rd, rn, rm);
    };

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1), r = cx.vtmp(2);
    ld_vec(cx, st.x, a, vn);
    ld_vec(cx, st.x, b, vm);

    uint32_t w = 0;
    bool ok = true;
    switch (op) {
        // --- logical: the "size" field selects the operation, not a width --
        case V3::AND: w = simd_3same(q, false, 0, 0x03, r, a, b); break;
        case V3::BIC: w = simd_3same(q, false, 1, 0x03, r, a, b); break;
        case V3::ORR: w = simd_3same(q, false, 2, 0x03, r, a, b); break;
        case V3::ORN: w = simd_3same(q, false, 3, 0x03, r, a, b); break;
        case V3::EOR: w = simd_3same(q, true,  0, 0x03, r, a, b); break;
        // BSL/BIT/BIF read the destination, so `r` must start as Vd.
        case V3::BSL: case V3::BIT: case V3::BIF: {
            ld_vec(cx, st.x, r, vd);
            const unsigned size = (op == V3::BSL) ? 1u
                                : (op == V3::BIT) ? 2u : 3u;
            w = simd_3same(q, true, size, 0x03, r, a, b);
            break;
        }
        // --- arithmetic ---------------------------------------------------
        case V3::ADD:
            w = flt ? simd_3same(q, false, 0, k3sFadd, r, a, b)
                    : emit3(false, sz, 0x10, r, a, b);
            break;
        case V3::SUB:
            w = flt ? simd_3same(q, false, 2, k3sFadd, r, a, b)
                    : emit3(true, sz, 0x10, r, a, b);
            break;
        case V3::MUL:
            // Neither the vector nor the scalar group has a 64-bit MUL.
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, true, 0, k3sFmul, r, a, b)
                    : simd_3same(q, false, sz, 0x13, r, a, b);
            break;
        case V3::MLA: case V3::MLS: {
            if (!flt && scalar_d) { ok = false; break; }
            ld_vec(cx, st.x, r, vd);
            const bool sub = (op == V3::MLS);
            w = flt ? simd_3same(q, false, sub ? 2u : 0u, k3sFmla, r, a, b)
                    : simd_3same(q, sub, sz, k3sMla, r, a, b);
            break;
        }
        case V3::MIN:
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, false, 2, k3sFmax, r, a, b)
                    : simd_3same(q, !sgn, sz, k3sSmin, r, a, b);
            break;
        case V3::MAX:
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, false, 0, k3sFmax, r, a, b)
                    : simd_3same(q, !sgn, sz, k3sSmax, r, a, b);
            break;
        // --- compares (all-ones / all-zero lane masks) --------------------
        case V3::CEQ:
            w = flt ? simd_3same(q, false, 0, k3sFcmeq, r, a, b)
                    : emit3(true, sz, k3sCmtst, r, a, b);
            break;
        case V3::CGT:
            w = flt ? simd_3same(q, true, 2, k3sFcmeq, r, a, b)
                    : emit3(!sgn, sz, k3sCmgt, r, a, b);
            break;
        case V3::CGE:
            w = flt ? simd_3same(q, true, 0, k3sFcmeq, r, a, b)
                    : emit3(!sgn, sz, k3sCmge, r, a, b);
            break;
        case V3::TST:
            w = emit3(false, sz, k3sCmtst, r, a, b);
            break;
        // VSHL with a REGISTER shift amount. ARM32 writes
        // `VSHL.<type> Vd, Vm, Vn` with Vm the value and Vn the per-lane
        // signed shift amounts (a negative amount shifts right, which is how
        // ARM32 expresses a variable right shift), and A64's SSHL/USHL take
        // Vn = value, Vm = amounts in the same written order.
        // sshl v0.2s,v1.2s,v2.2s == 0x0ea24420 (U=0, opcode 0x08). Verified.
        case V3::SHL:
            w = emit3(!sgn, sz, 0x08, r, a, b);
            break;

        // --- saturating / rounding, added by the coverage pass ------------
        // VQADD / VQSUB / VQSHL(reg) / VQRSHL / VRSHL all have 64-bit-lane
        // ARM32 forms and matching A64 SCALAR encodings (verified in
        // xlat_simd.h), so they go through emit3 like ADD/SUB do.
        case V3::QADD: w = emit3(!sgn, sz, k3sQadd,  r, a, b); break;
        case V3::QSUB: w = emit3(!sgn, sz, k3sQsub,  r, a, b); break;
        case V3::QSHL: w = emit3(!sgn, sz, k3sQshl,  r, a, b); break;
        case V3::QRSHL:w = emit3(!sgn, sz, k3sQrshl, r, a, b); break;
        case V3::RSHL: w = emit3(!sgn, sz, k3sRshl,  r, a, b); break;

        // The rest have NO 64-bit-lane form on either side (ARM32 tops out
        // at .32 for them, DDI 0406C.d A8.8.281/283/284/300/353/354/365),
        // so a scalar_d decode here is a malformed instruction and refusing
        // is right.
        case V3::HADD:
            if (scalar_d) { ok = false; break; }
            w = simd_3same(q, !sgn, sz, k3sHadd, r, a, b);
            break;
        case V3::HSUB:
            if (scalar_d) { ok = false; break; }
            w = simd_3same(q, !sgn, sz, k3sHsub, r, a, b);
            break;
        case V3::RHADD:
            if (scalar_d) { ok = false; break; }
            w = simd_3same(q, !sgn, sz, k3sRhadd, r, a, b);
            break;
        case V3::ABD:
            if (!flt && scalar_d) { ok = false; break; }
            // FABD is U=1 with size<1> == 1; the integer form is SABD/UABD.
            w = flt ? simd_3same(q, true, 2, k3sFabd, r, a, b)
                    : simd_3same(q, !sgn, sz, k3sAbd, r, a, b);
            break;
        case V3::ABA:
            // ABA accumulates into Vd, so `r` must start as Vd. There is no
            // float VABA on ARM32.
            if (flt || scalar_d) { ok = false; break; }
            ld_vec(cx, st.x, r, vd);
            w = simd_3same(q, !sgn, sz, k3sAba, r, a, b);
            break;
        // Pairwise. ARM32's integer VPADD / VPMAX / VPMIN are D-form only
        // (A8.8.365/366/367), and A64's ADDP / SMAXP / SMINP with Q == 0
        // define exactly the same "pairs of Vn then pairs of Vm" result.
        case V3::PADD:
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, true, 0, k3sFabd, r, a, b)   // FADDP
                    : simd_3same(q, false, sz, k3sAddp, r, a, b);
            break;
        case V3::PMAX:
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, true, 0, 0x1E, r, a, b)      // FMAXP
                    : simd_3same(q, !sgn, sz, k3sMaxp, r, a, b);
            break;
        case V3::PMIN:
            if (!flt && scalar_d) { ok = false; break; }
            w = flt ? simd_3same(q, true, 2, 0x1E, r, a, b)      // FMINP
                    : simd_3same(q, !sgn, sz, k3sMinp, r, a, b);
            break;
        // Doubling multiply-high. Signed only on both sides; the U bit
        // selects the ROUNDING variant rather than a signedness.
        case V3::QDMULH:
            if (scalar_d || lb == 8) { ok = false; break; }
            w = simd_3same(q, false, sz, k3sQdmulh, r, a, b);
            break;
        case V3::QRDMULH:
            if (scalar_d || lb == 8) { ok = false; break; }
            w = simd_3same(q, true, sz, k3sQdmulh, r, a, b);
            break;
        // Float-only helpers. ARM32 NEON floats are always F32, so size<0>
        // (sz) is 0 and only size<1> varies.
        case V3::ACGE:  w = simd_3same(q, true,  0, k3sFacge, r, a, b); break;
        case V3::ACGT:  w = simd_3same(q, true,  2, k3sFacge, r, a, b); break;
        case V3::RECPS: w = simd_3same(q, false, 0, 0x1F, r, a, b); break;
        case V3::RSQRTS:w = simd_3same(q, false, 2, 0x1F, r, a, b); break;
    }
    if (!ok) { pred_end(cx, g); return false; }
    put(cx, w);
    st_vec(cx, st.x, r, vd);
    pred_end(cx, g);
    return true;
}

// Two-register-miscellaneous shapes, plus the compare-against-#0 forms.
// [carry-over 6] Integer VNEG must lower to the per-lane integer NEG, not to
// the scalar FNEG path (which the lifter fell off, no-opping the instruction
// and leaving a stale register that a later store committed).
// [carry-over 4] VMVN's REGISTER form (dd = ~dm) is handled here.
enum class V2 { NEG, ABS, NOT, SQRT,
                CEQ0, CGT0, CGE0, CLT0, CLE0,
                // Added by the coverage pass. Same-arrangement only; the
                // widening / narrowing two-register forms (VPADDL, VPADAL,
                // VMOVN, VQMOVN, VMOVL, VSHLL) change arrangement between
                // source and destination and get their own handlers below.
                QABS, QNEG, CLS, CLZ, CNT, RECPE, RSQRTE,
                REV16, REV32, REV64 };

bool xlat_neon_2misc(XlatMemCtx& cx, const cs_insn* in, V2 op, int src_idx) {
    const cs_arm& d = in->detail->arm;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[src_idx].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[src_idx].reg);
    if (!vd.ok() || !vn.ok()) return false;

    const bool flt = vdata_float(d.vector_data);
    int lb = lane_bits_of(d);
    if (lb == 0) lb = 32;
    if (!lane_bits_valid(lb)) return false;
    const unsigned sz = size_log2(lb);
    const bool q = vd.q;
    // The float 2misc encodings live in the bit23 == 1 half of the size
    // field; ARM32 NEON only has F32, so that is size == 2.
    const unsigned fsz = 2u;
    // Same 64-bit-lane rule as the three-same group: a D-register op with
    // 64-bit lanes is an A64 SCALAR operation, because the vector group
    // leaves size == 11 with Q == 0 UNDEFINED.
    const bool scalar_d = (!q && lb == 64 && !flt);
    const unsigned a = cx.vtmp(0);
    auto emit2 = [&](bool u, unsigned size, unsigned opcode) {
        return scalar_d ? simd_2misc_scalar(u, size, opcode, a, a)
                        : simd_2misc(q, u, size, opcode, a, a);
    };

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    ld_vec(cx, st.x, a, vn);
    uint32_t w = 0;
    switch (op) {
        case V2::NEG:
            w = flt ? simd_2misc(q, true, fsz, kMiscFabsNeg, a, a)
                    : emit2(true, sz, kMiscAbsNeg);
            break;
        case V2::ABS:
            w = flt ? simd_2misc(q, false, fsz, kMiscFabsNeg, a, a)
                    : emit2(false, sz, kMiscAbsNeg);
            break;
        case V2::NOT:
            // NOT's size field is fixed at 00 (the arrangement is 8B / 16B),
            // so it is never the scalar form.
            w = simd_2misc(q, true, 0, kMiscNot, a, a);
            break;
        case V2::SQRT:
            w = simd_2misc(q, true, fsz, kMiscFsqrt, a, a);
            break;
        case V2::CEQ0:
            w = flt ? simd_2misc(q, false, fsz, kMiscFcmeqZ, a, a)
                    : emit2(false, sz, kMiscCmeqZ);
            break;
        case V2::CGT0:
            w = flt ? simd_2misc(q, false, fsz, kMiscFcmgtZ, a, a)
                    : emit2(false, sz, kMiscCmgtZ);
            break;
        case V2::CGE0:
            w = flt ? simd_2misc(q, true, fsz, kMiscFcmgtZ, a, a)
                    : emit2(true, sz, kMiscCmgtZ);
            break;
        case V2::CLT0:
            w = flt ? simd_2misc(q, false, fsz, kMiscFcmltZ, a, a)
                    : emit2(false, sz, kMiscCmltZ);
            break;
        case V2::CLE0:
            w = flt ? simd_2misc(q, true, fsz, kMiscFcmeqZ, a, a)
                    : emit2(true, sz, kMiscCmeqZ);
            break;

        // --- added by the coverage pass -----------------------------------
        // Saturating absolute / negate. ARM32 tops out at .s32
        // (DDI 0406C.d A8.8.286 / A8.8.294), but the A64 scalar-group
        // encodings exist, so emit2 keeps the 64-bit case encodable rather
        // than emitting the UNDEFINED size == 11, Q == 0 vector form.
        case V2::QABS: w = emit2(false, sz, kMiscQabs); break;
        case V2::QNEG: w = emit2(true,  sz, kMiscQabs); break;
        // Count leading sign bits / leading zeros / set bits. CNT's
        // arrangement is fixed at 8B / 16B, so its size field is 00.
        case V2::CLS: w = simd_2misc(q, false, sz, kMiscCls, a, a); break;
        case V2::CLZ: w = simd_2misc(q, true,  sz, kMiscCls, a, a); break;
        case V2::CNT: w = simd_2misc(q, false, 0,  kMiscCnt, a, a); break;
        // Reciprocal / reciprocal-square-root ESTIMATE. The integer
        // (.u32) and float (.f32) forms are different opcodes at the SAME
        // size field of 10, which is why this cannot key off `fsz` alone.
        case V2::RECPE:
            w = simd_2misc(q, false, 2, flt ? kMiscFrecpe : kMiscUrecpe, a, a);
            break;
        case V2::RSQRTE:
            w = simd_2misc(q, true, 2, flt ? kMiscFrecpe : kMiscUrecpe, a, a);
            break;
        // Element reverse within a 16- / 32- / 64-bit container. ARM32
        // leaves vector_data INVALID here and reports the ELEMENT width in
        // vector_size (measured, debug/implD_neon_probe.py), which
        // lane_bits_of already prefers-then-falls-back to. The A64 `size`
        // field is that element width; the container comes from the opcode.
        case V2::REV64: w = simd_2misc(q, false, sz, kMiscRev64, a, a); break;
        case V2::REV32: w = simd_2misc(q, true,  sz, kMiscRev64, a, a); break;
        case V2::REV16: w = simd_2misc(q, false, sz, kMiscRev16, a, a); break;
    }
    put(cx, w);
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// The NEON immediate-operand logical forms.
//   VORR.I<sz> Dd|Qd, #imm  ->  Vd |=  replicate(imm)
//   VBIC.I<sz> Dd|Qd, #imm  ->  Vd &= ~replicate(imm)
//   VMVN.I<sz> Dd|Qd, #imm  ->  Vd  =  ~replicate(imm)
// [carry-over 5] VBIC's immediate form was unhandled in the lifter, so the
// bits it was supposed to clear kept garbage.
enum class VImmOp { ORR, BIC, MVN };

bool xlat_neon_imm_logical(XlatMemCtx& cx, const cs_insn* in, VImmOp op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count < 2) return false;
    if (d.operands[0].type != ARM_OP_REG) return false;
    const cs_arm_op& last = d.operands[d.op_count - 1];
    if (last.type != ARM_OP_IMM) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    if (!vd.ok()) return false;
    int lb = vdata_bits(d.vector_data);
    if (lb == 0) lb = 32;
    const uint64_t pat = replicate_imm(static_cast<uint64_t>(last.imm), lb);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), c = cx.vtmp(1);
    if (op == VImmOp::MVN) {
        emit_vec_const(cx, a, ~pat, vd.q);
    } else {
        ld_vec(cx, st.x, a, vd);
        if (op == VImmOp::ORR) {
            emit_vec_const(cx, c, pat, vd.q);
            put(cx, simd_3same(vd.q, false, 2, 0x03, a, a, c));   // ORR
        } else {
            emit_vec_const(cx, c, ~pat, vd.q);
            put(cx, simd_3same(vd.q, false, 0, 0x03, a, a, c));   // AND ~imm
        }
    }
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// VDUP.<sz> Dd|Qd, Rt   and   VDUP.<sz> Dd|Qd, Dm[lane]
// [carry-over 10] A 32-bit lane takes the whole core register; only narrower
// lanes truncate. A64's DUP (general) does exactly that, so the rule is
// automatic here.
bool xlat_vdup(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    if (!vd.ok()) return false;
    int lb = lane_bits_of(d);
    if (lb == 0) lb = 32;
    if (!lane_bits_valid(lb)) return false;
    const unsigned el = size_log2(lb);
    const int rt = arm_core_idx(d.operands[1].reg);
    const int dm = vfp_d_idx(d.operands[1].reg);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0);
    bool ok = true;
    if (rt >= 0 && rt != 15) {
        put(cx, dup_gen(vd.q, vec_imm5(el, 0), a, host_reg(rt)));
    } else if (dm >= 0) {
        const unsigned idx =
            (d.operands[1].vector_index >= 0)
                ? static_cast<unsigned>(d.operands[1].vector_index) : 0u;
        ld_d_at(cx, st.x, a, dm);
        put(cx, dup_elem(vd.q, vec_imm5(el, idx), a, a));
    } else {
        ok = false;
    }
    if (ok) st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return ok;
}

// VEXT.8 Dd, Dn, Dm, #imm  /  VEXT.8 Qd, Qn, Qm, #imm
// The ARM32 encoding carries a BYTE index (the .16/.32/.64 mnemonics are
// assembler aliases that scale into it), and Capstone always decodes the raw
// form, reporting vector_size == 8. A64's EXT imm4 is also a byte index, so
// the immediate passes straight through; the scale factor below is 1 for the
// forms Capstone can produce and exists only so an aliased decode cannot
// silently shift the window.
bool xlat_vext(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 4) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    if (d.operands[3].type != ARM_OP_IMM) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    const VReg vm = vreg_of(d.operands[2].reg);
    if (!vd.ok() || !vn.ok() || !vm.ok()) return false;
    int lb = lane_bits_of(d);
    if (lb == 0) lb = 8;
    const unsigned bytes = static_cast<unsigned>(d.operands[3].imm) *
                           static_cast<unsigned>(lb / 8);
    if (bytes >= (vd.q ? 16u : 8u)) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1);
    ld_vec(cx, st.x, a, vn);
    ld_vec(cx, st.x, b, vm);
    put(cx, simd_ext(vd.q, a, a, b, bytes));
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// VZIP / VUZP / VTRN. These are the two-operand forms: BOTH registers are
// written, the first with the low result and the second with the high result.
//
// The Q form is exact here, unlike in the LLVM lifter, which refused it
// (arm32_lifter.cpp emit_v_permute: "a faithful per-half decomposition is
// only exact for VTRN"). With the bank memory-homed a guest Q register loads
// as one LDR Q, so ZIP1/ZIP2 on .16B is the architecture's own definition.
bool xlat_vperm(XlatMemCtx& cx, const cs_insn* in, unsigned op1,
                unsigned op2) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vm = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vm.ok()) return false;
    int lb = lane_bits_of(d);
    if (lb == 0) return false;
    if (!lane_bits_valid(lb)) return false;
    const unsigned sz = size_log2(lb);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1);
    const unsigned r0 = cx.vtmp(2), r1 = cx.vtmp(3);
    ld_vec(cx, st.x, a, vd);
    ld_vec(cx, st.x, b, vm);
    put(cx, simd_perm(vd.q, sz, op1, r0, a, b));
    put(cx, simd_perm(vd.q, sz, op2, r1, a, b));
    st_vec(cx, st.x, r0, vd);
    st_vec(cx, st.x, r1, vm);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// Widening / narrowing three-register forms (A64 "three different")
//
// ARM32 spells the widening ops `VMULL.S16 Qd, Dn, Dm` and the narrowing
// ones `VADDHN.I32 Dd, Qn, Qm`, and Capstone reports vector_data as the
// SOURCE element type in both directions (measured; `vaddhn.i32` means
// 32-bit sources and a 16-bit result). A64's three-different group takes
// `size` as the source element size for the widening forms and the
// DESTINATION element size for the xxHN narrowing forms, which is the one
// asymmetry this function has to get right.
//
// Q is always 0 here: ARM32 widens from a whole D register (the LOW half in
// A64 terms, so SMULL and never SMULL2) and narrows into a whole D register
// (ADDHN and never ADDHN2). vreg_of already picks the right transfer width
// per operand, so the loads and stores need no special-casing.
// ==================================================================
enum class V3D { ADDL, SUBL, ADDW, SUBW, ABAL, ABDL,
                 MULL, MLAL, MLSL, QDMULL, QDMLAL, QDMLSL,
                 ADDHN, SUBHN, RADDHN, RSUBHN };

bool xlat_neon_3diff(XlatMemCtx& cx, const cs_insn* in, V3D op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    const VReg vm = vreg_of(d.operands[2].reg);
    if (!vd.ok() || !vn.ok() || !vm.ok()) return false;

    const int src_bits = vdata_bits(d.vector_data);
    if (!lane_bits_valid(src_bits)) return false;
    const bool sgn = vdata_signed(d.vector_data);
    // This Capstone build knows only ARM_VECTORDATA_P8; VMULL.P64 needs
    // FEAT_PMULL, which no armeabi-v7a guest can carry, so P8 is the whole
    // polynomial surface here.
    const bool poly = (d.vector_data == ARM_VECTORDATA_P8);

    const bool narrowing = (op == V3D::ADDHN || op == V3D::SUBHN ||
                            op == V3D::RADDHN || op == V3D::RSUBHN);
    // Widening reads 8-, 16- or 32-bit lanes and writes twice that;
    // narrowing reads 16-, 32- or 64-bit lanes and writes half.
    if (narrowing) {
        if (src_bits == 8) return false;
    } else if (src_bits == 64) {
        return false;
    }
    // A64's `size` field: source width when widening, DESTINATION width
    // when narrowing.
    const unsigned sz = narrowing ? size_log2(src_bits / 2)
                                  : size_log2(src_bits);

    unsigned opcode = 0;
    bool u = !sgn;
    bool accum = false;
    switch (op) {
        case V3D::ADDL:   opcode = k3dAddl;  break;
        case V3D::SUBL:   opcode = k3dSubl;  break;
        case V3D::ADDW:   opcode = k3dAddw;  break;
        case V3D::SUBW:   opcode = k3dSubw;  break;
        case V3D::ABDL:   opcode = k3dAbdl;  break;
        case V3D::ABAL:   opcode = k3dAbal;  accum = true; break;
        case V3D::MULL:
            // VMULL.P8 is the polynomial multiply, a different opcode whose
            // U bit is 0 regardless of the (meaningless) signedness.
            opcode = poly ? k3dPmull : k3dMull;
            if (poly) u = false;
            break;
        case V3D::MLAL:   opcode = k3dMlal;  accum = true; break;
        case V3D::MLSL:   opcode = k3dMlsl;  accum = true; break;
        // The doubling forms are signed-only; U selects nothing here.
        case V3D::QDMULL: opcode = k3dQdmull; u = false; break;
        case V3D::QDMLAL: opcode = k3dQdmlal; u = false; accum = true; break;
        case V3D::QDMLSL: opcode = k3dQdmlsl; u = false; accum = true; break;
        case V3D::ADDHN:  opcode = k3dAddhn; u = false; break;
        case V3D::RADDHN: opcode = k3dAddhn; u = true;  break;
        case V3D::SUBHN:  opcode = k3dSubhn; u = false; break;
        case V3D::RSUBHN: opcode = k3dSubhn; u = true;  break;
    }
    // The doubling multiplies have no 8-bit form (DDI 0406C.d A8.8.293 and
    // A8.8.296: size is 01 or 10), and neither does A64's SQDMULL family.
    if ((op == V3D::QDMULL || op == V3D::QDMLAL || op == V3D::QDMLSL) &&
        src_bits == 8)
        return false;
    // PMULL on ARM32 is the .P8 form only (.P64 needs FEAT_PMULL, which no
    // ARMv7 guest can carry).
    if (poly && src_bits != 8) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1), r = cx.vtmp(2);
    ld_vec(cx, st.x, a, vn);
    ld_vec(cx, st.x, b, vm);
    if (accum) ld_vec(cx, st.x, r, vd);
    put(cx, simd_3diff(/*q=*/false, u, sz, opcode, r, a, b));
    st_vec(cx, st.x, r, vd);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// The BY-ELEMENT ("by scalar") forms
//
// `vmull.s16 q0, d1, d2[1]` multiplies every lane of Dn by ONE lane of Dm.
// Capstone reports it as three plain REG operands with `vector_index` set on
// the last one, so without this path it reaches xlat_neon_3same or
// xlat_neon_3diff and is translated as a full-vector operation against Dm --
// silently wrong rather than visibly stubbed. That is why the dispatch below
// tests the index BEFORE choosing a handler.
// ==================================================================
enum class VIdx { MUL, MLA, MLS, MULL, MLAL, MLSL,
                  QDMULL, QDMLAL, QDMLSL, QDMULH, QRDMULH };

bool xlat_neon_indexed(XlatMemCtx& cx, const cs_insn* in, VIdx op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    const int dm = vfp_d_idx(d.operands[2].reg);
    const int index = d.operands[2].vector_index;
    if (!vd.ok() || !vn.ok() || dm < 0 || index < 0) return false;

    // ARM32's by-element FP forms are F32 only (there is no NEON F16 or F64
    // arithmetic in A32), and the A64 index split below is derived for a
    // 32-bit element, so anything else is refused rather than guessed.
    const bool flt = vdata_float(d.vector_data);
    if (flt && d.vector_data != ARM_VECTORDATA_F32) return false;
    const int lb = flt ? 32 : vdata_bits(d.vector_data);
    if (!lane_bits_valid(lb)) return false;
    const bool sgn = vdata_signed(d.vector_data);
    const bool widening = (op == VIdx::MULL || op == VIdx::MLAL ||
                           op == VIdx::MLSL || op == VIdx::QDMULL ||
                           op == VIdx::QDMLAL || op == VIdx::QDMLSL);
    // ARM32's by-element forms exist only for 16- and 32-bit elements
    // (DDI 0406C.d A8.8.290 VMUL (by scalar): "size == 00 -> UNDEFINED"),
    // and the A64 index split is only defined for those two widths.
    if (lb != 16 && lb != 32) return false;
    const unsigned sz = flt ? 2u : size_log2(lb);
    if (lb == 16 && index > 7) return false;
    if (lb == 32 && index > 3) return false;

    unsigned opcode = 0;
    bool u = false;
    bool accum = false;
    switch (op) {
        // U comes from the OPERATION for the same-width forms (MLA/MLS are
        // U == 1, MUL is U == 0, the FP ones are all U == 0) and from the
        // SIGNEDNESS for the widening ones. Both verified against clang;
        // see the encoding table in xlat_simd.h.
        case VIdx::MUL:  opcode = flt ? kIdxFmul : kIdxMul; u = false; break;
        case VIdx::MLA:
            opcode = flt ? kIdxFmla : kIdxMla; u = !flt; accum = true; break;
        case VIdx::MLS:
            opcode = flt ? kIdxFmls : kIdxMls; u = !flt; accum = true; break;
        case VIdx::MULL: opcode = kIdxMull; u = !sgn; break;
        case VIdx::MLAL: opcode = kIdxMlal; u = !sgn; accum = true; break;
        case VIdx::MLSL: opcode = kIdxMlsl; u = !sgn; accum = true; break;
        case VIdx::QDMULL: opcode = kIdxQdmull; break;
        case VIdx::QDMLAL: opcode = kIdxQdmlal; accum = true; break;
        case VIdx::QDMLSL: opcode = kIdxQdmlsl; accum = true; break;
        case VIdx::QDMULH:  opcode = kIdxQdmulh;  break;
        case VIdx::QRDMULH: opcode = kIdxQrdmulh; break;
    }
    if (flt && (op != VIdx::MUL && op != VIdx::MLA && op != VIdx::MLS))
        return false;

    // A 16-bit-element indexed form has only FOUR bits of Rm, so the scalar
    // source must live in V0..V15. XlatMemCtx's default scratch bank is
    // v0..v7, but a caller may override it; refusing here keeps a
    // mis-configured context a VISIBLE stub instead of a silently wrong
    // register number.
    if (sz == 1 && cx.vtmp(1) >= 16) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1), r = cx.vtmp(2);
    ld_vec(cx, st.x, a, vn);
    ld_d_at(cx, st.x, b, dm);            // the scalar source is always a D
    if (accum) ld_vec(cx, st.x, r, vd);
    // Widening always reads the LOW half of Dn, so Q == 0; the same-width
    // forms take Q from the destination arrangement.
    put(cx, simd_indexed(widening ? false : vd.q, u, sz, opcode, r, a, b,
                         static_cast<unsigned>(index)));
    st_vec(cx, st.x, r, vd);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// The two-register forms whose source and destination ARRANGEMENTS differ,
// which is why they cannot ride xlat_neon_2misc.
// ==================================================================

// VPADDL / VPADAL: add adjacent lane PAIRS into lanes of twice the width.
// `vpaddl.s8 d0, d1` -> SADDLP Vd.4h, Vn.8b, and the A64 `size` field is the
// SOURCE width (verified: saddlp v0.4h, v1.8b == 0x0e202820).
bool xlat_vpaddl(XlatMemCtx& cx, const cs_insn* in, bool accumulate) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vn.ok()) return false;
    const int src_bits = vdata_bits(d.vector_data);
    if (src_bits != 8 && src_bits != 16 && src_bits != 32) return false;
    const bool u = !vdata_signed(d.vector_data);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), r = cx.vtmp(1);
    ld_vec(cx, st.x, a, vn);
    if (accumulate) ld_vec(cx, st.x, r, vd);
    put(cx, simd_2misc(vn.q, u, size_log2(src_bits),
                       accumulate ? kMiscAdalp : kMiscAddlp, r, a));
    st_vec(cx, st.x, r, vd);
    pred_end(cx, g);
    return true;
}

// VMOVN / VQMOVN / VQMOVUN: halve the lane width.
//   vmovn.i32  d0, q1 -> XTN    v0.4h, v1.4s   (size == DESTINATION width)
//   vqmovn.s32 d0, q1 -> SQXTN  v0.4h, v1.4s
//   vqmovn.u16 d0, q1 -> UQXTN  v0.4h, v1.8h
//   vqmovun.s16 d0,q1 -> SQXTUN v0.8b, v1.8h
enum class VNarrow { MOVN, QMOVN, QMOVUN };

bool xlat_vmovn(XlatMemCtx& cx, const cs_insn* in, VNarrow kind) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vn.ok()) return false;
    const int src_bits = vdata_bits(d.vector_data);
    if (src_bits != 16 && src_bits != 32 && src_bits != 64) return false;
    const unsigned sz = size_log2(src_bits / 2);
    const bool sgn = vdata_signed(d.vector_data);

    unsigned opcode = kMiscXtn;
    bool u = false;
    if (kind == VNarrow::QMOVN) { opcode = kMiscQxtn; u = !sgn; }
    else if (kind == VNarrow::QMOVUN) { opcode = kMiscXtn; u = true; }

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0);
    ld_vec(cx, st.x, a, vn);
    put(cx, simd_2misc(/*q=*/false, u, sz, opcode, a, a));
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// VMOVL / VSHLL: double the lane width, optionally shifting left first.
//   vmovl.s8  q0, d1     -> SSHLL v0.8h, v1.8b, #0   (a.k.a. SXTL)
//   vshll.s8  q0, d1, #3 -> SSHLL v0.8h, v1.8b, #3
//   vshll.i8  q0, d1, #8 -> SHLL  v0.8h, v1.8b, #8
// The last one is a DIFFERENT encoding: A64's shift-by-immediate group
// cannot express shift == esize (immh:immb would carry into the next immh),
// so the maximum shift has its own two-register-misc opcode. ARM32 makes the
// same split, which is why it spells that form `.I<size>` rather than
// `.S<size>` / `.U<size>` (DDI 0406C.d A8.8.399).
bool xlat_vmovl_vshll(XlatMemCtx& cx, const cs_insn* in, bool has_shift) {
    const cs_arm& d = in->detail->arm;
    const int want = has_shift ? 3 : 2;
    if (d.op_count != want) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    if (has_shift && d.operands[2].type != ARM_OP_IMM) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vn.ok()) return false;
    const int src_bits = vdata_bits(d.vector_data);
    if (src_bits != 8 && src_bits != 16 && src_bits != 32) return false;
    const int amount = has_shift ? static_cast<int>(d.operands[2].imm) : 0;
    if (amount < 0 || amount > src_bits) return false;
    const bool u = !vdata_signed(d.vector_data);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0);
    ld_vec(cx, st.x, a, vn);
    if (amount == src_bits) {
        put(cx, simd_2misc(/*q=*/false, /*u=*/true, size_log2(src_bits),
                           kMiscShll, a, a));
    } else {
        put(cx, simd_shift_imm(/*q=*/false, u,
                               static_cast<unsigned>(src_bits + amount),
                               kShiftShll, a, a));
    }
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// The shift-by-immediate family, generalised
//
// One function so the "a 64-bit-lane D operation is an A64 SCALAR" rule and
// the immh:immb arithmetic have exactly one implementation. The accumulating
// and inserting members (VSRA / VRSRA / VSRI / VSLI) read the destination,
// so they need it loaded into the result register first.
// ==================================================================
enum class VShImm { SHL, SHR, SRA, RSHR, RSRA, SRI, SLI, QSHL, QSHLU };

bool xlat_vshift_imm(XlatMemCtx& cx, const cs_insn* in, VShImm op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG ||
        d.operands[2].type != ARM_OP_IMM) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vn.ok()) return false;
    int lb = lane_bits_of(d);
    if (!lane_bits_valid(lb)) return false;
    const int amount = static_cast<int>(d.operands[2].imm);
    const bool sgn = vdata_signed(d.vector_data);

    const bool left = (op == VShImm::SHL || op == VShImm::SLI ||
                       op == VShImm::QSHL || op == VShImm::QSHLU);
    // DDI 0406C.d: a left shift takes 0..esize-1, a right shift 1..esize.
    if (amount < 0) return false;
    if (left ? (amount >= lb) : (amount < 1 || amount > lb)) return false;

    unsigned opcode = 0;
    bool u = false;
    bool accum = false;
    switch (op) {
        case VShImm::SHL:   opcode = kShiftShl;    u = false;   break;
        case VShImm::SHR:   opcode = kShiftSshr;   u = !sgn;    break;
        case VShImm::SRA:   opcode = kShiftSsra;   u = !sgn;  accum = true; break;
        case VShImm::RSHR:  opcode = kShiftSrshr;  u = !sgn;    break;
        case VShImm::RSRA:  opcode = kShiftSrsra;  u = !sgn;  accum = true; break;
        // SRI and SLI insert into the destination and are unsigned-encoded
        // regardless of the operand type.
        case VShImm::SRI:   opcode = kShiftSri;    u = true;  accum = true; break;
        case VShImm::SLI:   opcode = kShiftSli;    u = true;  accum = true; break;
        case VShImm::QSHL:  opcode = kShiftSqshl;  u = !sgn;    break;
        case VShImm::QSHLU: opcode = kShiftSqshlu; u = true;    break;
    }
    const unsigned immh_immb = left
        ? static_cast<unsigned>(lb + amount)
        : static_cast<unsigned>(2 * lb - amount);

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), r = cx.vtmp(1);
    ld_vec(cx, st.x, a, vn);
    const unsigned dst = accum ? r : a;
    if (accum) ld_vec(cx, st.x, r, vd);
    // A 64-bit-lane D-register shift is the A64 SCALAR form; the vector
    // shift-by-immediate group leaves immh == 1xxx with Q == 0 UNDEFINED.
    put(cx, (!vd.q && lb == 64)
                ? simd_shift_imm_scalar(u, immh_immb, opcode, dst, a)
                : simd_shift_imm(vd.q, u, immh_immb, opcode, dst, a));
    st_vec(cx, st.x, dst, vd);
    pred_end(cx, g);
    return true;
}

// The NARROWING right shifts: VSHRN / VRSHRN / VQSHRN / VQSHRUN / VQRSHRN /
// VQRSHRUN. Shape is (Dd, Qn, #imm) with vector_data naming the SOURCE
// (wide) element type, and A64's immh:immb is relative to the DESTINATION
// width (verified: shrn v0.4h, v1.4s, #3 == 0x0f1d8420, immh:immb == 29 ==
// 2*16 - 3).
enum class VShNarrow { SHRN, RSHRN, QSHRN, QSHRUN, QRSHRN, QRSHRUN };

bool xlat_vshift_narrow(XlatMemCtx& cx, const cs_insn* in, VShNarrow op) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG ||
        d.operands[2].type != ARM_OP_IMM) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vn = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vn.ok()) return false;
    const int src_bits = vdata_bits(d.vector_data);
    if (src_bits != 16 && src_bits != 32 && src_bits != 64) return false;
    const int dst_bits = src_bits / 2;
    const int amount = static_cast<int>(d.operands[2].imm);
    if (amount < 1 || amount > dst_bits) return false;
    const bool sgn = vdata_signed(d.vector_data);

    unsigned opcode = 0;
    bool u = false;
    switch (op) {
        case VShNarrow::SHRN:     opcode = kShiftShrn;   u = false; break;
        case VShNarrow::RSHRN:    opcode = kShiftRshrn;  u = false; break;
        case VShNarrow::QSHRN:    opcode = kShiftQshrn;  u = !sgn;  break;
        case VShNarrow::QRSHRN:   opcode = kShiftQrshrn; u = !sgn;  break;
        // The "unsigned result from a signed source" saturating narrows are
        // encoded in the U == 1 half of the plain SHRN / RSHRN opcodes.
        case VShNarrow::QSHRUN:   opcode = kShiftShrn;   u = true;  break;
        case VShNarrow::QRSHRUN:  opcode = kShiftRshrn;  u = true;  break;
    }

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0);
    ld_vec(cx, st.x, a, vn);
    put(cx, simd_shift_imm(/*q=*/false, u,
                           static_cast<unsigned>(2 * dst_bits - amount),
                           opcode, a, a));
    st_vec(cx, st.x, a, vd);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// VTBL / VTBX
//
// ARM32's table is 1..4 CONSECUTIVE D registers, i.e. 8n contiguous bytes,
// and an index >= 8n gives 0 (VTBL) or leaves the destination lane untouched
// (VTBX). A64's TBL/TBX table is 1..4 V registers, i.e. 16 bytes each, so a
// naive register-for-register mapping reads 8 bytes of the WRONG data for
// every index in [8n, 16n).
//
// The fix falls out of the memory-homed bank: guest d[k] and d[k+1] are
// adjacent 8-byte slots, so ONE 128-bit load at offset 8k already packs two
// table registers in the exact byte order A64 wants. n D registers therefore
// become ceil(n/2) V registers, and when n is odd the unused top half is
// explicitly zeroed so an out-of-range index still reads 0.
//
// VTBX then needs one more step, because A64's "out of range" is
// index >= 16*ceil(n/2) while ARM32's is index >= 8n. Rather than special-
// casing even n (where they coincide), the lowering always computes
// TBL + a per-byte "index < 8n" mask and blends, which is uniformly correct.
// ==================================================================
bool xlat_vtbl(XlatMemCtx& cx, const cs_insn* in, bool is_tbx) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count < 3 || d.op_count > 6) return false;
    for (int i = 0; i < d.op_count; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const int dd = vfp_d_idx(d.operands[0].reg);
    const int dm = vfp_d_idx(d.operands[d.op_count - 1].reg);
    if (dd < 0 || dm < 0) return false;
    const int n = d.op_count - 2;                 // table register count
    const int d_first = vfp_d_idx(d.operands[1].reg);
    if (d_first < 0) return false;
    for (int i = 1; i < n; ++i) {
        // A non-consecutive list is not encodable on ARM32 either
        // (DDI 0406C.d A8.8.331), so this is a malformed decode.
        if (vfp_d_idx(d.operands[1 + i].reg) != d_first + i) return false;
    }
    if (d_first + n > 32) return false;

    const int nq = (n + 1) / 2;                   // 128-bit table registers
    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned vidx = cx.vtmp(0);
    const unsigned vtab = cx.vtmp(1);             // vtmp(1)..vtmp(2)
    ld_d_at(cx, st.x, vidx, dm);
    for (int k = 0; k < nq; ++k) {
        const bool last_is_odd = (n & 1) && (k == nq - 1);
        if (last_is_odd) {
            // An odd-length table leaves the top half of the last 128-bit
            // register outside the table. LDR D zeroes bits 127:64 of the
            // destination (DDI 0487, LDR (immediate, SIMD&FP)), so loading
            // the last D register on its own both pads with zeros and
            // avoids reading guest_d_offset(32), which is past the end of
            // GuestState::d[].
            put(cx, ldr_d(vtab + k, st.x,
                          guest_d_offset(d_first + 2 * k)));
        } else {
            put(cx, ldr_q(vtab + k, st.x, guest_d_offset(d_first + 2 * k)));
        }
    }

    if (!is_tbx) {
        put(cx, vtbl(/*q=*/false, static_cast<unsigned>(nq), vidx, vtab, vidx));
        st_d_at(cx, st.x, vidx, dd);
    } else {
        const unsigned vmask = cx.vtmp(3);
        const unsigned vres = cx.vtmp(4);
        const unsigned vold = cx.vtmp(5);
        put(cx, vtbl(/*q=*/false, static_cast<unsigned>(nq), vres, vtab, vidx));
        // mask = (8n > index) per byte, unsigned.
        put(cx, simd_modimm(/*q=*/false, /*op=*/false, /*cmode=*/0xE,
                            /*o2=*/false, static_cast<uint8_t>(8 * n), vmask));
        put(cx, vcmhi(a64::V8B, vmask, vmask, vidx));
        ld_d_at(cx, st.x, vold, dd);
        // BSL Vd, Vn, Vm with Vd == mask: (mask & tbl) | (~mask & old).
        put(cx, vbsl(/*q=*/false, vmask, vres, vold));
        st_d_at(cx, st.x, vmask, dd);
    }
    pred_end(cx, g);
    return true;
}

// VSWP Dd, Dm / VSWP Qd, Qm -- exchange two whole registers. There is no
// A64 equivalent, and none is needed: with the bank memory-homed this is two
// loads and two stores. Capstone leaves both vector_data and vector_size
// INVALID here (measured), so the width comes from the register class.
bool xlat_vswp(XlatMemCtx& cx, const cs_insn* in) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const VReg vd = vreg_of(d.operands[0].reg);
    const VReg vm = vreg_of(d.operands[1].reg);
    if (!vd.ok() || !vm.ok() || vd.q != vm.q) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned a = cx.vtmp(0), b = cx.vtmp(1);
    ld_vec(cx, st.x, a, vd);
    ld_vec(cx, st.x, b, vm);
    st_vec(cx, st.x, b, vd);
    st_vec(cx, st.x, a, vm);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// The ARMv8-in-A32 VFP additions: VRINT*, VSEL*, VMAXNM / VMINNM
//
// All three families are SCALAR-only in practice here. Their NEON vector
// encodings exist in the architecture but this Capstone build cannot decode
// them (measured: `vrintz.f32 q0,q1` and `vmaxnm.f32 q0,q1,q2` both come
// back UNDECODABLE), so anything that reaches translate_simd is the S- or
// D-register form. Capstone also leaves vector_data INVALID for the .F64
// forms, so the operand WIDTH must come from the register class -- freg_of
// already does exactly that.
// ==================================================================
bool xlat_vrint(XlatMemCtx& cx, const cs_insn* in, unsigned fp_opcode) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 2) return false;
    if (d.operands[0].type != ARM_OP_REG ||
        d.operands[1].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    if (!fd.ok() || !fn.ok() || fd.dbl != fn.dbl) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0);
    ld_freg(cx, st.x, v0, fn);
    put(cx, fp1(fd.ptype(), fp_opcode, v0, v0));
    st_freg(cx, st.x, v0, fd);
    pred_end(cx, g);
    return true;
}

// VSEL<cc>.<F32|F64> Sd|Dd, Sn|Dn, Sm|Dm -> FCSEL. VSEL is in the
// UNCONDITIONAL encoding space (DDI 0406C.d A8.8.360 in the ARMv8 update),
// so `cc` here is the SELECTOR, not a predicate, and the instruction itself
// always executes.
bool xlat_vsel(XlatMemCtx& cx, const cs_insn* in, arm_cc sel) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    const FReg fm = freg_of(d.operands[2].reg);
    if (!fd.ok() || !fn.ok() || !fm.ok()) return false;
    if (fd.dbl != fn.dbl || fd.dbl != fm.dbl) return false;

    // The guard is a no-op for VSEL (its encoding space has no condition
    // field, so Capstone always reports AL) and is kept only so that every
    // handler in this file has the same shape.
    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0), v1 = cx.vtmp(1);
    ld_freg(cx, st.x, v0, fn);
    ld_freg(cx, st.x, v1, fm);
    put(cx, fcsel(fd.ptype(), v0, v0, v1, cond_of(sel)));
    st_freg(cx, st.x, v0, fd);
    pred_end(cx, g);
    return true;
}

// VMAXNM / VMINNM: IEEE-754-2008 maxNum / minNum, which differ from
// VMAX / VMIN in their NaN handling (a quiet NaN operand returns the other
// operand). A64's FMAXNM / FMINNM are the same operation.
bool xlat_vfp_minmaxnm(XlatMemCtx& cx, const cs_insn* in, bool is_max) {
    const cs_arm& d = in->detail->arm;
    if (d.op_count != 3) return false;
    for (int i = 0; i < 3; ++i)
        if (d.operands[i].type != ARM_OP_REG) return false;
    const FReg fd = freg_of(d.operands[0].reg);
    const FReg fn = freg_of(d.operands[1].reg);
    const FReg fm = freg_of(d.operands[2].reg);
    if (!fd.ok() || !fn.ok() || !fm.ok()) return false;
    if (fd.dbl != fn.dbl || fd.dbl != fm.dbl) return false;

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    const unsigned v0 = cx.vtmp(0), v1 = cx.vtmp(1);
    ld_freg(cx, st.x, v0, fn);
    ld_freg(cx, st.x, v1, fm);
    put(cx, fp2(fd.ptype(), is_max ? 0x6u : 0x7u, v0, v0, v1));
    st_freg(cx, st.x, v0, fd);
    pred_end(cx, g);
    return true;
}

// ==================================================================
// VLD1-4 / VST1-4
// ==================================================================

// The form selector and lane index, decoded from the instruction word.
// Capstone does not expose either (xlat_simd.h fact C1). Fields per
// ARM DDI 0406C.d A7.7 plus A8.8.320 / A8.8.321:
//
//   bit[23]      A: 0 = load/store MULTIPLE structures,
//                   1 = single structure (one lane, or to all lanes)
//   A == 1:
//     bits[11:8] == 0b11xx  -> "to all lanes"; bits[9:8] give n-1,
//                              bits[7:6] the element size, bit[5] the
//                              register-count / spacing selector
//     otherwise             -> one lane; bits[11:10] element size,
//                              bits[9:8] n-1, bits[7:4] index_align, from
//                              which the index is index_align >> (1 + size)
struct NeonLs {
    bool ok = false;
    bool single_lane = false;
    bool replicate = false;
    unsigned index = 0;
};

bool neon_ls_decode(const cs_insn* in, bool is_thumb, NeonLs* out) {
    if (in->size != 4) return false;
    const uint8_t* b = in->bytes;
    uint32_t w;
    if (is_thumb) {
        // T32 stores two little-endian halfwords, most significant first.
        w = (static_cast<uint32_t>(b[1]) << 24) |
            (static_cast<uint32_t>(b[0]) << 16) |
            (static_cast<uint32_t>(b[3]) << 8) | b[2];
    } else {
        w = static_cast<uint32_t>(b[0]) |
            (static_cast<uint32_t>(b[1]) << 8) |
            (static_cast<uint32_t>(b[2]) << 16) |
            (static_cast<uint32_t>(b[3]) << 24);
    }
    out->ok = true;
    if (((w >> 23) & 1u) == 0u) return true;  // multiple structures
    const unsigned type = (w >> 8) & 0xFu;
    if ((type & 0xCu) == 0xCu) {
        out->replicate = true;
        return true;
    }
    out->single_lane = true;
    const unsigned size = (w >> 10) & 3u;
    const unsigned index_align = (w >> 4) & 0xFu;
    out->index = index_align >> (1u + size);
    return true;
}

// A64 "load/store multiple structures" opcode for n interleaved structures
// spread over `k` registers. Returns false for a shape with no single-
// instruction equivalent.
bool multi_opcode(int n, int k, unsigned* opcode) {
    if (n == 1) {
        switch (k) {
            case 1: *opcode = 0x7; return true;
            case 2: *opcode = 0xA; return true;
            case 3: *opcode = 0x6; return true;
            case 4: *opcode = 0x2; return true;
            default: return false;
        }
    }
    if (n == 2 && k == 2) { *opcode = 0x8; return true; }
    if (n == 3 && k == 3) { *opcode = 0x4; return true; }
    if (n == 4 && k == 4) { *opcode = 0x0; return true; }
    // n == 2 with FOUR registers is ARM32's type == 0b0011 shape, which the
    // caller lowers as two separate LD2/ST2 passes; see xlat_neon_ldst.
    if (n == 2 && k == 4) { *opcode = 0x8; return true; }
    return false;
}

bool xlat_neon_ldst(XlatMemCtx& cx, const cs_insn* in, bool is_load, int n) {
    const cs_arm& d = in->detail->arm;
    const int mem_idx = find_mem_operand(d);
    if (mem_idx < 0) return false;
    if (arm_core_idx(d.operands[mem_idx].mem.base) < 0) return false;

    // The d-register list precedes the MEM operand; a post-index register
    // follows it (fact C4).
    std::vector<int> regs;
    for (int i = 0; i < mem_idx; ++i) {
        if (d.operands[i].type != ARM_OP_REG) return false;
        const int dn = vfp_d_idx(d.operands[i].reg);
        if (dn < 0) return false;
        regs.push_back(dn);
    }
    if (regs.empty() || regs.size() > 4) return false;
    int post_inc_reg = -1;
    for (int i = mem_idx + 1; i < d.op_count; ++i) {
        if (d.operands[i].type != ARM_OP_REG) continue;
        const int rr = arm_core_idx(d.operands[i].reg);
        if (rr >= 0) { post_inc_reg = rr; break; }
    }

    NeonLs form;
    if (!neon_ls_decode(in, cx.is_thumb, &form)) return false;
    int lb = lane_bits_of(d);
    if (lb == 0) lb = 8;
    if (!lane_bits_valid(lb)) return false;
    const unsigned esize = size_log2(lb);
    const int k = static_cast<int>(regs.size());

    if (form.replicate && !is_load) return false;  // no VSTnR exists

    // Bytes transferred, which is also the `[Rn]!` writeback amount.
    int total;
    if (form.single_lane)      total = n * (lb / 8);
    else if (form.replicate)   total = n * (lb / 8);
    else                       total = 8 * k;

    unsigned multi_op = 0;
    if (!form.single_lane && !form.replicate &&
        !multi_opcode(n, k, &multi_op)) {
        warn(cx, "unsupported NEON structure shape: n=" + std::to_string(n) +
                     " regs=" + std::to_string(k));
        return false;
    }

    PredScope g = pred_begin(cx, d.cc);
    const StatePtr st = make_state_ptr(cx);
    // [fact C3] The alignment qualifier is reported in mem.disp and must NOT
    // be added to the address.
    const AddrVal a = mem_effective_addr(cx, d.operands[mem_idx],
                                         /*ignore_disp=*/true, cx.tmp[1]);
    if (!a.ok) { pred_end(cx, g); return false; }
    const GuestAddrW wbase_val = a.reg;
    const unsigned xp = cx.tmp[2];
    emit_host_ptr(cx, xp, wbase_val);

    const unsigned v0 = cx.vtmp(0);

    if (form.replicate) {
        // LD1R writes one register; ARM32's `{d0[],d1[]}` replicates the SAME
        // element into every listed register, so one LD1R plus k stores. The
        // LD2R/LD3R/LD4R forms load n distinct elements into n consecutive
        // registers, which maps directly.
        const unsigned opcode = 6u | ((n >= 3) ? 1u : 0u);
        const bool r = (n == 2 || n == 4);
        put(cx, simd_ldst_single(/*q=*/false, true, r, opcode, /*s=*/false,
                                 esize, xp, v0));
        if (n == 1) {
            for (int i = 0; i < k; ++i) st_d_at(cx, st.x, v0, regs[i]);
        } else {
            for (int i = 0; i < k && i < n; ++i)
                st_d_at(cx, st.x, cx.vtmp(static_cast<unsigned>(i)), regs[i]);
        }
    } else if (form.single_lane) {
        // Exactly lb/8 bytes move, and every untouched lane of each register
        // is preserved, so the destinations are pre-loaded.
        // [carry-over 9] This is the case the LLVM lifter transfers as a full
        // 8 bytes, clobbering the register on load and overwriting
        // neighbouring memory on store.
        const unsigned idx = form.index;
        const unsigned lanes = static_cast<unsigned>(64 / lb);
        if (idx >= lanes) { pred_end(cx, g); return false; }
        for (int i = 0; i < k; ++i)
            ld_d_at(cx, st.x, cx.vtmp(static_cast<unsigned>(i)), regs[i]);
        // opcode base by element width, plus the structure-count selector.
        unsigned opcode_base, size_f;
        bool q_bit, s_bit;
        switch (lb) {
            case 8:
                opcode_base = 0; size_f = idx & 3u;
                s_bit = ((idx >> 2) & 1u) != 0; q_bit = ((idx >> 3) & 1u) != 0;
                break;
            case 16:
                opcode_base = 2; size_f = (idx & 1u) << 1;
                s_bit = ((idx >> 1) & 1u) != 0; q_bit = ((idx >> 2) & 1u) != 0;
                break;
            case 32:
                opcode_base = 4; size_f = 0;
                s_bit = (idx & 1u) != 0; q_bit = ((idx >> 1) & 1u) != 0;
                break;
            default:  // 64
                opcode_base = 4; size_f = 1; s_bit = false;
                q_bit = (idx & 1u) != 0;
                break;
        }
        const unsigned opcode = opcode_base | ((n >= 3) ? 1u : 0u);
        const bool r = (n == 2 || n == 4);
        put(cx, simd_ldst_single(q_bit, is_load, r, opcode, s_bit, size_f,
                                 xp, v0));
        if (is_load) {
            for (int i = 0; i < k; ++i)
                st_d_at(cx, st.x, cx.vtmp(static_cast<unsigned>(i)), regs[i]);
        }
    } else if (n == 2 && k == 4) {
        // ARM32's VLD2/VST2 "type == 0b0011" shape: regs == 2 passes with
        // inc == 2 (DDI 0406C.d A8.8.331 pseudocode). Pass r de-interleaves
        // 16 bytes into D[d+r] and D[d+r+2], so with Capstone's ascending
        // register list the pairs are (regs[0], regs[2]) then
        // (regs[1], regs[3]). A64's LD2 handles two registers at a time, so
        // this is two passes 16 bytes apart.
        const unsigned v1 = cx.vtmp(1);
        const unsigned xp2 = cx.tmp[3];
        put(cx, add_imm(true, xp2, xp, 16));
        for (int pass = 0; pass < 2; ++pass) {
            const int ra = regs[pass];
            const int rb = regs[pass + 2];
            const unsigned base = (pass == 0) ? xp : xp2;
            if (!is_load) {
                ld_d_at(cx, st.x, v0, ra);
                ld_d_at(cx, st.x, v1, rb);
            }
            put(cx, simd_ldst_multi(/*q=*/false, is_load, multi_op, esize,
                                    base, v0));
            if (is_load) {
                st_d_at(cx, st.x, v0, ra);
                st_d_at(cx, st.x, v1, rb);
            }
        }
    } else {
        if (!is_load) {
            for (int i = 0; i < k; ++i)
                ld_d_at(cx, st.x, cx.vtmp(static_cast<unsigned>(i)), regs[i]);
        }
        put(cx, simd_ldst_multi(/*q=*/false, is_load, multi_op, esize, xp, v0));
        if (is_load) {
            for (int i = 0; i < k; ++i)
                st_d_at(cx, st.x, cx.vtmp(static_cast<unsigned>(i)), regs[i]);
        }
    }

    // Writeback: `[Rn]!` advances by the transferred size; `[Rn], Rm` by Rm.
    if (d.writeback || post_inc_reg >= 0) {
        const int rbase = arm_core_idx(d.operands[mem_idx].mem.base);
        if (rbase >= 0 && rbase != 15) {
            const unsigned wb = host_reg(rbase);
            if (post_inc_reg >= 0 && post_inc_reg != 15) {
                put(cx, add_reg(false, wb, wb, host_reg(post_inc_reg)));
            } else {
                emit_add_imm32(cx, wb, wb, total, cx.tmp[3]);
            }
        }
    }
    pred_end(cx, g);
    return true;
}

}  // namespace

// ==================================================================

bool is_simd_insn(unsigned id) {
    switch (id) {
        case ARM_INS_VMOV: case ARM_INS_FCONSTS: case ARM_INS_FCONSTD:
        case ARM_INS_FMDHR: case ARM_INS_FMDLR:
        case ARM_INS_VLDR: case ARM_INS_VSTR:
        case ARM_INS_VLDMIA: case ARM_INS_VLDMDB:
        case ARM_INS_VSTMIA: case ARM_INS_VSTMDB:
        case ARM_INS_VPUSH: case ARM_INS_VPOP:
        case ARM_INS_VADD: case ARM_INS_VSUB: case ARM_INS_VMUL:
        case ARM_INS_VDIV: case ARM_INS_VNMUL:
        case ARM_INS_VABS: case ARM_INS_VNEG: case ARM_INS_VSQRT:
        case ARM_INS_VMLA: case ARM_INS_VMLS:
        case ARM_INS_VNMLA: case ARM_INS_VNMLS:
        case ARM_INS_VFMA: case ARM_INS_VFMS:
        case ARM_INS_VFNMA: case ARM_INS_VFNMS:
        case ARM_INS_VCMP: case ARM_INS_VCMPE:
        case ARM_INS_VMRS: case ARM_INS_FMSTAT: case ARM_INS_VMSR:
        case ARM_INS_VCVT: case ARM_INS_VCVTR:
        case ARM_INS_VCVTB: case ARM_INS_VCVTT:
        case ARM_INS_VAND: case ARM_INS_VORR: case ARM_INS_VEOR:
        case ARM_INS_VBIC: case ARM_INS_VORN: case ARM_INS_VMVN:
        case ARM_INS_VBSL: case ARM_INS_VBIT: case ARM_INS_VBIF:
        case ARM_INS_VCEQ: case ARM_INS_VCGT: case ARM_INS_VCGE:
        case ARM_INS_VCLT: case ARM_INS_VCLE: case ARM_INS_VTST:
        case ARM_INS_VMIN: case ARM_INS_VMAX:
        case ARM_INS_VSHL: case ARM_INS_VSHR:
        case ARM_INS_VZIP: case ARM_INS_VUZP: case ARM_INS_VTRN:
        case ARM_INS_VEXT: case ARM_INS_VDUP:
        case ARM_INS_VLD1: case ARM_INS_VLD2:
        case ARM_INS_VLD3: case ARM_INS_VLD4:
        case ARM_INS_VST1: case ARM_INS_VST2:
        case ARM_INS_VST3: case ARM_INS_VST4:
        // ---- added by the coverage pass ----------------------------
        // Widening / narrowing three-register.
        case ARM_INS_VMULL: case ARM_INS_VMLAL: case ARM_INS_VMLSL:
        case ARM_INS_VQDMULL: case ARM_INS_VQDMLAL: case ARM_INS_VQDMLSL:
        case ARM_INS_VADDL: case ARM_INS_VSUBL:
        case ARM_INS_VADDW: case ARM_INS_VSUBW:
        case ARM_INS_VABAL: case ARM_INS_VABDL:
        case ARM_INS_VADDHN: case ARM_INS_VSUBHN:
        case ARM_INS_VRADDHN: case ARM_INS_VRSUBHN:
        // Width-changing two-register.
        case ARM_INS_VMOVL: case ARM_INS_VMOVN: case ARM_INS_VSHLL:
        case ARM_INS_VQMOVN: case ARM_INS_VQMOVUN:
        case ARM_INS_VPADDL: case ARM_INS_VPADAL:
        // Element reverse / bit counting.
        case ARM_INS_VREV16: case ARM_INS_VREV32: case ARM_INS_VREV64:
        case ARM_INS_VCLS: case ARM_INS_VCLZ: case ARM_INS_VCNT:
        // Shift-by-immediate members beyond VSHL / VSHR.
        case ARM_INS_VSRA: case ARM_INS_VRSHR: case ARM_INS_VRSRA:
        case ARM_INS_VSRI: case ARM_INS_VSLI:
        case ARM_INS_VSHRN: case ARM_INS_VRSHRN:
        case ARM_INS_VQSHRN: case ARM_INS_VQSHRUN:
        case ARM_INS_VQRSHRN: case ARM_INS_VQRSHRUN:
        // Saturating / rounding three-register.
        case ARM_INS_VQADD: case ARM_INS_VQSUB:
        case ARM_INS_VQSHL: case ARM_INS_VQSHLU:
        case ARM_INS_VQRSHL: case ARM_INS_VRSHL:
        case ARM_INS_VQABS: case ARM_INS_VQNEG:
        case ARM_INS_VQDMULH: case ARM_INS_VQRDMULH:
        // Averaging / absolute-difference / pairwise.
        case ARM_INS_VHADD: case ARM_INS_VHSUB: case ARM_INS_VRHADD:
        case ARM_INS_VABD: case ARM_INS_VABA:
        case ARM_INS_VPADD: case ARM_INS_VPMAX: case ARM_INS_VPMIN:
        // Estimates, absolute compares and the table lookups.
        case ARM_INS_VRECPE: case ARM_INS_VRSQRTE:
        case ARM_INS_VRECPS: case ARM_INS_VRSQRTS:
        case ARM_INS_VACGE: case ARM_INS_VACGT:
        case ARM_INS_VTBL: case ARM_INS_VTBX: case ARM_INS_VSWP:
        // ARMv8-in-A32 VFP.
        case ARM_INS_VMAXNM: case ARM_INS_VMINNM:
        case ARM_INS_VSELEQ: case ARM_INS_VSELVS:
        case ARM_INS_VSELGE: case ARM_INS_VSELGT:
        case ARM_INS_VRINTA: case ARM_INS_VRINTM: case ARM_INS_VRINTN:
        case ARM_INS_VRINTP: case ARM_INS_VRINTR: case ARM_INS_VRINTX:
        case ARM_INS_VRINTZ:
        // VFPv1 legacy load/store-multiple.
        case ARM_INS_FSTMIAX: case ARM_INS_FSTMDBX:
        case ARM_INS_FLDMIAX: case ARM_INS_FLDMDBX:
            return true;
        default:
            // DELIBERATELY NOT CLAIMED, so the stub stays visible:
            //  * ARM_INS_VLSTM / ARM_INS_VLLDM are the ARMv8-M Security
            //    Extension lazy-FP save/restore (DDI 0553B.y B4.5). They are
            //    UNDEFINED on ARMv7-A and ARMv8-A AArch32, the only profiles
            //    Apk on Mac loads, so every occurrence is misdecoded data and
            //    inventing a behaviour for them would hide that.
            //  * ARM_INS_VSDOT / ARM_INS_VUDOT need FEAT_DotProd, which the
            //    assembler in this tree refuses for an ARMv7 target and
            //    which no armeabi-v7a guest can therefore contain. There is
            //    also no way to build a differential case for them, and an
            //    unverifiable handler is worse than a visible stub.
            return false;
    }
}

bool translate_simd(XlatMemCtx& cx, const cs_insn* in, XlatResult* result) {
    if (result) *result = XlatResult{};
    if (!in || !in->detail || !cx.buf) return false;
    if (!is_simd_insn(in->id)) return false;

    const cs_arm& d = in->detail->arm;
    const bool scalar = is_vfp_scalar(d);
    bool ok = false;

    switch (in->id) {
        // ---- VMOV and its Capstone aliases ------------------------
        case ARM_INS_VMOV:
        case ARM_INS_FCONSTS: case ARM_INS_FCONSTD:
        case ARM_INS_FMDHR:   case ARM_INS_FMDLR:
            ok = xlat_vmov(cx, in);
            break;

        // ---- VFP memory -------------------------------------------
        case ARM_INS_VLDR: ok = xlat_vldr_vstr(cx, in, true); break;
        case ARM_INS_VSTR: ok = xlat_vldr_vstr(cx, in, false); break;
        case ARM_INS_VLDMIA:
            ok = xlat_vldm_vstm(cx, in, true, false, -1, false, 0); break;
        case ARM_INS_VLDMDB:
            ok = xlat_vldm_vstm(cx, in, true, true, -1, false, 0); break;
        case ARM_INS_VSTMIA:
            ok = xlat_vldm_vstm(cx, in, false, false, -1, false, 0); break;
        case ARM_INS_VSTMDB:
            ok = xlat_vldm_vstm(cx, in, false, true, -1, false, 0); break;
        case ARM_INS_VPOP:
            ok = xlat_vldm_vstm(cx, in, true, false, kSP, true, 0); break;
        case ARM_INS_VPUSH:
            ok = xlat_vldm_vstm(cx, in, false, true, kSP, true, 0); break;
        // The VFPv1 "X" forms reserve one extra word past the register
        // block; see the note above xlat_vldm_vstm.
        case ARM_INS_FLDMIAX:
            ok = xlat_vldm_vstm(cx, in, true, false, -1, false, 4); break;
        case ARM_INS_FLDMDBX:
            ok = xlat_vldm_vstm(cx, in, true, true, -1, false, 4); break;
        case ARM_INS_FSTMIAX:
            ok = xlat_vldm_vstm(cx, in, false, false, -1, false, 4); break;
        case ARM_INS_FSTMDBX:
            ok = xlat_vldm_vstm(cx, in, false, true, -1, false, 4); break;

        // ---- arithmetic: scalar VFP or packed NEON ----------------
        case ARM_INS_VADD:
            ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x2, false)
                        : xlat_neon_3same(cx, in, V3::ADD, false);
            break;
        case ARM_INS_VSUB:
            ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x3, false)
                        : xlat_neon_3same(cx, in, V3::SUB, false);
            break;
        case ARM_INS_VMUL:
            // The BY-ELEMENT form `vmul.i16 d0,d1,d2[1]` arrives looking
            // exactly like the three-register form except for the index,
            // so it must be tested for BEFORE the vector path claims it.
            if (!scalar && is_by_element(d))
                ok = xlat_neon_indexed(cx, in, VIdx::MUL);
            else
                ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x0, false)
                            : xlat_neon_3same(cx, in, V3::MUL, false);
            break;
        case ARM_INS_VDIV:
            ok = xlat_vfp_scalar_arith(cx, in, 0x1, false);
            break;
        case ARM_INS_VNMUL:
            ok = xlat_vfp_scalar_arith(cx, in, 0x8, false);
            break;
        case ARM_INS_VABS:
            ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x01, true)
                        : xlat_neon_2misc(cx, in, V2::ABS, 1);
            break;
        case ARM_INS_VNEG:
            // [carry-over 6] the integer form must NOT fall into the scalar
            // FNEG path.
            ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x02, true)
                        : xlat_neon_2misc(cx, in, V2::NEG, 1);
            break;
        case ARM_INS_VSQRT:
            ok = scalar ? xlat_vfp_scalar_arith(cx, in, 0x03, true)
                        : xlat_neon_2misc(cx, in, V2::SQRT, 1);
            break;

        case ARM_INS_VMLA:
            if (!scalar && is_by_element(d))
                ok = xlat_neon_indexed(cx, in, VIdx::MLA);
            else
                ok = scalar ? xlat_vfp_mac(cx, in, MacOp::VMLA)
                            : xlat_neon_3same(cx, in, V3::MLA, false);
            break;
        case ARM_INS_VMLS:
            if (!scalar && is_by_element(d))
                ok = xlat_neon_indexed(cx, in, VIdx::MLS);
            else
                ok = scalar ? xlat_vfp_mac(cx, in, MacOp::VMLS)
                            : xlat_neon_3same(cx, in, V3::MLS, false);
            break;
        case ARM_INS_VNMLA: ok = xlat_vfp_mac(cx, in, MacOp::VNMLA); break;
        case ARM_INS_VNMLS: ok = xlat_vfp_mac(cx, in, MacOp::VNMLS); break;
        case ARM_INS_VFMA:  ok = xlat_vfp_mac(cx, in, MacOp::VFMA);  break;
        case ARM_INS_VFMS:  ok = xlat_vfp_mac(cx, in, MacOp::VFMS);  break;
        case ARM_INS_VFNMA: ok = xlat_vfp_mac(cx, in, MacOp::VFNMA); break;
        case ARM_INS_VFNMS: ok = xlat_vfp_mac(cx, in, MacOp::VFNMS); break;

        // ---- flags -------------------------------------------------
        case ARM_INS_VCMP:  ok = xlat_vcmp(cx, in, false); break;
        case ARM_INS_VCMPE: ok = xlat_vcmp(cx, in, true);  break;
        case ARM_INS_VMRS:
        case ARM_INS_FMSTAT: ok = xlat_vmrs(cx, in); break;
        case ARM_INS_VMSR:   ok = xlat_vmsr(cx, in); break;

        // ---- conversions -------------------------------------------
        case ARM_INS_VCVT:  ok = xlat_vcvt(cx, in, false); break;
        case ARM_INS_VCVTR: ok = xlat_vcvt(cx, in, true);  break;
        case ARM_INS_VCVTB: ok = xlat_vcvt_half(cx, in, false); break;
        case ARM_INS_VCVTT: ok = xlat_vcvt_half(cx, in, true);  break;

        // ---- NEON logical -------------------------------------------
        case ARM_INS_VAND: ok = xlat_neon_3same(cx, in, V3::AND, false); break;
        case ARM_INS_VEOR: ok = xlat_neon_3same(cx, in, V3::EOR, false); break;
        case ARM_INS_VORN: ok = xlat_neon_3same(cx, in, V3::ORN, false); break;
        case ARM_INS_VBSL: ok = xlat_neon_3same(cx, in, V3::BSL, false); break;
        case ARM_INS_VBIT: ok = xlat_neon_3same(cx, in, V3::BIT, false); break;
        case ARM_INS_VBIF: ok = xlat_neon_3same(cx, in, V3::BIF, false); break;
        case ARM_INS_VORR:
            // [carry-over 3] The register form is the NEON register-move
            // idiom `vorr dd,dn,dn` and MUST be handled; the lifter's
            // immediate-only path dropped it and left the destination
            // holding garbage that a later VST1 committed to memory.
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_REG)
                     ? xlat_neon_3same(cx, in, V3::ORR, false)
                     : xlat_neon_imm_logical(cx, in, VImmOp::ORR);
            break;
        case ARM_INS_VBIC:
            // [carry-over 5] Both forms.
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_REG)
                     ? xlat_neon_3same(cx, in, V3::BIC, false)
                     : xlat_neon_imm_logical(cx, in, VImmOp::BIC);
            break;
        case ARM_INS_VMVN:
            // [carry-over 4] Register form dd = ~dm, immediate form
            // dd = ~replicate(imm).
            ok = (d.op_count >= 2 &&
                  d.operands[d.op_count - 1].type == ARM_OP_REG)
                     ? xlat_neon_2misc(cx, in, V2::NOT, d.op_count - 1)
                     : xlat_neon_imm_logical(cx, in, VImmOp::MVN);
            break;

        // ---- NEON compares -----------------------------------------
        // [carry-over 7] The `, #0` immediate forms take the
        // compare-against-zero 2misc encodings instead of no-opping.
        case ARM_INS_VCEQ:
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM)
                     ? xlat_neon_2misc(cx, in, V2::CEQ0, 1)
                     : xlat_neon_3same(cx, in, V3::CEQ, false);
            break;
        case ARM_INS_VCGT:
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM)
                     ? xlat_neon_2misc(cx, in, V2::CGT0, 1)
                     : xlat_neon_3same(cx, in, V3::CGT, false);
            break;
        case ARM_INS_VCGE:
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM)
                     ? xlat_neon_2misc(cx, in, V2::CGE0, 1)
                     : xlat_neon_3same(cx, in, V3::CGE, false);
            break;
        case ARM_INS_VCLT:
            // A64 has no register CLT; it is CGT with the operands swapped.
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM)
                     ? xlat_neon_2misc(cx, in, V2::CLT0, 1)
                     : xlat_neon_3same(cx, in, V3::CGT, /*swap_ops=*/true);
            break;
        case ARM_INS_VCLE:
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_IMM)
                     ? xlat_neon_2misc(cx, in, V2::CLE0, 1)
                     : xlat_neon_3same(cx, in, V3::CGE, /*swap_ops=*/true);
            break;
        case ARM_INS_VTST: ok = xlat_neon_3same(cx, in, V3::TST, false); break;
        case ARM_INS_VMIN: ok = xlat_neon_3same(cx, in, V3::MIN, false); break;
        case ARM_INS_VMAX: ok = xlat_neon_3same(cx, in, V3::MAX, false); break;

        // ---- NEON permutes / shifts / broadcast ---------------------
        case ARM_INS_VZIP:
            ok = xlat_vperm(cx, in, kPermZip1, kPermZip2); break;
        case ARM_INS_VUZP:
            ok = xlat_vperm(cx, in, kPermUzp1, kPermUzp2); break;
        case ARM_INS_VTRN:
            ok = xlat_vperm(cx, in, kPermTrn1, kPermTrn2); break;
        case ARM_INS_VEXT: ok = xlat_vext(cx, in); break;
        case ARM_INS_VDUP: ok = xlat_vdup(cx, in); break;
        case ARM_INS_VSHL:
            // The register-amount form is a different encoding class
            // (SSHL/USHL) from the immediate form (SHL).
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_REG)
                     ? xlat_neon_3same(cx, in, V3::SHL, false)
                     : xlat_vshift_imm(cx, in, VShImm::SHL);
            break;
        case ARM_INS_VSHR: ok = xlat_vshift_imm(cx, in, VShImm::SHR); break;

        // ---- widening / narrowing three-register ---------------------
        case ARM_INS_VMULL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::MULL)
                                  : xlat_neon_3diff(cx, in, V3D::MULL);
            break;
        case ARM_INS_VMLAL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::MLAL)
                                  : xlat_neon_3diff(cx, in, V3D::MLAL);
            break;
        case ARM_INS_VMLSL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::MLSL)
                                  : xlat_neon_3diff(cx, in, V3D::MLSL);
            break;
        case ARM_INS_VQDMULL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::QDMULL)
                                  : xlat_neon_3diff(cx, in, V3D::QDMULL);
            break;
        case ARM_INS_VQDMLAL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::QDMLAL)
                                  : xlat_neon_3diff(cx, in, V3D::QDMLAL);
            break;
        case ARM_INS_VQDMLSL:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::QDMLSL)
                                  : xlat_neon_3diff(cx, in, V3D::QDMLSL);
            break;
        case ARM_INS_VADDL: ok = xlat_neon_3diff(cx, in, V3D::ADDL); break;
        case ARM_INS_VSUBL: ok = xlat_neon_3diff(cx, in, V3D::SUBL); break;
        case ARM_INS_VADDW: ok = xlat_neon_3diff(cx, in, V3D::ADDW); break;
        case ARM_INS_VSUBW: ok = xlat_neon_3diff(cx, in, V3D::SUBW); break;
        case ARM_INS_VABAL: ok = xlat_neon_3diff(cx, in, V3D::ABAL); break;
        case ARM_INS_VABDL: ok = xlat_neon_3diff(cx, in, V3D::ABDL); break;
        case ARM_INS_VADDHN:  ok = xlat_neon_3diff(cx, in, V3D::ADDHN);  break;
        case ARM_INS_VSUBHN:  ok = xlat_neon_3diff(cx, in, V3D::SUBHN);  break;
        case ARM_INS_VRADDHN: ok = xlat_neon_3diff(cx, in, V3D::RADDHN); break;
        case ARM_INS_VRSUBHN: ok = xlat_neon_3diff(cx, in, V3D::RSUBHN); break;

        // ---- width-changing two-register -----------------------------
        case ARM_INS_VMOVL: ok = xlat_vmovl_vshll(cx, in, false); break;
        case ARM_INS_VSHLL: ok = xlat_vmovl_vshll(cx, in, true);  break;
        case ARM_INS_VMOVN:   ok = xlat_vmovn(cx, in, VNarrow::MOVN);   break;
        case ARM_INS_VQMOVN:  ok = xlat_vmovn(cx, in, VNarrow::QMOVN);  break;
        case ARM_INS_VQMOVUN: ok = xlat_vmovn(cx, in, VNarrow::QMOVUN); break;
        case ARM_INS_VPADDL: ok = xlat_vpaddl(cx, in, false); break;
        case ARM_INS_VPADAL: ok = xlat_vpaddl(cx, in, true);  break;

        // ---- element reverse / bit counting --------------------------
        case ARM_INS_VREV64: ok = xlat_neon_2misc(cx, in, V2::REV64, 1); break;
        case ARM_INS_VREV32: ok = xlat_neon_2misc(cx, in, V2::REV32, 1); break;
        case ARM_INS_VREV16: ok = xlat_neon_2misc(cx, in, V2::REV16, 1); break;
        case ARM_INS_VCLS:   ok = xlat_neon_2misc(cx, in, V2::CLS, 1);   break;
        case ARM_INS_VCLZ:   ok = xlat_neon_2misc(cx, in, V2::CLZ, 1);   break;
        case ARM_INS_VCNT:   ok = xlat_neon_2misc(cx, in, V2::CNT, 1);   break;
        case ARM_INS_VQABS:  ok = xlat_neon_2misc(cx, in, V2::QABS, 1);  break;
        case ARM_INS_VQNEG:  ok = xlat_neon_2misc(cx, in, V2::QNEG, 1);  break;
        case ARM_INS_VRECPE: ok = xlat_neon_2misc(cx, in, V2::RECPE, 1); break;
        case ARM_INS_VRSQRTE:ok = xlat_neon_2misc(cx, in, V2::RSQRTE, 1);break;

        // ---- the rest of the shift-by-immediate family ---------------
        case ARM_INS_VSRA:  ok = xlat_vshift_imm(cx, in, VShImm::SRA);  break;
        case ARM_INS_VRSHR: ok = xlat_vshift_imm(cx, in, VShImm::RSHR); break;
        case ARM_INS_VRSRA: ok = xlat_vshift_imm(cx, in, VShImm::RSRA); break;
        case ARM_INS_VSRI:  ok = xlat_vshift_imm(cx, in, VShImm::SRI);  break;
        case ARM_INS_VSLI:  ok = xlat_vshift_imm(cx, in, VShImm::SLI);  break;
        case ARM_INS_VQSHLU:ok = xlat_vshift_imm(cx, in, VShImm::QSHLU);break;
        case ARM_INS_VQSHL:
            // Same register-vs-immediate split as VSHL.
            ok = (d.op_count == 3 && d.operands[2].type == ARM_OP_REG)
                     ? xlat_neon_3same(cx, in, V3::QSHL, false)
                     : xlat_vshift_imm(cx, in, VShImm::QSHL);
            break;
        case ARM_INS_VSHRN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::SHRN); break;
        case ARM_INS_VRSHRN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::RSHRN); break;
        case ARM_INS_VQSHRN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::QSHRN); break;
        case ARM_INS_VQSHRUN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::QSHRUN); break;
        case ARM_INS_VQRSHRN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::QRSHRN); break;
        case ARM_INS_VQRSHRUN:
            ok = xlat_vshift_narrow(cx, in, VShNarrow::QRSHRUN); break;

        // ---- saturating / averaging / pairwise three-register --------
        case ARM_INS_VQADD:  ok = xlat_neon_3same(cx, in, V3::QADD, false); break;
        case ARM_INS_VQSUB:  ok = xlat_neon_3same(cx, in, V3::QSUB, false); break;
        case ARM_INS_VQRSHL: ok = xlat_neon_3same(cx, in, V3::QRSHL, false); break;
        case ARM_INS_VRSHL:  ok = xlat_neon_3same(cx, in, V3::RSHL, false); break;
        case ARM_INS_VHADD:  ok = xlat_neon_3same(cx, in, V3::HADD, false); break;
        case ARM_INS_VHSUB:  ok = xlat_neon_3same(cx, in, V3::HSUB, false); break;
        case ARM_INS_VRHADD: ok = xlat_neon_3same(cx, in, V3::RHADD, false); break;
        case ARM_INS_VABD:   ok = xlat_neon_3same(cx, in, V3::ABD, false); break;
        case ARM_INS_VABA:   ok = xlat_neon_3same(cx, in, V3::ABA, false); break;
        case ARM_INS_VPADD:  ok = xlat_neon_3same(cx, in, V3::PADD, false); break;
        case ARM_INS_VPMAX:  ok = xlat_neon_3same(cx, in, V3::PMAX, false); break;
        case ARM_INS_VPMIN:  ok = xlat_neon_3same(cx, in, V3::PMIN, false); break;
        case ARM_INS_VACGE:  ok = xlat_neon_3same(cx, in, V3::ACGE, false); break;
        case ARM_INS_VACGT:  ok = xlat_neon_3same(cx, in, V3::ACGT, false); break;
        case ARM_INS_VRECPS: ok = xlat_neon_3same(cx, in, V3::RECPS, false); break;
        case ARM_INS_VRSQRTS:ok = xlat_neon_3same(cx, in, V3::RSQRTS, false); break;
        case ARM_INS_VQDMULH:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::QDMULH)
                                  : xlat_neon_3same(cx, in, V3::QDMULH, false);
            break;
        case ARM_INS_VQRDMULH:
            ok = is_by_element(d) ? xlat_neon_indexed(cx, in, VIdx::QRDMULH)
                                  : xlat_neon_3same(cx, in, V3::QRDMULH, false);
            break;

        // ---- table lookup and register exchange ----------------------
        case ARM_INS_VTBL: ok = xlat_vtbl(cx, in, false); break;
        case ARM_INS_VTBX: ok = xlat_vtbl(cx, in, true);  break;
        case ARM_INS_VSWP: ok = xlat_vswp(cx, in); break;

        // ---- ARMv8-in-A32 VFP ----------------------------------------
        case ARM_INS_VMAXNM: ok = xlat_vfp_minmaxnm(cx, in, true);  break;
        case ARM_INS_VMINNM: ok = xlat_vfp_minmaxnm(cx, in, false); break;
        case ARM_INS_VSELEQ: ok = xlat_vsel(cx, in, ARM_CC_EQ); break;
        case ARM_INS_VSELVS: ok = xlat_vsel(cx, in, ARM_CC_VS); break;
        case ARM_INS_VSELGE: ok = xlat_vsel(cx, in, ARM_CC_GE); break;
        case ARM_INS_VSELGT: ok = xlat_vsel(cx, in, ARM_CC_GT); break;
        // VRINTR rounds using the FPSCR mode; A64's FRINTI is the same
        // operation. VRINTX additionally raises Inexact, which is FRINTX.
        case ARM_INS_VRINTR: ok = xlat_vrint(cx, in, 0x0F); break;
        case ARM_INS_VRINTX: ok = xlat_vrint(cx, in, 0x0E); break;
        case ARM_INS_VRINTZ: ok = xlat_vrint(cx, in, 0x0B); break;
        case ARM_INS_VRINTA: ok = xlat_vrint(cx, in, 0x0C); break;
        case ARM_INS_VRINTN: ok = xlat_vrint(cx, in, 0x08); break;
        case ARM_INS_VRINTM: ok = xlat_vrint(cx, in, 0x0A); break;
        case ARM_INS_VRINTP: ok = xlat_vrint(cx, in, 0x09); break;

        // ---- NEON structure load / store ----------------------------
        case ARM_INS_VLD1: ok = xlat_neon_ldst(cx, in, true, 1); break;
        case ARM_INS_VLD2: ok = xlat_neon_ldst(cx, in, true, 2); break;
        case ARM_INS_VLD3: ok = xlat_neon_ldst(cx, in, true, 3); break;
        case ARM_INS_VLD4: ok = xlat_neon_ldst(cx, in, true, 4); break;
        case ARM_INS_VST1: ok = xlat_neon_ldst(cx, in, false, 1); break;
        case ARM_INS_VST2: ok = xlat_neon_ldst(cx, in, false, 2); break;
        case ARM_INS_VST3: ok = xlat_neon_ldst(cx, in, false, 3); break;
        case ARM_INS_VST4: ok = xlat_neon_ldst(cx, in, false, 4); break;

        default:
            return false;
    }

    if (!ok) {
        warn(cx, std::string("unhandled VFP/NEON form: ") + in->mnemonic +
                     " " + in->op_str);
    }
    if (result) result->handled = ok;
    return ok;
}

}  // namespace arm32rc
}  // namespace macapk
