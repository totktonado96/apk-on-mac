// xlat_simd.h -- direct ARM32/Thumb -> arm64 recompiler: the VFP / NEON
// translation stage.
//
// Owns:
//   VFP  VMOV (every form, including the GP<->FP transfers and the lane
//        insert/extract), VLDR / VSTR, VLDM / VSTM / VPUSH / VPOP,
//        VADD / VSUB / VMUL / VDIV / VABS / VNEG / VSQRT / VNMUL,
//        VMLA / VMLS / VNMLA / VNMLS / VFMA / VFMS / VFNMA / VFNMS,
//        VCMP / VCMPE + VMRS / VMSR, the VCVT family and VCVTR.
//   NEON VLD1-4 / VST1-4 in the multi-structure, single-lane and
//        load-to-all-lanes forms; VMOV.i / VMVN.i; VAND / VORR / VBIC /
//        VEOR / VORN / VMVN / VBSL / VBIT / VBIF (register AND immediate
//        forms); VADD / VSUB / VMUL / VMLA / VMLS (integer and float);
//        VNEG / VABS (integer and float); VCEQ / VCGT / VCGE / VCLT /
//        VCLE / VTST against a register and against #0; VMIN / VMAX;
//        VSHL / VSHR (immediate); VZIP / VUZP / VTRN; VEXT; VDUP.
//        Widening / narrowing: VMULL / VMLAL / VMLSL / VQDMULL / VQDMLAL /
//        VQDMLSL / VADDL / VSUBL / VADDW / VSUBW / VABAL / VABDL /
//        VADDHN / VSUBHN / VRADDHN / VRSUBHN / VMOVL / VMOVN / VQMOVN /
//        VQMOVUN / VSHLL / VSHRN / VRSHRN / VQSHRN / VQSHRUN / VQRSHRN /
//        VQRSHRUN. Saturating / rounding: VQADD / VQSUB / VQSHL / VQSHLU /
//        VQRSHL / VRSHL / VQABS / VQNEG / VQDMULH / VQRDMULH. Rounding
//        shifts and insert-shifts: VSRA / VRSHR / VRSRA / VSRI / VSLI.
//        Pairwise: VPADD / VPADDL / VPADAL / VPMAX / VPMIN. Bit / lane
//        counting and permutes: VCLS / VCLZ / VCNT / VREV16 / VREV32 /
//        VREV64 / VSWP / VTBL / VTBX. Estimates and helpers: VRECPE /
//        VRSQRTE / VRECPS / VRSQRTS / VABD / VABA / VHADD / VHSUB /
//        VRHADD / VACGE / VACGT. The BY-ELEMENT ("by scalar") forms of
//        VMUL / VMLA / VMLS / VMULL / VMLAL / VMLSL / VQDMULL / VQDMLAL /
//        VQDMLSL / VQDMULH / VQRDMULH. ARMv8-in-A32: VMAXNM / VMINNM /
//        VSEL{EQ,VS,GE,GT} / VRINT{A,M,N,P,R,X,Z}. VFPv1 legacy:
//        FSTMIAX / FSTMDBX / FLDMIAX / FLDMDBX.
//
//   NOT owned, deliberately: VLSTM / VLLDM (the ARMv8-M Security Extension
//        lazy FP save/restore, DDI 0553B.y B4.5). They are UNDEFINED on
//        ARMv7-A / ARMv8-A AArch32, which is the only profile Mac.apk
//        loads, so every occurrence in a guest .so is misdecoded data.
//        Refusing them keeps the stub visible instead of inventing
//        behaviour. VSDOT / VUDOT are likewise left out: see the note at
//        translate_simd's default arm.
//
// =====================================================================
//  THE VFP / NEON REGISTER MODEL
// =====================================================================
//
// guest_state.h homes the guest VFP bank in MEMORY, as `GuestState::d[32]`
// at offset 0, and that decision does most of this file's work for it.
// ARM32 aliases three widths over the same bits (s2n / s2n+1 are the low /
// high halves of dn; qn is the pair (d2n, d2n+1)), and AArch64 has no
// register whose two halves are two other architectural registers. Against a
// contiguous little-endian array all three views are EXACT and FREE:
//
//     guest Sn  ==  4 bytes at kOffD + 4*n     ->  LDR/STR Sv, [Xstate, #4n]
//     guest Dn  ==  8 bytes at kOffD + 8*n     ->  LDR/STR Dv, [Xstate, #8n]
//     guest Qn  == 16 bytes at kOffD + 16*n    ->  LDR/STR Qv, [Xstate, #16n]
//
// Consequences that shape every handler below:
//
//  * A Q-form NEON operation is ONE 128-bit host instruction, not two
//    64-bit halves. The LLVM lifter had to split every Q operation into two
//    d-register halves and, for VZIP / VUZP, refused the Q form entirely
//    because a per-half decomposition is simply wrong there
//    (arm32_lifter.cpp emit_v_permute). Here ZIP1/ZIP2 on .16B is exact.
//
//  * An odd s-register (s1, s3, ...) costs nothing. A register-pinned model
//    would need DUP/INS lane shuffles to reach the high half of a Vn.
//
//  * `VMOV Sn, Rt` and `VMOV Rt, Sn` are a single STR / LDR, and a lane
//    insert / extract such as `VMOV.32 d0[1], r2` or `VMOV.S8 r0, d1[3]` is a
//    single STR / LDRSB at the aliased byte offset.
//
//  * The scratch vector registers are free for the whole instruction, so the
//    A64 structure loads (LD3 / LD4 and friends), which can only name
//    CONSECUTIVE V registers, are always satisfiable: they target
//    XlatMemCtx::vtmp(0..3) and the results are then stored to whichever
//    guest d[] slots the register list named. The ARM32 stride-2 lists
//    (`{d0,d2,d4}`) that a register-pinned model cannot express with a single
//    LD3 therefore cost nothing extra here.
//
// Cost is two loads plus a store around each operation, which guest_state.h
// already accounts for and earmarks for a later block-local caching pass.
//
// =====================================================================
//  CAPSTONE FACTS THIS FILE DEPENDS ON (measured, not assumed)
// =====================================================================
//
// C1. For the NEON structure loads and stores, `cs_arm_op::vector_index` is
//     ALWAYS -1, even for `vld1.32 {d5[1]}, [r0]`. Capstone renders the lane
//     in op_str but does not expose it in the detail struct. The lane index,
//     and the multi / single-lane / all-lanes form selector, are therefore
//     decoded here from the instruction word per ARM DDI 0406C.d A7.7,
//     A8.8.320 (VLD1 single element to one lane) and A8.8.321 (VLD1 single
//     element to all lanes). See neon_ls_decode().
//
//     This is not a theoretical concern: because arm32_lifter.cpp keys its
//     single-lane path off `vector_index >= 0`, that path never fires, and
//     `vld1.32 {d5[1]}` takes its generic branch, which loads a full 8 bytes
//     and clobbers the whole d-register (and on the store side writes 8 bytes
//     over 4 bytes of neighbouring memory). The recompiler does not inherit
//     that bug.
//
// C2. `vector_index` IS populated for VDUP and for the VMOV lane forms
//     (`vdup.32 q0, d1[1]` -> 1, `vmov.32 d0[1], r2` -> 1,
//     `vmov.s8 r0, d1[3]` -> 3), so those use it directly.
//
// C3. The NEON `[Rn:align]` alignment qualifier is reported in
//     `op.mem.disp` (`[r0:64]` -> disp 64, `[r0:256]` -> disp 256) and must
//     NOT be added to the address. Same trap arm32_lifter.cpp documents.
//     A64's structure loads have no alignment qualifier and simply permit
//     unaligned access, so dropping it is strictly more permissive and can
//     never introduce a fault the guest would not have taken.
//
// C4. The post-indexed register form `[Rn], Rm` reports writeback == 0 and
//     appends Rm as a REG operand AFTER the MEM operand; `[Rn]!` reports
//     writeback == 1 with no extra operand.
//
// C5. `vmov.f32 s1, #1.5` arrives as ARM_INS_FCONSTS/FCONSTD with an
//     ARM_OP_FP operand carrying the expanded double; `vmov.32 d0[1], r2`
//     arrives as ARM_INS_FMDHR/FMDLR rather than ARM_INS_VMOV. Both are
//     routed to the VMOV handler, as arm32_lifter.cpp also found.
//
// No em dashes (project convention). C++17, -Wall -Wextra clean.

#ifndef MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_SIMD_H_
#define MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_SIMD_H_

#include <capstone/capstone.h>

#include <cstdint>

#include "xlat_mem.h"

namespace macapk {
namespace arm32rc {

// =====================================================================
// A64 SIMD encoders that a64_emit.h does not (yet) name.
//
// Every base constant below was checked against clang's assembler on the host
// (`clang -c -arch arm64` then `otool -tvVj`) rather than read off a table,
// because one wrong bit here is a silent wrong-code bug that presents as guest
// memory corruption. Field layouts are ARM DDI 0487 chapter C4.1
// "A64 Instruction Set Encoding", Advanced SIMD groups.
// =====================================================================
namespace simdenc {

// Advanced SIMD two-register miscellaneous.
//   0 Q U 0 1 1 1 0 size<2> 1 0 0 0 0 opcode<5> 1 0 Rn Rd
// neg v0.8b, v1.8b == 0x2e20b820 (U=1, size=0, opcode=0x0b). Verified.
inline uint32_t simd_2misc(bool q, bool u, unsigned size, unsigned opcode,
                           unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0E000000u |
           ((size & 3u) << 22) | (0x10u << 17) | ((opcode & 0x1Fu) << 12) |
           (0x2u << 10) | ((rn & 31u) << 5) | (rd & 31u);
}
// 2misc opcodes (with the U bit that goes with them).
enum : unsigned {
    kMiscNot     = 0x05,  // U=1, size=0        NOT (a.k.a. MVN)
    kMiscCmgtZ   = 0x08,  // U=0                CMGT #0   / U=1: CMGE #0
    kMiscCmeqZ   = 0x09,  // U=0                CMEQ #0   / U=1: CMLE #0
    kMiscCmltZ   = 0x0A,  // U=0                CMLT #0
    kMiscAbsNeg  = 0x0B,  // U=0 ABS, U=1 NEG
    kMiscFcmgtZ  = 0x0C,  // U=0 FCMGT #0, U=1 FCMGE #0   (bit23 = 1)
    kMiscFcmeqZ  = 0x0D,  // U=0 FCMEQ #0, U=1 FCMLE #0   (bit23 = 1)
    kMiscFcmltZ  = 0x0E,  // U=0 FCMLT #0                 (bit23 = 1)
    kMiscFabsNeg = 0x0F,  // U=0 FABS, U=1 FNEG           (bit23 = 1)
    kMiscFcvtzs  = 0x1B,  // U=0 FCVTZS, U=1 FCVTZU       (bit23 = 1)
    kMiscScvtf   = 0x1D,  // U=0 SCVTF,  U=1 UCVTF        (bit23 = 0)
    kMiscFsqrt   = 0x1F,  // U=1                          (bit23 = 1)
};

// Advanced SIMD three-same opcodes not named in a64_emit.h.
enum : unsigned {
    k3sCmgt  = 0x06,  // U=0 CMGT (signed),   U=1 CMHI (unsigned)
    k3sCmge  = 0x07,  // U=0 CMGE (signed),   U=1 CMHS (unsigned)
    k3sSmax  = 0x0C,  // U=0 SMAX,            U=1 UMAX
    k3sSmin  = 0x0D,  // U=0 SMIN,            U=1 UMIN
    k3sCmtst = 0x11,  // U=0 CMTST,           U=1 CMEQ (register)
    k3sMla   = 0x12,  // U=0 MLA,             U=1 MLS
    k3sFadd  = 0x1A,  // U=0 FADD (sz in size<0>), FSUB when size<1> == 1
    k3sFmla  = 0x19,  // U=0 FMLA, and FMLS when size<1> == 1
    k3sFmul  = 0x1B,  // U=1 FMUL
    k3sFcmeq = 0x1C,  // U=0 FCMEQ; U=1 FCMGE; U=1 + size<1> FCMGT
    k3sFmax  = 0x1E,  // U=0 FMAX, and FMIN when size<1> == 1
    k3sFdiv  = 0x1F,  // U=1 FDIV
};

// ---------------------------------------------------------------------
// The SCALAR (single 64-bit lane) counterparts.
//
// This is a real trap, and it produced the only invalid instructions the
// corpus sweep found. ARM32 has 64-bit-lane D-register operations
// (`vadd.i64 d0,d1,d2`, `vshl.u64 d0,d1,d2`, `vshr.u64 d0,d1,#n`), but A64's
// VECTOR three-same / two-misc / shift-immediate groups only allow size == 11
// together with Q == 1 (the .2D arrangement); size == 11 with Q == 0 (which
// would be ".1D") is UNDEFINED. The 64-bit single-lane operation is instead
// the Advanced SIMD SCALAR group, which reuses the SAME U / size / opcode
// fields with a different base, so routing is a base swap and dropping Q.
//
// add d0,d1,d2 == 0x5ee28420 ; sub == 0x7ee28420 ; sshl == 0x5ee24420 ;
// neg d0,d1 == 0x7ee0b820 ; abs == 0x5ee0b820 ; cmeq d0,d1,#0 == 0x5ee09820 ;
// sshr d0,d1,#3 == 0x5f7d0420 ; shl d0,d1,#3 == 0x5f435420. All verified.
inline uint32_t simd_3same_scalar(bool u, unsigned size, unsigned opcode,
                                  unsigned rd, unsigned rn, unsigned rm) {
    return (u ? 0x20000000u : 0u) | 0x5E200400u | ((size & 3u) << 22) |
           ((rm & 31u) << 16) | ((opcode & 0x1Fu) << 11) |
           ((rn & 31u) << 5) | (rd & 31u);
}
inline uint32_t simd_2misc_scalar(bool u, unsigned size, unsigned opcode,
                                  unsigned rd, unsigned rn) {
    return (u ? 0x20000000u : 0u) | 0x5E200800u | ((size & 3u) << 22) |
           ((opcode & 0x1Fu) << 12) | ((rn & 31u) << 5) | (rd & 31u);
}
inline uint32_t simd_shift_imm_scalar(bool u, unsigned immh_immb,
                                      unsigned opcode, unsigned rd,
                                      unsigned rn) {
    return (u ? 0x20000000u : 0u) | 0x5F000400u | ((immh_immb & 0x7Fu) << 16) |
           ((opcode & 0x1Fu) << 11) | ((rn & 31u) << 5) | (rd & 31u);
}

// ---------------------------------------------------------------------
// Advanced SIMD vector x indexed element (the "by scalar" NEON forms).
//   0 Q U 0 1 1 1 1 size<2> L M Rm<4> opcode<4> H 0 Rn Rd
//
// ARM32 spells these `vmull.s16 q0, d1, d2[1]` / `vmul.f32 q0, q1, d2[0]`,
// and Capstone DOES report the lane in `op.vector_index` for them (measured;
// see the C2 note above and debug/implD_neon_probe.py). They therefore reach
// a same-width handler looking exactly like an ordinary three-register form,
// which is why they need catching explicitly rather than by shape.
//
// THE TRAP is the index split, which differs per element size:
//   size == 01 (16-bit)  index = H:L:M, and Rm is only FOUR bits (V0..V15)
//   size == 10 (32-bit)  index = H:L,   and M becomes Rm<4> (V0..V31)
//   size == 11 (64-bit)  index = H,     L is zero, M is Rm<4>
//
// Verified against clang's assembler on the host, one per shape:
//   smull   v0.4s, v1.4h, v2.h[1] == 0x0f52a020   (size 01, H:L:M = 0:0:1)
//   smull2  v0.4s, v1.8h, v2.h[3] == 0x4f72a020
//   smlal   v0.4s, v1.4h, v2.h[5] == 0x0f522820   (H:L:M = 1:0:1)
//   smlsl   v0.4s, v1.4h, v2.h[7] == 0x0f726820
//   smull   v0.2d, v1.2s, v2.s[1] == 0x0fa2a020   (size 10, H:L = 0:1)
//   umull   v0.2d, v1.2s, v2.s[3] == 0x2fa2a820
//   sqdmull v0.4s, v1.4h, v2.h[1] == 0x0f52b020
//   mul     v0.4h, v1.4h, v2.h[1] == 0x0f528020
//   mla     v0.4s, v1.4s, v2.s[1] == 0x6fa20020   (U == 1 for MLA/MLS)
//   fmul    v0.4s, v1.4s, v2.s[1] == 0x4fa29020
//   fmla    v0.2s, v1.2s, v2.s[0] == 0x0f821020
//   sqdmulh v0.4h, v1.4h, v2.h[2] == 0x0f62c020
//   sqrdmulh v0.4s,v1.4s, v2.s[2] == 0x4f82d820
// DDI 0487, C4.1.6 "Advanced SIMD vector x indexed element".
inline uint32_t simd_indexed(bool q, bool u, unsigned size, unsigned opcode,
                             unsigned rd, unsigned rn, unsigned rm,
                             unsigned index) {
    unsigned l = 0, m = 0, h = 0;
    if (size == 1) {            // 16-bit elements: H:L:M, Rm limited to 4 bits
        m = index & 1u;
        l = (index >> 1) & 1u;
        h = (index >> 2) & 1u;
    } else if (size == 3) {     // 64-bit elements: H only
        h = index & 1u;
        m = (rm >> 4) & 1u;
    } else {                    // 32-bit elements: H:L, M is Rm<4>
        l = index & 1u;
        h = (index >> 1) & 1u;
        m = (rm >> 4) & 1u;
    }
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0F000000u |
           ((size & 3u) << 22) | (l << 21) | (m << 20) | ((rm & 15u) << 16) |
           ((opcode & 15u) << 12) | (h << 11) | ((rn & 31u) << 5) | (rd & 31u);
}
// The `opcode` column of that group, and where its U bit comes from. This
// is NOT the same rule as in the three-same group and the difference is
// easy to get backwards: the same-width MLA / MLS are U == 1 while MUL is
// U == 0, the widening forms take U from the SOURCE SIGNEDNESS, the
// doubling (SQDM*) forms are signed-only with U == 0, and ALL the FP forms
// here are U == 0 -- including FMUL, which is U == 1 in the three-same
// group and U == 0 here (0x4fa29020 above has bit 29 clear).
enum : unsigned {
    kIdxMla    = 0x0, kIdxFmla   = 0x1, kIdxMlal   = 0x2, kIdxQdmlal = 0x3,
    kIdxMls    = 0x4, kIdxFmls   = 0x5, kIdxMlsl   = 0x6, kIdxQdmlsl = 0x7,
    kIdxMul    = 0x8, kIdxFmul   = 0x9, kIdxMull   = 0xA, kIdxQdmull = 0xB,
    kIdxQdmulh = 0xC, kIdxQrdmulh = 0xD,
};

// Advanced SIMD two-register misc opcodes this file adds beyond the set
// already named above. Verified:
//   urecpe  v0.2s, v1.2s == 0x0ea1c820      ursqrte v0.4s, v1.4s == 0x6ea1c820
//   frecpe  v0.4s, v1.4s == 0x4ea1d820      frsqrte v0.2s, v1.2s == 0x2ea1d820
//   sqabs   v0.4h, v1.4h == 0x0e607820      sqneg   v0.16b,v1.16b== 0x6e207820
//   cls     v0.8b, v1.8b == 0x0e204820      clz     v0.8h, v1.8h == 0x6e604820
//   cnt     v0.8b, v1.8b == 0x0e205820
//   rev64   v0.8b, v1.8b == 0x0e200820      rev32   v0.4h, v1.4h == 0x2e600820
//   rev16   v0.16b,v1.16b== 0x4e201820
//   saddlp  v0.4h, v1.8b == 0x0e202820      uaddlp  v0.4s, v1.8h == 0x6e602820
//   sadalp  v0.4h, v1.8b == 0x0e206820      uadalp  v0.2d, v1.4s == 0x6ea06820
//   xtn     v0.4h, v1.4s == 0x0e612820      sqxtn   v0.4h, v1.4s == 0x0e614820
//   uqxtn   v0.4h, v1.4s == 0x2e614820      sqxtun  v0.4h, v1.4s == 0x2e612820
//   shll    v0.8h, v1.8b, #8 == 0x2e213820
enum : unsigned {
    kMiscRev64  = 0x00,  // U=0 REV64,  U=1 REV32
    kMiscRev16  = 0x01,
    kMiscAddlp  = 0x02,  // U=0 SADDLP, U=1 UADDLP
    kMiscCls    = 0x04,  // U=0 CLS,    U=1 CLZ
    kMiscCnt    = 0x05,  // U=0 CNT     (U=1 is NOT/RBIT, already named)
    kMiscAdalp  = 0x06,  // U=0 SADALP, U=1 UADALP
    kMiscQabs   = 0x07,  // U=0 SQABS,  U=1 SQNEG
    kMiscXtn    = 0x12,  // U=0 XTN,    U=1 SQXTUN
    kMiscShll   = 0x13,  // U=1                        (shift == esize)
    kMiscQxtn   = 0x14,  // U=0 SQXTN,  U=1 UQXTN
    kMiscUrecpe = 0x1C,  // U=0 URECPE, U=1 URSQRTE    (bit23 = 0)
    kMiscFrecpe = 0x1D,  // U=0 FRECPE, U=1 FRSQRTE    (bit23 = 1)
    kMiscFrintN = 0x18,  // U=0 FRINTN(bit23=0)/FRINTP(bit23=1),
                         // U=1 FRINTA(bit23=0)
    kMiscFrintM = 0x19,  // U=0 FRINTM(bit23=0)/FRINTZ(bit23=1),
                         // U=1 FRINTX(bit23=0)/FRINTI(bit23=1)
};

// Advanced SIMD three-same opcodes this file adds. Verified:
//   sqadd  v0.4h,v1.4h,v2.4h == 0x0e620c20   uqsub  .16b == 0x6e222c20
//   shadd  v0.4h,...         == 0x0e620420   uhsub  .16b == 0x6e222420
//   srhadd v0.8b,...         == 0x0e221420   sqshl  .4h  == 0x0e624c20
//   srshl  v0.4h,...         == 0x0e625420   uqrshl .4s  == 0x6ea25c20
//   addp   v0.4h,...         == 0x0e62bc20   smaxp  .4h  == 0x0e62a420
//   uminp  v0.8b,...         == 0x2e22ac20   sqdmulh.4h  == 0x0e62b420
//   sqrdmulh v0.4s,...       == 0x6ea2b420   saba   .4h  == 0x0e627c20
//   uabd   v0.8b,...         == 0x2e227420   facge  .2s  == 0x2e22ec20
//   facgt  v0.4s,...         == 0x6ea2ec20   frecps .4s  == 0x4e22fc20
//   frsqrts v0.2s,...        == 0x0ea2fc20   fmaxnm .2s  == 0x0e22c420
//   fminnm v0.4s,...         == 0x4ea2c420   faddp  .2s  == 0x2e22d420
//   fmaxp  v0.2s,...         == 0x2e22f420   fminp  .2s  == 0x2ea2f420
//   fabd   v0.4s,...         == 0x6ea2d420
enum : unsigned {
    k3sHadd   = 0x00,  // U=0 SHADD,   U=1 UHADD
    k3sQadd   = 0x01,  // U=0 SQADD,   U=1 UQADD
    k3sRhadd  = 0x02,  // U=0 SRHADD,  U=1 URHADD
    k3sHsub   = 0x04,  // U=0 SHSUB,   U=1 UHSUB
    k3sQsub   = 0x05,  // U=0 SQSUB,   U=1 UQSUB
    k3sQshl   = 0x09,  // U=0 SQSHL,   U=1 UQSHL   (register amount)
    k3sRshl   = 0x0A,  // U=0 SRSHL,   U=1 URSHL
    k3sQrshl  = 0x0B,  // U=0 SQRSHL,  U=1 UQRSHL
    k3sAbd    = 0x0E,  // U=0 SABD,    U=1 UABD
    k3sAba    = 0x0F,  // U=0 SABA,    U=1 UABA
    k3sMaxp   = 0x14,  // U=0 SMAXP,   U=1 UMAXP
    k3sMinp   = 0x15,  // U=0 SMINP,   U=1 UMINP
    k3sQdmulh = 0x16,  // U=0 SQDMULH, U=1 SQRDMULH
    k3sAddp   = 0x17,
    k3sFmaxnm = 0x18,  // U=0 FMAXNM (size<1>=0) / FMINNM (size<1>=1)
    k3sFacge  = 0x1D,  // U=1 FACGE (size<1>=0) / FACGT (size<1>=1);
                       // U=0 FRECPS (size<1>=0) / FRSQRTS (size<1>=1)
    k3sFabd   = 0x1A,  // U=1 + size<1>=1 FABD; U=1 + size<1>=0 FADDP
};

// Advanced SIMD three-different (widening / narrowing). Verified:
//   smull  v0.4s,v1.4h,v2.4h == 0x0e62c020   umull .8h == 0x2e22c020
//   pmull  v0.8h,v1.8b,v2.8b == 0x0e22e020   smlal .4s == 0x0e628020
//   umlsl  v0.4s,...         == 0x2e62a020   sqdmull   == 0x0e62d020
//   sqdmlal v0.4s,...        == 0x0e629020   sqdmlsl   == 0x0e62b020
//   saddl  v0.4s,...         == 0x0e620020   uaddw     == 0x2e621020
//   ssubl  v0.4s,...         == 0x0e622020   usubw     == 0x2e623020
//   sabal  v0.4s,...         == 0x0e625020   uabdl     == 0x2e627020
//   addhn  v0.4h,v1.4s,v2.4s == 0x0e624020   raddhn    == 0x2e624020
//   subhn  v0.4h,...         == 0x0e626020   rsubhn    == 0x2e626020
// `size` is the SOURCE element size for the widening forms and the
// DESTINATION element size for the narrowing (xxHN) ones.
enum : unsigned {
    k3dAddl  = 0x0, k3dAddw  = 0x1, k3dSubl  = 0x2, k3dSubw = 0x3,
    k3dAddhn = 0x4, k3dAbal  = 0x5, k3dSubhn = 0x6, k3dAbdl = 0x7,
    k3dMlal  = 0x8, k3dQdmlal = 0x9, k3dMlsl = 0xA, k3dQdmlsl = 0xB,
    k3dMull  = 0xC, k3dQdmull = 0xD, k3dPmull = 0xE,
};

// Advanced SIMD shift-by-immediate opcodes this file adds. Verified:
//   ssra   v0.2s,v1.2s,#4 == 0x0f3c1420   usra  .8b #2 == 0x2f0e1420
//   srshr  v0.4h,v1.4h,#3 == 0x0f1d2420   ursra .4s #5 == 0x6f3b3420
//   sri    v0.8h,v1.8h,#3 == 0x6f1d4420   sli   .2s #5 == 0x2f255420
//   shrn   v0.4h,v1.4s,#3 == 0x0f1d8420   rshrn        == 0x0f1d8c20
//   sqshrn v0.4h,v1.4s,#3 == 0x0f1d9420   uqshrn       == 0x2f1d9420
//   sqrshrn               == 0x0f1d9c20   uqrshrn      == 0x2f1d9c20
//   sqshrun               == 0x2f1d8420   sqrshrun     == 0x2f1d8c20
//   sqshl  v0.4h,v1.4h,#3 == 0x0f137420   uqshl        == 0x2f137420
//   sqshlu                == 0x2f136420   sshll .4s #3 == 0x0f13a420
enum : unsigned {
    kShiftSsra   = 0x02,  // U selects SSRA / USRA
    kShiftSrshr  = 0x04,
    kShiftSrsra  = 0x06,
    kShiftSri    = 0x08,  // U == 1
    kShiftSli    = 0x0A,  // U == 1 (U == 0 at this opcode is SHL)
    kShiftSqshlu = 0x0C,  // U == 1
    kShiftSqshl  = 0x0E,  // U selects SQSHL / UQSHL
    kShiftShrn   = 0x10,  // U=0 SHRN,    U=1 SQSHRUN
    kShiftRshrn  = 0x11,  // U=0 RSHRN,   U=1 SQRSHRUN
    kShiftQshrn  = 0x12,  // U=0 SQSHRN,  U=1 UQSHRN
    kShiftQrshrn = 0x13,  // U=0 SQRSHRN, U=1 UQRSHRN
    kShiftShll   = 0x14,  // U selects SSHLL / USHLL (a.k.a. SXTL / UXTL)
};

// Advanced SIMD permute: ZIP1/ZIP2/UZP1/UZP2/TRN1/TRN2.
//   0 Q 0 0 1 1 1 0 size<2> 0 Rm 0 opcode<3> 1 0 Rn Rd
// zip1 v0.8b, v1.8b, v2.8b == 0x0e023820. Verified.
inline uint32_t simd_perm(bool q, unsigned size, unsigned opcode, unsigned rd,
                          unsigned rn, unsigned rm) {
    return (q ? 0x40000000u : 0u) | 0x0E000000u | ((size & 3u) << 22) |
           ((rm & 31u) << 16) | ((opcode & 7u) << 12) | (0x2u << 10) |
           ((rn & 31u) << 5) | (rd & 31u);
}
enum : unsigned {
    kPermUzp1 = 1, kPermTrn1 = 2, kPermZip1 = 3,
    kPermUzp2 = 5, kPermTrn2 = 6, kPermZip2 = 7,
};

// Advanced SIMD extract (EXT). imm4 is a BYTE index.
// ext v0.8b, v1.8b, v2.8b, #1 == 0x2e020820. Verified.
inline uint32_t simd_ext(bool q, unsigned rd, unsigned rn, unsigned rm,
                         unsigned imm4) {
    return (q ? 0x40000000u : 0u) | 0x2E000000u | ((rm & 31u) << 16) |
           ((imm4 & 15u) << 11) | ((rn & 31u) << 5) | (rd & 31u);
}

// Advanced SIMD modified immediate (MOVI / MVNI).
//   0 Q op 0 1 1 1 1 0 0 0 0 0 abc<3> cmode<4> o2 1 defgh<5> Rd
// movi v0.8b, #0x55 == 0x0f02e6a0 ; mvni v0.4h, #0x55 == 0x2f0286a0. Verified.
inline uint32_t simd_modimm(bool q, bool op, unsigned cmode, bool o2,
                            uint8_t imm8, unsigned rd) {
    const unsigned abc = (imm8 >> 5) & 7u;
    const unsigned defgh = imm8 & 0x1Fu;
    return (q ? 0x40000000u : 0u) | (op ? 0x20000000u : 0u) | 0x0F000000u |
           (abc << 16) | ((cmode & 15u) << 12) | (o2 ? (1u << 11) : 0u) |
           (1u << 10) | (defgh << 5) | (rd & 31u);
}

// Advanced SIMD shift by immediate.
//   0 Q U 0 1 1 1 1 0 immh<4> immb<3> opcode<5> 1 Rn Rd
// sshr v0.8b, v1.8b, #3 == 0x0f0d0420 ; shl v0.8b, v1.8b, #3 == 0x0f0b5420.
// For a right shift immh:immb == 2*esize - amount; for a left shift it is
// esize + amount. Verified across .8b / .4h / .2s / .2d.
inline uint32_t simd_shift_imm(bool q, bool u, unsigned immh_immb,
                               unsigned opcode, unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0F000000u |
           ((immh_immb & 0x7Fu) << 16) | ((opcode & 0x1Fu) << 11) |
           (1u << 10) | ((rn & 31u) << 5) | (rd & 31u);
}
enum : unsigned { kShiftSshr = 0x00, kShiftShl = 0x0A };

// Advanced SIMD load/store multiple structures (no offset).
//   0 Q 0 0 1 1 0 0 0 L 0 0 0 0 0 0 opcode<4> size<2> Rn Rt
// opcode: 0000 LD4/ST4, 0010 LD1/ST1 x4, 0100 LD3/ST3, 0110 LD1 x3,
//         0111 LD1 x1, 1000 LD2/ST2, 1010 LD1 x2.
// ld1 {v0.8b}, [x1] == 0x0c407020 ; ld4 {v0-v3.8b}, [x1] == 0x0c400020.
inline uint32_t simd_ldst_multi(bool q, bool is_load, unsigned opcode,
                                unsigned size, unsigned rn, unsigned rt) {
    return (q ? 0x40000000u : 0u) | (0x18u << 23) |
           (is_load ? (1u << 22) : 0u) | ((opcode & 15u) << 12) |
           ((size & 3u) << 10) | ((rn & 31u) << 5) | (rt & 31u);
}

// Advanced SIMD load/store single structure (one lane, or to all lanes).
//   0 Q 0 0 1 1 0 1 0 L R 0 0 0 0 0 opcode<3> S size<2> Rn Rt
// ld1 {v0.s}[1], [x1] == 0x0d409020 ; ld1r {v0.8b}, [x1] == 0x0d40c020 ;
// ld3 {v0-v2.s}[1], [x1] == 0x0d40b020 ; ld2r {v0,v1.8b} == 0x0d60c020.
// One-lane forms: opcode<2:1> selects B(00) / H(01) / S,D(10) and opcode<0>
// plus R select the structure count; the element index is spread over
// Q : S : size as documented per element width. All verified.
inline uint32_t simd_ldst_single(bool q, bool is_load, bool r,
                                 unsigned opcode, bool s, unsigned size,
                                 unsigned rn, unsigned rt) {
    return (q ? 0x40000000u : 0u) | (0x1Au << 23) |
           (is_load ? (1u << 22) : 0u) | (r ? (1u << 21) : 0u) |
           ((opcode & 7u) << 13) | (s ? (1u << 12) : 0u) |
           ((size & 3u) << 10) | ((rn & 31u) << 5) | (rt & 31u);
}

}  // namespace simdenc

// ---------------------------------------------------------------------
// Capstone VFP register decoding
// ---------------------------------------------------------------------
int vfp_s_idx(unsigned reg);  // ARM_REG_S0..S31 -> 0..31, else -1
int vfp_d_idx(unsigned reg);  // ARM_REG_D0..D31 -> 0..31, else -1
int vfp_q_idx(unsigned reg);  // ARM_REG_Q0..Q15 -> 0..15, else -1

// ---------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------

// True when `id` belongs to this stage, so the driver can dispatch without a
// trial translation.
bool is_simd_insn(unsigned id);

// Translate one VFP / NEON instruction. Returns false when the instruction is
// not owned here, or when its form is not implemented (in which case
// XlatMemCtx::warn is called with a description and nothing observable is
// emitted).
bool translate_simd(XlatMemCtx& cx, const cs_insn* in, XlatResult* result);

}  // namespace arm32rc
}  // namespace macapk

#endif  // MACAPK_RUNTIME_TRANSLATOR_ARM32RC_XLAT_SIMD_H_
