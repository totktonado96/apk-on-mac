// a64_emit.h -- AArch64 (A64) instruction encoder for the direct ARM32 -> arm64
// recompiler (arm32rc). This is the ONLY place in arm32rc that knows A64 bit
// layouts; every translation stage emits through it.
//
// SOURCE OF TRUTH
// ---------------
// Every encoder below is transcribed from the Arm Architecture Reference
// Manual for A-profile architecture, DDI 0487
// (https://developer.arm.com/documentation/ddi0487/latest/). Citations are
// given as the manual's instruction-page name plus its encoding-class
// section, e.g.
//
//   ARM ARM C6.2 "Base Instructions" -> ADD (immediate)
//   encoding class C4.1.2 "Data Processing -- Immediate" / Add-subtract (immediate)
//
// Instruction-page NUMBERS (C6.2.<n>) shift between manual issues, so the
// citations name the instruction page and the stable encoding-class heading
// rather than a volatile number. Field names in the comments (sf, opc, N,
// immr, imms, hw, imm12, ...) are the manual's own field names, so a reader
// can diff a comment against the manual's encoding diagram directly.
//
// NOTHING HERE IS GUESSED. Per CLAUDE.md's struct-offset rule, every encoder
// is round-trip verified in a64_emit_test.cpp: the emitted word is compared
// against what `llvm-mc --triple=arm64-apple-darwin --show-encoding` produces
// for the intended assembly text, and the word is additionally disassembled
// with `llvm-mc --disassemble` to prove it is a legal, decodable encoding.
//
// Encoders whose bit patterns overlap the hand-validated set already living in
// runtime/translator/src/arm64_macho_emit.cpp (enc_adrp, enc_add_imm,
// enc_subs_imm, enc_ldr_imm, enc_ldr_reg, enc_str_imm, enc_str_reg, enc_br,
// enc_blr, enc_ret, enc_cbz, enc_b, enc_movz, enc_movk) reuse those EXACT bit
// patterns; each such encoder is tagged "[matches arm64_macho_emit.cpp]".
//
// CONVENTIONS
// -----------
//  * Registers are plain `unsigned` in 0..31. Whether 31 means SP or ZR is a
//    property of the instruction, not of the value; the comment on each
//    encoder says which. Use kZR / kSP for readability.
//  * `is64` selects the sf bit: true = X registers (64-bit), false = W (32-bit).
//  * Encoders are pure functions returning the 32-bit little-endian-stored
//    instruction word. They MASK their inputs rather than assert, so a bad
//    caller gets a deterministic (wrong) instruction, not UB. Range checking is
//    the caller's job via the fits_*() predicates; A64Buf does it for branches.
//  * Byte offsets: load/store and branch encoders take BYTE offsets and scale
//    internally. This mirrors arm64_macho_emit.cpp's enc_ldr_imm(pimm) and is
//    the shape a lifter actually has on hand.
//
// C++17. -Wall -Wextra clean.

#ifndef MACAPK_ARM32RC_A64_EMIT_H
#define MACAPK_ARM32RC_A64_EMIT_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace macapk {
namespace a64 {

// ---------------------------------------------------------------------------
// Register / operand vocabulary
// ---------------------------------------------------------------------------

// Register number 31 decodes as either the zero register or the stack pointer
// depending on the instruction (ARM ARM C1.2.5 "Register names"). These two
// names exist purely so call sites read correctly.
enum : unsigned {
    kZR = 31,  // XZR / WZR
    kSP = 31,  // SP / WSP
    kLR = 30,  // procedure link register
    kFP = 29,  // frame pointer
};

// Condition codes. ARM ARM C1.2.4 "Condition code" (table of cond<3:1>:cond<0>).
// The numeric values ARE the 4-bit cond field.
enum Cond : uint32_t {
    CondEQ = 0x0, CondNE = 0x1,
    CondCS = 0x2, CondCC = 0x3,
    CondMI = 0x4, CondPL = 0x5,
    CondVS = 0x6, CondVC = 0x7,
    CondHI = 0x8, CondLS = 0x9,
    CondGE = 0xa, CondLT = 0xb,
    CondGT = 0xc, CondLE = 0xd,
    CondAL = 0xe, CondNV = 0xf,
    CondHS = CondCS,  // "higher or same" == carry set
    CondLO = CondCC,  // "lower"          == carry clear
};

// Invert a condition. ARM ARM C1.2.4: for cond<3:1> != 0b111 the condition is
// inverted by toggling cond<0>. AL^1 == NV, and NV also means "always", so the
// identity holds for every value in the sense that the branch is still taken;
// callers that need a genuinely negated always-branch must handle AL/NV
// themselves.
constexpr Cond invert_cond(Cond c) { return static_cast<Cond>(c ^ 1u); }

// Shift kinds for the shifted-register data-processing forms.
// ARM ARM C4.1.5 "Data Processing -- Register", shift field <23:22>.
// NOTE: ROR is only legal on the logical (shifted register) group; the
// add/subtract (shifted register) group rejects shift==0b11.
enum Shift : uint32_t { ShiftLSL = 0, ShiftLSR = 1, ShiftASR = 2, ShiftROR = 3 };

// Extend kinds for the extended-register add/sub forms (needed whenever an
// operand is SP). ARM ARM "Add/subtract (extended register)", option field.
enum Extend : uint32_t {
    ExtUXTB = 0, ExtUXTH = 1, ExtUXTW = 2, ExtUXTX = 3,
    ExtSXTB = 4, ExtSXTH = 5, ExtSXTW = 6, ExtSXTX = 7,
    ExtLSL64 = 3,  // UXTX with a 64-bit operand prints as LSL
};

// Addressing-mode selector for the 9-bit-immediate load/store forms.
// ARM ARM "Load/store register (immediate post-indexed / pre-indexed /
// unscaled immediate)".
enum class Index { Offset, PostIndex, PreIndex };

// Access size for the generic load/store builders: log2 of the access width in
// bytes. size==0 -> byte, 1 -> halfword, 2 -> word, 3 -> doubleword,
// and for the SIMD&FP variants size==0 with opc<1>==1 -> 128-bit (Q).
enum : unsigned { kSizeB = 0, kSizeH = 1, kSizeW = 2, kSizeX = 3 };

// ---------------------------------------------------------------------------
// Bit helpers (internal)
// ---------------------------------------------------------------------------

namespace detail {
constexpr uint32_t r5(unsigned r) { return static_cast<uint32_t>(r) & 31u; }
constexpr uint32_t sf(bool is64) { return is64 ? 0x80000000u : 0u; }
}  // namespace detail

// ---------------------------------------------------------------------------
// Immediate encodability helpers
// ---------------------------------------------------------------------------

// Logical (bitmask) immediate, i.e. the N:immr:imms field shared by
// AND/ORR/EOR/ANDS (immediate) and their aliases.
// ARM ARM C4.1.2 "Logical (immediate)" plus the DecodeBitMasks() pseudocode in
// the shared-pseudocode appendix (aarch64/instrs/integer/bitmasks/DecodeBitMasks).
//
// Returns false if `value` is not representable (that includes 0 and all-ones,
// which the encoding cannot express). On success `*out` receives the 13-bit
// field already packed as (N << 12) | (immr << 6) | imms, which is exactly how
// the encoders below splice it into the word.
bool encode_logical_imm(uint64_t value, bool is64, uint32_t* out);

// Inverse of encode_logical_imm: expand a packed N:immr:imms field to the
// 64-bit (or 32-bit, zero-extended) mask it denotes. Returns false for the
// field combinations the manual leaves UNALLOCATED. Used by the test to
// enumerate every legal pattern, and useful for sanity-printing.
bool decode_logical_imm(uint32_t n_immr_imms, bool is64, uint64_t* out);

// 8-bit scalar floating-point immediate (FMOV (scalar, immediate)).
// ARM ARM C7.2 "SIMD and Floating-point Instructions" -> FMOV (scalar,
// immediate), plus the VFPExpandImm() shared pseudocode. The representable set
// is +/- (16+m)/16 * 2^e for m in 0..15 and e in -3..4.
// Returns false when `v` is not exactly representable.
bool encode_fp_imm8(double v, uint32_t* imm8);

// Inverse of encode_fp_imm8 (VFPExpandImm with N=64). Total: every one of the
// 256 imm8 values maps to a finite double.
double decode_fp_imm8(uint32_t imm8);

// Branch-displacement range predicates. All take a BYTE displacement measured
// from the address of the branch instruction itself. Every A64 branch
// displacement is a multiple of 4; a non-multiple always returns false.
//
// Ranges (ARM ARM C4.1.3 "Branches, Exception Generating and System
// instructions"):
//   imm26 << 2  -> +/-128 MiB   B, BL
//   imm19 << 2  -> +/-1 MiB     B.cond, CBZ/CBNZ, LDR (literal)
//   imm14 << 2  -> +/-32 KiB    TBZ/TBNZ
//   imm21       -> +/-1 MiB     ADR (byte granular)
//   imm21 pages -> +/-4 GiB     ADRP
bool fits_b26(int64_t byte_off);
bool fits_cond19(int64_t byte_off);
bool fits_tb14(int64_t byte_off);
bool fits_adr21(int64_t byte_off);
bool fits_adrp_pages(int64_t page_delta);

// Scaled unsigned load/store offset: legal iff byte_off is a non-negative
// multiple of (1 << size) and byte_off >> size < 4096.
bool fits_ldst_uimm(unsigned size, int64_t byte_off);
// Unscaled signed 9-bit load/store offset (LDUR/STUR and pre/post-index).
bool fits_ldst_simm9(int64_t byte_off);
// LDP/STP scaled signed 7-bit offset: multiple of (1 << size), imm7 in -64..63.
bool fits_ldst_pair(unsigned size, int64_t byte_off);

// ===========================================================================
// C4.1.2  Data Processing -- Immediate
// ===========================================================================

// PC-relative addressing. ARM ARM -> ADR / ADRP.
//   op immlo<2> 1 0 0 0 0 immhi<19> Rd
// ADR takes a BYTE delta from the instruction; ADRP takes a delta in 4 KiB
// PAGES between the page of the instruction and the page of the target.
// [matches arm64_macho_emit.cpp enc_adrp]
inline uint32_t adr(unsigned rd, int64_t byte_delta) {
    uint32_t immlo = static_cast<uint32_t>(byte_delta) & 3u;
    uint32_t immhi = static_cast<uint32_t>(byte_delta >> 2) & 0x7ffffu;
    return 0x10000000u | (immlo << 29) | (immhi << 5) | detail::r5(rd);
}
inline uint32_t adrp(unsigned rd, int64_t page_delta) {
    uint32_t immlo = static_cast<uint32_t>(page_delta) & 3u;
    uint32_t immhi = static_cast<uint32_t>(page_delta >> 2) & 0x7ffffu;
    return 0x90000000u | (immlo << 29) | (immhi << 5) | detail::r5(rd);
}

// Add/subtract (immediate). ARM ARM -> ADD/ADDS/SUB/SUBS (immediate).
//   sf op S 1 0 0 0 1 0 sh imm12<12> Rn Rd
// Rn is SP-capable on all four; Rd is SP-capable on ADD/SUB and is ZR on
// ADDS/SUBS. `sh` shifts imm12 left by 12.
// [ADD matches arm64_macho_emit.cpp enc_add_imm; SUBS matches enc_subs_imm]
inline uint32_t addsub_imm(bool is64, bool sub, bool set_flags, unsigned rd,
                           unsigned rn, uint32_t imm12, bool shift12) {
    uint32_t base = 0x11000000u | (sub ? 0x40000000u : 0u) | (set_flags ? 0x20000000u : 0u);
    return detail::sf(is64) | base | (shift12 ? (1u << 22) : 0u) |
           ((imm12 & 0xfffu) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t add_imm(bool is64, unsigned rd, unsigned rn, uint32_t imm12, bool sh = false) {
    return addsub_imm(is64, false, false, rd, rn, imm12, sh);
}
inline uint32_t adds_imm(bool is64, unsigned rd, unsigned rn, uint32_t imm12, bool sh = false) {
    return addsub_imm(is64, false, true, rd, rn, imm12, sh);
}
inline uint32_t sub_imm(bool is64, unsigned rd, unsigned rn, uint32_t imm12, bool sh = false) {
    return addsub_imm(is64, true, false, rd, rn, imm12, sh);
}
inline uint32_t subs_imm(bool is64, unsigned rd, unsigned rn, uint32_t imm12, bool sh = false) {
    return addsub_imm(is64, true, true, rd, rn, imm12, sh);
}
// CMP  Xn, #imm  == SUBS XZR, Xn, #imm   (alias, ARM ARM CMP (immediate))
inline uint32_t cmp_imm(bool is64, unsigned rn, uint32_t imm12, bool sh = false) {
    return subs_imm(is64, kZR, rn, imm12, sh);
}
// CMN  Xn, #imm  == ADDS XZR, Xn, #imm
inline uint32_t cmn_imm(bool is64, unsigned rn, uint32_t imm12, bool sh = false) {
    return adds_imm(is64, kZR, rn, imm12, sh);
}
// MOV Xd, Xn where either may be SP == ADD Xd, Xn, #0 (ARM ARM MOV (to/from SP))
inline uint32_t mov_sp(bool is64, unsigned rd, unsigned rn) {
    return add_imm(is64, rd, rn, 0, false);
}

// Logical (immediate). ARM ARM -> AND/ORR/EOR/ANDS (immediate).
//   sf opc<2> 1 0 0 1 0 0 N immr<6> imms<6> Rn Rd
// opc: 00=AND 01=ORR 10=EOR 11=ANDS. Rd is SP-capable except on ANDS; Rn is ZR.
//
// !! THE LAST ARGUMENT OF and_imm / orr_imm / eor_imm / ands_imm / tst_imm /
// mov_bitmask_imm IS AN ENCODED FIELD, NOT A VALUE. It is the 13-bit packed
// N:immr:imms produced by encode_logical_imm(), so you MUST call that first
// and check its bool result:
//
//     uint32_t f = 0;
//     if (!encode_logical_imm(0xfff00000u, /*is64=*/false, &f)) { ... }
//     buf.put(and_imm(false, wd, wn, f));      // correct
//     buf.put(and_imm(false, wd, wn, 0xfff00000u));   // WRONG, see below
//
// Passing a raw value silently truncates to 13 bits and assembles as some
// other, legal, wrong mask: 0xfff00000 becomes `and w12, w27, #0x1`. This
// has already cost one debugging session (it pointed every GuestState
// access at the bottom of the guest arena instead of the thread's slot, and
// the differential harness could not see it because the store and the load
// agreed on the same wrong address). There is no encoding for 0 or for
// all-ones, which is why encode_logical_imm returns bool and every caller
// needs a fallback path.
inline uint32_t logical_imm(bool is64, unsigned opc, unsigned rd, unsigned rn,
                            uint32_t n_immr_imms) {
    return detail::sf(is64) | 0x12000000u | ((opc & 3u) << 29) |
           ((n_immr_imms & 0x1fffu) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t and_imm(bool is64, unsigned rd, unsigned rn, uint32_t f) { return logical_imm(is64, 0, rd, rn, f); }
inline uint32_t orr_imm(bool is64, unsigned rd, unsigned rn, uint32_t f) { return logical_imm(is64, 1, rd, rn, f); }
inline uint32_t eor_imm(bool is64, unsigned rd, unsigned rn, uint32_t f) { return logical_imm(is64, 2, rd, rn, f); }
inline uint32_t ands_imm(bool is64, unsigned rd, unsigned rn, uint32_t f) { return logical_imm(is64, 3, rd, rn, f); }
// TST Xn, #imm == ANDS XZR, Xn, #imm
inline uint32_t tst_imm(bool is64, unsigned rn, uint32_t f) { return ands_imm(is64, kZR, rn, f); }
// MOV Xd, #bitmask-imm == ORR Xd, XZR, #imm  (ARM ARM MOV (bitmask immediate))
inline uint32_t mov_bitmask_imm(bool is64, unsigned rd, uint32_t f) { return orr_imm(is64, rd, kZR, f); }

// Move wide (immediate). ARM ARM -> MOVN / MOVZ / MOVK.
//   sf opc<2> 1 0 0 1 0 1 hw<2> imm16<16> Rd
// opc: 00=MOVN 10=MOVZ 11=MOVK. `hw` selects the halfword: shift = hw*16.
// For 32-bit forms hw must be 0 or 1.
// [MOVZ/MOVK match arm64_macho_emit.cpp enc_movz / enc_movk]
inline uint32_t movn(bool is64, unsigned rd, uint32_t imm16, unsigned hw = 0) {
    return detail::sf(is64) | 0x12800000u | ((hw & 3u) << 21) | ((imm16 & 0xffffu) << 5) | detail::r5(rd);
}
inline uint32_t movz(bool is64, unsigned rd, uint32_t imm16, unsigned hw = 0) {
    return detail::sf(is64) | 0x52800000u | ((hw & 3u) << 21) | ((imm16 & 0xffffu) << 5) | detail::r5(rd);
}
inline uint32_t movk(bool is64, unsigned rd, uint32_t imm16, unsigned hw = 0) {
    return detail::sf(is64) | 0x72800000u | ((hw & 3u) << 21) | ((imm16 & 0xffffu) << 5) | detail::r5(rd);
}

// Bitfield. ARM ARM -> SBFM / BFM / UBFM.
//   sf opc<2> 1 0 0 1 1 0 N immr<6> imms<6> Rn Rd
// opc: 00=SBFM 01=BFM 10=UBFM. N must equal sf.
inline uint32_t bitfield(bool is64, unsigned opc, unsigned rd, unsigned rn,
                         unsigned immr, unsigned imms) {
    return detail::sf(is64) | 0x13000000u | ((opc & 3u) << 29) | (is64 ? (1u << 22) : 0u) |
           ((immr & 0x3fu) << 16) | ((imms & 0x3fu) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t sbfm(bool is64, unsigned rd, unsigned rn, unsigned immr, unsigned imms) { return bitfield(is64, 0, rd, rn, immr, imms); }
inline uint32_t bfm (bool is64, unsigned rd, unsigned rn, unsigned immr, unsigned imms) { return bitfield(is64, 1, rd, rn, immr, imms); }
inline uint32_t ubfm(bool is64, unsigned rd, unsigned rn, unsigned immr, unsigned imms) { return bitfield(is64, 2, rd, rn, immr, imms); }

// Bitfield aliases. Preferred-alias formulas are quoted from the manual's
// "Alias conditions" tables on the UBFM / SBFM / BFM pages.
//   LSL  Rd, Rn, #s  == UBFM Rd, Rn, #(-s MOD width), #(width-1-s)
//   LSR  Rd, Rn, #s  == UBFM Rd, Rn, #s, #(width-1)
//   ASR  Rd, Rn, #s  == SBFM Rd, Rn, #s, #(width-1)
//   UBFX Rd, Rn, #l, #w == UBFM Rd, Rn, #l, #(l+w-1)
//   SBFX Rd, Rn, #l, #w == SBFM Rd, Rn, #l, #(l+w-1)
//   UBFIZ Rd,Rn,#l,#w== UBFM Rd, Rn, #(-l MOD width), #(w-1)
//   SBFIZ Rd,Rn,#l,#w== SBFM Rd, Rn, #(-l MOD width), #(w-1)
//   BFI  Rd, Rn, #l, #w == BFM Rd, Rn, #(-l MOD width), #(w-1)
//   BFXIL Rd,Rn,#l,#w== BFM Rd, Rn, #l, #(l+w-1)
inline uint32_t lsl_imm(bool is64, unsigned rd, unsigned rn, unsigned sh) {
    unsigned w = is64 ? 64u : 32u;
    return ubfm(is64, rd, rn, (w - sh) % w, w - 1u - sh);
}
inline uint32_t lsr_imm(bool is64, unsigned rd, unsigned rn, unsigned sh) {
    return ubfm(is64, rd, rn, sh, is64 ? 63u : 31u);
}
inline uint32_t asr_imm(bool is64, unsigned rd, unsigned rn, unsigned sh) {
    return sbfm(is64, rd, rn, sh, is64 ? 63u : 31u);
}
inline uint32_t ubfx(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    return ubfm(is64, rd, rn, lsb, lsb + width - 1u);
}
inline uint32_t sbfx(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    return sbfm(is64, rd, rn, lsb, lsb + width - 1u);
}
inline uint32_t ubfiz(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    unsigned w = is64 ? 64u : 32u;
    return ubfm(is64, rd, rn, (w - lsb) % w, width - 1u);
}
inline uint32_t sbfiz(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    unsigned w = is64 ? 64u : 32u;
    return sbfm(is64, rd, rn, (w - lsb) % w, width - 1u);
}
inline uint32_t bfi(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    unsigned w = is64 ? 64u : 32u;
    return bfm(is64, rd, rn, (w - lsb) % w, width - 1u);
}
inline uint32_t bfxil(bool is64, unsigned rd, unsigned rn, unsigned lsb, unsigned width) {
    return bfm(is64, rd, rn, lsb, lsb + width - 1u);
}
// Sign/zero extend aliases (SBFM/UBFM with fixed immr=0).
inline uint32_t sxtb(bool is64, unsigned rd, unsigned rn) { return sbfm(is64, rd, rn, 0, 7); }
inline uint32_t sxth(bool is64, unsigned rd, unsigned rn) { return sbfm(is64, rd, rn, 0, 15); }
inline uint32_t sxtw(unsigned rd, unsigned rn)            { return sbfm(true, rd, rn, 0, 31); }
inline uint32_t uxtb(unsigned rd, unsigned rn)            { return ubfm(false, rd, rn, 0, 7); }
inline uint32_t uxth(unsigned rd, unsigned rn)            { return ubfm(false, rd, rn, 0, 15); }

// Extract. ARM ARM -> EXTR.  sf 0 0 1 0 0 1 1 1 N 0 Rm imms<6> Rn Rd
// N must equal sf; imms is the LSB position within the Rn:Rm concatenation.
// ROR Rd, Rs, #sh is the preferred alias when Rn == Rm.
inline uint32_t extr(bool is64, unsigned rd, unsigned rn, unsigned rm, unsigned lsb) {
    return detail::sf(is64) | 0x13800000u | (is64 ? (1u << 22) : 0u) |
           (detail::r5(rm) << 16) | ((lsb & 0x3fu) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t ror_imm(bool is64, unsigned rd, unsigned rs, unsigned sh) {
    return extr(is64, rd, rs, rs, sh);
}

// ===========================================================================
// C4.1.5  Data Processing -- Register
// ===========================================================================

// Add/subtract (shifted register). ARM ARM -> ADD/ADDS/SUB/SUBS (shifted reg).
//   sf op S 0 1 0 1 1 shift<2> 0 Rm imm6<6> Rn Rd
// shift: 00=LSL 01=LSR 10=ASR. 11 is UNALLOCATED here. All operands are ZR-form
// (no SP). imm6 must be < 32 for the 32-bit form.
inline uint32_t addsub_shifted(bool is64, bool sub, bool set_flags, unsigned rd,
                               unsigned rn, unsigned rm, Shift sh = ShiftLSL,
                               unsigned amount = 0) {
    uint32_t base = 0x0b000000u | (sub ? 0x40000000u : 0u) | (set_flags ? 0x20000000u : 0u);
    return detail::sf(is64) | base | ((static_cast<uint32_t>(sh) & 3u) << 22) |
           (detail::r5(rm) << 16) | ((amount & 0x3fu) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t add_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return addsub_shifted(is64, false, false, rd, rn, rm, sh, a); }
inline uint32_t adds_reg(bool is64, unsigned rd, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return addsub_shifted(is64, false, true,  rd, rn, rm, sh, a); }
inline uint32_t sub_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return addsub_shifted(is64, true,  false, rd, rn, rm, sh, a); }
inline uint32_t subs_reg(bool is64, unsigned rd, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return addsub_shifted(is64, true,  true,  rd, rn, rm, sh, a); }
inline uint32_t cmp_reg (bool is64, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return subs_reg(is64, kZR, rn, rm, sh, a); }
inline uint32_t cmn_reg (bool is64, unsigned rn, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return adds_reg(is64, kZR, rn, rm, sh, a); }
inline uint32_t neg_reg (bool is64, unsigned rd, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return sub_reg(is64, rd, kZR, rm, sh, a); }
inline uint32_t negs_reg(bool is64, unsigned rd, unsigned rm, Shift sh = ShiftLSL, unsigned a = 0) { return subs_reg(is64, rd, kZR, rm, sh, a); }

// Add/subtract (extended register). ARM ARM -> ADD/ADDS/SUB/SUBS (extended reg).
//   sf op S 0 1 0 1 1 0 0 1 Rm option<3> imm3<3> Rn Rd
// This is the only add/sub register form whose Rn may be SP. imm3 is 0..4.
inline uint32_t addsub_extended(bool is64, bool sub, bool set_flags, unsigned rd,
                                unsigned rn, unsigned rm, Extend opt, unsigned imm3 = 0) {
    uint32_t base = 0x0b200000u | (sub ? 0x40000000u : 0u) | (set_flags ? 0x20000000u : 0u);
    return detail::sf(is64) | base | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(opt) & 7u) << 13) | ((imm3 & 7u) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t add_ext (bool is64, unsigned rd, unsigned rn, unsigned rm, Extend o, unsigned s = 0) { return addsub_extended(is64, false, false, rd, rn, rm, o, s); }
inline uint32_t adds_ext(bool is64, unsigned rd, unsigned rn, unsigned rm, Extend o, unsigned s = 0) { return addsub_extended(is64, false, true,  rd, rn, rm, o, s); }
inline uint32_t sub_ext (bool is64, unsigned rd, unsigned rn, unsigned rm, Extend o, unsigned s = 0) { return addsub_extended(is64, true,  false, rd, rn, rm, o, s); }
inline uint32_t subs_ext(bool is64, unsigned rd, unsigned rn, unsigned rm, Extend o, unsigned s = 0) { return addsub_extended(is64, true,  true,  rd, rn, rm, o, s); }

// Add/subtract with carry. ARM ARM -> ADC / ADCS / SBC / SBCS.
//   sf op S 1 1 0 1 0 0 0 0 Rm 0 0 0 0 0 0 Rn Rd
// These are the direct targets for ARM32's ADC/SBC/RSC and for any lifted
// 64-bit-from-32-bit arithmetic. NOTE the A64 carry convention for subtract
// matches ARM32's: C set means "no borrow".
inline uint32_t adc (bool is64, unsigned rd, unsigned rn, unsigned rm) { return detail::sf(is64) | 0x1a000000u | (detail::r5(rm) << 16) | (detail::r5(rn) << 5) | detail::r5(rd); }
inline uint32_t adcs(bool is64, unsigned rd, unsigned rn, unsigned rm) { return detail::sf(is64) | 0x3a000000u | (detail::r5(rm) << 16) | (detail::r5(rn) << 5) | detail::r5(rd); }
inline uint32_t sbc (bool is64, unsigned rd, unsigned rn, unsigned rm) { return detail::sf(is64) | 0x5a000000u | (detail::r5(rm) << 16) | (detail::r5(rn) << 5) | detail::r5(rd); }
inline uint32_t sbcs(bool is64, unsigned rd, unsigned rn, unsigned rm) { return detail::sf(is64) | 0x7a000000u | (detail::r5(rm) << 16) | (detail::r5(rn) << 5) | detail::r5(rd); }
inline uint32_t ngc (bool is64, unsigned rd, unsigned rm) { return sbc (is64, rd, kZR, rm); }
inline uint32_t ngcs(bool is64, unsigned rd, unsigned rm) { return sbcs(is64, rd, kZR, rm); }

// Logical (shifted register). ARM ARM -> AND/BIC/ORR/ORN/EOR/EON/ANDS/BICS.
//   sf opc<2> 0 1 0 1 0 shift<2> N Rm imm6<6> Rn Rd
// opc:N -> 00:0 AND, 00:1 BIC, 01:0 ORR, 01:1 ORN, 10:0 EOR, 10:1 EON,
//          11:0 ANDS, 11:1 BICS. ROR IS legal here (unlike add/sub).
inline uint32_t logical_shifted(bool is64, unsigned opc, bool invert_rm, unsigned rd,
                                unsigned rn, unsigned rm, Shift sh = ShiftLSL,
                                unsigned amount = 0) {
    return detail::sf(is64) | 0x0a000000u | ((opc & 3u) << 29) |
           ((static_cast<uint32_t>(sh) & 3u) << 22) | (invert_rm ? (1u << 21) : 0u) |
           (detail::r5(rm) << 16) | ((amount & 0x3fu) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t and_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 0, false, rd, rn, rm, s, a); }
inline uint32_t bic_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 0, true,  rd, rn, rm, s, a); }
inline uint32_t orr_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 1, false, rd, rn, rm, s, a); }
inline uint32_t orn_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 1, true,  rd, rn, rm, s, a); }
inline uint32_t eor_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 2, false, rd, rn, rm, s, a); }
inline uint32_t eon_reg (bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 2, true,  rd, rn, rm, s, a); }
inline uint32_t ands_reg(bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 3, false, rd, rn, rm, s, a); }
inline uint32_t bics_reg(bool is64, unsigned rd, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return logical_shifted(is64, 3, true,  rd, rn, rm, s, a); }
// MOV Rd, Rm == ORR Rd, ZR, Rm ; MVN Rd, Rm == ORN Rd, ZR, Rm ; TST == ANDS ZR
inline uint32_t mov_reg(bool is64, unsigned rd, unsigned rm) { return orr_reg(is64, rd, kZR, rm); }
inline uint32_t mvn_reg(bool is64, unsigned rd, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return orn_reg(is64, rd, kZR, rm, s, a); }
inline uint32_t tst_reg(bool is64, unsigned rn, unsigned rm, Shift s = ShiftLSL, unsigned a = 0) { return ands_reg(is64, kZR, rn, rm, s, a); }

// Data-processing (2 source). ARM ARM -> UDIV/SDIV/LSLV/LSRV/ASRV/RORV.
//   sf 0 S 1 1 0 1 0 1 1 0 Rm opcode<6> Rn Rd
// The variable-shift forms (LSLV etc.) are what an ARM32 register-shift
// operand lowers to. A64 shift amounts are taken MOD the register width, which
// differs from ARM32's saturating behaviour; that is the translator's problem,
// not the encoder's.
inline uint32_t dp2(bool is64, unsigned opcode, unsigned rd, unsigned rn, unsigned rm) {
    return detail::sf(is64) | 0x1ac00000u | (detail::r5(rm) << 16) |
           ((opcode & 0x3fu) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t udiv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x02, rd, rn, rm); }
inline uint32_t sdiv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x03, rd, rn, rm); }
inline uint32_t lslv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x08, rd, rn, rm); }
inline uint32_t lsrv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x09, rd, rn, rm); }
inline uint32_t asrv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x0a, rd, rn, rm); }
inline uint32_t rorv(bool is64, unsigned rd, unsigned rn, unsigned rm) { return dp2(is64, 0x0b, rd, rn, rm); }

// Data-processing (1 source). ARM ARM -> RBIT/REV16/REV32/REV/CLZ/CLS.
//   sf 1 S 1 1 0 1 0 1 1 0 opcode2<5> opcode<6> Rn Rd
// opcode: 000000 RBIT, 000001 REV16, 000010 REV32 (64-bit) or REV (32-bit),
//         000011 REV (64-bit), 000100 CLZ, 000101 CLS.
inline uint32_t dp1(bool is64, unsigned opcode, unsigned rd, unsigned rn) {
    return detail::sf(is64) | 0x5ac00000u | ((opcode & 0x3fu) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t rbit (bool is64, unsigned rd, unsigned rn) { return dp1(is64, 0x00, rd, rn); }
inline uint32_t rev16(bool is64, unsigned rd, unsigned rn) { return dp1(is64, 0x01, rd, rn); }
inline uint32_t rev32(unsigned rd, unsigned rn)            { return dp1(true,  0x02, rd, rn); }
// REV Wd,Wn uses opcode 000010; REV Xd,Xn uses 000011. One entry point.
inline uint32_t rev  (bool is64, unsigned rd, unsigned rn) { return dp1(is64, is64 ? 0x03u : 0x02u, rd, rn); }
inline uint32_t clz  (bool is64, unsigned rd, unsigned rn) { return dp1(is64, 0x04, rd, rn); }
inline uint32_t cls  (bool is64, unsigned rd, unsigned rn) { return dp1(is64, 0x05, rd, rn); }

// Data-processing (3 source). ARM ARM -> MADD/MSUB/SMADDL/SMSUBL/SMULH/
// UMADDL/UMSUBL/UMULH.
//   sf op54<2> 1 1 0 1 1 op31<3> Rm o0 Ra Rn Rd
// The "long" forms are 64-bit only (sf=1) and take W-register sources; they are
// the direct lowering of ARM32's SMULL/UMULL/SMLAL/UMLAL.
inline uint32_t dp3(bool is64, unsigned op31, bool o0, unsigned rd, unsigned rn,
                    unsigned rm, unsigned ra) {
    return detail::sf(is64) | 0x1b000000u | ((op31 & 7u) << 21) | (detail::r5(rm) << 16) |
           (o0 ? (1u << 15) : 0u) | (detail::r5(ra) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t madd(bool is64, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(is64, 0, false, rd, rn, rm, ra); }
inline uint32_t msub(bool is64, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(is64, 0, true,  rd, rn, rm, ra); }
inline uint32_t mul (bool is64, unsigned rd, unsigned rn, unsigned rm) { return madd(is64, rd, rn, rm, kZR); }
inline uint32_t mneg(bool is64, unsigned rd, unsigned rn, unsigned rm) { return msub(is64, rd, rn, rm, kZR); }
inline uint32_t smaddl(unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(true, 1, false, rd, rn, rm, ra); }
inline uint32_t smsubl(unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(true, 1, true,  rd, rn, rm, ra); }
inline uint32_t smull (unsigned rd, unsigned rn, unsigned rm) { return smaddl(rd, rn, rm, kZR); }
inline uint32_t smnegl(unsigned rd, unsigned rn, unsigned rm) { return smsubl(rd, rn, rm, kZR); }
inline uint32_t smulh (unsigned rd, unsigned rn, unsigned rm) { return dp3(true, 2, false, rd, rn, rm, kZR); }
inline uint32_t umaddl(unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(true, 5, false, rd, rn, rm, ra); }
inline uint32_t umsubl(unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return dp3(true, 5, true,  rd, rn, rm, ra); }
inline uint32_t umull (unsigned rd, unsigned rn, unsigned rm) { return umaddl(rd, rn, rm, kZR); }
inline uint32_t umnegl(unsigned rd, unsigned rn, unsigned rm) { return umsubl(rd, rn, rm, kZR); }
inline uint32_t umulh (unsigned rd, unsigned rn, unsigned rm) { return dp3(true, 6, false, rd, rn, rm, kZR); }

// ---------------------------------------------------------------------------
// Conditional select / conditional compare (the NZCV toolkit)
// ---------------------------------------------------------------------------
//
// ARM32 is flag-heavy: nearly every data-processing instruction has an S form,
// every instruction has a predicate, and the flags survive across instructions
// that a naive lowering would clobber. The pieces below are the ones the
// translation stages need:
//
//   * CSEL/CSINC/CSINV/CSNEG and the CSET/CSETM/CINC/CINV/CNEG aliases turn a
//     predicate into a value WITHOUT branching, which is how a predicated ARM32
//     instruction becomes straight-line arm64.
//   * CCMP/CCMN evaluate a second comparison only if the first predicate holds,
//     and otherwise force an explicit NZCV. That is the cheap lowering for
//     ARM32 compare chains.
//   * MRS/MSR NZCV save and restore the flag state around a sequence that must
//     clobber it (for example a helper call, or an address computation that has
//     to use ADDS). Pair them: `mrs(x, kSR_NZCV)` ... `msr_reg(kSR_NZCV, x)`.
//
// Flag mapping between the two architectures is 1:1 for N, Z, C, V, INCLUDING
// the subtract carry convention (C = NOT borrow on both). The differences a
// translator must handle in its own semantics, not here, are: ARM32 shifts
// write C from the shifted-out bit, and ARM32's C after a shift-by-zero is
// preserved.

// Conditional select. ARM ARM -> CSEL / CSINC / CSINV / CSNEG.
//   sf op S 1 1 0 1 0 1 0 0 Rm cond<4> op2<2> Rn Rd
inline uint32_t condsel(bool is64, bool op, unsigned op2, unsigned rd, unsigned rn,
                        unsigned rm, Cond c) {
    return detail::sf(is64) | 0x1a800000u | (op ? 0x40000000u : 0u) |
           (detail::r5(rm) << 16) | ((static_cast<uint32_t>(c) & 15u) << 12) |
           ((op2 & 3u) << 10) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t csel (bool is64, unsigned rd, unsigned rn, unsigned rm, Cond c) { return condsel(is64, false, 0, rd, rn, rm, c); }
inline uint32_t csinc(bool is64, unsigned rd, unsigned rn, unsigned rm, Cond c) { return condsel(is64, false, 1, rd, rn, rm, c); }
inline uint32_t csinv(bool is64, unsigned rd, unsigned rn, unsigned rm, Cond c) { return condsel(is64, true,  0, rd, rn, rm, c); }
inline uint32_t csneg(bool is64, unsigned rd, unsigned rn, unsigned rm, Cond c) { return condsel(is64, true,  1, rd, rn, rm, c); }
// CSET Rd, cond  == CSINC Rd, ZR, ZR, invert(cond)   (1 if cond else 0)
inline uint32_t cset (bool is64, unsigned rd, Cond c) { return csinc(is64, rd, kZR, kZR, invert_cond(c)); }
// CSETM Rd, cond == CSINV Rd, ZR, ZR, invert(cond)   (all-ones if cond else 0)
inline uint32_t csetm(bool is64, unsigned rd, Cond c) { return csinv(is64, rd, kZR, kZR, invert_cond(c)); }
// CINC Rd, Rn, cond == CSINC Rd, Rn, Rn, invert(cond)
inline uint32_t cinc (bool is64, unsigned rd, unsigned rn, Cond c) { return csinc(is64, rd, rn, rn, invert_cond(c)); }
inline uint32_t cinv (bool is64, unsigned rd, unsigned rn, Cond c) { return csinv(is64, rd, rn, rn, invert_cond(c)); }
inline uint32_t cneg (bool is64, unsigned rd, unsigned rn, Cond c) { return csneg(is64, rd, rn, rn, invert_cond(c)); }

// Conditional compare. ARM ARM -> CCMN/CCMP (register) and (immediate).
//   sf op S 1 1 0 1 0 0 1 0 Rm/imm5 cond<4> 0 imm-bit Rn 0 nzcv<4>
// op: 0=CCMN 1=CCMP. Bit 11 selects the immediate form. `nzcv` is the flag
// value forced when the condition is FALSE.
inline uint32_t ccmp_reg(bool is64, unsigned rn, unsigned rm, unsigned nzcv, Cond c) {
    return detail::sf(is64) | 0x7a400000u | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | (nzcv & 15u);
}
inline uint32_t ccmn_reg(bool is64, unsigned rn, unsigned rm, unsigned nzcv, Cond c) {
    return detail::sf(is64) | 0x3a400000u | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | (nzcv & 15u);
}
inline uint32_t ccmp_imm(bool is64, unsigned rn, unsigned imm5, unsigned nzcv, Cond c) {
    return detail::sf(is64) | 0x7a400800u | ((imm5 & 31u) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | (nzcv & 15u);
}
inline uint32_t ccmn_imm(bool is64, unsigned rn, unsigned imm5, unsigned nzcv, Cond c) {
    return detail::sf(is64) | 0x3a400800u | ((imm5 & 31u) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | (nzcv & 15u);
}

// ===========================================================================
// C4.1.3  Branches, Exception Generating and System instructions
// ===========================================================================

// Unconditional branch (immediate). ARM ARM -> B / BL.
//   op 0 0 1 0 1 imm26<26>     op: 0=B 1=BL
// `byte_off` is the displacement from THIS instruction. Range +/-128 MiB; use
// fits_b26() first (A64Buf does this for you).
// [B matches arm64_macho_emit.cpp enc_b]
inline uint32_t b(int64_t byte_off) {
    return 0x14000000u | (static_cast<uint32_t>(byte_off >> 2) & 0x03ffffffu);
}
inline uint32_t bl(int64_t byte_off) {
    return 0x94000000u | (static_cast<uint32_t>(byte_off >> 2) & 0x03ffffffu);
}

// Unconditional branch (register). ARM ARM -> BR / BLR / RET.
//   1 1 0 1 0 1 1 0 opc<4> 1 1 1 1 1 0 0 0 0 0 Rn 0 0 0 0 0
// [all three match arm64_macho_emit.cpp enc_br / enc_blr / enc_ret]
inline uint32_t br (unsigned rn) { return 0xd61f0000u | (detail::r5(rn) << 5); }
inline uint32_t blr(unsigned rn) { return 0xd63f0000u | (detail::r5(rn) << 5); }
inline uint32_t ret(unsigned rn = kLR) { return 0xd65f0000u | (detail::r5(rn) << 5); }

// Conditional branch (immediate). ARM ARM -> B.cond.
//   0 1 0 1 0 1 0 0 imm19<19> 0 cond<4>     Range +/-1 MiB.
inline uint32_t b_cond(Cond c, int64_t byte_off) {
    return 0x54000000u | ((static_cast<uint32_t>(byte_off >> 2) & 0x7ffffu) << 5) |
           (static_cast<uint32_t>(c) & 15u);
}

// Compare and branch. ARM ARM -> CBZ / CBNZ.
//   sf 0 1 1 0 1 0 op imm19<19> Rt          Range +/-1 MiB.
// [CBZ matches arm64_macho_emit.cpp enc_cbz]
inline uint32_t cbz(bool is64, unsigned rt, int64_t byte_off) {
    return detail::sf(is64) | 0x34000000u |
           ((static_cast<uint32_t>(byte_off >> 2) & 0x7ffffu) << 5) | detail::r5(rt);
}
inline uint32_t cbnz(bool is64, unsigned rt, int64_t byte_off) {
    return detail::sf(is64) | 0x35000000u |
           ((static_cast<uint32_t>(byte_off >> 2) & 0x7ffffu) << 5) | detail::r5(rt);
}

// Test and branch. ARM ARM -> TBZ / TBNZ.
//   b5 0 1 1 0 1 1 op b40<5> imm14<14> Rt   Range +/-32 KiB.
// The bit number is split: b5 is bit<31> and b40 is bits<23:19>. Bit numbers
// 32..63 therefore imply the 64-bit operand form automatically.
inline uint32_t tbz(unsigned rt, unsigned bit, int64_t byte_off) {
    return ((bit & 32u) ? 0x80000000u : 0u) | 0x36000000u | ((bit & 31u) << 19) |
           ((static_cast<uint32_t>(byte_off >> 2) & 0x3fffu) << 5) | detail::r5(rt);
}
inline uint32_t tbnz(unsigned rt, unsigned bit, int64_t byte_off) {
    return ((bit & 32u) ? 0x80000000u : 0u) | 0x37000000u | ((bit & 31u) << 19) |
           ((static_cast<uint32_t>(byte_off >> 2) & 0x3fffu) << 5) | detail::r5(rt);
}

// Exception generation. ARM ARM -> BRK / SVC / HLT.
//   1 1 0 1 0 1 0 0 opc<3> imm16<16> op2<3> LL<2>
inline uint32_t brk(uint32_t imm16) { return 0xd4200000u | ((imm16 & 0xffffu) << 5); }
inline uint32_t svc(uint32_t imm16) { return 0xd4000001u | ((imm16 & 0xffffu) << 5); }
inline uint32_t hlt(uint32_t imm16) { return 0xd4400000u | ((imm16 & 0xffffu) << 5); }

// Hints and barriers. ARM ARM -> HINT / DMB / DSB / ISB / CLREX.
//   1 1 0 1 0 1 0 1 0 0 0 0 0 0 1 1 0 0 1 1 CRm<4> op2<3> 1 1 1 1 1
// CRm for the barriers is the "option" field: 0b1111 = SY, 0b1011 = ISH,
// 0b1010 = ISHST, 0b1110 = ST, 0b1101 = LD.
inline uint32_t hint(unsigned imm7) { return 0xd503201fu | ((imm7 & 0x7fu) << 5); }
inline uint32_t nop()   { return hint(0); }
inline uint32_t yield() { return hint(1); }
inline uint32_t wfe()   { return hint(2); }
inline uint32_t sev()   { return hint(4); }
inline uint32_t dmb(unsigned crm = 0xf) { return 0xd50330bfu | ((crm & 15u) << 8); }
inline uint32_t dsb(unsigned crm = 0xf) { return 0xd503309fu | ((crm & 15u) << 8); }
inline uint32_t isb(unsigned crm = 0xf) { return 0xd50330dfu | ((crm & 15u) << 8); }
inline uint32_t clrex(unsigned crm = 0xf) { return 0xd503305fu | ((crm & 15u) << 8); }

// System register access. ARM ARM -> MRS / MSR (register).
//   MRS: 1 1 0 1 0 1 0 1 0 0 1 1 o0 op1<3> CRn<4> CRm<4> op2<3> Rt
//   MSR: 1 1 0 1 0 1 0 1 0 0 0 1 o0 op1<3> CRn<4> CRm<4> op2<3> Rt
// where o0 == op0<0> (op0 is always 2 or 3 for these). sysreg_fields() packs
// the five selector fields into their final bit positions so the MRS/MSR
// encoders are a plain OR.
constexpr uint32_t sysreg_fields(unsigned op0, unsigned op1, unsigned crn,
                                 unsigned crm, unsigned op2) {
    return ((op0 & 1u) << 19) | ((op1 & 7u) << 16) | ((crn & 15u) << 12) |
           ((crm & 15u) << 8) | ((op2 & 7u) << 5);
}
constexpr uint32_t kSR_NZCV       = sysreg_fields(3, 3,  4, 2, 0);
constexpr uint32_t kSR_FPCR       = sysreg_fields(3, 3,  4, 4, 0);
constexpr uint32_t kSR_FPSR       = sysreg_fields(3, 3,  4, 4, 1);
constexpr uint32_t kSR_TPIDR_EL0  = sysreg_fields(3, 3, 13, 0, 2);
constexpr uint32_t kSR_TPIDRRO_EL0= sysreg_fields(3, 3, 13, 0, 3);
constexpr uint32_t kSR_CTR_EL0    = sysreg_fields(3, 3,  0, 0, 1);
constexpr uint32_t kSR_DCZID_EL0  = sysreg_fields(3, 3,  0, 0, 7);
constexpr uint32_t kSR_CNTVCT_EL0 = sysreg_fields(3, 3, 14, 0, 2);
constexpr uint32_t kSR_CNTFRQ_EL0 = sysreg_fields(3, 3, 14, 0, 0);
inline uint32_t mrs(unsigned rt, uint32_t sr) { return 0xd5300000u | sr | detail::r5(rt); }
inline uint32_t msr_reg(uint32_t sr, unsigned rt) { return 0xd5100000u | sr | detail::r5(rt); }

// ===========================================================================
// C4.1.4  Loads and Stores
// ===========================================================================
//
// The whole non-pair load/store space shares one 4-field selector:
//   size<2>  access width, log2 bytes (00 B, 01 H, 10 W, 11 X)
//   V        0 = general register, 1 = SIMD&FP register
//   opc<2>   direction + sign-extension, meaning varies by size (see below)
//
//   opc for integer forms: 00 store, 01 zero-extending load,
//                          10 load with sign-extension to X,
//                          11 load with sign-extension to W (byte/half only)
//   opc for SIMD&FP forms: size==00 & opc==1x is the 128-bit (Q) form.

// Load/store register (unsigned immediate). ARM ARM -> LDR/STR (immediate),
// unsigned offset variant.
//   size<2> 1 1 1 V 0 1 opc<2> imm12<12> Rn Rt
// `byte_off` is scaled by the access size internally; use fits_ldst_uimm().
// [LDR/STR X match arm64_macho_emit.cpp enc_ldr_imm / enc_str_imm]
inline uint32_t ldst_uimm(unsigned size, bool is_fp, unsigned opc, unsigned rt,
                          unsigned rn, uint64_t byte_off) {
    uint32_t imm12 = static_cast<uint32_t>(byte_off >> size) & 0xfffu;
    return ((size & 3u) << 30) | 0x39000000u | (is_fp ? (1u << 26) : 0u) |
           ((opc & 3u) << 22) | (imm12 << 10) | (detail::r5(rn) << 5) | detail::r5(rt);
}
// Load/store register (unscaled / post-index / pre-index). One encoding class
// with bits<11:10> selecting the form: 00 unscaled (LDUR/STUR), 01 post-index,
// 11 pre-index. imm9 is a BYTE offset, sign-extended, NOT scaled.
//   size<2> 1 1 1 V 0 0 opc<2> 0 imm9<9> mode<2> Rn Rt
inline uint32_t ldst_simm9(unsigned size, bool is_fp, unsigned opc, unsigned rt,
                           unsigned rn, int64_t byte_off, Index idx) {
    uint32_t mode = (idx == Index::Offset) ? 0u : (idx == Index::PostIndex ? 1u : 3u);
    return ((size & 3u) << 30) | 0x38000000u | (is_fp ? (1u << 26) : 0u) |
           ((opc & 3u) << 22) | ((static_cast<uint32_t>(byte_off) & 0x1ffu) << 12) |
           (mode << 10) | (detail::r5(rn) << 5) | detail::r5(rt);
}
// Load/store register (register offset). ARM ARM -> LDR/STR (register).
//   size<2> 1 1 1 V 0 0 opc<2> 1 Rm option<3> S 1 0 Rn Rt
// `option` is an Extend value restricted to UXTW(2)/LSL==UXTX(3)/SXTW(6)/SXTX(7).
// `scaled` sets S, which multiplies the index by the access size.
// [LDR/STR X with option=UXTX,S=1 match arm64_macho_emit.cpp enc_ldr_reg/enc_str_reg]
inline uint32_t ldst_reg(unsigned size, bool is_fp, unsigned opc, unsigned rt,
                         unsigned rn, unsigned rm, Extend option = ExtLSL64,
                         bool scaled = true) {
    return ((size & 3u) << 30) | 0x38200800u | (is_fp ? (1u << 26) : 0u) |
           ((opc & 3u) << 22) | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(option) & 7u) << 13) | (scaled ? (1u << 12) : 0u) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
// Load register (literal). ARM ARM -> LDR (literal).
//   opc<2> 0 1 1 V 0 0 imm19<19> Rt
// opc: 00 = W, 01 = X, 10 = LDRSW (int) / with V=1: 00 = S, 01 = D, 10 = Q.
// Range +/-1 MiB; this is the "literal island" mechanism for constants that do
// not fit MOVZ/MOVK chains cheaply.
inline uint32_t ldr_literal(unsigned opc, bool is_fp, unsigned rt, int64_t byte_off) {
    return ((opc & 3u) << 30) | 0x18000000u | (is_fp ? (1u << 26) : 0u) |
           ((static_cast<uint32_t>(byte_off >> 2) & 0x7ffffu) << 5) | detail::r5(rt);
}

// --- Named integer load/store wrappers (byte offsets throughout) ------------
inline uint32_t str  (bool is64, unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(is64 ? kSizeX : kSizeW, false, 0, rt, rn, off); }
inline uint32_t ldr  (bool is64, unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(is64 ? kSizeX : kSizeW, false, 1, rt, rn, off); }
inline uint32_t strb (unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeB, false, 0, rt, rn, off); }
inline uint32_t ldrb (unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeB, false, 1, rt, rn, off); }
inline uint32_t ldrsb(bool is64, unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeB, false, is64 ? 2u : 3u, rt, rn, off); }
inline uint32_t strh (unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeH, false, 0, rt, rn, off); }
inline uint32_t ldrh (unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeH, false, 1, rt, rn, off); }
inline uint32_t ldrsh(bool is64, unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeH, false, is64 ? 2u : 3u, rt, rn, off); }
inline uint32_t ldrsw(unsigned rt, unsigned rn, uint64_t off) { return ldst_uimm(kSizeW, false, 2, rt, rn, off); }

inline uint32_t stur  (bool is64, unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(is64 ? kSizeX : kSizeW, false, 0, rt, rn, off, Index::Offset); }
inline uint32_t ldur  (bool is64, unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(is64 ? kSizeX : kSizeW, false, 1, rt, rn, off, Index::Offset); }
inline uint32_t sturb (unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeB, false, 0, rt, rn, off, Index::Offset); }
inline uint32_t ldurb (unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeB, false, 1, rt, rn, off, Index::Offset); }
inline uint32_t sturh (unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeH, false, 0, rt, rn, off, Index::Offset); }
inline uint32_t ldurh (unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeH, false, 1, rt, rn, off, Index::Offset); }
inline uint32_t ldursb(bool is64, unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeB, false, is64 ? 2u : 3u, rt, rn, off, Index::Offset); }
inline uint32_t ldursh(bool is64, unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeH, false, is64 ? 2u : 3u, rt, rn, off, Index::Offset); }
inline uint32_t ldursw(unsigned rt, unsigned rn, int64_t off) { return ldst_simm9(kSizeW, false, 2, rt, rn, off, Index::Offset); }

// Pre/post-indexed integer forms (the "writeback" addressing ARM32 uses for
// LDR/STR with ! and for its post-indexed forms).
inline uint32_t str_idx  (bool is64, unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(is64 ? kSizeX : kSizeW, false, 0, rt, rn, off, i); }
inline uint32_t ldr_idx  (bool is64, unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(is64 ? kSizeX : kSizeW, false, 1, rt, rn, off, i); }
inline uint32_t strb_idx (unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(kSizeB, false, 0, rt, rn, off, i); }
inline uint32_t ldrb_idx (unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(kSizeB, false, 1, rt, rn, off, i); }
inline uint32_t strh_idx (unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(kSizeH, false, 0, rt, rn, off, i); }
inline uint32_t ldrh_idx (unsigned rt, unsigned rn, int64_t off, Index i) { return ldst_simm9(kSizeH, false, 1, rt, rn, off, i); }

// Register-offset integer forms.
inline uint32_t str_r  (bool is64, unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(is64 ? kSizeX : kSizeW, false, 0, rt, rn, rm, o, s); }
inline uint32_t ldr_r  (bool is64, unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(is64 ? kSizeX : kSizeW, false, 1, rt, rn, rm, o, s); }
inline uint32_t strb_r (unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = false) { return ldst_reg(kSizeB, false, 0, rt, rn, rm, o, s); }
inline uint32_t ldrb_r (unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = false) { return ldst_reg(kSizeB, false, 1, rt, rn, rm, o, s); }
inline uint32_t strh_r (unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(kSizeH, false, 0, rt, rn, rm, o, s); }
inline uint32_t ldrh_r (unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(kSizeH, false, 1, rt, rn, rm, o, s); }
inline uint32_t ldrsb_r(bool is64, unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = false) { return ldst_reg(kSizeB, false, is64 ? 2u : 3u, rt, rn, rm, o, s); }
inline uint32_t ldrsh_r(bool is64, unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(kSizeH, false, is64 ? 2u : 3u, rt, rn, rm, o, s); }
inline uint32_t ldrsw_r(unsigned rt, unsigned rn, unsigned rm, Extend o = ExtLSL64, bool s = true) { return ldst_reg(kSizeW, false, 2, rt, rn, rm, o, s); }

// Load/store pair. ARM ARM -> LDP / STP / LDPSW.
//   opc<2> 1 0 1 V mode<3> L imm7<7> Rt2<5> Rn Rt
// mode: 000 no-allocate, 001 post-index, 010 signed offset, 011 pre-index.
// opc: integer 00 = W pair, 10 = X pair, 01 = LDPSW.
//      SIMD&FP  00 = S pair, 01 = D pair, 10 = Q pair.
// imm7 is scaled by the pair element size; `byte_off` here is unscaled.
inline uint32_t ldst_pair(unsigned opc, bool is_fp, Index idx, bool is_load,
                          unsigned rt, unsigned rt2, unsigned rn, int64_t byte_off,
                          unsigned elem_log2) {
    uint32_t mode = (idx == Index::Offset) ? 2u : (idx == Index::PostIndex ? 1u : 3u);
    uint32_t imm7 = static_cast<uint32_t>(byte_off >> elem_log2) & 0x7fu;
    return ((opc & 3u) << 30) | 0x28000000u | (is_fp ? (1u << 26) : 0u) | (mode << 23) |
           (is_load ? (1u << 22) : 0u) | (imm7 << 15) | (detail::r5(rt2) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t stp(bool is64, unsigned rt, unsigned rt2, unsigned rn, int64_t off, Index i = Index::Offset) {
    return ldst_pair(is64 ? 2u : 0u, false, i, false, rt, rt2, rn, off, is64 ? 3u : 2u);
}
inline uint32_t ldp(bool is64, unsigned rt, unsigned rt2, unsigned rn, int64_t off, Index i = Index::Offset) {
    return ldst_pair(is64 ? 2u : 0u, false, i, true, rt, rt2, rn, off, is64 ? 3u : 2u);
}
inline uint32_t ldpsw(unsigned rt, unsigned rt2, unsigned rn, int64_t off, Index i = Index::Offset) {
    return ldst_pair(1u, false, i, true, rt, rt2, rn, off, 2u);
}

// Load/store exclusive. ARM ARM -> LDXR/LDAXR/STXR/STLXR (and the pair forms).
//   size<2> 0 0 1 0 0 0 o2 L o1 Rs<5> o0 Rt2<5> Rn Rt
// o2=0 for the non-"LoR" forms, L selects load, o1 selects the pair form, o0
// adds acquire/release semantics.
// ARM32's LDREX/STREX map onto the 32-bit forms; LDREXB/H onto size 00/01;
// LDREXD/STREXD onto the 64-bit forms (an ARM32 register PAIR is one X here,
// so the translator must splice, or use the LDXP/STXP pair forms).
// Rs (the status register on stores) and Rt2 are set to ZR when unused, which
// is what the manual's encoding diagrams require.
inline uint32_t ldst_excl(unsigned size, bool o2, bool is_load, bool pair, bool o0,
                          unsigned rs, unsigned rt2, unsigned rn, unsigned rt) {
    return ((size & 3u) << 30) | 0x08000000u | (o2 ? (1u << 23) : 0u) |
           (is_load ? (1u << 22) : 0u) | (pair ? (1u << 21) : 0u) |
           (detail::r5(rs) << 16) | (o0 ? (1u << 15) : 0u) | (detail::r5(rt2) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t ldxr  (bool is64, unsigned rt, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, true, false, false, kZR, kZR, rn, rt); }
inline uint32_t ldaxr (bool is64, unsigned rt, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, true, false, true,  kZR, kZR, rn, rt); }
inline uint32_t ldxrb (unsigned rt, unsigned rn) { return ldst_excl(kSizeB, false, true, false, false, kZR, kZR, rn, rt); }
inline uint32_t ldaxrb(unsigned rt, unsigned rn) { return ldst_excl(kSizeB, false, true, false, true,  kZR, kZR, rn, rt); }
inline uint32_t ldxrh (unsigned rt, unsigned rn) { return ldst_excl(kSizeH, false, true, false, false, kZR, kZR, rn, rt); }
inline uint32_t ldaxrh(unsigned rt, unsigned rn) { return ldst_excl(kSizeH, false, true, false, true,  kZR, kZR, rn, rt); }
inline uint32_t stxr  (bool is64, unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, false, false, false, rs, kZR, rn, rt); }
inline uint32_t stlxr (bool is64, unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, false, false, true,  rs, kZR, rn, rt); }
inline uint32_t stxrb (unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(kSizeB, false, false, false, false, rs, kZR, rn, rt); }
inline uint32_t stlxrb(unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(kSizeB, false, false, false, true,  rs, kZR, rn, rt); }
inline uint32_t stxrh (unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(kSizeH, false, false, false, false, rs, kZR, rn, rt); }
inline uint32_t stlxrh(unsigned rs, unsigned rt, unsigned rn) { return ldst_excl(kSizeH, false, false, false, true,  rs, kZR, rn, rt); }
// Pair exclusives: size must be 10 (W pair) or 11 (X pair).
inline uint32_t ldxp (bool is64, unsigned rt, unsigned rt2, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, true, true, false, kZR, rt2, rn, rt); }
inline uint32_t ldaxp(bool is64, unsigned rt, unsigned rt2, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, true, true, true,  kZR, rt2, rn, rt); }
inline uint32_t stxp (bool is64, unsigned rs, unsigned rt, unsigned rt2, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, false, true, false, rs, rt2, rn, rt); }
inline uint32_t stlxp(bool is64, unsigned rs, unsigned rt, unsigned rt2, unsigned rn) { return ldst_excl(is64 ? kSizeX : kSizeW, false, false, true, true,  rs, rt2, rn, rt); }

// ===========================================================================
// C4.1.6 / C7  SIMD and Floating-point
// ===========================================================================
//
// `ptype` (the manual's field name) selects the scalar FP type:
//   00 = single (S), 01 = double (D), 11 = half (H).
enum : unsigned { kFpS = 0, kFpD = 1, kFpH = 3 };

// Floating-point data-processing (1 source). ARM ARM -> FMOV/FABS/FNEG/FSQRT/
// FCVT/FRINT*.
//   M 0 S 1 1 1 1 0 ptype<2> 1 opcode<6> 1 0 0 0 0 Rn Rd
inline uint32_t fp1(unsigned ptype, unsigned opcode, unsigned rd, unsigned rn) {
    return 0x1e204000u | ((ptype & 3u) << 22) | ((opcode & 0x3fu) << 15) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t fmov_reg(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x00, rd, rn); }
inline uint32_t fabs_f  (unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x01, rd, rn); }
inline uint32_t fneg_f  (unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x02, rd, rn); }
inline uint32_t fsqrt   (unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x03, rd, rn); }
// FCVT Rd(dst_type), Rn(src_type). opcode = 0b0001 : dst_type.
inline uint32_t fcvt(unsigned dst_ptype, unsigned src_ptype, unsigned rd, unsigned rn) {
    return fp1(src_ptype, 0x04u | (dst_ptype & 3u), rd, rn);
}
inline uint32_t frintn(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x08, rd, rn); }
inline uint32_t frintp(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x09, rd, rn); }
inline uint32_t frintm(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x0a, rd, rn); }
inline uint32_t frintz(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x0b, rd, rn); }
inline uint32_t frinta(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x0c, rd, rn); }
inline uint32_t frintx(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x0e, rd, rn); }
inline uint32_t frinti(unsigned ptype, unsigned rd, unsigned rn) { return fp1(ptype, 0x0f, rd, rn); }

// Floating-point data-processing (2 source). ARM ARM -> FMUL/FDIV/FADD/FSUB/
// FMAX/FMIN/FMAXNM/FMINNM/FNMUL.
//   M 0 S 1 1 1 1 0 ptype<2> 1 Rm opcode<4> 1 0 Rn Rd
inline uint32_t fp2(unsigned ptype, unsigned opcode, unsigned rd, unsigned rn, unsigned rm) {
    return 0x1e200800u | ((ptype & 3u) << 22) | (detail::r5(rm) << 16) |
           ((opcode & 15u) << 12) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t fmul  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x0, rd, rn, rm); }
inline uint32_t fdiv  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x1, rd, rn, rm); }
inline uint32_t fadd  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x2, rd, rn, rm); }
inline uint32_t fsub  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x3, rd, rn, rm); }
inline uint32_t fmax  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x4, rd, rn, rm); }
inline uint32_t fmin  (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x5, rd, rn, rm); }
inline uint32_t fmaxnm(unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x6, rd, rn, rm); }
inline uint32_t fminnm(unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x7, rd, rn, rm); }
inline uint32_t fnmul (unsigned p, unsigned rd, unsigned rn, unsigned rm) { return fp2(p, 0x8, rd, rn, rm); }

// Floating-point data-processing (3 source). ARM ARM -> FMADD/FMSUB/FNMADD/FNMSUB.
//   M 0 S 1 1 1 1 1 ptype<2> o1 Rm o0 Ra Rn Rd
// ARM32's VMLA/VMLS are NOT fused; VFMA/VFMS are. Pick accordingly.
inline uint32_t fp3(unsigned ptype, bool o1, bool o0, unsigned rd, unsigned rn,
                    unsigned rm, unsigned ra) {
    return 0x1f000000u | ((ptype & 3u) << 22) | (o1 ? (1u << 21) : 0u) |
           (detail::r5(rm) << 16) | (o0 ? (1u << 15) : 0u) | (detail::r5(ra) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t fmadd (unsigned p, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return fp3(p, false, false, rd, rn, rm, ra); }
inline uint32_t fmsub (unsigned p, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return fp3(p, false, true,  rd, rn, rm, ra); }
inline uint32_t fnmadd(unsigned p, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return fp3(p, true,  false, rd, rn, rm, ra); }
inline uint32_t fnmsub(unsigned p, unsigned rd, unsigned rn, unsigned rm, unsigned ra) { return fp3(p, true,  true,  rd, rn, rm, ra); }

// Floating-point compare. ARM ARM -> FCMP / FCMPE.
//   M 0 S 1 1 1 1 0 ptype<2> 1 Rm op<2> 1 0 0 0 Rn opcode2<5>
// opcode2: 00000 FCMP reg, 01000 FCMP #0.0, 10000 FCMPE reg, 11000 FCMPE #0.0.
// FCMP writes NZCV directly, which is why ARM32 VCMP + VMRS APSR_nzcv collapses
// to a single FCMP here.
inline uint32_t fcmp(unsigned p, unsigned rn, unsigned rm) {
    return 0x1e202000u | ((p & 3u) << 22) | (detail::r5(rm) << 16) | (detail::r5(rn) << 5);
}
inline uint32_t fcmp_zero(unsigned p, unsigned rn) {
    return 0x1e202000u | ((p & 3u) << 22) | (detail::r5(rn) << 5) | 0x08u;
}
inline uint32_t fcmpe(unsigned p, unsigned rn, unsigned rm) {
    return 0x1e202000u | ((p & 3u) << 22) | (detail::r5(rm) << 16) | (detail::r5(rn) << 5) | 0x10u;
}
inline uint32_t fcmpe_zero(unsigned p, unsigned rn) {
    return 0x1e202000u | ((p & 3u) << 22) | (detail::r5(rn) << 5) | 0x18u;
}
// FCSEL. M 0 S 1 1 1 1 0 ptype<2> 1 Rm cond<4> 1 1 Rn Rd
inline uint32_t fcsel(unsigned p, unsigned rd, unsigned rn, unsigned rm, Cond c) {
    return 0x1e200c00u | ((p & 3u) << 22) | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | detail::r5(rd);
}
// FCCMP / FCCMPE. M 0 S 1 1 1 1 0 ptype<2> 1 Rm cond<4> 0 1 Rn op nzcv<4>
inline uint32_t fccmp(unsigned p, unsigned rn, unsigned rm, unsigned nzcv, Cond c) {
    return 0x1e200400u | ((p & 3u) << 22) | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(c) & 15u) << 12) | (detail::r5(rn) << 5) | (nzcv & 15u);
}
inline uint32_t fccmpe(unsigned p, unsigned rn, unsigned rm, unsigned nzcv, Cond c) {
    return fccmp(p, rn, rm, nzcv, c) | 0x10u;
}

// Floating-point immediate. ARM ARM -> FMOV (scalar, immediate).
//   M 0 S 1 1 1 1 0 ptype<2> 1 imm8<8> 1 0 0 imm5<5> Rd
// `imm8` comes from encode_fp_imm8().
inline uint32_t fmov_imm(unsigned p, unsigned rd, uint32_t imm8) {
    return 0x1e201000u | ((p & 3u) << 22) | ((imm8 & 0xffu) << 13) | detail::r5(rd);
}

// Conversion between floating-point and integer. ARM ARM -> FCVT*S/FCVT*U,
// SCVTF/UCVTF, and the register-transfer FMOV forms.
//   sf 0 S 1 1 1 1 0 ptype<2> 1 rmode<2> opcode<3> 0 0 0 0 0 0 Rn Rd
// rmode: 00 = "N" (nearest) for FCVTNS/NU, and the mode used by SCVTF/UCVTF and
// the register-transfer FMOVs; 01 = P (+inf); 10 = M (-inf); 11 = Z (zero).
// opcode: 000 signed-to-int, 001 unsigned-to-int, 010 SCVTF, 011 UCVTF,
//         100 FCVTAS, 101 FCVTAU, 110 FMOV to GPR, 111 FMOV from GPR.
inline uint32_t fp_int(bool is64, unsigned ptype, unsigned rmode, unsigned opcode,
                       unsigned rd, unsigned rn) {
    return detail::sf(is64) | 0x1e200000u | ((ptype & 3u) << 22) |
           ((rmode & 3u) << 19) | ((opcode & 7u) << 16) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t fcvtns(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 0, rd, rn); }
inline uint32_t fcvtnu(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 1, rd, rn); }
inline uint32_t fcvtps(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 1, 0, rd, rn); }
inline uint32_t fcvtpu(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 1, 1, rd, rn); }
inline uint32_t fcvtms(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 2, 0, rd, rn); }
inline uint32_t fcvtmu(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 2, 1, rd, rn); }
inline uint32_t fcvtzs(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 3, 0, rd, rn); }
inline uint32_t fcvtzu(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 3, 1, rd, rn); }
inline uint32_t fcvtas(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 4, rd, rn); }
inline uint32_t fcvtau(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 5, rd, rn); }
inline uint32_t scvtf (bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 2, rd, rn); }
inline uint32_t ucvtf (bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 3, rd, rn); }
// FMOV Wd,Sn / Xd,Dn (to GPR) and FMOV Sd,Wn / Dd,Xn (from GPR).
inline uint32_t fmov_to_gpr  (bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 6, rd, rn); }
inline uint32_t fmov_from_gpr(bool is64, unsigned p, unsigned rd, unsigned rn) { return fp_int(is64, p, 0, 7, rd, rn); }
// FMOV Xd, Vn.D[1] / FMOV Vd.D[1], Xn (ptype=10, rmode=01). The high-half
// transfers, needed to move a 128-bit value through GPRs.
inline uint32_t fmov_to_gpr_hi  (unsigned rd, unsigned rn) { return fp_int(true, 2, 1, 6, rd, rn); }
inline uint32_t fmov_from_gpr_hi(unsigned rd, unsigned rn) { return fp_int(true, 2, 1, 7, rd, rn); }

// Fixed-point conversions (bit 21 clear, scale field replaces the zeros).
//   sf 0 S 1 1 1 1 0 ptype<2> 0 rmode<2> opcode<3> scale<6> Rn Rd
// `fbits` is the number of fraction bits, 1..(32 or 64); the encoded scale is
// 64 - fbits. This is the direct target of ARM32's VCVT with a #fbits operand.
inline uint32_t fp_int_fixed(bool is64, unsigned ptype, unsigned rmode, unsigned opcode,
                             unsigned rd, unsigned rn, unsigned fbits) {
    return detail::sf(is64) | 0x1e000000u | ((ptype & 3u) << 22) |
           ((rmode & 3u) << 19) | ((opcode & 7u) << 16) | (((64u - fbits) & 0x3fu) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t fcvtzs_fixed(bool is64, unsigned p, unsigned rd, unsigned rn, unsigned fbits) { return fp_int_fixed(is64, p, 3, 0, rd, rn, fbits); }
inline uint32_t fcvtzu_fixed(bool is64, unsigned p, unsigned rd, unsigned rn, unsigned fbits) { return fp_int_fixed(is64, p, 3, 1, rd, rn, fbits); }
inline uint32_t scvtf_fixed (bool is64, unsigned p, unsigned rd, unsigned rn, unsigned fbits) { return fp_int_fixed(is64, p, 0, 2, rd, rn, fbits); }
inline uint32_t ucvtf_fixed (bool is64, unsigned p, unsigned rd, unsigned rn, unsigned fbits) { return fp_int_fixed(is64, p, 0, 3, rd, rn, fbits); }

// --- SIMD&FP load/store (the V=1 half of the load/store space) --------------
// `vsize` here is the register width selector: kSizeB/H/W/X for B/H/S/D, and
// kVecQ for the 128-bit Q form (which encodes as size=00 with opc<1> set).
enum : unsigned { kVecQ = 4 };
inline uint32_t fp_ldst_uimm(unsigned vsize, bool is_load, unsigned rt, unsigned rn, uint64_t off) {
    unsigned size = (vsize == kVecQ) ? 0u : vsize;
    unsigned opc = (vsize == kVecQ ? 2u : 0u) | (is_load ? 1u : 0u);
    unsigned shift = (vsize == kVecQ) ? 4u : vsize;
    uint32_t imm12 = static_cast<uint32_t>(off >> shift) & 0xfffu;
    return ((size & 3u) << 30) | 0x3d000000u | ((opc & 3u) << 22) | (imm12 << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t fp_ldst_simm9(unsigned vsize, bool is_load, unsigned rt, unsigned rn,
                              int64_t off, Index idx) {
    unsigned size = (vsize == kVecQ) ? 0u : vsize;
    unsigned opc = (vsize == kVecQ ? 2u : 0u) | (is_load ? 1u : 0u);
    uint32_t mode = (idx == Index::Offset) ? 0u : (idx == Index::PostIndex ? 1u : 3u);
    return ((size & 3u) << 30) | 0x3c000000u | ((opc & 3u) << 22) |
           ((static_cast<uint32_t>(off) & 0x1ffu) << 12) | (mode << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t fp_ldst_reg(unsigned vsize, bool is_load, unsigned rt, unsigned rn,
                            unsigned rm, Extend option = ExtLSL64, bool scaled = true) {
    unsigned size = (vsize == kVecQ) ? 0u : vsize;
    unsigned opc = (vsize == kVecQ ? 2u : 0u) | (is_load ? 1u : 0u);
    return ((size & 3u) << 30) | 0x3c200800u | ((opc & 3u) << 22) | (detail::r5(rm) << 16) |
           ((static_cast<uint32_t>(option) & 7u) << 13) | (scaled ? (1u << 12) : 0u) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t ldr_s(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kSizeW, true,  rt, rn, off); }
inline uint32_t str_s(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kSizeW, false, rt, rn, off); }
inline uint32_t ldr_d(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kSizeX, true,  rt, rn, off); }
inline uint32_t str_d(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kSizeX, false, rt, rn, off); }
inline uint32_t ldr_q(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kVecQ,  true,  rt, rn, off); }
inline uint32_t str_q(unsigned rt, unsigned rn, uint64_t off) { return fp_ldst_uimm(kVecQ,  false, rt, rn, off); }
// SIMD&FP pairs. opc: 00 = S, 01 = D, 10 = Q. Element log2: 2 / 3 / 4.
inline uint32_t stp_fp(unsigned vsize, unsigned rt, unsigned rt2, unsigned rn, int64_t off, Index i = Index::Offset) {
    unsigned opc = (vsize == kSizeW) ? 0u : (vsize == kSizeX ? 1u : 2u);
    unsigned el = (vsize == kSizeW) ? 2u : (vsize == kSizeX ? 3u : 4u);
    return ldst_pair(opc, true, i, false, rt, rt2, rn, off, el);
}
inline uint32_t ldp_fp(unsigned vsize, unsigned rt, unsigned rt2, unsigned rn, int64_t off, Index i = Index::Offset) {
    unsigned opc = (vsize == kSizeW) ? 0u : (vsize == kSizeX ? 1u : 2u);
    unsigned el = (vsize == kSizeW) ? 2u : (vsize == kSizeX ? 3u : 4u);
    return ldst_pair(opc, true, i, true, rt, rt2, rn, off, el);
}

// --- Vector element move (the ARM32 VMOV.32 Rd, Dn[i] family) ---------------
// The imm5 "element selector" is shared by INS/UMOV/SMOV/DUP:
//   B[i] -> imm5 = (i << 1) | 1        H[i] -> (i << 2) | 2
//   S[i] -> imm5 = (i << 3) | 4        D[i] -> (i << 4) | 8
// ARM ARM C7.2 -> "Advanced SIMD copy" encoding class.
constexpr uint32_t vec_imm5(unsigned elem_log2, unsigned index) {
    return ((index << (elem_log2 + 1)) | (1u << elem_log2)) & 0x1fu;
}
// UMOV Rd, Vn.<T>[i].  0 Q 0 0 1 1 1 0 0 0 0 imm5<5> 0 0 1 1 1 1 Rn Rd
// Q must be 1 exactly when the element is D (a 64-bit result).
inline uint32_t umov(bool q, unsigned imm5, unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | 0x0e003c00u | ((imm5 & 0x1fu) << 16) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// SMOV Rd, Vn.<T>[i].  0 Q 0 0 1 1 1 0 0 0 0 imm5<5> 0 0 1 0 1 1 Rn Rd
// Q selects the X-register (sign-extend-to-64) form.
inline uint32_t smov(bool q, unsigned imm5, unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | 0x0e002c00u | ((imm5 & 0x1fu) << 16) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// INS Vd.<T>[i], Rn.  0 1 0 0 1 1 1 0 0 0 0 imm5<5> 0 0 0 1 1 1 Rn Rd
inline uint32_t ins_gen(unsigned imm5, unsigned rd, unsigned rn) {
    return 0x4e001c00u | ((imm5 & 0x1fu) << 16) | (detail::r5(rn) << 5) | detail::r5(rd);
}
// INS Vd.<T>[i1], Vn.<T>[i2].  0 1 1 0 1 1 1 0 0 0 0 imm5<5> 0 imm4<4> 1 Rn Rd
// imm4 is the SOURCE index shifted LEFT by the element's log2 size, i.e.
// imm4 == src_index << elem_log2 (verified against llvm-mc for B/H/S/D).
inline uint32_t ins_elem(unsigned imm5, unsigned imm4, unsigned rd, unsigned rn) {
    return 0x6e000400u | ((imm5 & 0x1fu) << 16) | ((imm4 & 15u) << 11) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// DUP Vd.<T>, Rn.  0 Q 0 0 1 1 1 0 0 0 0 imm5<5> 0 0 0 0 1 1 Rn Rd
inline uint32_t dup_gen(bool q, unsigned imm5, unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | 0x0e000c00u | ((imm5 & 0x1fu) << 16) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// DUP Vd.<T>, Vn.<T>[i].  0 Q 0 0 1 1 1 0 0 0 0 imm5<5> 0 0 0 0 0 1 Rn Rd
inline uint32_t dup_elem(bool q, unsigned imm5, unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | 0x0e000400u | ((imm5 & 0x1fu) << 16) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// (MOVI and the rest of the modified-immediate group live in the Advanced SIMD
// section below, alongside the shift-by-immediate group they share a base with.)

// ---------------------------------------------------------------------------
// Advanced SIMD (NEON)
// ---------------------------------------------------------------------------
//
// The existing LLVM-based ARM32 lifter already handles ~140 NEON/VFP mnemonics
// (VADD/VMLA/VQADD/VSHL/VLD1/VTBL/VZIP/...), so the direct recompiler needs the
// matching A64 encoders to reach parity. The mapping is mostly 1:1: A64 keeps
// the same operations, restructured around 128-bit V registers instead of
// overlapping D/Q registers. Register-file remapping is the translator's job;
// this file only encodes.
//
// A vector operand is an ARRANGEMENT: an element size plus Q (64- or 128-bit).
// VArr packs both so a single parameter carries what the manual writes as
// "Vd.<T>". Bit 0 is Q, bits 2:1 are the size field.
enum VArr : unsigned {
    V8B = 0, V16B = 1,
    V4H = 2, V8H = 3,
    V2S = 4, V4S = 5,
    V1D = 6, V2D = 7,
};
constexpr bool varr_q(VArr a) { return (static_cast<unsigned>(a) & 1u) != 0; }
constexpr unsigned varr_size(VArr a) { return (static_cast<unsigned>(a) >> 1) & 3u; }
constexpr unsigned varr_esize(VArr a) { return 8u << varr_size(a); }

// Floating-point vector arrangements. In the FP encodings the size field is
// split: size<0> ("sz") selects 32- vs 64-bit lanes, while size<1> selects
// between two operations sharing one opcode (FADD/FSUB, FMAX/FMIN, ...).
// Bit 0 is Q, bit 1 is sz.
enum FArr : unsigned { FV2S = 0, FV4S = 1, FV2D = 3 };
constexpr bool farr_q(FArr a) { return (static_cast<unsigned>(a) & 1u) != 0; }
constexpr unsigned farr_sz(FArr a) { return (static_cast<unsigned>(a) >> 1) & 1u; }

// --- Advanced SIMD three same ----------------------------------------------
//   0 Q U 0 1 1 1 0 size<2> 1 Rm opcode<5> 1 Rn Rd
// ARM ARM C4.1.6 encoding class "Advanced SIMD three same".
inline uint32_t simd_3same(bool q, bool u, unsigned size, unsigned opcode,
                           unsigned rd, unsigned rn, unsigned rm) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0e200400u |
           ((size & 3u) << 22) | (detail::r5(rm) << 16) | ((opcode & 0x1fu) << 11) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t v3s(VArr a, bool u, unsigned opcode, unsigned rd, unsigned rn, unsigned rm) {
    return simd_3same(varr_q(a), u, varr_size(a), opcode, rd, rn, rm);
}
// Floating-point three-same. `hi` is size<1>, the op selector.
inline uint32_t vf3s(FArr a, bool u, bool hi, unsigned opcode, unsigned rd, unsigned rn,
                     unsigned rm) {
    return simd_3same(farr_q(a), u, (hi ? 2u : 0u) | farr_sz(a), opcode, rd, rn, rm);
}

// Integer three-same. Opcode numbers are the manual's "opcode" column.
inline uint32_t vadd  (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x10, rd, rn, rm); }
inline uint32_t vsub  (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x10, rd, rn, rm); }
inline uint32_t vmul  (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x13, rd, rn, rm); }
inline uint32_t vpmul (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x13, rd, rn, rm); }
inline uint32_t vmla  (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x12, rd, rn, rm); }
inline uint32_t vmls  (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x12, rd, rn, rm); }
inline uint32_t vcmeq (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x11, rd, rn, rm); }
inline uint32_t vcmtst(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x11, rd, rn, rm); }
inline uint32_t vcmgt (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x06, rd, rn, rm); }
inline uint32_t vcmge (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x07, rd, rn, rm); }
inline uint32_t vcmhi (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x06, rd, rn, rm); }
inline uint32_t vcmhs (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x07, rd, rn, rm); }
inline uint32_t vsmax (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0c, rd, rn, rm); }
inline uint32_t vsmin (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0d, rd, rn, rm); }
inline uint32_t vumax (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0c, rd, rn, rm); }
inline uint32_t vumin (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0d, rd, rn, rm); }
inline uint32_t vsabd (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0e, rd, rn, rm); }
inline uint32_t vuabd (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0e, rd, rn, rm); }
inline uint32_t vsaba (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0f, rd, rn, rm); }
inline uint32_t vuaba (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0f, rd, rn, rm); }
inline uint32_t vsqadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x01, rd, rn, rm); }
inline uint32_t vuqadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x01, rd, rn, rm); }
inline uint32_t vsqsub(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x05, rd, rn, rm); }
inline uint32_t vuqsub(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x05, rd, rn, rm); }
inline uint32_t vshadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x00, rd, rn, rm); }
inline uint32_t vuhadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x00, rd, rn, rm); }
inline uint32_t vshsub(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x04, rd, rn, rm); }
inline uint32_t vuhsub(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x04, rd, rn, rm); }
inline uint32_t vsrhadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x02, rd, rn, rm); }
inline uint32_t vurhadd(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x02, rd, rn, rm); }
inline uint32_t vsshl (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x08, rd, rn, rm); }
inline uint32_t vushl (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x08, rd, rn, rm); }
inline uint32_t vsqshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x09, rd, rn, rm); }
inline uint32_t vuqshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x09, rd, rn, rm); }
inline uint32_t vsrshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0a, rd, rn, rm); }
inline uint32_t vurshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0a, rd, rn, rm); }
inline uint32_t vsqrshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x0b, rd, rn, rm); }
inline uint32_t vuqrshl(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x0b, rd, rn, rm); }
inline uint32_t vaddp (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x17, rd, rn, rm); }
inline uint32_t vsmaxp(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x14, rd, rn, rm); }
inline uint32_t vsminp(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x15, rd, rn, rm); }
inline uint32_t vumaxp(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x14, rd, rn, rm); }
inline uint32_t vuminp(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x15, rd, rn, rm); }
inline uint32_t vsqdmulh (VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, false, 0x16, rd, rn, rm); }
inline uint32_t vsqrdmulh(VArr a, unsigned rd, unsigned rn, unsigned rm) { return v3s(a, true,  0x16, rd, rn, rm); }

// Logical three-same. These have no element size: the arrangement is always
// 8B or 16B and the "size" field selects the operation instead.
inline uint32_t vand(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, false, 0, 0x03, rd, rn, rm); }
inline uint32_t vbic(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, false, 1, 0x03, rd, rn, rm); }
inline uint32_t vorr(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, false, 2, 0x03, rd, rn, rm); }
inline uint32_t vorn(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, false, 3, 0x03, rd, rn, rm); }
inline uint32_t veor(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, true,  0, 0x03, rd, rn, rm); }
inline uint32_t vbsl(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, true,  1, 0x03, rd, rn, rm); }
inline uint32_t vbit(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, true,  2, 0x03, rd, rn, rm); }
inline uint32_t vbif(bool q, unsigned rd, unsigned rn, unsigned rm) { return simd_3same(q, true,  3, 0x03, rd, rn, rm); }
inline uint32_t vmov_reg(bool q, unsigned rd, unsigned rn) { return vorr(q, rd, rn, rn); }  // MOV Vd.16B, Vn.16B

// Floating-point three-same.
inline uint32_t vfadd   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x1a, rd, rn, rm); }
inline uint32_t vfsub   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, true,  0x1a, rd, rn, rm); }
inline uint32_t vfmul   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1b, rd, rn, rm); }
inline uint32_t vfdiv   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1f, rd, rn, rm); }
inline uint32_t vfmla   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x19, rd, rn, rm); }
inline uint32_t vfmls   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, true,  0x19, rd, rn, rm); }
inline uint32_t vfmax   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x1e, rd, rn, rm); }
inline uint32_t vfmin   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, true,  0x1e, rd, rn, rm); }
inline uint32_t vfmaxnm (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x18, rd, rn, rm); }
inline uint32_t vfminnm (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, true,  0x18, rd, rn, rm); }
inline uint32_t vfabd   (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  true,  0x1a, rd, rn, rm); }
inline uint32_t vfcmeq  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x1c, rd, rn, rm); }
inline uint32_t vfcmge  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1c, rd, rn, rm); }
inline uint32_t vfcmgt  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  true,  0x1c, rd, rn, rm); }
inline uint32_t vfacge  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1d, rd, rn, rm); }
inline uint32_t vfacgt  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  true,  0x1d, rd, rn, rm); }
inline uint32_t vfrecps (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x1f, rd, rn, rm); }
inline uint32_t vfrsqrts(FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, true,  0x1f, rd, rn, rm); }
inline uint32_t vfaddp  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1a, rd, rn, rm); }
inline uint32_t vfmaxp  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  false, 0x1e, rd, rn, rm); }
inline uint32_t vfminp  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, true,  true,  0x1e, rd, rn, rm); }
inline uint32_t vfmulx  (FArr a, unsigned rd, unsigned rn, unsigned rm) { return vf3s(a, false, false, 0x1b, rd, rn, rm); }

// --- Advanced SIMD two-register miscellaneous -------------------------------
//   0 Q U 0 1 1 1 0 size<2> 1 0 0 0 0 opcode<5> 1 0 Rn Rd
inline uint32_t simd_2misc(bool q, bool u, unsigned size, unsigned opcode,
                           unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0e200800u |
           ((size & 3u) << 22) | ((opcode & 0x1fu) << 12) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t v2m(VArr a, bool u, unsigned opcode, unsigned rd, unsigned rn) {
    return simd_2misc(varr_q(a), u, varr_size(a), opcode, rd, rn);
}
inline uint32_t vf2m(FArr a, bool u, bool hi, unsigned opcode, unsigned rd, unsigned rn) {
    return simd_2misc(farr_q(a), u, (hi ? 2u : 0u) | farr_sz(a), opcode, rd, rn);
}
inline uint32_t vrev64(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x00, rd, rn); }
inline uint32_t vrev32(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x00, rd, rn); }
inline uint32_t vrev16(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x01, rd, rn); }
inline uint32_t vcls  (VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x04, rd, rn); }
inline uint32_t vclz  (VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x04, rd, rn); }
inline uint32_t vcnt  (bool q, unsigned rd, unsigned rn) { return simd_2misc(q, false, 0, 0x05, rd, rn); }
inline uint32_t vmvn  (bool q, unsigned rd, unsigned rn) { return simd_2misc(q, true,  0, 0x05, rd, rn); }  // NOT
inline uint32_t vrbit (bool q, unsigned rd, unsigned rn) { return simd_2misc(q, true,  1, 0x05, rd, rn); }
inline uint32_t vabs  (VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x0b, rd, rn); }
inline uint32_t vneg  (VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x0b, rd, rn); }
inline uint32_t vqabs (VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x07, rd, rn); }
inline uint32_t vqneg (VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x07, rd, rn); }
inline uint32_t vcmgt0(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x08, rd, rn); }
inline uint32_t vcmge0(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x08, rd, rn); }
inline uint32_t vcmeq0(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x09, rd, rn); }
inline uint32_t vcmle0(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x09, rd, rn); }
inline uint32_t vcmlt0(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x0a, rd, rn); }
inline uint32_t vsaddlp(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x02, rd, rn); }
inline uint32_t vuaddlp(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x02, rd, rn); }
inline uint32_t vsadalp(VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x06, rd, rn); }
inline uint32_t vuadalp(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x06, rd, rn); }
// Narrowing. `a` is the DESTINATION arrangement; Q selects XTN vs XTN2.
inline uint32_t vxtn   (VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x12, rd, rn); }
inline uint32_t vsqxtn (VArr a, unsigned rd, unsigned rn) { return v2m(a, false, 0x14, rd, rn); }
inline uint32_t vuqxtn (VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x14, rd, rn); }
inline uint32_t vsqxtun(VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x12, rd, rn); }
inline uint32_t vshll  (VArr a, unsigned rd, unsigned rn) { return v2m(a, true,  0x13, rd, rn); }  // SHLL, shift == esize
// FP two-reg misc.
inline uint32_t vfabs   (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x0f, rd, rn); }
inline uint32_t vfneg   (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x0f, rd, rn); }
inline uint32_t vfsqrt  (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x1f, rd, rn); }
inline uint32_t vfrecpe (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x1d, rd, rn); }
inline uint32_t vfrsqrte(FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x1d, rd, rn); }
inline uint32_t vfrintn (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, false, 0x18, rd, rn); }
inline uint32_t vfrintm (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, false, 0x19, rd, rn); }
inline uint32_t vfrintp (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x18, rd, rn); }
inline uint32_t vfrintz (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x19, rd, rn); }
inline uint32_t vfrinta (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  false, 0x18, rd, rn); }
inline uint32_t vfrintx (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  false, 0x19, rd, rn); }
inline uint32_t vfrinti (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x19, rd, rn); }
inline uint32_t vfcvtzs (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x1b, rd, rn); }
inline uint32_t vfcvtzu (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x1b, rd, rn); }
inline uint32_t vscvtf  (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, false, 0x1d, rd, rn); }
inline uint32_t vucvtf  (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  false, 0x1d, rd, rn); }
inline uint32_t vfcmgt0 (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x0c, rd, rn); }
inline uint32_t vfcmge0 (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x0c, rd, rn); }
inline uint32_t vfcmeq0 (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x0d, rd, rn); }
inline uint32_t vfcmle0 (FArr a, unsigned rd, unsigned rn) { return vf2m(a, true,  true,  0x0d, rd, rn); }
inline uint32_t vfcmlt0 (FArr a, unsigned rd, unsigned rn) { return vf2m(a, false, true,  0x0e, rd, rn); }
// FCVTN/FCVTL convert between 32- and 64-bit lanes (and 16/32 with sz=0).
// `sz`: 0 -> half<->single, 1 -> single<->double. Q selects the second half.
inline uint32_t vfcvtn(bool q, bool sz, unsigned rd, unsigned rn) { return simd_2misc(q, false, sz ? 1u : 0u, 0x16, rd, rn); }
inline uint32_t vfcvtl(bool q, bool sz, unsigned rd, unsigned rn) { return simd_2misc(q, false, sz ? 1u : 0u, 0x17, rd, rn); }

// --- Advanced SIMD shift by immediate ---------------------------------------
//   0 Q U 0 1 1 1 1 0 immh<4> immb<3> opcode<5> 1 Rn Rd
// immh must be nonzero (immh == 0 is the modified-immediate group below).
inline uint32_t simd_shift_imm(bool q, bool u, unsigned immh_immb, unsigned opcode,
                               unsigned rd, unsigned rn) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0f000400u |
           ((immh_immb & 0x7fu) << 16) | ((opcode & 0x1fu) << 11) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
// The manual encodes the shift amount relative to the element size:
//   left  shifts (SHL, SLI, SQSHL, SSHLL/SXTL): immh:immb = esize + shift
//   right shifts (SSHR, USHR, SRSHR, SRI, SHRN, ...): immh:immb = 2*esize - shift
// `esize` is the size the manual derives from immh: the operand size for
// same-width shifts, the SOURCE size for widening left shifts (SSHLL), and the
// DESTINATION size for narrowing right shifts (SHRN and friends).
constexpr unsigned simd_shl_bits(unsigned esize, unsigned shift) { return esize + shift; }
constexpr unsigned simd_shr_bits(unsigned esize, unsigned shift) { return 2u * esize - shift; }

inline uint32_t vshl_imm (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shl_bits(varr_esize(a), sh), 0x0a, rd, rn); }
inline uint32_t vsli     (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shl_bits(varr_esize(a), sh), 0x0a, rd, rn); }
inline uint32_t vsqshl_imm(VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shl_bits(varr_esize(a), sh), 0x0e, rd, rn); }
inline uint32_t vuqshl_imm(VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shl_bits(varr_esize(a), sh), 0x0e, rd, rn); }
inline uint32_t vsshr    (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shr_bits(varr_esize(a), sh), 0x00, rd, rn); }
inline uint32_t vushr    (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shr_bits(varr_esize(a), sh), 0x00, rd, rn); }
inline uint32_t vssra    (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shr_bits(varr_esize(a), sh), 0x02, rd, rn); }
inline uint32_t vusra    (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shr_bits(varr_esize(a), sh), 0x02, rd, rn); }
inline uint32_t vsrshr   (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shr_bits(varr_esize(a), sh), 0x04, rd, rn); }
inline uint32_t vurshr   (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shr_bits(varr_esize(a), sh), 0x04, rd, rn); }
inline uint32_t vsrsra   (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), false, simd_shr_bits(varr_esize(a), sh), 0x06, rd, rn); }
inline uint32_t vursra   (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shr_bits(varr_esize(a), sh), 0x06, rd, rn); }
inline uint32_t vsri     (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true,  simd_shr_bits(varr_esize(a), sh), 0x08, rd, rn); }
// Widening: `src` is the SOURCE arrangement (its Q selects the source half).
inline uint32_t vsshll(VArr src, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(src), false, simd_shl_bits(varr_esize(src), sh), 0x14, rd, rn); }
inline uint32_t vushll(VArr src, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(src), true,  simd_shl_bits(varr_esize(src), sh), 0x14, rd, rn); }
inline uint32_t vsxtl (VArr src, unsigned rd, unsigned rn) { return vsshll(src, rd, rn, 0); }
inline uint32_t vuxtl (VArr src, unsigned rd, unsigned rn) { return vushll(src, rd, rn, 0); }
// Narrowing: `dst` is the DESTINATION arrangement (its Q selects XXX vs XXX2).
inline uint32_t vshrn    (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), false, simd_shr_bits(varr_esize(dst), sh), 0x10, rd, rn); }
inline uint32_t vrshrn   (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), false, simd_shr_bits(varr_esize(dst), sh), 0x11, rd, rn); }
inline uint32_t vsqshrn  (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), false, simd_shr_bits(varr_esize(dst), sh), 0x12, rd, rn); }
inline uint32_t vsqrshrn (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), false, simd_shr_bits(varr_esize(dst), sh), 0x13, rd, rn); }
inline uint32_t vuqshrn  (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), true,  simd_shr_bits(varr_esize(dst), sh), 0x12, rd, rn); }
inline uint32_t vuqrshrn (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), true,  simd_shr_bits(varr_esize(dst), sh), 0x13, rd, rn); }
inline uint32_t vsqshrun (VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), true,  simd_shr_bits(varr_esize(dst), sh), 0x10, rd, rn); }
inline uint32_t vsqrshrun(VArr dst, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(dst), true,  simd_shr_bits(varr_esize(dst), sh), 0x11, rd, rn); }
inline uint32_t vsqshlu  (VArr a, unsigned rd, unsigned rn, unsigned sh) { return simd_shift_imm(varr_q(a), true, simd_shl_bits(varr_esize(a), sh), 0x0c, rd, rn); }

// --- Advanced SIMD three different (widening / narrowing) -------------------
//   0 Q U 0 1 1 1 0 size<2> 1 Rm opcode<4> 0 0 Rn Rd
// `size` is the SOURCE element size for the widening forms.
inline uint32_t simd_3diff(bool q, bool u, unsigned size, unsigned opcode,
                           unsigned rd, unsigned rn, unsigned rm) {
    return (q ? 0x40000000u : 0u) | (u ? 0x20000000u : 0u) | 0x0e200000u |
           ((size & 3u) << 22) | (detail::r5(rm) << 16) | ((opcode & 15u) << 12) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t v3d(VArr src, bool u, unsigned opcode, unsigned rd, unsigned rn, unsigned rm) {
    return simd_3diff(varr_q(src), u, varr_size(src), opcode, rd, rn, rm);
}
inline uint32_t vsaddl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x0, rd, rn, rm); }
inline uint32_t vuaddl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x0, rd, rn, rm); }
inline uint32_t vsaddw(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x1, rd, rn, rm); }
inline uint32_t vuaddw(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x1, rd, rn, rm); }
inline uint32_t vssubl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x2, rd, rn, rm); }
inline uint32_t vusubl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x2, rd, rn, rm); }
inline uint32_t vssubw(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x3, rd, rn, rm); }
inline uint32_t vusubw(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x3, rd, rn, rm); }
inline uint32_t vsabal(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x5, rd, rn, rm); }
inline uint32_t vuabal(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x5, rd, rn, rm); }
inline uint32_t vsabdl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x7, rd, rn, rm); }
inline uint32_t vuabdl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x7, rd, rn, rm); }
inline uint32_t vsmlal(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x8, rd, rn, rm); }
inline uint32_t vumlal(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0x8, rd, rn, rm); }
inline uint32_t vsmlsl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0xa, rd, rn, rm); }
inline uint32_t vumlsl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0xa, rd, rn, rm); }
inline uint32_t vsmull(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0xc, rd, rn, rm); }
inline uint32_t vumull(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, true,  0xc, rd, rn, rm); }
inline uint32_t vsqdmlal(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0x9, rd, rn, rm); }
inline uint32_t vsqdmlsl(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0xb, rd, rn, rm); }
inline uint32_t vsqdmull(VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0xd, rd, rn, rm); }
inline uint32_t vpmull  (VArr s, unsigned rd, unsigned rn, unsigned rm) { return v3d(s, false, 0xe, rd, rn, rm); }
// Narrowing adds: `dst` is the DESTINATION arrangement.
inline uint32_t vaddhn (VArr dst, unsigned rd, unsigned rn, unsigned rm) { return v3d(dst, false, 0x4, rd, rn, rm); }
inline uint32_t vraddhn(VArr dst, unsigned rd, unsigned rn, unsigned rm) { return v3d(dst, true,  0x4, rd, rn, rm); }
inline uint32_t vsubhn (VArr dst, unsigned rd, unsigned rn, unsigned rm) { return v3d(dst, false, 0x6, rd, rn, rm); }
inline uint32_t vrsubhn(VArr dst, unsigned rd, unsigned rn, unsigned rm) { return v3d(dst, true,  0x6, rd, rn, rm); }

// --- Permute / extract / table ----------------------------------------------
//   ZIP/UZP/TRN: 0 Q 0 0 1 1 1 0 size<2> 0 Rm 0 opcode<3> 1 0 Rn Rd
inline uint32_t simd_permute(bool q, unsigned size, unsigned opcode, unsigned rd,
                             unsigned rn, unsigned rm) {
    return (q ? 0x40000000u : 0u) | 0x0e000800u | ((size & 3u) << 22) |
           (detail::r5(rm) << 16) | ((opcode & 7u) << 12) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t vuzp1(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 1, rd, rn, rm); }
inline uint32_t vtrn1(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 2, rd, rn, rm); }
inline uint32_t vzip1(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 3, rd, rn, rm); }
inline uint32_t vuzp2(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 5, rd, rn, rm); }
inline uint32_t vtrn2(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 6, rd, rn, rm); }
inline uint32_t vzip2(VArr a, unsigned rd, unsigned rn, unsigned rm) { return simd_permute(varr_q(a), varr_size(a), 7, rd, rn, rm); }
//   EXT: 0 Q 1 0 1 1 1 0 0 0 0 Rm 0 imm4<4> 0 Rn Rd
inline uint32_t vext(bool q, unsigned rd, unsigned rn, unsigned rm, unsigned imm4) {
    return (q ? 0x40000000u : 0u) | 0x2e000000u | (detail::r5(rm) << 16) |
           ((imm4 & 15u) << 11) | (detail::r5(rn) << 5) | detail::r5(rd);
}
//   TBL/TBX: 0 Q 0 0 1 1 1 0 0 0 0 Rm 0 len<2> op 0 0 Rn Rd
// `nregs` is 1..4 consecutive table registers starting at Rn (len = nregs - 1).
inline uint32_t vtbl(bool q, unsigned nregs, unsigned rd, unsigned rn, unsigned rm) {
    return (q ? 0x40000000u : 0u) | 0x0e000000u | (detail::r5(rm) << 16) |
           (((nregs - 1u) & 3u) << 13) | (detail::r5(rn) << 5) | detail::r5(rd);
}
inline uint32_t vtbx(bool q, unsigned nregs, unsigned rd, unsigned rn, unsigned rm) {
    return vtbl(q, nregs, rd, rn, rm) | (1u << 12);
}

// --- Advanced SIMD modified immediate (MOVI / MVNI / vector FMOV) ------------
//   0 Q op 0 1 1 1 1 0 0 0 0 0 abc<3> cmode<4> o2 1 defgh<5> Rd
// This shares its base with the shift-by-immediate group and is distinguished
// by immh (bits 22:19) being zero. `imm8` is abc:defgh.
inline uint32_t simd_mod_imm(bool q, bool op, unsigned cmode, uint32_t imm8, unsigned rd) {
    return (q ? 0x40000000u : 0u) | (op ? 0x20000000u : 0u) | 0x0f000400u |
           (((imm8 >> 5) & 7u) << 16) | ((cmode & 15u) << 12) | ((imm8 & 0x1fu) << 5) |
           detail::r5(rd);
}
// The common cmode values: 0b0000/0010/0100/0110 shift an 8-bit value into a
// 32-bit lane by 0/8/16/24; 0b1000/1010 into a 16-bit lane by 0/8;
// 0b1110 with op=0 replicates the byte, and with op=1 is the 64-bit byte-mask
// form used by MOVI Vd.2D.
inline uint32_t vmovi_8b (bool q, uint32_t imm8, unsigned rd) { return simd_mod_imm(q, false, 0xe, imm8, rd); }
inline uint32_t vmovi_32 (bool q, uint32_t imm8, unsigned shift_bytes, unsigned rd) { return simd_mod_imm(q, false, (shift_bytes & 3u) << 1, imm8, rd); }
inline uint32_t vmvni_32 (bool q, uint32_t imm8, unsigned shift_bytes, unsigned rd) { return simd_mod_imm(q, true,  (shift_bytes & 3u) << 1, imm8, rd); }
inline uint32_t vmovi_16 (bool q, uint32_t imm8, unsigned shift_bytes, unsigned rd) { return simd_mod_imm(q, false, 0x8u | ((shift_bytes & 1u) << 1), imm8, rd); }
inline uint32_t vmvni_16 (bool q, uint32_t imm8, unsigned shift_bytes, unsigned rd) { return simd_mod_imm(q, true,  0x8u | ((shift_bytes & 1u) << 1), imm8, rd); }
inline uint32_t vmovi_2d (uint32_t imm8, unsigned rd) { return simd_mod_imm(true, true, 0xe, imm8, rd); }
inline uint32_t movi_2d_zero(unsigned rd) { return vmovi_2d(0, rd); }
// FMOV Vd.<T>, #imm  (cmode 0b1111): op=0 gives the 32-bit-lane form, op=1 the
// 64-bit-lane form. `imm8` is the same encoding as encode_fp_imm8().
inline uint32_t vfmov_imm(bool q, bool is_double, uint32_t imm8, unsigned rd) {
    return simd_mod_imm(q, is_double, 0xf, imm8, rd);
}

// --- Advanced SIMD load/store multiple structures (VLD1/VST1 family) ---------
//   no writeback: 0 Q 0 0 1 1 0 0 0 L 0 0 0 0 0 0 opcode<4> size<2> Rn Rt
//   post-index:   0 Q 0 0 1 1 0 0 1 L 0 Rm        opcode<4> size<2> Rn Rt
// Rm == 31 in the post-index form means "advance by the transfer size";
// any other Rm advances by that register's value.
// `opcode` selects the structure count and interleave; the constants below name
// the ones an ARM32 VLD1/VLD2/VLD3/VLD4 lowers to.
enum : unsigned {
    kSimdLd4  = 0x0,  // LD4/ST4, 4 registers, 4-way interleave
    kSimdLd1x4 = 0x2,  // LD1/ST1, 4 registers, no interleave
    kSimdLd3  = 0x4,
    kSimdLd1x3 = 0x6,
    kSimdLd1x1 = 0x7,
    kSimdLd2  = 0x8,
    kSimdLd1x2 = 0xa,
};
inline uint32_t simd_ldst_multi(bool q, bool is_load, unsigned opcode, unsigned size,
                                unsigned rt, unsigned rn) {
    return (q ? 0x40000000u : 0u) | 0x0c000000u | (is_load ? (1u << 22) : 0u) |
           ((opcode & 15u) << 12) | ((size & 3u) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t simd_ldst_multi_post(bool q, bool is_load, unsigned opcode, unsigned size,
                                     unsigned rt, unsigned rn, unsigned rm = kZR) {
    return simd_ldst_multi(q, is_load, opcode, size, rt, rn) | 0x00800000u |
           (detail::r5(rm) << 16);
}
// nregs is 1..4.
constexpr unsigned simd_ld1_opcode(unsigned nregs) {
    return nregs == 1 ? kSimdLd1x1 : (nregs == 2 ? kSimdLd1x2 : (nregs == 3 ? kSimdLd1x3 : kSimdLd1x4));
}
inline uint32_t vld1(VArr a, unsigned nregs, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), true,  simd_ld1_opcode(nregs), varr_size(a), rt, rn); }
inline uint32_t vst1(VArr a, unsigned nregs, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), false, simd_ld1_opcode(nregs), varr_size(a), rt, rn); }
inline uint32_t vld1_post(VArr a, unsigned nregs, unsigned rt, unsigned rn, unsigned rm = kZR) { return simd_ldst_multi_post(varr_q(a), true,  simd_ld1_opcode(nregs), varr_size(a), rt, rn, rm); }
inline uint32_t vst1_post(VArr a, unsigned nregs, unsigned rt, unsigned rn, unsigned rm = kZR) { return simd_ldst_multi_post(varr_q(a), false, simd_ld1_opcode(nregs), varr_size(a), rt, rn, rm); }
inline uint32_t vld2(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), true,  kSimdLd2, varr_size(a), rt, rn); }
inline uint32_t vst2(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), false, kSimdLd2, varr_size(a), rt, rn); }
inline uint32_t vld3(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), true,  kSimdLd3, varr_size(a), rt, rn); }
inline uint32_t vst3(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), false, kSimdLd3, varr_size(a), rt, rn); }
inline uint32_t vld4(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), true,  kSimdLd4, varr_size(a), rt, rn); }
inline uint32_t vst4(VArr a, unsigned rt, unsigned rn) { return simd_ldst_multi(varr_q(a), false, kSimdLd4, varr_size(a), rt, rn); }

// --- CRC32 (ARM32 has the same instructions; the mapping is 1:1) ------------
//   sf 0 0 1 1 0 1 0 1 1 0 Rm 0 1 0 C sz<2> Rn Rd
// sz: 00 byte, 01 halfword, 10 word, 11 doubleword (sz==11 requires sf==1).
// C selects the Castagnoli polynomial (CRC32C*).
inline uint32_t crc32(bool is64, bool castagnoli, unsigned sz, unsigned rd, unsigned rn,
                      unsigned rm) {
    return detail::sf(is64) | 0x1ac04000u | (detail::r5(rm) << 16) |
           (castagnoli ? (1u << 12) : 0u) | ((sz & 3u) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rd);
}

// --- Non-temporal pairs and prefetch ----------------------------------------
// LDNP/STNP are the ldst_pair encoding class with mode == 000.
inline uint32_t ldnp(bool is64, unsigned rt, unsigned rt2, unsigned rn, int64_t off) {
    const unsigned el = is64 ? 3u : 2u;
    return ((is64 ? 2u : 0u) << 30) | 0x28000000u | (1u << 22) |
           ((static_cast<uint32_t>(off >> el) & 0x7fu) << 15) | (detail::r5(rt2) << 10) |
           (detail::r5(rn) << 5) | detail::r5(rt);
}
inline uint32_t stnp(bool is64, unsigned rt, unsigned rt2, unsigned rn, int64_t off) {
    return ldnp(is64, rt, rt2, rn, off) & ~(1u << 22);
}
// PRFM (immediate) is the 64-bit unsigned-offset load/store slot with opc==10.
// `prfop` is the 5-bit <type><target><policy> operand (PLDL1KEEP == 0).
inline uint32_t prfm(unsigned prfop, unsigned rn, uint64_t off) {
    return ldst_uimm(kSizeX, false, 2, prfop, rn, off);
}

// ===========================================================================
// A64Buf: instruction buffer with labels and out-of-range reporting
// ===========================================================================

struct Label {
    uint32_t id = 0xffffffffu;
    bool valid() const { return id != 0xffffffffu; }
};

// The five PC-relative field shapes a fixup can target. The kind determines the
// range check and the bit placement at resolve() time.
enum class FixKind {
    B26,       // B, BL                       +/-128 MiB
    Cond19,    // B.cond, CBZ, CBNZ           +/-1 MiB
    Lit19,     // LDR (literal)               +/-1 MiB
    TB14,      // TBZ, TBNZ                   +/-32 KiB
    Adr21,     // ADR                         +/-1 MiB, byte granular
};

struct Fixup {
    FixKind  kind;
    uint32_t insn_index;  // word index of the instruction to patch
    Label    label;       // target
};

// A64Buf is deliberately thin: encoders stay pure functions and are emitted
// with put(). The buffer only owns the two things a pure function cannot do,
// namely (a) knowing the current PC and (b) patching a forward branch once its
// target is known.
//
// OUT-OF-RANGE PROTOCOL. resolve() never silently truncates a displacement.
// A displacement that does not fit its field is left UNPATCHED (the placeholder
// word stays exactly as emitted) and the Fixup is reported through
// out_overflow. The caller then rewrites that instruction itself, typically by
//   * inverting a B.cond/CBZ/TBZ to skip over a full-range B, or
//   * emitting a veneer (MOVZ/MOVK chain + BR) at the end of the function and
//     retargeting the branch at it, or
//   * planting a literal island within +/-1 MiB for an LDR (literal),
// and calls resolve() again. Repeat until it returns true. Because failures are
// reported rather than clamped, a recompiled function can never contain a
// branch that quietly lands in the wrong place.
class A64Buf {
public:
    A64Buf() = default;

    // --- raw emission ---
    void put(uint32_t word) { words_.push_back(word); }
    void put_many(const uint32_t* w, size_t n) { words_.insert(words_.end(), w, w + n); }
    void nop_pad_to(size_t byte_alignment);

    size_t size_words() const { return words_.size(); }
    size_t size_bytes() const { return words_.size() * 4; }
    // Byte offset of the NEXT instruction to be emitted.
    uint32_t pc() const { return static_cast<uint32_t>(words_.size() * 4); }
    const std::vector<uint32_t>& words() const { return words_; }
    std::vector<uint32_t>& words() { return words_; }
    // Little-endian byte image, ready to memcpy into a __text section.
    std::vector<uint8_t> bytes() const;
    void clear();

    // Overwrite an already-emitted word (used when a caller rewrites an
    // instruction reported by resolve() as out of range).
    void patch(uint32_t insn_index, uint32_t word) { words_[insn_index] = word; }
    uint32_t at(uint32_t insn_index) const { return words_[insn_index]; }

    // --- labels ---
    Label new_label();
    void bind(Label l);                    // bind to the current pc()
    void bind_at(Label l, uint32_t byte_off);
    bool is_bound(Label l) const;
    uint32_t label_offset(Label l) const;  // byte offset; only valid once bound

    // --- label-relative branches ---
    // Each emits a placeholder word (correct opcode and registers, zero
    // displacement) and records a Fixup. Backward branches are recorded too, so
    // that resolve() is the single place displacements are computed.
    void b(Label l);
    void bl(Label l);
    void b_cond(Cond c, Label l);
    void cbz(bool is64, unsigned rt, Label l);
    void cbnz(bool is64, unsigned rt, Label l);
    void tbz(unsigned rt, unsigned bit, Label l);
    void tbnz(unsigned rt, unsigned bit, Label l);
    void adr(unsigned rd, Label l);
    void ldr_literal(unsigned opc, bool is_fp, unsigned rt, Label l);

    const std::vector<Fixup>& fixups() const { return fixups_; }
    bool all_labels_bound() const;

    // Apply every pending fixup. Returns true when all fit. Fixups that do not
    // fit are appended to *out_overflow and REMAIN pending, so a caller can fix
    // them up and call resolve() again. Fixups whose label is still unbound are
    // treated as errors and also reported (with the range check skipped).
    bool resolve(std::vector<Fixup>* out_overflow = nullptr);

    // --- convenience sequences ---
    // Materialize an arbitrary constant into rd with the shortest sequence this
    // encoder knows: a single ORR-bitmask if the value is a logical immediate,
    // otherwise a MOVZ/MOVN seed plus MOVK for each remaining nonzero halfword.
    // Returns the number of instructions emitted (1..4).
    unsigned mov_imm(bool is64, unsigned rd, uint64_t value);

private:
    std::vector<uint32_t> words_;
    std::vector<int64_t>  labels_;  // byte offset, or -1 when unbound
    std::vector<Fixup>    fixups_;
};

// Free-standing version of A64Buf::mov_imm for callers that assemble into their
// own container. Appends to `out` and returns the instruction count.
unsigned mov_imm_seq(std::vector<uint32_t>* out, bool is64, unsigned rd, uint64_t value);

}  // namespace a64
}  // namespace macapk

#endif  // MACAPK_ARM32RC_A64_EMIT_H
