// a64_emit.cpp -- the non-trivial half of the A64 encoder: immediate encoding
// algorithms, range predicates, and the label/fixup buffer. The bit-splicing
// encoders themselves are inline in a64_emit.h.
//
// See a64_emit.h for the source-of-truth policy. Everything below is
// transcribed from the Arm Architecture Reference Manual DDI 0487
// (https://developer.arm.com/documentation/ddi0487/latest/), specifically the
// shared pseudocode functions DecodeBitMasks() and VFPExpandImm(), and is
// round-trip verified against llvm-mc in a64_emit_test.cpp.

#include "a64_emit.h"

#include <cstring>

namespace macapk {
namespace a64 {

namespace {

// --- small bit utilities (C++17, so no <bit>) ------------------------------
bool is_mask64(uint64_t v) { return v != 0 && ((v + 1) & v) == 0; }
bool is_shifted_mask64(uint64_t v) { return v != 0 && is_mask64((v - 1) | v); }
unsigned ctz64(uint64_t v) { return static_cast<unsigned>(__builtin_ctzll(v)); }
unsigned cto64(uint64_t v) { return v == ~0ull ? 64u : ctz64(~v); }
unsigned clo64(uint64_t v) { return v == ~0ull ? 64u : static_cast<unsigned>(__builtin_clzll(~v)); }

}  // namespace

// ---------------------------------------------------------------------------
// Logical (bitmask) immediates
// ---------------------------------------------------------------------------
//
// The N:immr:imms field denotes a value built by taking a run of (S+1) ones,
// rotating it right by R within an element of size esize, and replicating that
// element across the register. ARM ARM shared pseudocode
// aarch64/instrs/integer/bitmasks/DecodeBitMasks:
//
//   len = HighestSetBit(N:NOT(imms));  if len < 1 then UNDEFINED
//   esize = 1 << len;  if M < esize then UNDEFINED
//   levels = ZeroExtend(Ones(len), 6)
//   if immediate && (imms AND levels) == levels then UNDEFINED
//   S = UInt(imms AND levels);  R = UInt(immr AND levels)
//   welem = ZeroExtend(Ones(S+1), esize)
//   wmask = Replicate(ROR(welem, R))
//
// The ENCODE direction has no pseudocode in the manual (it is a search), so the
// implementation below follows the standard inversion: find the smallest
// element size whose replication reproduces the value, then read the rotation
// and run-length straight out of that element. This is the same derivation as
// LLVM's AArch64_AM::processLogicalImmediate, which is why the two agree bit
// for bit; the test verifies EVERY legal 64-bit and 32-bit pattern against
// llvm-mc, so the agreement is measured rather than assumed.

bool encode_logical_imm(uint64_t imm, bool is64, uint32_t* out) {
    const unsigned reg_size = is64 ? 64u : 32u;

    // 0 and all-ones are unrepresentable: (imms AND levels) == levels is
    // UNDEFINED, which is exactly the "all ones in the element" case, and a
    // zero run length cannot be encoded at all.
    if (imm == 0ull || imm == ~0ull) return false;
    if (reg_size != 64 && ((imm >> reg_size) != 0 || imm == (~0ull >> (64 - reg_size))))
        return false;

    // Step 1: the element size is the smallest power-of-two width (>= 2) whose
    // two halves are equal all the way down.
    unsigned size = reg_size;
    do {
        size /= 2;
        uint64_t mask = (1ull << size) - 1;
        if ((imm & mask) != ((imm >> size) & mask)) { size *= 2; break; }
    } while (size > 2);

    // Step 2: within one element, the value must be a rotated run of ones.
    // Two cases: the run does not wrap (a plain shifted mask), or it wraps
    // around the element boundary (the COMPLEMENT is a shifted mask).
    unsigned cto = 0, i = 0;
    uint64_t mask = ~0ull >> (64 - size);
    imm &= mask;

    if (is_shifted_mask64(imm)) {
        i = ctz64(imm);
        cto = cto64(imm >> i);
    } else {
        imm |= ~mask;
        if (!is_shifted_mask64(~imm)) return false;
        unsigned clo = clo64(imm);
        i = 64u - clo;
        cto = clo + cto64(imm) - (64u - size);
    }

    // immr counts the RORs needed to get FROM the canonical 0^m 1^n TO the
    // target; `i` counts them in the opposite direction.
    unsigned immr = (size - i) % size;

    // imms is 6 bits: the high bits encode the element size (a run of ones
    // above the size's top bit), the low bits encode (run length - 1).
    uint64_t nimms = ~static_cast<uint64_t>(size - 1) << 1;
    nimms |= (cto - 1);

    // N is imms bit 6 inverted; it only ever becomes 1 for a 64-bit element.
    unsigned n = (static_cast<unsigned>(nimms >> 6) & 1u) ^ 1u;

    *out = (n << 12) | (immr << 6) | (static_cast<uint32_t>(nimms) & 0x3fu);
    return true;
}

bool decode_logical_imm(uint32_t field, bool is64, uint64_t* out) {
    const unsigned n = (field >> 12) & 1u;
    const unsigned immr = (field >> 6) & 0x3fu;
    const unsigned imms = field & 0x3fu;
    const unsigned datasize = is64 ? 64u : 32u;

    // len = HighestSetBit(N:NOT(imms)) over 7 bits.
    const uint32_t ni = (n << 6) | ((~imms) & 0x3fu);
    int len = -1;
    for (int bit = 6; bit >= 0; --bit) {
        if (ni & (1u << bit)) { len = bit; break; }
    }
    if (len < 1) return false;

    const unsigned esize = 1u << static_cast<unsigned>(len);
    if (datasize < esize) return false;

    const unsigned levels = (1u << static_cast<unsigned>(len)) - 1u;
    if ((imms & levels) == levels) return false;  // UNDEFINED for the immediate form

    const unsigned s = imms & levels;
    const unsigned r = immr & levels;

    const uint64_t emask = (esize == 64) ? ~0ull : ((1ull << esize) - 1ull);
    uint64_t welem = ((1ull << (s + 1u)) - 1ull) & emask;   // s + 1 <= 63 always
    const uint64_t rotated = r ? (((welem >> r) | (welem << (esize - r))) & emask) : welem;

    uint64_t v = 0;
    for (unsigned off = 0; off < datasize; off += esize) v |= rotated << off;
    if (!is64) v &= 0xffffffffull;
    *out = v;
    return true;
}

// ---------------------------------------------------------------------------
// Scalar floating-point 8-bit immediate
// ---------------------------------------------------------------------------
//
// ARM ARM shared pseudocode aarch64/instrs/float/immediate/VFPExpandImm, with
// N = 64 (the double form; the S and H forms denote the same VALUE set, only
// the stored width differs, so one encoder serves all three):
//
//   E = 11;  F = 52
//   sign = imm8<7>
//   exp  = NOT(imm8<6>) : Replicate(imm8<6>, E-3) : imm8<5:4>
//   frac = imm8<3:0> : Zeros(F-4)
//
// So the representable set is +/- (16+m)/16 * 2^e for m in 0..15, e in -3..4:
// 4 mantissa bits and 3 bits of exponent range. Anything else, including 0,
// infinities and NaNs, must go through a literal load.

bool encode_fp_imm8(double v, uint32_t* imm8) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));

    const uint32_t sign = static_cast<uint32_t>(bits >> 63) & 1u;
    const int64_t exp = static_cast<int64_t>((bits >> 52) & 0x7ffu) - 1023;
    uint64_t mant = bits & 0xfffffffffffffull;

    // Only the top 4 mantissa bits are encodable.
    if (mant & 0xffffffffffffull) return false;
    mant >>= 48;

    // exp is derived from the biased field, so zero (field 0, exp -1023),
    // denormals, infinities and NaNs (field 0x7ff, exp 1024) all fall outside
    // this window and are correctly rejected.
    if (exp < -3 || exp > 4) return false;

    const uint32_t e = static_cast<uint32_t>(((exp + 3) & 7) ^ 4);
    *imm8 = (sign << 7) | (e << 4) | static_cast<uint32_t>(mant);
    return true;
}

double decode_fp_imm8(uint32_t imm8) {
    const uint64_t sign = (imm8 >> 7) & 1u;
    const uint32_t e = (imm8 >> 4) & 7u;
    const uint64_t frac = imm8 & 15u;

    const uint32_t b6 = (e >> 2) & 1u;
    uint64_t exp = static_cast<uint64_t>(b6 ^ 1u) << 10;   // NOT(imm8<6>)
    if (b6) exp |= 0xffull << 2;                            // Replicate(imm8<6>, E-3)
    exp |= (e & 3u);                                        // imm8<5:4>

    const uint64_t bits = (sign << 63) | (exp << 52) | (frac << 48);
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

// ---------------------------------------------------------------------------
// Range predicates
// ---------------------------------------------------------------------------
// Signed field of W bits scaled by 4 covers [-(2^(W+1)), 2^(W+1) - 4] bytes.

bool fits_b26(int64_t off)    { return (off & 3) == 0 && off >= -134217728 && off <= 134217724; }
bool fits_cond19(int64_t off) { return (off & 3) == 0 && off >= -1048576 && off <= 1048572; }
bool fits_tb14(int64_t off)   { return (off & 3) == 0 && off >= -32768 && off <= 32764; }
bool fits_adr21(int64_t off)  { return off >= -1048576 && off <= 1048575; }
bool fits_adrp_pages(int64_t pages) { return pages >= -1048576 && pages <= 1048575; }

bool fits_ldst_uimm(unsigned size, int64_t byte_off) {
    const int64_t scale = int64_t(1) << size;
    if (byte_off < 0 || (byte_off % scale) != 0) return false;
    return (byte_off / scale) < 4096;
}
bool fits_ldst_simm9(int64_t byte_off) { return byte_off >= -256 && byte_off <= 255; }
bool fits_ldst_pair(unsigned size, int64_t byte_off) {
    const int64_t scale = int64_t(1) << size;
    if ((byte_off % scale) != 0) return false;
    const int64_t s = byte_off / scale;
    return s >= -64 && s <= 63;
}

// ---------------------------------------------------------------------------
// A64Buf
// ---------------------------------------------------------------------------

std::vector<uint8_t> A64Buf::bytes() const {
    std::vector<uint8_t> out;
    out.reserve(words_.size() * 4);
    for (uint32_t w : words_) {
        out.push_back(static_cast<uint8_t>(w & 0xffu));
        out.push_back(static_cast<uint8_t>((w >> 8) & 0xffu));
        out.push_back(static_cast<uint8_t>((w >> 16) & 0xffu));
        out.push_back(static_cast<uint8_t>((w >> 24) & 0xffu));
    }
    return out;
}

void A64Buf::clear() {
    words_.clear();
    labels_.clear();
    fixups_.clear();
}

void A64Buf::nop_pad_to(size_t byte_alignment) {
    if (byte_alignment < 4) return;
    while ((size_bytes() % byte_alignment) != 0) put(nop());
}

Label A64Buf::new_label() {
    Label l;
    l.id = static_cast<uint32_t>(labels_.size());
    labels_.push_back(-1);
    return l;
}

void A64Buf::bind(Label l) { bind_at(l, pc()); }

void A64Buf::bind_at(Label l, uint32_t byte_off) {
    if (!l.valid() || l.id >= labels_.size()) return;
    labels_[l.id] = static_cast<int64_t>(byte_off);
}

bool A64Buf::is_bound(Label l) const {
    return l.valid() && l.id < labels_.size() && labels_[l.id] >= 0;
}

uint32_t A64Buf::label_offset(Label l) const {
    if (!is_bound(l)) return 0;
    return static_cast<uint32_t>(labels_[l.id]);
}

bool A64Buf::all_labels_bound() const {
    for (int64_t v : labels_) {
        if (v < 0) return false;
    }
    return true;
}

// Each label-relative emitter plants a zero-displacement placeholder so the
// buffer's byte layout is final before any displacement is known, then records
// the fixup. Layout-then-patch is what lets a single pass over an ARM32
// function emit forward branches at all.
void A64Buf::b(Label l) {
    fixups_.push_back({FixKind::B26, static_cast<uint32_t>(words_.size()), l});
    put(a64::b(0));
}
void A64Buf::bl(Label l) {
    fixups_.push_back({FixKind::B26, static_cast<uint32_t>(words_.size()), l});
    put(a64::bl(0));
}
void A64Buf::b_cond(Cond c, Label l) {
    fixups_.push_back({FixKind::Cond19, static_cast<uint32_t>(words_.size()), l});
    put(a64::b_cond(c, 0));
}
void A64Buf::cbz(bool is64, unsigned rt, Label l) {
    fixups_.push_back({FixKind::Cond19, static_cast<uint32_t>(words_.size()), l});
    put(a64::cbz(is64, rt, 0));
}
void A64Buf::cbnz(bool is64, unsigned rt, Label l) {
    fixups_.push_back({FixKind::Cond19, static_cast<uint32_t>(words_.size()), l});
    put(a64::cbnz(is64, rt, 0));
}
void A64Buf::tbz(unsigned rt, unsigned bit, Label l) {
    fixups_.push_back({FixKind::TB14, static_cast<uint32_t>(words_.size()), l});
    put(a64::tbz(rt, bit, 0));
}
void A64Buf::tbnz(unsigned rt, unsigned bit, Label l) {
    fixups_.push_back({FixKind::TB14, static_cast<uint32_t>(words_.size()), l});
    put(a64::tbnz(rt, bit, 0));
}
void A64Buf::adr(unsigned rd, Label l) {
    fixups_.push_back({FixKind::Adr21, static_cast<uint32_t>(words_.size()), l});
    put(a64::adr(rd, 0));
}
void A64Buf::ldr_literal(unsigned opc, bool is_fp, unsigned rt, Label l) {
    fixups_.push_back({FixKind::Lit19, static_cast<uint32_t>(words_.size()), l});
    put(a64::ldr_literal(opc, is_fp, rt, 0));
}

bool A64Buf::resolve(std::vector<Fixup>* out_overflow) {
    std::vector<Fixup> still_pending;
    bool ok = true;

    for (const Fixup& f : fixups_) {
        if (!is_bound(f.label)) {
            // An unbound label is a caller bug, but reporting it is strictly
            // better than silently emitting a branch to itself.
            ok = false;
            still_pending.push_back(f);
            if (out_overflow) out_overflow->push_back(f);
            continue;
        }

        const int64_t target = labels_[f.label.id];
        const int64_t site = static_cast<int64_t>(f.insn_index) * 4;
        const int64_t off = target - site;

        uint32_t w = words_[f.insn_index];
        bool fit = false;

        switch (f.kind) {
            case FixKind::B26:
                fit = fits_b26(off);
                if (fit) {
                    w = (w & 0xfc000000u) |
                        (static_cast<uint32_t>(off >> 2) & 0x03ffffffu);
                }
                break;
            case FixKind::Cond19:
            case FixKind::Lit19:
                fit = fits_cond19(off);
                if (fit) {
                    w = (w & ~(0x7ffffu << 5)) |
                        ((static_cast<uint32_t>(off >> 2) & 0x7ffffu) << 5);
                }
                break;
            case FixKind::TB14:
                fit = fits_tb14(off);
                if (fit) {
                    w = (w & ~(0x3fffu << 5)) |
                        ((static_cast<uint32_t>(off >> 2) & 0x3fffu) << 5);
                }
                break;
            case FixKind::Adr21:
                fit = fits_adr21(off);
                if (fit) {
                    w = (w & ~((3u << 29) | (0x7ffffu << 5))) |
                        ((static_cast<uint32_t>(off) & 3u) << 29) |
                        ((static_cast<uint32_t>(off >> 2) & 0x7ffffu) << 5);
                }
                break;
        }

        if (fit) {
            words_[f.insn_index] = w;
        } else {
            ok = false;
            still_pending.push_back(f);
            if (out_overflow) out_overflow->push_back(f);
        }
    }

    fixups_.swap(still_pending);
    return ok;
}

// ---------------------------------------------------------------------------
// Constant materialization
// ---------------------------------------------------------------------------
//
// Order of preference:
//   1. ORR Rd, ZR, #bitmask        1 instruction, covers all the repeating
//                                  bit patterns ARM32 code loads constantly
//                                  (0xff, 0xffff, 0x80000000, alternating
//                                  masks, ...).
//   2. MOVZ/MOVN seed + MOVK       up to 4 instructions; MOVN is chosen when
//                                  more halfwords are 0xffff than are 0, which
//                                  is what makes small negative constants one
//                                  instruction instead of four.
// A future stage may add a third option (an ADRP+ADD or a literal-pool load)
// when even the 4-instruction form is too expensive; nothing here forecloses it.

unsigned mov_imm_seq(std::vector<uint32_t>* out, bool is64, unsigned rd, uint64_t value) {
    const unsigned nhalf = is64 ? 4u : 2u;
    if (!is64) value &= 0xffffffffull;

    uint32_t field = 0;
    if (encode_logical_imm(value, is64, &field)) {
        out->push_back(mov_bitmask_imm(is64, rd, field));
        return 1;
    }

    unsigned zero_halves = 0, ones_halves = 0;
    for (unsigned i = 0; i < nhalf; ++i) {
        const uint32_t h = static_cast<uint32_t>((value >> (16u * i)) & 0xffffu);
        if (h == 0) ++zero_halves;
        if (h == 0xffff) ++ones_halves;
    }

    unsigned count = 0;

    if (ones_halves > zero_halves) {
        // MOVN Rd, #imm16, LSL#s computes NOT(imm16 << s), so every OTHER
        // halfword lands as 0xffff and needs no MOVK.
        const uint64_t inv = is64 ? ~value : ((~value) & 0xffffffffull);
        int seed = -1;
        for (unsigned i = 0; i < nhalf; ++i) {
            if (((inv >> (16u * i)) & 0xffffu) != 0) { seed = static_cast<int>(i); break; }
        }
        if (seed < 0) {  // value is all ones
            out->push_back(movn(is64, rd, 0, 0));
            return 1;
        }
        out->push_back(movn(is64, rd,
                            static_cast<uint32_t>((inv >> (16u * static_cast<unsigned>(seed))) & 0xffffu),
                            static_cast<unsigned>(seed)));
        count = 1;
        for (unsigned i = 0; i < nhalf; ++i) {
            if (static_cast<int>(i) == seed) continue;
            const uint32_t h = static_cast<uint32_t>((value >> (16u * i)) & 0xffffu);
            if (h == 0xffff) continue;
            out->push_back(movk(is64, rd, h, i));
            ++count;
        }
    } else {
        int seed = -1;
        for (unsigned i = 0; i < nhalf; ++i) {
            if (((value >> (16u * i)) & 0xffffu) != 0) { seed = static_cast<int>(i); break; }
        }
        if (seed < 0) {  // value is zero
            out->push_back(movz(is64, rd, 0, 0));
            return 1;
        }
        out->push_back(movz(is64, rd,
                            static_cast<uint32_t>((value >> (16u * static_cast<unsigned>(seed))) & 0xffffu),
                            static_cast<unsigned>(seed)));
        count = 1;
        for (unsigned i = 0; i < nhalf; ++i) {
            if (static_cast<int>(i) == seed) continue;
            const uint32_t h = static_cast<uint32_t>((value >> (16u * i)) & 0xffffu);
            if (h == 0) continue;
            out->push_back(movk(is64, rd, h, i));
            ++count;
        }
    }
    return count;
}

unsigned A64Buf::mov_imm(bool is64, unsigned rd, uint64_t value) {
    return mov_imm_seq(&words_, is64, rd, value);
}

}  // namespace a64
}  // namespace macapk
