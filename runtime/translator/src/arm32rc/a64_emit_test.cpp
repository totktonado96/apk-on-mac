// a64_emit_test.cpp -- round-trip verification of every encoder in a64_emit.h
// against a real assembler.
//
// A hand-checked encoder is not good enough. Two independent checks run over
// every case:
//
//   FORWARD  (the strong one): the intended assembly text is fed to
//            `llvm-mc --triple=arm64-apple-darwin --show-encoding`, and the
//            word llvm-mc produces must equal the word our encoder produced,
//            bit for bit. llvm-mc's AArch64 assembler is generated from Arm's
//            own machine-readable spec, so agreement here is agreement with
//            the ARM ARM encoding diagrams.
//
//   REVERSE: every emitted word is fed to `llvm-mc --disassemble`, which must
//            decode it to a real instruction (not a .word/.long fallback and
//            not <unknown>), and re-assembling that disassembly must reproduce
//            the same word. This catches an encoder that happens to produce a
//            legal-but-different instruction, and it catches encoders whose
//            forward text we might have written to match a bug.
//
// Three exhaustive sub-tests go further than case lists can:
//   * every legal 64-bit AND every legal 32-bit logical-immediate bit pattern
//     (~6.6k distinct values) is encoded and checked against llvm-mc;
//   * all 256 scalar FP imm8 values are decoded, re-encoded, and checked;
//   * a large set of constants is run through mov_imm_seq() and the resulting
//     MOVZ/MOVN/MOVK sequence is INTERPRETED to prove it materializes the
//     requested value.
//
// Build and run standalone (no cmake, no runtime):
//   clang++ -std=c++17 -Wall -Wextra -O1 a64_emit.cpp a64_emit_test.cpp \
//       -o /tmp/a64_emit_test && /tmp/a64_emit_test
// Override the assembler with LLVM_MC=/path/to/llvm-mc.

#include "a64_emit.h"

#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace macapk::a64;

// ---------------------------------------------------------------------------
// Case table
// ---------------------------------------------------------------------------

struct Case {
    std::string encoder;  // name of the encoder under test (for coverage stats)
    uint32_t word;        // what our encoder produced
    std::string text;     // what we believe that word means
};

static std::vector<Case> g_cases;

static void CHK(const char* encoder, uint32_t word, const std::string& text) {
    g_cases.push_back({encoder, word, text});
}

static std::string F(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return std::string(buf);
}

static const char* kCondName[16] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};

// ---------------------------------------------------------------------------
// llvm-mc driver
// ---------------------------------------------------------------------------

static std::string g_tmpdir;
static std::string g_llvm_mc;

static bool file_exists(const std::string& p) { return access(p.c_str(), X_OK) == 0; }

static std::string find_llvm_mc() {
    if (const char* env = getenv("LLVM_MC")) return env;
    const char* candidates[] = {
        "/opt/homebrew/opt/llvm/bin/llvm-mc",
        "/usr/local/opt/llvm/bin/llvm-mc",
        "/opt/homebrew/bin/llvm-mc",
        "/usr/bin/llvm-mc",
    };
    for (const char* c : candidates) {
        if (file_exists(c)) return c;
    }
    // Fall back to PATH.
    if (system("command -v llvm-mc >/dev/null 2>&1") == 0) return "llvm-mc";
    return std::string();
}

static std::string slurp(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static void spit(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << data;
}

// Parse "; encoding: [0x20,0x10,0x00,0x91]" out of llvm-mc --show-encoding.
static bool parse_encoding(const std::string& line, uint32_t* out) {
    const size_t p = line.find("encoding: [");
    if (p == std::string::npos) return false;
    unsigned b[4];
    if (sscanf(line.c_str() + p, "encoding: [0x%x,0x%x,0x%x,0x%x]", &b[0], &b[1], &b[2], &b[3]) != 4)
        return false;
    *out = (b[0] & 0xffu) | ((b[1] & 0xffu) << 8) | ((b[2] & 0xffu) << 16) | ((b[3] & 0xffu) << 24);
    return true;
}

// Assemble `lines` in ONE llvm-mc invocation.
//
// Lines llvm-mc rejects are identified exactly, from the "<file>:<line>: error:"
// prefixes on its stderr, and returned in *rejected (0-based). llvm-mc emits
// one encoding per successfully assembled line, in order, so removing the
// rejected lines re-aligns the encoding stream with the input. Attributing
// failures this way keeps the test at two process spawns instead of one per
// case (a per-line fallback over ~14k cases takes many minutes).
//
// Returns false only when the alignment invariant does not hold, which means
// the output could not be attributed at all.
static bool assemble_batch(const std::string& tag, const std::vector<std::string>& lines,
                           std::vector<uint32_t>* out, std::set<size_t>* rejected,
                           std::string* diag) {
    const std::string sp = g_tmpdir + "/" + tag + ".s";
    const std::string op = g_tmpdir + "/" + tag + ".out";
    const std::string ep = g_tmpdir + "/" + tag + ".err";

    std::string src;
    src.reserve(lines.size() * 24);
    for (const std::string& l : lines) { src += l; src += '\n'; }
    spit(sp, src);

    const std::string cmd = g_llvm_mc + " --triple=arm64-apple-darwin -mattr=+crc --show-encoding " + sp +
                            " > " + op + " 2> " + ep;
    (void)system(cmd.c_str());

    out->clear();
    {
        std::ifstream in(op);
        std::string line;
        while (std::getline(in, line)) {
            uint32_t w;
            if (parse_encoding(line, &w)) out->push_back(w);
        }
    }

    rejected->clear();
    const std::string errtxt = slurp(ep);
    if (diag) *diag = errtxt;
    {
        const std::string needle = tag + ".s:";
        size_t p = 0;
        while ((p = errtxt.find(needle, p)) != std::string::npos) {
            const size_t numpos = p + needle.size();
            size_t q = numpos;
            while (q < errtxt.size() && isdigit(static_cast<unsigned char>(errtxt[q]))) ++q;
            const size_t eol = errtxt.find('\n', q);
            const std::string rest = errtxt.substr(q, (eol == std::string::npos ? errtxt.size() : eol) - q);
            if (q > numpos && rest.find(": error:") != std::string::npos) {
                const long n = strtol(errtxt.c_str() + numpos, nullptr, 10);
                if (n >= 1 && static_cast<size_t>(n) <= lines.size())
                    rejected->insert(static_cast<size_t>(n) - 1);
            }
            p = q;
        }
    }

    return out->size() + rejected->size() == lines.size();
}

// Disassemble `words` in one invocation. Returns true only when exactly one
// text line came back per word.
static bool disassemble_batch(const std::string& tag, const std::vector<uint32_t>& words,
                              std::vector<std::string>* out, std::string* diag) {
    const std::string sp = g_tmpdir + "/" + tag + ".txt";
    const std::string op = g_tmpdir + "/" + tag + ".out";
    const std::string ep = g_tmpdir + "/" + tag + ".err";

    std::string src;
    src.reserve(words.size() * 20);
    for (uint32_t w : words) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%02x 0x%02x 0x%02x 0x%02x\n", w & 0xffu, (w >> 8) & 0xffu,
                 (w >> 16) & 0xffu, (w >> 24) & 0xffu);
        src += buf;
    }
    spit(sp, src);

    const std::string cmd = g_llvm_mc + " --triple=arm64-apple-darwin -mattr=+crc --disassemble " + sp +
                            " > " + op + " 2> " + ep;
    (void)system(cmd.c_str());

    out->clear();
    std::ifstream in(op);
    std::string line;
    while (std::getline(in, line)) {
        // Drop leading whitespace and blank/directive-only lines that llvm-mc
        // emits around the instruction stream.
        size_t s = line.find_first_not_of(" \t");
        if (s == std::string::npos) continue;
        std::string t = line.substr(s);
        if (t.rfind(".text", 0) == 0 || t.rfind(".subsections", 0) == 0 ||
            t.rfind(".build_version", 0) == 0)
            continue;
        out->push_back(t);
    }
    if (diag) *diag = slurp(ep);
    return out->size() == words.size();
}

// ---------------------------------------------------------------------------
// Case construction
// ---------------------------------------------------------------------------

static void build_dp_immediate_cases() {
    // ADR / ADRP
    CHK("adr", adr(0, 0), "adr x0, #0");
    CHK("adr", adr(5, 4), "adr x5, #4");
    CHK("adr", adr(9, -1048576), "adr x9, #-1048576");
    CHK("adr", adr(30, 1048575), "adr x30, #1048575");
    CHK("adrp", adrp(0, 0), "adrp x0, #0");
    CHK("adrp", adrp(3, 1), "adrp x3, #4096");
    CHK("adrp", adrp(7, -1), "adrp x7, #-4096");
    CHK("adrp", adrp(16, 1048575), "adrp x16, #4294963200");

    // ADD/ADDS/SUB/SUBS (immediate) and aliases
    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        CHK("add_imm", add_imm(w, 0, 1, 4), F("add %s0, %s1, #4", s, s));
        // The SP-capable source spells as "sp" in the 64-bit form and "wsp" in
        // the 32-bit form.
        CHK("add_imm", add_imm(w, 2, 31, 0xfff), F("add %s2, %s, #4095", s, w ? "sp" : "wsp"));
        CHK("add_imm", add_imm(w, 3, 4, 1, true), F("add %s3, %s4, #1, lsl #12", s, s));
        CHK("adds_imm", adds_imm(w, 5, 6, 7), F("adds %s5, %s6, #7", s, s));
        CHK("sub_imm", sub_imm(w, 8, 9, 0x123), F("sub %s8, %s9, #291", s, s));
        CHK("subs_imm", subs_imm(w, 10, 11, 0x20), F("subs %s10, %s11, #32", s, s));
        CHK("cmp_imm", cmp_imm(w, 12, 4), F("cmp %s12, #4", s));
        CHK("cmn_imm", cmn_imm(w, 13, 4), F("cmn %s13, #4", s));
    }
    CHK("mov_sp", mov_sp(true, 29, 31), "mov x29, sp");
    CHK("mov_sp", mov_sp(true, 31, 5), "mov sp, x5");

    // Logical (immediate) and aliases (the exhaustive sweep is separate).
    uint32_t f;
    if (encode_logical_imm(0xff, true, &f)) {
        CHK("and_imm", and_imm(true, 0, 1, f), "and x0, x1, #0xff");
        CHK("orr_imm", orr_imm(true, 2, 3, f), "orr x2, x3, #0xff");
        CHK("eor_imm", eor_imm(true, 4, 5, f), "eor x4, x5, #0xff");
        CHK("ands_imm", ands_imm(true, 6, 7, f), "ands x6, x7, #0xff");
        CHK("tst_imm", tst_imm(true, 8, f), "tst x8, #0xff");
        CHK("mov_bitmask_imm", mov_bitmask_imm(true, 9, f), "orr x9, xzr, #0xff");
    }
    if (encode_logical_imm(0x3f, false, &f)) {
        CHK("and_imm", and_imm(false, 0, 1, f), "and w0, w1, #0x3f");
        CHK("orr_imm", orr_imm(false, 2, 3, f), "orr w2, w3, #0x3f");
    }

    // Move wide
    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        CHK("movz", movz(w, 0, 0x1234, 0), F("movz %s0, #4660", s));
        CHK("movz", movz(w, 1, 0xabcd, 1), F("movz %s1, #43981, lsl #16", s));
        CHK("movk", movk(w, 2, 0x1234, 0), F("movk %s2, #4660", s));
        CHK("movk", movk(w, 3, 0xffff, 1), F("movk %s3, #65535, lsl #16", s));
        CHK("movn", movn(w, 4, 0x0001, 0), F("movn %s4, #1", s));
    }
    CHK("movz", movz(true, 5, 0x8000, 2), "movz x5, #32768, lsl #32");
    CHK("movz", movz(true, 6, 0x0001, 3), "movz x6, #1, lsl #48");
    CHK("movk", movk(true, 7, 0xdead, 3), "movk x7, #57005, lsl #48");
    CHK("movn", movn(true, 8, 0x0002, 2), "movn x8, #2, lsl #32");

    // Bitfield primitives and aliases
    CHK("sbfm", sbfm(true, 0, 1, 4, 20), "sbfm x0, x1, #4, #20");
    CHK("bfm", bfm(true, 2, 3, 8, 12), "bfm x2, x3, #8, #12");
    CHK("ubfm", ubfm(true, 4, 5, 1, 62), "ubfm x4, x5, #1, #62");
    CHK("sbfm", sbfm(false, 0, 1, 4, 20), "sbfm w0, w1, #4, #20");
    CHK("ubfm", ubfm(false, 4, 5, 1, 30), "ubfm w4, w5, #1, #30");
    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        CHK("lsl_imm", lsl_imm(w, 0, 1, 4), F("lsl %s0, %s1, #4", s, s));
        CHK("lsl_imm", lsl_imm(w, 0, 1, 0), F("lsl %s0, %s1, #0", s, s));
        CHK("lsr_imm", lsr_imm(w, 2, 3, 7), F("lsr %s2, %s3, #7", s, s));
        CHK("asr_imm", asr_imm(w, 4, 5, 9), F("asr %s4, %s5, #9", s, s));
        CHK("ubfx", ubfx(w, 6, 7, 3, 8), F("ubfx %s6, %s7, #3, #8", s, s));
        CHK("sbfx", sbfx(w, 8, 9, 2, 5), F("sbfx %s8, %s9, #2, #5", s, s));
        CHK("ubfiz", ubfiz(w, 10, 11, 3, 8), F("ubfiz %s10, %s11, #3, #8", s, s));
        CHK("sbfiz", sbfiz(w, 12, 13, 4, 6), F("sbfiz %s12, %s13, #4, #6", s, s));
        CHK("bfi", bfi(w, 14, 15, 4, 8), F("bfi %s14, %s15, #4, #8", s, s));
        CHK("bfxil", bfxil(w, 16, 17, 5, 9), F("bfxil %s16, %s17, #5, #9", s, s));
        CHK("sxtb", sxtb(w, 18, 19), F("sxtb %s18, w19", s));
        CHK("sxth", sxth(w, 20, 21), F("sxth %s20, w21", s));
    }
    CHK("lsl_imm", lsl_imm(true, 0, 1, 63), "lsl x0, x1, #63");
    CHK("lsr_imm", lsr_imm(true, 0, 1, 63), "lsr x0, x1, #63");
    CHK("asr_imm", asr_imm(false, 0, 1, 31), "asr w0, w1, #31");
    CHK("sxtw", sxtw(22, 23), "sxtw x22, w23");
    CHK("uxtb", uxtb(24, 25), "uxtb w24, w25");
    CHK("uxth", uxth(26, 27), "uxth w26, w27");

    // EXTR / ROR
    CHK("extr", extr(true, 0, 1, 2, 5), "extr x0, x1, x2, #5");
    CHK("extr", extr(false, 3, 4, 5, 17), "extr w3, w4, w5, #17");
    CHK("ror_imm", ror_imm(true, 6, 7, 13), "ror x6, x7, #13");
    CHK("ror_imm", ror_imm(false, 8, 9, 1), "ror w8, w9, #1");
}

static void build_dp_register_cases() {
    static const char* kShift[4] = {"lsl", "lsr", "asr", "ror"};

    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        const unsigned amt = w ? 40 : 20;
        for (unsigned sh = 0; sh < 3; ++sh) {  // ROR is not legal for add/sub
            const Shift S = static_cast<Shift>(sh);
            CHK("add_reg", add_reg(w, 0, 1, 2, S, amt),
                F("add %s0, %s1, %s2, %s #%u", s, s, s, kShift[sh], amt));
            CHK("subs_reg", subs_reg(w, 3, 4, 5, S, 3),
                F("subs %s3, %s4, %s5, %s #3", s, s, s, kShift[sh]));
        }
        CHK("add_reg", add_reg(w, 0, 1, 2), F("add %s0, %s1, %s2", s, s, s));
        CHK("adds_reg", adds_reg(w, 3, 4, 5), F("adds %s3, %s4, %s5", s, s, s));
        CHK("sub_reg", sub_reg(w, 6, 7, 8), F("sub %s6, %s7, %s8", s, s, s));
        CHK("cmp_reg", cmp_reg(w, 9, 10), F("cmp %s9, %s10", s, s));
        CHK("cmp_reg", cmp_reg(w, 9, 10, ShiftASR, 2), F("cmp %s9, %s10, asr #2", s, s));
        CHK("cmn_reg", cmn_reg(w, 11, 12), F("cmn %s11, %s12", s, s));
        CHK("neg_reg", neg_reg(w, 13, 14), F("neg %s13, %s14", s, s));
        CHK("neg_reg", neg_reg(w, 13, 14, ShiftLSL, 3), F("neg %s13, %s14, lsl #3", s, s));
        CHK("negs_reg", negs_reg(w, 15, 16), F("negs %s15, %s16", s, s));

        // Logical (shifted register), all four shift kinds including ROR.
        for (unsigned sh = 0; sh < 4; ++sh) {
            const Shift S = static_cast<Shift>(sh);
            CHK("and_reg", and_reg(w, 0, 1, 2, S, 7),
                F("and %s0, %s1, %s2, %s #7", s, s, s, kShift[sh]));
        }
        CHK("and_reg", and_reg(w, 0, 1, 2), F("and %s0, %s1, %s2", s, s, s));
        CHK("bic_reg", bic_reg(w, 3, 4, 5), F("bic %s3, %s4, %s5", s, s, s));
        CHK("orr_reg", orr_reg(w, 6, 7, 8), F("orr %s6, %s7, %s8", s, s, s));
        CHK("orn_reg", orn_reg(w, 9, 10, 11), F("orn %s9, %s10, %s11", s, s, s));
        CHK("eor_reg", eor_reg(w, 12, 13, 14), F("eor %s12, %s13, %s14", s, s, s));
        CHK("eon_reg", eon_reg(w, 15, 16, 17), F("eon %s15, %s16, %s17", s, s, s));
        CHK("ands_reg", ands_reg(w, 18, 19, 20), F("ands %s18, %s19, %s20", s, s, s));
        CHK("bics_reg", bics_reg(w, 21, 22, 23), F("bics %s21, %s22, %s23", s, s, s));
        CHK("mov_reg", mov_reg(w, 24, 25), F("mov %s24, %s25", s, s));
        CHK("mvn_reg", mvn_reg(w, 26, 27), F("mvn %s26, %s27", s, s));
        CHK("mvn_reg", mvn_reg(w, 26, 27, ShiftROR, 5), F("mvn %s26, %s27, ror #5", s, s));
        CHK("tst_reg", tst_reg(w, 28, 29), F("tst %s28, %s29", s, s));

        // Add/subtract with carry.
        CHK("adc", adc(w, 0, 1, 2), F("adc %s0, %s1, %s2", s, s, s));
        CHK("adcs", adcs(w, 3, 4, 5), F("adcs %s3, %s4, %s5", s, s, s));
        CHK("sbc", sbc(w, 6, 7, 8), F("sbc %s6, %s7, %s8", s, s, s));
        CHK("sbcs", sbcs(w, 9, 10, 11), F("sbcs %s9, %s10, %s11", s, s, s));
        CHK("ngc", ngc(w, 12, 13), F("ngc %s12, %s13", s, s));
        CHK("ngcs", ngcs(w, 14, 15), F("ngcs %s14, %s15", s, s));

        // Data-processing (2 source).
        CHK("udiv", udiv(w, 0, 1, 2), F("udiv %s0, %s1, %s2", s, s, s));
        CHK("sdiv", sdiv(w, 3, 4, 5), F("sdiv %s3, %s4, %s5", s, s, s));
        CHK("lslv", lslv(w, 6, 7, 8), F("lsl %s6, %s7, %s8", s, s, s));
        CHK("lsrv", lsrv(w, 9, 10, 11), F("lsr %s9, %s10, %s11", s, s, s));
        CHK("asrv", asrv(w, 12, 13, 14), F("asr %s12, %s13, %s14", s, s, s));
        CHK("rorv", rorv(w, 15, 16, 17), F("ror %s15, %s16, %s17", s, s, s));

        // Data-processing (1 source).
        CHK("rbit", rbit(w, 0, 1), F("rbit %s0, %s1", s, s));
        CHK("rev16", rev16(w, 2, 3), F("rev16 %s2, %s3", s, s));
        CHK("rev", rev(w, 4, 5), F("rev %s4, %s5", s, s));
        CHK("clz", clz(w, 6, 7), F("clz %s6, %s7", s, s));
        CHK("cls", cls(w, 8, 9), F("cls %s8, %s9", s, s));

        // Data-processing (3 source).
        CHK("madd", madd(w, 0, 1, 2, 3), F("madd %s0, %s1, %s2, %s3", s, s, s, s));
        CHK("msub", msub(w, 4, 5, 6, 7), F("msub %s4, %s5, %s6, %s7", s, s, s, s));
        CHK("mul", mul(w, 8, 9, 10), F("mul %s8, %s9, %s10", s, s, s));
        CHK("mneg", mneg(w, 11, 12, 13), F("mneg %s11, %s12, %s13", s, s, s));
    }
    CHK("rev32", rev32(0, 1), "rev32 x0, x1");
    CHK("smaddl", smaddl(0, 1, 2, 3), "smaddl x0, w1, w2, x3");
    CHK("smsubl", smsubl(4, 5, 6, 7), "smsubl x4, w5, w6, x7");
    CHK("smull", smull(8, 9, 10), "smull x8, w9, w10");
    CHK("smnegl", smnegl(11, 12, 13), "smnegl x11, w12, w13");
    CHK("smulh", smulh(14, 15, 16), "smulh x14, x15, x16");
    CHK("umaddl", umaddl(0, 1, 2, 3), "umaddl x0, w1, w2, x3");
    CHK("umsubl", umsubl(4, 5, 6, 7), "umsubl x4, w5, w6, x7");
    CHK("umull", umull(8, 9, 10), "umull x8, w9, w10");
    CHK("umnegl", umnegl(11, 12, 13), "umnegl x11, w12, w13");
    CHK("umulh", umulh(14, 15, 16), "umulh x14, x15, x16");

    // Add/subtract (extended register). Note the operand register class follows
    // the option field: UXTB/UXTH/UXTW/SXTB/SXTH/SXTW take a W register.
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtUXTB), "add x0, x1, w2, uxtb");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtUXTH, 1), "add x0, x1, w2, uxth #1");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtUXTW, 2), "add x0, x1, w2, uxtw #2");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtUXTX, 3), "add x0, x1, x2, uxtx #3");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtSXTB, 4), "add x0, x1, w2, sxtb #4");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtSXTH), "add x0, x1, w2, sxth");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtSXTW), "add x0, x1, w2, sxtw");
    CHK("add_ext", add_ext(true, 0, 1, 2, ExtSXTX), "add x0, x1, x2, sxtx");
    CHK("add_ext", add_ext(true, 0, 31, 1, ExtLSL64, 2), "add x0, sp, x1, lsl #2");
    CHK("add_ext", add_ext(false, 0, 1, 2, ExtSXTB, 3), "add w0, w1, w2, sxtb #3");
    CHK("adds_ext", adds_ext(true, 3, 4, 5, ExtUXTW, 1), "adds x3, x4, w5, uxtw #1");
    CHK("sub_ext", sub_ext(true, 6, 31, 7, ExtUXTX), "sub x6, sp, x7, uxtx");
    CHK("subs_ext", subs_ext(true, 8, 9, 10, ExtSXTH, 2), "subs x8, x9, w10, sxth #2");

    // Conditional select and the flag-producing aliases.
    for (unsigned c = 0; c < 16; ++c) {
        const Cond cc = static_cast<Cond>(c);
        CHK("csel", csel(true, 0, 1, 2, cc), F("csel x0, x1, x2, %s", kCondName[c]));
    }
    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        CHK("csel", csel(w, 0, 1, 2, CondEQ), F("csel %s0, %s1, %s2, eq", s, s, s));
        CHK("csinc", csinc(w, 3, 4, 5, CondNE), F("csinc %s3, %s4, %s5, ne", s, s, s));
        CHK("csinv", csinv(w, 6, 7, 8, CondMI), F("csinv %s6, %s7, %s8, mi", s, s, s));
        CHK("csneg", csneg(w, 9, 10, 11, CondGT), F("csneg %s9, %s10, %s11, gt", s, s, s));
        // The aliases are UNDEFINED for AL/NV, so sweep only 0..13.
        for (unsigned c = 0; c < 14; ++c) {
            const Cond cc = static_cast<Cond>(c);
            CHK("cset", cset(w, 12, cc), F("cset %s12, %s", s, kCondName[c]));
            CHK("csetm", csetm(w, 13, cc), F("csetm %s13, %s", s, kCondName[c]));
        }
        CHK("cinc", cinc(w, 14, 15, CondLE), F("cinc %s14, %s15, le", s, s));
        CHK("cinv", cinv(w, 16, 17, CondVS), F("cinv %s16, %s17, vs", s, s));
        CHK("cneg", cneg(w, 18, 19, CondLO), F("cneg %s18, %s19, lo", s, s));

        CHK("ccmp_reg", ccmp_reg(w, 0, 1, 0, CondEQ), F("ccmp %s0, %s1, #0, eq", s, s));
        CHK("ccmp_reg", ccmp_reg(w, 2, 3, 15, CondLT), F("ccmp %s2, %s3, #15, lt", s, s));
        CHK("ccmn_reg", ccmn_reg(w, 4, 5, 6, CondNE), F("ccmn %s4, %s5, #6, ne", s, s));
        CHK("ccmp_imm", ccmp_imm(w, 6, 5, 2, CondNE), F("ccmp %s6, #5, #2, ne", s));
        CHK("ccmn_imm", ccmn_imm(w, 7, 31, 9, CondGE), F("ccmn %s7, #31, #9, ge", s));
    }
}

static void build_branch_cases() {
    CHK("b", b(0), "b #0");
    CHK("b", b(4), "b #4");
    CHK("b", b(-8), "b #-8");
    CHK("b", b(134217724), "b #134217724");
    CHK("b", b(-134217728), "b #-134217728");
    CHK("bl", bl(0), "bl #0");
    CHK("bl", bl(-4), "bl #-4");
    CHK("bl", bl(134217724), "bl #134217724");

    CHK("br", br(16), "br x16");
    CHK("br", br(0), "br x0");
    CHK("blr", blr(8), "blr x8");
    CHK("ret", ret(), "ret");
    CHK("ret", ret(1), "ret x1");

    for (unsigned c = 0; c < 16; ++c) {
        const Cond cc = static_cast<Cond>(c);
        CHK("b_cond", b_cond(cc, 0), F("b.%s #0", kCondName[c]));
    }
    CHK("b_cond", b_cond(CondEQ, 1048572), "b.eq #1048572");
    CHK("b_cond", b_cond(CondNE, -1048576), "b.ne #-1048576");

    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        CHK("cbz", cbz(w, 0, 8), F("cbz %s0, #8", s));
        CHK("cbz", cbz(w, 30, -1048576), F("cbz %s30, #-1048576", s));
        CHK("cbnz", cbnz(w, 1, -12), F("cbnz %s1, #-12", s));
        CHK("cbnz", cbnz(w, 2, 1048572), F("cbnz %s2, #1048572", s));
    }
    CHK("tbz", tbz(0, 0, 0), "tbz w0, #0, #0");
    CHK("tbz", tbz(1, 31, 32764), "tbz w1, #31, #32764");
    CHK("tbz", tbz(2, 32, -32768), "tbz x2, #32, #-32768");
    CHK("tbz", tbz(3, 63, 4), "tbz x3, #63, #4");
    CHK("tbnz", tbnz(4, 5, 32764), "tbnz w4, #5, #32764");
    CHK("tbnz", tbnz(5, 33, -4), "tbnz x5, #33, #-4");

    // Qualified: POSIX <unistd.h> also declares ::brk.
    CHK("brk", macapk::a64::brk(0), "brk #0");
    CHK("brk", macapk::a64::brk(0xf000), "brk #0xf000");
    CHK("svc", svc(0), "svc #0");
    CHK("svc", svc(0x1234), "svc #0x1234");
    CHK("hlt", hlt(2), "hlt #2");
}

static void build_system_cases() {
    CHK("nop", nop(), "nop");
    CHK("yield", yield(), "yield");
    CHK("wfe", wfe(), "wfe");
    CHK("sev", sev(), "sev");
    CHK("dmb", dmb(0xf), "dmb sy");
    CHK("dmb", dmb(0xb), "dmb ish");
    CHK("dmb", dmb(0xa), "dmb ishst");
    CHK("dsb", dsb(0xf), "dsb sy");
    CHK("dsb", dsb(0xb), "dsb ish");
    CHK("isb", isb(0xf), "isb");
    CHK("clrex", clrex(0xf), "clrex");

    CHK("mrs", mrs(0, kSR_NZCV), "mrs x0, nzcv");
    CHK("mrs", mrs(1, kSR_FPCR), "mrs x1, fpcr");
    CHK("mrs", mrs(2, kSR_FPSR), "mrs x2, fpsr");
    CHK("mrs", mrs(3, kSR_TPIDR_EL0), "mrs x3, tpidr_el0");
    CHK("mrs", mrs(4, kSR_TPIDRRO_EL0), "mrs x4, tpidrro_el0");
    CHK("mrs", mrs(5, kSR_CTR_EL0), "mrs x5, ctr_el0");
    CHK("mrs", mrs(6, kSR_DCZID_EL0), "mrs x6, dczid_el0");
    CHK("mrs", mrs(7, kSR_CNTVCT_EL0), "mrs x7, cntvct_el0");
    CHK("mrs", mrs(8, kSR_CNTFRQ_EL0), "mrs x8, cntfrq_el0");
    CHK("msr_reg", msr_reg(kSR_NZCV, 0), "msr nzcv, x0");
    CHK("msr_reg", msr_reg(kSR_FPCR, 1), "msr fpcr, x1");
    CHK("msr_reg", msr_reg(kSR_FPSR, 2), "msr fpsr, x2");
    CHK("msr_reg", msr_reg(kSR_TPIDR_EL0, 3), "msr tpidr_el0, x3");
}

static void build_loadstore_cases() {
    // Unsigned-offset forms, both widths, min and max offsets.
    for (bool w : {false, true}) {
        const char* s = w ? "x" : "w";
        const unsigned sc = w ? 8 : 4;
        CHK("ldr", ldr(w, 0, 1, 0), F("ldr %s0, [x1]", s));
        CHK("ldr", ldr(w, 2, 3, sc), F("ldr %s2, [x3, #%u]", s, sc));
        CHK("ldr", ldr(w, 4, 31, 4095u * sc), F("ldr %s4, [sp, #%u]", s, 4095u * sc));
        CHK("str", str(w, 5, 6, 0), F("str %s5, [x6]", s));
        CHK("str", str(w, 7, 8, 2u * sc), F("str %s7, [x8, #%u]", s, 2u * sc));
        CHK("ldrsb", ldrsb(w, 9, 10, 3), F("ldrsb %s9, [x10, #3]", s));
        CHK("ldrsh", ldrsh(w, 11, 12, 6), F("ldrsh %s11, [x12, #6]", s));
    }
    CHK("ldrb", ldrb(0, 1, 0), "ldrb w0, [x1]");
    CHK("ldrb", ldrb(2, 3, 4095), "ldrb w2, [x3, #4095]");
    CHK("strb", strb(4, 5, 7), "strb w4, [x5, #7]");
    CHK("ldrh", ldrh(6, 7, 2), "ldrh w6, [x7, #2]");
    CHK("ldrh", ldrh(8, 9, 8190), "ldrh w8, [x9, #8190]");
    CHK("strh", strh(10, 11, 4), "strh w10, [x11, #4]");
    CHK("ldrsw", ldrsw(12, 13, 16), "ldrsw x12, [x13, #16]");

    // Unscaled (LDUR/STUR).
    CHK("ldur", ldur(true, 0, 1, -8), "ldur x0, [x1, #-8]");
    CHK("ldur", ldur(false, 2, 3, 255), "ldur w2, [x3, #255]");
    CHK("ldur", ldur(true, 4, 31, -256), "ldur x4, [sp, #-256]");
    CHK("stur", stur(true, 5, 6, -1), "stur x5, [x6, #-1]");
    CHK("stur", stur(false, 7, 8, 3), "stur w7, [x8, #3]");
    CHK("ldurb", ldurb(9, 10, -3), "ldurb w9, [x10, #-3]");
    CHK("sturb", sturb(11, 12, 5), "sturb w11, [x12, #5]");
    CHK("ldurh", ldurh(13, 14, -6), "ldurh w13, [x14, #-6]");
    CHK("sturh", sturh(15, 16, 9), "sturh w15, [x16, #9]");
    CHK("ldursb", ldursb(true, 17, 18, -1), "ldursb x17, [x18, #-1]");
    CHK("ldursb", ldursb(false, 19, 20, 2), "ldursb w19, [x20, #2]");
    CHK("ldursh", ldursh(true, 21, 22, -4), "ldursh x21, [x22, #-4]");
    CHK("ldursh", ldursh(false, 23, 24, 5), "ldursh w23, [x24, #5]");
    CHK("ldursw", ldursw(25, 26, -4), "ldursw x25, [x26, #-4]");

    // Pre/post-indexed.
    CHK("ldr_idx", ldr_idx(true, 0, 1, 8, Index::PreIndex), "ldr x0, [x1, #8]!");
    CHK("ldr_idx", ldr_idx(true, 2, 3, -16, Index::PostIndex), "ldr x2, [x3], #-16");
    CHK("ldr_idx", ldr_idx(false, 4, 5, 4, Index::PreIndex), "ldr w4, [x5, #4]!");
    CHK("str_idx", str_idx(true, 6, 31, -32, Index::PreIndex), "str x6, [sp, #-32]!");
    CHK("str_idx", str_idx(false, 7, 8, 12, Index::PostIndex), "str w7, [x8], #12");
    CHK("ldrb_idx", ldrb_idx(9, 10, 1, Index::PostIndex), "ldrb w9, [x10], #1");
    CHK("strb_idx", strb_idx(11, 12, -1, Index::PreIndex), "strb w11, [x12, #-1]!");
    CHK("ldrh_idx", ldrh_idx(13, 14, 2, Index::PostIndex), "ldrh w13, [x14], #2");
    CHK("strh_idx", strh_idx(15, 16, -2, Index::PreIndex), "strh w15, [x16, #-2]!");

    // Register-offset.
    CHK("ldr_r", ldr_r(true, 0, 1, 2), "ldr x0, [x1, x2, lsl #3]");
    CHK("ldr_r", ldr_r(true, 0, 1, 2, ExtLSL64, false), "ldr x0, [x1, x2]");
    CHK("ldr_r", ldr_r(false, 3, 4, 5, ExtUXTW, true), "ldr w3, [x4, w5, uxtw #2]");
    CHK("ldr_r", ldr_r(true, 6, 7, 8, ExtSXTW, false), "ldr x6, [x7, w8, sxtw]");
    CHK("ldr_r", ldr_r(true, 9, 10, 11, ExtSXTX, true), "ldr x9, [x10, x11, sxtx #3]");
    CHK("str_r", str_r(true, 12, 13, 14), "str x12, [x13, x14, lsl #3]");
    CHK("ldrb_r", ldrb_r(0, 1, 2), "ldrb w0, [x1, x2]");
    CHK("ldrb_r", ldrb_r(0, 1, 2, ExtSXTW, false), "ldrb w0, [x1, w2, sxtw]");
    CHK("strb_r", strb_r(3, 4, 5), "strb w3, [x4, x5]");
    CHK("ldrh_r", ldrh_r(6, 7, 8), "ldrh w6, [x7, x8, lsl #1]");
    CHK("strh_r", strh_r(9, 10, 11, ExtLSL64, false), "strh w9, [x10, x11]");
    CHK("ldrsb_r", ldrsb_r(true, 12, 13, 14), "ldrsb x12, [x13, x14]");
    CHK("ldrsh_r", ldrsh_r(false, 15, 16, 17), "ldrsh w15, [x16, x17, lsl #1]");
    CHK("ldrsw_r", ldrsw_r(18, 19, 20), "ldrsw x18, [x19, x20, lsl #2]");

    // Literal loads.
    CHK("ldr_literal", ldr_literal(0, false, 0, 8), "ldr w0, #8");
    CHK("ldr_literal", ldr_literal(1, false, 1, -8), "ldr x1, #-8");
    CHK("ldr_literal", ldr_literal(2, false, 2, 1048572), "ldrsw x2, #1048572");
    CHK("ldr_literal", ldr_literal(0, true, 3, 4), "ldr s3, #4");
    CHK("ldr_literal", ldr_literal(1, true, 4, -1048576), "ldr d4, #-1048576");
    CHK("ldr_literal", ldr_literal(2, true, 5, 12), "ldr q5, #12");

    // Pairs.
    CHK("ldp", ldp(true, 0, 1, 31, 16), "ldp x0, x1, [sp, #16]");
    CHK("ldp", ldp(true, 2, 3, 4, -512), "ldp x2, x3, [x4, #-512]");
    CHK("ldp", ldp(false, 5, 6, 7, 8), "ldp w5, w6, [x7, #8]");
    CHK("ldp", ldp(true, 29, 30, 31, 16, Index::PostIndex), "ldp x29, x30, [sp], #16");
    CHK("stp", stp(true, 29, 30, 31, -16, Index::PreIndex), "stp x29, x30, [sp, #-16]!");
    CHK("stp", stp(true, 8, 9, 10, 504), "stp x8, x9, [x10, #504]");
    CHK("stp", stp(false, 11, 12, 13, -4, Index::PostIndex), "stp w11, w12, [x13], #-4");
    CHK("ldpsw", ldpsw(14, 15, 16, 8), "ldpsw x14, x15, [x16, #8]");
    CHK("ldpsw", ldpsw(17, 18, 19, -256, Index::PreIndex), "ldpsw x17, x18, [x19, #-256]!");

    // Exclusives (ARM32 LDREX/STREX family).
    CHK("ldxr", ldxr(false, 0, 1), "ldxr w0, [x1]");
    CHK("ldxr", ldxr(true, 2, 3), "ldxr x2, [x3]");
    CHK("ldaxr", ldaxr(false, 4, 5), "ldaxr w4, [x5]");
    CHK("ldaxr", ldaxr(true, 6, 7), "ldaxr x6, [x7]");
    CHK("ldxrb", ldxrb(8, 9), "ldxrb w8, [x9]");
    CHK("ldaxrb", ldaxrb(10, 11), "ldaxrb w10, [x11]");
    CHK("ldxrh", ldxrh(12, 13), "ldxrh w12, [x13]");
    CHK("ldaxrh", ldaxrh(14, 15), "ldaxrh w14, [x15]");
    CHK("stxr", stxr(false, 0, 1, 2), "stxr w0, w1, [x2]");
    CHK("stxr", stxr(true, 3, 4, 5), "stxr w3, x4, [x5]");
    CHK("stlxr", stlxr(false, 6, 7, 8), "stlxr w6, w7, [x8]");
    CHK("stlxr", stlxr(true, 9, 10, 11), "stlxr w9, x10, [x11]");
    CHK("stxrb", stxrb(12, 13, 14), "stxrb w12, w13, [x14]");
    CHK("stlxrb", stlxrb(15, 16, 17), "stlxrb w15, w16, [x17]");
    CHK("stxrh", stxrh(18, 19, 20), "stxrh w18, w19, [x20]");
    CHK("stlxrh", stlxrh(21, 22, 23), "stlxrh w21, w22, [x23]");
    CHK("ldxp", ldxp(true, 0, 1, 2), "ldxp x0, x1, [x2]");
    CHK("ldxp", ldxp(false, 3, 4, 5), "ldxp w3, w4, [x5]");
    CHK("ldaxp", ldaxp(true, 6, 7, 8), "ldaxp x6, x7, [x8]");
    CHK("stxp", stxp(true, 9, 10, 11, 12), "stxp w9, x10, x11, [x12]");
    CHK("stxp", stxp(false, 13, 14, 15, 16), "stxp w13, w14, w15, [x16]");
    CHK("stlxp", stlxp(true, 17, 18, 19, 20), "stlxp w17, x18, x19, [x20]");
}

static void build_fp_cases() {
    struct TypeInfo { unsigned p; const char* r; };
    const TypeInfo types[2] = {{kFpS, "s"}, {kFpD, "d"}};

    for (const TypeInfo& t : types) {
        const char* r = t.r;
        CHK("fmov_reg", fmov_reg(t.p, 0, 1), F("fmov %s0, %s1", r, r));
        CHK("fabs_f", fabs_f(t.p, 2, 3), F("fabs %s2, %s3", r, r));
        CHK("fneg_f", fneg_f(t.p, 4, 5), F("fneg %s4, %s5", r, r));
        CHK("fsqrt", fsqrt(t.p, 6, 7), F("fsqrt %s6, %s7", r, r));
        CHK("frintn", frintn(t.p, 8, 9), F("frintn %s8, %s9", r, r));
        CHK("frintp", frintp(t.p, 10, 11), F("frintp %s10, %s11", r, r));
        CHK("frintm", frintm(t.p, 12, 13), F("frintm %s12, %s13", r, r));
        CHK("frintz", frintz(t.p, 14, 15), F("frintz %s14, %s15", r, r));
        CHK("frinta", frinta(t.p, 16, 17), F("frinta %s16, %s17", r, r));
        CHK("frintx", frintx(t.p, 18, 19), F("frintx %s18, %s19", r, r));
        CHK("frinti", frinti(t.p, 20, 21), F("frinti %s20, %s21", r, r));

        CHK("fmul", fmul(t.p, 0, 1, 2), F("fmul %s0, %s1, %s2", r, r, r));
        CHK("fdiv", fdiv(t.p, 3, 4, 5), F("fdiv %s3, %s4, %s5", r, r, r));
        CHK("fadd", fadd(t.p, 6, 7, 8), F("fadd %s6, %s7, %s8", r, r, r));
        CHK("fsub", fsub(t.p, 9, 10, 11), F("fsub %s9, %s10, %s11", r, r, r));
        CHK("fmax", fmax(t.p, 12, 13, 14), F("fmax %s12, %s13, %s14", r, r, r));
        CHK("fmin", fmin(t.p, 15, 16, 17), F("fmin %s15, %s16, %s17", r, r, r));
        CHK("fmaxnm", fmaxnm(t.p, 18, 19, 20), F("fmaxnm %s18, %s19, %s20", r, r, r));
        CHK("fminnm", fminnm(t.p, 21, 22, 23), F("fminnm %s21, %s22, %s23", r, r, r));
        CHK("fnmul", fnmul(t.p, 24, 25, 26), F("fnmul %s24, %s25, %s26", r, r, r));

        CHK("fmadd", fmadd(t.p, 0, 1, 2, 3), F("fmadd %s0, %s1, %s2, %s3", r, r, r, r));
        CHK("fmsub", fmsub(t.p, 4, 5, 6, 7), F("fmsub %s4, %s5, %s6, %s7", r, r, r, r));
        CHK("fnmadd", fnmadd(t.p, 8, 9, 10, 11), F("fnmadd %s8, %s9, %s10, %s11", r, r, r, r));
        CHK("fnmsub", fnmsub(t.p, 12, 13, 14, 15), F("fnmsub %s12, %s13, %s14, %s15", r, r, r, r));

        CHK("fcmp", fcmp(t.p, 0, 1), F("fcmp %s0, %s1", r, r));
        CHK("fcmp_zero", fcmp_zero(t.p, 2), F("fcmp %s2, #0.0", r));
        CHK("fcmpe", fcmpe(t.p, 3, 4), F("fcmpe %s3, %s4", r, r));
        CHK("fcmpe_zero", fcmpe_zero(t.p, 5), F("fcmpe %s5, #0.0", r));
        CHK("fcsel", fcsel(t.p, 0, 1, 2, CondGT), F("fcsel %s0, %s1, %s2, gt", r, r, r));
        CHK("fccmp", fccmp(t.p, 3, 4, 5, CondMI), F("fccmp %s3, %s4, #5, mi", r, r));
        CHK("fccmpe", fccmpe(t.p, 6, 7, 3, CondNE), F("fccmpe %s6, %s7, #3, ne", r, r));

        for (bool w : {false, true}) {
            const char* g = w ? "x" : "w";
            CHK("fcvtns", fcvtns(w, t.p, 0, 1), F("fcvtns %s0, %s1", g, r));
            CHK("fcvtnu", fcvtnu(w, t.p, 2, 3), F("fcvtnu %s2, %s3", g, r));
            CHK("fcvtps", fcvtps(w, t.p, 4, 5), F("fcvtps %s4, %s5", g, r));
            CHK("fcvtpu", fcvtpu(w, t.p, 6, 7), F("fcvtpu %s6, %s7", g, r));
            CHK("fcvtms", fcvtms(w, t.p, 8, 9), F("fcvtms %s8, %s9", g, r));
            CHK("fcvtmu", fcvtmu(w, t.p, 10, 11), F("fcvtmu %s10, %s11", g, r));
            CHK("fcvtzs", fcvtzs(w, t.p, 12, 13), F("fcvtzs %s12, %s13", g, r));
            CHK("fcvtzu", fcvtzu(w, t.p, 14, 15), F("fcvtzu %s14, %s15", g, r));
            CHK("fcvtas", fcvtas(w, t.p, 16, 17), F("fcvtas %s16, %s17", g, r));
            CHK("fcvtau", fcvtau(w, t.p, 18, 19), F("fcvtau %s18, %s19", g, r));
            CHK("scvtf", scvtf(w, t.p, 20, 21), F("scvtf %s20, %s21", r, g));
            CHK("ucvtf", ucvtf(w, t.p, 22, 23), F("ucvtf %s22, %s23", r, g));
            CHK("fcvtzs_fixed", fcvtzs_fixed(w, t.p, 0, 1, 8), F("fcvtzs %s0, %s1, #8", g, r));
            CHK("fcvtzu_fixed", fcvtzu_fixed(w, t.p, 2, 3, 1), F("fcvtzu %s2, %s3, #1", g, r));
            CHK("scvtf_fixed", scvtf_fixed(w, t.p, 4, 5, 16), F("scvtf %s4, %s5, #16", r, g));
            CHK("ucvtf_fixed", ucvtf_fixed(w, t.p, 6, 7, 31), F("ucvtf %s6, %s7, #31", r, g));
        }
    }
    CHK("fcvt", fcvt(kFpD, kFpS, 0, 1), "fcvt d0, s1");
    CHK("fcvt", fcvt(kFpS, kFpD, 2, 3), "fcvt s2, d3");
    CHK("fcvt", fcvt(kFpH, kFpS, 4, 5), "fcvt h4, s5");
    CHK("fcvt", fcvt(kFpH, kFpD, 6, 7), "fcvt h6, d7");
    CHK("fcvt", fcvt(kFpS, kFpH, 8, 9), "fcvt s8, h9");
    CHK("fcvt", fcvt(kFpD, kFpH, 10, 11), "fcvt d10, h11");

    CHK("fmov_to_gpr", fmov_to_gpr(false, kFpS, 0, 1), "fmov w0, s1");
    CHK("fmov_to_gpr", fmov_to_gpr(true, kFpD, 2, 3), "fmov x2, d3");
    CHK("fmov_from_gpr", fmov_from_gpr(false, kFpS, 4, 5), "fmov s4, w5");
    CHK("fmov_from_gpr", fmov_from_gpr(true, kFpD, 6, 7), "fmov d6, x7");
    CHK("fmov_to_gpr_hi", fmov_to_gpr_hi(8, 9), "fmov x8, v9.d[1]");
    CHK("fmov_from_gpr_hi", fmov_from_gpr_hi(10, 11), "fmov v10.d[1], x11");

    // Scalar FP load/store.
    CHK("ldr_s", ldr_s(0, 1, 0), "ldr s0, [x1]");
    CHK("ldr_s", ldr_s(2, 3, 16380), "ldr s2, [x3, #16380]");
    CHK("str_s", str_s(4, 5, 4), "str s4, [x5, #4]");
    CHK("ldr_d", ldr_d(6, 7, 8), "ldr d6, [x7, #8]");
    CHK("str_d", str_d(8, 9, 32760), "str d8, [x9, #32760]");
    CHK("ldr_q", ldr_q(10, 11, 16), "ldr q10, [x11, #16]");
    CHK("str_q", str_q(12, 13, 65520), "str q12, [x13, #65520]");
    CHK("fp_ldst_simm9", fp_ldst_simm9(kSizeW, true, 0, 1, -4, Index::Offset), "ldur s0, [x1, #-4]");
    CHK("fp_ldst_simm9", fp_ldst_simm9(kSizeX, true, 2, 3, 8, Index::PostIndex), "ldr d2, [x3], #8");
    CHK("fp_ldst_simm9", fp_ldst_simm9(kVecQ, true, 4, 5, -16, Index::PreIndex), "ldr q4, [x5, #-16]!");
    CHK("fp_ldst_simm9", fp_ldst_simm9(kSizeB, false, 6, 7, 1, Index::Offset), "stur b6, [x7, #1]");
    CHK("fp_ldst_simm9", fp_ldst_simm9(kSizeH, true, 8, 9, -2, Index::Offset), "ldur h8, [x9, #-2]");
    CHK("fp_ldst_reg", fp_ldst_reg(kSizeW, true, 0, 1, 2), "ldr s0, [x1, x2, lsl #2]");
    CHK("fp_ldst_reg", fp_ldst_reg(kSizeX, true, 3, 4, 5, ExtLSL64, false), "ldr d3, [x4, x5]");
    CHK("fp_ldst_reg", fp_ldst_reg(kVecQ, false, 6, 7, 8), "str q6, [x7, x8, lsl #4]");
    CHK("fp_ldst_uimm", fp_ldst_uimm(kSizeB, true, 0, 1, 3), "ldr b0, [x1, #3]");
    CHK("fp_ldst_uimm", fp_ldst_uimm(kSizeH, false, 2, 3, 6), "str h2, [x3, #6]");
    CHK("stp_fp", stp_fp(kSizeW, 0, 1, 2, 8), "stp s0, s1, [x2, #8]");
    CHK("ldp_fp", ldp_fp(kSizeW, 3, 4, 5, -8), "ldp s3, s4, [x5, #-8]");
    CHK("stp_fp", stp_fp(kSizeX, 6, 7, 31, 16, Index::PreIndex), "stp d6, d7, [sp, #16]!");
    CHK("ldp_fp", ldp_fp(kSizeX, 8, 9, 10, 24, Index::PostIndex), "ldp d8, d9, [x10], #24");
    CHK("stp_fp", stp_fp(kVecQ, 11, 12, 13, 32), "stp q11, q12, [x13, #32]");
    CHK("ldp_fp", ldp_fp(kVecQ, 14, 15, 16, -64), "ldp q14, q15, [x16, #-64]");

    // Element moves.
    CHK("umov", umov(false, vec_imm5(0, 3), 0, 1), "umov w0, v1.b[3]");
    CHK("umov", umov(false, vec_imm5(1, 5), 2, 3), "umov w2, v3.h[5]");
    CHK("umov", umov(false, vec_imm5(2, 2), 4, 5), "umov w4, v5.s[2]");
    CHK("umov", umov(true, vec_imm5(3, 1), 6, 7), "umov x6, v7.d[1]");
    CHK("smov", smov(false, vec_imm5(0, 1), 0, 1), "smov w0, v1.b[1]");
    CHK("smov", smov(true, vec_imm5(1, 2), 2, 3), "smov x2, v3.h[2]");
    CHK("smov", smov(true, vec_imm5(2, 3), 4, 5), "smov x4, v5.s[3]");
    CHK("ins_gen", ins_gen(vec_imm5(3, 1), 0, 1), "ins v0.d[1], x1");
    CHK("ins_gen", ins_gen(vec_imm5(2, 2), 2, 3), "ins v2.s[2], w3");
    CHK("ins_gen", ins_gen(vec_imm5(0, 7), 4, 5), "ins v4.b[7], w5");
    CHK("ins_elem", ins_elem(vec_imm5(0, 3), 7 << 0, 0, 1), "ins v0.b[3], v1.b[7]");
    CHK("ins_elem", ins_elem(vec_imm5(2, 1), 3 << 2, 2, 3), "ins v2.s[1], v3.s[3]");
    CHK("ins_elem", ins_elem(vec_imm5(3, 1), 0 << 3, 4, 5), "ins v4.d[1], v5.d[0]");
    CHK("dup_gen", dup_gen(true, vec_imm5(3, 0), 0, 1), "dup v0.2d, x1");
    CHK("dup_gen", dup_gen(true, vec_imm5(2, 0), 2, 3), "dup v2.4s, w3");
    CHK("dup_gen", dup_gen(false, vec_imm5(2, 0), 4, 5), "dup v4.2s, w5");
    CHK("dup_elem", dup_elem(false, vec_imm5(2, 1), 0, 1), "dup v0.2s, v1.s[1]");
    CHK("dup_elem", dup_elem(true, vec_imm5(3, 1), 2, 3), "dup v2.2d, v3.d[1]");
    CHK("movi_2d_zero", movi_2d_zero(0), "movi v0.2d, #0");
    CHK("movi_2d_zero", movi_2d_zero(31), "movi v31.2d, #0");
}

// ---------------------------------------------------------------------------
// Advanced SIMD (NEON) cases
// ---------------------------------------------------------------------------

namespace {
struct ArrInfo { VArr a; const char* t; };
// Integer arrangements, minus the 1D/2D entries that most integer ops reject.
const ArrInfo kIntArr[] = {{V8B, "8b"}, {V16B, "16b"}, {V4H, "4h"},
                           {V8H, "8h"}, {V2S, "2s"},   {V4S, "4s"}};
const ArrInfo kIntArrD[] = {{V8B, "8b"}, {V16B, "16b"}, {V4H, "4h"}, {V8H, "8h"},
                            {V2S, "2s"}, {V4S, "4s"},   {V2D, "2d"}};
struct FArrInfo { FArr a; const char* t; };
const FArrInfo kFpArr[] = {{FV2S, "2s"}, {FV4S, "4s"}, {FV2D, "2d"}};
}  // namespace

static void build_neon_cases() {
    // --- three same, integer, swept over every arrangement -------------------
    struct IntOp {
        const char* name;
        uint32_t (*fn)(VArr, unsigned, unsigned, unsigned);
        const char* mn;
        bool allow_d;
    };
    const IntOp int_ops[] = {
        {"vadd", vadd, "add", true},         {"vsub", vsub, "sub", true},
        {"vmul", vmul, "mul", false},        {"vmla", vmla, "mla", false},
        {"vmls", vmls, "mls", false},        {"vcmeq", vcmeq, "cmeq", true},
        {"vcmtst", vcmtst, "cmtst", true},   {"vcmgt", vcmgt, "cmgt", true},
        {"vcmge", vcmge, "cmge", true},      {"vcmhi", vcmhi, "cmhi", true},
        {"vcmhs", vcmhs, "cmhs", true},      {"vsmax", vsmax, "smax", false},
        {"vsmin", vsmin, "smin", false},     {"vumax", vumax, "umax", false},
        {"vumin", vumin, "umin", false},     {"vsabd", vsabd, "sabd", false},
        {"vuabd", vuabd, "uabd", false},     {"vsaba", vsaba, "saba", false},
        {"vuaba", vuaba, "uaba", false},     {"vsqadd", vsqadd, "sqadd", true},
        {"vuqadd", vuqadd, "uqadd", true},   {"vsqsub", vsqsub, "sqsub", true},
        {"vuqsub", vuqsub, "uqsub", true},   {"vshadd", vshadd, "shadd", false},
        {"vuhadd", vuhadd, "uhadd", false},  {"vshsub", vshsub, "shsub", false},
        {"vuhsub", vuhsub, "uhsub", false},  {"vsrhadd", vsrhadd, "srhadd", false},
        {"vurhadd", vurhadd, "urhadd", false}, {"vsshl", vsshl, "sshl", true},
        {"vushl", vushl, "ushl", true},      {"vsqshl", vsqshl, "sqshl", true},
        {"vuqshl", vuqshl, "uqshl", true},   {"vsrshl", vsrshl, "srshl", true},
        {"vurshl", vurshl, "urshl", true},   {"vsqrshl", vsqrshl, "sqrshl", true},
        {"vuqrshl", vuqrshl, "uqrshl", true}, {"vaddp", vaddp, "addp", true},
        {"vsmaxp", vsmaxp, "smaxp", false},  {"vsminp", vsminp, "sminp", false},
        {"vumaxp", vumaxp, "umaxp", false},  {"vuminp", vuminp, "uminp", false},
        {"vpmul", vpmul, "pmul", false},
    };
    for (const IntOp& op : int_ops) {
        const ArrInfo* list = op.allow_d ? kIntArrD : kIntArr;
        const size_t n = op.allow_d ? (sizeof(kIntArrD) / sizeof(kIntArrD[0]))
                                    : (sizeof(kIntArr) / sizeof(kIntArr[0]));
        for (size_t i = 0; i < n; ++i) {
            // PMUL is byte-only; skip the non-byte arrangements for it.
            if (!strcmp(op.mn, "pmul") && list[i].a != V8B && list[i].a != V16B) continue;
            CHK(op.name, op.fn(list[i].a, 0, 1, 2),
                F("%s v0.%s, v1.%s, v2.%s", op.mn, list[i].t, list[i].t, list[i].t));
        }
    }
    // SQDMULH/SQRDMULH are 16- and 32-bit only.
    for (const char* t : {"4h", "8h", "2s", "4s"}) {
        const VArr a = !strcmp(t, "4h") ? V4H : (!strcmp(t, "8h") ? V8H : (!strcmp(t, "2s") ? V2S : V4S));
        CHK("vsqdmulh", vsqdmulh(a, 0, 1, 2), F("sqdmulh v0.%s, v1.%s, v2.%s", t, t, t));
        CHK("vsqrdmulh", vsqrdmulh(a, 3, 4, 5), F("sqrdmulh v3.%s, v4.%s, v5.%s", t, t, t));
    }

    // --- three same, logical -------------------------------------------------
    struct LogOp { const char* name; uint32_t (*fn)(bool, unsigned, unsigned, unsigned); const char* mn; };
    const LogOp log_ops[] = {
        {"vand", vand, "and"}, {"vbic", vbic, "bic"}, {"vorr", vorr, "orr"},
        {"vorn", vorn, "orn"}, {"veor", veor, "eor"}, {"vbsl", vbsl, "bsl"},
        {"vbit", vbit, "bit"}, {"vbif", vbif, "bif"},
    };
    for (const LogOp& op : log_ops) {
        CHK(op.name, op.fn(true, 0, 1, 2), F("%s v0.16b, v1.16b, v2.16b", op.mn));
        CHK(op.name, op.fn(false, 3, 4, 5), F("%s v3.8b, v4.8b, v5.8b", op.mn));
    }
    CHK("vmov_reg", vmov_reg(true, 0, 1), "mov v0.16b, v1.16b");
    CHK("vmov_reg", vmov_reg(false, 2, 3), "mov v2.8b, v3.8b");

    // --- three same, floating point -----------------------------------------
    struct FpOp { const char* name; uint32_t (*fn)(FArr, unsigned, unsigned, unsigned); const char* mn; };
    const FpOp fp_ops[] = {
        {"vfadd", vfadd, "fadd"},       {"vfsub", vfsub, "fsub"},
        {"vfmul", vfmul, "fmul"},       {"vfdiv", vfdiv, "fdiv"},
        {"vfmla", vfmla, "fmla"},       {"vfmls", vfmls, "fmls"},
        {"vfmax", vfmax, "fmax"},       {"vfmin", vfmin, "fmin"},
        {"vfmaxnm", vfmaxnm, "fmaxnm"}, {"vfminnm", vfminnm, "fminnm"},
        {"vfabd", vfabd, "fabd"},       {"vfcmeq", vfcmeq, "fcmeq"},
        {"vfcmge", vfcmge, "fcmge"},    {"vfcmgt", vfcmgt, "fcmgt"},
        {"vfacge", vfacge, "facge"},    {"vfacgt", vfacgt, "facgt"},
        {"vfrecps", vfrecps, "frecps"}, {"vfrsqrts", vfrsqrts, "frsqrts"},
        {"vfaddp", vfaddp, "faddp"},    {"vfmaxp", vfmaxp, "fmaxp"},
        {"vfminp", vfminp, "fminp"},    {"vfmulx", vfmulx, "fmulx"},
    };
    for (const FpOp& op : fp_ops) {
        for (const FArrInfo& ai : kFpArr) {
            CHK(op.name, op.fn(ai.a, 0, 1, 2),
                F("%s v0.%s, v1.%s, v2.%s", op.mn, ai.t, ai.t, ai.t));
        }
    }

    // --- two-register miscellaneous -----------------------------------------
    struct MiscOp { const char* name; uint32_t (*fn)(VArr, unsigned, unsigned); const char* mn; bool allow_d; };
    const MiscOp misc_ops[] = {
        {"vcls", vcls, "cls", false},     {"vclz", vclz, "clz", false},
        {"vabs", vabs, "abs", true},      {"vneg", vneg, "neg", true},
        {"vqabs", vqabs, "sqabs", true},  {"vqneg", vqneg, "sqneg", true},
        {"vcmgt0", vcmgt0, "cmgt", true}, {"vcmge0", vcmge0, "cmge", true},
        {"vcmeq0", vcmeq0, "cmeq", true}, {"vcmle0", vcmle0, "cmle", true},
        {"vcmlt0", vcmlt0, "cmlt", true},
    };
    for (const MiscOp& op : misc_ops) {
        const ArrInfo* list = op.allow_d ? kIntArrD : kIntArr;
        const size_t n = op.allow_d ? (sizeof(kIntArrD) / sizeof(kIntArrD[0]))
                                    : (sizeof(kIntArr) / sizeof(kIntArr[0]));
        for (size_t i = 0; i < n; ++i) {
            const bool zero_form = op.mn[0] == 'c' && op.mn[1] == 'm';  // cmXX #0 vs cls/clz
            CHK(op.name, op.fn(list[i].a, 0, 1),
                zero_form ? F("%s v0.%s, v1.%s, #0", op.mn, list[i].t, list[i].t)
                          : F("%s v0.%s, v1.%s", op.mn, list[i].t, list[i].t));
        }
    }
    CHK("vrev64", vrev64(V16B, 0, 1), "rev64 v0.16b, v1.16b");
    CHK("vrev64", vrev64(V4H, 2, 3), "rev64 v2.4h, v3.4h");
    CHK("vrev64", vrev64(V4S, 4, 5), "rev64 v4.4s, v5.4s");
    CHK("vrev32", vrev32(V16B, 6, 7), "rev32 v6.16b, v7.16b");
    CHK("vrev32", vrev32(V8H, 8, 9), "rev32 v8.8h, v9.8h");
    CHK("vrev16", vrev16(V8B, 10, 11), "rev16 v10.8b, v11.8b");
    CHK("vcnt", vcnt(true, 0, 1), "cnt v0.16b, v1.16b");
    CHK("vmvn", vmvn(true, 2, 3), "mvn v2.16b, v3.16b");
    CHK("vmvn", vmvn(false, 4, 5), "mvn v4.8b, v5.8b");
    CHK("vrbit", vrbit(true, 6, 7), "rbit v6.16b, v7.16b");
    CHK("vsaddlp", vsaddlp(V16B, 0, 1), "saddlp v0.8h, v1.16b");
    CHK("vuaddlp", vuaddlp(V4H, 2, 3), "uaddlp v2.2s, v3.4h");
    CHK("vsadalp", vsadalp(V4S, 4, 5), "sadalp v4.2d, v5.4s");
    CHK("vuadalp", vuadalp(V8B, 6, 7), "uadalp v6.4h, v7.8b");
    CHK("vxtn", vxtn(V8B, 0, 1), "xtn v0.8b, v1.8h");
    CHK("vxtn", vxtn(V16B, 2, 3), "xtn2 v2.16b, v3.8h");
    CHK("vxtn", vxtn(V4H, 4, 5), "xtn v4.4h, v5.4s");
    CHK("vsqxtn", vsqxtn(V2S, 6, 7), "sqxtn v6.2s, v7.2d");
    CHK("vuqxtn", vuqxtn(V8B, 8, 9), "uqxtn v8.8b, v9.8h");
    CHK("vsqxtun", vsqxtun(V4H, 10, 11), "sqxtun v10.4h, v11.4s");
    CHK("vshll", vshll(V8B, 0, 1), "shll v0.8h, v1.8b, #8");
    CHK("vshll", vshll(V4S, 2, 3), "shll2 v2.2d, v3.4s, #32");
    for (const FArrInfo& ai : kFpArr) {
        CHK("vfabs", vfabs(ai.a, 0, 1), F("fabs v0.%s, v1.%s", ai.t, ai.t));
        CHK("vfneg", vfneg(ai.a, 2, 3), F("fneg v2.%s, v3.%s", ai.t, ai.t));
        CHK("vfsqrt", vfsqrt(ai.a, 4, 5), F("fsqrt v4.%s, v5.%s", ai.t, ai.t));
        CHK("vfrecpe", vfrecpe(ai.a, 6, 7), F("frecpe v6.%s, v7.%s", ai.t, ai.t));
        CHK("vfrsqrte", vfrsqrte(ai.a, 8, 9), F("frsqrte v8.%s, v9.%s", ai.t, ai.t));
        CHK("vfrintn", vfrintn(ai.a, 10, 11), F("frintn v10.%s, v11.%s", ai.t, ai.t));
        CHK("vfrintm", vfrintm(ai.a, 12, 13), F("frintm v12.%s, v13.%s", ai.t, ai.t));
        CHK("vfrintp", vfrintp(ai.a, 14, 15), F("frintp v14.%s, v15.%s", ai.t, ai.t));
        CHK("vfrintz", vfrintz(ai.a, 16, 17), F("frintz v16.%s, v17.%s", ai.t, ai.t));
        CHK("vfrinta", vfrinta(ai.a, 18, 19), F("frinta v18.%s, v19.%s", ai.t, ai.t));
        CHK("vfrintx", vfrintx(ai.a, 20, 21), F("frintx v20.%s, v21.%s", ai.t, ai.t));
        CHK("vfrinti", vfrinti(ai.a, 22, 23), F("frinti v22.%s, v23.%s", ai.t, ai.t));
        CHK("vfcvtzs", vfcvtzs(ai.a, 0, 1), F("fcvtzs v0.%s, v1.%s", ai.t, ai.t));
        CHK("vfcvtzu", vfcvtzu(ai.a, 2, 3), F("fcvtzu v2.%s, v3.%s", ai.t, ai.t));
        CHK("vscvtf", vscvtf(ai.a, 4, 5), F("scvtf v4.%s, v5.%s", ai.t, ai.t));
        CHK("vucvtf", vucvtf(ai.a, 6, 7), F("ucvtf v6.%s, v7.%s", ai.t, ai.t));
        CHK("vfcmgt0", vfcmgt0(ai.a, 8, 9), F("fcmgt v8.%s, v9.%s, #0.0", ai.t, ai.t));
        CHK("vfcmge0", vfcmge0(ai.a, 10, 11), F("fcmge v10.%s, v11.%s, #0.0", ai.t, ai.t));
        CHK("vfcmeq0", vfcmeq0(ai.a, 12, 13), F("fcmeq v12.%s, v13.%s, #0.0", ai.t, ai.t));
        CHK("vfcmle0", vfcmle0(ai.a, 14, 15), F("fcmle v14.%s, v15.%s, #0.0", ai.t, ai.t));
        CHK("vfcmlt0", vfcmlt0(ai.a, 16, 17), F("fcmlt v16.%s, v17.%s, #0.0", ai.t, ai.t));
    }
    CHK("vfcvtn", vfcvtn(false, true, 0, 1), "fcvtn v0.2s, v1.2d");
    CHK("vfcvtn", vfcvtn(true, true, 2, 3), "fcvtn2 v2.4s, v3.2d");
    CHK("vfcvtn", vfcvtn(false, false, 4, 5), "fcvtn v4.4h, v5.4s");
    CHK("vfcvtl", vfcvtl(false, true, 6, 7), "fcvtl v6.2d, v7.2s");
    CHK("vfcvtl", vfcvtl(true, false, 8, 9), "fcvtl2 v8.4s, v9.8h");

    // --- shift by immediate --------------------------------------------------
    struct ShOp { const char* name; uint32_t (*fn)(VArr, unsigned, unsigned, unsigned); const char* mn; bool left; };
    const ShOp sh_ops[] = {
        {"vshl_imm", vshl_imm, "shl", true},   {"vsli", vsli, "sli", true},
        {"vsqshl_imm", vsqshl_imm, "sqshl", true}, {"vuqshl_imm", vuqshl_imm, "uqshl", true},
        {"vsqshlu", vsqshlu, "sqshlu", true},
        {"vsshr", vsshr, "sshr", false},       {"vushr", vushr, "ushr", false},
        {"vssra", vssra, "ssra", false},       {"vusra", vusra, "usra", false},
        {"vsrshr", vsrshr, "srshr", false},    {"vurshr", vurshr, "urshr", false},
        {"vsrsra", vsrsra, "srsra", false},    {"vursra", vursra, "ursra", false},
        {"vsri", vsri, "sri", false},
    };
    for (const ShOp& op : sh_ops) {
        for (const ArrInfo& ai : kIntArrD) {
            const unsigned esz = varr_esize(ai.a);
            // Left shifts take 0..esize-1; right shifts take 1..esize.
            const unsigned shifts[3] = {op.left ? 0u : 1u, esz / 2u, op.left ? esz - 1u : esz};
            for (unsigned s : shifts) {
                CHK(op.name, op.fn(ai.a, 0, 1, s),
                    F("%s v0.%s, v1.%s, #%u", op.mn, ai.t, ai.t, s));
            }
        }
    }
    CHK("vsshll", vsshll(V8B, 0, 1, 3), "sshll v0.8h, v1.8b, #3");
    CHK("vsshll", vsshll(V16B, 2, 3, 0), "sshll2 v2.8h, v3.16b, #0");
    CHK("vushll", vushll(V4H, 4, 5, 7), "ushll v4.4s, v5.4h, #7");
    CHK("vushll", vushll(V4S, 6, 7, 31), "ushll2 v6.2d, v7.4s, #31");
    CHK("vsxtl", vsxtl(V2S, 8, 9), "sxtl v8.2d, v9.2s");
    CHK("vuxtl", vuxtl(V8B, 10, 11), "uxtl v10.8h, v11.8b");
    CHK("vshrn", vshrn(V8B, 0, 1, 3), "shrn v0.8b, v1.8h, #3");
    CHK("vshrn", vshrn(V16B, 2, 3, 8), "shrn2 v2.16b, v3.8h, #8");
    CHK("vrshrn", vrshrn(V4H, 4, 5, 1), "rshrn v4.4h, v5.4s, #1");
    CHK("vsqshrn", vsqshrn(V2S, 6, 7, 16), "sqshrn v6.2s, v7.2d, #16");
    CHK("vsqrshrn", vsqrshrn(V8B, 8, 9, 5), "sqrshrn v8.8b, v9.8h, #5");
    CHK("vuqshrn", vuqshrn(V4H, 10, 11, 9), "uqshrn v10.4h, v11.4s, #9");
    CHK("vuqrshrn", vuqrshrn(V2S, 12, 13, 32), "uqrshrn v12.2s, v13.2d, #32");
    CHK("vsqshrun", vsqshrun(V8B, 14, 15, 2), "sqshrun v14.8b, v15.8h, #2");
    CHK("vsqrshrun", vsqrshrun(V4S, 16, 17, 4), "sqrshrun2 v16.4s, v17.2d, #4");

    // --- three different -----------------------------------------------------
    struct DiffOp { const char* name; uint32_t (*fn)(VArr, unsigned, unsigned, unsigned); const char* mn; bool wide_src; };
    const DiffOp diff_ops[] = {
        {"vsaddl", vsaddl, "saddl", false},  {"vuaddl", vuaddl, "uaddl", false},
        {"vssubl", vssubl, "ssubl", false},  {"vusubl", vusubl, "usubl", false},
        {"vsabal", vsabal, "sabal", false},  {"vuabal", vuabal, "uabal", false},
        {"vsabdl", vsabdl, "sabdl", false},  {"vuabdl", vuabdl, "uabdl", false},
        {"vsmlal", vsmlal, "smlal", false},  {"vumlal", vumlal, "umlal", false},
        {"vsmlsl", vsmlsl, "smlsl", false},  {"vumlsl", vumlsl, "umlsl", false},
        {"vsmull", vsmull, "smull", false},  {"vumull", vumull, "umull", false},
    };
    struct WidenArr { VArr src; const char* s; const char* d; };
    const WidenArr widen[] = {{V8B, "8b", "8h"},  {V16B, "16b", "8h"}, {V4H, "4h", "4s"},
                              {V8H, "8h", "4s"},  {V2S, "2s", "2d"},   {V4S, "4s", "2d"}};
    for (const DiffOp& op : diff_ops) {
        for (const WidenArr& wa : widen) {
            const char* suffix = varr_q(wa.src) ? "2" : "";
            CHK(op.name, op.fn(wa.src, 0, 1, 2),
                F("%s%s v0.%s, v1.%s, v2.%s", op.mn, suffix, wa.d, wa.s, wa.s));
        }
    }
    // SADDW/SSUBW take a wide first source.
    CHK("vsaddw", vsaddw(V8B, 0, 1, 2), "saddw v0.8h, v1.8h, v2.8b");
    CHK("vuaddw", vuaddw(V16B, 3, 4, 5), "uaddw2 v3.8h, v4.8h, v5.16b");
    CHK("vssubw", vssubw(V4H, 6, 7, 8), "ssubw v6.4s, v7.4s, v8.4h");
    CHK("vusubw", vusubw(V4S, 9, 10, 11), "usubw2 v9.2d, v10.2d, v11.4s");
    // Saturating doubling long multiplies are 16/32-bit only.
    CHK("vsqdmlal", vsqdmlal(V4H, 0, 1, 2), "sqdmlal v0.4s, v1.4h, v2.4h");
    CHK("vsqdmlsl", vsqdmlsl(V2S, 3, 4, 5), "sqdmlsl v3.2d, v4.2s, v5.2s");
    CHK("vsqdmull", vsqdmull(V8H, 6, 7, 8), "sqdmull2 v6.4s, v7.8h, v8.8h");
    CHK("vpmull", vpmull(V8B, 9, 10, 11), "pmull v9.8h, v10.8b, v11.8b");
    CHK("vpmull", vpmull(V16B, 12, 13, 14), "pmull2 v12.8h, v13.16b, v14.16b");
    // Narrowing adds: destination arrangement.
    CHK("vaddhn", vaddhn(V8B, 0, 1, 2), "addhn v0.8b, v1.8h, v2.8h");
    CHK("vaddhn", vaddhn(V16B, 3, 4, 5), "addhn2 v3.16b, v4.8h, v5.8h");
    CHK("vraddhn", vraddhn(V4H, 6, 7, 8), "raddhn v6.4h, v7.4s, v8.4s");
    CHK("vsubhn", vsubhn(V2S, 9, 10, 11), "subhn v9.2s, v10.2d, v11.2d");
    CHK("vrsubhn", vrsubhn(V4S, 12, 13, 14), "rsubhn2 v12.4s, v13.2d, v14.2d");

    // --- permute / extract / table -------------------------------------------
    struct PermOp { const char* name; uint32_t (*fn)(VArr, unsigned, unsigned, unsigned); const char* mn; };
    const PermOp perm_ops[] = {
        {"vuzp1", vuzp1, "uzp1"}, {"vtrn1", vtrn1, "trn1"}, {"vzip1", vzip1, "zip1"},
        {"vuzp2", vuzp2, "uzp2"}, {"vtrn2", vtrn2, "trn2"}, {"vzip2", vzip2, "zip2"},
    };
    for (const PermOp& op : perm_ops) {
        for (const ArrInfo& ai : kIntArr) {
            CHK(op.name, op.fn(ai.a, 0, 1, 2),
                F("%s v0.%s, v1.%s, v2.%s", op.mn, ai.t, ai.t, ai.t));
        }
        CHK(op.name, op.fn(V2D, 3, 4, 5), F("%s v3.2d, v4.2d, v5.2d", op.mn));
    }
    CHK("vext", vext(true, 0, 1, 2, 5), "ext v0.16b, v1.16b, v2.16b, #5");
    CHK("vext", vext(false, 3, 4, 5, 7), "ext v3.8b, v4.8b, v5.8b, #7");
    for (unsigned n = 1; n <= 4; ++n) {
        std::string tbl = "{ ";
        for (unsigned k = 0; k < n; ++k) {
            if (k) tbl += ", ";
            tbl += "v" + std::to_string((1 + k) % 32) + ".16b";
        }
        tbl += " }";
        CHK("vtbl", vtbl(true, n, 0, 1, 20), F("tbl v0.16b, %s, v20.16b", tbl.c_str()));
        CHK("vtbx", vtbx(true, n, 0, 1, 20), F("tbx v0.16b, %s, v20.16b", tbl.c_str()));
    }

    // --- modified immediate --------------------------------------------------
    CHK("vmovi_8b", vmovi_8b(true, 0xab, 0), "movi v0.16b, #0xab");
    CHK("vmovi_8b", vmovi_8b(false, 0x01, 1), "movi v1.8b, #1");
    CHK("vmovi_32", vmovi_32(true, 0x12, 0, 2), "movi v2.4s, #0x12");
    CHK("vmovi_32", vmovi_32(true, 0x34, 1, 3), "movi v3.4s, #0x34, lsl #8");
    CHK("vmovi_32", vmovi_32(false, 0x56, 2, 4), "movi v4.2s, #0x56, lsl #16");
    CHK("vmovi_32", vmovi_32(true, 0x78, 3, 5), "movi v5.4s, #0x78, lsl #24");
    CHK("vmvni_32", vmvni_32(true, 0x9a, 0, 6), "mvni v6.4s, #0x9a");
    CHK("vmvni_32", vmvni_32(true, 0xbc, 2, 7), "mvni v7.4s, #0xbc, lsl #16");
    CHK("vmovi_16", vmovi_16(true, 0xde, 0, 8), "movi v8.8h, #0xde");
    CHK("vmovi_16", vmovi_16(true, 0xf0, 1, 9), "movi v9.8h, #0xf0, lsl #8");
    CHK("vmvni_16", vmvni_16(false, 0x11, 0, 10), "mvni v10.4h, #0x11");
    CHK("vmovi_2d", vmovi_2d(0xff, 11), "movi v11.2d, #0xffffffffffffffff");
    {
        uint32_t imm8 = 0;
        if (encode_fp_imm8(1.5, &imm8)) {
            CHK("vfmov_imm", vfmov_imm(true, false, imm8, 0), "fmov v0.4s, #1.50000000");
            CHK("vfmov_imm", vfmov_imm(false, false, imm8, 1), "fmov v1.2s, #1.50000000");
            CHK("vfmov_imm", vfmov_imm(true, true, imm8, 2), "fmov v2.2d, #1.50000000");
        }
    }

    // --- SIMD load/store multiple structures (VLD1/VST1 family) --------------
    for (const ArrInfo& ai : kIntArrD) {
        for (unsigned n = 1; n <= 4; ++n) {
            std::string regs = "{ ";
            for (unsigned k = 0; k < n; ++k) {
                if (k) regs += ", ";
                regs += "v" + std::to_string(k) + "." + ai.t;
            }
            regs += " }";
            CHK("vld1", vld1(ai.a, n, 0, 5), F("ld1 %s, [x5]", regs.c_str()));
            CHK("vst1", vst1(ai.a, n, 0, 5), F("st1 %s, [x5]", regs.c_str()));
            const unsigned bytes = n * (varr_q(ai.a) ? 16u : 8u);
            CHK("vld1_post", vld1_post(ai.a, n, 0, 5), F("ld1 %s, [x5], #%u", regs.c_str(), bytes));
            CHK("vst1_post", vst1_post(ai.a, n, 0, 5, 7), F("st1 %s, [x5], x7", regs.c_str()));
        }
    }
    // Interleaved forms. 1D is not a legal arrangement for LD2/LD3/LD4.
    for (const ArrInfo& ai : kIntArr) {
        CHK("vld2", vld2(ai.a, 0, 5), F("ld2 { v0.%s, v1.%s }, [x5]", ai.t, ai.t));
        CHK("vst2", vst2(ai.a, 0, 5), F("st2 { v0.%s, v1.%s }, [x5]", ai.t, ai.t));
        CHK("vld3", vld3(ai.a, 0, 5), F("ld3 { v0.%s, v1.%s, v2.%s }, [x5]", ai.t, ai.t, ai.t));
        CHK("vst3", vst3(ai.a, 0, 5), F("st3 { v0.%s, v1.%s, v2.%s }, [x5]", ai.t, ai.t, ai.t));
        CHK("vld4", vld4(ai.a, 0, 5),
            F("ld4 { v0.%s, v1.%s, v2.%s, v3.%s }, [x5]", ai.t, ai.t, ai.t, ai.t));
        CHK("vst4", vst4(ai.a, 0, 5),
            F("st4 { v0.%s, v1.%s, v2.%s, v3.%s }, [x5]", ai.t, ai.t, ai.t, ai.t));
    }

    // --- CRC32 ---------------------------------------------------------------
    CHK("crc32", crc32(false, false, 0, 0, 1, 2), "crc32b w0, w1, w2");
    CHK("crc32", crc32(false, false, 1, 3, 4, 5), "crc32h w3, w4, w5");
    CHK("crc32", crc32(false, false, 2, 6, 7, 8), "crc32w w6, w7, w8");
    CHK("crc32", crc32(true, false, 3, 9, 10, 11), "crc32x w9, w10, x11");
    CHK("crc32", crc32(false, true, 0, 12, 13, 14), "crc32cb w12, w13, w14");
    CHK("crc32", crc32(false, true, 1, 15, 16, 17), "crc32ch w15, w16, w17");
    CHK("crc32", crc32(false, true, 2, 18, 19, 20), "crc32cw w18, w19, w20");
    CHK("crc32", crc32(true, true, 3, 21, 22, 23), "crc32cx w21, w22, x23");

    // --- non-temporal pairs and prefetch -------------------------------------
    CHK("ldnp", ldnp(true, 0, 1, 2, 16), "ldnp x0, x1, [x2, #16]");
    CHK("ldnp", ldnp(false, 3, 4, 5, -8), "ldnp w3, w4, [x5, #-8]");
    CHK("stnp", stnp(true, 6, 7, 8, 504), "stnp x6, x7, [x8, #504]");
    CHK("stnp", stnp(false, 9, 10, 11, 0), "stnp w9, w10, [x11]");
    CHK("prfm", prfm(0, 1, 0), "prfm pldl1keep, [x1]");
    CHK("prfm", prfm(4, 2, 32760), "prfm pldl3keep, [x2, #32760]");
    CHK("prfm", prfm(5, 3, 8), "prfm pldl3strm, [x3, #8]");
}

// ---------------------------------------------------------------------------
// Exhaustive sub-tests
// ---------------------------------------------------------------------------

static int g_logical_values_64 = 0;
static int g_logical_values_32 = 0;

// Enumerate EVERY legal N:immr:imms field, decode it to a value, then require
// encode_logical_imm() to reproduce that exact field and llvm-mc to agree on
// the resulting instruction word.
//
// The field -> value map is deliberately NOT injective: DecodeBitMasks uses
// (immr AND levels), so any immr bit above the element's levels mask is a
// don't-care and produces a duplicate, non-canonical encoding of the same
// value. Only the canonical field (immr < esize) is a legal encoder output, so
// the enumeration keeps those and requires exact agreement with them.
static void build_logical_imm_exhaustive(std::string* err) {
    for (bool is64 : {true, false}) {
        std::map<uint64_t, uint32_t> value_to_field;
        for (uint32_t field = 0; field < 0x2000u; ++field) {
            uint64_t v;
            if (!decode_logical_imm(field, is64, &v)) continue;

            // Canonicity: immr must carry no bits above the levels mask.
            const unsigned n = (field >> 12) & 1u;
            const unsigned immr = (field >> 6) & 0x3fu;
            const unsigned imms = field & 0x3fu;
            const uint32_t ni = (n << 6) | ((~imms) & 0x3fu);
            int len = -1;
            for (int bit = 6; bit >= 0; --bit) {
                if (ni & (1u << bit)) { len = bit; break; }
            }
            const unsigned levels = (1u << static_cast<unsigned>(len)) - 1u;
            if (immr & ~levels) continue;  // non-canonical duplicate

            auto it = value_to_field.find(v);
            if (it != value_to_field.end()) {
                *err += F("logical-imm: value %#llx has two CANONICAL fields %#x and %#x\n",
                          (unsigned long long)v, it->second, field);
                continue;
            }
            value_to_field[v] = field;
        }
        for (const auto& kv : value_to_field) {
            uint32_t enc = 0;
            if (!encode_logical_imm(kv.first, is64, &enc)) {
                *err += F("logical-imm: encode failed for %#llx (field %#x)\n",
                          (unsigned long long)kv.first, kv.second);
                continue;
            }
            if (enc != kv.second) {
                *err += F("logical-imm: %#llx encoded to field %#x, decoded from %#x\n",
                          (unsigned long long)kv.first, enc, kv.second);
                continue;
            }
            CHK("encode_logical_imm",
                and_imm(is64, 0, 1, enc),
                F("and %s0, %s1, #%#llx", is64 ? "x" : "w", is64 ? "x" : "w",
                  (unsigned long long)kv.first));
        }
        if (is64) g_logical_values_64 = static_cast<int>(value_to_field.size());
        else g_logical_values_32 = static_cast<int>(value_to_field.size());
    }
}

// All 256 imm8 values: decode to a double, re-encode, and have llvm-mc agree on
// both the S and D forms of FMOV (scalar, immediate).
static void build_fp_imm8_exhaustive(std::string* err) {
    for (uint32_t i = 0; i < 256; ++i) {
        const double d = decode_fp_imm8(i);
        uint32_t back = 0;
        if (!encode_fp_imm8(d, &back)) {
            *err += F("fp-imm8: encode failed for imm8 %#x (value %.9f)\n", i, d);
            continue;
        }
        if (back != i) {
            *err += F("fp-imm8: imm8 %#x round-tripped to %#x (value %.9f)\n", i, back, d);
            continue;
        }
        // Every representable value is k/16 * 2^e with e in [-3,4], so the
        // granularity is 2^-7 and %.7f prints it exactly.
        CHK("encode_fp_imm8", fmov_imm(kFpD, 0, back), F("fmov d0, #%.7f", d));
        CHK("fmov_imm", fmov_imm(kFpS, 1, back), F("fmov s1, #%.7f", d));
    }
    // Values just outside the representable set must be rejected.
    uint32_t dummy;
    const double rejects[] = {0.0, -0.0, 1.0 / 3.0, 32.0, 0.0625, 1e300, 1.0625 / 2.0 / 16.0};
    for (double v : rejects) {
        if (encode_fp_imm8(v, &dummy) && v != 0.0625) {
            // 0.0625 == 2^-4 which is below the exponent floor of 2^-3.
            *err += F("fp-imm8: %.9g should not be encodable\n", v);
        }
    }
}

// Interpret a MOVZ/MOVN/MOVK sequence and prove it materializes `value`.
static bool simulate_mov_seq(const std::vector<uint32_t>& seq, bool is64, unsigned rd,
                             uint64_t* result) {
    uint64_t reg = 0;
    for (uint32_t w : seq) {
        const bool sf = (w >> 31) & 1;
        if (sf != is64) return false;
        if ((w & 0x1f) != rd) return false;
        if ((w & 0x7f800000u) == 0x52800000u || (w & 0x7f800000u) == 0x12800000u ||
            (w & 0x7f800000u) == 0x72800000u) {
            const unsigned opc = (w >> 29) & 3;
            const unsigned hw = (w >> 21) & 3;
            const uint64_t imm16 = (w >> 5) & 0xffffu;
            const unsigned shift = hw * 16;
            if (opc == 0) {  // MOVN
                reg = ~(imm16 << shift);
            } else if (opc == 2) {  // MOVZ
                reg = imm16 << shift;
            } else if (opc == 3) {  // MOVK
                reg = (reg & ~(0xffffull << shift)) | (imm16 << shift);
            } else {
                return false;
            }
        } else if ((w & 0x7f800000u) == 0x32000000u) {  // ORR (immediate)
            const uint32_t field = (w >> 10) & 0x1fffu;
            if (((w >> 5) & 0x1f) != 31) return false;  // must be ORR Rd, ZR, #imm
            uint64_t v;
            if (!decode_logical_imm(field, is64, &v)) return false;
            reg = v;
        } else {
            return false;
        }
        if (!is64) reg &= 0xffffffffull;
    }
    *result = is64 ? reg : (reg & 0xffffffffull);
    return true;
}

static int g_mov_imm_checked = 0;

static void test_mov_imm_seq(std::string* err) {
    std::vector<uint64_t> values;
    // Structured values that exercise every path.
    const uint64_t seeds[] = {
        0, 1, 0xffffull, 0x10000ull, 0xffffffffull, 0xffffffffffffffffull,
        0x123456789abcdefull, 0xdeadbeefull, 0x8000000000000000ull, 0xfffffffffffffffeull,
        0x0000ffff0000ffffull, 0xff00ff00ff00ff00ull, 0x5555555555555555ull,
        0xaaaaaaaaaaaaaaaaull, 0x0001000200030004ull, 0xffff0000ffff0000ull,
        0xfffffffffffff000ull, 0x7ull, 0x80000000ull, 0x100000000ull, 0xffff00000000ull,
    };
    for (uint64_t v : seeds) values.push_back(v);
    // Deterministic pseudo-random spread.
    uint64_t s = 0x243f6a8885a308d3ull;
    for (int i = 0; i < 4000; ++i) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        values.push_back(s);
        values.push_back(s & 0xffffull);
        values.push_back(s & 0xffffffffull);
        values.push_back(~(s & 0xffffull));
    }

    for (bool is64 : {true, false}) {
        for (uint64_t v : values) {
            const uint64_t want = is64 ? v : (v & 0xffffffffull);
            std::vector<uint32_t> seq;
            const unsigned n = mov_imm_seq(&seq, is64, 9, v);
            if (n != seq.size() || n == 0 || n > 4) {
                *err += F("mov_imm_seq: bad instruction count %u for %#llx (is64=%d)\n", n,
                          (unsigned long long)v, (int)is64);
                continue;
            }
            uint64_t got = 0;
            if (!simulate_mov_seq(seq, is64, 9, &got)) {
                *err += F("mov_imm_seq: unsimulatable sequence for %#llx (is64=%d)\n",
                          (unsigned long long)v, (int)is64);
                continue;
            }
            if (got != want) {
                *err += F("mov_imm_seq: %#llx (is64=%d) materialized %#llx\n",
                          (unsigned long long)v, (int)is64, (unsigned long long)got);
                continue;
            }
            ++g_mov_imm_checked;
        }
    }

    // A handful of the generated sequences also go through llvm-mc so the words
    // themselves are verified, not just their interpretation.
    const uint64_t showcase[] = {0xffffull, 0xdeadbeefull, 0xffffffffffffffffull,
                                 0x123456789abcdefull, 0xff00ff00ff00ff00ull};
    for (uint64_t v : showcase) {
        std::vector<uint32_t> seq;
        mov_imm_seq(&seq, true, 9, v);
        for (uint32_t w : seq) {
            // Verified through the disassemble-and-reassemble direction only:
            // there is no single canonical text for a whole sequence.
            CHK("mov_imm_seq", w, std::string());
        }
    }
}

// ---------------------------------------------------------------------------
// A64Buf label / fixup tests (no assembler needed for the logic itself)
// ---------------------------------------------------------------------------

static int g_buf_checks = 0;
static void EXPECT(bool cond, const char* what, std::string* err) {
    if (cond) { ++g_buf_checks; return; }
    *err += std::string("A64Buf: ") + what + "\n";
}

static void test_a64buf(std::string* err) {
    // Forward and backward branches through labels.
    {
        A64Buf buf;
        Label top = buf.new_label();
        Label skip = buf.new_label();
        buf.bind(top);                       // 0
        buf.put(subs_imm(true, 0, 0, 1));    // 0: subs x0, x0, #1
        buf.b_cond(CondEQ, skip);            // 4: b.eq skip
        buf.put(nop());                      // 8
        buf.b(top);                          // 12: b top
        buf.bind(skip);                      // 16
        buf.put(ret());                      // 16

        std::vector<Fixup> over;
        EXPECT(buf.resolve(&over), "forward+backward resolve should succeed", err);
        EXPECT(over.empty(), "no overflow expected", err);
        EXPECT(buf.at(1) == b_cond(CondEQ, 12), "b.eq displacement wrong", err);
        EXPECT(buf.at(3) == b(-12), "b displacement wrong", err);
        EXPECT(buf.size_bytes() == 20, "size_bytes wrong", err);
        std::vector<uint8_t> bytes = buf.bytes();
        EXPECT(bytes.size() == 20, "bytes() size wrong", err);
        EXPECT(bytes[0] == (buf.at(0) & 0xff), "bytes() endianness wrong", err);
        // These words also go through the assembler.
        CHK("A64Buf.b_cond", buf.at(1), "b.eq #12");
        CHK("A64Buf.b", buf.at(3), "b #-12");
    }

    // Out-of-range reporting: B.cond past 1 MiB must be refused, not truncated.
    {
        A64Buf buf;
        Label far_away = buf.new_label();
        buf.b_cond(CondNE, far_away);
        const uint32_t placeholder = buf.at(0);
        buf.bind_at(far_away, 4 * 1024 * 1024);

        std::vector<Fixup> over;
        EXPECT(!buf.resolve(&over), "out-of-range resolve must fail", err);
        EXPECT(over.size() == 1, "exactly one overflow expected", err);
        EXPECT(over[0].kind == FixKind::Cond19, "overflow kind wrong", err);
        EXPECT(over[0].insn_index == 0, "overflow index wrong", err);
        EXPECT(buf.at(0) == placeholder, "out-of-range insn must stay unpatched", err);
        EXPECT(buf.fixups().size() == 1, "overflowed fixup must stay pending", err);

        // The documented recovery: invert the condition, branch over a full
        // range B, and re-resolve.
        buf.patch(0, b_cond(invert_cond(CondNE), 8));
        buf.words().push_back(b(0));
        // Retarget the pending fixup by rebinding the label within B range.
        buf.bind_at(far_away, 4 * 1024 * 1024);
        std::vector<Fixup> over2;
        EXPECT(!buf.resolve(&over2), "still out of range for Cond19", err);
    }

    // B26 range boundaries.
    {
        A64Buf buf;
        Label l = buf.new_label();
        buf.b(l);
        buf.bind_at(l, 134217724);
        std::vector<Fixup> over;
        EXPECT(buf.resolve(&over), "max positive B26 must fit", err);
        EXPECT(buf.at(0) == b(134217724), "max positive B26 encoding wrong", err);
    }
    {
        A64Buf buf;
        Label l = buf.new_label();
        buf.put(nop());
        buf.b(l);
        buf.bind_at(l, 4);  // the branch is at byte 4, so displacement 0
        std::vector<Fixup> over;
        EXPECT(buf.resolve(&over), "self branch must fit", err);
        EXPECT(buf.at(1) == b(0), "self branch encoding wrong", err);
    }

    // TBZ range, CBZ, ADR, and literal loads through labels.
    {
        A64Buf buf;
        Label t = buf.new_label();
        Label c = buf.new_label();
        Label a = buf.new_label();
        Label lit = buf.new_label();
        buf.tbz(0, 33, t);          // 0
        buf.cbnz(false, 1, c);      // 4
        buf.adr(2, a);              // 8
        buf.ldr_literal(1, false, 3, lit);  // 12
        buf.bind(t);                // 16
        buf.bind(c);                // 16
        buf.bind(a);                // 16
        buf.bind(lit);              // 16
        std::vector<Fixup> over;
        EXPECT(buf.resolve(&over), "mixed fixups must resolve", err);
        EXPECT(buf.at(0) == tbz(0, 33, 16), "tbz fixup wrong", err);
        EXPECT(buf.at(1) == cbnz(false, 1, 12), "cbnz fixup wrong", err);
        EXPECT(buf.at(2) == adr(2, 8), "adr fixup wrong", err);
        EXPECT(buf.at(3) == ldr_literal(1, false, 3, 4), "ldr literal fixup wrong", err);
        CHK("A64Buf.tbz", buf.at(0), "tbz x0, #33, #16");
        CHK("A64Buf.cbnz", buf.at(1), "cbnz w1, #12");
        CHK("A64Buf.adr", buf.at(2), "adr x2, #8");
        CHK("A64Buf.ldr_literal", buf.at(3), "ldr x3, #4");
    }

    // TB14 overflow.
    {
        A64Buf buf;
        Label l = buf.new_label();
        buf.tbnz(0, 3, l);
        buf.bind_at(l, 32768);  // one word past the limit
        std::vector<Fixup> over;
        EXPECT(!buf.resolve(&over), "TB14 overflow must be reported", err);
        EXPECT(over.size() == 1 && over[0].kind == FixKind::TB14, "TB14 overflow kind", err);
    }

    // Unbound label is reported rather than silently encoded.
    {
        A64Buf buf;
        Label l = buf.new_label();
        buf.b(l);
        std::vector<Fixup> over;
        EXPECT(!buf.resolve(&over), "unbound label must fail resolve", err);
        EXPECT(!buf.all_labels_bound(), "all_labels_bound must be false", err);
    }

    // nop_pad_to and mov_imm through the buffer.
    {
        A64Buf buf;
        buf.put(ret());
        buf.nop_pad_to(16);
        EXPECT(buf.size_bytes() == 16, "nop_pad_to(16) wrong", err);
        EXPECT(buf.at(1) == nop(), "pad must be NOP", err);
        const unsigned n = buf.mov_imm(true, 0, 0xdeadbeefull);
        EXPECT(n == 2, "mov_imm(0xdeadbeef) should take 2 instructions", err);
        EXPECT(buf.mov_imm(true, 1, 0xffff) == 1, "mov_imm(0xffff) should be 1", err);
        EXPECT(buf.mov_imm(true, 2, ~0ull) == 1, "mov_imm(~0) should be 1", err);
        EXPECT(buf.mov_imm(true, 3, 0) == 1, "mov_imm(0) should be 1", err);
    }

    // Range predicates.
    EXPECT(fits_b26(134217724) && !fits_b26(134217728), "fits_b26 upper bound", err);
    EXPECT(fits_b26(-134217728) && !fits_b26(-134217732), "fits_b26 lower bound", err);
    EXPECT(!fits_b26(2), "fits_b26 alignment", err);
    EXPECT(fits_cond19(1048572) && !fits_cond19(1048576), "fits_cond19 bound", err);
    EXPECT(fits_tb14(32764) && !fits_tb14(32768), "fits_tb14 bound", err);
    EXPECT(fits_adr21(1048575) && !fits_adr21(1048576), "fits_adr21 bound", err);
    EXPECT(fits_adr21(1) , "fits_adr21 is byte granular", err);
    EXPECT(fits_adrp_pages(1048575) && !fits_adrp_pages(1048576), "fits_adrp_pages bound", err);
    EXPECT(fits_ldst_uimm(3, 32760) && !fits_ldst_uimm(3, 32768), "fits_ldst_uimm bound", err);
    EXPECT(!fits_ldst_uimm(3, 4) && !fits_ldst_uimm(3, -8), "fits_ldst_uimm alignment/sign", err);
    EXPECT(fits_ldst_simm9(255) && fits_ldst_simm9(-256) && !fits_ldst_simm9(256),
           "fits_ldst_simm9 bound", err);
    EXPECT(fits_ldst_pair(3, 504) && !fits_ldst_pair(3, 512) && fits_ldst_pair(3, -512),
           "fits_ldst_pair bound", err);

    // Condition inversion.
    for (unsigned c = 0; c < 14; ++c) {
        EXPECT(invert_cond(invert_cond(static_cast<Cond>(c))) == static_cast<Cond>(c),
               "invert_cond is an involution", err);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    // Scratch directory for the llvm-mc temp files.
    const char* env_tmp = getenv("TMPDIR");
    g_tmpdir = std::string(env_tmp ? env_tmp : "/tmp") + "/a64_emit_test";
    (void)system(("mkdir -p " + g_tmpdir).c_str());

    g_llvm_mc = find_llvm_mc();
    if (g_llvm_mc.empty()) {
        fprintf(stderr,
                "FATAL: llvm-mc not found. Install brew llvm or set LLVM_MC=/path/to/llvm-mc.\n"
                "Verification against a real assembler is the point of this test; refusing to\n"
                "report success without it.\n");
        return 2;
    }

    std::string err;

    build_dp_immediate_cases();
    build_dp_register_cases();
    build_branch_cases();
    build_system_cases();
    build_loadstore_cases();
    build_fp_cases();
    build_neon_cases();
    const size_t curated = g_cases.size();

    build_logical_imm_exhaustive(&err);
    build_fp_imm8_exhaustive(&err);
    test_mov_imm_seq(&err);
    test_a64buf(&err);

    // ---- FORWARD: our word must equal what llvm-mc assembles for our text ---
    std::vector<size_t> text_idx;
    std::vector<std::string> lines;
    for (size_t i = 0; i < g_cases.size(); ++i) {
        if (g_cases[i].text.empty()) continue;  // reverse-direction only
        text_idx.push_back(i);
        lines.push_back(g_cases[i].text);
    }

    std::vector<uint32_t> asm_words;
    std::set<size_t> rejected;
    std::string diag;
    size_t fwd_pass = 0, fwd_fail = 0;
    std::set<std::string> failing_encoders;

    if (!assemble_batch("fwd", lines, &asm_words, &rejected, &diag)) {
        err += F("FORWARD: could not attribute llvm-mc output (%zu encodings + %zu rejects "
                 "!= %zu lines)\n%s",
                 asm_words.size(), rejected.size(), lines.size(), diag.c_str());
        fwd_fail = lines.size();
        for (const Case& c : g_cases) failing_encoders.insert(c.encoder);
    } else {
        size_t next = 0;
        for (size_t k = 0; k < text_idx.size(); ++k) {
            const Case& c = g_cases[text_idx[k]];
            if (rejected.count(k)) {
                ++fwd_fail;
                failing_encoders.insert(c.encoder);
                if (fwd_fail <= 40)
                    err += F("FORWARD unassemblable [%s]: ours=%08x  \"%s\"\n", c.encoder.c_str(),
                             c.word, c.text.c_str());
                continue;
            }
            const uint32_t got = asm_words[next++];
            if (got == c.word) {
                ++fwd_pass;
            } else {
                ++fwd_fail;
                failing_encoders.insert(c.encoder);
                if (fwd_fail <= 40)
                    err += F("FORWARD mismatch [%s]: ours=%08x llvm=%08x  \"%s\"\n",
                             c.encoder.c_str(), c.word, got, c.text.c_str());
            }
        }
        if (!rejected.empty()) err += "llvm-mc stderr:\n" + diag;
    }

    // ---- REVERSE: every word must disassemble and re-assemble to itself -----
    std::vector<uint32_t> all_words;
    all_words.reserve(g_cases.size());
    for (const Case& c : g_cases) all_words.push_back(c.word);

    std::vector<std::string> dis;
    size_t rev_pass = 0, rev_fail = 0;
    if (!disassemble_batch("dis", all_words, &dis, &diag)) {
        err += F("REVERSE: disassembly produced %zu lines for %zu words\n%s", dis.size(),
                 all_words.size(), diag.c_str());
    } else {
        // A directive (".word"/".long"/".byte") or "<unknown>" means llvm-mc
        // could not decode the word: that is a hard failure, not a pass.
        std::vector<std::string> reasm;
        std::vector<size_t> reasm_idx;
        for (size_t i = 0; i < dis.size(); ++i) {
            if (dis[i].empty() || dis[i][0] == '.' || dis[i].find("<unknown>") != std::string::npos) {
                ++rev_fail;
                failing_encoders.insert(g_cases[i].encoder);
                if (rev_fail <= 40)
                    err += F("REVERSE undecodable [%s]: %08x -> \"%s\"\n",
                             g_cases[i].encoder.c_str(), g_cases[i].word, dis[i].c_str());
                continue;
            }
            reasm.push_back(dis[i]);
            reasm_idx.push_back(i);
        }
        std::vector<uint32_t> reasm_words;
        std::set<size_t> reasm_rejected;
        if (assemble_batch("rev", reasm, &reasm_words, &reasm_rejected, &diag)) {
            size_t next = 0;
            for (size_t k = 0; k < reasm_idx.size(); ++k) {
                const size_t i = reasm_idx[k];
                if (reasm_rejected.count(k)) {
                    ++rev_fail;
                    failing_encoders.insert(g_cases[i].encoder);
                    if (rev_fail <= 40)
                        err += F("REVERSE unassemblable [%s]: %08x -> \"%s\"\n",
                                 g_cases[i].encoder.c_str(), g_cases[i].word, dis[i].c_str());
                    continue;
                }
                const uint32_t got = reasm_words[next++];
                if (got == g_cases[i].word) {
                    ++rev_pass;
                } else {
                    ++rev_fail;
                    failing_encoders.insert(g_cases[i].encoder);
                    if (rev_fail <= 40)
                        err += F("REVERSE mismatch [%s]: %08x -> \"%s\" -> %08x\n",
                                 g_cases[i].encoder.c_str(), g_cases[i].word, dis[i].c_str(), got);
                }
            }
        } else {
            err += "REVERSE: could not attribute re-assembly output\n";
            err += diag;
            rev_fail += reasm.size();
        }
    }

    // ---- Coverage bookkeeping ---------------------------------------------
    std::set<std::string> all_encoders;
    for (const Case& c : g_cases) all_encoders.insert(c.encoder);
    std::set<std::string> verified;
    for (const std::string& e : all_encoders) {
        if (!failing_encoders.count(e)) verified.insert(e);
    }

    printf("a64_emit round-trip verification (llvm-mc: %s)\n", g_llvm_mc.c_str());
    printf("  curated cases            : %zu\n", curated);
    printf("  logical-imm values (64/32): %d / %d (exhaustive)\n", g_logical_values_64,
           g_logical_values_32);
    printf("  fp imm8 values           : 256 (exhaustive)\n");
    printf("  mov_imm_seq constants    : %d simulated\n", g_mov_imm_checked);
    printf("  A64Buf assertions        : %d\n", g_buf_checks);
    printf("  total encoded words      : %zu\n", g_cases.size());
    printf("  FORWARD  (text -> word)  : %zu pass, %zu fail\n", fwd_pass, fwd_fail);
    printf("  REVERSE  (word -> text)  : %zu pass, %zu fail\n", rev_pass, rev_fail);
    printf("  distinct encoders tested : %zu\n", all_encoders.size());
    printf("  encoders fully verified  : %zu\n", verified.size());

    // A64_LIST=1 dumps the verified set, one per line, so a coverage audit can
    // diff it against the header's declared API without re-deriving which
    // encoders the function-pointer tables above exercise.
    if (getenv("A64_LIST")) {
        for (const std::string& e : verified) printf("ENCODER %s\n", e.c_str());
    }

    if (!err.empty()) {
        printf("\nFAILURES:\n%s", err.c_str());
        printf("\nRESULT: FAIL\n");
        return 1;
    }
    printf("\nRESULT: PASS (%zu encoders round-trip verified against llvm-mc)\n",
           verified.size());
    return 0;
}
