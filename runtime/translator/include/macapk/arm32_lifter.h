// arm32_lifter.h -- decode ARM32 ELF function bytes (via Capstone) and
// emit LLVM IR text that, when compiled to arm64-apple-darwin, performs
// the equivalent computation.
//
// Stage 0 scope: a small instruction subset (PUSH, POP, MOV, ADD, SUB,
// STR, LDR, BX) sufficient to translate compiler-emitted leaf functions
// like `int add(int, int)`. The subset grows as we move to Stage 1 (real
// libgame.so coverage). The lifter's surface stays the same -- the
// caller hands in a Symbol from an Elf32Image and gets back a string of
// LLVM IR for that function.
//
// The IR uses a mem2reg-friendly pattern: a 16-slot register file in an
// alloca and a per-function virtual stack, both of which LLVM's standard
// optimizers collapse to SSA registers when run with -O2. Generated IR
// is verbose but produces tight ARM64 native code post-optimization.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "macapk/elf_reader.h"

namespace macapk::translator {

// One decoded guest instruction, recorded for DISCOVERY.
//
// Discovery needs each lifted function's true extent, and until v1.0.804 it
// recovered that by PARSING THE IR COMMENTS back out of `ir_body` (main.cpp
// scan_ir_body). That made a 917 MB-per-library text artifact load-bearing for
// correctness long after anything compiled it, and coupled discovery to the
// exact spelling of a comment: reformat the comment and function extents move
// silently, which on this project means a helper goes unlifted, its `bl` hits
// a panic stub, and the JVM heap corrupts. The lifter knows all of this at
// decode time, so it now says so directly.
struct DecodedInsn {
    uint32_t addr;
    // Mnemonic is one of the unambiguous return idioms (bx / pop / blx).
    // Deliberately a flag rather than the mnemonic string: the only consumer
    // asks exactly this question, and storing ~2M short strings per library
    // would trade one memory problem for another.
    bool     ret_idiom;
};

struct LiftedFunction {
    std::string name;
    // LLVM IR text for one function. EMPTY unless IR emission was explicitly
    // requested (--keep-ir): since v1.0.802 nothing compiles it. Use `insns`
    // for anything a later pass needs to know about the decode.
    std::string ir_body;
    // Every guest instruction the lifter decoded for this body, in decode
    // order. Populated ALWAYS, including when ir_body is empty.
    std::vector<DecodedInsn> insns;
    bool        success;
    std::string error;     // populated on failure; ir_body unspecified
};

class Arm32Lifter {
public:
    Arm32Lifter();
    ~Arm32Lifter();

    Arm32Lifter(const Arm32Lifter&) = delete;
    Arm32Lifter& operator=(const Arm32Lifter&) = delete;

    // Lift a single function from the loaded ELF image into LLVM IR.
    // The IR contains only the function definition; external call
    // targets accumulate in `external_targets()` and the caller emits
    // a single de-duplicated declare block at module scope.
    LiftedFunction lift_function(const Elf32Image& img, const Symbol& sym);

    // Lift an UNsymbolled function. Used by the discovery loop in
    // the translator's main: any BL / B-extern target that falls in
    // an executable PT_LOAD segment but has no corresponding symbol
    // table entry gets lifted as a synthetic. We cap the lift at
    // `size` bytes (the caller computes that from the next known
    // function start, or to segment end). The function exports
    // under the synthesized name "__macapk_synth_<hex_vaddr>".
    LiftedFunction lift_synthetic(const Elf32Image& img,
                                   uint32_t vaddr, uint32_t size,
                                   bool is_thumb);

    // Union of every BL / B-extern target seen across all
    // lift_function calls. Caller emits matching `declare i32
    // @__macapk_target_<hex>(i32, i32, i32, i32)` lines once at
    // module scope.
    const std::unordered_set<uint32_t>& external_targets() const;

    // Subset of external_targets() whose provenance is an actual
    // BL / BLX #imm instruction (a direct procedure CALL). These are
    // authoritative function entries per the ARM PCS: discovery must
    // lift them even when a heuristic synth's SKIPDATA over-run
    // wrongly recorded their address range as "inside its body".
    const std::unordered_set<uint32_t>& external_bl_targets() const;

    // v1.0.814: AUTHORITATIVE ISA mode for a direct-call target, taken from
    // the CALL SITE instead of sniffed from the callee's bytes.
    //
    // `BL #imm` never changes instruction set, so the callee runs in the
    // caller's mode; `BLX #imm` is exactly the interworking form, so the
    // callee runs in the opposite mode. Both are exact, and byte sniffing is
    // not: Thumb-2 `push.w {r4-r10,lr}` encodes as `e92d47f0`, byte-identical
    // to ARM `STMDB SP!,{...}`, so an unsymboled Thumb helper reached only by
    // BL gets decoded as ARM and its bytes then produce plausible nonsense.
    //
    // Returns nullopt when nothing is known OR when two call sites disagree.
    // A disagreement is NOT resolved by picking one -- callers fall back to
    // their existing heuristics, which is strictly no worse than before.
    std::optional<bool> call_target_thumb(uint32_t vaddr) const;

    // Map of (function entry vaddr -> exported name) for every symbol
    // we successfully lifted. Caller uses this to emit
    //   `@__macapk_target_<hex> = alias ..., ptr @<name>`
    // for each target that actually resolved to a lifted function in
    // this module, so intra-.so calls don't go through dynamic lookup.
    const std::unordered_map<uint32_t, std::string>&
    lifted_address_map() const;

    // Manually register a (vaddr -> exported name) mapping. Used
    // when main.cpp emits an override stub instead of going through
    // lift_function (e.g. neutered C++ exception runtime helpers).
    // The alias generator then sees the address as "local lifted"
    // and emits `__macapk_target_<addr>` as a real alias to the
    // override symbol, bypassing the panic-stub fallback.
    void register_lifted_function(uint32_t addr, const std::string& name);

    // Register a PLT vaddr as a "soft-float double-returning" math
    // import (sin, cos, tan, sqrt, etc.). emit_bl for these targets
    // emits an i64-returning call and splits the result into r0/r1
    // -- the ARM soft-float double-return ABI -- so the next
    // `vmov dN, r0, r1` in the caller correctly reconstructs the
    // result. Without this, only r0 gets the LOW 32 bits and the
    // caller reads stale r1, producing wrong projections (cocos2d-x
    // v2's setProjection(3D) computes cot(45deg)=1 instead of
    // cot(30deg)=1.732 because sin/cos return the input angle).
    void register_softfloat_double_import_plt(uint32_t plt_addr);
    // (2026-09-27: register_plt_local_redirect is retired with the
    // MACAPK_PLT_REDIRECT* knobs; intra-module PLT calls are bound through
    // the GOT and Elf32Image::plt_local_bindings, as Bionic binds them. See
    // docs/plt-redirect-knobs-retired_2026-09-27.md.)

    // Per-image load bias B (a guest-arena byte offset). When this image
    // is the 2nd+ ARM32 .so loaded by an APK, the runtime assigns it a
    // distinct B so its PT_LOAD segments do not collide with another .so
    // mapped into the SAME shared guest arena at overlapping link-time
    // vaddrs (the multi-.so collision: libarc.so + libarc-freetype.so both
    // start at vaddr 0). The lifter then materializes EVERY runtime guest
    // pointer as (B + vaddr) so g_guest_base + (B + vaddr) is unique per
    // image and cross-image pointers (full unified-space values) stay
    // unambiguous. B defaults to 0 -> the single-.so / main-lib path is
    // bit-identical. See the install_segments / register_function emission
    // (main.cpp) and the R_ARM_RELATIVE/GLOB_DAT relocation writes
    // (elf_reader.cpp), which add the SAME B.
    void set_load_bias(uint32_t bias);

    // When true, an unsupported instruction inside an otherwise
    // lift-able function fails the whole function. When false
    // (default), we emit a comment marker and continue, producing a
    // valid module at the cost of broken semantics for that one op.
    // The lenient mode is right for "lift everything we can; iterate
    // on whatever breaks at runtime."
    void set_strict(bool s);

    // Emit LLVM IR text into LiftedFunction::ir_body. DEFAULT OFF.
    // Nothing compiles the IR since v1.0.802, and formatting it costs
    // ~half of arm32rc's translate time (917 MB of text per library on
    // HCR 1.43), so it is produced only for --keep-ir. Discovery does
    // NOT depend on it -- see LiftedFunction::insns.
    void set_emit_ir(bool on);

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace macapk::translator
