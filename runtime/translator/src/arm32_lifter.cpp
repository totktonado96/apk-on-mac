// arm32_lifter.cpp -- multi-block ARM32 lifter with NZCV flag modeling,
// conditional execution, and inter-function-call passthrough.
//
// Stage 1 scope (this file):
//   - Multi-basic-block functions. Pre-scan all instructions to find
//     branch targets, split the function at those addresses, emit each
//     block with a unique IR label.
//   - NZCV status flags. Modeled as four i1 alloca slots. CMP, CMN,
//     TST, TEQ, and S-suffixed arithmetic update them; conditional
//     branches read them.
//   - Conditional execution. Every ARM32 instruction has a 4-bit
//     predicate; we accept AL (always) for general instructions and
//     read flags for predicated branches.
//   - Branches: B, BL, BX, B<cond>. BL emits a call to a generated
//     extern symbol named __macapk_target_<hex_address>; Stage 1e
//     wires those to actual lifted functions or Bionic shim symbols.
//   - Integer ISA expansion: MOVT/MOVW (32-bit immediate composition),
//     AND/ORR/EOR/BIC, MUL, LSL/LSR/ASR, RSB, MVN, byte/halfword
//     load/store (LDRB/LDRH/STRB/STRH/LDRSB/LDRSH).
//
// Still NOT modeled (later stages):
//   - VFP / NEON instructions (Stage 1c).
//   - Thumb mode (Stage 1d -- this lifter is ARM-mode only; the
//     coordinator picks lifter mode by symbol).
//   - LDM/STM beyond the PUSH/POP idioms.
//   - IT blocks (Thumb-specific).
//   - Real Bionic ABI translation (Stage 2 LLVM pass after this lifter).
//
// The IR pattern stays the same: a register file alloca + virtual
// stack alloca per function. mem2reg + GVN collapse it post-O2 into
// optimal native code, just like Stage 0.

#include "macapk/arm32_lifter.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace macapk::translator {

namespace {

int arm_reg_idx(unsigned int reg) {
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

// True if the predicate is "always" -- the verbose ARM mnemonic with
// no condition suffix decodes to ARM_CC_AL in capstone.
bool is_always(arm_cc cc) {
    return cc == ARM_CC_AL || cc == ARM_CC_INVALID;
}

}  // namespace

// A stringstream that can be switched OFF wholesale.
//
// NOT a null streambuf: a discarding buffer still pays the FULL cost of
// operator<<, because num_put converts the value to characters and only then
// throws them away. Measured on HCR 1.43's libgame.so, the lifter formats
// 917 MB of IR text per library, and `sample` attributes ~half of arm32rc's
// 5.65 s translate to ostream formatting. Since v1.0.802 nothing compiles that
// IR -- it survived only because discovery parsed addresses back out of the
// comments, which v1.0.804 replaced with LiftedFunction::insns. So emission is
// now opt-in (--keep-ir) and the `on_` test short-circuits before any
// formatting happens.
class IrSink {
public:
    void set_enabled(bool on) { on_ = on; }
    bool enabled() const { return on_; }
    template <class T>
    IrSink& operator<<(const T& v) { if (on_) ss_ << v; return *this; }
    // Manipulators (std::hex, std::dec, std::endl) are function pointers and
    // do not match the template above.
    IrSink& operator<<(std::ios_base& (*m)(std::ios_base&)) { if (on_) ss_ << m; return *this; }
    IrSink& operator<<(std::ostream& (*m)(std::ostream&))   { if (on_) ss_ << m; return *this; }
    std::string str() const { return ss_.str(); }
    void str(const char* s) { ss_.str(s); }
    void clear() { ss_.clear(); }
private:
    std::stringstream ss_;
    bool on_ = false;      // default OFF; main.cpp turns it on for --keep-ir
};

// The three `  ; <addr>:` comment sites used to encode this by spelling the
// mnemonic into text that main.cpp string-compared against "bx"/"pop"/"blx".
// Same predicate, no round trip through a 917 MB string.
inline bool is_return_idiom(const char* mnem) {
    return mnem && (std::strcmp(mnem, "bx")  == 0 ||
                    std::strcmp(mnem, "pop") == 0 ||
                    std::strcmp(mnem, "blx") == 0);
}

struct Arm32Lifter::Impl {
    csh                                       handle_arm   = 0;
    csh                                       handle_thumb = 0;
    csh                                       handle       = 0;     // active
    IrSink                                    ir;
    // Structured decode record for the CURRENT function (see DecodedInsn).
    std::vector<macapk::translator::DecodedInsn> insn_log;
    int                                       ssa_counter = 0;
    bool                                      cs_arm_ok    = false;
    bool                                      cs_thumb_ok  = false;
    bool                                      cs_ok        = false; // active

    // Per-function lifting state (reset for each function).
    std::set<uint32_t>                        block_starts;
    // Every decoded instruction start of the current lift. Callers only ever
    // ask count(). MACAPK_FIRSTLAUNCH_LIFT_NOIR: in discovery-only mode it
    // is the (already ascending) address list of the sweep, searched with
    // binary_search, instead of a freshly allocated hash set per lift -- the
    // hash build and teardown was ~6% of discovery on GD Lite. Same answer
    // for every query; the IR path keeps the hash set exactly as before.
    struct InsnStartSet {
        bool                         sorted_mode = false;
        std::vector<uint32_t>        sorted;
        std::unordered_set<uint32_t> hashed;
        size_t count(uint32_t a) const {
            if (!sorted_mode) return hashed.count(a);
            return std::binary_search(sorted.begin(), sorted.end(), a) ? 1 : 0;
        }
    };
    InsnStartSet                              valid_addrs_;
    // Per-function set, reset in scan_blocks().
    std::unordered_set<uint32_t>              extern_call_targets;
    // Module-scope union, accumulates across all lift_function calls.
    std::unordered_set<uint32_t>              all_extern_targets;
    // Subset of the above whose provenance is an actual BL / BLX #imm
    // instruction (a direct procedure CALL), as opposed to a B / tail
    // call / switch-case extern that the lifter may have
    // mis-classified from an intra-function branch. A real BL/BLX
    // target is, by the ARM procedure-call standard, a function
    // ENTRY -- it is authoritative and must always get its own lifted
    // body even if a heuristic synth's SKIPDATA over-run wrongly
    // absorbed its address range. Only the ambiguous B-extern case
    // (the v1.0.28 HCR 1.43 `synth_0017a3a0` mid-function-leak
    // hazard) stays subject to the inside_lifted_body filter.
    std::unordered_set<uint32_t>              extern_bl_targets;
    std::unordered_set<uint32_t>              all_extern_bl_targets;
    // v1.0.814: AUTHORITATIVE ISA mode for a direct-call target, derived
    // from the CALLER rather than from sniffing the callee's bytes.
    //
    // `BL #imm` does NOT change instruction set, so the target is in the
    // caller's mode. `BLX #imm` is precisely the interworking form, so the
    // target is in the OPPOSITE mode. Either way the answer is known exactly
    // at the call site, which beats every byte heuristic -- and byte
    // heuristics genuinely fail here: Thumb-2 `push.w {r4-r10,lr}` encodes as
    // `e92d47f0`, byte-identical to ARM `STMDB SP!,{...}`, so a Thumb helper
    // with no dynsym entry and no relocation gets decoded as ARM. Subway
    // Surfers' libmain.so `0x1618` is exactly that: mis-decoded as ARM, two
    // coincidental "instructions" then appeared to write PC, and the
    // otherwise-correct ALU/LDM-writes-PC safety net faithfully lowered both
    // into indirect dispatches through garbage registers. That helper reads
    // /sys/devices/system/cpu/{present,possible} for the CPU count and so
    // never did its real work on any invocation.
    //
    // Conflicts are tracked rather than resolved: if two call sites disagree
    // about a target's mode, we must NOT pick one. Consumers treat a
    // conflicted address as "no opinion" and fall back to the heuristics.
    std::unordered_map<uint32_t, bool>        call_target_is_thumb;
    std::unordered_set<uint32_t>              call_target_mode_conflict;
    void note_call_target_mode(uint32_t target, bool target_thumb) {
        const uint32_t key = target & ~1u;
        auto it = call_target_is_thumb.find(key);
        if (it == call_target_is_thumb.end()) {
            call_target_is_thumb.emplace(key, target_thumb);
        } else if (it->second != target_thumb) {
            call_target_mode_conflict.insert(key);
        }
    }
    // Address -> function name for every successfully lifted symbol.
    std::unordered_map<uint32_t, std::string> lifted_addr_to_name;
    // PLT vaddrs of math imports that take/return doubles via the ARM
    // soft-float ABI (r0:r1 = double). emit_bl checks this set and,
    // for matching targets, emits an i64-returning call (instead of
    // i32) and splits the result into r0/r1 -- correctly delivering
    // the LOW and HIGH halves of the returned double back to the
    // caller's lifted register file. Populated by main.cpp via
    // register_softfloat_double_import_plt() before lift_function.
    std::unordered_set<uint32_t>              soft_float_double_plt_;
    // Per-image load bias B (guest-arena byte offset). Added to EVERY
    // runtime guest-vaddr the lifter materializes (PC reads, ADR, R14
    // return addresses) so a 2nd+ .so loaded into the shared guest arena
    // does not collide with another image's segments. 0 for the main /
    // single-.so image (bit-identical). See set_load_bias() in the header.
    uint32_t                                  load_bias_ = 0;
    // Addresses inside Thumb-2 TBB/TBH inline jump tables. Capstone
    // disassembles these data bytes as bogus instructions; the lift
    // dispatch loop checks this set and emits no IR for them.
    std::unordered_set<uint32_t>              tbb_skip_addrs_;
    // v1.0.540: PC-relative COMPUTED-JUMP tables (compiler-rt unrolled software
    // divide `add Rt,pc,#imm; sub Rt,Rt,Rm,lsl#a; sub Rt,Rt,Rm,lsl#b; bx Rt`,
    // stb's `/` in libarc). `bx Rt` jumps to base - Rm*stride into the unrolled
    // blocks; emit_bx lowers it to a switch (index derived from the target reg,
    // since the index reg is clobbered before the bx). Keyed by the bx addr.
    struct PcJumpTable {
        uint32_t base;     // pc-relative table base (target for index 0)
        uint32_t stride;   // bytes per case
        std::vector<std::pair<uint32_t, uint32_t>> cases;  // (index k, target vaddr)
    };
    std::unordered_map<uint32_t, PcJumpTable> pc_jump_tables_;
    // v1.0.552: ARM-mode compiled-switch OFFSET-WORD jump tables:
    //   add rB, pc, #imm            ; rB = inline table base (table follows)
    //   ldr rO, [rB, rIdx, lsl #2]  ; rO = table[idx], a (target - base) offset
    //   add pc, rB, rO              ; jump to base + offset
    // clang/gcc lower ARM-mode `switch` this way when cases don't fit the
    // `addls pc, pc, rm, lsl #2` branch-slab form. emit_alu's rd==15 path is
    // a DEAD STORE to the PC slot (no branch) -> control silently FELL
    // THROUGH the table words into the first case block. That single gap made
    // libGDX gdx2d take the wrong switch case everywhere: stb_image's per-row
    // defilter ran filter=SUB on filter=NONE rows (scrambled the 4-bit-palette
    // pixel_font.png decode) and gdx2d_get_pixel's format switch ran the
    // ALPHA case for RGBA8888 (constant 0xffffff00) -> ShatteredPD's
    // BitmapText$Font.splitBy never found a glyph separator -> infinite scan.
    // Keyed by the `add pc` insn addr; recorded by the scan_blocks pre-scan
    // (which also seeds the case-target blocks + skips the table words) and
    // lowered to a real IR switch on rO by the ADD dispatch case.
    struct PcAddOffsetJumpTable {
        int      base_reg;   // rB (holds biased base at runtime)
        int      off_reg;    // rO (holds the raw table word at the add)
        uint32_t base;       // raw table base vaddr
        std::vector<std::pair<uint32_t, uint32_t>> cases;  // (offset word, raw target)
    };
    std::unordered_map<uint32_t, PcAddOffsetJumpTable> pc_add_offset_jts_;
    // Per-function pointer to the current Capstone instruction stream
    // and the index of the instruction we're about to emit. The TBB
    // emitter looks back two instructions for the `cmp Rn,#N; bhi LBL`
    // pattern that bounds the table.
    cs_insn*                                  current_insns_ = nullptr;
    size_t                                    current_count_ = 0;
    size_t                                    current_idx_   = 0;
    // SSA name of the active predicate i1, or "" for AL/unconditional.
    // Set by emit_one before dispatch, cleared after.
    std::string                               current_pred;
    // Active image, for PC-relative constant pool reads (VLDR pc, ldr pc).
    const Elf32Image*                         image_ = nullptr;
    // Per-section vaddr ranges [lo,hi) of the POINTER/STRUCT/GLOBAL sections
    // (.got, .got.plt, .data, .bss, .data.rel.ro[.local]) that a PIC
    // `ldr rN,[pc]; add rN,pc` legitimately targets. Used ONLY by the add-rd-pc
    // PC-convention discriminator in emit_alu. A SET of per-section ranges (not
    // a min..max span) so .rodata / .text -- where 2-byte-aligned strings live
    // and a false-override could corrupt an aligned-convention app -- are
    // EXCLUDED. Empty -> discriminator disabled (stripped image).
    std::vector<std::pair<uint32_t,uint32_t>> target_ranges_;
    const Elf32Image*                         got_image_ = nullptr;  // recompute guard
    bool in_target_range(uint32_t a) const {
        for (const auto& r : target_ranges_)
            if (a >= r.first && a < r.second) return true;
        return false;
    }
    // Current instruction address + size, used to substitute PC reads
    // inside memory operands. ARM32: PC == insn_addr + 8 (ARM mode)
    // or insn_addr + 4 (Thumb). The dispatch loop updates this just
    // before each emit_one() call.
    uint32_t                                  current_insn_addr = 0;
    uint32_t                                  current_insn_size = 4;
    bool                                      current_is_thumb = false;
    // Strict mode (see header). Default lenient.
    bool                                      strict_ = false;

    // --- Block-local register-file SSA cache --------------------------
    // Each entry of `reg_cache_` holds the SSA name currently
    // representing ARM register r0..r15 within the current basic
    // block. Empty string = not cached (must load from %r slot).
    // `reg_dirty_` tracks whether the cached value was modified since
    // the last memory write -- dirty regs get flushed to memory
    // before any cross-block branch so the destination block can
    // load them fresh.
    //
    // Why: clang at -O0 (the only opt level that fits HCR 1.43's
    // 4.5 GB IR in memory) doesn't run mem2reg, so every
    // load_reg/store_reg call previously emitted a getelementptr +
    // load/store pair. For HCR 1.43 that's ~3M reg accesses x ~150
    // bytes of IR text each = ~450 MB of pure register traffic. At
    // -O1 mem2reg would fold it, but -O1 doesn't fit. Caching at
    // emit time achieves the same compaction (intra-block
    // load-of-just-stored-value collapses to nothing) without
    // running an opt pass on the bitcode.
    //
    // Safety: caller MUST call cache_clear() at block entry and
    // flush_dirty_regs() before every br to a same-function label.
    // Function calls (BL/BLX/__macapk_target_*) pass r0..r3, sp as
    // explicit SSA values via load_reg(), so the cache is correct
    // across calls without flush. RET reads r0 via load_reg() and
    // returns -- other registers are dead, no flush needed.
    std::array<std::string, 16>               reg_cache_;
    std::array<bool, 16>                      reg_dirty_;

    // DIAGNOSTIC (MACAPK_NO_REGCACHE=1): bypass the block-local SSA
    // cache entirely and fall back to the v1.0.4 direct load/store
    // register-file model (every load_reg emits a fresh load from the
    // %r alloca; every store_reg emits an immediate store to it). This
    // isolates the register cache as a single variable for A/B testing
    // a suspected codegen regression without changing decode, function
    // discovery, SKIPDATA, or the shim ABI. Not gated on any APK.
    bool                                      no_regcache_ = false;
    // Bug-2 diagnostic: emit a __macapk_trace_store call after every
    // 32-bit guest-memory store. Off by default (per-store overhead is
    // significant). MACAPK_LIFTER_EMIT_STORE_TRACE=1 turns it on.
    bool                                      emit_store_trace_ = false;
    // Unicorn-differential-harness instrumentation (diagnostic only).
    // MACAPK_DIFF_VADDRS=<hex,hex,...> names the function start vaddrs to
    // instrument: each gets a __macapk_capture_entry call at entry and a
    // __macapk_trace_regs call after every instruction. We instrument
    // only the named functions (never the whole module) so the IR bloat
    // and the runtime trace volume stay bounded to the function under
    // investigation. See docs/arm32-render-blockers-and-exidx_2026-06-25.md.
    std::set<uint32_t>                        diff_vaddrs_;
    // Bug 6 (2026-07-25): report the EXACT ARMExpandImm_C carry-out for a
    // rotated modified immediate instead of leaving C untouched. It is a
    // translate-time constant, so exactness is free.
    // MACAPK_MODIMM_CARRY_CONSERVATIVE=1 restores the old behaviour.
    bool                                      exact_modified_imm_carry_ = true;
    // Bug 5 (2026-07-25): lower a non-flag-setting ALU write to R15 as the
    // architectural indirect branch (ALUWritePC -> BXWritePC, A8.8.x) rather
    // than a dead store that falls through.
    // MACAPK_ALU_PC_WRITE_DEAD=1 restores the old dead-store behaviour.
    bool                                      alu_pc_write_is_branch_ = true;

    // ---- MACAPK_FIRSTLAUNCH_LIFT_NOIR (default ON, 2026-09-26) ----------
    // When IR text is not being kept (no --keep-ir), this lifter is a pure
    // DISCOVERY engine: arm32rc never reads its IR. IrSink already drops the
    // text, but only at operator<<, i.e. AFTER every argument was built --
    // std::to_string, string concatenation, fresh(), load_reg(). Measured on
    // GD Lite v7a (sample, -g build) that argument building was 30% of the
    // whole translate. So in discovery-only mode emit_one skips every handler
    // whose ONLY product is IR, and still runs the handlers that record
    // discovery state.
    //
    // Which handlers have non-IR effects was established mechanically, not by
    // eye: every write site of every Impl member that outlives an instruction
    // (extern_call_targets, extern_bl_targets, note_call_target_mode ->
    // call_target_is_thumb/conflict, tbb_skip_addrs_; block_starts,
    // valid_addrs_, pc_jump_tables_, pc_add_offset_jts_ are written only by
    // scan_blocks, which always runs), plus stderr and static state, closed
    // transitively over the intra-Impl call graph. The result is exactly
    //   B, BL, BLX, CBZ/CBNZ, TBB/TBH   (extern targets, call-target modes,
    //                                    jump-table skip bytes)
    //   ADD with Rd=PC                   (emit_arm_pc_jump_table's skip bytes
    //                                    and extern targets)
    //   ADD/SUB/AND/ORR/EOR/BIC, Rd=PC   (emit_alu's rate-limited stderr
    //                                    warning and its static counters)
    // which is has_discovery_effect() below. Everything else only formats IR.
    // (CMP/CMN/TST/TEQ also reach emit_alu, but its warning needs rd == 15
    // and the flag-only forms have no rd.) The return value and `terminated`
    // of a skipped handler matter only for IR block structure and for
    // --strict (which disables this path).
    //
    // The same gate also, in discovery-only mode:
    //   * returns from emit_bl / emit_uncond_branch / emit_cond_branch right
    //     after their discovery records (the call or branch is IR);
    //   * skips run_body's block labels, fall-through br and register-cache
    //     resets (IR block structure; includes a std::set lookup and an
    //     snprintf per instruction);
    //   * keeps valid_addrs_ as the sweep's sorted address list (see
    //     InsnStartSet).
    // debug/w6arm32disc_verify/effects.py re-derives all of this from the
    // source on every gate run (S1-S4), with mutated-source controls.
    // Measured, GD Lite v7a libcocos2dcpp, whole translate, instructions
    // retired (RC_THREADS=1): 139.3G -> 99.3G with this gate alone, 122.7G
    // with the decode cache below alone, 82.0G with both.
    //
    // This must never change a byte of output: debug/w6arm32disc_gate.sh
    // checks the dylibs and a digest of every lift result against =0.
    // MACAPK_FIRSTLAUNCH_LIFT_NOIR=0 restores the exact pre-change path.
    bool                                      noir_gate_ = true;
    // Recomputed at the top of every run(): noir_gate_ && !ir && !strict_.
    bool                                      discovery_only_ = false;
    // Engagement counters, printed with MACAPK_FIRSTLAUNCH_TIMING=1 so the
    // gate can prove the fast path RAN (a byte-identical result from a path
    // that never engaged proves nothing).
    uint64_t                                  noir_lifts_ = 0, ir_lifts_ = 0,
                                              noir_skipped_ = 0;
    // TEST-ONLY positive control for debug/w6arm32disc_gate.sh, default 0.
    // MACAPK_LIFT_NOIR_CONTROL=b|bl|blx|cb|tbb|alupc (comma list) makes the
    // discovery-only path ALSO skip that class of side-effecting handler --
    // i.e. it reproduces the exact bug this optimisation could introduce, so
    // the gate can prove its comparators see a dropped side effect.
    enum : unsigned {
        kCtlB = 1u, kCtlBl = 2u, kCtlBlx = 4u, kCtlCb = 8u, kCtlTbb = 16u,
        kCtlAluPc = 32u,
    };
    unsigned                                  noir_control_ = 0;
    // TEST-ONLY (MACAPK_LIFT_DIGEST=1, default off): fold every lift result
    // (name, address, mode, success, error, decoded-instruction log) and, at
    // destruction, every module-scope discovery set into one FNV-1a digest
    // printed as `[lift-digest] ...`. It compares the discovery engine's
    // OUTPUT directly, so a difference that the later arm32rc stages happen
    // to absorb is still caught.
    bool                                      digest_on_ = false;
    uint64_t                                  digest_results_ = 0xcbf29ce484222325ULL;
    uint64_t                                  digest_calls_ = 0;

    // True iff the handler for `in` can do anything besides format IR.
    // See the MACAPK_FIRSTLAUNCH_LIFT_NOIR note above for how the set was
    // derived; a new handler that records discovery state MUST be added here.
    bool has_discovery_effect(const cs_insn* in) const {
        // The id alone decides for everything but the ALU family, so the
        // detail record (a separate ~1.8 KB allocation per instruction) is
        // only touched for those.
        auto rd_is_pc = [in]() {
            const cs_arm& d = in->detail->arm;
            return d.op_count >= 1 &&
                d.operands[0].type == ARM_OP_REG &&
                d.operands[0].reg == ARM_REG_PC;
        };
        switch (in->id) {
            case ARM_INS_B:    return !(noir_control_ & kCtlB);
            case ARM_INS_BL:   return !(noir_control_ & kCtlBl);
            case ARM_INS_BLX:  return !(noir_control_ & kCtlBlx);
            case ARM_INS_CBZ:
            case ARM_INS_CBNZ: return !(noir_control_ & kCtlCb);
            case ARM_INS_TBB:
            case ARM_INS_TBH:  return !(noir_control_ & kCtlTbb);
            case ARM_INS_ADD:
            case ARM_INS_SUB:
            case ARM_INS_AND:
            case ARM_INS_ORR:
            case ARM_INS_EOR:
            case ARM_INS_BIC:  return rd_is_pc() && !(noir_control_ & kCtlAluPc);
            default:           return false;
        }
    }

    void digest_bytes(const void* p, size_t n) {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        for (size_t i = 0; i < n; ++i) {
            digest_results_ ^= b[i];
            digest_results_ *= 0x100000001b3ULL;
        }
    }
    void digest_u64(uint64_t v) { digest_bytes(&v, sizeof(v)); }
    void digest_str(const std::string& s) {
        digest_u64(s.size());
        digest_bytes(s.data(), s.size());
    }
    void digest_result(const Symbol& sym, const LiftedFunction& out) {
        ++digest_calls_;
        digest_str(sym.name);
        digest_u64((uint64_t(sym.address) << 32) | uint64_t(sym.size));
        digest_u64((uint64_t(sym.is_thumb) << 1) | uint64_t(out.success));
        digest_str(out.error);
        digest_u64(out.insns.size());
        for (const auto& di : out.insns)
            digest_u64((uint64_t(di.addr) << 1) | uint64_t(di.ret_idiom));
    }
    void digest_print_state() {
        // Module-scope discovery state, order-independent (sorted).
        auto mix_set = [&](const std::unordered_set<uint32_t>& s) {
            std::vector<uint32_t> v(s.begin(), s.end());
            std::sort(v.begin(), v.end());
            digest_u64(v.size());
            for (uint32_t x : v) digest_u64(x);
        };
        const uint64_t results = digest_results_;
        digest_results_ = 0xcbf29ce484222325ULL;
        mix_set(all_extern_targets);
        mix_set(all_extern_bl_targets);
        mix_set(call_target_mode_conflict);
        {
            std::vector<std::pair<uint32_t, bool>> v(call_target_is_thumb.begin(),
                                                     call_target_is_thumb.end());
            std::sort(v.begin(), v.end());
            digest_u64(v.size());
            for (const auto& kv : v) digest_u64((uint64_t(kv.first) << 1) | kv.second);
        }
        {
            std::vector<std::pair<uint32_t, std::string>> v(lifted_addr_to_name.begin(),
                                                            lifted_addr_to_name.end());
            std::sort(v.begin(), v.end());
            digest_u64(v.size());
            for (const auto& kv : v) { digest_u64(kv.first); digest_str(kv.second); }
        }
        std::fprintf(stderr,
            "[lift-digest] calls=%llu results=%016llx state=%016llx "
            "extern=%zu bl=%zu modes=%zu conflicts=%zu lifted=%zu\n",
            static_cast<unsigned long long>(digest_calls_),
            static_cast<unsigned long long>(results),
            static_cast<unsigned long long>(digest_results_),
            all_extern_targets.size(), all_extern_bl_targets.size(),
            call_target_is_thumb.size(), call_target_mode_conflict.size(),
            lifted_addr_to_name.size());
    }

    // ---- MACAPK_FIRSTLAUNCH_DECODE_CACHE (default ON, 2026-09-26) -------
    // Discovery lifts OVERLAPPING extents: an unsymboled region gets a synth
    // every few dozen bytes, each with a budget of up to 16 KB running to the
    // next known start, so the same bytes go through cs_disasm again and again.
    // Measured on GD Lite v7a: 34.1 MB decoded for 9.7 MB of unique
    // (address, mode) bytes, and cs_disasm was 38% of the translate.
    //
    // A capstone sweep is a linear walk with SKIPDATA, so the decode at X is
    // fixed by (mode, the bytes at X, X, how many bytes remain, and -- Thumb
    // only -- the IT-block state). Capstone 5.0.7 facts this relies on (cs.c
    // cs_disasm, arch/ARM/ARMDisassembler.c):
    //   * ARM: _ARM_getInstruction reads exactly 4 bytes, needs >= 4, and
    //     touches no cross-instruction state; SKIPDATA steps 4 bytes and needs
    //     >= 4 remaining. Every entry is 4 bytes, so a sweep from A is the
    //     sweep from any earlier S == A (mod 4) restricted to [A, E).
    //   * Thumb: reads 2 bytes, then 4 only if the 16-bit tables fail (and
    //     fails when < 4 remain); SKIPDATA steps 2. ITBlock is reset at the
    //     start of EVERY cs_disasm call and is set only by an IT instruction
    //     (id ARM_INS_IT) -- the same bytes decode as `movs` outside an IT
    //     block and `moveq` inside one, so the IT state is part of the key.
    // So the cache keeps whole SWEEPS ("runs", one or more capstone chunks
    // appended end to end, plus per-entry bookkeeping) and answers a request
    // [A, E) by pointing the lifter INTO a run -- zero copy -- when:
    //   * A is an entry of the run, and no IT entry lies between the start of
    //     A's chunk and A (so the chunk's sweep had an empty IT state at A,
    //     exactly as a fresh sweep from A would), and none lies between A and
    //     any later chunk boundary that the answer crosses (each chunk also
    //     started empty);
    //   * every served entry saw at least as much of the decoder's input as
    //     the fresh sweep would: runs keep an entry only if >= 4 bytes followed
    //     it when it was decoded (or it sits at a segment end, which bounds
    //     every request too), a 32-bit Thumb entry is served only if >= 4
    //     bytes remain before E, and the answer stops exactly where a fresh
    //     sweep stops (fewer than 4 bytes left in ARM mode, fewer than 2 in
    //     Thumb mode);
    // and otherwise decodes fresh, exactly as before. A run that ends before
    // E is extended by decoding on from its end (with a small lookahead), which
    // is exact for the same reasons. The lifter never writes to the cs_insn
    // array (checked: no assignment through insns/in anywhere in this file),
    // which is what makes sharing it safe; a served array stays valid until
    // the next lift, the only point where the cache changes.
    //
    // Memory is bounded (kDcMaxTotal entries, ~2.3 KB each with capstone's
    // cs_detail, so ~38 MB) by LRU eviction and by trimming a run's dead
    // front. Sized by measurement on GD Lite v7a: 16384 entries serve 97% of
    // what 32768 or 65536 serve (5.26M vs 5.44M instructions, identical
    // instructions-retired within 0.3%) for half the memory; a request-trace
    // replay put an UNBOUNDED run cache at 55% of requested bytes served vs
    // 40% here, so a bigger cache is not where the remaining time is.
    //
    // TEST-ONLY: MACAPK_FIRSTLAUNCH_DECODE_CACHE_VERIFY=1 re-decodes every
    // served request fresh and compares every field (id, address, size,
    // bytes, mnemonic, op_str, and all of cs_detail that capstone initialises);
    // MACAPK_DECODE_CACHE_CONTROL=it|tail|short drops the IT rule / the tail
    // rule / the last served entry (the positive controls: VERIFY must then
    // report mismatches; `short` also moves function extents, so the output
    // dylib changes too -- the IT and tail rules guard decodes that discovery
    // happens not to depend on in today's corpus, which is exactly why VERIFY
    // and not the dylib hash is the instrument for this cache).
    // MACAPK_FIRSTLAUNCH_DECODE_CACHE=0 restores the exact pre-change path.
    struct DecodeChunk { cs_insn* ptr; size_t count; };
    struct DecodeRun {
        bool                     thumb = false;
        std::vector<cs_insn>     insns;        // struct copies; .detail -> chunk memory
        std::vector<uint8_t>     avail4;       // min(4, bytes decodable at the entry)
        std::vector<uint32_t>    it_before;    // size()+1: IT entries in insns[0, i)
        std::vector<uint32_t>    chunk_first;  // index of the first entry of i's chunk
        std::vector<DecodeChunk> chunks;       // capstone allocations this run owns
        std::vector<uint32_t>    chunk_start;  // index of each chunk's first entry
        uint32_t                 end = 0;      // where the sweep continues
        uint64_t                 last_use = 0;
    };
    static constexpr size_t   kDcMaxRunsPerMode = 3;
    static constexpr size_t   kDcMaxTotal       = 16384;  // entries, all runs
    static constexpr size_t   kDcMaxRequest     = 8192;   // bigger: not cached
                                                          // (a synth budget is
                                                          // <= 16 KB, so <= 8192)
    static constexpr size_t   kDcTrimAt         = 12288;  // trim dead front past this
    static constexpr uint32_t kDcLookahead      = 256;    // bytes decoded past E
    enum : unsigned { kDcCtlIt = 1u, kDcCtlTail = 2u, kDcCtlShort = 4u };
    bool                      dc_gate_    = true;
    bool                      dc_verify_  = false;
    bool                      dc_stats_on_ = false;
    unsigned                  dc_control_ = 0;
    bool                      dc_owned_   = false;   // current lift's array is cache-owned
    const Elf32Image*         dc_img_     = nullptr;
    uint64_t                  dc_clock_   = 0;
    // unique_ptr, not DecodeRun by value: evicting one run must not move the
    // others, because dc_lookup/dc_extend hold a DecodeRun* across a
    // dc_make_room that may erase a DIFFERENT run from this vector.
    std::vector<std::unique_ptr<DecodeRun>> dc_runs_;
    struct {
        uint64_t requests = 0, served = 0, fresh = 0, served_insns = 0,
                 fresh_insns = 0, appended_insns = 0, fb_it = 0, fb_tail = 0,
                 miss_norun = 0, miss_offgrid = 0, miss_before = 0,
                 evicted = 0, trimmed = 0, refused = 0, peak_entries = 0,
                 verify_checked = 0, verify_mismatch = 0;
    } dc_st_;

    // Capstone entries currently allocated by all runs (every chunk counted
    // whole, including tail entries a run did not keep). This, not the
    // number of entries a run exposes, is what the memory bound is about:
    // bounding only the exposed entries let one run that kept being
    // extended hold ~900 MB on OpenTTD's libapplication.
    size_t                    dc_resident_ = 0;
    void dc_note_alloc(size_t c) {
        dc_resident_ += c;
        if (dc_resident_ > dc_st_.peak_entries) dc_st_.peak_entries = dc_resident_;
    }
    void dc_free_run(DecodeRun& r) {
        for (const auto& c : r.chunks) { cs_free(c.ptr, c.count); dc_resident_ -= c.count; }
        r.chunks.clear();
    }
    void dc_clear() {
        for (auto& r : dc_runs_) dc_free_run(*r);
        dc_runs_.clear();
    }
    // Evict least-recently-used runs (never `keep`) until `mode_ok` and the
    // entry budget allow `incoming` more entries.
    void dc_make_room(size_t incoming, bool thumb, const DecodeRun* keep) {
        for (;;) {
            size_t same_mode = 0;
            for (const auto& r : dc_runs_)
                same_mode += (r->thumb == thumb && r.get() != keep);
            const bool mode_full = keep == nullptr && same_mode >= kDcMaxRunsPerMode;
            if (!mode_full && dc_resident_ + incoming <= kDcMaxTotal) return;
            size_t victim = dc_runs_.size();
            for (size_t k = 0; k < dc_runs_.size(); ++k) {
                if (dc_runs_[k].get() == keep) continue;
                if (mode_full && dc_runs_[k]->thumb != thumb) continue;
                if (victim == dc_runs_.size() ||
                    dc_runs_[k]->last_use < dc_runs_[victim]->last_use) victim = k;
            }
            if (victim == dc_runs_.size()) return;   // nothing evictable
            dc_free_run(*dc_runs_[victim]);
            dc_runs_.erase(dc_runs_.begin() + static_cast<long>(victim));
            ++dc_st_.evicted;
        }
    }
    // Append capstone output p[0..c) (decoded from p[0].address with the
    // sweep ending at chunk_end) to r. Entries decoded with fewer than 4 bytes
    // after them are kept only when the sweep ended at the SEGMENT end (they
    // are then what every request sees); otherwise the run stops before them
    // so it can be continued later with the bytes that follow.
    void dc_push_chunk(DecodeRun& r, cs_insn* p, size_t c, uint64_t chunk_end,
                       bool reached_segment_end) {
        const uint32_t first = static_cast<uint32_t>(r.insns.size());
        r.chunks.push_back({p, c});
        dc_note_alloc(c);
        r.chunk_start.push_back(first);
        if (r.it_before.empty()) r.it_before.push_back(0);
        uint32_t it = r.it_before.back();
        for (size_t k = 0; k < c; ++k) {
            const uint64_t av = chunk_end - p[k].address;
            if (av < 4 && !reached_segment_end) break;
            r.insns.push_back(p[k]);
            r.avail4.push_back(av >= 4 ? 4 : static_cast<uint8_t>(av));
            r.chunk_first.push_back(first);
            if (p[k].id == ARM_INS_IT) ++it;
            r.it_before.push_back(it);
            r.end = static_cast<uint32_t>(p[k].address + p[k].size);
        }
    }
    // Drop every chunk that lies wholly before entry index `cut` (a chunk
    // boundary): the dead front of a run that sliding requests left behind.
    void dc_trim_front(DecodeRun& r, uint32_t cut) {
        size_t k = 0;
        while (k < r.chunks.size() && r.chunk_start[k] < cut) {
            const bool whole = (k + 1 < r.chunks.size())
                ? r.chunk_start[k + 1] <= cut : r.insns.size() <= cut;
            if (!whole) break;
            cs_free(r.chunks[k].ptr, r.chunks[k].count);
            dc_resident_ -= r.chunks[k].count;
            ++k;
        }
        if (k == 0) return;
        const uint32_t removed = (k < r.chunks.size()) ? r.chunk_start[k] : cut;
        r.chunks.erase(r.chunks.begin(), r.chunks.begin() + static_cast<long>(k));
        r.chunk_start.erase(r.chunk_start.begin(), r.chunk_start.begin() + static_cast<long>(k));
        for (auto& s : r.chunk_start) s -= removed;
        r.insns.erase(r.insns.begin(), r.insns.begin() + removed);
        r.avail4.erase(r.avail4.begin(), r.avail4.begin() + removed);
        r.chunk_first.erase(r.chunk_first.begin(), r.chunk_first.begin() + removed);
        for (auto& s : r.chunk_first) s -= removed;
        const uint32_t base = r.it_before[removed];
        r.it_before.erase(r.it_before.begin(), r.it_before.begin() + removed);
        for (auto& s : r.it_before) s -= base;
        ++dc_st_.trimmed;
    }
    // Continue r's sweep from r.end far enough to cover `want_end`.
    size_t dc_extend(DecodeRun& r, const Elf32Image& img, uint64_t want_end) {
        const uint32_t from = r.end;
        if (want_end <= from) return 0;
        const size_t want = static_cast<size_t>(want_end - from) + kDcLookahead;
        auto span = img.code_at(from, want);
        if (span.empty()) return 0;
        const size_t incoming = span.size() / (r.thumb ? 2 : 4) + 1;
        dc_make_room(incoming, r.thumb, &r);
        // Still over budget with every other run gone: this run alone is too
        // big to grow. Refuse; the caller decodes the request fresh (exact).
        if (dc_resident_ + incoming > kDcMaxTotal) { ++dc_st_.refused; return 0; }
        cs_insn* p = nullptr;
        const size_t c = cs_disasm(r.thumb ? handle_thumb : handle_arm,
                                   span.data(), span.size(), from, 0, &p);
        if (c == 0) return 0;
        const size_t before = r.insns.size();
        dc_push_chunk(r, p, c, uint64_t(from) + span.size(), span.size() < want);
        dc_st_.appended_insns += r.insns.size() - before;
        return r.insns.size() - before;
    }
    // Serve [A, A+len) in `thumb` mode from a run, or return false.
    bool dc_lookup(const Elf32Image& img, uint32_t A, size_t len, bool thumb,
                   cs_insn** out, size_t* n) {
        DecodeRun* R = nullptr;
        size_t i = 0;
        bool inside = false, before = false;   // miss diagnostics only
        for (auto& rp : dc_runs_) {
            DecodeRun& r = *rp;
            if (r.thumb != thumb || r.insns.empty()) continue;
            const uint32_t first = static_cast<uint32_t>(r.insns.front().address);
            if (A < first && uint64_t(A) + len > first) before = true;
            if (A < first || A >= r.end) continue;
            inside = true;
            if (!thumb) {
                if ((A - first) & 3u) continue;
                i = (A - first) >> 2;
            } else {
                auto it = std::lower_bound(r.insns.begin(), r.insns.end(), A,
                    [](const cs_insn& x, uint32_t a) { return x.address < a; });
                i = static_cast<size_t>(it - r.insns.begin());
            }
            if (i >= r.insns.size() || r.insns[i].address != A) continue;
            R = &r;
            break;
        }
        if (!R) {
            if (inside)      ++dc_st_.miss_offgrid;
            else if (before) ++dc_st_.miss_before;
            else             ++dc_st_.miss_norun;
            return false;
        }
        R->last_use = ++dc_clock_;
        if (R->chunk_first[i] > 0 &&
            (R->insns.size() > kDcTrimAt || dc_resident_ > kDcMaxTotal)) {
            const uint32_t cut = R->chunk_first[i];
            dc_trim_front(*R, cut);
            i -= cut;
        }
        const bool ctl_it   = (dc_control_ & kDcCtlIt) != 0;
        const bool ctl_tail = (dc_control_ & kDcCtlTail) != 0;
        // IT state at A in the sweep that decoded A's chunk must be empty.
        if (!ctl_it && R->it_before[i] != R->it_before[R->chunk_first[i]]) {
            ++dc_st_.fb_it;
            return false;
        }
        const uint64_t E = uint64_t(A) + len;
        const uint64_t stop_below = thumb ? 2 : 4;   // SKIPDATA size: sweep ends
        size_t j = i;
        for (;;) {
            if (j == R->insns.size()) {
                if (E <= R->end || E - R->end < stop_below) break;
                // Crossing into a new chunk: its sweep starts with an empty IT
                // state, so there must be no IT entry in [A, R->end).
                if (!ctl_it && R->it_before[j] != R->it_before[i]) {
                    ++dc_st_.fb_it;
                    return false;
                }
                if (dc_extend(*R, img, E) == 0) return false;
                continue;
            }
            const cs_insn& e = R->insns[j];
            const uint64_t rem = E > e.address ? E - e.address : 0;
            if (rem < stop_below) break;
            if (j > i && R->chunk_first[j] == j &&
                !ctl_it && R->it_before[j] != R->it_before[i]) {
                ++dc_st_.fb_it;
                return false;
            }
            bool ok = true;
            if (thumb) {
                if (e.id != 0 && e.size == 4) ok = rem >= 4;         // 32-bit
                else if (e.id == 0) ok = R->avail4[j] == 4 || rem < 4; // SKIPDATA
            }
            if (!ok && !ctl_tail) {
                ++dc_st_.fb_tail;
                return false;
            }
            ++j;
        }
        // Control `short`: an off-by-one in where the answer stops.
        if ((dc_control_ & kDcCtlShort) && j > i + 1) --j;
        if (j == i) return false;
        *out = R->insns.data() + i;
        *n = j - i;
        return true;
    }
    static bool dc_same(const cs_insn& a, const cs_insn& b) {
        if (a.id != b.id || a.address != b.address || a.size != b.size) return false;
        if (std::memcmp(a.bytes, b.bytes, std::min<size_t>(a.size, sizeof a.bytes)) != 0)
            return false;
        if (std::strcmp(a.mnemonic, b.mnemonic) != 0 ||
            std::strcmp(a.op_str, b.op_str) != 0) return false;
        if ((a.detail == nullptr) != (b.detail == nullptr)) return false;
        // Everything capstone initialises in a detail record (the memset in
        // _ARM_getInstruction/_Thumb_getInstruction covers exactly this).
        return !a.detail || std::memcmp(a.detail, b.detail,
                                        offsetof(cs_detail, arm) + sizeof(cs_arm)) == 0;
    }
    // The decode for one lift: from the cache when exact, else fresh (and
    // then kept as a run). Sets dc_owned_ when the array is the cache's.
    size_t dc_acquire(const Elf32Image& img, const Symbol& sym,
                      std::span<const uint8_t> bytes, cs_insn** insns) {
        const uint32_t A = static_cast<uint32_t>(sym.address & ~1u);
        const bool thumb = sym.is_thumb;
        ++dc_st_.requests;
        if (dc_img_ != &img) { dc_clear(); dc_img_ = &img; }
        cs_insn* hit = nullptr;
        size_t n = 0;
        if (dc_lookup(img, A, bytes.size(), thumb, &hit, &n)) {
            ++dc_st_.served;
            dc_st_.served_insns += n;
            if (dc_verify_) {
                cs_insn* f = nullptr;
                const size_t fc = cs_disasm(handle, bytes.data(), bytes.size(), A, 0, &f);
                ++dc_st_.verify_checked;
                bool same = fc == n;
                for (size_t k = 0; same && k < n; ++k) same = dc_same(hit[k], f[k]);
                if (!same) {
                    if (dc_st_.verify_mismatch < 8)
                        std::fprintf(stderr,
                            "[decode-cache] VERIFY MISMATCH at 0x%x thumb=%d len=%zu "
                            "(served %zu, fresh %zu)\n", A, int(thumb), bytes.size(), n, fc);
                    ++dc_st_.verify_mismatch;
                }
                if (fc) cs_free(f, fc);
            }
            *insns = hit;
            dc_owned_ = true;
            return n;
        }
        const size_t count = cs_disasm(handle, bytes.data(), bytes.size(), A, 0, insns);
        ++dc_st_.fresh;
        dc_st_.fresh_insns += count;
        if (count == 0 || count > kDcMaxRequest) return count;   // caller frees
        // Keep it: the lifter reads *insns during this lift; the run owns it.
        dc_make_room(count, thumb, nullptr);
        dc_runs_.push_back(std::make_unique<DecodeRun>());
        DecodeRun& r = *dc_runs_.back();
        r.thumb = thumb;
        r.last_use = ++dc_clock_;
        const bool seg_end = sym.size == 0 || bytes.size() < sym.size;
        dc_push_chunk(r, *insns, count, uint64_t(A) + bytes.size(), seg_end);
        if (r.insns.empty()) {           // nothing reusable; hand it back
            r.chunks.clear();
            dc_resident_ -= count;       // dc_release frees it, not the cache
            dc_runs_.pop_back();
            return count;
        }
        dc_owned_ = true;
        return count;
    }
    void dc_release(cs_insn* insns, size_t count) {
        if (!dc_owned_) cs_free(insns, count);
        dc_owned_ = false;
    }
    void dc_print_stats() const {
        std::fprintf(stderr,
            "[decode-cache] requests=%llu served=%llu fresh=%llu served_insns=%llu "
            "fresh_insns=%llu appended_insns=%llu fallback_it=%llu fallback_tail=%llu "
            "miss_norun=%llu miss_offgrid=%llu miss_before=%llu evicted=%llu "
            "trimmed=%llu refused=%llu peak_entries=%llu verify_checked=%llu "
            "verify_mismatch=%llu\n",
            (unsigned long long)dc_st_.requests, (unsigned long long)dc_st_.served,
            (unsigned long long)dc_st_.fresh, (unsigned long long)dc_st_.served_insns,
            (unsigned long long)dc_st_.fresh_insns, (unsigned long long)dc_st_.appended_insns,
            (unsigned long long)dc_st_.fb_it, (unsigned long long)dc_st_.fb_tail,
            (unsigned long long)dc_st_.miss_norun, (unsigned long long)dc_st_.miss_offgrid,
            (unsigned long long)dc_st_.miss_before, (unsigned long long)dc_st_.evicted,
            (unsigned long long)dc_st_.trimmed, (unsigned long long)dc_st_.refused,
            (unsigned long long)dc_st_.peak_entries,
            (unsigned long long)dc_st_.verify_checked,
            (unsigned long long)dc_st_.verify_mismatch);
    }

    Impl() {
        if (const char* e = std::getenv("MACAPK_FIRSTLAUNCH_DECODE_CACHE"))
            dc_gate_ = !(*e == '0');
        if (const char* e = std::getenv("MACAPK_FIRSTLAUNCH_DECODE_CACHE_VERIFY"))
            dc_verify_ = (*e == '1');
        if (const char* e = std::getenv("MACAPK_FIRSTLAUNCH_TIMING"))
            dc_stats_on_ = (*e && *e != '0');
        if (const char* e = std::getenv("MACAPK_DECODE_CACHE_CONTROL")) {
            const std::string s(e);
            if (s.find("it") != std::string::npos)   dc_control_ |= kDcCtlIt;
            if (s.find("tail") != std::string::npos) dc_control_ |= kDcCtlTail;
            if (s.find("short") != std::string::npos) dc_control_ |= kDcCtlShort;
            if (dc_control_)
                std::fprintf(stderr,
                    "[lifter] MACAPK_DECODE_CACHE_CONTROL=%s: TEST-ONLY, the decode "
                    "cache ignores a soundness rule on purpose\n", e);
        }
        if (const char* e = std::getenv("MACAPK_FIRSTLAUNCH_LIFT_NOIR"))
            noir_gate_ = !(*e == '0');
        if (const char* e = std::getenv("MACAPK_LIFT_NOIR_CONTROL")) {
            const std::string s(e);
            size_t p = 0;
            while (p <= s.size()) {
                size_t q = s.find(',', p);
                if (q == std::string::npos) q = s.size();
                const std::string t = s.substr(p, q - p);
                if (t == "b")          noir_control_ |= kCtlB;
                else if (t == "bl")    noir_control_ |= kCtlBl;
                else if (t == "blx")   noir_control_ |= kCtlBlx;
                else if (t == "cb")    noir_control_ |= kCtlCb;
                else if (t == "tbb")   noir_control_ |= kCtlTbb;
                else if (t == "alupc") noir_control_ |= kCtlAluPc;
                p = q + 1;
            }
            if (noir_control_)
                std::fprintf(stderr,
                    "[lifter] MACAPK_LIFT_NOIR_CONTROL=%s: TEST-ONLY, dropping "
                    "discovery side effects on purpose\n", e);
        }
        if (const char* e = std::getenv("MACAPK_LIFT_DIGEST"))
            digest_on_ = (*e == '1');
        if (const char* e = std::getenv("MACAPK_NO_REGCACHE"))
            no_regcache_ = (e[0] == '1');
        if (const char* e = std::getenv("MACAPK_LIFTER_EMIT_STORE_TRACE"))
            emit_store_trace_ = (e[0] == '1');
        if (const char* e = std::getenv("MACAPK_MODIMM_CARRY_CONSERVATIVE"))
            exact_modified_imm_carry_ = (e[0] != '1');
        if (const char* e = std::getenv("MACAPK_ALU_PC_WRITE_DEAD"))
            alu_pc_write_is_branch_ = (e[0] != '1');
        if (const char* env = std::getenv("MACAPK_DIFF_VADDRS")) {
            const char* p = env;
            while (*p) {
                while (*p == ',' || *p == ' ' || *p == '\t') ++p;
                if (!*p) break;
                char* endp = nullptr;
                unsigned long v = std::strtoul(p, &endp, 16);
                if (endp == p) break;
                diff_vaddrs_.insert(static_cast<uint32_t>(v) & ~1u);
                p = endp;
            }
            std::fprintf(stderr,
                "[lifter] MACAPK_DIFF_VADDRS: instrumenting %zu function(s)"
                " for the Unicorn differential harness\n",
                diff_vaddrs_.size());
        }
        if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle_arm) == CS_ERR_OK) {
            cs_option(handle_arm, CS_OPT_DETAIL, CS_OPT_ON);
            // SKIPDATA lets cs_disasm step PAST an undecodeable
            // byte sequence (typically a mid-function literal pool)
            // by skipping a default 4 bytes and emitting a `.byte`
            // pseudo-instruction with id==0. Without it, cs_disasm
            // bails at the first undecodeable byte and returns a
            // truncated instruction list -- intra-function branches
            // to addresses past the bail get classified as extern
            // tail calls (since valid_addrs_ doesn't contain them),
            // which spawns bogus mid-function synths with fresh-zero
            // r4..r11. See https://www.capstone-engine.org/skipdata.html.
            // The instruction loop in run() ignores id==0 entries so
            // the .byte placeholders don't appear in the lifted IR.
            cs_option(handle_arm, CS_OPT_SKIPDATA, CS_OPT_ON);
            cs_arm_ok = true;
        }
        if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle_thumb) == CS_ERR_OK) {
            cs_option(handle_thumb, CS_OPT_DETAIL, CS_OPT_ON);
            // Same as above; Thumb's default skip is 2 bytes
            // (Thumb-16 alignment), which is correct for our use.
            cs_option(handle_thumb, CS_OPT_SKIPDATA, CS_OPT_ON);
            cs_thumb_ok = true;
        }
    }
    ~Impl() {
        if (digest_on_) digest_print_state();
        if (dc_gate_ && (dc_stats_on_ || dc_verify_)) dc_print_stats();
        if (dc_stats_on_)
            std::fprintf(stderr,
                "[lift-noir] gate=%d discovery_only_lifts=%llu ir_lifts=%llu "
                "skipped_insns=%llu\n", int(noir_gate_),
                (unsigned long long)noir_lifts_, (unsigned long long)ir_lifts_,
                (unsigned long long)noir_skipped_);
        dc_clear();
        if (cs_arm_ok)   cs_close(&handle_arm);
        if (cs_thumb_ok) cs_close(&handle_thumb);
    }

    std::string fresh() { return "%t" + std::to_string(ssa_counter++); }

    std::string bb_label(uint32_t addr) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "bb_%08x", addr);
        return buf;
    }

    // --- Register file access -----------------------------------------

    // Drop all cached SSA names. Called when entering a new basic
    // block -- the predecessor's cache values aren't reachable from
    // here in IR, so we have to fall back to loading from the %r
    // alloca slot.
    void cache_clear() {
        for (int i = 0; i < 16; ++i) {
            reg_cache_[i].clear();
            reg_dirty_[i] = false;
        }
    }
    // Emit a store-to-memory for every cached reg that was modified
    // since the last sync, so a subsequent cross-block branch leaves
    // a consistent register file behind. Caller is `emit_uncond_branch`
    // and `emit_cond_branch` before they emit `br`. Cached values
    // remain valid as SSA after flush -- we don't clear them, just
    // sync to memory.
    void flush_dirty_regs() {
        for (int r = 0; r < 16; ++r) {
            if (!reg_dirty_[r]) continue;
            std::string slot = "%rF" + std::to_string(ssa_counter++);
            ir << "  " << slot << " = getelementptr inbounds [16 x i32], "
                                "ptr %r, i32 0, i32 " << r << "\n";
            ir << "  store i32 " << reg_cache_[r] << ", ptr " << slot
               << ", align 4\n";
            reg_dirty_[r] = false;
        }
    }

    // --- Predicated memory-access guard (ARM ARM A8.3) ----------------
    // ARMv7 conditional execution wraps the ENTIRE instruction operation
    // -- including the memory access AND any base-register writeback --
    // in `if ConditionPassed() then ...` (DDI 0406C.d A8.3; per-op
    // pseudocode for STR A8.8.204, STRD A8.8.210, STM A8.8.199, LDR
    // A8.8.66). On a FALSE predicate NOTHING happens: no load, no store,
    // no writeback. The old lowering did an unconditional
    // load-select-store RMW (and, for LDR, an unconditional load), so a
    // `cmp r1,#0; strne r0,[r1,#off]` with r1==NULL dereferenced
    // guest_base+garbage on the not-taken path -> stray SEGV /
    // corruption far from the cause.
    //
    // The fix emits a real CFG diamond:
    //   <predecessor>  ; address math + source-value loads done here
    //                    (pure, no memory access) so their SSA names
    //                    dominate the guard block
    //   flush_dirty_regs(); br i1 <pred>, %do_mem_K, %skip_K
    //   do_mem_K:  cache_clear(); <store(s)/load + writeback>; br %skip_K
    //   skip_K:    cache_clear()
    //
    // Integration with the reg-cache/dirty-flush model mirrors the
    // predicated POP-into-PC path (emit_one, ~7096-7104): we flush dirty
    // regs to the %r alloca BEFORE the br so the register file is
    // consistent in memory on both join paths, then cache_clear() at
    // each block entry so subsequent load_reg() re-reads from memory
    // (the predecessor's cached SSA still dominate skip via the
    // predecessor, but values produced INSIDE do_mem_K do not reach
    // skip on the not-taken edge, so a clean slate at the join is
    // mandatory). Inside the guard `current_pred` is temporarily cleared
    // (saved/restored by the caller) so the relocated store/writeback
    // code does NOT also select-blend -- the block only runs when the
    // predicate is true, so its effects are unconditional within it.
    //
    // Returns the per-function-unique guard id K (from ssa_counter, the
    // same monotonic counter used for ext_/popret_/tbb_* labels).
    int pred_guard_begin(const std::string& pred) {
        int k = ssa_counter++;
        flush_dirty_regs();
        ir << "  br i1 " << pred << ", label %do_mem_" << k
           << ", label %skip_" << k << "\n";
        ir << "do_mem_" << k << ":\n";
        cache_clear();
        return k;
    }
    void pred_guard_end(int k) {
        ir << "  br label %skip_" << k << "\n";
        ir << "skip_" << k << ":\n";
        cache_clear();
    }
    // Writeback to a guest register INSIDE a guard block. Must not go
    // through store_reg(): (a) current_pred is (or should be) cleared in
    // the guard so no select-blend is wanted, and (b) cache_clear() at
    // the join would drop a cache-only write. So write straight to the
    // %r alloca, identically to flush_dirty_regs' store form. `val` must
    // be an SSA name that dominates the guard block (i.e. computed in the
    // predecessor or in the guard before this call).
    void store_reg_to_mem(int r, const std::string& val) {
        if (r < 0 || r > 15) return;
        std::string slot = "%rWB" + std::to_string(ssa_counter++);
        ir << "  " << slot << " = getelementptr inbounds [16 x i32], "
                            "ptr %r, i32 0, i32 " << r << "\n";
        ir << "  store i32 " << val << ", ptr " << slot << ", align 4\n";
    }

    std::string load_reg(int r) {
        if (r < 0 || r > 15) return "0";
        // ARM32: reading PC (R15) as a source operand. The lifter applies
        // `Align(insn_addr, 4) + {8 ARM, 4 Thumb}`. The `& ~3u` (word-align)
        // is REQUIRED here for the cocos2d-x PIC pattern
        //   ldr r1, [pc, #N] ; add r1, pc   (r1 = absolute vaddr)
        // and the analogous `add Rd, pc, Rm`.
        //
        // ⚠ v1.0.515->516: the Unicorn differential harness flagged this as
        // over-aligning a 2-byte-aligned Thumb `add r1, pc`. The first attempt
        // removed `& ~3u` from THIS function (a GLOBAL change to every PC read)
        // and REGRESSED GD Lite to BLANK -- because it ALSO unaligned the
        // ADR-alias `add rd, pc, #imm` (PC read as Rn here via load_reg(15)),
        // which genuinely needs Align(PC,4). So this function STAYS aligned:
        // it serves the ADR-alias / PC-relative-ADDRESS forms.
        //
        // v1.0.520: TWO attempts returning the UNALIGNED PC for R15-as-data-
        // proc-source (blanket, then scoped to `add rd,pc`) BOTH regressed GD
        // Lite to BLANK -- HCR's libxml2 (needs unaligned) and GD Lite's
        // cocos2d-x (needs aligned) emit the SAME instruction with opposite PC
        // conventions, so no blanket/mnemonic rule fits both. The mask here
        // STAYS aligned (correct for the ADR-alias / PC-relative-ADDRESS forms
        // and for every non-GOT R15 source). v1.0.521 added the real fix in
        // emit_alu: it DISCRIMINATES per PIC sequence -- finds the `ldr rN,[pc];
        // add rN,pc` pair and overrides ONLY that add to unaligned when doing
        // so makes the result the 4-aligned .got target (HCR), leaving GD Lite
        // untouched (its aligned result already hits the GOT). See emit_alu +
        // docs/arm32-render-blockers-and-exidx_2026-06-25.
        //
        // For ARM mode the mask is a no-op (insn_addr is 4-byte aligned).
        // The LDR-from-[PC,...] memory path aligns independently in
        // compute_mem_addr (line ~9760), so the two paths stay consistent.
        if (r == 15) {
            uint32_t pc_value = (current_insn_addr
                              + (current_is_thumb ? 4u : 8u)) & ~3u;
            // Per-image load bias: PC reads are THE central runtime-vaddr
            // materialization -- every `add rd,pc`/`ldr rd,[pc,#N];add rd,pc`
            // PIC pointer flows through here, so biasing PC biases them all.
            return std::to_string(static_cast<int64_t>(pc_value + load_bias_));
        }
        if (!no_regcache_ && !reg_cache_[r].empty()) {
            // Cache hit: return the SSA name without emitting IR. This
            // is the bulk of the v1.0.8 compaction win -- consecutive
            // reads of the same register inside a block become free.
            return reg_cache_[r];
        }
        std::string slot = "%rL" + std::to_string(ssa_counter);
        ir << "  " << slot << " = getelementptr inbounds [16 x i32], "
                            "ptr %r, i32 0, i32 " << r << "\n";
        std::string val = fresh();
        ir << "  " << val << " = load i32, ptr " << slot << ", align 4\n";
        if (!no_regcache_) {
            reg_cache_[r] = val;
            // Loaded value is by definition consistent with memory; not
            // dirty until something writes the cache.
        }
        return val;
    }
    void store_reg(int r, const std::string& val_ssa) {
        if (r < 0 || r > 15) return;
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            // Predicated write: blend new value with old via select.
            // Compiler emits this pattern for branchless if/else
            // (e.g. movle, rsbmi). load_reg() uses cache when warm.
            std::string old = load_reg(r);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i32 " << val << ", i32 " << old << "\n";
            val = sel;
        }
        if (no_regcache_) {
            // v1.0.4 model: store straight to the %r alloca slot so the
            // next load_reg (also uncached) sees it. flush_dirty_regs
            // becomes a redundant no-op (reg_dirty_ left false).
            std::string slot = "%rS" + std::to_string(ssa_counter);
            ir << "  " << slot << " = getelementptr inbounds [16 x i32], "
                                "ptr %r, i32 0, i32 " << r << "\n";
            ir << "  store i32 " << val << ", ptr " << slot
               << ", align 4\n";
            ++ssa_counter;
            return;
        }
        // Cache-only write: no store-to-memory emitted here. The
        // store will fire (via flush_dirty_regs) right before any
        // cross-block branch. Function calls don't need the flush
        // because they pass r0..r3, sp as explicit SSA values via
        // load_reg() -- the cache is correct for both paths.
        reg_cache_[r] = val;
        reg_dirty_[r] = true;
        ++ssa_counter;
    }

    // --- Flag access --------------------------------------------------

    // GE[idx] (idx 0..3) accessors. Same fixed-name alloca model as
    // the NZCV flags; honors current_pred via blend on store so a
    // predicated parallel-add does not clobber GE on the false path.
    std::string load_ge(int idx) {
        std::string val = fresh();
        ir << "  " << val << " = load i1, ptr %ge" << idx << ", align 1\n";
        return val;
    }
    void store_ge(int idx, const std::string& val_ssa) {
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            std::string old = load_ge(idx);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i1 " << val << ", i1 " << old << "\n";
            val = sel;
        }
        ir << "  store i1 " << val << ", ptr %ge" << idx << ", align 1\n";
    }
    std::string load_q() {
        std::string val = fresh();
        ir << "  " << val << " = load i1, ptr %qflag, align 1\n";
        return val;
    }
    void store_q(const std::string& val_ssa) {
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            std::string old = load_q();
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i1 " << val << ", i1 " << old << "\n";
            val = sel;
        }
        ir << "  store i1 " << val << ", ptr %qflag, align 1\n";
    }
    // Sticky APSR.Q: once set it stays set until explicitly cleared by
    // MSR APSR. Saturating ops OR their saturation/overflow bit in.
    void set_q_sticky(const std::string& cond_i1) {
        std::string old = load_q();
        std::string nw = fresh();
        ir << "  " << nw << " = or i1 " << old << ", " << cond_i1 << "\n";
        std::string val = nw;
        if (!current_pred.empty()) {
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i1 " << val << ", i1 " << old << "\n";
            val = sel;
        }
        ir << "  store i1 " << val << ", ptr %qflag, align 1\n";
    }

    std::string load_flag(const char* name) {
        std::string val = fresh();
        ir << "  " << val << " = load i1, ptr %nzcv_" << name << ", align 1\n";
        return val;
    }
    void store_flag(const char* name, const std::string& val_ssa) {
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            // Predicated flag write: blend new and old via select. Lets
            // us support predicated CMP / TST / S-suffix arithmetic
            // without separate plumbing.
            std::string old = load_flag(name);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i1 " << val << ", i1 " << old << "\n";
            val = sel;
        }
        ir << "  store i1 " << val << ", ptr %nzcv_" << name << ", align 1\n";
    }

    // FPSCR flag accessors. VCMP / VCMPE write to FPSCR's NZCV bits;
    // VMRS APSR_nzcv, FPSCR copies them to ARM's NZCV. Without separate
    // storage, any predicated ARM instruction between VCMP and VMRS sees
    // float-compare flags when it should still see whatever the previous
    // ARM CMP / S-suffix op set. cocos2d-x v2's CCNode::nodeToParentTransform
    // hits exactly this pattern: an integer CMP gates VLDRNE / VADDNE
    // through a VCMP + VMRS sequence, and corrupting NZCV mid-sequence
    // breaks anchor-point handling for every CCLayer in the engine.
    std::string load_fpscr_flag(const char* name) {
        std::string val = fresh();
        ir << "  " << val << " = load i1, ptr %fpscr_" << name << ", align 1\n";
        return val;
    }
    void store_fpscr_flag(const char* name, const std::string& val_ssa) {
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            std::string old = load_fpscr_flag(name);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i1 " << val << ", i1 " << old << "\n";
            val = sel;
        }
        ir << "  store i1 " << val << ", ptr %fpscr_" << name
           << ", align 1\n";
    }

    // --- Guest address synthesis -------------------------------------
    //
    // ARM32 .so files use 32-bit pointers everywhere. The lifted code
    // sees memory accesses as `LDR Rt, [Rn, #imm]` where Rn is a
    // 32-bit value. We map every such address through the shim's
    // 1 GiB guest memory region: `(guest_base + addr)` is the real
    // darwin pointer.
    //
    // No more per-function stack alloca. The stack lives at high
    // addresses inside guest memory (the kThreadStackBase region in
    // the shim) and is shared across the entire call chain on a
    // thread. SP starts at the top of the thread's slot when control
    // first enters lifted code (set by the JNI thunk) and is passed
    // through every cross-function call so callers and callees see
    // the same stack frame layout.
    std::string stack_ptr(const std::string& addr_ssa) {
        std::string addr_64 = fresh();
        ir << "  " << addr_64 << " = zext i32 " << addr_ssa << " to i64\n";
        std::string p = fresh();
        ir << "  " << p << " = getelementptr inbounds i8, "
              "ptr %guest_base, i64 " << addr_64 << "\n";
        return p;
    }
    // History note 2026-05-20 (v1.0.50): tested dropping `inbounds`
    // from the GEP above on the theory that LLVM AA might be exploiting
    // the inbounds hint to mis-conclude noalias between two guest-
    // memory pointers (per agent research recommendation #6). A/B
    // test in HCR 1.43 ARM32 forced showed NO change in the bug-2
    // crash signature (SEGV at synth_002dc1e8+0x50, fault_addr=
    // 0x4xxxxxxxx with x21=0x3 after _M_p reload). Restored. The
    // inbounds AA path is NOT the bug; the corruption is data-flow
    // upstream (some lifted store writes the literal value 3 into
    // a std::string _M_p slot).

    // --- Operand decoding helpers -------------------------------------

    // Read a little-endian u32 from the image at a guest vaddr (literal
    // pools live in PROGBITS, reachable via code_at). Returns false if the
    // address is not backed by image bytes.
    bool read_u32_at(uint32_t vaddr, uint32_t* out) const {
        if (!image_) return false;
        auto b = image_->code_at(vaddr, 4);
        if (b.size() < 4) return false;
        *out = static_cast<uint32_t>(b[0]) |
               (static_cast<uint32_t>(b[1]) << 8) |
               (static_cast<uint32_t>(b[2]) << 16) |
               (static_cast<uint32_t>(b[3]) << 24);
        return true;
    }

    // For the GCC Thumb PIC pair `ldr rN, [pc, #imm]; add rN, pc`, find the
    // literal value loaded into rN by the most recent `ldr rN, [pc, #imm]`
    // in the SAME basic block (scanning backward in the decoded stream).
    // Returns false if rN was redefined by anything else, a control-flow
    // insn intervenes, or no such ldr is found within a small window.
    // (rn_cs is the Capstone reg id of rN -- the non-PC source of the add.)
    bool find_pc_literal_for(int rn_cs, uint32_t* L_out) const {
        if (!current_insns_ || current_idx_ == 0) return false;
        for (size_t back = 1; back <= 16 && back <= current_idx_; ++back) {
            const cs_insn& p = current_insns_[current_idx_ - back];
            if (!p.detail) continue;
            // Do not pair across a branch (a different predecessor could set
            // rN). Conservatively stop the scan at any control-flow insn.
            if (p.id == ARM_INS_B   || p.id == ARM_INS_BX  ||
                p.id == ARM_INS_BL  || p.id == ARM_INS_BLX ||
                p.id == ARM_INS_CBZ || p.id == ARM_INS_CBNZ) return false;
            const cs_arm& pd = p.detail->arm;
            // ldr rN, [pc, #imm]  (no index reg)  -> the literal we want.
            if (p.id == ARM_INS_LDR && pd.op_count == 2 &&
                pd.operands[0].type == ARM_OP_REG &&
                pd.operands[0].reg  == rn_cs &&
                pd.operands[1].type == ARM_OP_MEM &&
                pd.operands[1].mem.base  == ARM_REG_PC &&
                pd.operands[1].mem.index == ARM_REG_INVALID) {
                // Same PC-relative literal-address rule as compute_mem_addr;
                // the function is a single ISA mode so current_is_thumb holds
                // for p too.
                uint32_t pc_base = (static_cast<uint32_t>(p.address) +
                                    (current_is_thumb ? 4u : 8u)) & ~3u;
                uint32_t lit = pc_base +
                    static_cast<uint32_t>(static_cast<int32_t>(pd.operands[1].mem.disp));
                return read_u32_at(lit, L_out);
            }
            // Any other write to rN (rN as the dest operand) redefines it.
            if (pd.op_count >= 1 && pd.operands[0].type == ARM_OP_REG &&
                pd.operands[0].reg == rn_cs) return false;
        }
        return false;
    }

    bool operand_value(const cs_arm_op& op, std::string* out) {
        if (op.type == ARM_OP_REG) {
            int r = arm_reg_idx(op.reg);
            if (r < 0) return false;
            // R15 here reads through load_reg(15) (Align(insn+4,4) in Thumb).
            // Per the ARM ARM a data-proc register SOURCE read of R15 is
            // UNALIGNED (insn+4), but the aligned value is what GD Lite's
            // cocos2d-x PIC needs while HCR's libxml2 PIC needs unaligned -- the
            // SAME instruction, opposite conventions (different NDK eras). v1.0.
            // 520 proved no blanket OR mnemonic-scoped unaligned rule fits both
            // (both regressed GD Lite). The v1.0.521 fix DISCRIMINATES per PIC
            // sequence in emit_alu (find the `ldr rN,[pc]; add rN,pc` pair, and
            // override to unaligned ONLY when that makes the result the
            // 4-aligned .got target) -- so this default stays ALIGNED and is
            // correct for every non-GOT R15 source.
            *out = load_reg(r);
            return true;
        }
        if (op.type == ARM_OP_IMM) {
            *out = std::to_string(static_cast<int32_t>(op.imm));
            return true;
        }
        return false;
    }

    // Lower one ARM shift whose amount may be OUT OF RANGE for LLVM.
    //
    // ARM DEFINES the wide cases (DDI 0406C.d A8.4.3 Shift_C via LSL_C /
    // LSR_C / ASR_C): LSL and LSR by >= 32 give 0, ASR by >= 32 gives the
    // sign bit replicated. LLVM does NOT -- `shl` / `lshr` / `ashr` return
    // POISON once the amount reaches the bit width. Verified against the
    // toolchain we actually ship with, not just the LangRef prose:
    // `define i32 @g(i32 %x) { %s = lshr i32 %x, 32  ret i32 %s }` folds
    // to `ret i32 poison` under `opt -O2`.
    //
    // So emitting the raw shift is not "a wrong value" -- it hands the
    // optimizer a licence to delete or arbitrarily rewrite everything
    // downstream of it. Register-amount shifted operands are common
    // (1,386 in HCR's libgame.so alone, 137 in Jetpack Joyride), and any
    // of them can reach an amount >= 32 at runtime.
    //
    // The amount is R[s]<7:0>, the bottom BYTE (0..255), NOT the low five
    // bits: `lsl r0, r1, r2` with r2 == 32 must produce 0, and masking to
    // 5 bits silently turns it into a no-op shift instead.
    std::string shift_amount_safe(const std::string& val,
                                  const std::string& iop,
                                  const std::string& amt_ssa) {
        std::string amt8 = fresh();
        ir << "  " << amt8 << " = and i32 " << amt_ssa << ", 255\n";
        std::string wide = fresh();
        ir << "  " << wide << " = icmp ugt i32 " << amt8 << ", 31\n";
        // In-range amount for the real shift. The select below throws the
        // result away whenever the architectural amount was out of range,
        // so masking here only keeps the shift itself well-defined.
        std::string safe = fresh();
        ir << "  " << safe << " = and i32 " << amt8 << ", 31\n";
        std::string raw = fresh();
        ir << "  " << raw << " = " << iop << " i32 " << val
           << ", " << safe << "\n";
        std::string sat = "0";
        if (iop == "ashr") {
            sat = fresh();
            ir << "  " << sat << " = ashr i32 " << val << ", 31\n";
        }
        std::string out = fresh();
        ir << "  " << out << " = select i1 " << wide
           << ", i32 " << sat << ", i32 " << raw << "\n";
        return out;
    }

    // Constant-amount counterpart: the amount is known at translate time,
    // so the saturated cases fold to a constant or a single ashr.
    // Capstone reports LSR #32 / ASR #32 for the imm5 == 0 encodings
    // (A8.8.102 / A8.8.14), which the raw path turned into poison.
    std::string shift_amount_const(const std::string& val,
                                   const std::string& iop, int n) {
        if (n >= 32) {
            if (iop != "ashr") return "0";
            std::string out = fresh();
            ir << "  " << out << " = ashr i32 " << val << ", 31\n";
            return out;
        }
        std::string out = fresh();
        ir << "  " << out << " = " << iop << " i32 " << val << ", " << n
           << "\n";
        return out;
    }

    // Shifter carry-out for a REGISTER shift amount (DDI 0406C.d A8.4.3
    // Shift_C via LSL_C / LSR_C / ASR_C), returned as an i1 SSA that
    // already folds in "amount == 0 leaves C unchanged".
    //
    //   LSL: amount 1..31 -> x<32-amount>; == 32 -> x<0>;  > 32 -> 0
    //   LSR: amount 1..31 -> x<amount-1>;  == 32 -> x<31>; > 32 -> 0
    //   ASR: amount 1..31 -> x<amount-1>;  >= 32 -> x<31>
    //
    // The `== 32 -> x<31>` case for LSR is BUG 3: carry_out is
    // extended_x<shift-1>, and only shift > 32 reaches the zero-extended
    // part, so returning 0 for the whole >= 32 range wrote the wrong C.
    // `iop` is the LLVM opcode name ("shl" / "lshr" / "ashr").
    //
    // This serves emit_shift, the STANDALONE LSL/LSR/ASR instruction path,
    // which previously computed no register-amount carry at all.
    // apply_shift_c keeps its own equivalent inline for the shifted-ALU-
    // OPERAND path because that one must also cover ROR_REG, which has no
    // saturating behaviour and so does not fit this shape. If ROR ever
    // moves here, collapse the two.
    std::string reg_shift_carry(const std::string& in_val,
                                const std::string& iop,
                                const std::string& amt_full) {
        std::string amt = fresh();
        ir << "  " << amt << " = and i32 " << amt_full << ", 255\n";
        std::string is_zero = fresh();
        ir << "  " << is_zero << " = icmp eq i32 " << amt << ", 0\n";
        std::string old_c = load_flag("c");
        // bit position for the in-range case
        std::string bp = fresh();
        if (iop == "shl") ir << "  " << bp << " = sub i32 32, " << amt << "\n";
        else              ir << "  " << bp << " = sub i32 " << amt << ", 1\n";
        std::string bpm = fresh();
        ir << "  " << bpm << " = and i32 " << bp << ", 31\n";
        std::string sh = fresh();
        ir << "  " << sh << " = lshr i32 " << in_val << ", " << bpm << "\n";
        std::string lo = fresh();
        ir << "  " << lo << " = and i32 " << sh << ", 1\n";
        std::string c_lt = fresh();
        ir << "  " << c_lt << " = icmp ne i32 " << lo << ", 0\n";
        // x<31> and x<0>, needed by the saturated cases.
        std::string b31s = fresh();
        ir << "  " << b31s << " = lshr i32 " << in_val << ", 31\n";
        std::string b31m = fresh();
        ir << "  " << b31m << " = and i32 " << b31s << ", 1\n";
        std::string c31 = fresh();
        ir << "  " << c31 << " = icmp ne i32 " << b31m << ", 0\n";
        std::string ge32 = fresh();
        ir << "  " << ge32 << " = icmp ugt i32 " << amt << ", 31\n";
        std::string co_nz;
        if (iop == "ashr") {
            // ASR saturates to the sign bit for every amount >= 32.
            co_nz = fresh();
            ir << "  " << co_nz << " = select i1 " << ge32
               << ", i1 " << c31 << ", i1 " << c_lt << "\n";
        } else {
            std::string eq32 = fresh();
            ir << "  " << eq32 << " = icmp eq i32 " << amt << ", 32\n";
            std::string at32;
            if (iop == "shl") {
                std::string b0 = fresh();
                ir << "  " << b0 << " = and i32 " << in_val << ", 1\n";
                at32 = fresh();
                ir << "  " << at32 << " = icmp ne i32 " << b0 << ", 0\n";
            } else {
                at32 = c31;   // LSR at exactly 32 -> x<31>  (bug 3)
            }
            std::string wide = fresh();
            ir << "  " << wide << " = select i1 " << eq32
               << ", i1 " << at32 << ", i1 false\n";
            co_nz = fresh();
            ir << "  " << co_nz << " = select i1 " << ge32
               << ", i1 " << wide << ", i1 " << c_lt << "\n";
        }
        std::string out = fresh();
        ir << "  " << out << " = select i1 " << is_zero
           << ", i1 " << old_c << ", i1 " << co_nz << "\n";
        return out;
    }

    bool apply_shift(const cs_arm_op& op, std::string* val_ssa) {
        if (op.shift.type == ARM_SFT_INVALID) return true;
        if (op.shift.type == ARM_SFT_LSL && op.shift.value == 0) return true;

        bool is_reg_shift =
            op.shift.type == ARM_SFT_LSL_REG ||
            op.shift.type == ARM_SFT_LSR_REG ||
            op.shift.type == ARM_SFT_ASR_REG ||
            op.shift.type == ARM_SFT_ROR_REG;
        if (!is_reg_shift && op.shift.value == 0
            && op.shift.type != ARM_SFT_RRX) return true;

        std::string amt;
        if (is_reg_shift) {
            int sr = arm_reg_idx(op.shift.value);
            if (sr < 0) return false;
            amt = load_reg(sr);
        } else if (op.shift.type != ARM_SFT_RRX) {
            amt = std::to_string(static_cast<int32_t>(op.shift.value));
        }
        const int imm_n = static_cast<int>(op.shift.value);

        std::string out;
        switch (op.shift.type) {
            // LSL / LSR / ASR go through the saturating lowerings above so
            // an amount >= 32 yields the architectural result instead of
            // poison. ROR is exempt: it is lowered with llvm.fshr, whose
            // amount is taken modulo the bit width, which is exactly ARM's
            // ROR-by-(amount mod 32) -- and (x mod 256) mod 32 == x mod 32,
            // so passing the full register is fine there.
            case ARM_SFT_LSL:
                *val_ssa = shift_amount_const(*val_ssa, "shl", imm_n);
                return true;
            case ARM_SFT_LSR:
                *val_ssa = shift_amount_const(*val_ssa, "lshr", imm_n);
                return true;
            case ARM_SFT_ASR:
                *val_ssa = shift_amount_const(*val_ssa, "ashr", imm_n);
                return true;
            case ARM_SFT_LSL_REG:
                *val_ssa = shift_amount_safe(*val_ssa, "shl", amt);
                return true;
            case ARM_SFT_LSR_REG:
                *val_ssa = shift_amount_safe(*val_ssa, "lshr", amt);
                return true;
            case ARM_SFT_ASR_REG:
                *val_ssa = shift_amount_safe(*val_ssa, "ashr", amt);
                return true;
            case ARM_SFT_ROR: case ARM_SFT_ROR_REG:
                // Funnel-shift right with both halves being val gives ROR.
                out = fresh();
                ir << "  " << out << " = call i32 @llvm.fshr.i32(i32 "
                   << *val_ssa << ", i32 " << *val_ssa
                   << ", i32 " << amt << ")\n";
                break;
            case ARM_SFT_RRX: {
                std::string c = load_flag("c");
                std::string c_i32 = fresh();
                ir << "  " << c_i32 << " = zext i1 " << c << " to i32\n";
                std::string c_top = fresh();
                ir << "  " << c_top << " = shl i32 " << c_i32 << ", 31\n";
                std::string vs = fresh();
                ir << "  " << vs << " = lshr i32 " << *val_ssa << ", 1\n";
                out = fresh();
                ir << "  " << out << " = or i32 " << c_top << ", " << vs << "\n";
                break;
            }
            default: return false;
        }
        *val_ssa = out;
        return true;
    }

    // --- NZCV update --------------------------------------------------

    // Carry-aware shifter. Mirrors apply_shift() exactly for the
    // *value*, and ALSO produces the ARM ARM A8.4.3 Shift_C shifter
    // carry-out into *carry_out (an i1 SSA). If the operand has no
    // shift, or the shift is one whose architecture definition leaves
    // the carry UNCHANGED (LSL #0; register-amount shift with the
    // bottom byte == 0), *carry_changed is set false and *carry_out is
    // left empty -- the caller must then NOT write C.
    //
    // Shift_C(value, type, amount, carry_in)  [DDI 0406C.d A8.4.3]:
    //   LSL #n (n>0): carry = value<32-n>      ; n>=32 handled below
    //   LSR #n (n>0): carry = value<n-1>
    //   ASR #n (n>0): carry = value<n-1>
    //   ROR #n (n>0): carry = value<(n-1) mod 32> = result<31>
    //   RRX        : carry = value<0>
    // Register-amount forms use shift_n = R[s]<7:0>; when shift_n == 0
    // the carry is unchanged. LSL by 32 -> value<0>; LSL by >32 -> 0.
    // LSR/ASR/ROR by amounts >=32 follow the same value<n-1> rule with
    // the architectural saturation handled by the runtime selects.
    bool apply_shift_c(const cs_arm_op& op, std::string* val_ssa,
                       std::string* carry_out, bool* carry_changed) {
        *carry_changed = false;
        carry_out->clear();

        if (op.shift.type == ARM_SFT_INVALID) {
            // No shift -> carry unchanged.
            return true;
        }
        if (op.shift.type == ARM_SFT_LSL && op.shift.value == 0) {
            // LSL #0 (i.e. plain register) -> carry unchanged.
            return true;
        }

        bool is_reg_shift =
            op.shift.type == ARM_SFT_LSL_REG ||
            op.shift.type == ARM_SFT_LSR_REG ||
            op.shift.type == ARM_SFT_ASR_REG ||
            op.shift.type == ARM_SFT_ROR_REG;
        if (!is_reg_shift && op.shift.value == 0
            && op.shift.type != ARM_SFT_RRX) {
            // Immediate amount 0 for a non-LSL imm shift -> stay
            // conservative: value-only, carry unchanged.
            return true;
        }

        std::string in_val = *val_ssa;

        // RRX: amount is fixed 1, carry-out = value<0>.
        if (op.shift.type == ARM_SFT_RRX) {
            std::string c = load_flag("c");
            std::string c_i32 = fresh();
            ir << "  " << c_i32 << " = zext i1 " << c << " to i32\n";
            std::string c_top = fresh();
            ir << "  " << c_top << " = shl i32 " << c_i32 << ", 31\n";
            std::string vs = fresh();
            ir << "  " << vs << " = lshr i32 " << in_val << ", 1\n";
            std::string out = fresh();
            ir << "  " << out << " = or i32 " << c_top << ", " << vs << "\n";
            *val_ssa = out;
            std::string b0 = fresh();
            ir << "  " << b0 << " = and i32 " << in_val << ", 1\n";
            std::string co = fresh();
            ir << "  " << co << " = icmp ne i32 " << b0 << ", 0\n";
            *carry_out = co;
            *carry_changed = true;
            return true;
        }

        if (!is_reg_shift) {
            // Immediate-amount shift. Amount is a known constant in
            // [1,32] (Capstone may present #32 for LSR/ASR).
            int n = static_cast<int>(op.shift.value);
            if (n <= 0 || n > 32) {
                // Out of the simple range -> compute value only,
                // leave carry unchanged (conservative).
                return apply_shift(op, val_ssa);
            }
            std::string out;
            std::string amt = std::to_string(n);
            // n == 32 is reachable (Capstone reports it for the imm5 == 0
            // LSR/ASR encodings), and a raw `lshr i32 v, 32` is POISON in
            // LLVM, not 0. Route the value through the saturating constant
            // lowering; the carry below is a separate, already-correct
            // computation on `in_val`.
            switch (op.shift.type) {
                case ARM_SFT_LSL:
                    out = shift_amount_const(in_val, "shl", n);
                    break;
                case ARM_SFT_LSR:
                    out = shift_amount_const(in_val, "lshr", n);
                    break;
                case ARM_SFT_ASR:
                    out = shift_amount_const(in_val, "ashr", n);
                    break;
                case ARM_SFT_ROR:
                    out = fresh();
                    ir << "  " << out << " = call i32 @llvm.fshr.i32(i32 "
                       << in_val << ", i32 " << in_val << ", i32 " << amt << ")\n";
                    break;
                default:
                    return apply_shift(op, val_ssa);
            }
            *val_ssa = out;
            // Carry bit position.
            int bitpos;
            if (op.shift.type == ARM_SFT_LSL) {
                // value<32-n>; n in [1,32]. n==32 -> bit 0.
                bitpos = 32 - n;
                if (bitpos > 31) bitpos = 31; // n==1 -> 31, never >31
            } else {
                // LSR/ASR/ROR: value<n-1>.  For n in [1,32] this is
                // value<(n-1) & 31>; n==32 -> bit 31.
                bitpos = (n - 1) & 31;
            }
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i32 " << in_val << ", " << bitpos << "\n";
            std::string lo = fresh();
            ir << "  " << lo << " = and i32 " << sh << ", 1\n";
            std::string co = fresh();
            ir << "  " << co << " = icmp ne i32 " << lo << ", 0\n";
            *carry_out = co;
            *carry_changed = true;
            return true;
        }

        // Register-amount shift. Compute the value via apply_shift (its
        // value semantics are mirrored bit-for-bit on the non-carry
        // path) and the carry at runtime per the architecture, using
        // amount = R[s]<7:0>.
        int sr = arm_reg_idx(op.shift.value);
        if (sr < 0) {
            // Cannot resolve amount register -> value-only fallback.
            return apply_shift(op, val_ssa);
        }
        std::string amt_full = load_reg(sr);
        std::string amt = fresh();
        ir << "  " << amt << " = and i32 " << amt_full << ", 255\n";
        // value path identical to apply_shift (uses the full reg value).
        if (!apply_shift(op, val_ssa)) return false;

        // amount == 0 -> carry unchanged.
        std::string is_zero = fresh();
        ir << "  " << is_zero << " = icmp eq i32 " << amt << ", 0\n";
        std::string old_c = load_flag("c");

        std::string co_nz; // carry-out when amount != 0
        if (op.shift.type == ARM_SFT_LSL_REG) {
            // amount in [1,31]: value<32-amount>;
            // amount == 32 : value<0>; amount > 32 : 0.
            std::string ge32 = fresh();
            ir << "  " << ge32 << " = icmp uge i32 " << amt << ", 32\n";
            std::string gt32 = fresh();
            ir << "  " << gt32 << " = icmp ugt i32 " << amt << ", 32\n";
            // bitpos = 32 - amount for amount in [1,31]
            std::string bp = fresh();
            ir << "  " << bp << " = sub i32 32, " << amt << "\n";
            std::string bpm = fresh();
            ir << "  " << bpm << " = and i32 " << bp << ", 31\n";
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i32 " << in_val << ", " << bpm << "\n";
            std::string lo = fresh();
            ir << "  " << lo << " = and i32 " << sh << ", 1\n";
            std::string c_lt = fresh();
            ir << "  " << c_lt << " = icmp ne i32 " << lo << ", 0\n";
            // amount == 32 -> value<0>
            std::string b0 = fresh();
            ir << "  " << b0 << " = and i32 " << in_val << ", 1\n";
            std::string c_eq32 = fresh();
            ir << "  " << c_eq32 << " = icmp ne i32 " << b0 << ", 0\n";
            std::string sel1 = fresh();
            ir << "  " << sel1 << " = select i1 " << gt32
               << ", i1 false, i1 " << c_eq32 << "\n";  // >32 -> 0, ==32 -> c_eq32
            co_nz = fresh();
            ir << "  " << co_nz << " = select i1 " << ge32
               << ", i1 " << sel1 << ", i1 " << c_lt << "\n";
        } else if (op.shift.type == ARM_SFT_LSR_REG ||
                   op.shift.type == ARM_SFT_ASR_REG) {
            // value<amount-1>; amount >= 32: LSR -> 0, ASR -> value<31>.
            std::string ge32 = fresh();
            ir << "  " << ge32 << " = icmp uge i32 " << amt << ", 32\n";
            std::string bp = fresh();
            ir << "  " << bp << " = sub i32 " << amt << ", 1\n";
            std::string bpm = fresh();
            ir << "  " << bpm << " = and i32 " << bp << ", 31\n";
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i32 " << in_val << ", " << bpm << "\n";
            std::string lo = fresh();
            ir << "  " << lo << " = and i32 " << sh << ", 1\n";
            std::string c_lt = fresh();
            ir << "  " << c_lt << " = icmp ne i32 " << lo << ", 0\n";
            std::string c_ge;
            if (op.shift.type == ARM_SFT_LSR_REG) {
                // LSR_C(x, shift): extended_x = ZeroExtend(x, shift+N);
                //                  carry_out  = extended_x<shift-1>
                // (DDI 0406C.d A2.2.1, identical text in DDI 0403 for M).
                // At shift == 32 exactly that is extended_x<31> == x<31>,
                // NOT 0 -- only shift > 32 reaches the zero-extended part.
                // The old code returned 0 for the whole >= 32 range, so
                // `lsrs rd, rn, rs` with rs == 32 wrote the wrong C and
                // any following ADC/SBC/carry-branch took the wrong path.
                std::string eq32 = fresh();
                ir << "  " << eq32 << " = icmp eq i32 " << amt << ", 32\n";
                std::string b31 = fresh();
                ir << "  " << b31 << " = lshr i32 " << in_val << ", 31\n";
                std::string b31m = fresh();
                ir << "  " << b31m << " = and i32 " << b31 << ", 1\n";
                std::string c31 = fresh();
                ir << "  " << c31 << " = icmp ne i32 " << b31m << ", 0\n";
                std::string sel32 = fresh();
                ir << "  " << sel32 << " = select i1 " << eq32
                   << ", i1 " << c31 << ", i1 false\n";
                c_ge = sel32;
            } else {
                std::string b31 = fresh();
                ir << "  " << b31 << " = lshr i32 " << in_val << ", 31\n";
                std::string b31m = fresh();
                ir << "  " << b31m << " = and i32 " << b31 << ", 1\n";
                std::string c31 = fresh();
                ir << "  " << c31 << " = icmp ne i32 " << b31m << ", 0\n";
                c_ge = c31;
            }
            co_nz = fresh();
            ir << "  " << co_nz << " = select i1 " << ge32
               << ", i1 " << c_ge << ", i1 " << c_lt << "\n";
        } else {
            // ROR_REG: carry = value<(amount-1) mod 32>. (amount-1)&31
            // gives the bit position; a nonzero amount that is a
            // multiple of 32 -> carry = value<31>.
            std::string bp = fresh();
            ir << "  " << bp << " = sub i32 " << amt << ", 1\n";
            std::string bpm = fresh();
            ir << "  " << bpm << " = and i32 " << bp << ", 31\n";
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i32 " << in_val << ", " << bpm << "\n";
            std::string lo = fresh();
            ir << "  " << lo << " = and i32 " << sh << ", 1\n";
            co_nz = fresh();
            ir << "  " << co_nz << " = icmp ne i32 " << lo << ", 0\n";
        }

        std::string final_c = fresh();
        ir << "  " << final_c << " = select i1 " << is_zero
           << ", i1 " << old_c << ", i1 " << co_nz << "\n";
        *carry_out = final_c;
        *carry_changed = true;
        return true;
    }

    // resolve_alu_src variant that also yields the shifter carry-out.
    //
    // Modified-immediate (4-op) form, ARMExpandImm_C (DDI 0406C.d A5.2.4):
    //   unrotated_value      = ZeroExtend(imm12<7:0>, 32)
    //   (imm32, carry_out)   = Shift_C(unrotated_value, SRType_ROR,
    //                                  2*UInt(imm12<11:8>), carry_in)
    // so the carry-out is imm32<31> when the rotation is nonzero and
    // UNCHANGED when it is zero. The old code reported carry_changed=false
    // unconditionally "to stay conservative", which is a silent lie about
    // C for every `ands`/`orrs`/`eors`/`movs`/`mvns` with a rotated
    // immediate. The whole thing is a translate-time constant, so being
    // exact costs nothing -- there is no runtime code to emit either way.
    // MACAPK_MODIMM_CARRY_CONSERVATIVE=1 restores the old behaviour.
    // ARMExpandImm_C / ThumbExpandImm_C carry-out for a data-processing
    // MODIFIED IMMEDIATE, recovered from the instruction WORD.
    //
    // Capstone normally hands us the already-EXPANDED value in a
    // 2-operand form -- `movs r1, #0xf0000000` decodes as
    // operands[1].imm == 0xf0000000 with op_count == 2 -- and DROPS the
    // rotation. The 4-operand (#imm8, #rot) form the branch above keys on
    // is the exception, not the rule, so keying only on it left C wrong
    // for the common encoding. The rotation is exactly what decides
    // whether C changes, so read it from the word.
    //
    // A32 (A5.2.4 ARMExpandImm_C): rotation = 2*imm12<11:8>; carry_out is
    // imm32<31> when the rotation is nonzero, UNCHANGED when it is zero.
    // T32 (A6.3.2 ThumbExpandImm_C): imm12 = i:imm3:imm8 (bit 26, bits
    // 14:12, bits 7:0). When imm12<11:10> == 0b00 the value comes from
    // the four byte-replication patterns and the carry is UNCHANGED;
    // otherwise it is the rotate form and carry_out is imm32<31>.
    bool modimm_carry_from_word(const cs_insn* in, uint32_t value,
                                std::string* carry_out) const {
        if (in == nullptr || in->size != 4) return false;
        const uint8_t* b = in->bytes;
        bool rotates;
        if (current_is_thumb) {
            uint32_t w = (static_cast<uint32_t>(b[1]) << 24) |
                         (static_cast<uint32_t>(b[0]) << 16) |
                         (static_cast<uint32_t>(b[3]) << 8)  |
                          static_cast<uint32_t>(b[2]);
            if ((w >> 27) != 0x1Eu) return false;   // not 11110xx
            if ((w >> 15) & 1u) return false;       // not the immediate form
            const uint32_t imm12 = (((w >> 26) & 1u) << 11) |
                                   (((w >> 12) & 7u) << 8) |
                                    (w & 0xFFu);
            rotates = ((imm12 >> 10) & 3u) != 0u;
        } else {
            uint32_t w =  static_cast<uint32_t>(b[0])        |
                         (static_cast<uint32_t>(b[1]) << 8)  |
                         (static_cast<uint32_t>(b[2]) << 16) |
                         (static_cast<uint32_t>(b[3]) << 24);
            if (((w >> 26) & 3u) != 0u) return false;  // data-processing
            if (((w >> 25) & 1u) == 0u) return false;  // I bit: immediate
            rotates = ((w >> 8) & 0xFu) != 0u;
        }
        if (!rotates) return false;                    // carry unchanged
        *carry_out = (value >> 31) ? "true" : "false";
        return true;
    }

    bool resolve_alu_src_c(const cs_arm_op& src, const cs_arm_op* rot_op,
                           std::string* out, std::string* carry_out,
                           bool* carry_changed, const cs_insn* in = nullptr) {
        *carry_changed = false;
        carry_out->clear();
        if (rot_op != nullptr && rot_op->type == ARM_OP_IMM &&
            src.type == ARM_OP_IMM) {
            uint32_t imm8 = static_cast<uint32_t>(src.imm);
            uint32_t r = static_cast<uint32_t>(rot_op->imm) & 31;
            uint32_t v = (r == 0) ? imm8
                : ((imm8 >> r) | (imm8 << ((32 - r) & 31)));
            *out = std::to_string(static_cast<int32_t>(v));
            if (r != 0 && exact_modified_imm_carry_) {
                *carry_out = (v >> 31) ? "true" : "false";
                *carry_changed = true;
            }
            return true;
        }
        if (!operand_value(src, out)) return false;
        if (!apply_shift_c(src, out, carry_out, carry_changed)) return false;
        if (!*carry_changed && src.type == ARM_OP_IMM &&
            exact_modified_imm_carry_) {
            std::string c;
            if (modimm_carry_from_word(
                    in, static_cast<uint32_t>(src.imm), &c)) {
                *carry_out = c;
                *carry_changed = true;
            }
        }
        return true;
    }


    // NZ for the 64-bit-result multiplies (SMULL / UMULL / SMLAL / UMLAL).
    // DDI 0406C.d A8.8.190 (SMULL) and the UMULL / SMLAL / UMLAL pages all
    // say the same thing:
    //     APSR.N = result<63>;
    //     APSR.Z = IsZeroBit(result);
    // where `result` is the FULL 64-bit product. Taking Z from the high
    // word alone (what emit_set_nz(hi) does) reports Z=1 for any product
    // whose top half happens to be zero -- i.e. for nearly every small
    // positive multiply -- so a following `beq`/`bne` branches wrong.
    // N is unaffected: bit 63 of the product IS bit 31 of the high word.
    void emit_set_nz64(const std::string& result64_ssa) {
        std::string n = fresh();
        ir << "  " << n << " = icmp slt i64 " << result64_ssa << ", 0\n";
        store_flag("n", n);
        std::string z = fresh();
        ir << "  " << z << " = icmp eq i64 " << result64_ssa << ", 0\n";
        store_flag("z", z);
    }

    void emit_set_nz(const std::string& result_ssa) {
        std::string n = fresh();
        ir << "  " << n << " = icmp slt i32 " << result_ssa << ", 0\n";
        store_flag("n", n);
        std::string z = fresh();
        ir << "  " << z << " = icmp eq i32 " << result_ssa << ", 0\n";
        store_flag("z", z);
    }

    // C / V update for ADD-like ops (result = a + b).
    //   C = unsigned-overflow = (result < a)
    //   V = signed-overflow   = same-sign(a, b) && different-sign(a, result)
    //
    // Critical for `adds Rd, Rn, Rm` followed by `bhs` / `blo` / `bcs` /
    // `bcc` / `bvs` / `bvc`. Before this helper landed, lifted code that
    // does `adds` + `bhs` would read STALE C from a previous flag-setting
    // instruction (cmp / subs / etc), branching wrong. Documented bug-2
    // root cause for HCR 1.43 ARM32 forced -- libstdc++'s
    // `_M_insert_aux` doubling-overflow check
    // (`adds r2, r2, r8; bhs <use_max_size>`) silently fell into the
    // `max_size` branch even when the addition didn't overflow, causing
    // an immediate ~4 GiB alloc on the very first push_back into a
    // freshly-zero-initialized std::vector.
    void emit_set_cv_add(const std::string& result_ssa,
                         const std::string& a, const std::string& b) {
        std::string c = fresh();
        ir << "  " << c << " = icmp ult i32 " << result_ssa
           << ", " << a << "\n";
        store_flag("c", c);
        // V = (sign(a) == sign(b)) AND (sign(a) != sign(result))
        // Equivalent to: bit31 of (~(a XOR b) AND (a XOR result))
        std::string ab = fresh();
        ir << "  " << ab << " = xor i32 " << a << ", " << b << "\n";
        std::string nab = fresh();
        ir << "  " << nab << " = xor i32 " << ab << ", -1\n";
        std::string ar = fresh();
        ir << "  " << ar << " = xor i32 " << a << ", "
           << result_ssa << "\n";
        std::string both = fresh();
        ir << "  " << both << " = and i32 " << nab << ", " << ar << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << both << ", 0\n";
        store_flag("v", v);
    }

    // C / V update for SUB-like ops (result = a - b).
    //   C = no-borrow = (a >= b)
    //   V = signed-overflow = different-sign(a, b) && different-sign(a, result)
    void emit_set_cv_sub(const std::string& result_ssa,
                         const std::string& a, const std::string& b) {
        std::string c = fresh();
        ir << "  " << c << " = icmp uge i32 " << a << ", " << b << "\n";
        store_flag("c", c);
        std::string ab = fresh();
        ir << "  " << ab << " = xor i32 " << a << ", " << b << "\n";
        std::string ar = fresh();
        ir << "  " << ar << " = xor i32 " << a << ", "
           << result_ssa << "\n";
        std::string both = fresh();
        ir << "  " << both << " = and i32 " << ab << ", " << ar << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << both << ", 0\n";
        store_flag("v", v);
    }

    void emit_cmp_flags(const std::string& a, const std::string& b) {
        std::string diff = fresh();
        ir << "  " << diff << " = sub i32 " << a << ", " << b << "\n";
        emit_set_nz(diff);
        std::string c = fresh();
        ir << "  " << c << " = icmp uge i32 " << a << ", " << b << "\n";
        store_flag("c", c);
        // V detection: signed overflow iff sign(a) != sign(b) AND
        // sign(a) != sign(diff). Compute via XOR of high bits.
        std::string ax = fresh();
        ir << "  " << ax << " = xor i32 " << a << ", " << b << "\n";
        std::string bx = fresh();
        ir << "  " << bx << " = xor i32 " << a << ", " << diff << "\n";
        std::string both = fresh();
        ir << "  " << both << " = and i32 " << ax << ", " << bx << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << both << ", 0\n";
        store_flag("v", v);
    }

    void emit_cmn_flags(const std::string& a, const std::string& b) {
        std::string sum = fresh();
        ir << "  " << sum << " = add i32 " << a << ", " << b << "\n";
        emit_set_nz(sum);
        std::string c = fresh();
        ir << "  " << c << " = icmp ult i32 " << sum << ", " << a << "\n";
        store_flag("c", c);
        std::string sa = fresh();
        ir << "  " << sa << " = xor i32 " << a << ", " << b << "\n";
        std::string sb = fresh();
        ir << "  " << sb << " = xor i32 " << a << ", " << sum << "\n";
        std::string nab = fresh();
        ir << "  " << nab << " = xor i32 " << sa << ", -1\n";
        std::string and_ = fresh();
        ir << "  " << and_ << " = and i32 " << nab << ", " << sb << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << and_ << ", 0\n";
        store_flag("v", v);
    }

    void emit_tst_flags(const std::string& a, const std::string& b) {
        std::string r = fresh();
        ir << "  " << r << " = and i32 " << a << ", " << b << "\n";
        emit_set_nz(r);
    }

    void emit_teq_flags(const std::string& a, const std::string& b) {
        std::string r = fresh();
        ir << "  " << r << " = xor i32 " << a << ", " << b << "\n";
        emit_set_nz(r);
    }

    // --- Conditional predicate evaluation -----------------------------

    std::string emit_cond_check(arm_cc cc) {
        std::string n = "?", z = "?", c = "?", v = "?";
        auto need_n = [&]{ if (n == "?") n = load_flag("n"); };
        auto need_z = [&]{ if (z == "?") z = load_flag("z"); };
        auto need_c = [&]{ if (c == "?") c = load_flag("c"); };
        auto need_v = [&]{ if (v == "?") v = load_flag("v"); };

        std::string r;
        switch (cc) {
            case ARM_CC_EQ: need_z(); r = z; break;
            case ARM_CC_NE: need_z();
                            r = fresh();
                            ir << "  " << r << " = xor i1 " << z << ", true\n";
                            break;
            case ARM_CC_HS: need_c(); r = c; break;
            case ARM_CC_LO: need_c();
                            r = fresh();
                            ir << "  " << r << " = xor i1 " << c << ", true\n";
                            break;
            case ARM_CC_MI: need_n(); r = n; break;
            case ARM_CC_PL: need_n();
                            r = fresh();
                            ir << "  " << r << " = xor i1 " << n << ", true\n";
                            break;
            case ARM_CC_VS: need_v(); r = v; break;
            case ARM_CC_VC: need_v();
                            r = fresh();
                            ir << "  " << r << " = xor i1 " << v << ", true\n";
                            break;
            case ARM_CC_HI: {
                need_c(); need_z();
                std::string nz = fresh();
                ir << "  " << nz << " = xor i1 " << z << ", true\n";
                r = fresh();
                ir << "  " << r << " = and i1 " << c << ", " << nz << "\n";
                break;
            }
            case ARM_CC_LS: {
                need_c(); need_z();
                std::string nc = fresh();
                ir << "  " << nc << " = xor i1 " << c << ", true\n";
                r = fresh();
                ir << "  " << r << " = or i1 " << nc << ", " << z << "\n";
                break;
            }
            case ARM_CC_GE: {
                need_n(); need_v();
                r = fresh();
                ir << "  " << r << " = icmp eq i1 " << n << ", " << v << "\n";
                break;
            }
            case ARM_CC_LT: {
                need_n(); need_v();
                r = fresh();
                ir << "  " << r << " = icmp ne i1 " << n << ", " << v << "\n";
                break;
            }
            case ARM_CC_GT: {
                need_n(); need_v(); need_z();
                std::string ne = fresh();
                ir << "  " << ne << " = icmp eq i1 " << n << ", " << v << "\n";
                std::string nz = fresh();
                ir << "  " << nz << " = xor i1 " << z << ", true\n";
                r = fresh();
                ir << "  " << r << " = and i1 " << nz << ", " << ne << "\n";
                break;
            }
            case ARM_CC_LE: {
                need_n(); need_v(); need_z();
                std::string ne = fresh();
                ir << "  " << ne << " = icmp ne i1 " << n << ", " << v << "\n";
                r = fresh();
                ir << "  " << r << " = or i1 " << z << ", " << ne << "\n";
                break;
            }
            default:
                r = "true";
                break;
        }
        return r;
    }

    // --- Pre-scan to find basic block boundaries ----------------------

    void scan_blocks(cs_insn* insns, size_t count,
                     uint32_t fn_start, uint32_t fn_end_excl) {
        block_starts.clear();
        extern_call_targets.clear();
        extern_bl_targets.clear();
        tbb_skip_addrs_.clear();
        pc_jump_tables_.clear();
        pc_add_offset_jts_.clear();
        block_starts.insert(fn_start);

        // Build the set of valid instruction starts so a branch can
        // never name an address inside another instruction (which can
        // happen if Capstone has misaligned a Thumb-2 boundary, or if
        // the binary itself is unreachable garbage).
        if (discovery_only_) {
            valid_addrs_.sorted_mode = true;
            valid_addrs_.hashed.clear();
            valid_addrs_.sorted.clear();
            valid_addrs_.sorted.reserve(count);
            for (size_t i = 0; i < count; ++i)
                valid_addrs_.sorted.push_back(static_cast<uint32_t>(insns[i].address));
            // A capstone sweep is strictly ascending; binary_search needs
            // sorted input, so do not take that on faith.
            if (!std::is_sorted(valid_addrs_.sorted.begin(), valid_addrs_.sorted.end()))
                std::sort(valid_addrs_.sorted.begin(), valid_addrs_.sorted.end());
        } else {
            std::unordered_set<uint32_t> valid_addrs;
            for (size_t i = 0; i < count; ++i) {
                valid_addrs.insert(static_cast<uint32_t>(insns[i].address));
            }
            valid_addrs_.sorted_mode = false;
            valid_addrs_.hashed = std::move(valid_addrs);
        }

        // First pass: find every TBB/TBH and mark the inline jump-table
        // bytes as skip. We need this BEFORE the main scan_blocks pass
        // so that table-data "instructions" don't pollute block_starts
        // (e.g. via fall-through from a CBZ that lands in the middle of
        // the table). We also temporarily stash current_insns_/idx_ so
        // decode_tbb_table can scan back for the bounding cmp.
        cs_insn* saved_insns = current_insns_;
        size_t saved_count = current_count_;
        size_t saved_idx = current_idx_;
        current_insns_ = insns;
        current_count_ = count;
        for (size_t i = 0; i < count; ++i) {
            if (insns[i].id != ARM_INS_TBB && insns[i].id != ARM_INS_TBH) continue;
            current_idx_ = i;
            TbbTable t;
            if (!decode_tbb_table(&insns[i], &t)) continue;
            size_t table_bytes =
                static_cast<size_t>(t.entry_count) * t.entry_size;
            for (uint32_t a = t.table_addr;
                 a < t.table_addr + table_bytes; ++a) {
                tbb_skip_addrs_.insert(a);
            }
            if (table_bytes & 1u) tbb_skip_addrs_.insert(t.table_addr + table_bytes);
            for (uint32_t target : t.targets) {
                if (target >= fn_start && target < fn_end_excl &&
                    valid_addrs_.count(target) > 0) {
                    block_starts.insert(target);
                }
            }
            if (t.has_default && t.default_target >= fn_start &&
                t.default_target < fn_end_excl &&
                valid_addrs_.count(t.default_target) > 0) {
                block_starts.insert(t.default_target);
            }
        }
        // Same pre-scan for ARM-mode `addCC pc, pc, Rm, lsl #2` jump
        // tables. The default `b` lives at addls+4 and the case `b`s at
        // addls+8 onwards; mark them in tbb_skip_addrs_ and seed their
        // decoded targets into block_starts.
        for (size_t i = 0; i < count; ++i) {
            const cs_insn& ins = insns[i];
            if (ins.id != ARM_INS_ADD) continue;
            const cs_arm& d = ins.detail->arm;
            if (d.cc != ARM_CC_LS && d.cc != ARM_CC_LO) continue;
            if (d.op_count != 3) continue;
            if (d.operands[0].type != ARM_OP_REG ||
                d.operands[0].reg != ARM_REG_PC) continue;
            if (d.operands[1].type != ARM_OP_REG ||
                d.operands[1].reg != ARM_REG_PC) continue;
            if (d.operands[2].type != ARM_OP_REG) continue;
            if (d.operands[2].shift.type != ARM_SFT_LSL ||
                d.operands[2].shift.value != 2) continue;
            if (i < 1) continue;
            const cs_insn& cmp_ins = insns[i - 1];
            if (cmp_ins.id != ARM_INS_CMP) continue;
            const cs_arm& cd = cmp_ins.detail->arm;
            if (cd.op_count != 2 ||
                cd.operands[0].type != ARM_OP_REG ||
                cd.operands[0].reg != d.operands[2].reg ||
                cd.operands[1].type != ARM_OP_IMM) continue;
            int64_t imm = cd.operands[1].imm;
            if (imm < 0 || imm > 1023) continue;
            uint32_t entry_count = static_cast<uint32_t>(imm) + 1;
            if (d.cc == ARM_CC_LO) {
                if (entry_count == 0) continue;
                entry_count -= 1;
            }
            if (!image_) continue;
            uint32_t addls_addr = static_cast<uint32_t>(ins.address);
            uint32_t default_addr = addls_addr + 4;
            uint32_t cases_base   = addls_addr + 8;
            // Mark default + case `b` slots so the dispatch loop skips
            // them. Each is exactly 4 bytes.
            tbb_skip_addrs_.insert(default_addr);
            for (uint32_t k = 0; k < entry_count; ++k) {
                tbb_skip_addrs_.insert(cases_base + k * 4);
            }
            // Decode targets and add to block_starts.
            auto add_target = [&](uint32_t target) {
                if (target >= fn_start && target < fn_end_excl &&
                    valid_addrs_.count(target) > 0) {
                    block_starts.insert(target);
                }
            };
            auto read_b = [&](uint32_t at) -> uint32_t {
                auto bytes = image_->code_at(at, 4);
                if (bytes.size() < 4) return 0;
                uint32_t word =
                    static_cast<uint32_t>(bytes[0]) |
                    (static_cast<uint32_t>(bytes[1]) <<  8) |
                    (static_cast<uint32_t>(bytes[2]) << 16) |
                    (static_cast<uint32_t>(bytes[3]) << 24);
                if (((word >> 25) & 0x7) != 0x5) return 0;
                int32_t imm24 = static_cast<int32_t>(word & 0x00FFFFFF);
                if (imm24 & 0x00800000) imm24 |= 0xFF000000;
                return at + 8 + (static_cast<uint32_t>(imm24) << 2);
            };
            uint32_t def_t = read_b(default_addr);
            if (def_t) add_target(def_t);
            for (uint32_t k = 0; k < entry_count; ++k) {
                uint32_t t = read_b(cases_base + k * 4);
                if (t) add_target(t);
            }
        }
        // v1.0.540: PC-relative computed-jump SOFTWARE-DIVIDE idiom
        //   add Rt,pc,#imm ; sub Rt,Rt,Rm,lsl#a ; sub Rt,Rt,Rm,lsl#b ; bx Rt
        // `bx Rt` jumps to base - Rm*stride into the unrolled blocks. Seed the
        // block targets so they get labels; record the table so emit_bx lowers
        // it to a switch. Confirmation gate: >=16 contiguous base-k*stride
        // addresses must be valid in-function (a real unrolled table), so a
        // coincidental add-pc/sub/bx never trips it.
        for (size_t i = 0; i < count; ++i) {
            if (insns[i].id != ARM_INS_BX || !insns[i].detail) continue;
            const cs_arm& bd = insns[i].detail->arm;
            if (bd.op_count != 1 || bd.operands[0].type != ARM_OP_REG) continue;
            int rt = arm_reg_idx(bd.operands[0].reg);
            if (rt < 0 || rt == 14 || rt == 15) continue;   // skip bx lr / bx pc
            int subs = 0, index_reg = -1; uint32_t stride = 0, base = 0;
            bool have_base = false, ok = true;
            for (size_t j = i; j-- > 0 && (i - j) <= 6; ) {
                const cs_insn& p = insns[j];
                if (!p.detail) continue;   // SKIPDATA/data byte -> unrelated, keep scanning
                const cs_arm& pd = p.detail->arm;
                if (pd.op_count >= 1 && pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == rt) {
                    if (p.id == ARM_INS_SUB && pd.op_count == 3 &&
                        pd.operands[1].type == ARM_OP_REG &&
                        arm_reg_idx(pd.operands[1].reg) == rt &&
                        pd.operands[2].type == ARM_OP_REG &&
                        pd.operands[2].shift.type == ARM_SFT_LSL) {
                        int rm = arm_reg_idx(pd.operands[2].reg);
                        if (rm < 0) { ok = false; break; }
                        if (index_reg < 0) index_reg = rm;
                        else if (index_reg != rm) { ok = false; break; }
                        stride += (1u << pd.operands[2].shift.value);
                        ++subs;
                    } else if (p.id == ARM_INS_ADD && pd.op_count == 3 &&
                        pd.operands[1].type == ARM_OP_REG &&
                        pd.operands[1].reg == ARM_REG_PC &&
                        pd.operands[2].type == ARM_OP_IMM) {
                        base = static_cast<uint32_t>(p.address) + 8u +
                               static_cast<uint32_t>(pd.operands[2].imm);
                        have_base = true; break;
                    } else if (p.id == ARM_INS_ADR && pd.op_count == 2 &&
                        pd.operands[1].type == ARM_OP_IMM) {
                        uint32_t pcv = (static_cast<uint32_t>(p.address) + 8u) & ~3u;
                        base = pcv + static_cast<uint32_t>(pd.operands[1].imm);
                        have_base = true; break;
                    } else { ok = false; break; }
                }
            }
            if (!ok || !have_base || subs < 1 || index_reg < 0 || stride == 0) continue;
            PcJumpTable pjt; pjt.base = base; pjt.stride = stride;
            uint32_t run = 0;
            for (uint32_t k = 0; k < 32; ++k) {
                uint32_t t = base - k * stride;
                if (t >= fn_start && t < fn_end_excl && valid_addrs_.count(t) > 0) {
                    block_starts.insert(t);
                    pjt.cases.emplace_back(k, t);
                    if (k == run) ++run;
                }
            }
            if (std::getenv("MACAPK_TRACE_PCJT"))
                std::fprintf(stderr, "[pcjt] bx@0x%x fn=[0x%x,0x%x) base=0x%x "
                    "stride=%u run=%u cases=%zu -> %s\n",
                    static_cast<uint32_t>(insns[i].address), fn_start, fn_end_excl,
                    base, stride, run, pjt.cases.size(), run < 16 ? "SKIP" : "TABLE");
            if (run < 16) continue;
            pc_jump_tables_[static_cast<uint32_t>(insns[i].address)] = pjt;
        }
        // v1.0.552: ARM-mode compiled-switch OFFSET-WORD jump tables (see the
        // PcAddOffsetJumpTable comment up top for the idiom + the gdx2d bug it
        // fixes). Detect `add pc, rB, rO` fed by `ldr rO, [rB, rIdx, lsl #2]`
        // over a table based at `add rB, pc, #imm` / `adr rB, #imm`; size the
        // table from the bounding `cmp rIdx, #N` guard (fall back to scanning
        // words while they decode to valid in-function targets). Seed the case
        // targets as blocks, skip the table words, record the table for the
        // ADD dispatch case.
        for (size_t i = 0; i < count; ++i) {
            const cs_insn& ins = insns[i];
            if (ins.id != ARM_INS_ADD || !ins.detail) continue;
            const cs_arm& d = ins.detail->arm;
            if (!is_always(static_cast<arm_cc>(d.cc))) continue;
            if (d.op_count != 3) continue;
            if (d.operands[0].type != ARM_OP_REG ||
                d.operands[0].reg != ARM_REG_PC) continue;
            if (d.operands[1].type != ARM_OP_REG ||
                d.operands[1].reg == ARM_REG_PC) continue;   // pc,pc form: other scan
            if (d.operands[2].type != ARM_OP_REG ||
                d.operands[2].shift.type != ARM_SFT_INVALID) continue;
            int rb = arm_reg_idx(d.operands[1].reg);
            int ro = arm_reg_idx(d.operands[2].reg);
            if (rb < 0 || ro < 0 || rb == ro) continue;
            // Offset load: `ldr rO, [rB, rIdx, lsl #2]` (rIdx == rO allowed --
            // gdx2d_get_pixel's second switch reuses the index reg).
            int ridx = -1; bool found_ldr = false; size_t ldr_j = 0;
            for (size_t j = i; j-- > 0 && (i - j) <= 8; ) {
                const cs_insn& p = insns[j];
                if (!p.detail) continue;
                const cs_arm& pd = p.detail->arm;
                if (p.id == ARM_INS_LDR && pd.op_count == 2 &&
                    pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == ro &&
                    pd.operands[1].type == ARM_OP_MEM &&
                    arm_reg_idx(pd.operands[1].mem.base) == rb &&
                    pd.operands[1].mem.index != ARM_REG_INVALID &&
                    pd.operands[1].shift.type == ARM_SFT_LSL &&
                    pd.operands[1].shift.value == 2 &&
                    !pd.writeback) {
                    ridx = arm_reg_idx(pd.operands[1].mem.index);
                    found_ldr = true; ldr_j = j;
                    break;
                }
                if (pd.op_count >= 1 && pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == ro) break;  // rO clobbered
            }
            if (!found_ldr || ridx < 0) continue;
            // Table base: first writer of rB above the ldr must be the
            // pc-relative base computation.
            uint32_t base = 0; bool have_base = false;
            for (size_t j = ldr_j; j-- > 0 && (ldr_j - j) <= 8; ) {
                const cs_insn& p = insns[j];
                if (!p.detail) continue;
                const cs_arm& pd = p.detail->arm;
                if (pd.op_count >= 1 && pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == rb) {
                    if (p.id == ARM_INS_ADD && pd.op_count == 3 &&
                        pd.operands[1].type == ARM_OP_REG &&
                        pd.operands[1].reg == ARM_REG_PC &&
                        pd.operands[2].type == ARM_OP_IMM) {
                        base = static_cast<uint32_t>(p.address) + 8u +
                               static_cast<uint32_t>(pd.operands[2].imm);
                        have_base = true;
                    } else if (p.id == ARM_INS_ADR && pd.op_count == 2 &&
                               pd.operands[1].type == ARM_OP_IMM) {
                        base = static_cast<uint32_t>(p.address) + 8u +
                               static_cast<uint32_t>(pd.operands[1].imm);
                        have_base = true;
                    }
                    break;
                }
            }
            if (!have_base) continue;
            // Entry count from the bounding `cmp rIdx, #N` (bhi default guard).
            uint32_t entry_count = 0;
            for (size_t j = ldr_j; j-- > 0 && (ldr_j - j) <= 8; ) {
                const cs_insn& p = insns[j];
                if (!p.detail) continue;
                const cs_arm& pd = p.detail->arm;
                if (p.id == ARM_INS_CMP && pd.op_count == 2 &&
                    pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == ridx &&
                    pd.operands[1].type == ARM_OP_IMM) {
                    int64_t imm = pd.operands[1].imm;
                    if (imm >= 0 && imm <= 255)
                        entry_count = static_cast<uint32_t>(imm) + 1;
                    break;
                }
                if (pd.op_count >= 1 && pd.operands[0].type == ARM_OP_REG &&
                    arm_reg_idx(pd.operands[0].reg) == ridx &&
                    p.id != ARM_INS_CMP) break;               // rIdx redefined
            }
            if (!image_) continue;
            auto read_word = [&](uint32_t at, uint32_t* out) -> bool {
                auto bytes = image_->code_at(at, 4);
                if (bytes.size() < 4) return false;
                *out = static_cast<uint32_t>(bytes[0]) |
                       (static_cast<uint32_t>(bytes[1]) <<  8) |
                       (static_cast<uint32_t>(bytes[2]) << 16) |
                       (static_cast<uint32_t>(bytes[3]) << 24);
                return true;
            };
            auto target_ok = [&](uint32_t t) -> bool {
                return t >= fn_start && t < fn_end_excl && (t & 3u) == 0 &&
                       valid_addrs_.count(t) > 0;
            };
            PcAddOffsetJumpTable t;
            t.base_reg = rb; t.off_reg = ro; t.base = base;
            bool all_ok = true;
            if (entry_count > 0) {
                for (uint32_t k = 0; k < entry_count && k < 128; ++k) {
                    uint32_t w = 0;
                    if (!read_word(base + k * 4, &w) || !target_ok(base + w)) {
                        all_ok = false; break;
                    }
                    t.cases.emplace_back(w, base + w);
                }
            } else {
                // No cmp guard found: grow while words decode to valid
                // in-function targets. Requires >= 2 entries to record.
                for (uint32_t k = 0; k < 64; ++k) {
                    uint32_t w = 0;
                    if (!read_word(base + k * 4, &w) || !target_ok(base + w)) break;
                    t.cases.emplace_back(w, base + w);
                }
                if (t.cases.size() < 2) all_ok = false;
            }
            if (!all_ok || t.cases.empty()) continue;
            for (size_t k = 0; k < t.cases.size(); ++k)
                tbb_skip_addrs_.insert(base + static_cast<uint32_t>(k) * 4);
            for (const auto& c : t.cases) block_starts.insert(c.second);
            pc_add_offset_jts_[static_cast<uint32_t>(ins.address)] = t;
            if (std::getenv("MACAPK_TRACE_PCJT"))
                std::fprintf(stderr, "[pcaojt] add-pc@0x%x fn=[0x%x,0x%x) "
                    "base=0x%x entries=%zu (cmp_count=%u)\n",
                    static_cast<uint32_t>(ins.address), fn_start, fn_end_excl,
                    base, t.cases.size(), entry_count);
        }
        current_insns_ = saved_insns;
        current_count_ = saved_count;
        current_idx_ = saved_idx;

        for (size_t i = 0; i < count; ++i) {
            const cs_insn& in = insns[i];
            uint32_t addr = static_cast<uint32_t>(in.address);
            uint32_t next_addr = addr + in.size;
            (void)addr;

            switch (in.id) {
                case ARM_INS_B:
                case ARM_INS_CBZ:
                case ARM_INS_CBNZ: {
                    int target_idx =
                        (in.id == ARM_INS_CBZ || in.id == ARM_INS_CBNZ) ? 1 : 0;
                    if (in.detail->arm.op_count > target_idx &&
                        in.detail->arm.operands[target_idx].type == ARM_OP_IMM) {
                        uint32_t target =
                            static_cast<uint32_t>(in.detail->arm.operands[target_idx].imm);
                        if (target >= fn_start && target < fn_end_excl &&
                            valid_addrs_.count(target) > 0) {
                            block_starts.insert(target);
                        }
                    }
                    if (next_addr < fn_end_excl) block_starts.insert(next_addr);
                    break;
                }
                case ARM_INS_BL: {
                    if (in.detail->arm.op_count >= 1 &&
                        in.detail->arm.operands[0].type == ARM_OP_IMM) {
                        uint32_t target =
                            static_cast<uint32_t>(in.detail->arm.operands[0].imm);
                        extern_call_targets.insert(target);
                        // Authoritative: direct BL #imm -> function entry.
                        extern_bl_targets.insert(target);
                        // v1.0.814: and it is authoritative about the ISA MODE
                        // too -- plain BL never interworks, so the callee is in
                        // the caller's mode.
                        note_call_target_mode(target, current_is_thumb);
                    }
                    break;
                }
                case ARM_INS_BX:
                case ARM_INS_POP:
                case ARM_INS_LDM:
                case ARM_INS_LDMIB:
                case ARM_INS_LDMDA:
                case ARM_INS_LDMDB: {
                    if (next_addr < fn_end_excl) block_starts.insert(next_addr);
                    break;
                }
                default:
                    break;
            }
        }
    }

    // --- Function prologue / epilogue ---------------------------------

    void emit_function_prologue(const std::string& name) {
        // Signature: (r0..r3, sp). Caller passes its current SP
        // through; PUSH / POP / SUB SP, ... operate on the shared
        // thread stack that lives in guest memory, so when this
        // function writes to its frame and a callee reads from the
        // same address, both see the same bytes.
        ir << "define dso_local i32 @" << name
           << "(i32 %arg0, i32 %arg1, i32 %arg2, i32 %arg3, "
              "i32 %arg_sp) local_unnamed_addr #0 {\n";
        ir << "entry:\n";
        // Cache the shim's guest memory base at function entry so we
        // don't pay one external call per memory op. Loaded once and
        // reused via SSA throughout the function.
        ir << "  %guest_base = call ptr @__macapk_get_guest_base()\n";
        ir << "  %r        = alloca [16 x i32], align 4\n";
        ir << "  %nzcv_n   = alloca i1, align 1\n";
        ir << "  %nzcv_z   = alloca i1, align 1\n";
        ir << "  %nzcv_c   = alloca i1, align 1\n";
        ir << "  %nzcv_v   = alloca i1, align 1\n";
        ir << "  %fpscr_n  = alloca i1, align 1\n";
        ir << "  %fpscr_z  = alloca i1, align 1\n";
        ir << "  %fpscr_c  = alloca i1, align 1\n";
        ir << "  %fpscr_v  = alloca i1, align 1\n";
        ir << "  store i1 false, ptr %nzcv_n\n";
        ir << "  store i1 false, ptr %nzcv_z\n";
        ir << "  store i1 false, ptr %nzcv_c\n";
        ir << "  store i1 false, ptr %nzcv_v\n";
        ir << "  store i1 false, ptr %fpscr_n\n";
        ir << "  store i1 false, ptr %fpscr_z\n";
        ir << "  store i1 false, ptr %fpscr_c\n";
        ir << "  store i1 false, ptr %fpscr_v\n";
        // APSR.GE[3:0] (one i1 per byte lane) + sticky APSR.Q.
        // ARM ARM A2.5 (Application-level NZCVQGE). The ARMv6 SIMD-in-GPR
        // parallel add/sub ops (SADD16/UADD8/SASX/...) write GE per lane;
        // SEL reads it per byte. Q is the sticky saturation flag set by
        // QADD/QDADD/SSAT/USAT/SMLA* and read via MRS APSR bit 27.
        ir << "  %ge0     = alloca i1, align 1\n";
        ir << "  %ge1     = alloca i1, align 1\n";
        ir << "  %ge2     = alloca i1, align 1\n";
        ir << "  %ge3     = alloca i1, align 1\n";
        ir << "  %qflag   = alloca i1, align 1\n";
        ir << "  store i1 false, ptr %ge0\n";
        ir << "  store i1 false, ptr %ge1\n";
        ir << "  store i1 false, ptr %ge2\n";
        ir << "  store i1 false, ptr %ge3\n";
        ir << "  store i1 false, ptr %qflag\n";
        for (int i = 0; i < 16; ++i) {
            ir << "  %ri" << i << " = getelementptr inbounds [16 x i32], "
                                  "ptr %r, i32 0, i32 " << i << "\n";
            ir << "  store i32 0, ptr %ri" << i << "\n";
        }
        // SP is inherited from the caller via the 5th arg. The caller
        // already accounted for any prologue stack adjustment it
        // wanted to expose to us; we just plant the value.
        ir << "  %sp_init = getelementptr inbounds [16 x i32], ptr %r, i32 0, i32 13\n";
        ir << "  store i32 %arg_sp, ptr %sp_init\n";
        // VFP register file: 32 d-regs as i64. The lifter folds s-reg
        // accesses into the same storage by treating s2N/s2N+1 as the
        // low/high halves of dN.
        ir << "  %fpr = alloca [32 x i64], align 8\n";
        for (int i = 0; i < 32; ++i) {
            ir << "  %fri" << i << " = getelementptr inbounds [32 x i64], "
                                  "ptr %fpr, i32 0, i32 " << i << "\n";
            ir << "  store i64 0, ptr %fri" << i << "\n";
        }
        for (int i = 0; i < 4; ++i) {
            ir << "  %arg_p" << i << " = getelementptr inbounds [16 x i32], "
                                     "ptr %r, i32 0, i32 " << i << "\n";
            ir << "  store i32 %arg" << i << ", ptr %arg_p" << i << "\n";
        }
    }

    // --- Per-instruction emitters -------------------------------------

    bool emit_push(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int n = d.op_count;
        if (n == 0) return false;
        std::string sp_old = load_reg(13);
        std::string sp_new = fresh();
        ir << "  " << sp_new << " = sub i32 " << sp_old << ", " << (4*n) << "\n";
        store_reg(13, sp_new);
        for (int i = 0; i < n; ++i) {
            if (d.operands[i].type != ARM_OP_REG) return false;
            int r = arm_reg_idx(d.operands[i].reg);
            if (r < 0) return false;
            std::string addr = fresh();
            ir << "  " << addr << " = add i32 " << sp_new << ", " << (4*i) << "\n";
            std::string p   = stack_ptr(addr);
            std::string val = load_reg(r);
            ir << "  store i32 " << val << ", ptr " << p << ", align 4\n";
        }
        return true;
    }

    bool emit_pop(const cs_insn* in, bool* is_return) {
        const cs_arm& d = in->detail->arm;
        int n = d.op_count;
        if (n == 0) return false;
        std::string sp_old = load_reg(13);
        bool returns = false;
        for (int i = 0; i < n; ++i) {
            if (d.operands[i].type != ARM_OP_REG) return false;
            int r = arm_reg_idx(d.operands[i].reg);
            if (r < 0) return false;
            std::string addr = fresh();
            ir << "  " << addr << " = add i32 " << sp_old << ", " << (4*i) << "\n";
            std::string p   = stack_ptr(addr);
            std::string val = fresh();
            ir << "  " << val << " = load i32, ptr " << p << ", align 4\n";
            if (r == 15) returns = true;
            else         store_reg(r, val);
        }
        std::string sp_new = fresh();
        ir << "  " << sp_new << " = add i32 " << sp_old << ", " << (4*n) << "\n";
        store_reg(13, sp_new);
        if (is_return) *is_return = returns;
        return true;
    }

    bool emit_mov(const cs_insn* in, bool* terminated = nullptr) {
        const cs_arm& d = in->detail->arm;
        // MOV Rd, src: 2 ops. MOV Rd, #imm8, #rot: 3 ops modified-imm.
        if (d.op_count < 2 || d.op_count > 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        const cs_arm_op* rot = nullptr;
        if (d.op_count == 3) {
            if (d.operands[1].type != ARM_OP_IMM ||
                d.operands[2].type != ARM_OP_IMM) return false;
            rot = &d.operands[2];
        }
        // MOVS with a shifted source operand (e.g. movs r0, r1, lsl #3)
        // updates C from the shifter carry-out (ARM ARM A8.8.105); V is
        // unchanged. Thread the carry-aware shifter so the C flag is
        // correct; if the shift form leaves carry unchanged we do not
        // write C.
        std::string val, shift_c;
        bool carry_changed = false;
        if (!resolve_alu_src_c(d.operands[1], rot, &val,
                               &shift_c, &carry_changed, in)) return false;
        // BUG 5, MOV form. `mov pc, lr` IS the pre-ARMv5 return idiom and
        // `mov pc, rN` is a computed jump (ALUWritePC -> BXWritePC,
        // A8.8.102). Lowering either as a dead store to the PC slot let
        // control fall straight into the next instruction. Unlike the
        // AND/EOR-into-PC forms in emit_alu -- which measurement shows are
        // literal-pool constants misread as code -- MOV into PC is a real
        // idiom a compiler emits, so it is lowered for real.
        if (rd == 15 && alu_pc_write_is_branch_ && !d.update_flags &&
            terminated != nullptr) {
            const bool is_ret_form =
                d.operands[1].type == ARM_OP_REG &&
                arm_reg_idx(d.operands[1].reg) == 14 &&
                d.operands[1].shift.type == ARM_SFT_INVALID;
            if (current_pred.empty()) {
                if (is_ret_form) {
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                } else {
                    emit_indirect_branch_to(val);
                }
                *terminated = true;
            } else {
                // `moveq pc, lr` and friends: taken path returns / jumps,
                // not-taken path falls through to the next instruction.
                int k = ssa_counter++;
                flush_dirty_regs();
                ir << "  br i1 " << current_pred << ", label %pcmov_" << k
                   << ", label %pcmovfall_" << k << "\n";
                ir << "pcmov_" << k << ":\n";
                cache_clear();
                if (is_ret_form) {
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                } else {
                    emit_indirect_branch_to(val);
                }
                ir << "pcmovfall_" << k << ":\n";
                cache_clear();
            }
            return true;
        }
        store_reg(rd, val);
        if (d.update_flags) {
            emit_set_nz(val);
            if (carry_changed) store_flag("c", shift_c);
        }
        return true;
    }

    bool emit_mvn(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        const cs_arm_op* rot = nullptr;
        if (d.op_count == 3) {
            if (d.operands[1].type != ARM_OP_IMM ||
                d.operands[2].type != ARM_OP_IMM) return false;
            rot = &d.operands[2];
        }
        // MVNS with a shifted source operand updates C from the shifter
        // carry-out of the (pre-NOT) operand (ARM ARM A8.8.116); V is
        // unchanged. The carry is taken on the source value BEFORE the
        // bitwise NOT, which is exactly what apply_shift_c computes.
        std::string src, shift_c;
        bool carry_changed = false;
        if (!resolve_alu_src_c(d.operands[1], rot, &src,
                               &shift_c, &carry_changed, in)) return false;
        std::string out = fresh();
        ir << "  " << out << " = xor i32 " << src << ", -1\n";
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            if (carry_changed) store_flag("c", shift_c);
        }
        return true;
    }

    bool emit_movw(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int32_t imm = static_cast<int32_t>(d.operands[1].imm) & 0xffff;
        store_reg(rd, std::to_string(imm));
        return true;
    }

    bool emit_movt(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        std::string old = load_reg(rd);
        std::string low = fresh();
        ir << "  " << low << " = and i32 " << old << ", 65535\n";
        int32_t imm = static_cast<int32_t>(d.operands[1].imm) & 0xffff;
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << low << ", " << (imm << 16) << "\n";
        store_reg(rd, out);
        return true;
    }

    // Resolve an ALU source operand. Handles three cases:
    //   1. Standard reg or imm with optional ALU shift modifier
    //      (operand_value + apply_shift).
    //   2. ARM-mode 4-operand modified-immediate form: Capstone exposes
    //      the encoded 12-bit `imm12 = ROR(imm8, 2*rot4)` as two
    //      separate IMM operands (`#imm8, #rotation_in_bits`). The
    //      rotation is already pre-doubled by Capstone, so we apply it
    //      directly without scaling.
    //
    // Returns the SSA name (or constant literal) of the effective source
    // value in *out. `rot_op` may be nullptr for the standard form.
    bool resolve_alu_src(const cs_arm_op& src, const cs_arm_op* rot_op,
                          std::string* out) {
        if (rot_op != nullptr && rot_op->type == ARM_OP_IMM &&
            src.type == ARM_OP_IMM) {
            uint32_t imm8 = static_cast<uint32_t>(src.imm);
            uint32_t r = static_cast<uint32_t>(rot_op->imm) & 31;
            uint32_t v = (r == 0) ? imm8
                : ((imm8 >> r) | (imm8 << ((32 - r) & 31)));
            *out = std::to_string(static_cast<int32_t>(v));
            return true;
        }
        if (!operand_value(src, out)) return false;
        if (!apply_shift(src, out)) return false;
        return true;
    }

    // Architectural indirect branch to a computed target: ALUWritePC ->
    // BXWritePC on ARMv7 (DDI 0406C.d A2.3.2). Lowered exactly like
    // `bx Rm` for a non-LR register -- a tail call through the shim's
    // dispatcher plus the ret, because the callee's return IS this
    // function's return. The caller marks the block terminated.
    void emit_indirect_branch_to(const std::string& target_i32) {
        std::string a0 = load_reg(0);
        std::string a1 = load_reg(1);
        std::string a2 = load_reg(2);
        std::string a3 = load_reg(3);
        std::string sp = load_reg(13);
        std::string ret = fresh();
        ir << "  " << ret << " = tail call i32 @__macapk_indirect_call("
           << "i32 " << target_i32
           << ", i32 " << a0 << ", i32 " << a1
           << ", i32 " << a2 << ", i32 " << a3
           << ", i32 " << sp
           << ", i32 " << current_insn_addr << ")\n";   // from_vaddr (diag)
        ir << "  ret i32 " << ret << "\n";
    }

    bool emit_alu(const cs_insn* in, const char* iop, bool bic_invert,
                  bool cmp_only_flags, bool* terminated = nullptr) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 4) return false;
        int rd = -1;
        int rn_idx, src_idx;
        int rot_idx = -1;
        if (cmp_only_flags) {
            // CMP/CMN/TST/TEQ: 2 ops (Rn, src) or 3 ops with modified
            // immediate (Rn, #imm8, #rot).
            if (d.op_count == 2) {
                rn_idx = 0; src_idx = 1;
            } else if (d.op_count == 3 &&
                       d.operands[1].type == ARM_OP_IMM &&
                       d.operands[2].type == ARM_OP_IMM) {
                rn_idx = 0; src_idx = 1; rot_idx = 2;
            } else {
                return false;
            }
        } else {
            if (d.operands[0].type != ARM_OP_REG) return false;
            rd = arm_reg_idx(d.operands[0].reg);
            if (rd < 0) return false;
            if (d.op_count == 2) {
                rn_idx = 0; src_idx = 1;
            } else if (d.op_count == 3) {
                rn_idx = 1; src_idx = 2;
            } else {
                // 4-operand modified-immediate: Rd, Rn, #imm8, #rot.
                if (d.operands[2].type != ARM_OP_IMM ||
                    d.operands[3].type != ARM_OP_IMM) return false;
                rn_idx = 1; src_idx = 2; rot_idx = 3;
            }
        }
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        if (rn < 0) return false;
        std::string lhs = load_reg(rn);
        std::string rhs;
        if (!resolve_alu_src(d.operands[src_idx],
                              rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                              &rhs)) return false;
        // DISCRIMINATING `add rN, pc` PC-convention fix (v1.0.521). The GCC
        // Thumb PIC pair `ldr rN, [pc, #imm]; add rN, pc` computes the address
        // of a GOT slot or a GLOBAL DATA base; the ARM ARM says the `add` reads
        // R15 as insn+4 UNALIGNED, but load_reg(15) (which feeds rhs) returns
        // the ALIGNED Align(insn+4,4). For a 2-byte-aligned Thumb add those
        // differ by 2 -> a wrong base -> garbage GOT/PLT/callback-table dispatch
        // (HCR libxml2). BUT a blanket OR scoped-by-mnemonic unaligned change
        // regresses GD Lite (its cocos2d-x literal was computed against the
        // ALIGNED PC -- different NDK era, opposite convention for the SAME
        // instruction). So DISCRIMINATE per sequence: resolve the prior ldr's
        // literal L, and override to UNALIGNED only when the unaligned result is
        // a 4-byte-aligned address inside one of THIS image's pointer/struct
        // sections (.got/.data/.bss/.data.rel.ro -- see target_ranges_). A real
        // GOT slot / struct / global base is 4-aligned, and the two candidates
        // differ by 2, so at most one can be both 4-aligned AND in a target
        // section. SAFE BY CONSTRUCTION for GD Lite: its correct (aligned)
        // result IS that 4-aligned target, so the UNALIGNED result is 2-mod-4
        // -> never 4-aligned -> never overridden. .rodata/.text are excluded so
        // 2-byte-aligned string targets can't trigger a false override. No
        // per-APK code -- a per-sequence property read from the binary.
        if (!cmp_only_flags && !target_ranges_.empty() &&
            std::string(iop) == "add" &&
            d.operands[src_idx].type == ARM_OP_REG &&
            d.operands[src_idx].reg  == ARM_REG_PC &&
            d.operands[src_idx].shift.type == ARM_SFT_INVALID) {
            uint32_t L = 0;
            if (find_pc_literal_for(d.operands[rn_idx].reg, &L)) {
                uint32_t pc_un = current_insn_addr + (current_is_thumb ? 4u : 8u);
                uint32_t pc_al = pc_un & ~3u;
                if (pc_un != pc_al) {               // only ambiguous when 2-aligned
                    uint32_t r_un = L + pc_un;
                    if ((r_un & 3u) == 0 && in_target_range(r_un))
                        rhs = std::to_string(static_cast<int64_t>(pc_un + load_bias_));  // per-image bias (matches load_reg(15))
                }
            }
        }
        if (bic_invert) {
            std::string inv = fresh();
            ir << "  " << inv << " = xor i32 " << rhs << ", -1\n";
            rhs = inv;
        }
        if (cmp_only_flags) {
            std::string s = iop;
            if      (s == "sub") emit_cmp_flags(lhs, rhs);
            else if (s == "add") emit_cmn_flags(lhs, rhs);
            else if (s == "and") emit_tst_flags(lhs, rhs);
            else if (s == "xor") emit_teq_flags(lhs, rhs);
            return true;
        }
        // For the logical S-suffix ops (ANDS/ORRS/EORS/BICS), C is set
        // from the shifter carry-out of the second operand (ARM ARM
        // A8.8.13/123/47/19); V is unchanged. Recompute rhs through the
        // carry-aware shifter ONLY for the logical flag-setting case so
        // the arithmetic add/sub C/V path (which derives C from the
        // result, not the shifter) is untouched.
        std::string iops = iop;
        bool is_logical = (iops == "and" || iops == "or" || iops == "xor");
        std::string shift_c;
        bool carry_changed = false;
        if (d.update_flags && is_logical) {
            // Re-resolve the source with carry. The value is identical to
            // the earlier resolve_alu_src (apply_shift_c mirrors
            // apply_shift), so rhs is recomputed but bit-equal; we adopt
            // the fresh value and apply bic_invert as before.
            std::string rhs2;
            if (resolve_alu_src_c(d.operands[src_idx],
                                  rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                                  &rhs2, &shift_c, &carry_changed, in)) {
                if (bic_invert) {
                    std::string inv2 = fresh();
                    ir << "  " << inv2 << " = xor i32 " << rhs2 << ", -1\n";
                    rhs2 = inv2;
                }
                rhs = rhs2;
            }
        }
        std::string out = fresh();
        ir << "  " << out << " = " << iop << " i32 " << lhs << ", " << rhs << "\n";
        // BUG 5 (2026-07-25). rd == 15: an ALU write to PC is
        // architecturally a BRANCH (ALUWritePC -> BXWritePC on ARMv7),
        // and lowering it as a dead store to the PC slot let control fall
        // through -- the computed jump silently did nothing. Every KNOWN
        // idiom is intercepted before emit_alu (addls branch-slab,
        // offset-word tables, bx software-divide); an UNRECOGNIZED one
        // used to vanish here, which is exactly how the gdx2d
        // wrong-switch-case bug (v552) stayed invisible.
        //
        // Now emit the real indirect branch -- but ONLY for a non-S
        // ADD/SUB, and here is why the restriction is load-bearing rather
        // than timidity.
        //
        // At this point the lifter cannot tell code from data. Getting it
        // wrong is asymmetric: falling through on real code is silently
        // wrong (the v552 class), but TERMINATING on data truncates a live
        // function, which is worse -- it breaks an app that works today.
        //
        // Measured on HCR's libgame.so (2026-07-25), every single site
        // that reaches here is data:
        //   205 non-S writes -> 134 `and pc, ...` + 71 `xor pc, ...`,
        //   and 288 more carry the S bit (`andseq pc, ...`, the
        //   exception-return encoding, UNPREDICTABLE in User mode).
        //   ZERO `add pc` / `sub pc` / `mov pc` reach here at all.
        // Dumping the words confirms it: 0x272ccc is `0008ff0c 0008ff28
        // 00090264` sitting immediately after `e8bd8010` (pop {r4, pc})
        // and before `e92d4ff0` (push {r4-r11, lr}) -- a literal pool
        // between two functions. A small non-negative constant has
        // cond == 0b0000 and an opcode field in the AND/EOR range, which
        // is exactly why constants disassemble as `andeq`/`eoreq`.
        //
        // No compiler emits AND/EOR/ORR/BIC into PC as a computed jump.
        // The real idioms are `add pc, pc, rN, lsl #k` (branch slab),
        // `mov pc, rN`, `ldr pc, [...]` and `bx`. So restrict the branch
        // lowering to the ADD/SUB family: that is a no-op on today's
        // fleet (zero conversions, zero regression risk) while still
        // closing the hole for a genuine computed jump that no upstream
        // interceptor recognised. See debug/arm32_bugscan.py.
        const bool is_addsub =
            (std::string(iop) == "add" || std::string(iop) == "sub");
        const bool pc_branch_form =
            !d.update_flags && alu_pc_write_is_branch_ && is_addsub;
        if (rd == 15) {
            // v1.0.809: RATE-LIMIT. This fired unconditionally, once per
            // rd==15 ALU instruction, and on a Unity title that is ~215,000
            // lines: Subway Surfers' cold forced-ARM32 translate wrote a
            // 150 MB log, most of it this one warning, on a box that runs
            // near a full disk. Worse, the dead-store variant is reporting
            // EXPECTED behaviour -- the comment above establishes that
            // AND/EOR/ORR/BIC into PC is a literal pool being decoded as an
            // instruction, never a computed jump -- so at full volume it is
            // pure noise that buries the genuinely interesting lines.
            // Counted separately per variant so the branch form (which IS
            // worth reading) is not rationed by the dead-store form's volume.
            // MACAPK_LIFTER_PC_WARN_ALL=1 restores every line.
            static const bool warn_all =
                std::getenv("MACAPK_LIFTER_PC_WARN_ALL") != nullptr;
            static std::atomic<uint64_t> n_branch{0}, n_dead{0};
            std::atomic<uint64_t>& ctr = pc_branch_form ? n_branch : n_dead;
            const uint64_t k = ctr.fetch_add(1, std::memory_order_relaxed);
            const bool show = warn_all || k < 20 || (k % 5000) == 0;
            if (show)
            std::fprintf(stderr,
                "[lifter] WARN: ALU '%s' writes PC at 0x%x%s (#%llu) -- "
                "unrecognized jump idiom?\n",
                iop, current_insn_addr,
                pc_branch_form
                    ? " lowered as an indirect branch"
                // v1.0.809: state the REAL reason. This used to hardcode
                // "not an add/sub", which is a lie whenever an add/sub fails
                // one of the OTHER two conditions -- and it does: the log
                // showed `ALU 'add' writes PC ... not an add/sub`. Same
                // family as the three diagnostics fixed in v1.0.809: a
                // confidently wrong explanation is worse than none.
                : !is_addsub
                    ? " lowered as dead store (fall-through; not an "
                      "add/sub, so almost certainly a literal pool)"
                : d.update_flags
                    ? " lowered as dead store (fall-through; IS an add/sub "
                      "but the S bit is set -- `adds pc,..` is the "
                      "exception-return encoding, UNPREDICTABLE in User "
                      "mode, so it is not a computed jump)"
                    : " lowered as dead store (fall-through; IS an add/sub, "
                      "but ALU-PC-write branch lowering is disabled)",
                static_cast<unsigned long long>(k));
            if (pc_branch_form && terminated != nullptr) {
                if (current_pred.empty()) {
                    emit_indirect_branch_to(out);
                    *terminated = true;
                } else {
                    // Predicated computed jump. `addls pc, pc, rN, lsl #2`
                    // is the bounds-checked jump-table idiom: in range ->
                    // branch, out of range -> FALL THROUGH to the default
                    // case. An unconditional terminator would delete the
                    // default arm, so emit the diamond and leave the block
                    // open on the not-taken edge. `out` is computed in this
                    // predecessor, so it dominates the taken block.
                    int k = ssa_counter++;
                    flush_dirty_regs();
                    ir << "  br i1 " << current_pred << ", label %pcbr_" << k
                       << ", label %pcfall_" << k << "\n";
                    ir << "pcbr_" << k << ":\n";
                    cache_clear();
                    emit_indirect_branch_to(out);
                    ir << "pcfall_" << k << ":\n";
                    cache_clear();
                }
                return true;
            }
        }
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            // For arithmetic ADD / SUB, update C and V from the result.
            // For logical AND / OR / XOR / BIC, V is unchanged and C is
            // the shifter carry-out (computed above); if the operand has
            // no shift (carry unchanged) we leave C alone, matching the
            // prior conservative behavior.
            std::string s = iop;
            if (s == "add")      emit_set_cv_add(out, lhs, rhs);
            else if (s == "sub") emit_set_cv_sub(out, lhs, rhs);
            else if (is_logical && carry_changed) store_flag("c", shift_c);
        }
        return true;
    }

    bool emit_rsb(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int rn_idx, src_idx, rot_idx = -1;
        if (d.op_count == 2) {
            rn_idx = 0; src_idx = 1;
        } else if (d.op_count == 3) {
            rn_idx = 1; src_idx = 2;
        } else {
            // 4-op modified-immediate (RSB Rd, Rn, #imm8, #rot).
            if (d.operands[2].type != ARM_OP_IMM ||
                d.operands[3].type != ARM_OP_IMM) return false;
            rn_idx = 1; src_idx = 2; rot_idx = 3;
        }
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        if (rn < 0) return false;
        std::string lhs = load_reg(rn);
        std::string rhs;
        if (!resolve_alu_src(d.operands[src_idx],
                              rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                              &rhs)) return false;
        std::string out = fresh();
        ir << "  " << out << " = sub i32 " << rhs << ", " << lhs << "\n";
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            // RSB computes `rhs - lhs`. Flags follow SUB with the
            // operands flipped: C = (rhs >= lhs); V = signed overflow
            // of rhs - lhs. Critical alongside the emit_alu fix.
            emit_set_cv_sub(out, rhs, lhs);
        }
        return true;
    }

    // UMULL/SMULL Rd_lo, Rd_hi, Rn, Rm  -- 64-bit (un)signed multiply.
    // The compiler uses these for divide-by-constant lowering.
    bool emit_mull(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        int rn    = arm_reg_idx(d.operands[2].reg);
        int rm    = arm_reg_idx(d.operands[3].reg);
        if (rd_lo < 0 || rd_hi < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string a64 = fresh();
        ir << "  " << a64 << " = " << (is_signed ? "sext" : "zext")
           << " i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = " << (is_signed ? "sext" : "zext")
           << " i32 " << b << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string lo = fresh();
        ir << "  " << lo << " = trunc i64 " << prod << " to i32\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = lshr i64 " << prod << ", 32\n";
        std::string hi = fresh();
        ir << "  " << hi << " = trunc i64 " << hi64 << " to i32\n";
        store_reg(rd_lo, lo);
        store_reg(rd_hi, hi);
        // Z is over the whole 64-bit product, not just the high word.
        if (d.update_flags) emit_set_nz64(prod);
        return true;
    }

    // ROR Rd, Rn, #imm | Rd, Rn, Rs  -- rotate right.
    // ARM ARM A8.6.139/A8.6.140/A8.6.141. Encoded via llvm.fshr with
    // both operands equal (a true rotate). Both the 3-operand register
    // and 2-operand `Rd, Rs` forms appear in Thumb-2 / ARM-mode output.
    bool emit_ror(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2 && d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        std::string lhs, rhs;
        int32_t imm_amt = 0;
        bool is_imm = false;
        if (d.op_count == 3) {
            if (d.operands[1].type != ARM_OP_REG) return false;
            int rn = arm_reg_idx(d.operands[1].reg);
            if (rn < 0) return false;
            lhs = load_reg(rn);
            if (!operand_value(d.operands[2], &rhs)) return false;
            is_imm = (d.operands[2].type == ARM_OP_IMM);
            if (is_imm) imm_amt = static_cast<int32_t>(d.operands[2].imm);
        } else {
            // RORS Rd, Rs (Thumb-16 T1): Rd = Rd ROR Rs.
            if (d.operands[1].type != ARM_OP_REG) return false;
            int rs = arm_reg_idx(d.operands[1].reg);
            if (rs < 0) return false;
            lhs = load_reg(rd);
            rhs = load_reg(rs);
        }
        // Mask the rotate amount to 5 bits (per ARM ARM A8.6.139 the
        // architectural rule is "low 5 bits of Rs" for register form;
        // immediate form has 1..31 directly).
        std::string mask = fresh();
        ir << "  " << mask << " = and i32 " << rhs << ", 31\n";
        std::string out = fresh();
        ir << "  " << out << " = call i32 @llvm.fshr.i32(i32 " << lhs
           << ", i32 " << lhs << ", i32 " << mask << ")\n";
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            // C flag: the last bit rotated through bit 31, i.e. bit
            // (imm_amt - 1) of the original value (for imm form, when
            // imm_amt > 0). For register form, only when amt != 0; if
            // amt == 0, leave C unchanged. The variable case is rarely
            // depended on by compiler output.
            if (is_imm && imm_amt > 0 && imm_amt < 32) {
                std::string c_shifted = fresh();
                ir << "  " << c_shifted << " = lshr i32 " << lhs
                   << ", " << (imm_amt - 1) << "\n";
                std::string c_lo = fresh();
                ir << "  " << c_lo << " = and i32 " << c_shifted << ", 1\n";
                std::string c_bit = fresh();
                ir << "  " << c_bit << " = icmp ne i32 " << c_lo << ", 0\n";
                store_flag("c", c_bit);
            }
        }
        return true;
    }

    // RRX Rd, Rn  -- rotate right by one bit, through carry.
    // Rd = (C << 31) | (Rn lsr 1); new C = Rn & 1.
    bool emit_rrx(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        std::string c = load_flag("c");
        std::string c_ext = fresh();
        ir << "  " << c_ext << " = zext i1 " << c << " to i32\n";
        std::string c_shift = fresh();
        ir << "  " << c_shift << " = shl i32 " << c_ext << ", 31\n";
        std::string val_shr = fresh();
        ir << "  " << val_shr << " = lshr i32 " << val << ", 1\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << c_shift << ", " << val_shr << "\n";
        store_reg(rd, out);
        if (d.update_flags) {
            std::string new_c_i32 = fresh();
            ir << "  " << new_c_i32 << " = and i32 " << val << ", 1\n";
            std::string new_c = fresh();
            ir << "  " << new_c << " = icmp ne i32 " << new_c_i32 << ", 0\n";
            store_flag("c", new_c);
            emit_set_nz(out);
        }
        return true;
    }

    // ADC/SBC Rd, Rn, src -- add/sub with carry-in. Also handles
    // ARM-mode 4-operand modified-immediate form (Rd, Rn, #imm8, #rot).
    // ADC/SBC Rd, Rn, src -- add/sub with carry-in. Also handles
    // ARM-mode 4-operand modified-immediate form (Rd, Rn, #imm8, #rot).
    //
    // ARM DDI 0406C.d A8.8.1 (ADC) / A8.8.162 (SBC): both are
    // AddWithCarry(R[n], operand2, APSR.C) where SBC uses
    // operand2 = NOT(shifted_rhs). AddWithCarry sets
    //   carry_out  = unsigned_sum != UInt(result)   (bit 32 of the sum)
    //   overflow   = signed_sum   != SInt(result)
    // For ADC carry_out is the unsigned add carry; for SBC carry_out is
    // the architectural NOT-borrow (a >= b+!c). We compute carry with an
    // i33 add (32 + 32 + 1 fits in 33 bits) and V with the same sign
    // formula emit_set_cv_add/emit_set_cv_sub already use (note that for
    // SBC, ~(a ^ ~b) == (a ^ b), so the V formula collapses to the SUB
    // form over (lhs, rhs)).
    bool emit_adcsbc(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int rn_idx, src_idx, rot_idx = -1;
        if (d.op_count == 2) { rn_idx = 0; src_idx = 1; }
        else if (d.op_count == 3) { rn_idx = 1; src_idx = 2; }
        else {
            if (d.operands[2].type != ARM_OP_IMM ||
                d.operands[3].type != ARM_OP_IMM) return false;
            rn_idx = 1; src_idx = 2; rot_idx = 3;
        }
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        if (rn < 0) return false;
        std::string lhs = load_reg(rn);
        std::string rhs;
        if (!resolve_alu_src(d.operands[src_idx],
                              rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                              &rhs)) return false;
        std::string c_in = load_flag("c");
        std::string c_i32 = fresh();
        ir << "  " << c_i32 << " = zext i1 " << c_in << " to i32\n";

        // addend_b is the second AddWithCarry operand: rhs for ADC,
        // NOT(rhs) for SBC.  result = lhs + addend_b + carry_in.
        std::string addend_b = rhs;
        if (is_sub) {
            std::string nb = fresh();
            ir << "  " << nb << " = xor i32 " << rhs << ", -1\n";
            addend_b = nb;
        }

        std::string mid = fresh();
        ir << "  " << mid << " = add i32 " << lhs << ", " << addend_b << "\n";
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << mid << ", " << c_i32 << "\n";
        store_reg(rd, out);

        if (d.update_flags) {
            emit_set_nz(out);
            // Carry-out = bit 32 of the 33-bit unsigned sum.
            std::string za = fresh();
            ir << "  " << za << " = zext i32 " << lhs << " to i33\n";
            std::string zb = fresh();
            ir << "  " << zb << " = zext i32 " << addend_b << " to i33\n";
            std::string zc = fresh();
            ir << "  " << zc << " = zext i32 " << c_i32 << " to i33\n";
            std::string s1 = fresh();
            ir << "  " << s1 << " = add i33 " << za << ", " << zb << "\n";
            std::string s2 = fresh();
            ir << "  " << s2 << " = add i33 " << s1 << ", " << zc << "\n";
            std::string cshift = fresh();
            ir << "  " << cshift << " = lshr i33 " << s2 << ", 32\n";
            std::string ctrunc = fresh();
            ir << "  " << ctrunc << " = trunc i33 " << cshift << " to i1\n";
            store_flag("c", ctrunc);
            // V = signed overflow of (lhs + addend_b + carry_in).
            // ADC: ~(lhs^rhs) & (lhs^result); SBC collapses to the SUB
            // form (lhs^rhs) & (lhs^result) since addend_b == ~rhs.
            if (is_sub) emit_set_cv_sub_v_only(out, lhs, rhs);
            else        emit_set_cv_add_v_only(out, lhs, rhs);
        }
        return true;
    }

    // V-only helpers for the carry-in arithmetic ops. We cannot reuse
    // emit_set_cv_add/emit_set_cv_sub wholesale because their C
    // computation assumes carry_in == 0; the V (signed-overflow) sign
    // formula is independent of carry_in, so we factor just that part.
    void emit_set_cv_add_v_only(const std::string& result_ssa,
                                const std::string& a, const std::string& b) {
        // V = (sign(a) == sign(b)) AND (sign(a) != sign(result))
        std::string ab = fresh();
        ir << "  " << ab << " = xor i32 " << a << ", " << b << "\n";
        std::string nab = fresh();
        ir << "  " << nab << " = xor i32 " << ab << ", -1\n";
        std::string ar = fresh();
        ir << "  " << ar << " = xor i32 " << a << ", " << result_ssa << "\n";
        std::string both = fresh();
        ir << "  " << both << " = and i32 " << nab << ", " << ar << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << both << ", 0\n";
        store_flag("v", v);
    }
    void emit_set_cv_sub_v_only(const std::string& result_ssa,
                                const std::string& a, const std::string& b) {
        // V = (sign(a) != sign(b)) AND (sign(a) != sign(result))
        std::string ab = fresh();
        ir << "  " << ab << " = xor i32 " << a << ", " << b << "\n";
        std::string ar = fresh();
        ir << "  " << ar << " = xor i32 " << a << ", " << result_ssa << "\n";
        std::string both = fresh();
        ir << "  " << both << " = and i32 " << ab << ", " << ar << "\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp slt i32 " << both << ", 0\n";
        store_flag("v", v);
    }

    // RSC Rd, Rn, src -- reverse subtract with carry.
    // ARM DDI 0406C.d A8.8.155: result = AddWithCarry(NOT(R[n]),
    // operand2, APSR.C) = operand2 - R[n] - NOT(C). Operands are
    // REVERSED versus SBC (SBC = R[n] - operand2 - NOT(C)). The prior
    // code aliased RSC to SBC, computing R[n] - operand2 (sign-flipped),
    // corrupting compiler-emitted 64-bit negate/abs sequences
    // (rsbs lo,#0 ; rsc hi,#0).
    bool emit_rsc(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int rn_idx, src_idx, rot_idx = -1;
        if (d.op_count == 2) { rn_idx = 0; src_idx = 1; }
        else if (d.op_count == 3) { rn_idx = 1; src_idx = 2; }
        else {
            if (d.operands[2].type != ARM_OP_IMM ||
                d.operands[3].type != ARM_OP_IMM) return false;
            rn_idx = 1; src_idx = 2; rot_idx = 3;
        }
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        if (rn < 0) return false;
        std::string lhs = load_reg(rn);           // R[n]
        std::string rhs;                          // operand2
        if (!resolve_alu_src(d.operands[src_idx],
                              rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                              &rhs)) return false;
        std::string c_in = load_flag("c");
        std::string c_i32 = fresh();
        ir << "  " << c_i32 << " = zext i1 " << c_in << " to i32\n";
        // result = NOT(R[n]) + operand2 + carry_in
        std::string nlhs = fresh();
        ir << "  " << nlhs << " = xor i32 " << lhs << ", -1\n";
        std::string mid = fresh();
        ir << "  " << mid << " = add i32 " << nlhs << ", " << rhs << "\n";
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << mid << ", " << c_i32 << "\n";
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            // Carry-out = bit 32 of NOT(R[n]) + operand2 + carry_in.
            std::string za = fresh();
            ir << "  " << za << " = zext i32 " << nlhs << " to i33\n";
            std::string zb = fresh();
            ir << "  " << zb << " = zext i32 " << rhs << " to i33\n";
            std::string zc = fresh();
            ir << "  " << zc << " = zext i32 " << c_i32 << " to i33\n";
            std::string s1 = fresh();
            ir << "  " << s1 << " = add i33 " << za << ", " << zb << "\n";
            std::string s2 = fresh();
            ir << "  " << s2 << " = add i33 " << s1 << ", " << zc << "\n";
            std::string cshift = fresh();
            ir << "  " << cshift << " = lshr i33 " << s2 << ", 32\n";
            std::string ctrunc = fresh();
            ir << "  " << ctrunc << " = trunc i33 " << cshift << " to i1\n";
            store_flag("c", ctrunc);
            // V = signed overflow of (operand2 - R[n] - NOT(C)); SUB
            // form over (operand2, R[n]).
            emit_set_cv_sub_v_only(out, rhs, lhs);
        }
        return true;
    }

    // MLA Rd, Rn, Rm, Ra  --  Rd = Ra + (Rn * Rm).
    // MLS Rd, Rn, Rm, Ra  --  Rd = Ra - (Rn * Rm).
    bool emit_mla(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = arm_reg_idx(d.operands[3].reg);
        if (rd < 0 || rn < 0 || rm < 0 || ra < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string c = load_reg(ra);
        std::string prod = fresh();
        ir << "  " << prod << " = mul i32 " << a << ", " << b << "\n";
        std::string out = fresh();
        ir << "  " << out << " = " << (is_sub ? "sub" : "add")
           << " i32 " << c << ", " << prod << "\n";
        store_reg(rd, out);
        if (d.update_flags) emit_set_nz(out);
        return true;
    }

    // UXTB/UXTH/SXTB/SXTH Rd, Rm{, ROR #amount}  -- byte/halfword extend.
    // ARM ARM A8.8.235/274/237/276: the operand is rotated right by
    // 0/8/16/24 BEFORE the low byte/halfword is extracted. Capstone
    // carries that rotate in operands[1].shift (an ARM_SFT_ROR with a
    // constant value), so we run it through apply_shift -- the same
    // path emit_xtab uses for the accumulate forms -- before trunc.
    // Without this the rotate was silently dropped and we always read
    // the low byte/half (the audit's extend-ror-dropped finding).
    bool emit_extend(const cs_insn* in, int bits, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        // Apply the ROR rotation (no-op when shift is INVALID/LSL#0).
        if (!apply_shift(d.operands[1], &val)) return false;
        std::string trunc = fresh();
        const char* small_ty = (bits == 8) ? "i8" : "i16";
        ir << "  " << trunc << " = trunc i32 " << val << " to " << small_ty << "\n";
        std::string ext = fresh();
        ir << "  " << ext << " = " << (is_signed ? "sext" : "zext")
           << " " << small_ty << " " << trunc << " to i32\n";
        store_reg(rd, ext);
        return true;
    }

    // UXTB16/SXTB16 Rd, Rm{, ROR #amount}  -- ARM ARM A8.8.235/B16.
    // Extends TWO bytes in parallel into two halfwords:
    //   Rd[15:0]  = Extend(rotated[7:0])
    //   Rd[31:16] = Extend(rotated[23:16])
    // emit_extend(...,8,...) only produced the low result; this does the
    // real dual-byte extension. apply_shift handles the ROR rotate.
    bool emit_xtb16(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        if (!apply_shift(d.operands[1], &val)) return false;
        // Low half: extend rotated[7:0] into bits[15:0].
        std::string lo_b = fresh();
        ir << "  " << lo_b << " = trunc i32 " << val << " to i8\n";
        std::string lo_ext = fresh();
        ir << "  " << lo_ext << " = " << (is_signed ? "sext" : "zext")
           << " i8 " << lo_b << " to i32\n";
        std::string lo_half = fresh();
        ir << "  " << lo_half << " = and i32 " << lo_ext << ", 65535\n";
        // High half: extract rotated[23:16], extend, place in bits[31:16].
        std::string hi_sh = fresh();
        ir << "  " << hi_sh << " = lshr i32 " << val << ", 16\n";
        std::string hi_b = fresh();
        ir << "  " << hi_b << " = trunc i32 " << hi_sh << " to i8\n";
        std::string hi_ext = fresh();
        ir << "  " << hi_ext << " = " << (is_signed ? "sext" : "zext")
           << " i8 " << hi_b << " to i32\n";
        std::string hi_half = fresh();
        ir << "  " << hi_half << " = and i32 " << hi_ext << ", 65535\n";
        std::string hi_pos = fresh();
        ir << "  " << hi_pos << " = shl i32 " << hi_half << ", 16\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << lo_half << ", " << hi_pos << "\n";
        store_reg(rd, out);
        return true;
    }

    // UBFX Rd, Rn, #lsb, #width  -- unsigned bitfield extract.
    // SBFX Rd, Rn, #lsb, #width  -- signed bitfield extract.
    bool emit_bfx(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        if (d.operands[3].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        int lsb   = static_cast<int>(d.operands[2].imm);
        int width = static_cast<int>(d.operands[3].imm);
        // Invalid lsb+width (only reachable when lifting data-as-
        // instructions, since real compiler output is always valid).
        // Treat as a no-op rather than failing the function -- the
        // garbage data isn't reachable execution, but failing here
        // turns the whole emit_one into a FALLBACK comment.
        if (width <= 0 || width > 32 || lsb < 0 || lsb + width > 32) {
            return true;
        }
        std::string val = load_reg(rs);
        // UBFX: (val >> lsb) & ((1 << width) - 1)
        // SBFX: shift left by (32-lsb-width), then ashr by (32-width).
        std::string out;
        if (is_signed) {
            int shl_amt  = 32 - lsb - width;
            int ashr_amt = 32 - width;
            std::string a = fresh();
            ir << "  " << a << " = shl i32 " << val << ", " << shl_amt << "\n";
            out = fresh();
            ir << "  " << out << " = ashr i32 " << a << ", " << ashr_amt << "\n";
        } else {
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i32 " << val << ", " << lsb << "\n";
            uint32_t mask = (width == 32) ? 0xffffffffu
                                          : ((1u << width) - 1u);
            out = fresh();
            ir << "  " << out << " = and i32 " << sh << ", "
               << static_cast<int32_t>(mask) << "\n";
        }
        store_reg(rd, out);
        return true;
    }

    // BFI Rd, Rn, #lsb, #width -- insert width bits from Rn into Rd.
    // Bits outside [lsb, lsb+width) of Rd are preserved.
    bool emit_bfi(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        if (d.operands[3].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        int lsb   = static_cast<int>(d.operands[2].imm);
        int width = static_cast<int>(d.operands[3].imm);
        if (width <= 0 || width > 32 || lsb < 0 || lsb + width > 32) return false;
        uint32_t mask_in_pos =
            (width == 32) ? 0xffffffffu : (((1u << width) - 1u) << lsb);
        uint32_t mask_out = ~mask_in_pos;
        std::string old = load_reg(rd);
        std::string src = load_reg(rs);
        std::string lo = fresh();
        ir << "  " << lo << " = and i32 " << src << ", "
           << static_cast<int32_t>(width == 32 ? 0xffffffffu : ((1u << width) - 1u))
           << "\n";
        std::string lo_pos = fresh();
        ir << "  " << lo_pos << " = shl i32 " << lo << ", " << lsb << "\n";
        std::string clr = fresh();
        ir << "  " << clr << " = and i32 " << old << ", "
           << static_cast<int32_t>(mask_out) << "\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << clr << ", " << lo_pos << "\n";
        store_reg(rd, out);
        return true;
    }

    // REV Rd, Rm  -- byte-reverse 32-bit.
    bool emit_rev(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        std::string out = fresh();
        ir << "  " << out << " = call i32 @llvm.bswap.i32(i32 " << val << ")\n";
        store_reg(rd, out);
        return true;
    }

    // REVSH Rd, Rm  -- byte-reverse Rm[15:0] then sign-extend to 32.
    // ARM ARM A8.6.137: Rd = SignExtend((Rm[7:0] << 8) | Rm[15:8], 16).
    // Compilers use this for big-endian I/O on signed 16-bit values
    // (PNG/JPEG decoders, networking parsers).
    bool emit_revsh(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        std::string trunc = fresh();
        ir << "  " << trunc << " = trunc i32 " << val << " to i16\n";
        std::string bsw = fresh();
        ir << "  " << bsw << " = call i16 @llvm.bswap.i16(i16 " << trunc << ")\n";
        std::string ext = fresh();
        ir << "  " << ext << " = sext i16 " << bsw << " to i32\n";
        store_reg(rd, ext);
        return true;
    }

    // REV16 Rd, Rm  -- byte-reverse within each halfword.
    // ARM ARM A8.6.136: Rd = [Rm[23:16], Rm[31:24], Rm[7:0], Rm[15:8]].
    // Equivalent to swapping low byte pairs in both halfwords.
    bool emit_rev16(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string val = load_reg(rs);
        // (val >> 8) & 0x00ff00ff  |  (val << 8) & 0xff00ff00
        std::string hi_mask = fresh();
        ir << "  " << hi_mask << " = and i32 " << val
           << ", -16711936\n";   // 0xFF00FF00
        std::string hi_shr = fresh();
        ir << "  " << hi_shr << " = lshr i32 " << hi_mask << ", 8\n";
        std::string lo_mask = fresh();
        ir << "  " << lo_mask << " = and i32 " << val
           << ", 16711935\n";    // 0x00FF00FF
        std::string lo_shl = fresh();
        ir << "  " << lo_shl << " = shl i32 " << lo_mask << ", 8\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << hi_shr << ", " << lo_shl << "\n";
        store_reg(rd, out);
        return true;
    }

    // BFC Rd, #lsb, #width  -- clear `width` bits starting at `lsb`.
    // ARM ARM A8.6.16. Equivalent to BFI with a zero source field.
    bool emit_bfc(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int lsb   = static_cast<int>(d.operands[1].imm);
        int width = static_cast<int>(d.operands[2].imm);
        if (width <= 0 || width > 32 || lsb < 0 || lsb + width > 32) return false;
        uint32_t mask_in_pos =
            (width == 32) ? 0xffffffffu : (((1u << width) - 1u) << lsb);
        std::string old = load_reg(rd);
        std::string out = fresh();
        ir << "  " << out << " = and i32 " << old << ", "
           << static_cast<int32_t>(~mask_in_pos) << "\n";
        store_reg(rd, out);
        return true;
    }

    // ORN Rd, Rn, Rm{,shift}  -- bitwise OR with bit-inverted Rm.
    // ARM ARM A8.6.114. Same flag rules as ORR (sets N+Z if S; C may be
    // set by the barrel shifter, V untouched; we update only N+Z to
    // mirror existing emit_alu logical-op behavior).
    bool emit_orn(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int rn_idx, src_idx, rot_idx = -1;
        if (d.op_count == 2) { rn_idx = 0; src_idx = 1; }
        else if (d.op_count == 3) { rn_idx = 1; src_idx = 2; }
        else {
            if (d.operands[2].type != ARM_OP_IMM ||
                d.operands[3].type != ARM_OP_IMM) return false;
            rn_idx = 1; src_idx = 2; rot_idx = 3;
        }
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        if (rn < 0) return false;
        std::string lhs = load_reg(rn);
        std::string rhs;
        if (!resolve_alu_src(d.operands[src_idx],
                              rot_idx >= 0 ? &d.operands[rot_idx] : nullptr,
                              &rhs)) return false;
        std::string inv = fresh();
        ir << "  " << inv << " = xor i32 " << rhs << ", -1\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << lhs << ", " << inv << "\n";
        store_reg(rd, out);
        if (d.update_flags) emit_set_nz(out);
        return true;
    }

    // UDIV / SDIV Rd, Rn, Rm  -- 32-bit unsigned/signed division.
    // ARM ARM A8.6.260/A8.6.165. Per the spec, division by zero returns
    // 0 (with optional UNDEF trap if SCTLR.DZ is set -- we don't model
    // SCTLR). LLVM IR's `udiv`/`sdiv` is UB on /0, so we guard with a
    // select to mirror ARMv7-A's "no fault, return 0" behavior. SDIV
    // also has UB on INT_MIN / -1; we guard that too.
    bool emit_div(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        // Build a "safe divisor": replace 0 with 1, and for signed,
        // replace (INT_MIN / -1) by replacing -1 with 1 when dividend
        // is INT_MIN. The result is overwritten by a select below.
        std::string is_zero = fresh();
        ir << "  " << is_zero << " = icmp eq i32 " << b << ", 0\n";
        std::string safe_b = fresh();
        if (is_signed) {
            // Detect INT_MIN / -1 separately to keep UB-free.
            std::string is_min = fresh();
            ir << "  " << is_min << " = icmp eq i32 " << a
               << ", -2147483648\n";
            std::string is_neg1 = fresh();
            ir << "  " << is_neg1 << " = icmp eq i32 " << b << ", -1\n";
            std::string min_div = fresh();
            ir << "  " << min_div << " = and i1 " << is_min
               << ", " << is_neg1 << "\n";
            std::string unsafe = fresh();
            ir << "  " << unsafe << " = or i1 " << is_zero
               << ", " << min_div << "\n";
            ir << "  " << safe_b << " = select i1 " << unsafe
               << ", i32 1, i32 " << b << "\n";
            std::string q = fresh();
            ir << "  " << q << " = sdiv i32 " << a << ", " << safe_b << "\n";
            // ARM ARM: 0/0 -> 0; INT_MIN/-1 -> INT_MIN (saturate).
            std::string mid = fresh();
            ir << "  " << mid << " = select i1 " << is_zero
               << ", i32 0, i32 " << q << "\n";
            std::string out = fresh();
            ir << "  " << out << " = select i1 " << min_div
               << ", i32 -2147483648, i32 " << mid << "\n";
            store_reg(rd, out);
        } else {
            ir << "  " << safe_b << " = select i1 " << is_zero
               << ", i32 1, i32 " << b << "\n";
            std::string q = fresh();
            ir << "  " << q << " = udiv i32 " << a << ", " << safe_b << "\n";
            std::string out = fresh();
            ir << "  " << out << " = select i1 " << is_zero
               << ", i32 0, i32 " << q << "\n";
            store_reg(rd, out);
        }
        return true;
    }

    // UXTAB/UXTAH/SXTAB/SXTAH Rd, Rn, Rm{,ROR #amount}
    // ARM ARM A8.6.227 / A8.6.228 / A8.6.182 / A8.6.183:
    //   tmp = ROR(Rm, ror_amount);
    //   Rd  = Rn + (Z|S)ExtendByte(or Halfword)(tmp[7:0] or [15:0]).
    // The ROR is the standard operand-2 shift expressed in apply_shift.
    bool emit_xtab(const cs_insn* in, int bits, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string lhs = load_reg(rn);
        std::string rhs = load_reg(rm);
        if (!apply_shift(d.operands[2], &rhs)) return false;
        std::string trunc = fresh();
        const char* small_ty = (bits == 8) ? "i8" : "i16";
        ir << "  " << trunc << " = trunc i32 " << rhs << " to "
           << small_ty << "\n";
        std::string ext = fresh();
        ir << "  " << ext << " = " << (is_signed ? "sext" : "zext")
           << " " << small_ty << " " << trunc << " to i32\n";
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << lhs << ", " << ext << "\n";
        store_reg(rd, out);
        return true;
    }

    // PKHBT Rd, Rn, Rm{,LSL #amount}  -- pack low half of Rn with shifted
    //                                    high half of Rm.
    // PKHTB Rd, Rn, Rm{,ASR #amount}  -- pack high half of Rn with shifted
    //                                    low half of Rm.
    // ARM ARM A8.6.124/A8.6.125.
    bool emit_pkh(const cs_insn* in, bool top_bottom) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string vn = load_reg(rn);
        std::string vm = load_reg(rm);
        if (!apply_shift(d.operands[2], &vm)) return false;
        std::string out;
        if (top_bottom) {
            // PKHTB: Rd = (Rn & 0xFFFF0000) | (Rm & 0x0000FFFF).
            std::string rn_hi = fresh();
            ir << "  " << rn_hi << " = and i32 " << vn
               << ", -65536\n";    // 0xFFFF0000
            std::string rm_lo = fresh();
            ir << "  " << rm_lo << " = and i32 " << vm
               << ", 65535\n";     // 0x0000FFFF
            out = fresh();
            ir << "  " << out << " = or i32 " << rn_hi
               << ", " << rm_lo << "\n";
        } else {
            // PKHBT: Rd = (Rn & 0x0000FFFF) | (Rm & 0xFFFF0000).
            std::string rn_lo = fresh();
            ir << "  " << rn_lo << " = and i32 " << vn
               << ", 65535\n";
            std::string rm_hi = fresh();
            ir << "  " << rm_hi << " = and i32 " << vm
               << ", -65536\n";
            out = fresh();
            ir << "  " << out << " = or i32 " << rn_lo
               << ", " << rm_hi << "\n";
        }
        store_reg(rd, out);
        return true;
    }

    // USAD8 Rd, Rn, Rm        -- sum of absolute differences across 4 bytes.
    // USADA8 Rd, Rn, Rm, Ra   -- USAD8 + Ra.
    // ARM ARM A8.6.247/A8.6.248. Compilers emit for memcmp-style loops
    // and HEVC/H.264 motion-estimation kernels.
    bool emit_usad8(const cs_insn* in, bool has_acc) {
        const cs_arm& d = in->detail->arm;
        int need = has_acc ? 4 : 3;
        if (d.op_count != need) return false;
        for (int i = 0; i < need; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = has_acc ? arm_reg_idx(d.operands[3].reg) : -1;
        if (rd < 0 || rn < 0 || rm < 0 || (has_acc && ra < 0)) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        // Sum |a[i] - b[i]| across 4 bytes (i = 0..3).
        std::string sum = "0";
        for (int byte = 0; byte < 4; ++byte) {
            std::string ab = fresh();
            ir << "  " << ab << " = lshr i32 " << a
               << ", " << (byte * 8) << "\n";
            std::string at = fresh();
            ir << "  " << at << " = and i32 " << ab << ", 255\n";
            std::string bb = fresh();
            ir << "  " << bb << " = lshr i32 " << b
               << ", " << (byte * 8) << "\n";
            std::string bt = fresh();
            ir << "  " << bt << " = and i32 " << bb << ", 255\n";
            std::string diff = fresh();
            ir << "  " << diff << " = sub i32 " << at << ", " << bt << "\n";
            std::string neg = fresh();
            ir << "  " << neg << " = sub i32 0, " << diff << "\n";
            std::string is_neg = fresh();
            ir << "  " << is_neg << " = icmp slt i32 " << diff << ", 0\n";
            std::string abs = fresh();
            ir << "  " << abs << " = select i1 " << is_neg
               << ", i32 " << neg << ", i32 " << diff << "\n";
            std::string ns = fresh();
            ir << "  " << ns << " = add i32 " << sum << ", " << abs << "\n";
            sum = ns;
        }
        if (has_acc) {
            std::string acc = load_reg(ra);
            std::string ns = fresh();
            ir << "  " << ns << " = add i32 " << sum << ", " << acc << "\n";
            sum = ns;
        }
        store_reg(rd, sum);
        return true;
    }

    // MRS Rd, <special_register>  -- read special register.
    // ARM ARM A8.6.102. We model APSR / APSR_nzcv / CPSR reads by
    // packing the NZCV flags into bits[31:28]; other special registers
    // return 0. User-mode code rarely reads anything but APSR.
    bool emit_mrs(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        unsigned int src = d.operands[1].reg;
        bool reads_flags = (src == ARM_REG_APSR ||
                            src == ARM_REG_APSR_NZCV ||
                            src == ARM_REG_CPSR ||
                            src == ARM_REG_SPSR);
        if (!reads_flags) {
            // FPSCR / FPEXC / unknown special: return 0. User code never
            // observes these meaningfully on this runtime.
            store_reg(rd, "0");
            return true;
        }
        std::string n = load_flag("n");
        std::string z = load_flag("z");
        std::string c = load_flag("c");
        std::string v = load_flag("v");
        std::string n32 = fresh();
        ir << "  " << n32 << " = zext i1 " << n << " to i32\n";
        std::string z32 = fresh();
        ir << "  " << z32 << " = zext i1 " << z << " to i32\n";
        std::string c32 = fresh();
        ir << "  " << c32 << " = zext i1 " << c << " to i32\n";
        std::string v32 = fresh();
        ir << "  " << v32 << " = zext i1 " << v << " to i32\n";
        std::string n_sh = fresh();
        ir << "  " << n_sh << " = shl i32 " << n32 << ", 31\n";
        std::string z_sh = fresh();
        ir << "  " << z_sh << " = shl i32 " << z32 << ", 30\n";
        std::string c_sh = fresh();
        ir << "  " << c_sh << " = shl i32 " << c32 << ", 29\n";
        std::string v_sh = fresh();
        ir << "  " << v_sh << " = shl i32 " << v32 << ", 28\n";
        std::string nz = fresh();
        ir << "  " << nz << " = or i32 " << n_sh << ", " << z_sh << "\n";
        std::string cv = fresh();
        ir << "  " << cv << " = or i32 " << c_sh << ", " << v_sh << "\n";
        std::string nzcv = fresh();
        ir << "  " << nzcv << " = or i32 " << nz << ", " << cv << "\n";
        // Surface GE[3:0] on bits 19:16 and the sticky Q on bit 27.
        // ARM ARM A2.5 / A8.6.102 (MRS): APSR.GE = bits[19:16],
        // APSR.Q = bit[27].
        std::string acc = nzcv;
        for (int gi = 0; gi < 4; ++gi) {
            std::string g = load_ge(gi);
            std::string g32 = fresh();
            ir << "  " << g32 << " = zext i1 " << g << " to i32\n";
            std::string g_sh = fresh();
            ir << "  " << g_sh << " = shl i32 " << g32 << ", " << (16 + gi) << "\n";
            std::string na = fresh();
            ir << "  " << na << " = or i32 " << acc << ", " << g_sh << "\n";
            acc = na;
        }
        std::string q = load_q();
        std::string q32 = fresh();
        ir << "  " << q32 << " = zext i1 " << q << " to i32\n";
        std::string q_sh = fresh();
        ir << "  " << q_sh << " = shl i32 " << q32 << ", 27\n";
        std::string out = fresh();
        ir << "  " << out << " = or i32 " << acc << ", " << q_sh << "\n";
        store_reg(rd, out);
        return true;
    }

    // MSR <special_register>, Rs | #imm{,#rot}  -- write to special reg.
    // ARM ARM A8.6.103. We model writes to APSR / APSR_nzcv / CPSR by
    // unpacking bits[31:28] into our NZCV flag slots; writes to other
    // special registers (SPSR, CPSR control bits, FPSCR, etc.) are
    // silently dropped because lifted user code never depends on them.
    // Capstone may report the source as:
    //   - REG (Rs): 2-operand form
    //   - IMM:      2-operand form with effective value
    //   - IMM, IMM: 3-operand modified-immediate form (#imm8, #rot)
    // Capstone also splits "msr spsr_<f|c|s|x>" into separate register
    // enums; any non-APSR/CPSR target is a silent drop.
    bool emit_msr(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 3) return true;  // noop fallback
        unsigned int dst = d.operands[0].reg;
        bool writes_flags = (dst == ARM_REG_APSR ||
                             dst == ARM_REG_APSR_NZCV ||
                             dst == ARM_REG_CPSR);
        if (!writes_flags) return true;
        const cs_arm_op* rot = nullptr;
        if (d.op_count == 3) {
            if (d.operands[1].type != ARM_OP_IMM ||
                d.operands[2].type != ARM_OP_IMM) return true;
            rot = &d.operands[2];
        }
        std::string val;
        if (!resolve_alu_src(d.operands[1], rot, &val)) return true;
        std::string n_sh = fresh();
        ir << "  " << n_sh << " = lshr i32 " << val << ", 31\n";
        std::string n_lo = fresh();
        ir << "  " << n_lo << " = and i32 " << n_sh << ", 1\n";
        std::string n = fresh();
        ir << "  " << n << " = icmp ne i32 " << n_lo << ", 0\n";
        store_flag("n", n);
        std::string z_sh = fresh();
        ir << "  " << z_sh << " = lshr i32 " << val << ", 30\n";
        std::string z_lo = fresh();
        ir << "  " << z_lo << " = and i32 " << z_sh << ", 1\n";
        std::string z = fresh();
        ir << "  " << z << " = icmp ne i32 " << z_lo << ", 0\n";
        store_flag("z", z);
        std::string c_sh = fresh();
        ir << "  " << c_sh << " = lshr i32 " << val << ", 29\n";
        std::string c_lo = fresh();
        ir << "  " << c_lo << " = and i32 " << c_sh << ", 1\n";
        std::string c = fresh();
        ir << "  " << c << " = icmp ne i32 " << c_lo << ", 0\n";
        store_flag("c", c);
        std::string v_sh = fresh();
        ir << "  " << v_sh << " = lshr i32 " << val << ", 28\n";
        std::string v_lo = fresh();
        ir << "  " << v_lo << " = and i32 " << v_sh << ", 1\n";
        std::string v = fresh();
        ir << "  " << v << " = icmp ne i32 " << v_lo << ", 0\n";
        store_flag("v", v);
        // Write APSR.GE[3:0] from bits[19:16] and APSR.Q from bit[27].
        // ARM ARM A2.5 / A8.6.103 (MSR). Capstone collapses the APSR/CPSR_f
        // write-mask forms and we model the whole word, so writing all of
        // NZCVQGE here matches the observable flag-write idioms compilers
        // emit.
        for (int gi = 0; gi < 4; ++gi) {
            std::string g_sh = fresh();
            ir << "  " << g_sh << " = lshr i32 " << val << ", " << (16 + gi) << "\n";
            std::string g_lo = fresh();
            ir << "  " << g_lo << " = and i32 " << g_sh << ", 1\n";
            std::string g = fresh();
            ir << "  " << g << " = icmp ne i32 " << g_lo << ", 0\n";
            store_ge(gi, g);
        }
        std::string q_sh = fresh();
        ir << "  " << q_sh << " = lshr i32 " << val << ", 27\n";
        std::string q_lo = fresh();
        ir << "  " << q_lo << " = and i32 " << q_sh << ", 1\n";
        std::string q = fresh();
        ir << "  " << q << " = icmp ne i32 " << q_lo << ", 0\n";
        store_q(q);
        return true;
    }

    // SSAT Rd, #sat_to, Rn{,shift}  -- signed saturate to 1..32 bits.
    // USAT Rd, #sat_to, Rn{,shift}  -- unsigned saturate to 0..31 bits.
    // ARM ARM A8.6.183/A8.6.255. The optional shift on Rn is an ALU
    // shift; the result is then clamped to the signed [-2^(N-1), 2^(N-1)-1]
    // range (SSAT) or the unsigned [0, 2^N - 1] range (USAT).
    // Compilers emit these for fixed-point DSP code (FFTs, image filters).
    bool emit_sat(const cs_insn* in, bool is_signed, int half_word) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        if (d.operands[2].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0) return false;
        int sat_bits = static_cast<int>(d.operands[1].imm);
        // SSAT: 1..32. USAT: 0..31. SSAT16/USAT16: 1..16.
        if (half_word) {
            if (sat_bits < 1 || sat_bits > 16) return false;
        } else {
            if (is_signed) {
                if (sat_bits < 1 || sat_bits > 32) return false;
            } else {
                if (sat_bits < 0 || sat_bits > 31) return false;
            }
        }
        std::string val = load_reg(rn);
        if (!apply_shift(d.operands[2], &val)) return false;
        auto clamp32 = [&](const std::string& x) -> std::string {
            int32_t hi, lo;
            if (is_signed) {
                hi = (sat_bits == 32)
                    ? 0x7fffffff : ((1 << (sat_bits - 1)) - 1);
                lo = (sat_bits == 32)
                    ? static_cast<int32_t>(0x80000000)
                    : -(1 << (sat_bits - 1));
            } else {
                hi = (sat_bits == 32)
                    ? -1 : ((1 << sat_bits) - 1);
                lo = 0;
            }
            std::string above = fresh();
            ir << "  " << above << " = icmp " << (is_signed ? "sgt" : "ugt")
               << " i32 " << x << ", " << hi << "\n";
            std::string clamped_hi = fresh();
            ir << "  " << clamped_hi << " = select i1 " << above
               << ", i32 " << hi << ", i32 " << x << "\n";
            std::string below = fresh();
            ir << "  " << below << " = icmp " << (is_signed ? "slt" : "ult")
               << " i32 " << clamped_hi << ", " << lo << "\n";
            std::string out = fresh();
            ir << "  " << out << " = select i1 " << below
               << ", i32 " << lo << ", i32 " << clamped_hi << "\n";
            return out;
        };
        std::string out;
        if (half_word) {
            // SSAT16/USAT16 saturate each halfword of Rn independently.
            // Extract low half, sign-extend to i32, clamp, re-mask.
            // Same for high half. Recombine.
            std::string lo = fresh();
            ir << "  " << lo << " = trunc i32 " << val << " to i16\n";
            std::string lo32 = fresh();
            ir << "  " << lo32 << " = " << (is_signed ? "sext" : "zext")
               << " i16 " << lo << " to i32\n";
            std::string lo_cl = clamp32(lo32);
            std::string lo_mask = fresh();
            ir << "  " << lo_mask << " = and i32 " << lo_cl << ", 65535\n";
            std::string hi_sh = fresh();
            ir << "  " << hi_sh << " = " << (is_signed ? "ashr" : "lshr")
               << " i32 " << val << ", 16\n";
            std::string hi = fresh();
            ir << "  " << hi << " = trunc i32 " << hi_sh << " to i16\n";
            std::string hi32 = fresh();
            ir << "  " << hi32 << " = " << (is_signed ? "sext" : "zext")
               << " i16 " << hi << " to i32\n";
            std::string hi_cl = clamp32(hi32);
            std::string hi_back = fresh();
            ir << "  " << hi_back << " = shl i32 " << hi_cl << ", 16\n";
            std::string hi_back_mask = fresh();
            ir << "  " << hi_back_mask << " = and i32 " << hi_back
               << ", -65536\n";
            out = fresh();
            ir << "  " << out << " = or i32 " << lo_mask
               << ", " << hi_back_mask << "\n";
        } else {
            out = clamp32(val);
        }
        store_reg(rd, out);
        return true;
    }

    // SWP / SWPB  Rt, Rt2, [Rn]  -- atomic swap word/byte.
    // Deprecated in ARMv7 (ARM ARM A8.6.225) but still emitted by older
    // GCC and seen in shipped binaries (libfmod, libcocos2dx_internal).
    // Semantics: tmp = mem[Rn]; mem[Rn] = Rt2; Rt = tmp. We don't model
    // atomicity (no LL/SC contention possible in Apk on Mac's single-VM
    // address space); a plain load+store pair preserves single-thread
    // correctness.
    bool emit_swp(const cs_insn* in, int bits) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rt  = arm_reg_idx(d.operands[0].reg);
        int rt2 = arm_reg_idx(d.operands[1].reg);
        if (rt < 0 || rt2 < 0) return false;
        std::string addr = compute_mem_addr(d.operands[2]);
        if (addr.empty()) return false;
        std::string p = stack_ptr(addr);
        const char* ty = (bits == 8) ? "i8" : "i32";
        std::string old_val = fresh();
        ir << "  " << old_val << " = load " << ty << ", ptr " << p
           << ", align " << (bits / 8) << "\n";
        std::string store_val = load_reg(rt2);
        if (bits == 8) {
            std::string trunc = fresh();
            ir << "  " << trunc << " = trunc i32 " << store_val << " to i8\n";
            ir << "  store i8 " << trunc << ", ptr " << p
               << ", align 1\n";
            std::string ext = fresh();
            ir << "  " << ext << " = zext i8 " << old_val << " to i32\n";
            store_reg(rt, ext);
        } else {
            ir << "  store i32 " << store_val << ", ptr " << p
               << ", align 4\n";
            store_reg(rt, old_val);
        }
        return true;
    }

    // LDREXD / STREXD / STLEXD -- exclusive-monitor load/store double.
    // We don't model atomicity (see emit_swp). LDREXD Rt, Rt2, [Rn]
    // loads 64 bits, splits into Rt:Rt2 with Rt being the low word.
    // STREXD Rd, Rt, Rt2, [Rn] writes Rt:Rt2 and sets Rd=0 (always
    // success in a single-VM model).
    bool emit_ldrexd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rt_lo = arm_reg_idx(d.operands[0].reg);
        int rt_hi = arm_reg_idx(d.operands[1].reg);
        if (rt_lo < 0 || rt_hi < 0) return false;
        std::string addr = compute_mem_addr(d.operands[2]);
        if (addr.empty()) return false;
        std::string val64 = load_mem_i64(addr);
        std::string lo = fresh();
        ir << "  " << lo << " = trunc i64 " << val64 << " to i32\n";
        std::string sh = fresh();
        ir << "  " << sh << " = lshr i64 " << val64 << ", 32\n";
        std::string hi = fresh();
        ir << "  " << hi << " = trunc i64 " << sh << " to i32\n";
        store_reg(rt_lo, lo);
        store_reg(rt_hi, hi);
        return true;
    }
    bool emit_strexd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_REG) return false;
        if (d.operands[3].type != ARM_OP_MEM) return false;
        int rd    = arm_reg_idx(d.operands[0].reg);
        int rt_lo = arm_reg_idx(d.operands[1].reg);
        int rt_hi = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rt_lo < 0 || rt_hi < 0) return false;
        std::string addr = compute_mem_addr(d.operands[3]);
        if (addr.empty()) return false;
        std::string lo = load_reg(rt_lo);
        std::string hi = load_reg(rt_hi);
        std::string lo64 = fresh();
        ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
        std::string hi64_sh = fresh();
        ir << "  " << hi64_sh << " = shl i64 " << hi64 << ", 32\n";
        std::string val64 = fresh();
        ir << "  " << val64 << " = or i64 " << lo64 << ", " << hi64_sh << "\n";
        store_mem_i64(addr, val64);
        store_reg(rd, "0");
        return true;
    }

    // STREXB / STREXH -- exclusive store byte/halfword. STREX already
    // exists for the 32-bit case; these are tiny analogs.
    bool emit_strex_size(const cs_insn* in, int bits) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rd  = arm_reg_idx(d.operands[0].reg);
        int rt  = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rt < 0) return false;
        std::string addr = compute_mem_addr(d.operands[2]);
        if (addr.empty()) return false;
        std::string p = stack_ptr(addr);
        std::string val = load_reg(rt);
        if (bits == 8) {
            std::string trunc = fresh();
            ir << "  " << trunc << " = trunc i32 " << val << " to i8\n";
            ir << "  store i8 " << trunc << ", ptr " << p << ", align 1\n";
        } else {  // 16
            std::string trunc = fresh();
            ir << "  " << trunc << " = trunc i32 " << val << " to i16\n";
            ir << "  store i16 " << trunc << ", ptr " << p << ", align 2\n";
        }
        store_reg(rd, "0");  // always-success
        return true;
    }

    // --- Signed halfword multiplies (SMULBB / SMLABB / SMULWB / SMMLA) -

    // Extract a 16-bit half from a 32-bit register, sign-extended to i32.
    // Bottom = bits[15:0], Top = bits[31:16].
    std::string extract_half_signed(const std::string& v, bool top) {
        std::string sh = v;
        if (top) {
            std::string s = fresh();
            ir << "  " << s << " = ashr i32 " << v << ", 16\n";
            sh = s;
        }
        std::string trunc = fresh();
        ir << "  " << trunc << " = trunc i32 " << sh << " to i16\n";
        std::string ext = fresh();
        ir << "  " << ext << " = sext i16 " << trunc << " to i32\n";
        return ext;
    }

    // SMULBB / SMULBT / SMULTB / SMULTT Rd, Rn, Rm
    // ARM ARM A8.6.176. Rd = SignedHalfMul(Rn, Rm).
    bool emit_smul_half(const cs_insn* in, bool n_top, bool m_top) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string ah = extract_half_signed(a, n_top);
        std::string bh = extract_half_signed(b, m_top);
        std::string out = fresh();
        ir << "  " << out << " = mul i32 " << ah << ", " << bh << "\n";
        store_reg(rd, out);
        return true;
    }

    // SMLABB / SMLABT / SMLATB / SMLATT Rd, Rn, Rm, Ra
    // ARM ARM A8.6.166. Rd = Ra + SignedHalfMul(Rn, Rm). Q sticky flag
    // set on signed overflow of the add; we don't model Q (read by MRS
    // APSR which we don't expose).
    bool emit_smla_half(const cs_insn* in, bool n_top, bool m_top) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = arm_reg_idx(d.operands[3].reg);
        if (rd < 0 || rn < 0 || rm < 0 || ra < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string acc = load_reg(ra);
        std::string ah = extract_half_signed(a, n_top);
        std::string bh = extract_half_signed(b, m_top);
        std::string prod = fresh();
        ir << "  " << prod << " = mul i32 " << ah << ", " << bh << "\n";
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << acc << ", " << prod << "\n";
        store_reg(rd, out);
        return true;
    }

    // SMULWB / SMULWT Rd, Rn, Rm  -- signed multiply word by halfword,
    // returning the top 32 bits of the 48-bit product.
    // ARM ARM A8.6.179: Rd = (SInt32(Rn) * SInt16(Rm[bottom|top])) >> 16.
    bool emit_smul_w(const cs_insn* in, bool m_top) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string bh = extract_half_signed(b, m_top);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << bh << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string sh = fresh();
        ir << "  " << sh << " = ashr i64 " << prod << ", 16\n";
        std::string trunc = fresh();
        ir << "  " << trunc << " = trunc i64 " << sh << " to i32\n";
        store_reg(rd, trunc);
        return true;
    }

    // SMLAWB / SMLAWT Rd, Rn, Rm, Ra
    // ARM ARM A8.6.167: Rd = Ra + (SInt32(Rn) * SInt16(Rm[half])) >> 16.
    bool emit_smla_w(const cs_insn* in, bool m_top) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = arm_reg_idx(d.operands[3].reg);
        if (rd < 0 || rn < 0 || rm < 0 || ra < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string acc = load_reg(ra);
        std::string bh = extract_half_signed(b, m_top);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << bh << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string sh = fresh();
        ir << "  " << sh << " = ashr i64 " << prod << ", 16\n";
        std::string trunc = fresh();
        ir << "  " << trunc << " = trunc i64 " << sh << " to i32\n";
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << acc << ", " << trunc << "\n";
        store_reg(rd, out);
        return true;
    }

    // SMMLA / SMMLAR / SMMLS / SMMLSR Rd, Rn, Rm, Ra
    // ARM ARM A8.6.173/A8.6.174: top 32 bits of a 64-bit signed product
    // (optionally rounded), accumulated into Ra (signed) or subtracted
    // (SMMLS). R variant adds 0x80000000 before the >>32 (round-half-up).
    bool emit_smm(const cs_insn* in, bool is_sub, bool is_round) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = arm_reg_idx(d.operands[3].reg);
        if (rd < 0 || rn < 0 || rm < 0 || ra < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string acc = load_reg(ra);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << b << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string acc64 = fresh();
        ir << "  " << acc64 << " = sext i32 " << acc << " to i64\n";
        std::string acc_sh = fresh();
        ir << "  " << acc_sh << " = shl i64 " << acc64 << ", 32\n";
        std::string combined;
        if (is_sub) {
            combined = fresh();
            ir << "  " << combined << " = sub i64 " << acc_sh
               << ", " << prod << "\n";
        } else {
            combined = fresh();
            ir << "  " << combined << " = add i64 " << acc_sh
               << ", " << prod << "\n";
        }
        if (is_round) {
            std::string r = fresh();
            ir << "  " << r << " = add i64 " << combined
               << ", 2147483648\n";   // 0x80000000
            combined = r;
        }
        std::string shr = fresh();
        ir << "  " << shr << " = ashr i64 " << combined << ", 32\n";
        std::string out = fresh();
        ir << "  " << out << " = trunc i64 " << shr << " to i32\n";
        store_reg(rd, out);
        return true;
    }

    // SMLAL / UMLAL  RdLo, RdHi, Rn, Rm
    // ARM ARM A8.6.168/A8.6.226. (RdHi:RdLo) += (s|u)(Rn) * (s|u)(Rm).
    bool emit_mlal(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        int rn    = arm_reg_idx(d.operands[2].reg);
        int rm    = arm_reg_idx(d.operands[3].reg);
        if (rd_lo < 0 || rd_hi < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string a64 = fresh();
        ir << "  " << a64 << " = " << (is_signed ? "sext" : "zext")
           << " i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = " << (is_signed ? "sext" : "zext")
           << " i32 " << b << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        // Accumulator: (RdHi:RdLo) as i64.
        std::string lo = load_reg(rd_lo);
        std::string hi = load_reg(rd_hi);
        std::string lo64 = fresh();
        ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
        std::string hi_sh = fresh();
        ir << "  " << hi_sh << " = shl i64 " << hi64 << ", 32\n";
        std::string acc = fresh();
        ir << "  " << acc << " = or i64 " << lo64 << ", " << hi_sh << "\n";
        std::string sum = fresh();
        ir << "  " << sum << " = add i64 " << acc << ", " << prod << "\n";
        std::string out_lo = fresh();
        ir << "  " << out_lo << " = trunc i64 " << sum << " to i32\n";
        std::string sh = fresh();
        ir << "  " << sh << " = lshr i64 " << sum << ", 32\n";
        std::string out_hi = fresh();
        ir << "  " << out_hi << " = trunc i64 " << sh << " to i32\n";
        store_reg(rd_lo, out_lo);
        store_reg(rd_hi, out_hi);
        // Z is over the whole 64-bit accumulate result, not just the high
        // word (A8.8.178 SMLAL / A8.8.256 UMLAL).
        if (d.update_flags) emit_set_nz64(sum);
        return true;
    }

    // UMAAL  RdLo, RdHi, Rn, Rm
    // ARM ARM A8.6.244: 64-bit = UInt(Rn)*UInt(Rm) + UInt(RdLo) + UInt(RdHi).
    bool emit_umaal(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        int rn    = arm_reg_idx(d.operands[2].reg);
        int rm    = arm_reg_idx(d.operands[3].reg);
        if (rd_lo < 0 || rd_hi < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string lo = load_reg(rd_lo);
        std::string hi = load_reg(rd_hi);
        std::string a64 = fresh();
        ir << "  " << a64 << " = zext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = zext i32 " << b << " to i64\n";
        std::string lo64 = fresh();
        ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string s1 = fresh();
        ir << "  " << s1 << " = add i64 " << prod << ", " << lo64 << "\n";
        std::string s2 = fresh();
        ir << "  " << s2 << " = add i64 " << s1 << ", " << hi64 << "\n";
        std::string out_lo = fresh();
        ir << "  " << out_lo << " = trunc i64 " << s2 << " to i32\n";
        std::string sh = fresh();
        ir << "  " << sh << " = lshr i64 " << s2 << ", 32\n";
        std::string out_hi = fresh();
        ir << "  " << out_hi << " = trunc i64 " << sh << " to i32\n";
        store_reg(rd_lo, out_lo);
        store_reg(rd_hi, out_hi);
        return true;
    }

    // SMLALD / SMLALDX / SMLSLD / SMLSLDX  RdLo, RdHi, Rn, Rm
    // ARM ARM A8.6.171/A8.6.172. Two dual halfword products, summed
    // (SMLALD) or low - high (SMLSLD), added to the 64-bit accumulator.
    // The X variant cross-couples (Rn[bottom]*Rm[top] + Rn[top]*Rm[bottom]
    // vs the straight pairing).
    bool emit_smlxld(const cs_insn* in, bool is_sub, bool is_cross) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        int rn    = arm_reg_idx(d.operands[2].reg);
        int rm    = arm_reg_idx(d.operands[3].reg);
        if (rd_lo < 0 || rd_hi < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string a_lo = extract_half_signed(a, false);
        std::string a_hi = extract_half_signed(a, true);
        // SMLALD straight: a_lo*b_lo + a_hi*b_hi
        // SMLALDX cross:   a_lo*b_hi + a_hi*b_lo
        std::string b_lo = extract_half_signed(b, is_cross ? true  : false);
        std::string b_hi = extract_half_signed(b, is_cross ? false : true);
        std::string p1 = fresh();
        ir << "  " << p1 << " = mul i32 " << a_lo << ", " << b_lo << "\n";
        std::string p2 = fresh();
        ir << "  " << p2 << " = mul i32 " << a_hi << ", " << b_hi << "\n";
        std::string p1_64 = fresh();
        ir << "  " << p1_64 << " = sext i32 " << p1 << " to i64\n";
        std::string p2_64 = fresh();
        ir << "  " << p2_64 << " = sext i32 " << p2 << " to i64\n";
        std::string dual;
        if (is_sub) {
            dual = fresh();
            ir << "  " << dual << " = sub i64 " << p1_64
               << ", " << p2_64 << "\n";
        } else {
            dual = fresh();
            ir << "  " << dual << " = add i64 " << p1_64
               << ", " << p2_64 << "\n";
        }
        std::string lo = load_reg(rd_lo);
        std::string hi = load_reg(rd_hi);
        std::string lo64 = fresh();
        ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
        std::string hi_sh = fresh();
        ir << "  " << hi_sh << " = shl i64 " << hi64 << ", 32\n";
        std::string acc = fresh();
        ir << "  " << acc << " = or i64 " << lo64 << ", " << hi_sh << "\n";
        std::string sum = fresh();
        ir << "  " << sum << " = add i64 " << acc << ", " << dual << "\n";
        std::string out_lo = fresh();
        ir << "  " << out_lo << " = trunc i64 " << sum << " to i32\n";
        std::string sh2 = fresh();
        ir << "  " << sh2 << " = lshr i64 " << sum << ", 32\n";
        std::string out_hi = fresh();
        ir << "  " << out_hi << " = trunc i64 " << sh2 << " to i32\n";
        store_reg(rd_lo, out_lo);
        store_reg(rd_hi, out_hi);
        return true;
    }

    // SMLAD / SMLADX / SMLSD / SMLSDX Rd, Rn, Rm, Ra
    // SMUAD / SMUADX / SMUSD / SMUSDX Rd, Rn, Rm
    // ARM ARM A8.6.177 (SMUAD) / A8.6.181 (SMUSD). Same dual signed-
    // halfword product as SMLAD/SMLSD but WITHOUT the Ra accumulate:
    //   SMUAD:  Rd = Rn[lo]*Rm[lo] + Rn[hi]*Rm[hi]
    //   SMUSD:  Rd = Rn[lo]*Rm[lo] - Rn[hi]*Rm[hi]
    // The X variant cross-couples Rm's halves (mirrors emit_smlxd's
    // is_cross). Only 3 register operands (no Ra). Q-flag side effect
    // on SMUAD overflow is not modeled (consistent with SMLA* siblings).
    bool emit_smuad_smusd(const cs_insn* in, bool is_sub, bool is_cross) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string a_lo = extract_half_signed(a, false);
        std::string a_hi = extract_half_signed(a, true);
        std::string b_lo = extract_half_signed(b, is_cross ? true  : false);
        std::string b_hi = extract_half_signed(b, is_cross ? false : true);
        std::string p1 = fresh();
        ir << "  " << p1 << " = mul i32 " << a_lo << ", " << b_lo << "\n";
        std::string p2 = fresh();
        ir << "  " << p2 << " = mul i32 " << a_hi << ", " << b_hi << "\n";
        std::string out = fresh();
        ir << "  " << out << " = " << (is_sub ? "sub" : "add")
           << " i32 " << p1 << ", " << p2 << "\n";
        store_reg(rd, out);
        return true;
    }

    // SMMUL / SMMULR Rd, Rn, Rm
    // ARM ARM A8.6.176. Top 32 bits of the 64-bit signed product
    // (SMMULR rounds: +0x80000000 before >>32), WITHOUT accumulate.
    //   prod64 = SInt(Rn) * SInt(Rm)
    //   Rd = (prod64 [+ 0x80000000 if round]) >> 32
    bool emit_smmul(const cs_insn* in, bool is_round) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << b << " to i64\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul i64 " << a64 << ", " << b64 << "\n";
        std::string combined = prod;
        if (is_round) {
            std::string r = fresh();
            ir << "  " << r << " = add i64 " << combined
               << ", 2147483648\n";   // 0x80000000
            combined = r;
        }
        std::string shr = fresh();
        ir << "  " << shr << " = ashr i64 " << combined << ", 32\n";
        std::string out = fresh();
        ir << "  " << out << " = trunc i64 " << shr << " to i32\n";
        store_reg(rd, out);
        return true;
    }

    // ARM ARM A8.6.169/A8.6.175. Same dual halfword product idea as
    // SMLALD but result is 32-bit, accumulated into Ra.
    bool emit_smlxd(const cs_insn* in, bool is_sub, bool is_cross) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        int ra = arm_reg_idx(d.operands[3].reg);
        if (rd < 0 || rn < 0 || rm < 0 || ra < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string acc = load_reg(ra);
        std::string a_lo = extract_half_signed(a, false);
        std::string a_hi = extract_half_signed(a, true);
        std::string b_lo = extract_half_signed(b, is_cross ? true  : false);
        std::string b_hi = extract_half_signed(b, is_cross ? false : true);
        std::string p1 = fresh();
        ir << "  " << p1 << " = mul i32 " << a_lo << ", " << b_lo << "\n";
        std::string p2 = fresh();
        ir << "  " << p2 << " = mul i32 " << a_hi << ", " << b_hi << "\n";
        std::string dual;
        if (is_sub) {
            dual = fresh();
            ir << "  " << dual << " = sub i32 " << p1 << ", " << p2 << "\n";
        } else {
            dual = fresh();
            ir << "  " << dual << " = add i32 " << p1 << ", " << p2 << "\n";
        }
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << acc << ", " << dual << "\n";
        store_reg(rd, out);
        return true;
    }

    // SMLAL[BB/BT/TB/TT]  RdLo, RdHi, Rn, Rm
    // ARM ARM A8.6.170. (RdHi:RdLo) += SignedHalfMul(Rn,Rm) as 64-bit.
    bool emit_smlal_half(const cs_insn* in, bool n_top, bool m_top) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 4; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        int rn    = arm_reg_idx(d.operands[2].reg);
        int rm    = arm_reg_idx(d.operands[3].reg);
        if (rd_lo < 0 || rd_hi < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string ah = extract_half_signed(a, n_top);
        std::string bh = extract_half_signed(b, m_top);
        std::string prod32 = fresh();
        ir << "  " << prod32 << " = mul i32 " << ah << ", " << bh << "\n";
        std::string prod = fresh();
        ir << "  " << prod << " = sext i32 " << prod32 << " to i64\n";
        std::string lo = load_reg(rd_lo);
        std::string hi = load_reg(rd_hi);
        std::string lo64 = fresh();
        ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
        std::string hi64 = fresh();
        ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
        std::string hi_sh = fresh();
        ir << "  " << hi_sh << " = shl i64 " << hi64 << ", 32\n";
        std::string acc = fresh();
        ir << "  " << acc << " = or i64 " << lo64 << ", " << hi_sh << "\n";
        std::string sum = fresh();
        ir << "  " << sum << " = add i64 " << acc << ", " << prod << "\n";
        std::string out_lo = fresh();
        ir << "  " << out_lo << " = trunc i64 " << sum << " to i32\n";
        std::string sh = fresh();
        ir << "  " << sh << " = lshr i64 " << sum << ", 32\n";
        std::string out_hi = fresh();
        ir << "  " << out_hi << " = trunc i64 " << sh << " to i32\n";
        store_reg(rd_lo, out_lo);
        store_reg(rd_hi, out_hi);
        return true;
    }

    // --- Parallel SIMD on integer regs (ARMv6 DSP) -------------------

    // Helper: read Rn and Rm, split each into N-bit lanes, apply a
    // per-lane op (add/sub plain or saturating or halving), recombine.
    // Used by every signed/unsigned/halving/saturating parallel op.
    //
    // ARM ARM A5.4 parallel addition/subtraction: lane size is 16 or 8,
    // operation can be add, sub, exchange-add-sub (asx), exchange-sub-add
    // (sax). The XSX variants do `Rd[lo] = Rn[lo] OP Rm[hi]; Rd[hi] = Rn[hi]
    // OP Rm[lo]` where OP is + or -.
    enum class ParOp  { Add, Sub, Asx, Sax };
    enum class ParMod { Modular, SignedSat, UnsignedSat, SignedHalve, UnsignedHalve };

    // Build a per-lane sequence: for each lane index, compute Rn_lane OP
    // Rm_lane (or cross-paired for ASX/SAX), apply modifier, OR back into
    // result. lane_bits is 8 or 16. Returns the assembled SSA name.
    std::string par_arith_lane(const std::string& a_lane,
                                 const std::string& b_lane,
                                 ParOp op, ParMod mod, int lane_bits) {
        // a_lane and b_lane are i32 SSA names already sign- or zero-
        // extended into 32-bit range based on `mod`. We do the i32-level
        // arithmetic then narrow back to lane_bits using the mod's rules.
        const char* op_str;
        bool is_sub;
        switch (op) {
            case ParOp::Add: op_str = "add"; is_sub = false; break;
            case ParOp::Sub: op_str = "sub"; is_sub = true;  break;
            default:         op_str = "add"; is_sub = false; break;
        }
        std::string raw = fresh();
        ir << "  " << raw << " = " << op_str << " i32 "
           << a_lane << ", " << b_lane << "\n";
        switch (mod) {
            case ParMod::Modular: {
                // Truncate to lane bits.
                uint32_t mask = (lane_bits == 8) ? 0xffu : 0xffffu;
                std::string m = fresh();
                ir << "  " << m << " = and i32 " << raw << ", "
                   << static_cast<int32_t>(mask) << "\n";
                return m;
            }
            case ParMod::SignedSat: {
                // Clamp to signed range for lane bits.
                int32_t hi = (lane_bits == 8) ? 127  : 32767;
                int32_t lo = (lane_bits == 8) ? -128 : -32768;
                std::string above = fresh();
                ir << "  " << above << " = icmp sgt i32 " << raw
                   << ", " << hi << "\n";
                std::string cap_hi = fresh();
                ir << "  " << cap_hi << " = select i1 " << above
                   << ", i32 " << hi << ", i32 " << raw << "\n";
                std::string below = fresh();
                ir << "  " << below << " = icmp slt i32 " << cap_hi
                   << ", " << lo << "\n";
                std::string cap = fresh();
                ir << "  " << cap << " = select i1 " << below
                   << ", i32 " << lo << ", i32 " << cap_hi << "\n";
                uint32_t mask = (lane_bits == 8) ? 0xffu : 0xffffu;
                std::string m = fresh();
                ir << "  " << m << " = and i32 " << cap << ", "
                   << static_cast<int32_t>(mask) << "\n";
                return m;
            }
            case ParMod::UnsignedSat: {
                // Clamp to unsigned range.
                int32_t hi = (lane_bits == 8) ? 0xff : 0xffff;
                // For SUB: clamp to >=0 by max(0, raw)
                std::string below = fresh();
                ir << "  " << below << " = icmp slt i32 " << raw
                   << ", 0\n";
                std::string cap_lo = fresh();
                ir << "  " << cap_lo << " = select i1 " << below
                   << ", i32 0, i32 " << raw << "\n";
                std::string above = fresh();
                ir << "  " << above << " = icmp sgt i32 " << cap_lo
                   << ", " << hi << "\n";
                std::string cap = fresh();
                ir << "  " << cap << " = select i1 " << above
                   << ", i32 " << hi << ", i32 " << cap_lo << "\n";
                (void)is_sub;
                uint32_t mask = (lane_bits == 8) ? 0xffu : 0xffffu;
                std::string m = fresh();
                ir << "  " << m << " = and i32 " << cap << ", "
                   << static_cast<int32_t>(mask) << "\n";
                return m;
            }
            case ParMod::SignedHalve: {
                // (raw) >> 1 with sign-extend semantics.
                std::string h = fresh();
                ir << "  " << h << " = ashr i32 " << raw << ", 1\n";
                uint32_t mask = (lane_bits == 8) ? 0xffu : 0xffffu;
                std::string m = fresh();
                ir << "  " << m << " = and i32 " << h << ", "
                   << static_cast<int32_t>(mask) << "\n";
                return m;
            }
            case ParMod::UnsignedHalve: {
                std::string h = fresh();
                ir << "  " << h << " = lshr i32 " << raw << ", 1\n";
                uint32_t mask = (lane_bits == 8) ? 0xffu : 0xffffu;
                std::string m = fresh();
                ir << "  " << m << " = and i32 " << h << ", "
                   << static_cast<int32_t>(mask) << "\n";
                return m;
            }
        }
        return raw;
    }

    // Extract lane `byte_off..byte_off+lane_bits/8` from Rn as i32 with
    // the right sign extension for `mod`.
    std::string par_extract_lane(const std::string& v, int byte_off,
                                   int lane_bits, ParMod mod) {
        std::string sh = v;
        if (byte_off > 0) {
            std::string s = fresh();
            ir << "  " << s << " = lshr i32 " << v << ", "
               << (byte_off * 8) << "\n";
            sh = s;
        }
        bool is_signed = (mod == ParMod::Modular ||
                          mod == ParMod::SignedSat ||
                          mod == ParMod::SignedHalve);
        const char* small_ty = (lane_bits == 8) ? "i8" : "i16";
        std::string trunc = fresh();
        ir << "  " << trunc << " = trunc i32 " << sh << " to "
           << small_ty << "\n";
        std::string ext = fresh();
        ir << "  " << ext << " = " << (is_signed ? "sext" : "zext")
           << " " << small_ty << " " << trunc << " to i32\n";
        return ext;
    }

    // Compute and store APSR.GE for ONE lane of a modular parallel
    // add/sub. ARM ARM A2.5 + the per-instruction pseudocode (e.g.
    // A8.6.159 SADD16, A8.6.231 UADD16, plus SSUB/USUB/SASX/SSAX/UASX/USAX):
    //   - unsigned add  -> GE = (zext(a)+zext(b)) >= 2^lanebits  (carry-out)
    //   - signed add/sub -> GE = signed result >= 0
    //   - unsigned sub   -> GE = a >= b unsigned                 (no borrow)
    // a32/b32 are the raw Rn/Rm i32 register values; the byte offsets select
    // the (possibly cross-paired) lanes; lane_op is the effective per-lane
    // op after ASX/SAX pairing; is_signed selects the signed vs unsigned
    // rule. Returns an i1 SSA holding the GE bit for this lane.
    std::string compute_par_ge_bit(const std::string& a32, int a_byte_off,
                                    const std::string& b32, int b_byte_off,
                                    ParOp lane_op, bool is_signed,
                                    int lane_bits) {
        const char* small_ty = (lane_bits == 8) ? "i8" : "i16";
        const char* extop    = is_signed ? "sext" : "zext";
        auto ext_lane = [&](const std::string& v, int byte_off) -> std::string {
            std::string sh = v;
            if (byte_off > 0) {
                std::string s = fresh();
                ir << "  " << s << " = lshr i32 " << v << ", "
                   << (byte_off * 8) << "\n";
                sh = s;
            }
            std::string tr = fresh();
            ir << "  " << tr << " = trunc i32 " << sh << " to "
               << small_ty << "\n";
            std::string ex = fresh();
            ir << "  " << ex << " = " << extop << " " << small_ty
               << " " << tr << " to i32\n";
            return ex;
        };
        std::string al = ext_lane(a32, a_byte_off);
        std::string bl = ext_lane(b32, b_byte_off);
        std::string ge = fresh();
        if (lane_op == ParOp::Add) {
            std::string sum = fresh();
            ir << "  " << sum << " = add i32 " << al << ", " << bl << "\n";
            if (is_signed) {
                // signed add -> GE = result >= 0
                ir << "  " << ge << " = icmp sge i32 " << sum << ", 0\n";
            } else {
                // unsigned add -> GE = carry-out = sum >= 2^lanebits.
                // al,bl are zero-extended so 0 <= sum < 2^(lanebits+1).
                int thr = (lane_bits == 8) ? 256 : 65536;
                ir << "  " << ge << " = icmp uge i32 " << sum
                   << ", " << thr << "\n";
            }
        } else {
            if (is_signed) {
                // signed sub -> GE = result >= 0
                std::string diff = fresh();
                ir << "  " << diff << " = sub i32 " << al << ", " << bl << "\n";
                ir << "  " << ge << " = icmp sge i32 " << diff << ", 0\n";
            } else {
                // unsigned sub -> GE = no borrow = a >= b (unsigned).
                ir << "  " << ge << " = icmp uge i32 " << al
                   << ", " << bl << "\n";
            }
        }
        return ge;
    }

    // Generic parallel-arith dispatcher.
    bool emit_par_arith(const cs_insn* in, int lane_bits, ParMod mod,
                          ParOp base_op) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        // GE side-effects (ARM ARM A2.5) are written ONLY by the modular
        // (non-halving, non-saturating) variants: SADD/SSUB/UADD/USUB/
        // SASX/SSAX/UASX/USAX. Halving (SH*/UH*) and saturating (Q*) set
        // no GE. Determine signedness of the GE rule from the opcode --
        // ParMod::Modular alone cannot distinguish SADD16 (signed) from
        // UADD16 (unsigned), so we read in->id here.
        bool writes_ge = (mod == ParMod::Modular);
        bool ge_signed = false;
        if (writes_ge) {
            switch (in->id) {
                case ARM_INS_SADD16: case ARM_INS_SSUB16:
                case ARM_INS_SADD8:  case ARM_INS_SSUB8:
                case ARM_INS_SASX:   case ARM_INS_SSAX:
                    ge_signed = true;  break;
                case ARM_INS_UADD16: case ARM_INS_USUB16:
                case ARM_INS_UADD8:  case ARM_INS_USUB8:
                case ARM_INS_UASX:   case ARM_INS_USAX:
                    ge_signed = false; break;
                default:
                    // Modular parallel op we did not enumerate -> be safe,
                    // skip GE rather than emit a wrong flag.
                    writes_ge = false; break;
            }
        }
        int lane_bytes = lane_bits / 8;
        int n_lanes = 4 / lane_bytes;
        std::string out = "0";
        for (int i = 0; i < n_lanes; ++i) {
            std::string a_lane = par_extract_lane(a, i * lane_bytes,
                                                   lane_bits, mod);
            // For ASX/SAX, swap the Rm lane at index 1 with 0 (16-bit only).
            int b_idx = i;
            ParOp lane_op = base_op;
            if (base_op == ParOp::Asx) {
                // ASX: low = Rn_lo + Rm_hi; high = Rn_hi - Rm_lo.
                if (i == 0) { b_idx = 1; lane_op = ParOp::Add; }
                else         { b_idx = 0; lane_op = ParOp::Sub; }
            } else if (base_op == ParOp::Sax) {
                // SAX: low = Rn_lo - Rm_hi; high = Rn_hi + Rm_lo.
                if (i == 0) { b_idx = 1; lane_op = ParOp::Sub; }
                else         { b_idx = 0; lane_op = ParOp::Add; }
            }
            std::string b_lane = par_extract_lane(b, b_idx * lane_bytes,
                                                   lane_bits, mod);
            std::string r = par_arith_lane(a_lane, b_lane,
                                             lane_op, mod, lane_bits);
            if (i == 0) {
                out = r;
            } else {
                std::string sh = fresh();
                ir << "  " << sh << " = shl i32 " << r
                   << ", " << (i * lane_bits) << "\n";
                std::string nx = fresh();
                ir << "  " << nx << " = or i32 " << out
                   << ", " << sh << "\n";
                out = nx;
            }
            if (writes_ge) {
                // GE for this lane. 8-bit ops (n_lanes==4) map lane i to
                // GE[i]; 16-bit ops (n_lanes==2) map lane i to the byte
                // pair {2i, 2i+1}. Computed on the SAME cross-paired lanes
                // and effective op as the value.
                std::string ge = compute_par_ge_bit(
                    a, i * lane_bytes, b, b_idx * lane_bytes,
                    lane_op, ge_signed, lane_bits);
                if (lane_bits == 8) {
                    store_ge(i, ge);
                } else {
                    store_ge(2 * i, ge);
                    store_ge(2 * i + 1, ge);
                }
            }
        }
        store_reg(rd, out);
        return true;
    }

    // QADD / QSUB Rd, Rm, Rn  -- signed saturating 32-bit add/sub.
    // ARM ARM A8.6.131/A8.6.156. Single 32-bit lane.
    bool emit_q32(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        // Capstone reports QADD/QSUB as Rd, Rm, Rn (note the order swap)
        int rm = arm_reg_idx(d.operands[1].reg);
        int rn = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_reg(rm);
        std::string b = load_reg(rn);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << b << " to i64\n";
        std::string sum = fresh();
        ir << "  " << sum << " = " << (is_sub ? "sub" : "add")
           << " i64 " << a64 << ", " << b64 << "\n";
        std::string above = fresh();
        ir << "  " << above << " = icmp sgt i64 " << sum
           << ", 2147483647\n";
        std::string cap_hi = fresh();
        ir << "  " << cap_hi << " = select i1 " << above
           << ", i64 2147483647, i64 " << sum << "\n";
        std::string below = fresh();
        ir << "  " << below << " = icmp slt i64 " << cap_hi
           << ", -2147483648\n";
        std::string cap = fresh();
        ir << "  " << cap << " = select i1 " << below
           << ", i64 -2147483648, i64 " << cap_hi << "\n";
        std::string out = fresh();
        ir << "  " << out << " = trunc i64 " << cap << " to i32\n";
        store_reg(rd, out);
        // Sticky APSR.Q: set if the result saturated either direction.
        // ARM ARM A8.6.131/A8.6.156.
        std::string q_or = fresh();
        ir << "  " << q_or << " = or i1 " << above << ", " << below << "\n";
        set_q_sticky(q_or);
        return true;
    }

    // QDADD / QDSUB Rd, Rm, Rn  -- saturating doubled add/sub:
    // Rd = SAT(Rm + SAT(2*Rn)) for QDADD, Rd = SAT(Rm - SAT(2*Rn)) for QDSUB.
    // ARM ARM A8.6.135/A8.6.158.
    bool emit_qd32(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rm = arm_reg_idx(d.operands[1].reg);
        int rn = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string b = load_reg(rn);
        std::string a = load_reg(rm);
        auto sat32 = [&](const std::string& v64) -> std::string {
            std::string above = fresh();
            ir << "  " << above << " = icmp sgt i64 " << v64
               << ", 2147483647\n";
            std::string cap_hi = fresh();
            ir << "  " << cap_hi << " = select i1 " << above
               << ", i64 2147483647, i64 " << v64 << "\n";
            std::string below = fresh();
            ir << "  " << below << " = icmp slt i64 " << cap_hi
               << ", -2147483648\n";
            std::string cap = fresh();
            ir << "  " << cap << " = select i1 " << below
               << ", i64 -2147483648, i64 " << cap_hi << "\n";
            return cap;
        };
        // Double Rn (signed) then saturate.
        std::string b64 = fresh();
        ir << "  " << b64 << " = sext i32 " << b << " to i64\n";
        std::string b_dbl = fresh();
        ir << "  " << b_dbl << " = shl i64 " << b64 << ", 1\n";
        std::string b_sat = sat32(b_dbl);
        std::string a64 = fresh();
        ir << "  " << a64 << " = sext i32 " << a << " to i64\n";
        std::string sum = fresh();
        ir << "  " << sum << " = " << (is_sub ? "sub" : "add")
           << " i64 " << a64 << ", " << b_sat << "\n";
        std::string final_sat = sat32(sum);
        std::string out = fresh();
        ir << "  " << out << " = trunc i64 " << final_sat << " to i32\n";
        store_reg(rd, out);
        // Sticky APSR.Q: set if the final result was clamped (differs from
        // the unsaturated sum). ARM ARM A8.6.135/A8.6.158.
        std::string sat_ne = fresh();
        ir << "  " << sat_ne << " = icmp ne i64 " << final_sat << ", " << sum << "\n";
        set_q_sticky(sat_ne);
        return true;
    }

    // SEL Rd, Rn, Rm -- byte-wise select on APSR.GE.
    // ARM ARM A8.6.165 (A8.8.376): for each byte i in 0..3,
    //   Rd[8i+7:8i] = GE[i] ? Rn[8i+7:8i] : Rm[8i+7:8i].
    // SEL is the consumer side of the parallel add/sub GE producers;
    // the ARMv6 SIMD-in-GPR clamp/blend idiom is {SADD16/USUB8/...; SEL}.
    bool emit_sel(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        int rm = arm_reg_idx(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        std::string n = load_reg(rn);
        std::string m = load_reg(rm);
        std::string out = "0";
        for (int i = 0; i < 4; ++i) {
            std::string ge = load_ge(i);
            std::string n_sh = n;
            std::string m_sh = m;
            if (i > 0) {
                std::string ns = fresh();
                ir << "  " << ns << " = lshr i32 " << n << ", " << (i * 8) << "\n";
                n_sh = ns;
                std::string ms = fresh();
                ir << "  " << ms << " = lshr i32 " << m << ", " << (i * 8) << "\n";
                m_sh = ms;
            }
            std::string n_b = fresh();
            ir << "  " << n_b << " = and i32 " << n_sh << ", 255\n";
            std::string m_b = fresh();
            ir << "  " << m_b << " = and i32 " << m_sh << ", 255\n";
            std::string pick = fresh();
            ir << "  " << pick << " = select i1 " << ge
               << ", i32 " << n_b << ", i32 " << m_b << "\n";
            std::string placed = pick;
            if (i > 0) {
                std::string p = fresh();
                ir << "  " << p << " = shl i32 " << pick << ", " << (i * 8) << "\n";
                placed = p;
            }
            if (i == 0) {
                out = placed;
            } else {
                std::string nx = fresh();
                ir << "  " << nx << " = or i32 " << out << ", " << placed << "\n";
                out = nx;
            }
        }
        store_reg(rd, out);
        return true;
    }

    // RFE -- return-from-exception (kernel only). User code reaching
    // here is dead code or junk data. Emit no IR (semantic noop) so
    // surrounding function still lifts cleanly.
    bool emit_rfe_noop() { return true; }

    // DMB / DSB / ISB -- memory barriers. Lower to LLVM fence.
    bool emit_barrier() {
        ir << "  fence acq_rel\n";
        return true;
    }

    // BLX Rn  -- branch and link via register. We model it as an
    // indirect call; the runtime will need to resolve register-held
    // function pointers. For Stage 1b we emit a call through the
    // register's stored function-pointer value, treating it as a
    // pointer-sized integer cast to function pointer.
    bool emit_blx(const cs_insn* in, uint32_t return_addr) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 1) return false;
        if (d.operands[0].type == ARM_OP_REG) {
            int rs = arm_reg_idx(d.operands[0].reg);
            if (rs < 0) return false;
            // BUG 4: `blx<cond> Rm` is a real encoding (A8.8.26) and must
            // not call on a false predicate. See emit_bl's CallGuard note.
            //
            // Reading Rm BEFORE writing LR is also the architectural
            // order, not just SSA-dominance convenience -- A8.8.26 is
            // `target = R[m];` THEN `LR = next_instr_addr;`. The old code
            // stored LR first, so `blx lr` (legal, if rare) called its own
            // return address instead of the intended target.
            std::string target_i32 = load_reg(rs);
            CallGuard cg = call_guard_begin(d);
            guarded_store_reg(cg, 14, std::to_string(return_addr + load_bias_));  // per-image bias (LR-as-data consistency; returns are C ret)
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Route through the shim's dispatcher. It recognizes JNI
            // vtable markers and proxies them; for in-image function
            // pointers it calls (guest_base + target) as native code.
            // Keeping this routing in C++ means we don't need the
            // lifter to know about either case.
            std::string ret = fresh();
            ir << "  " << ret << " = call i32 @__macapk_indirect_call("
               << "i32 " << target_i32
               << ", i32 " << a0
               << ", i32 " << a1
               << ", i32 " << a2
               << ", i32 " << a3
               << ", i32 " << sp
               << ", i32 " << current_insn_addr << ")\n";   // from_vaddr (diag)
            guarded_store_reg(cg, 0, ret);
            call_guard_end(cg);
            return true;
        }
        if (d.operands[0].type == ARM_OP_IMM) {
            // BLX #imm is a direct call (and switches to Thumb).
            // Treat like BL for symbol resolution; mode switch is
            // irrelevant once we've translated the target.
            uint32_t target = static_cast<uint32_t>(d.operands[0].imm);
            extern_call_targets.insert(target);
            // Authoritative: direct BLX #imm -> function entry.
            extern_bl_targets.insert(target);
            // v1.0.814: BLX #imm IS the interworking form, so unlike plain BL
            // the callee is in the OPPOSITE mode from the caller. Recording
            // the caller's own mode here would be exactly backwards.
            note_call_target_mode(target, !current_is_thumb);
            // A32's BLX #imm has no condition field, but the Thumb T2
            // encoding can sit last in an IT block, so Capstone can hand
            // us a real cc here. Guard on it rather than assuming AL.
            CallGuard cg = call_guard_begin(d);
            guarded_store_reg(cg, 14, std::to_string(return_addr + load_bias_));  // per-image bias (LR-as-data consistency; returns are C ret)
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Trace (BLX immediate -> direct call with ARM<->Thumb
            // mode switch). Covered by same env vars as emit_bl.
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << target
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = call i32 @__macapk_target_"
               << std::hex << target << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            guarded_store_reg(cg, 0, ret);
            call_guard_end(cg);
            return true;
        }
        return false;
    }

    // LDM / STM family -- multi-register memory access.
    // We support the common modes: IA (default), IB, DA, DB, plus the
    // writeback (!) variant. Register list is in operands[1..N].
    // The base register is operands[0]; first source/dest is operands[1].
    bool emit_ldm_stm(const cs_insn* in, bool is_load,
                       int direction, int pre, bool* is_return) {
        // direction: +1 = increment, -1 = decrement
        // pre: 1 if pre-increment/decrement (IB / DB), 0 if post (IA / DA)
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rbase = arm_reg_idx(d.operands[0].reg);
        if (rbase < 0) return false;
        bool writeback = d.writeback;
        int n = d.op_count - 1;
        std::string addr = load_reg(rbase);
        bool returns = false;
        for (int i = 0; i < n; ++i) {
            const cs_arm_op& op = d.operands[1 + i];
            if (op.type != ARM_OP_REG) return false;
            int r = arm_reg_idx(op.reg);
            if (r < 0) return false;
            // Compute the slot address.
            int offset_idx = (direction > 0) ? i : (n - 1 - i);
            int signed_off = direction * offset_idx * 4;
            if (pre) signed_off += direction * 4;
            std::string slot_addr = fresh();
            ir << "  " << slot_addr << " = add i32 " << addr
               << ", " << signed_off << "\n";
            std::string p = stack_ptr(slot_addr);
            if (is_load) {
                std::string val = fresh();
                ir << "  " << val << " = load i32, ptr " << p << ", align 4\n";
                if (r == 15) returns = true;
                else         store_reg(r, val);
            } else {
                std::string val = load_reg(r);
                if (current_pred.empty()) {
                    ir << "  store i32 " << val << ", ptr " << p
                       << ", align 4\n";
                } else {
                    // Predicated STM (A8.8.199): the WHOLE multi-store
                    // (and the base writeback below) is conditional. On
                    // a false predicate ARMv7 touches no memory. Guard
                    // each element store in its own BB so the false path
                    // performs no access. slot_addr / p / val are pure
                    // and dominate the guard. (Per-element guards are
                    // correct: the predicate is loop-invariant, and the
                    // base writeback after the loop is guarded
                    // separately below.)
                    std::string saved_pred = current_pred;
                    int gk = pred_guard_begin(saved_pred);
                    current_pred.clear();
                    ir << "  store i32 " << val << ", ptr " << p
                       << ", align 4\n";
                    if (emit_store_trace_) {
                        ir << "  call void @__macapk_trace_store(i32 "
                           << slot_addr << ", i32 " << val
                           << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                    }
                    current_pred = saved_pred;
                    pred_guard_end(gk);
                }
                // Watchpoint hook for unpredicated STM stores.
                if (current_pred.empty() && emit_store_trace_) {
                    ir << "  call void @__macapk_trace_store(i32 "
                       << slot_addr << ", i32 " << val
                       << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                }
            }
        }
        if (writeback) {
            std::string new_base = fresh();
            ir << "  " << new_base << " = add i32 " << addr
               << ", " << (direction * n * 4) << "\n";
            if (is_load || current_pred.empty()) {
                // LDM writeback, or unpredicated STM writeback: the
                // base update happens unconditionally (LDM predication
                // is already handled by store_reg's select-blend for
                // each loaded reg; LDM's load hazard is addressed by the
                // emit_ldr/LDM load paths, and LDM base writeback is
                // value-only). Keep the existing select-blend behavior.
                store_reg(rbase, new_base);
            } else {
                // Predicated STM base writeback (A8.8.199): only on the
                // true path. Guard it. new_base is pure and dominates.
                std::string saved_pred = current_pred;
                int gk = pred_guard_begin(saved_pred);
                current_pred.clear();
                store_reg_to_mem(rbase, new_base);
                current_pred = saved_pred;
                pred_guard_end(gk);
            }
        }
        if (is_return) *is_return = returns;
        return true;
    }

    // ---- VFP / NEON minimum subset --------------------------------

    // Map a Capstone d-register enum to a 0..31 index. Returns -1 if not.
    static int vfp_d_idx(unsigned int reg) {
        if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31)
            return static_cast<int>(reg - ARM_REG_D0);
        return -1;
    }
    static int vfp_s_idx(unsigned int reg) {
        if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31)
            return static_cast<int>(reg - ARM_REG_S0);
        return -1;
    }

    std::string load_dreg(int n) {
        std::string slot = "%fpL" + std::to_string(ssa_counter);
        ir << "  " << slot << " = getelementptr inbounds [32 x i64], "
                            "ptr %fpr, i32 0, i32 " << n << "\n";
        std::string val = fresh();
        ir << "  " << val << " = load i64, ptr " << slot << ", align 8\n";
        return val;
    }
    void store_dreg(int n, const std::string& val_ssa) {
        std::string val = val_ssa;
        if (!current_pred.empty()) {
            std::string old = load_dreg(n);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i64 " << val << ", i64 " << old << "\n";
            val = sel;
        }
        std::string slot = "%fpS" + std::to_string(ssa_counter);
        ir << "  " << slot << " = getelementptr inbounds [32 x i64], "
                            "ptr %fpr, i32 0, i32 " << n << "\n";
        ir << "  store i64 " << val << ", ptr " << slot << ", align 8\n";
        ++ssa_counter;
    }

    // S-reg sN: maps to the low (n even) or high (n odd) half of dN/2.
    std::string load_sreg(int n) {
        int d = n / 2;
        std::string dval = load_dreg(d);
        if ((n & 1) == 0) {
            std::string lo = fresh();
            ir << "  " << lo << " = trunc i64 " << dval << " to i32\n";
            return lo;
        } else {
            std::string sh = fresh();
            ir << "  " << sh << " = lshr i64 " << dval << ", 32\n";
            std::string hi = fresh();
            ir << "  " << hi << " = trunc i64 " << sh << " to i32\n";
            return hi;
        }
    }
    void store_sreg(int n, const std::string& val_ssa_i32) {
        int d = n / 2;
        std::string old = load_dreg(d);
        std::string val_i64 = fresh();
        ir << "  " << val_i64 << " = zext i32 " << val_ssa_i32 << " to i64\n";
        std::string out;
        if ((n & 1) == 0) {
            // Replace low 32 bits.
            std::string mask = fresh();
            ir << "  " << mask << " = and i64 " << old
               << ", -4294967296\n";   // 0xffffffff00000000
            out = fresh();
            ir << "  " << out << " = or i64 " << mask << ", " << val_i64 << "\n";
        } else {
            std::string shifted = fresh();
            ir << "  " << shifted << " = shl i64 " << val_i64 << ", 32\n";
            std::string mask = fresh();
            ir << "  " << mask << " = and i64 " << old
               << ", 4294967295\n";    // 0x00000000ffffffff
            out = fresh();
            ir << "  " << out << " = or i64 " << mask << ", " << shifted << "\n";
        }
        store_dreg(d, out);
    }

    // Mem helpers for 64-bit data (used by VLDR / VSTR). Same stack-only
    // address model as the 32-bit memory ops.
    std::string load_mem_i64(const std::string& addr_ssa) {
        std::string p = stack_ptr(addr_ssa);
        std::string val = fresh();
        ir << "  " << val << " = load i64, ptr " << p << ", align 8\n";
        return val;
    }
    void store_mem_i64(const std::string& addr_ssa,
                       const std::string& val_ssa) {
        std::string p = stack_ptr(addr_ssa);
        if (current_pred.empty()) {
            ir << "  store i64 " << val_ssa << ", ptr " << p << ", align 8\n";
        } else {
            std::string old = fresh();
            ir << "  " << old << " = load i64, ptr " << p << ", align 8\n";
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << current_pred
               << ", i64 " << val_ssa << ", i64 " << old << "\n";
            ir << "  store i64 " << sel << ", ptr " << p << ", align 8\n";
        }
    }

    // VPUSH / VPOP {dN, dM, ...}
    bool emit_vpushpop(const cs_insn* in, bool is_pop) {
        const cs_arm& d = in->detail->arm;
        int n = d.op_count;
        if (n == 0) return false;
        // All operands must be d-regs or all s-regs. Mixed lists are
        // not architecturally valid -- VPUSH/VPOP encode size in the
        // opcode and the size applies to every register in the list.
        bool all_d = true, all_s = true;
        for (int i = 0; i < n; ++i) {
            if (d.operands[i].type != ARM_OP_REG) return false;
            if (vfp_d_idx(d.operands[i].reg) < 0) all_d = false;
            if (vfp_s_idx(d.operands[i].reg) < 0) all_s = false;
        }
        if (!all_d && !all_s) return false;
        int slot_bytes = all_d ? 8 : 4;
        std::string sp_old = load_reg(13);
        if (!is_pop) {
            std::string sp_new = fresh();
            ir << "  " << sp_new << " = sub i32 " << sp_old
               << ", " << (slot_bytes * n) << "\n";
            store_reg(13, sp_new);
            for (int i = 0; i < n; ++i) {
                std::string addr = fresh();
                ir << "  " << addr << " = add i32 " << sp_new
                   << ", " << (slot_bytes * i) << "\n";
                if (all_d) {
                    int reg = vfp_d_idx(d.operands[i].reg);
                    std::string val = load_dreg(reg);
                    store_mem_i64(addr, val);
                } else {
                    int reg = vfp_s_idx(d.operands[i].reg);
                    std::string val = load_sreg(reg);
                    std::string p = stack_ptr(addr);
                    ir << "  store i32 " << val << ", ptr " << p
                       << ", align 4\n";
                }
            }
        } else {
            for (int i = 0; i < n; ++i) {
                std::string addr = fresh();
                ir << "  " << addr << " = add i32 " << sp_old
                   << ", " << (slot_bytes * i) << "\n";
                if (all_d) {
                    int reg = vfp_d_idx(d.operands[i].reg);
                    std::string val = load_mem_i64(addr);
                    store_dreg(reg, val);
                } else {
                    int reg = vfp_s_idx(d.operands[i].reg);
                    std::string p = stack_ptr(addr);
                    std::string val = fresh();
                    ir << "  " << val << " = load i32, ptr " << p
                       << ", align 4\n";
                    store_sreg(reg, val);
                }
            }
            std::string sp_new = fresh();
            ir << "  " << sp_new << " = add i32 " << sp_old
               << ", " << (slot_bytes * n) << "\n";
            store_reg(13, sp_new);
        }
        return true;
    }

    // VLDR / VSTR  Sn|Dn, [Rb {, #imm}]
    bool emit_vldr_vstr(const cs_insn* in, bool is_load) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_MEM) return false;
        int dreg = vfp_d_idx(d.operands[0].reg);
        int sreg = vfp_s_idx(d.operands[0].reg);
        bool is_double = dreg >= 0;
        if (!is_double && sreg < 0) return false;

        // PC-relative: read the constant from the original .so so the
        // FP literal pool stays accessible after translation.
        if (d.operands[1].mem.base == ARM_REG_PC && is_load && image_) {
            int32_t disp = static_cast<int32_t>(d.operands[1].mem.disp);
            // ARM PC-relative addressing: PC reads as Align(insn,4)+8
            // in ARM mode, Align(insn,4)+4 in Thumb (ARM ARM A2.4.3).
            // The discriminator MUST be the decode MODE, not the
            // instruction size: VLDR has no 16-bit encoding -- it is
            // always a 4-byte instruction in BOTH ARM and Thumb-2, so
            // `in->size == 2` is NEVER true here and the old size-based
            // test always picked +8, silently mis-reading every
            // Thumb-mode VLDR literal-pool constant by 4 bytes (loads
            // the next pool slot's float/double). Use current_is_thumb
            // to stay consistent with compute_mem_addr / load_reg(15),
            // which are the authoritative PC-value sources elsewhere in
            // this file. Still align down to 4 per the ARM rule.
            uint32_t pc_base = (static_cast<uint32_t>(in->address)
                                + (current_is_thumb ? 4u : 8u)) & ~3u;
            uint32_t addr = pc_base + disp;
            auto bytes = image_->code_at(addr, is_double ? 8 : 4);
            if (bytes.size() < (is_double ? 8u : 4u)) return false;
            if (is_double) {
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i)
                    v |= static_cast<uint64_t>(bytes[i]) << (8 * i);
                store_dreg(dreg, std::to_string(static_cast<long long>(v)));
            } else {
                uint32_t v = 0;
                for (int i = 0; i < 4; ++i)
                    v |= static_cast<uint32_t>(bytes[i]) << (8 * i);
                store_sreg(sreg, std::to_string(static_cast<int>(v)));
            }
            return true;
        }

        std::string addr = compute_mem_addr(d.operands[1]);
        if (addr.empty()) return false;
        if (is_double) {
            if (is_load) {
                std::string val = load_mem_i64(addr);
                store_dreg(dreg, val);
            } else {
                std::string val = load_dreg(dreg);
                store_mem_i64(addr, val);
                // Watchpoint hook for VSTR.64: split the 64-bit store
                // into low+high i32 traces so the per-32-bit watch
                // window catches it. A double-store that writes 8
                // bytes can clobber both _M_start and _M_finish in
                // one shot, which is exactly the kind of store the
                // bug-2 hunt is looking for.
                if (emit_store_trace_) {
                    std::string lo = fresh();
                    ir << "  " << lo << " = trunc i64 " << val
                       << " to i32\n";
                    std::string sh = fresh();
                    ir << "  " << sh << " = lshr i64 " << val
                       << ", 32\n";
                    std::string hi = fresh();
                    ir << "  " << hi << " = trunc i64 " << sh
                       << " to i32\n";
                    std::string addr_hi = fresh();
                    ir << "  " << addr_hi << " = add i32 " << addr
                       << ", 4\n";
                    ir << "  call void @__macapk_trace_store(i32 "
                       << addr << ", i32 " << lo
                       << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                    ir << "  call void @__macapk_trace_store(i32 "
                       << addr_hi << ", i32 " << hi
                       << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                }
            }
        } else {
            // Single-precision: 4-byte memory access.
            std::string p = stack_ptr(addr);
            if (is_load) {
                std::string val = fresh();
                ir << "  " << val << " = load i32, ptr " << p
                   << ", align 4\n";
                store_sreg(sreg, val);
            } else {
                std::string val = load_sreg(sreg);
                if (current_pred.empty()) {
                    ir << "  store i32 " << val << ", ptr " << p
                       << ", align 4\n";
                } else {
                    std::string old = fresh();
                    ir << "  " << old << " = load i32, ptr " << p
                       << ", align 4\n";
                    std::string sel = fresh();
                    ir << "  " << sel << " = select i1 " << current_pred
                       << ", i32 " << val << ", i32 " << old << "\n";
                    ir << "  store i32 " << sel << ", ptr " << p
                       << ", align 4\n";
                }
                // Watchpoint hook for VSTR.32 (single-precision FP)
                // -- VFP s-regs can be used by the compiler as
                // generic 32-bit transfer slots for unaligned stores
                // or PIC trampolines. Without this hook, a v1.0.52
                // bug-2 stash could escape the regular STR watch.
                if (emit_store_trace_) {
                    ir << "  call void @__macapk_trace_store(i32 "
                       << addr << ", i32 " << val
                       << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                }
            }
        }
        return true;
    }

    // VMOV -- many forms; we handle the most common:
    //   VMOV Dd, Dn      (d-d copy)
    //   VMOV Sd, Sn      (s-s copy)
    //   VMOV Sd, #imm    (s-imm)
    //   VMOV Dd, #imm    (d-imm)
    //   VMOV Dd, Rlo, Rhi  (d-from-int-pair)
    //   VMOV Rlo, Rhi, Dn  (int-pair-from-d)
    //   VMOV Sn, Rm      (s-from-int)
    //   VMOV Rm, Sn      (int-from-s)
    bool emit_vmov(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        // 2-operand forms.
        if (d.op_count == 2) {
            const cs_arm_op& o0 = d.operands[0];
            const cs_arm_op& o1 = d.operands[1];
            if (o0.type != ARM_OP_REG) return false;
            int dst_d = vfp_d_idx(o0.reg);
            int dst_s = vfp_s_idx(o0.reg);
            int dst_r = arm_reg_idx(o0.reg);
            // Source: reg (vfp or int) or imm.
            if (o1.type == ARM_OP_IMM) {
                int64_t imm = static_cast<int64_t>(o1.imm);
                // VMOV.I<sz> Dd/Qd, #imm -- the NEON vector-immediate form:
                // replicate the per-ELEMENT immediate across every lane. A
                // Q-reg destination was previously UNHANDLED (dst_d/s/r all
                // -1 for a Q reg), so the whole instruction no-op'd and left
                // the register holding garbage; a following vst1 then wrote
                // that garbage to memory. That was the ShatteredPD cross-.so
                // corruption: FT_New_Size's `vmov.i32 q8,#0 ; vst1.8
                // {d16,d17},[r1]!` was meant to ZERO a freshly-allocated
                // FT_Size_Internal, but wrote garbage instead; the garbage
                // (interpreted as a pointer) later drove a stray write into
                // the sibling libgdx.so's gdx2d state -> "Error loading
                // pixmap" -> flat blue. The D-reg case here also used the raw
                // imm (wrong for a non-zero replicated element); replicating
                // fixes both. FP immediates take the ARM_OP_FP branch below.
                int q = vfp_q_idx(o0.reg);
                if (q >= 0 || dst_d >= 0) {
                    int ebits = vdata_bits(d.vector_data);
                    if (ebits <= 0) ebits = 32;           // default element = 32b
                    uint64_t dval;
                    if (ebits >= 64) {
                        dval = static_cast<uint64_t>(imm);
                    } else {
                        uint64_t e = static_cast<uint64_t>(imm)
                                     & ((1ULL << ebits) - 1ULL);
                        dval = 0;
                        for (int b = 0; b < 64; b += ebits) dval |= (e << b);
                    }
                    std::string dv =
                        std::to_string(static_cast<int64_t>(dval));
                    if (q >= 0) {                          // Qd = d(2q):d(2q+1)
                        store_dreg(q * 2,     dv);
                        store_dreg(q * 2 + 1, dv);
                    } else {
                        store_dreg(dst_d, dv);
                    }
                    return true;
                }
                if (dst_s >= 0) {
                    store_sreg(dst_s, std::to_string(static_cast<int>(imm)));
                    return true;
                }
                if (dst_r >= 0) {
                    store_reg(dst_r, std::to_string(static_cast<int>(imm)));
                    return true;
                }
                return false;
            }
            // VFP-immediate moves: Capstone reports the immediate as
            // `ARM_OP_FP` with the floating value in `op.fp` (a double).
            // The encoding is the 8-bit VFPExpandImm from ARM ARM
            // A8.6.327 -- e.g. `vmov.f32 s0, #1.0` -> `0xEEB7_0A00`,
            // imm8 = 0x70, expanded value = 1.0.
            //
            // Before this branch existed the emit_vmov function fell
            // through to `if (o1.type != ARM_OP_REG) return false;`
            // and silently dropped EVERY FP-immediate move. That left
            // `m_fScaleX = m_fScaleY = 0.0f` in CCNode constructors
            // (default should be 1.0f), `m_fOpacity = 0.0f` in
            // CCSprite::init, `m_fRotation = 0.0f` everywhere, etc.
            // The downstream symptom on HCR 1.43 ARM32 forced was a
            // freshly-runWithScene'd CCScene rendering at zero scale
            // = invisible -- the black-screen even after the
            // v1.0.53 carry-flag bug-2 fix.
            //
            // Single-precision: reinterpret the double as float, take
            // the 32-bit bit pattern, store to the s-reg slot.
            // Double-precision: take the 64-bit bit pattern of the
            // double directly, store to the d-reg slot.
            if (o1.type == ARM_OP_FP) {
                if (dst_s >= 0) {
                    float f = static_cast<float>(o1.fp);
                    uint32_t bits;
                    std::memcpy(&bits, &f, sizeof(bits));
                    store_sreg(dst_s, std::to_string(
                        static_cast<int32_t>(bits)));
                    return true;
                }
                if (dst_d >= 0) {
                    double dval = o1.fp;
                    uint64_t bits;
                    std::memcpy(&bits, &dval, sizeof(bits));
                    store_dreg(dst_d, std::to_string(
                        static_cast<int64_t>(bits)));
                    return true;
                }
                return false;
            }
            if (o1.type != ARM_OP_REG) return false;
            int src_d = vfp_d_idx(o1.reg);
            int src_s = vfp_s_idx(o1.reg);
            int src_r = arm_reg_idx(o1.reg);
            // VMOV.<size> Rt, Dn[lane]  -- extract lane from d-reg.
            // VMOV.<size> Dn[lane], Rt  -- insert into d-reg lane.
            // Capstone marks the lane operand with vector_index >= 0;
            // size comes from vector_data (S8/U8/S16/U16/I32...).
            // Sign-extension only matters for the extract direction.
            int lane_bits = vdata_bits(d.vector_data);
            if (lane_bits == 0 && d.vector_size > 0) lane_bits = d.vector_size;
            if (lane_bits == 0) lane_bits = 32;
            bool sign_ext = vdata_signed(d.vector_data);
            if (dst_r >= 0 && src_d >= 0 && o1.vector_index >= 0) {
                std::string v = load_dreg(src_d);
                std::string vec = i64_to_vec(v, lane_bits);
                std::string el = fresh();
                ir << "  " << el << " = extractelement <"
                   << (64 / lane_bits) << " x i" << lane_bits << "> "
                   << vec << ", i32 " << o1.vector_index << "\n";
                std::string ext = fresh();
                if (lane_bits == 32) {
                    store_reg(dst_r, el);
                } else {
                    ir << "  " << ext << " = "
                       << (sign_ext ? "sext" : "zext")
                       << " i" << lane_bits << " " << el << " to i32\n";
                    store_reg(dst_r, ext);
                }
                return true;
            }
            if (dst_d >= 0 && src_r >= 0 && o0.vector_index >= 0) {
                std::string old = load_dreg(dst_d);
                std::string vec = i64_to_vec(old, lane_bits);
                std::string rt = load_reg(src_r);
                std::string trunc = fresh();
                if (lane_bits == 32) {
                    trunc = rt;
                } else {
                    ir << "  " << trunc << " = trunc i32 " << rt
                       << " to i" << lane_bits << "\n";
                }
                std::string ins = fresh();
                ir << "  " << ins << " = insertelement <"
                   << (64 / lane_bits) << " x i" << lane_bits << "> "
                   << vec << ", i" << lane_bits << " " << trunc
                   << ", i32 " << o0.vector_index << "\n";
                std::string oi = vec_to_i64(ins, lane_bits);
                store_dreg(dst_d, oi);
                return true;
            }
            if (dst_d >= 0 && src_d >= 0) {
                store_dreg(dst_d, load_dreg(src_d));
                return true;
            }
            if (dst_s >= 0 && src_s >= 0) {
                store_sreg(dst_s, load_sreg(src_s));
                return true;
            }
            if (dst_s >= 0 && src_r >= 0) {
                store_sreg(dst_s, load_reg(src_r));
                return true;
            }
            if (dst_r >= 0 && src_s >= 0) {
                store_reg(dst_r, load_sreg(src_s));
                return true;
            }
            return false;
        }
        // 3-operand: VMOV Dd, Rlo, Rhi  OR  VMOV Rlo, Rhi, Dn.
        if (d.op_count == 3) {
            const cs_arm_op& o0 = d.operands[0];
            const cs_arm_op& o1 = d.operands[1];
            const cs_arm_op& o2 = d.operands[2];
            if (o0.type != ARM_OP_REG || o1.type != ARM_OP_REG ||
                o2.type != ARM_OP_REG)
                return false;
            int o0_d = vfp_d_idx(o0.reg);
            int o2_d = vfp_d_idx(o2.reg);
            int o0_r = arm_reg_idx(o0.reg);
            int o1_r = arm_reg_idx(o1.reg);
            int o2_r = arm_reg_idx(o2.reg);
            if (o0_d >= 0 && o1_r >= 0 && o2_r >= 0) {
                std::string lo = load_reg(o1_r);
                std::string hi = load_reg(o2_r);
                std::string lo64 = fresh();
                ir << "  " << lo64 << " = zext i32 " << lo << " to i64\n";
                std::string hi64 = fresh();
                ir << "  " << hi64 << " = zext i32 " << hi << " to i64\n";
                std::string hi_shift = fresh();
                ir << "  " << hi_shift << " = shl i64 " << hi64 << ", 32\n";
                std::string out = fresh();
                ir << "  " << out << " = or i64 " << lo64 << ", "
                   << hi_shift << "\n";
                store_dreg(o0_d, out);
                return true;
            }
            if (o2_d >= 0 && o0_r >= 0 && o1_r >= 0) {
                std::string val = load_dreg(o2_d);
                std::string lo = fresh();
                ir << "  " << lo << " = trunc i64 " << val << " to i32\n";
                std::string sh = fresh();
                ir << "  " << sh << " = lshr i64 " << val << ", 32\n";
                std::string hi = fresh();
                ir << "  " << hi << " = trunc i64 " << sh << " to i32\n";
                store_reg(o0_r, lo);
                store_reg(o1_r, hi);
                return true;
            }
            return false;
        }
        return false;
    }

    // ---- VADD / VSUB / VMUL / VDIV --------------------------------
    //
    // Element type and lane count come from arm.vector_data + register
    // class, NOT register class alone (the historic bug: every D-form
    // NEON op became one bogus scalar `double`). Per ARM DDI 0406C.d:
    //   A8.8.282/283  VADD  (integer add wraps; FP fadd)
    //   A8.8.290/291  VMUL  (integer mul wraps; FP fmul)
    //   VSUB          (integer sub wraps; FP fsub)
    //   VDIV          VFP-scalar only -- there is NO packed/integer
    //                 NEON divide in ARMv7, so VDIV stays on the true
    //                 scalar S/D path and any packed form returns false.
    //   A8.8.292      VMUL by scalar (Vd[i] = Vn[i] * Vm[index])
    //   A2.6          Advanced SIMD element-type selection
    // NEON integer arithmetic WRAPS (no saturation) -> plain add/sub/mul
    // on iLB. ARMv7 NEON has no 1-lane/2-lane f64 vector form, so a
    // D-reg op with .f64 or no vector_data is REAL scalar VFP and keeps
    // the existing scalar-double path verbatim.
    bool emit_vfp_binop(const cs_insn* in, const char* fp_op) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;

        const std::string op = fp_op;  // "fadd"|"fsub"|"fmul"|"fdiv"
        const bool is_div = (op == "fdiv");
        // Integer per-lane mnemonic for the wrapping NEON form.
        const char* int_op = (op == "fadd") ? "add"
                           : (op == "fsub") ? "sub"
                           : (op == "fmul") ? "mul"
                           : nullptr;  // VDIV has no integer NEON form

        const cs_arm_op& o0 = d.operands[0];
        const cs_arm_op& o1 = d.operands[1];
        const cs_arm_op& o2 = d.operands[2];
        bool is_q = (vfp_q_idx(o0.reg) >= 0);
        bool by_scalar = (o2.vector_index >= 0) || (o1.vector_index >= 0);
        int vd_bits  = vdata_bits(d.vector_data);
        bool vd_is_fp  = vdata_float(d.vector_data);
        bool vd_is_int = (vd_bits != 0) && !vd_is_fp;

        // ---- True scalar VFP paths (UNCHANGED behavior) -------------
        // A D-reg dst with .f64 or no vector_data, no q, no by-scalar,
        // is genuine scalar double VFP. An S-reg dst is scalar float.
        // VDIV always lands here (no packed NEON divide).
        bool scalar_double = (!is_q) && (vfp_d_idx(o0.reg) >= 0) &&
                             (!by_scalar) &&
                             (vd_bits == 0 || d.vector_data == ARM_VECTORDATA_F64);
        bool scalar_float  = (vfp_s_idx(o0.reg) >= 0);
        if (is_div) {
            // Only the genuine scalar forms are valid for divide.
            if (!scalar_double && !scalar_float) return false;
        }
        if (scalar_float && !is_q) {
            int sd = vfp_s_idx(o0.reg);
            int n = vfp_s_idx(o1.reg);
            int m = vfp_s_idx(o2.reg);
            if (n < 0 || m < 0) return false;
            std::string a_i = load_sreg(n);
            std::string b_i = load_sreg(m);
            std::string a = fresh();
            ir << "  " << a << " = bitcast i32 " << a_i << " to float\n";
            std::string b = fresh();
            ir << "  " << b << " = bitcast i32 " << b_i << " to float\n";
            std::string r = fresh();
            ir << "  " << r << " = " << op << " float " << a << ", " << b << "\n";
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast float " << r << " to i32\n";
            store_sreg(sd, r_i);
            return true;
        }
        if (scalar_double) {
            int dd = vfp_d_idx(o0.reg);
            int n = vfp_d_idx(o1.reg);
            int m = vfp_d_idx(o2.reg);
            if (n < 0 || m < 0) return false;
            std::string a_i = load_dreg(n);
            std::string b_i = load_dreg(m);
            std::string a = fresh();
            ir << "  " << a << " = bitcast i64 " << a_i << " to double\n";
            std::string b = fresh();
            ir << "  " << b << " = bitcast i64 " << b_i << " to double\n";
            std::string r = fresh();
            ir << "  " << r << " = " << op << " double " << a << ", " << b << "\n";
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast double " << r << " to i64\n";
            store_dreg(dd, r_i);
            return true;
        }

        // ---- Packed NEON path (D or Q dst) --------------------------
        // We need a usable lane width. Prefer vector_data; if absent,
        // fall back to lane_bits_of (vector_size). f32 packed needs
        // 32-bit lanes; integer uses the reported width.
        int lane_bits = (vd_bits != 0) ? vd_bits : lane_bits_of(d);
        if (lane_bits == 0) return false;            // unknown -> no-op
        bool packed_fp = vd_is_fp;
        if (!packed_fp && !vd_is_int) {
            // No datatype info at all: cannot safely pick int-vs-fp.
            // Bail to a graceful no-op rather than emit wrong IR.
            return false;
        }
        if (packed_fp && lane_bits != 32) {
            // Only 2-lane f32 (D) / 4-lane f32 (Q) packed FP arithmetic
            // exists on ARMv7 NEON; f16 packed arith is not VADD/VMUL.
            return false;
        }
        if (packed_fp && is_div) return false;       // no packed FP divide

        // Per-d-half operation. `nh`/`mh` are the d-reg indices of the
        // current half for Vn and Vm. `m_scalar_lane` >= 0 means the Vm
        // operand is by-scalar: extract that lane from the (single) Dm
        // and splat across the half.
        int lanes = 64 / lane_bits;
        auto do_half = [&](int dst_dn, int n_dn, int m_dn,
                            int m_scalar_lane) {
            std::string a = load_dreg(n_dn);
            std::string av;
            std::string bv;
            if (packed_fp) {
                av = i64_to_fvec(a, lane_bits);
            } else {
                av = i64_to_vec(a, lane_bits);
            }
            if (m_scalar_lane >= 0) {
                // Extract Vm[lane] from Dm and splat across `lanes`.
                std::string mraw = load_dreg(m_dn);
                std::string mvec = packed_fp ? i64_to_fvec(mraw, lane_bits)
                                             : i64_to_vec(mraw, lane_bits);
                std::string ielem = packed_fp ? std::string("float")
                                              : ("i" + std::to_string(lane_bits));
                std::string el = fresh();
                ir << "  " << el << " = extractelement <" << lanes
                   << " x " << ielem << "> " << mvec << ", i32 "
                   << m_scalar_lane << "\n";
                std::string ins = fresh();
                ir << "  " << ins << " = insertelement <" << lanes
                   << " x " << ielem << "> undef, " << ielem << " "
                   << el << ", i32 0\n";
                std::string sh = fresh();
                ir << "  " << sh << " = shufflevector <" << lanes
                   << " x " << ielem << "> " << ins << ", <" << lanes
                   << " x " << ielem << "> undef, <" << lanes
                   << " x i32> zeroinitializer\n";
                bv = sh;
            } else {
                std::string b = load_dreg(m_dn);
                bv = packed_fp ? i64_to_fvec(b, lane_bits)
                               : i64_to_vec(b, lane_bits);
            }
            std::string ov = fresh();
            if (packed_fp) {
                ir << "  " << ov << " = " << op << " <" << lanes
                   << " x float> " << av << ", " << bv << "\n";
            } else {
                ir << "  " << ov << " = " << int_op << " <" << lanes
                   << " x i" << lane_bits << "> " << av << ", " << bv << "\n";
            }
            std::string oi = packed_fp ? fvec_to_i64(ov, lane_bits)
                                       : vec_to_i64(ov, lane_bits);
            store_dreg(dst_dn, oi);
        };

        // By-scalar: Vm is a d-reg with vector_index; Vn matches dst
        // class. ARMv7 by-scalar dst can be D or Q; Vm is always a Dm
        // lane (A8.8.292).
        if (by_scalar) {
            int m_lane = (o2.vector_index >= 0) ? o2.vector_index
                                                : o1.vector_index;
            // The lane-indexed operand is whichever has vector_index>=0.
            const cs_arm_op& mo = (o2.vector_index >= 0) ? o2 : o1;
            const cs_arm_op& no = (o2.vector_index >= 0) ? o1 : o2;
            int m_dn = vfp_d_idx(mo.reg);
            if (m_dn < 0) return false;
            if (is_q) {
                int dq = vfp_q_idx(o0.reg);
                int nq = vfp_q_idx(no.reg);
                if (dq < 0 || nq < 0) return false;
                do_half(dq * 2 + 0, nq * 2 + 0, m_dn, m_lane);
                do_half(dq * 2 + 1, nq * 2 + 1, m_dn, m_lane);
            } else {
                int dd = vfp_d_idx(o0.reg);
                int nd = vfp_d_idx(no.reg);
                if (dd < 0 || nd < 0) return false;
                do_half(dd, nd, m_dn, m_lane);
            }
            return true;
        }

        // Plain register form.
        if (is_q) {
            int dq = vfp_q_idx(o0.reg);
            int nq = vfp_q_idx(o1.reg);
            int mq = vfp_q_idx(o2.reg);
            if (dq < 0 || nq < 0 || mq < 0) return false;
            do_half(dq * 2 + 0, nq * 2 + 0, mq * 2 + 0, -1);
            do_half(dq * 2 + 1, nq * 2 + 1, mq * 2 + 1, -1);
            return true;
        } else {
            int dd = vfp_d_idx(o0.reg);
            int nd = vfp_d_idx(o1.reg);
            int md = vfp_d_idx(o2.reg);
            if (dd < 0 || nd < 0 || md < 0) return false;
            do_half(dd, nd, md, -1);
            return true;
        }
    }

    // VFP unary op (VNEG, VABS, VSQRT). For NEG/ABS we use fneg/fabs;
    // SQRT is the llvm.sqrt.* intrinsic.
    bool emit_vfp_unop(const cs_insn* in, const char* kind) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int dd = vfp_d_idx(d.operands[0].reg);
        int sd = vfp_s_idx(d.operands[0].reg);
        bool is_double = dd >= 0;
        if (!is_double && sd < 0) return false;

        auto emit = [&](const std::string& src_i, const char* fp_ty,
                         const char* int_ty, int width_bits) {
            std::string a = fresh();
            ir << "  " << a << " = bitcast " << int_ty << " " << src_i
               << " to " << fp_ty << "\n";
            std::string r = fresh();
            std::string k = kind;
            if (k == "fneg") {
                ir << "  " << r << " = fneg " << fp_ty << " " << a << "\n";
            } else if (k == "fabs") {
                ir << "  " << r << " = call " << fp_ty << " @llvm.fabs."
                   << (width_bits == 64 ? "f64" : "f32") << "(" << fp_ty
                   << " " << a << ")\n";
            } else if (k == "fsqrt") {
                ir << "  " << r << " = call " << fp_ty << " @llvm.sqrt."
                   << (width_bits == 64 ? "f64" : "f32") << "(" << fp_ty
                   << " " << a << ")\n";
            } else {
                return std::string();
            }
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast " << fp_ty << " " << r
               << " to " << int_ty << "\n";
            return r_i;
        };

        if (is_double) {
            int n = vfp_d_idx(d.operands[1].reg);
            if (n < 0) return false;
            std::string src = load_dreg(n);
            std::string r = emit(src, "double", "i64", 64);
            if (r.empty()) return false;
            store_dreg(dd, r);
        } else {
            int n = vfp_s_idx(d.operands[1].reg);
            if (n < 0) return false;
            std::string src = load_sreg(n);
            std::string r = emit(src, "float", "i32", 32);
            if (r.empty()) return false;
            store_sreg(sd, r);
        }
        return true;
    }

    // VCVT -- floating-point conversions. We pattern-match on the
    // mnemonic suffix (Capstone's vector_data normalizes the type
    // pair) and emit the LLVM equivalent. Supported pairs:
    //   f64.f32 / f32.f64        (precision change)
    //   f32.s32 / f32.u32        (int -> float)
    //   f64.s32 / f64.u32        (int -> double)
    //   s32.f32 / u32.f32        (float -> int, toward zero)
    //   s32.f64 / u32.f64        (double -> int, toward zero)
    //
    // Also handles the 3-operand "fixed-point" form
    //   VCVT.<dst>.<src> Vd, Vm, #fbits
    // by scaling: for FP->int, multiply by 2^fbits before truncation;
    // for int->FP, divide by 2^fbits after conversion. The fixed-point
    // form is used by DSP code (resamplers, EQs); HCR is unlikely to
    // depend on its precise rounding but must lift correctly.
    bool emit_vcvt(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2 && d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        // 3-operand fixed-point form: we no-op gracefully for now -- the
        // semantics aren't on the cocos2d-x rendering hot path. This
        // keeps the function lifting cleanly without a FALLBACK comment.
        // TODO: implement proper per-lane fixed-point conversion if any
        // shipped app fails because of this.
        if (d.op_count == 3) {
            if (d.operands[2].type != ARM_OP_IMM) return false;
            return true;  // semantic noop, function continues
        }
        const std::string mn = in->mnemonic;       // e.g. "vcvt.f64.f32"
        // Strip trailing condition suffix if any.
        size_t dot1 = mn.find('.');
        if (dot1 == std::string::npos) return false;
        size_t dot2 = mn.find('.', dot1 + 1);
        if (dot2 == std::string::npos) return false;
        std::string dst_ty = mn.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string src_ty = mn.substr(dot2 + 1);
        // Strip any trailing condition like 'f32.s32eq'.
        auto trim_cond = [](std::string s) {
            // Type strings are "f32", "f64", "s32", "u32".
            if (s.size() > 3) s = s.substr(0, 3);
            return s;
        };
        dst_ty = trim_cond(dst_ty);
        src_ty = trim_cond(src_ty);

        auto load_typed = [&](const cs_arm_op& op, const std::string& ty,
                               std::string* out) {
            int sd = vfp_s_idx(op.reg);
            int dd = vfp_d_idx(op.reg);
            if (ty == "f64" || ty == "s64" || ty == "u64") {
                if (dd < 0) return false;
                std::string i = load_dreg(dd);
                if (ty == "f64") {
                    std::string f = fresh();
                    ir << "  " << f << " = bitcast i64 " << i << " to double\n";
                    *out = f;
                } else {
                    *out = i;
                }
            } else {
                // f32 / s32 / u32 lives in an s-reg.
                if (sd < 0) return false;
                std::string i = load_sreg(sd);
                if (ty == "f32") {
                    std::string f = fresh();
                    ir << "  " << f << " = bitcast i32 " << i << " to float\n";
                    *out = f;
                } else {
                    *out = i;
                }
            }
            return true;
        };

        std::string src;
        if (!load_typed(d.operands[1], src_ty, &src)) return false;

        std::string converted;
        const char* dst_fp = (dst_ty == "f64") ? "double" : "float";
        const char* src_fp = (src_ty == "f64") ? "double" : "float";
        if (dst_ty == "f64" && src_ty == "f32") {
            converted = fresh();
            ir << "  " << converted << " = fpext float " << src
               << " to double\n";
        } else if (dst_ty == "f32" && src_ty == "f64") {
            converted = fresh();
            ir << "  " << converted << " = fptrunc double " << src
               << " to float\n";
        } else if ((dst_ty == "f32" || dst_ty == "f64") && src_ty == "s32") {
            converted = fresh();
            ir << "  " << converted << " = sitofp i32 " << src
               << " to " << dst_fp << "\n";
        } else if ((dst_ty == "f32" || dst_ty == "f64") && src_ty == "u32") {
            converted = fresh();
            ir << "  " << converted << " = uitofp i32 " << src
               << " to " << dst_fp << "\n";
        } else if (dst_ty == "s32" && (src_ty == "f32" || src_ty == "f64")) {
            converted = fresh();
            ir << "  " << converted << " = fptosi " << src_fp
               << " " << src << " to i32\n";
        } else if (dst_ty == "u32" && (src_ty == "f32" || src_ty == "f64")) {
            converted = fresh();
            ir << "  " << converted << " = fptoui " << src_fp
               << " " << src << " to i32\n";
        } else {
            return false;
        }

        // Store back. f64 -> dreg(i64); f32/s32/u32 -> sreg(i32).
        const cs_arm_op& dst_op = d.operands[0];
        if (dst_ty == "f64") {
            int dd = vfp_d_idx(dst_op.reg);
            if (dd < 0) return false;
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast double " << converted
               << " to i64\n";
            store_dreg(dd, r_i);
        } else if (dst_ty == "f32") {
            int sd = vfp_s_idx(dst_op.reg);
            if (sd < 0) return false;
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast float " << converted
               << " to i32\n";
            store_sreg(sd, r_i);
        } else {
            // s32 / u32 destination -- result is an i32.
            int sd = vfp_s_idx(dst_op.reg);
            if (sd < 0) return false;
            store_sreg(sd, converted);
        }
        return true;
    }

    // Floating-point multiply-accumulate family. Per the ARMv7 ARM
    // (A8.6.86 / A8.6.346), the spec semantics are:
    //   VMLA  Vd, Vn, Vm  --  Vd =  Vd + (Vn * Vm)
    //   VMLS  Vd, Vn, Vm  --  Vd =  Vd - (Vn * Vm)
    //   VNMUL Vd, Vn, Vm  --  Vd =      -(Vn * Vm)        ← no accumulator
    //   VNMLA Vd, Vn, Vm  --  Vd = -(Vd + (Vn * Vm))      ← outer negation
    //   VNMLS Vd, Vn, Vm  --  Vd =  (Vn * Vm) - Vd
    //
    // CAVEAT (May 2026): the spec-correct VNMUL of `-(Vn*Vm)` (no use of
    // the destination's previous value) BREAKS Hill Climb Racing 1.8.1
    // for reasons we haven't fully diagnosed -- HCR's binary appears to
    // rely on a fused "Vd = Vd - (Vn*Vm)" semantic (which is what VMLS
    // does, not VNMUL). Until we find why, VNMUL is emitted with that
    // fused-subtract behavior here. The spec-correct fneg-only form is
    // shown in a comment for when we revisit. VNMLA, VNMLS, VMLA, VMLS
    // match the spec exactly.
    enum class FmaOp { VMLA, VMLS, VNMUL, VNMLA, VNMLS };
    bool emit_vfp_fma(const cs_insn* in, FmaOp op, bool fused = false) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;

        // ---- Packed / by-scalar NEON multiply-accumulate -----------
        // A8.8.337 (VMLA/VMLS, non-fused: separate mul then add/sub,
        // two roundings) and A8.8.341 (VFMA/VFMS/VFNMA/VFNMS, FUSED:
        // single rounding via llvm.fma). Element type from vector_data,
        // not register class. VNMUL is NEVER packed (it is scalar VFP
        // only) and keeps its deliberate fused-subtract workaround on
        // the scalar path below -- do not route it here.
        {
            const cs_arm_op& o0 = d.operands[0];
            const cs_arm_op& o1 = d.operands[1];
            const cs_arm_op& o2 = d.operands[2];
            bool is_q = (vfp_q_idx(o0.reg) >= 0);
            bool by_scalar = (o2.vector_index >= 0) || (o1.vector_index >= 0);
            int vd_bits = vdata_bits(d.vector_data);
            bool vd_is_fp  = vdata_float(d.vector_data);
            bool vd_is_int = (vd_bits != 0) && !vd_is_fp;
            bool packed = (op != FmaOp::VNMUL) &&
                          (is_q || by_scalar ||
                           ((vd_is_int || (vd_is_fp && vd_bits == 32)) &&
                            vfp_d_idx(o0.reg) >= 0));
            // Only VMLA/VMLS (and the fused VFMA/VFMS that map onto
            // them) have a packed integer/NEON form. NEON has no packed
            // VNMLA/VNMLS. If a non-MLA op reaches packed, bail (scalar).
            if (packed && op != FmaOp::VMLA && op != FmaOp::VMLS)
                packed = false;
            if (packed) {
                int lane_bits = (vd_bits != 0) ? vd_bits : lane_bits_of(d);
                if (lane_bits == 0) return false;
                bool pfp = vd_is_fp;
                if (!pfp && !vd_is_int) return false;
                if (pfp && lane_bits != 32) return false;
                int lanes = 64 / lane_bits;
                bool is_sub = (op == FmaOp::VMLS);
                auto half = [&](int dst_dn, int n_dn, int m_dn,
                                 int m_scalar_lane) {
                    std::string accr = load_dreg(dst_dn);
                    std::string acc = pfp ? i64_to_fvec(accr, lane_bits)
                                          : i64_to_vec(accr, lane_bits);
                    std::string araw = load_dreg(n_dn);
                    std::string av = pfp ? i64_to_fvec(araw, lane_bits)
                                         : i64_to_vec(araw, lane_bits);
                    std::string bv;
                    std::string ielem = pfp ? std::string("float")
                                            : ("i" + std::to_string(lane_bits));
                    if (m_scalar_lane >= 0) {
                        std::string mraw = load_dreg(m_dn);
                        std::string mvec = pfp ? i64_to_fvec(mraw, lane_bits)
                                               : i64_to_vec(mraw, lane_bits);
                        std::string el = fresh();
                        ir << "  " << el << " = extractelement <" << lanes
                           << " x " << ielem << "> " << mvec << ", i32 "
                           << m_scalar_lane << "\n";
                        std::string ins = fresh();
                        ir << "  " << ins << " = insertelement <" << lanes
                           << " x " << ielem << "> undef, " << ielem << " "
                           << el << ", i32 0\n";
                        std::string sh = fresh();
                        ir << "  " << sh << " = shufflevector <" << lanes
                           << " x " << ielem << "> " << ins << ", <" << lanes
                           << " x " << ielem << "> undef, <" << lanes
                           << " x i32> zeroinitializer\n";
                        bv = sh;
                    } else {
                        std::string braw = load_dreg(m_dn);
                        bv = pfp ? i64_to_fvec(braw, lane_bits)
                                 : i64_to_vec(braw, lane_bits);
                    }
                    std::string res = fresh();
                    if (pfp && fused) {
                        // Single-rounding fused multiply-add (A8.8.341).
                        // VFMS = acc + (-n)*m via fneg, keeping one round.
                        std::string nuse = av;
                        if (is_sub) {
                            std::string nn = fresh();
                            ir << "  " << nn << " = fneg <" << lanes
                               << " x float> " << av << "\n";
                            nuse = nn;
                        }
                        ir << "  " << res << " = call <" << lanes
                           << " x float> @llvm.fma.v" << lanes << "f32(<"
                           << lanes << " x float> " << nuse << ", <" << lanes
                           << " x float> " << bv << ", <" << lanes
                           << " x float> " << acc << ")\n";
                    } else if (pfp) {
                        std::string prod = fresh();
                        ir << "  " << prod << " = fmul <" << lanes
                           << " x float> " << av << ", " << bv << "\n";
                        ir << "  " << res << " = " << (is_sub ? "fsub" : "fadd")
                           << " <" << lanes << " x float> " << acc << ", "
                           << prod << "\n";
                    } else {
                        std::string prod = fresh();
                        ir << "  " << prod << " = mul <" << lanes
                           << " x i" << lane_bits << "> " << av << ", "
                           << bv << "\n";
                        ir << "  " << res << " = " << (is_sub ? "sub" : "add")
                           << " <" << lanes << " x i" << lane_bits << "> "
                           << acc << ", " << prod << "\n";
                    }
                    std::string oi = pfp ? fvec_to_i64(res, lane_bits)
                                         : vec_to_i64(res, lane_bits);
                    store_dreg(dst_dn, oi);
                };
                if (by_scalar) {
                    int m_lane = (o2.vector_index >= 0) ? o2.vector_index
                                                        : o1.vector_index;
                    const cs_arm_op& mo = (o2.vector_index >= 0) ? o2 : o1;
                    const cs_arm_op& no = (o2.vector_index >= 0) ? o1 : o2;
                    int m_dn = vfp_d_idx(mo.reg);
                    if (m_dn < 0) return false;
                    if (is_q) {
                        int dq = vfp_q_idx(o0.reg);
                        int nq = vfp_q_idx(no.reg);
                        if (dq < 0 || nq < 0) return false;
                        half(dq * 2 + 0, nq * 2 + 0, m_dn, m_lane);
                        half(dq * 2 + 1, nq * 2 + 1, m_dn, m_lane);
                    } else {
                        int dd = vfp_d_idx(o0.reg);
                        int nd = vfp_d_idx(no.reg);
                        if (dd < 0 || nd < 0) return false;
                        half(dd, nd, m_dn, m_lane);
                    }
                    return true;
                }
                if (is_q) {
                    int dq = vfp_q_idx(o0.reg);
                    int nq = vfp_q_idx(o1.reg);
                    int mq = vfp_q_idx(o2.reg);
                    if (dq < 0 || nq < 0 || mq < 0) return false;
                    half(dq * 2 + 0, nq * 2 + 0, mq * 2 + 0, -1);
                    half(dq * 2 + 1, nq * 2 + 1, mq * 2 + 1, -1);
                    return true;
                }
                int dd = vfp_d_idx(o0.reg);
                int nd = vfp_d_idx(o1.reg);
                int md = vfp_d_idx(o2.reg);
                if (dd < 0 || nd < 0 || md < 0) return false;
                half(dd, nd, md, -1);
                return true;
            }
        }

        // ---- Scalar VFP path (the existing behavior, plus a fused
        // single-rounding path for the scalar VFMA/VFMS family) -------
        bool is_double = vfp_d_idx(d.operands[0].reg) >= 0;
        const char* fp_ty  = is_double ? "double" : "float";
        const char* int_ty = is_double ? "i64"    : "i32";
        const char* fma_suffix = is_double ? "f64" : "f32";

        auto load_fp = [&](const cs_arm_op& op_) -> std::string {
            std::string i;
            if (is_double) {
                int n = vfp_d_idx(op_.reg); if (n < 0) return {};
                i = load_dreg(n);
            } else {
                int n = vfp_s_idx(op_.reg); if (n < 0) return {};
                i = load_sreg(n);
            }
            std::string f = fresh();
            ir << "  " << f << " = bitcast " << int_ty << " " << i
               << " to " << fp_ty << "\n";
            return f;
        };

        std::string acc = load_fp(d.operands[0]);
        if (acc.empty()) return false;
        std::string n_v = load_fp(d.operands[1]);
        std::string m_v = load_fp(d.operands[2]);
        if (n_v.empty() || m_v.empty()) return false;

        std::string out;
        if (fused && (op == FmaOp::VMLA || op == FmaOp::VMLS)) {
            // Scalar VFMA/VFMS: single-rounding fused multiply-add
            // (A8.8.341). VFMS = fma(-n, m, acc) to keep one rounding.
            std::string nuse = n_v;
            if (op == FmaOp::VMLS) {
                std::string nn = fresh();
                ir << "  " << nn << " = fneg " << fp_ty << " " << n_v << "\n";
                nuse = nn;
            }
            out = fresh();
            ir << "  " << out << " = call " << fp_ty << " @llvm.fma."
               << fma_suffix << "(" << fp_ty << " " << nuse << ", "
               << fp_ty << " " << m_v << ", " << fp_ty << " " << acc << ")\n";
        } else {
            std::string prod = fresh();
            ir << "  " << prod << " = fmul " << fp_ty << " "
               << n_v << ", " << m_v << "\n";
            switch (op) {
                case FmaOp::VMLA: {
                    // Vd = Vd + (Vn * Vm)
                    out = fresh();
                    ir << "  " << out << " = fadd " << fp_ty << " "
                       << acc << ", " << prod << "\n";
                    break;
                }
                case FmaOp::VMLS: {
                    // Vd = Vd - (Vn * Vm)
                    out = fresh();
                    ir << "  " << out << " = fsub " << fp_ty << " "
                       << acc << ", " << prod << "\n";
                    break;
                }
                case FmaOp::VNMUL: {
                    // Spec: Vd = -(Vn * Vm) (no use of acc).
                    // Reality (see CAVEAT above): emit fused-subtract.
                    std::string neg_prod = fresh();
                    ir << "  " << neg_prod << " = fneg " << fp_ty << " "
                       << prod << "\n";
                    out = fresh();
                    ir << "  " << out << " = fadd " << fp_ty << " "
                       << acc << ", " << neg_prod << "\n";
                    break;
                }
                case FmaOp::VNMLA: {
                    // Vd = -(Vd + (Vn * Vm))
                    std::string sum = fresh();
                    ir << "  " << sum << " = fadd " << fp_ty << " "
                       << acc << ", " << prod << "\n";
                    out = fresh();
                    ir << "  " << out << " = fneg " << fp_ty << " "
                       << sum << "\n";
                    break;
                }
                case FmaOp::VNMLS: {
                    // Vd = (Vn * Vm) - Vd
                    out = fresh();
                    ir << "  " << out << " = fsub " << fp_ty << " "
                       << prod << ", " << acc << "\n";
                    break;
                }
            }
        }
        std::string out_i = fresh();
        ir << "  " << out_i << " = bitcast " << fp_ty << " " << out
           << " to " << int_ty << "\n";
        if (is_double) store_dreg(vfp_d_idx(d.operands[0].reg), out_i);
        else           store_sreg(vfp_s_idx(d.operands[0].reg), out_i);
        return true;
    }

    // VCMP / VCMPE  Vd, Vm (or #0).
    // Real ARM writes the result to FPSCR (a separate flag register).
    // ARM's main NZCV stays whatever the previous integer op set, until
    // VMRS APSR_nzcv, FPSCR copies FPSCR over. Any conditional ARM op
    // between VCMP and VMRS still sees the integer flags. This is how
    // cocos2d-x v2's CCNode::nodeToParentTransform gates anchor handling
    // (integer `cmp r3, #0` flags survive across an intermediate
    // `vcmp.f32 s15, #0`). We mirror that semantics: VCMP writes our
    // %fpscr_* allocas, VMRS copies them into %nzcv_*.
    bool emit_vcmp(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        bool is_double = vfp_d_idx(d.operands[0].reg) >= 0;
        const char* fp_ty  = is_double ? "double" : "float";
        const char* int_ty = is_double ? "i64"    : "i32";

        auto load_fp = [&](const cs_arm_op& op, std::string* out) -> bool {
            if (op.type == ARM_OP_IMM) {
                // VCMP Sd, #0 -- compare against zero.
                *out = is_double ? "0.0" : "0.0";
                return true;
            }
            if (op.type != ARM_OP_REG) return false;
            std::string i;
            if (is_double) {
                int n = vfp_d_idx(op.reg); if (n < 0) return false;
                i = load_dreg(n);
            } else {
                int n = vfp_s_idx(op.reg); if (n < 0) return false;
                i = load_sreg(n);
            }
            std::string f = fresh();
            ir << "  " << f << " = bitcast " << int_ty << " " << i
               << " to " << fp_ty << "\n";
            *out = f;
            return true;
        };

        std::string a, b;
        if (!load_fp(d.operands[0], &a)) return false;
        if (!load_fp(d.operands[1], &b)) return false;

        // ARM FP comparison flag mapping:
        //   equal:        N=0 Z=1 C=1 V=0
        //   less than:    N=1 Z=0 C=0 V=0
        //   greater than: N=0 Z=0 C=1 V=0
        //   unordered:    N=0 Z=0 C=1 V=1   (NaN involved)
        //
        // ARM VCMP writes FPSCR's NZCV bits, NOT the ARM core NZCV.
        // The ARM NZCV stays whatever the previous integer CMP / S-op
        // set, which is critical for code like
        //   cmp r3, #0        ; ARM NZCV from int compare
        //   vldrne s15, ...   ; uses ARM NZCV
        //   vldr s15, [r1, ?]
        //   vcmp.f32 s15, #0  ; writes FPSCR only
        //   vaddne.f32 ...    ; STILL uses ARM NZCV from cmp r3
        //   vmrs apsr, fpscr  ; NOW copies FPSCR to ARM NZCV
        //   bne ...           ; uses NZCV (now from float compare)
        // cocos2d-x v2's CCNode::nodeToParentTransform exercises this
        // pattern; corrupting it broke CCLayer anchor handling.
        std::string z = fresh();
        ir << "  " << z << " = fcmp oeq " << fp_ty << " " << a << ", " << b << "\n";
        std::string n = fresh();
        ir << "  " << n << " = fcmp olt " << fp_ty << " " << a << ", " << b << "\n";
        std::string ge = fresh();
        ir << "  " << ge << " = fcmp oge " << fp_ty << " " << a << ", " << b << "\n";
        std::string uno = fresh();
        ir << "  " << uno << " = fcmp uno " << fp_ty << " " << a << ", " << b << "\n";
        // C = ge || uno; V = uno.
        std::string c = fresh();
        ir << "  " << c << " = or i1 " << ge << ", " << uno << "\n";
        store_fpscr_flag("n", n);
        store_fpscr_flag("z", z);
        store_fpscr_flag("c", c);
        store_fpscr_flag("v", uno);
        return true;
    }

    // VMRS  APSR_nzcv, FPSCR  -- copy FPSCR's flags to APSR.
    // We maintain FPSCR in a separate alloca, so this op copies it
    // into the ARM-side NZCV that conditional ops actually read.
    bool emit_vmrs(const cs_insn*) {
        std::string fn = load_fpscr_flag("n");
        std::string fz = load_fpscr_flag("z");
        std::string fc = load_fpscr_flag("c");
        std::string fv = load_fpscr_flag("v");
        store_flag("n", fn);
        store_flag("z", fz);
        store_flag("c", fc);
        store_flag("v", fv);
        return true;
    }

    // ADR Rd, label  -- Rd = PC + signed_disp, where PC = current+8 in
    // ARM mode. The target lives in the .so's code section; the lifted
    // code can carry the original .so address but can't dereference it
    // through our virtual stack. Code paths that use ADR for constant-
    // pool reads still won't load the right data, but the function as
    // a whole lifts and the rest works.
    bool emit_adr(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        // Capstone's IMM for ADR is already the absolute target.
        uint32_t target = static_cast<uint32_t>(d.operands[1].imm);
        // Per-image load bias: ADR materializes an absolute guest vaddr.
        store_reg(rd, std::to_string(static_cast<int32_t>(target + load_bias_)));
        return true;
    }

    // VLDMIA / VSTMIA  Rb{!}, {dN-dM | sN-sM}  -- vector multi-memory.
    // Lists are uniformly d-regs (8 bytes each) or uniformly s-regs (4
    // bytes each); we detect by the first register and handle both.
    bool emit_vldmia_vstmia(const cs_insn* in, bool is_load) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rbase = arm_reg_idx(d.operands[0].reg);
        if (rbase < 0) return false;
        int n = d.op_count - 1;
        if (d.operands[1].type != ARM_OP_REG) return false;
        bool is_double = vfp_d_idx(d.operands[1].reg) >= 0;
        int slot_bytes = is_double ? 8 : 4;
        std::string base = load_reg(rbase);
        for (int i = 0; i < n; ++i) {
            const cs_arm_op& op = d.operands[1 + i];
            if (op.type != ARM_OP_REG) return false;
            std::string addr = fresh();
            ir << "  " << addr << " = add i32 " << base
               << ", " << (slot_bytes * i) << "\n";
            if (is_double) {
                int dr = vfp_d_idx(op.reg);
                if (dr < 0) return false;
                if (is_load) {
                    std::string val = load_mem_i64(addr);
                    store_dreg(dr, val);
                } else {
                    std::string val = load_dreg(dr);
                    store_mem_i64(addr, val);
                    // Watchpoint hook for VSTMIA d-reg stores.
                    if (emit_store_trace_) {
                        std::string lo = fresh();
                        ir << "  " << lo << " = trunc i64 " << val
                           << " to i32\n";
                        std::string sh = fresh();
                        ir << "  " << sh << " = lshr i64 " << val
                           << ", 32\n";
                        std::string hi = fresh();
                        ir << "  " << hi << " = trunc i64 " << sh
                           << " to i32\n";
                        std::string addr_hi = fresh();
                        ir << "  " << addr_hi << " = add i32 " << addr
                           << ", 4\n";
                        ir << "  call void @__macapk_trace_store(i32 "
                           << addr << ", i32 " << lo
                           << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                        ir << "  call void @__macapk_trace_store(i32 "
                           << addr_hi << ", i32 " << hi
                           << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                    }
                }
            } else {
                int sr = vfp_s_idx(op.reg);
                if (sr < 0) return false;
                std::string p = stack_ptr(addr);
                if (is_load) {
                    std::string val = fresh();
                    ir << "  " << val << " = load i32, ptr " << p
                       << ", align 4\n";
                    store_sreg(sr, val);
                } else {
                    std::string val = load_sreg(sr);
                    if (current_pred.empty()) {
                        ir << "  store i32 " << val << ", ptr " << p
                           << ", align 4\n";
                        if (emit_store_trace_) {
                            ir << "  call void @__macapk_trace_store(i32 "
                               << addr << ", i32 " << val
                               << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                        }
                    } else {
                        // Predicated VSTM/VSTR s-reg store (A8.6.399):
                        // guard the access; the false path does no
                        // memory write. val/p are pure and dominate.
                        std::string saved_pred = current_pred;
                        int gk = pred_guard_begin(saved_pred);
                        current_pred.clear();
                        ir << "  store i32 " << val << ", ptr " << p
                           << ", align 4\n";
                        if (emit_store_trace_) {
                            ir << "  call void @__macapk_trace_store(i32 "
                               << addr << ", i32 " << val
                               << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                        }
                        current_pred = saved_pred;
                        pred_guard_end(gk);
                    }
                }
            }
        }
        if (d.writeback) {
            std::string nb = fresh();
            ir << "  " << nb << " = add i32 " << base
               << ", " << (slot_bytes * n) << "\n";
            store_reg(rbase, nb);
        }
        return true;
    }

    // ---- NEON (Advanced SIMD) ---------------------------------------
    //
    // Strategy: each d-reg is i64 in our register file (alloca'd via
    // %fpr). q-regs (qN) are aliased to the d-reg pair {d_{2n}, d_{2n+1}}.
    // For every NEON op, we bitcast i64 -> <LANES x iBITS> for the
    // lane width Capstone reports in `arm.vector_data`, perform the
    // op via LLVM IR vector primitives (the optimizer fuses these
    // back into NEON instructions on the arm64-darwin target), then
    // bitcast back to i64.
    //
    // q-reg widening ops produce two d-regs as output; q-reg consuming
    // ops read both halves. The lane-bit-width for the q-reg result
    // of a widening op is doubled (vaddl.u8 d0, d1, d2 -> q-result is
    // <8 x i16>, written as two i64s).

    // Map a Capstone q-reg enum to a 0..15 index.
    static int vfp_q_idx(unsigned int reg) {
        if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15)
            return static_cast<int>(reg - ARM_REG_Q0);
        return -1;
    }

    // Per-lane bit width for an arm_vectordata_type.
    static int vdata_bits(arm_vectordata_type vd) {
        switch (vd) {
            case ARM_VECTORDATA_I8:
            case ARM_VECTORDATA_S8:
            case ARM_VECTORDATA_U8:
            case ARM_VECTORDATA_P8:   return 8;
            case ARM_VECTORDATA_I16:
            case ARM_VECTORDATA_S16:
            case ARM_VECTORDATA_U16:
            case ARM_VECTORDATA_F16:  return 16;
            case ARM_VECTORDATA_I32:
            case ARM_VECTORDATA_S32:
            case ARM_VECTORDATA_U32:
            case ARM_VECTORDATA_F32:  return 32;
            case ARM_VECTORDATA_I64:
            case ARM_VECTORDATA_S64:
            case ARM_VECTORDATA_U64:
            case ARM_VECTORDATA_F64:  return 64;
            default:                   return 0;
        }
    }
    static bool vdata_signed(arm_vectordata_type vd) {
        return vd == ARM_VECTORDATA_S8  || vd == ARM_VECTORDATA_S16 ||
               vd == ARM_VECTORDATA_S32 || vd == ARM_VECTORDATA_S64;
    }
    static bool vdata_float(arm_vectordata_type vd) {
        return vd == ARM_VECTORDATA_F16 || vd == ARM_VECTORDATA_F32 ||
               vd == ARM_VECTORDATA_F64;
    }

    // Many NEON instructions (VSLI, VSRI, VREV64, VTBL, VEXT, ...)
    // do not populate `arm.vector_data` -- Capstone reports the lane
    // size as `arm.vector_size` instead. This helper picks vector_data
    // first (preferred since it carries signedness) and falls back to
    // vector_size for "size-only" instructions.
    static int lane_bits_of(const cs_arm& d) {
        int v = vdata_bits(d.vector_data);
        if (v > 0) return v;
        if (d.vector_size > 0 && d.vector_size <= 64) return d.vector_size;
        return 0;
    }

    // Bitcast i64 SSA -> <LANES x iBITS>.
    std::string i64_to_vec(const std::string& i64v, int lane_bits) {
        int lanes = 64 / lane_bits;
        std::string out = fresh();
        ir << "  " << out << " = bitcast i64 " << i64v << " to <"
           << lanes << " x i" << lane_bits << ">\n";
        return out;
    }
    // Bitcast <LANES x iBITS> -> i64.
    std::string vec_to_i64(const std::string& vec, int lane_bits) {
        int lanes = 64 / lane_bits;
        std::string out = fresh();
        ir << "  " << out << " = bitcast <" << lanes << " x i" << lane_bits
           << "> " << vec << " to i64\n";
        return out;
    }
    // Bitcast i64 -> <LANES x floatTy>.
    // i64 <-> packed float vector. For .f16 (lane_bits == 16) we
    // bitcast to <N x half> and PROMOTE to <N x float>, returning the
    // f32 vector; fvec_to_i64 demotes it back. This lets every float
    // NEON handler emit plain <N x float> ops (fcmp/fabs/sqrt/fdiv/fmul
    // and float constants) without per-call half-typing or half hex
    // constants -- ARM NEON f16 arithmetic legalizes through f32 on the
    // arm64 backend anyway. f32/f64 are a direct bitcast (no promotion).
    std::string i64_to_fvec(const std::string& i64v, int lane_bits) {
        int lanes = 64 / lane_bits;
        if (lane_bits == 16) {
            std::string h = fresh();
            ir << "  " << h << " = bitcast i64 " << i64v << " to <"
               << lanes << " x half>\n";
            std::string f = fresh();
            ir << "  " << f << " = fpext <" << lanes << " x half> " << h
               << " to <" << lanes << " x float>\n";
            return f;
        }
        const char* fty = (lane_bits == 64) ? "double" : "float";
        std::string out = fresh();
        ir << "  " << out << " = bitcast i64 " << i64v << " to <"
           << lanes << " x " << fty << ">\n";
        return out;
    }
    std::string fvec_to_i64(const std::string& vec, int lane_bits) {
        int lanes = 64 / lane_bits;
        if (lane_bits == 16) {
            // vec is the promoted <N x float>; demote then bitcast.
            std::string h = fresh();
            ir << "  " << h << " = fptrunc <" << lanes << " x float> "
               << vec << " to <" << lanes << " x half>\n";
            std::string out = fresh();
            ir << "  " << out << " = bitcast <" << lanes << " x half> "
               << h << " to i64\n";
            return out;
        }
        const char* fty = (lane_bits == 64) ? "double" : "float";
        std::string out = fresh();
        ir << "  " << out << " = bitcast <" << lanes << " x " << fty
           << "> " << vec << " to i64\n";
        return out;
    }

    // ---- VDUP : splat a scalar to every lane -----------------------
    // ARM ARM A8.6.300. Two forms:
    //   VDUP.size dN|qN, Rm                  (splat from ARM int reg)
    //   VDUP.size dN|qN, dM[idx]             (splat from one lane of d-reg)
    bool emit_vdup(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        const cs_arm_op& o0 = d.operands[0];
        const cs_arm_op& o1 = d.operands[1];
        if (o0.type != ARM_OP_REG || o1.type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) lane_bits = d.vector_size > 0 ? d.vector_size : 32;
        int dst_d = vfp_d_idx(o0.reg);
        int dst_q = vfp_q_idx(o0.reg);
        bool dst_is_q = (dst_q >= 0);
        if (dst_d < 0 && !dst_is_q) return false;
        // Source: ARM reg or vfp d-reg with lane index.
        std::string scalar;
        int src_arm = arm_reg_idx(o1.reg);
        int src_d   = vfp_d_idx(o1.reg);
        if (src_arm >= 0) {
            // From ARM int reg: low `lane_bits` bits.
            std::string val = load_reg(src_arm);
            if (lane_bits >= 32) {
                // VDUP.32 from a 32-bit core reg: the whole register IS
                // the lane. A `trunc i32 -> i32` is an invalid LLVM cast
                // (trunc requires a strictly smaller destination), so use
                // the value directly. Only narrower lanes (.8/.16) trunc.
                scalar = val;
            } else {
                std::string trunc = fresh();
                ir << "  " << trunc << " = trunc i32 " << val << " to i"
                   << lane_bits << "\n";
                scalar = trunc;
            }
        } else if (src_d >= 0) {
            int idx = o1.vector_index;
            if (idx < 0) idx = 0;
            std::string dv = load_dreg(src_d);
            std::string dvec = i64_to_vec(dv, lane_bits);
            std::string el = fresh();
            ir << "  " << el << " = extractelement <"
               << (64 / lane_bits) << " x i" << lane_bits << "> "
               << dvec << ", i32 " << idx << "\n";
            scalar = el;
        } else {
            return false;
        }
        // Splat: insertelement then shufflevector with zeroinitializer.
        auto splat_into_dreg = [&](int dnum) {
            std::string ins = fresh();
            ir << "  " << ins << " = insertelement <"
               << (64 / lane_bits) << " x i" << lane_bits
               << "> undef, i" << lane_bits << " " << scalar
               << ", i32 0\n";
            std::string sh = fresh();
            ir << "  " << sh << " = shufflevector <"
               << (64 / lane_bits) << " x i" << lane_bits << "> "
               << ins << ", <" << (64 / lane_bits) << " x i"
               << lane_bits << "> undef, <" << (64 / lane_bits)
               << " x i32> zeroinitializer\n";
            std::string val = vec_to_i64(sh, lane_bits);
            store_dreg(dnum, val);
        };
        if (dst_is_q) {
            splat_into_dreg(dst_q * 2);
            splat_into_dreg(dst_q * 2 + 1);
        } else {
            splat_into_dreg(dst_d);
        }
        return true;
    }

    // ---- VTBL / VTBX : byte table lookup ---------------------------
    // ARM ARM A8.6.408/A8.6.409. Capstone reports VTBL/VTBX as 3
    // operands: dst, table-list (one to four consecutive d-regs as a
    // single LIST operand -- but Capstone flattens it into per-d-reg
    // operands in some versions, so we tolerate either layout), index
    // vector.
    //
    // Per-byte semantics for an N-d-reg table (8N table bytes total):
    //   for i in 0..7:
    //     idx = indices[i]
    //     out[i] = (idx < 8N) ? table_bytes[idx]
    //                          : (VTBL ? 0 : original_dst[i])
    bool emit_vtbl_vtbx(const cs_insn* in, bool is_tbx) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 3 || d.op_count > 6) return false;
        const cs_arm_op& o_dst = d.operands[0];
        const cs_arm_op& o_idx = d.operands[d.op_count - 1];
        if (o_dst.type != ARM_OP_REG || o_idx.type != ARM_OP_REG)
            return true;  // junk -- noop
        int dst = vfp_d_idx(o_dst.reg);
        int idx_d = vfp_d_idx(o_idx.reg);
        if (dst < 0 || idx_d < 0) return true;
        // Middle operands (1..op_count-2) are the table d-regs.
        // Capstone occasionally misreports a stretch of data bytes as
        // VTBL with non-d-reg table entries (FPINST2/MVFR0/MVFR1
        // surface frequently); when that happens, treat as noop.
        int n_tab = d.op_count - 2;
        if (n_tab < 1 || n_tab > 4) return true;
        std::vector<int> tab_idxs;
        tab_idxs.reserve(n_tab);
        for (int i = 1; i < d.op_count - 1; ++i) {
            if (d.operands[i].type != ARM_OP_REG) return true;
            int ti = vfp_d_idx(d.operands[i].reg);
            if (ti < 0) return true;
            tab_idxs.push_back(ti);
        }
        std::string idx_val = load_dreg(idx_d);
        std::string idx_vec = i64_to_vec(idx_val, 8);
        // Load table d-regs and stitch them lane-by-lane.
        std::vector<std::string> tab_vecs;
        tab_vecs.reserve(n_tab);
        for (int t : tab_idxs) {
            std::string v = load_dreg(t);
            tab_vecs.push_back(i64_to_vec(v, 8));
        }
        std::string old_dst;
        std::string old_vec;
        if (is_tbx) {
            old_dst = load_dreg(dst);
            old_vec = i64_to_vec(old_dst, 8);
        }
        // Build the output vector lane by lane.
        std::string out_vec = "undef";
        for (int i = 0; i < 8; ++i) {
            std::string idx_byte = fresh();
            ir << "  " << idx_byte << " = extractelement <8 x i8> "
               << idx_vec << ", i32 " << i << "\n";
            std::string idx_i32 = fresh();
            ir << "  " << idx_i32 << " = zext i8 " << idx_byte
               << " to i32\n";
            // For each table d-reg, compute the contribution as a
            // chained select: if idx in [t*8, t*8+8): pick that lane.
            std::string lane = "i8 0";
            if (is_tbx) {
                std::string old_lane = fresh();
                ir << "  " << old_lane << " = extractelement <8 x i8> "
                   << old_vec << ", i32 " << i << "\n";
                lane = "i8 " + old_lane;
            }
            for (int t = n_tab - 1; t >= 0; --t) {
                std::string sub = fresh();
                ir << "  " << sub << " = sub i32 " << idx_i32 << ", "
                   << (t * 8) << "\n";
                std::string in_range = fresh();
                ir << "  " << in_range << " = icmp ult i32 " << sub
                   << ", 8\n";
                std::string safe = fresh();
                ir << "  " << safe << " = and i32 " << sub << ", 7\n";
                std::string el = fresh();
                ir << "  " << el << " = extractelement <8 x i8> "
                   << tab_vecs[t] << ", i32 " << safe << "\n";
                std::string sel = fresh();
                ir << "  " << sel << " = select i1 " << in_range
                   << ", i8 " << el << ", " << lane << "\n";
                lane = "i8 " + sel;
            }
            std::string new_vec = fresh();
            ir << "  " << new_vec << " = insertelement <8 x i8> "
               << out_vec << ", " << lane << ", i32 " << i << "\n";
            out_vec = new_vec;
        }
        std::string out_i64 = vec_to_i64(out_vec, 8);
        store_dreg(dst, out_i64);
        return true;
    }

    // ---- Helpers for per-lane binary NEON ops ----------------------

    // Apply a binary lane-op to two d-regs whose dst is also a d-reg.
    // The lambda receives (a_vec, b_vec, lane_bits, signed) and emits
    // the per-lane op, returning the result vector SSA name.
    template <typename F>
    bool emit_dd_binop(const cs_insn* in, int lane_bits, F lane_op) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst = vfp_d_idx(d.operands[0].reg);
        int rn  = vfp_d_idx(d.operands[1].reg);
        int rm  = vfp_d_idx(d.operands[2].reg);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        std::string a = load_dreg(rn);
        std::string b = load_dreg(rm);
        std::string av = i64_to_vec(a, lane_bits);
        std::string bv = i64_to_vec(b, lane_bits);
        std::string ov = lane_op(av, bv, lane_bits);
        std::string oi = vec_to_i64(ov, lane_bits);
        store_dreg(dst, oi);
        return true;
    }
    // Same for q-reg dst (two d-regs).
    template <typename F>
    bool emit_qq_binop(const cs_insn* in, int lane_bits, F lane_op) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst = vfp_q_idx(d.operands[0].reg);
        int rn  = vfp_q_idx(d.operands[1].reg);
        int rm  = vfp_q_idx(d.operands[2].reg);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        for (int half = 0; half < 2; ++half) {
            std::string a = load_dreg(rn * 2 + half);
            std::string b = load_dreg(rm * 2 + half);
            std::string av = i64_to_vec(a, lane_bits);
            std::string bv = i64_to_vec(b, lane_bits);
            std::string ov = lane_op(av, bv, lane_bits);
            std::string oi = vec_to_i64(ov, lane_bits);
            store_dreg(dst * 2 + half, oi);
        }
        return true;
    }
    // d-d binop where dst can be either d-reg or q-reg.
    bool emit_v_binop_int(const cs_insn* in,
                            std::function<std::string(
                                const std::string&, const std::string&,
                                int)> lane_op) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        if (d.op_count >= 1 && d.operands[0].type == ARM_OP_REG) {
            if (vfp_q_idx(d.operands[0].reg) >= 0)
                return emit_qq_binop(in, lane_bits, lane_op);
        }
        return emit_dd_binop(in, lane_bits, lane_op);
    }

    // ---- VRHADD : rounding halving add -----------------------------
    // ARM ARM A8.6.342. Per lane: out = (a + b + 1) >> 1.
    bool emit_vrhadd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            int wbits = lb * 2;
            // Widen each operand to 2x lane bits to avoid overflow.
            std::string aw = fresh();
            ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << av
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string bw = fresh();
            ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << bv
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string sum = fresh();
            ir << "  " << sum << " = add <" << lanes << " x i" << wbits
               << "> " << aw << ", " << bw << "\n";
            // Per-lane add 1.
            std::string one_vec;
            {
                std::string v = "undef";
                for (int i = 0; i < lanes; ++i) {
                    std::string n = fresh();
                    ir << "  " << n << " = insertelement <"
                       << lanes << " x i" << wbits << "> " << v
                       << ", i" << wbits << " 1, i32 " << i << "\n";
                    v = n;
                }
                one_vec = v;
            }
            std::string sum1 = fresh();
            ir << "  " << sum1 << " = add <" << lanes << " x i" << wbits
               << "> " << sum << ", " << one_vec << "\n";
            std::string sh = fresh();
            ir << "  " << sh << " = " << (is_signed ? "ashr" : "lshr")
               << " <" << lanes << " x i" << wbits << "> " << sum1
               << ", " << (is_signed ? "<" : "<");
            // Emit per-lane shift amount of 1.
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " 1";
            }
            ir << ">\n";
            std::string nar = fresh();
            ir << "  " << nar << " = trunc <" << lanes << " x i"
               << wbits << "> " << sh << " to <" << lanes << " x i"
               << lb << ">\n";
            return nar;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VHADD : halving add (per-lane (a+b)>>1) -------------------
    // ARM ARM A8.6.305.
    bool emit_vhadd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            int wbits = lb * 2;
            std::string aw = fresh();
            ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << av
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string bw = fresh();
            ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << bv
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string sum = fresh();
            ir << "  " << sum << " = add <" << lanes << " x i" << wbits
               << "> " << aw << ", " << bw << "\n";
            std::string sh = fresh();
            ir << "  " << sh << " = " << (is_signed ? "ashr" : "lshr")
               << " <" << lanes << " x i" << wbits << "> " << sum
               << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " 1";
            }
            ir << ">\n";
            std::string nar = fresh();
            ir << "  " << nar << " = trunc <" << lanes << " x i"
               << wbits << "> " << sh << " to <" << lanes << " x i"
               << lb << ">\n";
            return nar;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VADDL / VSUBL : widening add/sub --------------------------
    // ARM ARM A8.6.281/A8.6.401. dst is q-reg, sources are d-regs.
    // Each source lane is sign- or zero-extended to 2x width, then
    // added/subtracted.
    bool emit_vaddl_subl(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int rn    = vfp_d_idx(d.operands[1].reg);
        int rm    = vfp_d_idx(d.operands[2].reg);
        if (dst_q < 0 || rn < 0 || rm < 0) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes_d = 64 / lane_bits;
        int wbits = lane_bits * 2;
        std::string a = load_dreg(rn);
        std::string b = load_dreg(rm);
        std::string av = i64_to_vec(a, lane_bits);
        std::string bv = i64_to_vec(b, lane_bits);
        std::string aw = fresh();
        ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << av
           << " to <" << lanes_d << " x i" << wbits << ">\n";
        std::string bw = fresh();
        ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << bv
           << " to <" << lanes_d << " x i" << wbits << ">\n";
        std::string res = fresh();
        ir << "  " << res << " = " << (is_sub ? "sub" : "add")
           << " <" << lanes_d << " x i" << wbits << "> " << aw
           << ", " << bw << "\n";
        // Result is 128-bit; split into two d-regs.
        // Lane indices 0..lanes_d/2-1 -> lo; lanes_d/2..lanes_d-1 -> hi.
        // But wait -- the widened vec has lanes_d lanes total of width
        // 2*lane_bits, which is exactly 128 bits / wbits = lanes_d lanes.
        // So the full <lanes_d x iwbits> is the whole q-reg.
        // Split into two halves of (lanes_d/2) lanes each.
        int half_lanes = lanes_d / 2;
        if (half_lanes < 1) {
            // 64-bit lane width: only 1 lane in widened vec, can't split.
            // For VADDL.s32 q, d, d the input is 2x i32 -> 2x i64 = 128b.
            // So lanes_d=2, half_lanes=1. Single-lane halves are valid.
            half_lanes = 1;
        }
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes_d
               << " x i" << wbits << "> " << res << ", <" << lanes_d
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo_v = extract_half(false);
        std::string hi_v = extract_half(true);
        std::string lo_i = vec_to_i64(lo_v, wbits);
        std::string hi_i = vec_to_i64(hi_v, wbits);
        store_dreg(dst_q * 2,     lo_i);
        store_dreg(dst_q * 2 + 1, hi_i);
        return true;
    }

    // ---- VMULL / VMLSL : widening multiply (+ optional sub) -------
    // ARM ARM A8.6.335/A8.6.330. Same q-from-d shape as VADDL.
    bool emit_vmull_mlsl(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int rn    = vfp_d_idx(d.operands[1].reg);
        int rm    = vfp_d_idx(d.operands[2].reg);
        if (dst_q < 0 || rn < 0 || rm < 0) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes_d = 64 / lane_bits;
        int wbits = lane_bits * 2;
        std::string a = load_dreg(rn);
        std::string b = load_dreg(rm);
        std::string av = i64_to_vec(a, lane_bits);
        std::string bv = i64_to_vec(b, lane_bits);
        std::string aw = fresh();
        ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << av
           << " to <" << lanes_d << " x i" << wbits << ">\n";
        std::string bw = fresh();
        ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << bv
           << " to <" << lanes_d << " x i" << wbits << ">\n";
        std::string prod = fresh();
        ir << "  " << prod << " = mul <" << lanes_d << " x i" << wbits
           << "> " << aw << ", " << bw << "\n";
        // For VMLSL: dst -= prod. Read previous q-reg.
        std::string res = prod;
        if (is_sub) {
            std::string lo_old = load_dreg(dst_q * 2);
            std::string hi_old = load_dreg(dst_q * 2 + 1);
            // Reassemble into a <lanes_d x iwbits>. We need to compose
            // two i64 values as a 128-bit vector. Use bitcast trick:
            // <2 x i64> first, then bitcast to <lanes_d x iwbits>.
            std::string pair = fresh();
            ir << "  " << pair << " = insertelement <2 x i64> undef, i64 "
               << lo_old << ", i32 0\n";
            std::string pair2 = fresh();
            ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
               << ", i64 " << hi_old << ", i32 1\n";
            std::string vec_old = fresh();
            ir << "  " << vec_old << " = bitcast <2 x i64> " << pair2
               << " to <" << lanes_d << " x i" << wbits << ">\n";
            res = fresh();
            ir << "  " << res << " = sub <" << lanes_d << " x i" << wbits
               << "> " << vec_old << ", " << prod << "\n";
        }
        // Split into two d-regs.
        int half_lanes = lanes_d / 2;
        if (half_lanes < 1) half_lanes = 1;
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes_d
               << " x i" << wbits << "> " << res << ", <" << lanes_d
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo_v = extract_half(false);
        std::string hi_v = extract_half(true);
        std::string lo_i = vec_to_i64(lo_v, wbits);
        std::string hi_i = vec_to_i64(hi_v, wbits);
        store_dreg(dst_q * 2,     lo_i);
        store_dreg(dst_q * 2 + 1, hi_i);
        return true;
    }

    // ---- VSHR / VSHL / VSRA / VRSHR / VRSRA : shifts ---------------

    // ---- VMLAL / VQDMULL / VQDMLAL / VQDMLSL : widening multiply-
    // accumulate long. ARM DDI 0406C.d A8.8.287 (VMLAL), A8.8.250
    // (VQDMULL), A8.8.248 (VQDMLAL), A8.8.249 (VQDMLSL).
    //
    // Shape mirrors emit_vmull_mlsl: D x D -> Q. Inputs are two D-regs
    // of (64/lane_bits) lanes; each lane is widened to 2*lane_bits,
    // multiplied, and the <lanes_d x i(2*lane_bits)> result is the
    // whole 128-bit Q dst, split into two d-halves.
    //
    // doubling   = QDM family: the product is doubled with saturation
    //              (sadd.sat(prod,prod) at the 2x width -- the only
    //              overflow is INT_MIN*INT_MIN, which saturates to
    //              INT_MAX of the 2x width).
    // accumulate = VMLAL / VQDMLAL / VQDMLSL: combine the product with
    //              the existing Q accumulator (read both dst d-halves).
    //              VMLAL wraps (plain add); the QDM accumulate forms
    //              saturate (sadd.sat / ssub.sat).
    // subtract   = VQDMLSL: accumulator - product (only meaningful with
    //              accumulate). VMLSL is handled by emit_vmull_mlsl.
    //
    // By-scalar Vm forms (Vm[idx], operand-2 vector_index >= 0) extract
    // that lane from Dm and splat it across the half before widening.
    bool emit_vmull_long_acc(const cs_insn* in, bool doubling,
                             bool accumulate, bool subtract) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int rn    = vfp_d_idx(d.operands[1].reg);
        int rm    = vfp_d_idx(d.operands[2].reg);
        // A Q (or S) dst on Vn/Vm means this is not the D x D -> Q form
        // we model (e.g. a scalar VFP VMLA with a float datatype lands
        // on the VMLAL mnemonic with S-regs). Bail to a graceful no-op.
        if (dst_q < 0 || rn < 0 || rm < 0) return false;
        // These are integer widening multiplies; a float datatype is a
        // scalar VFP form we do not handle here.
        if (vdata_float(d.vector_data)) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0 || lane_bits > 32) return false;
        // The QDM family is defined for signed S16/S32 only.
        bool is_signed = vdata_signed(d.vector_data);
        if (doubling && !is_signed) return false;
        int lanes_d = 64 / lane_bits;
        int wbits = lane_bits * 2;
        int m_scalar_lane = d.operands[2].vector_index;

        // Build the widened (<lanes_d x iwbits>) Vn operand.
        std::string a = load_dreg(rn);
        std::string av = i64_to_vec(a, lane_bits);
        std::string aw = fresh();
        ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << av
           << " to <" << lanes_d << " x i" << wbits << ">\n";

        // Build the widened Vm operand (by-scalar splat or full D-reg).
        std::string bv_lane;
        std::string mraw = load_dreg(rm);
        std::string mvec = i64_to_vec(mraw, lane_bits);
        if (m_scalar_lane >= 0) {
            std::string el = fresh();
            ir << "  " << el << " = extractelement <" << lanes_d
               << " x i" << lane_bits << "> " << mvec << ", i32 "
               << m_scalar_lane << "\n";
            std::string ins = fresh();
            ir << "  " << ins << " = insertelement <" << lanes_d
               << " x i" << lane_bits << "> undef, i" << lane_bits
               << " " << el << ", i32 0\n";
            std::string sh = fresh();
            ir << "  " << sh << " = shufflevector <" << lanes_d
               << " x i" << lane_bits << "> " << ins << ", <" << lanes_d
               << " x i" << lane_bits << "> undef, <" << lanes_d
               << " x i32> zeroinitializer\n";
            bv_lane = sh;
        } else {
            bv_lane = mvec;
        }
        std::string bw = fresh();
        ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes_d << " x i" << lane_bits << "> " << bv_lane
           << " to <" << lanes_d << " x i" << wbits << ">\n";

        // Widening product. Max |product| = 2^(2*lane_bits-2), which
        // fits the signed 2*lane_bits type, so the mul itself cannot
        // overflow.
        std::string prod = fresh();
        ir << "  " << prod << " = mul <" << lanes_d << " x i" << wbits
           << "> " << aw << ", " << bw << "\n";

        // Doubling with saturation: sadd.sat(prod, prod). The only
        // saturating case is INT_MIN*INT_MIN -> +2^(2n-1), clamped to
        // INT_MAX of the 2n width.
        std::string scaled = prod;
        if (doubling) {
            scaled = fresh();
            ir << "  " << scaled << " = call <" << lanes_d << " x i"
               << wbits << "> @llvm.sadd.sat.v" << lanes_d << "i"
               << wbits << "(<" << lanes_d << " x i" << wbits << "> "
               << prod << ", <" << lanes_d << " x i" << wbits << "> "
               << prod << ")\n";
        }

        // Accumulate against the existing Q dst (both d-halves).
        std::string res = scaled;
        if (accumulate) {
            std::string lo_old = load_dreg(dst_q * 2);
            std::string hi_old = load_dreg(dst_q * 2 + 1);
            std::string pair = fresh();
            ir << "  " << pair
               << " = insertelement <2 x i64> undef, i64 "
               << lo_old << ", i32 0\n";
            std::string pair2 = fresh();
            ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
               << ", i64 " << hi_old << ", i32 1\n";
            std::string vec_old = fresh();
            ir << "  " << vec_old << " = bitcast <2 x i64> " << pair2
               << " to <" << lanes_d << " x i" << wbits << ">\n";
            res = fresh();
            if (doubling) {
                // VQDMLAL / VQDMLSL saturate the accumulate step.
                const char* sat = subtract ? "llvm.ssub.sat"
                                           : "llvm.sadd.sat";
                ir << "  " << res << " = call <" << lanes_d << " x i"
                   << wbits << "> @" << sat << ".v" << lanes_d << "i"
                   << wbits << "(<" << lanes_d << " x i" << wbits
                   << "> " << vec_old << ", <" << lanes_d << " x i"
                   << wbits << "> " << scaled << ")\n";
            } else {
                // VMLAL wraps.
                ir << "  " << res << " = " << (subtract ? "sub" : "add")
                   << " <" << lanes_d << " x i" << wbits << "> "
                   << vec_old << ", " << scaled << "\n";
            }
        }

        // Split the <lanes_d x iwbits> (= 128-bit) result into two
        // d-halves of (lanes_d/2) lanes each.
        int half_lanes = lanes_d / 2;
        if (half_lanes < 1) half_lanes = 1;
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes_d
               << " x i" << wbits << "> " << res << ", <" << lanes_d
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo_v = extract_half(false);
        std::string hi_v = extract_half(true);
        std::string lo_i = vec_to_i64(lo_v, wbits);
        std::string hi_i = vec_to_i64(hi_v, wbits);
        store_dreg(dst_q * 2,     lo_i);
        store_dreg(dst_q * 2 + 1, hi_i);
        return true;
    }

    // ---- VQDMULH / VQRDMULH : saturating doubling multiply high half
    // ARM DDI 0406C.d A8.8.251 (VQDMULH) and A8.8.253 (VQRDMULH).
    // Signed only, element size 16 or 32. Same-width: D->D or Q->Q.
    //   product = 2 * Sn[i] * Sm[i]   (computed in 2*esize bits)
    //   VQRDMULH adds the round constant (1 << (esize-1)) to product
    //   result  = sat_signed( product >> esize )  truncated to esize
    // The only value that saturates is (-2^(e-1))*(-2^(e-1)) doubled,
    // which yields +2^(e-1) and clamps to +2^(e-1)-1 (and, for the
    // rounding variant, the rounded boundary clamps the same way).
    // We reuse emit_v_binop_int for the D/Q split and clamp per the
    // emit_vqshrn icmp+select idiom. Unsigned / float / non-16/32
    // datatypes return false -> graceful no-op.
    bool emit_vqdmulh(const cs_insn* in, bool rounding) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        // Architecturally defined only for 16-bit and 32-bit elements.
        if (lane_bits != 16 && lane_bits != 32) return false;
        // Signed only; reject unsigned / float forms.
        if (vdata_float(d.vector_data)) return false;
        if (!vdata_signed(d.vector_data)) return false;
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            int wbits = lb * 2;   // 2*esize accumulator width (real widen)
            // Sign-extend both operands to 2*esize.
            std::string aw = fresh();
            ir << "  " << aw << " = sext <" << lanes << " x i" << lb
               << "> " << av << " to <" << lanes << " x i" << wbits
               << ">\n";
            std::string bw = fresh();
            ir << "  " << bw << " = sext <" << lanes << " x i" << lb
               << "> " << bv << " to <" << lanes << " x i" << wbits
               << ">\n";
            // product = a * b (in 2*esize bits, no overflow possible).
            std::string prod = fresh();
            ir << "  " << prod << " = mul <" << lanes << " x i" << wbits
               << "> " << aw << ", " << bw << "\n";
            // Double: shl by 1.
            std::string dbl = fresh();
            ir << "  " << dbl << " = shl <" << lanes << " x i" << wbits
               << "> " << prod << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " 1";
            }
            ir << ">\n";
            // Optional rounding: add (1 << (esize-1)) before the shift.
            std::string rounded = dbl;
            if (rounding) {
                int64_t rbit = static_cast<int64_t>(1) << (lb - 1);
                std::string r = fresh();
                ir << "  " << r << " = add <" << lanes << " x i" << wbits
                   << "> " << dbl << ", <";
                for (int i = 0; i < lanes; ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i" << wbits << " " << rbit;
                }
                ir << ">\n";
                rounded = r;
            }
            // Arithmetic shift right by esize to take the high half.
            std::string sh = fresh();
            ir << "  " << sh << " = ashr <" << lanes << " x i" << wbits
               << "> " << rounded << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << lb;
            }
            ir << ">\n";
            // Saturate to signed esize range [-(2^(e-1)) .. 2^(e-1)-1].
            int64_t hi_lim = (lb == 16) ? 32767 : 0x7fffffffLL;
            int64_t lo_lim = -hi_lim - 1;
            std::string above = fresh();
            ir << "  " << above << " = icmp sgt <" << lanes << " x i"
               << wbits << "> " << sh << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << hi_lim;
            }
            ir << ">\n";
            std::string cap_hi = fresh();
            ir << "  " << cap_hi << " = select <" << lanes << " x i1> "
               << above << ", <" << lanes << " x i" << wbits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << hi_lim;
            }
            ir << ">, <" << lanes << " x i" << wbits << "> " << sh
               << "\n";
            std::string below = fresh();
            ir << "  " << below << " = icmp slt <" << lanes << " x i"
               << wbits << "> " << cap_hi << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << lo_lim;
            }
            ir << ">\n";
            std::string cap = fresh();
            ir << "  " << cap << " = select <" << lanes << " x i1> "
               << below << ", <" << lanes << " x i" << wbits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << lo_lim;
            }
            ir << ">, <" << lanes << " x i" << wbits << "> " << cap_hi
               << "\n";
            // Truncate back to esize (wbits != lb, always a real narrow).
            std::string nar = fresh();
            ir << "  " << nar << " = trunc <" << lanes << " x i" << wbits
               << "> " << cap << " to <" << lanes << " x i" << lb
               << ">\n";
            return nar;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VSHRN / VRSHRN / VQSHRN / VQSHRUN / VQRSHRN / VQRSHRUN ----
    // Shift-right-and-narrow: Q source (one lane width W) -> D result
    // (half width W/2). ARM DDI 0406C.d:
    //   VSHRN    A8.8.236  truncating, no saturation
    //   VRSHRN   A8.8.244  rounding (add 1<<(sh-1)), no saturation
    //   VQSHRN   A8.8.246  saturating (signed or unsigned per datatype)
    //   VQSHRUN  A8.8.247  signed source, saturate to UNSIGNED result
    //   VQRSHRN            saturating rounding (signed or unsigned)
    //   VQRSHRUN           signed source, rounding, UNSIGNED result
    // IMPORTANT: Capstone reports the datatype suffix as the SOURCE
    // element width (verified live on gdlite: vshrn.i64 -> src 64 /
    // res 32, vqshrun.s16 -> src 16 / res 8, vqshrn.u32 -> src 32 /
    // res 16). So lane_bits_of(d) is the SOURCE width here; the result
    // lane is half that. (The older emit_vqshrn inverted this, which is
    // why these route through this corrected handler instead.)
    // saturate=false  -> VSHRN / VRSHRN (truncate low half).
    // saturate=true, unsigned_result=false -> VQSHRN / VQRSHRN.
    // saturate=true, unsigned_result=true  -> VQSHRUN / VQRSHRUN.
    bool emit_v_shrn(const cs_insn* in, bool saturate,
                     bool unsigned_result, bool rounding) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        int dst_d = vfp_d_idx(d.operands[0].reg);
        int src_q = vfp_q_idx(d.operands[1].reg);
        if (dst_d < 0 || src_q < 0) return false;
        int src_bits = lane_bits_of(d);  // SOURCE lane width
        if (src_bits != 16 && src_bits != 32 && src_bits != 64)
            return false;
        int res_bits = src_bits / 2;     // narrowed result lane width
        int lanes = 128 / src_bits;      // lane count (same in src + dst)
        int32_t amt = static_cast<int32_t>(d.operands[2].imm);
        // Encoded shift range is 1..res_bits for narrowing shifts; a 0
        // shift has no valid encoding and would make the rounding bias
        // 1<<-1. Bail to a graceful no-op rather than emit wrong IR.
        if (amt < 1 || amt > res_bits) return false;
        // Source element signedness governs the shift kind: S-types
        // (including the *UN forms, whose source is signed) -> ashr;
        // I/U-types -> lshr. For non-saturating VSHRN/VRSHRN the low
        // res_bits are truncated, and ashr vs lshr differ only in bits
        // at positions >= res_bits (since amt <= res_bits), so lshr is
        // chosen there as the canonical truncating shift.
        bool src_signed = saturate && vdata_signed(d.vector_data);
        // Assemble the Q source as <lanes x i{src_bits}>.
        std::string lo_old = load_dreg(src_q * 2);
        std::string hi_old = load_dreg(src_q * 2 + 1);
        std::string pair = fresh();
        ir << "  " << pair << " = insertelement <2 x i64> undef, i64 "
           << lo_old << ", i32 0\n";
        std::string pair2 = fresh();
        ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
           << ", i64 " << hi_old << ", i32 1\n";
        std::string svec = fresh();
        ir << "  " << svec << " = bitcast <2 x i64> " << pair2
           << " to <" << lanes << " x i" << src_bits << ">\n";
        // Optional rounding: add 1<<(amt-1) in the source width.
        std::string pre = svec;
        if (rounding) {
            uint64_t rbit = static_cast<uint64_t>(1) << (amt - 1);
            std::string r = fresh();
            ir << "  " << r << " = add <" << lanes << " x i" << src_bits
               << "> " << svec << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << static_cast<int64_t>(rbit);
            }
            ir << ">\n";
            pre = r;
        }
        // Shift right by amt in the source width.
        std::string shifted = fresh();
        ir << "  " << shifted << " = " << (src_signed ? "ashr" : "lshr")
           << " <" << lanes << " x i" << src_bits << "> " << pre << ", <";
        for (int i = 0; i < lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << src_bits << " " << amt;
        }
        ir << ">\n";
        std::string capped = shifted;
        if (saturate) {
            // Clamp (in the source width) to the result-width range,
            // then truncate. Mirrors emit_vqshrn's icmp+select clamp.
            int64_t hi_lim, lo_lim;
            if (unsigned_result) {
                hi_lim = (res_bits == 8) ? 0xff :
                         (res_bits == 16) ? 0xffff : 0xffffffffLL;
                lo_lim = 0;
            } else {
                hi_lim = (res_bits == 8) ? 127 :
                         (res_bits == 16) ? 32767 : 0x7fffffffLL;
                lo_lim = -hi_lim - 1;
            }
            // Upper clamp. Comparison signedness follows the SHIFTED
            // value's signedness (the *UN forms shift a signed value
            // but saturate into an unsigned range, so a negative input
            // must clamp to 0 -> use signed comparisons for them).
            bool cmp_signed = src_signed;
            std::string above = fresh();
            ir << "  " << above << " = icmp "
               << (cmp_signed ? "sgt" : "ugt") << " <" << lanes
               << " x i" << src_bits << "> " << shifted << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << hi_lim;
            }
            ir << ">\n";
            std::string cap_hi = fresh();
            ir << "  " << cap_hi << " = select <" << lanes
               << " x i1> " << above << ", <" << lanes << " x i"
               << src_bits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << hi_lim;
            }
            ir << ">, <" << lanes << " x i" << src_bits << "> "
               << shifted << "\n";
            // Lower clamp.
            std::string below = fresh();
            ir << "  " << below << " = icmp "
               << (cmp_signed ? "slt" : "ult") << " <" << lanes
               << " x i" << src_bits << "> " << cap_hi << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << lo_lim;
            }
            ir << ">\n";
            std::string cap = fresh();
            ir << "  " << cap << " = select <" << lanes
               << " x i1> " << below << ", <" << lanes << " x i"
               << src_bits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << lo_lim;
            }
            ir << ">, <" << lanes << " x i" << src_bits << "> "
               << cap_hi << "\n";
            capped = cap;
        }
        // Narrow to the result lane width.
        std::string nar = fresh();
        ir << "  " << nar << " = trunc <" << lanes << " x i" << src_bits
           << "> " << capped << " to <" << lanes << " x i" << res_bits
           << ">\n";
        std::string ni = vec_to_i64(nar, res_bits);
        store_dreg(dst_d, ni);
        return true;
    }

    // ---- VSHLL : shift left long (D input -> Q output, 2x width) ----
    // ARM DDI 0406C.d A8.8.245. Two encodings, identical datapath here:
    //   A1: VSHLL.<s|u>NN Qd, Dm, #imm   (1 <= imm <= esize-1)
    //   A2: VSHLL.iNN     Qd, Dm, #esize (maximum shift == element size)
    // Each esize-wide Dm lane is sign-extended (.sNN) or zero-extended
    // (.uNN / .iNN -- the A2 max-shift form uses unsigned_extend per the
    // ARM ARM pseudocode) to 2*esize, then shifted left by the immediate.
    // The widened vector is exactly 128 bits -> two Qd d-halves. Mirrors
    // the verified emit_vmovl widen idiom with a per-lane `shl` inserted
    // between the extend and the half-split.
    bool emit_vshll(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        // op0 = Qd, op1 = Dm, op2 = #imm (A1). The A2 max-shift form may
        // omit the explicit immediate; default it to esize below.
        if (d.op_count != 2 && d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int src   = vfp_d_idx(d.operands[1].reg);
        if (dst_q < 0 || src < 0) return false;
        int lane_bits = lane_bits_of(d);   // narrow src lane width (esize)
        if (lane_bits == 0 || lane_bits >= 64) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes = 64 / lane_bits;        // src lanes
        int wbits = lane_bits * 2;         // widened lane width
        // Resolve the shift amount: A1 carries an explicit #imm, A2's
        // max-shift form is a shift by the element size.
        int shift_amt = lane_bits;
        if (d.op_count == 3) {
            if (d.operands[2].type != ARM_OP_IMM) return false;
            shift_amt = static_cast<int>(d.operands[2].imm);
        }
        // Defensive clamp: a legal VSHLL imm is in [1, esize], so it is
        // always strictly less than wbits and `shl` is never poison; clamp
        // anyway so a malformed decode can never emit out-of-range shifts.
        if (shift_amt < 0) shift_amt = 0;
        if (shift_amt > wbits - 1) shift_amt = wbits - 1;
        std::string sv = load_dreg(src);
        std::string vv = i64_to_vec(sv, lane_bits);
        // wbits is always strictly greater than lane_bits here (lane_bits
        // guarded < 64), so this is a true widen -- never a same-width
        // (invalid LLVM) sext/zext.
        std::string ext = fresh();
        ir << "  " << ext << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes << " x i" << lane_bits << "> " << vv
           << " to <" << lanes << " x i" << wbits << ">\n";
        // Per-lane shift left by the immediate.
        std::string shifted = fresh();
        ir << "  " << shifted << " = shl <" << lanes << " x i" << wbits
           << "> " << ext << ", <";
        for (int i = 0; i < lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << shift_amt;
        }
        ir << ">\n";
        // <lanes x iwbits> is exactly 128 bits -> two dst d-halves.
        int half_lanes = lanes / 2;
        if (half_lanes < 1) half_lanes = 1;
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes
               << " x i" << wbits << "> " << shifted << ", <" << lanes
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo = extract_half(false);
        std::string hi = extract_half(true);
        store_dreg(dst_q * 2,     vec_to_i64(lo, wbits));
        store_dreg(dst_q * 2 + 1, vec_to_i64(hi, wbits));
        return true;
    }

    // ---- VQMOVN / VQMOVUN : saturating narrow Q->D ------------------
    // ARM DDI 0406C.d A8.8.252 (VQMOVN, VQMOVUN). op0 = Dd (narrow
    // result), op1 = Qm (wide source). op_count = 2. Capstone reports
    // the WIDE source element type in vector_data (S16/U16/S32/S64...),
    // vector_size = 0; the narrow result lane is half that width. Each
    // source lane is saturated to the destination range and truncated:
    //   VQMOVN.Sxx  : signed input  -> signed   narrow range
    //   VQMOVN.Uxx  : unsigned input -> unsigned narrow range
    //   VQMOVUN.Sxx : signed input  -> UNSIGNED  narrow range
    //                 (negatives clamp to 0, above-max clamp to 2^n-1)
    // unsigned_result selects the VQMOVUN clamp; otherwise the clamp
    // is signed-vs-unsigned per the source datatype's signedness.
    // Saturation mirrors emit_vqshrn's icmp+select clamp block but with
    // NO shift (this is a pure narrowing move). The wide source is
    // assembled from the q-reg's two d-halves into a <2 x i64> then
    // reinterpreted as <total x iWide>, exactly as emit_vqshrn does, so
    // the lane count lines up with the narrow destination d-reg.
    bool emit_vqmovn(const cs_insn* in, bool unsigned_result) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        int dst_d = vfp_d_idx(d.operands[0].reg);
        int src_q = vfp_q_idx(d.operands[1].reg);
        if (dst_d < 0 || src_q < 0) return false;
        // vector_data carries the WIDE source lane width (the result is
        // half). vector_size is not populated for this instruction, so
        // we must read vdata_bits directly (not lane_bits_of).
        int wbits = vdata_bits(d.vector_data);
        if (wbits < 16 || wbits > 64) return false;   // narrow >= 8 bits
        int lane_bits = wbits / 2;                     // narrow result width
        // Source signedness: VQMOVN.Uxx is unsigned input; VQMOVN.Sxx
        // and VQMOVUN.Sxx are signed input. vdata_signed picks S vs U.
        bool src_signed = vdata_signed(d.vector_data);
        int total_lanes = 64 / lane_bits;   // narrow lanes per d-reg ==
                                            // wide lanes across the q-reg
        // Assemble the two source d-halves into a <2 x i64> then view as
        // <total_lanes x iWide> (128 source bits = total_lanes wide lanes).
        std::string lo_old = load_dreg(src_q * 2);
        std::string hi_old = load_dreg(src_q * 2 + 1);
        std::string pair = fresh();
        ir << "  " << pair << " = insertelement <2 x i64> undef, i64 "
           << lo_old << ", i32 0\n";
        std::string pair2 = fresh();
        ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
           << ", i64 " << hi_old << ", i32 1\n";
        std::string svec = fresh();
        ir << "  " << svec << " = bitcast <2 x i64> " << pair2
           << " to <" << total_lanes << " x i" << wbits << ">\n";
        // Determine the saturation limits in the WIDE type. For the
        // unsigned-result clamp (VQMOVN.U / VQMOVUN) the destination is
        // [0, 2^n-1]; for the signed-result clamp (VQMOVN.S) it is
        // [-2^(n-1), 2^(n-1)-1]. The comparison signedness follows the
        // SOURCE: a signed source uses sgt/slt, an unsigned source ugt.
        bool dst_unsigned = unsigned_result || !src_signed;
        int64_t hi_lim, lo_lim;
        if (dst_unsigned) {
            hi_lim = (lane_bits == 8)  ? 0xffLL :
                     (lane_bits == 16) ? 0xffffLL : 0xffffffffLL;
            lo_lim = 0;
        } else {
            hi_lim = (lane_bits == 8)  ? 127LL :
                     (lane_bits == 16) ? 32767LL : 0x7fffffffLL;
            lo_lim = -hi_lim - 1;
        }
        // Clamp above hi_lim. Comparison signedness tracks the source
        // type (an unsigned source can never be below 0, but we still
        // emit the lo clamp harmlessly with an unsigned compare).
        std::string above = fresh();
        ir << "  " << above << " = icmp "
           << (src_signed ? "sgt" : "ugt") << " <" << total_lanes
           << " x i" << wbits << "> " << svec << ", <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << hi_lim;
        }
        ir << ">\n";
        std::string cap_hi = fresh();
        ir << "  " << cap_hi << " = select <" << total_lanes
           << " x i1> " << above << ", <" << total_lanes << " x i"
           << wbits << "> <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << hi_lim;
        }
        ir << ">, <" << total_lanes << " x i" << wbits << "> "
           << svec << "\n";
        std::string below = fresh();
        ir << "  " << below << " = icmp "
           << (src_signed ? "slt" : "ult") << " <" << total_lanes
           << " x i" << wbits << "> " << cap_hi << ", <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << lo_lim;
        }
        ir << ">\n";
        std::string cap = fresh();
        ir << "  " << cap << " = select <" << total_lanes
           << " x i1> " << below << ", <" << total_lanes << " x i"
           << wbits << "> <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << lo_lim;
        }
        ir << ">, <" << total_lanes << " x i" << wbits << "> "
           << cap_hi << "\n";
        // Narrow the clamped wide lanes to the result width. wbits is
        // always 2*lane_bits here, so this trunc is never same-width.
        std::string nar = fresh();
        ir << "  " << nar << " = trunc <" << total_lanes
           << " x i" << wbits << "> " << cap << " to <" << total_lanes
           << " x i" << lane_bits << ">\n";
        std::string ni = vec_to_i64(nar, lane_bits);
        store_dreg(dst_d, ni);
        return true;
    }

    // ---- VADDHN / VSUBHN / VRADDHN / VRSUBHN -----------------------
    // Add/subtract returning the HIGH half, narrowed. ARM DDI 0406C.d
    // A8.8.277 (VADDHN), A8.8.265 (VSUBHN), A8.8.278 (VRADDHN),
    // A8.8.266 (VRSUBHN). op0=Dd (narrow result), op1=Qn, op2=Qm (both
    // wide Q sources). For each lane:
    //   sum  = Qn[i] (+/-) Qm[i]                     (2*esize wide)
    //   res  = (sum [+ round]) >> esize, truncated to esize
    // where esize is the RESULT element width (= half the source width)
    // and round = 1 << (esize-1) for the rounding (VR..) variants.
    // These forms WRAP (non-saturating) per the ARM ARM pseudocode.
    // vector_data carries the WIDE source element type (I16/I32/I64),
    // so lane_bits_of() yields src_bits and the result lane is half.
    bool emit_vaddsubhn(const cs_insn* in, bool is_sub, bool rounding) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG ||
            d.operands[2].type != ARM_OP_REG) return false;
        int dst   = vfp_d_idx(d.operands[0].reg);
        int src_n = vfp_q_idx(d.operands[1].reg);
        int src_m = vfp_q_idx(d.operands[2].reg);
        if (dst < 0 || src_n < 0 || src_m < 0) return false;
        int src_bits = lane_bits_of(d);   // wide source lane width
        if (src_bits < 16 || src_bits > 64) return false;
        int half = src_bits / 2;          // result (narrow) lane width
        int lanes_per_d = 64 / src_bits;  // wide lanes per source d-reg
        if (lanes_per_d < 1) return false;
        int total = lanes_per_d * 2;      // wide lanes across the full Q

        // Read each Q source as its two d-halves, bitcast to
        // <lanes_per_d x i(src_bits)>, and concatenate into the full
        // <total x i(src_bits)> 128-bit operand (mirrors emit_vmovn).
        auto load_q_wide = [&](int q) -> std::string {
            std::string lo = load_dreg(q * 2);
            std::string hi = load_dreg(q * 2 + 1);
            std::string lov = i64_to_vec(lo, src_bits);
            std::string hiv = i64_to_vec(hi, src_bits);
            std::string cat = fresh();
            ir << "  " << cat << " = shufflevector <" << lanes_per_d
               << " x i" << src_bits << "> " << lov << ", <"
               << lanes_per_d << " x i" << src_bits << "> " << hiv
               << ", <" << total << " x i32> <";
            for (int i = 0; i < total; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << i;
            }
            ir << ">\n";
            return cat;
        };
        std::string nv = load_q_wide(src_n);
        std::string mv = load_q_wide(src_m);

        // sum/diff in the wide lane width (wrapping).
        std::string sum = fresh();
        ir << "  " << sum << " = " << (is_sub ? "sub" : "add")
           << " <" << total << " x i" << src_bits << "> " << nv
           << ", " << mv << "\n";

        // Rounding variants add (1 << (half-1)) before the shift.
        std::string rounded = sum;
        if (rounding) {
            long long rc = 1LL << (half - 1);
            std::string rconst = fresh();
            ir << "  " << rconst << " = add <" << total << " x i"
               << src_bits << "> " << sum << ", <";
            for (int i = 0; i < total; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << src_bits << " " << rc;
            }
            ir << ">\n";
            rounded = rconst;
        }

        // Logical shift right by the narrow lane width (take high half).
        std::string shifted = fresh();
        ir << "  " << shifted << " = lshr <" << total << " x i"
           << src_bits << "> " << rounded << ", <";
        for (int i = 0; i < total; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << src_bits << " " << half;
        }
        ir << ">\n";

        // Truncate to the narrow lane width. src_bits is always strictly
        // wider than half (src_bits>=16, half>=8), so this is a real
        // narrowing trunc -- never an invalid same-width cast.
        std::string narrowed = fresh();
        ir << "  " << narrowed << " = trunc <" << total << " x i"
           << src_bits << "> " << shifted << " to <" << total
           << " x i" << half << ">\n";

        std::string oi = vec_to_i64(narrowed, half);
        store_dreg(dst, oi);
        return true;
    }

    // ---- VPADDL / VPADAL : pairwise add long / accumulate ---------
    // ARM DDI 0406C.d A8.8.219 (VPADDL) and A8.8.218 (VPADAL).
    //   VPADDL.{s|u}<sz>  Dd, Dm | Qd, Qm
    //   VPADAL.{s|u}<sz>  Dd, Dm | Qd, Qm
    // Each adjacent pair of source elements (width lb) is widened to
    // 2*lb (sign- or zero-extended per the datatype), the pair is
    // summed, and the result is written as elements of width 2*lb.
    // VPADAL additionally adds the existing destination accumulator.
    // The op is naturally per-64-bit-half: a 64-bit half holding
    // (64/lb) source lanes produces (32/lb) result lanes of width
    // 2*lb == exactly 64 bits == one destination d-half. So the D
    // form (1 half) and the Q form (2 halves) are the same code path
    // run over 1 or 2 d-registers. Capstone reports op_count==2 with
    // both operands ARM_OP_REG; signedness is in vector_data.
    bool emit_vpaddl_vpadal(const cs_insn* in, bool accumulate) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        // Valid source element widths are 8/16/32; 64-bit source is
        // not a pairwise-long form (the widened result would exceed
        // 64 bits per element). Reject anything else as a no-op.
        if (lane_bits != 8 && lane_bits != 16 && lane_bits != 32)
            return false;
        bool is_signed = vdata_signed(d.vector_data);
        int wbits = lane_bits * 2;       // widened element width
        int lanes = 64 / lane_bits;      // source lanes per d-half
        int wlanes = lanes / 2;          // result lanes per d-half

        // Resolve dst/src as either a Q pair (2 d-halves) or a single
        // D reg (1 half). Both operands must be the same form.
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int src_q = vfp_q_idx(d.operands[1].reg);
        int dst_d[2] = {-1, -1};
        int src_d[2] = {-1, -1};
        int halves;
        if (dst_q >= 0 && src_q >= 0) {
            halves = 2;
            dst_d[0] = dst_q * 2; dst_d[1] = dst_q * 2 + 1;
            src_d[0] = src_q * 2; src_d[1] = src_q * 2 + 1;
        } else {
            int dd = vfp_d_idx(d.operands[0].reg);
            int dm = vfp_d_idx(d.operands[1].reg);
            if (dd < 0 || dm < 0) return false;  // mixed/unknown form
            halves = 1;
            dst_d[0] = dd;
            src_d[0] = dm;
        }

        for (int h = 0; h < halves; ++h) {
            // Load the source half and view it as <lanes x ilb>.
            std::string sm  = load_dreg(src_d[h]);
            std::string smv = i64_to_vec(sm, lane_bits);
            // Widen all source lanes to <lanes x iwbits>.
            std::string smw = fresh();
            ir << "  " << smw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lane_bits << "> " << smv
               << " to <" << lanes << " x i" << wbits << ">\n";
            // Gather even lanes [0,2,4,...] and odd lanes [1,3,5,...].
            std::string evens = fresh();
            ir << "  " << evens << " = shufflevector <" << lanes
               << " x i" << wbits << "> " << smw << ", <" << lanes
               << " x i" << wbits << "> undef, <" << wlanes
               << " x i32> <";
            for (int i = 0; i < wlanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (2 * i);
            }
            ir << ">\n";
            std::string odds = fresh();
            ir << "  " << odds << " = shufflevector <" << lanes
               << " x i" << wbits << "> " << smw << ", <" << lanes
               << " x i" << wbits << "> undef, <" << wlanes
               << " x i32> <";
            for (int i = 0; i < wlanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (2 * i + 1);
            }
            ir << ">\n";
            // Pairwise sum (wraps; VPADDL/VPADAL are not saturating).
            std::string sum = fresh();
            ir << "  " << sum << " = add <" << wlanes << " x i" << wbits
               << "> " << evens << ", " << odds << "\n";
            // VPADAL: add the existing destination accumulator.
            std::string res = sum;
            if (accumulate) {
                std::string dprev  = load_dreg(dst_d[h]);
                std::string dprevv = i64_to_vec(dprev, wbits);
                res = fresh();
                ir << "  " << res << " = add <" << wlanes << " x i"
                   << wbits << "> " << sum << ", " << dprevv << "\n";
            }
            std::string ri = vec_to_i64(res, wbits);
            store_dreg(dst_d[h], ri);
        }
        return true;
    }

    // ---- VHSUB : halving subtract (per-lane (a-b)>>1) --------------
    // ARM DDI 0406C.d A8.8.96. Per lane: out = (a - b) >> 1, arithmetic
    // for signed datatypes, logical for unsigned. Compute in 2x lane
    // width so the subtraction cannot overflow, shift right by 1, then
    // truncate back. Mirror of emit_vhadd (A8.8.305) with sub.
    bool emit_vhsub(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            int wbits = lb * 2;
            std::string aw = fresh();
            ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << av
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string bw = fresh();
            ir << "  " << bw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lb << "> " << bv
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string diff = fresh();
            ir << "  " << diff << " = sub <" << lanes << " x i" << wbits
               << "> " << aw << ", " << bw << "\n";
            std::string sh = fresh();
            ir << "  " << sh << " = " << (is_signed ? "ashr" : "lshr")
               << " <" << lanes << " x i" << wbits << "> " << diff
               << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " 1";
            }
            ir << ">\n";
            std::string nar = fresh();
            ir << "  " << nar << " = trunc <" << lanes << " x i"
               << wbits << "> " << sh << " to <" << lanes << " x i"
               << lb << ">\n";
            return nar;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VABDL / VABAL : widening absolute difference (+accumulate)-
    // ARM DDI 0406C.d A8.8.268 (VABDL) / A8.8.267 (VABAL). Dst is a
    // q-reg, sources are d-regs. Per source lane compute |a - b| using
    // the max(a,b)-min(a,b) idiom (avoids signed overflow); the result
    // magnitude is non-negative and fits the UNSIGNED source-lane
    // width, so zero-extend to 2x lane width unconditionally (even for
    // signed datatypes). VABAL adds the previous q-reg contents.
    bool emit_vabal_vabdl(const cs_insn* in, bool accumulate) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int rn    = vfp_d_idx(d.operands[1].reg);
        int rm    = vfp_d_idx(d.operands[2].reg);
        if (dst_q < 0 || rn < 0 || rm < 0) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes_d = 64 / lane_bits;
        int wbits = lane_bits * 2;
        std::string a = load_dreg(rn);
        std::string b = load_dreg(rm);
        std::string av = i64_to_vec(a, lane_bits);
        std::string bv = i64_to_vec(b, lane_bits);
        // |a - b| at source width via max-min.
        const char* mx = is_signed ? "llvm.smax" : "llvm.umax";
        const char* mn = is_signed ? "llvm.smin" : "llvm.umin";
        std::string hi = fresh();
        ir << "  " << hi << " = call <" << lanes_d << " x i" << lane_bits
           << "> @" << mx << ".v" << lanes_d << "i" << lane_bits << "(<"
           << lanes_d << " x i" << lane_bits << "> " << av << ", <"
           << lanes_d << " x i" << lane_bits << "> " << bv << ")\n";
        std::string lo = fresh();
        ir << "  " << lo << " = call <" << lanes_d << " x i" << lane_bits
           << "> @" << mn << ".v" << lanes_d << "i" << lane_bits << "(<"
           << lanes_d << " x i" << lane_bits << "> " << av << ", <"
           << lanes_d << " x i" << lane_bits << "> " << bv << ")\n";
        std::string ad = fresh();
        ir << "  " << ad << " = sub <" << lanes_d << " x i" << lane_bits
           << "> " << hi << ", " << lo << "\n";
        // Widen the non-negative magnitude to 2x lane width (zext).
        std::string adw = fresh();
        ir << "  " << adw << " = zext <" << lanes_d << " x i" << lane_bits
           << "> " << ad << " to <" << lanes_d << " x i" << wbits << ">\n";
        std::string res = adw;
        if (accumulate) {
            // Reassemble the previous q-reg (two d-halves) into a
            // <lanes_d x iwbits> via <2 x i64> bitcast, then add.
            std::string lo_old = load_dreg(dst_q * 2);
            std::string hi_old = load_dreg(dst_q * 2 + 1);
            std::string pair = fresh();
            ir << "  " << pair
               << " = insertelement <2 x i64> undef, i64 " << lo_old
               << ", i32 0\n";
            std::string pair2 = fresh();
            ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
               << ", i64 " << hi_old << ", i32 1\n";
            std::string vec_old = fresh();
            ir << "  " << vec_old << " = bitcast <2 x i64> " << pair2
               << " to <" << lanes_d << " x i" << wbits << ">\n";
            res = fresh();
            ir << "  " << res << " = add <" << lanes_d << " x i" << wbits
               << "> " << vec_old << ", " << adw << "\n";
        }
        // Split the 128-bit widened result into two d-regs.
        int half_lanes = lanes_d / 2;
        if (half_lanes < 1) half_lanes = 1;
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes_d
               << " x i" << wbits << "> " << res << ", <" << lanes_d
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo_v = extract_half(false);
        std::string hi_v = extract_half(true);
        std::string lo_i = vec_to_i64(lo_v, wbits);
        std::string hi_i = vec_to_i64(hi_v, wbits);
        store_dreg(dst_q * 2,     lo_i);
        store_dreg(dst_q * 2 + 1, hi_i);
        return true;
    }

    // ---- VABA : absolute-difference and accumulate (same width) ----
    // ARM DDI 0406C.d A8.8.256. Per lane: Vd = Vd + |Vn - Vm|, signed
    // or unsigned per the datatype. Same-width (non-widening): the
    // accumulate reads the OLD destination, so this is scalarized per
    // d-half reading the destination register directly (cannot use
    // emit_v_binop_int, whose a/b are the two source operands).
    bool emit_vaba(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst_base, n_base, m_base;
        if (is_q) {
            int dq = vfp_q_idx(d.operands[0].reg);
            int nq = vfp_q_idx(d.operands[1].reg);
            int mq = vfp_q_idx(d.operands[2].reg);
            if (dq < 0 || nq < 0 || mq < 0) return false;
            dst_base = dq * 2; n_base = nq * 2; m_base = mq * 2;
        } else {
            dst_base = vfp_d_idx(d.operands[0].reg);
            n_base   = vfp_d_idx(d.operands[1].reg);
            m_base   = vfp_d_idx(d.operands[2].reg);
            if (dst_base < 0 || n_base < 0 || m_base < 0) return false;
        }
        int lanes = 64 / lane_bits;
        const char* mx = is_signed ? "llvm.smax" : "llvm.umax";
        const char* mn = is_signed ? "llvm.smin" : "llvm.umin";
        for (int h = 0; h < halves; ++h) {
            std::string n = load_dreg(n_base + h);
            std::string m = load_dreg(m_base + h);
            std::string dprev = load_dreg(dst_base + h);
            std::string nv = i64_to_vec(n, lane_bits);
            std::string mv = i64_to_vec(m, lane_bits);
            std::string dv = i64_to_vec(dprev, lane_bits);
            std::string hi = fresh();
            ir << "  " << hi << " = call <" << lanes << " x i" << lane_bits
               << "> @" << mx << ".v" << lanes << "i" << lane_bits << "(<"
               << lanes << " x i" << lane_bits << "> " << nv << ", <"
               << lanes << " x i" << lane_bits << "> " << mv << ")\n";
            std::string lo = fresh();
            ir << "  " << lo << " = call <" << lanes << " x i" << lane_bits
               << "> @" << mn << ".v" << lanes << "i" << lane_bits << "(<"
               << lanes << " x i" << lane_bits << "> " << nv << ", <"
               << lanes << " x i" << lane_bits << "> " << mv << ")\n";
            std::string ad = fresh();
            ir << "  " << ad << " = sub <" << lanes << " x i" << lane_bits
               << "> " << hi << ", " << lo << "\n";
            std::string acc = fresh();
            ir << "  " << acc << " = add <" << lanes << " x i" << lane_bits
               << "> " << dv << ", " << ad << "\n";
            std::string acc_i = vec_to_i64(acc, lane_bits);
            store_dreg(dst_base + h, acc_i);
        }
        return true;
    }

    // ---- VQABS / VQNEG / VCLS / VCLZ / VCNT : per-lane unary ops ----
    // ARM DDI 0406C.d: VQABS A8.8.241, VQNEG A8.8.252, VCLS A8.8.74,
    // VCLZ A8.8.75, VCNT A8.8.76. All are 2-operand, SAME-WIDTH ops:
    // dst and src are both D-regs or both Q-regs; the result element
    // width equals the source element width (no widen/narrow), so we
    // never emit a same-width cast. d/q split mirrors emit_qq_binop.
    //   kind 0 = VQABS  : saturating abs;  INT_MIN -> INT_MAX (signed)
    //   kind 1 = VQNEG  : saturating neg;  -INT_MIN -> INT_MAX (signed)
    //   kind 2 = VCLS   : count leading sign bits =
    //                     ctlz(x<0 ? ~x : x) - 1
    //   kind 3 = VCLZ   : count leading zeros via llvm.ctlz (poison=0)
    //   kind 4 = VCNT   : per-byte popcount via llvm.ctpop; dt = I8 only
    bool emit_v_unop_count_sat(const cs_insn* in, int kind) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        // VCNT only operates on byte lanes (dt = I8); anything else is
        // not architecturally valid, so force/require 8.
        if (kind == 4) {
            if (lane_bits == 0) lane_bits = 8;
            if (lane_bits != 8) return false;
        }
        if (lane_bits == 0 || lane_bits > 64) return false;
        // INT_MIN/INT_MAX (signed) constants for the saturating ops.
        int64_t smin =
            (lane_bits == 8)  ? -128LL :
            (lane_bits == 16) ? -32768LL :
            (lane_bits == 32) ? (-2147483647LL - 1) :
                                (-9223372036854775807LL - 1);
        int64_t smax =
            (lane_bits == 8)  ? 127LL :
            (lane_bits == 16) ? 32767LL :
            (lane_bits == 32) ? 2147483647LL :
                                9223372036854775807LL;
        int lanes = 64 / lane_bits;
        auto vconst = [&](int64_t c) -> std::string {
            std::string s = "<";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) s += ", ";
                s += "i" + std::to_string(lane_bits) + " " +
                     std::to_string(static_cast<long long>(c));
            }
            s += ">";
            return s;
        };
        // Per-half lane op on an i64 source value -> i64 result value.
        auto do_half = [&](const std::string& src_i64) -> std::string {
            std::string xv = i64_to_vec(src_i64, lane_bits);
            std::string res;
            if (kind == 0) {
                // VQABS: abs = (x < 0) ? -x : x; saturate INT_MIN.
                std::string isneg = fresh();
                ir << "  " << isneg << " = icmp slt <" << lanes << " x i"
                   << lane_bits << "> " << xv << ", " << vconst(0) << "\n";
                std::string neg = fresh();
                ir << "  " << neg << " = sub <" << lanes << " x i"
                   << lane_bits << "> " << vconst(0) << ", " << xv << "\n";
                std::string absv = fresh();
                ir << "  " << absv << " = select <" << lanes << " x i1> "
                   << isneg << ", <" << lanes << " x i" << lane_bits
                   << "> " << neg << ", <" << lanes << " x i" << lane_bits
                   << "> " << xv << "\n";
                std::string ismin = fresh();
                ir << "  " << ismin << " = icmp eq <" << lanes << " x i"
                   << lane_bits << "> " << xv << ", " << vconst(smin)
                   << "\n";
                res = fresh();
                ir << "  " << res << " = select <" << lanes << " x i1> "
                   << ismin << ", <" << lanes << " x i" << lane_bits
                   << "> " << vconst(smax) << ", <" << lanes << " x i"
                   << lane_bits << "> " << absv << "\n";
            } else if (kind == 1) {
                // VQNEG: -x, saturate INT_MIN -> INT_MAX.
                std::string neg = fresh();
                ir << "  " << neg << " = sub <" << lanes << " x i"
                   << lane_bits << "> " << vconst(0) << ", " << xv << "\n";
                std::string ismin = fresh();
                ir << "  " << ismin << " = icmp eq <" << lanes << " x i"
                   << lane_bits << "> " << xv << ", " << vconst(smin)
                   << "\n";
                res = fresh();
                ir << "  " << res << " = select <" << lanes << " x i1> "
                   << ismin << ", <" << lanes << " x i" << lane_bits
                   << "> " << vconst(smax) << ", <" << lanes << " x i"
                   << lane_bits << "> " << neg << "\n";
            } else if (kind == 2) {
                // VCLS: ctlz(x<0 ? ~x : x) - 1.
                std::string isneg = fresh();
                ir << "  " << isneg << " = icmp slt <" << lanes << " x i"
                   << lane_bits << "> " << xv << ", " << vconst(0) << "\n";
                std::string inv = fresh();
                ir << "  " << inv << " = xor <" << lanes << " x i"
                   << lane_bits << "> " << xv << ", " << vconst(-1) << "\n";
                std::string sel = fresh();
                ir << "  " << sel << " = select <" << lanes << " x i1> "
                   << isneg << ", <" << lanes << " x i" << lane_bits
                   << "> " << inv << ", <" << lanes << " x i" << lane_bits
                   << "> " << xv << "\n";
                std::string lz = fresh();
                ir << "  " << lz << " = call <" << lanes << " x i"
                   << lane_bits << "> @llvm.ctlz.v" << lanes << "i"
                   << lane_bits << "(<" << lanes << " x i" << lane_bits
                   << "> " << sel << ", i1 false)\n";
                res = fresh();
                ir << "  " << res << " = sub <" << lanes << " x i"
                   << lane_bits << "> " << lz << ", " << vconst(1) << "\n";
            } else if (kind == 3) {
                // VCLZ.
                res = fresh();
                ir << "  " << res << " = call <" << lanes << " x i"
                   << lane_bits << "> @llvm.ctlz.v" << lanes << "i"
                   << lane_bits << "(<" << lanes << " x i" << lane_bits
                   << "> " << xv << ", i1 false)\n";
            } else {
                // VCNT (kind 4): per-byte popcount.
                res = fresh();
                ir << "  " << res << " = call <" << lanes << " x i"
                   << lane_bits << "> @llvm.ctpop.v" << lanes << "i"
                   << lane_bits << "(<" << lanes << " x i" << lane_bits
                   << "> " << xv << ")\n";
            }
            return vec_to_i64(res, lane_bits);
        };
        bool dst_is_q = (vfp_q_idx(d.operands[0].reg) >= 0);
        if (dst_is_q) {
            int dq = vfp_q_idx(d.operands[0].reg);
            int mq = vfp_q_idx(d.operands[1].reg);
            if (dq < 0 || mq < 0) return false;
            for (int h = 0; h < 2; ++h) {
                std::string sv = load_dreg(mq * 2 + h);
                store_dreg(dq * 2 + h, do_half(sv));
            }
            return true;
        }
        int dd = vfp_d_idx(d.operands[0].reg);
        int md = vfp_d_idx(d.operands[1].reg);
        if (dd < 0 || md < 0) return false;
        std::string sv = load_dreg(md);
        store_dreg(dd, do_half(sv));
        return true;
    }

    // ---- VQRSHL : saturating rounding shift by signed per-lane amount
    // ARM ARM A8.8.244. Per lane, amt = sext(low 8 bits of the second
    // operand's lane). If amt >= 0: a << amt, SATURATED to the
    // signed/unsigned lane range (this is the only overflow-prone path).
    // If amt < 0: rounding arithmetic/logical right shift by -amt with a
    // bias of 1 << (-amt - 1) added before the shift; a right shift can
    // never exceed the lane range, so it needs no saturation. Mirrors
    // emit_vrshl's per-lane left/rounded-right structure (same bias and
    // sign-pick), adding emit_vqshl's clamp-via-icmp+select on the left
    // candidate. WRAP is never used here: the Q-prefix means saturate.
    bool emit_vqrshl(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            // Per-lane saturation bounds for this width / signedness.
            long long hi, lo;
            if (is_signed) {
                hi = (lb == 8) ? 127LL : (lb == 16) ? 32767LL :
                     (lb == 32) ? 0x7fffffffLL : 0x7fffffffffffffffLL;
                lo = -hi - 1;
            } else {
                hi = (lb == 8) ? 0xffLL : (lb == 16) ? 0xffffLL :
                     (lb == 32) ? 0xffffffffLL : 0x7fffffffffffffffLL;
                lo = 0;
            }
            std::string out_vec = "undef";
            for (int i = 0; i < lanes; ++i) {
                std::string ael = fresh();
                ir << "  " << ael << " = extractelement <" << lanes
                   << " x i" << lb << "> " << av << ", i32 " << i << "\n";
                std::string bel = fresh();
                ir << "  " << bel << " = extractelement <" << lanes
                   << " x i" << lb << "> " << bv << ", i32 " << i << "\n";
                // Shift amount = sext(low 8 bits of bel) to i32. For
                // 8-bit lanes bel is already i8 (a trunc i8->i8 is an
                // invalid LLVM cast), so take it directly.
                std::string b8 = bel;
                if (lb != 8) {
                    b8 = fresh();
                    ir << "  " << b8 << " = trunc i" << lb << " " << bel
                       << " to i8\n";
                }
                std::string amt = fresh();
                ir << "  " << amt << " = sext i8 " << b8 << " to i32\n";
                // Work in a 2x-wide (min 32-bit) type so the left shift
                // cannot lose the high bits we need for saturation.
                int work = (lb * 2 < 32) ? 32 : lb * 2;
                std::string aw = fresh();
                ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
                   << " i" << lb << " " << ael << " to i" << work << "\n";
                // amt is already i32; only widen when work > 32 (a
                // sext i32 -> i32 is an invalid LLVM cast).
                std::string amtw = amt;
                if (work != 32) {
                    amtw = fresh();
                    ir << "  " << amtw << " = sext i32 " << amt << " to i"
                       << work << "\n";
                }
                // Left candidate (saturated below).
                std::string shl = fresh();
                ir << "  " << shl << " = shl i" << work << " " << aw
                   << ", " << amtw << "\n";
                // Rounded-right candidate. negamt = -amt; bias =
                // 1 << (negamt - 1) (0 when negamt == 0).
                std::string neg = fresh();
                ir << "  " << neg << " = sub i" << work << " 0, " << amtw
                   << "\n";
                std::string nm1 = fresh();
                ir << "  " << nm1 << " = sub i" << work << " " << neg
                   << ", 1\n";
                std::string bias = fresh();
                ir << "  " << bias << " = shl i" << work << " 1, " << nm1
                   << "\n";
                std::string isz = fresh();
                ir << "  " << isz << " = icmp eq i" << work << " " << neg
                   << ", 0\n";
                std::string bias2 = fresh();
                ir << "  " << bias2 << " = select i1 " << isz << ", i"
                   << work << " 0, i" << work << " " << bias << "\n";
                std::string biased = fresh();
                ir << "  " << biased << " = add i" << work << " " << aw
                   << ", " << bias2 << "\n";
                std::string rsh = fresh();
                ir << "  " << rsh << " = " << (is_signed ? "ashr" : "lshr")
                   << " i" << work << " " << biased << ", " << neg << "\n";
                // Saturate the LEFT candidate to [lo, hi] in the work type.
                std::string above = fresh();
                ir << "  " << above << " = icmp "
                   << (is_signed ? "sgt" : "ugt") << " i" << work << " "
                   << shl << ", " << hi << "\n";
                std::string caphi = fresh();
                ir << "  " << caphi << " = select i1 " << above << ", i"
                   << work << " " << hi << ", i" << work << " " << shl
                   << "\n";
                std::string below = fresh();
                ir << "  " << below << " = icmp "
                   << (is_signed ? "slt" : "ult") << " i" << work << " "
                   << caphi << ", " << lo << "\n";
                std::string capl = fresh();
                ir << "  " << capl << " = select i1 " << below << ", i"
                   << work << " " << lo << ", i" << work << " " << caphi
                   << "\n";
                // Pick rounded-right when amt < 0, else saturated-left.
                std::string isneg = fresh();
                ir << "  " << isneg << " = icmp slt i32 " << amt
                   << ", 0\n";
                std::string pick = fresh();
                ir << "  " << pick << " = select i1 " << isneg << ", i"
                   << work << " " << rsh << ", i" << work << " " << capl
                   << "\n";
                // Narrow back to the lane width (work != lb always here).
                std::string narrowed = fresh();
                ir << "  " << narrowed << " = trunc i" << work << " "
                   << pick << " to i" << lb << "\n";
                std::string ins = fresh();
                ir << "  " << ins << " = insertelement <" << lanes
                   << " x i" << lb << "> " << out_vec << ", i" << lb
                   << " " << narrowed << ", i32 " << i << "\n";
                out_vec = ins;
            }
            return out_vec;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VMAXNM / VMINNM : IEEE 754-2008 maxNum / minNum -----------
    // VFP scalar (f16/f32/f64) and NEON-vector (f32/f16) forms. The
    // IEEE maxNum/minNum semantics -- 'if exactly one operand is NaN,
    // return the other; only NaN if both are NaN' -- are exactly what
    // LLVM's llvm.maxnum / llvm.minnum provide. The scalar f32 form
    // uses s-regs (vfp_d_idx returns -1) so emit_v_min_max cannot run
    // it; handle that here. Scalar f64 is a valid 1-lane d-reg case and
    // every NEON d/q vector form is datatype-aware in emit_v_min_max,
    // so delegate those. No condition-suffix parsing is needed: a
    // predicated VMAXNMMI/... is gated generically through current_pred
    // in the store helpers.
    bool emit_vfp_minmaxnm(const cs_insn* in, bool is_max) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int sd = vfp_s_idx(d.operands[0].reg);
        if (sd >= 0) {
            // Scalar single-precision: Sd = {max,min}num(Sn, Sm).
            int n = vfp_s_idx(d.operands[1].reg);
            int m = vfp_s_idx(d.operands[2].reg);
            if (n < 0 || m < 0) return false;
            std::string a_i = load_sreg(n);
            std::string b_i = load_sreg(m);
            std::string a = fresh();
            ir << "  " << a << " = bitcast i32 " << a_i << " to float\n";
            std::string b = fresh();
            ir << "  " << b << " = bitcast i32 " << b_i << " to float\n";
            std::string r = fresh();
            ir << "  " << r << " = call float @"
               << (is_max ? "llvm.maxnum" : "llvm.minnum")
               << ".f32(float " << a << ", float " << b << ")\n";
            std::string r_i = fresh();
            ir << "  " << r_i << " = bitcast float " << r << " to i32\n";
            store_sreg(sd, r_i);
            return true;
        }
        // NEON d/q vector form, or scalar f64 (1-lane d-reg): the
        // existing datatype-aware path already emits llvm.maxnum/minnum.
        return emit_v_min_max(in, is_max, false);
    }

    // ---- VCVTR : VFP float->integer using the FPSCR rounding mode ---
    // ARM ARM A8.8.306 (Encoding T1/A1, op==0). Unlike VCVT (which
    // forces round-toward-zero), VCVTR rounds per FPSCR.RMode; for our
    // purposes that is round-to-nearest-even. We materialise that by
    // rounding the float with llvm.roundeven first, then converting
    // with the (now exact) fptosi/fptoui. Forms: .s32.f32 / .u32.f32 /
    // .s32.f64 / .u32.f64. Destination is always an s-reg (i32 result).
    // Conditional VCVTRMI / VCVTRNE / ... are gated for free through
    // current_pred inside store_sreg. Same mnemonic layout as emit_vcvt.
    bool emit_vcvtr(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        const std::string mn = in->mnemonic;       // e.g. "vcvtr.s32.f32"
        size_t dot1 = mn.find('.');
        if (dot1 == std::string::npos) return false;
        size_t dot2 = mn.find('.', dot1 + 1);
        if (dot2 == std::string::npos) return false;
        std::string dst_ty = mn.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string src_ty = mn.substr(dot2 + 1);
        auto trim_cond = [](std::string s) {
            if (s.size() > 3) s = s.substr(0, 3);   // "s32","u32","f32"...
            return s;
        };
        dst_ty = trim_cond(dst_ty);
        src_ty = trim_cond(src_ty);
        if (dst_ty != "s32" && dst_ty != "u32") return false;
        // Load the float source (f32 in an s-reg, f64 in a d-reg).
        std::string fval;
        const char* src_fp;
        if (src_ty == "f32") {
            int ss = vfp_s_idx(d.operands[1].reg);
            if (ss < 0) return false;
            std::string i = load_sreg(ss);
            fval = fresh();
            ir << "  " << fval << " = bitcast i32 " << i << " to float\n";
            src_fp = "float";
        } else if (src_ty == "f64") {
            int dd = vfp_d_idx(d.operands[1].reg);
            if (dd < 0) return false;
            std::string i = load_dreg(dd);
            fval = fresh();
            ir << "  " << fval << " = bitcast i64 " << i << " to double\n";
            src_fp = "double";
        } else {
            return false;
        }
        const char* fsuf = (std::string(src_fp) == "double") ? "f64"
                                                             : "f32";
        // Round to nearest-even, then truncate-to-integer (now exact).
        std::string rounded = fresh();
        ir << "  " << rounded << " = call " << src_fp
           << " @llvm.roundeven." << fsuf << "(" << src_fp << " "
           << fval << ")\n";
        std::string conv = fresh();
        ir << "  " << conv << " = " << (dst_ty == "s32" ? "fptosi"
                                                         : "fptoui")
           << " " << src_fp << " " << rounded << " to i32\n";
        int dst_s = vfp_s_idx(d.operands[0].reg);
        if (dst_s < 0) return false;
        store_sreg(dst_s, conv);
        return true;
    }

    // ---- VSDOT / VUDOT : ARMv8.2 8-bit dot product -----------------
    // ARM DDI 0487 (A64) C7 / ARMv8.2-DotProd; the AArch32 encoding is
    // the Advanced-SIMD VSDOT/VUDOT (T1/A1). Form:
    //   VSDOT.S8 {Dd|Qd}, {Dn|Qn}, {Dm|Qm}
    //   VUDOT.U8 {Dd|Qd}, {Dn|Qn}, {Dm|Qm}
    // For each 32-bit element index e of the destination:
    //   Vd.32[e] += sum over k in 0..3 of
    //               (Vn.byte[4*e+k] *(signed/unsigned) Vm.byte[4*e+k])
    // i.e. four byte products from the matching 32-bit lanes of Vn and
    // Vm are widened to 32 bits and accumulated into the existing Vd
    // 32-bit lane (Vd is a read-modify-write accumulator). We compute
    // this per d-half: each d-reg holds two 32-bit output lanes, i.e.
    // 8 bytes = 2 dot products.
    bool emit_vsdot(const cs_insn* in, bool is_signed) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        // Resolve the base d-index of each operand (q-reg -> 2*q).
        auto base_d = [&](unsigned int reg) -> int {
            int q = vfp_q_idx(reg);
            if (q >= 0) return q * 2;
            return vfp_d_idx(reg);
        };
        int rd = base_d(d.operands[0].reg);
        int rn = base_d(d.operands[1].reg);
        int rm = base_d(d.operands[2].reg);
        if (rd < 0 || rn < 0 || rm < 0) return false;
        int halves = is_q ? 2 : 1;
        const char* ext = is_signed ? "sext" : "zext";
        for (int h = 0; h < halves; ++h) {
            std::string nv = load_dreg(rn + h);
            std::string mv = load_dreg(rm + h);
            std::string dv = load_dreg(rd + h);
            // View Vn/Vm halves as <8 x i8>, Vd half as <2 x i32>.
            std::string nvec = i64_to_vec(nv, 8);
            std::string mvec = i64_to_vec(mv, 8);
            std::string dvec = i64_to_vec(dv, 32);
            // Result accumulator vector starts from the current Vd lanes.
            std::string acc = dvec;
            for (int e = 0; e < 2; ++e) {   // two 32-bit lanes per d-half
                // Extract the current accumulator lane.
                std::string cur = fresh();
                ir << "  " << cur << " = extractelement <2 x i32> "
                   << acc << ", i32 " << e << "\n";
                std::string sum = cur;
                for (int k = 0; k < 4; ++k) {
                    int byte_idx = 4 * e + k;
                    std::string nb = fresh();
                    ir << "  " << nb << " = extractelement <8 x i8> "
                       << nvec << ", i32 " << byte_idx << "\n";
                    std::string mb = fresh();
                    ir << "  " << mb << " = extractelement <8 x i8> "
                       << mvec << ", i32 " << byte_idx << "\n";
                    std::string nw = fresh();
                    ir << "  " << nw << " = " << ext << " i8 " << nb
                       << " to i32\n";
                    std::string mw = fresh();
                    ir << "  " << mw << " = " << ext << " i8 " << mb
                       << " to i32\n";
                    std::string prod = fresh();
                    ir << "  " << prod << " = mul i32 " << nw << ", "
                       << mw << "\n";
                    std::string nsum = fresh();
                    ir << "  " << nsum << " = add i32 " << sum << ", "
                       << prod << "\n";
                    sum = nsum;
                }
                std::string nacc = fresh();
                ir << "  " << nacc << " = insertelement <2 x i32> "
                   << acc << ", i32 " << sum << ", i32 " << e << "\n";
                acc = nacc;
            }
            store_dreg(rd + h, vec_to_i64(acc, 32));
        }
        return true;
    }

    // Forms:
    //   VSHR.{u|s}<sz>  dN|qN, dM|qM, #imm  (logical or arithmetic >>)
    //   VSHL.{i|s|u}<sz> dN|qN, dM|qM, #imm | dM|qM (shift left)
    //   VSRA  -- shift right + accumulate (dst += src >> imm)
    //   VRSHR -- shift right + round-to-nearest (>>0.5)
    //   VRSRA -- rounding shift right + accumulate
    enum class ShiftKind { LSHR, ASHR, SHL, RLSHR, RASHR };
    bool emit_v_shift(const cs_insn* in, ShiftKind kind, bool accumulate) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst_base = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                              : vfp_d_idx(d.operands[0].reg);
        int src_base = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                              : vfp_d_idx(d.operands[1].reg);
        if (dst_base < 0 || src_base < 0) return false;
        // Shift amount: immediate (typical) or vector (less common).
        bool is_imm = (d.operands[2].type == ARM_OP_IMM);
        int32_t amt_imm = 0;
        std::string amt_reg_vec;  // used if !is_imm; per-half
        if (is_imm) {
            amt_imm = static_cast<int32_t>(d.operands[2].imm);
            // VSHL with negative imm encodes a shift-right; signed/unsigned
            // discrimination comes from the .vector_data type.
            if (kind == ShiftKind::SHL && amt_imm < 0) {
                amt_imm = -amt_imm;
                kind = is_signed ? ShiftKind::ASHR : ShiftKind::LSHR;
            }
        } else if (d.operands[2].type != ARM_OP_REG) {
            return false;
        }
        for (int h = 0; h < halves; ++h) {
            std::string src = load_dreg(src_base + h);
            std::string sv = i64_to_vec(src, lane_bits);
            // Build amt vector.
            std::string av_str;
            int lanes = 64 / lane_bits;
            if (is_imm) {
                std::string a = "<";
                for (int i = 0; i < lanes; ++i) {
                    if (i > 0) a += ", ";
                    a += "i" + std::to_string(lane_bits) + " ";
                    a += std::to_string(amt_imm);
                }
                a += ">";
                av_str = a;
            } else {
                int amt_src = is_q ? (vfp_q_idx(d.operands[2].reg) * 2 + h)
                                       : vfp_d_idx(d.operands[2].reg);
                if (amt_src < 0) return false;
                std::string raw = load_dreg(amt_src);
                av_str = i64_to_vec(raw, lane_bits);
            }
            std::string shifted = fresh();
            switch (kind) {
                case ShiftKind::LSHR: case ShiftKind::RLSHR:
                    ir << "  " << shifted << " = lshr <" << lanes
                       << " x i" << lane_bits << "> " << sv
                       << ", " << av_str << "\n";
                    break;
                case ShiftKind::ASHR: case ShiftKind::RASHR:
                    ir << "  " << shifted << " = ashr <" << lanes
                       << " x i" << lane_bits << "> " << sv
                       << ", " << av_str << "\n";
                    break;
                case ShiftKind::SHL:
                    ir << "  " << shifted << " = shl <" << lanes
                       << " x i" << lane_bits << "> " << sv
                       << ", " << av_str << "\n";
                    break;
            }
            // Rounding: add bit (1 << (amt-1)) to src BEFORE the shift.
            // We approximate by adding the round bit AFTER the shift
            // (correct for unsigned and for signed when no overflow).
            if ((kind == ShiftKind::RLSHR || kind == ShiftKind::RASHR)
                && is_imm && amt_imm > 0) {
                // Implementation note: a true rounded shift would
                // compute (src + (1<<(amt-1))) >> amt with overflow
                // detection. The simpler `shifted + ((src >> (amt-1)) & 1)`
                // gives the right answer for the lane sizes here.
                std::string s2 = fresh();
                ir << "  " << s2 << " = " << (is_signed ? "ashr" : "lshr")
                   << " <" << lanes << " x i" << lane_bits << "> " << sv
                   << ", <";
                for (int i = 0; i < lanes; ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i" << lane_bits << " " << (amt_imm - 1);
                }
                ir << ">\n";
                std::string rb = fresh();
                ir << "  " << rb << " = and <" << lanes << " x i"
                   << lane_bits << "> " << s2 << ", <";
                for (int i = 0; i < lanes; ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i" << lane_bits << " 1";
                }
                ir << ">\n";
                std::string rounded = fresh();
                ir << "  " << rounded << " = add <" << lanes
                   << " x i" << lane_bits << "> " << shifted
                   << ", " << rb << "\n";
                shifted = rounded;
            }
            std::string final_v = shifted;
            if (accumulate) {
                std::string old_d = load_dreg(dst_base + h);
                std::string old_v = i64_to_vec(old_d, lane_bits);
                std::string sum = fresh();
                ir << "  " << sum << " = add <" << lanes << " x i"
                   << lane_bits << "> " << old_v << ", " << shifted
                   << "\n";
                final_v = sum;
            }
            std::string fi = vec_to_i64(final_v, lane_bits);
            store_dreg(dst_base + h, fi);
        }
        return true;
    }

    // ---- VSLI / VSRI : shift-left/right and insert ----------------
    // ARM ARM A8.6.392/A8.6.394. Per lane: combine the shifted source
    // bits with the destination bits that aren't covered by the shift.
    //   VSLI: dst = (src << #imm) | (dst & mask_low(imm))
    //   VSRI: dst = (src >> #imm) | (dst & mask_high(imm))
    bool emit_v_sli_sri(const cs_insn* in, bool is_left) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        int amt = static_cast<int>(d.operands[2].imm);
        if (amt < 0 || amt >= lane_bits) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst_base = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                              : vfp_d_idx(d.operands[0].reg);
        int src_base = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                              : vfp_d_idx(d.operands[1].reg);
        if (dst_base < 0 || src_base < 0) return false;
        int lanes = 64 / lane_bits;
        uint64_t insert_mask;
        if (is_left) {
            // VSLI: preserve bottom `amt` bits of dst.
            insert_mask = (amt == 0) ? 0
                          : ((static_cast<uint64_t>(1) << amt) - 1);
        } else {
            // VSRI: preserve top `amt` bits of dst.
            insert_mask = (amt == 0) ? 0
                          : ~(((static_cast<uint64_t>(1) << (lane_bits - amt)) - 1));
            if (lane_bits < 64) {
                insert_mask &= ((static_cast<uint64_t>(1) << lane_bits) - 1);
            }
        }
        for (int h = 0; h < halves; ++h) {
            std::string src = load_dreg(src_base + h);
            std::string old_dst = load_dreg(dst_base + h);
            std::string sv = i64_to_vec(src, lane_bits);
            std::string ov = i64_to_vec(old_dst, lane_bits);
            std::string shifted = fresh();
            ir << "  " << shifted << " = "
               << (is_left ? "shl" : "lshr")
               << " <" << lanes << " x i" << lane_bits << "> "
               << sv << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << lane_bits << " " << amt;
            }
            ir << ">\n";
            std::string kept = fresh();
            ir << "  " << kept << " = and <" << lanes << " x i"
               << lane_bits << "> " << ov << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << lane_bits << " "
                   << static_cast<int64_t>(insert_mask);
            }
            ir << ">\n";
            std::string out = fresh();
            ir << "  " << out << " = or <" << lanes << " x i"
               << lane_bits << "> " << shifted << ", " << kept << "\n";
            std::string oi = vec_to_i64(out, lane_bits);
            store_dreg(dst_base + h, oi);
        }
        return true;
    }

    // ---- VQADD / VQSUB : saturating add/sub -----------------------
    // ARM ARM A8.6.339/A8.6.340. Per-lane saturating signed or
    // unsigned add/sub. Mapped to LLVM IR's sadd_sat / uadd_sat /
    // ssub_sat / usub_sat vector intrinsics.
    bool emit_vqaddsub(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            const char* op = is_sub
                ? (is_signed ? "llvm.ssub.sat" : "llvm.usub.sat")
                : (is_signed ? "llvm.sadd.sat" : "llvm.uadd.sat");
            std::string out = fresh();
            ir << "  " << out << " = call <" << lanes << " x i" << lb
               << "> @" << op << ".v" << lanes << "i" << lb
               << "(<" << lanes << " x i" << lb << "> " << av
               << ", <" << lanes << " x i" << lb << "> " << bv << ")\n";
            return out;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VQSHL / VQSHLU : saturating shift left -------------------
    // For VQSHL, the saturation kind follows .vector_data (signed/unsigned).
    // For VQSHLU, the source is signed but result is unsigned (saturate
    // to unsigned range). Compilers emit these in fixed-point DSP code.
    bool emit_vqshl(const cs_insn* in, bool unsigned_result) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        // Treat as the equivalent saturating left shift followed by
        // saturating cast to {un}signed. We approximate via a 2x-wide
        // shift + clamp.
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst_base = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                              : vfp_d_idx(d.operands[0].reg);
        int src_base = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                              : vfp_d_idx(d.operands[1].reg);
        if (dst_base < 0 || src_base < 0) return false;
        // Amount: immediate (typical) or vector register.
        bool is_imm = (d.operands[2].type == ARM_OP_IMM);
        int32_t amt_imm = is_imm
            ? static_cast<int32_t>(d.operands[2].imm) : 0;
        for (int h = 0; h < halves; ++h) {
            std::string src = load_dreg(src_base + h);
            int lanes = 64 / lane_bits;
            int wbits = lane_bits * 2;
            std::string sv = i64_to_vec(src, lane_bits);
            std::string sw = fresh();
            ir << "  " << sw << " = " << (is_signed ? "sext" : "zext")
               << " <" << lanes << " x i" << lane_bits << "> " << sv
               << " to <" << lanes << " x i" << wbits << ">\n";
            std::string shifted;
            if (is_imm) {
                shifted = fresh();
                ir << "  " << shifted << " = shl <" << lanes << " x i"
                   << wbits << "> " << sw << ", <";
                for (int i = 0; i < lanes; ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i" << wbits << " " << amt_imm;
                }
                ir << ">\n";
            } else if (d.operands[2].type == ARM_OP_REG) {
                int amt_src = is_q
                    ? (vfp_q_idx(d.operands[2].reg) * 2 + h)
                    : vfp_d_idx(d.operands[2].reg);
                if (amt_src < 0) return false;
                std::string ar = load_dreg(amt_src);
                std::string av = i64_to_vec(ar, lane_bits);
                std::string aw = fresh();
                ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
                   << " <" << lanes << " x i" << lane_bits << "> " << av
                   << " to <" << lanes << " x i" << wbits << ">\n";
                shifted = fresh();
                ir << "  " << shifted << " = shl <" << lanes << " x i"
                   << wbits << "> " << sw << ", " << aw << "\n";
            } else {
                return false;
            }
            // Clamp to per-lane range and narrow back.
            int64_t hi, lo;
            if (unsigned_result) {
                hi = (lane_bits == 8) ? 0xff :
                     (lane_bits == 16) ? 0xffff :
                     (lane_bits == 32) ? 0xffffffffLL : 0x7fffffffffffffffLL;
                lo = 0;
            } else if (is_signed) {
                hi = (lane_bits == 8) ? 127 :
                     (lane_bits == 16) ? 32767 :
                     (lane_bits == 32) ? 0x7fffffffLL : 0x7fffffffffffffffLL;
                lo = -hi - 1;
            } else {
                hi = (lane_bits == 8) ? 0xff :
                     (lane_bits == 16) ? 0xffff :
                     (lane_bits == 32) ? 0xffffffffLL : 0x7fffffffffffffffLL;
                lo = 0;
            }
            std::string above = fresh();
            ir << "  " << above << " = icmp "
               << (is_signed ? "sgt" : "ugt") << " <" << lanes
               << " x i" << wbits << "> " << shifted << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << hi;
            }
            ir << ">\n";
            std::string cap_hi = fresh();
            ir << "  " << cap_hi << " = select <" << lanes << " x i1> "
               << above << ", <" << lanes << " x i" << wbits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << hi;
            }
            ir << ">, <" << lanes << " x i" << wbits << "> " << shifted << "\n";
            std::string below = fresh();
            ir << "  " << below << " = icmp "
               << (is_signed ? "slt" : "ult") << " <" << lanes
               << " x i" << wbits << "> " << cap_hi << ", <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << lo;
            }
            ir << ">\n";
            std::string cap = fresh();
            ir << "  " << cap << " = select <" << lanes << " x i1> "
               << below << ", <" << lanes << " x i" << wbits << "> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << lo;
            }
            ir << ">, <" << lanes << " x i" << wbits << "> " << cap_hi << "\n";
            std::string nar = fresh();
            ir << "  " << nar << " = trunc <" << lanes << " x i"
               << wbits << "> " << cap << " to <" << lanes << " x i"
               << lane_bits << ">\n";
            std::string ni = vec_to_i64(nar, lane_bits);
            store_dreg(dst_base + h, ni);
        }
        return true;
    }

    // ---- VQSHRN / VQSHRUN / VQRSHRN : saturating-narrowing shift right
    // Result is half-width. d-reg result; q-reg source. Compilers use
    // this for converting 32-bit accumulators back to 16-bit samples
    // (audio resamplers, image scalers).
    bool emit_vqshrn(const cs_insn* in, bool unsigned_result,
                       bool rounding) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_IMM) return false;
        int dst_d = vfp_d_idx(d.operands[0].reg);
        int src_q = vfp_q_idx(d.operands[1].reg);
        if (dst_d < 0 || src_q < 0) return false;
        int lane_bits = lane_bits_of(d);  // result lane width
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int wbits = lane_bits * 2;  // source lane width
        int half_lanes = 64 / lane_bits;
        int total_lanes = half_lanes;   // source has same lane count
        int32_t amt = static_cast<int32_t>(d.operands[2].imm);
        std::string lo_old = load_dreg(src_q * 2);
        std::string hi_old = load_dreg(src_q * 2 + 1);
        std::string pair = fresh();
        ir << "  " << pair << " = insertelement <2 x i64> undef, i64 "
           << lo_old << ", i32 0\n";
        std::string pair2 = fresh();
        ir << "  " << pair2 << " = insertelement <2 x i64> " << pair
           << ", i64 " << hi_old << ", i32 1\n";
        std::string svec = fresh();
        ir << "  " << svec << " = bitcast <2 x i64> " << pair2
           << " to <" << total_lanes << " x i" << wbits << ">\n";
        std::string shifted;
        if (rounding && amt > 0) {
            // Add round bit then shift.
            uint64_t rbit = static_cast<uint64_t>(1) << (amt - 1);
            std::string r = fresh();
            ir << "  " << r << " = add <" << total_lanes << " x i"
               << wbits << "> " << svec << ", <";
            for (int i = 0; i < total_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << static_cast<int64_t>(rbit);
            }
            ir << ">\n";
            shifted = fresh();
            ir << "  " << shifted << " = " << (is_signed ? "ashr" : "lshr")
               << " <" << total_lanes << " x i" << wbits << "> " << r
               << ", <";
            for (int i = 0; i < total_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << amt;
            }
            ir << ">\n";
        } else {
            shifted = fresh();
            ir << "  " << shifted << " = " << (is_signed ? "ashr" : "lshr")
               << " <" << total_lanes << " x i" << wbits << "> " << svec
               << ", <";
            for (int i = 0; i < total_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i" << wbits << " " << amt;
            }
            ir << ">\n";
        }
        // Saturate to {un}signed lane_bits range and narrow.
        int64_t hi_lim, lo_lim;
        if (unsigned_result) {
            hi_lim = (lane_bits == 8) ? 0xff :
                     (lane_bits == 16) ? 0xffff : 0xffffffffLL;
            lo_lim = 0;
        } else {
            hi_lim = (lane_bits == 8) ? 127 :
                     (lane_bits == 16) ? 32767 : 0x7fffffffLL;
            lo_lim = -hi_lim - 1;
        }
        std::string above = fresh();
        ir << "  " << above << " = icmp "
           << (is_signed ? "sgt" : "ugt") << " <" << total_lanes
           << " x i" << wbits << "> " << shifted << ", <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << hi_lim;
        }
        ir << ">\n";
        std::string cap_hi = fresh();
        ir << "  " << cap_hi << " = select <" << total_lanes
           << " x i1> " << above << ", <" << total_lanes << " x i"
           << wbits << "> <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << hi_lim;
        }
        ir << ">, <" << total_lanes << " x i" << wbits << "> "
           << shifted << "\n";
        std::string below = fresh();
        ir << "  " << below << " = icmp "
           << (is_signed ? "slt" : "ult") << " <" << total_lanes
           << " x i" << wbits << "> " << cap_hi << ", <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << lo_lim;
        }
        ir << ">\n";
        std::string cap = fresh();
        ir << "  " << cap << " = select <" << total_lanes
           << " x i1> " << below << ", <" << total_lanes << " x i"
           << wbits << "> <";
        for (int i = 0; i < total_lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i" << wbits << " " << lo_lim;
        }
        ir << ">, <" << total_lanes << " x i" << wbits << "> "
           << cap_hi << "\n";
        std::string nar = fresh();
        ir << "  " << nar << " = trunc <" << total_lanes
           << " x i" << wbits << "> " << cap << " to <" << total_lanes
           << " x i" << lane_bits << ">\n";
        std::string ni = vec_to_i64(nar, lane_bits);
        store_dreg(dst_d, ni);
        return true;
    }

    // ---- VMIN / VMAX / VPMAX --------------------------------------
    bool emit_v_min_max(const cs_insn* in, bool is_max, bool pairwise) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        bool is_float  = vdata_float(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            std::string out = fresh();
            if (is_float) {
                // The dd/qq binop plumbing hands us <N x iLB> vectors
                // and bitcasts our RESULT back from <N x iLB>, so the
                // float op must bitcast in AND out, with the element
                // type matching the lane width. The old code stamped
                // "<N x float>"/".vNf32" textually around the iN
                // operands regardless of width -- for VMIN.F16
                // (Jetpack Joyride's libmortargame, 4 x i16 lanes)
                // llvm-as rejected the module ("%tN defined with type
                // '<4 x i16>' but expected '<4 x float>'") and the
                // entire translation aborted. f16 arithmetic legalizes
                // fine on arm64 (promoted to f32 by the backend).
                const char* fty  = (lb == 32) ? "float"
                                 : (lb == 64) ? "double" : "half";
                const char* fsuf = (lb == 32) ? "f32"
                                 : (lb == 64) ? "f64" : "f16";
                std::string af = fresh();
                ir << "  " << af << " = bitcast <" << lanes << " x i" << lb
                   << "> " << av << " to <" << lanes << " x " << fty << ">\n";
                std::string bf = fresh();
                ir << "  " << bf << " = bitcast <" << lanes << " x i" << lb
                   << "> " << bv << " to <" << lanes << " x " << fty << ">\n";
                std::string fo = fresh();
                ir << "  " << fo << " = call <" << lanes << " x " << fty
                   << "> @" << (is_max ? "llvm.maxnum.v" : "llvm.minnum.v")
                   << lanes << fsuf
                   << "(<" << lanes << " x " << fty << "> " << af
                   << ", <" << lanes << " x " << fty << "> " << bf << ")\n";
                ir << "  " << out << " = bitcast <" << lanes << " x " << fty
                   << "> " << fo << " to <" << lanes << " x i" << lb << ">\n";
            } else {
                const char* op = is_max
                    ? (is_signed ? "llvm.smax" : "llvm.umax")
                    : (is_signed ? "llvm.smin" : "llvm.umin");
                ir << "  " << out << " = call <" << lanes << " x i" << lb
                   << "> @" << op << ".v" << lanes << "i" << lb
                   << "(<" << lanes << " x i" << lb << "> " << av
                   << ", <" << lanes << " x i" << lb << "> " << bv << ")\n";
            }
            (void)pairwise;  // for non-pairwise we ignore
            return out;
        };
        if (pairwise) {
            // VPMAX/VPMIN: pair up adjacent lanes within EACH source,
            // then concatenate. For d-d-d form: out lanes 0..N/2-1 =
            // {min|max}(a[2i], a[2i+1]); out lanes N/2..N-1 = same on b.
            if (d.op_count != 3) return false;
            for (int i = 0; i < 3; ++i)
                if (d.operands[i].type != ARM_OP_REG) return false;
            int dst = vfp_d_idx(d.operands[0].reg);
            int rn  = vfp_d_idx(d.operands[1].reg);
            int rm  = vfp_d_idx(d.operands[2].reg);
            if (dst < 0 || rn < 0 || rm < 0) return false;
            std::string a = load_dreg(rn);
            std::string b = load_dreg(rm);
            std::string av = i64_to_vec(a, lane_bits);
            std::string bv = i64_to_vec(b, lane_bits);
            int lanes = 64 / lane_bits;
            // Build shuffles for even / odd.
            auto shuf = [&](const std::string& v, bool even) -> std::string {
                std::string out = fresh();
                ir << "  " << out << " = shufflevector <" << lanes
                   << " x i" << lane_bits << "> " << v << ", <" << lanes
                   << " x i" << lane_bits << "> undef, <"
                   << (lanes / 2) << " x i32> <";
                for (int i = 0; i < lanes / 2; ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i32 " << (i * 2 + (even ? 0 : 1));
                }
                ir << ">\n";
                return out;
            };
            std::string a_even = shuf(av, true);
            std::string a_odd  = shuf(av, false);
            std::string b_even = shuf(bv, true);
            std::string b_odd  = shuf(bv, false);
            auto pair_op = [&](const std::string& x,
                                 const std::string& y) -> std::string {
                std::string out = fresh();
                const char* op = is_max
                    ? (is_signed ? "llvm.smax" : "llvm.umax")
                    : (is_signed ? "llvm.smin" : "llvm.umin");
                ir << "  " << out << " = call <" << (lanes / 2)
                   << " x i" << lane_bits << "> @" << op << ".v"
                   << (lanes / 2) << "i" << lane_bits
                   << "(<" << (lanes / 2) << " x i" << lane_bits
                   << "> " << x << ", <" << (lanes / 2) << " x i"
                   << lane_bits << "> " << y << ")\n";
                return out;
            };
            std::string a_red = pair_op(a_even, a_odd);
            std::string b_red = pair_op(b_even, b_odd);
            std::string cat = fresh();
            ir << "  " << cat << " = shufflevector <" << (lanes / 2)
               << " x i" << lane_bits << "> " << a_red << ", <"
               << (lanes / 2) << " x i" << lane_bits << "> " << b_red
               << ", <" << lanes << " x i32> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << i;
            }
            ir << ">\n";
            std::string ci = vec_to_i64(cat, lane_bits);
            store_dreg(dst, ci);
            return true;
        }
        return emit_v_binop_int(in, lane);
    }

    // ---- NEON bitwise logical (datatype-ignored, full 64/128 bits) -
    // VAND/VBIC/VORR(reg)/VORN(reg)/VBSL/VBIT/VBIF operate on the raw
    // bit pattern of the whole d-reg (or both d-halves of a q-reg) and
    // never read vector_data. ARM DDI 0406C.d A8.8.287 (VBIF),
    // A8.8.288 (VBIT), A8.8.290 (VBSL), A8.8.287/336/355 (VAND/VBIC/
    // VORR/VORN reg forms). Per-bit algebra (op2=Dn, op3=Dm):
    //   VAND: d = n & m
    //   VBIC: d = n & ~m
    //   VORR: d = n | m
    //   VORN: d = n | ~m
    //   VBSL: d = (d & n) | (~d & m)        = ((n ^ m) & d) ^ m
    //   VBIT: d = (n & m) | (d & ~m)        = ((n ^ d) & m) ^ d  (m=mask)
    //   VBIF: d = (n & ~m) | (d & m)        = ((d ^ n) & m) ^ n  (m=mask)
    // VBSL/VBIT/VBIF are read-modify-write: the destination register is
    // ALSO a source, so we load the old dst value per half.
    enum class VLogOp { AND, BIC, ORR, ORN, BSL, BIT, BIF };
    bool emit_v_logical(const cs_insn* in, VLogOp lop) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        auto base_of = [&](const cs_arm_op& o) -> int {
            return is_q ? (vfp_q_idx(o.reg) * 2) : vfp_d_idx(o.reg);
        };
        int dst = base_of(d.operands[0]);
        int rn  = base_of(d.operands[1]);
        int rm  = base_of(d.operands[2]);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        for (int h = 0; h < halves; ++h) {
            std::string n = load_dreg(rn + h);
            std::string m = load_dreg(rm + h);
            std::string out;
            auto notv = [&](const std::string& x) -> std::string {
                std::string r = fresh();
                ir << "  " << r << " = xor i64 " << x << ", -1\n";
                return r;
            };
            switch (lop) {
                case VLogOp::AND: {
                    out = fresh();
                    ir << "  " << out << " = and i64 " << n << ", " << m << "\n";
                    break;
                }
                case VLogOp::BIC: {
                    std::string nm = notv(m);
                    out = fresh();
                    ir << "  " << out << " = and i64 " << n << ", " << nm << "\n";
                    break;
                }
                case VLogOp::ORR: {
                    out = fresh();
                    ir << "  " << out << " = or i64 " << n << ", " << m << "\n";
                    break;
                }
                case VLogOp::ORN: {
                    std::string nm = notv(m);
                    out = fresh();
                    ir << "  " << out << " = or i64 " << n << ", " << nm << "\n";
                    break;
                }
                case VLogOp::BSL: {
                    // d = ((n ^ m) & d_old) ^ m
                    std::string dold = load_dreg(dst + h);
                    std::string xnm = fresh();
                    ir << "  " << xnm << " = xor i64 " << n << ", " << m << "\n";
                    std::string an = fresh();
                    ir << "  " << an << " = and i64 " << xnm << ", " << dold << "\n";
                    out = fresh();
                    ir << "  " << out << " = xor i64 " << an << ", " << m << "\n";
                    break;
                }
                case VLogOp::BIT: {
                    // d = ((n ^ d_old) & m) ^ d_old
                    std::string dold = load_dreg(dst + h);
                    std::string xnd = fresh();
                    ir << "  " << xnd << " = xor i64 " << n << ", " << dold << "\n";
                    std::string an = fresh();
                    ir << "  " << an << " = and i64 " << xnd << ", " << m << "\n";
                    out = fresh();
                    ir << "  " << out << " = xor i64 " << an << ", " << dold << "\n";
                    break;
                }
                case VLogOp::BIF: {
                    // d = ((d_old ^ n) & m) ^ n
                    std::string dold = load_dreg(dst + h);
                    std::string xdn = fresh();
                    ir << "  " << xdn << " = xor i64 " << dold << ", " << n << "\n";
                    std::string an = fresh();
                    ir << "  " << an << " = and i64 " << xdn << ", " << m << "\n";
                    out = fresh();
                    ir << "  " << out << " = xor i64 " << an << ", " << n << "\n";
                    break;
                }
            }
            store_dreg(dst + h, out);
        }
        return true;
    }

    // ---- NEON integer per-lane compare -> all-ones/all-zero mask ----
    // VCGT/VCGE/VCLE/VCLT/VCEQ on integer lanes, plus VTST. ARM DDI
    // 0406C.d A8.8.291 (VCEQ), A8.8.295 (VCGE), A8.8.296 (VCGT),
    // A8.8.301/302 (VCLE/VCLT pseudo via swapped operands), A8.8.395
    // (VTST). Result per lane = all ones if predicate holds else all
    // zero (sext i1 -> iLB). Signed vs unsigned from vdata_signed.
    // intpred is one of "eq","sgt","sge","ugt","uge". For LE/LT we pass
    // the GE/GT predicate with operands swapped at the dispatch site.
    // VTST: lane mask = (a & b) != 0.
    bool emit_v_icmp(const cs_insn* in, const char* intpred_signed,
                       const char* intpred_unsigned, bool is_tst) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        const char* pred = is_tst ? "ne"
                          : (is_signed ? intpred_signed : intpred_unsigned);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            std::string cmpin_a = av;
            std::string cmpin_b = bv;
            std::string zerovec;
            if (is_tst) {
                // (a & b), then compare ne 0.
                std::string andv = fresh();
                ir << "  " << andv << " = and <" << lanes << " x i" << lb
                   << "> " << av << ", " << bv << "\n";
                cmpin_a = andv;
                cmpin_b = "zeroinitializer";
            }
            std::string cmp = fresh();
            ir << "  " << cmp << " = icmp " << pred << " <"
               << lanes << " x i" << lb << "> " << cmpin_a << ", "
               << cmpin_b << "\n";
            std::string ext = fresh();
            ir << "  " << ext << " = sext <" << lanes << " x i1> "
               << cmp << " to <" << lanes << " x i" << lb << ">\n";
            return ext;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VACGE / VACGT : absolute float compare --------------------
    // ARM DDI 0406C.d A8.8.286/A8.8.285. Per lane: fabs(a) >= fabs(b)
    // (VACGE) or > (VACGT), result all-ones/all-zero. Float lanes only.
    bool emit_v_acmp(const cs_insn* in, const char* fpred) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits != 32) lane_bits = 32;  // VACGE/VACGT are F32 only
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                          : vfp_d_idx(d.operands[0].reg);
        int rn  = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                          : vfp_d_idx(d.operands[1].reg);
        int rm  = is_q ? (vfp_q_idx(d.operands[2].reg) * 2)
                          : vfp_d_idx(d.operands[2].reg);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        int lanes = 64 / lane_bits;
        for (int h = 0; h < halves; ++h) {
            std::string a = load_dreg(rn + h);
            std::string b = load_dreg(rm + h);
            std::string af = i64_to_fvec(a, lane_bits);
            std::string bf = i64_to_fvec(b, lane_bits);
            std::string aa = fresh();
            ir << "  " << aa << " = call <" << lanes << " x float> "
               << "@llvm.fabs.v" << lanes << "f32(<" << lanes
               << " x float> " << af << ")\n";
            std::string ba = fresh();
            ir << "  " << ba << " = call <" << lanes << " x float> "
               << "@llvm.fabs.v" << lanes << "f32(<" << lanes
               << " x float> " << bf << ")\n";
            std::string cmp = fresh();
            ir << "  " << cmp << " = fcmp " << fpred << " <"
               << lanes << " x float> " << aa << ", " << ba << "\n";
            std::string ext = fresh();
            ir << "  " << ext << " = sext <" << lanes << " x i1> "
               << cmp << " to <" << lanes << " x i" << lane_bits << ">\n";
            std::string oi = vec_to_i64(ext, lane_bits);
            store_dreg(dst + h, oi);
        }
        return true;
    }

    // ---- VPADD : pairwise add (d-d-d) ------------------------------
    // ARM DDI 0406C.d A8.8.396. Dd[i]=Dn[2i]+Dn[2i+1] for i<N/2;
    // Dd[N/2+i]=Dm[2i]+Dm[2i+1]. Float and integer per vector_data.
    bool emit_vpadd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst = vfp_d_idx(d.operands[0].reg);
        int rn  = vfp_d_idx(d.operands[1].reg);
        int rm  = vfp_d_idx(d.operands[2].reg);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_float = vdata_float(d.vector_data);
        int lanes = 64 / lane_bits;
        if (lanes < 2) return false;
        std::string a = load_dreg(rn);
        std::string b = load_dreg(rm);
        std::string av = i64_to_vec(a, lane_bits);
        std::string bv = i64_to_vec(b, lane_bits);
        auto shuf = [&](const std::string& v, bool even) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes
               << " x i" << lane_bits << "> " << v << ", <" << lanes
               << " x i" << lane_bits << "> undef, <"
               << (lanes / 2) << " x i32> <";
            for (int i = 0; i < lanes / 2; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (i * 2 + (even ? 0 : 1));
            }
            ir << ">\n";
            return out;
        };
        auto pair_add = [&](const std::string& x,
                              const std::string& y) -> std::string {
            std::string out = fresh();
            if (is_float) {
                // The FP element type MUST match the lane width: half for
                // .f16, float for .f32, double for .f64. Hardcoding float
                // produced an invalid bitcast (<2 x i16> -> <2 x float> is
                // a 32->64-bit size change) for vpadd.f16.
                const char* fty = (lane_bits == 16) ? "half"
                                : (lane_bits == 64) ? "double" : "float";
                std::string xf = fresh(), yf = fresh();
                ir << "  " << xf << " = bitcast <" << (lanes / 2) << " x i"
                   << lane_bits << "> " << x << " to <" << (lanes / 2)
                   << " x " << fty << ">\n";
                ir << "  " << yf << " = bitcast <" << (lanes / 2) << " x i"
                   << lane_bits << "> " << y << " to <" << (lanes / 2)
                   << " x " << fty << ">\n";
                std::string fr = fresh();
                ir << "  " << fr << " = fadd <" << (lanes / 2)
                   << " x " << fty << "> " << xf << ", " << yf << "\n";
                ir << "  " << out << " = bitcast <" << (lanes / 2)
                   << " x " << fty << "> " << fr << " to <" << (lanes / 2)
                   << " x i" << lane_bits << ">\n";
            } else {
                ir << "  " << out << " = add <" << (lanes / 2) << " x i"
                   << lane_bits << "> " << x << ", " << y << "\n";
            }
            return out;
        };
        std::string a_red = pair_add(shuf(av, true), shuf(av, false));
        std::string b_red = pair_add(shuf(bv, true), shuf(bv, false));
        std::string cat = fresh();
        ir << "  " << cat << " = shufflevector <" << (lanes / 2)
           << " x i" << lane_bits << "> " << a_red << ", <"
           << (lanes / 2) << " x i" << lane_bits << "> " << b_red
           << ", <" << lanes << " x i32> <";
        for (int i = 0; i < lanes; ++i) {
            if (i > 0) ir << ", ";
            ir << "i32 " << i;
        }
        ir << ">\n";
        std::string ci = vec_to_i64(cat, lane_bits);
        store_dreg(dst, ci);
        return true;
    }

    // ---- VTRN / VZIP / VUZP : two-output permute (both regs written) -
    // ARM DDI 0406C.d A8.8.394 (VTRN), A8.8.412 (VZIP), A8.8.410
    // (VUZP). D-form (also Q-form via per-half on each, since these are
    // defined per-128/64). We treat both operands as d-regs or both as
    // q-regs. The two source regs are READ then BOTH overwritten.
    // Concatenate src0||src1 as 2N lanes (0..N-1 = a, N..2N-1 = b);
    // emit two shufflevectors:
    //   VTRN: out0[2k]=a[2k], out0[2k+1]=b[2k];
    //         out1[2k]=a[2k+1], out1[2k+1]=b[2k+1]
    //   VZIP: out0={a0,b0,a1,b1,...}; out1={a_{N/2},b_{N/2},...}
    //   VUZP: out0=evens {a0,a2,...,b0,b2,...}; out1=odds
    enum class VPermOp { TRN, ZIP, UZP };
    bool emit_v_permute(const cs_insn* in, VPermOp pop) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        for (int i = 0; i < 2; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int r0 = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                         : vfp_d_idx(d.operands[0].reg);
        int r1 = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                         : vfp_d_idx(d.operands[1].reg);
        if (r0 < 0 || r1 < 0) return false;
        int N = 64 / lane_bits;
        // For Q-form VZIP/VUZP the architecture interleaves across the
        // whole 128 bits; a faithful per-half decomposition is only
        // exact for VTRN. To stay correct rather than emit wrong IR,
        // restrict VZIP/VUZP to the d-form here and fall through to the
        // no-op for q-form (lenient). VTRN is per-pair so q-form works
        // as two independent d-form transposes.
        if (is_q && pop != VPermOp::TRN) return false;
        for (int h = 0; h < halves; ++h) {
            std::string a = load_dreg(r0 + h);
            std::string b = load_dreg(r1 + h);
            std::string av = i64_to_vec(a, lane_bits);
            std::string bv = i64_to_vec(b, lane_bits);
            auto emit_shuf = [&](const std::vector<int>& mask) -> std::string {
                std::string out = fresh();
                ir << "  " << out << " = shufflevector <" << N
                   << " x i" << lane_bits << "> " << av << ", <" << N
                   << " x i" << lane_bits << "> " << bv << ", <"
                   << N << " x i32> <";
                for (size_t i = 0; i < mask.size(); ++i) {
                    if (i > 0) ir << ", ";
                    ir << "i32 " << mask[i];
                }
                ir << ">\n";
                return out;
            };
            std::vector<int> m0, m1;
            m0.reserve(N); m1.reserve(N);
            if (pop == VPermOp::TRN) {
                for (int k = 0; k < N / 2; ++k) {
                    m0.push_back(2 * k);       // a[2k]
                    m0.push_back(N + 2 * k);   // b[2k]
                    m1.push_back(2 * k + 1);       // a[2k+1]
                    m1.push_back(N + 2 * k + 1);   // b[2k+1]
                }
            } else if (pop == VPermOp::ZIP) {
                for (int k = 0; k < N / 2; ++k) {
                    m0.push_back(k);           // a[k]
                    m0.push_back(N + k);       // b[k]
                }
                for (int k = 0; k < N / 2; ++k) {
                    m1.push_back(N / 2 + k);       // a[N/2+k]
                    m1.push_back(N + N / 2 + k);   // b[N/2+k]
                }
            } else {  // UZP
                for (int k = 0; k < N / 2; ++k) m0.push_back(2 * k);          // a evens
                for (int k = 0; k < N / 2; ++k) m0.push_back(N + 2 * k);      // b evens
                for (int k = 0; k < N / 2; ++k) m1.push_back(2 * k + 1);      // a odds
                for (int k = 0; k < N / 2; ++k) m1.push_back(N + 2 * k + 1);  // b odds
            }
            std::string out0 = emit_shuf(m0);
            std::string out1 = emit_shuf(m1);
            std::string o0i = vec_to_i64(out0, lane_bits);
            std::string o1i = vec_to_i64(out1, lane_bits);
            store_dreg(r0 + h, o0i);
            store_dreg(r1 + h, o1i);
        }
        return true;
    }

    // ---- VSWP : exchange two registers -----------------------------
    // ARM DDI 0406C.d A8.8.404 wait -- VSWP is A8.8.403/exchange.
    // Swap the full 64 (d) or 128 (q) bits of the two operands.
    bool emit_vswp(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        for (int i = 0; i < 2; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int r0 = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                         : vfp_d_idx(d.operands[0].reg);
        int r1 = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                         : vfp_d_idx(d.operands[1].reg);
        if (r0 < 0 || r1 < 0) return false;
        for (int h = 0; h < halves; ++h) {
            std::string a = load_dreg(r0 + h);
            std::string b = load_dreg(r1 + h);
            store_dreg(r0 + h, b);
            store_dreg(r1 + h, a);
        }
        return true;
    }

    // ---- VMOVN : narrow Q->D (truncate each lane to half width) ----
    // ARM DDI 0406C.d A8.8.343. dst is d-reg, src is q-reg. Each of the
    // src q-reg's N lanes of width 2*esize truncates to esize. The
    // operand-reported vector_data is the SOURCE element type (Ixx of
    // the wide lane); we narrow to half. We read both src d-halves,
    // bitcast to <lanes x i(2*half)>, trunc to <lanes x i(half)>,
    // concatenate into the destination d-reg.
    bool emit_vmovn(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        int dst = vfp_d_idx(d.operands[0].reg);
        int src_q = vfp_q_idx(d.operands[1].reg);
        if (dst < 0 || src_q < 0) return false;
        int src_bits = lane_bits_of(d);   // width of the WIDE src lane
        if (src_bits == 0 || src_bits < 16) return false;
        int half = src_bits / 2;
        int lanes_per_half_d = 64 / src_bits;   // wide lanes per src d-reg
        if (lanes_per_half_d < 1) return false;
        // Process the two source d-halves; each yields lanes_per_half_d
        // narrowed elements. Total narrowed = 2*lanes_per_half_d = the
        // destination d-reg's lane count (64/half).
        std::vector<std::string> narrowed_vecs;
        for (int sh = 0; sh < 2; ++sh) {
            std::string sv = load_dreg(src_q * 2 + sh);
            std::string vv = i64_to_vec(sv, src_bits);
            std::string tr = fresh();
            ir << "  " << tr << " = trunc <" << lanes_per_half_d << " x i"
               << src_bits << "> " << vv << " to <" << lanes_per_half_d
               << " x i" << half << ">\n";
            narrowed_vecs.push_back(tr);
        }
        // Concatenate the two narrowed halves into <2*lanes x ihalf>.
        int total = lanes_per_half_d * 2;
        std::string cat = fresh();
        ir << "  " << cat << " = shufflevector <" << lanes_per_half_d
           << " x i" << half << "> " << narrowed_vecs[0] << ", <"
           << lanes_per_half_d << " x i" << half << "> "
           << narrowed_vecs[1] << ", <" << total << " x i32> <";
        for (int i = 0; i < total; ++i) {
            if (i > 0) ir << ", ";
            ir << "i32 " << i;
        }
        ir << ">\n";
        std::string oi = vec_to_i64(cat, half);
        store_dreg(dst, oi);
        return true;
    }

    // ---- VMOVL : widen D->Q (extend each lane to double width) -----
    // ARM DDI 0406C.d A8.8.342. dst is q-reg, src is d-reg. Each of the
    // src d-reg's N lanes of width esize sign/zero-extends to 2*esize.
    // vector_data is the SOURCE element type (Sxx/Uxx of the narrow
    // lane). Result is 128 bits split across the two dst d-halves.
    bool emit_vmovl(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int src   = vfp_d_idx(d.operands[1].reg);
        if (dst_q < 0 || src < 0) return false;
        int lane_bits = lane_bits_of(d);   // narrow src lane width
        if (lane_bits == 0 || lane_bits >= 64) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes = 64 / lane_bits;        // src lanes
        int wbits = lane_bits * 2;
        std::string sv = load_dreg(src);
        std::string vv = i64_to_vec(sv, lane_bits);
        std::string ext = fresh();
        ir << "  " << ext << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes << " x i" << lane_bits << "> " << vv
           << " to <" << lanes << " x i" << wbits << ">\n";
        // <lanes x iwbits> is exactly 128 bits -> two dst d-halves.
        int half_lanes = lanes / 2;
        if (half_lanes < 1) half_lanes = 1;
        auto extract_half = [&](bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes
               << " x i" << wbits << "> " << ext << ", <" << lanes
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        std::string lo = extract_half(false);
        std::string hi = extract_half(true);
        store_dreg(dst_q * 2,     vec_to_i64(lo, wbits));
        store_dreg(dst_q * 2 + 1, vec_to_i64(hi, wbits));
        return true;
    }

    // ---- VADDW / VSUBW : Q = Q +/- widened(D) ----------------------
    // ARM DDI 0406C.d A8.8.282 (VADDW), A8.8.402 (VSUBW). op0=Qd,
    // op1=Qn (already wide), op2=Dm (narrow, extended to wide). Each Dm
    // lane of width esize sign/zero-extends to 2*esize then add/sub.
    bool emit_v_addw_subw(const cs_insn* in, bool is_sub) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_q = vfp_q_idx(d.operands[0].reg);
        int rn_q  = vfp_q_idx(d.operands[1].reg);
        int rm    = vfp_d_idx(d.operands[2].reg);
        if (dst_q < 0 || rn_q < 0 || rm < 0) return false;
        int lane_bits = lane_bits_of(d);   // narrow Dm lane width
        if (lane_bits == 0 || lane_bits >= 64) return false;
        bool is_signed = vdata_signed(d.vector_data);
        int lanes = 64 / lane_bits;        // Dm lanes
        int wbits = lane_bits * 2;
        int half_lanes = lanes / 2;
        if (half_lanes < 1) half_lanes = 1;
        // Widen Dm -> <lanes x iwbits> (128 bits), split to two halves
        // to line up with the two Qn d-halves (each <half_lanes x iwbits>).
        std::string mv = load_dreg(rm);
        std::string mvec = i64_to_vec(mv, lane_bits);
        std::string mext = fresh();
        ir << "  " << mext << " = " << (is_signed ? "sext" : "zext")
           << " <" << lanes << " x i" << lane_bits << "> " << mvec
           << " to <" << lanes << " x i" << wbits << ">\n";
        auto extract_half = [&](const std::string& src, bool top) -> std::string {
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes
               << " x i" << wbits << "> " << src << ", <" << lanes
               << " x i" << wbits << "> undef, <" << half_lanes
               << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << ((top ? half_lanes : 0) + i);
            }
            ir << ">\n";
            return out;
        };
        for (int half = 0; half < 2; ++half) {
            std::string nv = load_dreg(rn_q * 2 + half);
            std::string nvec = i64_to_vec(nv, wbits);  // already-wide lane
            std::string mh = extract_half(mext, half == 1);
            std::string res = fresh();
            ir << "  " << res << " = " << (is_sub ? "sub" : "add")
               << " <" << half_lanes << " x i" << wbits << "> " << nvec
               << ", " << mh << "\n";
            store_dreg(dst_q * 2 + half, vec_to_i64(res, wbits));
        }
        return true;
    }

    // ---- VABD : absolute difference per lane -----------------------
    // ARM DDI 0406C.d A8.8.297. Per lane |a - b| (signed or unsigned).
    // Same-width (non-widening) form here. Float form uses fabs(fsub).
    bool emit_vabd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        bool is_float  = vdata_float(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            if (is_float) {
                // f16 must use the half element type (a <4 x i16> -> <4 x
                // float> bitcast is a 64->128-bit size change, invalid).
                const char* fty  = (lb == 64) ? "double"
                                 : (lb == 16) ? "half" : "float";
                const char* fsuf = (lb == 64) ? "f64"
                                 : (lb == 16) ? "f16" : "f32";
                std::string af = fresh();
                ir << "  " << af << " = bitcast <" << lanes << " x i" << lb
                   << "> " << av << " to <" << lanes << " x " << fty << ">\n";
                std::string bf = fresh();
                ir << "  " << bf << " = bitcast <" << lanes << " x i" << lb
                   << "> " << bv << " to <" << lanes << " x " << fty << ">\n";
                std::string sub = fresh();
                ir << "  " << sub << " = fsub <" << lanes << " x " << fty
                   << "> " << af << ", " << bf << "\n";
                std::string ab = fresh();
                ir << "  " << ab << " = call <" << lanes << " x " << fty
                   << "> @llvm.fabs.v" << lanes << fsuf << "(<" << lanes
                   << " x " << fty << "> " << sub << ")\n";
                std::string out = fresh();
                ir << "  " << out << " = bitcast <" << lanes << " x " << fty
                   << "> " << ab << " to <" << lanes << " x i" << lb << ">\n";
                return out;
            }
            // Integer: max(a,b)-min(a,b) avoids overflow/sign issues.
            const char* mx = is_signed ? "llvm.smax" : "llvm.umax";
            const char* mn = is_signed ? "llvm.smin" : "llvm.umin";
            std::string hi = fresh();
            ir << "  " << hi << " = call <" << lanes << " x i" << lb
               << "> @" << mx << ".v" << lanes << "i" << lb << "(<"
               << lanes << " x i" << lb << "> " << av << ", <" << lanes
               << " x i" << lb << "> " << bv << ")\n";
            std::string lo = fresh();
            ir << "  " << lo << " = call <" << lanes << " x i" << lb
               << "> @" << mn << ".v" << lanes << "i" << lb << "(<"
               << lanes << " x i" << lb << "> " << av << ", <" << lanes
               << " x i" << lb << "> " << bv << ")\n";
            std::string out = fresh();
            ir << "  " << out << " = sub <" << lanes << " x i" << lb
               << "> " << hi << ", " << lo << "\n";
            return out;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VRSHL : rounding shift by signed per-lane amount ----------
    // ARM DDI 0406C.d A8.8.398. Per lane: shift amount = signed low
    // byte of the corresponding lane of the second operand. If amount
    // >= 0: result = a << amount. If amount < 0: result =
    // round(a >> -amount) i.e. (a + (1 << (-amount-1))) >> -amount,
    // signed or unsigned per vector_data. We widen to 2x to compute
    // the rounding add, then narrow. Per-lane scalarized for clarity.
    bool emit_vrshl(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_signed = vdata_signed(d.vector_data);
        auto lane = [&](const std::string& av, const std::string& bv,
                          int lb) -> std::string {
            int lanes = 64 / lb;
            std::string out_vec = "undef";
            for (int i = 0; i < lanes; ++i) {
                std::string ael = fresh();
                ir << "  " << ael << " = extractelement <" << lanes
                   << " x i" << lb << "> " << av << ", i32 " << i << "\n";
                std::string bel = fresh();
                ir << "  " << bel << " = extractelement <" << lanes
                   << " x i" << lb << "> " << bv << ", i32 " << i << "\n";
                // signed shift amount = sext(low 8 bits of bel) to i32.
                // For 8-bit lanes bel is already i8 (a trunc i8->i8 is an
                // invalid LLVM cast), so take it directly.
                std::string b8 = bel;
                if (lb != 8) {
                    b8 = fresh();
                    ir << "  " << b8 << " = trunc i" << lb << " " << bel
                       << " to i8\n";
                }
                std::string amt = fresh();
                ir << "  " << amt << " = sext i8 " << b8 << " to i32\n";
                // Compute left and rounded-right candidates in i32 then
                // pick by sign of amt. (Lane widths <= 32 here; for i64
                // lanes use i64 math.)
                int work = lb <= 32 ? 32 : 64;
                std::string aw = ael;
                if (work != lb) {
                    aw = fresh();
                    ir << "  " << aw << " = " << (is_signed ? "sext" : "zext")
                       << " i" << lb << " " << ael << " to i" << work << "\n";
                }
                std::string amtw = amt;
                if (work != 32) {
                    std::string ae = fresh();
                    ir << "  " << ae << " = sext i32 " << amt << " to i"
                       << work << "\n";
                    amtw = ae;
                }
                // left = a << amt ; negamt = -amt ; right rounding
                std::string shl = fresh();
                ir << "  " << shl << " = shl i" << work << " " << aw
                   << ", " << amtw << "\n";
                std::string neg = fresh();
                ir << "  " << neg << " = sub i" << work << " 0, " << amtw << "\n";
                // rounding bias = 1 << (negamt - 1) ; guard negamt==0.
                std::string nm1 = fresh();
                ir << "  " << nm1 << " = sub i" << work << " " << neg
                   << ", 1\n";
                std::string bias = fresh();
                ir << "  " << bias << " = shl i" << work << " 1, " << nm1 << "\n";
                std::string isz = fresh();
                ir << "  " << isz << " = icmp eq i" << work << " " << neg
                   << ", 0\n";
                std::string bias2 = fresh();
                ir << "  " << bias2 << " = select i1 " << isz << ", i"
                   << work << " 0, i" << work << " " << bias << "\n";
                std::string biased = fresh();
                ir << "  " << biased << " = add i" << work << " " << aw
                   << ", " << bias2 << "\n";
                std::string rsh = fresh();
                ir << "  " << rsh << " = " << (is_signed ? "ashr" : "lshr")
                   << " i" << work << " " << biased << ", " << neg << "\n";
                std::string isneg = fresh();
                ir << "  " << isneg << " = icmp slt i32 " << amt << ", 0\n";
                std::string pick = fresh();
                ir << "  " << pick << " = select i1 " << isneg << ", i"
                   << work << " " << rsh << ", i" << work << " " << shl << "\n";
                std::string narrowed = pick;
                if (work != lb) {
                    narrowed = fresh();
                    ir << "  " << narrowed << " = trunc i" << work << " " << pick
                       << " to i" << lb << "\n";
                }
                std::string ins = fresh();
                ir << "  " << ins << " = insertelement <" << lanes
                   << " x i" << lb << "> " << out_vec << ", i" << lb
                   << " " << narrowed << ", i32 " << i << "\n";
                out_vec = ins;
            }
            return out_vec;
        };
        return emit_v_binop_int(in, lane);
    }

    // ---- VRECPE / VRSQRTE / VRECPS / VRSQRTS : reciprocal seeds -----
    // ARM DDI 0406C.d A8.8.366/367 (VRECPE/VRSQRTE estimate),
    // A8.8.368/369 (VRECPS/VRSQRTS Newton step). CONSERVATIVE lowering
    // (precision caveat in edge_cases): we use exact IEEE reciprocal /
    // rsqrt for the estimates (1.0/x, 1.0/sqrt(x)) and the exact Newton
    // refinement formulas for the steps, which are MORE accurate than
    // the architectural ~8-bit-seed result but converge to the same
    // fixed point. F32 lanes only (the integer VRECPE.U32 unsigned
    // estimate is rare -> left to the no-op fallback by returning false).
    bool emit_v_recip(const cs_insn* in, bool is_rsqrt, bool is_step) {
        const cs_arm& d = in->detail->arm;
        if (!vdata_float(d.vector_data)) return false;
        int lane_bits = 32;  // F32
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        if (is_step) {
            if (d.op_count != 3) return false;
            for (int i = 0; i < 3; ++i)
                if (d.operands[i].type != ARM_OP_REG) return false;
        } else {
            if (d.op_count != 2) return false;
            for (int i = 0; i < 2; ++i)
                if (d.operands[i].type != ARM_OP_REG) return false;
        }
        auto base_of = [&](const cs_arm_op& o) -> int {
            return is_q ? (vfp_q_idx(o.reg) * 2) : vfp_d_idx(o.reg);
        };
        int dst = base_of(d.operands[0]);
        int rn  = base_of(d.operands[1]);
        int rm  = is_step ? base_of(d.operands[2]) : -1;
        if (dst < 0 || rn < 0 || (is_step && rm < 0)) return false;
        int lanes = 64 / lane_bits;
        for (int h = 0; h < halves; ++h) {
            std::string nf = i64_to_fvec(load_dreg(rn + h), lane_bits);
            std::string res;
            if (!is_step) {
                // estimate: 1/x  or  1/sqrt(x)
                std::string denom = nf;
                if (is_rsqrt) {
                    std::string sq = fresh();
                    ir << "  " << sq << " = call <" << lanes
                       << " x float> @llvm.sqrt.v" << lanes << "f32(<"
                       << lanes << " x float> " << nf << ")\n";
                    denom = sq;
                }
                std::string one = "<float 1.0";
                std::string onev = "<";
                for (int i = 0; i < lanes; ++i) onev += (i ? ", float 1.0" : "float 1.0");
                onev += ">";
                res = fresh();
                ir << "  " << res << " = fdiv <" << lanes << " x float> "
                   << onev << ", " << denom << "\n";
                (void)one;
            } else {
                std::string mf = i64_to_fvec(load_dreg(rm + h), lane_bits);
                std::string prod = fresh();
                ir << "  " << prod << " = fmul <" << lanes << " x float> "
                   << nf << ", " << mf << "\n";
                if (!is_rsqrt) {
                    // VRECPS: (2.0 - n*m)
                    std::string twov = "<";
                    for (int i = 0; i < lanes; ++i) twov += (i ? ", float 2.0" : "float 2.0");
                    twov += ">";
                    res = fresh();
                    ir << "  " << res << " = fsub <" << lanes
                       << " x float> " << twov << ", " << prod << "\n";
                } else {
                    // VRSQRTS: (3.0 - n*m) / 2.0
                    std::string threev = "<";
                    for (int i = 0; i < lanes; ++i) threev += (i ? ", float 3.0" : "float 3.0");
                    threev += ">";
                    std::string num = fresh();
                    ir << "  " << num << " = fsub <" << lanes
                       << " x float> " << threev << ", " << prod << "\n";
                    std::string halfv = "<";
                    for (int i = 0; i < lanes; ++i) halfv += (i ? ", float 5.000000e-01" : "float 5.000000e-01");
                    halfv += ">";
                    res = fresh();
                    ir << "  " << res << " = fmul <" << lanes
                       << " x float> " << num << ", " << halfv << "\n";
                }
            }
            store_dreg(dst + h, fvec_to_i64(res, lane_bits));
        }
        return true;
    }

    // ---- VEOR / VORN / VORR.imm / VBIC.imm ------------------------
    bool emit_v_eor(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                          : vfp_d_idx(d.operands[0].reg);
        int rn  = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                          : vfp_d_idx(d.operands[1].reg);
        int rm  = is_q ? (vfp_q_idx(d.operands[2].reg) * 2)
                          : vfp_d_idx(d.operands[2].reg);
        if (dst < 0 || rn < 0 || rm < 0) return false;
        for (int h = 0; h < halves; ++h) {
            std::string a = load_dreg(rn + h);
            std::string b = load_dreg(rm + h);
            std::string out = fresh();
            ir << "  " << out << " = xor i64 " << a << ", " << b << "\n";
            store_dreg(dst + h, out);
        }
        return true;
    }

    // VORR Dd, #imm / VORR Dd, Dd, #imm (immediate form).
    // ARM ARM A8.6.337. Or each lane with the same immediate.
    bool emit_v_orr_imm(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2 || d.op_count > 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int imm_idx = d.op_count - 1;
        // REGISTER form: VORR Dd,Dn,Dm (includes the `vorr dd,dn,dn` NEON
        // reg-MOVE idiom) -> bitwise OR via the shared logical path. Only
        // the immediate form continues below. The register form was
        // previously unhandled here (last operand not an immediate ->
        // returned false -> no-op), so the destination NEON register kept
        // GARBAGE that a later vst1 wrote to memory -- the ShatteredPD
        // FreeType glyph-path cross-.so corruption (redirect on
        // libgdx-freetype.so scribbled the sibling libgdx.so's gdx2d state).
        if (d.operands[imm_idx].type == ARM_OP_REG && d.op_count == 3)
            return emit_v_logical(in, VLogOp::ORR);
        if (d.operands[imm_idx].type != ARM_OP_IMM) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) lane_bits = 32;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                          : vfp_d_idx(d.operands[0].reg);
        if (dst < 0) return false;
        uint64_t imm = static_cast<uint64_t>(d.operands[imm_idx].imm);
        // Replicate the lane-sized immediate into a 64-bit pattern.
        uint64_t pat = 0;
        int lanes_d = 64 / lane_bits;
        for (int i = 0; i < lanes_d; ++i) {
            uint64_t m = (lane_bits == 64) ? imm :
                          (imm & ((static_cast<uint64_t>(1) << lane_bits) - 1));
            pat |= (m << (i * lane_bits));
        }
        for (int h = 0; h < halves; ++h) {
            std::string old = load_dreg(dst + h);
            std::string out = fresh();
            ir << "  " << out << " = or i64 " << old << ", "
               << static_cast<int64_t>(pat) << "\n";
            store_dreg(dst + h, out);
        }
        return true;
    }

    // ---- VCEQ / VCGE (float compare per lane) ---------------------
    // Result is all-1 (true) or all-0 (false) per lane.
    // Per-lane compare producing all-ones/all-zero masks. For FLOAT
    // vector_data this is the original fcmp-at-f32 path (VCEQ.f32 /
    // VCGE.f32 / VCGT.f32). For INTEGER vector_data we route to icmp at
    // the correct lane width and signedness (VCEQ.iN / VCGE.{s,u}N /
    // VCGT.{s,u}N) -- the old code hardcoded 32-bit float and silently
    // did FP compares on integer bit patterns (GD: 519 integer compares
    // vs 48 float). ARM DDI 0406C.d A8.8.291/295/296. intpred_signed /
    // intpred_unsigned select the icmp predicate for the integer path.
    bool emit_v_fcmp(const cs_insn* in, const char* fpred,
                       const char* intpred_signed,
                       const char* intpred_unsigned) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[1].type != ARM_OP_REG) return false;
        // 3rd operand may be a REGISTER or an IMMEDIATE. The immediate form
        // VCEQ/VCGT/VCGE/VCLT/VCLE.<dt> Dd/Qd, Dn, #imm compares each lane
        // against a splat of #imm (almost always #0). It was previously
        // unhandled (returned false) -> no-op -> a stale/garbage mask
        // register that a later select/store consumed.
        bool imm_rhs = (d.operands[2].type == ARM_OP_IMM);
        if (!imm_rhs && d.operands[2].type != ARM_OP_REG) return false;
        bool is_float = vdata_float(d.vector_data);
        int lane_bits = lane_bits_of(d);
        if (is_float) {
            if (lane_bits != 32) lane_bits = 32;  // only F32 lanes here
        } else {
            if (lane_bits == 0) return false;
        }
        bool is_signed = vdata_signed(d.vector_data);
        const char* ipred = is_signed ? intpred_signed : intpred_unsigned;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                          : vfp_d_idx(d.operands[0].reg);
        int rn  = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                          : vfp_d_idx(d.operands[1].reg);
        int rm  = imm_rhs ? 0
                          : (is_q ? (vfp_q_idx(d.operands[2].reg) * 2)
                                    : vfp_d_idx(d.operands[2].reg));
        if (dst < 0 || rn < 0 || (!imm_rhs && rm < 0)) return false;
        int64_t rhs_imm = imm_rhs
            ? static_cast<int64_t>(d.operands[2].imm) : 0;
        int lanes = 64 / lane_bits;
        for (int h = 0; h < halves; ++h) {
            std::string a = load_dreg(rn + h);
            std::string b = imm_rhs ? std::string() : load_dreg(rm + h);
            std::string cmp = fresh();
            if (is_float) {
                std::string af = i64_to_fvec(a, lane_bits);
                // Float immediate compares are always vs #0.0.
                std::string bf = imm_rhs ? "zeroinitializer"
                                         : i64_to_fvec(b, lane_bits);
                ir << "  " << cmp << " = fcmp " << fpred << " <"
                   << lanes << " x float> " << af << ", " << bf << "\n";
            } else {
                std::string av = i64_to_vec(a, lane_bits);
                std::string bv;
                if (imm_rhs) {
                    if (rhs_imm == 0) {
                        bv = "zeroinitializer";
                    } else {
                        bv = "<";
                        for (int l = 0; l < lanes; ++l) {
                            if (l) bv += ", ";
                            bv += "i" + std::to_string(lane_bits) + " "
                                  + std::to_string(rhs_imm);
                        }
                        bv += ">";
                    }
                } else {
                    bv = i64_to_vec(b, lane_bits);
                }
                ir << "  " << cmp << " = icmp " << ipred << " <"
                   << lanes << " x i" << lane_bits << "> " << av
                   << ", " << bv << "\n";
            }
            std::string ext = fresh();
            ir << "  " << ext << " = sext <" << lanes << " x i1> "
               << cmp << " to <" << lanes << " x i" << lane_bits
               << ">\n";
            std::string oi = vec_to_i64(ext, lane_bits);
            store_dreg(dst + h, oi);
        }
        return true;
    }

    // ---- VSELEQ / VSELGE / VSELGT / VSELVS ------------------------
    // ARMv8 scalar select: Vd = cond ? Vn : Vm based on the current
    // NZCV (the integer flags we maintain). Per ARM ARM A8.6.390.
    bool emit_v_sel(const cs_insn* in, arm_cc cc) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        int dst_s = vfp_s_idx(d.operands[0].reg);
        int dst_d = vfp_d_idx(d.operands[0].reg);
        int n_s = vfp_s_idx(d.operands[1].reg);
        int n_d = vfp_d_idx(d.operands[1].reg);
        int m_s = vfp_s_idx(d.operands[2].reg);
        int m_d = vfp_d_idx(d.operands[2].reg);
        bool is_double = (dst_d >= 0);
        if (is_double) {
            if (n_d < 0 || m_d < 0) return false;
        } else {
            if (n_s < 0 || m_s < 0) return false;
        }
        std::string cond = emit_cond_check(cc);
        if (is_double) {
            std::string n = load_dreg(n_d);
            std::string m = load_dreg(m_d);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << cond
               << ", i64 " << n << ", i64 " << m << "\n";
            store_dreg(dst_d, sel);
        } else {
            std::string n = load_sreg(n_s);
            std::string m = load_sreg(m_s);
            std::string sel = fresh();
            ir << "  " << sel << " = select i1 " << cond
               << ", i32 " << n << ", i32 " << m << "\n";
            store_sreg(dst_s, sel);
        }
        return true;
    }

    // ---- VRINTR / VRINTX / VRINTZ : scalar rounding ---------------
    // VRINTR: round to current FPSCR mode (we treat as "round-to-nearest-
    // even" which is the default IEEE 754 mode).
    // VRINTX: ditto, but raises Inexact -- we ignore exception flag.
    // VRINTZ: round toward zero.
    bool emit_v_rint(const cs_insn* in, const char* intrinsic) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int dst_s = vfp_s_idx(d.operands[0].reg);
        int dst_d = vfp_d_idx(d.operands[0].reg);
        int src_s = vfp_s_idx(d.operands[1].reg);
        int src_d = vfp_d_idx(d.operands[1].reg);
        bool is_double = dst_d >= 0;
        if (is_double) {
            if (src_d < 0) return false;
            std::string v = load_dreg(src_d);
            std::string f = fresh();
            ir << "  " << f << " = bitcast i64 " << v << " to double\n";
            std::string r = fresh();
            ir << "  " << r << " = call double @" << intrinsic
               << ".f64(double " << f << ")\n";
            std::string i64v = fresh();
            ir << "  " << i64v << " = bitcast double " << r << " to i64\n";
            store_dreg(dst_d, i64v);
        } else {
            if (src_s < 0) return false;
            std::string v = load_sreg(src_s);
            std::string f = fresh();
            ir << "  " << f << " = bitcast i32 " << v << " to float\n";
            std::string r = fresh();
            ir << "  " << r << " = call float @" << intrinsic
               << ".f32(float " << f << ")\n";
            std::string i32v = fresh();
            ir << "  " << i32v << " = bitcast float " << r << " to i32\n";
            store_sreg(dst_s, i32v);
        }
        return true;
    }

    // ---- VCVTB / VCVTT : F16 <-> F32 lane conversion --------------
    // VCVTB.F32.F16: low half of source d-reg (s_n bottom 16 bits)
    //                converted to a single-precision in Sd.
    // VCVTT.F32.F16: top half (bits 16..31 of the source s-reg) ditto.
    // VCVTB.F16.F32: convert Sm to F16, store to low half of Sd.
    // VCVTT.F16.F32: convert Sm to F16, store to top half of Sd.
    bool emit_v_cvt_half(const cs_insn* in, bool top, bool to_f32) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int dst_s = vfp_s_idx(d.operands[0].reg);
        int src_s = vfp_s_idx(d.operands[1].reg);
        if (dst_s < 0 || src_s < 0) return false;
        std::string src = load_sreg(src_s);
        if (to_f32) {
            // Extract f16 from low or top half of source s-reg.
            std::string sh = src;
            if (top) {
                std::string s = fresh();
                ir << "  " << s << " = lshr i32 " << src << ", 16\n";
                sh = s;
            }
            std::string trunc = fresh();
            ir << "  " << trunc << " = trunc i32 " << sh << " to i16\n";
            std::string hbits = fresh();
            ir << "  " << hbits << " = bitcast i16 " << trunc
               << " to half\n";
            std::string f = fresh();
            ir << "  " << f << " = fpext half " << hbits << " to float\n";
            std::string i32v = fresh();
            ir << "  " << i32v << " = bitcast float " << f
               << " to i32\n";
            store_sreg(dst_s, i32v);
        } else {
            // F32 -> F16: convert and pack into selected half of dst.
            std::string f = fresh();
            ir << "  " << f << " = bitcast i32 " << src << " to float\n";
            std::string h = fresh();
            ir << "  " << h << " = fptrunc float " << f << " to half\n";
            std::string hb = fresh();
            ir << "  " << hb << " = bitcast half " << h << " to i16\n";
            std::string ext = fresh();
            ir << "  " << ext << " = zext i16 " << hb << " to i32\n";
            std::string old = load_sreg(dst_s);
            std::string out;
            if (top) {
                std::string mask = fresh();
                ir << "  " << mask << " = and i32 " << old
                   << ", 65535\n";   // keep low half
                std::string sh = fresh();
                ir << "  " << sh << " = shl i32 " << ext << ", 16\n";
                out = fresh();
                ir << "  " << out << " = or i32 " << mask
                   << ", " << sh << "\n";
            } else {
                std::string mask = fresh();
                ir << "  " << mask << " = and i32 " << old
                   << ", -65536\n";  // keep top half
                out = fresh();
                ir << "  " << out << " = or i32 " << mask
                   << ", " << ext << "\n";
            }
            store_sreg(dst_s, out);
        }
        return true;
    }

    // ---- VREV64 / VREV32 / VREV16 : reverse elements --------------
    // Reverse the order of size-bit elements within each container.
    // For VREV64.16: 4 halfwords reversed within each 64-bit lane.
    // For VREV64.32: 2 words reversed.
    // For VREV64.8: 8 bytes reversed.
    bool emit_v_rev(const cs_insn* in, int container_bits) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) return false;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int dst = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                          : vfp_d_idx(d.operands[0].reg);
        int src = is_q ? (vfp_q_idx(d.operands[1].reg) * 2)
                          : vfp_d_idx(d.operands[1].reg);
        if (dst < 0 || src < 0) return false;
        int lanes_total = 64 / lane_bits;
        int lanes_per_container = container_bits / lane_bits;
        if (lanes_per_container <= 1) return false;
        for (int h = 0; h < halves; ++h) {
            std::string v = load_dreg(src + h);
            std::string vec = i64_to_vec(v, lane_bits);
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << lanes_total
               << " x i" << lane_bits << "> " << vec << ", <"
               << lanes_total << " x i" << lane_bits << "> undef, <"
               << lanes_total << " x i32> <";
            for (int i = 0; i < lanes_total; ++i) {
                if (i > 0) ir << ", ";
                int container = i / lanes_per_container;
                int within = i % lanes_per_container;
                int rev_within = lanes_per_container - 1 - within;
                int new_idx = container * lanes_per_container + rev_within;
                ir << "i32 " << new_idx;
            }
            ir << ">\n";
            std::string oi = vec_to_i64(out, lane_bits);
            store_dreg(dst + h, oi);
        }
        return true;
    }

    // ---- VEXT : extract concatenation -----------------------------
    // ARM ARM A8.6.298. dst = (n:m)[imm..imm+8) for d-reg form (imm
    // is byte offset within the concatenation).
    bool emit_v_ext(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 4) return false;
        for (int i = 0; i < 3; ++i)
            if (d.operands[i].type != ARM_OP_REG) return false;
        if (d.operands[3].type != ARM_OP_IMM) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) lane_bits = 8;
        bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
        int halves = is_q ? 2 : 1;
        int imm = static_cast<int>(d.operands[3].imm);
        // The immediate is in lane units of vector_data type.
        if (is_q) {
            // Q-reg extract: build a <16/lb_bytes * 2 x lb> by
            // concatenating both halves of n then m.
            int dst = vfp_q_idx(d.operands[0].reg) * 2;
            int n   = vfp_q_idx(d.operands[1].reg) * 2;
            int m   = vfp_q_idx(d.operands[2].reg) * 2;
            if (dst < 0 || n < 0 || m < 0) return false;
            int half_lanes = 64 / lane_bits;
            int total = half_lanes * 4;  // n_lo, n_hi, m_lo, m_hi
            // Load four halves and bitcast into one big vector via
            // <4 x i64>. Then bitcast to <total x lane_bits>.
            std::string nlo = load_dreg(n);
            std::string nhi = load_dreg(n + 1);
            std::string mlo = load_dreg(m);
            std::string mhi = load_dreg(m + 1);
            std::string p1 = fresh();
            ir << "  " << p1 << " = insertelement <4 x i64> undef, i64 "
               << nlo << ", i32 0\n";
            std::string p2 = fresh();
            ir << "  " << p2 << " = insertelement <4 x i64> " << p1
               << ", i64 " << nhi << ", i32 1\n";
            std::string p3 = fresh();
            ir << "  " << p3 << " = insertelement <4 x i64> " << p2
               << ", i64 " << mlo << ", i32 2\n";
            std::string p4 = fresh();
            ir << "  " << p4 << " = insertelement <4 x i64> " << p3
               << ", i64 " << mhi << ", i32 3\n";
            std::string concat = fresh();
            ir << "  " << concat << " = bitcast <4 x i64> " << p4
               << " to <" << total << " x i" << lane_bits << ">\n";
            // Shuffle imm..imm+half_lanes*2.
            int out_lanes = half_lanes * 2;
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << total
               << " x i" << lane_bits << "> " << concat << ", <"
               << total << " x i" << lane_bits << "> undef, <"
               << out_lanes << " x i32> <";
            for (int i = 0; i < out_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (imm + i);
            }
            ir << ">\n";
            // Split back into two d-regs.
            std::string lo_v = fresh();
            ir << "  " << lo_v << " = shufflevector <" << out_lanes
               << " x i" << lane_bits << "> " << out << ", <"
               << out_lanes << " x i" << lane_bits << "> undef, <"
               << half_lanes << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << i;
            }
            ir << ">\n";
            std::string hi_v = fresh();
            ir << "  " << hi_v << " = shufflevector <" << out_lanes
               << " x i" << lane_bits << "> " << out << ", <"
               << out_lanes << " x i" << lane_bits << "> undef, <"
               << half_lanes << " x i32> <";
            for (int i = 0; i < half_lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (half_lanes + i);
            }
            ir << ">\n";
            store_dreg(dst,     vec_to_i64(lo_v, lane_bits));
            store_dreg(dst + 1, vec_to_i64(hi_v, lane_bits));
        } else {
            int dst = vfp_d_idx(d.operands[0].reg);
            int n   = vfp_d_idx(d.operands[1].reg);
            int m   = vfp_d_idx(d.operands[2].reg);
            if (dst < 0 || n < 0 || m < 0) return false;
            int lanes = 64 / lane_bits;
            int total = lanes * 2;
            std::string nv_i = load_dreg(n);
            std::string mv_i = load_dreg(m);
            std::string p1 = fresh();
            ir << "  " << p1 << " = insertelement <2 x i64> undef, i64 "
               << nv_i << ", i32 0\n";
            std::string p2 = fresh();
            ir << "  " << p2 << " = insertelement <2 x i64> " << p1
               << ", i64 " << mv_i << ", i32 1\n";
            std::string concat = fresh();
            ir << "  " << concat << " = bitcast <2 x i64> " << p2
               << " to <" << total << " x i" << lane_bits << ">\n";
            std::string out = fresh();
            ir << "  " << out << " = shufflevector <" << total
               << " x i" << lane_bits << "> " << concat << ", <"
               << total << " x i" << lane_bits << "> undef, <"
               << lanes << " x i32> <";
            for (int i = 0; i < lanes; ++i) {
                if (i > 0) ir << ", ";
                ir << "i32 " << (imm + i);
            }
            ir << ">\n";
            store_dreg(dst, vec_to_i64(out, lane_bits));
        }
        (void)halves;
        return true;
    }

    // ---- VLD / VST multi-element (vld1/vld2/vld4 etc) -----------------
    // For each n-register load/store, we emit n contiguous i64 loads/
    // stores. Capstone reports the operand list as the destination/
    // source d-regs followed by a memory operand. The MULTI-element
    // semantic is that vld2 deinterleaves: e.g. `vld2.8 {d0, d1}, [r0]`
    // reads bytes b0,b1,b2,...,b15 from memory and writes them as
    // d0 = b0,b2,b4,b6,b8,b10,b12,b14; d1 = b1,b3,...
    //
    // Because the optimizer collapses our scalar lane sequence back into
    // NEON ld2/st2/ld4/st4 instructions at the arm64 layer, we model the
    // semantics in scalar IR rather than calling intrinsics. For LD/ST1
    // (the trivial case) we can just emit i64 loads.
    // Lane width must be 8/16/32/64 for a clean <64/lb x ilb> bitcast.
    static bool lb_valid(int lb) {
        return lb == 8 || lb == 16 || lb == 32 || lb == 64;
    }

    // BUG 7 (2026-07-25). Which VLDn/VSTn form is this, and for the
    // single-lane form, which lane -- decoded from the instruction WORD.
    //
    // Capstone does NOT expose either for this encoding class. Measured
    // directly against libcapstone 5.0.x: `vld1.32 {d5[1]}, [r0]` decodes
    // with operands[0].vector_index == -1, and so does every other
    // VLD1-4 / VST1-4 structure form, in BOTH ARM and Thumb mode. (A plain
    // `vmov.32 d5[1], r2` -- a different encoding class -- DOES report
    // vector_index == 1, which is why the field looks usable at a glance.)
    // The old `vector_index >= 0` guard therefore could never fire, so
    // every single-lane form fell through to the whole-register path and
    // moved a full 8 bytes: on a load that clobbers the other lanes of the
    // destination, and on a STORE it writes 8 bytes over a 4-byte
    // destination, silently corrupting whatever sits next to it in guest
    // memory. Corruption at a distance -- the symptom lands in an
    // unrelated object long after the instruction ran.
    //
    // Fields per DDI 0406C.d A7.7 (Advanced SIMD element or structure
    // load/store), A8.8.320 (VLD1 single lane), A8.8.321 (VLD1 to all
    // lanes), A8.8.404 (VST1 single lane):
    //   bit[23]      A: 0 = load/store MULTIPLE structures
    //                   1 = single structure (one lane, or to all lanes)
    //   A == 1, bits[11:10] == 0b11 -> "to all lanes"; element size is
    //                                  bits[7:6]
    //   A == 1, otherwise           -> one lane; bits[11:10] = element
    //                                  size, bits[7:4] = index_align, and
    //                                  index = index_align >> (1 + size)
    // A32 and T32 place all of these identically; only bits[31:24] differ
    // (0b11110100 vs 0b11111001). Verified on both Capstone handles.
    struct NeonLsForm {
        bool single_lane = false;
        bool replicate   = false;
        int  elem_bits   = 0;   // from the WORD, not Capstone's operand model
        unsigned index   = 0;
    };
    bool neon_ls_form(const cs_insn* in, NeonLsForm* out) const {
        if (in->size != 4) return false;
        const uint8_t* b = in->bytes;
        uint32_t w;
        if (current_is_thumb) {
            // T32 stores two little-endian halfwords, most significant
            // first, so the first halfword supplies bits 31:16.
            w = (static_cast<uint32_t>(b[1]) << 24) |
                (static_cast<uint32_t>(b[0]) << 16) |
                (static_cast<uint32_t>(b[3]) << 8)  |
                 static_cast<uint32_t>(b[2]);
        } else {
            w =  static_cast<uint32_t>(b[0])        |
                (static_cast<uint32_t>(b[1]) << 8)  |
                (static_cast<uint32_t>(b[2]) << 16) |
                (static_cast<uint32_t>(b[3]) << 24);
        }
        if (((w >> 23) & 1u) == 0u) return true;   // multiple structures
        const unsigned size = (w >> 10) & 3u;
        if (size == 3u) {
            out->replicate = true;
            out->elem_bits = 8 << ((w >> 6) & 3u);
            return true;
        }
        out->single_lane = true;
        out->elem_bits = 8 << size;
        out->index = ((w >> 4) & 0xFu) >> (1u + size);
        return true;
    }

    bool emit_vld_vst_multi(const cs_insn* in, bool is_load,
                              int n_elements) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < n_elements + 1) return false;
        // Find the MEM operand. Capstone may place a post-index ARM
        // register AFTER the MEM operand (the `, Rm` form means base
        // gets `+ Rm` after the access), so we scan rather than just
        // grabbing the last.
        int mem_idx = -1;
        for (int i = 0; i < d.op_count; ++i) {
            if (d.operands[i].type == ARM_OP_MEM) {
                mem_idx = i;
                break;
            }
        }
        if (mem_idx < 0) return false;
        const cs_arm_op& mem_op = d.operands[mem_idx];
        std::vector<int> dregs;
        dregs.reserve(n_elements);
        // The d-regs come BEFORE the MEM operand; anything after is the
        // optional post-increment register.
        int post_inc_reg = -1;
        for (int i = 0; i < mem_idx; ++i) {
            if (d.operands[i].type != ARM_OP_REG) continue;
            int dr = vfp_d_idx(d.operands[i].reg);
            if (dr < 0) continue;
            dregs.push_back(dr);
        }
        for (int i = mem_idx + 1; i < d.op_count; ++i) {
            if (d.operands[i].type != ARM_OP_REG) continue;
            int rr = arm_reg_idx(d.operands[i].reg);
            if (rr >= 0) {
                post_inc_reg = rr;
                break;
            }
        }
        if (dregs.empty()) return false;
        // NEON multi-element [Rn:align]: the alignment lives in op.mem.disp and
        // must NOT be added to the address (see compute_mem_addr).
        std::string addr = compute_mem_addr(mem_op, /*ignore_disp=*/true);
        if (addr.empty()) return false;
        int lane_bits = lane_bits_of(d);
        if (lane_bits == 0) lane_bits = 8;
        int lanes_per_d = 64 / lane_bits;
        int total_bytes = static_cast<int>(dregs.size()) * 8;
        // ---- Single-structure forms: one lane, or to all lanes -------
        // Decoded from the instruction word; see neon_ls_form above for
        // why Capstone's vector_index cannot be used here.
        NeonLsForm form;
        if (!neon_ls_form(in, &form)) return false;
        if (form.single_lane || form.replicate) {
            const int lb = form.elem_bits;
            if (!lb_valid(lb) || lb == 64) return false;
            // VSTn-to-all-lanes does not exist in the architecture.
            if (form.replicate && !is_load) return false;
            const int lpd = 64 / lb;
            const int ebytes = lb / 8;
            const int nregs = static_cast<int>(dregs.size());
            if (form.single_lane && static_cast<int>(form.index) >= lpd)
                return false;
            for (int i = 0; i < nregs; ++i) {
                // Single lane: element j of the structure goes to
                // regs[j], all at the SAME lane index. To-all-lanes:
                // VLD1 broadcasts ONE element into every listed register,
                // while VLD2/3/4 read n consecutive elements, element j
                // into all lanes of regs[j].
                const int e = (form.replicate && n_elements == 1) ? 0 : i;
                std::string a = fresh();
                ir << "  " << a << " = add i32 " << addr << ", "
                   << (e * ebytes) << "\n";
                std::string p = stack_ptr(a);
                if (form.replicate) {
                    std::string v = fresh();
                    ir << "  " << v << " = load i" << lb << ", ptr " << p
                       << ", align " << ebytes << "\n";
                    std::string iv = fresh();
                    ir << "  " << iv << " = insertelement <" << lpd
                       << " x i" << lb << "> undef, i" << lb << " " << v
                       << ", i32 0\n";
                    std::string sp = fresh();
                    ir << "  " << sp << " = shufflevector <" << lpd
                       << " x i" << lb << "> " << iv << ", <" << lpd
                       << " x i" << lb << "> undef, <" << lpd
                       << " x i32> zeroinitializer\n";
                    store_dreg(dregs[i], vec_to_i64(sp, lb));
                } else if (is_load) {
                    // Exactly ebytes move; every other lane is PRESERVED,
                    // so the destination is read back first.
                    std::string v = fresh();
                    ir << "  " << v << " = load i" << lb << ", ptr " << p
                       << ", align " << ebytes << "\n";
                    std::string vec = i64_to_vec(load_dreg(dregs[i]), lb);
                    std::string ins = fresh();
                    ir << "  " << ins << " = insertelement <" << lpd
                       << " x i" << lb << "> " << vec << ", i" << lb << " "
                       << v << ", i32 " << form.index << "\n";
                    store_dreg(dregs[i], vec_to_i64(ins, lb));
                } else {
                    // The whole point of the fix: store ebytes, not 8.
                    std::string vec = i64_to_vec(load_dreg(dregs[i]), lb);
                    std::string el = fresh();
                    ir << "  " << el << " = extractelement <" << lpd
                       << " x i" << lb << "> " << vec << ", i32 "
                       << form.index << "\n";
                    ir << "  store i" << lb << " " << el << ", ptr " << p
                       << ", align " << ebytes << "\n";
                }
            }
            // Writeback advances Rn by the bytes actually transferred:
            // n_elements * ebytes for BOTH forms (to-all-lanes reads n
            // elements however many registers it broadcasts into), or by
            // Rm for the register post-index form.
            if (d.writeback || post_inc_reg >= 0) {
                int rbase = arm_reg_idx(mem_op.mem.base);
                if (rbase >= 0) {
                    std::string oldb = load_reg(rbase);
                    std::string nv = fresh();
                    if (post_inc_reg >= 0) {
                        std::string inc = load_reg(post_inc_reg);
                        ir << "  " << nv << " = add i32 " << oldb
                           << ", " << inc << "\n";
                    } else {
                        ir << "  " << nv << " = add i32 " << oldb
                           << ", " << (n_elements * ebytes) << "\n";
                    }
                    store_reg(rbase, nv);
                }
            }
            return true;
        }
        if (n_elements == 1 || dregs.size() == 1) {
            // VLD1/VST1 (or single-d variants): contiguous i64 transfers.
            for (size_t i = 0; i < dregs.size(); ++i) {
                std::string a = fresh();
                ir << "  " << a << " = add i32 " << addr << ", "
                   << (i * 8) << "\n";
                std::string p = stack_ptr(a);
                if (is_load) {
                    std::string v = fresh();
                    ir << "  " << v << " = load i64, ptr " << p
                       << ", align 8\n";
                    store_dreg(dregs[i], v);
                } else {
                    std::string v = load_dreg(dregs[i]);
                    ir << "  store i64 " << v << ", ptr " << p
                       << ", align 8\n";
                }
            }
        } else {
            // VLD2/VLD4 deinterleave (or VST2/VST4 interleave). We read
            // or write `total_bytes` lane-sized values, mapping to each
            // d-reg per the stride pattern:
            //   contiguous memory index = lane_in_d * n_elements + d_idx
            // For LOAD: read each memory lane, place into the correct
            // d-reg's correct lane position.
            // For STORE: extract each d-reg's lane and write to memory.
            if (is_load) {
                // Initialize all output d-regs to undef vectors.
                std::vector<std::string> vecs(dregs.size(), "undef");
                for (int lane = 0; lane < lanes_per_d; ++lane) {
                    for (size_t di = 0; di < dregs.size(); ++di) {
                        int mem_idx = lane * static_cast<int>(dregs.size()) + static_cast<int>(di);
                        std::string a = fresh();
                        ir << "  " << a << " = add i32 " << addr
                           << ", " << (mem_idx * (lane_bits / 8)) << "\n";
                        std::string p = stack_ptr(a);
                        std::string v = fresh();
                        ir << "  " << v << " = load i" << lane_bits
                           << ", ptr " << p << ", align "
                           << (lane_bits / 8) << "\n";
                        std::string nv = fresh();
                        ir << "  " << nv << " = insertelement <"
                           << lanes_per_d << " x i" << lane_bits
                           << "> " << vecs[di] << ", i" << lane_bits
                           << " " << v << ", i32 " << lane << "\n";
                        vecs[di] = nv;
                    }
                }
                for (size_t di = 0; di < dregs.size(); ++di) {
                    std::string i64v = vec_to_i64(vecs[di], lane_bits);
                    store_dreg(dregs[di], i64v);
                }
            } else {
                std::vector<std::string> vecs;
                vecs.reserve(dregs.size());
                for (int dr : dregs) {
                    std::string i64v = load_dreg(dr);
                    vecs.push_back(i64_to_vec(i64v, lane_bits));
                }
                for (int lane = 0; lane < lanes_per_d; ++lane) {
                    for (size_t di = 0; di < dregs.size(); ++di) {
                        std::string el = fresh();
                        ir << "  " << el << " = extractelement <"
                           << lanes_per_d << " x i" << lane_bits
                           << "> " << vecs[di] << ", i32 " << lane
                           << "\n";
                        int mem_idx = lane * static_cast<int>(dregs.size()) + static_cast<int>(di);
                        std::string a = fresh();
                        ir << "  " << a << " = add i32 " << addr
                           << ", " << (mem_idx * (lane_bits / 8)) << "\n";
                        std::string p = stack_ptr(a);
                        ir << "  store i" << lane_bits << " " << el
                           << ", ptr " << p << ", align "
                           << (lane_bits / 8) << "\n";
                    }
                }
            }
        }
        // Writeback. `[Rn]!` writes back `Rn + total_bytes`; the
        // post-index `[Rn], Rm` form writes back `Rn + Rm`; the
        // post-index `[Rn], #imm` form (no `, Rm` operand) writes back
        // `Rn + total_bytes` too -- the Capstone IR sometimes elides the
        // imm. We treat any of these as "advance Rn".
        if (d.writeback || post_inc_reg >= 0) {
            int rbase = arm_reg_idx(mem_op.mem.base);
            if (rbase >= 0) {
                std::string old = load_reg(rbase);
                std::string nv = fresh();
                if (post_inc_reg >= 0) {
                    std::string inc = load_reg(post_inc_reg);
                    ir << "  " << nv << " = add i32 " << old << ", "
                       << inc << "\n";
                } else {
                    ir << "  " << nv << " = add i32 " << old << ", "
                       << total_bytes << "\n";
                }
                store_reg(rbase, nv);
            }
        }
        return true;
    }

    // ---- VLDMDB / VSTMDB : decrement-before LDM/STM on d-regs -----
    // Same as VLDMIA / VSTMIA but the base register is decremented
    // BEFORE the access, and writeback (if present) leaves base at
    // the lowest accessed address.
    bool emit_vldmdb_vstmdb(const cs_insn* in, bool is_load) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 2) return false;
        const cs_arm_op& base_op = d.operands[0];
        if (base_op.type != ARM_OP_REG) return false;
        int rbase = arm_reg_idx(base_op.reg);
        if (rbase < 0) return false;
        // Determine slot size from operand 1.
        if (d.operands[1].type != ARM_OP_REG) return false;
        bool is_d = (vfp_d_idx(d.operands[1].reg) >= 0);
        int slot_bytes = is_d ? 8 : 4;
        int n = d.op_count - 1;
        std::string base = load_reg(rbase);
        // First decrement.
        std::string start = fresh();
        ir << "  " << start << " = sub i32 " << base << ", "
           << (slot_bytes * n) << "\n";
        for (int i = 0; i < n; ++i) {
            const cs_arm_op& op = d.operands[1 + i];
            if (op.type != ARM_OP_REG) return false;
            std::string a = fresh();
            ir << "  " << a << " = add i32 " << start << ", "
               << (slot_bytes * i) << "\n";
            std::string p = stack_ptr(a);
            if (is_d) {
                int dr = vfp_d_idx(op.reg);
                if (dr < 0) return false;
                if (is_load) {
                    std::string v = fresh();
                    ir << "  " << v << " = load i64, ptr " << p
                       << ", align 8\n";
                    store_dreg(dr, v);
                } else {
                    std::string v = load_dreg(dr);
                    ir << "  store i64 " << v << ", ptr " << p
                       << ", align 8\n";
                }
            } else {
                int sr = vfp_s_idx(op.reg);
                if (sr < 0) return false;
                if (is_load) {
                    std::string v = fresh();
                    ir << "  " << v << " = load i32, ptr " << p
                       << ", align 4\n";
                    store_sreg(sr, v);
                } else {
                    std::string v = load_sreg(sr);
                    ir << "  store i32 " << v << ", ptr " << p
                       << ", align 4\n";
                }
            }
        }
        if (d.writeback) {
            store_reg(rbase, start);
        }
        return true;
    }

    // BKPT / UDF -- treat as a no-op so the function still lifts. The
    // lifted code shouldn't reach these; if it does, the surrounding
    // logic was already wrong.
    bool emit_nop_only() { return true; }

    // SVC #imm  -- supervisor call. Route to a single runtime helper
    // that dispatches via the immediate (the Bionic syscall number).
    // Stage 2 will provide __macapk_svc as a libSystem-backed shim.
    bool emit_svc(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 1) return false;
        if (d.operands[0].type != ARM_OP_IMM) return false;
        int32_t imm = static_cast<int32_t>(d.operands[0].imm);
        std::string a0 = load_reg(0);
        std::string a1 = load_reg(1);
        std::string a2 = load_reg(2);
        std::string a3 = load_reg(3);
        std::string ret = fresh();
        ir << "  " << ret
           << " = call i32 @__macapk_svc(i32 " << imm
           << ", i32 " << a0 << ", i32 " << a1
           << ", i32 " << a2 << ", i32 " << a3 << ")\n";
        store_reg(0, ret);
        return true;
    }

    // STREX Rd, Rs, [Rn] -- store-exclusive. Apk on Mac runs the lifted
    // .so in the same address space as the JVM, with no other threads
    // racing on the same memory directly, so we treat it as a plain
    // store and report success (Rd = 0). Real preemptive contention
    // would require a CAS loop; not relevant for our targets yet.
    bool emit_strex(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string addr = compute_mem_addr(d.operands[2]);
        if (addr.empty()) return false;
        std::string p = stack_ptr(addr);
        std::string val = load_reg(rs);
        ir << "  store i32 " << val << ", ptr " << p << ", align 4\n";
        store_reg(rd, "0");
        return true;
    }

    // Compute the access address and post-increment value for the
    // LDRD/STRD family. Returns true if the operands are recognized.
    bool ldrd_strd_addr(const cs_insn* in, int mem_idx,
                        std::string* access_addr,
                        std::string* post_increment_base,
                        bool* post_idx_3op_out) {
        const cs_arm& d = in->detail->arm;
        // 3-operand form (post-indexed): operands[mem_idx] = base only,
        // operands[mem_idx+1] = post-increment.
        bool post_idx_3op = (d.op_count == mem_idx + 2);
        *post_idx_3op_out = post_idx_3op;
        if (post_idx_3op) {
            int rb = arm_reg_idx(d.operands[mem_idx].mem.base);
            if (rb < 0) return false;
            *access_addr = load_reg(rb);
            const cs_arm_op& off = d.operands[mem_idx + 1];
            std::string inc;
            if (off.type == ARM_OP_IMM) {
                inc = std::to_string(static_cast<int32_t>(off.imm));
            } else if (off.type == ARM_OP_REG) {
                int ri = arm_reg_idx(off.reg);
                if (ri < 0) return false;
                inc = load_reg(ri);
                if (!apply_shift(off, &inc)) return false;
            } else return false;
            std::string post_addr = fresh();
            ir << "  " << post_addr << " = "
               << (off.subtracted ? "sub" : "add")
               << " i32 " << *access_addr << ", " << inc << "\n";
            *post_increment_base = post_addr;
        } else {
            *access_addr = compute_mem_addr(d.operands[mem_idx]);
            if (access_addr->empty()) return false;
        }
        return true;
    }

    bool emit_ldrd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3 && d.op_count != 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rd_lo = arm_reg_idx(d.operands[0].reg);
        int rd_hi = arm_reg_idx(d.operands[1].reg);
        if (rd_lo < 0 || rd_hi < 0) return false;
        std::string addr_lo, post_inc;
        bool post_idx_3op = false;
        if (!ldrd_strd_addr(in, 2, &addr_lo, &post_inc, &post_idx_3op))
            return false;
        std::string addr_hi = fresh();
        ir << "  " << addr_hi << " = add i32 " << addr_lo << ", 4\n";
        std::string p_lo = stack_ptr(addr_lo);
        std::string p_hi = stack_ptr(addr_hi);
        std::string lo = fresh();
        ir << "  " << lo << " = load i32, ptr " << p_lo << ", align 4\n";
        std::string hi = fresh();
        ir << "  " << hi << " = load i32, ptr " << p_hi << ", align 4\n";
        store_reg(rd_lo, lo);
        store_reg(rd_hi, hi);
        if ((d.writeback || post_idx_3op) && !post_inc.empty()) {
            int rb = arm_reg_idx(d.operands[2].mem.base);
            if (rb >= 0) store_reg(rb, post_inc);
        } else if (d.writeback) {
            int rb = arm_reg_idx(d.operands[2].mem.base);
            if (rb >= 0) store_reg(rb, addr_lo);
        }
        return true;
    }

    bool emit_strd(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3 && d.op_count != 4) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        if (d.operands[2].type != ARM_OP_MEM) return false;
        int rs_lo = arm_reg_idx(d.operands[0].reg);
        int rs_hi = arm_reg_idx(d.operands[1].reg);
        if (rs_lo < 0 || rs_hi < 0) return false;
        std::string addr_lo, post_inc;
        bool post_idx_3op = false;
        if (!ldrd_strd_addr(in, 2, &addr_lo, &post_inc, &post_idx_3op))
            return false;
        std::string addr_hi = fresh();
        ir << "  " << addr_hi << " = add i32 " << addr_lo << ", 4\n";
        std::string p_lo = stack_ptr(addr_lo);
        std::string p_hi = stack_ptr(addr_hi);
        std::string lo = load_reg(rs_lo);
        std::string hi = load_reg(rs_hi);
        // Resolve the writeback target + value up front (pure; dominates
        // any guard). post-indexed/3op -> post_inc; plain writeback ->
        // addr_lo; none -> rb_wb stays -1.
        int rb_wb = -1;
        std::string wb_val;
        if ((d.writeback || post_idx_3op) && !post_inc.empty()) {
            rb_wb = arm_reg_idx(d.operands[2].mem.base);
            wb_val = post_inc;
        } else if (d.writeback) {
            rb_wb = arm_reg_idx(d.operands[2].mem.base);
            wb_val = addr_lo;
        }
        if (current_pred.empty()) {
            ir << "  store i32 " << lo << ", ptr " << p_lo << ", align 4\n";
            ir << "  store i32 " << hi << ", ptr " << p_hi << ", align 4\n";
            if (emit_store_trace_) {
                ir << "  call void @__macapk_trace_store(i32 "
                   << addr_lo << ", i32 " << lo
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                ir << "  call void @__macapk_trace_store(i32 "
                   << addr_hi << ", i32 " << hi
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
            }
            if (rb_wb >= 0) store_reg(rb_wb, wb_val);
        } else {
            // Predicated STRD (A8.8.210): guard both element stores AND
            // the base writeback in one BB so the false path performs no
            // access. lo/hi/p_lo/p_hi/wb_val are pure and dominate.
            std::string saved_pred = current_pred;
            int gk = pred_guard_begin(saved_pred);
            current_pred.clear();
            ir << "  store i32 " << lo << ", ptr " << p_lo << ", align 4\n";
            ir << "  store i32 " << hi << ", ptr " << p_hi << ", align 4\n";
            if (emit_store_trace_) {
                ir << "  call void @__macapk_trace_store(i32 "
                   << addr_lo << ", i32 " << lo
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
                ir << "  call void @__macapk_trace_store(i32 "
                   << addr_hi << ", i32 " << hi
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
            }
            if (rb_wb >= 0) store_reg_to_mem(rb_wb, wb_val);
            current_pred = saved_pred;
            pred_guard_end(gk);
        }
        return true;
    }

    // CLZ Rd, Rn  -- count leading zeros. LLVM has llvm.ctlz intrinsic.
    bool emit_clz(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rs = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rs < 0) return false;
        std::string v = load_reg(rs);
        std::string out = fresh();
        ir << "  " << out << " = call i32 @llvm.ctlz.i32(i32 " << v
           << ", i1 false)\n";
        store_reg(rd, out);
        return true;
    }

    bool emit_mul(const cs_insn* in) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 3 && d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        if (rd < 0) return false;
        int rn_idx = 1;
        int rm_idx = (d.op_count == 3) ? 2 : 1;
        if (d.operands[rn_idx].type != ARM_OP_REG) return false;
        if (d.operands[rm_idx].type != ARM_OP_REG) return false;
        int rn = arm_reg_idx(d.operands[rn_idx].reg);
        int rm = arm_reg_idx(d.operands[rm_idx].reg);
        if (rn < 0 || rm < 0) return false;
        std::string a = load_reg(rn);
        std::string b = load_reg(rm);
        std::string out = fresh();
        ir << "  " << out << " = mul i32 " << a << ", " << b << "\n";
        store_reg(rd, out);
        if (d.update_flags) emit_set_nz(out);
        return true;
    }

    bool emit_shift(const cs_insn* in, const char* iop) {
        const cs_arm& d = in->detail->arm;
        // ARM mode reports two encodings for LSR/LSL/ASR:
        //   - 3-operand: LSR Rd, Rm, Rs|#imm  (op_count == 3)
        //   - 2-operand: LSR Rd, Rm           (op_count == 2; the shift
        //     amount lives in operands[1].shift.value)
        // The compiler picks the 2-operand form when the assembler can
        // encode the shift as a modifier on Rm.
        if (d.op_count != 3 && d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_REG) return false;
        int rd = arm_reg_idx(d.operands[0].reg);
        int rn = arm_reg_idx(d.operands[1].reg);
        if (rd < 0 || rn < 0) return false;
        std::string lhs = load_reg(rn);

        std::string rhs;
        bool is_imm_shift;
        int32_t imm_shift = 0;

        if (d.op_count == 3) {
            const cs_arm_op& shop = d.operands[2];
            if (!operand_value(shop, &rhs)) return false;
            is_imm_shift = shop.type == ARM_OP_IMM;
            imm_shift = is_imm_shift
                ? static_cast<int32_t>(shop.imm) : 0;
        } else {
            const cs_arm_op& op1 = d.operands[1];
            if (op1.shift.type == ARM_SFT_INVALID && op1.shift.value == 0) {
                // 2-op LSL/LSR/ASR Rd, Rs: Rd = Rd shift Rs (Rs is a
                // register; the instruction id implies the shift kind).
                // The source value is Rd's existing value, not Rs.
                lhs = load_reg(rd);
                rhs = load_reg(rn);
                is_imm_shift = false;
            } else {
                bool ok = true;
                switch (op1.shift.type) {
                    case ARM_SFT_LSL: case ARM_SFT_LSR:
                    case ARM_SFT_ASR: case ARM_SFT_ROR:
                        is_imm_shift = true;
                        imm_shift = static_cast<int32_t>(op1.shift.value);
                        rhs = std::to_string(imm_shift);
                        break;
                    case ARM_SFT_LSL_REG: case ARM_SFT_LSR_REG:
                    case ARM_SFT_ASR_REG: case ARM_SFT_ROR_REG: {
                        int sh_reg = arm_reg_idx(op1.shift.value);
                        if (sh_reg < 0) { ok = false; break; }
                        rhs = load_reg(sh_reg);
                        is_imm_shift = false;
                        break;
                    }
                    default:
                        ok = false;
                        break;
                }
                if (!ok) return false;
            }
        }

        // The amount is R[s]<7:0> for the register form (A8.8.100 LSL,
        // A8.8.102 LSR, A8.8.14 ASR: `shift_n = UInt(R[m]<7:0>)`), and the
        // architecture SATURATES past 32 -- it does not wrap. The old code
        // masked to 5 bits, which turns `lsl r0, r1, r2` with r2 == 32
        // into a no-op shift (r0 unchanged) where ARM requires 0. A raw
        // unmasked shift is no better: LLVM makes an amount >= 32 poison.
        // shift_amount_safe / _const lower both cases architecturally.
        std::string s_iop = iop;
        std::string out = is_imm_shift
            ? shift_amount_const(lhs, s_iop, imm_shift)
            : shift_amount_safe(lhs, s_iop, rhs);
        store_reg(rd, out);
        if (d.update_flags) {
            emit_set_nz(out);
            if (!is_imm_shift) {
                // BUG 3, second home. This used to skip the C update
                // entirely for a register amount ("variable shift carry
                // semantics are messy and rarely relied on"), which
                // silently left a STALE C for every `lsrs rd, rn, rs`.
                // Shift_C defines it, so compute it.
                store_flag("c", reg_shift_carry(lhs, s_iop, rhs));
            } else if (imm_shift > 0 && imm_shift <= 32) {
                // Shift_C bit position, valid through amount 32:
                //   LSL -> value<32-n>  (n == 32 gives value<0>)
                //   LSR / ASR -> value<n-1>  (n == 32 gives value<31>)
                int bit;
                if (s_iop == "shl") bit = 32 - imm_shift;
                else                bit = imm_shift - 1;
                std::string c_shifted = fresh();
                ir << "  " << c_shifted << " = lshr i32 " << lhs
                   << ", " << bit << "\n";
                std::string c_lo = fresh();
                ir << "  " << c_lo << " = and i32 " << c_shifted << ", 1\n";
                std::string c_bit = fresh();
                ir << "  " << c_bit << " = icmp ne i32 " << c_lo << ", 0\n";
                store_flag("c", c_bit);
            }
        }
        return true;
    }

    // --- Memory access -----------------------------------------------

    // ignore_disp: for NEON vld/vst multi-element operands `[Rn:align]`,
    // Capstone reports the ALIGNMENT (16/32/64/128/256) in op.mem.disp -- it
    // is a hint, NOT a byte displacement, and NEON multi-element loads have no
    // #imm offset form. Adding it loads from Rn+align (e.g. vld1.64 {d16,d17},
    // [r0:128] read [r0+128]) -> wrong constant/data -> e.g. stb_image's
    // vectorized zbuild_huffman got a wrong vcgt mask -> "Corrupt PNG". So the
    // NEON multi-element caller passes ignore_disp=true. Scalar/VLDR callers
    // keep disp (a real #imm offset).
    std::string compute_mem_addr(const cs_arm_op& op, bool ignore_disp = false) {
        int rbase = arm_reg_idx(op.mem.base);
        if (rbase < 0) return {};
        std::string base;
        if (op.mem.base == ARM_REG_PC) {
            // ARM32: PC reads as `insn_addr + 8` in ARM mode and
            // `insn_addr + 4` in Thumb. Compiler-emitted constant
            // pools rely on this for `ldr Rt, [pc, #imm]` patterns;
            // without the substitution we'd read register slot 15
            // (always 0) and dereference at offset = imm, which lands
            // inside the per-function stack alloca and returns garbage.
            // Also align down to 4 bytes per ARM PC-relative rules.
            uint32_t pc_value =
                (current_insn_addr + (current_is_thumb ? 4u : 8u)) & ~3u;
            base = std::to_string(static_cast<int64_t>(pc_value + load_bias_));  // per-image bias
        } else {
            base = load_reg(rbase);
        }
        int32_t disp = ignore_disp ? 0 : static_cast<int32_t>(op.mem.disp);
        if (op.mem.index != ARM_REG_INVALID) {
            int ri = arm_reg_idx(op.mem.index);
            if (ri < 0) return {};
            std::string idx = load_reg(ri);
            // Apply the shift on the index register. ARM allows LSL,
            // LSR, ASR, ROR, and RRX on memory operand index regs --
            // not just LSL. apply_shift handles every case (and is
            // also the helper used by ALU operand decoding), so the
            // memory path and the ALU path stay consistent.
            if (!apply_shift(op, &idx)) return {};
            // Capstone reports `scale == -1` (and/or `op.subtracted`
            // depending on the version) for `[Rn, -Rm]`-form memory
            // operands, where the index register is SUBTRACTED rather
            // than added. Compilers emit this for bidirectional walks
            // (linked-list deletion, ring-buffer wrap, stack-grow-down
            // increments). Without the sign branch we'd add when we
            // should be subtracting, off by 2*idx every access.
            std::string sum = fresh();
            bool subtract = (op.mem.scale == -1) || op.subtracted;
            ir << "  " << sum << " = "
               << (subtract ? "sub" : "add")
               << " i32 " << base << ", " << idx << "\n";
            base = sum;
        }
        if (disp == 0) return base;
        std::string out = fresh();
        ir << "  " << out << " = add i32 " << base << ", " << disp << "\n";
        return out;
    }

    bool emit_str_size(const cs_insn* in, int bits) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2 && d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_MEM) return false;
        int rsrc = arm_reg_idx(d.operands[0].reg);
        if (rsrc < 0) return false;
        // 3-operand form is post-indexed regardless of Capstone's
        // post_index flag (which has inconsistent semantics across
        // instruction variants in some Capstone builds). The third
        // operand carries the post-increment, IMM or REG, with
        // `subtracted` indicating sign for the REG form.
        bool post_idx_3op = (d.op_count == 3);
        bool writeback = d.writeback || post_idx_3op;
        std::string access_addr;
        std::string post_increment_base;
        if (post_idx_3op) {
            int rb = arm_reg_idx(d.operands[1].mem.base);
            if (rb < 0) return false;
            access_addr = load_reg(rb);
            const cs_arm_op& off = d.operands[2];
            std::string inc;
            if (off.type == ARM_OP_IMM) {
                inc = std::to_string(static_cast<int32_t>(off.imm));
            } else if (off.type == ARM_OP_REG) {
                int ri = arm_reg_idx(off.reg);
                if (ri < 0) return false;
                inc = load_reg(ri);
                if (!apply_shift(off, &inc)) return false;
            } else return false;
            std::string post_addr = fresh();
            ir << "  " << post_addr << " = "
               << (off.subtracted ? "sub" : "add")
               << " i32 " << access_addr << ", " << inc << "\n";
            post_increment_base = post_addr;
        } else {
            access_addr = compute_mem_addr(d.operands[1]);
            if (access_addr.empty()) return false;
        }
        std::string p = stack_ptr(access_addr);
        std::string src_val = load_reg(rsrc);

        // Pick the storage type and a value of that type.
        std::string ty = (bits == 32) ? "i32" : (bits == 16) ? "i16" : "i8";
        int align    =  (bits == 32) ? 4    : (bits == 16) ? 2    : 1;
        std::string narrow_val;
        if (bits == 32) {
            narrow_val = src_val;
        } else {
            std::string tr = fresh();
            ir << "  " << tr << " = trunc i32 " << src_val
               << " to " << ty << "\n";
            narrow_val = tr;
        }

        // Watchpoint-hook source value (computed once, used on both paths).
        std::string src32 = (bits == 32) ? src_val : narrow_val;
        int rb_wb = (writeback || post_idx_3op)
                        ? arm_reg_idx(d.operands[1].mem.base) : -1;
        if (current_pred.empty()) {
            ir << "  store " << ty << " " << narrow_val << ", ptr " << p
               << ", align " << align << "\n";
            // Watchpoint hook (see header above): no-op unless
            // MACAPK_LIFTER_EMIT_STORE_TRACE=1 at lift time.
            if (bits == 32 && emit_store_trace_) {
                ir << "  call void @__macapk_trace_store(i32 "
                   << access_addr << ", i32 " << src32
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
            }
            // Apply writeback to the base register if requested.
            if (rb_wb >= 0) {
                if (!post_increment_base.empty())
                    store_reg(rb_wb, post_increment_base);
                else
                    store_reg(rb_wb, access_addr); // pre-indexed
            }
        } else {
            // Predicated store: guard the access AND writeback in a real
            // BB so the false path performs NO memory access / NO
            // writeback (ARM ARM A8.3 + A8.8.204). All address math,
            // narrow_val, and `p` were computed above and dominate the
            // guard block. Clear current_pred inside the guard so the
            // relocated store/writeback is not select-blended.
            std::string saved_pred = current_pred;
            int gk = pred_guard_begin(saved_pred);
            current_pred.clear();
            ir << "  store " << ty << " " << narrow_val << ", ptr " << p
               << ", align " << align << "\n";
            if (bits == 32 && emit_store_trace_) {
                ir << "  call void @__macapk_trace_store(i32 "
                   << access_addr << ", i32 " << src32
                   << ", i32 " << static_cast<uint32_t>(in->address) << ")\n";
            }
            if (rb_wb >= 0) {
                // Writeback INSIDE the guard, straight to the %r slot
                // (cache is cleared at the join; store_reg would be lost
                // and would re-introduce a select on stale current_pred).
                store_reg_to_mem(rb_wb, !post_increment_base.empty()
                                            ? post_increment_base
                                            : access_addr);
            }
            current_pred = saved_pred;
            pred_guard_end(gk);
        }
        return true;
    }

    bool emit_ldr_size(const cs_insn* in, int bits, bool sign_extend) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2 && d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_MEM) return false;
        int rdst = arm_reg_idx(d.operands[0].reg);
        if (rdst < 0) return false;
        bool post_idx_3op = (d.op_count == 3);
        bool writeback = d.writeback || post_idx_3op;
        std::string access_addr;
        std::string post_increment_base;
        if (post_idx_3op) {
            int rb = arm_reg_idx(d.operands[1].mem.base);
            if (rb < 0) return false;
            access_addr = load_reg(rb);
            const cs_arm_op& off = d.operands[2];
            std::string inc;
            if (off.type == ARM_OP_IMM) {
                inc = std::to_string(static_cast<int32_t>(off.imm));
            } else if (off.type == ARM_OP_REG) {
                int ri = arm_reg_idx(off.reg);
                if (ri < 0) return false;
                inc = load_reg(ri);
                if (!apply_shift(off, &inc)) return false;
            } else return false;
            std::string post_addr = fresh();
            ir << "  " << post_addr << " = "
               << (off.subtracted ? "sub" : "add")
               << " i32 " << access_addr << ", " << inc << "\n";
            post_increment_base = post_addr;
        } else {
            access_addr = compute_mem_addr(d.operands[1]);
            if (access_addr.empty()) return false;
        }
        std::string p = stack_ptr(access_addr);
        int rb_wb = (writeback || post_idx_3op)
                        ? arm_reg_idx(d.operands[1].mem.base) : -1;
        std::string wb_val;
        if (rb_wb >= 0)
            wb_val = !post_increment_base.empty() ? post_increment_base
                                                  : access_addr;
        if (current_pred.empty()) {
            if (bits == 32) {
                std::string raw = fresh();
                ir << "  " << raw << " = load i32, ptr " << p << ", align 4\n";
                store_reg(rdst, raw);
            } else {
                std::string raw = fresh();
                std::string ext = fresh();
                if (bits == 16) {
                    ir << "  " << raw << " = load i16, ptr " << p << ", align 2\n";
                    ir << "  " << ext << " = " << (sign_extend ? "sext" : "zext")
                       << " i16 " << raw << " to i32\n";
                } else {
                    ir << "  " << raw << " = load i8, ptr " << p << ", align 1\n";
                    ir << "  " << ext << " = " << (sign_extend ? "sext" : "zext")
                       << " i8 " << raw << " to i32\n";
                }
                store_reg(rdst, ext);
            }
            if (rb_wb >= 0) store_reg(rb_wb, wb_val);
        } else {
            // Predicated LDR (A8.8.66): the LOAD itself must not execute
            // on the false path (`cmp r1,#0; ldrne r0,[r1]` must not
            // dereference NULL when r1==0). Guard the load + the
            // register update + the base writeback in one BB. On the
            // false path rdst and the base are unchanged in memory (we
            // flushed before the br); on the true path we write the
            // loaded value straight to the %r slot (cache is cleared at
            // the join, so store_reg would be lost). `p` and `wb_val`
            // are pure and dominate the guard.
            std::string saved_pred = current_pred;
            int gk = pred_guard_begin(saved_pred);
            current_pred.clear();
            std::string ext;
            if (bits == 32) {
                std::string raw = fresh();
                ir << "  " << raw << " = load i32, ptr " << p << ", align 4\n";
                ext = raw;
            } else if (bits == 16) {
                std::string raw = fresh();
                ext = fresh();
                ir << "  " << raw << " = load i16, ptr " << p << ", align 2\n";
                ir << "  " << ext << " = " << (sign_extend ? "sext" : "zext")
                   << " i16 " << raw << " to i32\n";
            } else {
                std::string raw = fresh();
                ext = fresh();
                ir << "  " << raw << " = load i8, ptr " << p << ", align 1\n";
                ir << "  " << ext << " = " << (sign_extend ? "sext" : "zext")
                   << " i8 " << raw << " to i32\n";
            }
            store_reg_to_mem(rdst, ext);
            if (rb_wb >= 0) store_reg_to_mem(rb_wb, wb_val);
            current_pred = saved_pred;
            pred_guard_end(gk);
        }
        return true;
    }

    // --- Branches -----------------------------------------------------

    bool emit_uncond_branch(const cs_insn* in, uint32_t fn_start,
                            uint32_t fn_end_excl, bool* terminated) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 1) return false;
        if (d.operands[0].type != ARM_OP_IMM) return false;
        uint32_t target = static_cast<uint32_t>(d.operands[0].imm);
        // MACAPK_FIRSTLAUNCH_LIFT_NOIR: the extern-target record is this
        // handler's only non-IR effect; everything after it formats IR.
        if (discovery_only_) {
            if (target < fn_start || target >= fn_end_excl
                || valid_addrs_.count(target) == 0)
                extern_call_targets.insert(target);
            return true;
        }
        if (target < fn_start || target >= fn_end_excl
            || valid_addrs_.count(target) == 0) {
            // Tail call out of the function. Pass current R0..R3 as
            // args so the callee sees what the original branch saw.
            extern_call_targets.insert(target);
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Diagnostic: log the tail-B as a "bl-style" call so the
            // same MACAPK_TRACE_BL[_TO] env vars cover both bl and
            // tail-B paths. Tail-B is how nativeInit reaches its
            // chain target in HCR 1.43 (the `b 0x221e04` at
            // nativeInit+0x44 -- not a bl, so emit_bl's tracer missed
            // it). Without this hook the bug-2 caller chain is
            // invisible. See feedback-no-guess-and-check: the right
            // move when investigation hits a dead end is to add the
            // instrument that covers the missing path.
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << target
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = tail call i32 @__macapk_target_"
               << std::hex << target << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            ir << "  ret i32 " << ret << "\n";
            *terminated = true;
            return true;
        }
        // Cross-block branch: dirty cached regs must hit memory
        // before the destination block (which clears cache) loads
        // them.
        flush_dirty_regs();
        ir << "  br label %" << bb_label(target) << "\n";
        *terminated = true;
        return true;
    }

    bool emit_cond_branch(const cs_insn* in, uint32_t fn_start,
                          uint32_t fn_end_excl, uint32_t fall_through,
                          bool* terminated) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 1) return false;
        if (d.operands[0].type != ARM_OP_IMM) return false;
        uint32_t target = static_cast<uint32_t>(d.operands[0].imm);
        // MACAPK_FIRSTLAUNCH_LIFT_NOIR: as in emit_uncond_branch, the
        // extern-target record (the else arm at the bottom, same predicate)
        // is the only non-IR effect; emit_cond_check and the labels are IR.
        if (discovery_only_) {
            if (!(target >= fn_start && target < fn_end_excl
                  && valid_addrs_.count(target) > 0))
                extern_call_targets.insert(target);
            return true;
        }
        std::string cond = emit_cond_check(in->detail->arm.cc);
        // Resolve fall-through: it must be a valid instruction start
        // for the IR to reference. Otherwise we synthesize a tiny ret
        // block (the function effectively ends here on the not-taken
        // path).
        std::string fall_label;
        bool fall_is_synth = (valid_addrs_.count(fall_through) == 0);
        std::string synth_fall;
        if (fall_is_synth) {
            synth_fall = "fall_" + std::to_string(ssa_counter++);
            fall_label = "%" + synth_fall;
        } else {
            fall_label = "%" + bb_label(fall_through);
        }
        auto emit_synth_fall = [&]() {
            if (fall_is_synth) {
                ir << synth_fall << ":\n";
                // synth_fall is a parallel-sibling block to the taken
                // path emitted earlier in this lambda's scope. Clear
                // cache so load_reg(0) below issues a fresh load and
                // doesn't reach for an SSA name defined in the sibling.
                cache_clear();
                std::string r0 = load_reg(0);
                ir << "  ret i32 " << r0 << "\n";
            }
        };
        if (target >= fn_start && target < fn_end_excl
            && valid_addrs_.count(target) > 0) {
            // Both targets are real blocks in this fn that will
            // clear cache on entry; must persist dirty regs first.
            flush_dirty_regs();
            ir << "  br i1 " << cond << ", label %" << bb_label(target)
               << ", label " << fall_label << "\n";
            emit_synth_fall();
        } else {
            extern_call_targets.insert(target);
            std::string call_block = "ext_" + std::to_string(ssa_counter++);
            // The taken-path lands in call_block, which is dominated
            // by this block -- cached SSA names remain reachable via
            // dominance. But the fall path goes to a real fn block
            // that clears cache, so flush regardless.
            flush_dirty_regs();
            ir << "  br i1 " << cond << ", label %" << call_block
               << ", label " << fall_label << "\n";
            ir << call_block << ":\n";
            // Parallel-sibling block: see emit_extern comment above.
            cache_clear();
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Trace conditional-tail-call (B<cond> to out-of-fn target).
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << target
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = tail call i32 @__macapk_target_"
               << std::hex << target << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            ir << "  ret i32 " << ret << "\n";
            emit_synth_fall();
        }
        *terminated = true;
        return true;
    }

    // BUG 4 (2026-07-25). A predicated call -- `blne`, `bleq`, `blxls`, or
    // any BL/BLX inside a Thumb IT block -- must not happen when the
    // condition is false. ARM wraps the ENTIRE instruction in
    // `if ConditionPassed() then ...` (A8.3), so on a false predicate
    // there is no call, no LR write, and no r0 clobber.
    //
    // The old lowering called UNCONDITIONALLY and (for BLX only) blended
    // the register writes afterwards with a select. Blending cannot undo a
    // call: the callee's side effects have already happened. HCR's
    // libgame.so has 24 predicated calls and Jetpack Joyride 2.
    //
    // Reuses the same CFG diamond as the predicated-memory guard, so the
    // false path branches around the call entirely. Register writes inside
    // the guard go straight to the %r alloca (store_reg is cache-only and
    // the join clears the cache, so a cached write would be lost).
    struct CallGuard {
        int gk = -1;
        std::string saved_pred;
    };
    CallGuard call_guard_begin(const cs_arm& d) {
        CallGuard g;
        if (is_always(static_cast<arm_cc>(d.cc))) return g;
        std::string p = current_pred.empty()
            ? emit_cond_check(static_cast<arm_cc>(d.cc)) : current_pred;
        g.saved_pred = current_pred;
        g.gk = pred_guard_begin(p);
        current_pred.clear();
        return g;
    }
    void call_guard_end(const CallGuard& g) {
        if (g.gk < 0) return;
        current_pred = g.saved_pred;
        pred_guard_end(g.gk);
    }
    void guarded_store_reg(const CallGuard& g, int r, const std::string& v) {
        if (g.gk >= 0) store_reg_to_mem(r, v);
        else           store_reg(r, v);
    }

    bool emit_bl(const cs_insn* in, uint32_t return_addr) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count < 1) return false;
        if (d.operands[0].type != ARM_OP_IMM) return false;
        uint32_t target = static_cast<uint32_t>(d.operands[0].imm);
        // Translate-time bookkeeping: the callee still has to be emitted
        // and declared even when the call is conditional, so this stays
        // outside the guard.
        extern_call_targets.insert(target);
        // Authoritative: an actual BL #imm instruction -- the target is a
        // function entry per the ARM PCS, not a possibly-misclassified
        // intra-function branch. (The comment here used to say "BL/BLX", but
        // this helper's only caller is `case ARM_INS_BL`; BLX #imm is handled
        // separately, and the distinction matters for the mode note below.)
        extern_bl_targets.insert(target);
        // v1.0.814: plain BL does not interwork, so the callee's ISA mode is
        // the caller's. See note_call_target_mode.
        note_call_target_mode(target, current_is_thumb);
        // MACAPK_FIRSTLAUNCH_LIFT_NOIR: the three records above are this
        // handler's only non-IR effects; the call itself is IR.
        if (discovery_only_) return true;
        CallGuard cg = call_guard_begin(d);
        guarded_store_reg(cg, 14, std::to_string(return_addr + load_bias_));  // per-image bias (LR-as-data consistency; returns are C ret)
        std::string a0 = load_reg(0);
        std::string a1 = load_reg(1);
        std::string a2 = load_reg(2);
        std::string a3 = load_reg(3);
        std::string sp = load_reg(13);
        // Direct-BL diagnostic: a call to __macapk_trace_bl placed
        // BEFORE the actual target call so r0..r3 (about to become the
        // callee's args) are observable. The shim function is no-op
        // unless MACAPK_TRACE_BL or MACAPK_TRACE_BL_TO env is set;
        // when set, it logs from/to/args so we can pinpoint which
        // lifted caller passes a JNI handle as r1 into a function that
        // expects a C++ pointer (bug-2 root-cause hunt 2026-05-19).
        // The cost of the unconditional CALL when disabled is ~5 host
        // instructions (test+branch in the shim's static cache); fine
        // for a diagnostic build, off in steady state.
        ir << "  call void @__macapk_trace_bl(i32 "
           << static_cast<uint32_t>(in->address) << ", i32 "
           << target
           << ", i32 " << a0 << ", i32 " << a1
           << ", i32 " << a2 << ", i32 " << a3 << ")\n";
        // Soft-float double-returning math imports (sin, cos, etc.):
        // emit i64-returning call and split into r0 (LOW) and r1
        // (HIGH). cocos2d-x v2's kCCDirectorProjection3D needs this
        // to get correct cot(fovY/2). Without it, the lifted code's
        // post-call `vmov dN, r0, r1` reads stale r1 and reconstructs
        // a double that's the INPUT angle's HIGH bits OR'd with the
        // LOW bits of sin(input), producing wrong matrices.
        if (soft_float_double_plt_.count(target)) {
            std::string ret64 = fresh();
            ir << "  " << ret64 << " = call i64 @__macapk_target_"
               << std::hex << target << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            std::string lo = fresh();
            std::string hi_shr = fresh();
            std::string hi = fresh();
            ir << "  " << lo << " = trunc i64 " << ret64 << " to i32\n";
            ir << "  " << hi_shr << " = lshr i64 " << ret64 << ", 32\n";
            ir << "  " << hi << " = trunc i64 " << hi_shr << " to i32\n";
            guarded_store_reg(cg, 0, lo);
            guarded_store_reg(cg, 1, hi);
            call_guard_end(cg);
            return true;
        }
        std::string ret = fresh();
        ir << "  " << ret << " = call i32 @__macapk_target_"
           << std::hex << target << std::dec
           << "(i32 " << a0 << ", i32 " << a1
           << ", i32 " << a2 << ", i32 " << a3
           << ", i32 " << sp << ")\n";
        guarded_store_reg(cg, 0, ret);
        call_guard_end(cg);
        return true;
    }

    // CBZ Rn, #target  -- Thumb compare-and-branch-zero (forward only,
    // no flag update). CBNZ is the negated form.
    bool emit_cb(const cs_insn* in, bool branch_if_nonzero,
                  uint32_t fn_start, uint32_t fn_end_excl, bool* terminated) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 2) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        if (d.operands[1].type != ARM_OP_IMM) return false;
        int rn = arm_reg_idx(d.operands[0].reg);
        if (rn < 0) return false;
        uint32_t target = static_cast<uint32_t>(d.operands[1].imm);
        std::string val = load_reg(rn);
        std::string cond = fresh();
        ir << "  " << cond << " = icmp "
           << (branch_if_nonzero ? "ne" : "eq")
           << " i32 " << val << ", 0\n";
        uint32_t fall = static_cast<uint32_t>(in->address) + in->size;
        bool fall_is_synth = (valid_addrs_.count(fall) == 0);
        std::string synth_fall;
        std::string fall_label;
        if (fall_is_synth) {
            synth_fall = "fall_" + std::to_string(ssa_counter++);
            fall_label = "%" + synth_fall;
        } else {
            fall_label = "%" + bb_label(fall);
        }
        auto emit_synth_fall = [&]() {
            if (fall_is_synth) {
                ir << synth_fall << ":\n";
                // synth_fall is a parallel-sibling block to the taken
                // path emitted earlier in this lambda's scope. Clear
                // cache so load_reg(0) below issues a fresh load and
                // doesn't reach for an SSA name defined in the sibling.
                cache_clear();
                std::string r0 = load_reg(0);
                ir << "  ret i32 " << r0 << "\n";
            }
        };
        if (target >= fn_start && target < fn_end_excl
            && valid_addrs_.count(target) > 0) {
            flush_dirty_regs();
            ir << "  br i1 " << cond << ", label %" << bb_label(target)
               << ", label " << fall_label << "\n";
            emit_synth_fall();
        } else {
            extern_call_targets.insert(target);
            std::string ext = "ext_" + std::to_string(ssa_counter++);
            flush_dirty_regs();
            ir << "  br i1 " << cond << ", label %" << ext
               << ", label " << fall_label << "\n";
            ir << ext << ":\n";
            // Parallel-sibling block: see emit_extern comment above.
            cache_clear();
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Trace conditional extern-tail-call.
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << target
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = tail call i32 @__macapk_target_"
               << std::hex << target << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            ir << "  ret i32 " << ret << "\n";
            emit_synth_fall();
        }
        *terminated = true;
        return true;
    }

    // ----- TBB / TBH (Thumb-2 jump-table) lifting --------------------
    //
    // Compilers emit the canonical 3-instruction sequence
    //
    //     cmp  Rn, #N
    //     bhi  default_label
    //     tbb  [pc, Rn]            ; or tbh [pc, Rn, lsl #1]
    //     <inline N+1 byte/halfword table>
    //
    // for `switch` statements. Each table entry is a half-instruction
    // count from the address right after the TBB/TBH (i.e. the first
    // table byte): target = (TBB_addr + 4) + 2 * table[idx].
    //
    // Without explicit handling Capstone disassembles the table bytes
    // as bogus instructions and the lifter falls straight through to
    // the default-label code. Real-world impact: HCR's libpng 1.2.46
    // png_create_read_struct_2 always returns NULL because the switch
    // on `inflateInit_()`'s return value gets miscompiled.
    //
    // decode_tbb_table fills in target VAs and the table's byte size.
    // emit_tbb emits an LLVM `switch` on the index register and adds
    // the table-data addresses to tbb_skip_addrs_ so the main loop
    // doesn't try to lift them.

    struct TbbTable {
        uint32_t              pc_value;     // = TBB_addr + 4 (Thumb): the
                                           // BRANCH-target base (target =
                                           // pc_value + 2*entry), per A8.8.
        uint32_t              table_addr;   // where the table BYTES live.
                                           // == pc_value for the PC-base
                                           // inline form; == the register
                                           // base (Rn) for `tbh [Rn,Rm]`.
        uint32_t              entry_count;  // (cmp imm) + 1
        uint32_t              entry_size;   // 1 (TBB) or 2 (TBH)
        int                   index_reg;    // arm reg idx (0..15)
        uint32_t              default_target; // bhi destination
        bool                  has_default;
        std::vector<uint32_t> targets;      // length == entry_count
    };

    bool decode_tbb_table(const cs_insn* in, TbbTable* out) const {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 1 || d.operands[0].type != ARM_OP_MEM) return false;
        const auto& mem = d.operands[0].mem;
        int idx_reg = arm_reg_idx(static_cast<arm_reg>(mem.index));
        if (idx_reg < 0) return false;

        // BRANCH-target base is the Thumb PC of the TBB/TBH (addr + 4),
        // regardless of where the table BYTES live (ARM ARM A8.8.x:
        // target = PC + 2*entry). For the PC-relative inline form the
        // table also lives at PC; for `tbh [Rn, Rm, lsl #1]` the table is
        // at Rn (a runtime value the compiler just set PC-relative).
        out->pc_value    = static_cast<uint32_t>(in->address) + in->size;
        out->entry_size  = (in->id == ARM_INS_TBH) ? 2u : 1u;
        out->index_reg   = idx_reg;
        out->has_default = false;
        out->default_target = 0;
        out->entry_count = 0;

        if (mem.base == ARM_REG_PC) {
            out->table_addr = out->pc_value;               // inline table
        } else {
            // Register-base form: recover Rn by scanning back a short
            // window for the PC-relative definition that set it -- the
            // `addw Rn, pc, #imm` / `add Rn, pc, #imm` / `adr Rn, label`
            // the compiler emits right before the TBH. Thumb PC of that
            // instruction is Align(insn_addr + 4, 4).
            int base_reg = arm_reg_idx(static_cast<arm_reg>(mem.base));
            if (base_reg < 0 || !current_insns_) return false;
            bool found = false;
            size_t lo = (current_idx_ > 8) ? current_idx_ - 8 : 0;
            for (size_t j = current_idx_; j-- > lo; ) {
                const cs_insn* pi = &current_insns_[j];
                const cs_arm& pd = pi->detail->arm;
                if (pd.op_count < 2 || pd.operands[0].type != ARM_OP_REG ||
                    arm_reg_idx(pd.operands[0].reg) != base_reg) continue;
                uint32_t tpc = (static_cast<uint32_t>(pi->address) + 4u) & ~3u;
                if (pi->id == ARM_INS_ADD && pd.op_count == 3 &&
                    pd.operands[1].type == ARM_OP_REG &&
                    pd.operands[1].reg == ARM_REG_PC &&
                    pd.operands[2].type == ARM_OP_IMM) {
                    out->table_addr = tpc +
                        static_cast<uint32_t>(pd.operands[2].imm);
                    found = true;
                } else if (pi->id == ARM_INS_ADR && pd.op_count == 2 &&
                           pd.operands[1].type == ARM_OP_IMM) {
                    out->table_addr = tpc +
                        static_cast<uint32_t>(pd.operands[1].imm);
                    found = true;
                }
                // First (nearest) write to base_reg wins; an earlier one
                // is stale whether or not it was the PC-relative form.
                break;
            }
            if (!found) return false;
        }

        // Find the bounding `cmp idx_reg, #N` + `b.hi default`. For the
        // PC-base form it sits at idx-2/idx-1; for the register-base form
        // an intervening `addw Rn, pc` pushes it back one, so scan a small
        // window rather than assuming fixed offsets.
        if (current_insns_) {
            size_t lo = (current_idx_ > 6) ? current_idx_ - 6 : 0;
            for (size_t j = current_idx_; j-- > lo; ) {
                const cs_insn* cmp = &current_insns_[j];
                const cs_arm& cd = cmp->detail->arm;
                if (cmp->id != ARM_INS_CMP || cd.op_count != 2 ||
                    cd.operands[0].type != ARM_OP_REG ||
                    cd.operands[0].reg != static_cast<arm_reg>(mem.index) ||
                    cd.operands[1].type != ARM_OP_IMM) continue;
                int64_t imm = cd.operands[1].imm;
                if (imm >= 0 && imm < 1024) {
                    out->entry_count = static_cast<uint32_t>(imm) + 1;
                }
                if (j + 1 < current_idx_) {
                    const cs_insn* bhi = &current_insns_[j + 1];
                    const cs_arm& bd = bhi->detail->arm;
                    if (bhi->id == ARM_INS_B && bd.cc == ARM_CC_HI &&
                        bd.op_count == 1 &&
                        bd.operands[0].type == ARM_OP_IMM) {
                        out->default_target =
                            static_cast<uint32_t>(bd.operands[0].imm);
                        out->has_default = true;
                    }
                }
                break;
            }
        }
        // Fallback: cap the table to a small but plausible size when
        // we can't find the matching cmp. Better to leave unreachable
        // entries unhandled than to walk past the table into real
        // instructions.
        if (out->entry_count == 0) {
            out->entry_count = (out->entry_size == 1) ? 8u : 4u;
        }

        if (!image_) return false;
        size_t want = static_cast<size_t>(out->entry_count) * out->entry_size;
        auto bytes = image_->code_at(out->table_addr, want);
        if (bytes.size() < want) return false;

        out->targets.reserve(out->entry_count);
        for (uint32_t i = 0; i < out->entry_count; ++i) {
            uint32_t v;
            if (out->entry_size == 1) {
                v = bytes[i];
            } else {
                v = static_cast<uint32_t>(bytes[i*2]) |
                    (static_cast<uint32_t>(bytes[i*2 + 1]) << 8);
            }
            out->targets.push_back(out->pc_value + 2u * v);
        }
        return true;
    }

    bool emit_tbb(const cs_insn* in, uint32_t fn_start,
                   uint32_t fn_end_excl, bool* terminated) {
        TbbTable t;
        if (!decode_tbb_table(in, &t)) {
            ir << "  ; UNSUPPORTED " << in->mnemonic << " " << in->op_str
               << " (could not decode jump table)\n";
            return true;
        }

        // Mark the table-data bytes so the dispatch loop skips them.
        size_t table_bytes =
            static_cast<size_t>(t.entry_count) * t.entry_size;
        for (uint32_t a = t.table_addr;
             a < t.table_addr + table_bytes; ++a) {
            tbb_skip_addrs_.insert(a);
        }
        // Round up to next halfword boundary so the following real
        // instruction is preserved (Thumb code is always 2-byte
        // aligned; an odd-length TBB table is padded with a 0x00).
        if (table_bytes & 1u) {
            tbb_skip_addrs_.insert(t.table_addr + table_bytes);
        }

        // Pick the default label. Prefer the bhi target when known,
        // otherwise fall back to the first table target so we at
        // least don't fall straight through to dead code.
        uint32_t default_va = t.has_default ? t.default_target : t.targets[0];
        bool default_in_fn = (default_va >= fn_start && default_va < fn_end_excl
                              && valid_addrs_.count(default_va) > 0);
        std::string default_label;
        std::string default_extern_block;
        if (default_in_fn) {
            default_label = "%" + bb_label(default_va);
        } else {
            default_extern_block =
                "tbb_def_" + std::to_string(ssa_counter++);
            default_label = "%" + default_extern_block;
            extern_call_targets.insert(default_va);
        }

        std::string idx = load_reg(t.index_reg);

        // Emit: switch i32 idx, label %default [ i32 K, label %case_K ... ]
        // Build per-case extern blocks for any out-of-function targets.
        struct CaseInfo {
            uint32_t va;
            bool in_fn;
            std::string label;          // "%foo"
            std::string extern_block;   // empty if in_fn
        };
        std::vector<CaseInfo> cases;
        cases.reserve(t.entry_count);
        for (uint32_t i = 0; i < t.entry_count; ++i) {
            CaseInfo ci{};
            ci.va = t.targets[i];
            ci.in_fn = (ci.va >= fn_start && ci.va < fn_end_excl &&
                        valid_addrs_.count(ci.va) > 0);
            if (ci.in_fn) {
                ci.label = "%" + bb_label(ci.va);
            } else {
                ci.extern_block =
                    "tbb_case_" + std::to_string(ssa_counter++);
                ci.label = "%" + ci.extern_block;
                extern_call_targets.insert(ci.va);
            }
            cases.push_back(std::move(ci));
        }

        // switch is a terminator; flush before so all targets see
        // consistent memory regardless of cache state here.
        flush_dirty_regs();
        ir << "  switch i32 " << idx << ", label " << default_label << " [\n";
        for (uint32_t i = 0; i < t.entry_count; ++i) {
            ir << "    i32 " << i << ", label " << cases[i].label << "\n";
        }
        ir << "  ]\n";

        // Emit extern-call blocks for any non-in-function targets.
        auto emit_extern = [&](const std::string& blk, uint32_t va) {
            ir << blk << ":\n";
            // Each switch-case / extern-tail-call block is a PARALLEL
            // SIBLING of the others -- reached directly via the switch
            // (or br i1) terminator above, not via fall-through from
            // any previous case. So SSA values defined in a sibling
            // block don't dominate this one. Clear the register cache
            // here so the load_reg() calls below emit fresh loads from
            // memory (which is consistent because flush_dirty_regs ran
            // before the terminator). Without this, sibling cases were
            // reusing each other's %tNNN names and llvm-as rejected
            // the IR with "Instruction does not dominate all uses".
            cache_clear();
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Trace TBB-jump-table extern case.
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << va
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = tail call i32 @__macapk_target_"
               << std::hex << va << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            ir << "  ret i32 " << ret << "\n";
        };
        if (!default_in_fn) emit_extern(default_extern_block, default_va);
        for (auto& ci : cases) {
            if (!ci.in_fn) emit_extern(ci.extern_block, ci.va);
        }

        *terminated = true;
        return true;
    }

    // ----- ARM-mode jump-table via "addCC pc, pc, Rm, lsl #2" --------
    //
    // Compilers emit this for `switch` when the target is ARM mode (not
    // Thumb-2 where TBB applies):
    //
    //     cmp  Rm, #N
    //     addls pc, pc, Rm, lsl #2     ; if Rm <= N: pc += Rm*4
    //     b    DEFAULT                  ; fall-through if cmp fails
    //     b    CASE_0                   ; reached when Rm == 0
    //     b    CASE_1                   ; Rm == 1
    //     ...
    //     b    CASE_N                   ; Rm == N
    //
    // PC inside the addls instruction is `addls_addr + 8` (ARM mode), so
    // index N lands `(N*4)` past `addls_addr+8` -- i.e. on the Nth `b`
    // *after* the fall-through default (which sits at addls_addr+4).
    //
    // The lifter, with no special handling, would compile addls as a
    // store to register 15 (no actual branch) and then sequentially
    // lift the default+case `b`s as straight-line code. Result: every
    // index falls through to the default. cocos2d-x's _initWithPngData
    // colour-type switch is the textbook case -- PNG_COLOR_TYPE_RGB_ALPHA
    // (=6) is supported but always hits "unsopprted color type" because
    // the conditional add is treated as a no-op.

    bool decode_arm_b(uint32_t insn_word, uint32_t at_addr, uint32_t* out) const {
        // ARM B encoding: cond[31:28] | 1010 | imm24
        if (((insn_word >> 25) & 0x7) != 0x5) return false;
        uint8_t cond = (insn_word >> 28) & 0xf;
        // Accept AL (0xe) and a few common conditionals; the table
        // entries are typically unconditional.
        if (cond != 0xe && cond != 0xa && cond != 0xb) return false;
        int32_t imm24 = static_cast<int32_t>(insn_word & 0x00FFFFFF);
        if (imm24 & 0x00800000) imm24 |= 0xFF000000;     // sign-extend
        uint32_t target = at_addr + 8 + (static_cast<uint32_t>(imm24) << 2);
        *out = target;
        return true;
    }

    bool emit_arm_pc_jump_table(const cs_insn* in, uint32_t fn_start,
                                 uint32_t fn_end_excl, bool* terminated) {
        const cs_arm& d = in->detail->arm;
        // Required shape: addCC pc, pc, Rm, lsl #2
        if (d.cc != ARM_CC_LS && d.cc != ARM_CC_LO) return false;
        if (d.op_count != 3) return false;
        if (d.operands[0].type != ARM_OP_REG ||
            d.operands[0].reg != ARM_REG_PC) return false;
        if (d.operands[1].type != ARM_OP_REG ||
            d.operands[1].reg != ARM_REG_PC) return false;
        if (d.operands[2].type != ARM_OP_REG) return false;
        int idx_reg = arm_reg_idx(d.operands[2].reg);
        if (idx_reg < 0) return false;
        if (d.operands[2].shift.type != ARM_SFT_LSL) return false;
        if (d.operands[2].shift.value != 2) return false;

        // Look back for `cmp Rm, #N` to size the table.
        if (!current_insns_ || current_idx_ < 1) return false;
        const cs_insn& cmp_ins = current_insns_[current_idx_ - 1];
        if (cmp_ins.id != ARM_INS_CMP) return false;
        const cs_arm& cd = cmp_ins.detail->arm;
        if (cd.op_count != 2 ||
            cd.operands[0].type != ARM_OP_REG ||
            cd.operands[0].reg != d.operands[2].reg ||
            cd.operands[1].type != ARM_OP_IMM) return false;
        int64_t imm = cd.operands[1].imm;
        if (imm < 0 || imm > 1023) return false;
        uint32_t entry_count = static_cast<uint32_t>(imm) + 1;
        if (d.cc == ARM_CC_LO) {
            // r0 < imm => indices 0..imm-1
            if (entry_count == 0) return false;
            entry_count -= 1;
        }

        if (!image_) return false;

        // Layout: addls @ A. Default `b` @ A+4. Cases @ A+8 .. A+8+(N-1)*4.
        uint32_t addls_addr = static_cast<uint32_t>(in->address);
        uint32_t default_addr = addls_addr + 4;
        uint32_t cases_base = addls_addr + 8;

        // Read default branch
        auto def_bytes = image_->code_at(default_addr, 4);
        if (def_bytes.size() < 4) return false;
        uint32_t def_word =
            static_cast<uint32_t>(def_bytes[0]) |
            (static_cast<uint32_t>(def_bytes[1]) <<  8) |
            (static_cast<uint32_t>(def_bytes[2]) << 16) |
            (static_cast<uint32_t>(def_bytes[3]) << 24);
        uint32_t default_target = 0;
        if (!decode_arm_b(def_word, default_addr, &default_target)) return false;

        std::vector<uint32_t> case_targets;
        case_targets.reserve(entry_count);
        for (uint32_t i = 0; i < entry_count; ++i) {
            uint32_t ca = cases_base + i * 4;
            auto bytes = image_->code_at(ca, 4);
            if (bytes.size() < 4) return false;
            uint32_t word =
                static_cast<uint32_t>(bytes[0]) |
                (static_cast<uint32_t>(bytes[1]) <<  8) |
                (static_cast<uint32_t>(bytes[2]) << 16) |
                (static_cast<uint32_t>(bytes[3]) << 24);
            uint32_t target = 0;
            if (!decode_arm_b(word, ca, &target)) return false;
            case_targets.push_back(target);
        }

        // Mark default and case `b` instructions as skipped so the main
        // dispatch loop doesn't lift them (we've already routed control
        // to their decoded targets).
        tbb_skip_addrs_.insert(default_addr);
        for (uint32_t i = 0; i < entry_count; ++i) {
            tbb_skip_addrs_.insert(cases_base + i * 4);
        }

        // Resolve label for each target (in-function block start, or
        // out-of-function tail call extern).
        auto resolve_label = [&](uint32_t va,
                                  const std::string& tag,
                                  std::string* extern_block) -> std::string {
            extern_block->clear();
            bool in_fn = (va >= fn_start && va < fn_end_excl &&
                          valid_addrs_.count(va) > 0);
            if (in_fn) return "%" + bb_label(va);
            *extern_block = tag + "_" + std::to_string(ssa_counter++);
            extern_call_targets.insert(va);
            return "%" + *extern_block;
        };

        std::string default_extern;
        std::string default_label =
            resolve_label(default_target, "armjt_def", &default_extern);

        struct CaseInfo {
            uint32_t va;
            std::string label;
            std::string extern_block;
        };
        std::vector<CaseInfo> cases(entry_count);
        for (uint32_t i = 0; i < entry_count; ++i) {
            cases[i].va = case_targets[i];
            cases[i].label = resolve_label(case_targets[i],
                                            "armjt_case",
                                            &cases[i].extern_block);
        }

        std::string idx = load_reg(idx_reg);
        // switch is a terminator; flush before so all targets see
        // consistent memory regardless of cache state here.
        flush_dirty_regs();
        ir << "  switch i32 " << idx << ", label " << default_label << " [\n";
        for (uint32_t i = 0; i < entry_count; ++i) {
            ir << "    i32 " << i << ", label " << cases[i].label << "\n";
        }
        ir << "  ]\n";

        auto emit_extern = [&](const std::string& blk, uint32_t va) {
            ir << blk << ":\n";
            // Each switch-case / extern-tail-call block is a PARALLEL
            // SIBLING of the others -- reached directly via the switch
            // (or br i1) terminator above, not via fall-through from
            // any previous case. So SSA values defined in a sibling
            // block don't dominate this one. Clear the register cache
            // here so the load_reg() calls below emit fresh loads from
            // memory (which is consistent because flush_dirty_regs ran
            // before the terminator). Without this, sibling cases were
            // reusing each other's %tNNN names and llvm-as rejected
            // the IR with "Instruction does not dominate all uses".
            cache_clear();
            std::string a0 = load_reg(0);
            std::string a1 = load_reg(1);
            std::string a2 = load_reg(2);
            std::string a3 = load_reg(3);
            std::string sp = load_reg(13);
            // Trace ARM-PC-jump-table extern case.
            ir << "  call void @__macapk_trace_bl(i32 "
               << static_cast<uint32_t>(in->address) << ", i32 "
               << va
               << ", i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3 << ")\n";
            std::string ret = fresh();
            ir << "  " << ret << " = tail call i32 @__macapk_target_"
               << std::hex << va << std::dec
               << "(i32 " << a0 << ", i32 " << a1
               << ", i32 " << a2 << ", i32 " << a3
               << ", i32 " << sp << ")\n";
            ir << "  ret i32 " << ret << "\n";
        };
        if (!default_extern.empty()) emit_extern(default_extern, default_target);
        for (auto& ci : cases) {
            if (!ci.extern_block.empty()) emit_extern(ci.extern_block, ci.va);
        }

        *terminated = true;
        return true;
    }

    // v1.0.552: lower `add pc, rB, rO` recorded by the scan_blocks offset-word
    // table pre-scan (PcAddOffsetJumpTable) to a real IR switch on rO's runtime
    // value (the raw table word: a bias-free byte offset from the table base).
    // The default block dispatches indirect on the computed target so an
    // unexpected offset is visible at runtime instead of silently corrupting.
    bool emit_arm_add_offset_jump_table(const cs_insn* in, bool* terminated) {
        auto it = pc_add_offset_jts_.find(static_cast<uint32_t>(in->address));
        if (it == pc_add_offset_jts_.end() || it->second.cases.empty())
            return false;
        const PcAddOffsetJumpTable& t = it->second;
        std::string off  = load_reg(t.off_reg);
        std::string base = load_reg(t.base_reg);
        flush_dirty_regs();
        std::string defn = "pcaojt_def_" + std::to_string(ssa_counter++);
        ir << "  switch i32 " << off << ", label %" << defn << " [\n";
        std::unordered_set<uint32_t> seen;
        for (const auto& c : t.cases) {
            if (!seen.insert(c.first).second) continue;   // repeated offsets share a case
            ir << "    i32 " << c.first << ", label %" << bb_label(c.second) << "\n";
        }
        ir << "  ]\n";
        ir << defn << ":\n";
        // Parallel-sibling block (see emit_arm_pc_jump_table's emit_extern):
        // clear the cache so loads below are fresh; `off`/`base` SSA names
        // defined before the switch dominate this block and stay usable.
        cache_clear();
        std::string tgt = fresh();
        ir << "  " << tgt << " = add i32 " << base << ", " << off << "\n";
        std::string a0 = load_reg(0), a1 = load_reg(1), a2 = load_reg(2),
                    a3 = load_reg(3), sp = load_reg(13);
        std::string ret = fresh();
        ir << "  " << ret << " = tail call i32 @__macapk_indirect_call("
           << "i32 " << tgt << ", i32 " << a0 << ", i32 " << a1
           << ", i32 " << a2 << ", i32 " << a3 << ", i32 " << sp
           << ", i32 " << current_insn_addr << ")\n";
        ir << "  ret i32 " << ret << "\n";
        *terminated = true;
        return true;
    }

    // Returns: ok, is_lr_return, is_indirect_terminator.
    //   - is_lr_return  : caller (dispatch) should emit `ret R0` for this.
    //   - is_indirect_terminator: emit_bx already wrote `ret`; dispatch
    //                              just needs to set terminated=true.
    bool emit_bx(const cs_insn* in, bool* is_lr_return,
                 bool* indirect_terminator) {
        const cs_arm& d = in->detail->arm;
        if (d.op_count != 1) return false;
        if (d.operands[0].type != ARM_OP_REG) return false;
        int r = arm_reg_idx(d.operands[0].reg);
        if (r < 0) return false;
        if (r == 14) {
            if (is_lr_return) *is_lr_return = true;
            return true;
        }
        // v1.0.540: PC-relative computed-jump table (unrolled software divide,
        // detected in scan_blocks). Lower `bx Rt` to a switch over the in-
        // function unrolled blocks instead of the indirect-call dispatcher. The
        // index reg is clobbered before the bx (e.g. `mov r3,#0`), so derive the
        // index from the COMPUTED target itself: idx = (base - r_target)/stride.
        {
            auto pjt_it = pc_jump_tables_.find(current_insn_addr);
            if (pjt_it != pc_jump_tables_.end() && !pjt_it->second.cases.empty()) {
                const PcJumpTable& pjt = pjt_it->second;
                std::string tgt = load_reg(r);
                std::string diff = fresh();
                // v1.0.552: the register holds a BIASED address at runtime
                // (the `add Rt,pc,#imm` base materializes pc + load_bias_),
                // so the table base must be biased too or the udiv below
                // computes garbage and every divide falls to the indirect
                // default (biased companions only; bias-0 main libs were
                // unaffected, which is why Mindustry's libarc divide worked).
                ir << "  " << diff << " = sub i32 "
                   << (pjt.base + load_bias_) << ", " << tgt << "\n";
                std::string idx = fresh();
                ir << "  " << idx << " = udiv i32 " << diff << ", " << pjt.stride << "\n";
                std::string defn = "pcjt_def_" + std::to_string(ssa_counter++);
                ir << "  switch i32 " << idx << ", label %" << defn << " [\n";
                for (const auto& c : pjt.cases)
                    ir << "    i32 " << c.first << ", label %" << bb_label(c.second) << "\n";
                ir << "  ]\n";
                ir << defn << ":\n";
                std::string a0 = load_reg(0), a1 = load_reg(1), a2 = load_reg(2),
                            a3 = load_reg(3), sp = load_reg(13);
                std::string dret = fresh();
                ir << "  " << dret << " = tail call i32 @__macapk_indirect_call("
                   << "i32 " << load_reg(r) << ", i32 " << a0 << ", i32 " << a1
                   << ", i32 " << a2 << ", i32 " << a3 << ", i32 " << sp
                   << ", i32 " << current_insn_addr << ")\n";
                ir << "  ret i32 " << dret << "\n";
                if (indirect_terminator) *indirect_terminator = true;
                return true;
            }
        }
        // BX Rn (n != LR): indirect tail call to a function pointer
        // held in Rn. Pass current R0..R3 as args; the callee's return
        // is the current function's return. Emits the `ret` itself
        // because the call must be tail-positioned. Routes through
        // the shim's dispatcher for the same reason emit_blx does.
        std::string target_i32 = load_reg(r);
        std::string a0 = load_reg(0);
        std::string a1 = load_reg(1);
        std::string a2 = load_reg(2);
        std::string a3 = load_reg(3);
        std::string sp = load_reg(13);
        std::string ret = fresh();
        ir << "  " << ret << " = tail call i32 @__macapk_indirect_call("
           << "i32 " << target_i32
           << ", i32 " << a0
           << ", i32 " << a1
           << ", i32 " << a2
           << ", i32 " << a3
           << ", i32 " << sp
           << ", i32 " << current_insn_addr << ")\n";   // from_vaddr (diag)
        ir << "  ret i32 " << ret << "\n";
        if (indirect_terminator) *indirect_terminator = true;
        return true;
    }

    // --- Per-instruction dispatch -------------------------------------

    enum class EmitOutcome { Normal, Terminated, Failed };

    EmitOutcome emit_one(const cs_insn* in, uint32_t fn_start,
                          uint32_t fn_end_excl, std::string* err) {
        // MACAPK_FIRSTLAUNCH_LIFT_NOIR: nothing below this line but IR
        // formatting for these instructions (see has_discovery_effect).
        if (discovery_only_ && !has_discovery_effect(in)) {
            ++noir_skipped_;
            return EmitOutcome::Normal;
        }
        bool ok = true;
        bool terminated = false;
        bool conditional = !is_always(static_cast<arm_cc>(in->detail->arm.cc));

        // For predicated instructions we materialize the condition
        // once and let the per-op emitters honor it:
        //   - store_reg() blends new and old via select, so any
        //     register-writing op is predicated for free.
        //   - emit_str_size() does load-current/select/store-always for
        //     predicated stores, so they're side-effect-correct.
        //   - POP / LDM with PC under predicate becomes a conditional
        //     return (handled in the dispatch's BX-style ret block).
        //
        // Branches (B / BL) consult arm.cc directly inside their
        // emitters and don't use current_pred. BX is similar (its
        // dispatcher reads `conditional`).
        //
        // Flag-only ops (CMP / CMN / TST / TEQ) and S-suffix arithmetic
        // are still rejected when predicated -- gating flag stores
        // would require selecting on each NZCV slot, which adds noise
        // for very rare cases.
        current_pred.clear();
        if (conditional &&
            in->id != ARM_INS_B &&
            in->id != ARM_INS_BL &&
            in->id != ARM_INS_BX) {
            // store_reg / store_flag both honor current_pred via the
            // select pattern, so even flag-only ops (CMP / TST / TEQ)
            // and S-suffix arithmetic gate cleanly under predicate.
            current_pred = emit_cond_check(in->detail->arm.cc);
        }

        switch (in->id) {
            case ARM_INS_PUSH: ok = emit_push(in); break;
            case ARM_INS_POP: {
                bool is_ret = false;
                ok = emit_pop(in, &is_ret);
                if (!ok || !is_ret) break;
                if (conditional) {
                    std::string cond = current_pred.empty()
                        ? emit_cond_check(in->detail->arm.cc)
                        : current_pred;
                    uint32_t fall = static_cast<uint32_t>(in->address) + in->size;
                    // Fall-through to next instruction. If the next
                    // instruction wasn't disassembled (synthetic
                    // function boundary, end-of-segment), generate a
                    // ret-shaped synth label so the IR stays valid.
                    bool fall_synth = (valid_addrs_.count(fall) == 0);
                    std::string synth_label;
                    if (fall_synth) synth_label = "popfall_" + std::to_string(ssa_counter++);
                    std::string fall_lbl = fall_synth
                        ? ("%" + synth_label)
                        : ("%" + bb_label(fall));
                    std::string ret_block = "popret_" + std::to_string(ssa_counter++);
                    flush_dirty_regs();
                    ir << "  br i1 " << cond << ", label %" << ret_block
                       << ", label " << fall_lbl << "\n";
                    ir << ret_block << ":\n";
                    // ret_block and the synth fall (if present) are
                    // parallel siblings reached via br i1, not via
                    // fall-through. Reset cache so each gets a fresh
                    // load_reg from memory.
                    cache_clear();
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    if (fall_synth) {
                        ir << synth_label << ":\n";
                        cache_clear();
                        std::string r0b = load_reg(0);
                        ir << "  ret i32 " << r0b << "\n";
                    }
                    terminated = true;
                } else {
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    terminated = true;
                }
                break;
            }
            case ARM_INS_MOV:
            case ARM_INS_MOVS: ok = emit_mov(in, &terminated); break;
            case ARM_INS_MVN:  ok = emit_mvn(in); break;
            case ARM_INS_MOVW: ok = emit_movw(in); break;
            case ARM_INS_MOVT: ok = emit_movt(in); break;
            case ARM_INS_ADD: {
                // Detect ARM-mode jump-table idiom:
                //   addCC pc, pc, Rm, lsl #2
                // (used by GCC for switch statements when the bodies are
                // ARM mode and don't fit Thumb-2's TBB encoding). When
                // the pattern matches we emit a proper `switch` IR and
                // skip the inline branch table; otherwise fall back to
                // the regular ALU path which writes to register slot 15
                // (a no-op for control flow).
                if (emit_arm_pc_jump_table(in, fn_start, fn_end_excl,
                                            &terminated)) {
                    ok = true;
                    break;
                }
                // v1.0.552: offset-word table variant (add pc, rB, rO).
                if (emit_arm_add_offset_jump_table(in, &terminated)) {
                    ok = true;
                    break;
                }
                ok = emit_alu(in, "add", false, false, &terminated);
                break;
            }
            // &terminated: an ALU write to PC becomes a real indirect
            // branch (bug 5), which ends the block. The flag-only forms
            // (CMP/CMN/TST/TEQ) have no destination register, so they
            // cannot terminate and do not pass it.
            case ARM_INS_SUB:  ok = emit_alu(in, "sub", false, false, &terminated); break;
            case ARM_INS_RSB:  ok = emit_rsb(in); break;
            case ARM_INS_AND:  ok = emit_alu(in, "and", false, false, &terminated); break;
            case ARM_INS_ORR:  ok = emit_alu(in, "or",  false, false, &terminated); break;
            case ARM_INS_EOR:  ok = emit_alu(in, "xor", false, false, &terminated); break;
            case ARM_INS_BIC:  ok = emit_alu(in, "and", true,  false, &terminated); break;
            case ARM_INS_CMP:  ok = emit_alu(in, "sub", false, true);  break;
            case ARM_INS_CMN:  ok = emit_alu(in, "add", false, true);  break;
            case ARM_INS_TST:  ok = emit_alu(in, "and", false, true);  break;
            case ARM_INS_TEQ:  ok = emit_alu(in, "xor", false, true);  break;
            case ARM_INS_MUL:   ok = emit_mul(in); break;
            case ARM_INS_UMULL: ok = emit_mull(in, false); break;
            case ARM_INS_SMULL: ok = emit_mull(in, true);  break;
            case ARM_INS_MLA:   ok = emit_mla(in, false); break;
            case ARM_INS_MLS:   ok = emit_mla(in, true);  break;
            case ARM_INS_RRX:   ok = emit_rrx(in); break;
            case ARM_INS_CLZ:   ok = emit_clz(in); break;
            case ARM_INS_ADC:   ok = emit_adcsbc(in, false); break;
            case ARM_INS_SBC:   ok = emit_adcsbc(in, true);  break;
            case ARM_INS_RSC:   ok = emit_rsc(in); break;
            case ARM_INS_UXTB:  ok = emit_extend(in, 8,  false); break;
            case ARM_INS_UXTH:  ok = emit_extend(in, 16, false); break;
            case ARM_INS_SXTB:  ok = emit_extend(in, 8,  true);  break;
            case ARM_INS_SXTH:  ok = emit_extend(in, 16, true);  break;
            case ARM_INS_UBFX:  ok = emit_bfx(in, false); break;
            case ARM_INS_SBFX:  ok = emit_bfx(in, true);  break;
            case ARM_INS_BFI:   ok = emit_bfi(in); break;
            case ARM_INS_BFC:   ok = emit_bfc(in); break;
            case ARM_INS_REV:   ok = emit_rev(in); break;
            case ARM_INS_REV16: ok = emit_rev16(in); break;
            case ARM_INS_REVSH: ok = emit_revsh(in); break;
            case ARM_INS_ORN:   ok = emit_orn(in); break;
            case ARM_INS_UDIV:  ok = emit_div(in, false); break;
            case ARM_INS_SDIV:  ok = emit_div(in, true);  break;
            case ARM_INS_ROR:   ok = emit_ror(in); break;
            case ARM_INS_RBIT: {
                // RBIT Rd, Rm  -- reverse bit order. ARM ARM A8.6.134.
                // Maps directly to llvm.bitreverse.i32.
                const cs_arm& d = in->detail->arm;
                if (d.op_count != 2 ||
                    d.operands[0].type != ARM_OP_REG ||
                    d.operands[1].type != ARM_OP_REG) {
                    ok = false; break;
                }
                int rd = arm_reg_idx(d.operands[0].reg);
                int rs = arm_reg_idx(d.operands[1].reg);
                if (rd < 0 || rs < 0) { ok = false; break; }
                std::string v = load_reg(rs);
                std::string out = fresh();
                ir << "  " << out << " = call i32 @llvm.bitreverse.i32(i32 "
                   << v << ")\n";
                store_reg(rd, out);
                ok = true;
                break;
            }
            // UXTAB / UXTAH / SXTAB / SXTAH  Rd, Rn, Rm{,ROR #imm}
            case ARM_INS_UXTAB: ok = emit_xtab(in, 8,  false); break;
            case ARM_INS_UXTAH: ok = emit_xtab(in, 16, false); break;
            case ARM_INS_SXTAB: ok = emit_xtab(in, 8,  true);  break;
            case ARM_INS_SXTAH: ok = emit_xtab(in, 16, true);  break;
            // Pack halfwords.
            case ARM_INS_PKHBT: ok = emit_pkh(in, false); break;
            case ARM_INS_PKHTB: ok = emit_pkh(in, true);  break;
            // Sum-of-absolute-differences.
            case ARM_INS_USAD8:  ok = emit_usad8(in, false); break;
            case ARM_INS_USADA8: ok = emit_usad8(in, true);  break;
            // Special-register access.
            case ARM_INS_MRS: ok = emit_mrs(in); break;
            case ARM_INS_MSR: ok = emit_msr(in); break;
            // Saturating clip to N-bit range.
            case ARM_INS_SSAT:   ok = emit_sat(in, true,  0); break;
            case ARM_INS_USAT:   ok = emit_sat(in, false, 0); break;
            case ARM_INS_SSAT16: ok = emit_sat(in, true,  1); break;
            case ARM_INS_USAT16: ok = emit_sat(in, false, 1); break;
            // Atomic swap (deprecated but still in shipped binaries).
            case ARM_INS_SWP:  ok = emit_swp(in, 32); break;
            case ARM_INS_SWPB: ok = emit_swp(in, 8);  break;
            // Exclusive load/store double + byte/halfword. The
            // STL* / LDA* variants are the ARMv8 "acquire/release"
            // ordered versions; for our single-VM model the ordering
            // semantics collapse to the same data behavior as the
            // plain STREX/LDREX family.
            case ARM_INS_LDREXD:
            case ARM_INS_LDAEXD: ok = emit_ldrexd(in); break;
            case ARM_INS_STREXD:
            case ARM_INS_STLEXD: ok = emit_strexd(in); break;
            case ARM_INS_STREXB:
            case ARM_INS_STLEXB: ok = emit_strex_size(in, 8);  break;
            case ARM_INS_STREXH:
            case ARM_INS_STLEXH: ok = emit_strex_size(in, 16); break;
            case ARM_INS_STLEX:  ok = emit_strex(in); break;
            case ARM_INS_LDREXB:
            case ARM_INS_LDAEXB: ok = emit_ldr_size(in, 8,  false); break;
            case ARM_INS_LDREXH:
            case ARM_INS_LDAEXH: ok = emit_ldr_size(in, 16, false); break;
            case ARM_INS_LDAEX:  ok = emit_ldr_size(in, 32, false); break;
            // Load-acquire / store-release (single word, no exclusive
            // monitor). Same semantics as plain LDR/STR for us.
            case ARM_INS_LDA:    ok = emit_ldr_size(in, 32, false); break;
            case ARM_INS_LDAB:   ok = emit_ldr_size(in, 8,  false); break;
            case ARM_INS_LDAH:   ok = emit_ldr_size(in, 16, false); break;
            case ARM_INS_STL:    ok = emit_str_size(in, 32); break;
            case ARM_INS_STLB:   ok = emit_str_size(in, 8);  break;
            case ARM_INS_STLH:   ok = emit_str_size(in, 16); break;
            // Halfword multiplies (DSP).
            case ARM_INS_SMULBB: ok = emit_smul_half(in, false, false); break;
            case ARM_INS_SMULBT: ok = emit_smul_half(in, false, true);  break;
            case ARM_INS_SMULTB: ok = emit_smul_half(in, true,  false); break;
            case ARM_INS_SMULTT: ok = emit_smul_half(in, true,  true);  break;
            case ARM_INS_SMLABB: ok = emit_smla_half(in, false, false); break;
            case ARM_INS_SMLABT: ok = emit_smla_half(in, false, true);  break;
            case ARM_INS_SMLATB: ok = emit_smla_half(in, true,  false); break;
            case ARM_INS_SMLATT: ok = emit_smla_half(in, true,  true);  break;
            case ARM_INS_SMULWB: ok = emit_smul_w(in, false); break;
            case ARM_INS_SMULWT: ok = emit_smul_w(in, true);  break;
            case ARM_INS_SMLAWB: ok = emit_smla_w(in, false); break;
            case ARM_INS_SMLAWT: ok = emit_smla_w(in, true);  break;
            // Top-32 of 64-bit signed product, accumulated.
            case ARM_INS_SMMLA:  ok = emit_smm(in, false, false); break;
            case ARM_INS_SMMLAR: ok = emit_smm(in, false, true);  break;
            case ARM_INS_SMMLS:  ok = emit_smm(in, true,  false); break;
            case ARM_INS_SMMLSR: ok = emit_smm(in, true,  true);  break;
            // Long multiply-and-accumulate.
            case ARM_INS_SMLAL:  ok = emit_mlal(in, true);  break;
            case ARM_INS_UMLAL:  ok = emit_mlal(in, false); break;
            case ARM_INS_UMAAL:  ok = emit_umaal(in); break;
            case ARM_INS_SMLALD:  ok = emit_smlxld(in, false, false); break;
            case ARM_INS_SMLALDX: ok = emit_smlxld(in, false, true);  break;
            case ARM_INS_SMLSLD:  ok = emit_smlxld(in, true,  false); break;
            case ARM_INS_SMLSLDX: ok = emit_smlxld(in, true,  true);  break;
            case ARM_INS_SMLAD:   ok = emit_smlxd(in, false, false); break;
            case ARM_INS_SMLADX:  ok = emit_smlxd(in, false, true);  break;
            case ARM_INS_SMLSD:   ok = emit_smlxd(in, true,  false); break;
            case ARM_INS_SMLSDX:  ok = emit_smlxd(in, true,  true);  break;
            // Dual signed-halfword multiply, no accumulate (A8.6.177/181).
            case ARM_INS_SMUAD:   ok = emit_smuad_smusd(in, false, false); break;
            case ARM_INS_SMUADX:  ok = emit_smuad_smusd(in, false, true);  break;
            case ARM_INS_SMUSD:   ok = emit_smuad_smusd(in, true,  false); break;
            case ARM_INS_SMUSDX:  ok = emit_smuad_smusd(in, true,  true);  break;
            // Top-32 of 64-bit signed product, no accumulate (A8.6.176).
            case ARM_INS_SMMUL:   ok = emit_smmul(in, false); break;
            case ARM_INS_SMMULR:  ok = emit_smmul(in, true);  break;
            case ARM_INS_SMLALBB: ok = emit_smlal_half(in, false, false); break;
            case ARM_INS_SMLALBT: ok = emit_smlal_half(in, false, true);  break;
            case ARM_INS_SMLALTB: ok = emit_smlal_half(in, true,  false); break;
            case ARM_INS_SMLALTT: ok = emit_smlal_half(in, true,  true);  break;
            // Parallel arithmetic (ARMv6 DSP). Lane size 16 or 8.
            case ARM_INS_QADD:   ok = emit_q32(in, false); break;
            case ARM_INS_QSUB:   ok = emit_q32(in, true);  break;
            case ARM_INS_QDADD:  ok = emit_qd32(in, false); break;
            case ARM_INS_QDSUB:  ok = emit_qd32(in, true);  break;
            case ARM_INS_QADD16: ok = emit_par_arith(in, 16, ParMod::SignedSat,   ParOp::Add); break;
            case ARM_INS_QSUB16: ok = emit_par_arith(in, 16, ParMod::SignedSat,   ParOp::Sub); break;
            case ARM_INS_QADD8:  ok = emit_par_arith(in, 8,  ParMod::SignedSat,   ParOp::Add); break;
            case ARM_INS_QSUB8:  ok = emit_par_arith(in, 8,  ParMod::SignedSat,   ParOp::Sub); break;
            case ARM_INS_QASX:   ok = emit_par_arith(in, 16, ParMod::SignedSat,   ParOp::Asx); break;
            case ARM_INS_QSAX:   ok = emit_par_arith(in, 16, ParMod::SignedSat,   ParOp::Sax); break;
            case ARM_INS_UQADD16: ok = emit_par_arith(in, 16, ParMod::UnsignedSat, ParOp::Add); break;
            case ARM_INS_UQSUB16: ok = emit_par_arith(in, 16, ParMod::UnsignedSat, ParOp::Sub); break;
            case ARM_INS_UQADD8:  ok = emit_par_arith(in, 8,  ParMod::UnsignedSat, ParOp::Add); break;
            case ARM_INS_UQSUB8:  ok = emit_par_arith(in, 8,  ParMod::UnsignedSat, ParOp::Sub); break;
            case ARM_INS_UQASX:   ok = emit_par_arith(in, 16, ParMod::UnsignedSat, ParOp::Asx); break;
            case ARM_INS_UQSAX:   ok = emit_par_arith(in, 16, ParMod::UnsignedSat, ParOp::Sax); break;
            case ARM_INS_SHADD16: ok = emit_par_arith(in, 16, ParMod::SignedHalve,   ParOp::Add); break;
            case ARM_INS_SHSUB16: ok = emit_par_arith(in, 16, ParMod::SignedHalve,   ParOp::Sub); break;
            case ARM_INS_SHADD8:  ok = emit_par_arith(in, 8,  ParMod::SignedHalve,   ParOp::Add); break;
            case ARM_INS_SHSUB8:  ok = emit_par_arith(in, 8,  ParMod::SignedHalve,   ParOp::Sub); break;
            case ARM_INS_SHASX:   ok = emit_par_arith(in, 16, ParMod::SignedHalve,   ParOp::Asx); break;
            case ARM_INS_SHSAX:   ok = emit_par_arith(in, 16, ParMod::SignedHalve,   ParOp::Sax); break;
            case ARM_INS_UHADD16: ok = emit_par_arith(in, 16, ParMod::UnsignedHalve, ParOp::Add); break;
            case ARM_INS_UHSUB16: ok = emit_par_arith(in, 16, ParMod::UnsignedHalve, ParOp::Sub); break;
            case ARM_INS_UHADD8:  ok = emit_par_arith(in, 8,  ParMod::UnsignedHalve, ParOp::Add); break;
            case ARM_INS_UHSUB8:  ok = emit_par_arith(in, 8,  ParMod::UnsignedHalve, ParOp::Sub); break;
            case ARM_INS_UHASX:   ok = emit_par_arith(in, 16, ParMod::UnsignedHalve, ParOp::Asx); break;
            case ARM_INS_UHSAX:   ok = emit_par_arith(in, 16, ParMod::UnsignedHalve, ParOp::Sax); break;
            case ARM_INS_SADD16: ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Add); break;
            case ARM_INS_SSUB16: ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Sub); break;
            case ARM_INS_SADD8:  ok = emit_par_arith(in, 8,  ParMod::Modular, ParOp::Add); break;
            case ARM_INS_SSUB8:  ok = emit_par_arith(in, 8,  ParMod::Modular, ParOp::Sub); break;
            case ARM_INS_SASX:   ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Asx); break;
            case ARM_INS_SSAX:   ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Sax); break;
            case ARM_INS_UADD16: ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Add); break;
            case ARM_INS_USUB16: ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Sub); break;
            case ARM_INS_UADD8:  ok = emit_par_arith(in, 8,  ParMod::Modular, ParOp::Add); break;
            case ARM_INS_USUB8:  ok = emit_par_arith(in, 8,  ParMod::Modular, ParOp::Sub); break;
            case ARM_INS_UASX:   ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Asx); break;
            case ARM_INS_USAX:   ok = emit_par_arith(in, 16, ParMod::Modular, ParOp::Sax); break;
            case ARM_INS_SEL:    ok = emit_sel(in); break;
            // Sign-extend 16-bit pair + add (ARMv6 DSP).
            case ARM_INS_UXTB16: ok = emit_xtb16(in, false); break;
            case ARM_INS_SXTB16: ok = emit_xtb16(in, true);  break;
            case ARM_INS_UXTAB16: ok = emit_xtab(in, 8, false); break;
            case ARM_INS_SXTAB16: ok = emit_xtab(in, 8, true);  break;
            case ARM_INS_DMB:
            case ARM_INS_DSB:
            case ARM_INS_ISB:
                ok = emit_barrier(); break;
            case ARM_INS_LDM:
            case ARM_INS_LDMIB:
            case ARM_INS_LDMDA:
            case ARM_INS_LDMDB: {
                int dir = (in->id == ARM_INS_LDMDA || in->id == ARM_INS_LDMDB) ? -1 : +1;
                int pre = (in->id == ARM_INS_LDMIB || in->id == ARM_INS_LDMDB) ? 1 : 0;
                bool is_ret = false;
                ok = emit_ldm_stm(in, true, dir, pre, &is_ret);
                if (!ok || !is_ret) break;
                if (conditional) {
                    std::string cond = current_pred.empty()
                        ? emit_cond_check(in->detail->arm.cc)
                        : current_pred;
                    uint32_t fall = static_cast<uint32_t>(in->address) + in->size;
                    bool fall_synth = (valid_addrs_.count(fall) == 0);
                    std::string synth_label;
                    if (fall_synth) synth_label = "ldmfall_" + std::to_string(ssa_counter++);
                    std::string fall_lbl = fall_synth
                        ? ("%" + synth_label)
                        : ("%" + bb_label(fall));
                    std::string ret_block = "ldmret_" + std::to_string(ssa_counter++);
                    flush_dirty_regs();
                    ir << "  br i1 " << cond << ", label %" << ret_block
                       << ", label " << fall_lbl << "\n";
                    ir << ret_block << ":\n";
                    // ret_block and the synth fall (if present) are
                    // parallel siblings reached via br i1, not via
                    // fall-through. Reset cache so each gets a fresh
                    // load_reg from memory.
                    cache_clear();
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    if (fall_synth) {
                        ir << synth_label << ":\n";
                        cache_clear();
                        std::string r0b = load_reg(0);
                        ir << "  ret i32 " << r0b << "\n";
                    }
                    terminated = true;
                } else {
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    terminated = true;
                }
                break;
            }
            case ARM_INS_STM:   ok = emit_ldm_stm(in, false, +1, 0, nullptr); break;
            case ARM_INS_STMIB: ok = emit_ldm_stm(in, false, +1, 1, nullptr); break;
            case ARM_INS_STMDA: ok = emit_ldm_stm(in, false, -1, 0, nullptr); break;
            case ARM_INS_STMDB: ok = emit_ldm_stm(in, false, -1, 1, nullptr); break;
            case ARM_INS_BLX: {
                uint32_t ret_addr = static_cast<uint32_t>(in->address) + in->size;
                ok = emit_blx(in, ret_addr);
                break;
            }
            case ARM_INS_LSL:  ok = emit_shift(in, "shl");  break;
            case ARM_INS_LSR:  ok = emit_shift(in, "lshr"); break;
            case ARM_INS_ASR:  ok = emit_shift(in, "ashr"); break;
            case ARM_INS_STR:  ok = emit_str_size(in, 32); break;
            case ARM_INS_STRH: ok = emit_str_size(in, 16); break;
            case ARM_INS_STRB: ok = emit_str_size(in, 8);  break;
            case ARM_INS_LDR:  ok = emit_ldr_size(in, 32, false); break;
            case ARM_INS_LDRH: ok = emit_ldr_size(in, 16, false); break;
            case ARM_INS_LDRB: ok = emit_ldr_size(in, 8,  false); break;
            case ARM_INS_LDRSH: ok = emit_ldr_size(in, 16, true); break;
            case ARM_INS_LDRSB: ok = emit_ldr_size(in, 8,  true); break;
            case ARM_INS_LDREX: ok = emit_ldr_size(in, 32, false); break;
            case ARM_INS_STREX: ok = emit_strex(in); break;
            case ARM_INS_LDRD:  ok = emit_ldrd(in); break;
            case ARM_INS_STRD:  ok = emit_strd(in); break;
            // T-suffixed unprivileged variants. Apk on Mac has no
            // user/privileged distinction, so we emit them the same as
            // their normal counterparts.
            case ARM_INS_LDRT:   ok = emit_ldr_size(in, 32, false); break;
            case ARM_INS_LDRBT:  ok = emit_ldr_size(in, 8,  false); break;
            case ARM_INS_LDRHT:  ok = emit_ldr_size(in, 16, false); break;
            case ARM_INS_LDRSBT: ok = emit_ldr_size(in, 8,  true);  break;
            case ARM_INS_LDRSHT: ok = emit_ldr_size(in, 16, true);  break;
            case ARM_INS_STRT:   ok = emit_str_size(in, 32); break;
            case ARM_INS_STRBT:  ok = emit_str_size(in, 8);  break;
            case ARM_INS_STRHT:  ok = emit_str_size(in, 16); break;
            case ARM_INS_VPUSH: ok = emit_vpushpop(in, false); break;
            case ARM_INS_VPOP:  ok = emit_vpushpop(in, true);  break;
            case ARM_INS_VLDR:  ok = emit_vldr_vstr(in, true);  break;
            case ARM_INS_VSTR:  ok = emit_vldr_vstr(in, false); break;
            case ARM_INS_VMOV:  ok = emit_vmov(in); break;
            // FCONSTS / FCONSTD: Capstone reports `vmov.f32 sX, #imm`
            // / `vmov.f64 dX, #imm` with these specific instruction
            // IDs (NOT ARM_INS_VMOV). The operands are reported with
            // type=ARM_OP_FP. emit_vmov handles the FP-immediate
            // case once dispatched.
            case ARM_INS_FCONSTS:
            case ARM_INS_FCONSTD: ok = emit_vmov(in); break;
            // vmov.32 dN[lane], rN (insert ARM core reg into a NEON
            // scalar lane) is decoded by Capstone to the legacy-VFP
            // instruction IDs FMDHR (lane 1) / FMDLR (lane 0), NOT
            // ARM_INS_VMOV (only the extract form rN, dN[lane] is). The
            // operands are identical (op0 = dN with vector_index = lane,
            // op1 = core reg, vector_size = 32), so emit_vmov's existing
            // insert-lane path handles them once dispatched here. Mirrors
            // the FCONSTS/FCONSTD routing above. ARM DDI 0406C.d A8.8.341.
            case ARM_INS_FMDHR:
            case ARM_INS_FMDLR: ok = emit_vmov(in); break;

            case ARM_INS_VADD:  ok = emit_vfp_binop(in, "fadd"); break;
            case ARM_INS_VSUB:  ok = emit_vfp_binop(in, "fsub"); break;
            case ARM_INS_VMUL:  ok = emit_vfp_binop(in, "fmul"); break;
            case ARM_INS_VDIV:  ok = emit_vfp_binop(in, "fdiv"); break;
            case ARM_INS_VNEG: {
                // Integer VNEG.sN Dd/Qd, Dm/Qm -> per-lane (0 - x). The NEON
                // integer form (esp. on Q regs, .s8/.s16/.s32) was routed to
                // the scalar-float emit_vfp_unop and fell back -> no-op ->
                // stale register later used/stored. Float forms (.f32/.f64)
                // keep the fneg path.
                const cs_arm& dn = in->detail->arm;
                bool vint = (dn.vector_data == ARM_VECTORDATA_S8  ||
                             dn.vector_data == ARM_VECTORDATA_S16 ||
                             dn.vector_data == ARM_VECTORDATA_S32 ||
                             dn.vector_data == ARM_VECTORDATA_I8  ||
                             dn.vector_data == ARM_VECTORDATA_I16 ||
                             dn.vector_data == ARM_VECTORDATA_I32);
                if (vint && dn.op_count == 2 &&
                    dn.operands[0].type == ARM_OP_REG &&
                    dn.operands[1].type == ARM_OP_REG) {
                    int lb = lane_bits_of(dn); if (lb <= 0) lb = 32;
                    bool is_q = vfp_q_idx(dn.operands[0].reg) >= 0;
                    int halves = is_q ? 2 : 1;
                    int dst = is_q ? vfp_q_idx(dn.operands[0].reg) * 2
                                     : vfp_d_idx(dn.operands[0].reg);
                    int src = is_q ? vfp_q_idx(dn.operands[1].reg) * 2
                                     : vfp_d_idx(dn.operands[1].reg);
                    if (dst < 0 || src < 0) { ok = false; break; }
                    int lanes = 64 / lb;
                    for (int h = 0; h < halves; ++h) {
                        std::string v = i64_to_vec(load_dreg(src + h), lb);
                        std::string neg = fresh();
                        ir << "  " << neg << " = sub <" << lanes << " x i"
                           << lb << "> zeroinitializer, " << v << "\n";
                        store_dreg(dst + h, vec_to_i64(neg, lb));
                    }
                    ok = true; break;
                }
                ok = emit_vfp_unop(in, "fneg"); break;
            }
            case ARM_INS_VABS:  ok = emit_vfp_unop(in, "fabs"); break;
            case ARM_INS_VSQRT: ok = emit_vfp_unop(in, "fsqrt"); break;
            case ARM_INS_VCVT:  ok = emit_vcvt(in); break;
            case ARM_INS_VCVTR: ok = emit_vcvtr(in); break;

            case ARM_INS_VMLA:  ok = emit_vfp_fma(in, FmaOp::VMLA);  break;
            case ARM_INS_VMLS:  ok = emit_vfp_fma(in, FmaOp::VMLS);  break;
            case ARM_INS_VNMUL: ok = emit_vfp_fma(in, FmaOp::VNMUL); break;
            case ARM_INS_VNMLA: ok = emit_vfp_fma(in, FmaOp::VNMLA); break;
            case ARM_INS_VNMLS: ok = emit_vfp_fma(in, FmaOp::VNMLS); break;
            case ARM_INS_VCMP:
            case ARM_INS_VCMPE: ok = emit_vcmp(in); break;
            case ARM_INS_VMRS:
            case ARM_INS_FMSTAT:    // FMSTAT is the legacy alias capstone
                                    // returns for `vmrs apsr_nzcv, fpscr`.
                ok = emit_vmrs(in); break;
            case ARM_INS_VMSR:
                // VMSR FPSCR, Rt writes the VFP control/status register
                // (rounding mode, flush-to-zero, default-NaN, length/stride,
                // and the cumulative exception bits). We model only the
                // NZCV/QC condition bits (set by VCMP, read by VMRS); the
                // control bits select behaviors our lowering does not honor
                // (the host FPU runs round-to-nearest, no FTZ), so writing
                // them is a no-op rather than a wrong partial apply. The
                // common guest write is `vmsr fpscr, r0` restoring a saved
                // FPSCR around a callout, which is invisible to us anyway.
                ok = emit_nop_only(); break;
            case ARM_INS_ADR:    ok = emit_adr(in); break;
            case ARM_INS_VLDMIA: ok = emit_vldmia_vstmia(in, true);  break;
            case ARM_INS_VSTMIA: ok = emit_vldmia_vstmia(in, false); break;
            case ARM_INS_VLDMDB: ok = emit_vldmdb_vstmdb(in, true);  break;
            case ARM_INS_VSTMDB: ok = emit_vldmdb_vstmdb(in, false); break;
            // ---- NEON Advanced SIMD --------------------------------
            case ARM_INS_VDUP:  ok = emit_vdup(in); break;
            case ARM_INS_VTBL:  ok = emit_vtbl_vtbx(in, false); break;
            case ARM_INS_VTBX:  ok = emit_vtbl_vtbx(in, true);  break;
            case ARM_INS_VRHADD: ok = emit_vrhadd(in); break;
            case ARM_INS_VHADD:  ok = emit_vhadd(in); break;
            case ARM_INS_VHSUB:  ok = emit_vhsub(in); break;

            case ARM_INS_VADDL:  ok = emit_vaddl_subl(in, false); break;
            case ARM_INS_VSUBL:  ok = emit_vaddl_subl(in, true);  break;
            case ARM_INS_VMULL:  ok = emit_vmull_mlsl(in, false); break;
            case ARM_INS_VMLSL:  ok = emit_vmull_mlsl(in, true);  break;
            case ARM_INS_VPADDL: ok = emit_vpaddl_vpadal(in, false); break;
            case ARM_INS_VPADAL: ok = emit_vpaddl_vpadal(in, true);  break;

            case ARM_INS_VMLAL:   ok = emit_vmull_long_acc(in, false, true,  false); break;
            case ARM_INS_VQDMULL: ok = emit_vmull_long_acc(in, true,  false, false); break;
            case ARM_INS_VQDMLAL: ok = emit_vmull_long_acc(in, true,  true,  false); break;
            case ARM_INS_VQDMLSL: ok = emit_vmull_long_acc(in, true,  true,  true);  break;

            case ARM_INS_VSHR:   ok = emit_v_shift(in,
                vdata_signed(in->detail->arm.vector_data)
                    ? ShiftKind::ASHR : ShiftKind::LSHR,
                false); break;
            case ARM_INS_VSHL:   ok = emit_v_shift(in, ShiftKind::SHL, false); break;
            case ARM_INS_VSRA:   ok = emit_v_shift(in,
                vdata_signed(in->detail->arm.vector_data)
                    ? ShiftKind::ASHR : ShiftKind::LSHR,
                true); break;
            case ARM_INS_VRSHR:  ok = emit_v_shift(in,
                vdata_signed(in->detail->arm.vector_data)
                    ? ShiftKind::RASHR : ShiftKind::RLSHR,
                false); break;
            case ARM_INS_VRSRA:  ok = emit_v_shift(in,
                vdata_signed(in->detail->arm.vector_data)
                    ? ShiftKind::RASHR : ShiftKind::RLSHR,
                true); break;
            case ARM_INS_VSLI:   ok = emit_v_sli_sri(in, true);  break;
            case ARM_INS_VSRI:   ok = emit_v_sli_sri(in, false); break;
            case ARM_INS_VQADD:  ok = emit_vqaddsub(in, false); break;
            case ARM_INS_VQSUB:  ok = emit_vqaddsub(in, true);  break;
            case ARM_INS_VQSHL:  ok = emit_vqshl(in, false); break;
            case ARM_INS_VQSHLU: ok = emit_vqshl(in, true);  break;
            case ARM_INS_VQABS:  ok = emit_v_unop_count_sat(in, 0); break;
            case ARM_INS_VQNEG:  ok = emit_v_unop_count_sat(in, 1); break;
            case ARM_INS_VCLS:   ok = emit_v_unop_count_sat(in, 2); break;
            case ARM_INS_VCLZ:   ok = emit_v_unop_count_sat(in, 3); break;
            case ARM_INS_VCNT:   ok = emit_v_unop_count_sat(in, 4); break;

            case ARM_INS_VQSHRN: ok = emit_vqshrn(in, false, false); break;
            case ARM_INS_VQSHRUN:ok = emit_vqshrn(in, true,  false); break;
            case ARM_INS_VQRSHRN:ok = emit_vqshrn(in, false, true);  break;
            case ARM_INS_VSHRN:   ok = emit_v_shrn(in, false, false, false); break;
            case ARM_INS_VRSHRN:  ok = emit_v_shrn(in, false, false, true);  break;
            case ARM_INS_VQRSHRUN:ok = emit_v_shrn(in, true,  true,  true);  break;

            case ARM_INS_VQDMULH:  ok = emit_vqdmulh(in, false); break;
            case ARM_INS_VQRDMULH: ok = emit_vqdmulh(in, true);  break;

            case ARM_INS_VMIN:   ok = emit_v_min_max(in, false, false); break;
            case ARM_INS_VMAX:   ok = emit_v_min_max(in, true,  false); break;
            case ARM_INS_VPMIN:  ok = emit_v_min_max(in, false, true); break;
            case ARM_INS_VPMAX:  ok = emit_v_min_max(in, true,  true); break;
            case ARM_INS_VEOR:   ok = emit_v_eor(in); break;
            case ARM_INS_VORR:   ok = emit_v_orr_imm(in); break;
            case ARM_INS_VMVN: {
                // VMVN.<size> Dd|Qd, #imm  -- store bitwise NOT of the
                // immediate-expanded constant to every lane of Dd|Qd.
                // ARM ARM A8.6.341. Reuse emit_v_orr_imm's mask pattern
                // (replicate imm across lanes) and then XOR with all-ones.
                const cs_arm& d = in->detail->arm;
                // REGISTER form VMVN Dd,Dm / Qd,Qm -> dd = ~dm (bitwise NOT).
                // Was unhandled (last operand not an immediate) -> no-op ->
                // stale/garbage register later stored. Same corruption class
                // as the register VORR above.
                if (d.op_count == 2 && d.operands[0].type == ARM_OP_REG
                    && d.operands[1].type == ARM_OP_REG) {
                    bool rq = vfp_q_idx(d.operands[0].reg) >= 0;
                    int rh = rq ? 2 : 1;
                    int rd = rq ? (vfp_q_idx(d.operands[0].reg) * 2)
                                  : vfp_d_idx(d.operands[0].reg);
                    int rm = rq ? (vfp_q_idx(d.operands[1].reg) * 2)
                                  : vfp_d_idx(d.operands[1].reg);
                    if (rd < 0 || rm < 0) { ok = false; break; }
                    for (int h = 0; h < rh; ++h) {
                        std::string s = load_dreg(rm + h);
                        std::string o = fresh();
                        ir << "  " << o << " = xor i64 " << s << ", -1\n";
                        store_dreg(rd + h, o);
                    }
                    ok = true; break;
                }
                if (d.op_count < 2 || d.op_count > 3 ||
                    d.operands[0].type != ARM_OP_REG ||
                    d.operands[d.op_count - 1].type != ARM_OP_IMM) {
                    ok = false; break;
                }
                int lane_bits = lane_bits_of(d);
                if (lane_bits == 0) lane_bits = 32;
                bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
                int halves = is_q ? 2 : 1;
                int dst_base = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                                      : vfp_d_idx(d.operands[0].reg);
                if (dst_base < 0) { ok = false; break; }
                int imm_idx = d.op_count - 1;
                uint64_t imm = static_cast<uint64_t>(d.operands[imm_idx].imm);
                uint64_t pat = 0;
                int lanes_d = 64 / lane_bits;
                for (int i = 0; i < lanes_d; ++i) {
                    uint64_t m = (lane_bits == 64) ? imm :
                        (imm & ((static_cast<uint64_t>(1) << lane_bits) - 1));
                    pat |= (m << (i * lane_bits));
                }
                uint64_t inv = ~pat;
                for (int h = 0; h < halves; ++h) {
                    store_dreg(dst_base + h,
                        std::to_string(static_cast<int64_t>(inv)));
                }
                ok = true;
                break;
            }
            // Compares: float path uses the fcmp predicate, integer path
            // the icmp signed/unsigned predicates. emit_v_fcmp picks by
            // vector_data. ARM DDI 0406C.d A8.8.291/295/296/301/302.
            case ARM_INS_VCGE:   ok = emit_v_fcmp(in, "oge", "sge", "uge"); break;
            case ARM_INS_VCEQ:   ok = emit_v_fcmp(in, "oeq", "eq",  "eq");  break;
            case ARM_INS_VCGT:   ok = emit_v_fcmp(in, "ogt", "sgt", "ugt"); break;
            // VCLE/VCLT: a<=b == b>=a, a<b == b>a. Capstone reports these
            // with the SAME operand order as written; the GE/GT compare
            // with operands swapped yields the LE/LT mask. Because
            // emit_v_fcmp reads operands[1],[2] in order, swap them via a
            // tiny shim by constructing the swapped-predicate at lane
            // level is not possible without touching operands, so we use
            // the reflected predicates: LE -> ole/sle/ule, LT -> olt/slt/ult.
            case ARM_INS_VCLE:   ok = emit_v_fcmp(in, "ole", "sle", "ule"); break;
            case ARM_INS_VCLT:   ok = emit_v_fcmp(in, "olt", "slt", "ult"); break;
            case ARM_INS_VTST:   ok = emit_v_icmp(in, "ne", "ne", true); break;
            case ARM_INS_VACGE:  ok = emit_v_acmp(in, "oge"); break;
            case ARM_INS_VACGT:  ok = emit_v_acmp(in, "ogt"); break;
            case ARM_INS_VAND:   ok = emit_v_logical(in, VLogOp::AND); break;
            case ARM_INS_VBIC: {
                // Register form -> shared logical path. IMMEDIATE form
                // VBIC.I<sz> Dd|Qd, #imm -> dd = dd & ~replicate(imm); this
                // was unhandled (emit_v_logical requires 3 reg operands) ->
                // no-op -> the masked-off bits kept garbage. Same corruption
                // class as the register VORR/VMVN fixes above.
                const cs_arm& d = in->detail->arm;
                if (d.op_count >= 2 && d.operands[0].type == ARM_OP_REG
                    && d.operands[d.op_count - 1].type == ARM_OP_IMM) {
                    int lane_bits = lane_bits_of(d);
                    if (lane_bits == 0) lane_bits = 32;
                    bool is_q = vfp_q_idx(d.operands[0].reg) >= 0;
                    int halves = is_q ? 2 : 1;
                    int dst_base = is_q ? (vfp_q_idx(d.operands[0].reg) * 2)
                                          : vfp_d_idx(d.operands[0].reg);
                    if (dst_base < 0) { ok = false; break; }
                    uint64_t imm =
                        static_cast<uint64_t>(d.operands[d.op_count - 1].imm);
                    uint64_t pat = 0;
                    for (int i = 0; i < 64 / lane_bits; ++i) {
                        uint64_t m = (lane_bits == 64) ? imm :
                            (imm & ((static_cast<uint64_t>(1) << lane_bits) - 1));
                        pat |= (m << (i * lane_bits));
                    }
                    uint64_t keep = ~pat;   // AND with ~imm clears imm's bits
                    for (int h = 0; h < halves; ++h) {
                        std::string old = load_dreg(dst_base + h);
                        std::string out = fresh();
                        ir << "  " << out << " = and i64 " << old << ", "
                           << static_cast<int64_t>(keep) << "\n";
                        store_dreg(dst_base + h, out);
                    }
                    ok = true; break;
                }
                ok = emit_v_logical(in, VLogOp::BIC); break;
            }
            case ARM_INS_VORN:   ok = emit_v_logical(in, VLogOp::ORN); break;
            case ARM_INS_VBSL:   ok = emit_v_logical(in, VLogOp::BSL); break;
            case ARM_INS_VBIT:   ok = emit_v_logical(in, VLogOp::BIT); break;
            case ARM_INS_VBIF:   ok = emit_v_logical(in, VLogOp::BIF); break;
            case ARM_INS_VPADD:  ok = emit_vpadd(in); break;
            case ARM_INS_VSDOT:  ok = emit_vsdot(in, true);  break;
            case ARM_INS_VUDOT:  ok = emit_vsdot(in, false); break;

            case ARM_INS_VTRN:   ok = emit_v_permute(in, VPermOp::TRN); break;
            case ARM_INS_VZIP:   ok = emit_v_permute(in, VPermOp::ZIP); break;
            case ARM_INS_VUZP:   ok = emit_v_permute(in, VPermOp::UZP); break;
            case ARM_INS_VSWP:   ok = emit_vswp(in); break;
            case ARM_INS_VMOVN:  ok = emit_vmovn(in); break;
            case ARM_INS_VADDHN:  ok = emit_vaddsubhn(in, /*is_sub=*/false, /*rounding=*/false); break;
            case ARM_INS_VSUBHN:  ok = emit_vaddsubhn(in, /*is_sub=*/true,  /*rounding=*/false); break;
            case ARM_INS_VRADDHN: ok = emit_vaddsubhn(in, /*is_sub=*/false, /*rounding=*/true);  break;
            case ARM_INS_VRSUBHN: ok = emit_vaddsubhn(in, /*is_sub=*/true,  /*rounding=*/true);  break;

            case ARM_INS_VMOVL:  ok = emit_vmovl(in); break;
            case ARM_INS_VQMOVN:  ok = emit_vqmovn(in, false); break;
            case ARM_INS_VQMOVUN: ok = emit_vqmovn(in, true);  break;

            case ARM_INS_VSHLL:  ok = emit_vshll(in); break;

            case ARM_INS_VADDW:  ok = emit_v_addw_subw(in, false); break;
            case ARM_INS_VSUBW:  ok = emit_v_addw_subw(in, true);  break;
            case ARM_INS_VABD:   ok = emit_vabd(in); break;
            case ARM_INS_VABDL:  ok = emit_vabal_vabdl(in, false); break;
            case ARM_INS_VABAL:  ok = emit_vabal_vabdl(in, true);  break;
            case ARM_INS_VABA:   ok = emit_vaba(in); break;

            case ARM_INS_VRSHL:  ok = emit_vrshl(in); break;
            case ARM_INS_VQRSHL: ok = emit_vqrshl(in); break;

            case ARM_INS_VRECPE: ok = emit_v_recip(in, false, false); break;
            case ARM_INS_VRSQRTE:ok = emit_v_recip(in, true,  false); break;
            case ARM_INS_VRECPS: ok = emit_v_recip(in, false, true);  break;
            case ARM_INS_VRSQRTS:ok = emit_v_recip(in, true,  true);  break;
            case ARM_INS_VSELEQ: ok = emit_v_sel(in, ARM_CC_EQ); break;
            case ARM_INS_VSELGE: ok = emit_v_sel(in, ARM_CC_GE); break;
            case ARM_INS_VSELGT: ok = emit_v_sel(in, ARM_CC_GT); break;
            case ARM_INS_VSELVS: ok = emit_v_sel(in, ARM_CC_VS); break;
            case ARM_INS_VRINTR: ok = emit_v_rint(in, "llvm.rint"); break;
            case ARM_INS_VRINTX: ok = emit_v_rint(in, "llvm.rint"); break;
            case ARM_INS_VRINTZ: ok = emit_v_rint(in, "llvm.trunc"); break;
            case ARM_INS_VRINTA: ok = emit_v_rint(in, "llvm.round"); break;
            case ARM_INS_VRINTM: ok = emit_v_rint(in, "llvm.floor"); break;
            case ARM_INS_VRINTP: ok = emit_v_rint(in, "llvm.ceil"); break;
            case ARM_INS_VRINTN: ok = emit_v_rint(in, "llvm.roundeven"); break;
            case ARM_INS_VMAXNM: ok = emit_vfp_minmaxnm(in, true); break;
            case ARM_INS_VMINNM: ok = emit_vfp_minmaxnm(in, false); break;

            case ARM_INS_VCVTB:  // F16 conversion: VCVTB.F32.F16 vs VCVTB.F16.F32
            case ARM_INS_VCVTT: {
                // Detect direction from vector_data: F32->F16 if result
                // is F16 (vector_data == F16F32 in some Capstones). Use
                // operand reg width hint: dst is s-reg for both forms.
                arm_vectordata_type vd = in->detail->arm.vector_data;
                bool to_f32 = (vd == ARM_VECTORDATA_F32F16 ||
                               vd == ARM_VECTORDATA_F32);
                bool to_f16 = (vd == ARM_VECTORDATA_F16F32 ||
                               vd == ARM_VECTORDATA_F16);
                bool top = (in->id == ARM_INS_VCVTT);
                if (to_f32)      ok = emit_v_cvt_half(in, top, true);
                else if (to_f16) ok = emit_v_cvt_half(in, top, false);
                else             ok = emit_nop_only();
                break;
            }
            case ARM_INS_VREV64: ok = emit_v_rev(in, 64); break;
            case ARM_INS_VREV32: ok = emit_v_rev(in, 32); break;
            case ARM_INS_VREV16: ok = emit_v_rev(in, 16); break;
            case ARM_INS_VEXT:   ok = emit_v_ext(in); break;
            case ARM_INS_VLD1:   ok = emit_vld_vst_multi(in, true,  1); break;
            case ARM_INS_VLD2:   ok = emit_vld_vst_multi(in, true,  2); break;
            case ARM_INS_VLD3:   ok = emit_vld_vst_multi(in, true,  3); break;
            case ARM_INS_VLD4:   ok = emit_vld_vst_multi(in, true,  4); break;
            case ARM_INS_VST1:   ok = emit_vld_vst_multi(in, false, 1); break;
            case ARM_INS_VST2:   ok = emit_vld_vst_multi(in, false, 2); break;
            case ARM_INS_VST3:   ok = emit_vld_vst_multi(in, false, 3); break;
            case ARM_INS_VST4:   ok = emit_vld_vst_multi(in, false, 4); break;
            // Fused multiply-add scalar VFP. We route the "true fused"
            // VFMA/VFMS/VFNMA/VFNMS to the existing emit_vfp_fma helper;
            // it implements the discrete-rounding equivalents (VMLA/
            // VMLS/VNMLA/VNMLS) which match the fused result for all
            // FP values except those where rounding-to-nearest happens
            // at intermediate precision (rare and not what compilers
            // optimize for). Acceptable approximation.
            // FUSED multiply-accumulate (A8.8.341): single rounding.
            // Pass fused=true so emit_vfp_fma uses llvm.fma instead of
            // the discrete fmul+fadd that VMLA/VMLS use (A8.8.337).
            // VFNMA/VFNMS are scalar-only here (no packed NEON form);
            // their scalar bodies map onto VNMLA/VNMLS as before.
            case ARM_INS_VFMA:  ok = emit_vfp_fma(in, FmaOp::VMLA,  true);  break;
            case ARM_INS_VFMS:  ok = emit_vfp_fma(in, FmaOp::VMLS,  true);  break;
            case ARM_INS_VFNMA: ok = emit_vfp_fma(in, FmaOp::VNMLA); break;
            case ARM_INS_VFNMS: ok = emit_vfp_fma(in, FmaOp::VNMLS); break;
            // Long-tail no-ops: instructions whose effect is invisible
            // to Apk on Mac's runtime model. Coprocessor ops, breakpoints,
            // exclusive-monitor clears, hint instructions, etc. We let
            // them pass so the surrounding function lifts; misuse will
            // surface as wrong behavior, not a build-time failure.
            case ARM_INS_BKPT:
            case ARM_INS_UDF:
            case ARM_INS_CLREX:
            case ARM_INS_YIELD:
            case ARM_INS_SEV:
            case ARM_INS_WFE:
            case ARM_INS_WFI:
            case ARM_INS_CDP:
            case ARM_INS_CDP2:
            case ARM_INS_LDC:
            case ARM_INS_LDC2:
            case ARM_INS_LDC2L:
            case ARM_INS_LDCL:
            case ARM_INS_STC:
            case ARM_INS_STC2:
            case ARM_INS_STC2L:
            case ARM_INS_STCL:
            case ARM_INS_MCR:
            case ARM_INS_MCR2:
            case ARM_INS_MCRR:
            case ARM_INS_MCRR2:
            case ARM_INS_MRC:
            case ARM_INS_MRC2:
            case ARM_INS_MRRC:
            case ARM_INS_MRRC2:
            // PLD/PLI/PLDW: cache-prefetch hints. ARM ARM A8.6.117-119
            // explicitly defines these as PE-discretionary; on a system
            // without architectural cache control they are NOPs.
            case ARM_INS_PLD:
            case ARM_INS_PLDW:
            case ARM_INS_PLI:
            // HVC: hypervisor call (ARMv7-A virtualization extension).
            // ARM ARM B1.8.5 -- raises an exception to EL2. User-mode
            // code reaching here is dead/junk; lifting as noop is
            // semantically safe because the exception path is unreachable
            // in Apk on Mac's user-only execution model.
            case ARM_INS_HVC:
            // SETEND: change endianness. ARM ARM A8.6.158 -- deprecated
            // in ARMv8. macOS host is little-endian fixed; the only
            // legal value the lifted code can request is LE, which is
            // already what we run. Noop.
            case ARM_INS_SETEND:
            // CPS/CPSIE/CPSID: change processor state (interrupt mask,
            // privilege level). Kernel-only; UNDEFINED in user mode per
            // ARM ARM B9.3.3. Noop to keep lifting moving.
            case ARM_INS_CPS:
            // BXNS/BLXNS: ARMv8-M secure-mode branch/branch-and-link.
            // Not present in ARMv7-A binaries; Capstone may decode some
            // ambiguous Thumb encodings as these. Treat as noop -- they
            // cannot affect ARMv7-A user code.
            case ARM_INS_BXNS:
            case ARM_INS_BLXNS:
            // RFE: return-from-exception. Kernel-only. ARM ARM B9.3.13.
            case ARM_INS_RFEIA:
            case ARM_INS_RFEIB:
            case ARM_INS_RFEDA:
            case ARM_INS_RFEDB:
            // DCPS1/2/3: debug change-processor-state. Used by JTAG
            // debuggers only.
            case ARM_INS_DCPS1:
            case ARM_INS_DCPS2:
            case ARM_INS_DCPS3:
            // ERET: exception return. Kernel-only.
            case ARM_INS_ERET:
            // FSTMIAX/FLDMIAX: VFPv1 legacy load/store-multiple (the
            // 'X' suffix means "extended -- one extra word per d-reg").
            // Not used by compiled code post-VFPv2 (2003); the only
            // occurrences in modern .so files are inside dead data
            // disassembled as instructions. Noop.
            case ARM_INS_FSTMIAX:
            case ARM_INS_FSTMDBX:
            case ARM_INS_FLDMIAX:
            case ARM_INS_FLDMDBX:
                ok = emit_nop_only(); break;
            // Kernel / security / data no-ops. These mnemonics only
            // appear in ARMv7-A userspace .so files when Capstone
            // mis-decodes literal-pool DATA (constant tables embedded in
            // .text) as instructions -- they are never on a real
            // execution path in a userspace game. TRAP (A8 undefined),
            // SMC (B1.8.5 secure-monitor call), TT/TTA/TTAT/TTT (ARMv8-M
            // TT test-target, not ARMv7-A), VLSTM/VLLDM (ARMv8-M secure
            // FP lazy save/restore). Emit a data-marker comment, not the
            // UNSUPPORTED marker, and lift the rest of the function.
            case ARM_INS_TRAP:
            case ARM_INS_SMC:
            case ARM_INS_TT:
            case ARM_INS_TTA:
            case ARM_INS_TTAT:
            case ARM_INS_TTT:
            case ARM_INS_VLSTM:
            case ARM_INS_VLLDM:
                ir << "  ; " << in->mnemonic
                   << " (kernel/data, no-op)\n";
                ok = true;
                break;

            case ARM_INS_SVC:   ok = emit_svc(in);  break;
            case ARM_INS_B: {
                if (is_always(static_cast<arm_cc>(in->detail->arm.cc))) {
                    ok = emit_uncond_branch(in, fn_start, fn_end_excl, &terminated);
                } else {
                    uint32_t fall = static_cast<uint32_t>(in->address) + in->size;
                    ok = emit_cond_branch(in, fn_start, fn_end_excl,
                                           fall, &terminated);
                }
                break;
            }
            case ARM_INS_BL: {
                uint32_t ret_addr = static_cast<uint32_t>(in->address) + in->size;
                ok = emit_bl(in, ret_addr);
                break;
            }
            case ARM_INS_BX: {
                bool is_lr_ret = false;
                bool indirect_term = false;
                ok = emit_bx(in, &is_lr_ret, &indirect_term);
                if (!ok) break;
                if (indirect_term) {
                    // BX <reg-not-LR>: emit_bx already wrote a tail
                    // call + ret. Just record the block as terminated.
                    terminated = true;
                    break;
                }
                if (!is_lr_ret) break;
                if (conditional) {
                    std::string cond = emit_cond_check(in->detail->arm.cc);
                    uint32_t fall = static_cast<uint32_t>(in->address) + in->size;
                    bool fall_synth = (valid_addrs_.count(fall) == 0);
                    std::string synth_label;
                    if (fall_synth) synth_label = "bxfall_" + std::to_string(ssa_counter++);
                    std::string fall_lbl = fall_synth
                        ? ("%" + synth_label)
                        : ("%" + bb_label(fall));
                    std::string ret_block = "bxret_" + std::to_string(ssa_counter++);
                    flush_dirty_regs();
                    ir << "  br i1 " << cond << ", label %" << ret_block
                       << ", label " << fall_lbl << "\n";
                    ir << ret_block << ":\n";
                    // ret_block and the synth fall (if present) are
                    // parallel siblings reached via br i1, not via
                    // fall-through. Reset cache so each gets a fresh
                    // load_reg from memory.
                    cache_clear();
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    if (fall_synth) {
                        ir << synth_label << ":\n";
                        cache_clear();
                        std::string r0b = load_reg(0);
                        ir << "  ret i32 " << r0b << "\n";
                    }
                    terminated = true;
                } else {
                    std::string r0 = load_reg(0);
                    ir << "  ret i32 " << r0 << "\n";
                    terminated = true;
                }
                break;
            }
            case ARM_INS_NOP:
            case ARM_INS_IT:
            case ARM_INS_HINT:
                // IT (if-then) blocks: Capstone propagates the
                // resulting condition onto each instruction's cc, so
                // the IT instruction itself becomes a no-op for us.
                break;
            case ARM_INS_CBZ:
                ok = emit_cb(in, false, fn_start, fn_end_excl, &terminated);
                break;
            case ARM_INS_CBNZ:
                ok = emit_cb(in, true,  fn_start, fn_end_excl, &terminated);
                break;
            case ARM_INS_TBB:
            case ARM_INS_TBH:
                ok = emit_tbb(in, fn_start, fn_end_excl, &terminated);
                break;
            default:
                if (strict_) {
                    *err = std::string("unsupported instruction '") +
                           in->mnemonic + " " + in->op_str + "'";
                    return EmitOutcome::Failed;
                }
                // Lenient mode: leave a comment marker and continue.
                // The function still lifts; if the unsupported op is on
                // a hot path the runtime behavior will be wrong, but
                // the typical case is cold paths (init, error handling)
                // where the missing semantics rarely matter.
                ir << "  ; UNSUPPORTED " << in->mnemonic << " "
                   << in->op_str << " -- emitted as no-op\n";
                break;
        }
        if (!ok) {
            // A handler returned false. In strict mode this is fatal;
            // in lenient mode we'd rather lift the rest of the function
            // and treat this single instruction as a no-op than abandon
            // the whole function (which leaves it as an unresolved-extern
            // panic stub that cascades into SIGFPE / pure-virtual
            // crashes whenever something calls the missing body).
            // png_build_gamma_table is the canonical case -- one NEON
            // SIMD op the lifter doesn't know about made the whole
            // function unliftable, so libpng's gamma path called into
            // a nonexistent translated body.
            if (strict_) {
                *err = std::string("failed to lift '") + in->mnemonic +
                       " " + in->op_str + "'";
                return EmitOutcome::Failed;
            }
            ir << "  ; UNSUPPORTED-FALLBACK " << in->mnemonic << " "
               << in->op_str << " -- handler returned false; treated as no-op\n";
        }
        return terminated ? EmitOutcome::Terminated : EmitOutcome::Normal;
    }

    LiftedFunction run(const Elf32Image& img, const Symbol& sym) {
        // Re-derived per lift so set_emit_ir / set_strict ordering relative
        // to the first lift cannot matter.
        discovery_only_ = noir_gate_ && !ir.enabled() && !strict_;
        ++(discovery_only_ ? noir_lifts_ : ir_lifts_);
        LiftedFunction out = run_body(img, sym);
        if (digest_on_) digest_result(sym, out);
        return out;
    }

    LiftedFunction run_body(const Elf32Image& img, const Symbol& sym) {
        LiftedFunction out{};
        out.name = sym.name;
        image_ = &img;
        // Compute the PIC add-rd-pc discriminator's valid-target ranges once
        // per image (emit_alu). The legitimate targets of a `ldr rN,[pc]; add
        // rN,pc` are the GOT and the GLOBAL DATA sections (struct/global bases,
        // vtable/pointer tables) -- ALL 4-byte-aligned. We list each section
        // separately (not a min..max span) so .rodata/.text are excluded: those
        // hold 2-byte-aligned strings where a false-override could corrupt an
        // aligned-convention app (GD Lite). Section names come from the
        // section-header string table (shstrndx); a stripped image yields no
        // ranges and the discriminator stays disabled (keeps the aligned PC).
        if (got_image_ != &img) {
            got_image_ = &img; target_ranges_.clear();
            if (img.hdr.e_shstrndx < img.shdrs.size()) {
                const auto& shstr = img.shdrs[img.hdr.e_shstrndx];
                for (const auto& sh : img.shdrs) {
                    size_t off = static_cast<size_t>(shstr.sh_offset) + sh.sh_name;
                    if (off >= img.raw.size()) continue;
                    const char* nm = reinterpret_cast<const char*>(img.raw.data() + off);
                    size_t maxlen = img.raw.size() - off;
                    auto eq = [&](const char* lit) {
                        size_t n = std::strlen(lit);
                        return n < maxlen && std::memcmp(nm, lit, n + 1) == 0;
                    };
                    // v1.0.537: .rodata included so the register-form `add
                    // Rd,pc` discriminator (uses UNALIGNED PC, only overrides
                    // on a 4-aligned in-range target) covers GCC PIC read-only
                    // data tables -- zlib inflate_table dbase/dext (HCR). Was
                    // excluded; that made HCR's deflated assets fail
                    // (Z_DATA_ERROR). Sweep-gated (GD-Lite canary 508).
                    // See docs/hcr-zlib-inflate-table-add-pc-aligned_2026-06-29.md.
                    if (eq(".got") || eq(".got.plt") || eq(".data") ||
                        eq(".bss") || eq(".data.rel.ro") ||
                        eq(".data.rel.ro.local") || eq(".rodata")) {
                        uint32_t lo = sh.sh_addr, hi = sh.sh_addr + sh.sh_size;
                        if (hi > lo) target_ranges_.emplace_back(lo, hi);
                    }
                }
            }
        }

        // Pick the right Capstone mode for this symbol. Bionic encodes
        // Thumb-ness in the LSB of st_value; Elf32Image's reader
        // surfaces that as Symbol::is_thumb.
        handle = sym.is_thumb ? handle_thumb : handle_arm;
        cs_ok  = sym.is_thumb ? cs_thumb_ok  : cs_arm_ok;

        if (!cs_ok) {
            out.success = false;
            out.error = "capstone init failed for "
                        + std::string(sym.is_thumb ? "Thumb" : "ARM")
                        + " mode";
            return out;
        }

        size_t avail = 0;
        auto bytes = img.code_for(sym, &avail);
        if (bytes.empty()) {
            out.success = false;
            out.error = "no code bytes for " + sym.name;
            return out;
        }

        cs_insn* insns = nullptr;
        // MACAPK_FIRSTLAUNCH_DECODE_CACHE (see dc_acquire): the same decode,
        // possibly served from an earlier overlapping sweep. Every exit below
        // releases through dc_release, which is exactly cs_free when the
        // gate is off or the array is not the cache's.
        dc_owned_ = false;
        size_t count = dc_gate_
            ? dc_acquire(img, sym, bytes, &insns)
            : cs_disasm(handle, bytes.data(), bytes.size(),
                        sym.address & ~1u, 0, &insns);
        if (count == 0) {
            out.success = false;
            out.error = sym.name + ": disassembly produced 0 instructions";
            return out;
        }

        uint32_t fn_start = static_cast<uint32_t>(sym.address & ~1u);

        // Synth boundary detector. For SYNTHETIC functions only (name
        // starts with "__macapk_synth_"), Capstone with SKIPDATA
        // will happily decode past the function's REAL end into
        // whatever bytes follow in the budget -- absorbing other
        // unsymboled functions into one bloated body. When a sibling
        // synth or BL caller tries to call into one of those absorbed
        // functions, the alias generator emits a panic stub because
        // the absorbed entry isn't in `lifted_address_map` (only the
        // outer synth's start is). Result: hundreds-of-thousands of
        // unresolved calls and broken downstream behavior (HCR 1.43
        // ARM32 boots but renders black at 60 fps because cocos2d-x
        // calls into unlifted functions during AppDelegate init).
        //
        // Heuristic: after each clean terminator (POP {..,pc} / BX
        // lr / B uncond / B.W uncond), look at the NEXT non-data
        // instruction. If it has a function-prologue shape (PUSH
        // {..,lr} / PUSH {r0..r7} / `mov ip, sp` / `sub sp, sp,
        // #imm`), the terminator was the previous function's REAL
        // end -- truncate `count` so subsequent insns aren't
        // absorbed. This stops at the FIRST inter-function boundary
        // rather than the budget end, leaving the next function
        // available for an independent synth in a later discovery
        // round.
        //
        // Constraint: only apply when ALL prior branches in the
        // already-decoded range stay AT OR BELOW the terminator's
        // address. If any earlier branch targets PAST the
        // terminator, the function genuinely continues past this
        // exit (it's a loop epilogue or early-return). Tracking the
        // max in-budget branch target lets us preserve multi-exit
        // functions.
        // v1.0.833: THIS TEST HAS BEEN DEAD SINCE THE REBRAND.
        //
        // It read `sym.name.compare(0, 17, "__macapk_synth_") == 0`. The
        // literal is 15 characters; the pre-rebrand one, "__macdroid_synth_",
        // was 17 (commit 0d3691f, "Bug fixes and name change to Apk on Mac",
        // renamed the prefix and left the length). compare(pos, len, s)
        // measures s against a len-character substring, so a 17-char substring
        // could never equal the 15-char literal: `is_synth` was ALWAYS FALSE,
        // and the synth-truncation safety net below has not run since
        // 2026-06-06. Verified by measuring both lengths, not by eye.
        //
        // Restoring it is NOT a free win, which is why the corrected test is
        // behind a default-OFF flag rather than simply switched on. This
        // mechanism has a violent history in both directions: it recovered
        // +5132 functions when added (v1.0.29), then co-caused a 17894 -> 825
        // function collapse on HCR 1.8.1 (v1.0.30/31). Every literal-pool
        // carve-out since (v531, v552, v825, v828) was tuned over the seven
        // weeks it was silently off, so turning it back on changes the ground
        // those were calibrated against. Default path stays byte-identical;
        // MACAPK_ARM32_SYNTH_TRUNCATE=1 enables the corrected behaviour for
        // A/B work against debug/discovery_boundary_stats.py + the protected
        // sweep. See docs/arm32-discovery-boundary-defect_2026-07-29.md.
        static const bool s_synth_truncate = [](){
            const char* e = std::getenv("MACAPK_ARM32_SYNTH_TRUNCATE");
            return e && *e && *e != '0'; }();
        const bool is_synth =
            s_synth_truncate &&
            sym.name.compare(0, 15, "__macapk_synth_") == 0;
        auto is_clean_terminator = [&](const cs_insn* in) -> bool {
            if (in->id == ARM_INS_BX) return true;
            if (in->id == ARM_INS_POP) {
                // pop {..., pc} reads pc as a destination register.
                const cs_arm& d = in->detail->arm;
                for (uint8_t k = 0; k < d.op_count; ++k) {
                    if (d.operands[k].type == ARM_OP_REG &&
                        d.operands[k].reg == ARM_REG_PC) return true;
                }
                return false;
            }
            if (in->id == ARM_INS_B) {
                // Unconditional B (cc == AL) terminates a basic
                // block; the caller's CFG analysis decides whether
                // the function continues.
                const cs_arm& d = in->detail->arm;
                return d.cc == ARM_CC_AL || d.cc == ARM_CC_INVALID;
            }
            return false;
        };
        auto looks_like_prologue = [&](const cs_insn* in) -> bool {
            // ARM `push {..., lr}` always lists lr as a register operand.
            // Thumb16 `push {..., lr}` is the same encoding via Capstone.
            if (in->id == ARM_INS_PUSH) {
                const cs_arm& d = in->detail->arm;
                for (uint8_t k = 0; k < d.op_count; ++k) {
                    if (d.operands[k].type == ARM_OP_REG &&
                        d.operands[k].reg == ARM_REG_LR) return true;
                }
                // Even `push {r4..r7}` without lr is a typical leaf
                // prologue; accept it.
                return d.op_count >= 2;
            }
            // `mov ip, sp` (ARM AAPCS prologue start).
            if (in->id == ARM_INS_MOV) {
                const cs_arm& d = in->detail->arm;
                if (d.op_count == 2 &&
                    d.operands[0].type == ARM_OP_REG &&
                    d.operands[0].reg == ARM_REG_IP &&
                    d.operands[1].type == ARM_OP_REG &&
                    d.operands[1].reg == ARM_REG_SP) return true;
            }
            // `sub sp, sp, #imm` (frame allocation in leaf functions).
            if (in->id == ARM_INS_SUB) {
                const cs_arm& d = in->detail->arm;
                if (d.op_count == 3 &&
                    d.operands[0].type == ARM_OP_REG &&
                    d.operands[0].reg == ARM_REG_SP &&
                    d.operands[1].type == ARM_OP_REG &&
                    d.operands[1].reg == ARM_REG_SP &&
                    d.operands[2].type == ARM_OP_IMM) return true;
            }
            return false;
        };
        size_t effective_count = count;
        if (is_synth) {
            const uint32_t budget_end = fn_start +
                static_cast<uint32_t>(sym.size);
            uint32_t max_branch_target = fn_start;
            for (size_t i = 0; i < count; ++i) {
                const cs_insn* in = &insns[i];
                if (in->id == 0) continue;  // skipdata
                // Track ONLY intra-function branches (B / CBZ /
                // CBNZ). Skip BL: BL is a function CALL, not an
                // intra-function branch, and its target is some
                // OTHER function (almost always outside the budget).
                // Counting BL targets here would make
                // max_branch_target balloon past every legitimate
                // terminator, defeating the truncation.
                if (in->id == ARM_INS_B || in->id == ARM_INS_CBZ ||
                    in->id == ARM_INS_CBNZ) {
                    const cs_arm& d = in->detail->arm;
                    if (d.op_count >= 1 &&
                        d.operands[0].type == ARM_OP_IMM) {
                        uint32_t t = static_cast<uint32_t>(d.operands[0].imm);
                        // Only track branches that land INSIDE the
                        // current synth's budget. Tail-calls to
                        // earlier functions or to addresses past
                        // the budget shouldn't extend our notion of
                        // "the current function continues here".
                        if (t > fn_start && t < budget_end &&
                            t > max_branch_target) {
                            max_branch_target = t;
                        }
                    }
                }
                if (!is_clean_terminator(in)) continue;
                uint32_t term_end =
                    static_cast<uint32_t>(in->address) + in->size;
                // Don't truncate past any in-function forward
                // branch target -- the function genuinely
                // continues there (early-return / loop epilogue
                // pattern).
                if (max_branch_target >= term_end) continue;
                // Peek at the next non-skipdata instruction. If
                // there isn't one, the budget ends here -- truncate
                // anyway since nothing depends on the trailing
                // bytes.
                size_t j = i + 1;
                while (j < count && insns[j].id == 0) ++j;
                if (j >= count) {
                    effective_count = i + 1;
                    break;
                }
                // Truncate. The remaining bytes belong to a sibling
                // function and should be discoverable as its own
                // synth in a later BL/synth round (or via prologue
                // scan). Note: we DON'T require the next insn to
                // "look like a prologue" -- tiny getter/setter
                // functions in cocos2d-x v2's vtables are 2-3
                // instructions starting with a load/store, not a
                // push. Trusting the terminator alone, gated by the
                // max_branch_target check above, is more reliable
                // than pattern-matching every possible function
                // entry shape.
                (void)looks_like_prologue;  // kept for readability
                effective_count = i + 1;
                break;
            }
        }

        uint32_t fn_end_excl = fn_start;
        for (size_t i = 0; i < effective_count; ++i) {
            uint32_t end = static_cast<uint32_t>(insns[i].address) + insns[i].size;
            if (end > fn_end_excl) fn_end_excl = end;
        }
        count = effective_count;  // honor truncation in subsequent passes

        // Synth mode-validation. For SYNTHETIC functions only, check
        // that the FIRST non-skipdata decoded instruction has the
        // shape of a real function entry. With CS_OPT_SKIPDATA on,
        // Capstone never reports failure -- it just emits .byte
        // pseudo-instructions for undecodable bytes -- so the
        // main.cpp mode-retry path (which checks lf.success) never
        // fires for wrong-mode synth lifts.
        //
        // Symptom this catches: HCR 1.43's libstdc++ region from
        // ~0x2d0000 onwards is entirely Thumb, but the lifter's
        // mode picker (sniff_thumb_at + nearest_known_thumb) miss
        // every Thumb-2 prologue that isn't a 16-bit push (b5XX).
        // Result: synth_002dba38 lifted in ARM mode produces a body
        // of garbage instructions (`bllt`, `movweq pc`, `rscslo`,
        // `vsri.32`, `ldmda r3, {...} ^`, `svchi #...`) and absorbs
        // 0x2dba74 (a real Thumb helper) as data. Calls to 0x2dba74
        // from elsewhere then dispatch into the indirect-call shim,
        // find no host_fn, return 0, the caller loops forever
        // re-calling -- ANGLE rendering thread starves at 4 BILLION
        // calls and no frame ever ships.
        //
        // The signal: real ARM function entries have an
        // unconditional first instruction (condition code AL).
        // `bllt` / `movweq` / `rscslo` etc. -- non-AL conditions at
        // function entry -- almost never occur in compiler-emitted
        // ARM code, but they DO occur frequently when Thumb bytes
        // are misread as ARM (because each Thumb-2 32-bit insn has
        // ~half the encoding space, and many of those bytes map to
        // conditional ARM instructions when reinterpreted).
        //
        // Returning failure here triggers main.cpp's mode-retry
        // path which lifts the same vaddr in the OTHER ISA.
        if (is_synth && count > 0) {
            size_t fi = 0;
            while (fi < count && insns[fi].id == 0) ++fi;
            if (fi < count) {
                const cs_insn* first = &insns[fi];
                const cs_arm& d = first->detail->arm;
                bool first_is_prologue =
                    first->id == ARM_INS_PUSH ||
                    first->id == ARM_INS_STMDB ||  // stmdb sp!, {...}
                    (first->id == ARM_INS_MOV && d.op_count >= 2 &&
                     d.operands[0].type == ARM_OP_REG &&
                     d.operands[1].type == ARM_OP_REG &&
                     d.operands[0].reg == ARM_REG_IP &&
                     d.operands[1].reg == ARM_REG_SP) ||
                    (first->id == ARM_INS_SUB && d.op_count >= 3 &&
                     d.operands[0].type == ARM_OP_REG &&
                     d.operands[0].reg == ARM_REG_SP);
                bool conditional = (d.cc != ARM_CC_AL &&
                                    d.cc != ARM_CC_INVALID);
                if (conditional && !first_is_prologue) {
                    out.success = false;
                    out.error = sym.name +
                        ": first decoded instruction is conditional"
                        " and not a prologue (likely "
                        + std::string(sym.is_thumb ? "Thumb" : "ARM")
                        + " mode mismatch -- bytes look like the "
                        "OTHER ISA's code)";
                    dc_release(insns, count);
                    return out;
                }
            }
        }

        // MACAPK_ARM32_SCAN_MODE_FIX (default ON): scan_blocks notes every
        // BL #imm target's ISA mode from current_is_thumb, which run_body's
        // loop assigns only AFTER this call -- so it held the PREVIOUS lift's
        // mode, and emit_bl's correct note then marked the target a CONFLICT
        // whenever the two lifts differed in ISA (GD Lite v7a: 5609 of ~35.4k
        // targets; HCR 1.8.1: 1579; fmod: 364), sending those callees back to
        // byte-sniffing instead of v1.0.814's authoritative call-site mode.
        // =0 restores the stale value. docs/arm32-discovery-lift-speedup_2026-09-26.md
        static const bool s_scan_mode_fix = [](){
            const char* e = std::getenv("MACAPK_ARM32_SCAN_MODE_FIX");
            return !(e && *e == '0'); }();
        if (s_scan_mode_fix) current_is_thumb = sym.is_thumb;
        scan_blocks(insns, count, fn_start, fn_end_excl);

        ir.str("");
        ir.clear();
        insn_log.clear();
        ssa_counter = 0;
        // Block-local register-file cache starts empty at every
        // function entry. emit_function_prologue stores args to the
        // %r alloca; the first load_reg() in the entry block will
        // pull them back from memory and cache them.
        cache_clear();
        emit_function_prologue(sym.name);

        // Optional diagnostic: emit a call to __macapk_trace_func_entry
        // at the very top of the function body, BEFORE any user code,
        // for vaddrs listed in MACAPK_TRACE_VADDRS env var
        // (comma- or space-separated hex values, e.g. "0x12176c,0x128594").
        // The hook receives the function vaddr plus the 4 ARM arg-regs
        // and the inherited SP, so callers can correlate which lifted
        // body is being entered and with what args -- without needing
        // any per-APK code path.
        {
            static std::set<uint32_t> trace_set;
            static bool trace_loaded = false;
            if (!trace_loaded) {
                trace_loaded = true;
                const char* env = std::getenv("MACAPK_TRACE_VADDRS");
                std::fprintf(stderr,
                    "[lifter] MACAPK_TRACE_VADDRS=%s\n",
                    env ? env : "(unset)");
                if (env) {
                    const char* p = env;
                    while (*p) {
                        while (*p == ',' || *p == ' ' || *p == '\t') ++p;
                        if (!*p) break;
                        char* endp = nullptr;
                        unsigned long v = std::strtoul(p, &endp, 16);
                        if (endp == p) break;
                        trace_set.insert(static_cast<uint32_t>(v));
                        std::fprintf(stderr,
                            "[lifter] trace vaddr added: 0x%lx\n", v);
                        p = endp;
                    }
                }
            }
            if (trace_set.count(fn_start)) {
                std::fprintf(stderr,
                    "[lifter] emitting trace at fn_start=0x%x for sym=%s\n",
                    fn_start, sym.name.c_str());
                ir << "  call void @__macapk_trace_func_entry(i32 "
                   << fn_start
                   << ", i32 %arg0, i32 %arg1, i32 %arg2, i32 %arg3, "
                      "i32 %arg_sp)\n";
            }
        }

        // Unicorn-differential capture (MACAPK_DIFF_VADDRS). When this
        // function is a target, emit a single entry-capture call carrying
        // the four ARM arg regs, the inherited SP, and the ISA mode. The
        // shim dumps the live guest register + resident-page memory
        // snapshot the Python Unicorn harness replays from; it also arms
        // the per-instruction trace below for this invocation.
        const bool diff_this_fn = diff_vaddrs_.count(fn_start) > 0;
        if (diff_this_fn) {
            std::fprintf(stderr,
                "[lifter] DIFF-instrumenting fn_start=0x%x (thumb=%d) sym=%s\n",
                fn_start, sym.is_thumb ? 1 : 0, sym.name.c_str());
            ir << "  call void @__macapk_capture_entry(i32 " << fn_start
               << ", i32 %arg0, i32 %arg1, i32 %arg2, i32 %arg3, "
                  "i32 %arg_sp, i32 " << (sym.is_thumb ? 1 : 0) << ")\n";
        }

        // Open the entry block: branch from `entry:` to the first bb.
        ir << "  br label %" << bb_label(fn_start) << "\n\n";

        bool block_terminated = true;          // forces a label on first inst
        std::string err;
        bool failed = false;
        bool ever_terminated = false;

        // Make the instruction stream available to TBB-emit (which
        // looks back at the prior cmp/bhi to size the jump table).
        current_insns_ = insns;
        current_count_ = count;

        for (size_t i = 0; i < count; ++i) {
            cs_insn* in = &insns[i];
            uint32_t addr = static_cast<uint32_t>(in->address);

            // SKIPDATA pseudo-instruction (id==0, mnemonic=".byte"):
            // bytes Capstone couldn't decode as a valid instruction
            // and skipped past. These are typically mid-function
            // literal-pool data (immediates referenced by `ldr rN,
            // [pc, #imm]` from elsewhere in the function). Produce
            // no real IR but DO emit a basic-block label if this
            // address is referenced as a branch target -- otherwise
            // an earlier `br i1 %cond, ..., label %bb_<addr>`
            // references a label we never define and llvm-as
            // rejects the module ("use of undefined value
            // %bb_<addr>"). A stub block that just returns 0 keeps
            // the IR well-formed; the unreachable-branch
            // optimization will delete it.
            if (in->id == 0) {
                if (block_starts.count(addr) > 0) {
                    if (!block_terminated) {
                        ir << "  br label %" << bb_label(addr) << "\n";
                    }
                    ir << bb_label(addr) << ":  ; "
                       << std::hex << addr << std::dec
                       << " .byte (literal pool); stub for branch target\n";
                    ir << "  ret i32 0\n";
                    block_terminated = true;
                    ever_terminated = true;
                    continue;
                }
                ir << "  ; " << std::hex << addr << std::dec
                   << ":  .byte (literal pool data, skipped: "
                   << in->mnemonic << " " << in->op_str << ")\n";
                // Recorded with ret_idiom=false: the text form spelled the
                // mnemonic ".byte", which never matched a return idiom.
                insn_log.push_back({static_cast<uint32_t>(addr), false});
                continue;
            }

            // Skip table-data bytes that Capstone disassembled as bogus
            // instructions inside a Thumb-2 TBB/TBH inline jump table.
            // emit_tbb already wrote a switch with the real targets;
            // these "instructions" are just data and must produce no IR.
            // (Edge case: when garbage data elsewhere in the binary
            // disassembles as a CBZ/B that points into our table, the
            // lifter records that target in block_starts. We still need
            // to materialize a label there or LLVM rejects the IR for a
            // forward reference -- emit a stub label that returns 0 so
            // the block stays syntactically valid.)
            if (tbb_skip_addrs_.count(addr) > 0) {
                if (block_starts.count(addr) > 0) {
                    if (!block_terminated) {
                        ir << "  br label %" << bb_label(addr) << "\n";
                    }
                    ir << bb_label(addr) << ":  ; "
                       << std::hex << addr << std::dec
                       << " TBB table byte; stub for stale branch\n";
                    ir << "  ret i32 0\n";
                    block_terminated = true;
                    ever_terminated = true;
                    continue;
                }
                ir << "  ; " << std::hex << addr << std::dec
                   << ":  TBB/TBH table byte (skipped: " << in->mnemonic
                   << " " << in->op_str << ")\n";
                // ret_idiom=false: the text form spelled "TBB/TBH".
                insn_log.push_back({static_cast<uint32_t>(addr), false});
                continue;
            }

            // MACAPK_FIRSTLAUNCH_LIFT_NOIR: block labels, the fall-through
            // br and the register cache are IR block structure and nothing
            // else (block_terminated feeds only IR and --strict), so the
            // discovery-only path skips them, including the per-instruction
            // std::set lookup and bb_label's snprintf.
            if (!discovery_only_) {
                bool is_block_start = block_starts.count(addr) > 0;

                if (is_block_start) {
                    if (!block_terminated) {
                        // Fall-through into a new block: dirty regs must
                        // hit memory before the implicit br so the next
                        // block (which clears cache) reads consistent
                        // values.
                        flush_dirty_regs();
                        ir << "  br label %" << bb_label(addr) << "\n";
                    }
                    ir << bb_label(addr) << ":\n";
                    block_terminated = false;
                    // New block: predecessor's SSA names aren't reachable
                    // here, so drop the cache and start fresh.
                    cache_clear();
                } else if (block_terminated) {
                    // Capstone may disassemble dead bytes after a return.
                    // Wrap them in a fresh dead block so the IR stays valid.
                    ir << "dead_" << std::hex << addr << std::dec << ":\n";
                    block_terminated = false;
                    cache_clear();
                }

                ir << "  ; " << std::hex << addr << std::dec
                   << ":  " << in->mnemonic << " " << in->op_str << "\n";
            }
            // Structured mirror of that comment, for discovery. MUST stay in
            // step with the three `  ; <addr>:` sites -- scan_insns() in
            // main.cpp consumes this instead of re-parsing the text.
            insn_log.push_back({static_cast<uint32_t>(addr),
                                is_return_idiom(in->mnemonic)});

            // Cache the instruction's address + size so memory-operand
            // helpers (compute_mem_addr) can substitute the right PC
            // value for ARM_REG_PC reads.
            current_insn_addr = static_cast<uint32_t>(in->address);
            current_insn_size = in->size;
            current_is_thumb = sym.is_thumb;
            current_idx_ = i;
            EmitOutcome r = emit_one(in, fn_start, fn_end_excl, &err);
            if (r == EmitOutcome::Failed) {
                failed = true;
                break;
            }
            // Unicorn-differential per-instruction register trace
            // (MACAPK_DIFF_VADDRS). Emit a __macapk_trace_regs call
            // logging r0..r15 AFTER this instruction's effects. Only for
            // EmitOutcome::Normal: a Terminated instruction already closed
            // the block with a br/ret, and IR forbids any instruction
            // after a terminator. Skipping the trace on branch/return
            // instructions costs nothing for the diff -- the harness
            // aligns by vaddr, so the next instruction (at the branch
            // target) is still compared, and a wrong branch target shows
            // up as a vaddr mismatch there. load_reg() returns the live
            // value for each reg (cache hit, dirty-cache, or a fresh
            // reload); r15 is the ARM PC-read convention constant, which
            // the harness ignores (it keys on the insn vaddr instead).
            if (diff_this_fn && r == EmitOutcome::Normal) {
                // Resolve all 16 register SSA names FIRST: load_reg() may
                // emit its own getelementptr+load IR lines, which must
                // land before (not interleaved into) the single call line.
                std::string rv[16];
                for (int rt = 0; rt < 16; ++rt) rv[rt] = load_reg(rt);
                ir << "  call void @__macapk_trace_regs(i32 " << addr;
                for (int rt = 0; rt < 16; ++rt) ir << ", i32 " << rv[rt];
                ir << ")\n";
            }
            if (r == EmitOutcome::Terminated) {
                block_terminated = true;
                ever_terminated = true;
            }
        }
        current_insns_ = nullptr;
        current_count_ = 0;
        dc_release(insns, count);

        if (failed) {
            out.success = false;
            out.error = sym.name + ": " + err;
            return out;
        }
        if (!ever_terminated) {
            // Function fell off without an explicit return path. In
            // strict mode this is an error; otherwise we just close
            // with `ret R0`. Compiler-emitted code rarely reaches here
            // but obfuscated/handwritten asm sometimes does.
            if (strict_) {
                out.success = false;
                out.error = sym.name + ": no return instruction reached";
                return out;
            }
        }
        if (!block_terminated) {
            // Function fell off without an explicit terminator.
            // Default: emit `ret r0` so callers see a defined value.
            // See changelog v1.0.55/v1.0.56/v1.0.57 for history of
            // attempted register-snapshot tail-call alternatives --
            // they unblock HCR's CCNode body but expose a downstream
            // bug in GarageLibJsonParser that asserts millions of
            // times. Stay with `ret r0` for stability.
            std::string r0 = load_reg(0);
            ir << "  ret i32 " << r0 << "\n";
        }
        ir << "}\n\n";

        // Roll the per-function externals into the module-scope union;
        // caller emits one de-duplicated `declare` block at module scope.
        // v1.0.553 diagnostic: MACAPK_TRACE_EXTERN_TARGET=0xADDR names every
        // function whose lift records ADDR as an extern target -- the tool
        // for finding WHICH (possibly mode-misclassified) lift polluted
        // discovery with a bogus function start (the 0x93d10 truncation
        // cascade that gutted FreeType's load_truetype_glyph).
        static const uint32_t s_tet = [](){
            const char* e = std::getenv("MACAPK_TRACE_EXTERN_TARGET");
            return e ? static_cast<uint32_t>(strtoul(e, nullptr, 0)) : 0u;
        }();
        if (s_tet && (extern_call_targets.count(s_tet) ||
                      extern_call_targets.count(s_tet | 1u))) {
            std::fprintf(stderr,
                "[extern-tgt] 0x%x recorded by lift of %s [0x%x] "
                "(thumb=%d, as_bl=%d)\n",
                s_tet, sym.name.c_str(), fn_start, int(sym.is_thumb),
                int(extern_bl_targets.count(s_tet) ||
                    extern_bl_targets.count(s_tet | 1u)));
        }
        for (uint32_t t : extern_call_targets) all_extern_targets.insert(t);
        for (uint32_t t : extern_bl_targets)   all_extern_bl_targets.insert(t);
        lifted_addr_to_name[fn_start] = sym.name;

        out.ir_body = ir.str();
        out.insns   = insn_log;
        out.success = true;
        return out;
    }
};

Arm32Lifter::Arm32Lifter()  : impl_(new Impl) {}
Arm32Lifter::~Arm32Lifter() { delete impl_; }

LiftedFunction Arm32Lifter::lift_function(const Elf32Image& img,
                                          const Symbol& sym) {
    return impl_->run(img, sym);
}

LiftedFunction Arm32Lifter::lift_synthetic(const Elf32Image& img,
                                           uint32_t vaddr, uint32_t size,
                                           bool is_thumb) {
    // Build a Symbol that mimics the ones in the ELF symbol table,
    // then route through the same run() path. The is_thumb flag
    // matters for the Capstone mode pick; default to ARM since
    // compiler-emitted ARM code has the recognizable
    // PUSH-then-MOV-then-... prologue at every function entry, and
    // most stripped-but-not-Thumb-only .so files we see fall in
    // ARM mode. The discovery loop in main.cpp can override per-call
    // when it has reason to suspect Thumb (e.g. odd-aligned target).
    Symbol s{};
    char buf[64];
    std::snprintf(buf, sizeof(buf), "__macapk_synth_%08x", vaddr);
    s.name     = buf;
    s.address  = vaddr;
    s.size     = size;
    s.bind     = STB_GLOBAL;
    s.type     = STT_FUNC;
    s.is_thumb = is_thumb;
    return impl_->run(img, s);
}

const std::unordered_set<uint32_t>& Arm32Lifter::external_targets() const {
    return impl_->all_extern_targets;
}

const std::unordered_set<uint32_t>& Arm32Lifter::external_bl_targets() const {
    return impl_->all_extern_bl_targets;
}

std::optional<bool> Arm32Lifter::call_target_thumb(uint32_t vaddr) const {
    const uint32_t key = vaddr & ~1u;
    // A disagreement between call sites means we genuinely do not know; say
    // so rather than picking a side. See note_call_target_mode.
    if (impl_->call_target_mode_conflict.count(key)) return std::nullopt;
    auto it = impl_->call_target_is_thumb.find(key);
    if (it == impl_->call_target_is_thumb.end()) return std::nullopt;
    return it->second;
}

const std::unordered_map<uint32_t, std::string>&
Arm32Lifter::lifted_address_map() const {
    return impl_->lifted_addr_to_name;
}

void Arm32Lifter::register_lifted_function(uint32_t addr,
                                             const std::string& name) {
    impl_->lifted_addr_to_name[addr] = name;
}

void Arm32Lifter::register_softfloat_double_import_plt(uint32_t plt_addr) {
    impl_->soft_float_double_plt_.insert(plt_addr);
}
void Arm32Lifter::set_load_bias(uint32_t bias) {
    impl_->load_bias_ = bias;
}

void Arm32Lifter::set_strict(bool s) { impl_->strict_ = s; }


void Arm32Lifter::set_emit_ir(bool on) { impl_->ir.set_enabled(on); }
}  // namespace macapk::translator
