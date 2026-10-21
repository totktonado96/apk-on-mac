// macho_link.h -- the OUTPUT STAGE of the ARM32 direct recompiler.
//
// Replaces `llvm-as -> opt -> llc -> ld64.lld` with an in-process
// Mach-O linker: the recompiler (arm32rc/a64_emit.h, regmap.h,
// xlat_core.h, xlat_mem.h, xlat_simd.h) hands us finished arm64
// machine code plus a symbol table plus a fixup list, and we produce a
// signed, loadable arm64 MH_DYLIB. No external toolchain, no temporary
// .ll / .bc / .o files.
//
// LINEAGE. runtime/translator/src/arm64_macho_emit.cpp already
// hand-builds a valid classic-format MH_DYLIB (LC_DYLD_INFO_ONLY
// rebase/bind/export-trie + __mod_init_func) and is proven in
// production on the Stage-6 arm64 path. Its machinery -- the ULEB
// writer, the export-trie builder, the segment/section layout walk,
// the codesign step -- is reused here (copied rather than shared: that
// file's helpers live in an anonymous namespace and it is owned by the
// Stage-6 path, which must not be destabilised by this work). What
// arm64_macho_emit.cpp does NOT do, and what this file adds, is real
// LINKING:
//
//   * veneer synthesis -- a BL that cannot reach its target (an
//                         undefined external, or a defined symbol
//                         beyond +/-128 MiB) needs a small in-image
//                         trampoline; see "BRANCH ISLANDS / VENEER
//                         POOLS" below
//   * GOT synthesis    -- a __DATA,__got slot for dyld to bind
//   * indirect symtab  -- the S_NON_LAZY_SYMBOL_POINTERS contract that
//                         makes otool/dyld agree on which GOT slot
//                         belongs to which symbol
//   * ordinal binding  -- two-level for symbols the bionic shim
//                         actually exports, flat lookup otherwise
//
// SCALE (measured 2026-07-25 on the incumbent lld output for the
// small/medium fleet; the veneer-pool redesign below exists because of
// a 2026-07-28 measurement far outside this table -- see that section):
//
//   app     __text     exports  undefs  veneers  got  indirect syms
//   flappy    16 KiB       102      21     20    1             21
//   HCR     5.69 MiB    14,967     249    248    1            249
//
//   HCR's 249 undefineds resolve, under lld, as: 219 -> the bionic
//   shim, 25 -> libSystem, 5 -> dynamic lookup.
//
// WHAT WE DO DIFFERENTLY FROM ld64.lld, AND WHY (each is a deliberate,
// measured deviation, not an accident):
//
//  1. NON-LAZY BINDING ONLY. lld emits __la_symbol_ptr + __stub_helper
//     + a lazy-bind opcode stream + a dyld_stub_binder import, so the
//     first call to each import traps into dyld. We bind every import
//     eagerly through __DATA,__got instead. The veneer shape is
//     unchanged (adrp x16 / ldr x16 / br x16 -- byte-identical in form
//     to lld's stubs, just pointing at __got rather than
//     __la_symbol_ptr), so callers cannot tell. This deletes
//     __stub_helper, the lazy opcode stream, and the dyld_stub_binder
//     dependency outright. Cost: a handful of extra binds at dlopen,
//     which is noise next to the translation it replaces. Modern
//     toolchains dropped lazy binding for the same reason.
//
//  2. TWO-LEVEL FOR THE SHIM, FLAT FOR EVERYTHING ELSE. lld resolves
//     each undefined against the dylibs on its command line and falls
//     back to DYNAMIC_LOOKUP_ORDINAL under `-undefined dynamic_lookup`.
//     We read the shim's export trie ourselves and bind hits to
//     ordinal 1; everything else gets BIND_SPECIAL_DYLIB_FLAT_LOOKUP.
//     Verified equivalent on HCR: every one of the 25 names lld bound
//     to libSystem (_btowc, _clock, _getopt, _wmemset, ...) is absent
//     from the shim's 1,476 exports, so flat lookup finds the same
//     libSystem definition lld picked. The deviation is strictly more
//     permissive, never less. It also gives us a free diagnostic --
//     see LinkResult::flat_symbols, which is the "missing shims are
//     silent killers" list, surfaced at link time instead of as a
//     panic stub at run time.
//
//  3. NO __unwind_info / __eh_frame. Lifted ARM32 code does not throw
//     through host frames; the incumbent's tables come from clang's
//     codegen, not from anything the guest needs. Omitted until an app
//     proves otherwise (it would surface as a crash inside
//     _Unwind_RaiseException, not as silent corruption).
//
//  4. NO DEDICATED __stubs SECTION. Every undefined-external veneer
//     lives in a "veneer pool" (see below), which is ordinary __text
//     content, not a S_SYMBOL_STUBS section. dyld's LAZY-binding
//     machinery is what actually needs S_SYMBOL_STUBS (reserved1 keys
//     the indirect symbol table dyld_stub_binder consults on the first
//     call through a stub); since deviation 1 already means every GOT
//     slot is bound eagerly before any guest code runs, nothing at
//     load time or run time ever needs to find these bytes via
//     reserved1/reserved2. otool shows them as anonymous __text rather
//     than "stub for _foo", which costs a little tooling
//     introspection and buys the ability to place as many of them as
//     needed, anywhere in a multi-hundred-MiB image (see below).
//     Islands (a branch to a defined but far-away symbol) were never a
//     distinct Mach-O section either -- the two are now one mechanism,
//     differing only in the veneer's second instruction: ADD-immediate
//     for a direct target, GOT-relative LDR for an undefined external.
//
// -------------------------------------------------------------------
// BRANCH ISLANDS / VENEER POOLS (redesigned 2026-07-28; see
// docs/arm32rc-branch-islands_2026-07-28.md for the fleet measurement
// that found this and the full design rationale).
//
// THE BUG THIS REPLACES. B/BL (Fix::Branch26) encodes a 26-bit
// word-aligned PC-relative displacement (ARM ARM DDI 0487 C6.2.26 /
// C6.2.33): +/-128 MiB, full stop, no exceptions. The ORIGINAL design
// appended every needed island/stub ONCE, in a single block glued to
// the end of the raw code bytes. That is fine as long as __text is
// comfortably under 128 MiB, which was true of every app this
// recompiler had translated before (HCR 5.69 MiB, Jetpack Joyride the
// previous high-water mark at 21 MiB) -- until a 2026-07-28 fleet
// sweep hit two independent Unity/il2cpp titles (Subway Surfers, Dumb
// Ways to Die) whose libunity.so / libil2cpp.so recompile to 240-380
// MiB of arm64 __text apiece. A call site near the FRONT of a 340 MiB
// module reaching for a helper via a stub/island glued to the very END
// is asking for a branch several hundred MiB long; no single
// end-of-text block can ever be in range of it (and the mirror case, a
// call near the end reaching for a helper near the front, has the same
// problem). Production linkers (ld64 itself, LLVM's
// AArch64BranchRelaxation) solve this by distributing stub/veneer
// islands AT INTERVALS through a large section -- "stub group size" in
// ld64's own terminology -- so every call site has one within reach.
// That is what this file now does.
//
// THE KEY SIMPLIFICATION THAT MAKES THIS TRACTABLE. Once a caller has
// reached ANY veneer via a Branch26, the veneer's OWN second hop
// (loading the true target, whether a direct address or a GOT
// pointer) is an ADRP-based sequence, and ADRP's page-relative
// immediate is 21 bits of signed PAGE delta (ARM ARM C6.2.11): a
// +/-4 GiB reach. Every fleet binary (past, present, and any we can
// foresee) fits its whole __TEXT+__DATA well inside that 4 GiB window,
// so a veneer standing ANYWHERE in the image can reach ANY target OR
// the GOT directly, with NO further Branch26 hop and therefore no
// chaining needed. The only range-limited leg of the whole path is the
// first one: call site -> nearest veneer. This also matches Arm's own
// characterisation of x16/x17: the Procedure Call Standard for the Arm
// 64-bit Architecture (AAPCS64), section 6.1.1 / table 2, names them
// "intra-procedure-call temporary registers" that "can be used by call
// veneers and PLT code" -- the ABI's own model for a veneer is exactly
// this one-hop trampoline, never a chain. See regmap.h, which reserves
// x16/x17 for precisely this and static_asserts no guest register ever
// lands on them.
//
// THE MECHANISM: veneer pools. reserve_veneer_pool() appends a
// fixed-capacity, zero-filled block directly into __text via the same
// append-only path as ordinary code, so it can NEVER perturb an offset
// any earlier add_text() call already handed back -- there is no
// retroactive insertion, no remapping pass, no risk of silently
// shifting a symbol or fixup already recorded relative to Sec::Text.
// The producer (arm32rc_driver.cpp) calls this periodically while it
// walks the function list -- roughly every
// kVeneerPoolRecommendedIntervalBytes -- which naturally lands each
// reservation on a real function boundary (the call always happens
// right after the driver finishes one DiscoveredFunction and before it
// starts the next), so a pool can never split a function's own control
// flow. assign_veneers() then routes every Branch26 fixup that cannot
// reach its target directly to the NEAREST pool within +/-128 MiB that
// still has room, sharing one veneer per (pool, symbol) pair so a hot
// helper referenced from all over a 340 MiB module costs one slot per
// pool that actually has a nearby caller, not one slot per call site.
// If the producer never reserves a pool at all (every existing caller,
// and every module comfortably under the range limit), write()
// auto-reserves exactly one at the current tail before layout() runs --
// byte-for-byte the old single-shared-region behavior, so this
// redesign is a strict superset, never a parallel path.
//
// Because pools are fully sized and placed BEFORE layout() ever runs
// (the producer has finished emitting text by the time write() is
// called), there is no more chicken-and-egg between "how big is
// __text" and "how many islands does it need" -- the old 8-round
// fixed-point loop is gone; layout() -> assign_veneers() -> patch() is
// a straight line.
//
// -------------------------------------------------------------------
// SOURCES. Every Mach-O constant and opcode semantic below is taken
// from a header or from dyld's own parser, never from memory:
//   * <mach-o/loader.h> / <mach-o/nlist.h> (MacOSX.sdk) -- section
//     types, the indirect-symbol-table contract quoted at
//     stub_indirect_index(), DYNAMIC_LOOKUP_ORDINAL, the bind opcodes.
//   * dyld, src/ImageLoaderMachOCompressed.cpp, eachBind() -- the
//     BIND_OPCODE_SET_DYLIB_SPECIAL_IMM sign extension quoted at
//     emit_bind_ordinal(), and the fact that
//     BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB's operand is relative to
//     the segment's load address.
//     https://github.com/Apple-FOSS-Mirror/dyld/blob/master/src/ImageLoaderMachOCompressed.cpp
//   * ARM ARM (DDI 0487) C6.2 -- the instruction encodings patched by
//     each Fix kind, quoted at each patcher; C6.2.26/C6.2.33 (B/BL,
//     +/-128 MiB) and C6.2.11 (ADRP, +/-4 GiB) are what the veneer-pool
//     design above rests on.
//   * Arm, "Procedure Call Standard for the Arm 64-bit Architecture"
//     (AAPCS64), section 6.1.1 / table 2 -- x16 (IP0) and x17 (IP1) as
//     the intra-procedure-call temporary registers a veneer may use.
//
// -------------------------------------------------------------------
// ASSUMPTIONS ABOUT THE PRODUCER (P1-P5). This interface is written
// against the contract the producer needs to meet, and every
// assumption is checkable rather than implicit:
//
//   P1. The recompiler emits POSITION-INDEPENDENT arm64 with all
//       intra-function control flow already resolved (a branch inside
//       one function body never reaches the linker; see a64_emit.h's
//       own Fixup/resolve(), which operates at single-function scope
//       and therefore never approaches the range this file cares
//       about). Only cross-function and external references become
//       Fixups here.
//   P2. Every guest function that can be called by address is declared
//       via define(), so guest-vaddr -> host-address resolution stays
//       a symbol lookup rather than an offset guess.
//   P3. Guest data (literal pools, jump tables) goes in Sec::Const;
//       mutable runtime state in Sec::Data / Sec::Bss. The linker does
//       not inspect their contents, only the fixups pointed at them.
//   P4. The module initialiser (segment install + function-LUT
//       registration, i.e. what the LLVM path emits into
//       llvm.global_ctors) is registered with add_initializer().
//   P5. For a module whose translated code may approach the +/-128 MiB
//       B/BL range (in practice: Unity/il2cpp-scale libraries), the
//       producer periodically calls reserve_veneer_pool() so every
//       call site ends up with a reachable pool -- see
//       kVeneerPoolRecommendedIntervalBytes. A producer that never
//       calls it at all gets the auto-reserved single tail pool
//       instead, identical to every module built before this existed.
//
// This header is C++17 and has no LLVM dependency by design.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace macapk::translator::arm32rc {

// Which output section a byte offset refers to.
enum class Sec : uint8_t {
    Text,    // __TEXT,__text   -- recompiled code (r-x)
    Const,   // __TEXT,__const  -- literal pools, jump tables (r-x seg, ro)
    Data,    // __DATA,__data   -- initialised mutable data (rw-)
    Bss,     // __DATA,__bss    -- zero-filled, no file bytes (rw-)
};

// A relocation the linker resolves once addresses are known.
enum class Fix : uint8_t {
    // B / BL, imm26 (ARM ARM C6.2.26 / C6.2.33). Range +/-128 MiB.
    // To an undefined symbol this ALWAYS routes through a veneer (its
    // real address is not known until dyld binds it); to a defined
    // symbol it branches direct, or through a veneer if the
    // displacement does not fit. See "BRANCH ISLANDS / VENEER POOLS"
    // above.
    Branch26,
    // ADRP, immhi:immlo (C6.2.11): (page(target) - page(pc)) >> 12.
    Adrp21,
    // ADD (immediate), imm12 with shift 0 (C6.2.5): target & 0xfff.
    AddLo12,
    // LDR/STR (immediate, unsigned offset), imm12 (C6.2.132): the
    // encoded field is (target & 0xfff) / scale, so `scale` MUST match
    // the access size of the instruction being patched (8 for an X-reg
    // load, 4 for W, 16 for Q). A mismatch silently mis-addresses.
    LdrLo12,
    // ADRP naming the page of the symbol's GOT slot (allocating one if
    // needed). The pair for an address-of-import.
    GotAdrp21,
    // LDR from that GOT slot; always scale 8.
    GotLdrLo12,
    // An 8-byte absolute pointer in Data. Internal targets become a
    // rebase; external ones become a bind.
    Ptr64,
    // A 4-byte signed (target - address_of_this_word) delta. What a
    // compact jump table wants.
    Delta32,
};

inline constexpr uint32_t kNoSym = 0xffffffffu;

// A fixup target: either a symbol, or a raw location in this image.
struct Ref {
    uint32_t sym = kNoSym;
    Sec      sec = Sec::Text;
    uint64_t off = 0;

    static Ref symbol(uint32_t s) { Ref r; r.sym = s; return r; }
    static Ref local(Sec s, uint64_t o) { Ref r; r.sec = s; r.off = o; return r; }
    bool is_symbol() const { return sym != kNoSym; }
};

struct Fixup {
    Fix      kind = Fix::Branch26;
    Sec      sec  = Sec::Text;   // section holding the word to patch
    uint64_t off  = 0;           // byte offset of that word within `sec`
    Ref      target;
    int64_t  addend = 0;
    uint32_t scale  = 1;         // LdrLo12 only; see the enum comment
};

// Advisory constants for a producer emitting a module that may approach
// the +/-128 MiB B/BL range (P5 above). Neither is enforced by the
// linker: a producer that never calls reserve_veneer_pool() still
// gets a single auto-reserved pool at the tail, and a producer that
// calls it with a different capacity is free to. They are exposed
// here (rather than left as a private constant in macho_link.cpp) so
// the producer and the linker never have to agree on the number by
// two separately-maintained copies of it.
//
// kVeneerPoolRecommendedIntervalBytes: called roughly this often, a
// producer guarantees every call site is within kBranchMax of at
// least one pool with generous headroom (worst case, exactly midway
// between two pools, is half this value -- about 8x under the
// +/-128 MiB limit at the default).
inline constexpr uint64_t kVeneerPoolRecommendedIntervalBytes = 32ull * 1024 * 1024;
// kVeneerPoolCapacityBytes: default capacity of one reserve_veneer_pool()
// call, in bytes (must be a multiple of 12, one veneer's size).
//
// MEASURED, not guessed: an initial estimate of 16 KiB (1365 slots) --
// reasoned only from HCR's 249 distinct undefined externals in a
// 5.69 MiB image -- was tried against Subway Surfers' libunity.so
// (~340 MiB __text) on 2026-07-28 and undershot badly. The dominant
// cost is NOT undefined externals (that vocabulary really is small and
// roughly constant regardless of module size); it is the DEFINED-but-
// far case: arm32rc_driver.cpp mints one small panic trampoline
// (Sec::Text, ~8 bytes) per DISTINCT unresolved-indirect-call target
// address, and all of them are clustered together in one place (its
// own "phase 2", emitted once, after every real function). A caller
// anywhere in "phase 1" (the bulk of a large module) is typically
// hundreds of MiB from that cluster, so nearly every reference to one
// of these trampolines needs a veneer -- and a sufficiently large
// il2cpp module can mint tens of thousands of distinct ones. 1 MiB
// (87,381 slots) is sized against that failure directly (confirmed:
// this capacity links Subway's libunity.so end to end), with several
// times the headroom the first, HCR-only-informed guess had. On a
// 340 MiB module with pools every kVeneerPoolRecommendedIntervalBytes,
// this is roughly 3% file-size overhead -- cheap next to "does not
// link at all". assign_veneers()'s hard-error path (never a silent
// overflow) is what makes it safe to ship a reasoned-not-measured
// default at all: a module that still exceeds this fails LOUDLY,
// naming the exact symbol and offset, rather than corrupting output.
inline constexpr uint64_t kVeneerPoolCapacityBytes = 1024ull * 1024;

struct LinkOptions {
    // LC_ID_DYLIB. The incumbent passes the absolute output path, so a
    // dlopen by that path matches the install name.
    std::string install_name;
    // LC_LOAD_DYLIB #1 -- the import source for two-level binds.
    std::string shim_install_name = "@rpath/libmacapk-bionic-shim.dylib";
    // On-disk path to that dylib. Its export trie decides ordinal 1 vs
    // flat lookup (see deviation 2 above). If empty or unreadable,
    // EVERY undefined falls back to flat lookup -- still correct, just
    // less faithful to lld, and flagged in LinkResult::shim_trie_read.
    std::string shim_path;
    // Added as LC_RPATH so dyld can find the shim.
    std::string shim_dir;
    bool adhoc_sign = true;      // codesign -f -s - (ships with macOS)
    bool verbose    = false;
};

struct LinkResult {
    bool     ok = false;
    std::string error;

    size_t   exports   = 0;   // exported defined symbols
    size_t   locals    = 0;   // non-exported defined symbols
    size_t   undefs    = 0;   // distinct undefined externals
    // Additional LC_LOAD_DYLIB dependencies registered via
    // add_dependency() (cross-guest-library linking -- see
    // docs/cross-guest-library-linking_2026-07-28.md). Symbols provided by
    // these still bind through the ordinary flat-lookup path below; this
    // count is purely diagnostic (did the producer's sibling scan find
    // anything to add).
    size_t   extra_deps = 0;
    // GOT-relative veneer entries synthesised (one per (pool, undefined
    // symbol) pair actually needed), summed across every veneer pool.
    // Before the 2026-07-28 redesign this counted a single __TEXT,
    // __stubs section's entries; the field name stayed so no caller
    // needs to change, only what it counts.
    size_t   stubs     = 0;
    size_t   got_slots = 0;   // __DATA,__got entries
    size_t   indirect  = 0;   // indirect symbol table entries (__got only)
    // Direct-address veneer entries synthesised (one per (pool, defined
    // out-of-range symbol) pair actually needed), summed across every
    // veneer pool. Same pre-2026-07-28 field-name note as `stubs`.
    size_t   islands   = 0;
    size_t   veneer_pools = 0;   // how many pools write() ended up with
    size_t   binds_two_level = 0;
    size_t   binds_flat      = 0;
    size_t   rebases   = 0;
    uint64_t text_bytes = 0;
    uint64_t file_bytes = 0;
    // Bytes of never-used veneer capacity cut off the end of __text by
    // MACAPK_ARM32RC_TRIM_VENEER_TAIL (see write()). 0 when the gate is
    // off, when the last pool is not the tail of __text, or when the
    // re-derived layout could not reproduce the veneer assignment and the
    // trim was rolled back.
    uint64_t veneer_tail_trimmed = 0;
    bool     shim_trie_read = false;

    // Undefineds that fell through to flat lookup, i.e. names the
    // bionic shim does NOT export. On a healthy build this is the
    // libSystem set; anything __macapk_shim_*-shaped in here is a
    // MISSING SHIM and will trap at run time, so the caller should log
    // it (see CLAUDE.md, "Missing shims are silent killers").
    std::vector<std::string> flat_symbols;
};

// ---------------------------------------------------------------------
// The linker. Build content, declare symbols, record fixups, write.
// Not thread-safe; one instance per output dylib.
// ---------------------------------------------------------------------
class MachOLinker {
public:
    explicit MachOLinker(LinkOptions opts);
    ~MachOLinker();
    MachOLinker(const MachOLinker&) = delete;
    MachOLinker& operator=(const MachOLinker&) = delete;

    // -- content. Each returns the byte offset of the appended blob
    //    within its section. `align` is applied before appending.
    uint64_t add_text (const void* p, size_t n, size_t align = 4);
    uint64_t add_const(const void* p, size_t n, size_t align = 8);
    uint64_t add_data (const void* p, size_t n, size_t align = 8);
    uint64_t add_bss  (size_t n, size_t align = 8);

    // Reserve a fixed-capacity, zero-filled veneer pool at the CURRENT
    // end of __text (P5 above). Returns the pool's byte offset within
    // Sec::Text. Because this is a plain append -- exactly like
    // add_text() -- it can never invalidate an offset any earlier
    // add_text()/define()/add_fixup() call already handed back. Safe
    // to call between any two functions the producer emits; unsafe
    // (undefined layout) to call in the middle of one, since a
    // reservation the linker later fills with veneer code must never
    // land somewhere a guest function might fall through into.
    uint64_t reserve_veneer_pool(uint64_t capacity_bytes = kVeneerPoolCapacityBytes);

    // Current size of Sec::Text, including every veneer pool reserved
    // so far. A producer emitting a module that may need periodic
    // reserve_veneer_pool() calls (P5) should drive the cadence off
    // this rather than tracking its own running total by hand -- it
    // is queried fresh, so it can never drift from what add_text()
    // and reserve_veneer_pool() actually did across several call sites.
    uint64_t text_size_hint() const;

    // Mutable view of already-appended bytes, for a producer that
    // patches its own code before linking. Valid until the next add_*
    // on the same section. Returns nullptr if [off, off+n) is out of
    // range.
    uint8_t* mutable_bytes(Sec sec, uint64_t off, size_t n);

    // -- symbols.
    // A defined symbol at (sec, off). `exported` puts it in the export
    // trie and marks it N_EXT, which is what makes dlsym find it; a
    // non-exported define is still usable as a fixup target but stays
    // private to the image.
    uint32_t define(std::string name, Sec sec, uint64_t off, bool exported);
    // An undefined external, deduped by name. Names are given WITHOUT
    // the Mach-O leading underscore (pass "malloc", not "_malloc") --
    // the linker adds it, exactly once, so a caller cannot double it.
    uint32_t undefined(const std::string& name);
    // Is `name` already in the symbol table, defined OR undefined? Lets a
    // caller add an OPTIONAL name (an ELF alias export) without upgrading a
    // pending undefined external into a local definition, which is what
    // define() does to a forward-referenced name. Pure query, no side effect.
    bool has_symbol(const std::string& name) const;

    // -- fixups.
    void add_fixup(const Fixup& f);
    // Convenience for the common shapes.
    void branch(Sec sec, uint64_t off, uint32_t sym);
    void adrp_add_pair(Sec sec, uint64_t adrp_off, uint64_t add_off, Ref target);

    // -- the module initialiser (P4). May be called more than once;
    //    they run in registration order.
    void add_initializer(Ref fn);

    // -- cross-guest-library linking (2026-07-28). Register an ADDITIONAL
    //    LC_LOAD_DYLIB naming another translated sibling dylib in this same
    //    app -- e.g. a Firebase plugin .so that genuinely calls into a
    //    sibling libFirebaseCppApp.so also being translated for this app.
    //    The sibling need not exist on disk yet: dyld resolves the path at
    //    DLOPEN time, and AppClassLoader.preloadAllApkLibs() already
    //    guarantees every sibling .so in an app is translated before any of
    //    them is handed to System.load() (see the design doc). Idempotent
    //    -- registering the same absolute path twice is a no-op.
    //
    //    This does NOT introduce a new binding mechanism: a symbol this
    //    dependency happens to provide still resolves through the ORDINARY
    //    two-level-shim-or-flat-lookup decision in resolve_ordinals()
    //    (almost always flat lookup, since a sibling's C++-mangled export
    //    is never in the bionic shim's own export trie). This call's only
    //    job is to guarantee dyld maps -- and, per its own
    //    initializer-ordering invariant, fully constructs -- the named
    //    dylib BEFORE processing this image's own binds, regardless of
    //    what order the Java loader happens to dlopen things in. See
    //    docs/cross-guest-library-linking_2026-07-28.md for the empirical
    //    verification (four dyld experiments on this host) that this is
    //    both necessary and sufficient.
    void add_dependency(std::string install_name);

    // -- MACAPK_ARM32_CXXABI_SIBLING_FIRST (2026-09-27). Bind the undefined
    //    `name` TWO-LEVEL to the add_dependency() entry `install_name`
    //    (its LC_LOAD_DYLIB ordinal: shim 1, libSystem 2, extra deps 3..),
    //    instead of the flat lookup resolve_ordinals() would choose. Needed
    //    when the host process ALSO exports the name and would win a flat
    //    lookup: `__dynamic_cast` is exported by macOS libc++abi, which
    //    macapk-runtime loads long before any guest dylib, so a flat bind
    //    of OpenTTD libapplication.so's `__dynamic_cast` reached the host's
    //    64-bit implementation with 32-bit guest pointers although its
    //    DT_NEEDED libc++_shared.so defines it (Bionic's BFS order picks the
    //    sibling). The bind is WEAK: if the sibling dylib does not export the
    //    name (its body failed to translate), dyld binds 0 and the process
    //    still loads, so the failure is a call-time fault at 0, never a
    //    dlopen failure. A no-op for a name that is never made undefined or a
    //    path that is not a registered dependency. Nothing calls this unless
    //    the gate fires, so an image without such imports is byte-identical.
    void bind_to_dependency(const std::string& name,
                            const std::string& install_name);

    // -- emit. Lays out, resolves, patches, serialises, signs.
    //
    // MACAPK_ARM32RC_TRIM_VENEER_TAIL (default ON; =0 is the exact
    // pre-2026-09-26 output). The producer ends __text with an
    // unconditional reserve_veneer_pool() (arm32rc_driver.cpp), so the
    // LAST pool is always the tail of __text, and it is sized for the
    // Unity/il2cpp worst case (kVeneerPoolCapacityBytes, 1 MiB) while a
    // typical module fills a few hundred bytes of it: Flappy's dylib was
    // 1.15 MB, 1 MiB of it zeros. Once assign_veneers() has run, the
    // pool's final fill is known, so write() cuts the unused tail off and
    // lays the image out again. Nothing after __text holds a baked
    // address: every reference into __const / __data / __bss / __got is
    // a Fixup that patch() resolves from the FINAL layout, and every
    // header / symtab / export-trie / modinit / rebase / bind value is
    // computed by emit() from that same layout. The veneer assignment is
    // re-derived against the trimmed layout and must come out identical
    // (it depends only on __text offsets, which the trim does not move);
    // if it does not, the trim is rolled back and the untrimmed image is
    // written. See docs/arm32rc-veneer-tail-trim-and-atomic-output_2026-09-26.md.
    //
    // The file itself is written through AtomicOutputFile (below).
    LinkResult write(const std::string& out_path);

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

// ---------------------------------------------------------------------
// AtomicOutputFile -- how BOTH translator outputs reach their final path
// (this arm32rc Mach-O, and the Stage-6 arm64 wrapper via arm64_pack.cpp;
// it lives here only because this is the translator's shared output
// stage).
//
// MACAPK_XLAT_ATOMIC_WRITE (default ON; =0 is the exact pre-2026-09-26
// path: std::ofstream(out, trunc) and `codesign -f` IN PLACE on the final
// path). Before this, a reader of the output path could observe, in turn,
// a truncated file, a partly written one, and a complete but UNSIGNED one
// (which dlopen refuses on Apple Silicon), and a killed translator left
// whichever of those it had reached; two translators aimed at the same
// path (two runtimes launching the same app) interleaved their writes in
// one inode. It also blocked MACAPK_CACHE_COMPRESS=all
// (docs/disk-size-efficiency_2026-09-26.md), whose background job has to
// be sure the dylib it compressed is still the one at the path.
//
// With the gate on, the producer writes and signs the file inside a
// private staging directory created NEXT TO the target
// (<dir>/.macapk-xlat.<pid>.XXXXXX/<same basename>), so:
//   * the rename that publishes it never crosses a filesystem (macOS
//     rename(2): old and new "must reside on the same file system"; "If
//     new exists, it is first removed", and "rename() ... guarantees that
//     an instance of new will always exist, even if the system should
//     crash in the middle of the operation"), so no reader ever finds the
//     path missing or half-replaced;
//   * the file keeps its basename, so everything codesign derives from
//     the name (the ad-hoc Identifier is "<basename minus extension>-
//     <LC_UUID hex>") is exactly what an in-place write produced -- the
//     output is BYTE-IDENTICAL to the in-place path;
//   * a reader sees either the previous complete, signed file or the new
//     complete, signed file, never anything in between.
// commit() fsync(2)s the staged file (plain fsync, ~1 ms measured; NOT
// F_FULLFSYNC, which measured 3-22 ms per file on this class of machine
// and buys power-loss ordering for an artifact the loader regenerates),
// then (MACAPK_XLAT_STAMP_INVALIDATE,
// default ON) unlinks the target's stale "<out>.nativeid" stamp, THEN
// renames, then fsyncs the directory. The stamp is written by the Java
// loader only after the translator returns success
// (AppClassLoader.writeNativeIdStamp), so the sequence a concurrent reader
// can observe is [old id, old dylib] -> [no id, old dylib] ->
// [no id, new dylib] -> [new id, new dylib]: no stamp ever vouches for a
// dylib it was not written for, in either direction (an OLD runtime can no
// longer accept a NEW translator's dylib under its old id, and a new id
// can never sit next to an old dylib). A missing stamp is the loader's
// safe direction: it re-translates.
//
// A staging directory left by a killed translator is reaped by the next
// AtomicOutputFile in the same directory once its pid is gone.
// A final path that is itself a symlink is written in place, as before:
// renaming over it would replace the link rather than its target.
// ---------------------------------------------------------------------
class AtomicOutputFile {
public:
    explicit AtomicOutputFile(std::string final_path);
    ~AtomicOutputFile();      // removes an uncommitted staging copy
    AtomicOutputFile(const AtomicOutputFile&) = delete;
    AtomicOutputFile& operator=(const AtomicOutputFile&) = delete;

    // Where the producer must write (and sign). The final path itself
    // when the gate is off or staging was not possible.
    const std::string& write_path() const { return write_path_; }
    bool staged() const { return staged_; }

    // Publish the staged file at the final path. A no-op success when not
    // staged. On failure the final path is untouched and *err says why.
    bool commit(std::string* err);

private:
    std::string final_path_;
    std::string write_path_;
    std::string stage_dir_;
    bool staged_ = false;
    bool committed_ = false;
};

}  // namespace macapk::translator::arm32rc
