// arm32rc_driver.h -- the piece that turns the arm32rc translation
// LIBRARY into a working output stage.
//
// The four arm32rc components each solve one problem and were each
// verified on their own:
//
//   a64_emit    encode one arm64 instruction
//   xlat_core   translate one integer/control-flow ARM32 instruction
//   xlat_mem    ... one load/store        } given an A64Buf
//   xlat_simd   ... one VFP/NEON op       }
//   macho_link  turn sections + symbols + fixups into a .dylib
//
// Nothing joined them up. This file is that join: it walks the function
// set the existing discovery pipeline found, drives each function's
// instruction stream through the three translators into one A64Buf,
// wraps it in the host-ABI prologue/epilogue, resolves intra-function
// branches to labels and inter-function ones to linker fixups, emits the
// module constructor by hand, and links the result.
//
// It is deliberately a DROP-IN for the LLVM path's output contract, not
// a new one: same `__macapk_synth_<8hex>` symbol names, same
// `__macapk_register_segment` / `__macapk_register_function` /
// `.init_array`-via-`__macapk_invoke_safe` constructor, same 5-argument
// `(r0,r1,r2,r3,sp) -> r0` function signature. That is what makes the
// two paths A/B-comparable per function, which is the only honest way to
// retire the incumbent (codegen bugs are silent and data-dependent, so
// "it still boots" is not evidence).
//
// TWO THINGS THIS DRIVER DOES THAT ARE NOT "TRANSLATE THE BYTES":
//
//  1. DISPOSITION. The input is a `DiscoveredFunction` vector, not a
//     bare address list, because "discovery found a function here" and
//     "translate the guest bytes here" are DIFFERENT statements. For 91
//     addresses in HCR 1.8.1 the incumbent substitutes a host body
//     instead of lifting, and a consumer that cannot see that runs the
//     guest's own `__cxa_throw` (SIGABRT or infinite self-recursion)
//     and the guest's `__cxa_guard_acquire` (never fires
//     `pthread_mutex_lock`, so every cocos singleton vptr stays
//     unwritten). The guest's `__dynamic_cast` used to be listed here as
//     "returns garbage non-NULL, so cocos2d-x skips `onEnter`"; that was
//     the deleted LLVM lifter's miscompile, not this driver's. Measured
//     2026-09-26, this driver's translation of it matches the guest bytes
//     on an ARMv7 CPU exactly, so it is now translated by default
//     (main.cpp arm32_guest_dynamic_cast_on,
//     MACAPK_ARM32_GUEST_DYNAMIC_CAST=0 restores the host walker).
//     410 call sites in HCR, 155 in JJ, 0 in Flappy (the original
//     census, dynamic_cast included), which is exactly why Flappy never
//     exposed it. See
//     macapk/arm32_discovery.h for the contract and the census.
//
//  2. JNI ENTRY THUNKS. A guest `Java_*` body speaks the lifted ABI
//     (five i32s, guest SP in the 5th). HotSpot calls it with AAPCS64:
//     a 64-bit `JNIEnv*` in x0, 64-bit `jobject`s after it, and
//     whatever the JVM felt like in x4 -- which the guest prologue
//     would read as its stack pointer. So the recompiled body is
//     exported as `__macapk_arm32_<name>` and an AAPCS64 thunk is
//     exported under `<name>`; that thunk is what dlsym and the JVM
//     bind to. This mirrors main.cpp:5288-5421 instruction for
//     instruction. HCR has 21 such entry points.
//
// C++17. No em dashes (project convention).

#ifndef MACAPK_RUNTIME_TRANSLATOR_ARM32RC_DRIVER_H_
#define MACAPK_RUNTIME_TRANSLATOR_ARM32RC_DRIVER_H_

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "macapk/arm32_discovery.h"
#include "macapk/elf_reader.h"

namespace macapk::translator::arm32rc {

// The input is `std::vector<DiscoveredFunction>` (macapk/arm32_discovery.h).
// There is deliberately no local function-descriptor struct here: one
// existed until the contract landed, it carried only "there is a
// function at this address", and that missing bit is precisely what let
// the recompiler translate guest bodies the incumbent replaces.

struct RcOptions {
    uint32_t    load_bias = 0;
    std::string shim_dir;       // for LC_RPATH + the export-trie read
    std::string shim_path;      // on-disk libmacapk-bionic-shim.dylib
    bool        verbose = false;

    // Resolve an import's ELF name to the host symbol a call should bind
    // to, or "" for "nothing can answer this; route it to the panic stub".
    //
    // This is a CALLBACK rather than a rule reimplemented here because
    // the decision is genuinely non-trivial (kPointerAwareImports and the
    // soft-float sets in main.cpp) and the two output paths MUST agree:
    // binding `__stack_chk_fail` to `__macapk_shim___stack_chk_fail`,
    // which the shim does not export, is a hard dlopen failure rather
    // than a runtime one, because macho_link uses non-lazy binding only.
    // Duplicating the list here would be a silent-drift hazard.
    std::function<std::string(const std::string&)> resolve_import;

    // "Is this PLT vaddr one of kSoftFloatDoubleImports?" Those shims
    // return the double packed as an int64 and AAPCS32 wants it in r0:r1,
    // so the call site has to split it. main.cpp owns the set.
    std::function<bool(uint32_t)> is_softfloat_double_plt;

    // MACAPK_ARM32RC_POOL_RESYNC: "does main.cpp's literal-pool BYTE SCAN mark
    // this guest vaddr?" That scan is a blind heuristic (any Thumb halfword
    // matching the LDR-literal encoding 0x48xx-0x4fxx marks 4 bytes), not a
    // proof -- it also fires on the second halfword of an ordinary 32-bit
    // Thumb-2 instruction. The resync code must therefore also gate on the
    // BRANCH SOURCE (is the branch instruction itself inside a marked byte,
    // or lld's 0xd4d4 trap fill?), never on the covering instruction alone;
    // see arm32rc_driver.cpp's todo-loop comment for the two confirmed
    // miscompiles this caused when that second check was missing. Empty =
    // no resync, exactly the pre-gate decode.
    std::function<bool(uint32_t)> is_literal_pool_byte;
    // Fail the build if any function fails to translate. Off by default:
    // bring-up wants the coverage report, not a wall.
    bool        strict = false;

    // Cross-guest-library linking (2026-07-28). Absolute on-disk paths of
    // sibling guest dylibs (translated from OTHER .so files in this same
    // app) that main.cpp's ELF-based sibling scan determined actually
    // provide one or more of this module's otherwise-unresolvable
    // imports -- e.g. a Firebase plugin .so genuinely calling into a
    // sibling libFirebaseCppApp.so. Forwarded verbatim to
    // MachOLinker::add_dependency() so dyld loads (and fully constructs)
    // each one before processing this module's own binds, independent of
    // what order the Java loader dlopens things in. See
    // docs/cross-guest-library-linking_2026-07-28.md. Empty for the
    // common case (no cross-.so calls detected).
    std::vector<std::string> extra_dylib_deps;

    // ---- ARM32 data-import runtime link (MACAPK_ARM32_DATA_IMPORT_LINK) ----
    // When set, build_module emits the image's link descriptor (its PT_DYNAMIC
    // vaddr, basename and every Elf32Image::data_imports site) as a __const
    // blob, one `b <host>` thunk per FUNC data import that we deliberately
    // provide as an Android system-library function, and a call to
    // `__macapk_arm32_link_image(desc, size, B)` in the module constructor
    // after the LUT registrations and before .init_array. When clear, NONE of
    // that is emitted and not one output byte changes (not even an undefined
    // symbol: symbol-table order is output bytes).
    // docs/arm32-data-import-resolution-design_2026-09-27.md.
    bool        data_import_link = false;
    std::string image_basename;   // "libfoo.so": the registry's second key

    // Which tier resolve_import would answer an import from, without its
    // side effects (no WARN line, no panic-import count). Only the Shim and
    // RuntimeNs tiers earn a host-function fallback thunk for a data import:
    // those are the names we deliberately provide as Android system-library
    // functions. HostDlsym is the wrong-ABI class
    // (docs/arm32-wrong-abi-bare-resolve_2026-07-28.md), and Bionic's system
    // libraries may not define such a name at all.
    enum class ImportTier { Shim, RuntimeNs, HostDlsym, Sibling, None };
    std::function<ImportTier(const std::string&, std::string* host)> import_tier;

    // MACAPK_ARM32_CXXABI_SIBLING_FIRST: PLT imports that must bind TWO-LEVEL
    // to one specific sibling dylib instead of by flat lookup, as
    // (import name -> sibling dylib install path). main.cpp fills it for C++
    // runtime ABI names that no Android system library defines, that the
    // importer's DT_NEEDED BFS closure finds in a sibling first, and that flat
    // lookup would otherwise hand to the HOST's libc++abi (a 64-bit ABI fed
    // 32-bit guest pointers). The dylib path is also in extra_dylib_deps.
    std::map<std::string, std::string> two_level_imports;

    // ---- MACAPK_ARM32_EXPORT_ALIASES (2026-09-27, default ON) ----------
    // Every defined GLOBAL/WEAK STT_FUNC name of the image's .dynsym, keyed by
    // its entry (st_value with the Thumb bit cleared). Bionic resolves an
    // import by NAME through the provider's dynsym hash and binds it to that
    // entry's st_value + load_bias (linker_soinfo.cpp gnu_lookup / elf_lookup,
    // linker_soinfo.h resolve_symbol_address), so two names sharing one
    // st_value are two ordinary exports of one address: a C1/C2 or D1/D2
    // constructor pair, identical-code-folded twins, a WEAK spelling of a
    // GLOBAL. Discovery keys one NAME per address (lifted_address_map is
    // last-wins in symbol order), so build_module used to export exactly one
    // of them and every import of another failed its flat bind at dlopen.
    // build_module exports each name whose entry is a translated FUNCTION
    // START as an alias of that body (a JNI-shaped name gets its own AAPCS64
    // thunk onto the same body). Empty (the gate off) = not one output byte
    // changes. docs/arm32rc-alias-exports_2026-09-27.md.
    struct AliasExport {
        uint32_t    vaddr = 0;       // entry, bit 0 clear
        std::string name;
        bool        is_jni = false;  // Java_* / JNI_OnLoad: needs a JNI thunk
    };
    std::vector<AliasExport> alias_exports;
};

// Everything the caller wants to know afterwards. Coverage is the whole
// point during bring-up: "how much of the fleet can this path actually
// express yet" is the question that decides when the incumbent can go.
struct RcStats {
    size_t functions_in = 0;
    size_t functions_ok = 0;        // fully translated
    size_t functions_partial = 0;   // emitted, but >= 1 instruction stubbed
    size_t functions_failed = 0;    // not emitted at all

    // Dispositions honoured (these are NOT translated, so they are not
    // counted in functions_ok / _partial). Printing them is the cheapest
    // guard against the failure this whole contract exists to prevent:
    // a zero here on HCR means the driver is running guest bodies the
    // incumbent replaces, and every A/B against it is comparing two
    // different programs.
    size_t functions_override_shim = 0;
    size_t functions_override_const = 0;
    size_t functions_veneer = 0;
    size_t jni_thunks = 0;          // AAPCS64 entry thunks emitted

    size_t insns_total = 0;
    size_t insns_core = 0;
    size_t insns_mem = 0;
    size_t insns_simd = 0;
    size_t insns_stubbed = 0;       // no translator claimed it
    size_t insns_skipdata = 0;      // capstone SKIPDATA pseudo-instruction
    size_t pool_resync_targets = 0; // MACAPK_ARM32RC_POOL_RESYNC re-decodes

    size_t extern_call_sites = 0;
    size_t extern_targets_resolved = 0;   // to a function in this module
    size_t extern_targets_stubbed = 0;    // to a panic stub
    // `mov lr, pc` + a PC write is an indirect CALL, not a tail jump. Counted
    // because the two are indistinguishable in a render verdict: getting it
    // wrong makes the CALLER return early and silently discards the callee's
    // result. Overwhelmingly an armeabi/ARMv4T-era idiom (Jetpack Joyride:
    // 1075 sites vs 2 `blx <reg>`).
    size_t pc_write_calls = 0;
    size_t plt_thunks = 0;                // import PLT trampolines in the LUT

    // Mnemonic -> count, for the instructions nothing handled. This is
    // the work list; sorted descending it says exactly what to build
    // next, which beats guessing.
    std::map<std::string, size_t> stub_histogram;

    uint64_t text_bytes = 0;
    uint64_t file_bytes = 0;
    // Unused tail of the last veneer pool cut off __text
    // (MACAPK_ARM32RC_TRIM_VENEER_TAIL; LinkResult::veneer_tail_trimmed).
    uint64_t veneer_tail_trimmed = 0;
    std::vector<std::string> flat_symbols;   // see LinkResult::flat_symbols

    // MACAPK_ARM32_EXPORT_ALIASES (RcOptions::alias_exports). All zero when
    // the list is empty.
    size_t alias_candidates = 0;     // names handed in
    size_t alias_exported = 0;       // defined at their function's body
    size_t alias_jni_thunks = 0;     // JNI-shaped aliases given their own thunk
    size_t alias_already = 0;        // the name IS the body's own export
    size_t alias_taken = 0;          // name already in the symbol table: skipped
    size_t alias_no_entry = 0;       // entry is not a translated function start
    std::vector<std::string> alias_no_entry_names;   // first few, for the log
};

// Translate + link. Returns false and fills *error on a hard failure.
bool build_module(const Elf32Image& img,
                  const std::vector<DiscoveredFunction>& funcs,
                  const RcOptions& opts,
                  const std::string& out_path,
                  RcStats* stats,
                  std::string* error);

// Render `stats` as the human-readable coverage report the bring-up
// loop reads. Kept here so both the translator CLI and the differential
// harness print the same thing.
std::string format_stats(const RcStats& s, size_t top_n = 25);

}  // namespace macapk::translator::arm32rc

#endif  // MACAPK_RUNTIME_TRANSLATOR_ARM32RC_DRIVER_H_
