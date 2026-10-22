// elf_reader.h -- minimal ELF32 reader for the Apk on Mac translator.
//
// Only the slice we actually need to lift an ARM32 Bionic shared
// object: the file header, program headers, dynamic table, symbol
// table, string table, .text segment bytes, and basic relocations.
// We deliberately do NOT pull in libelf or LLVM's Object library;
// the format we care about is small and stable, and a hand-written
// reader keeps the translator binary tiny and dependency-free apart
// from Capstone (the ARM disassembler).
//
// Endianness: ARM Bionic .so files are always little-endian on the
// target platforms Apk on Mac cares about. We read structs by raw memcpy
// from the mmap'd file and trust the host (Apple Silicon) is also
// little-endian.

#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unordered_set>
#include <map>
#include <vector>
#include <span>
#include <utility>

namespace macapk::translator {

// Subset of ELF32 constants we use directly in switch statements.
// Mirrors <elf.h> on Linux but doesn't pull it in (macOS doesn't ship
// an elf.h on the default include path).
constexpr uint8_t  ELFCLASS32       = 1;
constexpr uint8_t  ELFCLASS64       = 2;
constexpr uint8_t  ELFDATA2LSB      = 1;
constexpr uint16_t ET_DYN           = 3;
constexpr uint16_t EM_ARM           = 40;
constexpr uint16_t EM_AARCH64       = 183;
constexpr uint32_t PT_LOAD          = 1;
constexpr uint32_t PT_DYNAMIC       = 2;
constexpr uint32_t SHT_PROGBITS     = 1;
constexpr uint32_t SHT_SYMTAB       = 2;
constexpr uint32_t SHT_STRTAB       = 3;
constexpr uint32_t SHT_REL          = 9;
constexpr uint32_t SHT_DYNSYM       = 11;
constexpr uint32_t SHT_RELA         = 4;
constexpr uint32_t STB_GLOBAL       = 1;
constexpr uint32_t STB_WEAK         = 2;
constexpr uint32_t STT_FUNC         = 2;
constexpr uint32_t STT_OBJECT       = 1;
constexpr uint32_t SHF_EXECINSTR    = 0x4;
constexpr uint32_t PF_X             = 0x1;
// ARM32 PLT layout: PLT[0] is 20 bytes (the resolver), each subsequent
// PLT[N] for N >= 1 is 12 bytes (3 ARM32 instructions). The address of
// the Nth import's stub is PLT_BASE + 20 + (N-1)*12. Order of imports
// matches the order of entries in .rel.plt.
constexpr uint32_t ARM_PLT0_SIZE    = 20;
constexpr uint32_t ARM_PLT_ENTRY    = 12;

#pragma pack(push, 1)
struct Elf32Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf32Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Elf32Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Elf32Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};
#pragma pack(pop)

struct Symbol {
    std::string name;
    uint32_t    address;     // virtual address inside the .so
    uint32_t    size;        // bytes; 0 if unknown
    uint8_t     bind;        // STB_*
    uint8_t     type;        // STT_*
    bool        is_thumb;    // ARM Bionic encodes Thumb-ness in lsb of st_value
};

// Imported (undefined) symbol -- the .so depends on something defined
// elsewhere. The Bionic linker resolves these at runtime; for our
// translation we map each one to a real libSystem function (where ABI
// matches) or to a macapk-bionic-shim helper.
struct ImportedSymbol {
    std::string name;
    uint8_t     bind;
    uint8_t     type;
    uint32_t    plt_addr;    // PLT stub virtual address (0 if not in .rel.plt)
};

struct CodeSegment {
    uint32_t                 vaddr;     // virtual address inside the .so
    std::vector<uint8_t>     bytes;     // raw machine code from this segment
    bool                     executable;
};

// A DATA relocation (R_ARM_ABS32 / R_ARM_GLOB_DAT in .rel.dyn / .rela.dyn)
// against an UNDEFINED symbol that has no PLT stub. The translator cannot
// resolve these: the defining image is another .so (a sibling in the app, or
// an Android system library) and its address is only known at load time. They
// used to be left holding the in-place word (A, or 0), i.e. `skipped_no_plt`.
// The runtime linker (bionic_shim_arm32_link.cpp, MACAPK_ARM32_DATA_IMPORT_LINK)
// resolves them the way Bionic's linker does.
// docs/arm32-data-import-resolution-design_2026-09-27.md.
struct DataImportSite {
    uint32_t slot;          // unbiased r_offset
    // Bionic's addend for this entry (linker_relocate.cpp android14-release
    // :227-231, :326-341): REL R_ARM_ABS32 = the in-place word, REL
    // R_ARM_GLOB_DAT = 0, RELA = r_addend. Independent of
    // MACAPK_ARM32_BIONIC_DATA_RELOC, which governs DEFINED-symbol writes only.
    uint32_t addend;
    uint32_t import_index;  // into Elf32Image::imports (name, bind, type)
    uint8_t  r_type;        // 2 (R_ARM_ABS32) or 21 (R_ARM_GLOB_DAT)
};

// MACAPK_ARM32_DATA_IMPORT_LINK (translate time, default ON): emit a per-image
// link descriptor + one `__macapk_arm32_link_image` call into the arm32rc
// module constructor so the runtime resolves DataImportSites. `=0` emits
// nothing and the dylib is byte-identical to the pre-change translator. Read
// once per process; shared by elf_reader.cpp and main.cpp so both halves agree.
inline bool arm32_data_import_link_on() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_ARM32_DATA_IMPORT_LINK");
        return !(e && e[0] == '0' && e[1] == '\0');
    }();
    return on;
}

// Parsed view of an ARM32 ELF shared object. Owns the file bytes and
// the parsed metadata; cheap to move, expensive to construct.
struct Elf32Image {
    std::vector<uint8_t>          raw;          // full file contents
    Elf32Ehdr                     hdr;
    std::vector<Elf32Phdr>        phdrs;
    std::vector<Elf32Shdr>        shdrs;
    std::vector<Symbol>           symbols;       // defined symbols (st_shndx != SHN_UNDEF)
    std::vector<ImportedSymbol>   imports;       // imports (st_shndx == SHN_UNDEF) with PLT stub vaddr
    std::vector<CodeSegment>      loadable;      // PT_LOAD segments (executable + data)
    std::vector<uint32_t>         init_funcs;    // .preinit_array + .init_array entry vaddrs
    // Function pointers found in static data via R_ARM_RELATIVE
    // relocations. Each entry is the relocation's addend (= function
    // vaddr) when the target lives in an executable PT_LOAD; the low
    // bit is the Thumb marker. Used as additional discovery seeds:
    // libxml2 / libstdc++ statically-linked into HCR's libgame have
    // Thumb-mode init helpers (xmlInitParser etc.) that are reached
    // only from other Thumb code we may not have lifted yet, so they
    // never show up in `lifter.external_targets()`. By treating
    // every static fnptr as an entry, we catch vtable bodies, the
    // libxml2 callback tables (xmlOutputCallbackTable et al.) that
    // sprite-frame caches dispatch through, and similar globals.
    std::vector<uint32_t>         data_fnptr_seeds;
    // v1.0.63: subset of data_fnptr_seeds whose provenance is an
    // R_ARM_RELATIVE relocation (linker-authoritative). These are
    // GUARANTEED real function pointers (the linker emitted the
    // reloc because the source said `&Class::method` or similar).
    // The rest (data_fnptr_seeds \ authoritative_fnptr_seeds) come
    // from the elf_reader's heuristic PC-rel `ldr+add` scan and
    // need our own admission filtering before they can be lifted.
    // Splitting matters for vtable function pointers: HCR's
    // AppDelegate vtable[2] = 0x76268 is in this authoritative
    // set, but the function entry is preceded by an unrecognized
    // long-call veneer (so the terminator-check rejects it from
    // the PC-rel branch). Trusting the linker's relocation
    // unblocks it without admitting bogus heuristic seeds.
    std::vector<uint32_t>         authoritative_fnptr_seeds;
    // v1.0.806: subset of authoritative_fnptr_seeds whose ONLY backing is
    // the ARM-mode PIC `ldr Rt,[pc,#imm]; add Rt,pc,Rt; str/stm Rt,[..]`
    // pattern scan (elf_reader.cpp, "the ARM-mode analog of the Thumb16
    // PIC-fnptr scan"), NOT a .ARM.exidx entry or an R_ARM_RELATIVE
    // relocation. The other two provenances are LINKER/TOOLCHAIN-VERIFIED:
    // exidx is the linker's own unwind-table function-boundary list, and an
    // R_ARM_RELATIVE relocation exists only because the compiler emitted
    // "take the address of this function" -- both are ground truth
    // regardless of what precedes the target in .text. This scan is not:
    // it is a bare byte-pattern match over raw code, and "compute a
    // PC-relative address, then store it" is also exactly how ordinary
    // value/struct construction compiles (e.g. a `CCPoint(x, y)` call
    // sequence is structurally identical to installing a function
    // pointer). So a target this scan reports can be a real in-range
    // .text address that is NOT a function start -- just an ordinary
    // instruction the scan's arithmetic happened to land on. main.cpp
    // uses this set to require candidates prove they are NOT mere
    // fall-through (the terminator-precedence check) before admission,
    // while still letting genuinely-authoritative exidx/relocation seeds
    // bypass that check as before (v1.0.552/v1.0.63 both depend on that
    // bypass for real entries that follow a literal pool or an
    // unrecognized long-call veneer -- see the admission-loop comment in
    // main.cpp for the confirmed case-by-case verification).
    // See docs/arm32-discovery-mid-instruction-fnptr-seed_2026-07-28.md.
    std::vector<uint32_t>         heuristic_pic_fnptr_seeds;
    // Every function start named by .ARM.exidx (PREL31-decoded, bit0
    // cleared). Parsed UNCONDITIONALLY and cheaply -- this is a VALIDATION
    // set, not a seed list. Seeding from exidx is a separate, expensive,
    // opt-in thing (MACAPK_EXIDX_DISCOVERY) because it is a broad net that
    // roughly doubles lifted IR; merely KNOWING which addresses the linker
    // called functions costs one pass over an 8 KB table.
    //
    // Why it is worth knowing: exidx is the only complete function-boundary
    // table that survives stripping, so it is the one source that can veto a
    // HEURISTIC false positive. Concretely, main.cpp's blind literal-pool
    // scan flagged HCR 1.43's 0x204704 -- a real 5-instruction ARM leaf
    // (ldr/ldr/str/str/bx lr), exidx entry #4749 -- as pool data, and the
    // existing carve-out could not save it because it keys on
    // looks_like_fn_prologue and a LEAF has no push prologue. That single
    // unlifted function panic-stubbed the cocos2d-x SAX parser's init chain
    // and the whole app rendered nothing.
    std::unordered_set<uint32_t>  exidx_fn_starts;
    std::map<uint32_t, uint32_t>  exidx_entries;   // .ARM.exidx: fn start -> word 1 (EXTAB ref / inline / CANTUNWIND)
    // v1.0.808: intra-module PLT bindings (plt_stub_vaddr, local_fn_vaddr)
    // for EVERY `.rel.plt` R_ARM_JUMP_SLOT whose symbol is defined in this
    // image: a .so built with default visibility + PIC routes calls to its OWN
    // exported functions through its OWN PLT. This is the plain fact the ELF
    // states, with no policy applied -- Bionic binds every such slot eagerly
    // with no per-library or per-name rule, and so do we. Operator new/delete
    // are excluded (elf_reader routes them to the guest-heap shim as synthetic
    // imports). The Thumb bit is CLEARED (masked raw vaddr, st_value & ~1),
    // which is what arm32rc's `vaddr_to_sym` lookup keys on. This is a
    // TRANSLATE-TIME key only: the GOT word the guest reads keeps bit 0, as
    // Bionic writes it (MACAPK_ARM32_BIONIC_THUMB_BIT, elf_reader.cpp).
    //
    // (2026-09-27: the gated `plt_local_redirects` subset that used to sit
    // beside this -- MACAPK_PLT_REDIRECT / MACAPK_PLT_REDIRECT_FREETYPE plus a
    // FT_/ft_ name filter, consumed only by Arm32Lifter -- is retired. See
    // docs/plt-redirect-knobs-retired_2026-09-27.md.)
    //
    // arm32rc needs this because it decodes branch targets itself rather than
    // executing the guest `.plt`: a `bl <own_plt_stub>` fell through to the
    // panic stub and RETURNED 0 silently. ShatteredPD's `gdx2d_get_pixel@plt`
    // (0x268e0 -> 0x9cbc) is the confirmed case -- once per pixel, hence a
    // 100%-CPU spin.
    std::vector<std::pair<uint32_t,uint32_t>> plt_local_bindings;
    // Every DATA relocation against an undefined symbol with no PLT stub, in
    // .rel.dyn order (see DataImportSite). Pure bookkeeping: collecting it
    // changes no segment byte. Excludes `_toupper_tab_` / `_tolower_tab_`
    // (and `_ctype_` unless MACAPK_ARM32_CTYPE_TABLE=0), which keep their
    // synthetic-segment backing store -- except when that segment would not
    // fit inside this image's 64 KiB bias band (then they are listed here
    // and resolved from libc host data; see elf_reader.cpp).
    std::vector<DataImportSite>   data_imports;
    // PT_DYNAMIC p_vaddr (unbiased); 0 when the image has none. The runtime
    // linker reads DT_SYMTAB / DT_STRTAB / DT_GNU_HASH / DT_HASH / DT_NEEDED
    // out of the image's own bytes in the arena through it, as Bionic's
    // soinfo reads its mapped image.
    uint32_t                      dynamic_vaddr = 0;
    std::string                   soname;        // DT_SONAME if present, else basename

    // Convenience: returns the bytes for a symbol, walking the loadable
    // segments to find the one that contains the symbol's vaddr.
    // `out_size` is set to the bytes available before the next segment
    // ends; falls back to symbol.size when known.
    std::span<const uint8_t> code_for(const Symbol& sym, size_t* out_size) const;

    // Lookup the executable bytes at an arbitrary vaddr (used to follow
    // branch targets that point outside the original symbol's range).
    std::span<const uint8_t> code_at(uint32_t vaddr, size_t bytes_wanted) const;
};

// Read and parse an ELF32 ARM file. Returns a non-empty error string on
// any structural problem; otherwise the caller takes the populated
// Elf32Image. Out-of-bounds reads in the file are checked.
// `load_bias` is the per-image guest-arena offset B (0 for the main /
// single-.so image). When non-zero, the relocation pass writes
// load-base-relative pointers as (B + addend): R_ARM_RELATIVE slots and
// R_ARM_GLOB_DAT/ABS32 GOT slots, so a 2nd+ .so's in-memory pointers /
// PLT-stub references resolve in the biased region rather than colliding
// with another image. At B=0 every reloc write is identical to today.
std::string read_elf32(const std::string& path, Elf32Image* out,
                       uint32_t load_bias = 0);

}  // namespace macapk::translator
