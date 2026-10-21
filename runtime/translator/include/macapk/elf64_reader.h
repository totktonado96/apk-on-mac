// elf64_reader.h -- minimal ELF64 reader for AArch64 Bionic shared
// objects. Mirrors elf_reader.h (Elf32) one-to-one but with the 64-bit
// struct layout and AArch64-specific PLT geometry.
//
// We keep both readers in the project (rather than templating one)
// because the per-bit code paths -- PLT layout, ARM-vs-Thumb mode bits,
// constant pool quirks -- are different enough that two flat readers
// are clearer than one parameterized one.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace macapk::translator {

// ELF64 / AArch64 constants used by the reader. ELFCLASS64 itself is
// declared in elf_reader.h so both readers can share it.
constexpr uint16_t EM_AARCH64_64    = 183;  // same number as 32-bit's EM_AARCH64

// AArch64 PLT layout: PLT[0] is 32 bytes (resolver shim), each
// subsequent PLT[N] for N >= 1 is 16 bytes (4 instructions: ADRP, LDR,
// ADD, BR). The address of the Nth import's stub is
// PLT_BASE + 32 + (N-1)*16, in .rela.plt order.
constexpr uint32_t AARCH64_PLT0_SIZE  = 32;
constexpr uint32_t AARCH64_PLT_ENTRY  = 16;

#pragma pack(push, 1)
struct Elf64Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;     // note: flags before offset on ELF64
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};
#pragma pack(pop)

struct Symbol64 {
    std::string name;
    uint64_t    address;     // virtual address inside the .so
    uint64_t    size;        // bytes; 0 if unknown
    uint8_t     bind;        // STB_*
    uint8_t     type;        // STT_*
};

struct ImportedSymbol64 {
    std::string name;
    uint8_t     bind;
    uint8_t     type;
    uint64_t    plt_addr;    // PLT stub virtual address (0 if not in .rela.plt)
};

struct CodeSegment64 {
    uint64_t                 vaddr;
    std::vector<uint8_t>     bytes;
    bool                     executable;
};

// Parsed view of an AArch64 ELF shared object. Owns the file bytes and
// the parsed metadata.
struct Elf64Image {
    std::vector<uint8_t>            raw;
    Elf64Ehdr                       hdr;
    std::vector<Elf64Phdr>          phdrs;
    std::vector<Elf64Shdr>          shdrs;
    std::vector<Symbol64>           symbols;
    std::vector<ImportedSymbol64>   imports;
    std::vector<CodeSegment64>      loadable;
    // .preinit_array + .init_array entries (function vaddrs). Always
    // empty on the arm64 path today -- the AAPCS lifter emits its
    // exports as native arm64 ABI functions and the dyld-side linker
    // already runs darwin-arm64 ctors, so we don't need to mirror
    // them here. Kept on the struct so the templated runtime pipeline
    // can read it uniformly.
    std::vector<uint64_t>           init_funcs;
    std::string                     soname;

    std::span<const uint8_t> code_for(const Symbol64& sym, size_t* out_size) const;
    std::span<const uint8_t> code_at(uint64_t vaddr, size_t bytes_wanted) const;
};

// Read and parse an ELF64 AArch64 file. Returns a non-empty error
// string on any structural problem; otherwise the caller takes the
// populated Elf64Image.
std::string read_elf64(const std::string& path, Elf64Image* out);

// Same, but lets a caller that never reads segment CONTENTS skip copying
// them. With copy_segment_bytes=false every CodeSegment64 still gets its
// vaddr and executable flag, but `bytes` stays EMPTY, so code_at() /
// code_for() return empty spans. The Stage-6 pack (arm64_pack.cpp) is that
// caller: it reads only the symbol tables and `raw`, and the per-segment copy
// was a second resident copy of the whole library (plus .bss zero-fill).
// MACAPK_FIRSTLAUNCH_FASTREAD=0 ignores the flag and copies, restoring the
// exact pre-2026-09-26 behaviour.
std::string read_elf64(const std::string& path, Elf64Image* out,
                       bool copy_segment_bytes);

}  // namespace macapk::translator
