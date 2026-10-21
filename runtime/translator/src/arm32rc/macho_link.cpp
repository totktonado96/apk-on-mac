// macho_link.cpp -- implementation of the ARM32 recompiler's output stage.
//
// See macho_link.h for the contract, the measured scale, the three
// deliberate deviations from ld64.lld, and the source citations. This
// file is the mechanism.
//
// Pipeline inside write():
//
//   1. plan()           allocate one __got slot per symbol ever bound
//                        through a GOT-relative fixup (a Branch26 to an
//                        undefined external, or an explicit GotAdrp21/
//                        GotLdrLo12). Address-independent, runs once.
//   2. ensure a pool     if the producer never called
//                        reserve_veneer_pool() at all, auto-reserve one
//                        at the current tail of __text -- see
//                        macho_link.h, P5 and "BRANCH ISLANDS / VENEER
//                        POOLS".
//   3. layout()          assign every section a file offset + vmaddr.
//                        Every veneer pool is ALREADY part of `text`
//                        (the producer or step 2 appended it before
//                        this runs), so unlike the pre-2026-07-28
//                        design this has nothing left to iterate on:
//                        it runs exactly once.
//   4. assign_veneers()  for every Branch26 fixup that cannot reach its
//                        target directly, pick the nearest veneer pool
//                        within +/-128 MiB that has room, sharing one
//                        veneer per (pool, symbol) pair. Hard error
//                        (never a silent mis-branch) if no pool in
//                        reach has room.
//   5. patch()           resolve each fixup to an address, write the
//                        instruction/word field, and write every
//                        assigned veneer's 3 instructions into its
//                        pool slot.
//   6. linkedit()        rebase + bind opcode streams, export trie,
//                        symtab, indirect symbol table, string table.
//   7. emit()            mach header + load commands + the file image,
//                        then ad-hoc codesign.
//
// The layout mirrors arm64_macho_emit.cpp's (16 KiB pages, __TEXT at
// vmaddr 0 with the header in it, __DATA then __LINKEDIT), because that
// layout is proven to load.

#include "macho_link.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unordered_map>

namespace macapk::translator::arm32rc {

namespace {

constexpr uint64_t kPageSize = 0x4000;   // 16 KiB, the Apple Silicon page

// One veneer slot: adrp/add/br (direct target) or adrp/ldr/br (GOT
// target). Always three instructions, 12 bytes, regardless of which
// form. Every veneer pool's capacity is a multiple of this.
constexpr uint64_t kVeneerSlotSize = 12;

// B/BL imm26 reach: +/- 2^27 bytes. Leave a page of margin so a veneer
// right at the edge of what count/assign consider "in range" is still
// reachable after alignment padding.
constexpr int64_t kBranchMax = (int64_t(1) << 27) - int64_t(kPageSize);

inline uint64_t round_up(uint64_t v, uint64_t a) {
    return a ? ((v + (a - 1)) & ~(a - 1)) : v;
}

// Same contract as round_up(), but correct for a NON-power-of-two `a`
// (round_up()'s bitmask trick silently gives the wrong answer for one --
// e.g. round_up(16384, 12) via the mask is 16384 itself, which is not a
// multiple of 12). Used only for kVeneerSlotSize (12): everywhere else
// in this file `a` is 4, 8, 16, or kPageSize, all genuine powers of two,
// so round_up() stays correct for them and is left as-is.
inline uint64_t round_up_any(uint64_t v, uint64_t a) {
    return a ? ((v + a - 1) / a) * a : v;
}

// A default-ON bisect gate: unset or empty is ON, a value starting with
// '0' is OFF (the same reading as MACAPK_ARM32RC_MULTI_ENTRY and the
// MACAPK_FIRSTLAUNCH_* gates).
bool gate_on(const char* name) {
    const char* e = std::getenv(name);
    return !(e && e[0] == '0');
}

// ------------------------------------------------------------------
// Byte buffer + LEB128. Same shape as arm64_macho_emit.cpp's; copied
// rather than shared because that file's helpers are in an anonymous
// namespace and the Stage-6 path must not be perturbed by this work.
// ------------------------------------------------------------------
struct Buf {
    std::vector<uint8_t> b;
    size_t size() const { return b.size(); }
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { for (int i = 0; i < 2; ++i) b.push_back(uint8_t(v >> (8 * i))); }
    void u32(uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i))); }
    void u64(uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back(uint8_t(v >> (8 * i))); }
    void bytes(const void* p, size_t n) {
        const uint8_t* s = static_cast<const uint8_t*>(p);
        b.insert(b.end(), s, s + n);
    }
    void cstr(const std::string& s) { bytes(s.data(), s.size()); b.push_back(0); }
    void pad_to(size_t n) { while (b.size() < n) b.push_back(0); }
    void align(size_t a) { while (a && b.size() % a) b.push_back(0); }
};

void uleb(Buf& out, uint64_t v) {
    do {
        uint8_t byte = v & 0x7f;
        v >>= 7;
        if (v) byte |= 0x80;
        out.u8(byte);
    } while (v);
}

size_t uleb_size(uint64_t v) {
    size_t n = 0;
    do { ++n; v >>= 7; } while (v);
    return n;
}

// ------------------------------------------------------------------
// AArch64 field patchers. Each clears the instruction's immediate
// field and ORs the resolved value in, so a producer that emitted the
// instruction with a placeholder immediate gets a correct result
// regardless of what the placeholder was. Encodings: ARM ARM DDI 0487,
// C6.2 (quoted per function).
// ------------------------------------------------------------------

// C6.2.26 B / C6.2.33 BL: imm26 in bits [25:0], offset = SignExtend(imm26:'00').
bool patch_branch26(uint32_t* w, int64_t byte_delta) {
    if (byte_delta & 3) return false;
    const int64_t imm = byte_delta >> 2;
    if (imm < -(int64_t(1) << 25) || imm >= (int64_t(1) << 25)) return false;
    *w = (*w & 0xFC000000u) | (uint32_t(imm) & 0x03FFFFFFu);
    return true;
}

// C6.2.11 ADRP: immlo in bits [30:29], immhi in bits [23:5]; the value
// is SignExtend(immhi:immlo:Zeros(12)) added to the PC's page base.
bool patch_adrp(uint32_t* w, uint64_t pc, uint64_t target) {
    const int64_t d = int64_t(target >> 12) - int64_t(pc >> 12);
    if (d < -(int64_t(1) << 20) || d >= (int64_t(1) << 20)) return false;
    const uint32_t immlo = uint32_t(d) & 3u;
    const uint32_t immhi = uint32_t(d >> 2) & 0x7FFFFu;
    *w &= ~((3u << 29) | (0x7FFFFu << 5));
    *w |= (immlo << 29) | (immhi << 5);
    return true;
}

// C6.2.5 ADD (immediate): imm12 in bits [21:10], shift bit 22 left 0.
void patch_add_lo12(uint32_t* w, uint64_t target) {
    *w &= ~(0xFFFu << 10);
    *w |= uint32_t(target & 0xFFF) << 10;
}

// C6.2.132 LDR (immediate, unsigned offset): imm12 in bits [21:10],
// the byte offset being imm12 * <access size>. `scale` must therefore
// match the instruction's access size or the address is silently wrong.
bool patch_ldr_lo12(uint32_t* w, uint64_t target, uint32_t scale) {
    if (scale == 0) scale = 1;
    const uint64_t lo = target & 0xFFF;
    if (lo % scale) return false;
    const uint64_t imm12 = lo / scale;
    if (imm12 > 0xFFF) return false;
    *w &= ~(0xFFFu << 10);
    *w |= uint32_t(imm12) << 10;
    return true;
}

uint32_t enc_adrp_raw(uint32_t rd) { return 0x90000000u | (rd & 31); }
uint32_t enc_add_imm_raw(uint32_t rd, uint32_t rn) {
    return 0x91000000u | ((rn & 31) << 5) | (rd & 31);
}
uint32_t enc_ldr_imm_raw(uint32_t rt, uint32_t rn) {
    return 0xF9400000u | ((rn & 31) << 5) | (rt & 31);
}
uint32_t enc_br(uint32_t rn) { return 0xD61F0000u | ((rn & 31) << 5); }

// ------------------------------------------------------------------
// Export trie writer. Copied from arm64_macho_emit.cpp (see the
// LINEAGE note in the header); the fixed-point offset convergence is
// the subtle part -- a child's offset is a ULEB whose own width
// depends on its value, so the layout has to settle before emission.
// ------------------------------------------------------------------
struct TrieEntry { std::string name; uint64_t addr; };

struct TrieNode {
    std::string edge;
    bool is_terminal = false;
    uint64_t addr = 0;
    std::vector<int> children;
    size_t offset = 0;
};

class ExportTrie {
public:
    explicit ExportTrie(const std::vector<TrieEntry>& entries) {
        nodes_.push_back(TrieNode{});
        for (const auto& e : entries) insert(0, e.name, e.addr);
    }

    std::vector<uint8_t> serialize() {
        std::vector<int> order;
        order.reserve(nodes_.size());
        preorder(0, order);
        for (int idx : order) nodes_[idx].offset = 0;
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 64) {
            changed = false;
            size_t cursor = 0;
            for (int idx : order) {
                if (nodes_[idx].offset != cursor) { nodes_[idx].offset = cursor; changed = true; }
                cursor += node_size(idx);
            }
        }
        std::vector<uint8_t> blob;
        for (int idx : order) emit_node(blob, idx);
        return blob;
    }

private:
    std::vector<TrieNode> nodes_;

    void insert(int at, const std::string& key, uint64_t addr) {
        // Every push_back may reallocate, so never hold a reference or
        // a string ref into nodes_ across one -- re-index each time.
        const size_t nchildren = nodes_[at].children.size();
        for (size_t k = 0; k < nchildren; ++k) {
            const int ci = nodes_[at].children[k];
            const std::string edge = nodes_[ci].edge;
            size_t common = 0;
            while (common < edge.size() && common < key.size() &&
                   edge[common] == key[common])
                ++common;
            if (common == 0) continue;
            if (common == edge.size()) {
                if (common == key.size()) {
                    nodes_[ci].is_terminal = true;
                    nodes_[ci].addr = addr;
                } else {
                    insert(ci, key.substr(common), addr);
                }
                return;
            }
            const int split = int(nodes_.size());
            nodes_.push_back(TrieNode{});
            int leaf = -1;
            if (common != key.size()) {
                leaf = int(nodes_.size());
                nodes_.push_back(TrieNode{});
            }
            nodes_[split].edge = edge.substr(0, common);
            nodes_[split].children.push_back(ci);
            nodes_[ci].edge = edge.substr(common);
            if (leaf < 0) {
                nodes_[split].is_terminal = true;
                nodes_[split].addr = addr;
            } else {
                nodes_[leaf].edge = key.substr(common);
                nodes_[leaf].is_terminal = true;
                nodes_[leaf].addr = addr;
                nodes_[split].children.push_back(leaf);
            }
            nodes_[at].children[k] = split;
            return;
        }
        const int leaf = int(nodes_.size());
        nodes_.push_back(TrieNode{});
        nodes_[leaf].edge = key;
        nodes_[leaf].is_terminal = true;
        nodes_[leaf].addr = addr;
        nodes_[at].children.push_back(leaf);
    }

    void preorder(int idx, std::vector<int>& order) {
        order.push_back(idx);
        for (int c : nodes_[idx].children) preorder(c, order);
    }

    size_t node_size(int idx) {
        const TrieNode& n = nodes_[idx];
        size_t sz = 0;
        if (n.is_terminal) {
            const size_t term = uleb_size(0) + uleb_size(n.addr);
            sz += uleb_size(term) + term;
        } else {
            sz += uleb_size(0);
        }
        sz += 1;
        for (int c : nodes_[idx].children) {
            sz += nodes_[c].edge.size() + 1;
            sz += uleb_size(nodes_[c].offset);
        }
        return sz;
    }

    void emit_node(std::vector<uint8_t>& blob, int idx) {
        Buf tmp;
        const TrieNode& n = nodes_[idx];
        if (n.is_terminal) {
            Buf term;
            uleb(term, 0);            // flags: regular export
            uleb(term, n.addr);       // image-relative address
            uleb(tmp, term.size());
            tmp.bytes(term.b.data(), term.b.size());
        } else {
            uleb(tmp, 0);
        }
        tmp.u8(uint8_t(n.children.size()));
        for (int c : nodes_[idx].children) {
            tmp.cstr(nodes_[c].edge);
            uleb(tmp, nodes_[c].offset);
        }
        blob.insert(blob.end(), tmp.b.begin(), tmp.b.end());
    }
};

// ------------------------------------------------------------------
// Export trie READER -- used on the bionic shim to decide, per
// undefined symbol, two-level ordinal 1 vs flat lookup (deviation 2 in
// the header). Handles both the modern LC_DYLD_EXPORTS_TRIE and the
// classic LC_DYLD_INFO_ONLY export_off/size; the shim as built today
// uses the former (verified: otool -l shows LC_DYLD_EXPORTS_TRIE).
//
// Node format, per <mach-o/loader.h>'s export-trie description:
//   uleb terminalSize; <terminalSize bytes of payload>
//   u8   childCount; { cstring edge; uleb childNodeOffset } * childCount
// ------------------------------------------------------------------
uint64_t read_uleb(const uint8_t* p, const uint8_t* end, size_t& i) {
    uint64_t v = 0;
    int shift = 0;
    while (p + i < end) {
        const uint8_t b = p[i++];
        if (shift < 64) v |= uint64_t(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    return v;
}

void trie_collect(const uint8_t* trie, size_t size, size_t node_off,
                  std::string prefix, std::vector<std::string>& out,
                  int depth) {
    if (depth > 128 || node_off >= size) return;
    if (out.size() > 2000000) return;          // pathological-input guard
    const uint8_t* end = trie + size;
    size_t i = node_off;
    const uint64_t term_size = read_uleb(trie, end, i);
    if (term_size) {
        out.push_back(prefix);
        i += size_t(term_size);
        if (i >= size) return;
    }
    const uint8_t nchildren = (i < size) ? trie[i++] : 0;
    for (uint8_t k = 0; k < nchildren && i < size; ++k) {
        const char* edge = reinterpret_cast<const char*>(trie + i);
        const size_t maxlen = size - i;
        const size_t elen = ::strnlen(edge, maxlen);
        if (elen == maxlen) return;            // unterminated: malformed
        i += elen + 1;
        const uint64_t child = read_uleb(trie, end, i);
        if (child == node_off) return;         // self-loop: malformed
        trie_collect(trie, size, size_t(child), prefix + std::string(edge, elen),
                     out, depth + 1);
    }
}

// Read `path`'s export trie and return the exported names WITHOUT the
// leading Mach-O underscore (so they compare directly against the
// names callers pass to undefined()). Empty on any failure.
std::vector<std::string> read_dylib_exports(const std::string& path) {
    std::vector<std::string> names;
    if (path.empty()) return names;
    std::ifstream f(path, std::ios::binary);
    if (!f) return names;
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    if (raw.size() < sizeof(struct mach_header_64)) return names;
    struct mach_header_64 mh{};
    std::memcpy(&mh, raw.data(), sizeof(mh));
    if (mh.magic != MH_MAGIC_64) return names;   // fat/32-bit: not ours

    uint32_t trie_off = 0, trie_size = 0;
    size_t off = sizeof(mh);
    for (uint32_t c = 0; c < mh.ncmds; ++c) {
        if (off + sizeof(struct load_command) > raw.size()) break;
        struct load_command lc{};
        std::memcpy(&lc, raw.data() + off, sizeof(lc));
        if (lc.cmdsize < sizeof(lc) || off + lc.cmdsize > raw.size()) break;
        if (lc.cmd == LC_DYLD_EXPORTS_TRIE) {
            struct linkedit_data_command ld{};
            std::memcpy(&ld, raw.data() + off, sizeof(ld));
            trie_off = ld.dataoff; trie_size = ld.datasize;
        } else if (lc.cmd == LC_DYLD_INFO_ONLY || lc.cmd == LC_DYLD_INFO) {
            struct dyld_info_command di{};
            std::memcpy(&di, raw.data() + off, sizeof(di));
            if (di.export_size) { trie_off = di.export_off; trie_size = di.export_size; }
        }
        off += lc.cmdsize;
    }
    if (!trie_size || uint64_t(trie_off) + trie_size > raw.size()) return names;
    std::vector<std::string> raw_names;
    trie_collect(raw.data() + trie_off, trie_size, 0, std::string(), raw_names, 0);
    names.reserve(raw_names.size());
    for (auto& n : raw_names) {
        if (!n.empty() && n[0] == '_') names.push_back(n.substr(1));
        else names.push_back(n);
    }
    return names;
}

// ------------------------------------------------------------------
// Internal tables.
// ------------------------------------------------------------------
struct Symbol {
    std::string name;        // WITHOUT the Mach-O underscore
    bool defined  = false;
    bool exported = false;
    Sec  sec      = Sec::Text;
    uint64_t off  = 0;
    // Assigned during planning:
    uint32_t got_index  = kNoSym;   // index into the GOT array
    uint32_t sym_index  = 0;        // final nlist index (set in linkedit)
    bool     in_shim    = false;    // resolved to ordinal 1
    // bind_to_dependency(): a two-level WEAK bind to this LC_LOAD_DYLIB
    // ordinal (3 = the first extra dependency). 0 = the usual decision.
    uint16_t dep_ordinal = 0;
};

// A veneer pool: a fixed-capacity, zero-filled block the producer (or
// write()'s own tail fallback) appended into Sec::Text via the same
// append-only path as ordinary code. `text_off` is therefore a STABLE,
// FINAL Sec::Text byte offset from the moment it is reserved -- nothing
// ever moves it, which is what lets assign_veneers()/patch() run
// without any remapping pass. `slot` maps a symbol index to the
// ABSOLUTE Sec::Text byte offset of that symbol's veneer WITHIN this
// pool (not pool-relative), so callers can address it the same way as
// any other Sec::Text location.
struct VeneerPool {
    uint64_t text_off = 0;
    uint64_t capacity = 0;
    uint64_t used     = 0;
    std::unordered_map<uint32_t, uint64_t> slot;
};

// Sentinel for Impl::fixup_veneer_off: this Branch26 fixup branches
// straight to its target's own address, no veneer needed.
constexpr uint64_t kNoVeneer = UINT64_MAX;

}  // namespace

// ======================================================================
// Impl
// ======================================================================
struct MachOLinker::Impl {
    LinkOptions opt;

    std::vector<uint8_t> text, cnst, data;
    uint64_t bss_size = 0;

    std::vector<Symbol> syms;
    std::unordered_map<std::string, uint32_t> sym_by_name;
    std::vector<Fixup> fixups;
    std::vector<Ref> inits;
    // Cross-guest-library linking (2026-07-28): additional LC_LOAD_DYLIB
    // dependencies beyond the shim + libSystem, registered via
    // add_dependency(). Deduped by exact absolute path. See
    // docs/cross-guest-library-linking_2026-07-28.md.
    std::vector<std::string> extra_deps;
    // bind_to_dependency(): undefined name -> extra_deps install path.
    std::unordered_map<std::string, std::string> two_level_dep;

    std::vector<uint32_t> got_syms;     // got  i -> symbol index

    // Sorted by text_off by construction: reserve_pool() only ever
    // appends at the current end of `text`, so each new pool's
    // text_off is >= every earlier one's. assign_veneers() relies on
    // this to binary-search for the nearest pool to a call site.
    std::vector<VeneerPool> veneer_pools;
    // Parallel to `fixups`. Filled by assign_veneers(), consulted by
    // patch(). kNoVeneer means "branch straight to the target" (only
    // valid when the target is a defined symbol in direct range).
    std::vector<uint64_t> fixup_veneer_off;

    // Layout (filled by layout()).
    uint64_t text_sec_off = 0, text_size = 0, text_vmaddr = 0;
    uint64_t const_off = 0, const_vmaddr = 0;
    uint64_t text_filesize = 0;
    uint64_t data_vmaddr = 0, data_fileoff = 0, data_filesize = 0, data_vmsize = 0;
    uint64_t got_off = 0, got_vmaddr = 0;
    uint64_t modinit_off = 0, modinit_vmaddr = 0;
    uint64_t data_sec_off = 0, data_sec_vmaddr = 0;
    uint64_t bss_vmaddr = 0;
    uint64_t lc_end = 0;
    uint32_t text_nsects = 0, data_nsects = 0;
    uint32_t sizeofcmds = 0, ncmds = 0;

    LinkResult res;

    // ---- helpers -----------------------------------------------------
    std::vector<uint8_t>* sec_vec(Sec s) {
        switch (s) {
            case Sec::Text:  return &text;
            case Sec::Const: return &cnst;
            case Sec::Data:  return &data;
            case Sec::Bss:   return nullptr;
        }
        return nullptr;
    }

    uint64_t sec_vmaddr(Sec s) const {
        switch (s) {
            case Sec::Text:  return text_vmaddr;
            case Sec::Const: return const_vmaddr;
            case Sec::Data:  return data_sec_vmaddr;
            case Sec::Bss:   return bss_vmaddr;
        }
        return 0;
    }

    // File offset of a section byte, for the writer. Bss has none.
    bool sec_fileoff(Sec s, uint64_t off, uint64_t* out) const {
        switch (s) {
            case Sec::Text:  *out = text_sec_off + off; return true;
            case Sec::Const: *out = const_off + off;    return true;
            case Sec::Data:  *out = data_sec_off + off; return true;
            case Sec::Bss:   return false;
        }
        return false;
    }

    bool ref_address(const Ref& r, uint64_t* out) const {
        if (r.is_symbol()) {
            if (r.sym >= syms.size()) return false;
            const Symbol& s = syms[r.sym];
            if (!s.defined) return false;
            *out = sec_vmaddr(s.sec) + s.off;
            return true;
        }
        *out = sec_vmaddr(r.sec) + r.off;
        return true;
    }

    uint64_t got_addr(uint32_t i)  const { return got_vmaddr + uint64_t(i) * 8; }

    // Reserve `capacity` (rounded up to a multiple of kVeneerSlotSize)
    // zero-filled bytes at the current end of `text` and register a
    // new pool. Shared by the public reserve_veneer_pool() wrapper and
    // by write()'s own "ensure at least one pool exists" fallback.
    uint64_t reserve_pool(uint64_t capacity);

    // ---- pipeline ----------------------------------------------------
    void plan();
    void resolve_ordinals();
    void layout();
    bool assign_veneers(std::string* err);
    bool trim_tail_pool(uint64_t* trimmed, std::string* why_not);
    bool patch(std::string* err);
    bool emit(const std::string& out_path, std::string* err);
};

// ----------------------------------------------------------------------
// 1. plan -- allocate one GOT slot per symbol ever bound through a
//    GOT-relative fixup. Address-independent (no veneer pool needs to
//    exist yet: every pool reads the SAME got_addr(), whichever pool
//    ends up hosting a given symbol's veneer -- see assign_veneers()).
// ----------------------------------------------------------------------
void MachOLinker::Impl::plan() {
    got_syms.clear();
    for (auto& s : syms) s.got_index = kNoSym;

    auto need_got = [&](uint32_t si) {
        if (si >= syms.size()) return;
        if (syms[si].got_index == kNoSym) {
            syms[si].got_index = uint32_t(got_syms.size());
            got_syms.push_back(si);
        }
    };

    for (const auto& f : fixups) {
        if (!f.target.is_symbol()) continue;
        const uint32_t si = f.target.sym;
        if (si >= syms.size()) continue;
        switch (f.kind) {
            case Fix::Branch26:
                // An UNDEFINED target always needs a GOT slot (its real
                // address is not known until dyld binds it, so its
                // veneer -- wherever assign_veneers() places it -- must
                // read through the GOT). A defined target never needs
                // one for the branch itself.
                if (!syms[si].defined) need_got(si);
                break;
            case Fix::GotAdrp21:
            case Fix::GotLdrLo12:
                need_got(si);
                break;
            default:
                break;
        }
    }
}

// ----------------------------------------------------------------------
// 2. ordinals -- which undefineds the shim exports (two-level, ordinal
//    1) and which fall through to flat lookup. See header deviation 2.
// ----------------------------------------------------------------------
void MachOLinker::Impl::resolve_ordinals() {
    const std::vector<std::string> exports = read_dylib_exports(opt.shim_path);
    res.shim_trie_read = !exports.empty();
    std::unordered_map<std::string, char> in_shim;
    in_shim.reserve(exports.size() * 2);
    for (const auto& e : exports) in_shim.emplace(e, 1);
    for (auto& s : syms) {
        if (s.defined) continue;
        // bind_to_dependency() wins over both the shim and flat lookup.
        // Empty map (every image that does not trip the gate): no change.
        if (!two_level_dep.empty()) {
            auto td = two_level_dep.find(s.name);
            if (td != two_level_dep.end()) {
                for (size_t k = 0; k < extra_deps.size(); ++k)
                    if (extra_deps[k] == td->second) {
                        s.dep_ordinal = uint16_t(3 + k);   // shim 1, libSystem 2
                        break;
                    }
                if (s.dep_ordinal) continue;
            }
        }
        s.in_shim = in_shim.count(s.name) != 0;
        if (!s.in_shim) res.flat_symbols.push_back(s.name);
    }
    std::sort(res.flat_symbols.begin(), res.flat_symbols.end());
}

// ----------------------------------------------------------------------
// 3. layout -- file offsets + vmaddrs for everything.
// ----------------------------------------------------------------------
void MachOLinker::Impl::layout() {
    auto lc_dylib_size = [](const std::string& p) -> uint32_t {
        return uint32_t(round_up(24 + p.size() + 1, 8));
    };
    auto lc_rpath_size = [](const std::string& p) -> uint32_t {
        return uint32_t(round_up(12 + p.size() + 1, 8));
    };
    const uint32_t kSegCmd = uint32_t(sizeof(struct segment_command_64));
    const uint32_t kSect   = uint32_t(sizeof(struct section_64));

    text_nsects = 1;                                   // __text always
    if (!cnst.empty())      ++text_nsects;             // __const
    data_nsects = 0;
    if (!got_syms.empty())  ++data_nsects;             // __got
    if (!inits.empty())     ++data_nsects;             // __modinit
    if (!data.empty())      ++data_nsects;             // __data
    if (bss_size)           ++data_nsects;             // __bss

    const std::string libsystem = "/usr/lib/libSystem.B.dylib";
    const std::string rpath_loader = "@loader_path";

    ncmds = 12;                                        // see the list below
    if (!opt.shim_dir.empty()) ++ncmds;                // second LC_RPATH
    // Cross-guest-library linking (2026-07-28): one more LC_LOAD_DYLIB per
    // extra_deps entry, beyond the fixed shim + libSystem pair below. See
    // docs/cross-guest-library-linking_2026-07-28.md.
    ncmds += uint32_t(extra_deps.size());
    sizeofcmds =
        (kSegCmd + text_nsects * kSect)                // LC_SEGMENT_64 __TEXT
      + (kSegCmd + data_nsects * kSect)                // LC_SEGMENT_64 __DATA
      + kSegCmd                                        // LC_SEGMENT_64 __LINKEDIT
      + uint32_t(sizeof(struct dyld_info_command))     // LC_DYLD_INFO_ONLY
      + uint32_t(sizeof(struct symtab_command))        // LC_SYMTAB
      + uint32_t(sizeof(struct dysymtab_command))      // LC_DYSYMTAB
      + lc_dylib_size(opt.install_name)                // LC_ID_DYLIB
      + lc_dylib_size(opt.shim_install_name)           // LC_LOAD_DYLIB
      + lc_dylib_size(libsystem)                       // LC_LOAD_DYLIB
      + lc_rpath_size(rpath_loader)                    // LC_RPATH
      + uint32_t(sizeof(struct build_version_command)) // LC_BUILD_VERSION
      + uint32_t(sizeof(struct uuid_command));         // LC_UUID
    if (!opt.shim_dir.empty()) sizeofcmds += lc_rpath_size(opt.shim_dir);
    for (const auto& d : extra_deps) sizeofcmds += lc_dylib_size(d);

    lc_end = sizeof(struct mach_header_64) + sizeofcmds;

    // codesign appends an LC_CODE_SIGNATURE right after our last load
    // command, so reserve room or it would overwrite the first
    // instructions of __text.
    const uint64_t codesign_reserve = sizeof(struct linkedit_data_command);

    // __TEXT: header+LCs, then __text, then __const. Every veneer pool
    // is ALREADY inside `text` (the producer's reserve_veneer_pool()
    // calls, or write()'s own tail fallback, appended it before this
    // ever runs -- see the file header, "BRANCH ISLANDS / VENEER
    // POOLS"), so unlike the pre-2026-07-28 design there is no separate
    // islands/stubs region to size here at all.
    text_sec_off = round_up(lc_end + codesign_reserve, 16);
    text_size    = round_up(text.size(), 4);
    const_off    = round_up(text_sec_off + text_size, 16);
    const uint64_t text_used_end = const_off + cnst.size();
    text_filesize = round_up(text_used_end, kPageSize);

    // __TEXT's segment vmaddr is 0 (the mach header lives at its
    // start), so every section's vmaddr equals its file offset. A
    // Sec::Text offset is relative to the __text SECTION, hence
    // text_vmaddr == text_sec_off rather than 0.
    text_vmaddr  = text_sec_off;
    const_vmaddr = const_off;

    // __DATA at the next page.
    data_vmaddr  = text_filesize;
    data_fileoff = text_filesize;
    uint64_t cur = data_fileoff;
    got_off = cur; cur += got_syms.size() * 8;
    modinit_off = cur; cur += inits.size() * 8;
    data_sec_off = cur; cur += data.size();
    const uint64_t data_file_used = cur;
    // filesize is a SIZE, not an end offset: `cur` walked forward from
    // data_fileoff, so subtract the base before rounding. Getting this
    // wrong makes dyld reject the image with "segment '__DATA'
    // filesize exceeds vmsize".
    data_filesize = round_up(data_file_used - data_fileoff, kPageSize);

    got_vmaddr      = data_vmaddr + (got_off - data_fileoff);
    modinit_vmaddr  = data_vmaddr + (modinit_off - data_fileoff);
    data_sec_vmaddr = data_vmaddr + (data_sec_off - data_fileoff);
    // __bss is zerofill and must be the LAST section of __DATA.
    const uint64_t bss_vm_off = data_file_used - data_fileoff;
    bss_vmaddr = data_vmaddr + bss_vm_off;
    data_vmsize = round_up(bss_vm_off + bss_size, kPageSize);
}

// ----------------------------------------------------------------------
// 4. assign_veneers -- for every Branch26 fixup that cannot reach its
//    target directly, pick a veneer pool within +/-128 MiB of the call
//    site that still has room, allocating a new slot in it if this
//    (pool, symbol) pair has not been used before. An UNDEFINED target
//    ALWAYS needs a veneer (its real address is not known until dyld
//    binds it); a DEFINED target only needs one when the direct
//    displacement does not fit. See the file header, "BRANCH ISLANDS /
//    VENEER POOLS", for why a veneer never needs to chain to another
//    veneer -- the second hop (ADRP-based) has a +/-4 GiB reach, so
//    landing on ANY in-range pool is sufficient, never just the
//    nearest one.
// ----------------------------------------------------------------------
bool MachOLinker::Impl::assign_veneers(std::string* err) {
    auto fail = [&](const std::string& m) { *err = m; return false; };

    fixup_veneer_off.assign(fixups.size(), kNoVeneer);
    for (auto& p : veneer_pools) { p.slot.clear(); p.used = 0; }

    if (veneer_pools.empty()) {
        // write() reserves a fallback pool before layout() runs
        // whenever the producer created none itself, so this is an
        // internal-ordering bug, not a reachable user-facing failure.
        return fail("internal error: assign_veneers() ran with zero "
                    "veneer pools -- write() must reserve a fallback "
                    "before layout()");
    }

    for (size_t i = 0; i < fixups.size(); ++i) {
        const Fixup& f = fixups[i];
        if (f.kind != Fix::Branch26 || !f.target.is_symbol()) continue;
        const uint32_t si = f.target.sym;
        if (si >= syms.size()) continue;
        const Symbol& s = syms[si];
        const uint64_t pc = sec_vmaddr(f.sec) + f.off;

        if (s.defined) {
            const uint64_t to = sec_vmaddr(s.sec) + s.off + uint64_t(f.addend);
            const int64_t d = int64_t(to) - int64_t(pc);
            if (d <= kBranchMax && d >= -kBranchMax) continue;   // direct, no veneer
        }

        // pool.text_off is already Sec::Text-relative, so subtracting
        // text_vmaddr makes pc directly comparable to it regardless of
        // which section this particular call site lives in.
        const int64_t pc_text_off = int64_t(pc) - int64_t(text_vmaddr);

        // Prefer a pool that already hosts a veneer for this exact
        // symbol (costs nothing new); otherwise the nearest in-range
        // pool with free capacity. Both candidates are scanned from
        // among ONLY the pools within kBranchMax of this call site, so
        // whichever is picked is guaranteed reachable by construction.
        VeneerPool* reuse = nullptr;
        VeneerPool* nearest_free = nullptr;
        int64_t reuse_dist = 0, nearest_dist = 0;
        for (auto& pool : veneer_pools) {
            const int64_t d = int64_t(pool.text_off) - pc_text_off;
            if (d > kBranchMax || d < -kBranchMax) continue;
            const int64_t ad = d < 0 ? -d : d;
            if (pool.slot.count(si)) {
                if (!reuse || ad < reuse_dist) { reuse = &pool; reuse_dist = ad; }
            } else if (pool.used + kVeneerSlotSize <= pool.capacity) {
                if (!nearest_free || ad < nearest_dist) { nearest_free = &pool; nearest_dist = ad; }
            }
        }
        VeneerPool* chosen = reuse ? reuse : nearest_free;
        if (!chosen) {
            char msg[320];
            std::snprintf(msg, sizeof(msg),
                "no veneer pool within +/-128 MiB of the call site at "
                "Sec::Text offset 0x%llx has room for '%s' (%zu pool(s) "
                "exist) -- widen kVeneerPoolRecommendedIntervalBytes or "
                "kVeneerPoolCapacityBytes",
                (unsigned long long)pc_text_off, s.name.c_str(),
                veneer_pools.size());
            return fail(msg);
        }
        auto it = chosen->slot.find(si);
        if (it != chosen->slot.end()) {
            fixup_veneer_off[i] = it->second;
        } else {
            const uint64_t abs_off = chosen->text_off + chosen->used;
            chosen->used += kVeneerSlotSize;
            chosen->slot.emplace(si, abs_off);
            fixup_veneer_off[i] = abs_off;
        }
    }
    return true;
}

// ----------------------------------------------------------------------
// 4b. trim_tail_pool -- MACAPK_ARM32RC_TRIM_VENEER_TAIL. Runs after
//     assign_veneers() and BEFORE patch(): cut the never-used capacity off
//     the LAST veneer pool when that pool is the tail of __text, then
//     re-derive layout() and the veneer assignment from scratch.
//
// Why this is exact, and not a patch-up of already-computed addresses:
//   * Nothing has been resolved yet. patch() and emit() run after this and
//     read ONLY the final layout: every Branch26 / Adrp21 / AddLo12 /
//     LdrLo12 / Got* / Delta32 / Ptr64 fixup is recomputed from
//     sec_vmaddr() / got_addr(); the veneers' own adrp/add|ldr pairs are
//     written by patch() from the same; nlist values, the export trie,
//     __modinit pointers, defined-symbol __got slots and the segment /
//     section headers are computed by emit(); rebase and bind offsets are
//     __DATA-segment-relative. The producer never bakes an address of its
//     own (arm32rc_driver.cpp routes every cross-function or cross-section
//     reference through add_fixup / branch / adrp_add_pair, and never uses
//     mutable_bytes()).
//   * What the trim moves: __const (it starts right after __text), and
//     __DATA / __LINKEDIT (they start at the next page after __TEXT). What
//     it does NOT move: any Sec::Text offset, text_vmaddr (a function of
//     the load-command size only) or any pool's text_off -- so every call
//     site and every pool stay where assign_veneers() saw them.
//   * The ONE pre-patch decision that depends on addresses is
//     assign_veneers() (direct vs veneer, and which pool). It is re-run on
//     the trimmed layout and must reproduce the original assignment slot
//     for slot; a Branch26 whose pc or target lies outside __text is the
//     only thing that could make it differ (the driver emits none), and if
//     anything differs the trim is rolled back to the untrimmed layout,
//     never shipped approximately.
//   * Nothing may live in the cut range except this pool's unused slots:
//     a Sec::Text symbol, fixup word or local reference at or beyond the
//     new end refuses the trim.
// *trimmed = the bytes cut (0 when nothing was cut; *why_not then says why
// when the reason is worth a log line). Returns false only if the rollback
// itself failed, which leaves no consistent layout to write.
// ----------------------------------------------------------------------
bool MachOLinker::Impl::trim_tail_pool(uint64_t* trimmed, std::string* why_not) {
    *trimmed = 0;
    if (veneer_pools.empty()) return true;
    VeneerPool& last = veneer_pools.back();
    const uint64_t old_cap = last.capacity;
    const uint64_t pool_end = last.text_off + old_cap;
    if (pool_end != text.size()) {
        *why_not = "the last veneer pool is not the tail of __text";
        return true;
    }
    // used is a multiple of kVeneerSlotSize (12) and text_off is 4-aligned
    // (append(..., 4)), so the new end stays 4-aligned like every other
    // __text size layout() has ever seen.
    const uint64_t new_cap = last.used;
    if (new_cap >= old_cap) return true;
    const uint64_t new_end = last.text_off + new_cap;

    for (const Symbol& s : syms) {
        if (s.defined && s.sec == Sec::Text && s.off >= new_end) {
            *why_not = "symbol '" + s.name + "' is defined inside the unused pool tail";
            return true;
        }
    }
    for (const Fixup& f : fixups) {
        if (f.sec == Sec::Text && f.off + 4 > new_end) {
            *why_not = "a fixup patches a word inside the unused pool tail";
            return true;
        }
        if (!f.target.is_symbol() && f.target.sec == Sec::Text && f.target.off >= new_end) {
            *why_not = "a fixup targets an offset inside the unused pool tail";
            return true;
        }
    }
    for (const Ref& r : inits) {
        if (!r.is_symbol() && r.sec == Sec::Text && r.off >= new_end) {
            *why_not = "an initialiser points inside the unused pool tail";
            return true;
        }
    }

    // The assignment the untrimmed layout produced, to compare against.
    const std::vector<uint64_t> fixup_before = fixup_veneer_off;
    std::vector<std::unordered_map<uint32_t, uint64_t>> slots_before;
    std::vector<uint64_t> used_before;
    slots_before.reserve(veneer_pools.size());
    used_before.reserve(veneer_pools.size());
    for (const auto& p : veneer_pools) {
        slots_before.push_back(p.slot);
        used_before.push_back(p.used);
    }

    // The cut bytes are the pool's untouched zero fill: patch() has not
    // written a single veneer yet, so a rollback restores them exactly.
    text.resize(size_t(new_end));
    last.capacity = new_cap;
    layout();

    std::string err;
    bool same = assign_veneers(&err) && fixup_veneer_off == fixup_before;
    for (size_t i = 0; same && i < veneer_pools.size(); ++i)
        same = veneer_pools[i].used == used_before[i]
               && veneer_pools[i].slot == slots_before[i];
    if (same) {
        *trimmed = pool_end - new_end;
        return true;
    }

    text.resize(size_t(pool_end), 0);
    last.capacity = old_cap;
    layout();
    std::string err2;
    if (!assign_veneers(&err2)) {
        // Cannot happen (this exact layout assigned cleanly before the
        // trim); reported rather than assumed.
        *why_not = "rollback re-assignment failed: " + err2;
        return false;
    }
    *why_not = err.empty()
        ? "the trimmed layout changed the veneer assignment; rolled back"
        : "the trimmed layout could not assign veneers (" + err + "); rolled back";
    return true;
}

// ----------------------------------------------------------------------
// 5. patch -- resolve every fixup and write its field.
// ----------------------------------------------------------------------
bool MachOLinker::Impl::patch(std::string* err) {
    auto fail = [&](const std::string& m) { *err = m; return false; };

    // Veneers: adrp x16, TARGET@PAGE ; { add x16,x16,@PAGEOFF (direct)
    // | ldr x16,[x16,@PAGEOFF] (GOT) } ; br x16. x16 is IP0, the
    // intra-procedure-call scratch register (AAPCS64 6.1.1 / table 2),
    // so clobbering it across a veneer is exactly what it is for --
    // true both for a BL and for a B tail call. Byte-identical in FORM
    // to what ld64.lld emits for a __stubs entry (see the file header,
    // deviation 1), just written directly into `text` at whatever
    // pool slot assign_veneers() picked, rather than into one
    // dedicated section built once. See macho_link.h, "BRANCH ISLANDS
    // / VENEER POOLS".
    for (auto& pool : veneer_pools) {
        for (const auto& kv : pool.slot) {
            const uint32_t sym_idx = kv.first;
            const uint64_t abs_off = kv.second;
            if (abs_off + kVeneerSlotSize > text.size())
                return fail("veneer slot out of range (internal error)");
            const Symbol& s = syms[sym_idx];
            const uint64_t veneer_pc = text_vmaddr + abs_off;
            uint32_t w0 = enc_adrp_raw(16);
            uint32_t w1;
            const uint32_t w2 = enc_br(16);
            if (s.defined) {
                const uint64_t to = sec_vmaddr(s.sec) + s.off;
                if (!patch_adrp(&w0, veneer_pc, to))
                    return fail("veneer ADRP out of range for '" + s.name + "'");
                w1 = enc_add_imm_raw(16, 16);
                patch_add_lo12(&w1, to);
            } else {
                if (s.got_index == kNoSym)
                    return fail("no GOT slot for '" + s.name +
                                "' (internal error: plan() should have "
                                "allocated one for every undefined "
                                "Branch26 target)");
                const uint64_t g = got_addr(s.got_index);
                if (!patch_adrp(&w0, veneer_pc, g))
                    return fail("veneer ADRP out of range for '" + s.name + "'");
                w1 = enc_ldr_imm_raw(16, 16);
                if (!patch_ldr_lo12(&w1, g, 8))
                    return fail("veneer LDR offset unencodable for '" + s.name + "'");
            }
            std::memcpy(text.data() + abs_off + 0, &w0, 4);
            std::memcpy(text.data() + abs_off + 4, &w1, 4);
            std::memcpy(text.data() + abs_off + 8, &w2, 4);
        }
    }

    // The producer's own fixups.
    for (size_t fi = 0; fi < fixups.size(); ++fi) {
        const Fixup& f = fixups[fi];
        std::vector<uint8_t>* v = sec_vec(f.sec);
        if (!v) return fail("fixup into a zerofill section (__bss)");
        const size_t need = (f.kind == Fix::Ptr64) ? 8 : 4;
        if (f.off + need > v->size()) return fail("fixup offset out of range");
        const uint64_t pc = sec_vmaddr(f.sec) + f.off;

        // Where does this fixup point?
        uint64_t target = 0;
        bool bind_here = false;         // Ptr64 to an undefined external
        if (f.target.is_symbol()) {
            if (f.target.sym >= syms.size()) return fail("fixup names an unknown symbol");
            Symbol& s = syms[f.target.sym];
            if (s.defined) {
                target = sec_vmaddr(s.sec) + s.off;
            } else {
                switch (f.kind) {
                    case Fix::Branch26:
                        // Resolved below via fixup_veneer_off, which
                        // assign_veneers() always sets for an
                        // undefined Branch26 target -- `target` is
                        // unused for this (kind, undefined) pair.
                        break;
                    case Fix::GotAdrp21:
                    case Fix::GotLdrLo12:
                        break;          // handled below via got_index
                    case Fix::Ptr64:
                        bind_here = true;
                        break;
                    default:
                        return fail("fixup kind cannot reference the undefined symbol '"
                                    + s.name + "'");
                }
            }
            if (f.kind == Fix::GotAdrp21 || f.kind == Fix::GotLdrLo12) {
                if (s.got_index == kNoSym) return fail("no GOT slot for '" + s.name + "'");
                target = got_addr(s.got_index);
            }
        } else {
            if (!ref_address(f.target, &target)) return fail("unresolvable local fixup target");
        }
        if (!bind_here) target = uint64_t(int64_t(target) + f.addend);

        uint32_t w = 0;
        if (f.kind != Fix::Ptr64) std::memcpy(&w, v->data() + f.off, 4);

        switch (f.kind) {
            case Fix::Branch26: {
                const uint64_t veneer_off = fi < fixup_veneer_off.size()
                                                ? fixup_veneer_off[fi] : kNoVeneer;
                const uint64_t dest = (veneer_off != kNoVeneer)
                                           ? (text_vmaddr + veneer_off)
                                           : target;
                if (!patch_branch26(&w, int64_t(dest) - int64_t(pc))) {
                    // assign_veneers() already verified this call site
                    // either reaches `target` directly or reaches its
                    // assigned pool, both within kBranchMax -- reaching
                    // here means the two range checks disagree, which
                    // is an internal bug, not a reachable user-facing
                    // failure. Reported rather than silently
                    // mis-branched either way.
                    char msg[256];
                    const char* nm = f.target.is_symbol()
                                     ? syms[f.target.sym].name.c_str() : "<local>";
                    std::snprintf(msg, sizeof(msg),
                        "internal error: B/BL to '%s' is %+lld bytes away "
                        "(beyond +/-128 MiB) after assign_veneers() judged "
                        "it reachable -- veneer_off=%s",
                        nm, (long long)(int64_t(dest) - int64_t(pc)),
                        veneer_off != kNoVeneer ? "set" : "kNoVeneer");
                    return fail(msg);
                }
                break;
            }
            case Fix::Adrp21:
            case Fix::GotAdrp21:
                if (!patch_adrp(&w, pc, target)) return fail("ADRP target out of +/-4 GiB range");
                break;
            case Fix::AddLo12:
                patch_add_lo12(&w, target);
                break;
            case Fix::LdrLo12:
                if (!patch_ldr_lo12(&w, target, f.scale))
                    return fail("LDR/STR imm12 unencodable (check Fixup::scale)");
                break;
            case Fix::GotLdrLo12:
                if (!patch_ldr_lo12(&w, target, 8))
                    return fail("GOT LDR imm12 unencodable");
                break;
            case Fix::Delta32: {
                const int64_t d = int64_t(target) - int64_t(pc);
                if (d < -(int64_t(1) << 31) || d >= (int64_t(1) << 31))
                    return fail("Delta32 does not fit in 32 bits");
                const int32_t d32 = int32_t(d);
                std::memcpy(v->data() + f.off, &d32, 4);
                continue;
            }
            case Fix::Ptr64: {
                if (f.sec != Sec::Data)
                    return fail("Ptr64 must live in Sec::Data -- __TEXT is read-only "
                                "and cannot be rebased or bound; use Delta32 for a "
                                "jump table in Sec::Const");
                const uint64_t val = bind_here ? 0 : target;
                std::memcpy(v->data() + f.off, &val, 8);
                continue;
            }
        }
        std::memcpy(v->data() + f.off, &w, 4);
    }
    return true;
}

// ----------------------------------------------------------------------
// 6. emit -- __LINKEDIT, load commands, the file, codesign.
// ----------------------------------------------------------------------
bool MachOLinker::Impl::emit(const std::string& out_path, std::string* err) {
    auto fail = [&](const std::string& m) { *err = m; return false; };

    // ---- symbol ordering. LC_DYSYMTAB requires locals, then external
    // defined, then undefined, each contiguous.
    std::vector<uint32_t> locals, extdef, undefs;
    for (uint32_t i = 0; i < syms.size(); ++i) {
        if (!syms[i].defined) undefs.push_back(i);
        else if (syms[i].exported) extdef.push_back(i);
        else locals.push_back(i);
    }
    uint32_t next = 0;
    for (uint32_t i : locals) syms[i].sym_index = next++;
    for (uint32_t i : extdef) syms[i].sym_index = next++;
    for (uint32_t i : undefs) syms[i].sym_index = next++;

    // ---- string table + nlist array.
    // nlist n_sect is a 1-based index over ALL sections in load-command
    // order, and sections are emitted conditionally (an empty __const or
    // __bss is skipped entirely), so the numbering has to be derived
    // from the same presence tests the load commands use. Computed once
    // here rather than per symbol.
    uint8_t sect_no[4] = {0, 0, 0, 0};   // indexed by Sec
    {
        uint8_t n = 0;
        sect_no[size_t(Sec::Text)] = ++n;                  // __text
        if (!cnst.empty()) sect_no[size_t(Sec::Const)] = ++n;
        if (!got_syms.empty()) ++n;                        // __got
        if (!inits.empty()) ++n;                           // __modinit
        if (!data.empty()) sect_no[size_t(Sec::Data)] = ++n;
        if (bss_size)      sect_no[size_t(Sec::Bss)]  = ++n;
    }

    Buf strtab;
    strtab.u8(0);
    Buf nlist;
    auto emit_nlist = [&](const Symbol& s) {
        struct nlist_64 nl{};
        nl.n_un.n_strx = uint32_t(strtab.size());
        strtab.cstr("_" + s.name);
        if (s.defined) {
            nl.n_type = uint8_t(N_SECT | (s.exported ? N_EXT : 0));
            nl.n_sect = sect_no[size_t(s.sec)];
            nl.n_value = sec_vmaddr(s.sec) + s.off;
        } else {
            nl.n_type = N_UNDF | N_EXT;
            nl.n_sect = NO_SECT;
            // <mach-o/nlist.h>: the library ordinal lives in the high
            // byte of n_desc (SET_LIBRARY_ORDINAL), and
            // DYNAMIC_LOOKUP_ORDINAL (0xfe) marks a symbol looked up
            // flat at run time -- which is legal in, and only meaningful
            // for, a two-level-namespace image.
            const uint16_t ord = s.dep_ordinal ? s.dep_ordinal
                               : (s.in_shim ? 1u : uint16_t(DYNAMIC_LOOKUP_ORDINAL));
            nl.n_desc = uint16_t(ord << 8);
            // bind_to_dependency() binds are weak references (N_WEAK_REF,
            // <mach-o/nlist.h>): a missing export binds 0, never fails dlopen.
            if (s.dep_ordinal) nl.n_desc = uint16_t(nl.n_desc | N_WEAK_REF);
            nl.n_value = 0;
        }
        nlist.u32(nl.n_un.n_strx);
        nlist.u8(nl.n_type);
        nlist.u8(nl.n_sect);
        nlist.u16(nl.n_desc);
        nlist.u64(nl.n_value);
    };
    for (uint32_t i : locals) emit_nlist(syms[i]);
    for (uint32_t i : extdef) emit_nlist(syms[i]);
    for (uint32_t i : undefs) emit_nlist(syms[i]);
    const uint32_t nsyms = uint32_t(syms.size());

    // ---- indirect symbol table.
    // <mach-o/loader.h>: "For each of the entries in the section the
    // indirect symbol table entries, in corresponding order in the
    // indirect symbol table, start at the index stored in the
    // reserved1 field of the section structure." __got is the only
    // section left that uses this (veneer pools are plain __text, not
    // S_SYMBOL_STUBS -- see macho_link.h deviation 4), so its
    // reserved1 is simply 0.
    Buf indirect;
    for (uint32_t si : got_syms) indirect.u32(syms[si].sym_index);
    const uint32_t nindirect = uint32_t(got_syms.size());

    // ---- rebase stream: __modinit pointers + internal Ptr64s in __data.
    // Both live in __DATA, segment index 1 (__TEXT=0, __DATA=1,
    // __LINKEDIT=2), and the opcode's operand is the offset from that
    // segment's load address (dyld, ImageLoaderMachOCompressed.cpp:
    // "address = segActualLoadAddress(segmentIndex) + read_uleb128").
    constexpr uint8_t kDataSeg = 1;
    std::vector<uint64_t> rebase_offs;
    for (size_t i = 0; i < inits.size(); ++i)
        rebase_offs.push_back((modinit_off - data_fileoff) + i * 8);
    for (const auto& f : fixups) {
        if (f.kind != Fix::Ptr64 || f.sec != Sec::Data) continue;
        const bool external = f.target.is_symbol()
                              && f.target.sym < syms.size()
                              && !syms[f.target.sym].defined;
        if (!external) rebase_offs.push_back((data_sec_off - data_fileoff) + f.off);
    }
    std::sort(rebase_offs.begin(), rebase_offs.end());
    rebase_offs.erase(std::unique(rebase_offs.begin(), rebase_offs.end()),
                      rebase_offs.end());
    // Encode the (sorted, deduped) slot list, coalescing each run of
    // 8-strided slots into one DO_REBASE. Called again below if GOT
    // slots for defined symbols have to be folded in.
    Buf rebase;
    auto encode_rebase = [&]() {
        rebase.b.clear();
        if (rebase_offs.empty()) return;
        rebase.u8(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
        size_t i = 0;
        while (i < rebase_offs.size()) {
            size_t j = i + 1;
            while (j < rebase_offs.size() && rebase_offs[j] == rebase_offs[j - 1] + 8) ++j;
            const size_t count = j - i;
            rebase.u8(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | kDataSeg);
            uleb(rebase, rebase_offs[i]);
            if (count <= 15) {
                rebase.u8(uint8_t(REBASE_OPCODE_DO_REBASE_IMM_TIMES | count));
            } else {
                rebase.u8(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
                uleb(rebase, count);
            }
            i = j;
        }
        rebase.u8(REBASE_OPCODE_DONE);
    };
    encode_rebase();
    res.rebases = rebase_offs.size();

    // ---- bind stream: every __got slot, plus any Ptr64 in __data that
    // names an undefined external.
    Buf bind;
    auto emit_bind_ordinal = [&](const Symbol& s) {
        if (s.dep_ordinal) {
            // <mach-o/loader.h>: BIND_OPCODE_SET_DYLIB_ORDINAL_IMM carries a
            // 4-bit ordinal; larger ones need the ULEB form.
            if (s.dep_ordinal <= 15) {
                bind.u8(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | uint8_t(s.dep_ordinal));
            } else {
                bind.u8(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
                uleb(bind, s.dep_ordinal);
            }
            ++res.binds_two_level;
        } else if (s.in_shim) {
            bind.u8(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1);
            ++res.binds_two_level;
        } else {
            // dyld, ImageLoaderMachOCompressed.cpp, eachBind():
            //   case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            //       // the special ordinals are negative numbers
            //       if ( immediate == 0 ) libraryOrdinal = 0;
            //       else { int8_t signExtended = BIND_OPCODE_MASK | immediate;
            //              libraryOrdinal = signExtended; }
            // BIND_OPCODE_MASK is 0xF0, so the 4-bit immediate for
            // BIND_SPECIAL_DYLIB_FLAT_LOOKUP (-2) is 0xE: 0xF0|0xE ==
            // 0xFE == -2 as int8_t. Writing the ordinal itself here
            // would silently mean "ordinal 14".
            bind.u8(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
                    | uint8_t(BIND_SPECIAL_DYLIB_FLAT_LOOKUP & 0x0F));
            ++res.binds_flat;
        }
    };
    auto emit_bind = [&](const Symbol& s, uint64_t seg_off) {
        emit_bind_ordinal(s);
        bind.u8(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                | (s.dep_ordinal ? BIND_SYMBOL_FLAGS_WEAK_IMPORT : 0));
        bind.cstr("_" + s.name);
        bind.u8(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        bind.u8(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | kDataSeg);
        uleb(bind, seg_off);
        bind.u8(BIND_OPCODE_DO_BIND);
    };
    for (size_t i = 0; i < got_syms.size(); ++i) {
        const Symbol& s = syms[got_syms[i]];
        if (s.defined) continue;      // a defined symbol's slot is rebased below
        emit_bind(s, (got_off - data_fileoff) + i * 8);
    }
    for (const auto& f : fixups) {
        if (f.kind != Fix::Ptr64 || f.sec != Sec::Data) continue;
        if (!f.target.is_symbol() || f.target.sym >= syms.size()) continue;
        const Symbol& s = syms[f.target.sym];
        if (s.defined) continue;
        emit_bind(s, (data_sec_off - data_fileoff) + f.off);
    }
    if (bind.size()) bind.u8(BIND_OPCODE_DONE);

    // A GOT slot for a DEFINED symbol holds an image address, so it
    // needs a rebase rather than a bind. Fold those in (rare, but a
    // producer may legitimately route an internal call through the GOT).
    {
        std::vector<uint64_t> extra;
        for (size_t i = 0; i < got_syms.size(); ++i)
            if (syms[got_syms[i]].defined)
                extra.push_back((got_off - data_fileoff) + i * 8);
        if (!extra.empty()) {
            rebase_offs.insert(rebase_offs.end(), extra.begin(), extra.end());
            std::sort(rebase_offs.begin(), rebase_offs.end());
            rebase_offs.erase(std::unique(rebase_offs.begin(), rebase_offs.end()),
                              rebase_offs.end());
            encode_rebase();
            res.rebases = rebase_offs.size();
        }
    }

    // ---- export trie.
    std::vector<TrieEntry> trie_entries;
    trie_entries.reserve(extdef.size());
    for (uint32_t i : extdef)
        trie_entries.push_back(TrieEntry{"_" + syms[i].name,
                                         sec_vmaddr(syms[i].sec) + syms[i].off});
    std::vector<uint8_t> export_blob = ExportTrie(trie_entries).serialize();

    // ---- assemble __LINKEDIT.
    const uint64_t linkedit_fileoff = data_fileoff + data_filesize;
    const uint64_t linkedit_vmaddr  = data_vmaddr + data_vmsize;
    Buf le;
    auto le_off = [&](size_t local) -> uint32_t {
        return uint32_t(linkedit_fileoff + local);
    };
    const uint32_t rebase_off = le_off(le.size());
    le.bytes(rebase.b.data(), rebase.b.size());
    const uint32_t rebase_sz = uint32_t(rebase.size());
    le.align(8);
    const uint32_t bind_off = le_off(le.size());
    le.bytes(bind.b.data(), bind.b.size());
    const uint32_t bind_sz = uint32_t(bind.size());
    le.align(8);
    const uint32_t export_off = le_off(le.size());
    le.bytes(export_blob.data(), export_blob.size());
    const uint32_t export_sz = uint32_t(export_blob.size());
    le.align(8);
    const uint32_t symoff = le_off(le.size());
    le.bytes(nlist.b.data(), nlist.b.size());
    le.align(8);
    const uint32_t indirectsymoff = le_off(le.size());
    le.bytes(indirect.b.data(), indirect.b.size());
    le.align(8);
    const uint32_t stroff = le_off(le.size());
    le.bytes(strtab.b.data(), strtab.b.size());
    const uint32_t strsize = uint32_t(strtab.size());
    le.align(8);
    const uint64_t linkedit_filesize = round_up(le.size(), kPageSize);

    // ---- mach header + load commands.
    Buf hdr;
    hdr.u32(MH_MAGIC_64);
    hdr.u32(uint32_t(CPU_TYPE_ARM64));
    hdr.u32(uint32_t(CPU_SUBTYPE_ARM64_ALL));
    hdr.u32(MH_DYLIB);
    hdr.u32(ncmds);
    hdr.u32(sizeofcmds);
    hdr.u32(MH_DYLDLINK | MH_TWOLEVEL | MH_NO_REEXPORTED_DYLIBS);
    hdr.u32(0);

    auto emit_sect = [&](const char* sn, const char* sg, uint64_t addr,
                         uint64_t size, uint32_t off, uint32_t align_pow2,
                         uint32_t flags, uint32_t r1, uint32_t r2) {
        char s[16] = {0}; std::strncpy(s, sn, 16); hdr.bytes(s, 16);
        char g[16] = {0}; std::strncpy(g, sg, 16); hdr.bytes(g, 16);
        hdr.u64(addr);
        hdr.u64(size);
        hdr.u32(off);
        hdr.u32(align_pow2);
        hdr.u32(0);            // reloff  (fully resolved; no relocs shipped)
        hdr.u32(0);            // nreloc
        hdr.u32(flags);
        hdr.u32(r1);
        hdr.u32(r2);
        hdr.u32(0);            // reserved3
    };

    // __TEXT
    {
        hdr.u32(LC_SEGMENT_64);
        hdr.u32(uint32_t(sizeof(struct segment_command_64)
                         + text_nsects * sizeof(struct section_64)));
        char nm[16] = {0}; std::strncpy(nm, "__TEXT", 16); hdr.bytes(nm, 16);
        hdr.u64(0);                       // vmaddr: the header lives here
        hdr.u64(text_filesize);
        hdr.u64(0);                       // fileoff
        hdr.u64(text_filesize);
        hdr.u32(VM_PROT_READ | VM_PROT_EXECUTE);
        hdr.u32(VM_PROT_READ | VM_PROT_EXECUTE);
        hdr.u32(text_nsects);
        hdr.u32(0);
        // __text carries every veneer pool too (see macho_link.h,
        // "BRANCH ISLANDS / VENEER POOLS") -- there is no separate
        // __stubs section to emit; S_ATTR_SOME_INSTRUCTIONS already
        // covers a section that mixes translated code and veneers.
        emit_sect("__text", "__TEXT", text_vmaddr, text_size,
                  uint32_t(text_sec_off), 2,
                  S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS, 0, 0);
        if (!cnst.empty()) {
            emit_sect("__const", "__TEXT", const_vmaddr, cnst.size(),
                      uint32_t(const_off), 4, S_REGULAR, 0, 0);
        }
    }
    // __DATA
    {
        hdr.u32(LC_SEGMENT_64);
        hdr.u32(uint32_t(sizeof(struct segment_command_64)
                         + data_nsects * sizeof(struct section_64)));
        char nm[16] = {0}; std::strncpy(nm, "__DATA", 16); hdr.bytes(nm, 16);
        hdr.u64(data_vmaddr);
        hdr.u64(data_vmsize);
        hdr.u64(data_fileoff);
        hdr.u64(data_filesize);
        hdr.u32(VM_PROT_READ | VM_PROT_WRITE);
        hdr.u32(VM_PROT_READ | VM_PROT_WRITE);
        hdr.u32(data_nsects);
        hdr.u32(0);
        if (!got_syms.empty()) {
            // reserved1 = 0: __got is the only indirect-symbol-table
            // user now that veneer pools have replaced __stubs.
            emit_sect("__got", "__DATA", got_vmaddr, got_syms.size() * 8,
                      uint32_t(got_off), 3, S_NON_LAZY_SYMBOL_POINTERS,
                      0, 0);
        }
        if (!inits.empty()) {
            emit_sect("__modinit", "__DATA", modinit_vmaddr, inits.size() * 8,
                      uint32_t(modinit_off), 3, S_MOD_INIT_FUNC_POINTERS, 0, 0);
        }
        if (!data.empty()) {
            emit_sect("__data", "__DATA", data_sec_vmaddr, data.size(),
                      uint32_t(data_sec_off), 3, S_REGULAR, 0, 0);
        }
        if (bss_size) {
            emit_sect("__bss", "__DATA", bss_vmaddr, bss_size, 0, 3, S_ZEROFILL, 0, 0);
        }
    }
    // __LINKEDIT
    {
        hdr.u32(LC_SEGMENT_64);
        hdr.u32(uint32_t(sizeof(struct segment_command_64)));
        char nm[16] = {0}; std::strncpy(nm, "__LINKEDIT", 16); hdr.bytes(nm, 16);
        hdr.u64(linkedit_vmaddr);
        hdr.u64(linkedit_filesize);
        hdr.u64(linkedit_fileoff);
        hdr.u64(linkedit_filesize);
        hdr.u32(VM_PROT_READ);
        hdr.u32(VM_PROT_READ);
        hdr.u32(0);
        hdr.u32(0);
    }
    // LC_DYLD_INFO_ONLY
    {
        hdr.u32(LC_DYLD_INFO_ONLY);
        hdr.u32(uint32_t(sizeof(struct dyld_info_command)));
        hdr.u32(rebase_sz ? rebase_off : 0); hdr.u32(rebase_sz);
        hdr.u32(bind_sz ? bind_off : 0);     hdr.u32(bind_sz);
        hdr.u32(0); hdr.u32(0);              // weak bind
        hdr.u32(0); hdr.u32(0);              // lazy bind (deviation 1)
        hdr.u32(export_sz ? export_off : 0); hdr.u32(export_sz);
    }
    // LC_SYMTAB
    {
        hdr.u32(LC_SYMTAB);
        hdr.u32(uint32_t(sizeof(struct symtab_command)));
        hdr.u32(symoff);
        hdr.u32(nsyms);
        hdr.u32(stroff);
        hdr.u32(strsize);
    }
    // LC_DYSYMTAB
    {
        hdr.u32(LC_DYSYMTAB);
        hdr.u32(uint32_t(sizeof(struct dysymtab_command)));
        hdr.u32(0);                                   // ilocalsym
        hdr.u32(uint32_t(locals.size()));             // nlocalsym
        hdr.u32(uint32_t(locals.size()));             // iextdefsym
        hdr.u32(uint32_t(extdef.size()));             // nextdefsym
        hdr.u32(uint32_t(locals.size() + extdef.size()));  // iundefsym
        hdr.u32(uint32_t(undefs.size()));             // nundefsym
        hdr.u32(0); hdr.u32(0);                       // toc
        hdr.u32(0); hdr.u32(0);                       // modtab
        hdr.u32(0); hdr.u32(0);                       // extrefsyms
        hdr.u32(nindirect ? indirectsymoff : 0);
        hdr.u32(nindirect);
        hdr.u32(0); hdr.u32(0);                       // extrel
        hdr.u32(0); hdr.u32(0);                       // locrel
    }
    auto emit_dylib_lc = [&](uint32_t cmd, const std::string& path) {
        const uint32_t cmdsize = uint32_t(round_up(24 + path.size() + 1, 8));
        hdr.u32(cmd);
        hdr.u32(cmdsize);
        hdr.u32(24);                  // name.offset
        hdr.u32(1);                   // timestamp
        hdr.u32(0);                   // current_version
        hdr.u32(0);                   // compatibility_version
        const size_t start = hdr.size();
        hdr.cstr(path);
        hdr.pad_to(start + (cmdsize - 24));
    };
    emit_dylib_lc(LC_ID_DYLIB, opt.install_name);
    emit_dylib_lc(LC_LOAD_DYLIB, opt.shim_install_name);
    emit_dylib_lc(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib");
    // Cross-guest-library linking (2026-07-28): sibling guest dylibs this
    // module's own resolver decided it needs (main.cpp's ELF-based sibling
    // scan; see docs/cross-guest-library-linking_2026-07-28.md). Emitted
    // AFTER the shim so ordinal 1 (the shim, relied on by
    // resolve_ordinals()/emit_bind_ordinal) is undisturbed; nothing binds
    // to these by explicit ordinal -- their exports simply need to be
    // loaded into the flat namespace before this image's own binds run,
    // which a plain LC_LOAD_DYLIB dependency edge guarantees regardless of
    // ordinal position.
    for (const auto& dep : extra_deps) emit_dylib_lc(LC_LOAD_DYLIB, dep);
    auto emit_rpath_lc = [&](const std::string& path) {
        const uint32_t cmdsize = uint32_t(round_up(12 + path.size() + 1, 8));
        hdr.u32(LC_RPATH);
        hdr.u32(cmdsize);
        hdr.u32(12);                  // path.offset
        const size_t start = hdr.size();
        hdr.cstr(path);
        hdr.pad_to(start + (cmdsize - 12));
    };
    emit_rpath_lc("@loader_path");
    if (!opt.shim_dir.empty()) emit_rpath_lc(opt.shim_dir);
    // LC_BUILD_VERSION -- matches the incumbent's
    // `-platform_version macos 12.0 12.0`.
    {
        hdr.u32(LC_BUILD_VERSION);
        hdr.u32(uint32_t(sizeof(struct build_version_command)));
        hdr.u32(PLATFORM_MACOS);
        hdr.u32(0x000C0000);          // minos 12.0
        hdr.u32(0x000C0000);          // sdk   12.0
        hdr.u32(0);                   // ntools
    }
    // LC_UUID -- deterministic FNV-1a over the code + symbol count, so
    // rebuilding the same input yields the same build id.
    {
        uint8_t uuid[16] = {0};
        uint64_t h = 1469598103934665603ull;
        for (uint8_t c : text) { h ^= c; h *= 1099511628211ull; }
        for (uint8_t c : cnst) { h ^= c; h *= 1099511628211ull; }
        const uint64_t h2 = h ^ (uint64_t(syms.size()) * 1099511628211ull);
        for (int i = 0; i < 8; ++i) uuid[i]     = uint8_t(h >> (8 * i));
        for (int i = 0; i < 8; ++i) uuid[8 + i] = uint8_t(h2 >> (8 * i));
        uuid[6] = uint8_t((uuid[6] & 0x0f) | 0x40);   // RFC-4122 version 4
        uuid[8] = uint8_t((uuid[8] & 0x3f) | 0x80);   // variant
        hdr.u32(LC_UUID);
        hdr.u32(uint32_t(sizeof(struct uuid_command)));
        hdr.bytes(uuid, 16);
    }

    if (hdr.size() != lc_end) {
        char msg[160];
        std::snprintf(msg, sizeof(msg),
            "internal error: LC region %zu bytes but %llu reserved",
            hdr.size(), (unsigned long long)lc_end);
        return fail(msg);
    }

    // ---- serialise the file image.
    std::vector<uint8_t> file;
    file.reserve(size_t(linkedit_fileoff + linkedit_filesize));
    file.insert(file.end(), hdr.b.begin(), hdr.b.end());
    file.resize(size_t(text_sec_off), 0);
    // `text` already contains every veneer pool (the producer's own
    // reserve_veneer_pool() calls, or write()'s tail fallback, appended
    // them before patch() ran) -- one insert covers translated code and
    // every veneer together. resize() to const_off below zero-pads any
    // rounding gap between text.size() and text_size/const_off; no
    // separate islands/stubs splice is needed any more.
    file.insert(file.end(), text.begin(), text.end());
    file.resize(size_t(const_off), 0);
    file.insert(file.end(), cnst.begin(), cnst.end());
    file.resize(size_t(text_filesize), 0);
    // __DATA. __got starts zeroed (dyld binds it); __modinit holds the
    // pre-slide initialiser addresses (the rebase adds the slide).
    file.resize(size_t(got_off), 0);
    for (size_t i = 0; i < got_syms.size(); ++i) {
        const Symbol& s = syms[got_syms[i]];
        uint64_t v = 0;
        if (s.defined) v = sec_vmaddr(s.sec) + s.off;
        for (int k = 0; k < 8; ++k) file.push_back(uint8_t(v >> (8 * k)));
    }
    file.resize(size_t(modinit_off), 0);
    for (const Ref& r : inits) {
        uint64_t a = 0;
        if (!ref_address(r, &a)) return fail("initialiser references an undefined symbol");
        for (int k = 0; k < 8; ++k) file.push_back(uint8_t(a >> (8 * k)));
    }
    file.resize(size_t(data_sec_off), 0);
    file.insert(file.end(), data.begin(), data.end());
    file.resize(size_t(data_fileoff + data_filesize), 0);
    file.resize(size_t(linkedit_fileoff), 0);
    file.insert(file.end(), le.b.begin(), le.b.end());
    file.resize(size_t(linkedit_fileoff + linkedit_filesize), 0);

    // MACAPK_XLAT_ATOMIC_WRITE: write + sign a staged copy with the same
    // basename, publish it with one rename (see AtomicOutputFile in
    // macho_link.h). Gate off: wpath IS out_path, and the ofstream +
    // in-place codesign below are the pre-change path byte for byte.
    AtomicOutputFile out(out_path);
    const std::string& wpath = out.write_path();
    {
        std::ofstream f(wpath, std::ios::binary | std::ios::trunc);
        if (!f) return fail("cannot open " + wpath + " for write");
        f.write(reinterpret_cast<const char*>(file.data()), std::streamsize(file.size()));
        if (!f.good()) return fail("write failed for " + wpath);
    }

    // Sum veneer counts across every pool: `stubs` = GOT-relative
    // (undefined-symbol) entries, `islands` = direct-address (defined,
    // out-of-range) entries. Same pre-2026-07-28 field meaning as a
    // single-section count, just now summed over however many pools
    // write() ended up with.
    size_t n_stub_veneers = 0, n_island_veneers = 0;
    for (const auto& pool : veneer_pools)
        for (const auto& kv : pool.slot)
            (syms[kv.first].defined ? n_island_veneers : n_stub_veneers)++;

    res.file_bytes    = file.size();
    res.text_bytes    = text_size;
    res.stubs         = n_stub_veneers;
    res.got_slots     = got_syms.size();
    res.indirect      = nindirect;
    res.islands       = n_island_veneers;
    res.veneer_pools  = veneer_pools.size();
    res.exports       = extdef.size();
    res.locals        = locals.size();
    res.undefs        = undefs.size();
    res.extra_deps    = extra_deps.size();

    // ---- ad-hoc sign. codesign ships with base macOS (no Xcode), and
    // an unsigned arm64 dylib will not load on Apple Silicon.
    // Signed BEFORE the publish rename, so the final path never holds an
    // unsigned image (which dlopen refuses on Apple Silicon).
    if (opt.adhoc_sign) {
        std::string q = "'";
        for (char c : wpath) { if (c == '\'') q += "'\\''"; else q += c; }
        q += "'";
        const std::string cmd = "codesign -f -s - " + q + " 2>&1";
        const int rc = std::system(cmd.c_str());
        if (rc != 0) {
            char msg[128];
            std::snprintf(msg, sizeof(msg), "codesign failed (rc=%d)", rc);
            return fail(msg);
        }
    }
    std::string cerr;
    if (!out.commit(&cerr)) return fail(cerr);
    return true;
}

// ======================================================================
// Public surface
// ======================================================================

MachOLinker::MachOLinker(LinkOptions opts) : p_(new Impl) {
    p_->opt = std::move(opts);
}
MachOLinker::~MachOLinker() = default;

namespace {
uint64_t append(std::vector<uint8_t>& v, const void* p, size_t n, size_t align) {
    while (align && v.size() % align) v.push_back(0);
    const uint64_t off = v.size();
    if (p && n) {
        const uint8_t* s = static_cast<const uint8_t*>(p);
        v.insert(v.end(), s, s + n);
    } else if (n) {
        v.insert(v.end(), n, uint8_t(0));
    }
    return off;
}
}  // namespace

uint64_t MachOLinker::add_text(const void* p, size_t n, size_t align) {
    return append(p_->text, p, n, align);
}
uint64_t MachOLinker::add_const(const void* p, size_t n, size_t align) {
    return append(p_->cnst, p, n, align);
}
uint64_t MachOLinker::add_data(const void* p, size_t n, size_t align) {
    return append(p_->data, p, n, align);
}
uint64_t MachOLinker::add_bss(size_t n, size_t align) {
    if (align) p_->bss_size = round_up(p_->bss_size, align);
    const uint64_t off = p_->bss_size;
    p_->bss_size += n;
    return off;
}

// A plain append -- exactly like add_text() -- so it can never
// invalidate an offset any earlier call already handed back. See
// macho_link.h, "BRANCH ISLANDS / VENEER POOLS".
uint64_t MachOLinker::Impl::reserve_pool(uint64_t capacity) {
    capacity = round_up_any(capacity, kVeneerSlotSize);
    const uint64_t off = append(text, nullptr, size_t(capacity), 4);
    VeneerPool pool;
    pool.text_off = off;
    pool.capacity = capacity;
    veneer_pools.push_back(pool);
    return off;
}

uint64_t MachOLinker::reserve_veneer_pool(uint64_t capacity_bytes) {
    return p_->reserve_pool(capacity_bytes);
}

uint64_t MachOLinker::text_size_hint() const { return p_->text.size(); }

uint8_t* MachOLinker::mutable_bytes(Sec sec, uint64_t off, size_t n) {
    std::vector<uint8_t>* v = p_->sec_vec(sec);
    if (!v || off + n > v->size()) return nullptr;
    return v->data() + off;
}

uint32_t MachOLinker::define(std::string name, Sec sec, uint64_t off, bool exported) {
    // A name may have been forward-referenced by undefined(); upgrade
    // that entry in place so both sides share one symbol index.
    auto it = p_->sym_by_name.find(name);
    if (it != p_->sym_by_name.end()) {
        Symbol& s = p_->syms[it->second];
        if (!s.defined) {
            s.defined = true;
            s.exported = exported;
            s.sec = sec;
            s.off = off;
        }
        return it->second;
    }
    Symbol s;
    s.name = std::move(name);
    s.defined = true;
    s.exported = exported;
    s.sec = sec;
    s.off = off;
    p_->syms.push_back(std::move(s));
    const uint32_t idx = uint32_t(p_->syms.size() - 1);
    p_->sym_by_name.emplace(p_->syms[idx].name, idx);
    return idx;
}

uint32_t MachOLinker::undefined(const std::string& name) {
    auto it = p_->sym_by_name.find(name);
    if (it != p_->sym_by_name.end()) return it->second;
    Symbol s;
    s.name = name;
    p_->syms.push_back(std::move(s));
    const uint32_t idx = uint32_t(p_->syms.size() - 1);
    p_->sym_by_name.emplace(name, idx);
    return idx;
}

bool MachOLinker::has_symbol(const std::string& name) const {
    return p_->sym_by_name.find(name) != p_->sym_by_name.end();
}

void MachOLinker::add_fixup(const Fixup& f) { p_->fixups.push_back(f); }

void MachOLinker::branch(Sec sec, uint64_t off, uint32_t sym) {
    Fixup f;
    f.kind = Fix::Branch26;
    f.sec = sec;
    f.off = off;
    f.target = Ref::symbol(sym);
    p_->fixups.push_back(f);
}

void MachOLinker::adrp_add_pair(Sec sec, uint64_t adrp_off, uint64_t add_off, Ref target) {
    Fixup a;
    a.kind = Fix::Adrp21; a.sec = sec; a.off = adrp_off; a.target = target;
    p_->fixups.push_back(a);
    Fixup b;
    b.kind = Fix::AddLo12; b.sec = sec; b.off = add_off; b.target = target;
    p_->fixups.push_back(b);
}

void MachOLinker::add_initializer(Ref fn) { p_->inits.push_back(fn); }

void MachOLinker::bind_to_dependency(const std::string& name,
                                     const std::string& install_name) {
    if (name.empty() || install_name.empty()) return;
    p_->two_level_dep[name] = install_name;
}

void MachOLinker::add_dependency(std::string install_name) {
    if (install_name.empty()) return;
    for (const auto& d : p_->extra_deps)
        if (d == install_name) return;         // already registered
    p_->extra_deps.push_back(std::move(install_name));
}

LinkResult MachOLinker::write(const std::string& out_path) {
    Impl& I = *p_;
    I.res = LinkResult{};

    I.plan();
    I.resolve_ordinals();

    // Guarantee at least one veneer pool exists, at the current tail
    // of __text, for a producer that never called
    // reserve_veneer_pool() itself (every caller before 2026-07-28,
    // and every module comfortably under the range limit). This is
    // byte-for-byte the old single-shared-region behavior. See
    // macho_link.h, P5 and "BRANCH ISLANDS / VENEER POOLS".
    if (I.veneer_pools.empty()) I.reserve_pool(kVeneerPoolCapacityBytes);

    // Every veneer pool is already IN `text` and fully sized by this
    // point (the producer is done emitting text, and the fallback
    // above just ran), so unlike the pre-2026-07-28 design there is no
    // more chicken-and-egg between "how big is __text" and "how many
    // veneers does it need" -- this is a straight line, not a
    // fixed-point loop.
    I.layout();

    std::string err;
    if (!I.assign_veneers(&err)) { I.res.error = err; return I.res; }
    // MACAPK_ARM32RC_TRIM_VENEER_TAIL: see macho_link.h at write() and
    // Impl::trim_tail_pool(). Off (=0) leaves this exact pre-change line
    // sequence: layout -> assign_veneers -> patch -> emit.
    if (gate_on("MACAPK_ARM32RC_TRIM_VENEER_TAIL")) {
        std::string why_not;
        uint64_t cut = 0;
        if (!I.trim_tail_pool(&cut, &why_not)) {
            I.res.error = "veneer tail trim: " + why_not;
            return I.res;
        }
        I.res.veneer_tail_trimmed = cut;
        if (!cut && !why_not.empty())
            std::fprintf(stderr, "[macho_link] veneer tail NOT trimmed: %s\n",
                         why_not.c_str());
    }
    if (!I.patch(&err)) { I.res.error = err; return I.res; }
    if (!I.emit(out_path, &err)) { I.res.error = err; return I.res; }

    I.res.ok = true;
    if (I.opt.verbose) {
        std::fprintf(stderr,
            "[macho_link] %s: %zu exports, %zu locals, %zu undefs "
            "(%zu two-level / %zu flat), %zu stubs, %zu got, %zu indirect, "
            "%zu islands, %zu veneer pool(s), %zu rebases, %zu extra dep(s), "
            "%llu bytes\n",
            out_path.c_str(), I.res.exports, I.res.locals, I.res.undefs,
            I.res.binds_two_level, I.res.binds_flat, I.res.stubs,
            I.res.got_slots, I.res.indirect, I.res.islands,
            I.res.veneer_pools, I.res.rebases, I.res.extra_deps,
            (unsigned long long)I.res.file_bytes);
        if (I.res.veneer_tail_trimmed)
            std::fprintf(stderr,
                "[macho_link] %s: veneer tail trimmed, %llu bytes\n",
                out_path.c_str(),
                (unsigned long long)I.res.veneer_tail_trimmed);
    }
    return I.res;
}

// ======================================================================
// AtomicOutputFile (MACAPK_XLAT_ATOMIC_WRITE / MACAPK_XLAT_STAMP_INVALIDATE).
// The contract and the reasons are in macho_link.h; this is the mechanism.
// ======================================================================
namespace {

constexpr char kStagePrefix[] = ".macapk-xlat.";

std::string dir_of(const std::string& p) {
    const size_t s = p.rfind('/');
    if (s == std::string::npos) return ".";
    if (s == 0) return "/";
    return p.substr(0, s);
}

std::string base_of(const std::string& p) {
    const size_t s = p.rfind('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

// A staging dir only ever holds the staged output (and whatever temporary
// codesign may leave next to it), so remove the plain files in it, then
// the dir. A subdirectory, which we never create, makes rmdir fail and the
// dir is left alone rather than recursed into.
void remove_stage_dir(const std::string& dir) {
    if (DIR* d = ::opendir(dir.c_str())) {
        while (const struct dirent* e = ::readdir(d)) {
            if (!std::strcmp(e->d_name, ".") || !std::strcmp(e->d_name, ".."))
                continue;
            ::unlink((dir + "/" + e->d_name).c_str());
        }
        ::closedir(d);
    }
    ::rmdir(dir.c_str());
}

// Reap staging dirs left by translators that were killed mid-write (a
// SIGKILL runs no destructor). The owner's pid is in the name; a dir is
// removed only when that pid no longer exists (kill(pid, 0) == ESRCH). A
// live pid -- including an unrelated process that reused it -- keeps its
// dir, which is the safe direction: it is reaped by a later run.
void reap_dead_stages(const std::string& dir) {
    DIR* d = ::opendir(dir.c_str());
    if (!d) return;
    std::vector<std::string> dead;
    const size_t plen = sizeof(kStagePrefix) - 1;
    while (const struct dirent* e = ::readdir(d)) {
        if (std::strncmp(e->d_name, kStagePrefix, plen) != 0) continue;
        const char* p = e->d_name + plen;
        char* endp = nullptr;
        const long pid = std::strtol(p, &endp, 10);
        if (endp == p || *endp != '.' || pid <= 0) continue;
        if (pid == long(::getpid())) continue;
        if (::kill(pid_t(pid), 0) == 0 || errno != ESRCH) continue;
        const std::string full = dir + "/" + e->d_name;
        struct stat st;
        if (::lstat(full.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        dead.push_back(full);
    }
    ::closedir(d);
    for (const auto& s : dead) remove_stage_dir(s);
}

std::string errno_text(const char* what, const std::string& path, int e) {
    return std::string(what) + " " + path + ": " + std::strerror(e);
}

}  // namespace

AtomicOutputFile::AtomicOutputFile(std::string final_path)
    : final_path_(std::move(final_path)), write_path_(final_path_) {
    if (!gate_on("MACAPK_XLAT_ATOMIC_WRITE")) return;
    struct stat st;
    if (::lstat(final_path_.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
        std::fprintf(stderr,
            "[xlat-out] %s is a symlink: writing in place (a rename would "
            "replace the link, not its target)\n", final_path_.c_str());
        return;
    }
    const std::string dir = dir_of(final_path_);
    reap_dead_stages(dir);
    std::string tmpl = dir + "/" + kStagePrefix + std::to_string(long(::getpid()))
                     + ".XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) {
        // Same directory the in-place write would need, so this is rare;
        // degrade to the pre-change behaviour instead of failing harder.
        std::fprintf(stderr,
            "[xlat-out] cannot stage next to %s (%s): writing in place\n",
            final_path_.c_str(), std::strerror(errno));
        return;
    }
    stage_dir_ = buf.data();
    write_path_ = stage_dir_ + "/" + base_of(final_path_);
    staged_ = true;
}

AtomicOutputFile::~AtomicOutputFile() {
    if (staged_ && !committed_) remove_stage_dir(stage_dir_);
}

bool AtomicOutputFile::commit(std::string* err) {
    if (!staged_ || committed_) return true;
    // 1. The staged bytes (as codesign left them) leave the host before
    //    the name that publishes them does.
    const int fd = ::open(write_path_.c_str(), O_RDONLY);
    if (fd < 0) {
        *err = errno_text("cannot reopen staged output", write_path_, errno);
        return false;
    }
    if (::fsync(fd) != 0) {
        const int e = errno;
        ::close(fd);
        *err = errno_text("fsync failed for", write_path_, e);
        return false;
    }
    ::close(fd);
    // 2. The stale stamp goes BEFORE the swap: from here until the loader
    //    re-stamps, no id vouches for whichever dylib is at the path.
    if (gate_on("MACAPK_XLAT_STAMP_INVALIDATE")) {
        const std::string stamp = final_path_ + ".nativeid";
        if (::unlink(stamp.c_str()) != 0 && errno != ENOENT) {
            // Leaving it would let it vouch for the new dylib; refuse the
            // swap so the (old stamp, old dylib) pair stays consistent.
            *err = errno_text("cannot invalidate stale stamp", stamp, errno);
            return false;
        }
    }
    // 3. Publish.
    if (::rename(write_path_.c_str(), final_path_.c_str()) != 0) {
        *err = errno_text("cannot publish staged output as", final_path_, errno);
        return false;
    }
    committed_ = true;
    // 4. Make the new directory entry durable too. Best effort: the file is
    //    already published and complete, so a failure here changes nothing
    //    a reader can see.
    const std::string dir = dir_of(final_path_);
    const int dfd = ::open(dir.c_str(), O_RDONLY);
    if (dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
    remove_stage_dir(stage_dir_);
    return true;
}

}  // namespace macapk::translator::arm32rc
