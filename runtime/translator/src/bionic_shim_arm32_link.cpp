// bionic_shim_arm32_link.cpp -- a Bionic-shaped load-time linker for ARM32
// DATA imports: relocations against an UNDEFINED symbol that has no PLT stub.
//
// WHY. elf_reader.cpp applies every relocation it can at translate time, but a
// data relocation against an undefined symbol names something another .so
// defines -- a sibling library of the app (OpenTTD libapplication.so's 1,311
// typeinfo vptrs point into libc++_shared.so) or an Android system library
// (`__stack_chk_guard`, `__sF`, `SL_IID_ENGINE`). Its address exists only at
// load time, so the translator used to leave the in-place word (A, or 0)
// there: 3,572 such sites in 226 of 246 ARM32 corpus libraries. Full census
// and design: docs/arm32-data-import-resolution-design_2026-09-27.md.
//
// WHAT. Each translated image's arm32rc module constructor calls
//     __macapk_arm32_link_image(desc, size, B)
// after its segments and LUT entries are registered and before its
// .init_array (arm32rc_driver.cpp). `desc` is the image's site table plus its
// PT_DYNAMIC vaddr. This file registers the image, reads its OWN .dynamic /
// .dynsym / .dynstr / .gnu.hash / .hash out of the arena (the bytes
// __macapk_register_segment just copied), and resolves every site the way
// Bionic's linker does (AOSP platform_bionic, android14-release):
//
//   linker_relocate.cpp :97-128 lookup_symbol: soinfo_do_lookup over the
//     lookup list; not found and the referencing symbol is not STB_WEAK ->
//     DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...").
//   linker_relocate.cpp :285-303: sym_addr = found_in->resolve_symbol_address
//     (st_value + load_bias; Bionic masks nothing); a weak undefined -> 0.
//   linker_relocate.cpp :326-341: R_GENERIC_ABSOLUTE (R_ARM_ABS32) =
//     sym_addr + get_addend_rel(); R_GENERIC_GLOB_DAT = sym_addr +
//     get_addend_norel(). The translator already normalised the addend
//     (DataImportSite::addend), so every write here is S + A.
//   linker_relocate.h :60-69 is_symbol_global_and_defined: bind GLOBAL or
//     WEAK and st_shndx != SHN_UNDEF. The FIRST library of the lookup list
//     that defines the name wins (linker_soinfo.cpp :119-205); GLOBAL is not
//     preferred over WEAK across libraries; a versym-hidden definition is
//     skipped when no version is requested (:108-115 check_symbol_version).
//   linker_soinfo.cpp :330-380 gnu_lookup: kBloomMaskBits =
//     sizeof(ElfW(Addr)) * 8 = 32 on ARM32; word = bloom[(h / 32) & mask];
//     test bits h % 32 and (h >> shift2) % 32; walk the chain while
//     ((chain[n] ^ h) >> 1) == 0 is checked per entry, stop at (chain[n] & 1).
//     :382-400 elf_lookup (sysv): bucket[h % nbucket], chain[n].
//   linker.cpp :2873-2900 DT_HASH / DT_GNU_HASH layouts (gnu: nbucket, symndx,
//     maskwords, shift2, bloom[maskwords], buckets[nbucket], chain[] - symndx).
//   linker.cpp :700-733 walk_dependencies_tree: the local group is the BFS
//     closure over DT_NEEDED.
//
// ORDER. For one site: (1) BFS over the importer's DT_NEEDED closure starting
// at the importer. A registered ARM32 image answers from its own hash table
// (S = st_value + its B, Thumb bit KEPT: __macapk_resolve_function masks bit 0
// and a provider's own R_ARM_RELATIVE vtables keep it, so identity matches). A
// SYSTEM library (the NDK stable set below) answers OBJECT/NOTYPE names from
// the host-data table (materialised in GUEST memory, attributed by library so
// `SL_IID_*` matches only at libOpenSLES) and FUNC names from the translator's
// host-function fallback thunk (key + B). An APK library named in DT_NEEDED
// but not registered yet makes the answer PROVISIONAL. (2) Not found and not
// WEAK: every registered image, in registration order -- the pre-API-23 flat
// behaviour, logged, a safety net only (a device's dlopen would fail here).
// A WEAK reference skips it: Bionic at API >= 23 gives it 0 (HCR 1.43's
// libImmEndpointWarpJ.so weak `__cxa_call_unexpected` must stay 0). (3) A FUNC
// with a fallback thunk. (4) Nothing: WEAK -> 0 + A; GLOBAL -> Bionic's own
// "cannot locate symbol" line, counted, and retried whenever a later image
// registers. We do NOT fail the load: that would turn today's silent A into a
// crash on apps that currently run.
//
// DEVIATIONS from Bionic, each an approximation that only matters in corner
// cases the corpus does not contain: (a) the closure is rooted at the IMPORTER,
// not at the dlopen root (exact whenever each library is loaded as its own
// root, which is what AppClassLoader's preloadDependencies + System.load do);
// (b) no requested symbol version (vi = nullptr): only the hidden bit is
// honoured; (c) we relocate each image in its own constructor, after its
// dependencies' constructors (dyld's bottom-up order), where Bionic relocates
// the whole group first -- both write the slot before the importer's
// .init_array, which is what matters; (d) a late (re)bind when a later image
// registers only ever converges on what Bionic would have written; (e) which
// system library exports a FUNC is decided by system_lib_exports_fn (exact
// version-script lists for libstdc++ / libdl / libz, the NDK naming convention
// for the rest, libc + libm as the catch-all) rather than by that library's
// real symbol table; and when the owning library has no guest-ABI body here
// (no fallback thunk) the BFS continues where Bionic would have stopped, so a
// later library's own copy beats a NULL. (The design note proposed "a FUNC
// fallback matches at ANY system node"; that would have sent OpenTTD's 278
// `__cxa_pure_virtual` vtable slots to our shim instead of its
// libc++_shared.so, because liblog.so precedes it in DT_NEEDED.)
//
// GATE. MACAPK_ARM32_DATA_IMPORT_BIND (runtime): unset / `1` = write every
// result; `sibling` = write only results whose provider is an ARM32 image
// (the resolver runs the IDENTICAL search in every mode -- a mode that changed
// the DECISION would make the A/B measure a different linker); `0` = register
// nothing and write nothing, i.e. exactly the guest memory of a pre-change
// build. The translate-time half is MACAPK_ARM32_DATA_IMPORT_LINK
// (elf_reader.h). Gate: debug/dataimport_gate.sh.
//
// C++17. No em dashes (project convention).

#include <crt_externs.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C" {
void* __macapk_get_guest_base(void);
// bionic_shim.cpp, hidden accessors (see the block after guest_alloc there).
uint32_t macapk_arm32_link_guest_alloc(size_t bytes);
void macapk_arm32_link_write32(uint32_t vaddr, uint32_t value);
void macapk_arm32_link_handle_alias(uint32_t guest_addr, void* host);
}

namespace {

// ---- guest memory --------------------------------------------------------
uint8_t* arena() { return static_cast<uint8_t*>(__macapk_get_guest_base()); }

bool rd32(uint32_t va, uint32_t* out) {
    uint8_t* g = arena();
    if (!g || va > 0xfffffffcu) return false;
    std::memcpy(out, g + va, 4);
    return true;
}
bool rd16(uint32_t va, uint16_t* out) {
    uint8_t* g = arena();
    if (!g || va > 0xfffffffeu) return false;
    std::memcpy(out, g + va, 2);
    return true;
}
// A NUL-terminated string at guest `va`, at most `cap` bytes.
std::string rdstr(uint32_t va, size_t cap = 4096) {
    uint8_t* g = arena();
    std::string s;
    if (!g) return s;
    for (size_t i = 0; i < cap; ++i) {
        const uint64_t a = uint64_t(va) + i;
        if (a > 0xffffffffull) break;
        const char c = static_cast<char>(g[a]);
        if (!c) break;
        s.push_back(c);
    }
    return s;
}
void wr_bytes(uint32_t va, const void* p, size_t n) {
    uint8_t* g = arena();
    if (!g || !va || uint64_t(va) + n > 0x100000000ull) return;
    std::memcpy(g + va, p, n);
}
void wr32_heap(uint32_t va, uint32_t v) { wr_bytes(va, &v, 4); }

// ---- the gate --------------------------------------------------------------
enum class BindMode { All, Sibling, Off };
BindMode bind_mode() {
    static const BindMode m = [] {
        const char* e = std::getenv("MACAPK_ARM32_DATA_IMPORT_BIND");
        if (!e || !*e) return BindMode::All;
        if (std::strcmp(e, "0") == 0) return BindMode::Off;
        if (std::strcmp(e, "sibling") == 0) return BindMode::Sibling;
        return BindMode::All;
    }();
    return m;
}
const char* mode_name(BindMode m) {
    return m == BindMode::All ? "all" : m == BindMode::Sibling ? "sibling" : "0";
}

// ---- ELF32 constants (Bionic / gABI) ---------------------------------------
constexpr int32_t  DT_NULL = 0, DT_NEEDED = 1, DT_HASH = 4, DT_STRTAB = 5,
                   DT_SYMTAB = 6, DT_STRSZ = 10, DT_SONAME = 14;
constexpr int32_t  DT_GNU_HASH = 0x6ffffef5, DT_VERSYM = 0x6ffffff0;
constexpr uint8_t  STB_GLOBAL = 1, STB_WEAK = 2;
constexpr uint8_t  STT_FUNC = 2, STT_GNU_IFUNC = 10;
constexpr uint16_t kVersymHiddenBit = 0x8000;   // linker_soinfo.h
constexpr uint32_t kMaxChain = 1u << 20;        // corrupt-table backstop

// ---- one registered image --------------------------------------------------
struct Entry {
    uint32_t slot, addend, fallback_key;
    std::string name;
    uint8_t r_type, sym_type, sym_bind;
};
struct Image {
    std::string soname, basename;
    uint32_t B = 0, seg_lo = 0, seg_hi = 0;
    // Biased guest vaddrs of the tables (0 = absent).
    uint32_t symtab = 0, strtab = 0, strsz = 0, versym = 0;
    uint32_t nbucket = 0, nchain = 0, bucket = 0, chain = 0;        // DT_HASH
    uint32_t gnu_nbucket = 0, gnu_symndx = 0, gnu_maskwords = 0,   // DT_GNU_HASH
             gnu_shift2 = 0, gnu_bloom = 0, gnu_bucket = 0, gnu_chain0 = 0;
    std::vector<std::string> needed;
    std::vector<Entry> entries;
    // Per entry: the value last written (valid when written[i]).
    std::vector<uint32_t> last;
    std::vector<uint8_t> written;
};

std::mutex g_mtx;
std::deque<std::unique_ptr<Image>> g_images;              // registration order
std::unordered_map<std::string, Image*> g_by_name;        // soname + basename
std::unordered_set<uint64_t> g_flat_logged;               // (image idx, hash)
struct Pending { Image* img; size_t idx; };
std::vector<Pending> g_pending;

// The NDK's stable system libraries (developer.android.com/ndk/guides/stable_apis).
// A DT_NEEDED name in this set is answered by Apk on Mac's own implementation of
// that library; any other unregistered name is taken to be an APK library that
// has not registered yet (-> PROVISIONAL).
bool is_system_lib(const std::string& n) {
    static const std::unordered_set<std::string> k = {
        "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
        "libandroid.so", "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so",
        "libGLESv3.so", "libOpenSLES.so", "libOpenMAXAL.so", "libmediandk.so",
        "libjnigraphics.so", "libvulkan.so", "libaaudio.so", "libamidi.so",
        "libnativewindow.so", "libstdc++.so", "libcamera2ndk.so",
        "libneuralnetworks.so", "libsync.so", "libbinder_ndk.so", "libicu.so",
    };
    return k.count(n) != 0;
}

// Does system library `lib` export FUNCTION `name`? Only consulted for a FUNC
// data import that has a host-function fallback thunk, to decide whether the
// BFS stops at this system node or continues to a later library (an APK
// library that defines it, as Bionic would find when this system library does
// not: OpenTTD libapplication.so lists liblog.so, libz.so, libdl.so and
// libm.so before libc++_shared.so, whose `__cxa_pure_virtual` its 278 vtable
// slots must reach). Exact lists where AOSP's version scripts are small
// (android14-release: bionic libc/libstdc++.map.txt, libdl/libdl.map.txt,
// external/zlib/libz.map.txt), the NDK naming convention for the rest, and
// libc.so / libm.so as the catch-all for every other name -- which libc and
// libm between them do export for every C library function a guest imports.
bool system_lib_exports_fn(const std::string& lib, const std::string& n) {
    static const std::unordered_set<std::string> kStdcxx = {   // libstdc++.map.txt
        "__cxa_guard_abort", "__cxa_guard_acquire", "__cxa_guard_release",
        "__cxa_pure_virtual", "_ZdaPv", "_ZdaPvRKSt9nothrow_t", "_ZdlPv",
        "_ZdlPvRKSt9nothrow_t", "_Znaj", "_ZnajRKSt9nothrow_t", "_Znwj",
        "_ZnwjRKSt9nothrow_t",
    };
    static const std::unordered_set<std::string> kDl = {         // libdl.map.txt (arm)
        "__cfi_init", "__cfi_shadow_size", "__cfi_slowpath", "__cfi_slowpath_diag",
        "android_dlopen_ext", "android_get_LD_LIBRARY_PATH",
        "android_get_application_target_sdk_version", "android_handle_signal",
        "dl_iterate_phdr", "dl_unwind_find_exidx", "dladdr", "dlclose", "dlerror",
        "dlopen", "dlsym", "dlvsym",
    };
    static const std::unordered_set<std::string> kZ = {          // libz.map.txt
        "_tr_align", "_tr_flush_bits", "_tr_flush_block", "_tr_init",
        "_tr_stored_block", "_tr_tally", "adler32", "adler32_combine",
        "adler32_combine64", "adler32_z", "compress", "compress2", "compressBound",
        "crc32", "crc32_combine", "crc32_combine64", "crc32_z", "deflate",
        "deflateBound", "deflateCopy", "deflateEnd", "deflateGetDictionary",
        "deflateInit2_", "deflateInit_", "deflateParams", "deflatePending",
        "deflatePrime", "deflateReset", "deflateResetKeep", "deflateSetDictionary",
        "deflateSetHeader", "deflateTune", "get_crc_table", "gz_error", "gz_intmax",
        "gzbuffer", "gzclearerr", "gzclose", "gzclose_r", "gzclose_w", "gzdirect",
        "gzdopen", "gzeof", "gzerror", "gzflush", "gzfread", "gzfwrite", "gzgetc",
        "gzgetc_", "gzgets", "gzoffset", "gzoffset64", "gzopen", "gzopen64",
        "gzprintf", "gzputc", "gzputs", "gzread", "gzrewind", "gzseek", "gzseek64",
        "gzsetparams", "gztell", "gztell64", "gzungetc", "gzvprintf", "gzwrite",
        "inflate", "inflateBack", "inflateBackEnd", "inflateBackInit_",
        "inflateCodesUsed", "inflateCopy", "inflateEnd", "inflateGetDictionary",
        "inflateGetHeader", "inflateInit2_", "inflateInit_", "inflateMark",
        "inflatePrime", "inflateReset", "inflateReset2", "inflateResetKeep",
        "inflateSetDictionary", "inflateSync", "inflateSyncPoint",
        "inflateUndermine", "inflateValidate", "inflate_fast", "inflate_table",
        "uncompress", "uncompress2", "zError", "zcalloc", "zcfree",
        "zlibCompileFlags", "zlibVersion",
    };
    auto pre = [&](const char* p) { return n.rfind(p, 0) == 0; };
    auto pre_upper = [&](const char* p) {   // "gl" + an upper-case letter, ...
        const size_t k = std::strlen(p);
        return n.size() > k && n.compare(0, k, p) == 0 && n[k] >= 'A' && n[k] <= 'Z';
    };
    const char* owner;
    // Itanium-mangled names and the __cxa_* runtime: no Android system library
    // exports any beyond libstdc++'s dozen and libc's three (libc.map.txt
    // __cxa_atexit / __cxa_finalize / __cxa_thread_atexit_impl), so they must
    // not stop the BFS at libc / libm.
    const bool cxx = (pre("_Z") || pre("__cxa_")) && !kStdcxx.count(n);
    if (cxx && n != "__cxa_atexit" && n != "__cxa_finalize" &&
        n != "__cxa_thread_atexit_impl")
        return false;
    if (kStdcxx.count(n))                         owner = "libstdc++.so";
    else if (kDl.count(n))                        owner = "libdl.so";
    else if (kZ.count(n))                         owner = "libz.so";
    else if (pre_upper("gl"))                     owner = "GLES";
    else if (pre_upper("egl"))                    owner = "libEGL.so";
    else if (pre("__android_log") || pre("android_log")) owner = "liblog.so";
    else if (pre_upper("sl"))                     owner = "libOpenSLES.so";
    else if (pre_upper("xa"))                     owner = "libOpenMAXAL.so";
    else if (pre("AMedia"))                       owner = "libmediandk.so";
    else if (pre("AndroidBitmap_"))               owner = "libjnigraphics.so";
    else if (pre_upper("vk"))                     owner = "libvulkan.so";
    else if (pre("AAudio"))                       owner = "libaaudio.so";
    else if (pre("AMidi"))                        owner = "libamidi.so";
    else if (pre("ACamera"))                      owner = "libcamera2ndk.so";
    else if (pre("ANeuralNetworks"))              owner = "libneuralnetworks.so";
    else if (pre("sync_"))                        owner = "libsync.so";
    else if (pre("AIBinder") || pre("AParcel") || pre("AStatus") ||
             pre("AServiceManager"))              owner = "libbinder_ndk.so";
    else if (pre("ANativeWindow_") || pre("AHardwareBuffer_"))
                                                  owner = "WINDOW";
    else if (pre_upper("A"))                      owner = "libandroid.so";
    else                                          owner = "LIBC";
    if (std::strcmp(owner, "GLES") == 0)
        return lib == "libGLESv1_CM.so" || lib == "libGLESv2.so" || lib == "libGLESv3.so";
    if (std::strcmp(owner, "WINDOW") == 0)
        return lib == "libnativewindow.so" || lib == "libandroid.so";
    if (std::strcmp(owner, "LIBC") == 0)
        return lib == "libc.so" || lib == "libm.so";
    return lib == owner;
}

uint32_t gnu_hash(const std::string& s) {
    uint32_t h = 5381;
    for (unsigned char c : s) h = h * 33 + c;
    return h;
}
uint32_t elf_hash(const std::string& s) {
    uint32_t h = 0;
    for (unsigned char c : s) {
        h = (h << 4) + c;
        const uint32_t g = h & 0xf0000000u;
        h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

// Parse PT_DYNAMIC at guest `dyn` (already biased) the way prelink_image does.
void parse_dynamic(Image& im, uint32_t dyn) {
    uint32_t needed_off[256];
    size_t n_needed = 0;
    uint32_t soname_off = 0;
    bool have_soname = false;
    for (uint32_t i = 0; i < 4096; ++i) {
        uint32_t tag = 0, val = 0;
        if (!rd32(dyn + i * 8, &tag) || !rd32(dyn + i * 8 + 4, &val)) break;
        const int32_t t = static_cast<int32_t>(tag);
        if (t == DT_NULL) break;
        switch (t) {
            case DT_NEEDED: if (n_needed < 256) needed_off[n_needed++] = val; break;
            case DT_SONAME: soname_off = val; have_soname = true; break;
            case DT_STRTAB: im.strtab = val + im.B; break;
            case DT_STRSZ:  im.strsz = val; break;
            case DT_SYMTAB: im.symtab = val + im.B; break;
            case DT_VERSYM: im.versym = val + im.B; break;
            case DT_HASH: {
                const uint32_t h = val + im.B;
                rd32(h, &im.nbucket);
                rd32(h + 4, &im.nchain);
                im.bucket = h + 8;
                im.chain = h + 8 + im.nbucket * 4;
                break;
            }
            case DT_GNU_HASH: {
                const uint32_t h = val + im.B;
                rd32(h, &im.gnu_nbucket);
                rd32(h + 4, &im.gnu_symndx);
                uint32_t mw = 0;
                rd32(h + 8, &mw);
                rd32(h + 12, &im.gnu_shift2);
                // linker.cpp :2892-2897: maskwords must be a power of two;
                // stored minus one as the AND mask.
                if (mw == 0 || (mw & (mw - 1)) != 0) break;
                im.gnu_maskwords = mw - 1;
                im.gnu_bloom = h + 16;
                im.gnu_bucket = im.gnu_bloom + mw * 4;   // ElfW(Addr) = 4 on LP32
                im.gnu_chain0 = im.gnu_bucket + im.gnu_nbucket * 4 - im.gnu_symndx * 4;
                break;
            }
            default: break;
        }
    }
    if (im.strtab) {
        for (size_t k = 0; k < n_needed; ++k)
            im.needed.push_back(rdstr(im.strtab + needed_off[k]));
        if (have_soname) im.soname = rdstr(im.strtab + soname_off);
    }
}

struct SymHit { bool ok = false; uint32_t value = 0; uint8_t type = 0; };

bool sym_matches(const Image& im, uint32_t idx, const std::string& name,
                 SymHit* hit) {
    const uint32_t s = im.symtab + idx * 16;
    uint32_t st_name = 0, st_value = 0;
    uint8_t st_info = 0;
    uint16_t st_shndx = 0;
    if (!rd32(s, &st_name) || !rd32(s + 4, &st_value)) return false;
    uint8_t* g = arena();
    st_info = g[s + 12];
    if (!rd16(s + 14, &st_shndx)) return false;
    const uint8_t bind = st_info >> 4;
    if (bind != STB_GLOBAL && bind != STB_WEAK) return false;   // is_symbol_global_and_defined
    if (st_shndx == 0) return false;
    if (im.versym) {                                            // check_symbol_version, vi == nullptr
        uint16_t v = 0;
        if (rd16(im.versym + idx * 2, &v) && (v & kVersymHiddenBit)) return false;
    }
    if (im.strsz && st_name >= im.strsz) return false;
    if (rdstr(im.strtab + st_name, name.size() + 1) != name) return false;
    hit->ok = true;
    hit->value = st_value;
    hit->type = st_info & 0xf;
    return true;
}

// soinfo::find_symbol_by_name for one image: gnu when present, else sysv.
SymHit lookup(const Image& im, const std::string& name) {
    SymHit hit;
    if (!im.symtab || !im.strtab) return hit;
    if (im.gnu_bloom && im.gnu_nbucket) {
        const uint32_t h = gnu_hash(name);
        constexpr uint32_t kBloomMaskBits = 32;   // sizeof(ElfW(Addr)) * 8 on LP32
        uint32_t word = 0;
        if (!rd32(im.gnu_bloom + ((h / kBloomMaskBits) & im.gnu_maskwords) * 4, &word))
            return hit;
        const uint32_t h1 = h % kBloomMaskBits;
        const uint32_t h2 = (h >> im.gnu_shift2) % kBloomMaskBits;
        if ((1u & (word >> h1) & (word >> h2)) == 0) return hit;
        uint32_t n = 0;
        if (!rd32(im.gnu_bucket + (h % im.gnu_nbucket) * 4, &n) || n == 0) return hit;
        for (uint32_t guard = 0; guard < kMaxChain; ++guard, ++n) {
            uint32_t c = 0;
            if (!rd32(im.gnu_chain0 + n * 4, &c)) return hit;
            if (((c ^ h) >> 1) == 0 && sym_matches(im, n, name, &hit)) return hit;
            if (c & 1) break;
        }
        return hit;
    }
    if (im.nbucket) {
        const uint32_t h = elf_hash(name);
        uint32_t n = 0;
        if (!rd32(im.bucket + (h % im.nbucket) * 4, &n)) return hit;
        for (uint32_t guard = 0; n != 0 && guard < kMaxChain; ++guard) {
            if (im.nchain && n >= im.nchain) break;
            if (sym_matches(im, n, name, &hit)) return hit;
            if (!rd32(im.chain + n * 4, &n)) break;
        }
    }
    return hit;
}

Image* find_image(const std::string& n) {
    auto it = g_by_name.find(n);
    return it == g_by_name.end() ? nullptr : it->second;
}

// ---- host-provided system-library DATA, in guest memory ---------------------
// Process-wide singletons, as libc's own objects are. Allocated lazily from the
// guest heap (never in an image's bias band). Every value is what the Android
// library holds; sources inline.
std::unordered_map<std::string, uint32_t> g_host_data;    // "lib:name" -> guest addr

uint32_t galloc(size_t n) {
    const uint32_t a = macapk_arm32_link_guest_alloc(n < 4 ? 4 : n);
    if (a) { std::vector<uint8_t> z(n < 4 ? 4 : n, 0); wr_bytes(a, z.data(), z.size()); }
    return a;
}
uint32_t gstr(const char* s) {
    if (!s) return 0;
    const size_t n = std::strlen(s) + 1;
    const uint32_t a = galloc(n);
    if (a) wr_bytes(a, s, n);
    return a;
}
uint32_t cell(uint32_t value) {
    const uint32_t a = galloc(4);
    if (a) wr32_heap(a, value);
    return a;
}
// A u32 array of `n` guest string pointers (NULL where s[i] is null).
uint32_t str_array(const char* const* s, size_t n) {
    const uint32_t a = galloc(n * 4);
    if (!a) return 0;
    for (size_t i = 0; i < n; ++i) wr32_heap(a + uint32_t(i) * 4, s[i] ? gstr(s[i]) : 0);
    return a;
}

// Look up one of the shim's own `__macapk_arm64_<name>` exports (the Stage-6
// data surface: SL_IID_*, AMEDIAFORMAT_KEY_*), so this file never carries a
// second copy of those values.
void* shim_symbol(const std::string& name) {
    static void* self = [] {
        Dl_info di{};
        if (!dladdr(reinterpret_cast<void*>(&shim_symbol), &di) || !di.dli_fname)
            return static_cast<void*>(nullptr);
        return dlopen(di.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
    }();
    return self ? dlsym(self, name.c_str()) : nullptr;
}

// Bionic's libc/upstream-openbsd/lib/libc/gen/ctype_.c `_C_ctype_` (257 bytes,
// element 0 = EOF) -- the same bits elf_reader.cpp's synthetic segment writes
// (kitkat ctype.h: U 01 L 02 N 04 S 08 P 10 C 20 X 40 B 80).
void bionic_ctype(uint8_t t[257]) {
    constexpr uint8_t U = 0x01, L = 0x02, N = 0x04, S = 0x08, P = 0x10, C = 0x20,
                      X = 0x40, B = 0x80;
    std::memset(t, 0, 257);
    for (int c = 0; c < 128; ++c) {
        uint8_t v;
        if (c < 0x20)       v = (c >= 0x09 && c <= 0x0d) ? (C | S) : C;
        else if (c == 0x20) v = S | B;
        else if (c < 0x30)  v = P;
        else if (c < 0x3a)  v = N;
        else if (c < 0x41)  v = P;
        else if (c < 0x47)  v = U | X;
        else if (c < 0x5b)  v = U;
        else if (c < 0x61)  v = P;
        else if (c < 0x67)  v = L | X;
        else if (c < 0x7b)  v = L;
        else if (c < 0x7f)  v = P;
        else                v = C;
        t[1 + c] = v;
    }
}
// bionic libc/stdlib/{toupper,tolower}_.c `_C_toupper_` / `_C_tolower_`:
// 257 shorts, element 0 = EOF (-1), C locale.
uint32_t case_table(bool upper) {
    int16_t t[257];
    t[0] = -1;
    for (int c = 0; c < 256; ++c) {
        int r = c;
        if (upper) { if (c >= 'a' && c <= 'z') r = c - 'a' + 'A'; }
        else       { if (c >= 'A' && c <= 'Z') r = c - 'A' + 'a'; }
        t[c + 1] = static_cast<int16_t>(r);
    }
    const uint32_t a = galloc(sizeof t);
    if (a) wr_bytes(a, t, sizeof t);
    return a;
}

// LP32 Linux ARM signal numbers (bionic libc/kernel/uapi/asm-arm/asm/signal.h)
// and names/descriptions (libc/private/bionic_sigdefs.h; strsignal.cpp builds
// sys_signame as the name without "SIG"). NSIG = 65 on LP32.
constexpr size_t kNsig = 65;
void sig_tables(const char* names[kNsig], const char* descs[kNsig]) {
    struct D { int n; const char* name; const char* desc; };
    static const D kSig[] = {
        {1, "HUP", "Hangup"}, {2, "INT", "Interrupt"}, {3, "QUIT", "Quit"},
        {4, "ILL", "Illegal instruction"}, {5, "TRAP", "Trap"},
        {6, "ABRT", "Aborted"}, {7, "BUS", "Bus error"},
        {8, "FPE", "Floating point exception"}, {9, "KILL", "Killed"},
        {10, "USR1", "User signal 1"}, {11, "SEGV", "Segmentation fault"},
        {12, "USR2", "User signal 2"}, {13, "PIPE", "Broken pipe"},
        {14, "ALRM", "Alarm clock"}, {15, "TERM", "Terminated"},
        {16, "STKFLT", "Stack fault"}, {17, "CHLD", "Child exited"},
        {18, "CONT", "Continue"}, {19, "STOP", "Stopped (signal)"},
        {20, "TSTP", "Stopped"}, {21, "TTIN", "Stopped (tty input)"},
        {22, "TTOU", "Stopped (tty output)"}, {23, "URG", "Urgent I/O condition"},
        {24, "XCPU", "CPU time limit exceeded"},
        {25, "XFSZ", "File size limit exceeded"},
        {26, "VTALRM", "Virtual timer expired"},
        {27, "PROF", "Profiling timer expired"},
        {28, "WINCH", "Window size changed"}, {29, "IO", "I/O possible"},
        {30, "PWR", "Power failure"}, {31, "SYS", "Bad system call"},
    };
    for (size_t i = 0; i < kNsig; ++i) { names[i] = nullptr; descs[i] = nullptr; }
    for (const D& d : kSig) { names[d.n] = d.name; descs[d.n] = d.desc; }
}

// Materialise `name` as library `lib` would export it. 0 = this library does
// not export it (the BFS continues).
uint32_t host_data(const std::string& lib, const std::string& name) {
    const std::string key = lib + ":" + name;
    auto it = g_host_data.find(key);
    if (it != g_host_data.end()) return it->second;
    uint32_t a = 0;
    if (lib == "libc.so") {
        if (name == "__stack_chk_guard") {
            // bionic __libc_init_main_thread.cpp: `uintptr_t __stack_chk_guard`,
            // filled by __libc_safe_arc4random_buf. Written once, never changed.
            uint32_t v = 0;
            while (v == 0) v = arc4random();
            a = cell(v);
        } else if (name == "__sF" || name == "stdin" || name == "stdout" ||
                   name == "stderr") {
            // stdio.cpp :72-105: FILE __sF[3] = MAKE_STD_STREAM(__SRD, 0),
            // (__SWR, 1), (__SWR|__SNBF, 2); stdin/out/err = &__sF[i]. LP32
            // FILE is 84 bytes (bits/struct_file.h); stdio/local.h puts
            // `short _flags` at +12, `short _file` at +14, `void* _cookie` at
            // +28. The function pointers stay 0: guest stdio calls go to our
            // shims, which map these three addresses to the host streams
            // through the handle table (the same boxing fopen uses).
            auto sf = g_host_data.find("libc.so:__sF");
            uint32_t base = sf == g_host_data.end() ? 0 : sf->second;
            if (!base) {
                base = galloc(3 * 84);
                if (base) {
                    static const uint16_t kFlags[3] = {0x0004, 0x0008, 0x0008 | 0x0002};
                    FILE* host[3] = {stdin, stdout, stderr};
                    for (uint32_t i = 0; i < 3; ++i) {
                        const uint32_t f = base + 84 * i;
                        const uint16_t fd = static_cast<uint16_t>(i);
                        wr_bytes(f + 12, &kFlags[i], 2);
                        wr_bytes(f + 14, &fd, 2);
                        wr32_heap(f + 28, f);
                        macapk_arm32_link_handle_alias(f, host[i]);
                    }
                    g_host_data["libc.so:__sF"] = base;
                }
            }
            if (name == "__sF") a = base;
            else if (base) a = cell(base + 84 * (name == "stdin" ? 0 : name == "stdout" ? 1 : 2));
        } else if (name == "environ") {
            // A NULL-terminated guest char*[] snapshot of the host environment.
            char** e = *_NSGetEnviron();
            size_t n = 0;
            while (e && e[n]) ++n;
            std::vector<const char*> v(e, e + n);
            v.push_back(nullptr);
            a = cell(str_array(v.data(), v.size()));
        } else if (name == "optarg" || name == "optreset") {
            a = cell(0);   // upstream-freebsd getopt_long.c :73-77
        } else if (name == "optind" || name == "opterr") {
            a = cell(1);
        } else if (name == "optopt") {
            a = cell('?');
        } else if (name == "daylight" || name == "timezone" || name == "tzname") {
            // tzcode/localtime.c :199-206 (`char* tzname[2]`, `long timezone`,
            // `int daylight`), after tzset(). long is 4 bytes on LP32.
            tzset();
            if (name == "daylight") a = cell(static_cast<uint32_t>(::daylight));
            else if (name == "timezone") a = cell(static_cast<uint32_t>(::timezone));
            else { const char* t[2] = {::tzname[0], ::tzname[1]}; a = str_array(t, 2); }
        } else if (name == "sys_signame" || name == "sys_siglist") {
            const char* nm[kNsig];
            const char* ds[kNsig];
            sig_tables(nm, ds);
            a = str_array(name == "sys_signame" ? nm : ds, kNsig);
        } else if (name == "in6addr_any" || name == "in6addr_loopback") {
            uint8_t v[16] = {0};
            if (name == "in6addr_loopback") v[15] = 1;
            a = galloc(16);
            if (a) wr_bytes(a, v, 16);
        } else if (name == "_ctype_") {
            // Reached only when elf_reader could not place its synthetic
            // segment inside the image's bias band (MACAPK_ARM32_DATA_IMPORT_LINK).
            uint8_t t[257];
            bionic_ctype(t);
            const uint32_t tab = galloc(257);
            if (tab) { wr_bytes(tab, t, 257); a = cell(tab); }
        } else if (name == "_toupper_tab_" || name == "_tolower_tab_") {
            const uint32_t tab = case_table(name == "_toupper_tab_");
            if (tab) a = cell(tab);
        }
    } else if (lib == "libm.so") {
        if (name == "signgam" || name == "__fe_dfl_env") a = cell(0);
    } else if (lib == "libOpenSLES.so") {
        if (name.rfind("SL_IID_", 0) == 0) {
            // `extern const SLInterfaceID SL_IID_X`: a pointer to a 16-byte
            // GUID. The canonical GUIDs are the shim's kMacSlGuid* table,
            // reached through the Stage-6 export `__macapk_arm64_SL_IID_X`.
            if (void* p = shim_symbol("__macapk_arm64_" + name)) {
                const void* guid = *static_cast<const void* const*>(p);
                const uint32_t g = guid ? galloc(16) : 0;
                if (g) { wr_bytes(g, guid, 16); a = cell(g); }
            }
        }
    } else if (lib == "libmediandk.so") {
        if (name.rfind("AMEDIAFORMAT_KEY_", 0) == 0) {
            // `EXPORT const char* AMEDIAFORMAT_KEY_X = "..."` (NdkMediaFormat.cpp);
            // values from the shim's Stage-6 exports (media_ndk.cpp).
            if (void* p = shim_symbol("__macapk_arm64_" + name)) {
                const char* s = *static_cast<const char* const*>(p);
                if (s) { const uint32_t str = gstr(s); if (str) a = cell(str); }
            }
        }
    }
    if (a) g_host_data[key] = a;
    return a;
}

// ---- the resolver -----------------------------------------------------------
enum class Kind { None, Arm32, HostData, HostFn, Flat };
struct Result {
    Kind kind = Kind::None;
    uint32_t S = 0;
    bool provisional = false;
    // A FUNC name reached a system library with no host-function fallback:
    // a device's libc would define it, Apk on Mac has no guest-ABI body for it.
    bool system_func_unprovided = false;
    const Image* provider = nullptr;
    std::string where;   // provider name, for logs
};

Result resolve(const Image& im, const Entry& e) {
    Result r;
    // (1) BFS over the DT_NEEDED closure, starting at the importer.
    std::unordered_set<std::string> seen;
    bool unknown_seen = false;
    std::vector<const Image*> nodes{&im};
    std::vector<std::string> node_names{im.basename};
    seen.insert(im.basename);
    if (!im.soname.empty()) seen.insert(im.soname);
    for (size_t qi = 0; qi < node_names.size() && qi < 4096; ++qi) {
        const Image* node = nodes[qi];
        const std::string& nn = node_names[qi];
        if (node) {
            const SymHit h = lookup(*node, e.name);
            if (h.ok && h.type != STT_GNU_IFUNC) {
                r.kind = Kind::Arm32;
                r.S = h.value + node->B;
                r.provider = node;
                r.where = node->basename;
                r.provisional = unknown_seen;
                return r;
            }
            for (const std::string& dn : node->needed) {
                if (seen.count(dn)) continue;
                seen.insert(dn);
                nodes.push_back(find_image(dn));
                node_names.push_back(dn);
            }
        } else if (is_system_lib(nn)) {
            if (e.sym_type != STT_FUNC) {
                const uint32_t a = host_data(nn, e.name);
                if (a) {
                    r.kind = Kind::HostData;
                    r.S = a;
                    r.where = nn;
                    r.provisional = unknown_seen;
                    return r;
                }
            } else if (system_lib_exports_fn(nn, e.name)) {
                if (e.fallback_key) {
                    r.kind = Kind::HostFn;
                    r.S = e.fallback_key + im.B;
                    r.where = nn;
                    r.provisional = unknown_seen;
                    return r;
                }
                // Bionic would stop here; we have no guest-ABI body, so keep
                // walking (a later library's own copy beats a NULL).
                r.system_func_unprovided = true;
            }
        } else {
            unknown_seen = true;   // an APK library that has not registered yet
        }
    }
    r.provisional = unknown_seen;
    // (2) the flat step: GLOBAL only.
    if (e.sym_bind != STB_WEAK) {
        for (const auto& up : g_images) {
            const SymHit h = lookup(*up, e.name);
            if (h.ok && h.type != STT_GNU_IFUNC) {
                r.kind = Kind::Flat;
                r.S = h.value + up->B;
                r.provider = up.get();
                r.where = up->basename;
                return r;
            }
        }
    }
    // (3) a FUNC fallback with no system node in the closure.
    if (e.sym_type == STT_FUNC && e.fallback_key) {
        r.kind = Kind::HostFn;
        r.S = e.fallback_key + im.B;
        r.where = "(host fallback)";
    }
    return r;
}

bool mode_writes(Kind k) {
    switch (bind_mode()) {
        case BindMode::All: return true;
        case BindMode::Sibling: return k == Kind::Arm32 || k == Kind::Flat;
        case BindMode::Off: return false;
    }
    return false;
}

struct Counts { size_t arm32 = 0, host_data = 0, host_fn = 0, flat = 0,
                weak0 = 0, unresolved = 0, provisional = 0, filtered = 0; };

// Resolve + write entry i. Returns true when the answer is FINAL (no retry).
bool bind_one(Image& im, size_t i, Counts* c, int* n_logged, bool late) {
    const Entry& e = im.entries[i];
    const Result r = resolve(im, e);
    uint32_t value = 0;
    bool have = false;
    if (r.kind != Kind::None) {
        value = r.S + e.addend;
        have = mode_writes(r.kind);
        if (c) {
            if (!have) ++c->filtered;
            else if (r.kind == Kind::Arm32) ++c->arm32;
            else if (r.kind == Kind::HostData) ++c->host_data;
            else if (r.kind == Kind::HostFn) ++c->host_fn;
            else ++c->flat;
        }
        if (r.kind == Kind::Flat) {
            const uint64_t k = (uint64_t(reinterpret_cast<uintptr_t>(&im)) << 16) ^
                               std::hash<std::string>{}(e.name);
            if (g_flat_logged.insert(k).second)
                std::fprintf(stderr,
                    "[arm32-link] %s: \"%s\" is defined only OUTSIDE its DT_NEEDED "
                    "closure, in %s -- bound by the pre-API-23 flat rule (a device's "
                    "dlopen would fail)\n",
                    im.basename.c_str(), e.name.c_str(), r.where.c_str());
        }
    } else if (e.sym_bind == STB_WEAK) {
        // Bionic: a weak undefined is sym_addr 0 -> 0 + A (GLOB_DAT A = 0).
        value = e.addend;
        have = bind_mode() == BindMode::All;
        if (c) { if (have) ++c->weak0; else ++c->filtered; }
    } else {
        if (c) ++c->unresolved;
        if (n_logged && *n_logged < 16 && !late) {
            ++*n_logged;
            std::fprintf(stderr,
                "[arm32-link] cannot locate symbol \"%s\" referenced by \"%s\"...%s\n",
                e.name.c_str(), im.basename.c_str(),
                r.provisional ? " (pending: a DT_NEEDED library has not registered)"
                : r.system_func_unprovided
                    ? " (a system library defines it on a device; Apk on Mac has no "
                      "guest-ABI body for it -- the slot keeps its in-place word)"
                    : "");
        }
    }
    if (have && (!im.written[i] || im.last[i] != value)) {
        if (late && im.written[i])
            std::fprintf(stderr,
                "[arm32-link] LATE rebind %s slot 0x%x \"%s\": 0x%x -> 0x%x (%s)\n",
                im.basename.c_str(), e.slot + im.B, e.name.c_str(), im.last[i],
                value, r.where.c_str());
        else if (late)
            std::fprintf(stderr,
                "[arm32-link] LATE bind %s slot 0x%x \"%s\" -> 0x%x (%s)\n",
                im.basename.c_str(), e.slot + im.B, e.name.c_str(), value,
                r.where.c_str());
        macapk_arm32_link_write32(e.slot + im.B, value);
        im.last[i] = value;
        im.written[i] = 1;
    }
    // MACAPK_ARM32_LINK_TRACE=1: one line per resolution (diagnostic only).
    static const bool trace = [] {
        const char* t = std::getenv("MACAPK_ARM32_LINK_TRACE");
        return t && *t && *t != '0';
    }();
    if (trace)
        std::fprintf(stderr,
            "[arm32-link] trace %s slot 0x%x \"%s\" kind=%d S=0x%x A=0x%x -> %s0x%x via %s%s\n",
            im.basename.c_str(), e.slot + im.B, e.name.c_str(), static_cast<int>(r.kind),
            r.S, e.addend, have ? "" : "(not written) ", value,
            r.where.empty() ? "-" : r.where.c_str(), r.provisional ? " PROVISIONAL" : "");
    if (c && r.provisional) ++c->provisional;
    // Final unless the answer could still change when another image
    // registers: a provisional answer (an unregistered DT_NEEDED library
    // precedes it in the BFS) or a GLOBAL miss (a later image may define it,
    // by the flat rule). A WEAK miss skips the flat step, so only the
    // provisional case can change it.
    if (r.kind == Kind::None)
        return e.sym_bind == STB_WEAK && !r.provisional;
    return !r.provisional;
}

void retry_pending() {
    std::vector<Pending> keep;
    for (const Pending& p : g_pending)
        if (!bind_one(*p.img, p.idx, nullptr, nullptr, /*late=*/true)) keep.push_back(p);
    g_pending.swap(keep);
}

bool parse_desc(const uint8_t* d, uint32_t size, Image* im, uint32_t* dyn_vaddr) {
    auto u32 = [&](uint32_t off) {
        uint32_t v;
        std::memcpy(&v, d + off, 4);
        return v;
    };
    if (!d || size < 40 || u32(0) != 0x3149444du || u32(4) != 1u) return false;
    *dyn_vaddr = u32(8);
    const uint32_t basename_off = u32(12);
    im->seg_lo = u32(16);
    im->seg_hi = u32(20);
    const uint32_t n = u32(24), imports_off = u32(28), str_off = u32(32),
                   str_size = u32(36);
    if (uint64_t(imports_off) + uint64_t(n) * 20 > size) return false;
    if (uint64_t(str_off) + str_size > size) return false;
    auto str = [&](uint32_t o) -> std::string {
        if (o >= str_size) return {};
        const char* s = reinterpret_cast<const char*>(d + str_off + o);
        return std::string(s, strnlen(s, str_size - o));
    };
    im->basename = str(basename_off);
    im->entries.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t o = imports_off + i * 20;
        Entry e;
        e.slot = u32(o);
        e.name = str(u32(o + 4));
        e.addend = u32(o + 8);
        e.fallback_key = u32(o + 12);
        e.r_type = d[o + 16];
        e.sym_type = d[o + 17];
        e.sym_bind = d[o + 18];
        im->entries.push_back(std::move(e));
    }
    return true;
}

}  // namespace

extern "C" {

// Called from every ARM32 image's module constructor (arm32rc_driver.cpp),
// after __macapk_register_segment / __macapk_register_function and before
// .init_array. `B` is the image's load bias.
__attribute__((visibility("default")))
void __macapk_arm32_link_image(const void* desc, uint32_t size, uint32_t B) {
    const BindMode mode = bind_mode();
    if (mode == BindMode::Off) {
        static std::once_flag once;
        std::call_once(once, [] {
            std::fprintf(stderr,
                "[arm32-link] MACAPK_ARM32_DATA_IMPORT_BIND=0: ARM32 data imports "
                "left unresolved (pre-change guest memory)\n");
        });
        return;
    }
    std::lock_guard<std::mutex> lk(g_mtx);
    auto im = std::make_unique<Image>();
    im->B = B;
    uint32_t dyn = 0;
    if (!parse_desc(static_cast<const uint8_t*>(desc), size, im.get(), &dyn)) {
        std::fprintf(stderr,
            "[arm32-link] bad link descriptor (size %u, B=0x%x): image not "
            "registered -- translator/shim version skew?\n", size, B);
        return;
    }
    if (dyn) parse_dynamic(*im, dyn + B);
    if (!im->gnu_bloom && !im->nbucket && dyn)
        std::fprintf(stderr,
            "[arm32-link] %s: no DT_GNU_HASH or DT_HASH (Bionic rejects such an "
            "image, linker.cpp :3238-3241); it cannot provide symbols\n",
            im->basename.c_str());
    im->last.assign(im->entries.size(), 0);
    im->written.assign(im->entries.size(), 0);
    Image* raw = im.get();
    g_images.push_back(std::move(im));
    g_by_name[raw->basename] = raw;
    if (!raw->soname.empty()) g_by_name[raw->soname] = raw;

    Counts c;
    int n_logged = 0;
    for (size_t i = 0; i < raw->entries.size(); ++i)
        if (!bind_one(*raw, i, &c, &n_logged, false))
            g_pending.push_back({raw, i});
    // Other images' misses (or provisional answers) this image may now settle.
    retry_pending();
    std::fprintf(stderr,
        "[arm32-link] %s B=0x%x: %zu slot(s) -> %zu ARM32, %zu host-data, "
        "%zu host-fn, %zu flat, %zu weak-0, %zu UNRESOLVED, %zu provisional, "
        "%zu not written (mode=%s); %zu pending process-wide\n",
        raw->basename.c_str(), B, raw->entries.size(), c.arm32, c.host_data,
        c.host_fn, c.flat, c.weak0, c.unresolved, c.provisional, c.filtered,
        mode_name(mode), g_pending.size());
}

// Bionic-order lookup of `name` in a REGISTERED ARM32 image (by DT_SONAME or
// basename), or in the host-data table for a system library: the guest address
// Bionic's dlsym would return, 0 when absent. For debug/dataimport_gate.sh and
// a future guest dlsym.
__attribute__((visibility("default")))
uint32_t __macapk_arm32_dlsym_image(const char* lib, const char* name) {
    if (!lib || !name) return 0;
    std::lock_guard<std::mutex> lk(g_mtx);
    if (Image* im = find_image(lib)) {
        const SymHit h = lookup(*im, name);
        return h.ok ? h.value + im->B : 0;
    }
    if (is_system_lib(lib)) return host_data(lib, name);
    return 0;
}

}  // extern "C"
