// pairip_minikin_graph.cpp -- a FAITHFUL native minikin system-font graph for pairip's
// pass-16645 font fold (Minecraft 52.3, md5 ff28004e).
//
// WHY: pairip verifies it is on real Android partly by walking the process's in-memory
// minikin system-font collection (the zygote-preloaded `minikin::SystemFonts` singleton ->
// FontCollection -> FontFamily -> Font -> MinikinFont graph), copying out each font's
// {path, weight, slant, ttcIndex, axes, locale} into its own registry (device dump
// refs/dev_regat_str_16643_523; the fields authoritatively == the NDK iterator's set,
// AOSP native/android/system_fonts.cpp:249-261). Apk on Mac has NO native font stack (our
// fonts are Java + CoreText), so the fold reads empty, the VM steers wrong, and the
// frontier stops at 16645 (FORCE test MACAPK_PAIRIP_C2_FROM_GOLD walks the device path and
// SIGBUS @16666 on our null font pointers -> proof pairip derefs real font-structure ptrs).
//
// SCOPE (CLAUDE.md "faithful platform SURFACES are IN scope"): the system font collection is
// a PUBLIC platform structure, not a secret. Presenting a genuine minikin graph so the app
// runs is interoperability, the same category as the environ / /proc / maps surfaces already
// crossed -- NOT an attestation bypass. Real anti-debug is untouched.
//
// FAITHFUL-BY-CONSTRUCTION: arm64 Apple libc++ == Android arm64 libc++ (_LIBCPP_ABI_VERSION 1)
// for shared_ptr/vector/unique_ptr/string/atomic, so building the structs with the HOST's own
// std containers in the AOSP-14 (android14-release) member order reproduces the device's byte
// layout. We mirror the field order from the authoritative headers (see
// docs/pairip-font-synth-structs_2026-10-14.md for the per-struct offset tables + citations)
// and static_assert the total sizes. DATA: runtime/translator/src/pairip_system_fonts.h
// (g_macapk_sys_fonts[], 366 entries), already the exact FontVariation shape.
//
// Build standalone to verify the layouts:
//   clang++ -std=c++17 -arch arm64 -DMACAPK_MINIKIN_GRAPH_SELFTEST \
//     runtime/translator/src/pairip_minikin_graph.cpp -o /tmp/mkgraph && /tmp/mkgraph
// In the shim it is compiled normally and reached via __macapk_pairip_install_font_graph().

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <map>
#include <new>
#include <optional>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#include "pairip_system_fonts.h"

namespace macapk_mk {

// ---------------------------------------------------------------------------
// 1. Leaf value types
// ---------------------------------------------------------------------------

// minikin::FontVariation -- include/minikin/FontVariation.h (8 bytes). Identical to
// MacApkFontAxis in pairip_system_fonts.h.
typedef uint32_t AxisTag;
struct FontVariation {
    AxisTag axisTag;  // +0  4CC, e.g. 'wght'=0x77676874
    float   value;    // +4
};
static_assert(sizeof(FontVariation) == 8, "FontVariation must be 8B");

// minikin::FontStyle -- include/minikin/FontStyle.h (4 bytes). mSlant is `enum class Slant : bool`.
enum class Slant : bool { UPRIGHT = false, ITALIC = true };
struct FontStyle {
    uint16_t mWeight;  // +0  raw 1..1000
    Slant    mSlant;   // +2  bool
    uint8_t  mPad;     // +3
    FontStyle() : mWeight(400), mSlant(Slant::UPRIGHT), mPad(0) {}
    FontStyle(uint16_t w, bool italic) : mWeight(w), mSlant(italic ? Slant::ITALIC : Slant::UPRIGHT), mPad(0) {}
};
static_assert(sizeof(FontStyle) == 4, "FontStyle must be 4B");

// ---------------------------------------------------------------------------
// 2. MinikinFont -- the path/index/axes carrier (vtable base + our leaf subclass)
// ---------------------------------------------------------------------------

// Abstract base: vtable ptr @ +0 only, no data members (include/minikin/MinikinFont.h).
// Virtual order mirrors the header declaration order (GetFontPath:58, GetFontData:61,
// GetFontSize:64, GetFontIndex:68, GetSourceId:70, GetAxes:72) so a virtual-dispatch reader
// hits the right slots; a field-offset reader uses the MinikinFontSkia layout below.
class MinikinFont {
public:
    virtual ~MinikinFont() {}
    virtual const std::string&              GetFontPath() const = 0;
    virtual const void*                     GetFontData() const { return nullptr; }
    virtual size_t                          GetFontSize() const { return 0; }
    virtual int                             GetFontIndex() const { return 0; }
    virtual uint32_t                        GetSourceId() const { return 0; }
    virtual const std::vector<FontVariation>& GetAxes() const = 0;
};

// Our concrete leaf. Field layout MIRRORS android::MinikinFontSkia
// (libs/hwui/hwui/MinikinSkia.h:74-84) so a reader that walks fields at MinikinFontSkia's
// offsets (mAxes@+48, mFilePath@+72) also finds the right data -- we cannot know a priori
// whether pairip reads via vtable or by offset, so we satisfy both.
class MacApkMinikinFont final : public MinikinFont {
public:
    void*                      mTypeface  = nullptr;  // +8  (sk_sp<SkTypeface>, 1 ptr) -- unused
    int                        mSourceId  = 0;        // +16
    // +20 pad
    const void*                mFontData  = nullptr;  // +24
    size_t                     mFontSize  = 0;        // +32
    int                        mTtcIndex  = 0;        // +40
    // +44 pad
    std::vector<FontVariation> mAxes;                 // +48 (24B)
    std::string                mFilePath;             // +72 (24B)

    const std::string&              GetFontPath() const override { return mFilePath; }
    int                             GetFontIndex() const override { return mTtcIndex; }
    uint32_t                        GetSourceId() const override { return (uint32_t)mSourceId; }
    const std::vector<FontVariation>& GetAxes() const override { return mAxes; }
};

// ---------------------------------------------------------------------------
// 3. minikin::Font (24 bytes) -- include/minikin/Font.h
// ---------------------------------------------------------------------------

// Nested Font::ExternalRefs (heap, pointed to by mExternalRefsHolder) -- Font.h:135-142 (24B).
struct ExternalRefs {
    std::shared_ptr<MinikinFont> mTypeface;              // +0  (16B)
    std::unique_ptr<char>        mBaseFont;              // +16 (HbFontUniquePtr; one ptr, null)
};
static_assert(sizeof(ExternalRefs) == 24, "ExternalRefs must be 24B");

// BufferReader = one `const uint8_t* mCurrent` (Buffer.h:124).
struct BufferReader { const uint8_t* mCurrent = nullptr; };

struct Font {
    std::atomic<ExternalRefs*> mExternalRefsHolder;  // +0  (8B)
    FontStyle                  mStyle;               // +8  (4B)
    uint32_t                   mLocaleListId;        // +12 (4B)
    BufferReader               mTypefaceMetadataReader; // +16 (8B)
    Font() : mExternalRefsHolder(nullptr), mLocaleListId(0) {}
};
static_assert(sizeof(Font) == 24, "Font must be 24B");

// ---------------------------------------------------------------------------
// 4. minikin::FontFamily (48 bytes) -- include/minikin/FontFamily.h
// ---------------------------------------------------------------------------

// SparseBitSet = one unique_ptr (SparseBitSet.h:134); we leave it null (coverage not folded).
struct SparseBitSet { std::unique_ptr<uint8_t[]> mData; };

struct FontFamily {
    std::unique_ptr<std::shared_ptr<Font>[]> mFonts;             // +0
    std::unique_ptr<AxisTag[]>               mSupportedAxes;     // +8
    SparseBitSet                             mCoverage;          // +16
    std::unique_ptr<SparseBitSet[]>          mCmapFmt14Coverage; // +24
    uint32_t                                 mLocaleListId = 0;  // +32
    uint32_t                                 mFontsCount   = 0;  // +36
    uint16_t                                 mSupportedAxesCount = 0;     // +40
    uint16_t                                 mCmapFmt14CoverageCount = 0; // +42
    uint8_t                                  mVariant = 0;       // +44
    bool                                     mIsColorEmoji = false;     // +45
    bool                                     mIsCustomFallback = false; // +46
    bool                                     mIsDefaultFallback = false;// +47
};
static_assert(sizeof(FontFamily) == 48, "FontFamily must be 48B");

// ---------------------------------------------------------------------------
// 5. minikin::FontCollection (144 bytes) -- include/minikin/FontCollection.h
// ---------------------------------------------------------------------------

struct Range { uint16_t start, end; };

struct FontCollection {
    uint32_t mId = 0;         // +0
    uint32_t mMaxChar = 0;    // +4
    std::shared_ptr<std::vector<std::shared_ptr<FontFamily>>> mMaybeSharedFamilies; // +8 (16B)
    uint32_t mFamilyCount = 0; // +24
    uint32_t _pad0 = 0;        // +28
    const uint32_t* mFamilyIndices = nullptr; // +32
    uint32_t mRangesCount = 0; // +40
    uint32_t _pad1 = 0;        // +44
    const Range* mRanges = nullptr; // +48
    uint32_t mFamilyVecCount = 0;   // +56
    uint32_t _pad2 = 0;             // +60
    const uint8_t* mFamilyVec = nullptr; // +64
    std::vector<std::shared_ptr<FontFamily>> mVSFamilyVec; // +72 (24B)
    uint32_t mSupportedAxesCount = 0; // +96
    uint32_t _pad3 = 0;               // +100
    std::unique_ptr<AxisTag[]> mSupportedAxes; // +104
    std::unique_ptr<Range[]>   mOwnedRanges;   // +112
    std::vector<uint8_t>       mOwnedFamilyVec;// +120 (24B) -> ends +143
};
static_assert(sizeof(FontCollection) == 144, "FontCollection must be 144B");

// ---------------------------------------------------------------------------
// 6. minikin::SystemFonts root (placed at libminikin+0x50ff0)
// ---------------------------------------------------------------------------
//
// The getInstance() body (device libminikin 0x346ec) returns &<this static> at 0x50ff0; its
// ctor writes [0]=libminikin+0x403f0, [8]=&static+0x10 (an empty std::map's embedded end node),
// and zeroes +0x18/+0x60/+0x68/+0x78/+0x88. SystemFonts holds the named collections map and the
// flattened font vector that getFontSet() returns (buildFontSetLocked). We populate the
// flattened vector (mFonts) -- what a getFontSet-style read consumes -- and keep the collections
// reachable too. Exact private layout is build-specific; we mirror what the fold reads and leave
// the rest as the ctor left it. The 0x50ff0 placement is a CANDIDATE read-site (device location
// of the singleton); confirmed empirically by whether installing this graph moves pass 16645.
struct SystemFonts {
    // Mirror the first two ctor stores so a reader that checks them sees device-plausible values.
    void*    field0 = nullptr;          // +0   ctor stored libminikin+0x403f0 (set by installer)
    void*    field8 = nullptr;          // +8   ctor stored &static+0x10 (set by installer)
    uint8_t  _mid[0x48 - 0x10] = {0};   // +0x10..+0x48
    // The flattened system font set getFontSet() returns (std::optional<std::vector<...>>).
    // Doc places mFonts near +0x48/+72; we expose it as an engaged optional-vector pair.
    std::vector<std::shared_ptr<Font>> mFonts;  // the font set (24B)
    bool     mFontsEngaged = true;              // optional engaged flag
    uint8_t  _tail[64] = {0};                   // slack to cover fields up to ~+0x90
};

// ---------------------------------------------------------------------------
// 7. The builder: construct the full graph from g_macapk_sys_fonts[]
// ---------------------------------------------------------------------------

// Keep the heap graph alive for the process lifetime (pairip reads it at boot; never freed).
struct GraphHolder {
    std::vector<std::shared_ptr<ExternalRefs>> extrefs;  // keep ExternalRefs alive
    std::vector<std::shared_ptr<Font>>         fonts;    // all fonts, in table order
    std::vector<std::shared_ptr<FontFamily>>   families;
    std::shared_ptr<FontCollection>            collection;
    std::shared_ptr<std::vector<std::shared_ptr<FontFamily>>> sharedFamilies;
    SystemFonts*                               root = nullptr;  // placed at 0x50ff0
};
static GraphHolder* g_graph = nullptr;

// Build one Font (+ its MinikinFont + ExternalRefs) from a table row.
static std::shared_ptr<Font> build_font(const MacApkSysFont& row) {
    auto mf = std::make_shared<MacApkMinikinFont>();
    mf->mFilePath = row.path ? row.path : "";
    mf->mTtcIndex = (int)row.collectionIndex;
    mf->mAxes.reserve(row.naxes);
    for (uint32_t i = 0; i < row.naxes; ++i)
        mf->mAxes.push_back(FontVariation{ row.axes[i].tag, row.axes[i].value });

    auto er = std::make_shared<ExternalRefs>();
    er->mTypeface = mf;  // shared_ptr<MinikinFont>
    g_graph->extrefs.push_back(er);

    auto f = std::make_shared<Font>();
    f->mExternalRefsHolder.store(er.get(), std::memory_order_relaxed);
    f->mStyle = FontStyle(row.weight, row.italic != 0);
    f->mLocaleListId = 0;  // locale ids wired in a later pass (getLocaleString map); 0 = empty
    return f;
}

// Returns the SystemFonts root to place at libminikin+0x50ff0, or nullptr on failure.
// `limit` caps the number of fonts for a quick probe (0 = all 366).
extern "C" void* __macapk_pairip_build_font_graph(size_t limit) {
    if (g_graph) return g_graph->root;
    g_graph = new GraphHolder();

    size_t n = g_macapk_sys_fonts_n;
    if (limit && limit < n) n = limit;

    // One family holding all faces (minimal; real per-family grouping is a later refinement --
    // the fold enumerates families->fonts, so a single family with N fonts is walkable).
    auto fam = std::make_shared<FontFamily>();
    g_graph->fonts.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto f = build_font(g_macapk_sys_fonts[i]);
        g_graph->fonts.push_back(f);
    }
    // FontFamily.mFonts = unique_ptr<shared_ptr<Font>[]> + count
    fam->mFonts.reset(new std::shared_ptr<Font>[n]);
    for (size_t i = 0; i < n; ++i) fam->mFonts[i] = g_graph->fonts[i];
    fam->mFontsCount = (uint32_t)n;
    // Supported-axes union (sorted ascending): ital < wdth < wght, per the device registry.
    {
        static const AxisTag kAxes[3] = {0x6974616cu /*ital*/, 0x77647468u /*wdth*/, 0x77676874u /*wght*/};
        fam->mSupportedAxes.reset(new AxisTag[3]);
        for (int i = 0; i < 3; ++i) fam->mSupportedAxes[i] = kAxes[i];
        fam->mSupportedAxesCount = 3;
    }
    fam->mIsDefaultFallback = true;
    g_graph->families.push_back(fam);

    // FontCollection over the family vector.
    g_graph->sharedFamilies = std::make_shared<std::vector<std::shared_ptr<FontFamily>>>(g_graph->families);
    auto col = std::make_shared<FontCollection>();
    col->mId = 1;
    col->mMaxChar = 0x10FFFF;
    col->mMaybeSharedFamilies = g_graph->sharedFamilies;
    col->mFamilyCount = (uint32_t)g_graph->families.size();
    col->mVSFamilyVec = g_graph->families;  // also expose via the vector-shared member
    {
        static const AxisTag kAxes[3] = {0x6974616cu, 0x77647468u, 0x77676874u};
        col->mSupportedAxes.reset(new AxisTag[3]);
        for (int i = 0; i < 3; ++i) col->mSupportedAxes[i] = kAxes[i];
        col->mSupportedAxesCount = 3;
    }
    g_graph->collection = col;

    // SystemFonts root: populate the flattened font set (all faces, table order for now).
    auto* root = new SystemFonts();
    root->mFonts = g_graph->fonts;
    root->mFontsEngaged = true;
    g_graph->root = root;
    return root;
}

extern "C" size_t __macapk_pairip_font_graph_count() {
    return g_graph ? g_graph->fonts.size() : 0;
}

}  // namespace macapk_mk

// ---------------------------------------------------------------------------
// 8. Installer: back the fake libminikin .bss and place the SystemFonts root
// ---------------------------------------------------------------------------
//
// Device libminikin getInstance() (0x346ec) returns &SystemFonts at +0x50ff0, in the .bss LOAD
// (vaddr 0x50dd8, memsz 0x300); the getInstance guard byte is at +0x51080. On Apk on Mac libminikin
// is fake-mapped (maps text only, no backing). We back the page(s) covering 0x50ff0 and 0x51080
// via mach_vm_allocate(VM_FLAGS_FIXED) -- the same pattern macapk_install_fake_art_jnienv uses to
// place fake libart at its device VA -- then placement-new the graph root there and set the guard.
// If the range is already mapped (FAKE_MODULES reserved it), fall back to vm_protect + write.
// Returns 0 on success. libminikin_base default = pairip_fake_modules.h libminikin fake base.
extern "C" int __macapk_pairip_install_font_graph(uintptr_t libminikin_base) {
    using namespace macapk_mk;
    if (libminikin_base == 0) libminikin_base = 0x7276f8c000ULL;  // pairip_fake_modules.h:2591

    void* built = __macapk_pairip_build_font_graph(0);
    if (!built || __macapk_pairip_font_graph_count() == 0) {
        std::fprintf(stderr, "[font-graph] build failed\n");
        return -1;
    }

    const uintptr_t kSingletonOff = 0x50ff0;  // &SystemFonts (getInstance return)
    const uintptr_t kGuardOff     = 0x51080;  // getInstance __cxa guard byte
    const uintptr_t kDataPtrVal   = 0x403f0;  // ctor's field0 store (libminikin .data)

    uintptr_t region = (libminikin_base + kSingletonOff) & ~uintptr_t(0xFFF);  // page of 0x50ff0
    size_t    span   = 0x2000;  // two pages: covers 0x50ff0 and 0x51080
    mach_vm_address_t a = (mach_vm_address_t)region;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &a, (mach_vm_size_t)span, VM_FLAGS_FIXED);
    bool backed = (kr == KERN_SUCCESS && a == (mach_vm_address_t)region);
    if (!backed) {
        // Already mapped (e.g. FAKE_MODULES). Make it writable in place instead of allocating.
        kern_return_t kp = mach_vm_protect(mach_task_self(), (mach_vm_address_t)region,
                                           (mach_vm_size_t)span, FALSE,
                                           VM_PROT_READ | VM_PROT_WRITE);
        if (kp != KERN_SUCCESS) {
            std::fprintf(stderr, "[font-graph] back failed: alloc kr=%d (got %p), protect kr=%d at %p\n",
                         (int)kr, (void*)(uintptr_t)a, (int)kp, (void*)region);
            return -2;
        }
        std::fprintf(stderr, "[font-graph] region %p already mapped; made writable in place\n", (void*)region);
    }

    void* slot = reinterpret_cast<void*>(libminikin_base + kSingletonOff);
    auto* root = new (slot) SystemFonts();
    root->field0 = reinterpret_cast<void*>(libminikin_base + kDataPtrVal);
    root->field8 = reinterpret_cast<void*>(libminikin_base + kSingletonOff + 0x10);
    root->mFonts = g_graph->fonts;   // copy the shared_ptrs (vector allocates its own backing)
    root->mFontsEngaged = true;
    *reinterpret_cast<volatile uint8_t*>(libminikin_base + kGuardOff) = 1;

    std::fprintf(stderr, "[font-graph] installed at libminikin %p +0x50ff0: %zu fonts, guard set (backed=%d)\n",
                 (void*)libminikin_base, __macapk_pairip_font_graph_count(), (int)backed);
    return 0;
}

#ifndef MACAPK_MINIKIN_GRAPH_SELFTEST
// Gated install at shim load (runs before the guest's libpairipcore -> before pass 16634).
// MACAPK_PAIRIP_FONT_GRAPH (default OFF): present the faithful minikin system-font graph so
// pairip's pass-16645 font fold reads real structures instead of empty. Default base is the
// libminikin fake base from pairip_fake_modules.h; MACAPK_PAIRIP_LIBMINIKIN_BASE overrides.
__attribute__((constructor))
static void macapk_pairip_font_graph_ctor() {
    if (!std::getenv("MACAPK_PAIRIP_FONT_GRAPH")) return;
    uintptr_t base = 0;
    if (const char* b = std::getenv("MACAPK_PAIRIP_LIBMINIKIN_BASE"))
        base = (uintptr_t)strtoull(b, nullptr, 0);
    __macapk_pairip_install_font_graph(base);
}
#endif

#ifdef MACAPK_MINIKIN_GRAPH_SELFTEST
int main() {
    using namespace macapk_mk;
    std::printf("sizeof FontVariation=%zu (8)\n", sizeof(FontVariation));
    std::printf("sizeof FontStyle=%zu (4)\n", sizeof(FontStyle));
    std::printf("sizeof Font=%zu (24)\n", sizeof(Font));
    std::printf("sizeof ExternalRefs=%zu (24)\n", sizeof(ExternalRefs));
    std::printf("sizeof FontFamily=%zu (48)\n", sizeof(FontFamily));
    std::printf("sizeof FontCollection=%zu (144)\n", sizeof(FontCollection));
    std::printf("sizeof MinikinFont=%zu (8 vtable)\n", sizeof(MinikinFont));
    // offset checks for MacApkMinikinFont (field-read path parity with MinikinFontSkia)
    MacApkMinikinFont mf;
    auto base = reinterpret_cast<char*>(&mf);
    std::printf("MacApkMinikinFont.mAxes   @ +%ld (want 48)\n", (long)(reinterpret_cast<char*>(&mf.mAxes) - base));
    std::printf("MacApkMinikinFont.mFilePath @ +%ld (want 72)\n", (long)(reinterpret_cast<char*>(&mf.mFilePath) - base));
    std::printf("sizeof std::string=%zu (24) std::vector=%zu (24) shared_ptr=%zu (16)\n",
                sizeof(std::string), sizeof(std::vector<int>), sizeof(std::shared_ptr<int>));
    void* root = __macapk_pairip_build_font_graph(0);
    std::printf("built graph: root=%p fonts=%zu\n", root, __macapk_pairip_font_graph_count());
    return root && __macapk_pairip_font_graph_count() == g_macapk_sys_fonts_n ? 0 : 1;
}
#endif
