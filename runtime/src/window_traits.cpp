// window_traits.cpp -- see include/macapk/window_traits.h.
//
// AXML layout (AOSP ResourceTypes.h, the same one apk_unpacker.cpp's
// ParseBinaryManifest and BinaryXmlParser.java read): ResChunk_header{u16 type,
// u16 headerSize, u32 size}; RES_STRING_POOL 0x0001, RES_XML_RESOURCE_MAP
// 0x0180, START_ELEMENT 0x0102, END_ELEMENT 0x0103. An attribute record is
// {ns u32, name u32, rawValue u32, Res_value{size u16, res0 u8, dataType u8,
// data u32}} -- dataType at +15, data at +16.
//
// Attribute ids are matched by pool NAME or by resource id, because aapt2 may
// emit an empty name and rely on the resource map. Every id below was MEASURED
// from the resource maps of the 62 corpus manifests (the pool name and the id
// sit at the same index), not recalled: screenOrientation 0x0101001e,
// resizeableActivity 0x010104f6, supportsPictureInPicture 0x010104f7,
// appCategory 0x01010545, targetActivity 0x01010202, enabled 0x0101000e,
// name 0x01010003, value 0x01010024, minSdkVersion 0x0101020c,
// targetSdkVersion 0x01010270, smallScreens 0x01010284, normalScreens
// 0x01010285, largeScreens 0x01010286, resizeable 0x0101028d, anyDensity
// 0x0101026c, xlargeScreens 0x010102bf. No corpus manifest declares the other
// five, so their ids come from com/macapk/loader/FrameworkAttrIds.java, the
// table generated from android16 core/res/res/values/public-final.xml (whose
// ids can never be reassigned): maxAspectRatio 0x01010560, minAspectRatio
// 0x0101059b, requiresSmallestWidthDp 0x01010364, compatibleWidthLimitDp
// 0x01010365, largestWidthLimitDp 0x01010366. The same extraction reproduces
// all sixteen measured ids above, which is the check that it was read right.
// android:theme is 0x01010000 (public-final.xml: <public type="attr"
// name="theme" id="0x01010000" />, the first attr id there is).
#include "macapk/window_traits.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#ifndef MACAPK_WINPOLICY_MUTANT
#define MACAPK_WINPOLICY_MUTANT 0
#endif
#define WP_MUTANT(n) (MACAPK_WINPOLICY_MUTANT == (n))

namespace macapk {
namespace winpolicy {

namespace {

// Res_value data types; TYPE_INT_BOOLEAN (0x12) falls inside IsIntType.
constexpr uint8_t kTypeReference = 0x01, kTypeString = 0x03, kTypeFloat = 0x04;

// The five framework attr ids no corpus manifest exercises (see the header
// comment for their source). Mutant 22 zeroes them, i.e. the pre-review
// name-only match, which an aapt2 build that blanks attribute names defeats.
constexpr uint32_t kIdMaxAspectRatio          = WP_MUTANT(22) ? 0 : 0x01010560;
constexpr uint32_t kIdMinAspectRatio          = WP_MUTANT(22) ? 0 : 0x0101059b;
constexpr uint32_t kIdRequiresSmallestWidthDp = WP_MUTANT(22) ? 0 : 0x01010364;
constexpr uint32_t kIdCompatibleWidthLimitDp  = WP_MUTANT(22) ? 0 : 0x01010365;
constexpr uint32_t kIdLargestWidthLimitDp     = WP_MUTANT(22) ? 0 : 0x01010366;

bool IsIntType(uint8_t t) { return t >= 0x10 && t <= 0x1f; }

constexpr uint32_t kIdTheme = 0x01010000;   // android:theme

// ---- framework theme window styles (window_traits.h FrameworkThemeWindowStyle) ----
// Generated 2026-09-25 from aosp-mirror platform_frameworks_base android14-release
// core/res/res/values/{themes,themes_holo,themes_material,themes_device_defaults}.xml
// (+ values-large/ for the DialogWhenLarge rows): every <public type="style">
// Theme* id in public-final.xml, its <item name="windowIsTranslucent" |
// "windowIsFloating" | "windowShowWallpaper" | "windowNoDisplay"> taken from the
// nearest style in its parent chain (explicit parent=, else the dotted prefix)
// that declares it. Only rows with a flag set are listed; e.g. Theme.Translucent
// declares windowIsTranslucent=true (themes.xml), Theme.Dialog
// windowIsFloating=true, Theme.Wallpaper windowShowWallpaper=true, Theme.NoDisplay
// windowIsTranslucent + windowNoDisplay. FrameworkWindowStyle.java carries the
// SAME rows (debug/winpolicy_gate.sh compares them).
const FrameworkWindowStyleRow kFrameworkWindowStyles[] = {
    {0x0103000b, "Theme.Dialog", kStyleFloating},
    {0x0103000f, "Theme.Translucent", kStyleTranslucent},
    {0x01030010, "Theme.Translucent.NoTitleBar", kStyleTranslucent},
    {0x01030011, "Theme.Translucent.NoTitleBar.Fullscreen", kStyleTranslucent},
    {0x01030054, "Theme.InputMethod", kStyleTranslucent | kStyleFloating},
    {0x01030055, "Theme.NoDisplay", kStyleTranslucent | kStyleNoDisplay},
    {0x01030059, "Theme.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103005a, "Theme.Light.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103005e, "Theme.Wallpaper", kStyleShowWallpaper},
    {0x0103005f, "Theme.Wallpaper.NoTitleBar", kStyleShowWallpaper},
    {0x01030060, "Theme.Wallpaper.NoTitleBar.Fullscreen", kStyleShowWallpaper},
    {0x01030061, "Theme.WallpaperSettings", kStyleTranslucent},
    {0x01030062, "Theme.Light.WallpaperSettings", kStyleTranslucent},
    {0x0103006f, "Theme.Holo.Dialog", kStyleFloating},
    {0x01030070, "Theme.Holo.Dialog.MinWidth", kStyleFloating},
    {0x01030071, "Theme.Holo.Dialog.NoActionBar", kStyleFloating},
    {0x01030072, "Theme.Holo.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x01030073, "Theme.Holo.Light.Dialog", kStyleFloating},
    {0x01030074, "Theme.Holo.Light.Dialog.MinWidth", kStyleFloating},
    {0x01030075, "Theme.Holo.Light.Dialog.NoActionBar", kStyleFloating},
    {0x01030076, "Theme.Holo.Light.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x01030077, "Theme.Holo.DialogWhenLarge", kStyleFloating},  // values-large
    {0x01030078, "Theme.Holo.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x01030079, "Theme.Holo.Light.DialogWhenLarge", kStyleFloating},  // values-large
    {0x0103007a, "Theme.Holo.Light.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x0103007b, "Theme.Holo.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103007c, "Theme.Holo.Light.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103007d, "Theme.Holo.Wallpaper", kStyleShowWallpaper},
    {0x0103007e, "Theme.Holo.Wallpaper.NoTitleBar", kStyleShowWallpaper},
    {0x0103007f, "Theme.Holo.InputMethod", kStyleTranslucent | kStyleFloating},
    {0x0103012e, "Theme.DeviceDefault.Dialog", kStyleFloating},
    {0x0103012f, "Theme.DeviceDefault.Dialog.MinWidth", kStyleFloating},
    {0x01030130, "Theme.DeviceDefault.Dialog.NoActionBar", kStyleFloating},
    {0x01030131, "Theme.DeviceDefault.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x01030132, "Theme.DeviceDefault.Light.Dialog", kStyleFloating},
    {0x01030133, "Theme.DeviceDefault.Light.Dialog.MinWidth", kStyleFloating},
    {0x01030134, "Theme.DeviceDefault.Light.Dialog.NoActionBar", kStyleFloating},
    {0x01030135, "Theme.DeviceDefault.Light.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x01030136, "Theme.DeviceDefault.DialogWhenLarge", kStyleFloating},  // values-large
    {0x01030137, "Theme.DeviceDefault.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x01030138, "Theme.DeviceDefault.Light.DialogWhenLarge", kStyleFloating},  // values-large
    {0x01030139, "Theme.DeviceDefault.Light.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x0103013a, "Theme.DeviceDefault.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103013b, "Theme.DeviceDefault.Light.Panel", kStyleTranslucent | kStyleFloating},
    {0x0103013c, "Theme.DeviceDefault.Wallpaper", kStyleShowWallpaper},
    {0x0103013d, "Theme.DeviceDefault.Wallpaper.NoTitleBar", kStyleShowWallpaper},
    {0x0103013e, "Theme.DeviceDefault.InputMethod", kStyleTranslucent | kStyleFloating},
    {0x01030225, "Theme.Material.Dialog", kStyleFloating},
    {0x01030226, "Theme.Material.Dialog.Alert", kStyleFloating},
    {0x01030227, "Theme.Material.Dialog.MinWidth", kStyleFloating},
    {0x01030228, "Theme.Material.Dialog.NoActionBar", kStyleFloating},
    {0x01030229, "Theme.Material.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x0103022b, "Theme.Material.DialogWhenLarge", kStyleFloating},  // values-large
    {0x0103022c, "Theme.Material.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x0103022d, "Theme.Material.InputMethod", kStyleTranslucent | kStyleFloating},
    {0x01030232, "Theme.Material.Panel", kStyleTranslucent | kStyleFloating},
    {0x01030234, "Theme.Material.Voice", kStyleFloating},
    {0x01030235, "Theme.Material.Wallpaper", kStyleShowWallpaper},
    {0x01030236, "Theme.Material.Wallpaper.NoTitleBar", kStyleShowWallpaper},
    {0x01030239, "Theme.Material.Light.Dialog", kStyleFloating},
    {0x0103023a, "Theme.Material.Light.Dialog.Alert", kStyleFloating},
    {0x0103023b, "Theme.Material.Light.Dialog.MinWidth", kStyleFloating},
    {0x0103023c, "Theme.Material.Light.Dialog.NoActionBar", kStyleFloating},
    {0x0103023d, "Theme.Material.Light.Dialog.NoActionBar.MinWidth", kStyleFloating},
    {0x0103023f, "Theme.Material.Light.DialogWhenLarge", kStyleFloating},  // values-large
    {0x01030240, "Theme.Material.Light.DialogWhenLarge.NoActionBar", kStyleFloating},  // values-large
    {0x01030245, "Theme.Material.Light.Panel", kStyleTranslucent | kStyleFloating},
    {0x01030246, "Theme.Material.Light.Voice", kStyleFloating},
    {0x010302d1, "Theme.DeviceDefault.Dialog.Alert", kStyleFloating},
    {0x010302d2, "Theme.DeviceDefault.Light.Dialog.Alert", kStyleFloating},
    {0x010302d6, "ThemeOverlay.Material.Dialog", kStyleFloating},
    {0x010302d7, "ThemeOverlay.Material.Dialog.Alert", kStyleFloating},
};

std::string ShellQuote(const std::string& s) {
    std::string o = "'";
    for (char c : s) { if (c == '\'') o += "'\\''"; else o.push_back(c); }
    return o + "'";
}

bool Capture(const std::string& cmd, std::string* out) {
    out->clear();
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, p)) > 0) out->append(buf, n);
    pclose(p);                     // tar --fast-read reaps unzip with SIGPIPE
    return !out->empty();
}

// The SDK level the package parser's Resources run at. ParsingPackageUtils
// builds them as `new Resources(assets, mDisplayMetrics, null)` (PPU16:598),
// and ResourcesImpl.updateConfiguration hands the AssetManager
// Build.VERSION.RESOURCES_SDK_INT -- the PLATFORM's level, which is the
// android16 model this policy ports, not the SDK Mac.apk presents to the app.
constexpr uint32_t kParserResourcesSdk = 36;

// ResTable_config (AOSP ResourceTypes.h; the same offsets ArscReader.java
// reads): size u32 @0, imsi @4, locale @8, screenType @12 (orientation,
// touchscreen, density u16 @14), input @16, screenSize @20, version @24
// (sdkVersion u16 @24, minorVersion u16 @26), then screenConfig, screenSizeDp
// and the rest. `cfg` points at the size field.
//
// Which entries the parser's configuration can select. It sets ONLY the SDK
// level (and the display density, which no manifest-referenced bool or integer
// is qualified by in practice), so an entry matches when every other field is
// zero and its sdkVersion is at most kParserResourcesSdk; among matches the
// highest sdkVersion wins (ResTable_config::isBetterThan prefers the larger
// version when both match). An entry qualified by anything else (sw600dp,
// land, a locale) never matches, and a reference with NO matching entry
// resolves to nothing, so the attribute keeps its default -- exactly what the
// parser does.
bool ParserConfigMatch(const uint8_t* cfg, size_t cfg_avail, uint32_t* sdk_out) {
    if (cfg_avail < 4) return false;
    const uint32_t size = cfg[0] | (uint32_t(cfg[1]) << 8) | (uint32_t(cfg[2]) << 16)
                        | (uint32_t(cfg[3]) << 24);
    const size_t n = std::min<size_t>(size, cfg_avail);
    uint32_t sdk = 0;
    for (size_t c = 4; c < n; ++c) {
        if (c == 24 || c == 25) continue;
        if (cfg[c] != 0) return false;
    }
    if (n >= 26) sdk = cfg[24] | (uint32_t(cfg[25]) << 8);
    if (sdk > kParserResourcesSdk) return false;
    *sdk_out = sdk;
    return true;
}

// ---- resources.arsc: (type, data) of one id at the PARSER's configuration ----
// Same chunk walk as apk_unpacker.cpp ArscResolveString (which mirrors the
// apktool-differentialled ArscReader.java); follows up to 4 reference hops.
bool ArscLookup(const std::string& arsc, uint32_t resid, uint8_t* out_type, uint32_t* out_data) {
    if (arsc.size() < 12 || resid == 0) return false;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(arsc.data());
    const size_t n = arsc.size();
    auto u16 = [&](size_t o) -> uint32_t { return (o + 1 < n) ? (b[o] | (uint32_t(b[o + 1]) << 8)) : 0; };
    auto i32 = [&](size_t o) -> uint32_t {
        return (o + 3 < n) ? (b[o] | (uint32_t(b[o + 1]) << 8) | (uint32_t(b[o + 2]) << 16)
                              | (uint32_t(b[o + 3]) << 24)) : 0;
    };
    if (u16(0) != 0x0002) return false;
    const size_t table_hdr = u16(2);
    const size_t table_total = std::min<size_t>(i32(4), n);
    for (int hop = 0; hop < 4 && resid != 0; ++hop) {
        const uint32_t want_pkg = (resid >> 24) & 0xff, want_type = (resid >> 16) & 0xff,
                       want_entry = resid & 0xffff;
        bool found = false, found_default = false;
        uint32_t found_sdk = 0;
        uint8_t dt = 0; uint32_t dv = 0;
        size_t off = table_hdr;
        while (off + 8 <= table_total) {
            const uint32_t type = u16(off), hdr = u16(off + 2), sz = i32(off + 4);
            if (sz < 8 || off + sz > table_total) break;
            if (type == 0x0200 && i32(off + 8) == want_pkg) {
                size_t p = off + hdr, pend = off + sz;
                while (p + 8 <= pend) {
                    const uint32_t ptype = u16(p), phdr = u16(p + 2), psz = i32(p + 4);
                    if (psz < 8 || p + psz > pend) break;
                    if (ptype == 0x0201 && !(WP_MUTANT(21) && found_default)
                        && p + 24 <= n && b[p + 8] == want_type) {
                        const uint32_t tflags = b[p + 9], ecount = i32(p + 12),
                                       estart = i32(p + 16), cfg_size = i32(p + 20);
                        bool is_default = true;
                        for (uint32_t c = 4; c < cfg_size && p + 20 + c < n; ++c)
                            if (b[p + 20 + c] != 0) { is_default = false; break; }
                        uint32_t cfg_sdk = 0;
                        const bool usable = WP_MUTANT(21)
                            || ParserConfigMatch(b + p + 20, n - (p + 20), &cfg_sdk);
                        const size_t off_array = p + phdr, entries = p + estart;
                        uint32_t rel = 0xffffffffu;
                        if (tflags & 0x01) {                        // FLAG_SPARSE
                            for (uint32_t i = 0; i < ecount; ++i) {
                                uint32_t packed = i32(off_array + size_t(i) * 4);
                                if ((packed & 0xffff) == want_entry) { rel = ((packed >> 16) & 0xffff) * 4u; break; }
                            }
                        } else if (want_entry < ecount) {
                            if (tflags & 0x02) {                    // FLAG_OFFSET16
                                uint32_t o16 = u16(off_array + size_t(want_entry) * 2);
                                rel = (o16 == 0xffff) ? 0xffffffffu : o16 * 4u;
                            } else {
                                rel = i32(off_array + size_t(want_entry) * 4);
                            }
                        }
                        if (rel != 0xffffffffu && entries + rel + 8 <= n) {
                            const size_t e = entries + rel;
                            const uint32_t eflags = u16(e + 2);
                            uint8_t t = 0; uint32_t v = 0; bool have = false;
                            if (eflags & 0x0008) { t = uint8_t((eflags >> 8) & 0xff); v = i32(e + 4); have = true; }
                            else if (!(eflags & 0x0001)) {
                                const size_t val = e + u16(e);
                                if (val + 8 <= n) { t = b[val + 3]; v = i32(val + 4); have = true; }
                            }
                            if (WP_MUTANT(21)) {
                                // Mutant 21: the pre-review rule -- any
                                // configuration, the all-zero one preferred.
                                if (have && (!found || is_default)) {
                                    dt = t; dv = v; found = true; found_default = is_default;
                                }
                            } else if (have && usable && (!found || cfg_sdk > found_sdk)) {
                                dt = t; dv = v; found = true; found_sdk = cfg_sdk;
                            }
                        }
                    }
                    p += psz;
                }
            }
            off += sz;
        }
        if (!found) return false;
        if (dt == kTypeReference && dv != 0 && dv != resid) { resid = dv; continue; }
        *out_type = dt; *out_data = dv;
        return true;
    }
    return false;
}

struct Attr {
    std::string name;
    uint32_t    resid = 0;
    uint8_t     type = 0;
    uint32_t    data = 0;
    std::string str;       // TYPE_STRING value
};

struct Resolver {
    const std::string& arsc;
    std::string* notes;
    // Resolve a @reference through resources.arsc; a literal passes through.
    bool Resolve(const Attr& a, uint8_t* t, uint32_t* d) const {
        if (a.type != kTypeReference) { *t = a.type; *d = a.data; return true; }
        if (ArscLookup(arsc, a.data, t, d)) return true;
        char buf[96];
        std::snprintf(buf, sizeof buf, "%sunresolved %s=@0x%08x", notes->empty() ? "" : "; ",
                      a.name.c_str(), a.data);
        *notes += buf;
        return false;
    }
    bool Bool(const Attr& a, bool* out) const {
        uint8_t t; uint32_t d;
        if (!Resolve(a, &t, &d) || !IsIntType(t)) return false;
        *out = d != 0;
        return true;
    }
    bool Int(const Attr& a, int* out) const {
        uint8_t t; uint32_t d;
        if (!Resolve(a, &t, &d) || !IsIntType(t)) return false;
        *out = static_cast<int>(d);
        return true;
    }
    bool Float(const Attr& a, float* out) const {
        uint8_t t; uint32_t d;
        if (!Resolve(a, &t, &d) || t != kTypeFloat) return false;
        std::memcpy(out, &d, sizeof *out);
        return true;
    }
};

// Build.VERSION_CODES for a <uses-sdk> value: a number, a numeric string, or a
// codename (a pre-release SDK), which parses as CUR_DEVELOPMENT (10000).
int SdkValue(const Attr& a, const Resolver& r, int dflt) {
    if (a.type == kTypeString) {
        if (a.str.empty()) return dflt;
        char* end = nullptr;
        const long v = std::strtol(a.str.c_str(), &end, 10);
        return (end && *end == '\0') ? static_cast<int>(v) : 10000;
    }
    int v;
    return r.Int(a, &v) ? v : dflt;
}

struct Comp {
    bool is_alias = false;
    std::string name, target;
    bool enabled = true;
    bool launcher = false;
    bool leanback_launcher = false;   // MAIN + LEANBACK_LAUNCHER in one filter
    ComponentTraits traits;
};

std::string Normalize(const std::string& pkg, const std::string& n) {
    if (n.empty()) return n;
    if (n[0] == '.') return pkg + n;
    if (n.find('.') == std::string::npos) return pkg + "." + n;
    return n;
}

// ParsedActivityImpl.makeAlias (PAI16:166-195) copies the target's
// screenOrientation, theme, flags (PiP among them), resizeMode and the max/min
// aspect ATTRIBUTE values; the meta-data (android.max_aspect,
// android.supports_size_changes) the post-passes read, and the <property>
// entries looked up by the launched component, are the ALIAS's own
// (PPU16:2943-2997 iterate pkg.getActivities(), aliases included; AR16:1852
// mActivityComponent = the intent's component). Mutant 20: the target's.
ComponentTraits AliasOf(const ComponentTraits& target, const ComponentTraits& own) {
    ComponentTraits a = target;
    if (!WP_MUTANT(20)) {
        a.has_meta_max_aspect = own.has_meta_max_aspect;
        a.meta_max_aspect = own.meta_max_aspect;
        a.meta_supports_size_changes = own.meta_supports_size_changes;
        a.prop_allow_restricted_resizability = own.prop_allow_restricted_resizability;
        a.prop_allow_user_aspect_override = own.prop_allow_user_aspect_override;
    }
    return a;
}

}  // namespace

WindowTraits ParseWindowTraits(const std::string& d, const std::string& arsc) {
    WindowTraits t;
    if (d.size() < 8) return t;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(d.data());
    const size_t n = d.size();
    auto u16 = [&](size_t o) -> uint32_t { return (o + 1 < n) ? (b[o] | (uint32_t(b[o + 1]) << 8)) : 0; };
    auto i32 = [&](size_t o) -> uint32_t {
        return (o + 3 < n) ? (b[o] | (uint32_t(b[o + 1]) << 8) | (uint32_t(b[o + 2]) << 16)
                              | (uint32_t(b[o + 3]) << 24)) : 0;
    };
    if (u16(0) != 0x0003) return t;
    t.ok = true;
    Resolver r{arsc, &t.notes};

    std::vector<std::string> pool;
    std::vector<uint32_t> resmap;
    std::vector<std::string> stack;          // open element tags
    std::vector<Comp> comps;
    Comp cur;
    bool in_comp = false;
    bool filter_main = false, filter_launcher = false, filter_leanback = false;
    bool comp_any_main = false, comp_any_launcher = false;   // mutant 10 only

    size_t off = u16(2);
    const size_t total = std::min<size_t>(i32(4), n);
    while (off + 8 <= total) {
        const uint32_t type = u16(off), hdr = u16(off + 2), sz = i32(off + 4);
        if (sz < 8 || off + sz > total) break;
        if (type == 0x0001) {                                   // string pool
            const uint32_t count = i32(off + 8), flags = i32(off + 16), str_start = i32(off + 20);
            const bool utf8 = (flags & 0x100) != 0;
            const size_t idx = off + hdr, base = off + str_start;
            pool.assign(count, std::string());
            for (uint32_t i = 0; i < count; ++i) {
                size_t so = base + i32(idx + size_t(i) * 4);
                if (so >= n) continue;
                if (utf8) {
                    size_t p = so;
                    if (p < n && (b[p] & 0x80)) p++;
                    p++;
                    if (p >= n) continue;
                    uint32_t blen = b[p++];
                    if (blen & 0x80) { blen = ((blen & 0x7f) << 8) | b[p++]; }
                    if (p + blen <= n) pool[i].assign(reinterpret_cast<const char*>(b + p), blen);
                } else {
                    size_t p = so;
                    uint32_t clen = u16(p); p += 2;
                    if (clen & 0x8000) { clen = ((clen & 0x7fff) << 16) | u16(p); p += 2; }
                    std::string s;
                    for (uint32_t c = 0; c < clen && p + 1 < n; ++c, p += 2) {
                        const uint32_t ch = u16(p);
                        s.push_back(ch < 0x80 ? char(ch) : '?');   // names/ids are ASCII
                    }
                    pool[i] = s;
                }
            }
        } else if (type == 0x0180) {                            // resource map
            const uint32_t count = (sz - hdr) / 4;
            resmap.resize(count);
            for (uint32_t i = 0; i < count; ++i) resmap[i] = i32(off + hdr + size_t(i) * 4);
        } else if (type == 0x0102) {                            // START_ELEMENT
            const size_t ext = off + hdr;
            const uint32_t name_idx = i32(ext + 4);
            const std::string tag = name_idx < pool.size() ? pool[name_idx] : "";
            const std::string parent = stack.empty() ? "" : stack.back();
            stack.push_back(tag);
            std::vector<Attr> attrs;
            {
                const uint32_t attr_start = u16(ext + 8), attr_size = u16(ext + 10),
                               attr_count = u16(ext + 12);
                for (uint32_t i = 0; i < attr_count; ++i) {
                    const size_t a = ext + attr_start + size_t(i) * attr_size;
                    if (a + 20 > total) break;
                    Attr at;
                    const uint32_t an = i32(a + 4), raw = i32(a + 8);
                    at.name = an < pool.size() ? pool[an] : "";
                    at.resid = an < resmap.size() ? resmap[an] : 0;
                    at.type = b[a + 15];
                    at.data = i32(a + 16);
                    if (at.type == kTypeString && at.data < pool.size()) at.str = pool[at.data];
                    else if (raw < pool.size()) at.str = pool[raw];
                    attrs.push_back(at);
                }
            }
            auto is = [](const Attr& a, const char* nm, uint32_t id) {
                return a.name == nm || (id != 0 && a.resid == id);
            };
            if (tag == "manifest" && parent.empty()) {
                for (const Attr& a : attrs)
                    if (a.name == "package" && a.type == kTypeString) t.package = a.str;
            } else if (tag == "uses-sdk" && parent == "manifest") {
                t.has_uses_sdk = true;
                bool have_target = false;
                int min_v = 1, target_v = 0;
                for (const Attr& a : attrs) {
                    if (is(a, "minSdkVersion", 0x0101020c)) min_v = SdkValue(a, r, 1);
                    else if (is(a, "targetSdkVersion", 0x01010270)) {
                        target_v = SdkValue(a, r, 0); have_target = true;
                    }
                }
                t.min_sdk = min_v;
                t.target_sdk = have_target ? target_v : min_v;   // PPU: target falls back to min
            } else if (tag == "supports-screens" && parent == "manifest") {
                for (const Attr& a : attrs) {
                    int v;
                    int* slot = nullptr;
                    if (is(a, "smallScreens", 0x01010284))        slot = &t.small_screens;
                    else if (is(a, "normalScreens", 0x01010285))  slot = &t.normal_screens;
                    else if (is(a, "largeScreens", 0x01010286))   slot = &t.large_screens;
                    else if (is(a, "xlargeScreens", 0x010102bf))  slot = &t.xlarge_screens;
                    else if (is(a, "resizeable", 0x0101028d))     slot = &t.resizeable_screens;
                    else if (is(a, "anyDensity", 0x0101026c))     slot = &t.any_density;
                    if (slot && r.Int(a, &v)) { *slot = v; continue; }
                    if (is(a, "requiresSmallestWidthDp", kIdRequiresSmallestWidthDp) && r.Int(a, &v))
                        t.requires_smallest_width_dp = v;
                    else if (is(a, "compatibleWidthLimitDp", kIdCompatibleWidthLimitDp) && r.Int(a, &v))
                        t.compatible_width_limit_dp = v;
                    else if (is(a, "largestWidthLimitDp", kIdLargestWidthLimitDp) && r.Int(a, &v))
                        t.largest_width_limit_dp = v;
                }
            } else if (tag == "application" && parent == "manifest") {
                for (const Attr& a : attrs) {
                    bool bv; int iv; float fv;
                    if (is(a, "resizeableActivity", 0x010104f6)) {
                        if (r.Bool(a, &bv)) t.app_resizeable_activity = bv ? Tri::kTrue : Tri::kFalse;
                        else t.app_resizeable_activity = Tri::kTrue;   // hasValueOrEmpty, default true
                    } else if (is(a, "appCategory", 0x01010545)) {
                        if (r.Int(a, &iv)) t.app_category = iv;
                    } else if (is(a, "maxAspectRatio", kIdMaxAspectRatio)) {
                        // aFloat(...): any float. A non-float reads as 0 = unset.
                        if (r.Float(a, &fv)) { t.app_has_max_aspect = true; t.app_max_aspect = fv; }
                    } else if (is(a, "minAspectRatio", kIdMinAspectRatio)) {
                        if (r.Float(a, &fv)) { t.app_has_min_aspect = true; t.app_min_aspect = fv; }
                    } else if (is(a, "theme", kIdTheme) && a.type == kTypeReference) {
                        t.app_theme = a.data;
                    }
                }
            } else if ((tag == "activity" || tag == "activity-alias") && parent == "application") {
                cur = Comp();
                cur.is_alias = (tag == "activity-alias");
                in_comp = true;
                comp_any_main = comp_any_launcher = false;
                for (const Attr& a : attrs) {
                    bool bv; int iv; float fv;
                    if (is(a, "name", 0x01010003) && a.type == kTypeString) cur.name = a.str;
                    else if (is(a, "targetActivity", 0x01010202) && a.type == kTypeString) cur.target = a.str;
                    else if (is(a, "enabled", 0x0101000e)) { if (r.Bool(a, &bv)) cur.enabled = bv; }
                    else if (is(a, "screenOrientation", 0x0101001e)) {
                        if (r.Int(a, &iv)) cur.traits.screen_orientation = iv;
                    } else if (is(a, "resizeableActivity", 0x010104f6)) {
                        if (r.Bool(a, &bv)) cur.traits.resizeable_activity = bv ? Tri::kTrue : Tri::kFalse;
                    } else if (is(a, "supportsPictureInPicture", 0x010104f7)) {
                        if (r.Bool(a, &bv)) cur.traits.supports_pip = bv;
                    } else if (is(a, "maxAspectRatio", kIdMaxAspectRatio)) {
                        if (r.Float(a, &fv)) { cur.traits.has_max_aspect = true; cur.traits.max_aspect = fv; }
                    } else if (is(a, "minAspectRatio", kIdMinAspectRatio)) {
                        if (r.Float(a, &fv)) { cur.traits.has_min_aspect = true; cur.traits.min_aspect = fv; }
                    } else if (is(a, "theme", kIdTheme) && a.type == kTypeReference) {
                        cur.traits.theme = a.data;   // the style id; the app-level fallback comes later
                    }
                }
            } else if (tag == "intent-filter" && in_comp && stack.size() >= 2
                       && (parent == "activity" || parent == "activity-alias")) {
                filter_main = filter_launcher = filter_leanback = false;
            } else if ((tag == "action" || tag == "category") && parent == "intent-filter" && in_comp) {
                for (const Attr& a : attrs) {
                    if (!is(a, "name", 0x01010003) || a.type != kTypeString) continue;
                    if (tag == "action" && a.str == "android.intent.action.MAIN") {
                        filter_main = true; comp_any_main = true;
                    }
                    if (tag == "category" && a.str == "android.intent.category.LAUNCHER") {
                        filter_launcher = true; comp_any_launcher = true;
                    }
                    if (tag == "category" && a.str == "android.intent.category.LEANBACK_LAUNCHER") {
                        filter_leanback = true;
                    }
                }
            } else if ((tag == "meta-data" || tag == "property")
                       && (parent == "application" || ((parent == "activity" || parent == "activity-alias") && in_comp))) {
                std::string key;
                const Attr* value = nullptr;
                for (const Attr& a : attrs) {
                    if (is(a, "name", 0x01010003) && a.type == kTypeString) key = a.str;
                    else if (is(a, "value", 0x01010024)) value = &a;
                }
                if (value) {
                    const bool at_app = (parent == "application");
                    ComponentTraits& ct = cur.traits;
                    bool bv; float fv;
                    if (tag == "meta-data" && key == "android.max_aspect") {
                        // Bundle.getFloat: only a FLOAT value counts.
                        if (r.Float(*value, &fv)) {
                            if (at_app) { t.app_has_meta_max_aspect = true; t.app_meta_max_aspect = fv; }
                            else        { ct.has_meta_max_aspect = true; ct.meta_max_aspect = fv; }
                        }
                    } else if (tag == "meta-data" && key == "android.supports_size_changes") {
                        if (r.Bool(*value, &bv)) {
                            if (at_app) t.app_meta_supports_size_changes = bv;
                            else        ct.meta_supports_size_changes = bv;
                        }
                    } else if (tag == "property"
                               && key == "android.window.PROPERTY_COMPAT_ALLOW_RESTRICTED_RESIZABILITY") {
                        if (r.Bool(*value, &bv)) {
                            (at_app ? t.app_prop_allow_restricted_resizability
                                    : ct.prop_allow_restricted_resizability) = bv ? Tri::kTrue : Tri::kFalse;
                        }
                    } else if (tag == "property"
                               && key == "android.window.PROPERTY_COMPAT_ALLOW_USER_ASPECT_RATIO_OVERRIDE") {
                        if (r.Bool(*value, &bv)) {
                            (at_app ? t.app_prop_allow_user_aspect_override
                                    : ct.prop_allow_user_aspect_override) = bv ? Tri::kTrue : Tri::kFalse;
                        }
                    }
                }
            }
        } else if (type == 0x0103) {                            // END_ELEMENT
            const std::string tag = stack.empty() ? "" : stack.back();
            if (!stack.empty()) stack.pop_back();
            const std::string parent = stack.empty() ? "" : stack.back();
            if (tag == "intent-filter" && in_comp
                && (parent == "activity" || parent == "activity-alias")) {
                // MAIN + LAUNCHER in the SAME filter (Manifest.findLaunchable).
                if (filter_main && filter_launcher) cur.launcher = true;
                if (filter_main && filter_leanback) cur.leanback_launcher = true;
            } else if ((tag == "activity" || tag == "activity-alias") && parent == "application" && in_comp) {
                if (WP_MUTANT(10) && comp_any_main && comp_any_launcher) cur.launcher = true;
                comps.push_back(cur);
                in_comp = false;
            }
        }
        off += sz;
    }

    // Launcher: Manifest.findLaunchable over <activity> first, then
    // <activity-alias>, document order, enabled != false.
    const Comp* chosen = nullptr;
    // Passes 2-3: the TV-only fallback (Manifest.java's launchableCategory):
    // with no LAUNCHER entry anywhere, the MAIN + LEANBACK_LAUNCHER component
    // is the one that starts, in the same activity-then-alias order.
    for (int pass = 0; pass < 4 && !chosen; ++pass) {
        for (const Comp& c : comps) {
            if (c.is_alias != (pass % 2 == 1)) continue;
            if (!c.enabled && !WP_MUTANT(9)) continue;
            if ((c.is_alias ? c.target : c.name).empty()) continue;
            if (pass < 2 ? c.launcher : c.leanback_launcher) { chosen = &c; break; }
        }
    }
    if (chosen) {
        t.launcher_found = true;
        t.launcher_is_alias = chosen->is_alias;
        t.launcher_component = Normalize(t.package, chosen->name);
        if (!chosen->is_alias) {
            t.activity = chosen->traits;
            t.activity.name = t.launcher_component;
        } else {
            // An alias is its target's attributes with its own meta-data and
            // properties (AliasOf). The target must be an <activity> declared
            // earlier.
            const std::string want = Normalize(t.package, chosen->target);
            bool found = false;
            if (WP_MUTANT(13)) { t.activity = chosen->traits; found = true; }
            for (const Comp& c : comps) {
                if (found) break;
                if (!c.is_alias && Normalize(t.package, c.name) == want) {
                    t.activity = AliasOf(c.traits, chosen->traits);
                    found = true;
                    break;
                }
            }
            t.activity.name = want;
            if (!found) t.notes += std::string(t.notes.empty() ? "" : "; ")
                                 + "alias target " + want + " not found";
        }
    }

    // Phase 3: EVERY <activity> and <activity-alias>, each resolved the way the
    // launcher is (an alias: AliasOf its target, which may be declared anywhere
    // in the manifest -- PackageParser resolves aliases after the whole
    // <application> is read), with ActivityInfo.getThemeResource's fallback to
    // the application theme (AI16: `theme != 0 ? theme : applicationInfo.theme`)
    // and that theme's window style.
    auto finish = [&](ComponentTraits* ct) {
        if (ct->theme == 0) ct->theme = t.app_theme;
        ct->window_style = WindowStyleForTheme(ct->theme);
    };
    if (t.launcher_found) finish(&t.activity);
    t.components.reserve(comps.size());
    for (const Comp& c : comps) {
        ComponentTraits ct = c.traits;
        if (c.is_alias) {
            const std::string want = Normalize(t.package, c.target);
            for (const Comp& g : comps) {
                if (!g.is_alias && Normalize(t.package, g.name) == want) {
                    ct = AliasOf(g.traits, c.traits);
                    break;
                }
            }
            ct.is_alias = true;
            ct.target = want;
        }
        ct.name = Normalize(t.package, c.name);
        ct.enabled = c.enabled;
        finish(&ct);
        t.components.push_back(ct);
    }
    return t;
}

int FrameworkThemeWindowStyle(uint32_t theme_id) {
    for (const FrameworkWindowStyleRow& r : kFrameworkWindowStyles) {
        // Mutant 62: Theme.Translucent.NoTitleBar.Fullscreen missing from the
        // table (Subway's Play Games bridge and ad activities would OCCLUDE).
        if (WP_MUTANT(62) && r.id == 0x01030011) continue;
        if (r.id == theme_id) return r.flags;
    }
    return 0;
}

int WindowStyleForTheme(uint32_t theme_id) {
    if (theme_id == 0) return 0;                        // Theme / Theme_Holo (AR16:1892-1895)
    if ((theme_id >> 24) == 0x01) return FrameworkThemeWindowStyle(theme_id);
    return kWindowStyleUnresolved;                      // an app style: resolved at runtime
}

std::vector<FrameworkWindowStyleRow> FrameworkWindowStyleTable() {
    std::vector<FrameworkWindowStyleRow> v;
    for (const FrameworkWindowStyleRow& r : kFrameworkWindowStyles) {
        if (WP_MUTANT(62) && r.id == 0x01030011) continue;
        v.push_back(r);
    }
    return v;
}

WindowTraits ReadWindowTraits(const std::string& apk_path, const std::string& nested_base) {
    std::string axml;
    auto fetch = [&](const char* entry, std::string* out) {
        if (nested_base.empty()) {
            return Capture("unzip -p " + ShellQuote(apk_path) + " " + entry + " 2>/dev/null", out);
        }
        return Capture("unzip -p " + ShellQuote(apk_path) + " " + ShellQuote(nested_base)
                       + " 2>/dev/null | tar --fast-read -xOf - " + entry + " 2>/dev/null", out);
    };
    fetch("AndroidManifest.xml", &axml);
    WindowTraits t = ParseWindowTraits(axml, std::string());
    if (t.ok && t.notes.find("unresolved") != std::string::npos) {
        // Only now pay for resources.arsc (it can sit late in a large base).
        std::string arsc;
        if (fetch("resources.arsc", &arsc)) t = ParseWindowTraits(axml, arsc);
    }
    return t;
}

// ---- cache form --------------------------------------------------------------

namespace {
const char* TriName(Tri v) { return v == Tri::kTrue ? "1" : v == Tri::kFalse ? "0" : "-"; }
Tri TriFrom(const std::string& s) { return s == "1" ? Tri::kTrue : s == "0" ? Tri::kFalse : Tri::kUnset; }
std::string F(float v) { char b[32]; std::snprintf(b, sizeof b, "%.9g", v); return b; }
std::string Hex(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "0x%08x", v); return b; }
uint32_t FromHex(const std::string& s) {
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 16));
}
void ParsePair(const std::string& v, bool* has, float* f) {
    const size_t c = v.find(':');
    if (c == std::string::npos) return;
    *has = v.substr(0, c) == "1";
    *f = std::strtof(v.c_str() + c + 1, nullptr);
}
// One `comp=` line (phase 3): name|alias|target|enabled|orientation|resizeable|
// pip|max|min|meta_max|size_changes|prop_restricted|prop_user|theme|style.
std::string CompLine(const ComponentTraits& c) {
    std::ostringstream o;
    o << c.name << '|' << c.is_alias << '|' << c.target << '|' << c.enabled << '|'
      << c.screen_orientation << '|' << TriName(c.resizeable_activity) << '|' << c.supports_pip
      << '|' << c.has_max_aspect << ':' << F(c.max_aspect)
      << '|' << c.has_min_aspect << ':' << F(c.min_aspect)
      << '|' << c.has_meta_max_aspect << ':' << F(c.meta_max_aspect)
      << '|' << c.meta_supports_size_changes
      << '|' << TriName(c.prop_allow_restricted_resizability)
      << '|' << TriName(c.prop_allow_user_aspect_override)
      << '|' << Hex(c.theme) << '|' << c.window_style;
    return o.str();
}
bool CompFrom(const std::string& v, ComponentTraits* out) {
    std::vector<std::string> f;
    std::istringstream in(v);
    std::string part;
    while (std::getline(in, part, '|')) f.push_back(part);
    if (v.size() && v.back() == '|') f.push_back(std::string());
    if (f.size() != 15) return false;
    ComponentTraits c;
    c.name = f[0];
    c.is_alias = f[1] == "1";
    c.target = f[2];
    c.enabled = f[3] == "1";
    c.screen_orientation = std::atoi(f[4].c_str());
    c.resizeable_activity = TriFrom(f[5]);
    c.supports_pip = f[6] == "1";
    ParsePair(f[7], &c.has_max_aspect, &c.max_aspect);
    ParsePair(f[8], &c.has_min_aspect, &c.min_aspect);
    ParsePair(f[9], &c.has_meta_max_aspect, &c.meta_max_aspect);
    c.meta_supports_size_changes = f[10] == "1";
    c.prop_allow_restricted_resizability = TriFrom(f[11]);
    c.prop_allow_user_aspect_override = TriFrom(f[12]);
    c.theme = FromHex(f[13]);
    c.window_style = std::atoi(f[14].c_str());
    *out = c;
    return true;
}
}  // namespace

std::string SerializeTraits(const WindowTraits& t) {
    std::ostringstream o;
    const ComponentTraits& a = t.activity;
    o << "v=" << kTraitsFormatVersion << "\n"
      << "ok=" << t.ok << "\npackage=" << t.package << "\nlauncher_found=" << t.launcher_found
      << "\nlauncher=" << t.launcher_component << "\nlauncher_alias=" << t.launcher_is_alias
      << "\nact.name=" << a.name << "\nact.orientation=" << a.screen_orientation
      << "\nact.resizeable=" << TriName(a.resizeable_activity) << "\nact.pip=" << a.supports_pip
      << "\nact.max=" << a.has_max_aspect << ":" << F(a.max_aspect)
      << "\nact.min=" << a.has_min_aspect << ":" << F(a.min_aspect)
      << "\nact.meta_max=" << a.has_meta_max_aspect << ":" << F(a.meta_max_aspect)
      << "\nact.size_changes=" << a.meta_supports_size_changes
      << "\nact.prop_restricted=" << TriName(a.prop_allow_restricted_resizability)
      << "\nact.prop_user=" << TriName(a.prop_allow_user_aspect_override)
      << "\nact.theme=" << Hex(a.theme) << "\nact.style=" << a.window_style
      << "\nuses_sdk=" << t.has_uses_sdk << "\nmin_sdk=" << t.min_sdk << "\ntarget_sdk=" << t.target_sdk
      << "\napp.resizeable=" << TriName(t.app_resizeable_activity)
      << "\napp.max=" << t.app_has_max_aspect << ":" << F(t.app_max_aspect)
      << "\napp.min=" << t.app_has_min_aspect << ":" << F(t.app_min_aspect)
      << "\napp.meta_max=" << t.app_has_meta_max_aspect << ":" << F(t.app_meta_max_aspect)
      << "\napp.size_changes=" << t.app_meta_supports_size_changes
      << "\napp.category=" << t.app_category
      << "\napp.prop_restricted=" << TriName(t.app_prop_allow_restricted_resizability)
      << "\napp.prop_user=" << TriName(t.app_prop_allow_user_aspect_override)
      << "\napp.theme=" << Hex(t.app_theme)
      << "\nss=" << t.small_screens << "," << t.normal_screens << "," << t.large_screens << ","
      << t.xlarge_screens << "," << t.resizeable_screens << "," << t.any_density << ","
      << t.requires_smallest_width_dp << "," << t.compatible_width_limit_dp << ","
      << t.largest_width_limit_dp
      << "\nnotes=" << t.notes << "\n";
    for (const ComponentTraits& c : t.components) o << "comp=" << CompLine(c) << "\n";
    return o.str();
}

bool DeserializeTraits(const std::string& text, WindowTraits* out) {
    WindowTraits t;
    std::istringstream in(text);
    std::string line;
    bool version_ok = false, comps_ok = true;
    auto pair = ParsePair;
    while (std::getline(in, line)) {
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        const int iv = std::atoi(v.c_str());
        ComponentTraits& a = t.activity;
        if (k == "v") version_ok = (iv == kTraitsFormatVersion);
        else if (k == "ok") t.ok = iv != 0;
        else if (k == "package") t.package = v;
        else if (k == "launcher_found") t.launcher_found = iv != 0;
        else if (k == "launcher") t.launcher_component = v;
        else if (k == "launcher_alias") t.launcher_is_alias = iv != 0;
        else if (k == "act.name") a.name = v;
        else if (k == "act.orientation") a.screen_orientation = iv;
        else if (k == "act.resizeable") a.resizeable_activity = TriFrom(v);
        else if (k == "act.pip") a.supports_pip = iv != 0;
        else if (k == "act.max") pair(v, &a.has_max_aspect, &a.max_aspect);
        else if (k == "act.min") pair(v, &a.has_min_aspect, &a.min_aspect);
        else if (k == "act.meta_max") pair(v, &a.has_meta_max_aspect, &a.meta_max_aspect);
        else if (k == "act.size_changes") a.meta_supports_size_changes = iv != 0;
        else if (k == "act.prop_restricted") a.prop_allow_restricted_resizability = TriFrom(v);
        else if (k == "act.prop_user") a.prop_allow_user_aspect_override = TriFrom(v);
        else if (k == "act.theme") a.theme = FromHex(v);
        else if (k == "act.style") a.window_style = iv;
        else if (k == "uses_sdk") t.has_uses_sdk = iv != 0;
        else if (k == "min_sdk") t.min_sdk = iv;
        else if (k == "target_sdk") t.target_sdk = iv;
        else if (k == "app.resizeable") t.app_resizeable_activity = TriFrom(v);
        else if (k == "app.max") pair(v, &t.app_has_max_aspect, &t.app_max_aspect);
        else if (k == "app.min") pair(v, &t.app_has_min_aspect, &t.app_min_aspect);
        else if (k == "app.meta_max") pair(v, &t.app_has_meta_max_aspect, &t.app_meta_max_aspect);
        else if (k == "app.size_changes") t.app_meta_supports_size_changes = iv != 0;
        else if (k == "app.category") t.app_category = iv;
        else if (k == "app.prop_restricted") t.app_prop_allow_restricted_resizability = TriFrom(v);
        else if (k == "app.prop_user") t.app_prop_allow_user_aspect_override = TriFrom(v);
        else if (k == "app.theme") t.app_theme = FromHex(v);
        else if (k == "comp") {
            ComponentTraits c;
            if (CompFrom(v, &c)) t.components.push_back(c);
            else comps_ok = false;
        }
        else if (k == "ss") {
            int* slots[] = {&t.small_screens, &t.normal_screens, &t.large_screens, &t.xlarge_screens,
                            &t.resizeable_screens, &t.any_density, &t.requires_smallest_width_dp,
                            &t.compatible_width_limit_dp, &t.largest_width_limit_dp};
            std::istringstream ss(v);
            std::string part;
            for (int* s : slots) { if (!std::getline(ss, part, ',')) break; *s = std::atoi(part.c_str()); }
        } else if (k == "notes") t.notes = v;
    }
    if (!version_ok || !comps_ok) return false;
    *out = t;
    return true;
}

bool TraitsEqual(const WindowTraits& a, const WindowTraits& b, std::string* diff) {
    const std::string sa = SerializeTraits(a), sb = SerializeTraits(b);
    if (sa == sb) return true;
    if (diff) {
        std::istringstream ia(sa), ib(sb);
        std::string la, lb;
        while (std::getline(ia, la) && std::getline(ib, lb))
            if (la != lb) *diff += la + " | " + lb + "; ";
    }
    return false;
}

}  // namespace winpolicy
}  // namespace macapk
