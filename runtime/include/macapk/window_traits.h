// window_traits.h
//
// Read the manifest facts the window policy needs (window_policy.h
// WindowTraits) straight from an APK's BINARY AndroidManifest.xml, before any
// extraction, JVM or window exists.
//
// Why a separate reader rather than BinaryManifestInfo (apk_unpacker.cpp): that
// reader resolves the launcher by OR-ing MAIN and LAUNCHER across ALL of an
// activity's intent-filters and ignores android:enabled, so it named F-Droid's
// disabled decoy CalculatorActivity and Super Jetpack's landscape
// MortarGameActivity (docs/window-size-policy_2026-09-25.md, critique section
// 5). This one mirrors Manifest.findLaunchable: MAIN + LAUNCHER in the SAME
// <intent-filter>, enabled != false, activities before aliases, an alias
// resolved to its targetActivity. It is pure C++ plus `unzip`/`tar` children,
// so the offline gate links it without the rest of the runtime.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "macapk/window_policy.h"

namespace macapk {
namespace winpolicy {

// Parse a binary manifest. `arsc` is the APK's resources.arsc, or empty; it is
// only consulted when an attribute the policy needs is a @bool / @integer /
// @float reference. It is resolved at the PACKAGE PARSER's configuration: that
// Resources object carries the platform SDK level (RESOURCES_SDK_INT, 36 here)
// and the display density and nothing else, so a values-v24 override DOES
// apply (highest matching sdkVersion wins) while a values-sw600dp one does not.
// A reference with no matching entry is left at its AOSP default and named in
// traits.notes.
WindowTraits ParseWindowTraits(const std::string& axml, const std::string& arsc);

// Read the traits of an APK file. `nested_base` names the base apk INSIDE a
// split bundle (.apkm / .xapk / .apks); empty for a plain APK. The nested read
// streams `unzip -p <bundle> <base> | tar --fast-read` so only the bytes up to
// the manifest are inflated (the manifest is the first entry of every corpus
// base; measured 6 ms on a 139 MB base in apk_unpacker.cpp). resources.arsc is
// fetched only when a reference needs resolving.
WindowTraits ReadWindowTraits(const std::string& apk_path, const std::string& nested_base);

// Serialised form for the per-APK cache (key=value lines) and its inverse.
// Bump kTraitsFormatVersion whenever the reader's RULES change, so a cache
// written by an older reader is a miss rather than a stale answer (the
// .gles31cache lesson, v1.0.1574-1576).
// v2 (2026-09-25 review): alias meta-data/properties are the alias's own; refs
// resolve at the parser's SDK-qualified configuration; five attrs match by id.
// v3 (2026-09-25, phase 3): every activity and alias (`comp=` lines), the
// application and activity themes, and each theme's window style.
constexpr int kTraitsFormatVersion = 3;

// The window-style flags (window_policy.h kStyle*) of a FRAMEWORK theme id,
// flattened through its parent chain from AOSP core/res/res/values/themes.xml,
// themes_holo.xml, themes_material.xml, themes_device_defaults.xml and, for the
// DialogWhenLarge family, values-large/ (the policy only runs on a large
// display); ids from public-final.xml. 0 for a theme the table does not list
// (every other public theme is opaque: none of the four flags set anywhere in
// its chain). The SAME rows as FrameworkWindowStyle.java's -- the offline gate
// compares the two tables.
int FrameworkThemeWindowStyle(uint32_t theme_id);
// ActivityRecord's realTheme (AR16:1892-1895) -> window style: 0 (Theme /
// Theme_Holo, opaque) for no theme, the table for a framework id, and
// kWindowStyleUnresolved for an app style (resolved at runtime).
int WindowStyleForTheme(uint32_t theme_id);
struct FrameworkWindowStyleRow { uint32_t id; const char* name; int flags; };
std::vector<FrameworkWindowStyleRow> FrameworkWindowStyleTable();

std::string SerializeTraits(const WindowTraits& t);
bool        DeserializeTraits(const std::string& text, WindowTraits* out);
bool        TraitsEqual(const WindowTraits& a, const WindowTraits& b, std::string* diff);

}  // namespace winpolicy
}  // namespace macapk
