// config.h
//
// Compile-time knobs for the runtime. Anything that varies between dev
// machines or run scenarios goes here, so we don't sprinkle #ifdefs or
// hard-coded paths across the rest of the source.
//
// Anything that varies per-run (APK path, window size, ...) does NOT
// belong here -- those come in via argv or the launcher UI.

#pragma once

#include <string>

namespace macapk {

// JDK location used at link time for libjvm; matches the path baked into
// CMakeLists.txt rpath. Used at runtime only for diagnostics.
constexpr const char* kJdkHome =
    "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home";

// Where the build script drops the framework jar and the loader jar.
// The native launcher hands these to JNI_CreateJavaVM as part of the
// classpath. Resolved relative to the binary's own location.
constexpr const char* kFrameworkJarRel  = "../lib/android-framework.jar";
constexpr const char* kLoaderJarRel     = "../lib/macapk-loader.jar";

// ---- Split code/data layout (Contract 1, per-app bundles) -------------
//
// The per-app on-disk layout separates the regenerable install products
// from the app's own data, both keyed on the SAME per-version name
// (owner decision 2026-08-10: per-VERSION identity is the default --
// versions of one package coexist, "one .app per version" -- so nothing
// ever collapses versioned dirs into one per package):
//
//   <android_root>/.macapk/code/<pkg>_<ver>/   classes.jar, _apkt/,
//                                              lib_native/, stamps --
//                                              regenerable, REPLACED on
//                                              a same-version reinstall
//   <android_root>/data/data/<pkg>_<ver>/      app data + extracted
//                                              assets -- precious, never
//                                              deleted by the runtime
//
// The shared basename is load-bearing: the runtime hands Boot.java the
// CODE dir as appDir, and Boot derives the data-dir name LEXICALLY from
// basename(appDir) (Boot.java ~:760), so the two sides agree on the
// version-qualified name with no change to Boot.java/AppClassLoader.java.
// Since the bundle decision (owner, 2026-08-10) the <android_root> is
// normally a per-app bundle's Contents/android and this pair is the
// app's ONLY home. Versions are INDEPENDENT: a same-version reinstall
// preserves the data dir; a NEW version starts with a fresh, empty one.
// There is NO cross-version carry-forward ("for dev, we will start
// fresh") -- the pick_predecessor/carry_forward machinery is deleted.
constexpr const char* kCodeRootRel = ".macapk/code";

// The raw android:versionName from an APK's (or bundle's base APK's)
// BINARY manifest; "" when undeclared or unreadable. Exposed because
// per-version dir naming must come from the binary manifest: apktool's
// text decode drops versionName for every app (measured fleet-wide,
// 0 of 64 decoded manifests carry it), which is how 8 of 64 live dirs
// ended up suffixed with the ANDROID platform version instead of the
// app's.
std::string BinaryManifestVersionName(const std::string& apk_path);

// Package name from the binary manifest; "" when unreadable. The dir-naming
// fallback when the apktool-decoded manifest is absent (see the definition's
// comment for the 2026-08-14 incident this prevents recurring).
std::string BinaryManifestPackage(const std::string& apk_path);

// android:versionCode from the binary manifest; 0 when undeclared,
// matching AOSP's default (deliberately NOT platformBuildVersionCode,
// which is an SDK level and would make a versionless APK compare newer
// than a real version 1). This is the update-vs-downgrade classifier.
long long BinaryManifestVersionCode(const std::string& apk_path);

// v1.0.1590 (the manifest is read from the apk, never from an apktool text
// decode): the launcher activity's android:screenOrientation as the
// ActivityInfo.SCREEN_ORIENTATION_* int (-2 when no MAIN+LAUNCHER activity
// declares one), and the manifest's platformBuildVersionName ("" when absent).
int BinaryManifestLauncherOrientation(const std::string& apk_path);
std::string BinaryManifestPlatformBuildVersionName(const std::string& apk_path);

// Resolve the user-visible android root: cli value > MACAPK_ANDROID_ROOT
// env > $HOME/Documents/android > ./android, tilde-expanded, with the
// trailing "android" path component forced. One shared implementation
// (apk_unpacker.cpp) because three independent copies of this chain had
// already grown in main.cpp and any divergence splits the cache from
// the data tree.
std::string ResolveAndroidRootDir(const std::string& cli_root);

// ---- Build identity (Contract 3) --------------------------------------
//
// Which converter/framework (JAVA_ID) and which translator/shim
// (NATIVE_ID) produced an artifact. Cache stamps record these so a
// rebuilt toolchain invalidates its own products; VERSION is the wrong
// key in both directions (bumps every turn, and bumps for unrelated
// edits). Empty string = identity UNKNOWN; consumers must then REUSE
// the cache and say so loudly, never invalidate (an unknown identity
// that invalidated would re-convert the fleet on every launch).
struct BuildIdentity {
    std::string java_id;    // android-framework.jar + macapk-loader.jar
    std::string native_id;  // macapk-translator + libmacapk-bionic-shim.dylib
};

// Memoized per process. The first caller must pass the runtime binary's
// directory (so the jars/binaries resolve the same way main.cpp's
// classpath does); later callers may pass "" to read the memo.
const BuildIdentity& GetBuildIdentity(const std::string& binary_dir);

// True for the CLOSED set of runtime-generated, regenerable artifact
// names that live in a per-app dir (classes.jar, _apkt, lib_native,
// ...). Everything NOT on this list is treated as app data and never
// deleted -- unknown names default to precious, which is the safe
// direction when a later lane adds a new artifact name.
bool IsCodeArtifactName(const std::string& name);

// Copy launcher-facing metadata (meta.json, icon.png) from a split-layout
// code dir into the matching data/data/<pkg> dir, so the launcher's
// existing data/data scan keeps rendering tiles for split installs.
// No-op unless app_dir lives under <root>/.macapk/code.
void MirrorInstallMetadata(const std::string& app_dir);

// Code-dir name of the launcher icon's density RASTER when the icon id also has
// an anydpi XML row (adaptive / vector), which Android prefers at every density.
// WriteAppMetadata keeps the raster here instead of in icon.png; the install
// path promotes it to icon.png only when the framework rasterizer produced none.
// The ".macapk" prefix marks it as ours to every code-dir scanner.
inline constexpr const char* kIconRasterFallback = ".macapk-icon-raster";

// --peek-manifest: print {"package","versionCode","versionName","label"}
// for an APK or bundle to stdout as one JSON line. Returns the process
// exit code (0 on success). Lives in apk_unpacker.cpp so it can reuse
// the binary-AXML reader and the bundle base-apk selection.
int RunPeekManifest(const std::string& apk_or_bundle_path);

// Cocoa window default size, point space (the Metal drawable scales 2x
// on retina). The launcher UI overrides this via CocoaSetPhoneSize
// before the activity boots.
constexpr int kDefaultWindowWidth  = 360;
constexpr int kDefaultWindowHeight = 640;

}  // namespace macapk
