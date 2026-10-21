// apk_unpacker.h
//
// Owns the dex-to-jar conversion plus mirroring the rest of the APK to
// disk so the JVM can `new ZipFile(...)` it directly. We unpack once per
// APK and boot straight from that cache on subsequent runs.
//
// The unpack target is the CODE half of the split layout:
//   <android_root>/.macapk/code/<pkg>_<ver>/   regenerable; replaced on
//                                              reinstall, deleted on uninstall
//   <android_root>/data/data/<pkg>_<ver>/      the app's own data; never
//                                              deleted by the runtime
// The two share a basename, which is what lets Boot.java derive the data
// dir lexically from the code dir with no extra plumbing.
//
// Cache reuse is keyed on the source APK's mtime + ABI AND on JAVA_ID (the
// identity of the framework jars + converter that produced the artifacts),
// so a Mac.apk rebuild that changes those regenerates rather than silently
// reusing output from code that no longer exists.
//
// (An earlier revision documented a <kAppsRootRel> target. That constant
// resolved relative to the RUNTIME BINARY, so with no cache-dir env set it
// wrote inside the .app bundle. It is gone; do not reintroduce it.)

#pragma once

#include <filesystem>  // SettlePendingDexJar's app_dir
#include <string>
#include <vector>

namespace macapk {

struct UnpackedApp {
    std::string app_dir;       // <android_root>/.macapk/code/<pkg>_<ver>
                               // (a per-process staging dir until main.cpp
                               // finalizes a cold extract)
    std::string app_jar;       // <app_dir>/classes.jar (com.macapk.dex product)
    std::string apk_path;      // the EFFECTIVE apk: the installed base.apk,
                               // or the synthetic _merged.apk for a split set
    std::string installed_apk; // <android_root>/data/app/~~<nonce>/<pkg>-<nonce>/
                               // base.apk -- the ONE copy of the app the
                               // runtime keeps (docs/disk-footprint-and-space-
                               // efficiency_2026-09-19.md); what a stub launches
    std::vector<std::string> split_paths; // the installed split_*.apk beside it,
                               // sorted by name; empty for a plain apk. Read in
                               // place (no _merged.apk since v1.0.1586): main.cpp
                               // extracts libs/assets from each member.
    std::string package_name;  // parsed from AndroidManifest.xml later
    std::string manifest_path; // <app_dir>/AndroidManifest.xml -- the conventional
                               // TEXT-manifest location; nothing writes it since
                               // v1.0.1590 (readers are binary-first: the manifest
                               // is parsed from the installed base.apk)
    bool staged_fresh = false; // this run COLD-extracted into a private
                               // "<pkg>.staging.<pid>" dir that main.cpp must
                               // finalize-rename to "<pkg>_<ver>". False on
                               // every cache-hit path (app_dir is already the
                               // long-term dir). Keying main.cpp's rename off
                               // this instead of the dir NAME is what lets
                               // staging dirs be per-process, which is what
                               // makes concurrent same-package installs safe.
};

// The base apk entry inside a split bundle (.apkm/.xapk/.apks), picked by the
// same SelectBundleApks rule the install merge uses; "" for none. Used by the
// window policy to read the base manifest before the unpack.
std::string BundleBaseApkEntry(const std::string& bundle_path);

// Run a shell command and capture its stdout (apk_unpacker.cpp's RunCapture,
// exported). Used by main.cpp's extracted-asset reclaim, which lists apk
// entries the same way the unpacker does.
bool RunCaptureCmd(const std::string& cmd, std::string* out);

// Convert+stage an APK. The first run does the full conversion
// (in-process com.macapk.dex for DEX->JAR; the manifest and resources are
// read from the installed apk set in place, nothing is decoded).
// Subsequent runs reuse the cached output when the source mtime is
// unchanged. Returns the staged paths or aborts the process on hard failure.
UnpackedApp UnpackApk(const std::string& apk_path,
                      const std::string& binary_dir);

// Adopt (or, when wait_if_running, wait for) a background DEX conversion
// recorded in app_dir's ".dexjar-pending" sidecar -- the install may have
// handed a long conversion to a detached child (see apk_unpacker.cpp,
// "Background DEX conversion hand-off"). Safe no-op when nothing is pending.
// main.cpp calls this after finalize on DIRECT launches (a cold extract that
// boots in the same process), where the sidecar was written moments ago and
// booting per-class under the app JVM's 1 GiB heap is the measured OOM risk.
void SettlePendingDexJar(const std::filesystem::path& app_dir,
                         bool wait_if_running);

// Which lib/<abi>/ directory should be extracted for this APK.
//
// Android installs exactly ONE primary ABI per app; extracting all of them
// wastes disk we never read (measured over the 22-app fleet: 956MB extracted
// vs 704MB needed, 26%). Preference order matches AppClassLoader.ABI_ORDER --
// arm64-v8a (Stage 6, no translation) > armeabi-v7a > armeabi -- and x86 /
// x86_64 / mips are NEVER selected: nothing in Mac.apk can load them.
//
//   chosen      the abi to extract, or "" when the APK has no usable one
//               (no native code at all, or x86-only)
//   present     every lib/<abi>/ the APK actually contains
//   skipped_bytes  uncompressed size of what we are NOT extracting
//
// MACAPK_FORCE_ABI=<abi> (the existing diagnostic override) pins the choice
// so the extractor and AppClassLoader cannot disagree about which .so tree
// exists on disk.
struct ApkAbiChoice {
    std::string chosen;
    std::vector<std::string> present;
    unsigned long long skipped_bytes = 0;
};
ApkAbiChoice SelectApkAbi(const std::string& apk_path);
// The same choice over an installed SPLIT SET (base + split_*.apk): the ABI
// split carries the libs on a device, so the preference runs over the union
// of every member's lib/ trees. `carriers` names the members that hold the
// chosen ABI (usually one), which is what main.cpp extracts from.
struct ApkSetAbiChoice {
    ApkAbiChoice choice;
    std::vector<std::string> carriers;
};
ApkSetAbiChoice SelectApkSetAbi(const std::vector<std::string>& members);
// The INSTRUCTION SET an ABI's libraries are installed under, exactly
// libcore's VMRuntime.getInstructionSet (dalvik/system/VMRuntime.java:
// ABI_TO_INSTRUCTION_SET_MAP): arm64-v8a -> "arm64", armeabi-v7a and armeabi
// -> "arm", x86 -> "x86", x86_64 -> "x86_64". The install dir's native
// library directory is lib/<isa>/, never lib/<abi>/ (NativeLibraryHelper.
// copyNativeBinariesForSupportedAbi, PackageAbiHelperImpl). Empty for an
// empty or unknown abi.
std::string InstructionSetOf(const std::string& abi);

// NOTE: an `AppDirAbiSelectorDiffers()` helper lived here briefly (v1.0.863) to
// drive a `lib_native/` purge on ABI change. Removed at v1.0.864 after measuring:
// AppClassLoader already gives a forced-ABI translation an "-<abi>" cache suffix,
// so `libgdx.dylib` and `libgdx-armeabi-v7a.dylib` coexist and a default run
// cannot inherit a forced run's dylib. Purging would have deleted the other
// ABI's dylib on every tier switch -- defeating that suffix's stated purpose and
// paying a full re-translation for a collision that cannot happen. The real
// protections are CacheIsFresh's ABI stamp (for `_apkt/`) and that suffix.


}  // namespace macapk
