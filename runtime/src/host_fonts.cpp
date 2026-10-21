// host_fonts.cpp -- NativeCocoa.hostFontFile: the file behind a host font's
// PostScript name, from CoreText.
//
// Used by android.graphics.MacApkHostFonts to back the CJK families of the
// native-stack /system/etc/fonts.xml with the Mac's own faces (Hiragino Sans GB,
// Heiti, Hiragino Sans, Apple SD Gothic Neo; PingFang where it is drawable):
// decision ladder rung 1, macOS already ships these scripts. Only the name ->
// file answer comes from here; whether the guest's FreeType can draw the face is
// MacApkHostFonts' check, from the file's own tables. Kept out of native_methods.cpp so CoreText's headers
// (MacTypes, CoreGraphics) stay out of that translation unit.
//
// CTFontCreateWithName never fails: an unknown name comes back as a fallback
// face (LastResort or the system UI font), so the answer counts only when the
// returned face's own PostScript name is the one asked for. The URL is
// kCTFontURLAttribute, the file CoreText itself opens for that face.
#include <CoreText/CoreText.h>
#include <jni.h>
#include <limits.h>
#include <string>

extern "C" jstring Cocoa_hostFontFile(JNIEnv* env, jclass, jstring ps_j) {
    if (!ps_j) return nullptr;
    const char* ps = env->GetStringUTFChars(ps_j, nullptr);
    if (!ps) return nullptr;
    std::string want(ps);
    env->ReleaseStringUTFChars(ps_j, ps);

    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, want.c_str(),
                                                 kCFStringEncodingUTF8);
    if (!name) return nullptr;
    CTFontRef font = CTFontCreateWithName(name, 12.0, nullptr);
    CFRelease(name);
    if (!font) return nullptr;

    std::string path;
    bool same = false;
    if (CFStringRef got = CTFontCopyPostScriptName(font)) {
        char buf[256];
        same = CFStringGetCString(got, buf, sizeof buf, kCFStringEncodingUTF8) && want == buf;
        CFRelease(got);
    }
    if (same) {
        CFTypeRef url = CTFontCopyAttribute(font, kCTFontURLAttribute);
        if (url && CFGetTypeID(url) == CFURLGetTypeID()) {
            char buf[PATH_MAX];
            if (CFURLGetFileSystemRepresentation(static_cast<CFURLRef>(url), true,
                                                 reinterpret_cast<UInt8*>(buf), sizeof buf))
                path = buf;
        }
        if (url) CFRelease(url);
    }
    CFRelease(font);
    // A host font file name can hold Japanese characters; every one is in the
    // BMP, where modified UTF-8 and UTF-8 are the same bytes.
    return path.empty() ? nullptr : env->NewStringUTF(path.c_str());
}
