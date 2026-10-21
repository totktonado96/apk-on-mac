// wallpaper_bridge.mm -- the Mac desktop picture as Android's wallpaper, for Material You.
//
// WHY THIS EXISTS. On Android 12+ the system palette (@android:color/system_accent*_*,
// system_neutral*_* and, from API 34, the system_<role>_{light,dark} aliases) is not a
// constant: SystemUI's ThemeOverlayController derives it from the WALLPAPER
// (WallpaperManagerService.extractColors -> WallpaperColors.fromBitmap -> CelebiQuantizer
// -> ColorScheme.getSeedColor -> ColorScheme/SchemeTonalSpot) and installs it as
// fabricated overlays on the "android" package. Mac.apk served the no-seed fallback
// forever, so every dynamic-colour app painted the same blue-violet whatever the user's
// desktop looked like. The Mac already HAS a wallpaper, so this is rung 1 of the host-first
// decision ladder: route the question to the host (NSWorkspace) and run AOSP's own
// extraction over the answer. The extraction itself lives in Java
// (com.macapk.loader.monet, ported from android14-release); this file only answers the two
// questions Java cannot: WHICH image is on the screen, and WHAT PIXELS it shows.
//
// THE ANDROID ANALOG, and why we render rather than just decode. extractColors decodes the
// wallpaper's CROP FILE -- the visible region, already scaled to the display -- and
// WallpaperColors.fromBitmap then nearest-neighbour downsamples it
// (Bitmap.createScaledBitmap(..., filter=false)) to calculateOptimalSize(), an area of at
// most 112*112. The Mac's "visible region at display resolution" is what the desktop
// actually shows: the picture placed per NSWorkspaceDesktopImageScalingKey /
// AllowClippingKey over NSWorkspaceDesktopImageFillColorKey, at the screen's BACKING
// (pixel) size. So macapk_wallpaper_render draws exactly that into a screen-sized sRGB
// bitmap and then samples it the way Skia's nearest filter does. Colour management: the
// context is sRGB, so a Display P3 wallpaper (Apple ships its own that way) is converted
// the way Android's Bitmap.getPixels converts to sRGB.
//
// THREADING. The first caller is whichever thread initialises ResourceIndex, usually the
// macapk-fwres-prefetch thread, i.e. NOT the AppKit main thread. This never hops to the
// main queue: Boot.run parks the main thread waiting on Java work, and a dispatch_sync
// from here would be the v1.0.1644 CocoaDisplayHz deadlock again. NSScreen/NSWorkspace are
// queried off-main inside a local autorelease pool, as cocoa_bridge.mm's CocoaSetPhoneSize
// already does. Offline gate debug/monet_gate.sh exercises this file off the main thread
// with the main thread blocked, which is the shape that would hang if it ever did hop.
//
// NO ARC IN THIS TU (matches cocoa_bridge.mm / camera_capture.mm): only autoreleased
// objects and explicitly released CF objects.
//
// Gate: MACAPK_MONET_WALLPAPER_SEED (read in Java, com.macapk.loader.monet.Monet). With it
// =0 nothing here is ever called. See docs/monet-wallpaper-seed_2026-09-26.md.

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

#include <jni.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// C contract (also driven directly by the offline gate's probe binary)
// ---------------------------------------------------------------------------

// Largest screen we will render at backing resolution: 8192x8192 (an 8K display is 33 M
// pixels). Mirrored by HostWallpaper.MAX_SCREEN_PIXELS; above it the query answers "no
// usable picture" and the fixed palette stands.
static const int64_t kMaxScreenPixels = (int64_t) 8192 * 8192;

extern "C" {

// NSImageScaling raw values (AppKit NSImageCell.h): the desktop's placement mode.
//   0 NSImageScaleProportionallyDown, 1 NSImageScaleAxesIndependently,
//   2 NSImageScaleNone, 3 NSImageScaleProportionallyUpOrDown.
struct MacapkDesktopInfo {
    char     path[4096];
    int      scaling;       // NSImageScaling, -1 if AppKit gave none
    int      allowClipping; // 0/1
    uint32_t fillArgb;      // NSWorkspaceDesktopImageFillColorKey in sRGB, 0xff000000 if absent
    int      screenPxW;     // backing-pixel size of the screen the window opens on
    int      screenPxH;
};

// The desktop picture of the screen our window opens on: [NSScreen mainScreen] (the screen
// with the key window, else the menu-bar screen) -- the same screen cocoa_bridge.mm sizes
// the phone window against. Returns false when there is no screen, no URL, or the URL is
// not a readable regular file (a folder rotation, a live/dynamic wallpaper provider with no
// file): the caller then serves the no-wallpaper palette.
bool macapk_wallpaper_desktop_info(MacapkDesktopInfo* out) {
    if (!out) return false;
    std::memset(out, 0, sizeof(*out));
    out->scaling = -1;
    out->fillArgb = 0xff000000u;
    bool ok = false;
    @autoreleasepool {
        NSScreen* screen = [NSScreen mainScreen];
        if (!screen) {
            NSArray<NSScreen*>* all = [NSScreen screens];
            if (all.count > 0) screen = all.firstObject;
        }
        if (!screen) return false;
        const CGFloat scale = screen.backingScaleFactor > 0 ? screen.backingScaleFactor : 1.0;
        const NSRect frame = screen.frame;
        out->screenPxW = (int) std::lround(frame.size.width * scale);
        out->screenPxH = (int) std::lround(frame.size.height * scale);

        NSWorkspace* ws = [NSWorkspace sharedWorkspace];
        NSURL* url = [ws desktopImageURLForScreen:screen];
        if (!url || !url.isFileURL) return false;
        const char* p = url.path.fileSystemRepresentation;
        if (!p || !*p || std::strlen(p) >= sizeof(out->path)) return false;
        BOOL isDir = NO;
        if (![[NSFileManager defaultManager] fileExistsAtPath:url.path isDirectory:&isDir] || isDir) {
            return false;
        }
        std::strncpy(out->path, p, sizeof(out->path) - 1);

        NSDictionary* opts = [ws desktopImageOptionsForScreen:screen];
        NSNumber* sc = opts[NSWorkspaceDesktopImageScalingKey];
        NSNumber* clip = opts[NSWorkspaceDesktopImageAllowClippingKey];
        NSColor* fill = opts[NSWorkspaceDesktopImageFillColorKey];
        if (sc) out->scaling = sc.intValue;
        out->allowClipping = clip ? (clip.boolValue ? 1 : 0) : 0;
        if (fill) {
            NSColor* s = [fill colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
            if (s) {
                auto ch = [](CGFloat v) -> uint32_t {
                    long x = std::lround(v * 255.0);
                    return (uint32_t) (x < 0 ? 0 : (x > 255 ? 255 : x));
                };
                out->fillArgb = 0xff000000u | (ch(s.redComponent) << 16)
                              | (ch(s.greenComponent) << 8) | ch(s.blueComponent);
            }
        }
        ok = out->screenPxW > 0 && out->screenPxH > 0
          && (int64_t) out->screenPxW * out->screenPxH <= kMaxScreenPixels;
    }
    return ok;
}

// Where AppKit places an iw x ih picture on a sw x sh screen, in screen pixels (origin
// top-left). Mirrors the NSImageScaling contract; `allowClipping` is what separates
// "Fill Screen" (cover, cropped) from "Fit to Screen" (contain, letterboxed) for the
// proportional mode, which is how System Settings stores those two choices.
static CGRect place_on_screen(double iw, double ih, double sw, double sh,
                              int scaling, int allowClipping) {
    double w = iw, h = ih;
    switch (scaling) {
        case 1:                                       // AxesIndependently: stretch
            w = sw; h = sh;
            break;
        case 2:                                       // None: centred at its own size
            break;
        case 0: {                                     // ProportionallyDown: only shrink
            double s = std::fmin(sw / iw, sh / ih);
            if (s < 1.0) { w = iw * s; h = ih * s; }
            break;
        }
        case 3:                                       // ProportionallyUpOrDown
        default: {
            double s = allowClipping ? std::fmax(sw / iw, sh / ih)
                                     : std::fmin(sw / iw, sh / ih);
            w = iw * s; h = ih * s;
            break;
        }
    }
    return CGRectMake((sw - w) / 2.0, (sh - h) / 2.0, w, h);
}

// Render the desktop as the screen shows it (sw x sh pixels, sRGB) and nearest-neighbour
// sample it to ow x oh, writing packed NON-premultiplied ARGB (Bitmap.getPixels layout) into
// `out` (ow*oh entries). Sampling mirrors Skia's nearest filter for the scale-only matrix
// Bitmap.createScaledBitmap builds: dst pixel centre (x + 0.5) maps back through the float
// inverse scale and floors. Returns false on any decode/allocation failure.
bool macapk_wallpaper_render(const char* path, int scaling, int allowClipping,
                             uint32_t fillArgb, int sw, int sh, int ow, int oh,
                             uint32_t* out) {
    if (!path || !out || sw <= 0 || sh <= 0 || ow <= 0 || oh <= 0) return false;
    // The screen-sized buffer is the one big allocation (3360x2100 is 28 MB, a 6K display
    // 81 MB). Cap it well above any real backing size (HostWallpaper.parse applies the same
    // cap) and allocate it nothrow below: a std::bad_alloc escaping a JNI native would abort
    // the whole runtime, where this file's contract is "fail soft, keep the fixed palette".
    if ((int64_t) sw * sh > kMaxScreenPixels) return false;
    bool ok = false;
    @autoreleasepool {
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(
            nullptr, (const UInt8*) path, (CFIndex) std::strlen(path), false);
        if (!url) return false;
        CGImageSourceRef src = CGImageSourceCreateWithURL(url, nullptr);
        CFRelease(url);
        if (!src) return false;

        // Oriented pixel size first, so we can ask ImageIO for a decode no larger than the
        // placement needs (a 6K JPEG shown on a 3K screen decodes via DCT scaling instead of
        // at full size). kCGImageSourceCreateThumbnailWithTransform applies EXIF orientation,
        // which is what the desktop shows.
        double iw = 0, ih = 0;
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, nullptr);
        if (props) {
            CFNumberRef nw = (CFNumberRef) CFDictionaryGetValue(props, kCGImagePropertyPixelWidth);
            CFNumberRef nh = (CFNumberRef) CFDictionaryGetValue(props, kCGImagePropertyPixelHeight);
            CFNumberRef no = (CFNumberRef) CFDictionaryGetValue(props, kCGImagePropertyOrientation);
            int orient = 1;
            if (nw) CFNumberGetValue(nw, kCFNumberDoubleType, &iw);
            if (nh) CFNumberGetValue(nh, kCFNumberDoubleType, &ih);
            if (no) CFNumberGetValue(no, kCFNumberIntType, &orient);
            if (orient >= 5 && orient <= 8) std::swap(iw, ih);   // rotated 90/270
            CFRelease(props);
        }
        if (iw < 1 || ih < 1) { CFRelease(src); return false; }

        const CGRect dst = place_on_screen(iw, ih, sw, sh, scaling, allowClipping);
        double need = std::ceil(std::fmax(dst.size.width, dst.size.height));
        double full = std::fmax(iw, ih);
        if (need > full) need = full;                     // never upsample in the decoder
        if (need < 1) need = 1;
        int maxPx = (int) need;
        CFNumberRef maxNum = CFNumberCreate(nullptr, kCFNumberIntType, &maxPx);
        const void* keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                               kCGImageSourceCreateThumbnailWithTransform,
                               kCGImageSourceThumbnailMaxPixelSize,
                               kCGImageSourceShouldCacheImmediately };
        const void* vals[] = { kCFBooleanTrue, kCFBooleanTrue, maxNum, kCFBooleanTrue };
        CFDictionaryRef topts = CFDictionaryCreate(nullptr, keys, vals, 4,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, topts);
        CFRelease(topts);
        CFRelease(maxNum);
        CFRelease(src);
        if (!img) return false;

        CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        std::unique_ptr<uint8_t[]> screen(
            new (std::nothrow) uint8_t[(size_t) sw * (size_t) sh * 4u]);
        CGContextRef ctx = (srgb && screen) ? CGBitmapContextCreate(screen.get(), (size_t) sw, (size_t) sh,
            8, (size_t) sw * 4u, srgb,
            (CGBitmapInfo) kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big) : nullptr;
        if (ctx) {
            const CGFloat fr = ((fillArgb >> 16) & 0xff) / 255.0;
            const CGFloat fg = ((fillArgb >> 8) & 0xff) / 255.0;
            const CGFloat fb = (fillArgb & 0xff) / 255.0;
            CGContextSetRGBFillColor(ctx, fr, fg, fb, 1.0);
            CGContextFillRect(ctx, CGRectMake(0, 0, sw, sh));
            CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
            // CG's origin is bottom-left; place_on_screen is centred, so the y flip is a no-op
            // for every mode it produces.
            CGContextDrawImage(ctx, dst, img);
            CGContextFlush(ctx);

            // Skia nearest: srcX = floor((x + 0.5f) * (1 / sx)), sx = ow / (float) sw.
            const float invX = 1.0f / ((float) ow / (float) sw);
            const float invY = 1.0f / ((float) oh / (float) sh);
            for (int y = 0; y < oh; ++y) {
                int sy = (int) std::floor(((float) y + 0.5f) * invY);
                if (sy < 0) sy = 0;
                if (sy >= sh) sy = sh - 1;
                const uint8_t* row = screen.get() + (size_t) sy * (size_t) sw * 4u;
                for (int x = 0; x < ow; ++x) {
                    int sx = (int) std::floor(((float) x + 0.5f) * invX);
                    if (sx < 0) sx = 0;
                    if (sx >= sw) sx = sw - 1;
                    const uint8_t* p = row + (size_t) sx * 4u;
                    uint32_t r = p[0], g = p[1], b = p[2], a = p[3];
                    if (a != 0 && a != 255) {             // un-premultiply (opaque in practice)
                        r = (r * 255u + a / 2u) / a;
                        g = (g * 255u + a / 2u) / a;
                        b = (b * 255u + a / 2u) / a;
                    }
                    out[(size_t) y * (size_t) ow + (size_t) x] =
                        (a << 24) | (r << 16) | (g << 8) | b;
                }
            }
            CGContextRelease(ctx);
            ok = true;
        }
        if (srgb) CGColorSpaceRelease(srgb);
        CGImageRelease(img);
    }
    return ok;
}

}  // extern "C"

// ---------------------------------------------------------------------------
// JNI seam -- com.macapk.loader.monet.HostWallpaper
// ---------------------------------------------------------------------------
//
// Bound via RegisterNatives from native_methods.cpp (the JVM does not resolve Java_*
// symbols out of the main executable on macOS). Soft-fail: a registration miss leaves the
// natives unbound, the Java side catches the UnsatisfiedLinkError and serves the
// no-wallpaper palette, exactly as with the gate off -- but it LOGS that case as its own
// line ("wallpaper natives unbound"), distinct from a host that genuinely shows no
// picture, so a forgotten registration cannot pass for a headless host.

namespace macapk {
namespace wallpaper {
namespace {

// THE PATH CROSSES AS BYTES, NEVER AS A jstring. fileSystemRepresentation is standard UTF-8
// (4-byte sequences for anything outside the BMP, e.g. an emoji file name), while
// NewStringUTF / GetStringUTFChars speak MODIFIED UTF-8 (a non-BMP character is two 3-byte
// surrogates). Round-tripping a path through them hands CGImageSource bytes that name no
// file, so a picture called "<emoji>.jpg" silently fell back to the fixed palette. Java
// decodes these bytes with StandardCharsets.UTF_8 and re-encodes the same way, which
// round-trips any valid UTF-8 exactly.

// UTF-8 "path\tscaling\tallowClipping\tfillArgb\tscreenPxW\tscreenPxH", or null.
jbyteArray JNICALL nativeDesktopInfo(JNIEnv* env, jclass) {
    MacapkDesktopInfo info;
    if (!macapk_wallpaper_desktop_info(&info)) return nullptr;
    std::string s = info.path;
    s += '\t'; s += std::to_string(info.scaling);
    s += '\t'; s += std::to_string(info.allowClipping);
    s += '\t'; s += std::to_string((long long) info.fillArgb);
    s += '\t'; s += std::to_string(info.screenPxW);
    s += '\t'; s += std::to_string(info.screenPxH);
    jbyteArray arr = env->NewByteArray((jsize) s.size());
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, (jsize) s.size(), reinterpret_cast<const jbyte*>(s.data()));
    return arr;
}

// Largest sample grid we hand back. WallpaperColors.calculateOptimalSize keeps the area at
// or under MAX_WALLPAPER_EXTRACTION_AREA (112*112); this is only a sanity bound.
static const int64_t kMaxSamplePixels = (int64_t) 1024 * 1024;

jintArray JNICALL nativeRender(JNIEnv* env, jclass, jbyteArray jpath, jint scaling,
                               jint allowClipping, jint fillArgb, jint sw, jint sh,
                               jint ow, jint oh) {
    if (!jpath || ow <= 0 || oh <= 0 || (int64_t) ow * oh > kMaxSamplePixels) return nullptr;
    const jsize n = env->GetArrayLength(jpath);
    if (n <= 0 || n >= 4096) return nullptr;
    char path[4096];
    env->GetByteArrayRegion(jpath, 0, n, reinterpret_cast<jbyte*>(path));
    path[n] = '\0';
    if (std::strlen(path) != (size_t) n) return nullptr;   // an embedded NUL names no file
    std::unique_ptr<uint32_t[]> px(new (std::nothrow) uint32_t[(size_t) ow * (size_t) oh]);
    if (!px) return nullptr;
    if (!macapk_wallpaper_render(path, scaling, allowClipping, (uint32_t) fillArgb,
                                 sw, sh, ow, oh, px.get())) {
        return nullptr;
    }
    const jsize count = (jsize) ((size_t) ow * (size_t) oh);
    jintArray arr = env->NewIntArray(count);
    if (!arr) return nullptr;
    env->SetIntArrayRegion(arr, 0, count, reinterpret_cast<const jint*>(px.get()));
    return arr;
}

const JNINativeMethod kWallpaperBridgeMethods[] = {
    { const_cast<char*>("nativeDesktopInfo"), const_cast<char*>("()[B"),
      reinterpret_cast<void*>(nativeDesktopInfo) },
    { const_cast<char*>("nativeRender"), const_cast<char*>("([BIIIIIII)[I"),
      reinterpret_cast<void*>(nativeRender) },
};

}  // namespace

void RegisterWallpaperBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/monet/HostWallpaper");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(HostWallpaper) failed; Material You stays on "
                     "the no-wallpaper palette\n");
        env->ExceptionClear();
        return;
    }
    const jint count = (jint) (sizeof(kWallpaperBridgeMethods) / sizeof(kWallpaperBridgeMethods[0]));
    if (env->RegisterNatives(cls, kWallpaperBridgeMethods, count) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(HostWallpaper) failed; Material You stays "
                     "on the no-wallpaper palette\n");
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
}

}  // namespace wallpaper
}  // namespace macapk
