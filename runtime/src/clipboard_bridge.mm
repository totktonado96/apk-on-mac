// clipboard_bridge.mm -- the macOS pasteboard behind android.content.ClipboardManager.
//
// Host-first rung 1 (CLAUDE.md "THE DECISION LADDER"): macOS already has exactly
// one system clipboard, NSPasteboard's general pasteboard, so Android's single
// shared clipboard is ROUTED THERE rather than modelled in-process. A clip the
// guest sets is what Safari/Notes/Mail paste; what they copy is what the guest's
// getPrimaryClip() returns. The Java side (ClipboardManager.java, nested class
// MacApkHostPasteboard) owns every Android semantic -- validation, the
// focused-app read rule, listener dispatch on the main looper, the access
// notice; this file is only the pasteboard transport, gated by
// MACAPK_CLIPBOARD_HOST on the Java side.
//
// WHY NOT java.awt.datatransfer (the pre-bridge path, still reachable with
// MACAPK_CLIPBOARD_HOST=0): the first AWT touch on macOS constructs
// LWCToolkit, whose native initAppkit BLOCKS until the Cocoa main thread
// services it. That produced the v1.0.1134 three-way deadlock that black-
// screened about half of all Minecraft launches
// (docs/mcpe-black-launch-clipboard-appkit-deadlock_2026-08-31.md). It is also
// text-only and has no changeCount, so it can neither carry HTML nor tell a
// listener that another app copied. Nothing in this file ever waits for the
// main thread: every call runs on the calling thread under one private mutex.
//
// THREADING. NSPasteboard's thread-safety is not documented either way, so all
// of OUR pasteboard traffic is serialised by g_mu (the Java side additionally
// orders state + write under its own monitor, always taken BEFORE g_mu, never
// after). NSRunningApplication IS documented thread-safe: "NSRunningApplication
// is thread safe, in that its properties are returned atomically"
// (NSRunningApplication.h, macOS 26 SDK), which is why the focus probe below
// reads it off the main thread instead of NSApp.isActive.
//
// MACOS PASTEBOARD PRIVACY. macOS 15.4 added NSPasteboard.accessBehavior and an
// opt-in alert on programmatic reads of the GENERAL pasteboard ("The default
// behavior for the General pasteboard is to ask upon programmatic access",
// NSPasteboard.h). It is a developer preview, not on by default in macOS 26.
// We are written to be quiet under it anyway: the listener poll reads ONLY
// changeCount, and pasteboard CONTENT is read only when the guest itself calls
// getPrimaryClip / getPrimaryClipDescription -- the Android moment of paste.
//
// STRINGS cross JNI as UTF-16 (GetStringChars / NewString), never as
// NewStringUTF: JNI's "modified UTF-8" encodes a supplementary character as two
// 3-byte surrogates, so an emoji copied in Safari would arrive mangled through
// the UTF-8 route.
//
// TEST HOOK. MACAPK_CLIPBOARD_TEST_PASTEBOARD=unique switches this process to a
// PRIVATE pasteboard from +pasteboardWithUniqueName (any other value opens the
// pasteboard of that name). It exists so debug/clipboard_gate.sh can exercise
// the real pasteboard server end to end, with a second process playing "another
// macOS app", without ever writing the user's clipboard. Unset in every real
// launch; when set, one loud line says so.
//
// NO ARC IN THIS TU (matches cocoa_bridge.mm / camera_capture.mm).

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include <jni.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

static_assert(sizeof(jchar) == sizeof(unichar), "jchar and unichar are both UTF-16 code units");

// Types beyond AppKit's constants.
//
// org.nspasteboard.ConcealedType -- the nspasteboard.org convention every
// macOS clipboard manager honours: "This marker's presence indicates content
// that should be treated as confidential", so managers obfuscate it and do not
// record it. It is the host's counterpart of Android's
// ClipDescription.EXTRA_IS_SENSITIVE, which Android 13+ uses to hide a clip's
// preview; the mapping runs both ways.
NSString* const kConcealedType = @"org.nspasteboard.ConcealedType";
// Our own two markers, so a clip survives a trip through the pasteboard with
// the two facts Android's clipboard service keeps beside it: WHICH package set
// it (ClipboardService's primaryClipUid/mPrimaryClipPackage, which decides
// whether reading it is "another app's clip") and the ClipDescription label.
// Another Mac.apk app, or this app after a restart, reads them back.
NSString* const kSourceType = @"org.macapk.android.clip.source";
NSString* const kLabelType  = @"org.macapk.android.clip.label";

// Bit layout shared with ClipboardManager.MacApkHostPasteboard.TYPE_*.
enum : jint {
    kTypeText      = 1,
    kTypeHtml      = 2,
    kTypeUrl       = 4,
    kTypeConcealed = 8,
    kTypeMacApk    = 16,
};

std::mutex g_mu;
NSPasteboard* g_pb = nil;      // retained for the life of the process
bool g_pb_resolved = false;

// Caller holds g_mu and an autorelease pool.
NSPasteboard* BoardLocked() {
    if (!g_pb_resolved) {
        g_pb_resolved = true;
        NSPasteboard* pb = nil;
        const char* test = std::getenv("MACAPK_CLIPBOARD_TEST_PASTEBOARD");
        @try {
            if (test && test[0]) {
                pb = (std::strcmp(test, "unique") == 0)
                    ? [NSPasteboard pasteboardWithUniqueName]
                    : [NSPasteboard pasteboardWithName:[NSString stringWithUTF8String:test]];
                std::fprintf(stderr,
                    "[I] clipboard: TEST pasteboard '%s' in use "
                    "(MACAPK_CLIPBOARD_TEST_PASTEBOARD); the general pasteboard is untouched\n",
                    pb ? [[pb name] UTF8String] : "(null)");
            } else {
                pb = [NSPasteboard generalPasteboard];
            }
        } @catch (NSException* e) {
            std::fprintf(stderr, "[E] clipboard: pasteboard unavailable: %s\n",
                         [[e reason] UTF8String]);
            pb = nil;
        }
        g_pb = [pb retain];
    }
    return g_pb;
}

NSString* ToNS(JNIEnv* env, jstring s) {
    if (!s) return nil;
    const jsize n = env->GetStringLength(s);
    const jchar* chars = env->GetStringChars(s, nullptr);
    if (!chars) {
        env->ExceptionClear();
        return nil;
    }
    NSString* out = [NSString stringWithCharacters:reinterpret_cast<const unichar*>(chars)
                                            length:static_cast<NSUInteger>(n)];
    env->ReleaseStringChars(s, chars);
    return out;
}

jstring ToJ(JNIEnv* env, NSString* s) {
    if (!s) return nullptr;
    const NSUInteger n = [s length];
    std::vector<unichar> buf(n ? n : 1);
    [s getCharacters:buf.data() range:NSMakeRange(0, n)];
    jstring out = env->NewString(reinterpret_cast<const jchar*>(buf.data()),
                                 static_cast<jsize>(n));
    if (!out) env->ExceptionClear();
    return out;
}

jint TypesMaskLocked(NSPasteboard* pb) {
    NSArray* types = [pb types];
    if (!types) return 0;
    jint m = 0;
    if ([types containsObject:NSPasteboardTypeString]) m |= kTypeText;
    if ([types containsObject:NSPasteboardTypeHTML])   m |= kTypeHtml;
    if ([types containsObject:NSPasteboardTypeURL] ||
        [types containsObject:NSPasteboardTypeFileURL]) m |= kTypeUrl;
    if ([types containsObject:kConcealedType])         m |= kTypeConcealed;
    if ([types containsObject:kSourceType])            m |= kTypeMacApk;
    return m;
}

// ---- JNI: android.content.ClipboardManager$MacApkHostPasteboard ----

// -1 when there is no pasteboard at all (the Java side then keeps its
// pre-bridge path). changeCount is metadata: it never reads content and never
// triggers the macOS paste-privacy alert.
jlong JNICALL NativeChangeCount(JNIEnv*, jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        @try {
            NSPasteboard* pb = BoardLocked();
            return pb ? static_cast<jlong>([pb changeCount]) : static_cast<jlong>(-1);
        } @catch (NSException*) {
            return static_cast<jlong>(-1);
        }
    }
}

jint JNICALL NativeTypes(JNIEnv*, jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        @try {
            NSPasteboard* pb = BoardLocked();
            return pb ? TypesMaskLocked(pb) : static_cast<jint>(-1);
        } @catch (NSException*) {
            return static_cast<jint>(-1);
        }
    }
}

// Replace the pasteboard with ONE item carrying every representation we have.
// Returns the changeCount after the write (what the Java side records as "our
// clip"), or -1. A sensitive clip is written with
// NSPasteboardContentsCurrentHostOnly ("should not be available to other
// devices", NSPasteboard.h) so a password does not ride Universal Clipboard to
// the user's phone, plus the ConcealedType marker for clipboard managers.
jlong JNICALL NativeWrite(JNIEnv* env, jclass, jstring jtext, jstring jhtml, jstring jurl,
                          jstring jsource, jstring jlabel, jboolean sensitive) {
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        NSString* text   = ToNS(env, jtext);
        NSString* html   = ToNS(env, jhtml);
        NSString* url    = ToNS(env, jurl);
        NSString* source = ToNS(env, jsource);
        NSString* label  = ToNS(env, jlabel);
        @try {
            NSPasteboard* pb = BoardLocked();
            if (!pb) return static_cast<jlong>(-1);
            if (sensitive) {
                [pb prepareForNewContentsWithOptions:NSPasteboardContentsCurrentHostOnly];
            } else {
                [pb clearContents];
            }
            bool ok = true;
            if (text) ok = [pb setString:text forType:NSPasteboardTypeString] && ok;
            if (html) ok = [pb setString:html forType:NSPasteboardTypeHTML] && ok;
            if (url)  ok = [pb setString:url forType:NSPasteboardTypeURL] && ok;
            if (sensitive) [pb setString:@"" forType:kConcealedType];
            if (source) [pb setString:source forType:kSourceType];
            if (label)  [pb setString:label forType:kLabelType];
            if (!ok) {
                std::fprintf(stderr,
                    "[W] clipboard: the pasteboard refused a representation of the clip\n");
            }
            return static_cast<jlong>([pb changeCount]);
        } @catch (NSException* e) {
            std::fprintf(stderr, "[E] clipboard: write failed: %s\n", [[e reason] UTF8String]);
            return static_cast<jlong>(-1);
        }
    }
}

// Android clearPrimaryClip. clearContents leaves NO types, which is what a
// cleared clipboard is to every other macOS app (nothing to paste).
jlong JNICALL NativeClear(JNIEnv*, jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        @try {
            NSPasteboard* pb = BoardLocked();
            if (!pb) return static_cast<jlong>(-1);
            [pb clearContents];
            return static_cast<jlong>([pb changeCount]);
        } @catch (NSException*) {
            return static_cast<jlong>(-1);
        }
    }
}

// Read every representation we understand, as ONE consistent snapshot: the
// changeCount is sampled before and after, and a snapshot that straddles
// another app's copy is retried. Returns {text, html, url, sourcePackage,
// label} (each nullable) and writes {changeCount, typesMask} into out[0..1].
jobjectArray JNICALL NativeRead(JNIEnv* env, jclass, jlongArray out) {
    if (!out || env->GetArrayLength(out) < 2) return nullptr;
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        @try {
            NSPasteboard* pb = BoardLocked();
            if (!pb) return nullptr;
            NSString* text = nil;
            NSString* html = nil;
            NSString* url = nil;
            NSString* source = nil;
            NSString* label = nil;
            NSInteger count = 0;
            jint mask = 0;
            bool consistent = false;
            for (int attempt = 0; attempt < 3 && !consistent; ++attempt) {
                const NSInteger before = [pb changeCount];
                text   = [pb stringForType:NSPasteboardTypeString];
                html   = [pb stringForType:NSPasteboardTypeHTML];
                url    = [pb stringForType:NSPasteboardTypeURL];
                if (!url) url = [pb stringForType:NSPasteboardTypeFileURL];
                source = [pb stringForType:kSourceType];
                label  = [pb stringForType:kLabelType];
                mask   = TypesMaskLocked(pb);
                count  = [pb changeCount];
                consistent = (before == count);
            }
            jclass strCls = env->FindClass("java/lang/String");
            if (!strCls) {
                env->ExceptionClear();
                return nullptr;
            }
            jobjectArray arr = env->NewObjectArray(5, strCls, nullptr);
            env->DeleteLocalRef(strCls);
            if (!arr) {
                env->ExceptionClear();
                return nullptr;
            }
            NSString* parts[5] = {text, html, url, source, label};
            for (int i = 0; i < 5; ++i) {
                jstring js = ToJ(env, parts[i]);
                if (js) {
                    env->SetObjectArrayElement(arr, i, js);
                    env->DeleteLocalRef(js);
                }
            }
            const jlong vals[2] = {static_cast<jlong>(count), static_cast<jlong>(mask)};
            env->SetLongArrayRegion(out, 0, 2, vals);
            return arr;
        } @catch (NSException* e) {
            std::fprintf(stderr, "[E] clipboard: read failed: %s\n", [[e reason] UTF8String]);
            return nullptr;
        }
    }
}

// Is this process the active (focused) macOS app? The host equivalent of
// ClipboardService's `mWm.isUidFocused(uid)`: on Android only the app whose
// window has focus may read the clipboard. Documented thread-safe (see header).
jboolean JNICALL NativeHostFocused(JNIEnv*, jclass) {
    @autoreleasepool {
        @try {
            return [[NSRunningApplication currentApplication] isActive] ? JNI_TRUE : JNI_FALSE;
        } @catch (NSException*) {
            return JNI_FALSE;
        }
    }
}

// The name of the pasteboard this process uses (the gate asserts it is NOT
// the general pasteboard before it writes anything).
jstring JNICALL NativePasteboardName(JNIEnv* env, jclass) {
    std::lock_guard<std::mutex> lock(g_mu);
    @autoreleasepool {
        @try {
            NSPasteboard* pb = BoardLocked();
            return pb ? ToJ(env, [pb name]) : nullptr;
        } @catch (NSException*) {
            return nullptr;
        }
    }
}

// Every native MacApkHostPasteboard declares must be listed here, with the
// exact descriptor: RegisterNatives fails the WHOLE table on one mismatch.
const JNINativeMethod kClipboardMethods[] = {
    {const_cast<char*>("nativeChangeCount"), const_cast<char*>("()J"),
     reinterpret_cast<void*>(NativeChangeCount)},
    {const_cast<char*>("nativeTypes"), const_cast<char*>("()I"),
     reinterpret_cast<void*>(NativeTypes)},
    {const_cast<char*>("nativeWrite"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                       "Ljava/lang/String;Ljava/lang/String;Z)J"),
     reinterpret_cast<void*>(NativeWrite)},
    {const_cast<char*>("nativeClear"), const_cast<char*>("()J"),
     reinterpret_cast<void*>(NativeClear)},
    {const_cast<char*>("nativeRead"), const_cast<char*>("([J)[Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeRead)},
    {const_cast<char*>("nativeHostFocused"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(NativeHostFocused)},
    {const_cast<char*>("nativePasteboardName"), const_cast<char*>("()Ljava/lang/String;"),
     reinterpret_cast<void*>(NativePasteboardName)},
};

}  // namespace

namespace macapk {
namespace clipboard {

// Registers android.content.ClipboardManager$MacApkHostPasteboard's natives.
// SOFT-FAILS like the camera / webview registrations: a miss leaves the Java
// side's first native call throwing UnsatisfiedLinkError, which it catches and
// answers by keeping the pre-bridge path for the run. Clipboard trouble must
// never abort boot.
void RegisterClipboardBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/content/ClipboardManager$MacApkHostPasteboard");
    if (!cls) {
        std::fprintf(stderr,
            "[E] clipboard: FindClass(android.content.ClipboardManager$MacApkHostPasteboard) "
            "failed; ClipboardManager keeps its pre-bridge path this run\n");
        env->ExceptionClear();
        return;
    }
    if (env->RegisterNatives(cls, kClipboardMethods,
                             sizeof(kClipboardMethods) / sizeof(kClipboardMethods[0])) != JNI_OK) {
        std::fprintf(stderr,
            "[E] clipboard: RegisterNatives failed; ClipboardManager keeps its "
            "pre-bridge path this run\n");
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
}

}  // namespace clipboard
}  // namespace macapk
