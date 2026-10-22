// document_picker.mm -- DocumentsUI's picker realised with the macOS open/save
// panel (v1.0.1653; com.macapk.loader.DocumentPickerHandler is the Java half).
//
// Rung 1 of the host ladder: macOS ships a native document picker. The Java
// handler claims the caller's activity result and calls nativePick or
// nativePickEx; this file shows NSOpenPanel (GET_CONTENT / OPEN_DOCUMENT),
// NSSavePanel (CREATE_DOCUMENT) or a directory-choosing NSOpenPanel
// (OPEN_DOCUMENT_TREE, v1.0.1654) on the AppKit main thread, asynchronously, and
// hands the chosen paths back through
// DocumentPickerHandler.macapkOnPicked(long, String[]) (an empty array when the
// user cancels). Nothing blocks the Android main looper: the app is covered
// (paused + stopped) while the panel is up, as it is under a full-screen
// DocumentsUI on a device.
//
// The requested MIME types become UTType filters: "*/*" allows everything,
// "image/*" / "video/*" / "audio/*" / "text/*" map to the UTType families, any
// other concrete type goes through UTType typeWithMIMEType:. A type macOS does
// not know is dropped from the filter rather than making the panel reject every
// file.
//
// nativePickEx (v1.0.1654) adds a mode and a starting directory:
//   * mode 0 / 1 are the open / save panels above, opened at `initialDir`
//     (DocumentsContract.EXTRA_INITIAL_URI, resolved by the Java side);
//   * mode 2 chooses ONE directory. Its button reads "Use this folder"
//     (DocumentsUI's open_tree_button), and a delegate asks Java
//     (DocumentPickerHandler.macapkTreeBlockReason) whether DocumentsUI would
//     refuse the directory -- ExternalStorageProvider.shouldBlockFromTree's host
//     analogue. A refused choice gets DocumentsUI's own message, "Can't use this
//     folder" / "To protect your privacy, choose another folder"
//     (strings.xml directory_blocked_header_title / _subtitle), and the panel
//     stays open, as PickFragment keeps "Use this folder" disabled on a device
//     (PickFragment.updateView :180-189). Backing out is RESULT_CANCELED.
//
// Compiled with ARC (see CMakeLists.txt): the panel, its delegate and the filter
// arrays are owned by blocks that outlive the JNI call.
//
// Registered SOFTLY (RegisterDocumentPickerMethods), one method at a time: a
// framework jar without a Java declaration must not abort boot, and a jar that
// has nativePick but not nativePickEx keeps the v1.0.1653 panel. The Java side
// cancels a pick whose native method is missing.

#import <AppKit/AppKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <jni.h>
#include <cstdio>

namespace macapk {
namespace docpicker {

static JavaVM*   g_vm = nullptr;
static jclass    g_cls = nullptr;
static jmethodID g_on_picked = nullptr;
static jmethodID g_block_reason = nullptr;   // String macapkTreeBlockReason(String), optional

static JNIEnv* attachedEnv() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21);
    if (r == JNI_EDETACHED) g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
    return env;
}

static void deliver(jlong id, NSArray<NSURL*>* urls) {
    if (!g_vm || !g_cls || !g_on_picked) return;
    JNIEnv* env = attachedEnv();
    if (!env) return;
    jclass str = env->FindClass("java/lang/String");
    jsize n = urls ? (jsize) urls.count : 0;
    jobjectArray arr = env->NewObjectArray(n, str, nullptr);
    for (jsize i = 0; i < n; i++) {
        NSString* p = urls[(NSUInteger) i].path;
        jstring js = env->NewStringUTF(p ? p.UTF8String : "");
        env->SetObjectArrayElement(arr, i, js);
        env->DeleteLocalRef(js);
    }
    env->CallStaticVoidMethod(g_cls, g_on_picked, id, arr);
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
    env->DeleteLocalRef(arr);
    env->DeleteLocalRef(str);
}

/** Java's verdict on a directory for OPEN_DOCUMENT_TREE: nil when it may be
 *  granted, else the reason. Without the Java method, nil (the Java side still
 *  refuses a blocked directory when the pick is delivered). */
static NSString* blockReason(NSString* path) {
    if (!g_cls || !g_block_reason || !path) return nil;
    JNIEnv* env = attachedEnv();
    if (!env) return nil;
    jstring jp = env->NewStringUTF(path.UTF8String);
    jstring jr = (jstring) env->CallStaticObjectMethod(g_cls, g_block_reason, jp);
    env->DeleteLocalRef(jp);
    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); return nil; }
    if (!jr) return nil;
    NSString* out = nil;
    const char* c = env->GetStringUTFChars(jr, nullptr);
    if (c) { out = [NSString stringWithUTF8String:c]; env->ReleaseStringUTFChars(jr, c); }
    env->DeleteLocalRef(jr);
    return out;
}

static NSArray<UTType*>* contentTypesFor(NSArray<NSString*>* mimes) {
    NSMutableArray<UTType*>* out = [NSMutableArray array];
    for (NSString* m in mimes) {
        NSString* mime = m.lowercaseString;
        if ([mime isEqualToString:@"*/*"] || mime.length == 0) return nil;   // anything
        if ([mime isEqualToString:@"image/*"]) { [out addObject:UTTypeImage]; continue; }
        if ([mime isEqualToString:@"video/*"]) { [out addObject:UTTypeMovie]; continue; }
        if ([mime isEqualToString:@"audio/*"]) { [out addObject:UTTypeAudio]; continue; }
        if ([mime isEqualToString:@"text/*"])  { [out addObject:UTTypeText];  continue; }
        if ([mime hasSuffix:@"/*"]) return nil;   // a family macOS has no single type for
        UTType* t = [UTType typeWithMIMEType:mime];
        if (t) [out addObject:t];
    }
    return out.count ? out : nil;
}

static NSString* jstr(JNIEnv* env, jstring s) {
    if (!s) return nil;
    NSString* out = nil;
    const char* c = env->GetStringUTFChars(s, nullptr);
    if (c) { out = [NSString stringWithUTF8String:c]; env->ReleaseStringUTFChars(s, c); }
    return out;
}

static NSMutableArray<NSString*>* jstrs(JNIEnv* env, jobjectArray a) {
    NSMutableArray<NSString*>* out = [NSMutableArray array];
    jsize n = a ? env->GetArrayLength(a) : 0;
    for (jsize i = 0; i < n; i++) {
        jstring s = (jstring) env->GetObjectArrayElement(a, i);
        if (!s) continue;
        NSString* v = jstr(env, s);
        if (v) [out addObject:v];
        env->DeleteLocalRef(s);
    }
    return out;
}

}  // namespace docpicker
}  // namespace macapk

/** The OPEN_DOCUMENT_TREE panel's delegate: refuses a directory DocumentsUI would
 *  refuse, with DocumentsUI's message; AppKit shows the error and keeps the panel
 *  open (NSOpenSavePanelDelegate panel:validateURL:error:). */
@interface MacApkTreePanelDelegate : NSObject <NSOpenSavePanelDelegate>
@end

@implementation MacApkTreePanelDelegate
- (BOOL)panel:(id)sender validateURL:(NSURL*)url error:(NSError**)outError {
    NSString* why = macapk::docpicker::blockReason(url.path);
    if (!why) return YES;
    std::fprintf(stderr, "[I] documents: tree pick refused (%s)\n", why.UTF8String);
    if (outError) {
        *outError = [NSError errorWithDomain:@"io.github.totktonado96.apkonmac.documents" code:1 userInfo:@{
            NSLocalizedDescriptionKey : @"Can’t use this folder",
            NSLocalizedRecoverySuggestionErrorKey : @"To protect your privacy, choose another folder",
        }];
    }
    return NO;
}
@end

namespace macapk {
namespace docpicker {

static constexpr int kModeOpen = 0, kModeSave = 1, kModeTree = 2;

/** Show the panel for `mode` on the AppKit main queue. `initialDir` nil keeps the
 *  panel's own last directory (the v1.0.1653 behaviour). */
static void showPanel(int mode, bool many, NSArray<NSString*>* mimes, NSString* name,
                      NSString* initialDir, jlong id) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSURL* start = initialDir.length ? [NSURL fileURLWithPath:initialDir isDirectory:YES] : nil;
        if (mode == kModeSave) {
            NSArray<UTType*>* types = contentTypesFor(mimes);
            NSSavePanel* p = [NSSavePanel savePanel];
            if (name.length) p.nameFieldStringValue = name;
            if (types.count == 1) p.allowedContentTypes = types;
            p.canCreateDirectories = YES;
            if (start) p.directoryURL = start;
            [p beginWithCompletionHandler:^(NSModalResponse r) {
                deliver(id, (r == NSModalResponseOK && p.URL) ? @[ p.URL ] : @[]);
            }];
        } else if (mode == kModeTree) {
            NSOpenPanel* p = [NSOpenPanel openPanel];
            MacApkTreePanelDelegate* d = [MacApkTreePanelDelegate new];
            p.canChooseFiles = NO;
            p.canChooseDirectories = YES;
            p.allowsMultipleSelection = NO;
            p.canCreateDirectories = YES;
            p.prompt = @"Use this folder";   // DocumentsUI open_tree_button
            p.delegate = d;                  // weak: `d` is kept alive by the block below
            if (start) p.directoryURL = start;
            [p beginWithCompletionHandler:^(NSModalResponse r) {
                (void) d;
                p.delegate = nil;
                deliver(id, (r == NSModalResponseOK && p.URL) ? @[ p.URL ] : @[]);
            }];
        } else {
            NSArray<UTType*>* types = contentTypesFor(mimes);
            NSOpenPanel* p = [NSOpenPanel openPanel];
            p.canChooseFiles = YES;
            p.canChooseDirectories = NO;
            p.allowsMultipleSelection = many;
            if (types) p.allowedContentTypes = types;
            if (start) p.directoryURL = start;
            [p beginWithCompletionHandler:^(NSModalResponse r) {
                deliver(id, r == NSModalResponseOK ? p.URLs : @[]);
            }];
        }
    });
}

static jboolean nativePick(JNIEnv* env, jclass, jboolean save, jboolean multiple,
                           jobjectArray mimes_j, jstring name_j, jlong id) {
  // A JNI caller thread has no autorelease pool of its own.
  @autoreleasepool {
    NSMutableArray<NSString*>* mimes = jstrs(env, mimes_j);
    NSString* name = jstr(env, name_j);
    showPanel(save == JNI_TRUE ? kModeSave : kModeOpen, multiple == JNI_TRUE, mimes, name, nil, id);
  }
    return JNI_TRUE;
}

static jboolean nativePickEx(JNIEnv* env, jclass, jint mode, jboolean multiple,
                             jobjectArray mimes_j, jstring name_j, jstring dir_j, jlong id) {
    if (mode != kModeOpen && mode != kModeSave && mode != kModeTree) return JNI_FALSE;
  @autoreleasepool {
    NSMutableArray<NSString*>* mimes = jstrs(env, mimes_j);
    NSString* name = jstr(env, name_j);
    NSString* dir = jstr(env, dir_j);
    showPanel((int) mode, multiple == JNI_TRUE, mimes, name, dir, id);
  }
    return JNI_TRUE;
}

static const JNINativeMethod kPick = {
    const_cast<char*>("nativePick"),
    const_cast<char*>("(ZZ[Ljava/lang/String;Ljava/lang/String;J)Z"),
    reinterpret_cast<void*>(nativePick)};

static const JNINativeMethod kPickEx = {
    const_cast<char*>("nativePickEx"),
    const_cast<char*>("(IZ[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)Z"),
    reinterpret_cast<void*>(nativePickEx)};

}  // namespace docpicker

void RegisterDocumentPickerMethods(JNIEnv* env) {
    using namespace docpicker;
    jclass cls = env->FindClass("com/macapk/loader/DocumentPickerHandler");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] documents: this loader jar has no DocumentPickerHandler;"
                             " the document picker is inactive this run\n");
        return;
    }
    if (env->RegisterNatives(cls, &kPick, 1) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] documents: DocumentPickerHandler.nativePick not declared;"
                             " the document picker is inactive this run\n");
        env->DeleteLocalRef(cls);
        return;
    }
    if (env->RegisterNatives(cls, &kPickEx, 1) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] documents: DocumentPickerHandler.nativePickEx not declared;"
                             " no tree picker or starting directory this run\n");
    }
    g_on_picked = env->GetStaticMethodID(cls, "macapkOnPicked", "(J[Ljava/lang/String;)V");
    if (!g_on_picked) { env->ExceptionClear(); env->DeleteLocalRef(cls); return; }
    g_block_reason = env->GetStaticMethodID(cls, "macapkTreeBlockReason",
                                            "(Ljava/lang/String;)Ljava/lang/String;");
    if (!g_block_reason) env->ExceptionClear();
    env->GetJavaVM(&g_vm);
    g_cls = (jclass) env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
}

}  // namespace macapk
