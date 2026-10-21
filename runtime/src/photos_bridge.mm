// photos_bridge.mm -- the macOS Photos LIBRARY as a read-only media source for
// android.provider.MediaStore (the nativePhotos* methods of
// android.provider.MediaStoreProvider -- on that class, not a new one, so FRAMEWORK_ID
// does not move and no installed app re-converts).
//
// WHY THIS EXISTS. A Mac keeps its camera roll in the Photos library, not in
// loose files, so an Android gallery on Mac.apk saw an almost empty volume even
// after ~/Pictures was mapped in (docs/shared-storage-real-mac-folders-design_
// 2026-09-25.md). The library package itself is TCC-protected and its layout is
// private, so MediaStore never walks it (MediaStoreProvider.HOST_PACKAGE_EXT).
// Rung 1 of the host-first ladder is PhotoKit, Apple's public API for exactly
// this, and it is what this file wraps. Design + decisions:
// docs/photokit-mediastore-design_2026-09-28.md; lane note
// docs/photos-library-mediastore_2026-09-29.md.
//
// CONTRACT (Photos.framework headers, MacOSX 26 SDK, quoted):
//   PHPhotoLibrary.h:19  PHAuthorizationStatus NotDetermined=0, Restricted=1,
//                        Denied=2, Authorized=3, Limited=4.
//   PHPhotoLibrary.h:64  + authorizationStatusForAccessLevel: (never prompts;
//                        measured from a non-bundle process on 26.5.2: returns 0,
//                        no TCC kill).
//   PHPhotoLibrary.h:65  + requestAuthorizationForAccessLevel:handler: -- raises
//                        macOS's own prompt, attributed to the RESPONSIBLE bundle.
//   PHAssetResourceManager.h:44 "Handlers are called on an arbitrary serial queue."
//                        - writeDataForAssetResource:toFile:options:completionHandler:
//   PHAssetResourceManager.h:26 networkAccessAllowed (we pass NO: an iCloud-only
//                        original is listed but never downloaded by a scroll).
//   PHImageManager.h:155 "If -[PHImageRequestOptions isSynchronous] returns YES,
//                        resultHandler will be called exactly once, synchronously
//                        and on the calling thread."
//   PHAssetResource.h:25 contentType (UTType, macOS 26; uniformTypeIdentifier is
//                        deprecated -- no deprecated APIs on 26+).
//
// READ-ONLY, BY CONSTRUCTION. Nothing here creates a PHChangeRequest or calls
// -performChanges:. The only library-side effects are a TCC prompt (the user's
// answer) and PhotoKit's own read caches.
//
// THE PURPOSE STRING IS A HARD PRECONDITION. A process that asks PhotoKit for
// authorization without NSPhotoLibraryUsageDescription in the responsible
// bundle's Info.plist is TERMINATED by TCC. So the request is only ever issued
// from inside a .app whose Info.plist carries the key (the generated app stub:
// launcher/BundleGenerator.swift; the stub execs the runtime through its
// Contents/MacOS link, so NSBundle.mainBundle IS the stub, see camera_capture.mm).
// The dev binary is not a bundle: it never prompts, and it lists nothing unless
// its responsible process was ALREADY authorized -- which keeps harnesses
// hermetic on a machine where nobody granted the terminal Photos access.
//
// LAZY LOAD. Photos.framework is dlopen'd on first use instead of being linked:
// linking would load it (and PhotoLibraryServices/CoreData behind it) into EVERY
// app's boot, including the vast majority that never touch MediaStore. Classes
// are reached with NSClassFromString, so this TU has no link-time Photos symbol.
//
// THREADING. Every entry point runs on the calling Java thread and never hops to
// the main queue (Boot.run parks the AppKit main thread on Java work; a
// dispatch_sync to main from here would deadlock -- the v1.0.1644 CocoaDisplayHz
// lesson). Export waits on a semaphore for a handler PhotoKit delivers on its own
// serial queue; the thumbnail request is synchronous by option.
//
// ARC translation unit (CMakeLists sets -fobjc-arc), like document_picker.mm:
// completion handlers capture state that outlives the call frame.
//
// Gate: MACAPK_PHOTOKIT (read in Java, MediaStoreProvider.photosEnabled); =0 never calls in here.

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <Photos/Photos.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <ImageIO/ImageIO.h>
#include <jni.h>
#include <dlfcn.h>
#include <atomic>
#include <cstdio>

static std::atomic<long long> g_macapk_photos_generation{0};

// PHPhotoLibraryChangeObserver: any library change (an import, a delete, the
// user widening a limited selection) bumps the generation so Java re-lists on its
// next sync instead of re-fetching the whole library on every MediaStore query.
@interface MacApkPhotosObserver : NSObject <PHPhotoLibraryChangeObserver>
@end
@implementation MacApkPhotosObserver
- (void)photoLibraryDidChange:(PHChange*)changeInstance {
    (void)changeInstance;
    g_macapk_photos_generation.fetch_add(1);
}
@end

namespace macapk {
namespace photos {
namespace {

bool LoadPhotos() {
    static std::atomic<int> state{0};   // 0 unknown, 1 loaded, 2 unavailable
    int s = state.load();
    if (s != 0) return s == 1;
    void* h = dlopen("/System/Library/Frameworks/Photos.framework/Photos", RTLD_LAZY);
    bool ok = h != nullptr && NSClassFromString(@"PHPhotoLibrary") != nil;
    if (!ok) std::fprintf(stderr, "[photos] Photos.framework unavailable: %s\n", dlerror());
    state.store(ok ? 1 : 2);
    return ok;
}

id PHLibraryClass() { return (id)NSClassFromString(@"PHPhotoLibrary"); }

// True when the responsible bundle may ASK: a .app with the purpose string.
bool CanPrompt() {
    NSBundle* b = [NSBundle mainBundle];
    if (![b.bundlePath hasSuffix:@".app"]) return false;
    return [b objectForInfoDictionaryKey:@"NSPhotoLibraryUsageDescription"] != nil;
}

PHAuthorizationStatus Status() {
    if (!LoadPhotos()) return PHAuthorizationStatusRestricted;
    return (PHAuthorizationStatus)[PHLibraryClass()
        authorizationStatusForAccessLevel:PHAccessLevelReadWrite];
}

bool Readable(PHAuthorizationStatus s) {
    return s == PHAuthorizationStatusAuthorized || s == PHAuthorizationStatusLimited;
}

void EnsureObserver() {
    static std::atomic<bool> registered{false};
    if (registered.exchange(true)) return;
    static MacApkPhotosObserver* observer = [MacApkPhotosObserver new];
    PHPhotoLibrary* lib = (PHPhotoLibrary*)[PHLibraryClass() sharedPhotoLibrary];
    [lib registerChangeObserver:observer];
}

// The resource a device would hand a gallery: the CURRENT rendition (the
// FullSize* resource PhotoKit keeps for an edited asset) when there is one, else
// the original. `original` is the unedited resource, whose originalFilename is
// the camera's own name (IMG_0001.HEIC) rather than "FullSizeRender.jpg".
void PickResources(PHAsset* a, PHAssetResource** exportRes, PHAssetResource** original) {
    NSArray<PHAssetResource*>* rs = [(id)NSClassFromString(@"PHAssetResource")
        assetResourcesForAsset:a];
    const bool video = a.mediaType == PHAssetMediaTypeVideo;
    const PHAssetResourceType origType = video ? PHAssetResourceTypeVideo : PHAssetResourceTypePhoto;
    const PHAssetResourceType fullType = video ? PHAssetResourceTypeFullSizeVideo
                                               : PHAssetResourceTypeFullSizePhoto;
    PHAssetResource* orig = nil;
    PHAssetResource* full = nil;
    for (PHAssetResource* r in rs) {
        if (r.type == origType && orig == nil) orig = r;
        if (r.type == fullType && full == nil) full = r;
    }
    if (orig == nil && rs.count > 0) orig = rs[0];
    *original = orig;
    *exportRes = full != nil ? full : orig;
}

// A file-name component: no record separators, no path separators.
NSString* Clean(NSString* s) {
    if (s == nil) return @"";
    NSCharacterSet* bad = [NSCharacterSet characterSetWithCharactersInString:@"\t\n\r/:"];
    return [[s componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@"_"];
}

PHAsset* AssetFor(NSString* localId) {
    PHFetchResult<PHAsset*>* r = [(id)NSClassFromString(@"PHAsset")
        fetchAssetsWithLocalIdentifiers:@[ localId ] options:nil];
    return r.count > 0 ? r.firstObject : nil;
}

// Java <-> NSString through UTF-16, the encoding both sides really hold. JNI's
// GetStringUTFChars/NewStringUTF speak MODIFIED UTF-8, which writes a supplementary
// character (an emoji in a file name or in the android-root path) as TWO 3-byte
// surrogate halves; +stringWithUTF8String: rejects that as invalid and returns nil,
// so every export of such an asset would fail "no such asset".
// BEGIN ToNS
NSString* ToNS(JNIEnv* env, jstring s) {
    if (s == nullptr) return nil;
    const jchar* c = env->GetStringChars(s, nullptr);
    if (c == nullptr) return nil;
    NSString* out = [NSString stringWithCharacters:reinterpret_cast<const unichar*>(c)
                                            length:(NSUInteger)env->GetStringLength(s)];
    env->ReleaseStringChars(s, c);
    return out;
}
// END ToNS

// BEGIN FromNS
jstring FromNS(JNIEnv* env, NSString* s) {
    if (s == nil) return nullptr;
    const NSUInteger n = s.length;
    unichar* buf = static_cast<unichar*>(malloc((n ? n : 1) * sizeof(unichar)));
    if (buf == nullptr) return nullptr;
    [s getCharacters:buf range:NSMakeRange(0, n)];
    jstring out = env->NewString(reinterpret_cast<const jchar*>(buf), (jsize)n);
    free(buf);
    return out;
}
// END FromNS

jint JNICALL nStatus(JNIEnv*, jclass) {
    @autoreleasepool { return (jint)Status(); }
}

jboolean JNICALL nCanPrompt(JNIEnv*, jclass) {
    @autoreleasepool { return CanPrompt() ? JNI_TRUE : JNI_FALSE; }
}

// Non-blocking, once per process. The handler only bumps the generation; Java
// polls status. Blocking here would deadlock an app that queried MediaStore from
// the thread the prompt's answer has to come back through.
jboolean JNICALL nRequestAuth(JNIEnv*, jclass) {
    @autoreleasepool {
        static std::atomic<bool> asked{false};
        if (!CanPrompt() || !LoadPhotos()) return JNI_FALSE;
        if (Status() != PHAuthorizationStatusNotDetermined) return JNI_FALSE;
        if (asked.exchange(true)) return JNI_FALSE;
        std::fprintf(stderr, "[photos] requesting Photos access (macOS prompt)\n");
        [PHLibraryClass() requestAuthorizationForAccessLevel:PHAccessLevelReadWrite
                                                     handler:^(PHAuthorizationStatus s) {
            std::fprintf(stderr, "[photos] Photos access answered: %ld\n", (long)s);
            g_macapk_photos_generation.fetch_add(1);
        }];
        return JNI_TRUE;
    }
}

jlong JNICALL nGeneration(JNIEnv*, jclass) { return (jlong)g_macapk_photos_generation.load(); }

// One tab-separated record per asset:
//   localIdentifier, mediaType (MediaStore: 1 image / 3 video), creation ms,
//   modification ms, pixelWidth, pixelHeight, duration ms, file name, mime.
// null = not readable (no grant, no framework); an empty array = an empty (or
// empty limited) library. Java tells those two apart on purpose: only an
// authoritative answer may delete rows.
jobjectArray JNICALL nList(JNIEnv* env, jclass, jboolean images, jboolean videos) {
    @autoreleasepool {
        if (!LoadPhotos() || !Readable(Status())) return nullptr;
        EnsureObserver();
        PHFetchOptions* o = [[(id)NSClassFromString(@"PHFetchOptions") alloc] init];
        o.includeHiddenAssets = NO;   // Hidden album stays hidden, as in Photos
        o.sortDescriptors = @[ [NSSortDescriptor sortDescriptorWithKey:@"creationDate"
                                                             ascending:YES] ];
        if (images && videos) {
            o.predicate = [NSPredicate predicateWithFormat:@"mediaType == %d || mediaType == %d",
                           (int)PHAssetMediaTypeImage, (int)PHAssetMediaTypeVideo];
        } else {
            o.predicate = [NSPredicate predicateWithFormat:@"mediaType == %d",
                           (int)(images ? PHAssetMediaTypeImage : PHAssetMediaTypeVideo)];
        }
        PHFetchResult<PHAsset*>* r = [(id)NSClassFromString(@"PHAsset") fetchAssetsWithOptions:o];
        NSMutableArray<NSString*>* rows = [NSMutableArray arrayWithCapacity:r.count];
        for (PHAsset* a in r) {
            @autoreleasepool {
                PHAssetResource* res = nil;
                PHAssetResource* orig = nil;
                PickResources(a, &res, &orig);
                if (res == nil) continue;
                // localIdentifier is "<UUID>/L0/001": it keeps its '/' (AssetFor looks
                // it up verbatim) and can never hold a tab or newline.
                if ([a.localIdentifier rangeOfCharacterFromSet:
                        [NSCharacterSet newlineCharacterSet]].location != NSNotFound ||
                    [a.localIdentifier containsString:@"\t"]) continue;
                const bool video = a.mediaType == PHAssetMediaTypeVideo;
                NSString* base = [Clean(orig.originalFilename) stringByDeletingPathExtension];
                if (base.length == 0) base = video ? @"VID" : @"IMG";
                NSString* ext = res.contentType.preferredFilenameExtension;
                if (ext.length == 0) ext = orig.originalFilename.pathExtension;
                if (ext.length == 0) ext = video ? @"mov" : @"jpg";
                NSString* mime = res.contentType.preferredMIMEType;
                if (mime.length == 0) mime = video ? @"video/quicktime" : @"image/jpeg";
                long long created = a.creationDate
                    ? (long long)(a.creationDate.timeIntervalSince1970 * 1000.0) : 0;
                long long modified = a.modificationDate
                    ? (long long)(a.modificationDate.timeIntervalSince1970 * 1000.0) : created;
                [rows addObject:[NSString stringWithFormat:@"%@\t%d\t%lld\t%lld\t%lu\t%lu\t%lld\t%@.%@\t%@",
                    a.localIdentifier, video ? 3 : 1, created, modified,
                    (unsigned long)a.pixelWidth, (unsigned long)a.pixelHeight,
                    (long long)(a.duration * 1000.0), base, Clean(ext), mime]];
            }
        }
        jclass sc = env->FindClass("java/lang/String");
        jobjectArray out = env->NewObjectArray((jsize)rows.count, sc, nullptr);
        if (out == nullptr) return nullptr;
        for (NSUInteger i = 0; i < rows.count; i++) {
            jstring js = FromNS(env, rows[i]);
            env->SetObjectArrayElement(out, (jsize)i, js);
            env->DeleteLocalRef(js);
        }
        return out;
    }
}

// Writes the asset's current rendition to `path` (which must not exist; Java
// passes a fresh temp name and renames). Returns null on success, else a reason.
jstring JNICALL nExport(JNIEnv* env, jclass, jstring jid, jstring jpath) {
    @autoreleasepool {
        if (!LoadPhotos() || !Readable(Status())) return env->NewStringUTF("not authorized");
        NSString* lid = ToNS(env, jid);
        NSString* path = ToNS(env, jpath);
        PHAsset* a = lid ? AssetFor(lid) : nil;
        if (a == nil || path == nil) return env->NewStringUTF("no such asset");
        PHAssetResource* res = nil;
        PHAssetResource* orig = nil;
        PickResources(a, &res, &orig);
        if (res == nil) return env->NewStringUTF("asset has no resource");
        PHAssetResourceRequestOptions* ro =
            [[(id)NSClassFromString(@"PHAssetResourceRequestOptions") alloc] init];
        ro.networkAccessAllowed = NO;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block NSString* failure = nil;
        PHAssetResourceManager* mgr =
            (PHAssetResourceManager*)[(id)NSClassFromString(@"PHAssetResourceManager") defaultManager];
        [mgr writeDataForAssetResource:res
                               toFile:[NSURL fileURLWithPath:path]
                              options:ro
                    completionHandler:^(NSError* error) {
            if (error != nil) failure = [error.localizedDescription copy];
            dispatch_semaphore_signal(done);
        }];
        // A local original writes in well under a second; the bound exists only so
        // a wedged photolibraryd cannot hang an app's query thread forever.
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW,
                                                        120LL * NSEC_PER_SEC)) != 0) {
            return env->NewStringUTF("timed out");
        }
        return failure ? FromNS(env, failure) : nullptr;
    }
}

// A JPEG of the asset rendered by PhotoKit no smaller than w x h on EITHER axis
// (aspect kept), for MediaStore's EXTRA_SIZE thumbnail path: no full export needed
// to fill a grid. AspectFill, not AspectFit: fit returns an image INSIDE w x h,
// which ContentResolver.loadThumbnail would then upscale on its short axis (blurry
// cells); AOSP's ThumbnailUtils takes the MIN sample so both axes stay >= the request.
jboolean JNICALL nThumbnail(JNIEnv* env, jclass, jstring jid, jint w, jint h, jstring jpath) {
    @autoreleasepool {
        if (!LoadPhotos() || !Readable(Status()) || w <= 0 || h <= 0) return JNI_FALSE;
        NSString* lid = ToNS(env, jid);
        NSString* path = ToNS(env, jpath);
        PHAsset* a = lid ? AssetFor(lid) : nil;
        if (a == nil || path == nil) return JNI_FALSE;
        PHImageRequestOptions* io = [[(id)NSClassFromString(@"PHImageRequestOptions") alloc] init];
        io.synchronous = YES;
        io.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;
        io.resizeMode = PHImageRequestOptionsResizeModeFast;
        io.networkAccessAllowed = NO;
        __block CGImageRef cg = NULL;
        PHImageManager* im = (PHImageManager*)[(id)NSClassFromString(@"PHImageManager") defaultManager];
        [im requestImageForAsset:a
                      targetSize:CGSizeMake(w, h)
                     contentMode:PHImageContentModeAspectFill
                         options:io
                   resultHandler:^(NSImage* img, NSDictionary* info) {
            (void)info;
            if (img == nil) return;
            CGImageRef c = [img CGImageForProposedRect:NULL context:nil hints:nil];
            if (c) cg = CGImageRetain(c);
        }];
        if (cg == NULL) return JNI_FALSE;
        CGImageDestinationRef d = CGImageDestinationCreateWithURL(
            (__bridge CFURLRef)[NSURL fileURLWithPath:path],
            (__bridge CFStringRef)UTTypeJPEG.identifier, 1, NULL);
        bool ok = false;
        if (d) {
            CGImageDestinationAddImage(d, cg, NULL);
            ok = CGImageDestinationFinalize(d);
            CFRelease(d);
        }
        CGImageRelease(cg);
        return ok ? JNI_TRUE : JNI_FALSE;
    }
}

const JNINativeMethod kPhotosMethods[] = {
    {(char*)"nativePhotosStatus", (char*)"()I", (void*)nStatus},
    {(char*)"nativePhotosCanPrompt", (char*)"()Z", (void*)nCanPrompt},
    {(char*)"nativePhotosRequestAuth", (char*)"()Z", (void*)nRequestAuth},
    {(char*)"nativePhotosGeneration", (char*)"()J", (void*)nGeneration},
    {(char*)"nativePhotosList", (char*)"(ZZ)[Ljava/lang/String;", (void*)nList},
    {(char*)"nativePhotosExport", (char*)"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
     (void*)nExport},
    {(char*)"nativePhotosThumbnail", (char*)"(Ljava/lang/String;IILjava/lang/String;)Z",
     (void*)nThumbnail},
};

}  // namespace

// Test hook for debug/photos_gate.sh (declared and registered only by that gate's
// JNI shim, never by the runtime): a Java string through ToNS and back through
// FromNS, so the gate can prove a supplementary character survives the round trip.
jstring RoundTripForTest(JNIEnv* env, jstring s) {
    @autoreleasepool { return FromNS(env, ToNS(env, s)); }
}

// Soft-fails like the other host bridges: a jar without the natives simply has no
// Photos source (MediaStore keeps its volume-only answer).
void RegisterPhotosBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/provider/MediaStoreProvider");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(MediaStoreProvider) failed; no Photos library source\n");
        env->ExceptionClear();
        return;
    }
    const jint n = (jint)(sizeof(kPhotosMethods) / sizeof(kPhotosMethods[0]));
    if (env->RegisterNatives(cls, kPhotosMethods, n) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(MediaStoreProvider photos) failed; no Photos library source\n");
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
}

}  // namespace photos
}  // namespace macapk
