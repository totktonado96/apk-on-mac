// notification_bridge.mm -- android.app.NotificationManager <-> macOS Notification
// Center (UNUserNotificationCenter).
//
// AOSP NotificationManager.notify() enqueues into NotificationManagerService,
// whose output surface is the shade/heads-up. The Mac's equivalent is the
// Notification Center banner, so posts are forwarded there (decision-ladder
// rung 1). UserNotifications.framework is in the dyld shared cache.
//
// UNUserNotificationCenter throws unless the process is a real app bundle
// ([NSBundle mainBundle].bundleIdentifier != nil), so every entry point
// no-ops (logging once) when run bare from a `java` launcher.
//
// Threading: the center is touched on the main queue only. The delegate and
// the completion handlers run on a private UN queue; a click hops to the main
// queue, activates the app, and calls Java there (attached as a daemon) -- the
// Java side re-posts onto the main Looper, as MacApkNowPlaying does.
//
// MRC, like the other .mm bridges in this target.
#import <AppKit/AppKit.h>
#import <UserNotifications/UserNotifications.h>
#include <jni.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace macapk {
namespace notification {
namespace {

JavaVM*   g_vm = nullptr;
jclass    g_cls = nullptr;          // global ref to android.app.NotificationManager
jmethodID g_on_click = nullptr;
jmethodID g_on_cold_click = nullptr;
jmethodID g_on_action = nullptr;
// Cold-click stash (main queue only). A click that LAUNCHED the app arrives from
// the UN delegate long before Java has an Activity; firing the PendingIntent
// then would start an Activity under a half-booted app. Hold it until Java
// reports the first Activity resumed (nativeBootReady).
bool      g_boot_ready = false;
NSMutableArray* g_cold_stash = nil;  // of copied blocks, run on boot ready
std::atomic<int> g_auth{0};         // 0 unknown / not asked, 1 granted, 2 denied
bool      g_asked = false;          // main queue only

bool HaveBundle() {
    static int has = -1;
    if (has < 0) {
        has = [NSBundle mainBundle].bundleIdentifier != nil ? 1 : 0;
        if (!has)
            std::fprintf(stderr, "[I] notification: no bundle identifier; "
                         "notifications are not bridged in an unbundled process\n");
    }
    return has == 1;
}

JNIEnv* Env() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21);
    if (r == JNI_EDETACHED &&
        g_vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) {
        return nullptr;
    }
    return env;
}

void SendClick(NSString* key) {
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_click || !key) return;
    jstring js = env->NewStringUTF(key.UTF8String);
    env->CallStaticVoidMethod(g_cls, g_on_click, js);
    env->DeleteLocalRef(js);
    if (env->ExceptionCheck()) {
        std::fprintf(stderr, "[W] notification: Java threw in macapkOnNotificationClicked\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

// MACAPK_NOTIF_COLD_CLICK=0 restores the old behaviour (a click with no live
// Notification in the Java map is dropped).
bool ColdEnabled() {
    const char* e = std::getenv("MACAPK_NOTIF_COLD_CLICK");
    return !(e && std::strcmp(e, "0") == 0);
}

void SendColdClick(NSString* key, NSString* payload) {
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_cold_click || !key || !payload) return;
    jstring jk = env->NewStringUTF(key.UTF8String);
    jstring jp = env->NewStringUTF(payload.UTF8String);
    env->CallStaticVoidMethod(g_cls, g_on_cold_click, jk, jp);
    env->DeleteLocalRef(jk);
    env->DeleteLocalRef(jp);
    if (env->ExceptionCheck()) {
        std::fprintf(stderr, "[W] notification: Java threw in macapkOnColdNotificationClicked\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

// Main queue only. Runs `fn` now, or after the first Activity is up.
void RunWhenReady(void (^fn)(void)) {
    if (g_boot_ready) { fn(); return; }
    if (!g_cold_stash) g_cold_stash = [[NSMutableArray alloc] init];
    [g_cold_stash addObject:[[fn copy] autorelease]];
}

// MACAPK_NOTIF_ACTIONS=0 turns the action buttons off (no category is attached).
bool ActionsEnabled() {
    const char* e = std::getenv("MACAPK_NOTIF_ACTIONS");
    return !(e && std::strcmp(e, "0") == 0);
}

// Main queue only.
void HandleClick(NSString* key, NSString* payload) {
    if (payload && ColdEnabled() && g_on_cold_click) {
        [key retain]; [payload retain];
        RunWhenReady(^{ SendColdClick(key, payload); [key release]; [payload release]; });
        return;
    }
    SendClick(key);
}

// Main queue only. `cold` is the base64 action payload from userInfo (may be nil).
void HandleAction(NSString* key, int index, NSString* text, NSString* cold) {
    if (!g_on_action) return;
    [key retain]; [text retain]; [cold retain];
    RunWhenReady(^{
        JNIEnv* env = Env();
        if (env && g_cls) {
            jstring jk = env->NewStringUTF(key.UTF8String);
            jstring jt = text ? env->NewStringUTF(text.UTF8String) : nullptr;
            jstring jc = cold ? env->NewStringUTF(cold.UTF8String) : nullptr;
            env->CallStaticVoidMethod(g_cls, g_on_action, jk, (jint)index, jt, jc);
            env->DeleteLocalRef(jk);
            if (jt) env->DeleteLocalRef(jt);
            if (jc) env->DeleteLocalRef(jc);
            if (env->ExceptionCheck()) {
                std::fprintf(stderr, "[W] notification: Java threw in macapkOnNotificationAction\n");
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
        }
        [key release]; [text release]; [cold release];
    });
}

uint64_t Fnv1a(NSString* s) {
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char* p = (const unsigned char*)s.UTF8String; p && *p; ++p) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

NSString* Str(JNIEnv* env, jstring s) {
    if (!s) return nil;
    const char* c = env->GetStringUTFChars(s, nullptr);
    if (!c) return nil;
    NSString* out = [[NSString alloc] initWithUTF8String:c];
    env->ReleaseStringUTFChars(s, c);
    return [out autorelease];
}

}  // namespace
}  // namespace notification
}  // namespace macapk

@interface MacApkNotificationDelegate : NSObject <UNUserNotificationCenterDelegate>
@end

@implementation MacApkNotificationDelegate
// A banner is shown even while the app is frontmost: Android shows heads-up
// regardless of which app is in the foreground, and an app that posts while
// visible expects the user to see it.
- (void)userNotificationCenter:(UNUserNotificationCenter*)center
       willPresentNotification:(UNNotification*)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))done {
    done(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList |
         UNNotificationPresentationOptionSound);
}
- (void)userNotificationCenter:(UNUserNotificationCenter*)center
didReceiveNotificationResponse:(UNNotificationResponse*)response
         withCompletionHandler:(void (^)(void))done {
    NSString* key = [response.notification.request.identifier copy];
    id pl = response.notification.request.content.userInfo[@"macapk.pi"];
    NSString* payload = [pl isKindOfClass:[NSString class]] ? [pl copy] : nil;
    if ([response.actionIdentifier isEqualToString:UNNotificationDefaultActionIdentifier]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                [NSApp activateIgnoringOtherApps:YES];
                macapk::notification::HandleClick(key, payload);
            }
            [key release];
            [payload release];
        });
    } else if (macapk::notification::ActionsEnabled() &&
               [response.actionIdentifier hasPrefix:@"macapk.a"]) {
        int idx = [[response.actionIdentifier substringFromIndex:8] intValue];
        NSString* text = [response isKindOfClass:[UNTextInputNotificationResponse class]]
            ? [[(UNTextInputNotificationResponse*)response userText] copy] : nil;
        id acts = response.notification.request.content.userInfo[@"macapk.act"];
        NSString* cold = nil;
        if ([acts isKindOfClass:[NSArray class]] && idx >= 0 && (NSUInteger)idx < [acts count]) {
            id v = acts[idx];
            if ([v isKindOfClass:[NSString class]] && [v length] > 0) cold = [v copy];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                macapk::notification::HandleAction(key, idx, text, cold);
            }
            [key release]; [payload release]; [text release]; [cold release];
        });
    } else {
        [key release];
        [payload release];
    }
    done();
}
@end

namespace macapk {
namespace notification {
namespace {

MacApkNotificationDelegate* g_delegate = nil;   // main queue only

void EnsureDelegateOnMain() {
    if (g_delegate || !HaveBundle()) return;
    g_delegate = [[MacApkNotificationDelegate alloc] init];
    [UNUserNotificationCenter currentNotificationCenter].delegate = g_delegate;
}

void EnsureAuthOnMain() {
    if (g_asked || !HaveBundle()) return;
    g_asked = true;
    [[UNUserNotificationCenter currentNotificationCenter]
        requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound |
                                         UNAuthorizationOptionBadge)
                      completionHandler:^(BOOL granted, NSError* err) {
        g_auth = granted ? 1 : 2;
        if (!granted)
            std::fprintf(stderr, "[I] notification: authorization denied%s%s\n",
                         err ? ": " : "", err ? err.localizedDescription.UTF8String : "");
    }];
}

// Java String[] -> NSArray of NSString (NSNull for a null element); autoreleased.
NSArray* StrArray(JNIEnv* env, jobjectArray a) {
    if (!a) return nil;
    jsize n = env->GetArrayLength(a);
    NSMutableArray* out = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (jsize i = 0; i < n; i++) {
        jstring js = (jstring)env->GetObjectArrayElement(a, i);
        NSString* v = Str(env, js);
        [out addObject:v ? v : (id)[NSNull null]];
        if (js) env->DeleteLocalRef(js);
    }
    return out;
}

// Categories are per-app and setNotificationCategories REPLACES the set, so the
// set is kept cumulative (union) -- an older delivered banner keeps its buttons.
// First use in a run merges what the system already holds, so a relaunch does not
// drop the categories of notifications still in Notification Center.
NSMutableSet* g_cats = nil;      // main queue only
bool g_cats_loaded = false;

void WithCategories(void (^then)(void)) {
    if (g_cats_loaded) { then(); return; }
    void (^h)(void) = [then copy];
    [[UNUserNotificationCenter currentNotificationCenter]
        getNotificationCategoriesWithCompletionHandler:^(NSSet<UNNotificationCategory*>* existing) {
        [existing retain];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!g_cats) g_cats = [[NSMutableSet alloc] init];
            [g_cats unionSet:existing];
            [existing release];
            g_cats_loaded = true;
            h();
            [h release];
        });
    }];
}

NSString* CategoryFor(NSArray* titles, NSArray* inputs) {
    NSMutableString* sig = [NSMutableString string];
    for (NSUInteger i = 0; i < titles.count && i < 3; i++) {
        id in = i < inputs.count ? inputs[i] : [NSNull null];
        [sig appendFormat:@"%lu\x1f%@\x1f%@\x1e", (unsigned long)i, titles[i],
            [in isKindOfClass:[NSString class]] ? in : @""];
    }
    NSString* cid = [NSString stringWithFormat:@"macapk.cat.%016llx", (unsigned long long)Fnv1a(sig)];
    for (UNNotificationCategory* c in g_cats)
        if ([c.identifier isEqualToString:cid]) return cid;
    NSMutableArray* acts = [NSMutableArray array];
    for (NSUInteger i = 0; i < titles.count && i < 3; i++) {
        if (![titles[i] isKindOfClass:[NSString class]]) continue;   // action with no PendingIntent
        NSString* ident = [NSString stringWithFormat:@"macapk.a%lu", (unsigned long)i];
        id in = i < inputs.count ? inputs[i] : [NSNull null];
        if ([in isKindOfClass:[NSString class]]) {
            [acts addObject:[UNTextInputNotificationAction actionWithIdentifier:ident title:titles[i]
                options:UNNotificationActionOptionNone textInputButtonTitle:titles[i]
                textInputPlaceholder:in]];
        } else {
            [acts addObject:[UNNotificationAction actionWithIdentifier:ident title:titles[i]
                options:UNNotificationActionOptionNone]];
        }
    }
    [g_cats addObject:[UNNotificationCategory categoryWithIdentifier:cid actions:acts
        intentIdentifiers:@[] options:UNNotificationCategoryOptionNone]];
    [[UNUserNotificationCenter currentNotificationCenter] setNotificationCategories:g_cats];
    return cid;
}

void JNICALL Notif_nativePost(JNIEnv* env, jclass, jstring key, jstring title, jstring text,
                              jstring subtitle, jbyteArray png, jboolean silent, jstring cold,
                              jobjectArray actionTitles, jobjectArray actionInputs,
                              jobjectArray actionPayloads) {
    NSString* k = [Str(env, key) retain];
    NSString* t = [Str(env, title) retain];
    NSString* x = [Str(env, text) retain];
    NSString* s = [Str(env, subtitle) retain];
    NSString* cp = [Str(env, cold) retain];
    NSData* icon = nil;
    if (png) {
        jsize n = env->GetArrayLength(png);
        if (n > 0) {
            jbyte* b = env->GetByteArrayElements(png, nullptr);
            if (b) {
                icon = [[NSData alloc] initWithBytes:b length:(NSUInteger)n];
                env->ReleaseByteArrayElements(png, b, JNI_ABORT);
            }
        }
    }
    const bool quiet = silent == JNI_TRUE;
    NSArray* aTitles = ActionsEnabled() ? StrArray(env, actionTitles) : nil;
    NSArray* aInputs = StrArray(env, actionInputs);
    NSArray* aPayloads = StrArray(env, actionPayloads);
    [aTitles retain]; [aInputs retain]; [aPayloads retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            if (HaveBundle() && k) {
                EnsureDelegateOnMain();
                EnsureAuthOnMain();
                UNMutableNotificationContent* c = [[[UNMutableNotificationContent alloc] init] autorelease];
                if (t) c.title = t;
                if (s) c.subtitle = s;
                if (x) c.body = x;
                // Serialized contentIntent, so a click after the process exited
                // (macOS relaunches the app) can still be fired; see HandleClick.
                NSMutableDictionary* ui = [NSMutableDictionary dictionary];
                if (cp) ui[@"macapk.pi"] = cp;
                // Per-action serialized PendingIntent (+RemoteInputs) for the same
                // cold-start case; "" where an action has none.
                const bool haveActs = aTitles.count > 0;
                if (haveActs) {
                    NSMutableArray* pl = [NSMutableArray array];
                    for (NSUInteger i = 0; i < aTitles.count; i++) {
                        id v = i < aPayloads.count ? aPayloads[i] : nil;
                        [pl addObject:[v isKindOfClass:[NSString class]] ? v : @""];
                    }
                    ui[@"macapk.act"] = pl;
                }
                if (ui.count) c.userInfo = ui;
                if (!quiet) c.sound = [UNNotificationSound defaultSound];
                if (icon) {
                    // The attachment's file is moved into the data store by the
                    // system, so a unique temp name per post is enough.
                    NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"macapk-notif-%@.png", [[NSUUID UUID] UUIDString]]];
                    if ([icon writeToFile:path atomically:YES]) {
                        NSError* e = nil;
                        UNNotificationAttachment* a = [UNNotificationAttachment
                            attachmentWithIdentifier:@"icon" URL:[NSURL fileURLWithPath:path]
                                             options:nil error:&e];
                        if (a) c.attachments = @[a];
                    }
                }
                // Same identifier replaces the delivered banner in place.
                void (^submit)(void) = ^{
                    if (haveActs) c.categoryIdentifier = CategoryFor(aTitles, aInputs);
                    UNNotificationRequest* r = [UNNotificationRequest requestWithIdentifier:k
                                                                                    content:c trigger:nil];
                    [[UNUserNotificationCenter currentNotificationCenter]
                        addNotificationRequest:r withCompletionHandler:^(NSError* err) {
                        if (err) std::fprintf(stderr, "[W] notification: post failed: %s\n",
                                              err.localizedDescription.UTF8String);
                    }];
                };
                if (haveActs) WithCategories(submit); else submit();
            }
        }
        [k release]; [t release]; [x release]; [s release]; [cp release]; [icon release];
        [aTitles release]; [aInputs release]; [aPayloads release];
    });
}

void JNICALL Notif_nativeCancel(JNIEnv* env, jclass, jstring key) {
    NSString* k = [Str(env, key) retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (HaveBundle() && k) {
            UNUserNotificationCenter* uc = [UNUserNotificationCenter currentNotificationCenter];
            [uc removeDeliveredNotificationsWithIdentifiers:@[k]];
            [uc removePendingNotificationRequestsWithIdentifiers:@[k]];
        }
        [k release];
    });
}

void JNICALL Notif_nativeCancelAll(JNIEnv*, jclass) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!HaveBundle()) return;
        UNUserNotificationCenter* uc = [UNUserNotificationCenter currentNotificationCenter];
        [uc removeAllDeliveredNotifications];
        [uc removeAllPendingNotificationRequests];
    });
}

void JNICALL Notif_nativeBootReady(JNIEnv*, jclass) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            g_boot_ready = true;
            NSArray* items = g_cold_stash;
            g_cold_stash = nil;
            for (NSArray* it in items) SendColdClick(it[0], it[1]);
            [items release];
        }
    });
}

jboolean JNICALL Notif_nativeIsDenied(JNIEnv*, jclass) {
    return g_auth.load() == 2 ? JNI_TRUE : JNI_FALSE;
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativePost"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[BZLjava/lang/String;"
                       "[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V"),
     reinterpret_cast<void*>(Notif_nativePost)},
    {const_cast<char*>("nativeCancel"), const_cast<char*>("(Ljava/lang/String;)V"),
     reinterpret_cast<void*>(Notif_nativeCancel)},
    {const_cast<char*>("nativeCancelAll"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(Notif_nativeCancelAll)},
    {const_cast<char*>("nativeBootReady"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(Notif_nativeBootReady)},
    {const_cast<char*>("nativeIsDenied"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(Notif_nativeIsDenied)},
};

}  // namespace

// Soft-fails like the Now Playing registration: a framework jar older than this
// binary simply has no notification bridge this run. The delegate is installed
// here (not on first post) so a click that launched the app is delivered.
void RegisterNotificationBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/app/NotificationManager");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] notification: no NotificationManager in this framework jar\n");
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] notification: RegisterNatives(NotificationManager) failed; "
                     "notifications are not bridged this run\n");
        env->DeleteLocalRef(cls);
        return;
    }
    g_on_click = env->GetStaticMethodID(cls, "macapkOnNotificationClicked", "(Ljava/lang/String;)V");
    if (!g_on_click) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] notification: macapkOnNotificationClicked missing; clicks only focus the app\n");
    }
    g_on_cold_click = env->GetStaticMethodID(cls, "macapkOnColdNotificationClicked",
                                             "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!g_on_cold_click) env->ExceptionClear();
    g_on_action = env->GetStaticMethodID(cls, "macapkOnNotificationAction",
                                         "(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V");
    if (!g_on_action) env->ExceptionClear();
    env->GetJavaVM(&g_vm);
    g_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
    if (std::getenv("MACAPK_NOTIFICATIONS") && std::strcmp(std::getenv("MACAPK_NOTIFICATIONS"), "0") == 0)
        return;
    dispatch_async(dispatch_get_main_queue(), ^{ @autoreleasepool { EnsureDelegateOnMain(); } });
}

}  // namespace notification
}  // namespace macapk
