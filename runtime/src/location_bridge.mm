// Mac Location Services -> android.location: the native half of
// com.macapk.loader.LocationBridge (MACAPK_LOCATION_HOST, default ON).
//
// Rung 1 of the decision ladder. On Android, LocationManagerService fans fixes
// out from the GNSS HAL and the network location provider; on macOS
// CoreLocation already fuses every source the Mac has (Wi-Fi positioning, and
// GNSS when a device supplies it) behind one CLLocationManager. So we route to
// it and hand Java each CLLocation as a neutral record. The Java side
// (android.location.LocationManager) does what LocationProviderManager does with
// it: per-registration interval / displacement filtering, maxUpdates, the
// getCurrentLocation 30 s age and timeout rules, and permission gating.
//
// PERMISSION. macOS asks the user through TCC, and that prompt IS the Android
// runtime-permission dialog for ACCESS_FINE/COARSE_LOCATION here
// (SpecialAccessHandler calls requestAuth when the app calls
// requestPermissions). TCC refuses outright, without prompting, when the
// responsible bundle has no NSLocationWhenInUseUsageDescription (every
// generated bundle carries one, launcher/BundleGenerator.swift), and under the
// hardened runtime it also needs com.apple.security.personal-information.location
// (runtime/scripts/jit-entitlements.plist). Nothing here requests authorization
// on its own except nativeStart, which only Java calls once the app holds the
// Android permission; reading the status never prompts.
//
// THREADING. CLLocationManager delivers delegate callbacks on the run loop of
// the thread that created it, so the one manager lives on the main queue (the
// AppKit thread, which runs the Cocoa run loop for the whole process) and every
// mutation is dispatch_async'd there. NEVER dispatch_sync: a Java thread
// blocking on the main queue deadlocks the moment the main thread is itself
// waiting on Java. Status reads come from an atomic the delegate keeps fresh,
// seeded once by a probe instance (reading authorizationStatus on a fresh
// manager is a plain query; it neither prompts nor needs a run loop).
//
// THE HELPER (2026-10-06). macOS shows its location prompt only to a process
// that IS an app bundle's executable; the runtime is not one (the stub execs
// the shared binary through a symlink), so CoreLocationAgent logged "client
// bundle is NULL. Skip showing AuthPrompt" for every request and the app
// waited on an answer that never came. So when "Mac.apk Location.app"
// (launcher/LocationHelperMain.swift, in Mac.apk.app/Contents/Helpers) can be
// found, CoreLocation runs THERE: this file spawns it as a child, speaks its
// line protocol over a pipe pair, and turns its lines into the same Java
// callbacks. Without the helper (an old Mac.apk.app, a dev tree) the
// in-process CLLocationManager below is the fallback, which can read state and
// fixes for an already-authorized identity but can never get a prompt shown
// (nativeCanPrompt says so, and Java does not wait on one).
//
// Built with ARC (CMakeLists.txt): the delegate and blocks own the manager.

#import <CoreLocation/CoreLocation.h>
#import <Foundation/Foundation.h>
#include <jni.h>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace macapk {
namespace location {

namespace {

JavaVM*   g_vm = nullptr;
jclass    g_cls = nullptr;          // global ref to com.macapk.loader.LocationBridge
jmethodID g_on_location = nullptr;
jmethodID g_on_auth = nullptr;

// CLAuthorizationStatus, or -1 = not read yet. Written by the delegate on the
// main thread and by the one-time probe; read from any Java thread.
std::atomic<int>  g_status{-1};
std::atomic<bool> g_reduced{false};

CLLocationManager* g_mgr = nil;     // main-queue only
id                 g_delegate = nil;
bool               g_updating = false;  // main-queue only

bool TraceOn() {
    static int on = -1;
    if (on < 0) {
        const char* e = std::getenv("MACAPK_TRACE_LOCATION");
        on = (e && *e && std::strcmp(e, "0") != 0) ? 1 : 0;
    }
    return on == 1;
}

JNIEnv* Env() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21);
    // As a DAEMON: the helper's reader thread must never keep the JVM alive.
    if (r == JNI_EDETACHED &&
        g_vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) {
        return nullptr;
    }
    return env;
}

void ClearException(JNIEnv* env, const char* what) {
    if (env->ExceptionCheck()) {
        std::fprintf(stderr, "[W] location: Java threw in %s\n", what);
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void Record(CLLocationManager* m) {
    g_status.store((int)m.authorizationStatus);
    g_reduced.store(m.accuracyAuthorization == CLAccuracyAuthorizationReducedAccuracy);
}

void SeedStatus() {
    if (g_status.load() >= 0) return;
    @autoreleasepool {
        CLLocationManager* probe = [[CLLocationManager alloc] init];
        Record(probe);
    }
}

// The neutral record Java turns into an android.location.Location. CoreLocation
// marks an invalid component with a negative accuracy (or a negative value for
// speed / course), per the field docs in
// _LocationEssentials.framework/Headers/CLLocationEssentials.h; Java maps each
// negative to "has no X" rather than inventing a value.
void Deliver(CLLocation* loc) {
    if (!loc || loc.horizontalAccuracy < 0) return;   // lateral fix invalid
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_location) return;
    env->CallStaticVoidMethod(g_cls, g_on_location,
        (jdouble)loc.coordinate.latitude, (jdouble)loc.coordinate.longitude,
        (jdouble)loc.ellipsoidalAltitude, (jdouble)loc.altitude,
        (jdouble)loc.horizontalAccuracy, (jdouble)loc.verticalAccuracy,
        (jdouble)loc.speed, (jdouble)loc.speedAccuracy,
        (jdouble)loc.course, (jdouble)loc.courseAccuracy,
        (jlong)llround(loc.timestamp.timeIntervalSince1970 * 1000.0),
        (jboolean)(loc.sourceInformation && loc.sourceInformation.isSimulatedBySoftware));
    ClearException(env, "onNativeLocation");
}

void ReportAuth() {
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_auth) return;
    env->CallStaticVoidMethod(g_cls, g_on_auth, (jint)g_status.load(),
                              (jboolean)g_reduced.load());
    ClearException(env, "onNativeAuthorization");
}

// ---- the Mac.apk Location helper ------------------------------------------

std::mutex              g_hmu;          // guards everything below
std::condition_variable g_hcv;
std::string             g_helper;       // executable path, from Java (nativeSetHelper)
pid_t                   g_hpid = 0;
int                     g_hin = -1;     // we write commands here
int                     g_hfails = 0;   // spawns that died before saying anything
bool                    g_cached_ready = false;
std::vector<double>     g_cached;       // empty = "cached none"

constexpr int kMaxHelperFails = 3;

bool HelperConfigured() {
    std::lock_guard<std::mutex> lk(g_hmu);
    return !g_helper.empty() && g_hfails < kMaxHelperFails;
}

// The 12 fields of a "fix" / "cached" line, in onNativeLocation's order.
bool ParseFields(const char* p, double out[12]) {
    for (int i = 0; i < 12; i++) {
        char* end = nullptr;
        out[i] = std::strtod(p, &end);
        if (end == p) return false;
        p = end;
    }
    return true;
}

void DeliverFields(const double v[12]) {
    if (v[4] < 0) return;   // horizontalAccuracy < 0: no lateral fix
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_location) return;
    env->CallStaticVoidMethod(g_cls, g_on_location,
        (jdouble)v[0], (jdouble)v[1], (jdouble)v[2], (jdouble)v[3], (jdouble)v[4],
        (jdouble)v[5], (jdouble)v[6], (jdouble)v[7], (jdouble)v[8], (jdouble)v[9],
        (jlong)v[10], (jboolean)(v[11] != 0));
    ClearException(env, "onNativeLocation");
}

void HelperLine(const std::string& line, bool& spoke) {
    if (TraceOn()) std::fprintf(stderr, "[location] helper: %s\n", line.c_str());
    if (line.compare(0, 5, "auth ") == 0) {
        int st = -1, red = 0;
        if (std::sscanf(line.c_str() + 5, "%d %d", &st, &red) >= 1 && st >= 0) {
            spoke = true;
            g_status.store(st);
            g_reduced.store(red != 0);
            { std::lock_guard<std::mutex> lk(g_hmu); g_hfails = 0; }
            g_hcv.notify_all();
            ReportAuth();
        }
    } else if (line.compare(0, 4, "fix ") == 0) {
        double v[12];
        if (ParseFields(line.c_str() + 4, v)) DeliverFields(v);
    } else if (line.compare(0, 7, "cached ") == 0) {
        double v[12];
        std::lock_guard<std::mutex> lk(g_hmu);
        g_cached.clear();
        if (ParseFields(line.c_str() + 7, v)) g_cached.assign(v, v + 12);
        g_cached_ready = true;
        g_hcv.notify_all();
    } else if (line.compare(0, 6, "error ") == 0) {
        // kCLErrorLocationUnknown (0) is transient; CoreLocation keeps trying.
        if (TraceOn() || line != "error 0")
            std::fprintf(stderr, "[location] CoreLocation (helper) %s\n", line.c_str());
    }
}

void HelperReader(int fd, pid_t pid) {
    std::string buf;
    char chunk[1024];
    bool spoke = false;
    for (;;) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        buf.append(chunk, (size_t)n);
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            HelperLine(buf.substr(0, nl), spoke);
            buf.erase(0, nl + 1);
        }
    }
    close(fd);
    int status = 0;
    waitpid(pid, &status, 0);
    std::lock_guard<std::mutex> lk(g_hmu);
    if (g_hpid == pid) {
        g_hpid = 0;
        if (g_hin >= 0) { close(g_hin); g_hin = -1; }
    }
    if (!spoke) g_hfails++;
    std::fprintf(stderr, "[location] Mac.apk Location helper exited (status %d)%s\n", status,
                 g_hfails >= kMaxHelperFails ? "; not restarting it" : "");
    g_hcv.notify_all();
}

// Start the helper if it is not running. Caller holds g_hmu.
bool HelperUpLocked() {
    if (g_hpid > 0) return true;
    if (g_helper.empty() || g_hfails >= kMaxHelperFails) return false;
    int in[2], out[2];
    if (pipe(in) != 0) return false;
    if (pipe(out) != 0) { close(in[0]); close(in[1]); return false; }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawn_file_actions_addinherit_np(&fa, 2);   // its stderr is the app's run log
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    // Only stdio crosses: no run lock, no guest fds, no sockets.
    posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT);
    char* argv[] = { const_cast<char*>(g_helper.c_str()), nullptr };
    pid_t pid = 0;
    int rc = posix_spawn(&pid, g_helper.c_str(), &fa, &at, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    close(in[0]);
    close(out[1]);
    if (rc != 0) {
        close(in[1]);
        close(out[0]);
        g_hfails = kMaxHelperFails;   // not there / not runnable: do not retry
        std::fprintf(stderr, "[location] cannot start %s: %s\n", g_helper.c_str(), strerror(rc));
        return false;
    }
    fcntl(in[1], F_SETNOSIGPIPE, 1);   // a helper that died must not SIGPIPE the runtime
    fcntl(in[1], F_SETFD, FD_CLOEXEC);
    fcntl(out[0], F_SETFD, FD_CLOEXEC);
    g_hpid = pid;
    g_hin = in[1];
    std::thread(HelperReader, out[0], pid).detach();
    if (TraceOn()) std::fprintf(stderr, "[location] started Mac.apk Location helper pid %d\n", pid);
    return true;
}

bool HelperSend(const char* line) {
    std::lock_guard<std::mutex> lk(g_hmu);
    if (!HelperUpLocked()) return false;
    std::string l = std::string(line) + "\n";
    return write(g_hin, l.data(), l.size()) == (ssize_t)l.size();
}

// The helper reports its authorization as soon as it starts; wait briefly for
// that first answer.
bool HelperStatus() {
    std::unique_lock<std::mutex> lk(g_hmu);
    if (!HelperUpLocked()) return false;
    if (g_status.load() < 0) {
        g_hcv.wait_for(lk, std::chrono::seconds(3),
                       [] { return g_status.load() >= 0 || g_hpid == 0; });
    }
    return g_status.load() >= 0;
}

}  // namespace
}  // namespace location
}  // namespace macapk

using namespace macapk::location;

@interface MacApkLocationDelegate : NSObject <CLLocationManagerDelegate>
@end

@implementation MacApkLocationDelegate
- (void)locationManagerDidChangeAuthorization:(CLLocationManager*)manager {
    Record(manager);
    if (TraceOn())
        std::fprintf(stderr, "[location] authorization status=%d reduced=%d\n",
                     g_status.load(), (int)g_reduced.load());
    ReportAuth();
}
- (void)locationManager:(CLLocationManager*)manager didUpdateLocations:(NSArray<CLLocation*>*)locations {
    (void)manager;
    for (CLLocation* l in locations) Deliver(l);
}
- (void)locationManager:(CLLocationManager*)manager didFailWithError:(NSError*)error {
    (void)manager;
    // kCLErrorLocationUnknown is transient ("unable to obtain a location right
    // now; keep trying"): CoreLocation keeps the session running, so do we.
    // kCLErrorDenied arrives together with an authorization change, which is
    // the event Java acts on.
    if (TraceOn() || error.code != kCLErrorLocationUnknown)
        std::fprintf(stderr, "[location] CoreLocation error %ld (%s)\n", (long)error.code,
                     error.localizedDescription.UTF8String);
}
@end

namespace macapk {
namespace location {
namespace {

// Main queue only.
CLLocationManager* Manager() {
    if (!g_mgr) {
        g_mgr = [[CLLocationManager alloc] init];
        g_delegate = [[MacApkLocationDelegate alloc] init];
        g_mgr.delegate = g_delegate;   // CoreLocation reports the initial status at once
        Record(g_mgr);
    }
    return g_mgr;
}

// Answers "are the natives registered" without touching CoreLocation: even a
// probe CLLocationManager registers this process with locationd (it then lists
// Mac.apk under Location Services), which a mere permission check must not do.
jboolean JNICALL NativeBound(JNIEnv*, jclass) { return JNI_TRUE; }

void JNICALL NativeSetHelper(JNIEnv* env, jclass, jstring path) {
    std::lock_guard<std::mutex> lk(g_hmu);
    g_helper.clear();
    if (!path) return;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p) { g_helper = p; env->ReleaseStringUTFChars(path, p); }
}

// Can a macOS prompt actually appear? Only through the helper.
jboolean JNICALL NativeCanPrompt(JNIEnv*, jclass) {
    return (jboolean)HelperConfigured();
}

jint JNICALL NativeAuthStatus(JNIEnv*, jclass) {
    if (HelperConfigured()) {
        if (HelperStatus()) return (jint)g_status.load();
    }
    SeedStatus();
    return (jint)g_status.load();
}

jboolean JNICALL NativeReducedAccuracy(JNIEnv* env, jclass cls) {
    NativeAuthStatus(env, cls);
    return (jboolean)g_reduced.load();
}

// Apple: "If NO, and you proceed to call other CoreLocation API, user will be
// prompted with the warning dialog" (CLLocationManager.h). A class query that
// may touch locationd, so callers do not make it on the main thread.
jboolean JNICALL NativeServicesEnabled(JNIEnv*, jclass) {
    return (jboolean)[CLLocationManager locationServicesEnabled];
}

// CoreLocation's cached fix for this app (CLLocationManager.location: "the most
// recently retrieved user location", nil if none), read on the CALLING thread
// from a probe instance: a property read, no session, no prompt, no run loop
// needed. Backs getLastKnownLocation before this process has run a session,
// which is how Android answers it too (the platform keeps the last fix across
// apps). Same field order as onNativeLocation; null when there is none.
jdoubleArray JNICALL NativeCachedFix(JNIEnv* env, jclass) {
    if (HelperConfigured()) {
        {
            std::lock_guard<std::mutex> lk(g_hmu);
            g_cached_ready = false;
        }
        if (HelperSend("cached")) {
            std::unique_lock<std::mutex> lk(g_hmu);
            g_hcv.wait_for(lk, std::chrono::seconds(2), [] { return g_cached_ready || g_hpid == 0; });
            if (!g_cached_ready || g_cached.size() != 12 || g_cached[4] < 0) return nullptr;
            jdoubleArray out = env->NewDoubleArray(12);
            if (out) env->SetDoubleArrayRegion(out, 0, 12, g_cached.data());
            return out;
        }
    }
    @autoreleasepool {
        CLLocationManager* probe = [[CLLocationManager alloc] init];
        CLLocation* loc = probe.location;
        if (!loc || loc.horizontalAccuracy < 0) return nullptr;
        const jdouble v[12] = {
            loc.coordinate.latitude, loc.coordinate.longitude,
            loc.ellipsoidalAltitude, loc.altitude,
            loc.horizontalAccuracy, loc.verticalAccuracy,
            loc.speed, loc.speedAccuracy, loc.course, loc.courseAccuracy,
            (jdouble)llround(loc.timestamp.timeIntervalSince1970 * 1000.0),
            (loc.sourceInformation && loc.sourceInformation.isSimulatedBySoftware) ? 1.0 : 0.0,
        };
        jdoubleArray out = env->NewDoubleArray(12);
        if (out) env->SetDoubleArrayRegion(out, 0, 12, v);
        return out;
    }
}

void JNICALL NativeRequestAuth(JNIEnv*, jclass) {
    if (HelperConfigured() && HelperSend("auth")) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        CLLocationManager* m = Manager();
        if (m.authorizationStatus == kCLAuthorizationStatusNotDetermined) {
            if (TraceOn()) std::fprintf(stderr, "[location] requesting authorization\n");
            [m requestWhenInUseAuthorization];
        } else {
            // Already decided: CoreLocation will not prompt again, so answer
            // the waiter from the state we have.
            Record(m);
            ReportAuth();
        }
    });
}

void JNICALL NativeStart(JNIEnv*, jclass, jboolean reduced) {
    const bool r = reduced == JNI_TRUE;
    if (HelperConfigured() && HelperSend(r ? "start 1" : "start 0")) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        CLLocationManager* m = Manager();
        // An app holding only ACCESS_COARSE_LOCATION gets an approximate fix
        // on Android (LocationFudger); CoreLocation's reduced-accuracy mode is
        // the host's own version of exactly that.
        m.desiredAccuracy = r ? kCLLocationAccuracyReduced : kCLLocationAccuracyBest;
        m.distanceFilter = kCLDistanceFilterNone;   // Java applies minDistance per registration
        if (m.authorizationStatus == kCLAuthorizationStatusNotDetermined)
            [m requestWhenInUseAuthorization];
        if (!g_updating) {
            g_updating = true;
            if (TraceOn()) std::fprintf(stderr, "[location] startUpdatingLocation (reduced=%d)\n", r);
            [m startUpdatingLocation];
        }
        // The cached fix, if any, so a fresh session is not blind until the
        // next Wi-Fi scan; its timestamp is its real age, Java ages it. Not in
        // reduced mode: the cache may hold a precise fix from before.
        if (!r && m.location) Deliver(m.location);
    });
}

void JNICALL NativeStop(JNIEnv*, jclass) {
    if (HelperConfigured()) {
        std::lock_guard<std::mutex> lk(g_hmu);
        if (g_hpid > 0 && g_hin >= 0) {
            (void)!write(g_hin, "stop\n", 5);
            return;
        }
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_mgr && g_updating) {
            g_updating = false;
            if (TraceOn()) std::fprintf(stderr, "[location] stopUpdatingLocation\n");
            [g_mgr stopUpdatingLocation];
        }
    });
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeBound"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&NativeBound)},
    {const_cast<char*>("nativeSetHelper"), const_cast<char*>("(Ljava/lang/String;)V"),
     reinterpret_cast<void*>(&NativeSetHelper)},
    {const_cast<char*>("nativeCanPrompt"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&NativeCanPrompt)},
    {const_cast<char*>("nativeAuthStatus"), const_cast<char*>("()I"),
     reinterpret_cast<void*>(&NativeAuthStatus)},
    {const_cast<char*>("nativeReducedAccuracy"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&NativeReducedAccuracy)},
    {const_cast<char*>("nativeServicesEnabled"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&NativeServicesEnabled)},
    {const_cast<char*>("nativeCachedFix"), const_cast<char*>("()[D"),
     reinterpret_cast<void*>(&NativeCachedFix)},
    {const_cast<char*>("nativeRequestAuth"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(&NativeRequestAuth)},
    {const_cast<char*>("nativeStart"), const_cast<char*>("(Z)V"),
     reinterpret_cast<void*>(&NativeStart)},
    {const_cast<char*>("nativeStop"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(&NativeStop)},
};

}  // namespace

void RegisterLocationBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/LocationBridge");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(LocationBridge) failed\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(LocationBridge) failed\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        return;
    }
    g_on_location = env->GetStaticMethodID(cls, "onNativeLocation", "(DDDDDDDDDDJZ)V");
    g_on_auth = env->GetStaticMethodID(cls, "onNativeAuthorization", "(IZ)V");
    if (!g_on_location || !g_on_auth) {
        std::fprintf(stderr, "[macapk] LocationBridge callbacks missing; location not bridged\n");
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        return;
    }
    env->GetJavaVM(&g_vm);
    g_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
}

}  // namespace location
}  // namespace macapk
