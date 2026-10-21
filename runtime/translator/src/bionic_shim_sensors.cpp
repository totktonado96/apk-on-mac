// bionic_shim_sensors.cpp -- the NDK sensor API (libandroid ASensorManager_* /
// ASensorEventQueue_* / ASensor_*) backed by Mac.apk's Java SensorManager.
//
// WHY. A native game reads motion through this API, not through
// android.hardware.SensorManager: Unity's Input.acceleration / gyro, Gameloft's
// engines, any NativeActivity. Until 2026-10-05 every entry point here was a stub
// (an empty sensor list, a queue that never had events), so for a native game the
// device simply had no accelerometer -- and Controls -> Tilt Control, which
// drives the Java sensors, could not steer it. On Android both APIs are views of
// ONE sensor service; here the Java SensorManager is that service, and this file
// is the NDK view of it: it mirrors the Java catalog (same types, names, ranges,
// delays) and asks Java for each event's values (SensorManager.macapkNativeSample
// -> makeEvent), so a native reader sees exactly what a Java listener sees: the
// at-rest pose, or the Tilt Control pose while it is on.
//
// SHAPE (AOSP frameworks/base native/android/sensor.cpp + frameworks/native
// libs/sensor/SensorEventQueue.cpp, android14-release):
//  - ASensorManager_createEventQueue(mgr, looper, ident, callback, data) needs a
//    looper, and adds the queue's receive fd to it with ALOOPER_EVENT_INPUT, the
//    ident and callback the caller gave (sensor.cpp:114-132). Ours is a
//    non-blocking pipe; a per-queue ticker thread writes a byte whenever an
//    enabled sensor's sampling period elapses, which is what makes the looper
//    wake (ALooper_pollAll returns `ident`, or the callback runs) like the
//    BitTube from the sensor service does.
//  - enableSensor uses SENSOR_DELAY_NORMAL = 200000 us (SensorEventQueue.h:66,
//    SensorEventQueue.cpp:125-127); registerSensor / setEventRate take the
//    caller's period. The service clamps a period to the sensor's minDelay.
//  - getEvents(queue, events, count) returns up to count ASensorEvents: one per
//    enabled sensor whose period has elapsed (continuous reporting), values and
//    timestamp from Java. hasEvents polls the fd with no timeout (sensor.cpp:262).
//  - ASensorEvent is the sensor.h layout: version = sizeof(ASensorEvent) = 104,
//    sensor = the handle, type, reserved0, timestamp, data[16] (ASensorVector:
//    v[3] + int8 status), flags, reserved1[3]. 3-axis sensors carry
//    status = ASENSOR_STATUS_ACCURACY_HIGH (3).
//
// Java reached through a JavaVM captured on the main thread at boot
// (__macapk_register_sensor_natives, from __macapk_init_assets), with global refs,
// because a game's sensor thread is a native thread the class loader lookup from
// FindClass would not see the framework through reliably. Each call attaches the
// calling thread for its duration (the EnvGuard pattern of
// bionic_shim_nativeactivity.cpp).
//
// MACAPK_NDK_SENSORS=0 restores the old stubs' answers (no sensors, no events).
// Generic across every native app; no per-APK code.

#include <jni.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" {
int __macapk_arm64_ALooper_removeFd(void* looper, int fd);
int __macapk_looper_add_fd_plain(void* looper, int fd, int ident, int events,
                                 void* callback, void* data);
int __macapk_looper_fd_count(void* looper);
}

namespace {

// ---- AOSP sensor.h shapes ----------------------------------------------------
struct ASensorVector {
    float v[3];
    int8_t status;
    uint8_t reserved[3];
};
struct ASensorEvent {
    int32_t version;
    int32_t sensor;
    int32_t type;
    int32_t reserved0;
    int64_t timestamp;
    union {
        float data[16];
        uint64_t u64[8];
    };
    uint32_t flags;
    int32_t reserved1[3];
};
static_assert(sizeof(ASensorEvent) == 104, "ASensorEvent must match sensor.h");

constexpr int32_t kSensorDelayNormalUs = 200000;   // SensorEventQueue.h:66
constexpr int8_t kStatusAccuracyHigh = 3;           // ASENSOR_STATUS_ACCURACY_HIGH

bool Enabled() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_NDK_SENSORS");
        return !(e && e[0] == '0');
    }();
    return on;
}

// ---- Java -----------------------------------------------------------------
JavaVM*   g_vm = nullptr;
jclass    g_sm = nullptr;          // android.hardware.SensorManager (global ref)
jmethodID g_catalog = nullptr;     // static int[] macapkNativeCatalog()
jmethodID g_floats = nullptr;      // static float[] macapkNativeFloats(int)
jmethodID g_string = nullptr;      // static String macapkNativeString(int,int)
jmethodID g_sample = nullptr;      // static int macapkNativeSample(int,float[],long[])

struct EnvGuard {
    JNIEnv* env = nullptr;
    bool attached = false;
    EnvGuard() {
        if (!g_vm) return;
        jint rc = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
        if (rc == JNI_EDETACHED) {
            attached = g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK;
            if (!attached) env = nullptr;
        } else if (rc != JNI_OK) {
            env = nullptr;
        }
    }
    ~EnvGuard() { if (attached) g_vm->DetachCurrentThread(); }
};

// ---- the catalog (ASensor*) ------------------------------------------------
struct MacApkSensor {
    int handle;            // ASensor_getHandle / ASensorEvent.sensor
    int type;
    int min_delay_us;
    int reporting_mode;
    float max_range, resolution, power;
    std::string name, string_type;
};
std::mutex g_catalog_mu;
std::vector<MacApkSensor*> g_sensors;   // never freed: ASensor* lives as long as the process
bool g_catalog_loaded = false;

void LoadCatalogLocked() {
    if (g_catalog_loaded) return;
    g_catalog_loaded = true;
    if (!Enabled() || !g_sm) return;
    EnvGuard g;
    JNIEnv* env = g.env;
    if (!env) return;
    jintArray arr = static_cast<jintArray>(env->CallStaticObjectMethod(g_sm, g_catalog));
    if (env->ExceptionCheck() || !arr) { env->ExceptionClear(); return; }
    jsize n = env->GetArrayLength(arr) / 3;
    std::vector<jint> v(static_cast<size_t>(n) * 3);
    env->GetIntArrayRegion(arr, 0, n * 3, v.data());
    env->DeleteLocalRef(arr);
    for (jsize i = 0; i < n; i++) {
        auto* s = new MacApkSensor();
        s->handle = static_cast<int>(i) + 1;   // 0 is never a valid handle
        s->type = v[i * 3];
        s->min_delay_us = v[i * 3 + 1];
        s->reporting_mode = v[i * 3 + 2];
        jfloatArray fa = static_cast<jfloatArray>(env->CallStaticObjectMethod(g_sm, g_floats, i));
        if (!env->ExceptionCheck() && fa) {
            jfloat f[3] = {0, 0, 0};
            env->GetFloatArrayRegion(fa, 0, 3, f);
            s->max_range = f[0]; s->resolution = f[1]; s->power = f[2];
            env->DeleteLocalRef(fa);
        }
        env->ExceptionClear();
        for (int which = 0; which < 2; which++) {
            jstring js = static_cast<jstring>(env->CallStaticObjectMethod(g_sm, g_string, i, which));
            if (!env->ExceptionCheck() && js) {
                const char* c = env->GetStringUTFChars(js, nullptr);
                (which == 0 ? s->name : s->string_type) = c ? c : "";
                if (c) env->ReleaseStringUTFChars(js, c);
                env->DeleteLocalRef(js);
            }
            env->ExceptionClear();
        }
        g_sensors.push_back(s);
    }
    std::fprintf(stderr, "[ndk-sensors] catalog: %zu sensor(s) mirrored from SensorManager\n",
                 g_sensors.size());
}

const std::vector<MacApkSensor*>& Catalog() {
    std::lock_guard<std::mutex> lk(g_catalog_mu);
    LoadCatalogLocked();
    return g_sensors;
}

MacApkSensor* AsSensor(const void* p) {
    for (MacApkSensor* s : Catalog()) if (s == p) return s;
    return nullptr;
}

// ---- event queues ----------------------------------------------------------
struct Enabled_ {
    MacApkSensor* sensor;
    int64_t period_ns;
    int64_t next_due_ns;   // host steady clock
};
struct MacApkQueue {
    std::mutex mu;
    std::vector<Enabled_> enabled;
    void* looper = nullptr;
    int read_fd = -1, write_fd = -1;
    std::atomic<bool> stop{false};
    std::thread ticker;
    std::atomic<int> pending_bytes{0};
};
std::mutex g_queues_mu;
std::vector<MacApkQueue*> g_queues;

int64_t NowNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

MacApkQueue* AsQueue(void* p) {
    std::lock_guard<std::mutex> lk(g_queues_mu);
    for (MacApkQueue* q : g_queues) if (q == p) return q;
    return nullptr;
}

// Signal readiness: one byte in the pipe while any sensor is due. Kept to a
// single outstanding byte so a slow reader never fills the pipe.
void Signal(MacApkQueue* q) {
    int expected = 0;
    if (q->pending_bytes.compare_exchange_strong(expected, 1)) {
        char b = 1;
        if (::write(q->write_fd, &b, 1) != 1) q->pending_bytes.store(0);
    }
}

void Drain(MacApkQueue* q) {
    char buf[64];
    while (::read(q->read_fd, buf, sizeof buf) > 0) {}
    q->pending_bytes.store(0);
}

void TickerMain(MacApkQueue* q) {
    pthread_setname_np("macapk-sensor-tick");
    while (!q->stop.load()) {
        int64_t now = NowNs(), wait_ns = 50'000'000;   // idle re-check: 50 ms
        bool due = false;
        {
            std::lock_guard<std::mutex> lk(q->mu);
            for (const Enabled_& e : q->enabled) {
                int64_t d = e.next_due_ns - now;
                if (d <= 0) due = true;
                else if (d < wait_ns) wait_ns = d;
            }
        }
        if (due) { Signal(q); wait_ns = 2'000'000; }   // re-check soon; the reader advances next_due
        static const bool trace = [] {
            const char* e = std::getenv("MACAPK_NDK_SENSORS_TRACE");
            return e && e[0] == '1';
        }();
        static thread_local int64_t last = 0;
        if (trace && now - last > 5'000'000'000LL) {
            last = now;
            std::fprintf(stderr, "[ndk-sensors] tick: queue %p looper fds=%d unread=%d enabled=%zu\n",
                         static_cast<void*>(q), __macapk_looper_fd_count(q->looper),
                         q->pending_bytes.load(), q->enabled.size());
        }
        std::this_thread::sleep_for(std::chrono::nanoseconds(wait_ns));
    }
}

int64_t ClampPeriodNs(const MacApkSensor* s, int64_t period_us) {
    // The sensor service clamps a request to the sensor's fastest rate.
    if (period_us < s->min_delay_us) period_us = s->min_delay_us;
    if (period_us <= 0) period_us = s->min_delay_us > 0 ? s->min_delay_us : 10000;
    return period_us * 1000;
}

int EnableLocked(MacApkQueue* q, MacApkSensor* s, int64_t period_us) {
    int64_t period_ns = ClampPeriodNs(s, period_us);
    for (Enabled_& e : q->enabled) {
        if (e.sensor == s) { e.period_ns = period_ns; return 0; }
    }
    q->enabled.push_back(Enabled_{s, period_ns, NowNs()});   // first event right away
    return 0;
}

// One sample for sensor s from Java. Returns false if Java had no value.
bool Sample(JNIEnv* env, MacApkSensor* s, ASensorEvent* out, jfloatArray fa, jlongArray la) {
    jint n = env->CallStaticIntMethod(g_sm, g_sample, s->type, fa, la);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    if (n <= 0) return false;
    std::memset(out, 0, sizeof *out);
    out->version = static_cast<int32_t>(sizeof(ASensorEvent));
    out->sensor = s->handle;
    out->type = s->type;
    jlong ts = 0;
    env->GetLongArrayRegion(la, 0, 1, &ts);
    out->timestamp = ts;
    jfloat v[16] = {0};
    env->GetFloatArrayRegion(fa, 0, n > 16 ? 16 : n, v);
    for (int i = 0; i < n && i < 16; i++) out->data[i] = v[i];
    if (n == 3) reinterpret_cast<ASensorVector*>(out->data)->status = kStatusAccuracyHigh;
    return true;
}

}  // namespace

// Called from bionic_shim.cpp's __macapk_init_assets on the main thread.
extern "C" void __macapk_register_sensor_natives(JavaVM* vm) {
    g_vm = vm;
    JNIEnv* env = nullptr;
    if (!vm || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) return;
    jclass c = env->FindClass("android/hardware/SensorManager");
    if (!c) { env->ExceptionClear(); std::fprintf(stderr, "[ndk-sensors] SensorManager not found\n"); return; }
    g_catalog = env->GetStaticMethodID(c, "macapkNativeCatalog", "()[I");
    g_floats = env->GetStaticMethodID(c, "macapkNativeFloats", "(I)[F");
    g_string = env->GetStaticMethodID(c, "macapkNativeString", "(II)Ljava/lang/String;");
    g_sample = env->GetStaticMethodID(c, "macapkNativeSample", "(I[F[J)I");
    if (!g_catalog || !g_floats || !g_string || !g_sample) {
        env->ExceptionClear();
        std::fprintf(stderr, "[ndk-sensors] SensorManager bridge methods missing; NDK sensors stay empty\n");
        env->DeleteLocalRef(c);
        return;
    }
    g_sm = static_cast<jclass>(env->NewGlobalRef(c));
    env->DeleteLocalRef(c);
}

// ---- ASensorManager ----------------------------------------------------------
alignas(16) static uint8_t g_manager[64];

extern "C" void* __macapk_arm64_ASensorManager_getInstance() { return g_manager; }
extern "C" void* __macapk_arm64_ASensorManager_getInstanceForPackage(const char*) { return g_manager; }

extern "C" int __macapk_arm64_ASensorManager_getSensorList(void* /*mgr*/, void const* const** outList) {
    // ASensorList is `ASensor const* const*`; the array must outlive the call.
    static std::vector<void const*> list;
    static std::once_flag once;
    std::call_once(once, [] { for (MacApkSensor* s : Catalog()) list.push_back(s); });
    if (outList) *outList = list.empty() ? nullptr : list.data();
    return static_cast<int>(list.size());
}

extern "C" void* __macapk_arm64_ASensorManager_getDefaultSensor(void* /*mgr*/, int type) {
    for (MacApkSensor* s : Catalog()) if (s->type == type) return s;
    return nullptr;
}

extern "C" void* __macapk_arm64_ASensorManager_getDefaultSensorEx(void* mgr, int type, bool wakeUp) {
    if (wakeUp) return nullptr;   // the catalog has only non-wake-up sensors (SensorManager)
    return __macapk_arm64_ASensorManager_getDefaultSensor(mgr, type);
}

extern "C" void* __macapk_arm64_ASensorManager_createEventQueue(
        void* /*mgr*/, void* looper, int ident, void* callback, void* data) {
    if (!looper) return nullptr;   // sensor.cpp:118-121: "looper cannot be NULL"
    auto* q = new MacApkQueue();
    int p[2];
    if (::pipe(p) != 0) { delete q; return nullptr; }
    for (int f : p) {
        ::fcntl(f, F_SETFL, ::fcntl(f, F_GETFL, 0) | O_NONBLOCK);
        ::fcntl(f, F_SETFD, ::fcntl(f, F_GETFD, 0) | FD_CLOEXEC);
    }
    q->read_fd = p[0];
    q->write_fd = p[1];
    q->looper = looper;
    {
        std::lock_guard<std::mutex> lk(g_queues_mu);
        g_queues.push_back(q);
    }
    __macapk_looper_add_fd_plain(looper, q->read_fd, ident, 1 /*ALOOPER_EVENT_INPUT*/, callback, data);
    q->ticker = std::thread(TickerMain, q);
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1) < 4) {
        char tn[64] = {0};
        pthread_getname_np(pthread_self(), tn, sizeof tn);
        std::fprintf(stderr, "[ndk-sensors] event queue %p (ident=%d, callback=%p, looper=%p, thread=%s)\n",
                     static_cast<void*>(q), ident, callback, looper, tn);
    }
    return q;
}

extern "C" int __macapk_arm64_ASensorManager_destroyEventQueue(void* /*mgr*/, void* queue) {
    MacApkQueue* q = AsQueue(queue);
    if (!q) return -22;   // BAD_VALUE
    {
        std::lock_guard<std::mutex> lk(g_queues_mu);
        for (auto it = g_queues.begin(); it != g_queues.end(); ++it)
            if (*it == q) { g_queues.erase(it); break; }
    }
    q->stop.store(true);
    if (q->ticker.joinable()) q->ticker.join();
    if (q->looper) __macapk_arm64_ALooper_removeFd(q->looper, q->read_fd);
    ::close(q->read_fd);
    ::close(q->write_fd);
    delete q;
    return 0;
}

// ---- ASensorEventQueue -------------------------------------------------------
extern "C" int __macapk_arm64_ASensorEventQueue_registerSensor(
        void* queue, void const* sensor, int32_t samplingPeriodUs, int64_t maxBatchReportLatencyUs) {
    MacApkQueue* q = AsQueue(queue);
    MacApkSensor* s = AsSensor(sensor);
    if (!q || !s || samplingPeriodUs < 0 || maxBatchReportLatencyUs < 0) return -22;
    std::lock_guard<std::mutex> lk(q->mu);
    return EnableLocked(q, s, samplingPeriodUs);
}

extern "C" int __macapk_arm64_ASensorEventQueue_enableSensor(void* queue, void const* sensor) {
    MacApkQueue* q = AsQueue(queue);
    MacApkSensor* s = AsSensor(sensor);
    if (!q || !s) return -22;
    std::lock_guard<std::mutex> lk(q->mu);
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1) < 8)
        std::fprintf(stderr, "[ndk-sensors] enable %s (type %d)\n", s->name.c_str(), s->type);
    return EnableLocked(q, s, kSensorDelayNormalUs);
}

extern "C" int __macapk_arm64_ASensorEventQueue_disableSensor(void* queue, void const* sensor) {
    MacApkQueue* q = AsQueue(queue);
    MacApkSensor* s = AsSensor(sensor);
    if (!q || !s) return -22;
    std::lock_guard<std::mutex> lk(q->mu);
    for (auto it = q->enabled.begin(); it != q->enabled.end(); ++it)
        if (it->sensor == s) { q->enabled.erase(it); break; }
    return 0;
}

extern "C" int __macapk_arm64_ASensorEventQueue_setEventRate(void* queue, void const* sensor, int32_t usec) {
    MacApkQueue* q = AsQueue(queue);
    MacApkSensor* s = AsSensor(sensor);
    if (!q || !s || usec < 0) return -22;
    std::lock_guard<std::mutex> lk(q->mu);
    for (Enabled_& e : q->enabled)
        if (e.sensor == s) { e.period_ns = ClampPeriodNs(s, usec); return 0; }
    return 0;
}

extern "C" int __macapk_arm64_ASensorEventQueue_hasEvents(void* queue) {
    MacApkQueue* q = AsQueue(queue);
    if (!q) return -22;
    pollfd pfd{q->read_fd, POLLIN, 0};
    int n = ::poll(&pfd, 1, 0);
    return n < 0 ? -errno : (n > 0 ? 1 : 0);
}

extern "C" long __macapk_arm64_ASensorEventQueue_getEvents(void* queue, void* events, size_t count) {
    MacApkQueue* q = AsQueue(queue);
    if (!q || !events) return -22;
    static std::atomic<bool> first{true};
    if (first.exchange(false)) {
        char tn[64] = {0};
        pthread_getname_np(pthread_self(), tn, sizeof tn);
        std::fprintf(stderr, "[ndk-sensors] first getEvents call (thread=%s, count=%zu)\n", tn, count);
    }
    Drain(q);
    std::vector<MacApkSensor*> due;
    int64_t now = NowNs();
    {
        std::lock_guard<std::mutex> lk(q->mu);
        for (Enabled_& e : q->enabled) {
            if (due.size() >= count) break;
            if (e.next_due_ns > now) continue;
            due.push_back(e.sensor);
            // Next deadline from the old one, not from now, so the long-run
            // rate is the period; a reader that fell behind is not owed a burst.
            e.next_due_ns += e.period_ns;
            if (e.next_due_ns <= now) e.next_due_ns = now + e.period_ns;
        }
    }
    if (due.empty()) return 0;
    EnvGuard g;
    JNIEnv* env = g.env;
    if (!env || !g_sm) return 0;
    jfloatArray fa = env->NewFloatArray(16);
    jlongArray la = env->NewLongArray(1);
    long n = 0;
    auto* out = static_cast<ASensorEvent*>(events);
    for (MacApkSensor* s : due) {
        if (Sample(env, s, &out[n], fa, la)) n++;
    }
    env->DeleteLocalRef(fa);
    env->DeleteLocalRef(la);
    static std::atomic<int> logged{0};
    // MACAPK_NDK_SENSORS_TRACE=1: one line every 500 ms for the whole run, so a
    // harness can watch a native game's accelerometer follow Tilt Control.
    static const bool trace = [] {
        const char* e = std::getenv("MACAPK_NDK_SENSORS_TRACE");
        return e && e[0] == '1';
    }();
    static std::atomic<int64_t> last_trace{0};
    int64_t t = NowNs();
    if (n > 0 && (logged.fetch_add(1) < 3 || (trace && t - last_trace.load() > 500'000'000))) {
        last_trace.store(t);
        std::fprintf(stderr, "[ndk-sensors] getEvents -> %ld event(s), first type %d = (%.3f, %.3f, %.3f)\n",
                     n, out[0].type, out[0].data[0], out[0].data[1], out[0].data[2]);
    }
    return n;
}

extern "C" int __macapk_arm64_ASensorEventQueue_requestAdditionalInfoEvents(void* queue, bool) {
    return AsQueue(queue) ? 0 : -22;
}

// ---- ASensor -----------------------------------------------------------------
extern "C" const char* __macapk_arm64_ASensor_getName(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->name.c_str() : nullptr;
}
extern "C" const char* __macapk_arm64_ASensor_getVendor(void const* sensor) {
    return AsSensor(sensor) ? "Mac.apk" : nullptr;   // Sensor.getVendor()
}
extern "C" int __macapk_arm64_ASensor_getType(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->type : 0;
}
extern "C" float __macapk_arm64_ASensor_getResolution(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->resolution : 0.0f;
}
extern "C" int __macapk_arm64_ASensor_getMinDelay(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->min_delay_us : 0;
}
extern "C" const char* __macapk_arm64_ASensor_getStringType(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->string_type.c_str() : nullptr;
}
extern "C" int __macapk_arm64_ASensor_getFifoReservedEventCount(void const*) { return 0; }
extern "C" int __macapk_arm64_ASensor_getFifoMaxEventCount(void const*) { return 0; }
extern "C" int __macapk_arm64_ASensor_isWakeUpSensor(void const*) { return 0; }
extern "C" int __macapk_arm64_ASensor_getReportingMode(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->reporting_mode : -1;   // AREPORTING_MODE_INVALID
}
extern "C" int __macapk_arm64_ASensor_getHandle(void const* sensor) {
    MacApkSensor* s = AsSensor(sensor);
    return s ? s->handle : -1;           // ASENSOR_INVALID
}
