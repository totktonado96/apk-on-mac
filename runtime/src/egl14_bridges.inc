// egl14_bridges.inc -- hand-written JNI bridges for android.opengl.EGL14,
// EGL15, and EGLExt. Included by native_methods.cpp inside
// namespace macapk { namespace { ... } }. Do NOT add a `native` decl in the
// Java EGL14/15/EGLExt classes without adding the matching bridge + table
// entry here (lockstep -- see the lesson in the GLES3 generator header).
//
// Handle marshaling: the android.opengl EGL handle wrappers (EGLDisplay,
// EGLContext, EGLSurface, EGLConfig, EGLImage, EGLSync) box an opaque native
// handle as a Java long (EGLObjectHandle.mHandle, read via getNativeHandle()).
// egl_h() unwraps a wrapper to its raw EGL pointer; egl_box() builds a fresh
// wrapper around a returned EGL pointer. All real EGL traffic forwards to
// ANGLE's libEGL via gl3_resolve() (defined just above this include), so a
// missing symbol or an ANGLE-less build degrades to a safe no-op rather than
// failing the dylib link or RegisterNatives. (Project convention: no em dashes.)

// Cache the (long) ctor + getNativeHandle for each wrapper class. Lazily
// initialized on first use; global refs so they survive across calls.
namespace {
struct EglClass { jclass cls = nullptr; jmethodID ctor = nullptr; };
EglClass g_eglDisplay, g_eglContext, g_eglSurface, g_eglConfig,
         g_eglImage, g_eglSync;
jmethodID g_eglGetNativeHandle = nullptr;  // EGLObjectHandle.getNativeHandle()J

void egl_init_cls(JNIEnv* env, EglClass* slot, const char* cn) {
    if (slot->cls) return;
    jclass c = env->FindClass(cn);
    if (!c) { env->ExceptionClear(); return; }
    slot->cls  = (jclass)env->NewGlobalRef(c);
    slot->ctor = env->GetMethodID(c, "<init>", "(J)V");
    env->DeleteLocalRef(c);
    if (!g_eglGetNativeHandle) {
        jclass base = env->FindClass("android/opengl/EGLObjectHandle");
        if (base) {
            g_eglGetNativeHandle =
                env->GetMethodID(base, "getNativeHandle", "()J");
            env->DeleteLocalRef(base);
        }
    }
}

// An EGL error this file raised itself rather than ANGLE (so far only
// eglCreateWindowSurface's EGL_BAD_ALLOC for a stream that is abandoned or
// already has a producer; see "EGL14 window surfaces" below). eglGetError
// answers it once. EGL's error is that of the MOST RECENT call on the thread,
// and ANGLE resets its own at every call, so this one must not outlive the
// next call either: egl_h() clears it, which covers every bridge that names a
// handle, and egl_err_reset() the few that name none.
thread_local int t_egl14PendingError = 0;
inline void egl_err_reset() { t_egl14PendingError = 0; }

// Unwrap any EGL handle wrapper to its raw native pointer (0 if null).
void* egl_h(JNIEnv* env, jobject wrapper) {
    egl_err_reset();
    if (!wrapper || !g_eglGetNativeHandle) {
        // getNativeHandle id may not be cached yet if no wrapper was made; do
        // a one-shot resolve so the very first unwrap works.
        if (wrapper && !g_eglGetNativeHandle) {
            jclass base = env->FindClass("android/opengl/EGLObjectHandle");
            if (base) {
                g_eglGetNativeHandle =
                    env->GetMethodID(base, "getNativeHandle", "()J");
                env->DeleteLocalRef(base);
            }
        }
        if (!wrapper || !g_eglGetNativeHandle) return nullptr;
    }
    jlong h = env->CallLongMethod(wrapper, g_eglGetNativeHandle);
    // A Call*Method must be followed by an exception check before the next JNI
    // call (JNI spec; -Xcheck:jni warned once per egl_h, 148 times in one
    // egl14window gate run). getNativeHandle is a field read and never throws.
    if (env->ExceptionCheck()) return nullptr;
    return reinterpret_cast<void*>(static_cast<intptr_t>(h));
}

// MACAPK_EGL14_NOHANDLE_SINGLETON (default ON). For a NULL handle AOSP hands
// back the very objects it stored in EGL14.EGL_NO_CONTEXT / EGL_NO_DISPLAY /
// EGL_NO_SURFACE, never a new wrapper (frameworks/base core/jni/
// android_opengl_EGL14.cpp toEGLHandle; nativeClassInit sets those three
// static fields to the same global refs). Apps compare by REFERENCE: WebRTC's
// EglBase14Impl.createSurfaceInternal tests the new window with if_acmpeq
// against EGL14.EGL_NO_SURFACE (Telegram 12.9.1, read off its classes.jar),
// so the fresh EGLSurface(0) we returned sailed past that check and the app
// drew into nothing. =0 restores the fresh wrapper.
bool egl14_nohandle_singleton() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_EGL14_NOHANDLE_SINGLETON");
        return !(e && std::strcmp(e, "0") == 0);
    }();
    return on;
}
jobject g_eglNoDisplay = nullptr, g_eglNoContext = nullptr, g_eglNoSurface = nullptr;
// The EGL14 sentinel for `slot`'s class, or null (not one of the three, or
// EGL14 unreadable). A benign race can resolve it twice; both refs are equal.
jobject egl_no_handle(JNIEnv* env, EglClass* slot) {
    jobject* cache; const char* field; const char* sig;
    if (slot == &g_eglSurface)      { cache = &g_eglNoSurface; field = "EGL_NO_SURFACE"; sig = "Landroid/opengl/EGLSurface;"; }
    else if (slot == &g_eglContext) { cache = &g_eglNoContext; field = "EGL_NO_CONTEXT"; sig = "Landroid/opengl/EGLContext;"; }
    else if (slot == &g_eglDisplay) { cache = &g_eglNoDisplay; field = "EGL_NO_DISPLAY"; sig = "Landroid/opengl/EGLDisplay;"; }
    else return nullptr;
    jobject got = __atomic_load_n(cache, __ATOMIC_ACQUIRE);
    if (got) return got;
    jclass c = env->FindClass("android/opengl/EGL14");
    if (!c) { env->ExceptionClear(); return nullptr; }
    jfieldID f = env->GetStaticFieldID(c, field, sig);
    jobject v = f ? env->GetStaticObjectField(c, f) : nullptr;
    if (!f) env->ExceptionClear();
    env->DeleteLocalRef(c);
    if (!v) return nullptr;
    got = env->NewGlobalRef(v);
    env->DeleteLocalRef(v);
    __atomic_store_n(cache, got, __ATOMIC_RELEASE);
    return got;
}

// Box a returned native EGL pointer into the appropriate wrapper object.
jobject egl_box(JNIEnv* env, EglClass* slot, const char* cn, void* native) {
    if (!native && egl14_nohandle_singleton()) {
        if (jobject none = egl_no_handle(env, slot)) return env->NewLocalRef(none);
    }
    egl_init_cls(env, slot, cn);
    if (!slot->cls || !slot->ctor) return nullptr;
    return env->NewObject(slot->cls, slot->ctor,
        static_cast<jlong>(reinterpret_cast<intptr_t>(native)));
}

// Convenience boxers.
jobject boxDisplay(JNIEnv* e, void* p){ return egl_box(e,&g_eglDisplay,"android/opengl/EGLDisplay",p); }
jobject boxContext(JNIEnv* e, void* p){ return egl_box(e,&g_eglContext,"android/opengl/EGLContext",p); }
jobject boxSurface(JNIEnv* e, void* p){ return egl_box(e,&g_eglSurface,"android/opengl/EGLSurface",p); }
jobject boxConfig (JNIEnv* e, void* p){ return egl_box(e,&g_eglConfig, "android/opengl/EGLConfig", p); }
jobject boxImage  (JNIEnv* e, void* p){ return egl_box(e,&g_eglImage,  "android/opengl/EGLImage",  p); }
jobject boxSync   (JNIEnv* e, void* p){ return egl_box(e,&g_eglSync,   "android/opengl/EGLSync",   p); }

// A critical pin of a SINGLE-VALUE out-parameter array (`base[off] = v`). Legal
// as used below: nothing but that one store runs between the Get and the
// Release. Do not use it to hold an array across any other call.
struct AttribGuard {
    JNIEnv* env; jintArray arr; jint* base;
    AttribGuard(JNIEnv* e, jintArray a): env(e), arr(a), base(nullptr) {
        if (arr) base = (jint*)env->GetPrimitiveArrayCritical(arr, nullptr);
    }
    ~AttribGuard() { if (arr && base) env->ReleasePrimitiveArrayCritical(arr, base, 0); }
};

// A READ-ONLY attrib list (`int[]`/`long[] attrib_list, int offset`) handed to
// an EGL entry point whose bridge also makes JNI calls around it: egl_h()'s
// CallLongMethod upcall and a box*() NewObject (plus FindClass / GetMethodID /
// NewGlobalRef on its first use). Those used to run while the list was held by
// GetPrimitiveArrayCritical, which the JNI spec forbids. On JDK 21 SerialGC it
// works only while the heap can still expand: at -Xmx the allocation inside the
// pin gets OutOfMemoryError (fatal "Possible deadlock due to allocating while
// in jni critical section" under -Xcheck:jni; jdk21u genCollectedHeap.cpp
// :312-348). On JDK 25 it can HANG the process at any heap size: a GC request
// there waits for every thread to leave its critical region, the requester
// included (JDK-8192647; docs/gclocker-critical-release-design_2026-09-25.md,
// 2.2 and the ADVERSARIAL CRITIQUE P0 #1).
//
// AOSP never pins these. frameworks/base core/jni/android_opengl_EGL14.cpp
// (android14-release) takes every attrib list with GetIntArrayElements -- a
// COPY on both ART and HotSpot -- and releases it JNI_ABORT (:376/:446
// eglChooseConfig, :699/:724 eglCreatePbufferSurface, :876/:903
// eglCreatePbufferFromClientBuffer, :1015/:1040 eglCreateContext), and android_opengl_EGL15.cpp does the same
// with GetLongArrayElements (:222/:233 eglCreateSync, :354/:365
// eglGetPlatformDisplay, :496/:509 eglCreateImage). GetArrayRegion is that copy
// without the C-heap round trip. The list is only ever read, so nothing is
// written back (JNI_ABORT's meaning).
//
// Two hidden EGL_NONE words follow the copy. Invisible to a well-formed list
// (EGL stops at the first EGL_NONE in an attribute slot), they keep a list
// that lacks its terminator from reading past OUR buffer, whatever its parity.
// (AOSP throws IllegalArgumentException "attrib_list must contain EGL_NONE!"
// there instead; we have never done that, and changing it is app-visible.)
//
// BISECT GATE: MACAPK_JNI_NO_CALLS_IN_CRITICAL=0 restores the pre-fix pin,
// held for the same scope as before (release() marks the old early release
// point where there was one). jni_no_calls_in_critical() is defined in the
// gles3_bridges.inc preamble, which native_methods.cpp includes before this file.
inline void egl_get_region(JNIEnv* e, jintArray a, jsize o, jsize n, jint* b) { e->GetIntArrayRegion(a, o, n, b); }
inline void egl_get_region(JNIEnv* e, jlongArray a, jsize o, jsize n, jlong* b) { e->GetLongArrayRegion(a, o, n, b); }
template <typename JArr, typename T>
class AttribListIn {
 public:
    // `off` must already have passed gl3_check_offset (0 <= off < length).
    AttribListIn(JNIEnv* e, JArr a, jint off) : env_(e), arr_(a) {
        if (!arr_) return;
        if (jni_no_calls_in_critical()) {
            const jsize n = env_->GetArrayLength(arr_) - off;
            if (n <= 0) return;
            copy_.assign(static_cast<size_t>(n) + 2, static_cast<T>(0x3038 /*EGL_NONE*/));
            egl_get_region(env_, arr_, off, n, copy_.data());
            list_ = copy_.data();
        } else {
            pinned_ = env_->GetPrimitiveArrayCritical(arr_, nullptr);
            if (pinned_) list_ = static_cast<const T*>(pinned_) + off;
        }
    }
    ~AttribListIn() { release(); }
    AttribListIn(const AttribListIn&) = delete;
    AttribListIn& operator=(const AttribListIn&) = delete;
    const T* get() const { return list_; }
    // Ends a pre-fix pin (gate off); a no-op for the copy.
    void release() {
        if (pinned_) { env_->ReleasePrimitiveArrayCritical(arr_, pinned_, 0); pinned_ = nullptr; }
    }
 private:
    JNIEnv* env_;
    JArr arr_;
    void* pinned_ = nullptr;
    const T* list_ = nullptr;
    std::vector<T> copy_;
};
using IntAttribs  = AttribListIn<jintArray, jint>;
using LongAttribs = AttribListIn<jlongArray, jlong>;
}  // namespace

// ---- typedefs for the EGL entry points we forward to (Khronos EGL 1.4/1.5) ----
typedef int          MEGLBoolean;
typedef int          MEGLint;
typedef void*        MEGLDisplay;
typedef void*        MEGLSurface;
typedef void*        MEGLContext;
typedef void*        MEGLConfig;
typedef void*        MEGLImage;
typedef void*        MEGLSync;
typedef void*        MEGLClientBuffer;
typedef void*        MEGLNativeWindow;
typedef long long    MEGLTime;

// ===================== EGL14 window surfaces =====================
//
// WHY (2026-09-26, docs/egl14-window-surface_2026-09-26.md). AOSP's
// EGL14.eglCreateWindowSurface builds a real window, on the Surface it is
// handed or on a SurfaceTexture's BufferQueue producer (frameworks/base
// core/jni/android_opengl_EGL14.cpp android_eglCreateWindowSurface /
// android_eglCreateWindowSurfaceTexture: `window = new android::Surface(
// producer, true)`). This bridge used to return EGL_NO_SURFACE for EVERY
// window and set no error, so WebRTC's EglBase14Impl (Telegram, Signal), Rive
// (Duolingo) and CameraX's OpenGlRenderer never had a surface to draw into.
//
// A SurfaceTexture window (or a Surface built from one) is now the window the
// javax EGL10 facade already makes (javax.microedition.khronos.egl.
// MacApkGlWindow): an ANGLE pbuffer sized to the stream's default buffer size,
// read back at each swap on the swapping thread, flipped, and queued into THAT
// SurfaceTexture. AOSP EGL14.java's Java dispatch (SurfaceView / SurfaceHolder
// / Surface / SurfaceTexture, else UnsupportedOperationException) and the JNI
// argument checks (IllegalArgumentException) run in
// MacApkGlWindow.egl14CreateWindowSurface, reached by an upcall, so EGL14.java
// keeps its generated native method. Any OTHER window (a SurfaceView's, which
// the MTKView driver owns; an ImageReader's; a plain Surface) is refused the
// way EGL refuses a window it cannot use: ANGLE's own eglCreateWindowSurface
// with no native window, which validates the display and config and then sets
// EGL_BAD_NATIVE_WINDOW (ANGLE validationEGL.cpp ValidateCreateWindowSurface),
// as Android's loader does for a window it cannot connect
// (egl_platform_entries.cpp eglCreateWindowSurfaceTmpl: `if (!window) return
// setError(EGL_BAD_NATIVE_WINDOW, EGL_NO_SURFACE)`).
//
// THE DISPLAY stays what EGL14.eglGetDisplay(EGL_DEFAULT_DISPLAY) always
// returned: ANGLE's eglGetDisplay(0), the display the NDK EGL shim hands native
// engines (__macapk_arm64_eglGetDisplay, bionic_shim.cpp), because Android's
// libEGL has ONE default display for both APIs and the corpus depends on it:
// Subway Surfers' NatCorder (class i.a, "GLRenderContext.java") creates an
// EGL14 context on EGL14.eglGetDisplay(0) that SHARES Unity's native context,
// and Rive hands its EGL14 display and surface handles to C++ that drives the
// NDK EGL with them. A private display (the EGL10 facade's choice, where no
// such sharing exists) would turn the first into EGL_BAD_MATCH.
// MEASURED (egl14window gate, DPY rows): on the default Metal path this is
// also the FRAMEWORK display. angle_glue.cpp asks for TYPE=METAL explicitly,
// but ANGLE resolves TYPE_DEFAULT from the environment BEFORE it keys the
// display map (Display.cpp GetDisplayFromNativeDisplay ->
// UpdateAttribsFromEnvironment -> GetDisplayTypeFromEnvironment), so both
// requests land on one Display and one Metal command queue. (Only
// ANGLE_DEFAULT_PLATFORM=vulkan splits them.) The window readback therefore
// shares the queue the stranded-buffer deadlock of
// docs/angle-metal-per-display-command-queue-deadlock_2026-07-04.md lived on.
// Why it does not park there: that hang is CommandQueue::
// ensureResourceReadyForCPU walking the queue's FIFO and waiting on its front
// buffer, which may be another context's uncommitted one; but a pbuffer
// readback first flushes its OWN buffer with WaitUntilFinished whenever the
// texture is in use (FrameBufferMtl.mm readPixelsImpl), and the completed
// serial is a running max (mtl_command_buffer.mm storeMaxValue), so the texture
// no longer reads as in use when getBytes reaches the walk. The gate's
// SHARED-DPY row parks a context on this display with uncommitted work and
// requires a window swap to finish; it did, in 0 ms.
//
// HANDLES. An EGL14 handle is the native EGLSurface itself (EGLObjectHandle's
// final mHandle), and apps hand it to native code (Rive's
// RiveEGLSurface.getSurfaceNativePointer). So a window's handle is the pbuffer
// made at creation, a real ANGLE surface. A real window takes a new
// setDefaultBufferSize at its next dequeue (the facade does it after a swap);
// here the pbuffer behind the handle is replaced then, every bridge naming a
// surface translates the app's handle to the current pbuffer (egl14_win_cur),
// and eglGetCurrentSurface translates back (egl14_win_app). The creation
// pbuffer stays allocated until the window is destroyed: ANGLE's
// HandleAllocator gives a released surface id to the NEXT surface created
// (HandleAllocator::allocate pops mReleasedList first), which would then alias
// the app's handle.
//
// BISECT GATE: MACAPK_EGL14_WINDOW_REAL=0 returns boxSurface(nullptr) from
// eglCreateWindowSurface exactly as before; nothing is ever registered, so
// every other bridge below takes its pre-change path.
bool egl14_window_real() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_EGL14_WINDOW_REAL");
        return !(e && std::strcmp(e, "0") == 0);
    }();
    return on;
}

struct Egl14Win { void* dpy; void* app; void* cur; };
std::vector<Egl14Win> g_egl14Wins;   // guarded by Egl14WinLock
bool g_egl14WinBusy = false;
// A spin lock on compiler builtins: this file is included inside a namespace
// (by native_methods.cpp and two gate harnesses), so it cannot include
// <mutex>. Held only across a scan of a handful of entries, never across a
// JNI or EGL call.
struct Egl14WinLock {
    Egl14WinLock() { while (__atomic_test_and_set(&g_egl14WinBusy, __ATOMIC_ACQUIRE)) {} }
    ~Egl14WinLock() { __atomic_clear(&g_egl14WinBusy, __ATOMIC_RELEASE); }
    Egl14WinLock(const Egl14WinLock&) = delete;
    Egl14WinLock& operator=(const Egl14WinLock&) = delete;
};
// The pbuffer currently behind an app's window handle; any other surface
// (a pbuffer, EGL_NO_SURFACE, the EGL10 facade's windows) is its own.
void* egl14_win_cur(void* dpy, void* s) {
    if (!s) return s;
    Egl14WinLock l;
    for (const Egl14Win& w : g_egl14Wins)
        if (w.dpy == dpy && w.app == s) return w.cur; /*XLATE*/
    return s;
}
// The reverse: the app's handle for the pbuffer a thread has current.
void* egl14_win_app(void* dpy, void* s) {
    if (!s) return s;
    Egl14WinLock l;
    for (const Egl14Win& w : g_egl14Wins)
        if (w.dpy == dpy && w.cur == s) return w.app;
    return s;
}
bool egl14_win_find(void* dpy, void* app, Egl14Win* out) {
    if (!app) return false;
    Egl14WinLock l;
    for (const Egl14Win& w : g_egl14Wins)
        if (w.dpy == dpy && w.app == app) { *out = w; return true; }
    return false;
}
// Remove and return one window (app != null) or any window of `dpy`.
bool egl14_win_take(void* dpy, void* app, Egl14Win* out) {
    Egl14WinLock l;
    for (size_t i = 0; i < g_egl14Wins.size(); ++i) {
        const Egl14Win& w = g_egl14Wins[i];
        if (w.dpy == dpy && (!app || w.app == app)) {
            *out = w;
            g_egl14Wins.erase(g_egl14Wins.begin() + static_cast<long>(i));
            return true;
        }
    }
    return false;
}
void egl14_win_add(void* dpy, void* s) {
    Egl14WinLock l;
    g_egl14Wins.push_back(Egl14Win{dpy, s, s});
}
void egl14_win_set_cur(void* dpy, void* app, void* cur) {
    Egl14WinLock l;
    for (Egl14Win& w : g_egl14Wins)
        if (w.dpy == dpy && w.app == app) { w.cur = cur; return; }
}

// The MacApkGlWindow upcalls, resolved once. `create` is published last, so a
// reader that sees it sees the rest.
struct Egl14Upcalls {
    jclass cls = nullptr;
    jmethodID swap = nullptr, destroy = nullptr, create = nullptr;
    bool missing = false;
};
Egl14Upcalls g_egl14Up;
bool egl14_upcalls(JNIEnv* env) {
    if (__atomic_load_n(&g_egl14Up.create, __ATOMIC_ACQUIRE)) return true;
    if (__atomic_load_n(&g_egl14Up.missing, __ATOMIC_RELAXED)) return false;
    jclass c = env->FindClass("javax/microedition/khronos/egl/MacApkGlWindow");
    jmethodID cr = nullptr, sw = nullptr, de = nullptr;
    if (c) {
        cr = env->GetStaticMethodID(c, "egl14CreateWindowSurface",
            "(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Ljava/lang/Object;[II)J");
        if (cr) sw = env->GetStaticMethodID(c, "egl14SwapWindow", "(JJI)J");
        if (sw) de = env->GetStaticMethodID(c, "egl14DestroyWindow", "(JJ)Z");
    }
    if (!c || !cr || !sw || !de) {
        // Never inert: say once that windows fall back to the pre-change
        // answer (an older framework jar ahead of this bridge, or a harness
        // that does not ship the class).
        env->ExceptionClear();
        if (c) env->DeleteLocalRef(c);
        __atomic_store_n(&g_egl14Up.missing, true, __ATOMIC_RELAXED);
        fprintf(stderr, "[egl14] MacApkGlWindow EGL14 upcalls missing; "
                "eglCreateWindowSurface answers EGL_NO_SURFACE as before\n");
        return false;
    }
    g_egl14Up.cls = static_cast<jclass>(env->NewGlobalRef(c));
    env->DeleteLocalRef(c);
    g_egl14Up.swap = sw;
    g_egl14Up.destroy = de;
    __atomic_store_n(&g_egl14Up.create, cr, __ATOMIC_RELEASE);
    return true;
}

// Destroy one window taken out of the registry: the facade disconnects the
// stream and destroys the CURRENT pbuffer; the creation pbuffer, kept to hold
// the app's handle, goes too once a resize had replaced it. The facade's
// destroy is the last EGL call, so its error is what eglGetError reports.
// False with a Java exception pending only if the upcall threw.
bool egl14_win_destroy(JNIEnv* env, const Egl14Win& w, jboolean* result) {
    static auto destroyNative = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface))gl3_resolve("eglDestroySurface");
    MEGLBoolean held = 1;
    if (w.cur != w.app && destroyNative) held = destroyNative(w.dpy, w.app);
    jboolean r = env->CallStaticBooleanMethod(g_egl14Up.cls, g_egl14Up.destroy,
        static_cast<jlong>(reinterpret_cast<intptr_t>(w.dpy)),
        static_cast<jlong>(reinterpret_cast<intptr_t>(w.app)));
    if (env->ExceptionCheck()) return false;
    *result = (r && held) ? JNI_TRUE : JNI_FALSE;
    return true;
}

// The window half of eglSwapBuffers, before the native swap. EGL wants the
// surface current to the calling thread (EGL 1.4 §3.9.3, else
// EGL_BAD_SURFACE); when it is not, nothing is read back and the native swap
// on the current pbuffer reports that error itself. On a resize the new
// pbuffer replaces the old in this thread's binding, the old one is destroyed
// unless it is the creation pbuffer that holds the app's handle, and the
// registry translates from then on. False only with a Java exception pending.
bool egl14_win_swap(JNIEnv* env, const Egl14Win& w) {
    static auto curDisplay = (MEGLDisplay(*)())gl3_resolve("eglGetCurrentDisplay");
    static auto curSurface = (MEGLSurface(*)(MEGLint))gl3_resolve("eglGetCurrentSurface");
    static auto curContext = (MEGLContext(*)())gl3_resolve("eglGetCurrentContext");
    static auto queryContext = (MEGLBoolean(*)(MEGLDisplay, MEGLContext, MEGLint, MEGLint*))gl3_resolve("eglQueryContext");
    static auto makeCurrent = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLSurface, MEGLContext))gl3_resolve("eglMakeCurrent");
    static auto destroyNative = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface))gl3_resolve("eglDestroySurface");
    if (!curDisplay || !curSurface || !curContext || !queryContext || !makeCurrent || !destroyNative)
        return true;
    if (curDisplay() != w.dpy || curSurface(0x3059 /*EGL_DRAW*/) != w.cur) return true;
    MEGLContext ctx = curContext();
    MEGLint version = 2;
    queryContext(w.dpy, ctx, 0x3098 /*EGL_CONTEXT_CLIENT_VERSION*/, &version);
    jlong nh = env->CallStaticLongMethod(g_egl14Up.cls, g_egl14Up.swap,
        static_cast<jlong>(reinterpret_cast<intptr_t>(w.dpy)),
        static_cast<jlong>(reinterpret_cast<intptr_t>(w.app)), static_cast<jint>(version));
    if (env->ExceptionCheck()) return false;
    void* next = reinterpret_cast<void*>(static_cast<intptr_t>(nh));
    if (next && next != w.cur) {
        MEGLSurface read = curSurface(0x305A /*EGL_READ*/);
        makeCurrent(w.dpy, next, read == w.cur ? next : read, ctx);
        egl14_win_set_cur(w.dpy, w.app, next);
        if (w.cur != w.app) destroyNative(w.dpy, w.cur);
    }
    return true;
}

// ---- The native half of an EGL14 window (GitHub #16) ----
//
// An app may create the window through Java EGL14 and hand the handles to C++
// that renders and swaps through the NDK's libEGL: MapLibre Native's Android GL
// backend does (EGL14.eglCreateWindowSurface on a TextureView's SurfaceTexture,
// then a native eglMakeCurrent / draw / eglSwapBuffers on its render thread), and
// so does Rive (RiveEGLSurface.getSurfaceNativePointer). On a device both
// libraries are one libEGL and one window, so the native swap queues the frame
// to the SurfaceTexture exactly as the Java one does. Here the window is a
// pbuffer whose present (readback + queue) lived only in EGL14_eglSwapBuffers,
// so a native swap was a pbuffer flush and the TextureView stayed blank; the
// reporter's extra Java EGL14.eglSwapBuffers after each frame made it appear.
// This was OPEN 1 of docs/egl14-window-surface_2026-09-26.md.
//
// The bionic shim's __macapk_arm64_eglSwapBuffers / eglMakeCurrent /
// eglQuerySurface call these through extern "C" exports defined after the
// namespace in native_methods.cpp (__macapk_egl14_window_swap / _resolve),
// looked up with dlsym(RTLD_DEFAULT), the way the shim already reaches
// CocoaEnsureNativeEglLayer. A process without them (a harness, an older
// runtime) keeps the plain ANGLE forward. With MACAPK_EGL14_WINDOW_REAL=0 the
// registry is always empty, so both answer "not a window".

// The pbuffer behind an app's window handle, for the shim's native bridges
// (any other surface is returned unchanged).
__attribute__((unused)) void* egl14_native_resolve(void* dpy, void* s) {
    return egl14_win_cur(dpy, s);
}

// The window half of a NATIVE eglSwapBuffers: -1 when `s` is not an EGL14
// window (the caller swaps it as before), else the readback + queue of
// egl14_win_swap ran on this thread (1), or its upcall threw (0: logged and
// cleared, since no Java caller is there to receive it). The caller then swaps
// egl14_native_resolve(dpy, s), as EGL14_eglSwapBuffers does. A render thread
// the JVM does not know is attached for the call and detached after it.
__attribute__((unused)) int egl14_native_swap(void* dpy, void* s) {
    Egl14Win w;
    if (!s || !egl14_win_find(dpy, s, &w)) return -1;
    // Looked up, not linked: the gate harnesses that include this file are not
    // all linked against libjvm.
    static auto getVms = (jint(*)(JavaVM**, jsize, jsize*))dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    JavaVM* vm = nullptr;
    jsize n = 0;
    if (!getVms || getVms(&vm, 1, &n) != JNI_OK || n < 1 || !vm) return -1;
    JNIEnv* env = nullptr;
    bool attached = false;
    jint rc = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if (vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env), nullptr) != JNI_OK)
            return -1;
        attached = true;
    } else if (rc != JNI_OK || !env) {
        return -1;
    }
    int r = 1;
    if (!egl14_upcalls(env) || env->ExceptionCheck()) {
        r = -1;
    } else if (!egl14_win_swap(env, w)) {
        fprintf(stderr, "[egl14] native eglSwapBuffers: the window's frame upcall threw\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        r = 0;
    }
    if (attached) vm->DetachCurrentThread();
    return r;
}

// ===================== EGL14 =====================
jint EGL14_eglGetError(JNIEnv*, jclass) {
    static auto p = (MEGLint(*)())gl3_resolve("eglGetError");
    if (int e = t_egl14PendingError) {
        // Ours was the most recent error. Reading clears it, and ANGLE's
        // (SUCCESS from our own bookkeeping calls) is cleared with it.
        t_egl14PendingError = 0;
        if (p) p();
        return e;
    }
    return p ? p() : 0x3000 /*EGL_SUCCESS*/;
}
jobject EGL14_eglGetDisplay(JNIEnv* env, jclass, jint id) {
    static auto p = (MEGLDisplay(*)(void*))gl3_resolve("eglGetDisplay");
    egl_err_reset();
    void* d = p ? p(reinterpret_cast<void*>(static_cast<intptr_t>(id))) : nullptr;
    return boxDisplay(env, d);
}
// ---- Array+offset validation for every `<type>[] arr, int off` pair below.
//
// These bridges do raw pointer arithmetic on an app-supplied offset
// (`base + attOff`, `base[valOff] = v`). Unvalidated that is a heap
// out-of-bounds READ (attrib lists) or WRITE (the out-parameters), from a
// value the app fully controls. AOSP validates before it pins anything and
// raises IllegalArgumentException: see
// frameworks/base/core/jni/android_opengl_EGL14.cpp (android16-release)
// :369-374 + :422-427 (android_eglChooseConfig, "attrib_listOffset < 0" /
// "length - num_configOffset < 1 < needed") and :484-495
// (android_eglGetConfigAttrib, the "offset < 0" / "_remaining < 1" pair every
// single-value out-parameter entry point repeats).
//
// gl3_check_offset() (native_methods.cpp, just above the gles3_bridges.inc
// include) enforces exactly that floor: offset >= 0 and at least one element
// remaining, else throw. It MUST be called before GetPrimitiveArrayCritical --
// JNI forbids FindClass/ThrowNew inside a critical section. A null array stays
// a no-op here rather than the throw AOSP does, matching what these bridges
// have always done for null.
// The per-display initialize/terminate refcount AOSP's libEGL keeps
// (frameworks/native/opengl/libs/EGL/egl_display.cpp: "display termination is
// ref-counted"). It lives in the bionic shim, next to the guest's own
// eglInitialize/eglTerminate, so a display shared by Java EGL14 callers and
// native engines (both reach ANGLE's default display) carries ONE count. If
// the shim is not loaded the bridges keep their old, uncounted behaviour.
static void egl14_display_ref(void* d) {
    static auto f = (void(*)(void*))dlsym(RTLD_DEFAULT, "__macapk_egl_display_ref");
    if (f && d) f(d);
}
static bool egl14_display_unref(void* d) {
    static auto f = (int(*)(void*))dlsym(RTLD_DEFAULT, "__macapk_egl_display_unref");
    return f ? f(d) != 0 : true;
}
jboolean EGL14_eglInitialize(JNIEnv* env, jclass, jobject dpy,
                             jintArray major, jint majOff,
                             jintArray minor, jint minOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLint*, MEGLint*))gl3_resolve("eglInitialize");
    if (!gl3_check_offset(env, major, majOff, "eglInitialize: major offset out of range"))
        return JNI_FALSE;
    if (!gl3_check_offset(env, minor, minOff, "eglInitialize: minor offset out of range"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    MEGLint mj = 0, mn = 0;
    void* d = egl_h(env, dpy);
    MEGLBoolean r = p(d, &mj, &mn);
    if (r) egl14_display_ref(d);
    if (major) { AttribGuard g(env, major); if (g.base) g.base[majOff] = mj; }
    if (minor) { AttribGuard g(env, minor); if (g.base) g.base[minOff] = mn; }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglTerminate(JNIEnv* env, jclass, jobject dpy) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay))gl3_resolve("eglTerminate");
    void* d = egl_h(env, dpy);
    // AOSP's libEGL refcounts initialize/terminate per display; only the
    // terminate matching the last initialize reaches the driver.
    if (!egl14_display_unref(d)) return JNI_TRUE;
    // ANGLE invalidates every surface of a terminated display at once
    // (Display::terminate, "Handles to all such resources are invalid as soon
    // as eglTerminate returns"), so its windows leave their streams now,
    // before the terminate, whose error is then the one eglGetError reports.
    // (A registered window implies the upcalls resolved: create registers.)
    Egl14Win w;
    while (egl14_window_real() && egl14_win_take(d, nullptr, &w)) {
        jboolean ignored;
        if (!egl14_win_destroy(env, w, &ignored)) return JNI_FALSE;
    }
    return (p && p(d)) ? JNI_TRUE : JNI_FALSE;
}
jstring EGL14_eglQueryString(JNIEnv* env, jclass, jobject dpy, jint name) {
    static auto p = (const char*(*)(MEGLDisplay, MEGLint))gl3_resolve("eglQueryString");
    const char* s = p ? p(egl_h(env, dpy), name) : nullptr;
    return env->NewStringUTF(s ? s : "");
}
jboolean EGL14_eglGetConfigs(JNIEnv* env, jclass, jobject dpy,
                             jobjectArray configs, jint cfgOff, jint cfgSize,
                             jintArray num, jint numOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLConfig*, MEGLint, MEGLint*))gl3_resolve("eglGetConfigs");
    if (!gl3_check_offset(env, num, numOff, "eglGetConfigs: num_config offset out of range"))
        return JNI_FALSE;
    // AOSP additionally demands the configs array hold config_size entries
    // from configsOffset (android_opengl_EGL14.cpp:399-406). Without it the
    // SetObjectArrayElement loop below throws ArrayIndexOutOfBoundsException
    // mid-way, leaving a pending exception and a half-filled array.
    if (!gl3_check_config_span(env, configs, cfgOff, cfgSize,
                               "eglGetConfigs: length - configsOffset < config_size"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    std::vector<MEGLConfig> tmp(cfgSize > 0 ? cfgSize : 0);
    MEGLint n = 0;
    MEGLBoolean r = p(egl_h(env, dpy), configs ? tmp.data() : nullptr, cfgSize, &n);
    if (num) { AttribGuard g(env, num); if (g.base) g.base[numOff] = n; }
    if (configs && r) {
        for (jint i = 0; i < n && i < cfgSize; ++i)
            env->SetObjectArrayElement(configs, cfgOff + i, boxConfig(env, tmp[i]));
    }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglChooseConfig(JNIEnv* env, jclass, jobject dpy,
                               jintArray attribs, jint attOff,
                               jobjectArray configs, jint cfgOff, jint cfgSize,
                               jintArray num, jint numOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, const MEGLint*, MEGLConfig*, MEGLint, MEGLint*))gl3_resolve("eglChooseConfig");
    if (!gl3_check_offset(env, attribs, attOff, "eglChooseConfig: attrib_list offset out of range"))
        return JNI_FALSE;
    if (!gl3_check_offset(env, num, numOff, "eglChooseConfig: num_config offset out of range"))
        return JNI_FALSE;
    if (!gl3_check_config_span(env, configs, cfgOff, cfgSize,
                               "eglChooseConfig: length - configsOffset < config_size"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    std::vector<MEGLConfig> tmp(cfgSize > 0 ? cfgSize : 0);
    MEGLint n = 0;
    // Copy, not pin: the boxConfig loop below runs while `al` is in scope.
    IntAttribs al(env, attribs, attOff);
    const MEGLint* alist = al.get();
    MEGLBoolean r = p(egl_h(env, dpy), alist, configs ? tmp.data() : nullptr, cfgSize, &n);
    if (num) { AttribGuard g(env, num); if (g.base) g.base[numOff] = n; }
    if (configs && r) {
        for (jint i = 0; i < n && i < cfgSize; ++i)
            env->SetObjectArrayElement(configs, cfgOff + i, boxConfig(env, tmp[i]));
    }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglGetConfigAttrib(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                  jint attr, jintArray val, jint valOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLConfig, MEGLint, MEGLint*))gl3_resolve("eglGetConfigAttrib");
    if (!gl3_check_offset(env, val, valOff, "eglGetConfigAttrib: offset out of range"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    MEGLint v = 0;
    MEGLBoolean r = p(egl_h(env, dpy), egl_h(env, cfg), attr, &v);
    if (val) { AttribGuard g(env, val); if (g.base) g.base[valOff] = v; }
    return r ? JNI_TRUE : JNI_FALSE;
}
jobject EGL14_eglCreateWindowSurface(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                     jobject win, jintArray attribs, jint attOff) {
    // See "EGL14 window surfaces" above. Gate off (or no upcall class): the
    // pre-change answer, EGL_NO_SURFACE with no error set.
    if (!egl14_window_real() || !egl14_upcalls(env)) return boxSurface(env, nullptr);
    void* d = egl_h(env, dpy);
    jlong r = env->CallStaticLongMethod(g_egl14Up.cls, g_egl14Up.create, dpy, cfg, win, attribs, attOff);
    if (env->ExceptionCheck()) return nullptr;   // AOSP's IllegalArgument / UnsupportedOperation
    if (r > 0) {
        void* s = reinterpret_cast<void*>(static_cast<intptr_t>(r));
        egl14_win_add(d, s);
        return boxSurface(env, s);
    }
    static auto p = (MEGLSurface(*)(MEGLDisplay, MEGLConfig, MEGLNativeWindow, const MEGLint*))gl3_resolve("eglCreateWindowSurface");
    if (r == -2) {
        // A SurfaceView's Surface (GitHub #15): a real ANGLE window on the
        // SurfaceView's native window, the dedicated native-EGL CAMetalLayer
        // (ANGLE-Metal takes a CALayer as its EGLNativeWindowType). The same
        // window ANativeWindow_fromSurface + the NDK eglCreateWindowSurface
        // make (__macapk_arm64_egl_create_window_surface_bridge) and the
        // EGL10 survivor path makes (angle_glue.cpp CreateSurfaceViewWindow),
        // so it presents through ANGLE's own swap from Java or native code and
        // is destroyed by a plain eglDestroySurface; it is not registered.
        // Looked up, not linked: the gate harnesses that include this file
        // have no Cocoa bridge. No layer (no render view yet) refuses the way
        // a window that cannot connect is refused, EGL_BAD_NATIVE_WINDOW.
        static auto ensureLayer = (void*(*)(int*, int*))dlsym(RTLD_DEFAULT, "CocoaEnsureNativeEglLayer");
        static auto noteLive = (void(*)())dlsym(RTLD_DEFAULT, "CocoaNoteNativeEglSurfaceLive");
        void* c = egl_h(env, cfg);
        int lw = 0, lh = 0;
        void* layer = ensureLayer ? ensureLayer(&lw, &lh) : nullptr;
        if (!layer) {
            fprintf(stderr, "[egl14] eglCreateWindowSurface(SurfaceView): no native-EGL "
                    "layer (no render view yet) -> EGL_NO_SURFACE\n");
            if (p) p(d, c, nullptr, nullptr);
            return boxSurface(env, nullptr);
        }
        // MacApkGlWindow already applied AOSP's checks (offset >= 0, EGL_NONE
        // present); copy, do not pin, since EGL runs arbitrary work first.
        IntAttribs al(env, attribs, attOff);
        void* s = p ? p(d, c, layer, al.get()) : nullptr;
        al.release();   // before any JNI call (a pre-fix pin is a critical section)
        if (s) {
            if (noteLive) noteLive();
            fprintf(stderr, "[egl14] eglCreateWindowSurface(SurfaceView) -> EGLSurface %p on "
                    "native-EGL layer %p (%dx%d)\n", s, layer, lw, lh);
        }
        return boxSurface(env, s);   // a refusal leaves ANGLE's own error
    }
    if (r == 0) {
        // Not a stream: let ANGLE refuse a window it cannot use. The attrib
        // list is not passed: both loaders reject the window before reading it.
        void* c = egl_h(env, cfg);
        if (p) p(d, c, nullptr, nullptr);
        return boxSurface(env, nullptr);
    }
    if (r < -1) t_egl14PendingError = static_cast<int>(-r);   // EGL_BAD_ALLOC
    return boxSurface(env, nullptr);   // r == -1: the pbuffer's own error stands
}
jobject EGL14_eglCreatePbufferSurface(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                      jintArray attribs, jint attOff) {
    static auto p = (MEGLSurface(*)(MEGLDisplay, MEGLConfig, const MEGLint*))gl3_resolve("eglCreatePbufferSurface");
    if (!gl3_check_offset(env, attribs, attOff, "eglCreatePbufferSurface: attrib_list offset out of range"))
        return boxSurface(env, nullptr);
    IntAttribs al(env, attribs, attOff);   // copy, not pin: egl_h + boxSurface below
    const MEGLint* alist = al.get();
    void* s = p ? p(egl_h(env, dpy), egl_h(env, cfg), alist) : nullptr;
    return boxSurface(env, s);
}
jobject EGL14_eglCreatePixmapSurface(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                     jint pix, jintArray attribs, jint attOff) {
    // Pixmap surfaces are not supported by ANGLE/Metal; return EGL_NO_SURFACE.
    (void)pix; (void)attribs; (void)attOff; (void)cfg; (void)dpy;
    return boxSurface(env, nullptr);
}
jboolean EGL14_eglDestroySurface(JNIEnv* env, jclass, jobject dpy, jobject surf) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface))gl3_resolve("eglDestroySurface");
    void* d = egl_h(env, dpy);
    void* s = egl_h(env, surf);
    Egl14Win w;
    if (egl14_window_real() && egl14_win_take(d, s, &w)) {
        jboolean r = JNI_FALSE;
        return egl14_win_destroy(env, w, &r) ? r : JNI_FALSE;
    }
    return (p && p(d, s)) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglQuerySurface(JNIEnv* env, jclass, jobject dpy, jobject surf,
                               jint attr, jintArray val, jint valOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLint, MEGLint*))gl3_resolve("eglQuerySurface");
    if (!gl3_check_offset(env, val, valOff, "eglQuerySurface: offset out of range"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    MEGLint v = 0;
    void* d = egl_h(env, dpy);
    MEGLBoolean r = p(d, egl14_win_cur(d, egl_h(env, surf)), attr, &v);
    if (val) { AttribGuard g(env, val); if (g.base) g.base[valOff] = v; }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglBindAPI(JNIEnv*, jclass, jint api) {
    static auto p = (MEGLBoolean(*)(MEGLint))gl3_resolve("eglBindAPI");
    egl_err_reset();
    return (p && p(api)) ? JNI_TRUE : JNI_FALSE;
}
jint EGL14_eglQueryAPI(JNIEnv*, jclass) {
    static auto p = (MEGLint(*)())gl3_resolve("eglQueryAPI");
    egl_err_reset();
    return p ? p() : 0x30A0 /*EGL_OPENGL_ES_API*/;
}
jboolean EGL14_eglWaitClient(JNIEnv*, jclass) {
    static auto p = (MEGLBoolean(*)())gl3_resolve("eglWaitClient");
    egl_err_reset();
    return (p && p()) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglReleaseThread(JNIEnv*, jclass) {
    static auto p = (MEGLBoolean(*)())gl3_resolve("eglReleaseThread");
    egl_err_reset();
    return (p && p()) ? JNI_TRUE : JNI_FALSE;
}
jobject EGL14_eglCreatePbufferFromClientBuffer(JNIEnv* env, jclass, jobject dpy,
                                               jint buftype, jint buffer, jobject cfg,
                                               jintArray attribs, jint attOff) {
    static auto p = (MEGLSurface(*)(MEGLDisplay, MEGLint, MEGLClientBuffer, MEGLConfig, const MEGLint*))gl3_resolve("eglCreatePbufferFromClientBuffer");
    if (!gl3_check_offset(env, attribs, attOff, "eglCreatePbufferFromClientBuffer: attrib_list offset out of range"))
        return boxSurface(env, nullptr);
    IntAttribs al(env, attribs, attOff);   // copy, not pin: egl_h + boxSurface below
    const MEGLint* alist = al.get();
    void* s = p ? p(egl_h(env, dpy), buftype,
                    reinterpret_cast<void*>(static_cast<intptr_t>(buffer)),
                    egl_h(env, cfg), alist) : nullptr;
    return boxSurface(env, s);
}
jboolean EGL14_eglSurfaceAttrib(JNIEnv* env, jclass, jobject dpy, jobject surf,
                                jint attr, jint value) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLint, MEGLint))gl3_resolve("eglSurfaceAttrib");
    void* d = egl_h(env, dpy);
    return (p && p(d, egl14_win_cur(d, egl_h(env, surf)), attr, value)) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglBindTexImage(JNIEnv* env, jclass, jobject dpy, jobject surf, jint buf) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLint))gl3_resolve("eglBindTexImage");
    void* d = egl_h(env, dpy);
    return (p && p(d, egl14_win_cur(d, egl_h(env, surf)), buf)) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglReleaseTexImage(JNIEnv* env, jclass, jobject dpy, jobject surf, jint buf) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLint))gl3_resolve("eglReleaseTexImage");
    void* d = egl_h(env, dpy);
    return (p && p(d, egl14_win_cur(d, egl_h(env, surf)), buf)) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglSwapInterval(JNIEnv* env, jclass, jobject dpy, jint interval) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLint))gl3_resolve("eglSwapInterval");
    return (p && p(egl_h(env, dpy), interval)) ? JNI_TRUE : JNI_FALSE;
}
jobject EGL14_eglCreateContext(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                               jobject share, jintArray attribs, jint attOff) {
    static auto p = (MEGLContext(*)(MEGLDisplay, MEGLConfig, MEGLContext, const MEGLint*))gl3_resolve("eglCreateContext");
    if (!gl3_check_offset(env, attribs, attOff, "eglCreateContext: attrib_list offset out of range"))
        return boxContext(env, nullptr);
    IntAttribs al(env, attribs, attOff);   // copy, not pin: egl_h + boxContext below
    const MEGLint* alist = al.get();
    void* c = p ? p(egl_h(env, dpy), egl_h(env, cfg), egl_h(env, share), alist) : nullptr;
    return boxContext(env, c);
}
jboolean EGL14_eglDestroyContext(JNIEnv* env, jclass, jobject dpy, jobject ctx) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLContext))gl3_resolve("eglDestroyContext");
    return (p && p(egl_h(env, dpy), egl_h(env, ctx))) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglMakeCurrent(JNIEnv* env, jclass, jobject dpy, jobject draw,
                              jobject read, jobject ctx) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLSurface, MEGLContext))gl3_resolve("eglMakeCurrent");
    void* d = egl_h(env, dpy);
    void* dr = egl14_win_cur(d, egl_h(env, draw));
    void* rd = egl14_win_cur(d, egl_h(env, read));
    return (p && p(d, dr, rd, egl_h(env, ctx))) ? JNI_TRUE : JNI_FALSE;
}
jobject EGL14_eglGetCurrentContext(JNIEnv* env, jclass) {
    static auto p = (MEGLContext(*)())gl3_resolve("eglGetCurrentContext");
    egl_err_reset();
    return boxContext(env, p ? p() : nullptr);
}
jobject EGL14_eglGetCurrentSurface(JNIEnv* env, jclass, jint readdraw) {
    static auto p = (MEGLSurface(*)(MEGLint))gl3_resolve("eglGetCurrentSurface");
    static auto curDisplay = (MEGLDisplay(*)())gl3_resolve("eglGetCurrentDisplay");
    egl_err_reset();
    void* s = p ? p(readdraw) : nullptr;
    // A resized window's pbuffer answers with the handle the app holds.
    if (s && curDisplay) s = egl14_win_app(curDisplay(), s);
    return boxSurface(env, s);
}
jobject EGL14_eglGetCurrentDisplay(JNIEnv* env, jclass) {
    static auto p = (MEGLDisplay(*)())gl3_resolve("eglGetCurrentDisplay");
    egl_err_reset();
    return boxDisplay(env, p ? p() : nullptr);
}
jboolean EGL14_eglQueryContext(JNIEnv* env, jclass, jobject dpy, jobject ctx,
                               jint attr, jintArray val, jint valOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLContext, MEGLint, MEGLint*))gl3_resolve("eglQueryContext");
    if (!gl3_check_offset(env, val, valOff, "eglQueryContext: offset out of range"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    MEGLint v = 0;
    MEGLBoolean r = p(egl_h(env, dpy), egl_h(env, ctx), attr, &v);
    if (val) { AttribGuard g(env, val); if (g.base) g.base[valOff] = v; }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglWaitGL(JNIEnv*, jclass) {
    static auto p = (MEGLBoolean(*)())gl3_resolve("eglWaitGL");
    egl_err_reset();
    return (p && p()) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglWaitNative(JNIEnv*, jclass, jint engine) {
    static auto p = (MEGLBoolean(*)(MEGLint))gl3_resolve("eglWaitNative");
    egl_err_reset();
    return (p && p(engine)) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglSwapBuffers(JNIEnv* env, jclass, jobject dpy, jobject surf) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface))gl3_resolve("eglSwapBuffers");
    void* d = egl_h(env, dpy);
    void* s = egl_h(env, surf);
    Egl14Win w;
    if (egl14_window_real() && egl14_win_find(d, s, &w)) {
        // Read the frame back and queue it, then swap the (possibly new)
        // pbuffer: a pbuffer swap is only an implicit flush (EGL 1.4 §3.9.3),
        // but it is the call whose error the app reads.
        if (!egl14_win_swap(env, w)) return JNI_FALSE;
    }
    return (p && p(d, egl14_win_cur(d, s))) ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL14_eglCopyBuffers(JNIEnv* env, jclass, jobject dpy, jobject surf, jint target) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, void*))gl3_resolve("eglCopyBuffers");
    void* d = egl_h(env, dpy);
    return (p && p(d, egl14_win_cur(d, egl_h(env, surf)),
                   reinterpret_cast<void*>(static_cast<intptr_t>(target)))) ? JNI_TRUE : JNI_FALSE;
}

const JNINativeMethod kEgl14Methods[] = {
    {(char*)"eglGetError", (char*)"()I", (void*)EGL14_eglGetError},
    {(char*)"eglGetDisplay", (char*)"(I)Landroid/opengl/EGLDisplay;", (void*)EGL14_eglGetDisplay},
    {(char*)"eglInitialize", (char*)"(Landroid/opengl/EGLDisplay;[II[II)Z", (void*)EGL14_eglInitialize},
    {(char*)"eglTerminate", (char*)"(Landroid/opengl/EGLDisplay;)Z", (void*)EGL14_eglTerminate},
    {(char*)"eglQueryString", (char*)"(Landroid/opengl/EGLDisplay;I)Ljava/lang/String;", (void*)EGL14_eglQueryString},
    {(char*)"eglGetConfigs", (char*)"(Landroid/opengl/EGLDisplay;[Landroid/opengl/EGLConfig;II[II)Z", (void*)EGL14_eglGetConfigs},
    {(char*)"eglChooseConfig", (char*)"(Landroid/opengl/EGLDisplay;[II[Landroid/opengl/EGLConfig;II[II)Z", (void*)EGL14_eglChooseConfig},
    {(char*)"eglGetConfigAttrib", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;I[II)Z", (void*)EGL14_eglGetConfigAttrib},
    {(char*)"eglCreatePbufferSurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;[II)Landroid/opengl/EGLSurface;", (void*)EGL14_eglCreatePbufferSurface},
    {(char*)"eglCreatePixmapSurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;I[II)Landroid/opengl/EGLSurface;", (void*)EGL14_eglCreatePixmapSurface},
    {(char*)"eglDestroySurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z", (void*)EGL14_eglDestroySurface},
    {(char*)"eglQuerySurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I[II)Z", (void*)EGL14_eglQuerySurface},
    {(char*)"eglBindAPI", (char*)"(I)Z", (void*)EGL14_eglBindAPI},
    {(char*)"eglQueryAPI", (char*)"()I", (void*)EGL14_eglQueryAPI},
    {(char*)"eglWaitClient", (char*)"()Z", (void*)EGL14_eglWaitClient},
    {(char*)"eglReleaseThread", (char*)"()Z", (void*)EGL14_eglReleaseThread},
    {(char*)"eglCreatePbufferFromClientBuffer", (char*)"(Landroid/opengl/EGLDisplay;IILandroid/opengl/EGLConfig;[II)Landroid/opengl/EGLSurface;", (void*)EGL14_eglCreatePbufferFromClientBuffer},
    {(char*)"eglSurfaceAttrib", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;II)Z", (void*)EGL14_eglSurfaceAttrib},
    {(char*)"eglBindTexImage", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I)Z", (void*)EGL14_eglBindTexImage},
    {(char*)"eglReleaseTexImage", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I)Z", (void*)EGL14_eglReleaseTexImage},
    {(char*)"eglSwapInterval", (char*)"(Landroid/opengl/EGLDisplay;I)Z", (void*)EGL14_eglSwapInterval},
    {(char*)"eglCreateContext", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Landroid/opengl/EGLContext;[II)Landroid/opengl/EGLContext;", (void*)EGL14_eglCreateContext},
    {(char*)"eglDestroyContext", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;)Z", (void*)EGL14_eglDestroyContext},
    {(char*)"eglMakeCurrent", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;Landroid/opengl/EGLSurface;Landroid/opengl/EGLContext;)Z", (void*)EGL14_eglMakeCurrent},
    {(char*)"eglGetCurrentContext", (char*)"()Landroid/opengl/EGLContext;", (void*)EGL14_eglGetCurrentContext},
    {(char*)"eglGetCurrentSurface", (char*)"(I)Landroid/opengl/EGLSurface;", (void*)EGL14_eglGetCurrentSurface},
    {(char*)"eglGetCurrentDisplay", (char*)"()Landroid/opengl/EGLDisplay;", (void*)EGL14_eglGetCurrentDisplay},
    {(char*)"eglQueryContext", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;I[II)Z", (void*)EGL14_eglQueryContext},
    {(char*)"eglWaitGL", (char*)"()Z", (void*)EGL14_eglWaitGL},
    {(char*)"eglWaitNative", (char*)"(I)Z", (void*)EGL14_eglWaitNative},
    {(char*)"eglSwapBuffers", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;)Z", (void*)EGL14_eglSwapBuffers},
    {(char*)"eglCopyBuffers", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;I)Z", (void*)EGL14_eglCopyBuffers},
    {(char*)"eglCreateWindowSurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Ljava/lang/Object;[II)Landroid/opengl/EGLSurface;", (void*)EGL14_eglCreateWindowSurface},
};

// ===================== EGL15 =====================
jobject EGL15_eglCreateSync(JNIEnv* env, jclass, jobject dpy, jint type,
                            jlongArray attribs, jint attOff) {
    static auto p = (MEGLSync(*)(MEGLDisplay, MEGLint, const long long*))gl3_resolve("eglCreateSync");
    if (!gl3_check_offset(env, attribs, attOff, "eglCreateSync: attrib_list offset out of range"))
        return boxSync(env, nullptr);
    LongAttribs al(env, attribs, attOff);  // copy, not pin: egl_h below
    const long long* alist = reinterpret_cast<const long long*>(al.get());
    void* s = p ? p(egl_h(env, dpy), type, alist) : nullptr;
    al.release();
    return boxSync(env, s);
}
jboolean EGL15_eglGetSyncAttrib(JNIEnv* env, jclass, jobject dpy, jobject sync,
                                jint attr, jlongArray val, jint valOff) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSync, MEGLint, long long*))gl3_resolve("eglGetSyncAttrib");
    if (!gl3_check_offset(env, val, valOff, "eglGetSyncAttrib: offset out of range"))
        return JNI_FALSE;
    if (!p) return JNI_FALSE;
    long long v = 0;
    MEGLBoolean r = p(egl_h(env, dpy), egl_h(env, sync), attr, &v);
    if (val) {
        void* base = env->GetPrimitiveArrayCritical(val, nullptr);
        if (base) { ((long long*)base)[valOff] = v;
                    env->ReleasePrimitiveArrayCritical(val, base, 0); }
    }
    return r ? JNI_TRUE : JNI_FALSE;
}
jboolean EGL15_eglDestroySync(JNIEnv* env, jclass, jobject dpy, jobject sync) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSync))gl3_resolve("eglDestroySync");
    return (p && p(egl_h(env, dpy), egl_h(env, sync))) ? JNI_TRUE : JNI_FALSE;
}
jint EGL15_eglClientWaitSync(JNIEnv* env, jclass, jobject dpy, jobject sync,
                             jint flags, jlong timeout) {
    static auto p = (MEGLint(*)(MEGLDisplay, MEGLSync, MEGLint, MEGLTime))gl3_resolve("eglClientWaitSync");
    return p ? p(egl_h(env, dpy), egl_h(env, sync), flags, timeout) : 0;
}
jobject EGL15_eglGetPlatformDisplay(JNIEnv* env, jclass, jint platform,
                                    jlong nativeDisplay, jlongArray attribs, jint attOff) {
    static auto p = (MEGLDisplay(*)(MEGLint, void*, const long long*))gl3_resolve("eglGetPlatformDisplay");
    egl_err_reset();
    if (!gl3_check_offset(env, attribs, attOff, "eglGetPlatformDisplay: attrib_list offset out of range"))
        return boxDisplay(env, nullptr);
    // No JNI call ran inside this pin, but a display query is not a memory
    // copy either (on JDK 25 a critical held across it stalls every allocating
    // thread for its length); same AOSP copy as the other attrib lists.
    LongAttribs al(env, attribs, attOff);
    const long long* alist = reinterpret_cast<const long long*>(al.get());
    void* d = p ? p(platform, reinterpret_cast<void*>(static_cast<intptr_t>(nativeDisplay)), alist) : nullptr;
    al.release();
    return boxDisplay(env, d);
}
jobject EGL15_eglCreatePlatformWindowSurface(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                             jobject /*Buffer*/, jlongArray, jint) {
    // No ANativeWindow for an arbitrary Java Buffer on macOS; ANGLE binds a
    // CAMetalLayer. Return EGL_NO_SURFACE rather than guessing a window.
    (void)dpy; (void)cfg;
    return boxSurface(env, nullptr);
}
jobject EGL15_eglCreatePlatformPixmapSurface(JNIEnv* env, jclass, jobject dpy, jobject cfg,
                                             jobject /*Buffer*/, jlongArray, jint) {
    (void)dpy; (void)cfg;
    return boxSurface(env, nullptr);  // pixmap unsupported on ANGLE/Metal
}
jboolean EGL15_eglWaitSync(JNIEnv* env, jclass, jobject dpy, jobject sync, jint flags) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSync, MEGLint))gl3_resolve("eglWaitSync");
    return (p && p(egl_h(env, dpy), egl_h(env, sync), flags)) ? JNI_TRUE : JNI_FALSE;
}
jobject EGL15_eglCreateImage(JNIEnv* env, jclass, jobject dpy, jobject ctx,
                             jint target, jlong buffer, jlongArray attribs, jint attOff) {
    static auto p = (MEGLImage(*)(MEGLDisplay, MEGLContext, MEGLint, void*, const long long*))gl3_resolve("eglCreateImage");
    if (!gl3_check_offset(env, attribs, attOff, "eglCreateImage: attrib_list offset out of range"))
        return boxImage(env, nullptr);
    LongAttribs al(env, attribs, attOff);  // copy, not pin: egl_h below
    const long long* alist = reinterpret_cast<const long long*>(al.get());
    void* im = p ? p(egl_h(env, dpy), egl_h(env, ctx), target,
                     reinterpret_cast<void*>(static_cast<intptr_t>(buffer)), alist) : nullptr;
    al.release();
    return boxImage(env, im);
}
jboolean EGL15_eglDestroyImage(JNIEnv* env, jclass, jobject dpy, jobject img) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLImage))gl3_resolve("eglDestroyImage");
    return (p && p(egl_h(env, dpy), egl_h(env, img))) ? JNI_TRUE : JNI_FALSE;
}

const JNINativeMethod kEgl15Methods[] = {
    {(char*)"eglCreateSync", (char*)"(Landroid/opengl/EGLDisplay;I[JI)Landroid/opengl/EGLSync;", (void*)EGL15_eglCreateSync},
    {(char*)"eglGetSyncAttrib", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSync;I[JI)Z", (void*)EGL15_eglGetSyncAttrib},
    {(char*)"eglDestroySync", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSync;)Z", (void*)EGL15_eglDestroySync},
    {(char*)"eglClientWaitSync", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSync;IJ)I", (void*)EGL15_eglClientWaitSync},
    {(char*)"eglGetPlatformDisplay", (char*)"(IJ[JI)Landroid/opengl/EGLDisplay;", (void*)EGL15_eglGetPlatformDisplay},
    {(char*)"eglCreatePlatformWindowSurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Ljava/nio/Buffer;[JI)Landroid/opengl/EGLSurface;", (void*)EGL15_eglCreatePlatformWindowSurface},
    {(char*)"eglCreatePlatformPixmapSurface", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLConfig;Ljava/nio/Buffer;[JI)Landroid/opengl/EGLSurface;", (void*)EGL15_eglCreatePlatformPixmapSurface},
    {(char*)"eglWaitSync", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSync;I)Z", (void*)EGL15_eglWaitSync},
    {(char*)"eglCreateImage", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLContext;IJ[JI)Landroid/opengl/EGLImage;", (void*)EGL15_eglCreateImage},
    {(char*)"eglDestroyImage", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLImage;)Z", (void*)EGL15_eglDestroyImage},
};

// ===================== EGLExt =====================
jboolean EGLExt_eglPresentationTimeANDROID(JNIEnv* env, jclass, jobject dpy,
                                           jobject surf, jlong time) {
    static auto p = (MEGLBoolean(*)(MEGLDisplay, MEGLSurface, MEGLTime))gl3_resolve("eglPresentationTimeANDROID");
    void* d = egl_h(env, dpy);
    return (p && p(d, egl14_win_cur(d, egl_h(env, surf)), time)) ? JNI_TRUE : JNI_FALSE;
}

const JNINativeMethod kEglExtMethods[] = {
    {(char*)"eglPresentationTimeANDROID", (char*)"(Landroid/opengl/EGLDisplay;Landroid/opengl/EGLSurface;J)Z", (void*)EGLExt_eglPresentationTimeANDROID},
};

void RegisterEgl14Methods(JNIEnv* env) {
    Bind(env, "android/opengl/EGL14",  kEgl14Methods,
         sizeof(kEgl14Methods)  / sizeof(kEgl14Methods[0]));
    Bind(env, "android/opengl/EGL15",  kEgl15Methods,
         sizeof(kEgl15Methods)  / sizeof(kEgl15Methods[0]));
    Bind(env, "android/opengl/EGLExt", kEglExtMethods,
         sizeof(kEglExtMethods) / sizeof(kEglExtMethods[0]));
}
