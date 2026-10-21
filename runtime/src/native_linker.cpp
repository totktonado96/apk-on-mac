// native_linker.cpp -- com.macapk.loader.NativeLinker: map a translated library
// the way the Android DYNAMIC LINKER maps a DT_NEEDED dependency, i.e. WITHOUT
// the JNI half of System.load().
//
// WHY THIS EXISTS (2026-09-29, lanes19 meta-apps; docs/soloader-premap-jni-onload-timing_2026-09-29.md).
// AppClassLoader.premapDependencyLibs maps a SoLoader app's DT_NEEDED providers
// at Boot so the libraries SoLoader dlopens LATER resolve their relocations
// against loaded_images(). It used System.load() for that, and System.load()
// is not "map": the JDK calls the library's JNI_OnLoad as part of it
// (jdk21u src/java.base/share/native/libjava/NativeLibraries.c:130-139,
// `handle = ... JVM_LoadLibrary(cname, ...); JNI_OnLoad = findJniFunction(...);
// ... jniVersion = (*JNI_OnLoad)(jvm, NULL);`). So every dependency's JNI_OnLoad
// ran before the app had executed a single line -- before its Application had
// called SoLoader.init / NativeLoader.init. fbjni's JNI_OnLoad
// (fbjni cxx/fbjni/OnLoad.cpp: `facebook::jni::initialize(vm, [] { ...
// ThreadScope::OnLoad(); ... })`) initialises com.facebook.jni.ThreadScopeSupport,
// whose <clinit> is `NativeLoader.loadLibrary("fbjni")`, which throws
// "NativeLoader has not been initialized" (SoLoader NativeLoader.java:42-46)
// when sDelegate is still null. The class is then permanently erroneous and the
// next fbjni C++ throw has no handler: std::terminate -> SIGABRT at boot
// (measured: Efteling 5.24.0, a React Native + Hermes app).
//
// WHAT ANDROID DOES. A DT_NEEDED dependency is loaded by the linker, which runs
// its constructors and nothing else (bionic linker/linker_soinfo.cpp
// soinfo::call_constructors: children first, then DT_INIT, then
// DT_INIT_ARRAY). JNI_OnLoad is called ONLY by JavaVMExt::LoadNativeLibrary,
// i.e. for a library the app itself hands to System.load/loadLibrary
// (art runtime/jni/java_vm_ext.cc:1120-1135, `library->FindSymbol("JNI_OnLoad")
// ... (*jni_on_load)(this, nullptr)`). So the faithful primitive for "map a
// dependency" is dlopen() alone. A later System.load() of the same file by the
// app (SoLoader) then gets a fresh JVM registration and runs JNI_OnLoad at the
// moment Android would.
//
// The dlopen mode is HotSpot's own (jdk21u src/hotspot/os/bsd/os_bsd.cpp:
// `::dlopen(filename, RTLD_LAZY)`), so the image dyld hands the JVM on that
// later System.load() is the very one mapped here: same handle, constructors
// (our Stage-6 ELF loader in the dylib's __mod_init_func) run exactly once.
//
// Kept in its own translation unit, with an exported JNI name as well as the
// RegisterNatives table, so debug/soloader_premap_gate.sh compiles THIS file
// into a bare JVM and tests the shipped code, not a copy.

#include <jni.h>
#include <dlfcn.h>
#include <cstdio>

extern "C" JNIEXPORT jstring JNICALL
Java_com_macapk_loader_NativeLinker_nativeLinkOnly(JNIEnv* env, jclass, jstring jpath) {
    if (!jpath) return env->NewStringUTF("null path");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return env->NewStringUTF("GetStringUTFChars failed");
    // Deliberately never dlclose()d: a DT_NEEDED dependency lives as long as
    // the process on Android too (its dependents hold it).
    void* h = ::dlopen(path, RTLD_LAZY);
    jstring err = nullptr;
    if (!h) {
        const char* e = ::dlerror();
        err = env->NewStringUTF(e ? e : "dlopen failed");
    }
    env->ReleaseStringUTFChars(jpath, path);
    return err;   // null == mapped
}

namespace macapk {
namespace nativelinker {

void RegisterNativeLinkerMethods(JNIEnv* env) {
    static const JNINativeMethod kMethods[] = {
        {const_cast<char*>("nativeLinkOnly"),
         const_cast<char*>("(Ljava/lang/String;)Ljava/lang/String;"),
         reinterpret_cast<void*>(&Java_com_macapk_loader_NativeLinker_nativeLinkOnly)},
    };
    // Soft-fail, like the clipboard/wallpaper bridges: a jar without the class
    // must not abort boot. AppClassLoader catches the UnsatisfiedLinkError and
    // keeps the pre-change System.load path for that run.
    jclass cls = env->FindClass("com/macapk/loader/NativeLinker");
    if (!cls) {
        std::fprintf(stderr, "[E] nativelinker: FindClass(com.macapk.loader.NativeLinker) failed; "
                             "SoLoader dependency premap keeps System.load this run\n");
        env->ExceptionClear();
        return;
    }
    if (env->RegisterNatives(cls, kMethods, 1) != JNI_OK) {
        std::fprintf(stderr, "[E] nativelinker: RegisterNatives failed; SoLoader dependency "
                             "premap keeps System.load this run\n");
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
}

}  // namespace nativelinker
}  // namespace macapk
