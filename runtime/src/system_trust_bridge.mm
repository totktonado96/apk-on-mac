// system_trust_bridge.mm -- android.security.MacApkSystemTrust.nativeUserRoots:
// the macOS admin/user-domain trusted roots (enterprise CAs pushed by MDM, a
// corporate or developer CA the user trusted in Keychain Access) as DER arrays,
// for the JVM's TLS trust. The Security-framework work lives in the Bionic shim
// (bionic_shim_cacerts.cpp, which also builds /system/etc/security/cacerts from
// the same set), so both views of "what this Mac trusts" cannot drift; this
// file only reaches it through dlsym, like Cocoa_setSharedStorageRoot does.
#include <dlfcn.h>
#include <jni.h>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace macapk {
namespace systemtrust {
namespace {

using Der = std::vector<uint8_t>;
using Fn = size_t (*)(void (*)(const uint8_t*, size_t, void*), void*);

jobjectArray JNICALL SystemTrust_nativeUserRoots(JNIEnv* env, jclass) {
    Fn fn = reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, "__macapk_user_trust_roots"));
    std::vector<Der> roots;
    if (fn) {
        fn([](const uint8_t* p, size_t n, void* ctx) {
            static_cast<std::vector<Der>*>(ctx)->emplace_back(p, p + n);
        }, &roots);
    } else {
        std::fprintf(stderr, "[I] system-trust: shim lacks __macapk_user_trust_roots\n");
    }
    jclass bytes = env->FindClass("[B");
    jobjectArray out = env->NewObjectArray((jsize)roots.size(), bytes, nullptr);
    for (size_t i = 0; out && i < roots.size(); i++) {
        jbyteArray a = env->NewByteArray((jsize)roots[i].size());
        if (!a) break;
        env->SetByteArrayRegion(a, 0, (jsize)roots[i].size(),
                                reinterpret_cast<const jbyte*>(roots[i].data()));
        env->SetObjectArrayElement(out, (jsize)i, a);
        env->DeleteLocalRef(a);
    }
    env->DeleteLocalRef(bytes);
    return out;
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeUserRoots"), const_cast<char*>("()[[B"),
     reinterpret_cast<void*>(SystemTrust_nativeUserRoots)},
};

}  // namespace

void RegisterSystemTrustBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/security/MacApkSystemTrust");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] system-trust: no MacApkSystemTrust in this framework jar\n");
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] system-trust: RegisterNatives failed\n");
    }
    env->DeleteLocalRef(cls);
}

}  // namespace systemtrust
}  // namespace macapk
