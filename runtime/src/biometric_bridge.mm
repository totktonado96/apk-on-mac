// biometric_bridge.mm -- android.hardware.biometrics.MacApkBiometric <->
// LocalAuthentication (Touch ID, with the login password as the credential
// fallback).
//
// Android's BiometricManager.canAuthenticate / BiometricPrompt.authenticate ask
// the system whether the user can be verified and show the system prompt. On the
// Mac the same role is LAContext: canEvaluatePolicy: answers availability and
// evaluatePolicy:localizedReason:reply: shows the system Touch ID sheet.
//   BIOMETRIC_STRONG/WEAK -> LAPolicyDeviceOwnerAuthenticationWithBiometrics
//   DEVICE_CREDENTIAL     -> LAPolicyDeviceOwnerAuthentication (password fallback)
//
// The bridge hands raw LAError codes (0 = success) to Java, which owns the
// Android-side mapping; this file knows nothing about BiometricPrompt codes.
// Each in-flight prompt is an LAContext keyed by a Java-chosen id so a
// CancellationSignal can [LAContext invalidate] it (AOSP: cancel() ->
// IBiometricService.cancelAuthentication).
//
// Threading: the reply block runs on a private LA queue; it attaches that thread
// to the JVM (daemon) and calls MacApkBiometric.macapkOnResult. MRC, like the
// other .mm bridges in this target.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <jni.h>
#include <cstdio>

namespace macapk {
namespace biometric {
namespace {

JavaVM*   g_vm = nullptr;
jclass    g_cls = nullptr;
jmethodID g_on_result = nullptr;
NSMutableDictionary* g_contexts = nil;   // @(id) -> LAContext (retained by the dict)

NSString* Str(JNIEnv* env, jstring js) {
    if (!js) return @"";
    const jchar* c = env->GetStringChars(js, nullptr);
    NSString* s = [NSString stringWithCharacters:(const unichar*)c
                                          length:(NSUInteger)env->GetStringLength(js)];
    env->ReleaseStringChars(js, c);
    return s;
}

LAPolicy Policy(jboolean credential) {
    return credential ? LAPolicyDeviceOwnerAuthentication
                      : LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

jint JNICALL Bio_nativeCanEvaluate(JNIEnv*, jclass, jboolean credential) {
    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        NSError* err = nil;
        BOOL ok = [ctx canEvaluatePolicy:Policy(credential) error:&err];
        [ctx release];
        if (ok) return 0;
        return err ? (jint)err.code : (jint)LAErrorNotInteractive;
    }
}

void Deliver(int id, int code) {
    if (!g_vm || !g_cls || !g_on_result) return;
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21) == JNI_EDETACHED &&
        g_vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env), nullptr) != JNI_OK)
        return;
    if (!env) return;
    env->CallStaticVoidMethod(g_cls, g_on_result, (jint)id, (jint)code);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

void JNICALL Bio_nativeAuthenticate(JNIEnv* env, jclass, jint id, jboolean credential,
                                    jstring jreason, jstring jcancel) {
    NSString* reason = Str(env, jreason);
    NSString* cancel = Str(env, jcancel);
    if (reason.length == 0) reason = @"Authenticate";   // localizedReason must be non-empty
    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        // Biometric-only prompts: no "Enter Password" button (the app asked for
        // biometrics only). The cancel button carries the app's negative text.
        if (!credential) ctx.localizedFallbackTitle = @"";
        if (cancel.length > 0) ctx.localizedCancelTitle = cancel;
        @synchronized ([NSNull null]) {
            if (!g_contexts) g_contexts = [[NSMutableDictionary alloc] init];
            g_contexts[@(id)] = ctx;
        }
        [ctx evaluatePolicy:Policy(credential)
            localizedReason:reason
                      reply:^(BOOL success, NSError* error) {
            @synchronized ([NSNull null]) { [g_contexts removeObjectForKey:@(id)]; }
            Deliver(id, success ? 0 : (error ? (int)error.code : (int)LAErrorAuthenticationFailed));
        }];
        [ctx release];   // the dictionary (and LA's own copy of the block) keep it alive
    }
}

void JNICALL Bio_nativeCancel(JNIEnv*, jclass, jint id) {
    LAContext* ctx = nil;
    @synchronized ([NSNull null]) { ctx = [[g_contexts[@(id)] retain] autorelease]; }
    [ctx invalidate];   // the pending reply then fires with LAErrorAppCancel
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeCanEvaluate"), const_cast<char*>("(Z)I"),
     reinterpret_cast<void*>(Bio_nativeCanEvaluate)},
    {const_cast<char*>("nativeAuthenticate"),
     const_cast<char*>("(IZLjava/lang/String;Ljava/lang/String;)V"),
     reinterpret_cast<void*>(Bio_nativeAuthenticate)},
    {const_cast<char*>("nativeCancel"), const_cast<char*>("(I)V"),
     reinterpret_cast<void*>(Bio_nativeCancel)},
};

}  // namespace

// Soft-fails: a framework jar without the class means no biometric bridge this
// run, and BiometricManager keeps reporting NO_HARDWARE.
void RegisterBiometricBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/hardware/biometrics/MacApkBiometric");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] biometric: no MacApkBiometric in this framework jar\n");
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] biometric: RegisterNatives(MacApkBiometric) failed\n");
        env->DeleteLocalRef(cls);
        return;
    }
    g_on_result = env->GetStaticMethodID(cls, "macapkOnResult", "(II)V");
    if (!g_on_result) env->ExceptionClear();
    env->GetJavaVM(&g_vm);
    g_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
}

}  // namespace biometric
}  // namespace macapk
