// jvm_loader.h
//
// Thin wrapper around JNI_CreateJavaVM. The native launcher uses this to
// embed HotSpot in-process; once the VM is up, all further work happens
// in Java (the Android framework reimpl + the app's own DEX-converted
// jar). The launcher keeps owning the Cocoa main loop and serves JNI
// callbacks coming back from Java.
//
// Lifetime: one VM per process. Created in main() before Cocoa runs the
// event loop, torn down only at shutdown. Worker threads attach via
// AttachCurrentThread on demand (we keep almost everything single-
// threaded for now -- single Cocoa thread = single Java thread).

#pragma once

#include <jni.h>
#include <string>
#include <vector>

namespace macapk {

struct JvmConfig {
    // Each entry is appended to -Djava.class.path, separated by ':'.
    std::vector<std::string> classpath_entries;

    // Extra "-D" system properties or "-X" options. We always pass
    // "-Xrs" to keep the JVM from installing its own SIGINT handler
    // (Cocoa wants those signals).
    std::vector<std::string> extra_options;

    // Print HotSpot diagnostic info on startup. Wires through to
    // -XX:+PrintFlagsFinal etc. when set.
    bool verbose = false;
};

// Boots a JVM in the calling process. Aborts the process on failure --
// recovery from a bad JNI_CreateJavaVM doesn't give us anything we can
// usefully do. Caller must call this from the thread that will own the
// "main" Java thread (we re-use the Cocoa main thread for that).
//
// On return, *out_vm and *out_env are non-null and the JVM is running.
void StartJvm(const JvmConfig& cfg, JavaVM** out_vm, JNIEnv** out_env);

// Convenience: log + abort if a JNI exception is pending. Used after
// every Find/Get/Call so we surface Java-side problems early.
void CheckException(JNIEnv* env, const char* where);

}  // namespace macapk
