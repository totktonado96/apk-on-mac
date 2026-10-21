// native_methods.h
//
// Registry of JNI functions that the v2 native launcher exposes to the
// Android framework reimpl (Java code under runtime/java/).
//
// We use RegisterNatives rather than the JNI naming convention so we
// don't have to keep mangled C symbol names in sync with Java package
// renames. The launcher calls RegisterAll(env) once after the JVM is
// up, and the bound classes appear callable from Java immediately.

#pragma once

#include <jni.h>

namespace macapk {

// Register every native method this binary implements with HotSpot.
// Aborts on any failure (a missing class is unrecoverable: it means
// the framework jar wasn't on the classpath or didn't compile).
void RegisterAllNativeMethods(JNIEnv* env);

// MACAPK_CHOREO_VSYNC_THREADS (2026-09-27): deliver ONE display vsync to every
// per-thread Java Choreographer that requested one (NativeLooper.scheduleVsync),
// stamped now in the System.nanoTime() timebase, and wake each owning looper.
// Called by cocoa_bridge.mm once per display tick, beside the NDK
// AChoreographer fire. Returns how many loopers it woke; costs one relaxed
// atomic load when no Java Choreographer is waiting.
int JavaVsyncFire();

}  // namespace macapk
