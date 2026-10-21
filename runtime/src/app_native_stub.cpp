// app_native_stub.cpp -- a no-op dylib that masquerades as the APK's
// native library. Mac.apk cannot yet load real ARM bionic .so files
// (that's the bionic_translation work that is vendored but not yet
// linked); for now we make System.loadLibrary("name") succeed by
// pointing at this stub.
//
// The dylib intentionally exports nothing -- not even JNI_OnLoad. dlopen
// reports success, the JVM caches the load, and the app's <clinit>
// completes. The first JNI call into the app's "real" native methods
// then throws UnsatisfiedLinkError, which the loader's runTolerant
// wrappers catch so the lifecycle keeps running and we still reach the
// Cocoa runloop with a window on screen.
//
// The empty translation unit is intentional. Some toolchains complain
// when a SHARED library has zero exports, so we pin one symbol that
// nobody calls.

extern "C" __attribute__((used, visibility("default")))
void macapk_app_native_stub_marker(void) {}
