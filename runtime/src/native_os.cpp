// native_os.cpp -- JNI bridge from com.macapk.loader.NativeOs to the
// macOS/Darwin libc, backing the raw-fd operations of the
// android.system.Os framework reimpl (lseek / close / dup / sysconf /
// memfd_create / statvfs). The Java side (android/system/Os.java) extracts the
// int fd out of a java.io.FileDescriptor (reflection, enabled by the
// runtime's --add-opens=java.base/java.io=ALL-UNNAMED) and calls these
// with the raw int; results < 0 carry -errno so the Java side can
// throw the AOSP-shaped ErrnoException.
//
// Why JNI vs FFM (CORRECTED 2026-08-31): we pin JDK 21, where FFM is
// preview-only (JEP 442) and would need --enable-preview on every javac
// AND on the JVM launch -- VM-wide, so it would apply to the entire
// framework jar and pin its classfiles to exactly 21.0.x. FFM has been
// FINAL since JDK 22 (JEP 454), so this is a consequence of the pin, not
// a property of FFM.
// ⚠ The old text here said "JNI is faster per call". That is UNCITED and
// WRONG as a general rule -- JEP 454's own goal is "overhead comparable
// to, if not better than, JNI", and a measured comparison puts FFM ahead
// on a bare downcall. It happens to hold for THIS file's shape: the
// pointer-out / struct-by-pointer pattern is the one regime where JNI
// measured ~15% faster, because FFM needs an Arena where C takes the
// address of a local. Right conclusion, wrong reason -- and it sat in a
// header a session reads while deciding whether to look further.
//
// Why raw int fds cross the boundary (not jobject FileDescriptor):
// keeps this file free of JVM-version-specific FileDescriptor field
// lookups; the reflection lives in one place on the Java side.
//
// memfd_create: Darwin has no memfd_create(2). We emulate it with an
// unlinked temp file (anonymous, read/write, supports ftruncate+mmap
// MAP_SHARED) -- the operations apps actually use a memfd for.
//
// sysconf: apps pass the *bionic* _SC_* selector values (they compiled
// against bionic's OsConstants). We translate the handful that matter
// to the Darwin _SC_* symbolic constants before calling sysconf(3), so
// the returned page size / CPU count / clock tick is the real host
// value. Bionic values verified against
// aosp-mirror/platform_bionic libc/include/bits/sysconf.h:
//   _SC_PAGESIZE=0x27(39) _SC_PAGE_SIZE=0x28(40) _SC_CLK_TCK=0x06(6)
//   _SC_NPROCESSORS_CONF=0x60(96) _SC_NPROCESSORS_ONLN=0x61(97)
#include <jni.h>
#include <dlfcn.h>         // dlsym(RTLD_DEFAULT): the shim's guest-environment bridge
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>      // flock(2), for NativeOs_takeRunLock
#include <stdlib.h>
#include <cstdio>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <compression.h>   // Apple's Compression framework: COMPRESSION_LZMA
#include <vector>

namespace macapk {
namespace osnative {

namespace {

jlong NativeOs_lseek(JNIEnv*, jclass, jint fd, jlong offset, jint whence) {
    off_t r = ::lseek((int)fd, (off_t)offset, (int)whence);
    return (r == (off_t)-1) ? (jlong)(-errno) : (jlong)r;
}

jint NativeOs_close(JNIEnv*, jclass, jint fd) {
    return (::close((int)fd) < 0) ? -errno : 0;
}

jint NativeOs_dup(JNIEnv*, jclass, jint fd) {
    int r = ::dup((int)fd);
    return (r < 0) ? -errno : r;
}

jint NativeOs_dup2(JNIEnv*, jclass, jint oldfd, jint newfd) {
    int r = ::dup2((int)oldfd, (int)newfd);
    return (r < 0) ? -errno : r;
}

jlong NativeOs_sysconf(JNIEnv*, jclass, jint bionicName) {
    int darwin;
    switch (bionicName) {
        case 0x27: /* _SC_PAGESIZE  */
        case 0x28: /* _SC_PAGE_SIZE */ darwin = _SC_PAGESIZE; break;
        case 0x06: /* _SC_CLK_TCK   */ darwin = _SC_CLK_TCK; break;
        case 0x60: /* _SC_NPROCESSORS_CONF */ darwin = _SC_NPROCESSORS_CONF; break;
        case 0x61: /* _SC_NPROCESSORS_ONLN */ darwin = _SC_NPROCESSORS_ONLN; break;
        default:   darwin = (int)bionicName; break;  // best-effort passthrough
    }
    long r = ::sysconf(darwin);
    return (jlong)r;
}

jint NativeOs_memfdCreate(JNIEnv*, jclass, jstring /*name*/, jint /*flags*/) {
    // Darwin has no memfd_create(2); an unlinked temp file is anonymous,
    // read/write, and supports ftruncate + mmap(MAP_SHARED) -- the uses
    // apps put a memfd to.
    char tmpl[] = "/tmp/macapk_memfd_XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) return -errno;
    ::unlink(tmpl);
    return fd;
}


jlongArray NativeOs_fstat(JNIEnv* env, jclass, jint fd) {
    struct stat st;
    if (::fstat((int)fd, &st) < 0) return nullptr;
    jlong vals[11] = {
        (jlong)st.st_dev, (jlong)st.st_ino, (jlong)st.st_mode, (jlong)st.st_nlink,
        (jlong)st.st_size, (jlong)st.st_atime, (jlong)st.st_mtime, (jlong)st.st_ctime,
        (jlong)st.st_blksize, (jlong)st.st_blocks, (jlong)st.st_rdev,
    };
    jlongArray arr = env->NewLongArray(11);
    if (arr != nullptr) env->SetLongArrayRegion(arr, 0, 11, vals);
    return arr;
}

// The app's run lock (com.macapk.loader.RunLock): open run/<dirName>.pid and
// take flock(LOCK_EX | LOCK_NB) on it for the life of this process, writing our
// pid. flock, NOT fcntl/FileChannel: the per-app stub and macapk-installhelper's
// CallerIdentity both use flock, and flock locks belong to the open file
// description, so probing with a NEW fd neither releases nor steals a lock this
// process already inherited from its stub (that probe just fails EWOULDBLOCK).
// O_CLOEXEC: a forked child must not keep the lock alive after we die.
// Returns the held fd, or -errno (-EWOULDBLOCK: someone, maybe us, holds it).
jint NativeOs_takeRunLock(JNIEnv* env, jclass, jstring jpath) {
    if (jpath == nullptr) return -EINVAL;
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return -ENOMEM;
    int fd = ::open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    int err = errno;
    env->ReleaseStringUTFChars(jpath, path);
    if (fd < 0) return -err;
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        err = errno;
        ::close(fd);
        return -err;
    }
    char buf[32];
    int n = snprintf(buf, sizeof buf, "%d\n", (int)getpid());
    if (::ftruncate(fd, 0) == 0 && n > 0) {
        ::lseek(fd, 0, SEEK_SET);
        (void)!::write(fd, buf, (size_t)n);
    }
    return fd;   // intentionally never closed: the lock lives as long as we do
}

jint NativeOs_ftruncate(JNIEnv*, jclass, jint fd, jlong length) {
    return (::ftruncate((int)fd, (off_t)length) < 0) ? -errno : 0;
}

// read(2) / write(2). AOSP's android.system.Os.read / .write are a raw read(2) /
// write(2) on the fd (libcore Libcore.os.read -> Posix.read) that does NOT take
// ownership of the fd -- so we call the bare syscall, never a FileInputStream
// wrapper (whose close/finalize would steal the fd). Bytes stage through a
// native buffer rather than GetPrimitiveArrayCritical, because a critical region
// must not span a BLOCKING syscall. EINTR is retried in-place: AOSP surfaces it
// as InterruptedIOException so a caller can react to Thread.interrupt(), but no
// corpus caller depends on that, and a robust retry is the safer default. A
// short read is returned as-is (the caller loops), 0 means EOF, <0 carries
// -errno for the Java side to throw the AOSP-shaped ErrnoException.
jint NativeOs_read(JNIEnv* env, jclass, jint fd, jbyteArray buf, jint off, jint count) {
    if (buf == nullptr) return -EFAULT;
    jsize len = env->GetArrayLength(buf);
    if (off < 0 || count < 0 || off > len || count > len - off) return -EINVAL;
    if (count == 0) return 0;
    std::vector<unsigned char> tmp((size_t)count);
    ssize_t r;
    do { r = ::read((int)fd, tmp.data(), (size_t)count); } while (r < 0 && errno == EINTR);
    if (r < 0) return -errno;
    if (r > 0) env->SetByteArrayRegion(buf, off, (jsize)r, (const jbyte*)tmp.data());
    return (jint)r;
}

jint NativeOs_write(JNIEnv* env, jclass, jint fd, jbyteArray buf, jint off, jint count) {
    if (buf == nullptr) return -EFAULT;
    jsize len = env->GetArrayLength(buf);
    if (off < 0 || count < 0 || off > len || count > len - off) return -EINVAL;
    if (count == 0) return 0;
    std::vector<unsigned char> tmp((size_t)count);
    env->GetByteArrayRegion(buf, off, count, (jbyte*)tmp.data());
    ssize_t r;
    do { r = ::write((int)fd, tmp.data(), (size_t)count); } while (r < 0 && errno == EINTR);
    if (r < 0) return -errno;
    return (jint)r;
}

// --- statvfs / fstatvfs ----------------------------------------------------
// android.system.Os.statvfs / .fstatvfs return a StructStatVfs. AOSP maps them
// straight onto statvfs(3) / fstatvfs(3) via Libcore.os
// (libcore/luni/src/main/java/android/system/Os.java:915 and :197), and macOS
// exports both under the same names with a field-for-field identical struct --
// so this is the host-native rung of the decision ladder, not an emulation.
//
//   Darwin  <sys/statvfs.h>            Bionic  bionic/libc/include/sys/statvfs.h
//     unsigned long f_bsize;             unsigned long f_bsize;
//     unsigned long f_frsize;            unsigned long f_frsize;
//     fsblkcnt_t    f_blocks;            fsblkcnt_t    f_blocks;
//     fsblkcnt_t    f_bfree;             fsblkcnt_t    f_bfree;
//     fsblkcnt_t    f_bavail;            fsblkcnt_t    f_bavail;
//     fsfilcnt_t    f_files;             fsfilcnt_t    f_files;
//     fsfilcnt_t    f_ffree;             fsfilcnt_t    f_ffree;
//     fsfilcnt_t    f_favail;            fsfilcnt_t    f_favail;
//     unsigned long f_fsid;              unsigned long f_fsid;
//     unsigned long f_flag;              unsigned long f_flag;
//     unsigned long f_namemax;           unsigned long f_namemax;
// Same 11 members, same order, same meaning. The ONE divergence worth naming is
// f_flag: Darwin defines only ST_RDONLY (1) and ST_NOSUID (2), where Linux and
// Bionic also define ST_NODEV/ST_NOEXEC/ST_SYNCHRONOUS/... So f_flag carries
// fewer bits here than on a device. No caller in the corpus reads it; the
// free-space members that callers DO read (f_bavail * f_frsize) are exact.
//
// Returned as long[11] in declaration order, or null on failure -- the same
// shape and the same null-means-it-failed contract as NativeOs_fstat above.
jlongArray statvfs_to_array(JNIEnv* env, const struct statvfs& sv) {
    const jlong vals[11] = {
        (jlong)sv.f_bsize,  (jlong)sv.f_frsize, (jlong)sv.f_blocks,
        (jlong)sv.f_bfree,  (jlong)sv.f_bavail, (jlong)sv.f_files,
        (jlong)sv.f_ffree,  (jlong)sv.f_favail, (jlong)sv.f_fsid,
        (jlong)sv.f_flag,   (jlong)sv.f_namemax,
    };
    jlongArray arr = env->NewLongArray(11);
    if (arr != nullptr) env->SetLongArrayRegion(arr, 0, 11, vals);
    return arr;
}

jlongArray NativeOs_statvfs(JNIEnv* env, jclass, jstring path) {
    if (path == nullptr) return nullptr;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p == nullptr) return nullptr;
    struct statvfs sv;
    const int rc = ::statvfs(p, &sv);
    env->ReleaseStringUTFChars(path, p);
    return (rc < 0) ? nullptr : statvfs_to_array(env, sv);
}

jlongArray NativeOs_fstatvfs(JNIEnv* env, jclass, jint fd) {
    struct statvfs sv;
    if (::fstatvfs((int)fd, &sv) < 0) return nullptr;
    return statvfs_to_array(env, sv);
}

// --- process environment (setenv / getenv / unsetenv) ----------------------
// These MUST hit the environment the app's NATIVE code reads, not the JVM's
// copy. java.lang.System.getenv() returns an IMMUTABLE snapshot taken at JVM
// startup, so a Java-side map cannot be observed by native code -- and
// native code is the entire reason an app calls android.system.Os.setenv.
// Measured case: AnkiDroid's Application.onCreate sets env vars that its
// Rust backend (librsdroid.so, loaded through Stage 6) later reads with
// getenv(3); a no-op setenv leaves the backend unconfigured.
//
// AOSP maps these straight onto Bionic setenv/getenv/unsetenv via Libcore.os
// (libcore/luni/src/main/java/android/system/Os.java:675,232,973 ->
// libcore/luni/src/main/native/libcore_io_Linux.cpp Linux_setenv :2418 /
// Linux_getenv :1446, LineageOS android_libcore lineage-21.0), i.e. plain
// setenv(3)/getenv(3) on the ONE `environ` the app's native code also reads.
//
// ⚠ CORRECTED 2026-09-26: this used to call Darwin setenv(3) on the HOST
// environment, on the reasoning that Darwin's POSIX functions are "a direct
// match". They stopped being one when the guest's getenv moved to the
// Android-shaped environment (bionic_shim.cpp, MACAPK_ANDROID_ENVIRON, 2026-09-11):
// from then on a Java Os.setenv landed where no guest looked, and the measured
// AnkiDroid case above had been silently broken ever since (its backend then
// fell back to /data/local/tmp). The guest environment lives in the shim, so
// the calls go there: __macapk_guest_setenv / __macapk_guest_unsetenv /
// __macapk_guest_getenv, resolved with dlsym(RTLD_DEFAULT) the way every other
// runtime-to-shim call is (native_methods.cpp __macapk_property_put and
// friends; main.cpp dlopens the shim RTLD_GLOBAL before Boot.run). The shim owns
// the bisect gate MACAPK_GUEST_ENV_MUTABLE: at 0 those functions ARE the host
// calls below, so this file never reads the gate itself.
//
// Host fallback: only when the shim is absent (a bare harness without it). It
// is the pre-2026-09-26 behaviour, and it says so once on stderr, because an
// Os.setenv that silently misses the guest is exactly the bug this fixes.
//
// Nothing of OURS relies on Os.setenv reaching the host environment: no
// runtime Java calls Os.setenv/getenv/unsetenv (grep, 2026-09-26), and every
// MACAPK_* flag is read from the host environment by getenv(3) or
// System.getenv(), which this does not touch.
//
// Thread-safety: the shim serializes writers and keeps readers lock-free,
// and never frees an array a concurrent guest getenv may be walking (see
// the block comment above __macapk_arm64_setenv).
struct GuestEnvFns {
    int (*set)(const char*, const char*, int);   // 0 or -errno
    int (*unset)(const char*);                   // 0 or -errno
    const char* (*get)(const char*);
};
const GuestEnvFns* guest_env_fns() {
    static const GuestEnvFns fns = [] {
        GuestEnvFns f{};
        f.set   = reinterpret_cast<int (*)(const char*, const char*, int)>(
                      dlsym(RTLD_DEFAULT, "__macapk_guest_setenv"));
        f.unset = reinterpret_cast<int (*)(const char*)>(
                      dlsym(RTLD_DEFAULT, "__macapk_guest_unsetenv"));
        f.get   = reinterpret_cast<const char* (*)(const char*)>(
                      dlsym(RTLD_DEFAULT, "__macapk_guest_getenv"));
        if (!f.set || !f.unset || !f.get) {
            // All three or none: half a bridge would split one environment in two.
            std::fprintf(stderr,
                "[macapk] NativeOs: shim guest-environment bridge missing (%s); "
                "Os.setenv/getenv/unsetenv use the HOST environment, which guest "
                "native code does not read\n", dlerror());
            f = GuestEnvFns{};
        }
        return f;
    }();
    return fns.set ? &fns : nullptr;
}

jint NativeOs_setenv(JNIEnv* env, jclass, jstring name, jstring value, jboolean overwrite) {
    if (name == nullptr || value == nullptr) return -EINVAL;
    const char* n = env->GetStringUTFChars(name, nullptr);
    const char* v = env->GetStringUTFChars(value, nullptr);
    jint rc = 0;
    if (n == nullptr || v == nullptr) {
        rc = -ENOMEM;
    } else if (const GuestEnvFns* g = guest_env_fns()) {
        rc = g->set(n, v, overwrite ? 1 : 0);
    } else if (::setenv(n, v, overwrite ? 1 : 0) < 0) {
        rc = -errno;
    }
    if (n != nullptr) env->ReleaseStringUTFChars(name, n);
    if (v != nullptr) env->ReleaseStringUTFChars(value, v);
    return rc;
}

jstring NativeOs_getenv(JNIEnv* env, jclass, jstring name) {
    if (name == nullptr) return nullptr;
    const char* n = env->GetStringUTFChars(name, nullptr);
    if (n == nullptr) return nullptr;
    const GuestEnvFns* g = guest_env_fns();
    // The value is copied into a Java string before anything else can run; the
    // shim never frees a string it has handed out (Bionic does not either).
    const char* v = g ? g->get(n) : ::getenv(n);
    jstring out = (v == nullptr) ? nullptr : env->NewStringUTF(v);
    env->ReleaseStringUTFChars(name, n);
    return out;
}

jint NativeOs_unsetenv(JNIEnv* env, jclass, jstring name) {
    if (name == nullptr) return -EINVAL;
    const char* n = env->GetStringUTFChars(name, nullptr);
    if (n == nullptr) return -ENOMEM;
    jint rc;
    if (const GuestEnvFns* g = guest_env_fns()) rc = g->unset(n);
    else rc = (::unsetenv(n) < 0) ? -errno : 0;
    env->ReleaseStringUTFChars(name, n);
    return rc;
}

// android.system.Os.open(path, flags, mode). Apps pass the *bionic* O_* flag
// bits (they compiled against bionic's OsConstants / NDK fcntl.h), which differ
// from Darwin's above the low two access-mode bits -- so we translate each bit
// before calling open(2), the same bionic->Darwin remap this file already does
// for sysconf. Returns the raw fd, or -errno on failure (the Java side turns
// that into an AOSP-shaped ErrnoException). Instagram's obfuscated resource/init
// code (X.1di.A00 in attachBaseContext) calls Os.open(path, 0, 0) = O_RDONLY;
// without this method that call is a NoSuchMethodError that aborts the app's
// init chain. The full translation keeps any other caller correct too.
//
// Bionic values: aosp-mirror/platform_bionic libc/kernel/uapi/asm-generic/fcntl.h
//   (aarch64 uses the asm-generic set, no arch override):
//     O_CREAT 0100  O_EXCL 0200  O_NOCTTY 0400  O_TRUNC 01000  O_APPEND 02000
//     O_NONBLOCK 04000  O_DSYNC 010000  O_DIRECT 040000  O_LARGEFILE 0100000
//     O_DIRECTORY 0200000  O_NOFOLLOW 0400000  O_CLOEXEC 02000000
//     __O_SYNC 04000000 (O_SYNC = __O_SYNC|O_DSYNC)
// Darwin values: MacOSX.sdk sys/fcntl.h (verified locally).
jint NativeOs_open(JNIEnv* env, jclass, jstring jpath, jint bionicFlags, jint mode) {
    if (jpath == nullptr) return -EINVAL;
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return -ENOMEM;

    // Bionic O_* bit constants (source cited above).
    enum : int {
        B_ACCMODE = 03, B_CREAT = 0100, B_EXCL = 0200, B_NOCTTY = 0400,
        B_TRUNC = 01000, B_APPEND = 02000, B_NONBLOCK = 04000, B_DSYNC = 010000,
        B_DIRECTORY = 0200000, B_NOFOLLOW = 0400000, B_CLOEXEC = 02000000,
        B__SYNC = 04000000,
        // Ignored on Darwin (no direct equivalent, and harmless to drop):
        // O_DIRECT (040000), O_LARGEFILE (0100000, macOS off_t is always 64-bit).
    };
    int df = (int)(bionicFlags & B_ACCMODE);   // O_RDONLY/WRONLY/RDWR share values
    if (bionicFlags & B_CREAT)     df |= O_CREAT;
    if (bionicFlags & B_EXCL)      df |= O_EXCL;
    if (bionicFlags & B_NOCTTY)    df |= O_NOCTTY;
    if (bionicFlags & B_TRUNC)     df |= O_TRUNC;
    if (bionicFlags & B_APPEND)    df |= O_APPEND;
    if (bionicFlags & B_NONBLOCK)  df |= O_NONBLOCK;
    if (bionicFlags & B_DSYNC)     df |= O_DSYNC;
    if (bionicFlags & B_DIRECTORY) df |= O_DIRECTORY;
    if (bionicFlags & B_NOFOLLOW)  df |= O_NOFOLLOW;
    if (bionicFlags & B_CLOEXEC)   df |= O_CLOEXEC;
    if (bionicFlags & B__SYNC)     df |= O_SYNC;

    int fd = ::open(path, df, (mode_t)mode);
    int e = errno;
    env->ReleaseStringUTFChars(jpath, path);
    return fd >= 0 ? fd : -e;
}

// ---- XZ (.xz / LZMA) decompression, host-native -----------------------------
//
// WHY THIS EXISTS. Meta apps pack their compiled layouts into ONE xz-compressed
// blob and rewrite each resources.arsc entry from "res/layout/x.xml" to a private
// token ("L|<hexOffset>|<hexLen>|<hexHash>"). Instagram 445 does this for 5,947 of
// its 6,017 layouts -- including its main activity's -- so without the blob the
// inflater has nothing to inflate and setContentView fails.
//
// Java SE has no XZ/LZMA decoder (java.util.zip is deflate/gzip only), so this is
// the host-first rung of CLAUDE.md's decision ladder: macOS ships one. Apple's
// Compression framework decodes the .xz CONTAINER directly under
// COMPRESSION_LZMA -- MEASURED on Instagram's assets/layouts.bin.xz: 858,608
// bytes in, 9,933,932 out, byte-identical to python's lzma, and the bytes at the
// token's offset begin 03 00 08 00 (RES_XML_TYPE), i.e. a real compiled-XML chunk.
// It is in the dyld shared cache (link -lcompression), so nothing is bundled and
// there is no Homebrew dependency -- which matters because a Dock-launched app has
// no Homebrew PATH, so shelling out to /opt/homebrew/bin/xz would work here and
// fail for a shipped app.
//
// Returns null on any failure; the caller treats that as "no blob" and degrades to
// its normal miss rather than throwing.
jbyteArray NativeOs_xzDecompress(JNIEnv* env, jclass, jbyteArray in) {
    if (in == nullptr) return nullptr;
    const jsize n = env->GetArrayLength(in);
    if (n <= 0) return nullptr;
    jbyte* src = env->GetByteArrayElements(in, nullptr);
    if (src == nullptr) return nullptr;

    compression_stream s{};
    if (compression_stream_init(&s, COMPRESSION_STREAM_DECODE, COMPRESSION_LZMA)
            != COMPRESSION_STATUS_OK) {
        env->ReleaseByteArrayElements(in, src, JNI_ABORT);
        return nullptr;
    }
    // Grow geometrically from a guess of 8x the compressed size: an xz stream does
    // not carry its uncompressed length in a form we can cheaply trust, so we
    // simply keep feeding until the stream reports END.
    std::vector<unsigned char> out;
    out.resize(static_cast<size_t>(n) * 8 + (1u << 20));
    size_t produced = 0;
    bool ok = false;
    s.src_ptr  = reinterpret_cast<const uint8_t*>(src);
    s.src_size = static_cast<size_t>(n);
    for (;;) {
        s.dst_ptr  = out.data() + produced;
        s.dst_size = out.size() - produced;
        compression_status st =
            compression_stream_process(&s, COMPRESSION_STREAM_FINALIZE);
        produced = out.size() - s.dst_size;
        if (st == COMPRESSION_STATUS_END) { ok = true; break; }
        if (st == COMPRESSION_STATUS_ERROR) break;
        if (s.dst_size == 0) {              // output full -- grow and continue
            if (out.size() > (256u << 20)) break;   // runaway guard
            out.resize(out.size() * 2);
            continue;
        }
        break;                               // made no progress and not END
    }
    compression_stream_destroy(&s);
    env->ReleaseByteArrayElements(in, src, JNI_ABORT);
    if (!ok || produced == 0) return nullptr;

    jbyteArray res = env->NewByteArray(static_cast<jsize>(produced));
    if (res == nullptr) return nullptr;
    env->SetByteArrayRegion(res, 0, static_cast<jsize>(produced),
                            reinterpret_cast<const jbyte*>(out.data()));
    return res;
}

const JNINativeMethod kNativeOsMethods[] = {
    {(char*)"xzDecompress", (char*)"([B)[B",          (void*)NativeOs_xzDecompress},
    {(char*)"open",        (char*)"(Ljava/lang/String;II)I", (void*)NativeOs_open},
    {(char*)"lseek",       (char*)"(IJI)J",                 (void*)NativeOs_lseek},
    {(char*)"close",       (char*)"(I)I",                   (void*)NativeOs_close},
    {(char*)"dup",         (char*)"(I)I",                   (void*)NativeOs_dup},
    {(char*)"dup2",        (char*)"(II)I",                  (void*)NativeOs_dup2},
    {(char*)"sysconf",     (char*)"(I)J",                   (void*)NativeOs_sysconf},
    {(char*)"memfdCreate", (char*)"(Ljava/lang/String;I)I", (void*)NativeOs_memfdCreate},
    {(char*)"fstat",       (char*)"(I)[J",                  (void*)NativeOs_fstat},
    {(char*)"ftruncate",   (char*)"(IJ)I",                  (void*)NativeOs_ftruncate},
    {(char*)"takeRunLock", (char*)"(Ljava/lang/String;)I",  (void*)NativeOs_takeRunLock},
    {(char*)"read",        (char*)"(I[BII)I",               (void*)NativeOs_read},
    {(char*)"write",       (char*)"(I[BII)I",               (void*)NativeOs_write},
    {(char*)"statvfs",     (char*)"(Ljava/lang/String;)[J", (void*)NativeOs_statvfs},
    {(char*)"fstatvfs",    (char*)"(I)[J",                  (void*)NativeOs_fstatvfs},
    {(char*)"setenv",      (char*)"(Ljava/lang/String;Ljava/lang/String;Z)I", (void*)NativeOs_setenv},
    {(char*)"getenv",      (char*)"(Ljava/lang/String;)Ljava/lang/String;",   (void*)NativeOs_getenv},
    {(char*)"unsetenv",    (char*)"(Ljava/lang/String;)I",  (void*)NativeOs_unsetenv},
};

}  // anonymous namespace

// Registered from native_methods.cpp's RegisterAllNativeMethods at boot.
// Never hard-fails: a missing class just leaves the natives unbound (they
// throw UnsatisfiedLinkError lazily if actually called), matching the
// tolerant policy elsewhere in native_methods.cpp.
void RegisterNativeOsMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/NativeOs");
    if (cls == nullptr) {
        env->ExceptionClear();
        return;
    }
    if (env->RegisterNatives(cls, kNativeOsMethods,
                             sizeof(kNativeOsMethods) / sizeof(kNativeOsMethods[0])) != JNI_OK) {
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
}

}  // namespace osnative
}  // namespace macapk
