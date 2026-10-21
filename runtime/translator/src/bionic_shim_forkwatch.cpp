// bionic_shim_forkwatch.cpp -- an app's forked processes die with the app, on
// EVERY kind of app death, the way they do on a device.
//
// THE AOSP CONTRACT. When an app process dies for any reason -- killed, crashed,
// exited -- ActivityManagerService.appDiedLocked runs, and ProcessRecord.killLocked
// (frameworks/base/services/core/java/com/android/server/am/ProcessRecord.java,
// android14-release :1208-1213) does
//     Process.killProcessQuiet(mPid);
//     killProcessGroupIfNecessaryLocked(asyncKPG);
// which ends in libprocessgroup's killProcessGroup(uid, initialPid, SIGKILL)
// (system/core/libprocessgroup/processgroup.cpp:537): SIGKILL to every pid in the
// app's cgroup "uid_<uid>/pid_<initialPid>", i.e. every process the app forked at
// any depth, whatever process group or session it moved itself into. So on a
// device a fork child can never outlive its app.
//
// WHAT WE HAD. runtime/src/app_process_group.cpp (MACAPK_QUIT_PROCESS_GROUP)
// kills the app-owned descendants on OUR quit paths only (window close, Cmd-Q,
// Dock Quit -> macapk_terminate_now). A SIGTERM from the launcher / Activity
// Monitor / a harness, a SIGKILL, or a crash took the default action and the
// forks were re-parented to launchd. Measured on Instagram 2026-09-30: its
// ForkJail child (libstartup.so facebook::forkjail::ForkJail::forkAndRun, a
// clone(CLONE_CHILD_CLEARTID|SIGCHLD) fork) was still alive at ppid 1, ~100% CPU,
// 1.4 MB RSS, 10 s after the runtime was SIGTERMed (ORPHANS_AFTER_10s=1 via
// debug/scratch_bundle_run.sh --orphan-wait 10). (Why it SPUN is a separate bug,
// the raw exit_group that returned -ENOSYS; see case 94 in __macapk_arm64_syscall.)
//
// THE MAPPING. macOS has no cgroup and no PR_SET_PDEATHSIG, and nothing inside a
// SIGKILLed process can act, so "the system notices the app died" needs a
// process that is NOT the app: a small watcher that holds a kqueue
// EVFILT_PROC/NOTE_EXIT on the app pid (kqueue(2): "NOTE_EXIT The process has
// exited") and, when it fires, SIGKILLs every fork the app registered with it
// plus their descendants. It is started lazily, just before the app's FIRST fork
// (an app that never forks never gets one), and the app's fork paths register
// each child: the Linux clone() fork shape in the raw syscall router and the
// by-name fork() shim below.
//
// SHAPE DECISIONS (each one measured or forced):
//   * The watcher is a FRESH IMAGE, not a copy of the app: the shim
//     posix_spawn()s the sibling helper `macapk-elfexec --macapk-forkwatch <pid>`
//     (libSystem only; POSIX_SPAWN_CLOEXEC_DEFAULT hands it exactly the pipe as
//     fd 3 and fd 2). A fork() of the app would pin, copy-on-write, every
//     pre-fork page the app later rewrites for the app's whole life (measured;
//     forkwatch_watcher.h). Only if that helper is missing or refuses the mode
//     (exit status != 0: a stale bundle) does the shim fall back to running the
//     same watcher as a double fork() of the app.
//   * Either way the watcher is a GRANDCHILD (the spawned/forked intermediate
//     forks it and exits at once; the app reaps the intermediate) so it is NOT
//     the app's child: a guest that reaps "all my children" with a blocking
//     waitpid(-1) loop, or counts them, sees exactly the processes it forked, as
//     on a device. It is re-parented to launchd at once and setsid()s itself out
//     of the app's group and session; kqueue proc filters work on any same-uid
//     process, not just children.
//   * Every record carries the child's start time (proc_bsdinfo pbi_start_tv*),
//     and the watcher re-checks it before signalling, so a pid that died and was
//     REUSED by an unrelated process is never killed.
//   * The watcher (forkwatch_watcher.h) runs only async-signal-safe calls (it
//     may be a fork of a multithreaded JVM in the fallback), closes every
//     inherited fd but its pipe and fd 2 (a pipe write end it kept would hide EOF
//     from whoever reads that pipe) and ignores the job-control/termination
//     signals a whole process group can be sent.
//   * The pipe's write end is O_NONBLOCK (a stuck watcher must never block an
//     app's fork) and FD_CLOEXEC (an exec'd program is not a fork of the app and
//     keeps none of the app's state); a fork of a fork inherits it, so
//     grandchildren register with the SAME watcher and die with the app too.
//
// MACAPK_FORK_WATCHER (default ON). "0": no watcher is started and nothing is
// registered, so every fork path does exactly what it did before (the fork()
// shim is then a bare ::fork(), the same call a guest's fork import used to bind
// to directly).
//
// Self-contained on purpose (libc + libproc only): debug/forkwatch_gate.sh drives
// it through the SAME shim dylib (and sibling macapk-elfexec) the runtime loads.

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <climits>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "forkwatch_watcher.h"

using namespace macapk_forkwatch;

namespace {

bool watcher_on() {
    static const bool on = [] {
        const char* e = std::getenv("MACAPK_FORK_WATCHER");
        return !(e && e[0] == '0');
    }();
    return on;
}

// 0 = not started, 1 = starting, 2 = running (g_wfd valid), -1 = off / failed.
std::atomic<int> g_state{0};
std::atomic<int> g_wfd{-1};
// Identity of the registration pipe's write end. A fork child inherits g_wfd as
// a bare NUMBER: if the guest closed that descriptor (a daemon's close-all, a
// double close) and the number was reused, a registration would write 24 binary
// bytes into whatever file or socket now holds it. register checks first.
dev_t g_wdev = 0;
ino_t g_wino = 0;

// `macapk-elfexec` next to this dylib (runtime/build/bin, a bundle's
// Contents/bin, the staged shared runtime's bin/ -- see build.sh
// sync_payload_into). Empty when it cannot be found.
bool helper_path(char* out, size_t cap) {
    Dl_info di;
    if (!::dladdr(reinterpret_cast<const void*>(&helper_path), &di) || !di.dli_fname) return false;
    const char* slash = std::strrchr(di.dli_fname, '/');
    const size_t dir = slash ? (size_t) (slash - di.dli_fname) : 0;
    static const char kName[] = "macapk-elfexec";
    if (!slash || dir + 1 + sizeof kName > cap) return false;
    std::memcpy(out, di.dli_fname, dir);
    out[dir] = '/';
    std::memcpy(out + dir + 1, kName, sizeof kName);
    return ::access(out, X_OK) == 0;
}

// Spawn `macapk-elfexec --macapk-forkwatch <app>` with `rfd` as its fd 3. It
// forks the watcher and exits 0; returns that intermediate's pid, or -1.
pid_t spawn_helper(int rfd, pid_t app) {
    char path[PATH_MAX];
    if (!helper_path(path, sizeof path)) return -1;
    int dupfd = -1;                      // dup2(3, 3) would leave FD_CLOEXEC set
    if (rfd == 3) {
        dupfd = ::fcntl(rfd, F_DUPFD_CLOEXEC, 4);
        if (dupfd < 0) return -1;
        rfd = dupfd;
    }
    char appbuf[24], *p = appbuf;
    put_num(p, (long) app);
    *p = 0;
    char arg0[] = "macapk-elfexec", arg1[] = "--macapk-forkwatch";
    char* argv[] = {arg0, arg1, appbuf, nullptr};
    char* envp[] = {nullptr};
    pid_t mid = -1;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    if (::posix_spawn_file_actions_init(&fa) == 0) {
        if (::posix_spawnattr_init(&at) == 0) {
            // CLOEXEC_DEFAULT: the helper starts with ONLY fd 3 (the pipe) and
            // fd 2 -- none of the app's files, sockets or pipes.
            ::posix_spawn_file_actions_adddup2(&fa, rfd, 3);
            if (::fcntl(2, F_GETFD) != -1) ::posix_spawn_file_actions_addinherit_np(&fa, 2);
            sigset_t none, all;
            sigemptyset(&none);
            sigfillset(&all);
            ::posix_spawnattr_setsigmask(&at, &none);
            ::posix_spawnattr_setsigdefault(&at, &all);
            ::posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT |
                                            POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
            if (::posix_spawn(&mid, path, &fa, &at, argv, envp) != 0) mid = -1;
            ::posix_spawnattr_destroy(&at);
        }
        ::posix_spawn_file_actions_destroy(&fa);
    }
    if (dupfd >= 0) ::close(dupfd);
    return mid;
}

// Reap the intermediate; true when it exited 0 (the watcher is running).
bool reaped_ok(pid_t mid) {
    int status = 0;
    while (::waitpid(mid, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}  // namespace

// Start the watcher if it is not running yet. Called by every app fork path
// BEFORE it forks, so the child inherits the registration pipe.
extern "C" __attribute__((visibility("default")))
void __macapk_forkwatch_before_fork(void) {
    if (!watcher_on()) return;
    int st = g_state.load();
    if (st == 2 || st == -1) return;
    int expected = 0;
    if (!g_state.compare_exchange_strong(expected, 1)) {
        // Another thread is starting it: wait (bounded) so our registration lands.
        for (int i = 0; i < 2000 && g_state.load() == 1; ++i) ::usleep(1000);
        return;
    }
    int p[2];
    if (::pipe(p) != 0) { g_state.store(-1); return; }
    ::fcntl(p[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(p[1], F_SETFD, FD_CLOEXEC);
    ::fcntl(p[0], F_SETFL, O_NONBLOCK);
    ::fcntl(p[1], F_SETFL, O_NONBLOCK);
    // A registration written after the watcher is gone must fail with EPIPE,
    // never raise SIGPIPE (whose default action would kill the app).
    ::fcntl(p[1], F_SETNOSIGPIPE, 1);
    {
        struct stat st;
        if (::fstat(p[1], &st) == 0) { g_wdev = st.st_dev; g_wino = st.st_ino; }
    }
    const pid_t app = ::getpid();
    // NORMAL PATH: a fresh image (see the banner and forkwatch_watcher.h).
    const pid_t spawned = spawn_helper(p[0], app);
    if (!(spawned > 0 && reaped_ok(spawned))) {
        // FALLBACK (helper missing / stale, or spawn failed): the same watcher as
        // a double fork() of the app. Costs the copy-on-write pin, never a fork.
        pid_t mid = ::fork();
        if (mid == 0) {
            // Intermediate: fork the watcher and leave at once, so the watcher is
            // a grandchild (re-parented to launchd), never a child the app can
            // wait on.
            pid_t w = ::fork();
            if (w == 0) {
                ::close(p[1]);
                watcher_main(p[0], app);
            }
            ::_exit(w > 0 ? 0 : 1);
        }
        if (mid < 0 || !reaped_ok(mid)) {
            ::close(p[0]);
            ::close(p[1]);
            g_state.store(-1);
            return;
        }
    }
    ::close(p[0]);
    g_wfd.store(p[1]);
    g_state.store(2);
}

// Record `child` (just forked by the app, or by one of the app's forks) with the
// watcher. Parent side only.
extern "C" __attribute__((visibility("default")))
void __macapk_forkwatch_register(pid_t child) {
    if (child <= 0 || g_state.load() != 2) return;
    Rec r{};
    r.pid = child;
    if (!start_time(child, &r.sec, &r.usec)) return;   // already gone: nothing to kill
    const int saved = errno;
    const int fd = g_wfd.load();
    struct stat st;
    if (::fstat(fd, &st) != 0 || st.st_ino != g_wino || st.st_dev != g_wdev) {
        errno = saved;                   // not our pipe any more: never write into it
        return;
    }
    ssize_t w = ::write(fd, &r, sizeof r);
    (void) w;                            // EAGAIN: a stuck watcher never blocks a fork
    errno = saved;
}

// The watcher's pid-independent state for the gate: 2 when running.
extern "C" __attribute__((visibility("default")))
int __macapk_forkwatch_state(void) { return g_state.load(); }

// Bionic fork(). The call itself is unchanged -- the guest used to bind straight
// to libSystem fork(), and ::fork() is that call -- plus the registration that
// lets the child die with the app (see the banner).
extern "C" __attribute__((visibility("default")))
pid_t __macapk_arm64_fork(void) {
    __macapk_forkwatch_before_fork();
    pid_t r = ::fork();
    if (r > 0) {
        const int saved = errno;
        __macapk_forkwatch_register(r);
        errno = saved;
    }
    return r;
}
