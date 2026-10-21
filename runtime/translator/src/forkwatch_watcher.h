// forkwatch_watcher.h -- the body of the "an app's forks die with the app"
// watcher (see bionic_shim_forkwatch.cpp's banner for the AOSP contract), shared
// by the two images that can run it:
//   * macapk-elfexec --macapk-forkwatch <app pid>  (elfexec_main.cpp) -- the
//     NORMAL path: a fresh, libSystem-only image the shim posix_spawn()s, so the
//     watcher holds nothing of the app's address space;
//   * a double fork() of the app itself (bionic_shim_forkwatch.cpp) -- only when
//     that helper is missing or refuses the mode (a stale bundle).
//
// WHY A FRESH IMAGE (2026-10-01 review of v1.0.1659). The first version always
// ran this as a fork() grandchild of the app. A fork shares every pre-fork
// anonymous page copy-on-write; once the app REWRITES such a page (every GC
// cycle, every malloc churn) the app gets a new copy and the ORIGINAL stays
// resident for as long as the watcher lives -- i.e. for the app's whole life.
// Measured: a 128 MB buffer rewritten by the parent stays 128 MB resident in an
// idle fork child (mincore MINCORE_INCORE, child side) while the parent holds its
// own 128 MB. No per-process tool shows it (the child's RSS/footprint stay ~1
// MB: the pages are mapped in no pmap), so it is invisible memory on an 8 GB box.
//
// Everything below runs only async-signal-safe calls (close, sigaction,
// sigprocmask, setsid, kqueue/kevent, read, write, kill, proc_pidinfo,
// proc_listchildpids, _exit): in the fallback it is a fork of a multithreaded
// JVM, where any lock another thread held at fork time stays held forever.
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <libproc.h>
#include <signal.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <unistd.h>

namespace macapk_forkwatch {
namespace {

struct Rec {                 // 24 bytes: one write() < PIPE_BUF is atomic
    int32_t  pid;
    uint32_t pad;
    uint64_t sec;
    uint64_t usec;
};

bool start_time(pid_t pid, uint64_t* sec, uint64_t* usec) {
    struct proc_bsdinfo bi;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, (int) sizeof bi) != (int) sizeof bi)
        return false;
    *sec = bi.pbi_start_tvsec;
    *usec = bi.pbi_start_tvusec;
    return true;
}

// ---- async-signal-safe helpers used inside the watcher --------------------
void put(char*& p, const char* s) { while (*s) *p++ = *s++; }
void put_num(char*& p, long v) {
    char t[24]; int n = 0;
    if (v < 0) { *p++ = '-'; v = -v; }
    do { t[n++] = char('0' + v % 10); v /= 10; } while (v && n < 23);
    while (n) *p++ = t[--n];
}

constexpr int kMaxRecs = 4096;
Rec g_recs[kMaxRecs];        // watcher-only storage (BSS, untouched in the app)
int g_nrecs = 0;

bool rec_alive(const Rec& r) {
    uint64_t s = 0, u = 0;
    return r.pid > 0 && start_time(r.pid, &s, &u) && s == r.sec && u == r.usec;
}

void add_rec(const Rec& r) {
    if (g_nrecs == kMaxRecs) {           // full: drop records whose process is gone
        int k = 0;
        for (int i = 0; i < g_nrecs; ++i)
            if (rec_alive(g_recs[i])) g_recs[k++] = g_recs[i];
        g_nrecs = k;
        if (g_nrecs == kMaxRecs) return; // 4096 live forks: nothing sane left to do
    }
    g_recs[g_nrecs++] = r;
}

void drain(int rfd, bool* eof) {
    Rec buf[64];
    for (;;) {
        ssize_t n = ::read(rfd, buf, sizeof buf);
        if (n > 0) {
            for (size_t i = 0; i < (size_t) n / sizeof(Rec); ++i) add_rec(buf[i]);
            continue;
        }
        if (n == 0) *eof = true;
        return;                          // EAGAIN (non-blocking) or EOF
    }
}

// SIGKILL `pid`'s descendants deepest first, then `pid`. Fixed stack, no malloc.
int kill_tree(pid_t pid, int depth) {
    int killed = 0;
    if (depth < 16) {
        pid_t kids[256];
        int n = proc_listchildpids(pid, kids, (int) sizeof kids);
        if (n > 256) n = 256;
        for (int i = 0; i < n; ++i)
            if (kids[i] > 1 && kids[i] != pid) killed += kill_tree(kids[i], depth + 1);
    }
    if (::kill(pid, SIGKILL) == 0) ++killed;
    return killed;
}

[[noreturn]] void watcher_main(int rfd, pid_t app) {
    // Leave the app's process group AND session. AOSP's killProcessGroup works on
    // the app's cgroup, whatever group or session a fork moved itself into; a
    // watcher left in the app's group dies with a group-wide SIGKILL (kill -9
    // -<pgid>) at the same instant as the app, so a fork that had called
    // setsid() would survive with nobody left to end it. Async-signal-safe.
    ::setsid();
    // Signals: a fault here must just end the watcher (no inherited JVM/shim
    // handler), and a group-wide termination signal must not stop it early.
    struct sigaction dfl;
    std::memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    for (int s = 1; s < NSIG; ++s)
        if (s != SIGKILL && s != SIGSTOP) ::sigaction(s, &dfl, nullptr);
    struct sigaction ign = dfl;
    ign.sa_handler = SIG_IGN;
    const int ignored[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGTSTP,
                           SIGTTIN, SIGTTOU, SIGUSR1, SIGUSR2, SIGALRM, SIGVTALRM, SIGPROF};
    for (int s : ignored) ::sigaction(s, &ign, nullptr);
    sigset_t none;
    sigemptyset(&none);
    ::sigprocmask(SIG_SETMASK, &none, nullptr);

    // Close every inherited descriptor except the pipe and fd 2 (the run log).
    for (int round = 0; round < 64; ++round) {
        static struct proc_fdinfo fds[1024];
        int bytes = proc_pidinfo(::getpid(), PROC_PIDLISTFDS, 0, fds, (int) sizeof fds);
        if (bytes <= 0) break;
        int n = bytes / (int) sizeof(struct proc_fdinfo), closed = 0;
        for (int i = 0; i < n; ++i) {
            int fd = fds[i].proc_fd;
            if (fd == rfd || fd == 2) continue;
            ::close(fd);
            ++closed;
        }
        if (!closed) break;
    }

    int kq = ::kqueue();
    bool app_dead = false, eof = false;
    if (kq >= 0) {
        // EV_RECEIPT: the registering call returns one receipt per change at
        // once (EV_ERROR set, data = 0 or the errno) and consumes NO real event.
        // Without it this call would also WAIT, and a NOTE_EXIT delivered to it
        // (EV_ONESHOT: never again) would be lost if it were not handled here.
        struct kevent ch[2];
        EV_SET(&ch[0], app, EVFILT_PROC, EV_ADD | EV_ONESHOT | EV_RECEIPT, NOTE_EXIT, 0, nullptr);
        EV_SET(&ch[1], rfd, EVFILT_READ, EV_ADD | EV_RECEIPT, 0, 0, nullptr);
        struct kevent res[2];
        int n = ::kevent(kq, ch, 2, res, 2, nullptr);
        // ESRCH on the proc filter: the app is already gone.
        for (int i = 0; i < n; ++i)
            if ((res[i].flags & EV_ERROR) && res[i].data != 0 && res[i].filter == EVFILT_PROC)
                app_dead = true;
        if (n < 0 && errno == ESRCH) app_dead = true;
        while (!app_dead) {
            struct kevent ev;
            int m = ::kevent(kq, nullptr, 0, &ev, 1, nullptr);
            if (m < 0) {
                if (errno == EINTR) continue;
                break;                   // cannot wait any more: fall through and act
            }
            if (m == 0) continue;
            if (ev.filter == EVFILT_PROC && (ev.fflags & NOTE_EXIT)) { app_dead = true; break; }
            if (ev.filter == EVFILT_READ) {
                drain(rfd, &eof);
                if (eof) {               // every writer closed: stop polling the pipe
                    struct kevent del;
                    EV_SET(&del, rfd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
                    ::kevent(kq, &del, 1, nullptr, 0, nullptr);
                }
            }
        }
    } else {
        // No kqueue: poll the app's existence (never expected; keeps the contract).
        while (::kill(app, 0) == 0 || errno == EPERM) ::usleep(200000);
    }
    drain(rfd, &eof);

    int victims = 0;
    for (int i = 0; i < g_nrecs; ++i)
        if (rec_alive(g_recs[i])) victims += kill_tree(g_recs[i].pid, 0);
    if (victims) {
        char line[160], *p = line;
        put(p, "[forkwatch] app pid ");
        put_num(p, app);
        put(p, " exited; SIGKILLed ");
        put_num(p, victims);
        put(p, " of its forked process(es) (AOSP killProcessGroup)\n");
        ssize_t w = ::write(2, line, (size_t) (p - line));
        (void) w;
    }
    ::_exit(0);
}


}  // namespace
}  // namespace macapk_forkwatch
