// app_process_group.h
//
// When an Android app process dies, the system kills its WHOLE process group,
// not just the one pid. AOSP android14-release
// frameworks/base/services/core/java/com/android/server/am/ProcessRecord.java
// killLocked (:1208-1213):
//     Process.killProcessQuiet(mPid);
//     killProcessGroupIfNecessaryLocked(asyncKPG);
// which ends in libprocessgroup's killProcessGroup(uid, initialPid, SIGKILL)
// (system/core/libprocessgroup/processgroup.cpp:537), a loop over every pid in
// the app's cgroup "uid_<uid>/pid_<initialPid>" -- i.e. every process the app
// forked, at any depth. So on a device a child an app fork()ed can never
// outlive the app.
//
// Apk on Mac leaves the process with _exit() (cocoa_bridge.mm
// macapk_terminate_now), and a guest fork() child is re-parented to launchd and
// keeps running: MEASURED on Instagram (lanes18 NN residual, Current_State
// 2026-09-28) as orphaned `.Instagram` processes, ppid 1, ~97% CPU, that
// survive SIGTERM and had to be reaped by hand.
//
// THE MAPPING. macOS has no cgroup, so "the app's process group" is rebuilt
// from the process tree: the descendants of this process that are the APP's
// OWN processes. That is
//   * a fork() child that has not exec'd: its executable is still ours
//     (proc_pidpath == our proc_pidpath) -- the guest clone(SIGCHLD)/fork()
//     shape, which is the Instagram orphan; and
//   * an APK-shipped native executable, which Apk on Mac runs through the
//     macapk-elfexec stand-in (apk_native_exec.cpp kHelperName).
// Everything else a Apk on Mac process spawns plays a SYSTEM role on Android and
// must outlive the app exactly as system_server does there: the install helper
// mid-Touch-ID (PackageInstaller runs in its own process on a device), the
// detached relaunch shell CocoaExitProcess starts, `open` for a cross-app
// launch, pmset/ioreg shell-outs. Those are neither killed nor walked into.
//
// Pure C++ + libproc, no AppKit/JNI, so debug/app_procgroup_gate.sh links the
// SAME translation unit the runtime ships.
#pragma once

#include <sys/types.h>
#include <vector>

namespace macapk {

// Collect (and unless dry_run, signal with `sig`) the app-owned descendants of
// `root` as defined above, deepest first so no victim is re-parented to
// launchd between the walk and the kill. `self_path` is the executable path
// that identifies an un-exec'd fork (normally proc_pidpath(getpid())); empty
// means "look it up for root". Returns the victims (pids), in kill order.
std::vector<pid_t> KillAppProcessGroup(pid_t root, int sig, bool dry_run = false,
                                       const char* self_path = nullptr);

}  // namespace macapk
