// jit_wx_guard.h
//
// Keeps HotSpot's per-thread JIT write mode intact across the dyld calls libjvm
// makes. On macOS 27, when the kernel turns on hardware TPRO for a process
// (dyld_hw_tpro=1 in apple[], seen on Macs with SIP disabled), dyld rewrites
// the thread's whole permission register around dlopen and friends, and that
// write also flips the MAP_JIT write/execute bit back to EXECUTE. HotSpot caches
// the mode it last asked for, so after the dlopen of libjava in
// Threads::create_vm its next code-cache write faults in CodeHeap::allocate and
// the VM aborts before any app code runs. Every app fails the same way.
//
// InstallJvmJitWxGuard() rebinds libjvm's imports of the dyld entry points and
// of pthread_jit_write_protect_np (fishhook, libjvm only): the wrappers record
// the mode HotSpot asked for on each thread and re-assert WRITE after a dyld
// call when that is what HotSpot last asked for. Nothing else changes; on a Mac
// without TPRO the re-assert is a no-op write of the value already there.
//
// Env (diagnostic only):
//   MACAPK_JIT_WX_GUARD=0           do not install (bisect).
//   MACAPK_JIT_WX_SIMULATE_RESET=1  after every wrapped dyld call, switch the
//                                   thread to EXECUTE the way TPRO does, to
//                                   reproduce the crash on a Mac that lacks
//                                   TPRO. With the guard off it crashes in
//                                   CodeHeap::allocate; with it on, the VM boots.
//
// See docs/macos27-tpro-jit-wx-reset_2026-10-19.md.

#pragma once

namespace macapk {

// Call before JNI_CreateJavaVM, once libjvm is loaded. Idempotent.
void InstallJvmJitWxGuard();

// One stderr line with how many dyld calls and WX switches the wrappers saw.
// A guard that saw zero WX switches is not wired in.
void LogJvmJitWxGuardStats();

}  // namespace macapk
