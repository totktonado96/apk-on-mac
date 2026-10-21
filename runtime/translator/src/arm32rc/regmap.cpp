// regmap.cpp -- implementation of the guest ARM32 -> host arm64
// register map declared in regmap.h.
//
// Everything here is translate-time only: it runs inside the
// translator process while it is emitting code, never inside the
// translated program. That makes correctness far more valuable than
// speed, so the self-test is exhaustive and the queries are simple
// linear scans over 16- and 32-element tables.
//
// C++17. No em dashes (project convention).

#include "regmap.h"

#include <cstdio>

namespace macapk::arm32rc {

// =====================================================================
// Reverse map
// =====================================================================

int guest_for_host_gpr(HostGpr h) {
    if (h == HostGpr::kNone) return -1;
    for (int i = 0; i < kNumGuestGpr; ++i)
        if (kGuestGprHome[i] == h) return i;
    return -1;
}

// =====================================================================
// Classification
// =====================================================================

bool host_gpr_is_reserved(HostGpr h) {
    return h == kHostReservedPlatform ||   // x18, platform-reserved by Apple
           h == kHostGuestBase        ||   // x28, guest memory arena base
           h == kHostFramePointer     ||   // x29, frame record
           h == kHostLinkRegister;         // x30
}

bool host_gpr_is_guest_home(HostGpr h) {
    return guest_for_host_gpr(h) >= 0;
}

bool host_gpr_is_scratch(HostGpr h) {
    for (int i = 0; i < kNumScratchGpr; ++i)
        if (kScratchGpr[i] == h) return true;
    return false;
}

// AAPCS64 Table 2 "General-purpose registers and AAPCS64 usage":
// r0-r7 parameter/result (Caller-saved), r8 indirect result location
// (Caller-saved), r9-r15 Caller-saved, r16/r17 IP0/IP1 usable as
// Caller-saved, r18 the Platform Register, r19-r28 Callee-saved,
// r29 FP, r30 LR.
//
// x18 answers TRUE here only in the narrow sense that the base standard
// would call it caller-saved when unused as a platform register. On
// Apple platforms it is reserved outright and host_gpr_is_reserved()
// is the query that matters.
bool host_gpr_is_caller_saved(HostGpr h) {
    if (h == HostGpr::kNone) return false;
    const uint8_t n = static_cast<uint8_t>(h);
    if (n <= 17) return true;                 // x0-x17
    if (n == 18) return true;                 // x18, but see note above
    if (n >= 19 && n <= 28) return false;     // x19-x28 callee-saved
    return false;                             // x29 / x30 / sp
}

bool host_vec_is_scratch(HostVec v) {
    for (int i = 0; i < kNumScratchVec; ++i)
        if (kScratchVec[i] == v) return true;
    return false;
}

// =====================================================================
// ScratchSet
// =====================================================================

HostGpr ScratchSet::acquire() {
    for (int i = 0; i < kNumScratchGpr; ++i) {
        const uint32_t bit = 1u << i;
        if (!(gpr_taken_ & bit)) {
            gpr_taken_ |= bit;
            return kScratchGpr[i];
        }
    }
    // A translator bug, not a runtime condition. No single ARM32
    // instruction lowering needs more than a handful of temporaries.
    std::fprintf(stderr, "[arm32rc] FATAL: GPR scratch pool exhausted\n");
    return HostGpr::kNone;
}

HostVec ScratchSet::acquire_vec() {
    for (int i = 0; i < kNumScratchVec; ++i) {
        const uint32_t bit = 1u << i;
        if (!(vec_taken_ & bit)) {
            vec_taken_ |= bit;
            return kScratchVec[i];
        }
    }
    std::fprintf(stderr, "[arm32rc] FATAL: vector scratch pool exhausted\n");
    return HostVec::kNone;
}

void ScratchSet::release(HostGpr h) {
    for (int i = 0; i < kNumScratchGpr; ++i)
        if (kScratchGpr[i] == h) { gpr_taken_ &= ~(1u << i); return; }
}

void ScratchSet::release(HostVec v) {
    for (int i = 0; i < kNumScratchVec; ++i)
        if (kScratchVec[i] == v) { vec_taken_ &= ~(1u << i); return; }
}

void ScratchSet::release_all() {
    gpr_taken_ = 0;
    vec_taken_ = 0;
}

void ScratchSet::reserve(HostGpr h) {
    for (int i = 0; i < kNumScratchGpr; ++i)
        if (kScratchGpr[i] == h) { gpr_taken_ |= (1u << i); return; }
}

// =====================================================================
// Names and symbol suffixes
// =====================================================================

const char* host_gpr_name(HostGpr h) {
    static const char* kNames[32] = {
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
        "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp/zr",
    };
    if (h == HostGpr::kNone) return "<none>";
    const uint8_t n = static_cast<uint8_t>(h);
    return (n < 32) ? kNames[n] : "<bad>";
}

const char* host_vec_name(HostVec v) {
    static const char* kNames[32] = {
        "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",
        "v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
        "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
    };
    if (v == HostVec::kNone) return "<none>";
    const uint8_t n = static_cast<uint8_t>(v);
    return (n < 32) ? kNames[n] : "<bad>";
}

const char* guest_gpr_name(int guest_reg) {
    static const char* kNames[kNumGuestGpr] = {
        "r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    };
    return (guest_reg >= 0 && guest_reg < kNumGuestGpr) ? kNames[guest_reg]
                                                        : "<bad>";
}

const char* recompiled_entry_suffix() { return ""; }
const char* recompiled_fast_suffix()  { return "$rcfast"; }

// =====================================================================
// Stack geometry cross-check
// =====================================================================
//
// guest_state.h mirrors three constants from bionic_shim.cpp because
// that file exposes no header. Silent drift there would put GuestState
// somewhere other than the bottom of the thread's stack slot, which
// means the recompiled code would read and write another thread's guest
// stack as if it were the VFP bank. That failure mode is close to
// undebuggable, so it gets a loud check instead.

bool arm32rc_verify_stack_geometry(uint32_t shim_stack_base,
                                   uint32_t shim_stack_slot,
                                   uint32_t shim_max_threads) {
    bool ok = true;
    if (shim_stack_base != kThreadStackBase) {
        std::fprintf(stderr,
            "[arm32rc] FATAL: kThreadStackBase drift: shim=0x%08x "
            "arm32rc=0x%08x\n", shim_stack_base, kThreadStackBase);
        ok = false;
    }
    if (shim_stack_slot != kThreadStackSlot) {
        std::fprintf(stderr,
            "[arm32rc] FATAL: kThreadStackSlot drift: shim=0x%08x "
            "arm32rc=0x%08x\n", shim_stack_slot, kThreadStackSlot);
        ok = false;
    }
    if (shim_max_threads != kMaxThreads) {
        std::fprintf(stderr,
            "[arm32rc] WARN: kMaxThreads drift: shim=%u arm32rc=%u "
            "(not fatal; only the reserve accounting cares)\n",
            shim_max_threads, kMaxThreads);
    }
    // The AND trick in the design doc only recovers the slot base when
    // the slot size is a power of two and the base is slot-aligned.
    if ((shim_stack_slot & (shim_stack_slot - 1u)) != 0) {
        std::fprintf(stderr,
            "[arm32rc] FATAL: thread stack slot 0x%08x is not a power of "
            "two; the `and w,#mask` slot-base derivation is invalid\n",
            shim_stack_slot);
        ok = false;
    }
    if ((shim_stack_base & (shim_stack_slot - 1u)) != 0) {
        std::fprintf(stderr,
            "[arm32rc] FATAL: thread stack base 0x%08x is not slot "
            "aligned; the slot-base derivation is invalid\n",
            shim_stack_base);
        ok = false;
    }
    return ok;
}

// =====================================================================
// Self-test
// =====================================================================

bool regmap_self_test() {
    bool ok = true;
    auto fail = [&ok](const char* what) {
        std::fprintf(stderr, "[arm32rc] regmap_self_test FAILED: %s\n", what);
        ok = false;
    };

    // Forward and reverse maps must agree.
    for (int i = 0; i < kNumGuestGpr; ++i) {
        const HostGpr h = host_gpr_for_guest(i);
        if (i == kPC) {
            if (h != HostGpr::kNone) fail("r15 must not have a host home");
            continue;
        }
        if (h == HostGpr::kNone) { fail("guest register without a home"); continue; }
        if (guest_for_host_gpr(h) != i) fail("forward/reverse map disagree");
        if (host_gpr_is_reserved(h))    fail("guest register homed on a reserved host register");
        if (host_gpr_is_scratch(h))     fail("guest register homed on a scratch register");
    }

    // Preservation classes must line up. This is the property that makes
    // guest r4-r11 and guest SP survive a call into a clang-compiled
    // shim with no save/restore code of our own.
    for (int i = 0; i < kNumGuestGpr; ++i) {
        if (i == kPC) continue;
        const bool guest_saved = guest_gpr_is_callee_saved(i);
        const bool host_saved  = !host_gpr_is_caller_saved(host_gpr_for_guest(i));
        if (guest_saved != host_saved) fail("AAPCS32/AAPCS64 preservation mismatch");
    }

    // The scratch pools must not touch anything that matters.
    for (int i = 0; i < kNumScratchGpr; ++i) {
        if (host_gpr_is_reserved(kScratchGpr[i]))   fail("scratch pool contains a reserved register");
        if (host_gpr_is_guest_home(kScratchGpr[i])) fail("scratch pool contains a guest home");
        if (!host_gpr_is_caller_saved(kScratchGpr[i]))
            fail("scratch pool contains a callee-saved register (would need save/restore)");
    }
    for (int i = 0; i < kNumScratchVec; ++i) {
        const uint8_t n = static_cast<uint8_t>(kScratchVec[i]);
        if (n >= 8 && n <= 15)
            fail("vector scratch pool contains v8-v15 (callee-saved low 64 bits)");
    }

    // x18 must appear nowhere at all.
    if (host_gpr_is_guest_home(HostGpr::X18)) fail("x18 holds guest state");
    if (host_gpr_is_scratch(HostGpr::X18))    fail("x18 is in the scratch pool");

    // Pool exhaustion behaviour.
    {
        ScratchSet s;
        for (int i = 0; i < kNumScratchGpr; ++i)
            if (s.acquire() == HostGpr::kNone) { fail("scratch pool exhausted early"); break; }
        s.release_all();
        if (s.acquire() == HostGpr::kNone) fail("release_all did not free the pool");
    }

    // GuestState placement math.
    for (uint32_t slot = 0; slot < kMaxThreads; ++slot) {
        const uint32_t base = guest_state_vaddr_for_slot(slot);
        const uint32_t sp   = base + kThreadStackSlot - 16u;   // what the shim hands out
        if (guest_state_vaddr_for_sp(sp) != base)
            fail("guest_state_vaddr_for_sp does not recover the slot base");
        if (base < kThreadStackBase) fail("slot base below the stack region");
    }

    if (ok) {
        std::fprintf(stderr,
            "[arm32rc] regmap_self_test OK: %d guest GPRs pinned, "
            "%d GPR scratch, %d vector scratch, GuestState %zu bytes at "
            "slot+0\n",
            kNumGuestGpr - 1, kNumScratchGpr, kNumScratchVec,
            sizeof(GuestState));
    }
    return ok;
}

}  // namespace macapk::arm32rc
