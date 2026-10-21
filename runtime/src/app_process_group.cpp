// app_process_group.cpp -- see include/macapk/app_process_group.h for the AOSP
// contract (ProcessRecord.killLocked -> killProcessGroup) and the mapping.
#include "macapk/app_process_group.h"

#include <libproc.h>
#include <signal.h>
#include <string>
#include <cstring>

namespace macapk {
namespace {

std::string PathOf(pid_t pid) {
    char buf[PROC_PIDPATHINFO_MAXSIZE];
    int n = proc_pidpath(pid, buf, sizeof(buf));
    return n > 0 ? std::string(buf, (size_t) n) : std::string();
}

// Direct children of `ppid`. proc_listchildpids returns a COUNT of pids
// (xnu libsyscall/wrappers/libproc/libproc.c: `return numpids / sizeof(int)`
// over proc_listpids' byte count), and a short buffer truncates silently, so
// grow until the answer fits with room to spare.
std::vector<pid_t> ChildrenOf(pid_t ppid) {
    std::vector<pid_t> out(64);
    for (int attempt = 0; attempt < 6; ++attempt) {
        int n = proc_listchildpids(ppid, out.data(), (int) (out.size() * sizeof(pid_t)));
        if (n < 0) return {};
        if ((size_t) n < out.size()) { out.resize((size_t) n); return out; }
        out.resize(out.size() * 4);
    }
    return out;
}

bool IsAppOwned(pid_t pid, const std::string& self_path) {
    std::string p = PathOf(pid);
    if (p.empty()) return false;              // gone, or not ours to inspect
    if (!self_path.empty() && p == self_path) return true;   // un-exec'd fork
    size_t slash = p.rfind('/');
    const char* base = p.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    return std::strcmp(base, "macapk-elfexec") == 0;          // APK native executable
}

void Walk(pid_t parent, const std::string& self_path, std::vector<pid_t>& victims, int depth) {
    if (depth > 16) return;                   // a fork bomb is not worth a stack
    for (pid_t c : ChildrenOf(parent)) {
        if (c <= 0 || c == parent) continue;
        if (!IsAppOwned(c, self_path)) continue;   // a SYSTEM-role child: not walked, not killed
        Walk(c, self_path, victims, depth + 1);    // its descendants first
        victims.push_back(c);
    }
}

}  // namespace

std::vector<pid_t> KillAppProcessGroup(pid_t root, int sig, bool dry_run,
                                       const char* self_path) {
    std::string self = (self_path && self_path[0]) ? std::string(self_path) : PathOf(root);
    std::vector<pid_t> victims;
    Walk(root, self, victims, 0);
    if (!dry_run) {
        for (pid_t v : victims) ::kill(v, sig);
    }
    return victims;
}

}  // namespace macapk
