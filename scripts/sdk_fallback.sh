# sdk_fallback.sh -- SOURCED (not executed) by every script that compiles and
# links: runtime/scripts/build.sh, scripts/build_launcher.sh, debug/gates.sh.
#
# ⚠ INTERIM -- RETIRE WHEN XCODE 27 IS INSTALLED (tracked in Current_State.md,
# "Per-APK patches (to retire)" -> interim rows). Added 2026-10-03 (v1.0.1701).
#
# WHY. On 2026-10-03 this Mac upgraded itself to macOS 27.0.1 and Software
# Update moved the Command Line Tools to the macOS 27 SDK, while Xcode stayed at
# 26.6. xcode-select points at Xcode, so its linker (ld-1267) is the one that
# runs, and it cannot read the 27 SDK's text stubs:
#   MacOSX27.0.sdk/usr/lib/libSystem.B.tbd:4:20: error: unknown architecture
#     arm64e.x1-macos, arm64e.x1-maccatalyst ]
# so EVERY link against the default SDK fails (cmake targets, swiftc, the gates'
# own C harnesses), for every session on this machine.
#
# WHAT IT DOES. Probes once whether a trivial C program links with the current
# setup (SDKROOT if the caller set one, else the default SDK). If it does, it
# changes nothing. If it does not, it tries every installed versioned macOS SDK,
# newest first, exports SDKROOT to the first one the active linker can link
# against, and prints ONE loud line naming both SDKs. It never pins silently, and
# it never changes anything on a machine whose toolchain is consistent.
# MACAPK_NO_SDK_FALLBACK=1 disables it (to see the raw failure).
macapk_sdk_fallback() {
  [ -n "${MACAPK_SDK_FALLBACK_DONE:-}" ] && return 0
  export MACAPK_SDK_FALLBACK_DONE=1
  [ "$(uname -s)" = Darwin ] || return 0
  [ "${MACAPK_NO_SDK_FALLBACK:-0}" = 1 ] && return 0
  command -v clang >/dev/null 2>&1 || return 0
  local t sdk def ver err
  t=$(mktemp -d "${TMPDIR:-/tmp}/macapk_sdkprobe.XXXXXX") || return 0
  printf 'int main(void){return 0;}\n' > "$t/p.c"
  if clang "$t/p.c" -o "$t/p" > "$t/err" 2>&1; then rm -rf "$t"; return 0; fi
  err=$(grep -m1 -i 'error' "$t/err" | cut -c1-160)
  def=${SDKROOT:-$(xcrun --show-sdk-path 2>/dev/null)}
  [ -n "$def" ] && def=$(cd "$def" 2>/dev/null && pwd -P || echo "$def")
  # Versioned SDK bundles only (MacOSX26.5.sdk, not the MacOSX.sdk symlink),
  # from both the CLT and the selected Xcode, newest version first.
  for sdk in $( { ls -d /Library/Developer/CommandLineTools/SDKs/MacOSX[0-9]*.[0-9]*.sdk \
                         "$(xcode-select -p 2>/dev/null)"/Platforms/MacOSX.platform/Developer/SDKs/MacOSX[0-9]*.[0-9]*.sdk \
                         2>/dev/null; } \
                 | while read -r p; do ver=${p##*/MacOSX}; echo "${ver%.sdk} $p"; done \
                 | sort -r -V -k1,1 | awk '{print $2}'); do
    [ "$sdk" = "$def" ] && continue
    if SDKROOT="$sdk" clang "$t/p.c" -o "$t/p" > /dev/null 2>&1; then
      export SDKROOT="$sdk"
      echo "[sdk] ⚠⚠ INTERIM SDK FALLBACK (retire when Xcode 27 is installed): the active linker ($(ld -v 2>&1 | head -1 | sed 's/.*PROJECT://')) cannot link against the default SDK ${def:-?} (${err:-link failed}); building against $sdk instead (SDKROOT exported). scripts/sdk_fallback.sh" >&2
      rm -rf "$t"; return 0
    fi
  done
  echo "[sdk] ✗ no installed macOS SDK links with the active linker (default ${def:-?}: ${err:-link failed}); install Xcode matching the Command Line Tools" >&2
  rm -rf "$t"; return 1
}
macapk_sdk_fallback || true
