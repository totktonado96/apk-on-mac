# Mac.apk translator

Standalone CLI that converts **ARM32 Bionic ELF `.so`** files into **arm64-apple-darwin Mach-O dylibs** that load and run natively on Apple Silicon. No emulation, no virtualization. The output is real ARM64 machine code that the macOS dyld treats like any other dylib, and HotSpot loads via `System.loadLibrary` like any other JNI library.

## Pipeline

```
input.so (ARM32 ELF, Bionic-linked)
   │
   ├── elf_reader.cpp         parse header, segments, symbols, PLT,
   │                          relocations, init_array seeds
   │
   ├── arm32_lifter.cpp       DISCOVERY ONLY on this path: function
   │                          boundaries, external/BL targets, the
   │                          lifted-address map and the synthetic-function
   │                          cascade. Its IR-emission half still compiles
   │                          but nothing consumes it here.
   │
   ├── main.cpp               function discovery (symbols + BL targets +
   │                          init_array seeds + prologue scan), trampoline
   │                          generation for PLT imports, override hooks
   │                          for known-troublesome libstdc++ helpers
   │
   ├── arm32rc/               the recompiler: xlat_core / xlat_mem /
   │                          xlat_simd translate one ARM32 instruction at a
   │                          time, a64_emit encodes one arm64 instruction,
   │                          regmap pins guest r0-r14 onto host registers
   │                          (x18 is NEVER allocated, static_assert-enforced)
   │
   └── macho_link.cpp         writes the Mach-O 64-bit arm64 dylib DIRECTLY.
                              Non-lazy binds only, so every undefined symbol
                              MUST resolve at link time. dlopen-able, and
                              JVM-loadable via System.loadLibrary.
```

⚠ **There is no LLVM IR, no `llvm-as`, no clang and no linker subprocess on
this path.** The lift-to-LLVM-IR pipeline this file used to describe was
replaced by `arm32rc` at **v1.0.802**, and `llvm` + `lld` were dropped from the
project's brew requirements at the same time. `--keep-ir` still writes an IR
text file next to the output, but purely as a debugging artifact that nothing
compiles. If you are reading this file to understand why lifted IR is written
in a verbose virtual-register-file style, that reasoning applied to the old
path only: it existed so LLVM's mem2reg/GVN could fold it back down, and no
optimizer runs on this path any more.

See `docs/arm32rc-integration_2026-07-25.md` for the host-ABI contract and the
sharp edges before editing anything under `src/arm32rc/`.

## Status

### Stage 0 — round-trip prototype (✓ shipped)

End-to-end pipeline validated: the translator builds, translates ARM32 functions for a small instruction subset, and produces a working arm64-apple-darwin Mach-O dylib that dlopen/dlsym/call round-trips. (Historical note: at the time this was validated the backend was lift-to-LLVM-IR plus clang; since v1.0.802 the same round-trip is served by arm32rc emitting Mach-O directly.)

For arithmetic-only functions, three lifted functions compile to:

```
_add:        add w0, w1, w0 ; ret           (2 instructions)
_sub:        sub w0, w0, w1 ; ret           (2 instructions)
_triple_add: add w8, w1, w0
             add w0, w8, w2 ; ret           (3 instructions)
```

Identical to a hand-written native arm64 build.

### Stage 1 — production-quality ARM32 (mostly done)

What's currently lifted on a real cocos2d-x `libgame.so` (3 MB, 31509 functions):

- **All common ARM/Thumb integer instructions**: ADD/SUB/RSB/AND/ORR/EOR/CMP/CMN/TST, MOV/MVN/MOVT/MOVW with immediate composition, MUL/MLA/UMULL/SMULL, SDIV/UDIV.
- **All addressing modes**: immediate offset, register offset, pre/post-indexed with writeback, shifted index, PC-relative literal pool reads.
- **Byte/halfword memory**: STRB/STRH/LDRB/LDRH (signed and unsigned).
- **Multi-register memory**: LDM/STM in IA/IB/DA/DB modes with writeback, including the "base in register list" edge case.
- **Predicated execution**: every conditional variant (EQ/NE/LT/GE/HI/LS/...) emits a `select` on the NZCV flag bits, including IT-block predication in Thumb.
- **VFP**: VLDR/VSTR/VPUSH/VPOP, VMOV in all its forms (D-D, S-S, D-imm, S-imm, D-from-Rlo-Rhi, S-from-R, R-from-S), VADD/VSUB/VMUL/VDIV, VFP unary (VNEG/VABS/VSQRT), VFP fused multiply-accumulate variants (VMLA/VMLS/VNMUL/VNMLA/VNMLS), VCMP + FPSCR + VMRS, VCVT.
- **Function calls**: BL to local addresses (resolved via the addr → symbol map), BL to PLT entries (routed through `__macapk_target_<addr>` trampolines into shim functions or panic stubs for unresolved externals).
- **NEON (partial)**: most common load/store/arithmetic intrinsics. Lifter is lenient — unsupported instructions become a comment + no-op so the rest of the function still lifts.

Per-binary stats for HCR's `libgame.so` at the time of writing: 31509 functions lifted, 17894 via BL/synth discovery, 2814 via `.init_array` seed, 21596 intra-module aliases, 226 import aliases, 2751 unresolved panic stubs (most of which are unused dead code).

### Framework-level overrides (Stage 2)

A handful of lifted symbols get **replaced** with hand-written IR instead of lifted from the original `.so`. These solve issues that no amount of better ARM lifting would fix:

| Replaced symbol | Why |
|-----------------|-----|
| `__cxa_guard_acquire`/`release`/`abort` | Lifted versions deref the guard byte through the host's low-memory layout (wrong) instead of the guest's `.bss` (right). The shim does the bit-test/bit-set on `guest_base + guard_addr`. |
| `__cxa_atexit`/`finalize`, `atexit` | No-ops — statics live until process exit anyway. |
| `_ZN7cocos2d11CCFileUtils24fullPathFromRelativePathEPKc` | RETIRED by default (2026-09-26, `MACAPK_COCOS_OWN_FULLPATH`): the guest's own body (`return pszRelativePath;`) is translated, as a device runs it, and getFileData reads the asset through minizip against the installed base.apk. `MACAPK_COCOS_OWN_FULLPATH=0` or `MACAPK_COCOS_FORCE_FOPEN=1` re-installs the historical override, whose shim can prepend the asset directory. See `docs/cocos-fullpath-override-retired_2026-09-26.md`. |
| `__dynamic_cast` | RETIRED by default (2026-09-26, `MACAPK_ARM32_GUEST_DYNAMIC_CAST`): the image's own libsupc++ / libc++abi body is translated, as a device runs it; the arm32rc translation matched the guest bytes on an ARMv7 CPU in every in-contract cast measured on HCR 1.8.1, HCR 1.43, GD Lite 2.2.11 and JJ 1.3.5. `=0` re-installs the historical host RTTI walker (written for the deleted LLVM lifter's miscompile), which ignores private bases and ARM EABI's by-name type_info compare. See `docs/dynamic-cast-override-retired_2026-09-26.md`. |
| `_ZN7cocos2d7CCImage16_initWithPngDataEPvi` | Lifted libpng corrupts a `png_struct` field after ~95 decoded rows under `-O1`. Routed to host libpng instead. |
| `__aeabi_idiv0`/`__aeabi_ldiv0` | Real ARM EABI raises SIGFPE on divide-by-zero; macOS arm64 silently returns 0. The lifted stubs raised SIGFPE, our handler longjmp'd, and the BMFont parser retried forever. Override returns INT_MAX, matching macOS semantics. |
| Exception-runtime helpers (`__cxa_throw` etc.) | macOS uses Itanium C++ ABI but the symbol set differs from Bionic's. Stubbed to no-op-returning-0; no current APK exercises real C++ exceptions in the hot path. |

### Stage 3 — install pipeline integration (✓ shipped)

The translator runs at APK unpack time inside `apk_unpacker.cpp`, output cached at `build/var/apps/<pkg>/lib_native/lib<name>.dylib`. `AppClassLoader.findLibrary` returns the translated path so `System.loadLibrary("game")` finds it on first call. First translation takes 2-3 minutes for a 3 MB `.so` at `-O1`; subsequent boots reuse the cache.

## Bionic shim surface

The lifted dylib is linked against `libmacapk-bionic-shim.dylib`, which provides:

- **libc**: malloc/calloc/realloc/free, memcpy/memmove/memset/memcmp, strlen/strcmp/strchr/strstr, fopen/fread/fwrite/fseek/fgets/fclose, printf-family (with guest-pointer-translated format args), **sscanf** (full implementation with cocos2d-x BMFont short-field quirk), strtol/strtoul/strtod, atoi/atof.
- **libm**: sin/cos/tan/asin/acos/atan/atan2 and friends. ARM AAPCS soft-float passes doubles in `r0:r1`; macOS arm64 hard-float uses `d0`. The shim packs/unpacks the ABI mismatch (returns `i64` to the lifter, which splits into the `r0/r1` pair at the call site).
- **pthread**: best-effort mapping to libSystem `pthread_*`. Some Bionic-specific behaviors (e.g. `pthread_setname_np` arg order) are normalized.
- **errno**: returns a guest-VA into a per-thread shim-managed 4-byte slot.
- **GLES 2.0 (~120 entry points)**: routed through ANGLE. Pointer arguments are translated from guest VA to host pointer before being passed to ANGLE.
- **JNI**: bridged through the JVM's `JNIEnv*` — the lifted JNI methods see the real JVM and can call back into Java.

## Build

```bash
cd runtime/translator
mkdir -p build && cd build
cmake ..
cmake --build .
```

Output: `build/macapk-translator` and `build/libmacapk-bionic-shim.dylib`.

Requires Capstone (BSD-3-Clause) at `/opt/homebrew/opt/capstone/`:

```bash
brew install capstone
```

The Stage 0 round-trip test additionally needs a cross-compiler to BUILD its
ARM32 fixture (it compiles `test/test_add.c` for `armv7-linux-gnueabihf`).
That is a requirement of the TEST, not of the translator: the translator itself
shells out to no compiler and no linker.

## CLI

```bash
macapk-translator --in path/to/lib.so --out path/to/lib.dylib \
                   --shim-dir path/to/dir-with-libmacapk-bionic-shim.dylib \
                   [--keep-ir] [--verbose] [--strict] [--load-bias <addr>] \
                   [--emit-discovery <path>|auto]
```

- `--keep-ir` writes the discovery pass's LLVM IR text next to the output. A
  debugging artifact only: nothing compiles it (see the pipeline note above).
- `--verbose` prints per-function translation status.
- `--strict` makes any unsupported instruction inside a function fail the whole function (default: lenient — emit a comment + no-op fallback so the rest of the function still translates).
- `--load-bias` overrides the load bias for the emitted image.
- `--emit-discovery <path>` (or `auto` / `1` for `<output>.disc.tsv`) writes the
  ARM32 discovery sidecar that `debug/arm32_sidecar.py` reads.

Environment overrides:

- `MACAPK_DISCOVERY_SIDECAR` — same as `--emit-discovery`, for callers that fork
  the translator and cannot add a flag (`runtime/src/apk_unpacker.cpp` builds its
  own argv).

There is no `--clang` flag and no `MACAPK_OPT_LEVEL`; both belonged to the
removed LLVM path.

## Test

```bash
bash runtime/translator/test/run_stage0.sh
```

Cross-compiles `test/test_add.c` to ARM32 ELF via `clang -target armv7-linux-gnueabihf` + lld, runs the translator on it, builds a tiny C harness that dlopens the result and verifies `add(2, 3) == 5`, `sub(10, 4) == 6`, `triple_add(1, 2, 3) == 6`.

## License

Same as the rest of Mac.apk (see top-level `LICENSE` — free for all non-profit use with attribution, paid commercial license available). Capstone is BSD-3-Clause and dynamically linked. Nothing in the current build links or shells out to LLVM/clang. No GPL contagion.
