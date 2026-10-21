#!/usr/bin/env bash
# run_stage0.sh -- end-to-end test of the Stage 0 translator pipeline.
#
# 1. Cross-compile test_add.c to an ARM32 Linux ELF .so via clang+lld.
# 2. Translate that .so to an arm64-apple-darwin Mach-O dylib via
#    macapk-translator.
# 3. Build a tiny C harness that dlopens the result and calls add(2,3).
# 4. Run the harness; expect exit code 0 (success) and stdout "5".

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TRANSLATOR_DIR="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
BUILD_DIR="$TRANSLATOR_DIR/build"
WORK="$BUILD_DIR/test_stage0"
mkdir -p "$WORK"

LLD=/opt/homebrew/bin/ld.lld
if [[ ! -x "$LLD" ]]; then
    echo "[stage0] lld not found at $LLD; install with: brew install lld" >&2
    exit 1
fi

TRANSLATOR="$BUILD_DIR/macapk-translator"
if [[ ! -x "$TRANSLATOR" ]]; then
    echo "[stage0] translator not built at $TRANSLATOR" >&2
    echo "        build with: cd $TRANSLATOR_DIR && mkdir -p build && cd build && cmake .. && cmake --build ." >&2
    exit 1
fi

echo "[stage0] 1) cross-compile test_add.c -> ARM32 ELF"
clang -target armv7-linux-gnueabihf -shared -fPIC -nostdlib \
    "-fuse-ld=$LLD" \
    "$SCRIPT_DIR/test_add.c" \
    -o "$WORK/test_add.so"
file "$WORK/test_add.so"

echo "[stage0] 2) translate ARM32 ELF -> arm64-darwin Mach-O dylib"
"$TRANSLATOR" --in "$WORK/test_add.so" --out "$WORK/test_add.dylib" --keep-ir --verbose
file "$WORK/test_add.dylib"

echo "[stage0] 3) build dlopen harness"
cat > "$WORK/harness.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*add_fn)(int, int);

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dylib>\n", argv[0]); return 2; }
    void* h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }
    add_fn add = (add_fn) dlsym(h, "add");
    if (!add) { fprintf(stderr, "dlsym add: %s\n", dlerror()); return 4; }
    int r = add(2, 3);
    printf("add(2, 3) = %d\n", r);
    return r == 5 ? 0 : 5;
}
EOF
clang -O0 "$WORK/harness.c" -o "$WORK/harness"

echo "[stage0] 4) run dlopen harness"
"$WORK/harness" "$WORK/test_add.dylib"
echo "[stage0] PASS"
