#!/usr/bin/env bash
# run_stage1a.sh -- end-to-end Stage 1a validation.
#
# Cross-compiles test_branches.c with optimization (so the compiler
# generates real CMP / B<cond> / multi-block code), translates the
# resulting ARM32 ELF .so, dlopens the output, and validates a handful
# of inputs against expected results.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TRANSLATOR_DIR="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
BUILD_DIR="$TRANSLATOR_DIR/build"
WORK="$BUILD_DIR/test_stage1a"
mkdir -p "$WORK"

LLD=/opt/homebrew/bin/ld.lld
TRANSLATOR="$BUILD_DIR/macapk-translator"
[[ -x "$LLD" ]]        || { echo "lld not found at $LLD" >&2; exit 1; }
[[ -x "$TRANSLATOR" ]] || { echo "translator not built at $TRANSLATOR" >&2; exit 1; }

echo "[stage1a] 1) cross-compile test_branches.c -> ARM32 ELF (-O1 to keep ARM mode)"
clang -target armv7-linux-gnueabihf -shared -fPIC -nostdlib -O1 -marm \
    "-fuse-ld=$LLD" \
    "$SCRIPT_DIR/test_branches.c" \
    -o "$WORK/test_branches.so"
file "$WORK/test_branches.so"

echo "[stage1a] 2) translate"
"$TRANSLATOR" --in "$WORK/test_branches.so" --out "$WORK/test_branches.dylib" --keep-ir
file "$WORK/test_branches.dylib"

echo "[stage1a] 3) build harness"
cat > "$WORK/harness.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
typedef int (*fn1)(int);
typedef int (*fn2)(int, int);

int main(int argc, char** argv) {
    void* h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    fn2 mx = (fn2)dlsym(h, "max");
    fn1 st = (fn1)dlsym(h, "sum_to");
    fn2 ad = (fn2)dlsym(h, "abs_diff");
    fn1 nb = (fn1)dlsym(h, "nested_branches");

    if (!mx || !st || !ad || !nb) {
        fprintf(stderr, "dlsym: missing one of max/sum_to/abs_diff/nested_branches\n");
        return 2;
    }

    int errors = 0;
    int got, want;

    got = mx(7, 3);   want = 7;   if (got != want) { fprintf(stderr, "max(7,3)=%d want %d\n", got, want); errors++; }
    got = mx(2, 9);   want = 9;   if (got != want) { fprintf(stderr, "max(2,9)=%d want %d\n", got, want); errors++; }
    got = mx(-5, -1); want = -1;  if (got != want) { fprintf(stderr, "max(-5,-1)=%d want %d\n", got, want); errors++; }

    got = st(5);   want = 15;  if (got != want) { fprintf(stderr, "sum_to(5)=%d want %d\n", got, want); errors++; }
    got = st(10);  want = 55;  if (got != want) { fprintf(stderr, "sum_to(10)=%d want %d\n", got, want); errors++; }
    got = st(0);   want = 0;   if (got != want) { fprintf(stderr, "sum_to(0)=%d want %d\n", got, want); errors++; }

    got = ad(7, 3);   want = 4;  if (got != want) { fprintf(stderr, "abs_diff(7,3)=%d want %d\n", got, want); errors++; }
    got = ad(3, 7);   want = 4;  if (got != want) { fprintf(stderr, "abs_diff(3,7)=%d want %d\n", got, want); errors++; }
    got = ad(-2, 5);  want = 7;  if (got != want) { fprintf(stderr, "abs_diff(-2,5)=%d want %d\n", got, want); errors++; }

    got = nb(-1);   want = -1;  if (got != want) { fprintf(stderr, "nested_branches(-1)=%d want %d\n", got, want); errors++; }
    got = nb(0);    want = 0;   if (got != want) { fprintf(stderr, "nested_branches(0)=%d want %d\n", got, want); errors++; }
    got = nb(5);    want = 1;   if (got != want) { fprintf(stderr, "nested_branches(5)=%d want %d\n", got, want); errors++; }
    got = nb(50);   want = 2;   if (got != want) { fprintf(stderr, "nested_branches(50)=%d want %d\n", got, want); errors++; }
    got = nb(500);  want = 3;   if (got != want) { fprintf(stderr, "nested_branches(500)=%d want %d\n", got, want); errors++; }

    if (errors == 0) printf("[stage1a] ALL %d test cases passed\n", 14);
    return errors;
}
EOF
clang -O0 "$WORK/harness.c" -o "$WORK/harness"

echo "[stage1a] 4) run"
"$WORK/harness" "$WORK/test_branches.dylib"
echo "[stage1a] PASS"
