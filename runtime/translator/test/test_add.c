// test_add.c -- the source used to generate the Stage 0 input artifact.
// Cross-compile with clang -target armv7-linux-gnueabihf -shared -fPIC
// -nostdlib -fuse-ld=lld test_add.c -o test_add.so. The exported `add`
// symbol becomes our translator input.
//
// The function is intentionally trivial: PUSH/POP frame, two i32
// arguments, no FPU, no memory traffic outside its own stack frame, no
// external calls. This is the absolute minimum a real ARM Bionic .so
// would do in any leaf function -- if the translator can't handle this
// shape, it can't handle anything.

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int triple_add(int a, int b, int c) {
    return a + b + c;
}
