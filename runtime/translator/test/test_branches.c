// test_branches.c -- Stage 1a control-flow validation source.
//
// max() exercises CMP + B<cond> + multi-block.
// sum_to() exercises a forward loop with CMP + BLE/BGE.
// abs_diff() exercises a small if/else.
// nested_branches() forces a multi-comparison decision tree.
//
// All four must round-trip through the translator and produce the
// expected return values when called from the dlopen harness.

int max(int a, int b) {
    if (a > b) return a;
    return b;
}

int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; ++i) s += i;
    return s;
}

int abs_diff(int a, int b) {
    int d = a - b;
    return d < 0 ? -d : d;
}

int nested_branches(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    if (x < 10) return 1;
    if (x < 100) return 2;
    return 3;
}
