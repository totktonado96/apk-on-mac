#!/usr/bin/env python3
# debug/gles_gen/reconstruct_sigs.py
#
# WHAT: Rebuild the /tmp/glsig/*.txt javap-signature inputs that
# debug/gles_gen/gen.py consumes, by reading them back out of the Java files
# gen.py itself emitted (runtime/java/android/opengl/GLES3*.java, EGL*.java).
#
# WHY: gen.py's real input was `javap -p -constants` run against an android-34
# android.jar that is not on this machine, and /tmp/glsig is long gone (it is
# /tmp). That made the generator UNRUNNABLE, which in turn made "fix the
# generator and regenerate" impossible and pushed every fix toward hand-editing
# 100+ generated functions -- exactly what the generator exists to prevent.
#
# The generated Java is a lossless rendering of what gen.py parsed: every
# constant, every `public static native` decl, and (for EGL) every EGL_NO_*
# object field. So we can round-trip it back into javap's spelling. The proof
# that the round-trip is faithful is `--verify`: regenerate from the
# reconstruction and require the emitted files to be byte-identical to the
# committed ones. If that check passes, the reconstruction is not an
# approximation, it is the same input.
#
# Usage:
#   python3 debug/gles_gen/reconstruct_sigs.py           # write /tmp/glsig
#   python3 debug/gles_gen/reconstruct_sigs.py --verify  # write, regen into a
#                                                        # temp tree, diff
import os, re, sys, shutil, subprocess, tempfile

SRC = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(SRC, "..", ".."))
JAVA_DIR = os.path.join(REPO, "runtime", "java", "android", "opengl")
SIG_DIR = "/tmp/glsig"

GL_CLASSES = ["GLES30", "GLES31", "GLES31Ext", "GLES32"]
EGL_CLASSES = ["EGL14", "EGL15", "EGLExt"]

# Reverse of gen.py's java_type()/egl_jtype(): Java source spelling -> the
# fully-qualified spelling javap prints.
TO_JAVAP = {
    "String": "java.lang.String",
    "String[]": "java.lang.String[]",
    "Buffer": "java.nio.Buffer",
    "IntBuffer": "java.nio.IntBuffer",
    "FloatBuffer": "java.nio.FloatBuffer",
    "LongBuffer": "java.nio.LongBuffer",
    "ByteBuffer": "java.nio.ByteBuffer",
    "GLES32.DebugProc": "android.opengl.GLES32$DebugProc",
    "GLES31Ext.DebugProcKHR": "android.opengl.GLES31Ext$DebugProcKHR",
    "EGLDisplay": "android.opengl.EGLDisplay",
    "EGLContext": "android.opengl.EGLContext",
    "EGLSurface": "android.opengl.EGLSurface",
    "EGLConfig": "android.opengl.EGLConfig",
    "EGLImage": "android.opengl.EGLImage",
    "EGLSync": "android.opengl.EGLSync",
}

CONST_J = re.compile(r"public static final (int|long)\s+(\w+)\s*=\s*(-?\d+)L?;")
NATIVE_J = re.compile(r"public static native\s+([\w.$\[\]]+)\s+(\w+)\s*\(([^)]*)\);")
OBJFIELD_J = re.compile(r"public static final (EGL\w+) (\w+) = new EGL\w+\(0L\);")


def to_javap(t):
    return TO_JAVAP.get(t, t)


def reconstruct(cls, is_egl):
    lines = []
    src = open(os.path.join(JAVA_DIR, cls + ".java")).read()
    for m in CONST_J.finditer(src):
        kind, name, val = m.groups()
        # javap -constants prints a long literal with a lowercase trailing l,
        # which is what gen.py's CONST_RE expects (`l?`).
        suffix = "l" if kind == "long" else ""
        lines.append("  public static final %s %s = %s%s;" % (kind, name, val, suffix))
    if is_egl:
        for m in OBJFIELD_J.finditer(src):
            typ, name = m.groups()
            lines.append("  public static %s %s;" % (to_javap(typ), name))
    for m in NATIVE_J.finditer(src):
        ret, name, args = m.groups()
        # EGL14's eglCreateWindowSurface(...Object...) is APPENDED by gen.py
        # itself rather than parsed, so it must not be fed back in or it would
        # be emitted twice.
        if cls == "EGL14" and name == "eglCreateWindowSurface" and "Object" in args:
            continue
        ptypes = []
        for a in [x.strip() for x in args.split(",")] if args.strip() else []:
            ptypes.append(to_javap(a.rsplit(" ", 1)[0].strip()))
        lines.append("  public static native %s %s(%s);"
                     % (to_javap(ret), name, ", ".join(ptypes)))
    return "\n".join(lines) + "\n"


def write_all(dest):
    os.makedirs(dest, exist_ok=True)
    for c in GL_CLASSES:
        open(os.path.join(dest, c + ".txt"), "w").write(reconstruct(c, False))
    for c in EGL_CLASSES:
        open(os.path.join(dest, c + ".txt"), "w").write(reconstruct(c, True))


def main():
    write_all(SIG_DIR)
    print("wrote", SIG_DIR)
    if "--verify" not in sys.argv:
        return 0
    # Regenerate into a scratch copy of the two output trees and diff.
    tmp = tempfile.mkdtemp(prefix="glsigverify")
    shadow_java = os.path.join(tmp, "runtime", "java", "android", "opengl")
    shadow_src = os.path.join(tmp, "runtime", "src")
    os.makedirs(shadow_java); os.makedirs(shadow_src)
    gen = open(os.path.join(SRC, "gen.py")).read()
    # Point the generator's two output paths at the shadow tree. Both are
    # built from SRC/../.. so a single SRC rebind moves everything.
    gen = gen.replace('SRC = os.path.dirname(os.path.abspath(__file__))',
                      'SRC = %r' % os.path.join(tmp, "debug", "gles_gen"), 1)
    os.makedirs(os.path.join(tmp, "debug", "gles_gen"))
    shadow_gen = os.path.join(tmp, "debug", "gles_gen", "gen.py")
    open(shadow_gen, "w").write(gen)
    r = subprocess.run([sys.executable, shadow_gen], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        return 1
    bad = 0
    checks = [(os.path.join(REPO, "runtime", "src", "gles3_bridges.inc"),
               os.path.join(shadow_src, "gles3_bridges.inc"))]
    for c in GL_CLASSES + EGL_CLASSES:
        checks.append((os.path.join(JAVA_DIR, c + ".java"),
                       os.path.join(shadow_java, c + ".java")))
    for have, got in checks:
        if not os.path.exists(got):
            print("MISSING  %s" % got); bad += 1; continue
        if open(have, "rb").read() == open(got, "rb").read():
            print("IDENTICAL %s" % os.path.basename(have))
        else:
            print("DIFFERS   %s" % os.path.basename(have))
            subprocess.run(["diff", "-u", have, got])
            bad += 1
    shutil.rmtree(tmp, ignore_errors=True)
    print("VERIFY:", "PASS" if bad == 0 else "FAIL (%d)" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
