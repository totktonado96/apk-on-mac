#!/usr/bin/env python3
"""Generate the GLES1 (fixed-function) JNI bridges + Java native declarations.

WHY THIS EXISTS. android.opengl.GLES10/GLES11 are the fixed-function API that
pre-2012 Android games use (glMatrixMode, glVertexPointer, glFogf, ...). They have
no GLES2 equivalent, so an app that calls one hits NoSuchMethodError at the first
call. ANGLE already exports the entire GLES1 entry-point set and Mac.apk already
requests an ES1 CONTEXT when the guest's native libs import ES1 symbols
(runtime/src/main.cpp ApkNeedsGles1 -> MACAPK_GLES1_CONTEXT -> angle_glue.cpp).
The ONLY missing link was the Java->native bridge, which is what this emits.

⚠ THE ES1 CONTEXT IS A PREREQUISITE, NOT AN OPTIONAL EXTRA. ANGLE gates every ES1
entry point on `context->getClientVersion() < ES_2_0` and otherwise returns
GL_INVALID_OPERATION *without doing anything*. Bridges on an ES2 context would
therefore be present, callable and silently inert -- the exact
capability-we-cannot-honour shape CLAUDE.md forbids. Do not ship these without the
context selection working.

Input : debug/gles_gen/gles1_native_needed.txt  (name + JNI descriptor per method)
Output: runtime/src/gles1_bridges.inc           (bridges + registration tables)
        plus the Java `native` declarations printed for pasting into GLES10/11.

Mirrors gen.py's conventions exactly: gl3_resolve() for lazy symbol lookup,
gl3_buffer_ptr() for java.nio.Buffer, gl3_check_offset() +
GetPrimitiveArrayCritical for array+offset pairs.
"""
import re, sys, os, collections

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gles1_native_needed.txt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "runtime", "src", "gles1_bridges.inc")

# JNI descriptor primitive -> (jni type, C type used when calling through ANGLE)
PRIM = {"I": ("jint", "GLint"), "F": ("jfloat", "GLfloat"), "Z": ("jboolean", "GLboolean"),
        "J": ("jlong", "GLint64"), "S": ("jshort", "GLshort"), "B": ("jbyte", "GLbyte")}
ARR  = {"[F": ("jfloatArray", "GLfloat"), "[I": ("jintArray", "GLint"),
        "[S": ("jshortArray", "GLshort"), "[B": ("jbyteArray", "GLbyte")}


def parse_params(desc):
    """Descriptor params -> list of ('prim'|'arr'|'obj', jni_type, c_type)."""
    inner = desc[1:desc.index(")")]
    out, i = [], 0
    while i < len(inner):
        c = inner[i]
        if c == "L":
            j = inner.index(";", i)
            # KEEP the exact class name. Collapsing every L...; to java.nio.Buffer
            # made the Java declaration's descriptor differ from the registration
            # row's ((ILjava/nio/Buffer;)V vs (ILjava/nio/FloatBuffer;)V), and
            # RegisterNatives matches on name+descriptor -- so 24 rows resolved to
            # nothing and the JNI gate correctly said "WOULD ABORT AT BOOT".
            out.append(("obj", inner[i+1:j].replace("/", "."), "void*")); i = j + 1
        elif c == "[":
            tag = inner[i:i+2]
            if tag not in ARR:
                raise SystemExit("unhandled array type %s in %s" % (tag, desc))
            out.append(("arr",) + ARR[tag]); i += 2
        else:
            if c not in PRIM:
                raise SystemExit("unhandled primitive %s in %s" % (c, desc))
            out.append(("prim",) + PRIM[c]); i += 1
    return out


def main():
    groups = collections.OrderedDict()
    cls = None
    for line in open(SRC):
        m = re.match(r"^### (\S+)\s+--", line)
        if m:
            cls = m.group(1).split("/")[-1]; groups.setdefault(cls, []); continue
        m = re.match(r'^\s*\{"([^"]+)",\s*"([^"]+)"\}', line)
        if m and cls:
            groups[cls].append((m.group(1), m.group(2)))

    body, tables, javadecls = [], [], collections.defaultdict(list)
    for cls, meths in groups.items():
        if cls == "EGLExt":
            # eglDupNativeFenceFDANDROID returns android.hardware.SyncFence. We have
            # no sync_file, so the honest answer is an INVALID fence -- and that is
            # expressible in pure Java, with no bridge. Handled at the Java site.
            continue
        seen = collections.Counter(n for n, _ in meths)
        idx = collections.Counter()
        rows = []
        for name, desc in meths:
            params = parse_params(desc)
            suffix = ""
            if seen[name] > 1:
                idx[name] += 1; suffix = "_%d" % idx[name]
            fn = "GL1_%s_%s%s" % (cls, name, suffix)

            sig, call, pre, post = [], [], [], []
            i = 0
            while i < len(params):
                kind, jt, ct = params[i]
                if kind == "arr":
                    # AOSP pairs every array with a following int offset.
                    if i + 1 >= len(params) or params[i+1][0] != "prim":
                        raise SystemExit("array without offset in %s%s" % (name, desc))
                    sig.append("%s a%d" % (jt, i)); sig.append("jint a%d" % (i+1))
                    pre.append('    if (!gl3_check_offset(env, a%d, a%d, "%s: offset out of range")) return;'
                               % (i, i+1, name))
                    pre.append("    void* base%d = a%d ? env->GetPrimitiveArrayCritical(a%d, nullptr) : nullptr;"
                               % (i, i, i))
                    post.append("    if (a%d) env->ReleasePrimitiveArrayCritical(a%d, base%d, 0);"
                                % (i, i, i))
                    call.append(("%s*" % ct, "(base%d ? (%s*)base%d + a%d : nullptr)" % (i, ct, i, i+1)))
                    i += 2
                elif kind == "obj":
                    sig.append("jobject a%d" % i)
                    pre.append("    void* buf%d = a%d ? gl3_buffer_ptr(env, a%d) : nullptr;" % (i, i, i))
                    call.append(("void*", "buf%d" % i))
                    i += 1
                else:
                    sig.append("%s a%d" % (jt, i))
                    call.append((ct, "(%s)a%d" % (ct, i)))
                    i += 1

            ctypes = ", ".join(c for c, _ in call) or "void"
            args   = ", ".join(a for _, a in call)
            body.append("void %s(JNIEnv* env, jclass%s) {" % (fn, (", " + ", ".join(sig)) if sig else ""))
            body.append('    static auto _p = (void*)gl3_resolve("%s");' % name)
            body.extend(pre)
            body.append("    if (_p) ((void(*)(%s))_p)(%s);" % (ctypes, args))
            body.extend(post)
            body.append("}\n")
            rows.append('    {(char*)"%s", (char*)"%s", (void*)%s},' % (name, desc, fn))

            jparams = []
            i = 0
            JT = {"jint": "int", "jfloat": "float", "jboolean": "boolean", "jlong": "long",
                  "jshort": "short", "jbyte": "byte", "jfloatArray": "float[]",
                  "jintArray": "int[]", "jshortArray": "short[]", "jbyteArray": "byte[]"}
            for k, (kind, jt, _ct) in enumerate(params):
                jparams.append("%s a%d" % (jt if kind == "obj" else JT[jt], k))
            javadecls[cls].append("    public static native void %s(%s);" % (name, ", ".join(jparams)))

        tables.append("const JNINativeMethod kGl1%sMethods[] = {\n%s\n};\n" % (cls, "\n".join(rows)))

    hdr = ["// GENERATED by debug/gles_gen/gen_gles1.py -- GLES10/GLES11 fixed-function",
           "// JNI bridges + registration tables. Included by native_methods.cpp inside",
           "// namespace macapk { namespace { ... } }. Do NOT hand-edit.",
           "//",
           "// ⚠ These are INERT without an ES1 context: ANGLE returns GL_INVALID_OPERATION",
           "// for every GLES1 entry point on an ES2 context. main.cpp's ApkNeedsGles1 scan",
           "// sets MACAPK_GLES1_CONTEXT, which angle_glue.cpp turns into",
           "// EGL_CONTEXT_CLIENT_VERSION 1. That selection is a PREREQUISITE, not a tuning knob.",
           ""]
    open(os.path.normpath(OUT), "w").write("\n".join(hdr + body + tables))
    print("wrote %s" % os.path.normpath(OUT))
    for cls, decls in javadecls.items():
        print("\n// ==== %s : %d native declarations ====" % (cls, len(decls)))
        print("\n".join(decls))


if __name__ == "__main__":
    main()
