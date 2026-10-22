#!/usr/bin/env python3
"""build_ids.py -- Apk on Mac's per-subsystem build identity (Contract 3).

Prints KEY=value lines on stdout, one per identity, in a stable order:

    CONVERTER_ID   the DEX->JVM converter's own bytecode (com.macapk.dex; NOT
                   the dalvik.system dynamic-dex driver, see
                   CONVERTER_PREFIXES), PLUS the bracketed converter
                   invocation in runtime/src/apk_unpacker.cpp (its -cp is the
                   type universe ClassHierarchyOracle reasons in). Changing
                   either changes what a converted classes.jar CONTAINS, so it
                   must re-convert. See CONVERTER_RECIPE below.
    FRAMEWORK_ID   the CLASS SHAPE of everything on the converter's classpath:
                   for each class, its name, access_flags, this/super class and
                   declared interfaces. NOT method bodies, NOT constants, NOT
                   fields, NOT annotations.
    JAVA_ID        = f(CONVERTER_ID, FRAMEWORK_ID). ** THE DEX-CACHE KEY. **
                   The name and the role are unchanged (apk_unpacker.cpp stamps
                   it into each app's .source-mtime and re-converts on a
                   mismatch); only the BASIS narrowed, from "any byte of either
                   jar" to "the two things that can actually invalidate a
                   converted jar".
    JARS_ID        full entry-content digest of both jars -- the OLD JAVA_ID
                   basis, kept for STALENESS DIAGNOSTICS ONLY (debug/staleness.sh
                   check 3, "were these artifacts really staged by build.sh").
                   It is deliberately NOT a cache key: it churns on every
                   framework method-body edit, which is most sessions.
    NATIVE_ID      translator + bionic shim content. Gates the translated-dylib
                   cache (AppClassLoader.nativeIdMatches).

WHY THE SPLIT EXISTS (owner, 2026-08-10): "once the apps are installed if we
make runtime only changes we won't need to reinstall the apps every time. So we
could maybe design a system that reinstalls the apps if a change to the dex2jar
or similar is changed but not reinstall if it's runtime only."  A single JAVA_ID
over the whole framework jar made EVERY framework edit re-convert EVERY
installed app (~8 GB of work across the fleet) -- and a framework method-body
change cannot invalidate a converted jar.

WHY FRAMEWORK_ID IS SHAPED THE WAY IT IS -- established from the code, 2026-08-11:
the converter reads the framework jar in exactly ONE place,
ClassHierarchyOracle.readResource (runtime/java/com/macapk/dex/
ClassHierarchyOracle.java:117), via getResourceAsStream(<internal name>
+ ".class") on DexConverter's own class loader (DexConverter.java:132), and
interprets exactly THREE things out of the bytes it gets back:

  * whether the resource EXISTS at all      (null -> Entry.UNKNOWN)
  * access_flags & ACC_INTERFACE            (ClassHierarchyOracle.java:181)
  * the super_class name                    (ClassHierarchyOracle.java:179-189)

Those three feed: the Methodref-vs-InterfaceMethodref constant-pool tag on
invokestatic/invokespecial (Translator.java:1632-1634 -- a wrong answer is an
IncompatibleClassChangeError at RESOLUTION time, which -Xverify:none does not
hide), the reference least-upper-bound that lands in every StackMapTable frame
(DexType.lubClass, DexType.java:439-470), and whether a narrowing checkcast is
emitted (TypeInference.assignableTo:1674, Translator.assignableTo:1955).
Nothing else in com/macapk/dex/** touches the classpath: SuperInterfacePlan,
NestIndex, NestPlan and InitRepointPlan all read only the APK's own parsed DEX
(the session's byName map), and Main.java's ZipFile use is the INPUT apk.

Two consequences worth stating out loud, because getting either wrong ships a
silently wrong StackMapTable under a VM-wide -Xverify:none:

  1. Class PRESENCE is part of the answer. Adding a framework class flips the
     oracle from UNKNOWN (-> java/lang/Object fallback) to a real supertype for
     any app that references it, which changes emitted frames. So the class NAME
     SET is in the digest, and adding a new class DOES re-convert. (This
     contradicts a "new unrelated class must not re-convert" intuition; we
     cannot know at build time which app references which name.)
  2. Declared INTERFACES are in the digest even though the oracle does not read
     them today, and so are the full access_flags rather than just ACC_INTERFACE.
     Both are free, and both are the err-toward-including-more direction: the
     cost of over-including is one extra re-convert, the cost of under-including
     is a wrong frame nobody sees.

Class shapes are keyed by internal NAME and deduped in CLASSPATH ORDER
(android-framework.jar, macapk-loader.jar, bcprov -- main.cpp:2025-2030), so
moving a class between our jars is correctly a no-op. java_base_patch is folded
in too (it is served to the oracle through --patch-module=java.base).

USED BY: runtime/scripts/build.sh (writes runtime/build/build-id.txt) and
debug/staleness.sh (recomputes and compares). ONE implementation on purpose --
the previous arrangement duplicated the digest as inline python in both files
under a "keep in sync" comment, and the halves would have silently diverged the
first time one of them was edited.
"""

import hashlib
import os
import sys
import zipfile

FRAMEWORK_JAR = "android-framework.jar"
LOADER_JAR = "macapk-loader.jar"
# Every --patch-module dir main.cpp passes. Each one serves classes to the
# converter's oracle in place of the JDK's own, so each one's class shapes
# belong in FRAMEWORK_ID on exactly the same reasoning as java_base_patch.
PATCH_DIRS = ("java_base_patch", "jdk_unsupported_patch")

# main.cpp pushes framework, loader, then bcprov onto the JVM classpath
# (runtime/src/main.cpp:2025-2030), and getResourceAsStream resolves
# first-wins in that order. Any vendored jar added there belongs here too.
VENDOR_JARS = ("bcprov-jdk18on-1.79.jar",)

# The converter itself: com.macapk.dex (in macapk-loader.jar). A change there
# changes what a converted classes.jar contains.
#
# dalvik/system/MacApkDexConverter USED to be listed here, on the stated
# grounds that it changes "what a converted classes.jar contains". It never
# did: the EAGER classes.jar is written by the com.macapk.dex.Main subprocess
# inside apk_unpacker.cpp's MACAPK_CONVERTER_RECIPE markers, and the LAZY path
# is dalvik.system.LazyDexSource, which persists nothing. MacApkDexConverter
# serves only DexClassLoader / InMemoryDexClassLoader / DexFile, and since
# 2026-09-24 its own output is a content-addressed cache whose key already
# includes a SHA-256 of MacApkDexConverter.class itself
# (docs/dynamic-dex-cache_2026-09-24.md). Keeping it here meant every edit to
# that one driver re-converted every installed app's classes.jar for nothing.
CONVERTER_PREFIXES = (
    "com/macapk/dex/",
)

# CONVERTER_RECIPE -- the OTHER half of "what the converter does".
#
# CONVERTER_ID above covers the converter's own bytecode. It does NOT cover how
# the eager install path INVOKES it, and that lives in C++
# (runtime/src/apk_unpacker.cpp): the -cp it hands the subprocess IS the type
# universe ClassHierarchyOracle reasons in, so changing it changes the emitted
# StackMapTable frames just as surely as editing DexType.lubClass would. Before
# 2026-08-18 that classpath was macapk-loader.jar alone while every offline gate
# passed the framework jars too, so the gates graded a configuration we did not
# ship -- measured across 16 APKs, 288 split-verifier errors in the shipped
# artifact against 7 in the gated one.
#
# Hashing the WHOLE C++ file would be wrong in the expensive direction: it
# churns CONVERTER_ID on every unrelated edit to a 2,800-line file and
# re-converts the entire fleet each time (the same trap CLAUDE.md flags for
# folding macapk-runtime into NATIVE_ID). So apk_unpacker.cpp brackets exactly
# the invocation in MACAPK_CONVERTER_RECIPE_BEGIN/END markers and only that text
# is hashed. Move or rename the markers and this falls back to a fixed literal,
# which is stated rather than silent.
RECIPE_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "src", "apk_unpacker.cpp")
RECIPE_BEGIN = "MACAPK_CONVERTER_RECIPE_BEGIN"
RECIPE_END = "MACAPK_CONVERTER_RECIPE_END"


def converter_recipe():
    """The bracketed converter-invocation text, or a NAMED fallback.

    The fallback is a constant on purpose: a missing source tree (a recompute
    run from somewhere that has only the artifacts) must not make CONVERTER_ID
    churn, and must not silently pretend the recipe is empty either -- the
    marker string is part of the digest input so the two cases stay distinct.
    """
    try:
        with open(RECIPE_SRC, "r") as f:
            text = f.read()
    except OSError:
        return b"recipe=source-unavailable"
    i = text.find(RECIPE_BEGIN)
    j = text.find(RECIPE_END)
    if i < 0 or j < 0 or j < i:
        sys.stderr.write(
            "build_ids.py: WARNING -- %s / %s markers not found in %s; the "
            "converter's classpath is NOT covered by CONVERTER_ID, so a change "
            "to it will not re-convert cached jars\n"
            % (RECIPE_BEGIN, RECIPE_END, RECIPE_SRC))
        return b"recipe=markers-missing"
    return text[i:j].encode()

# Constant-pool entry sizes AFTER the tag byte (JVMS SE21 4.4). Long and Double
# are handled separately because they occupy TWO pool slots -- the classic
# off-by-one in this loop, and the same one ClassHierarchyOracle.parseHeader
# calls out.
_CP_FIXED = {
    3: 4, 4: 4,                      # Integer, Float
    9: 4, 10: 4, 11: 4,              # Fieldref, Methodref, InterfaceMethodref
    12: 4, 17: 4, 18: 4,             # NameAndType, Dynamic, InvokeDynamic
    8: 2, 16: 2, 19: 2, 20: 2,       # String, MethodType, Module, Package
    15: 3,                           # MethodHandle
}


def class_shape(b):
    """(access_flags, this, super, [interfaces]) or None if unparseable.

    Mirrors ClassHierarchyOracle.parseHeader's constant-pool walk exactly, then
    reads the interfaces table it stops short of. Header-only: nothing past the
    interfaces array is touched, so a method body cannot move the result.
    """
    try:
        if b[:4] != b"\xca\xfe\xba\xbe":
            return None
        p = 8                                    # skip magic + minor + major
        count = (b[p] << 8) | b[p + 1]
        p += 2
        cls_name_idx = [0] * count
        utf = [None] * count
        i = 1
        while i < count:
            tag = b[p]
            p += 1
            if tag == 1:                          # Utf8
                ln = (b[p] << 8) | b[p + 1]
                p += 2
                utf[i] = bytes(b[p:p + ln])
                p += ln
            elif tag == 7:                        # Class
                cls_name_idx[i] = (b[p] << 8) | b[p + 1]
                p += 2
            elif tag == 5 or tag == 6:            # Long, Double: two slots
                p += 8
                i += 1
            else:
                size = _CP_FIXED.get(tag)
                if size is None:
                    return None                   # pool desynchronised
                p += size
            i += 1
        if p + 8 > len(b):
            return None

        def name_of(idx):
            if idx <= 0 or idx >= count:
                return b""
            ni = cls_name_idx[idx]
            if ni <= 0 or ni >= count or utf[ni] is None:
                return b""
            return utf[ni]

        access = (b[p] << 8) | b[p + 1]
        this_name = name_of((b[p + 2] << 8) | b[p + 3])
        super_name = name_of((b[p + 4] << 8) | b[p + 5])
        n_ifaces = (b[p + 6] << 8) | b[p + 7]
        p += 8
        if p + 2 * n_ifaces > len(b):
            return None
        ifaces = [name_of((b[p + 2 * k] << 8) | b[p + 2 * k + 1])
                  for k in range(n_ifaces)]
        return access, this_name, super_name, ifaces
    except (IndexError, ValueError):
        return None


def shape_record(name, data):
    """The bytes a class contributes to FRAMEWORK_ID."""
    s = class_shape(data)
    if s is None:
        # Cannot interpret it, so cannot claim a method-body change is
        # irrelevant to it. Fall back to full content: over-invalidating is
        # the safe direction.
        return b"%s\x00RAW\x00%s\n" % (name.encode(),
                                       hashlib.sha256(data).hexdigest().encode())
    access, this_name, super_name, ifaces = s
    return b"%s\x00%04x\x00%s\x00%s\x00%s\n" % (
        name.encode(), access, this_name, super_name, b",".join(ifaces))


def collect(lib_dir):
    """(jars_hash, converter_bytes, shape_map) in one pass over the jars.

    shape_map is keyed by internal class name, first definition wins, walked in
    JVM classpath order so it models what getResourceAsStream would answer.
    """
    jars = hashlib.sha256()
    conv = []
    shapes = {}

    # JARS_ID keeps the ORIGINAL macapk_java_id() semantics byte for byte
    # (basename + sorted entry name + uncompressed bytes over exactly the two
    # jars), so its value is continuous across this refactor and a mismatch
    # after a clean build means a real divergence, not a redefinition.
    for jar_name in (FRAMEWORK_JAR, LOADER_JAR):
        path = os.path.join(lib_dir, jar_name)
        jars.update(os.path.basename(path).encode())
        try:
            z = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            jars.update(b"absent")
            continue
        with z:
            for n in sorted(z.namelist()):
                data = z.read(n)
                jars.update(n.encode())
                jars.update(data)
                if n.startswith(CONVERTER_PREFIXES):
                    conv.append((n, data))
                if n.endswith(".class") and n[:-6] not in shapes:
                    shapes[n[:-6]] = shape_record(n[:-6], data)

    for jar_name in VENDOR_JARS:
        path = os.path.join(lib_dir, jar_name)
        try:
            z = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            continue
        with z:
            for n in sorted(z.namelist()):
                if n.endswith(".class") and n[:-6] not in shapes:
                    shapes[n[:-6]] = shape_record(n[:-6], z.read(n))

    # --patch-module classes (main.cpp). The boot/platform loader serves these
    # to getResourceAsStream in place of the JDK's own, so a shape change here
    # would change the oracle's answer for a java.* / sun.* type.
    for patch_name in PATCH_DIRS:
        patch = os.path.join(lib_dir, patch_name)
        for root, _dirs, files in os.walk(patch):
            for f in sorted(files):
                if not f.endswith(".class"):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, patch)[:-6]
                with open(full, "rb") as fh:
                    # Deliberately overrides: --patch-module wins over the JDK,
                    # and our jars may not define java.* at all.
                    shapes[rel] = shape_record(rel, fh.read())

    return jars.hexdigest()[:16], conv, shapes


def jdk_stamp(java_home):
    """The JDK whose java.* class shapes the oracle also sees.

    Read from $JAVA_HOME/release rather than by running `java -version`, which
    would add a JVM start to every build for one string.
    """
    if not java_home:
        return "unknown"
    try:
        with open(os.path.join(java_home, "release"), "r") as f:
            for line in f:
                if line.startswith("JAVA_VERSION="):
                    return line.strip().split("=", 1)[1].strip('"')
    except OSError:
        pass
    return "unknown"


def native_id(paths):
    """md5-of-md5s, EXACTLY reproducing the previous shell macapk_native_id():
    `md5 -q` per file joined by single spaces WITH a trailing space, then md5 of
    that string, first 16 chars. Both binaries are byte-stable across a no-op
    rebuild (measured 2026-08-10), so a plain content hash is enough here.
    """
    parts = ""
    for p in paths:
        if os.path.isfile(p):
            h = hashlib.md5()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            parts += h.hexdigest() + " "
        else:
            parts += "absent "
    return hashlib.md5(parts.encode()).hexdigest()[:16]


def main(argv):
    lib_dir = bin_dir = None
    java_home = os.environ.get("JAVA_HOME", "")
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--lib-dir":
            lib_dir = argv[i + 1]; i += 2
        elif a == "--bin-dir":
            bin_dir = argv[i + 1]; i += 2
        elif a == "--java-home":
            java_home = argv[i + 1]; i += 2
        else:
            sys.stderr.write("build_ids.py: unknown arg %s\n" % a)
            return 2
    if not lib_dir or not bin_dir:
        sys.stderr.write(
            "usage: build_ids.py --lib-dir <runtime/build/lib> "
            "--bin-dir <runtime/build/bin> [--java-home <dir>]\n")
        return 2

    jars_id, conv, shapes = collect(lib_dir)

    h = hashlib.sha256()
    for n, data in sorted(conv):
        h.update(n.encode())
        h.update(data)
    # ...plus how the eager install path invokes it. See CONVERTER_RECIPE.
    h.update(b"\x00RECIPE\x00")
    h.update(converter_recipe())
    converter_id = h.hexdigest()[:16]

    h = hashlib.sha256()
    h.update(b"jdk=%s\n" % jdk_stamp(java_home).encode())
    for k in sorted(shapes):
        h.update(shapes[k])
    framework_id = h.hexdigest()[:16]

    # The DEX cache invalidates on EXACTLY these two and nothing else.
    java_id = hashlib.sha256(
        b"CONVERTER=%s\nFRAMEWORK=%s\n"
        % (converter_id.encode(), framework_id.encode())).hexdigest()[:16]

    nid = native_id([os.path.join(bin_dir, "macapk-translator"),
                     os.path.join(bin_dir, "libmacapk-bionic-shim.dylib")])

    out = ["CONVERTER_ID=%s" % converter_id,
           "FRAMEWORK_ID=%s" % framework_id,
           "JAVA_ID=%s" % java_id,
           "JARS_ID=%s" % jars_id,
           "NATIVE_ID=%s" % nid]
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
