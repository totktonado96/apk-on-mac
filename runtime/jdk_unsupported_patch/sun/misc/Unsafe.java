// sun.misc.Unsafe -- Android's (libcore's) Unsafe, served to guest code in
// place of the JDK's.
//
// WHY THIS FILE EXISTS
// --------------------
// On Android, `sun.misc.Unsafe` is a PLATFORM class shipped by libcore, and a
// large family of libraries obtains it the documented way:
//
//     Unsafe.class.getDeclaredMethod("getUnsafe").invoke(null)
//
// (LSPosed HiddenApiBypass, Netty, Kryo, protobuf, RxJava, okio, ...). On the
// host JDK that call is IMPOSSIBLE for guest code, for two independent reasons,
// and both are pure host artifacts that no Android device has:
//
//   1. The JDK's sun.misc.Unsafe.getUnsafe() is @CallerSensitive and resolves
//      its caller with jdk.internal.reflect.Reflection.getCallerClass(), which
//      DELIBERATELY SKIPS reflection frames -- so it sees the guest class and
//      throws SecurityException("Unsafe"). ART resolves the same check with
//      VMStack.getStackClass2(), which COUNTS the reflection frames, so on a
//      device the caller reads as java.lang.reflect.Method (bootclasspath,
//      loader == null) and the check PASSES. Same check, different stack-walk.
//   2. The JDK's sun.misc.Unsafe.<clinit> calls
//      Reflection.registerMethodsToFilter(Unsafe.class, Set.of("getUnsafe")),
//      so once ANYTHING in the VM has initialized the class, getUnsafe() is
//      invisible to getDeclaredMethod() and the same call fails with
//      NoSuchMethodException instead. Android has no such filter. (This makes
//      the host behaviour ORDER-DEPENDENT, which is worse than either outcome:
//      before v1.0.9xx, whether a guest saw SecurityException or
//      NoSuchMethodException depended on whether libcore.io.Memory's
//      Class.forName("sun.misc.Unsafe") had run first.)
//
// Measured consequence (2026-08-12): Aurora Store 4.8.4's AuroraApp.onCreate
// aborts at the R8-inserted `getstatic nk3.a` class-init trigger for the
// inlined HiddenApiBypass.addHiddenApiExemptions -- and that getstatic sits
// OUTSIDE the ReflectiveOperationException handler R8 kept around the actual
// bypass calls, so the ExceptionInInitializerError escapes Application.onCreate
// entirely and ~580 bytecodes of app setup never run.
//
// WHAT THIS CLASS IS
// ------------------
// A faithful port of AOSP libcore's sun.misc.Unsafe -- the EXACT public surface
// (68 methods; nothing added, nothing removed), with AOSP's own bodies where
// AOSP writes them in Java, delegating to the host's jdk.internal.misc.Unsafe
// where AOSP delegates to its own native/internal Unsafe. That is precisely the
// shape of the real thing: the JDK's own sun.misc.Unsafe is likewise a thin
// facade over jdk.internal.misc.Unsafe.
//
// Source of truth, fetched 2026-08-12:
//   ojluni/src/main/java/sun/misc/Unsafe.java  (AOSP libcore; read via the
//   GrapheneOS/platform_libcore mirror, branch `17`, because
//   cs.android.com is JS-rendered and returns empty to WebFetch and
//   aosp-mirror/platform_libcore 404s)
//   - class + singletons + getUnsafe(): lines 46-75
//   - objectFieldOffset / arrayBaseOffset / arrayIndexScale: lines 91-136
//   - getAndAddInt/Long, getAndSetInt/Long/Object (CAS loops): lines 725-812
//
// The surface being EXACTLY AOSP's is load-bearing, not tidiness: guest
// bytecode is compiled against the Android SDK, so it can only ever reference
// what AOSP declares. Mirroring AOSP exactly is therefore complete BY
// CONSTRUCTION for any Android app, and adding JDK-only methods (invokeCleaner,
// staticFieldOffset, defineClass, ...) would let a guest observe a surface no
// device has.
//
// HOW IT IS DELIVERED
// -------------------
// javac refuses `package sun.misc;` in the unnamed module ("package exists in
// another module: jdk.unsupported"), so this compiles under
// `--patch-module jdk.unsupported=<this dir>` and the runtime passes the
// matching `--patch-module=jdk.unsupported=<lib>/jdk_unsupported_patch`
// (runtime/src/main.cpp). It REPLACES the JDK's class VM-wide rather than
// shadowing per-loader, which keeps exactly one sun.misc.Unsafe in the VM (no
// loader-constraint hazard) and keeps Unsafe.class.getClassLoader() == null,
// i.e. the bootclasspath identity AOSP's own check is written against.
//
// Blast-radius survey done before choosing VM-wide (2026-08-12): the only
// consumer anywhere in this tree is runtime/java/libcore/io/Memory.java, which
// reaches Unsafe by name via the `theUnsafe` FIELD and binds MethodHandles for
// getByte/getShort/getInt/getLong(long) and putByte/putShort/putInt/putLong
// (long,x) -- every one of which AOSP declares and this class provides. bcprov
// has zero references; the runtime's C++/Swift has zero; nothing in java.base
// uses sun.misc.Unsafe (the JDK uses jdk.internal.misc.Unsafe internally).
//
// NO em dashes in this file (project convention).
package sun.misc;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public final class Unsafe {
    /** Traditional dalvik name. AOSP libcore Unsafe.java:48. */
    private static final Unsafe THE_ONE = new Unsafe();

    /** AOSP libcore Unsafe.java:50. Kept because libraries (and our own
     *  runtime/java/libcore/io/Memory.java) read this field reflectively as
     *  the second, filter-proof way of obtaining the singleton. */
    private static final Unsafe theUnsafe = THE_ONE;

    private static final jdk.internal.misc.Unsafe theInternalUnsafe =
            jdk.internal.misc.Unsafe.getUnsafe();

    /** AOSP libcore Unsafe.java:52. */
    public static final int INVALID_FIELD_OFFSET = -1;

    /** ART resolves getUnsafe()'s caller with VMStack.getStackClass2(), which
     *  COUNTS reflection frames. HotSpot's Reflection.getCallerClass() is
     *  @CallerSensitive and skips them. We must match ART, or the reflective
     *  entry point every Android library uses is unreachable. SHOW_REFLECT_FRAMES
     *  is what makes java.lang.reflect.Method / the reflection accessors visible
     *  in the walk, exactly as they are visible to ART's stack walker.
     *  RETAIN_CLASS_REFERENCE is required to read getDeclaringClass(). */
    private static final StackWalker CALLER_WALKER =
            StackWalker.getInstance(java.util.Set.of(
                    StackWalker.Option.RETAIN_CLASS_REFERENCE,
                    StackWalker.Option.SHOW_REFLECT_FRAMES));

    /** This class is only privately instantiable. AOSP Unsafe.java:57. */
    private Unsafe() {}

    /**
     * Gets the unique instance of this class. This is only allowed in
     * very limited situations.
     *
     * AOSP libcore Unsafe.java:63-75, verbatim logic:
     *
     *     Class<?> caller = Reflection.getCallerClass();
     *     ClassLoader calling = (caller == null) ? null : caller.getClassLoader();
     *     if ((calling != null) && (calling != Unsafe.class.getClassLoader())) {
     *         throw new SecurityException("Unsafe access denied");
     *     }
     *     return THE_ONE;
     *
     * The ONLY substitution is how "the caller" is resolved, and that
     * substitution is what makes us match the device rather than the host:
     * see CALLER_WALKER. The consequences are exactly Android's --
     *   - a DIRECT call from a guest class still throws SecurityException
     *     (the frame above us is the guest class, whose loader is neither null
     *     nor our own), which is what a device does;
     *   - a REFLECTIVE call succeeds, because the frame above us is the
     *     reflection machinery, which is bootclasspath code.
     */
    public static Unsafe getUnsafe() {
        Class<?> caller = callerClass();
        /*
         * Only code on the bootclasspath is allowed to get at the
         * Unsafe instance.
         */
        ClassLoader calling = (caller == null) ? null : caller.getClassLoader();
        if ((calling != null) && (calling != Unsafe.class.getClassLoader())) {
            throw new SecurityException("Unsafe access denied");
        }

        return THE_ONE;
    }

    /** The first frame above getUnsafe(), reflection frames INCLUDED. Returns
     *  null if the walk cannot produce one, which getUnsafe() treats as
     *  bootclasspath (AOSP does the same for a null caller). */
    private static Class<?> callerClass() {
        try {
            return CALLER_WALKER.walk(s -> s
                    .map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(c -> c != Unsafe.class)
                    .findFirst()
                    .orElse(null));
        } catch (Throwable t) {
            // A stack walk must never be the reason Unsafe is unavailable.
            return null;
        }
    }

    // ---- offsets -------------------------------------------------------
    // AOSP Unsafe.java:91-136. The guards are AOSP's; the final call is where
    // AOSP calls its own theInternalUnsafe.

    /**
     * Gets the raw byte offset from the start of an object's memory to
     * the memory used to store the indicated instance field.
     */
    public long objectFieldOffset(Field f) {
        if (f == null) {
            throw new NullPointerException();
        }
        Class<?> declaringClass = f.getDeclaringClass();
        if (Modifier.isStatic(f.getModifiers())) {
            throw new IllegalArgumentException("valid for instance fields only");
        }
        if (declaringClass.isHidden()) {
            throw new UnsupportedOperationException(
                    "can't get field offset on a hidden class: " + f);
        }
        // AOSP gates the record rejection on
        // forbidObtainingRecordFieldOffsets(), i.e. SDK > BAKLAVA on BOTH the
        // device and the app's target. Apk on Mac presents SDK 29, so that gate
        // is false and AOSP would ALLOW a record field offset here. The host's
        // jdk.internal.misc.Unsafe rejects records unconditionally, so a guest
        // asking for a record field offset gets UnsupportedOperationException
        // either way. Left as a known, bounded divergence rather than faked:
        // records need API 34+ and are vanishingly rare in shipped APKs.
        return theInternalUnsafe.objectFieldOffset(f);
    }

    /**
     * Gets the offset from the start of an array object's memory to
     * the memory used to store its initial (zeroeth) element.
     */
    public int arrayBaseOffset(Class clazz) {
        Class<?> component = clazz.getComponentType();
        if (component == null) {
            throw new IllegalArgumentException("Valid for array classes only: " + clazz);
        }
        // (int): jdk.internal.misc.Unsafe.arrayBaseOffset returns int on JDK 21 and
        // long from JDK 25 (src.zip 25.0.2, jdk/internal/misc/Unsafe.java). An
        // array base offset is a header size (16 on arm64), so the narrowing is
        // exact, and the cast keeps ONE source compiling on both JDKs; libcore's
        // public API (what apps call) stays int, as on Android.
        return (int) theInternalUnsafe.arrayBaseOffset(clazz);
    }

    /** Gets the size of each element of the given array class. */
    public int arrayIndexScale(Class clazz) {
        Class<?> component = clazz.getComponentType();
        if (component == null) {
            throw new IllegalArgumentException("Valid for array classes only: " + clazz);
        }
        return theInternalUnsafe.arrayIndexScale(clazz);
    }

    // ---- compare-and-swap ----------------------------------------------
    // AOSP names these compareAndSwapX (the pre-JDK9 spelling). The host's
    // internal Unsafe renamed them compareAndSetX / ...Reference.

    public boolean compareAndSwapInt(Object obj, long offset,
            int expectedValue, int newValue) {
        return theInternalUnsafe.compareAndSetInt(obj, offset, expectedValue, newValue);
    }

    public boolean compareAndSwapLong(Object obj, long offset,
            long expectedValue, long newValue) {
        return theInternalUnsafe.compareAndSetLong(obj, offset, expectedValue, newValue);
    }

    public boolean compareAndSwapObject(Object obj, long offset,
            Object expectedValue, Object newValue) {
        return theInternalUnsafe.compareAndSetReference(obj, offset, expectedValue, newValue);
    }

    // ---- volatile object-field access ----------------------------------

    public int getIntVolatile(Object obj, long offset) {
        return theInternalUnsafe.getIntVolatile(obj, offset);
    }

    public void putIntVolatile(Object obj, long offset, int newValue) {
        theInternalUnsafe.putIntVolatile(obj, offset, newValue);
    }

    public long getLongVolatile(Object obj, long offset) {
        return theInternalUnsafe.getLongVolatile(obj, offset);
    }

    public void putLongVolatile(Object obj, long offset, long newValue) {
        theInternalUnsafe.putLongVolatile(obj, offset, newValue);
    }

    public Object getObjectVolatile(Object obj, long offset) {
        return theInternalUnsafe.getReferenceVolatile(obj, offset);
    }

    public void putObjectVolatile(Object obj, long offset, Object newValue) {
        theInternalUnsafe.putReferenceVolatile(obj, offset, newValue);
    }

    // ---- plain object-field access -------------------------------------

    public int getInt(Object obj, long offset) {
        return theInternalUnsafe.getInt(obj, offset);
    }

    public void putInt(Object obj, long offset, int newValue) {
        theInternalUnsafe.putInt(obj, offset, newValue);
    }

    /** Lazy/ordered store. AOSP's putOrderedX is the release-store; the host
     *  spells it putXRelease. */
    public void putOrderedInt(Object obj, long offset, int newValue) {
        theInternalUnsafe.putIntRelease(obj, offset, newValue);
    }

    public long getLong(Object obj, long offset) {
        return theInternalUnsafe.getLong(obj, offset);
    }

    public void putLong(Object obj, long offset, long newValue) {
        theInternalUnsafe.putLong(obj, offset, newValue);
    }

    public void putOrderedLong(Object obj, long offset, long newValue) {
        theInternalUnsafe.putLongRelease(obj, offset, newValue);
    }

    public Object getObject(Object obj, long offset) {
        return theInternalUnsafe.getReference(obj, offset);
    }

    public void putObject(Object obj, long offset, Object newValue) {
        theInternalUnsafe.putReference(obj, offset, newValue);
    }

    public void putOrderedObject(Object obj, long offset, Object newValue) {
        theInternalUnsafe.putReferenceRelease(obj, offset, newValue);
    }

    public boolean getBoolean(Object obj, long offset) {
        return theInternalUnsafe.getBoolean(obj, offset);
    }

    public void putBoolean(Object obj, long offset, boolean newValue) {
        theInternalUnsafe.putBoolean(obj, offset, newValue);
    }

    public byte getByte(Object obj, long offset) {
        return theInternalUnsafe.getByte(obj, offset);
    }

    public void putByte(Object obj, long offset, byte newValue) {
        theInternalUnsafe.putByte(obj, offset, newValue);
    }

    public char getChar(Object obj, long offset) {
        return theInternalUnsafe.getChar(obj, offset);
    }

    public void putChar(Object obj, long offset, char newValue) {
        theInternalUnsafe.putChar(obj, offset, newValue);
    }

    public short getShort(Object obj, long offset) {
        return theInternalUnsafe.getShort(obj, offset);
    }

    public void putShort(Object obj, long offset, short newValue) {
        theInternalUnsafe.putShort(obj, offset, newValue);
    }

    public float getFloat(Object obj, long offset) {
        return theInternalUnsafe.getFloat(obj, offset);
    }

    public void putFloat(Object obj, long offset, float newValue) {
        theInternalUnsafe.putFloat(obj, offset, newValue);
    }

    public double getDouble(Object obj, long offset) {
        return theInternalUnsafe.getDouble(obj, offset);
    }

    public void putDouble(Object obj, long offset, double newValue) {
        theInternalUnsafe.putDouble(obj, offset, newValue);
    }

    // ---- parking -------------------------------------------------------

    /** Parks the calling thread. AOSP Unsafe.java:486. */
    public void park(boolean absolute, long time) {
        theInternalUnsafe.park(absolute, time);
    }

    /** Unparks the given object, which must be a Thread. AOSP Unsafe.java:496. */
    public void unpark(Object obj) {
        theInternalUnsafe.unpark(obj);
    }

    /**
     * Allocates an instance of the given class without running any constructor.
     *
     * AOSP declares this native with NO checked exception; the host's
     * internal Unsafe declares InstantiationException. Guest bytecode compiled
     * against the Android SDK does not catch it and does not list it, so
     * letting a checked exception escape here would be a surface a device
     * never has. Wrapped as InstantiationError, which is what a failed
     * instantiation surfaces as on the VM anyway.
     */
    public Object allocateInstance(Class<?> c) {
        try {
            return theInternalUnsafe.allocateInstance(c);
        } catch (InstantiationException e) {
            InstantiationError err = new InstantiationError(String.valueOf(e.getMessage()));
            err.initCause(e);
            throw err;
        }
    }

    // ---- raw memory ----------------------------------------------------

    /** Size of a native pointer, in bytes. AOSP Unsafe.java:510. */
    public int addressSize() {
        return theInternalUnsafe.addressSize();
    }

    /** Size of a native page, in bytes. AOSP Unsafe.java:518. */
    public int pageSize() {
        return theInternalUnsafe.pageSize();
    }

    public long allocateMemory(long bytes) {
        return theInternalUnsafe.allocateMemory(bytes);
    }

    public void freeMemory(long address) {
        theInternalUnsafe.freeMemory(address);
    }

    public void setMemory(long address, long bytes, byte value) {
        theInternalUnsafe.setMemory(address, bytes, value);
    }

    public byte getByte(long address) {
        return theInternalUnsafe.getByte(address);
    }

    public void putByte(long address, byte x) {
        theInternalUnsafe.putByte(address, x);
    }

    public short getShort(long address) {
        return theInternalUnsafe.getShort(address);
    }

    public void putShort(long address, short x) {
        theInternalUnsafe.putShort(address, x);
    }

    public char getChar(long address) {
        return theInternalUnsafe.getChar(address);
    }

    public void putChar(long address, char x) {
        theInternalUnsafe.putChar(address, x);
    }

    public int getInt(long address) {
        return theInternalUnsafe.getInt(address);
    }

    public void putInt(long address, int x) {
        theInternalUnsafe.putInt(address, x);
    }

    public long getLong(long address) {
        return theInternalUnsafe.getLong(address);
    }

    public void putLong(long address, long x) {
        theInternalUnsafe.putLong(address, x);
    }

    public float getFloat(long address) {
        return theInternalUnsafe.getFloat(address);
    }

    public void putFloat(long address, float x) {
        theInternalUnsafe.putFloat(address, x);
    }

    public double getDouble(long address) {
        return theInternalUnsafe.getDouble(address);
    }

    public void putDouble(long address, double x) {
        theInternalUnsafe.putDouble(address, x);
    }

    /** Copies raw memory into a primitive array. AOSP Unsafe.java:683.
     *  The host expresses "raw address" as a null base object. */
    public void copyMemoryToPrimitiveArray(long srcAddr, Object dst,
            long dstOffset, long bytes) {
        theInternalUnsafe.copyMemory(null, srcAddr, dst, dstOffset, bytes);
    }

    /** Copies a primitive array into raw memory. AOSP Unsafe.java:696. */
    public void copyMemoryFromPrimitiveArray(Object src, long srcOffset,
            long dstAddr, long bytes) {
        theInternalUnsafe.copyMemory(src, srcOffset, null, dstAddr, bytes);
    }

    /** Copies raw memory to raw memory. AOSP Unsafe.java:707. */
    public void copyMemory(long srcAddr, long dstAddr, long bytes) {
        theInternalUnsafe.copyMemory(srcAddr, dstAddr, bytes);
    }

    // ---- CAS-based helpers ---------------------------------------------
    // AOSP writes these in Java as CAS loops (Unsafe.java:725-812) rather than
    // delegating, and they are `final`. Mirrored body-for-body: they call OUR
    // methods, so anything that instruments this class sees the same traffic a
    // device would.

    public final int getAndAddInt(Object o, long offset, int delta) {
        int v;
        do {
            v = getIntVolatile(o, offset);
        } while (!compareAndSwapInt(o, offset, v, v + delta));
        return v;
    }

    public final long getAndAddLong(Object o, long offset, long delta) {
        long v;
        do {
            v = getLongVolatile(o, offset);
        } while (!compareAndSwapLong(o, offset, v, v + delta));
        return v;
    }

    public final int getAndSetInt(Object o, long offset, int newValue) {
        int v;
        do {
            v = getIntVolatile(o, offset);
        } while (!compareAndSwapInt(o, offset, v, newValue));
        return v;
    }

    public final long getAndSetLong(Object o, long offset, long newValue) {
        long v;
        do {
            v = getLongVolatile(o, offset);
        } while (!compareAndSwapLong(o, offset, v, newValue));
        return v;
    }

    public final Object getAndSetObject(Object o, long offset, Object newValue) {
        Object v;
        do {
            v = getObjectVolatile(o, offset);
        } while (!compareAndSwapObject(o, offset, v, newValue));
        return v;
    }

    // ---- fences --------------------------------------------------------

    public void loadFence() {
        theInternalUnsafe.loadFence();
    }

    public void storeFence() {
        theInternalUnsafe.storeFence();
    }

    public void fullFence() {
        theInternalUnsafe.fullFence();
    }
}
