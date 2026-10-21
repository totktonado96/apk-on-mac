/*
 * Copyright (c) 2001, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk.internal.reflect;

import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import jdk.internal.access.SharedSecrets;
import jdk.internal.misc.VM;
import jdk.internal.module.ModuleBootstrap;
import jdk.internal.vm.annotation.ForceInline;
import jdk.internal.vm.annotation.IntrinsicCandidate;

/** Common utility routines used by both java.lang and
    java.lang.reflect */

public class Reflection {

    /** Used to filter out fields and methods from certain classes from public
        view, where they are sensitive or they may contain VM-internal objects.
        These Maps are updated very rarely. Rather than synchronize on
        each access, we use copy-on-write */
    private static volatile Map<Class<?>, Set<String>> fieldFilterMap;
    private static volatile Map<Class<?>, Set<String>> methodFilterMap;
    private static final String WILDCARD = "*";
    public static final Set<String> ALL_MEMBERS = Set.of(WILDCARD);

    static {
        fieldFilterMap = Map.of(
            Reflection.class, ALL_MEMBERS,
            AccessibleObject.class, ALL_MEMBERS,
            Class.class, Set.of("classLoader", "classData"),
            // ⚠ Mac.apk java.base overlay (--patch-module java.base). This file is
            // the JDK 21 jdk.internal.reflect.Reflection VERBATIM except that the
            // stock line `ClassLoader.class, ALL_MEMBERS,` has been REMOVED from
            // this map (it sat right here). Stock HotSpot filters EVERY field of
            // java.lang.ClassLoader out of reflection (getDeclaredField[s] see
            // nothing). Android's ART does NOT filter ClassLoader, and real apps
            // rely on that: com.facebook.common.dextricks.MultiDexClassLoader.
            // <clinit> does ClassLoader.class.getDeclaredField("parent").get(
            // appLoader) to locate the system loader, and on stock HotSpot that
            // throws NoSuchFieldException -> ExceptionInInitializerError ->
            // FatalDexError -> System.exit(10), which blocked Instagram's feed.
            // Dropping this ONE entry (every other filtered class is untouched)
            // makes our HotSpot present the same reflective ClassLoader surface
            // ART does. App-agnostic; matches the target platform's behaviour.
            Constructor.class, ALL_MEMBERS,
            Field.class, ALL_MEMBERS,
            Method.class, ALL_MEMBERS,
            Module.class, ALL_MEMBERS,
            System.class, Set.of("security")
        );
        methodFilterMap = Map.of();
    }

    /** Returns the class of the caller of the method calling this method,
        ignoring frames associated with java.lang.reflect.Method.invoke()
        and its implementation. */
    @CallerSensitive
    @IntrinsicCandidate
    public static native Class<?> getCallerClass();

    /** Retrieves the access flags written to the class file. For
        inner classes these flags may differ from those returned by
        Class.getModifiers(), which searches the InnerClasses
        attribute to find the source-level access flags. This is used
        instead of Class.getModifiers() for run-time access checks due
        to compatibility reasons; see 4471811. Only the values of the
        low 13 bits (i.e., a mask of 0x1FFF) are guaranteed to be
        valid. */
    @IntrinsicCandidate
    public static native int getClassAccessFlags(Class<?> c);


    /**
     * Ensures that access to a member is granted and throws
     * IllegalAccessException if not.
     *
     * @param currentClass the class performing the access
     * @param memberClass the declaring class of the member being accessed
     * @param targetClass the class of target object if accessing instance
     *                    field or method;
     *                    or the declaring class if accessing constructor;
     *                    or null if accessing static field or method
     * @param modifiers the member's access modifiers
     * @throws IllegalAccessException if access to member is denied
     */
    public static void ensureMemberAccess(Class<?> currentClass,
                                          Class<?> memberClass,
                                          Class<?> targetClass,
                                          int modifiers)
        throws IllegalAccessException
    {
        if (!verifyMemberAccess(currentClass, memberClass, targetClass, modifiers)) {
            throw newIllegalAccessException(currentClass, memberClass, targetClass, modifiers);
        }
    }

    @ForceInline
    public static void ensureNativeAccess(Class<?> currentClass, Class<?> owner, String methodName) {
        // if there is no caller class, act as if the call came from unnamed module of system class loader
        Module module = currentClass != null ?
                currentClass.getModule() :
                ClassLoader.getSystemClassLoader().getUnnamedModule();
        SharedSecrets.getJavaLangAccess().ensureNativeAccess(module, owner, methodName);
    }

    /**
     * Verify access to a member and return {@code true} if it is granted.
     *
     * @param currentClass the class performing the access
     * @param memberClass the declaring class of the member being accessed
     * @param targetClass the class of target object if accessing instance
     *                    field or method;
     *                    or the declaring class if accessing constructor;
     *                    or null if accessing static field or method
     * @param modifiers the member's access modifiers
     * @return {@code true} if access to member is granted
     */
    public static boolean verifyMemberAccess(Class<?> currentClass,
                                             Class<?> memberClass,
                                             Class<?> targetClass,
                                             int modifiers)
    {
        Objects.requireNonNull(currentClass);
        Objects.requireNonNull(memberClass);

        if (currentClass == memberClass) {
            // Always succeeds
            return true;
        }

        if (!verifyModuleAccess(currentClass.getModule(), memberClass)) {
            return false;
        }

        boolean gotIsSameClassPackage = false;
        boolean isSameClassPackage = false;

        // ⚠ Mac.apk java.base overlay, second deviation from JDK 21: a PUBLIC
        // member is accessible whatever its declaring class's access. The
        // stock code first rejects any non-public declaring class from
        // another package, so Method.invoke on a public method of a
        // package-private class throws IllegalAccessException unless the
        // caller called setAccessible(true). ART never checks the class:
        // art/runtime/reflection.cc VerifyAccess() starts with
        // `if ((access_flags & kAccPublic) != 0) return true;`, and apps
        // rely on it. React Native's ViewManagersPropertyCache invokes
        // react-native-svg's setters on the package-private
        // VirtualViewManager$c this way; on stock HotSpot that threw,
        // aborted the createView batch, and left the Xbox app black after
        // sign-in. verifyModuleAccess above still runs first, so JDK
        // module encapsulation is unchanged. Non-public members keep the
        // stock checks, which already require the same package (or a
        // subclass, or a nestmate) and so match ART for them too.
        if (Modifier.isPublic(modifiers)) {
            return true;
        }

        if (!Modifier.isPublic(getClassAccessFlags(memberClass))) {
            isSameClassPackage = isSameClassPackage(currentClass, memberClass);
            gotIsSameClassPackage = true;
            if (!isSameClassPackage) {
                return false;
            }
        }

        // At this point we know that currentClass can access memberClass.

        // Check for nestmate access if member is private
        if (Modifier.isPrivate(modifiers)) {
            // Note: targetClass may be outside the nest, but that is okay
            //       as long as memberClass is in the nest.
            if (areNestMates(currentClass, memberClass)) {
                return true;
            }
        }

        boolean successSoFar = false;

        if (Modifier.isProtected(modifiers)) {
            // See if currentClass is a subclass of memberClass
            if (isSubclassOf(currentClass, memberClass)) {
                successSoFar = true;
            }
        }

        if (!successSoFar && !Modifier.isPrivate(modifiers)) {
            if (!gotIsSameClassPackage) {
                isSameClassPackage = isSameClassPackage(currentClass,
                                                        memberClass);
                gotIsSameClassPackage = true;
            }

            if (isSameClassPackage) {
                successSoFar = true;
            }
        }

        if (!successSoFar) {
            return false;
        }

        // Additional test for protected instance members
        // and protected constructors: JLS 6.6.2
        if (targetClass != null && Modifier.isProtected(modifiers) &&
            targetClass != currentClass)
        {
            if (!gotIsSameClassPackage) {
                isSameClassPackage = isSameClassPackage(currentClass, memberClass);
                gotIsSameClassPackage = true;
            }
            if (!isSameClassPackage) {
                if (!isSubclassOf(targetClass, currentClass)) {
                    return false;
                }
            }
        }

        return true;
    }

    /*
     * Verify if a member is public and memberClass is a public type
     * in a package that is unconditionally exported and
     * return {@code true} if it is granted.
     *
     * @param memberClass the declaring class of the member being accessed
     * @param modifiers the member's access modifiers
     * @return {@code true} if the member is public and in a publicly accessible type
     */
    public static boolean verifyPublicMemberAccess(Class<?> memberClass, int modifiers) {
        Module m = memberClass.getModule();
        return Modifier.isPublic(modifiers)
            && m.isExported(memberClass.getPackageName())
            && Modifier.isPublic(Reflection.getClassAccessFlags(memberClass));
    }

    /**
     * Returns {@code true} if memberClass's module exports memberClass's
     * package to currentModule.
     */
    public static boolean verifyModuleAccess(Module currentModule, Class<?> memberClass) {
        Module memberModule = memberClass.getModule();
        if (currentModule == memberModule) {
            // same module (named or unnamed) or both null if called
            // before module system is initialized, which means we are
            // dealing with java.base only.
            return true;
        } else {
            String pkg = memberClass.getPackageName();
            return memberModule.isExported(pkg, currentModule);
        }
    }

    /**
     * Returns true if two classes in the same package.
     */
    private static boolean isSameClassPackage(Class<?> c1, Class<?> c2) {
        if (c1.getClassLoader() != c2.getClassLoader())
            return false;
        return Objects.equals(c1.getPackageName(), c2.getPackageName());
    }

    static boolean isSubclassOf(Class<?> queryClass,
                                Class<?> ofClass)
    {
        while (queryClass != null) {
            if (queryClass == ofClass) {
                return true;
            }
            queryClass = queryClass.getSuperclass();
        }
        return false;
    }

    // fieldNames must contain only interned Strings
    public static synchronized void registerFieldsToFilter(Class<?> containingClass,
                                                           Set<String> fieldNames) {
        fieldFilterMap =
            registerFilter(fieldFilterMap, containingClass, fieldNames);
    }

    // methodNames must contain only interned Strings
    public static synchronized void registerMethodsToFilter(Class<?> containingClass,
                                                            Set<String> methodNames) {
        methodFilterMap =
            registerFilter(methodFilterMap, containingClass, methodNames);
    }

    private static Map<Class<?>, Set<String>> registerFilter(Map<Class<?>, Set<String>> map,
                                                             Class<?> containingClass,
                                                             Set<String> names) {
        if (map.get(containingClass) != null) {
            throw new IllegalArgumentException
                            ("Filter already registered: " + containingClass);
        }
        map = new HashMap<>(map);
        map.put(containingClass, Set.copyOf(names));
        return map;
    }

    public static Field[] filterFields(Class<?> containingClass, Field[] fields) {
        if (fieldFilterMap == null) {
            // Bootstrapping
            return fields;
        }
        return (Field[])filter(fields, fieldFilterMap.get(containingClass));
    }

    public static Method[] filterMethods(Class<?> containingClass, Method[] methods) {
        if (methodFilterMap == null) {
            // Bootstrapping
            return methods;
        }
        return (Method[])filter(methods, methodFilterMap.get(containingClass));
    }

    private static Member[] filter(Member[] members, Set<String> filteredNames) {
        if ((filteredNames == null) || (members.length == 0)) {
            return members;
        }
        Class<?> memberType = members[0].getClass();
        if (filteredNames.contains(WILDCARD)) {
            return (Member[]) Array.newInstance(memberType, 0);
        }
        int numNewMembers = 0;
        for (Member member : members) {
            if (!filteredNames.contains(member.getName())) {
                ++numNewMembers;
            }
        }
        Member[] newMembers = (Member[])Array.newInstance(memberType, numNewMembers);
        int destIdx = 0;
        for (Member member : members) {
            if (!filteredNames.contains(member.getName())) {
                newMembers[destIdx++] = member;
            }
        }
        return newMembers;
    }

    /**
     * Tests if the given method is caller-sensitive and the declaring class
     * is defined by either the bootstrap class loader or platform class loader.
     */
    public static boolean isCallerSensitive(Method m) {
        final ClassLoader loader = m.getDeclaringClass().getClassLoader();
        if (VM.isSystemDomainLoader(loader)) {
            return m.isAnnotationPresent(CallerSensitive.class);
        }
        return false;
    }

    /*
     * Tests if the given Field is a trusted final field and it cannot be
     * modified reflectively regardless of the value of its accessible flag.
     */
    public static boolean isTrustedFinalField(Field field) {
        return SharedSecrets.getJavaLangReflectAccess().isTrustedFinalField(field);
    }

    /**
     * Returns an IllegalAccessException with an exception message based on
     * the access that is denied.
     */
    public static IllegalAccessException newIllegalAccessException(Class<?> currentClass,
                                                                   Class<?> memberClass,
                                                                   Class<?> targetClass,
                                                                   int modifiers)
    {
        if (currentClass == null)
            return newIllegalAccessException(memberClass, modifiers);

        String currentSuffix = "";
        String memberSuffix = "";
        Module m1 = currentClass.getModule();
        if (m1.isNamed())
            currentSuffix = " (in " + m1 + ")";
        Module m2 = memberClass.getModule();
        if (m2.isNamed())
            memberSuffix = " (in " + m2 + ")";

        String memberPackageName = memberClass.getPackageName();

        String msg = currentClass + currentSuffix + " cannot access ";
        if (m2.isExported(memberPackageName, m1)) {
            // module access okay so include the modifiers in the message
            msg += "a member of " + memberClass + memberSuffix + msgSuffix(modifiers);
        } else {
            // module access failed
            msg += memberClass + memberSuffix+ " because "
                   + m2 + " does not export " + memberPackageName;
            if (m2.isNamed()) msg += " to " + m1;
        }

        return new IllegalAccessException(msg);
    }

    /**
     * Returns an IllegalAccessException with an exception message where
     * there is no caller frame.
     */
    private static IllegalAccessException newIllegalAccessException(Class<?> memberClass,
                                                                    int modifiers)
    {
        String memberSuffix = "";
        Module m2 = memberClass.getModule();
        if (m2.isNamed())
            memberSuffix = " (in " + m2 + ")";

        String memberPackageName = memberClass.getPackageName();

        String msg = "JNI attached native thread (null caller frame) cannot access ";
        if (m2.isExported(memberPackageName)) {
            // module access okay so include the modifiers in the message
            msg += "a member of " + memberClass + memberSuffix + msgSuffix(modifiers);
        } else {
            // module access failed
            msg += memberClass + memberSuffix+ " because "
                + m2 + " does not export " + memberPackageName;
        }

        return new IllegalAccessException(msg);
    }

    private static String msgSuffix(int modifiers) {
        boolean packageAccess =
            ((Modifier.PRIVATE |
              Modifier.PROTECTED |
              Modifier.PUBLIC) & modifiers) == 0;
        return packageAccess ?
            " with package access" :
            " with modifiers \"" + Modifier.toString(modifiers) + "\"";
    }

    /**
     * Returns true if {@code currentClass} and {@code memberClass}
     * are nestmates - that is, if they have the same nesthost as
     * determined by the VM.
     */
    public static native boolean areNestMates(Class<?> currentClass,
                                              Class<?> memberClass);
}
