// McsSpool -- keep FCM messages that arrive on the wrong app's MCS socket.
//
// On a device ONE GMS process owns the MCS connection and hands each message to
// the package named in `category` (GCM's routing field), launching that app's
// FirebaseMessagingService if it is not running (GmsCore McsService ->
// GcmChimeraService, android14 GMS has no AOSP source; the contract is the
// com.google.android.c2dm.intent.RECEIVE broadcast to the target package).
// Apk on Mac has one process PER APP, all logged in under the same androidId, so
// Google may deliver app B's message down app A's socket -- and the cumulative
// stream ack then consumes it (see McsClient.handleData). Instead of losing it,
// the receiving process files it here and app B replays it at its next boot.
//
// Layout: <GmsStore.dir()>/spool/<package>/<millis>-<seq>.msg, java.util.Properties
// ("d.<key>" = data bundle entries, "spooledAt" = epoch millis), files 0600 and
// directories 0700 because the payload is the user's private push data.
//
// Gate: MACAPK_PUSH_SPOOL=0 restores the old drop-and-ack behaviour.
//
// Deliberately NOT done: posting a macOS notification for a spooled message. A
// UNUserNotificationCenter belongs to the posting bundle, so this process could
// only show it under the WRONG app's icon, and a click would launch the wrong app.
// The target app builds its own notification when it replays the message.
package com.macapk.gms;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public final class McsSpool {
    private McsSpool() {}

    private static final int MAX_PER_PACKAGE = 100;
    /** FCM's own cap on `time_to_live` is 4 weeks. */
    private static final long MAX_AGE_MS = 28L * 24 * 3600 * 1000;
    private static final AtomicLong SEQ = new AtomicLong();

    public static boolean enabled() { return !"0".equals(System.getenv("MACAPK_PUSH_SPOOL")); }

    private static File dirFor(String pkg) {
        // pkg comes off the wire: keep it a single path segment.
        String safe = pkg.replaceAll("[^A-Za-z0-9._-]", "_");
        return new File(new File(GmsStore.dir(), "spool"), safe);
    }

    private static void mkdirs700(File d) throws java.io.IOException {
        if (d.isDirectory()) return;
        Files.createDirectories(d.toPath(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }

    /** File a message for `pkg`. Returns false (caller must not ack) if it could
     *  not be stored. */
    public static boolean spool(String pkg, Map<String, String> extras) {
        if (pkg == null || pkg.isEmpty() || extras == null) return false;
        try {
            File d = dirFor(pkg);
            mkdirs700(d.getParentFile());
            mkdirs700(d);
            String[] existing = d.list((dir, n) -> n.endsWith(".msg"));
            if (existing != null && existing.length >= MAX_PER_PACKAGE) {
                Arrays.sort(existing);   // oldest first
                for (int i = 0; i <= existing.length - MAX_PER_PACKAGE; i++) new File(d, existing[i]).delete();
            }
            Properties p = new Properties();
            p.setProperty("spooledAt", Long.toString(System.currentTimeMillis()));
            for (Map.Entry<String, String> e : extras.entrySet()) p.setProperty("d." + e.getKey(), e.getValue());
            String name = String.format("%015d-%06d.msg", System.currentTimeMillis(), SEQ.incrementAndGet() % 1000000);
            File tmp = new File(d, name + ".tmp");
            Set<PosixFilePermission> rw = PosixFilePermissions.fromString("rw-------");
            Files.deleteIfExists(tmp.toPath());
            Files.createFile(tmp.toPath(), PosixFilePermissions.asFileAttribute(rw));
            try (OutputStream o = Files.newOutputStream(tmp.toPath())) { p.store(o, null); }
            Files.move(tmp.toPath(), new File(d, name).toPath(), StandardCopyOption.ATOMIC_MOVE);
            McsClient.log("spooled push for " + pkg + " -> " + name);
            return true;
        } catch (Throwable t) {
            McsClient.log("could not spool push for " + pkg + ": " + t);
            return false;
        }
    }

    /** Deliver every spooled message for `pkg` through the live dispatcher (the
     *  same RECEIVE broadcast a live push uses), oldest first, deleting each. */
    public static int replay(String pkg) {
        if (!enabled() || pkg == null || pkg.isEmpty()) return 0;
        int n = 0;
        try {
            File d = dirFor(pkg);
            String[] names = d.list((dir, nm) -> nm.endsWith(".msg"));
            if (names == null) return 0;
            Arrays.sort(names);
            long now = System.currentTimeMillis();
            for (String nm : names) {
                File f = new File(d, nm);
                Properties p = new Properties();
                try (InputStream in = Files.newInputStream(f.toPath())) { p.load(in); }
                catch (Throwable t) { f.delete(); continue; }
                long at = 0;
                try { at = Long.parseLong(p.getProperty("spooledAt", "0")); } catch (NumberFormatException ignored) {}
                Map<String, String> extras = new LinkedHashMap<>();
                for (String k : p.stringPropertyNames())
                    if (k.startsWith("d.")) extras.put(k.substring(2), p.getProperty(k));
                f.delete();   // delete first: a crashing receiver must not be re-fed forever
                if (at != 0 && now - at > MAX_AGE_MS) continue;
                McsClient.dispatchLocal(pkg, extras);
                n++;
            }
            if (n > 0) McsClient.log("replayed " + n + " spooled push(es) to " + pkg);
        } catch (Throwable t) {
            McsClient.log("spool replay failed for " + pkg + ": " + t);
        }
        return n;
    }
}
