package com.macapk.loader;

import android.content.Intent;
import android.net.Uri;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * ACTION_SEND / ACTION_SEND_MULTIPLE -> the macOS share sheet
 * (NSSharingServicePicker, share_bridge.mm). On a device the chooser lists the
 * apps that take the share; on the Mac the picker lists Mail, Messages,
 * AirDrop, Notes and the rest of the system's sharing services, which is the
 * same role. Payload: EXTRA_TEXT (+ EXTRA_SUBJECT) and EXTRA_STREAM URIs.
 *
 * A stream URI becomes a host file path: a file: URI directly, one of ours
 * (HostDocumentsProvider) through its document id, anything else (an app's own
 * FileProvider, MediaStore) is copied through ContentResolver into a temp dir,
 * because NSSharingService needs a real file. MACAPK_SHARE_SHEET=0 disables
 * this; with no native bridge (an older binary) share() reports false and
 * ActivityHost keeps the mailto: text fallback.
 */
final class ShareSheet {
    private static final String TAG = "Apk on Mac.Share";
    private static final boolean ON = !"0".equals(System.getenv("MACAPK_SHARE_SHEET"));
    private static final int MAX_COPY_BYTES = 256 * 1024 * 1024;

    static boolean enabled() { return ON; }

    /** JNI (share_bridge.mm): present the picker. True when it was queued. */
    private static native boolean nativeShare(String subject, String text, String[] paths);

    /** Present the share sheet for `send` (the intent inside any chooser). */
    static boolean share(Intent send) {
        if (!ON || send == null) return false;
        try {
            CharSequence text = send.getCharSequenceExtra(Intent.EXTRA_TEXT);
            CharSequence subject = send.getCharSequenceExtra(Intent.EXTRA_SUBJECT);
            List<Uri> uris = new ArrayList<>();
            if (Intent.ACTION_SEND_MULTIPLE.equals(send.getAction())) {
                java.util.ArrayList<? extends android.os.Parcelable> l =
                        send.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
                if (l != null) for (android.os.Parcelable p : l) if (p instanceof Uri) uris.add((Uri) p);
            } else {
                android.os.Parcelable p = send.getParcelableExtra(Intent.EXTRA_STREAM);
                if (p instanceof Uri) uris.add((Uri) p);
            }
            List<String> paths = new ArrayList<>();
            for (Uri u : uris) {
                File f = toHostFile(u);
                if (f != null) paths.add(f.getAbsolutePath());
            }
            String t = text != null ? text.toString() : "";
            String s = subject != null ? subject.toString() : "";
            if (t.isEmpty() && s.isEmpty() && paths.isEmpty()) return false;
            return nativeShare(s, t, paths.toArray(new String[0]));
        } catch (UnsatisfiedLinkError e) {
            return false;   // no bridge in this binary: mailto: fallback
        } catch (Throwable t) {
            NativeLog.w(TAG, "share: " + t);
            return false;
        }
    }

    private static File toHostFile(Uri u) {
        if (u == null) return null;
        if ("file".equals(u.getScheme())) {
            File f = new File(u.getPath());
            return f.isFile() ? f : null;
        }
        File own = HostDocumentsProvider.fileForUri(u);
        if (own != null && own.isFile()) return own;
        android.app.Activity a = ActivityHost.peek();
        if (a == null) return null;
        String name = null;
        try (android.database.Cursor c = a.getContentResolver().query(u,
                new String[]{ android.provider.OpenableColumns.DISPLAY_NAME }, null, null, null)) {
            if (c != null && c.moveToFirst()) name = c.getString(0);
        } catch (Throwable ignored) {}
        if (name == null || name.isEmpty()) name = u.getLastPathSegment();
        if (name == null || name.isEmpty()) name = "shared";
        name = name.replace('/', '_').replace('\\', '_');   // a name, never a path
        try {
            File dir = new File(System.getProperty("java.io.tmpdir"), "macapk-share-" + System.nanoTime());
            if (!dir.mkdirs()) return null;
            File out = new File(dir, name);
            try (InputStream in = a.getContentResolver().openInputStream(u);
                 OutputStream os = new java.io.FileOutputStream(out)) {
                if (in == null) return null;
                byte[] buf = new byte[64 * 1024];
                long total = 0;
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_COPY_BYTES) { out.delete(); return null; }
                    os.write(buf, 0, n);
                }
            }
            return out;
        } catch (Throwable t) {
            NativeLog.w(TAG, "share: could not read " + u + ": " + t);
            return null;
        }
    }
}
