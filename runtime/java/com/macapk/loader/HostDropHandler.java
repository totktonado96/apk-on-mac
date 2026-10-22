package com.macapk.loader;

import android.app.Activity;
import android.content.ClipData;
import android.content.Intent;
import android.content.MacApkUriGrants;
import android.content.pm.ResolveInfo;
import android.net.Uri;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Files dropped from Finder onto the app window (cocoa_bridge.mm
 * performDragOperation:). A device hands a dropped/shared file to an app as
 * Intent.ACTION_SEND(_MULTIPLE) with EXTRA_STREAM content:// URIs (what a share
 * sheet or Android 7+ drag-and-drop delivers), or as ACTION_VIEW with the URI
 * ("open with"). We do the same, aimed at the app's OWN package: Apk on Mac runs
 * one app per process, so the receiving app is always this one.
 *
 * The URIs are minted by HostDocumentsProvider.mint (the document picker's
 * mechanism) with a READ grant, and the intent carries FLAG_GRANT_READ_URI_PERMISSION
 * plus a ClipData of the same URIs, which is how ChooserActivity / ClipDescription
 * grants propagate (Intent.migrateExtraStreamToClipData).
 *
 * Order of attempts, each only if the app has an activity that resolves it
 * (PackageManager.queryIntentActivities, as the app itself would check):
 * SEND / SEND_MULTIPLE, then VIEW of the first file. Nothing resolving gives a
 * short Toast. MACAPK_DRAG_DROP=0 turns the feature off (the native side then
 * never registers the drag types).
 */
final class HostDropHandler {
    private static final String TAG = "Apk on Mac.Drop";

    /** JNI-reachable through TouchDispatcher.dispatchHostFiles. */
    static void onDropped(final String[] paths) {
        if (paths == null || paths.length == 0) return;
        ActivityHost.macapkPostOnOwner(() -> {
            try { handle(paths); }
            catch (Throwable t) { NativeLog.w(TAG, "drop: " + t); }
        });
    }

    private static void handle(String[] paths) {
        Activity ctx = ActivityHost.peek();
        if (ctx == null) { NativeLog.i(TAG, "drop: no activity"); return; }
        final String own = ctx.getPackageName();
        List<Uri> uris = new ArrayList<>();
        List<String> types = new ArrayList<>();
        for (String p : paths) {
            if (p == null) continue;
            File f = new File(p);
            if (!f.isFile()) continue;   // a dropped folder has no share semantics
            uris.add(HostDocumentsProvider.mint(f, false));
            types.add(mimeFor(f.getName()));
        }
        if (uris.isEmpty()) return;
        String type = commonType(types);

        Intent send;
        if (uris.size() == 1) {
            send = new Intent(Intent.ACTION_SEND);
            send.putExtra(Intent.EXTRA_STREAM, uris.get(0));
        } else {
            send = new Intent(Intent.ACTION_SEND_MULTIPLE);
            send.putParcelableArrayListExtra(Intent.EXTRA_STREAM, new ArrayList<>(uris));
        }
        send.setType(type);
        if (tryStart(ctx, own, send, uris)) return;

        Intent view = new Intent(Intent.ACTION_VIEW);
        view.setDataAndType(uris.get(0), types.get(0));
        if (tryStart(ctx, own, view, uris.subList(0, 1))) return;

        NativeLog.i(TAG, "drop: no activity of " + own + " resolves SEND or VIEW for " + type);
        android.widget.Toast.makeText(ctx, "This app can't open dropped files",
                android.widget.Toast.LENGTH_SHORT).show();
    }

    private static boolean tryStart(Activity ctx, String own, Intent in, List<Uri> uris) {
        in.setPackage(own);
        in.addCategory(Intent.CATEGORY_DEFAULT);
        in.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
        ClipData clip = new ClipData(null, new String[]{ in.getType() != null ? in.getType() : "*/*" },
                new ClipData.Item(uris.get(0)));
        for (int i = 1; i < uris.size(); i++) clip.addItem(new ClipData.Item(uris.get(i)));
        in.setClipData(clip);
        List<ResolveInfo> rows = ctx.getPackageManager()
                .queryIntentActivities(in, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY);
        boolean mine = false;
        if (rows != null) for (ResolveInfo ri : rows)
            if (ri != null && ri.activityInfo != null && own.equals(ri.activityInfo.packageName)) { mine = true; break; }
        if (!mine) return false;
        MacApkUriGrants.grantFromIntent(in);
        NativeLog.i(TAG, "drop: " + uris.size() + " file(s) -> " + in.getAction() + " " + in.getType());
        ActivityHost.start(in);
        return true;
    }

    private static String mimeFor(String name) {
        int dot = name.lastIndexOf('.');
        String ext = dot >= 0 ? name.substring(dot + 1).toLowerCase(java.util.Locale.ROOT) : "";
        String m = null;
        try { m = android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext); }
        catch (Throwable ignored) {}
        if (m == null) m = java.net.URLConnection.guessContentTypeFromName(name);
        return m != null ? m : "application/octet-stream";
    }

    /** A.getType() equal for all -> it; same major type -> "major/*"; else "*&#47;*". */
    private static String commonType(List<String> types) {
        String first = types.get(0);
        boolean same = true, sameMajor = true;
        String major = first.substring(0, Math.max(0, first.indexOf('/')));
        for (String t : types) {
            if (!t.equals(first)) same = false;
            if (!t.startsWith(major + "/")) sameMajor = false;
        }
        if (same) return first;
        return sameMajor ? major + "/*" : "*/*";
    }
}
