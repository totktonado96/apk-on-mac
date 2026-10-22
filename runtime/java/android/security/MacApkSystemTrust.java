// android.security.MacApkSystemTrust -- the macOS admin/user-domain trusted
// roots (enterprise CAs pushed by MDM, a corporate / dev CA trusted in Keychain
// Access) made visible to the JVM's TLS trust.
//
// WHY a merged file and not -Djavax.net.ssl.trustStoreType=KeychainStore-ROOT:
// that type only exists from JDK 23, and the default build links JDK 21
// (runtime/scripts/build.sh); on 21 an unknown type makes the DEFAULT trust
// manager fail at first use, i.e. every HTTPS request. It would also REPLACE the
// bundled cacerts rather than add to them, and does not honour per-cert Deny.
// Instead the roots (trust settings already applied natively, see
// bionic_shim_cacerts.cpp) are unioned into a copy of the JDK's cacerts, cached
// by digest, and pointed at with the standard javax.net.ssl.trustStore*
// properties. That reaches EVERY consumer of the default store -- the default
// SSLContext, HttpsURLConnection, and apps (OkHttp, Cronet-less stacks) that do
// TrustManagerFactory.init((KeyStore) null) -- which a SSLContext.setDefault
// replacement would miss. The properties are read once, on first TLS use, so
// Boot calls this before any app code.
//
// MACAPK_SYSTEM_TRUST=0 skips it. An app-/user-supplied trustStore property is
// left alone.
package android.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class MacApkSystemTrust {
    private MacApkSystemTrust() {}

    private static final String TAG = "SystemTrust";
    private static final char[] PW = "changeit".toCharArray();   // the JDK cacerts convention

    private static native byte[][] nativeUserRoots();

    public static boolean enabled() { return !"0".equals(System.getenv("MACAPK_SYSTEM_TRUST")); }

    private static List<X509Certificate> sRoots;
    private static List<byte[]> sRootDers;

    /** The admin/user-domain roots macOS trusts for TLS (denied ones excluded);
     *  empty when off, unbridged or none. */
    public static synchronized List<X509Certificate> userRoots() {
        if (sRoots != null) return sRoots;
        List<X509Certificate> out = new ArrayList<>();
        List<byte[]> ders = new ArrayList<>();
        if (enabled()) {
            try {
                byte[][] raw = nativeUserRoots();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                if (raw != null) for (byte[] d : raw) {
                    try {
                        out.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(d)));
                        ders.add(d);
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable t) {
                // UnsatisfiedLinkError on a binary without the bridge: no extra roots.
            }
        }
        sRootDers = ders;
        return sRoots = Collections.unmodifiableList(out);
    }

    /** Point the JVM's default trust store at JDK cacerts + userRoots(). */
    public static void installDefaultTrust() {
        if (!enabled() || System.getProperty("javax.net.ssl.trustStore") != null) return;
        List<X509Certificate> roots = userRoots();
        if (roots.isEmpty()) return;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] d : sRootDers) md.update(d);
            StringBuilder key = new StringBuilder();
            byte[] sum = md.digest();
            for (int i = 0; i < 8; i++) key.append(String.format("%02x", sum[i]));
            File dir = new File(System.getenv("HOME") + "/Library/Caches/MacApk/jvm-truststore");
            File f = new File(dir, key + ".p12");
            if (!f.isFile()) {
                dir.mkdirs();
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                File jdk = new File(System.getProperty("java.home"), "lib/security/cacerts");
                KeyStore base = KeyStore.getInstance("JKS");
                try (FileInputStream in = new FileInputStream(jdk)) { base.load(in, PW); }
                for (java.util.Enumeration<String> e = base.aliases(); e.hasMoreElements();) {
                    String a = e.nextElement();
                    java.security.cert.Certificate c = base.getCertificate(a);
                    if (c != null) ks.setCertificateEntry("jdk:" + a, c);
                }
                int n = 0;
                for (X509Certificate c : roots) ks.setCertificateEntry("macos:" + (n++), c);
                File tmp = new File(dir, key + ".tmp" + ProcessHandle.current().pid());
                try (FileOutputStream out = new FileOutputStream(tmp)) { ks.store(out, PW); }
                if (!tmp.renameTo(f)) tmp.delete();   // lost a race: the winner's file is identical
            }
            if (!f.isFile()) return;
            System.setProperty("javax.net.ssl.trustStore", f.getAbsolutePath());
            System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
            System.setProperty("javax.net.ssl.trustStorePassword", new String(PW));
            com.macapk.loader.NativeLog.i(TAG, "default TLS trust = JDK cacerts + " + roots.size()
                    + " macOS admin/user roots (" + f + ")");
        } catch (Throwable t) {
            com.macapk.loader.NativeLog.w(TAG, "could not merge macOS trust (" + t
                    + "); JDK cacerts only");
        }
    }
}
