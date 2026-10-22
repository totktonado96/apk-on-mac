// android.security.MacApkNetworkSecurity -- the app's Network Security Config
// (res/xml/network_security_config, android:networkSecurityConfig).
//
// WHAT AOSP DOES (frameworks/base/core/java/android/security/net/config/:
// XmlConfigSource, NetworkSecurityConfig, ApplicationConfig, RootTrustManager,
// NetworkSecurityTrustManager): the XML is parsed once per process into a base
// config plus domain configs; NetworkSecurityPolicy answers cleartext per host;
// and a Conscrypt provider ("AndroidNSSP") replaces the default
// TrustManagerFactory so TrustManagerFactory.init(null) -- what OkHttp and the
// default SSLContext use -- yields a RootTrustManager that picks the matching
// config by the connection's host, validates against THAT config's anchors and
// then checks its pins.
//
// WHAT THIS DOES, the same way: parse -> State; NetworkSecurityPolicy reads State;
// when the app HAS a config, a provider of the same role is inserted at position 1
// (see Provider below) and the default SSLContext / HttpsURLConnection factory are
// rebuilt on it. An app without a config is left completely untouched.
//
// SUPPORTED: <base-config>, <domain-config> (nested ones inherit), <domain
// includeSubdomains>, cleartextTrafficPermitted, <trust-anchors><certificates
// src="system|user|@raw/x">, <pin-set expiration><pin digest="SHA-256">.
// <debug-overrides> is ignored (a release posture, as on a non-debuggable app).
// NOT SUPPORTED: overridePins, certificate transparency config, non-SHA-256 pins
// (skipped, AOSP rejects the whole file).
//
// "user" = the macOS admin/user trusted roots (MacApkSystemTrust); "system" = the
// JDK cacerts + Apple anchors, WITHOUT those roots. An app with no <trust-anchors>
// at all gets both: AOSP's default would be system-only for targetSdk >= 24, but
// that would silently stop honouring the enterprise CAs this Mac's admin trusts for
// every other app, so the no-opinion case follows the Mac.
//
// CLEARTEXT. An explicit cleartextTrafficPermitted (or android:usesCleartextTraffic
// when there is no config) is honoured. AOSP's IMPLICIT default -- false for
// targetSdk >= 28 -- is applied only with MACAPK_NSC_CLEARTEXT=1: Apk on Mac has
// always allowed cleartext, apps that rely on that by accident would newly fail
// (OkHttp throws UnknownServiceException the moment the policy says no), and the
// protection is for cooperative clients only anyway (the JDK's own
// HttpURLConnection does not consult the policy).
//
// MACAPK_NSC=0 disables all of it (policy answers true, no provider installed).
package android.security;

import android.content.res.Resources;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.xmlpull.v1.XmlPullParser;

public final class MacApkNetworkSecurity {
    private MacApkNetworkSecurity() {}

    private static final String TAG = "NetworkSecurityConfig";
    private static final boolean ON = !"0".equals(System.getenv("MACAPK_NSC"));
    private static final boolean ENFORCE_DEFAULT_CLEARTEXT =
            "1".equals(System.getenv("MACAPK_NSC_CLEARTEXT"));

    // ---- model ---------------------------------------------------------------

    /** Which roots a config trusts. certs = explicit @raw certificates. */
    static final class Anchors {
        boolean system, user;
        final List<X509Certificate> certs = new ArrayList<>();
        // built lazily, shared by every config that uses this object
        private X509ExtendedTrustManager tm;
        private KeyStore store;

        synchronized KeyStore store() throws Exception {
            if (store != null) return store;
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            int n = 0;
            List<X509Certificate> user = MacApkSystemTrust.userRoots();
            if (system) {
                for (X509Certificate c : defaultIssuers()) {
                    boolean isUser = user.contains(c);
                    if (isUser ? this.user : system) ks.setCertificateEntry("a" + (n++), c);
                }
            }
            if (this.user) for (X509Certificate c : user) {
                if (ks.getCertificateAlias(c) == null) ks.setCertificateEntry("a" + (n++), c);
            }
            for (X509Certificate c : certs) ks.setCertificateEntry("a" + (n++), c);
            return store = ks;
        }

        synchronized X509ExtendedTrustManager tm() throws Exception {
            if (tm != null) return tm;
            TrustManagerFactory f = TrustManagerFactory.getInstance("PKIX", realProvider());
            f.init(store());
            for (TrustManager t : f.getTrustManagers())
                if (t instanceof X509ExtendedTrustManager) return tm = (X509ExtendedTrustManager) t;
            throw new CertificateException("no extended PKIX trust manager");
        }
    }

    static final class Pins {
        final List<byte[]> sha256 = new ArrayList<>();
        long expiryMillis;   // 0 = never
        boolean active() { return !sha256.isEmpty() && (expiryMillis == 0 || System.currentTimeMillis() < expiryMillis); }
    }

    /** A parsed config element; null fields inherit from the parent / defaults. */
    static final class Cfg {
        Boolean cleartext;
        Anchors anchors;
        Pins pins;
        final List<String[]> domains = new ArrayList<>();   // {host, "1"|"0" includeSubdomains}
        final List<Cfg> children = new ArrayList<>();
    }

    /** One resolved (inheritance applied) domain entry. */
    static final class Dom {
        final String host; final boolean sub; final Boolean cleartext; final Anchors anchors; final Pins pins;
        Dom(String h, boolean s, Boolean c, Anchors a, Pins p) { host = h; sub = s; cleartext = c; anchors = a; pins = p; }
    }

    static final class State {
        Boolean baseCleartext;
        Anchors baseAnchors;
        Pins basePins;
        final List<Dom> doms = new ArrayList<>();
        int targetSdk;
        boolean hasConfig;
    }

    private static volatile State sState;

    // ---- public surface used by NetworkSecurityPolicy -------------------------

    static boolean cleartextPermitted(String host) {
        State s = sState;
        if (!ON || s == null) return true;
        Dom d = match(s, host);
        Boolean c = d != null ? d.cleartext : null;
        if (c == null) c = s.baseCleartext;
        if (c == null) return !(ENFORCE_DEFAULT_CLEARTEXT && s.targetSdk >= 28);
        return c;
    }

    static boolean cleartextPermittedEverywhere() {
        State s = sState;
        if (!ON || s == null) return true;
        if (!cleartextPermitted(null)) return false;
        for (Dom d : s.doms) if (!cleartextPermitted(d.host)) return false;
        return true;
    }

    private static String norm(String h) {
        if (h == null) return null;
        h = h.toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h;
    }

    /** AOSP NetworkSecurityConfig lookup: the most specific domain wins. */
    private static Dom match(State s, String host) {
        host = norm(host);
        if (host == null || host.isEmpty()) return null;
        Dom best = null;
        for (Dom d : s.doms) {
            boolean ok = d.host.equals(host) || (d.sub && host.endsWith("." + d.host));
            if (!ok) continue;
            if (best == null || d.host.length() > best.host.length()
                    || (d.host.length() == best.host.length() && d.host.equals(host))) best = d;
        }
        return best;
    }

    // ---- install -----------------------------------------------------------------

    /** Boot hook. rawRef is the manifest's networkSecurityConfig value ("@xml/x",
     *  "@0x7f..."), null when absent; usesCleartext is android:usesCleartextTraffic
     *  (null when absent). */
    public static void install(Resources res, String pkg, String rawRef, Boolean usesCleartext,
            int targetSdk) {
        if (!ON) return;
        State s = new State();
        s.targetSdk = targetSdk;
        s.baseCleartext = usesCleartext;      // only consulted when there is no config
        try {
            if (rawRef != null && !rawRef.isEmpty()) {
                int id = resolveId(res, pkg, rawRef, "xml");
                if (id != 0) {
                    XmlPullParser p = res.getXml(id);
                    parse(p, res, pkg, s);
                    s.hasConfig = true;
                } else {
                    com.macapk.loader.NativeLog.w(TAG, "networkSecurityConfig " + rawRef + " not found");
                }
            }
        } catch (Throwable t) {
            // AOSP fails the process on a malformed config; we log and fall back to
            // the platform default rather than refuse to start the app.
            com.macapk.loader.NativeLog.w(TAG, "could not parse " + rawRef + ": " + t);
            s = new State(); s.targetSdk = targetSdk; s.baseCleartext = usesCleartext;
        }
        sState = s;
        if (!s.hasConfig) return;
        com.macapk.loader.NativeLog.i(TAG, "config loaded: " + s.doms.size() + " domain entries, base cleartext="
                + s.baseCleartext + ", targetSdk=" + targetSdk);
        try {
            Security.insertProviderAt(new NscProvider(), 1);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] { new NscTrustManager() }, null);
            SSLContext.setDefault(ctx);
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        } catch (Throwable t) {
            com.macapk.loader.NativeLog.w(TAG, "could not install the trust manager: " + t);
        }
    }

    private static int resolveId(Resources res, String pkg, String ref, String type) {
        try {
            if (ref.startsWith("@0x") || ref.startsWith("@0X")) return (int) Long.parseLong(ref.substring(3), 16);
            if (ref.startsWith("@")) {
                String r = ref.substring(1);
                int slash = r.indexOf('/');
                if (slash > 0) {
                    String t = r.substring(0, slash).replace("*", "");
                    if (t.contains(":")) t = t.substring(t.indexOf(':') + 1);
                    return res.getIdentifier(r.substring(slash + 1), t, pkg);
                }
            }
        } catch (Throwable ignored) {}
        return 0;
    }

    // ---- parser ----------------------------------------------------------------------

    private static String attr(XmlPullParser p, String name) {
        for (int i = 0; i < p.getAttributeCount(); i++) {
            String n = p.getAttributeName(i);
            if (n != null && n.substring(n.indexOf(':') + 1).equals(name)) return p.getAttributeValue(i);
        }
        return null;
    }

    private static Boolean attrBool(XmlPullParser p, String name) {
        String v = attr(p, name);
        if (v == null) return null;
        return v.equalsIgnoreCase("true") || v.equals("-1") || v.equals("1");
    }

    /** Consume the element just started (through its END_TAG). */
    private static void skip(XmlPullParser p) throws Exception {
        int depth = 1;
        while (depth > 0) {
            int ev = p.next();
            if (ev == XmlPullParser.START_TAG) depth++;
            else if (ev == XmlPullParser.END_TAG) depth--;
            else if (ev == XmlPullParser.END_DOCUMENT) return;
        }
    }

    private static String text(XmlPullParser p) throws Exception {
        StringBuilder sb = new StringBuilder();
        int depth = 1;
        while (depth > 0) {
            int ev = p.next();
            if (ev == XmlPullParser.TEXT) sb.append(p.getText());
            else if (ev == XmlPullParser.START_TAG) depth++;
            else if (ev == XmlPullParser.END_TAG) depth--;
            else if (ev == XmlPullParser.END_DOCUMENT) break;
        }
        return sb.toString().trim();
    }

    private static void parse(XmlPullParser p, Resources res, String pkg, State s) throws Exception {
        int ev;
        while ((ev = p.next()) != XmlPullParser.START_TAG) {
            if (ev == XmlPullParser.END_DOCUMENT) return;
        }
        if (!"network-security-config".equals(p.getName())) throw new CertificateException("root is " + p.getName());
        Cfg base = null;
        List<Cfg> top = new ArrayList<>();
        while ((ev = p.next()) != XmlPullParser.END_TAG && ev != XmlPullParser.END_DOCUMENT) {
            if (ev != XmlPullParser.START_TAG) continue;
            String n = p.getName();
            if ("base-config".equals(n)) base = config(p, res, pkg);
            else if ("domain-config".equals(n)) top.add(config(p, res, pkg));
            else skip(p);   // debug-overrides and anything newer
        }
        if (base != null) { s.baseCleartext = base.cleartext; s.baseAnchors = base.anchors; s.basePins = base.pins; }
        else s.baseCleartext = null;
        for (Cfg c : top) flatten(c, s.baseCleartext, s.baseAnchors, s.basePins, s.doms);
    }

    private static void flatten(Cfg c, Boolean ct, Anchors an, Pins pins, List<Dom> out) {
        if (c.cleartext != null) ct = c.cleartext;
        if (c.anchors != null) an = c.anchors;
        if (c.pins != null) pins = c.pins;
        for (String[] d : c.domains) out.add(new Dom(d[0], "1".equals(d[1]), ct, an, pins));
        for (Cfg k : c.children) flatten(k, ct, an, pins, out);
    }

    /** Parse one base-config / domain-config; the START_TAG is current. */
    private static Cfg config(XmlPullParser p, Resources res, String pkg) throws Exception {
        Cfg c = new Cfg();
        c.cleartext = attrBool(p, "cleartextTrafficPermitted");
        int ev;
        while ((ev = p.next()) != XmlPullParser.END_TAG && ev != XmlPullParser.END_DOCUMENT) {
            if (ev != XmlPullParser.START_TAG) continue;
            String n = p.getName();
            if ("domain".equals(n)) {
                Boolean sub = attrBool(p, "includeSubdomains");
                String h = norm(text(p));
                if (h != null && !h.isEmpty()) c.domains.add(new String[] { h, Boolean.TRUE.equals(sub) ? "1" : "0" });
            } else if ("trust-anchors".equals(n)) {
                c.anchors = anchors(p, res, pkg);
            } else if ("pin-set".equals(n)) {
                c.pins = pins(p);
            } else if ("domain-config".equals(n)) {
                c.children.add(config(p, res, pkg));
            } else {
                skip(p);   // debug-overrides
            }
        }
        return c;
    }

    private static Anchors anchors(XmlPullParser p, Resources res, String pkg) throws Exception {
        Anchors a = new Anchors();
        int ev;
        while ((ev = p.next()) != XmlPullParser.END_TAG && ev != XmlPullParser.END_DOCUMENT) {
            if (ev != XmlPullParser.START_TAG) continue;
            if ("certificates".equals(p.getName())) {
                String src = attr(p, "src");
                if ("system".equals(src)) a.system = true;
                else if ("user".equals(src)) a.user = true;
                else if (src != null) {
                    try {
                        int id = resolveId(res, pkg, src, "raw");
                        try (InputStream in = res.openRawResource(id)) {
                            for (Certificate c : CertificateFactory.getInstance("X.509")
                                    .generateCertificates(new ByteArrayInputStream(in.readAllBytes())))
                                a.certs.add((X509Certificate) c);
                        }
                    } catch (Throwable t) {
                        com.macapk.loader.NativeLog.w(TAG, "certificates src=" + src + ": " + t);
                    }
                }
            }
            skip(p);
        }
        return a;
    }

    private static Pins pins(XmlPullParser p) throws Exception {
        Pins pins = new Pins();
        String exp = attr(p, "expiration");
        if (exp != null) {
            try {
                SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd", Locale.ROOT);
                f.setTimeZone(TimeZone.getTimeZone("UTC"));
                Date d = f.parse(exp.trim());
                // AOSP: pins stop applying from the START of the expiration day (UTC).
                pins.expiryMillis = d.getTime();
            } catch (Throwable ignored) {}
        }
        int ev;
        while ((ev = p.next()) != XmlPullParser.END_TAG && ev != XmlPullParser.END_DOCUMENT) {
            if (ev != XmlPullParser.START_TAG) continue;
            if ("pin".equals(p.getName())) {
                String digest = attr(p, "digest");
                String b64 = text(p);
                if ("SHA-256".equalsIgnoreCase(digest)) {
                    try { pins.sha256.add(Base64.getMimeDecoder().decode(b64)); } catch (Throwable ignored) {}
                }
            } else {
                skip(p);
            }
        }
        return pins;
    }

    // ---- trust ------------------------------------------------------------------------

    private static Provider sReal;
    static synchronized Provider realProvider() throws Exception {
        if (sReal == null) sReal = Security.getProvider("SunJSSE");
        if (sReal == null) throw new CertificateException("SunJSSE missing");
        return sReal;
    }

    private static List<X509Certificate> sDefaultIssuers;
    /** The JVM's default trust anchors (JDK cacerts, plus macOS admin/user roots
     *  when MacApkSystemTrust merged them). Taken from SunJSSE directly so it never
     *  recurses into the provider installed below. */
    static synchronized List<X509Certificate> defaultIssuers() throws Exception {
        if (sDefaultIssuers != null) return sDefaultIssuers;
        TrustManagerFactory f = TrustManagerFactory.getInstance("PKIX", realProvider());
        f.init((KeyStore) null);
        List<X509Certificate> out = new ArrayList<>();
        for (TrustManager t : f.getTrustManagers())
            if (t instanceof X509TrustManager) out.addAll(Arrays.asList(((X509TrustManager) t).getAcceptedIssuers()));
        return sDefaultIssuers = out;
    }

    private static final Anchors DEFAULT_ANCHORS = new Anchors();
    static { DEFAULT_ANCHORS.system = true; DEFAULT_ANCHORS.user = true; }

    static final class NscTrustManager extends X509ExtendedTrustManager {
        private Anchors anchorsFor(String host) {
            State s = sState;
            Dom d = s == null ? null : match(s, host);
            Anchors a = d != null ? d.anchors : null;
            if (a == null && s != null) a = s.baseAnchors;
            return a != null ? a : DEFAULT_ANCHORS;
        }

        private Pins pinsFor(String host) {
            State s = sState;
            Dom d = s == null ? null : match(s, host);
            return d != null ? d.pins : (s != null ? s.basePins : null);
        }

        private void check(X509Certificate[] chain, String authType, String host, Socket sock,
                SSLEngine eng) throws CertificateException {
            try {
                Anchors a = anchorsFor(host);
                X509ExtendedTrustManager tm = a.tm();
                if (sock != null) tm.checkServerTrusted(chain, authType, sock);
                else if (eng != null) tm.checkServerTrusted(chain, authType, eng);
                else tm.checkServerTrusted(chain, authType);
                Pins pins = pinsFor(host);
                if (pins != null && pins.active() && !pinMatches(chain, a, pins)) {
                    throw new CertificateException("Pin verification failed for " + host);
                }
            } catch (CertificateException e) {
                throw e;
            } catch (Exception e) {
                throw new CertificateException(e);
            }
        }

        /** AOSP NetworkSecurityTrustManager.checkPins: any certificate in the
         *  VALIDATED path (leaf..anchor), not merely any the server sent. */
        private boolean pinMatches(X509Certificate[] chain, Anchors a, Pins pins) throws Exception {
            X509CertSelector sel = new X509CertSelector();
            sel.setCertificate(chain[0]);
            PKIXBuilderParameters bp = new PKIXBuilderParameters(a.store(), sel);
            bp.setRevocationEnabled(false);
            bp.addCertStore(CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(Arrays.asList(chain))));
            PKIXCertPathBuilderResult r = (PKIXCertPathBuilderResult)
                    CertPathBuilder.getInstance("PKIX").build(bp);
            List<X509Certificate> path = new ArrayList<>();
            for (Certificate c : r.getCertPath().getCertificates()) path.add((X509Certificate) c);
            if (r.getTrustAnchor().getTrustedCert() != null) path.add(r.getTrustAnchor().getTrustedCert());
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (X509Certificate c : path) {
                byte[] h = md.digest(c.getPublicKey().getEncoded());   // SubjectPublicKeyInfo DER
                for (byte[] pin : pins.sha256) if (MessageDigest.isEqual(h, pin)) return true;
            }
            return false;
        }

        private static String host(Socket s) {
            try {
                if (s instanceof SSLSocket) {
                    SSLSession hs = ((SSLSocket) s).getHandshakeSession();
                    if (hs != null && hs.getPeerHost() != null) return hs.getPeerHost();
                }
                if (s.getRemoteSocketAddress() instanceof InetSocketAddress)
                    return ((InetSocketAddress) s.getRemoteSocketAddress()).getHostString();
            } catch (Throwable ignored) {}
            return null;
        }

        private static String host(SSLEngine e) {
            try {
                SSLSession hs = e.getHandshakeSession();
                if (hs != null && hs.getPeerHost() != null) return hs.getPeerHost();
            } catch (Throwable ignored) {}
            return e.getPeerHost();
        }

        @Override public void checkServerTrusted(X509Certificate[] c, String t, Socket s)
                throws CertificateException { check(c, t, host(s), s, null); }
        @Override public void checkServerTrusted(X509Certificate[] c, String t, SSLEngine e)
                throws CertificateException { check(c, t, host(e), null, e); }
        @Override public void checkServerTrusted(X509Certificate[] c, String t)
                throws CertificateException { check(c, t, null, null, null); }
        @Override public void checkClientTrusted(X509Certificate[] c, String t, Socket s)
                throws CertificateException { throw new CertificateException("client auth unsupported"); }
        @Override public void checkClientTrusted(X509Certificate[] c, String t, SSLEngine e)
                throws CertificateException { throw new CertificateException("client auth unsupported"); }
        @Override public void checkClientTrusted(X509Certificate[] c, String t)
                throws CertificateException { throw new CertificateException("client auth unsupported"); }
        @Override public X509Certificate[] getAcceptedIssuers() {
            try {
                return anchorsFor(null).tm().getAcceptedIssuers();
            } catch (Exception e) { return new X509Certificate[0]; }
        }
    }

    /** AOSP's "AndroidNSSP": TrustManagerFactory.PKIX whose init(null) yields the
     *  config-aware manager; an explicit KeyStore (an app pinning its own roots)
     *  goes to the real factory untouched. */
    static final class NscProvider extends Provider {
        NscProvider() {
            super("AndroidNSSP", 1.0, "Network Security Config trust manager");
            putService(new Service(this, "TrustManagerFactory", "PKIX",
                    NscFactorySpi.class.getName(), Arrays.asList("SunPKIX", "X509", "X.509"), null) {
                @Override public Object newInstance(Object ctorParam) { return new NscFactorySpi(); }
            });
        }
    }

    public static final class NscFactorySpi extends TrustManagerFactorySpi {
        private TrustManagerFactory real;   // set when the app supplied its own KeyStore/params
        private boolean nsc;

        @Override protected void engineInit(KeyStore ks) throws java.security.KeyStoreException {
            if (ks == null) { nsc = true; return; }
            try {
                real = TrustManagerFactory.getInstance("PKIX", realProvider());
                real.init(ks);
            } catch (java.security.GeneralSecurityException e) {
                throw new java.security.KeyStoreException(e);
            } catch (Exception e) { throw new java.security.KeyStoreException(e); }
        }

        @Override protected void engineInit(ManagerFactoryParameters p)
                throws java.security.InvalidAlgorithmParameterException {
            try {
                real = TrustManagerFactory.getInstance("PKIX", realProvider());
                real.init(p);
            } catch (java.security.InvalidAlgorithmParameterException e) {
                throw e;
            } catch (Exception e) { throw new java.security.InvalidAlgorithmParameterException(e); }
        }

        @Override protected TrustManager[] engineGetTrustManagers() {
            if (real != null) return real.getTrustManagers();
            if (!nsc) throw new IllegalStateException("not initialized");
            return new TrustManager[] { new NscTrustManager() };
        }
    }
}
