// HucFollow -- the shared state of one wrapped HttpURLConnection
// (HucConnection for http, HucsConnection for https): the CURRENT JDK
// connection, the request side as the app set it, and the one behaviour that
// differs from the JDK -- following a 300-303 answer to a STREAMED request as
// a GET, the way Android's OkHttp-backed HttpURLConnection does. The rule and
// its AOSP citations are in AndroidHttpHandlerProvider's header.

package com.macapk.net;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@SuppressWarnings("deprecation")   // new URL(URL, String): see AndroidHttpHandlerProvider
final class HucFollow {
    /** OkHttp HttpEngine.MAX_FOLLOW_UPS. */
    static final int MAX_FOLLOW_UPS = 20;

    final AndroidHttpHandlerProvider.Handler handler;
    final Proxy proxy;
    /** The live JDK connection; replaced when a redirect is followed. */
    HttpURLConnection d;

    // Request side as the app set it. The JDK forbids reading request
    // properties once connected (IllegalStateException "Already connected"),
    // and a follow-up request needs them after the first one was sent.
    final LinkedHashMap<String, List<String>> reqProps = new LinkedHashMap<String, List<String>>();
    boolean streaming;
    private boolean resolved;
    private int followUps;

    HucFollow(AndroidHttpHandlerProvider.Handler handler, Proxy proxy, URL u) throws IOException {
        this.handler = handler;
        this.proxy = proxy;
        this.d = handler.jdkConnection(u, proxy);
    }

    void setRequestProperty(String k, String v) {
        d.setRequestProperty(k, v);
        if (k == null) return;
        List<String> l = new ArrayList<String>(1);
        l.add(v);
        removeKey(k);
        reqProps.put(k, l);
    }

    void addRequestProperty(String k, String v) {
        d.addRequestProperty(k, v);
        if (k == null) return;
        String key = findKey(k);
        if (key == null) { key = k; reqProps.put(key, new ArrayList<String>(1)); }
        reqProps.get(key).add(v);
    }

    private String findKey(String k) {
        for (String e : reqProps.keySet()) if (e.equalsIgnoreCase(k)) return e;
        return null;
    }

    private void removeKey(String k) {
        String e = findKey(k);
        if (e != null) reqProps.remove(e);
    }

    /** Called first by every RESPONSE accessor of the wrapper. Does nothing
     *  unless the app streamed a request body -- every other request is the
     *  JDK's, untouched. An IOException is not raised here: the accessor then
     *  calls the JDK connection, which raises (or swallows) it exactly as it
     *  would have without the wrapper. */
    void resolve() {
        if (resolved || !streaming) return;
        resolved = true;
        try {
            follow();
        } catch (IOException ignored) {
            // see above
        }
    }

    private void follow() throws IOException {
        while (true) {
            String method = d.getRequestMethod();
            // A GET/HEAD follow-up is followed by the JDK itself (it has no
            // body, so the streaming refusal does not apply to it).
            if ("GET".equals(method) || "HEAD".equals(method)) return;
            if (!d.getInstanceFollowRedirects()) return;
            int code = d.getResponseCode();   // JDK: 302 here, its HttpRetryException swallowed
            if (code != HttpURLConnection.HTTP_MULT_CHOICE && code != HttpURLConnection.HTTP_MOVED_PERM
                    && code != HttpURLConnection.HTTP_MOVED_TEMP && code != HttpURLConnection.HTTP_SEE_OTHER) {
                return;   // 307/308 of a POST is not followed on Android either
            }
            String location = d.getHeaderField("Location");
            if (location == null) return;
            URL prev = d.getURL();
            URL next;
            try {
                next = new URL(prev, location);
            } catch (MalformedURLException e) {
                return;   // OkHttp: an unresolvable Location is not followed
            }
            // Android's HttpURLConnection does not follow https <-> http.
            if (!next.getProtocol().equalsIgnoreCase(prev.getProtocol())) return;
            if (++followUps > MAX_FOLLOW_UPS) {
                throw new ProtocolException("Too many follow-up requests: " + followUps);
            }
            HttpURLConnection n = handler.jdkConnection(next, proxy);
            n.setConnectTimeout(d.getConnectTimeout());
            n.setReadTimeout(d.getReadTimeout());
            n.setUseCaches(d.getUseCaches());
            n.setDoInput(d.getDoInput());
            n.setIfModifiedSince(d.getIfModifiedSince());
            n.setAllowUserInteraction(d.getAllowUserInteraction());
            n.setInstanceFollowRedirects(true);
            if (d instanceof javax.net.ssl.HttpsURLConnection && n instanceof javax.net.ssl.HttpsURLConnection) {
                javax.net.ssl.HttpsURLConnection a = (javax.net.ssl.HttpsURLConnection) d;
                javax.net.ssl.HttpsURLConnection b = (javax.net.ssl.HttpsURLConnection) n;
                b.setSSLSocketFactory(a.getSSLSocketFactory());
                b.setHostnameVerifier(a.getHostnameVerifier());
            }
            boolean sameConnection = sameConnection(prev, next);
            for (Map.Entry<String, List<String>> e : reqProps.entrySet()) {
                String k = e.getKey();
                if (k.equalsIgnoreCase("Transfer-Encoding") || k.equalsIgnoreCase("Content-Length")
                        || k.equalsIgnoreCase("Content-Type")) continue;
                if (!sameConnection && k.equalsIgnoreCase("Authorization")) continue;
                boolean first = true;
                for (String v : e.getValue()) {
                    if (first) n.setRequestProperty(k, v); else n.addRequestProperty(k, v);
                    first = false;
                }
            }
            // n's method is GET (the JDK default): the redirectsToGet rule.
            d.disconnect();
            d = n;
        }
    }

    /** OkHttp HttpEngine.sameConnection: same host, port and scheme. */
    private static boolean sameConnection(URL a, URL b) {
        return a.getHost().equalsIgnoreCase(b.getHost())
                && effectivePort(a) == effectivePort(b)
                && a.getProtocol().equalsIgnoreCase(b.getProtocol());
    }

    private static int effectivePort(URL u) {
        return u.getPort() != -1 ? u.getPort() : u.getDefaultPort();
    }
}
