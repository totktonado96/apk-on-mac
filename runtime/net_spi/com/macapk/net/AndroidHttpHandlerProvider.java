// AndroidHttpHandlerProvider -- give guests Android's HttpURLConnection
// REDIRECT semantics for a STREAMED request body, instead of stock OpenJDK's.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS (the divergence, both sides cited)
// ---------------------------------------------------------------------------
// Android's java.net.HttpURLConnection is OkHttp
// (platform/external/okhttp, com.squareup.okhttp.internal.huc
// .HttpURLConnectionImpl, repackaged com.android.okhttp). When a POST gets a
// 300/301/302/303 it follows the Location as a bodiless GET -- and because the
// method changed, a body the app STREAMED (setFixedLengthStreamingMode /
// setChunkedStreamingMode) is simply dropped, not an obstacle
// (HttpURLConnectionImpl.getResponse, fetched 2026-09-30 from
// android.googlesource.com/platform/external/okhttp main):
//
//     // Although RFC 2616 10.3.2 specifies that a HTTP_MOVED_PERM redirect
//     // should keep the same method, Chrome, Firefox and the RI all issue GETs
//     // when following any redirect.
//     Sink requestBody = httpEngine.getRequestBody();
//     if (!followUp.method().equals(method)) {
//       requestBody = null;
//     }
//     if (requestBody != null && !(requestBody instanceof RetryableSink)) {
//       throw new HttpRetryException("Cannot retry streamed HTTP body", responseCode);
//     }
//
// and HttpEngine.followUpRequest builds that GET (same file set):
//
//     case HTTP_MULT_CHOICE: case HTTP_MOVED_PERM: case HTTP_MOVED_TEMP: case HTTP_SEE_OTHER:
//       if (!client.getFollowRedirects()) return null;
//       String location = userResponse.header("Location");
//       if (location == null) return null;
//       ...
//       boolean sameScheme = url.scheme().equals(userRequest.httpUrl().scheme());
//       if (!sameScheme && !client.getFollowSslRedirects()) return null;
//       if (HttpMethod.permitsRequestBody(method)) {
//         if (HttpMethod.redirectsToGet(method)) requestBuilder.method("GET", null);
//         ...
//         requestBuilder.removeHeader("Transfer-Encoding");
//         requestBuilder.removeHeader("Content-Length");
//         requestBuilder.removeHeader("Content-Type");
//       }
//       if (!sameConnection(url)) requestBuilder.removeHeader("Authorization");
//
// OpenJDK's sun.net.www.protocol.http.HttpURLConnection instead REFUSES any
// redirect of a streamed request: followRedirect0 does
//     if (streaming()) { throw new HttpRetryException(RETRY_MSG3, stat, loc); }
// and getResponseCode() swallows that exception and reports the 302 from the
// status line. So the same app code that follows the redirect on a phone sees
// a bare 302 here. Measured 2026-09-30: NewPipe's YoutubeHttpDataSource
// streams a 2-byte POST body to googlevideo.com with instanceFollowRedirects
// = true; YouTube answers 302, and every VOD failed with
// "InvalidResponseCodeException: Response code: 302" ("Videos do not play").
//
// ---------------------------------------------------------------------------
// WHAT THIS DOES, and what it deliberately does not
// ---------------------------------------------------------------------------
// A java.net.spi.URLStreamHandlerProvider (registered in
// META-INF/services, consulted by java.net.URL before the built-in handlers
// and AFTER any factory the app installs with URL.setURLStreamHandlerFactory
// -- so an app that brings its own factory, as some OkHttp users do, still
// gets it, exactly as on Android where no platform factory is installed).
// For http/https it returns a handler whose connections are the JDK's own,
// wrapped (HucConnection / HucsConnection) so that ONE case changes: a
// request whose body the app streamed, answered 300-303 while
// instanceFollowRedirects is on, is followed as a GET per the OkHttp rule
// above (same-scheme only -- Android's HttpURLConnection never follows
// https<->http; headers minus Transfer-Encoding/Content-Length/Content-Type,
// minus Authorization across hosts; at most 20 follow-ups, OkHttp's
// HttpEngine.MAX_FOLLOW_UPS). Every other request is forwarded to the JDK
// connection untouched: the wrapper records the request side only, and
// resolves nothing unless a streaming mode was set.
//
// Gate: MACAPK_HTTP_STREAMED_REDIRECTS (default ON). =0 makes the provider
// return null, so java.net.URL falls through to the built-in handlers: the
// pre-change behaviour, byte for byte. Offline gate: debug/hucredirect_gate.sh.
// Needs --add-exports java.base/sun.net.www.protocol.{http,https} (set in
// runtime/src/jvm_loader.cpp) to construct the built-in handlers; without
// them this provider logs once and returns null (the old behaviour).

package com.macapk.net;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.spi.URLStreamHandlerProvider;

// The URL(URL, String, URLStreamHandler) constructor is deprecated since JDK 20,
// but it is what the JDK's own redirect code resolves a Location with; URL.of /
// URI would reject spellings (unencoded characters) the JDK connection accepts.
@SuppressWarnings("deprecation")
public final class AndroidHttpHandlerProvider extends URLStreamHandlerProvider {

    static final boolean ENABLED = !"0".equals(System.getenv("MACAPK_HTTP_STREAMED_REDIRECTS"));

    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if (!ENABLED || protocol == null) return null;
        String p = protocol.toLowerCase(java.util.Locale.ROOT);
        if (!p.equals("http") && !p.equals("https")) return null;
        URLStreamHandler builtin = builtinHandler(p);
        return builtin == null ? null : new Handler(p, builtin);
    }

    /** The JDK's own handler for `scheme` (sun.net.www.protocol.<scheme>.Handler,
     *  public class, public no-arg constructor; reachable once the package is
     *  exported to the unnamed module). */
    static URLStreamHandler builtinHandler(String scheme) {
        try {
            Class<?> c = Class.forName("sun.net.www.protocol." + scheme + ".Handler");
            return (URLStreamHandler) c.getConstructor().newInstance();
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            System.err.println("[W] AndroidHttpHandlerProvider: built-in " + scheme
                    + " handler unavailable (" + e + ") -- stock JDK redirect semantics");
            return null;
        }
    }

    /** Mirrors the JDK http/https Handler's surface: openConnection with and
     *  without a Proxy, and the scheme's default port (URL.getDefaultPort,
     *  equals and hashCode read it). */
    static final class Handler extends URLStreamHandler {
        final String scheme;
        final URLStreamHandler builtin;

        Handler(String scheme, URLStreamHandler builtin) {
            this.scheme = scheme;
            this.builtin = builtin;
        }

        @Override protected int getDefaultPort() { return scheme.equals("https") ? 443 : 80; }

        @Override protected URLConnection openConnection(URL u) throws IOException {
            return wrap(new HucFollow(this, null, u));
        }

        @Override protected URLConnection openConnection(URL u, Proxy p) throws IOException {
            if (p == null) throw new IllegalArgumentException("proxy can not be null");
            return wrap(new HucFollow(this, p, u));
        }

        private URLConnection wrap(HucFollow f) {
            return (f.d instanceof javax.net.ssl.HttpsURLConnection) ? new HucsConnection(f) : new HucConnection(f);
        }

        /** A URL spelled the same but resolved through THIS handler, so a URL an
         *  app derives from getURL() keeps Android semantics. */
        URL rebind(URL jdkUrl) {
            try {
                return new URL(null, jdkUrl.toExternalForm(), this);
            } catch (java.net.MalformedURLException e) {
                return jdkUrl;
            }
        }

        /** The JDK connection for `u` (through `proxy` when non-null). */
        java.net.HttpURLConnection jdkConnection(URL u, Proxy proxy) throws IOException {
            URL viaBuiltin = new URL(null, u.toExternalForm(), builtin);
            URLConnection c = proxy == null ? viaBuiltin.openConnection() : viaBuiltin.openConnection(proxy);
            return (java.net.HttpURLConnection) c;
        }
    }
}
