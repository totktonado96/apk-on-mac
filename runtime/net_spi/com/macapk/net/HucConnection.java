// HucConnection -- the http (cleartext) connection AndroidHttpHandlerProvider hands an app: the JDK's
// own connection (HucFollow.d), forwarded method for method, except that every
// response accessor first lets HucFollow.resolve() follow a 300-303 answer to a
// STREAMED request as a GET (Android's OkHttp rule; see the provider's header).
// A java.net.HttpURLConnection, not an HttpsURLConnection, exactly as on Android.
// GENERATED shape: HucConnection and HucsConnection carry the same forwarding
// body (Java has no mixin for two unrelated superclasses); change both.

package com.macapk.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.ProtocolException;
import java.net.URL;
import java.security.Permission;
import java.util.List;
import java.util.Map;

final class HucConnection extends java.net.HttpURLConnection {
    final HucFollow f;

    HucConnection(HucFollow f) {
        super(f.handler.rebind(f.d.getURL()));
        this.f = f;
    }

    // ---- request side: forwarded; the core records what a follow-up needs ----
    @Override public void connect() throws IOException { f.d.connect(); connected = true; }
    @Override public void setRequestProperty(String k, String v) { f.setRequestProperty(k, v); }
    @Override public void addRequestProperty(String k, String v) { f.addRequestProperty(k, v); }
    @Override public String getRequestProperty(String k) { return f.d.getRequestProperty(k); }
    @Override public Map<String, List<String>> getRequestProperties() { return f.d.getRequestProperties(); }
    @Override public void setFixedLengthStreamingMode(int n) { f.d.setFixedLengthStreamingMode(n); f.streaming = true; }
    @Override public void setFixedLengthStreamingMode(long n) { f.d.setFixedLengthStreamingMode(n); f.streaming = true; }
    @Override public void setChunkedStreamingMode(int n) { f.d.setChunkedStreamingMode(n); f.streaming = true; }
    @Override public void setRequestMethod(String m) throws ProtocolException { f.d.setRequestMethod(m); }
    @Override public String getRequestMethod() { return f.d.getRequestMethod(); }
    @Override public void setInstanceFollowRedirects(boolean b) { f.d.setInstanceFollowRedirects(b); }
    @Override public boolean getInstanceFollowRedirects() { return f.d.getInstanceFollowRedirects(); }
    @Override public void setAuthenticator(Authenticator a) { f.d.setAuthenticator(a); }
    @Override public void setConnectTimeout(int t) { f.d.setConnectTimeout(t); }
    @Override public int getConnectTimeout() { return f.d.getConnectTimeout(); }
    @Override public void setReadTimeout(int t) { f.d.setReadTimeout(t); }
    @Override public int getReadTimeout() { return f.d.getReadTimeout(); }
    @Override public void setDoInput(boolean b) { f.d.setDoInput(b); }
    @Override public boolean getDoInput() { return f.d.getDoInput(); }
    @Override public void setDoOutput(boolean b) { f.d.setDoOutput(b); }
    @Override public boolean getDoOutput() { return f.d.getDoOutput(); }
    @Override public void setAllowUserInteraction(boolean b) { f.d.setAllowUserInteraction(b); }
    @Override public boolean getAllowUserInteraction() { return f.d.getAllowUserInteraction(); }
    @Override public void setUseCaches(boolean b) { f.d.setUseCaches(b); }
    @Override public boolean getUseCaches() { return f.d.getUseCaches(); }
    @Override public void setIfModifiedSince(long t) { f.d.setIfModifiedSince(t); }
    @Override public long getIfModifiedSince() { return f.d.getIfModifiedSince(); }
    @Override public void setDefaultUseCaches(boolean b) { f.d.setDefaultUseCaches(b); }
    @Override public boolean getDefaultUseCaches() { return f.d.getDefaultUseCaches(); }
    @Override public OutputStream getOutputStream() throws IOException { return f.d.getOutputStream(); }
    @Override public Permission getPermission() throws IOException { return f.d.getPermission(); }
    @Override public boolean usingProxy() { return f.d.usingProxy(); }
    @Override public void disconnect() { f.d.disconnect(); }
    @Override public URL getURL() { return f.handler.rebind(f.d.getURL()); }
    @Override public String toString() { return f.d.toString(); }

    // ---- response side: resolve() first (a no-op unless a body was streamed) ----
    @Override public int getResponseCode() throws IOException { f.resolve(); return f.d.getResponseCode(); }
    @Override public String getResponseMessage() throws IOException { f.resolve(); return f.d.getResponseMessage(); }
    @Override public InputStream getInputStream() throws IOException { f.resolve(); return f.d.getInputStream(); }
    @Override public InputStream getErrorStream() { f.resolve(); return f.d.getErrorStream(); }
    @Override public String getHeaderField(String k) { f.resolve(); return f.d.getHeaderField(k); }
    @Override public String getHeaderField(int n) { f.resolve(); return f.d.getHeaderField(n); }
    @Override public String getHeaderFieldKey(int n) { f.resolve(); return f.d.getHeaderFieldKey(n); }
    @Override public Map<String, List<String>> getHeaderFields() { f.resolve(); return f.d.getHeaderFields(); }
    @Override public int getHeaderFieldInt(String k, int def) { f.resolve(); return f.d.getHeaderFieldInt(k, def); }
    @Override public long getHeaderFieldLong(String k, long def) { f.resolve(); return f.d.getHeaderFieldLong(k, def); }
    @Override public long getHeaderFieldDate(String k, long def) { f.resolve(); return f.d.getHeaderFieldDate(k, def); }
    @Override public int getContentLength() { f.resolve(); return f.d.getContentLength(); }
    @Override public long getContentLengthLong() { f.resolve(); return f.d.getContentLengthLong(); }
    @Override public String getContentType() { f.resolve(); return f.d.getContentType(); }
    @Override public String getContentEncoding() { f.resolve(); return f.d.getContentEncoding(); }
    @Override public long getExpiration() { f.resolve(); return f.d.getExpiration(); }
    @Override public long getDate() { f.resolve(); return f.d.getDate(); }
    @Override public long getLastModified() { f.resolve(); return f.d.getLastModified(); }
    @Override public Object getContent() throws IOException { f.resolve(); return f.d.getContent(); }
    @Override public Object getContent(Class<?>[] classes) throws IOException { f.resolve(); return f.d.getContent(classes); }
}
