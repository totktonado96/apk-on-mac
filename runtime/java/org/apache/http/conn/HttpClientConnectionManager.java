package org.apache.http.conn;
import java.util.concurrent.TimeUnit;
/** apache-httpclient 4.3 connection manager. Inert on Apk on Mac. */
public interface HttpClientConnectionManager {
    void closeIdleConnections(long idletime, TimeUnit tunit);
    void closeExpiredConnections();
    void shutdown();
}
