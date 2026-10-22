// android.security.NetworkSecurityPolicy -- the runtime view of the
// app's Network Security Config. Previously an empty stub, so any call
// (OkHttp, Conscrypt, WebView, analytics SDKs all probe
// isCleartextTrafficPermitted before an HTTP request) threw
// NoSuchMethodError.
//
// Answers come from MacApkNetworkSecurity, which parses the app's
// res/xml/network_security_config (cleartextTrafficPermitted per base-config /
// domain-config). With no config, or MACAPK_NSC=0, cleartext is permitted -- the
// behaviour this class always had; AOSP's implicit "false for targetSdk >= 28" is
// opt-in via MACAPK_NSC_CLEARTEXT=1 (rationale in MacApkNetworkSecurity). OkHttp
// and friends reach these two methods reflectively.
package android.security;

public class NetworkSecurityPolicy {
    private static final NetworkSecurityPolicy INSTANCE = new NetworkSecurityPolicy();

    public static NetworkSecurityPolicy getInstance() { return INSTANCE; }

    public NetworkSecurityPolicy() {}

    /** Whether cleartext (HTTP) traffic is permitted application-wide. */
    public boolean isCleartextTrafficPermitted() { return MacApkNetworkSecurity.cleartextPermittedEverywhere(); }

    /** Whether cleartext traffic is permitted for the given host. */
    public boolean isCleartextTrafficPermitted(String hostname) { return MacApkNetworkSecurity.cleartextPermitted(hostname); }

    /** Whether Certificate Transparency verification is required for the given
     *  hostname (API 36, android.security.certificate_transparency_configuration).
     *  AOSP reads the app's Network Security Config; ours declares no CT policy
     *  and the platform default is that CT is NOT required, so false is the
     *  faithful answer. Note this reports what the app's CONFIG demands -- it
     *  does not weaken any verification that the TLS stack performs anyway. */
    public boolean isCertificateTransparencyVerificationRequired(String hostname) {
        return false;
    }

    /** Deprecated test hook on real Android; accept and ignore. */
    public void setCleartextTrafficPermitted(boolean permitted) {}
}
