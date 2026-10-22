// bionic_shim_cacerts.cpp -- Android's system CA store, backed by the Mac's own
// trusted roots.
//
// WHAT A DEVICE HAS. Every Android device carries its trusted root certificates
// as one PEM file per root in /system/etc/security/cacerts (and, since Android
// 14, the updatable copy in /apex/com.android.conscrypt/cacerts), each named
// <subject_hash_old>.<n> (AOSP system/ca-certificates; the names are OpenSSL's
// X509_NAME_hash_old so a hashed-dir lookup can find them). Native TLS stacks
// that ship their own OpenSSL read that directory, because the platform's Java
// trust manager is out of their reach: Unreal Engine's FSslCertificateManager
// on Android loads every file in it into the SSL context its HTTP and WebSocket
// clients verify against.
//
// WHAT WE HAD. The path did not exist, so such a stack saw an EMPTY system store
// and trusted only whatever bundle the app happened to ship. Measured on RL
// Sideswipe 1.12.5 (2026-10-06, MACAPK_NET_TRACE): every TLS handshake to its
// multiplayer service ws.rlmp.psynet.gg (and many to *.epicgames.dev) ended
// with the client's fatal alert `15 03 03 00 02 02 30` -- unknown_ca (48) --
// and the game showed "connection lost to the server".
//
// WHAT THIS DOES (rung 1: macOS has a trust store). The remap in bionic_shim.cpp
// answers both Android spellings with a directory built from
// SecTrustCopyAnchorCertificates (the system anchors macOS itself trusts): one
// PEM file per root, named <subject_hash_old>.<n> exactly as AOSP names them.
// The directory is keyed by a digest of the anchor set, so it is built once per
// distinct set (a macOS update that changes the roots yields a new one) under
// ~/Library/Caches/MacApk/android-cacerts/, written to a temporary name and
// renamed into place so a concurrent app never sees a half-built store.
//
// MACAPK_SYSTEM_CACERTS=0: the path stays absent (the pre-change behaviour).
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

// One DER TLV at p[0..n): sets *hdr (tag + length bytes) and *len (content
// length). False on anything malformed.
bool der_tlv(const uint8_t* p, size_t n, size_t* hdr, size_t* len) {
    if (n < 2) return false;
    size_t h = 2;
    size_t l = p[1];
    if (l & 0x80) {
        const size_t k = l & 0x7f;
        if (k == 0 || k > 4 || n < 2 + k) return false;
        l = 0;
        for (size_t i = 0; i < k; i++) l = (l << 8) | p[2 + i];
        h = 2 + k;
    }
    if (h + l > n) return false;
    *hdr = h;
    *len = l;
    return true;
}

// The DER encoding of a certificate's subject Name (RFC 5280 4.1:
// Certificate = SEQ { tbsCertificate SEQ { [0] version OPTIONAL, serialNumber,
// signature, issuer, validity, subject, ... }, ... }).
bool der_subject(const uint8_t* cert, size_t n, const uint8_t** out, size_t* outlen) {
    size_t h, l;
    if (!der_tlv(cert, n, &h, &l) || cert[0] != 0x30) return false;
    const uint8_t* tbs = cert + h;
    size_t tn = l;
    if (!der_tlv(tbs, tn, &h, &l) || tbs[0] != 0x30) return false;
    const uint8_t* p = tbs + h;
    size_t rem = l;
    int field = 0;
    if (rem && p[0] == 0xa0) field = -1;          // explicit version present
    for (; rem; field++) {
        if (!der_tlv(p, rem, &h, &l)) return false;
        if (field == 4) {                          // serial, sig, issuer, validity, SUBJECT
            *out = p;
            *outlen = h + l;
            return true;
        }
        p += h + l;
        rem -= h + l;
    }
    return false;
}

// OpenSSL's X509_NAME_hash_old: the first four bytes of MD5(DER name), read
// little-endian (crypto/x509/x509_cmp.c).
unsigned long subject_hash_old(const uint8_t* name, size_t n) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(name, (CC_LONG)n, md);
#pragma clang diagnostic pop
    return ((unsigned long)md[0]) | ((unsigned long)md[1] << 8)
         | ((unsigned long)md[2] << 16) | ((unsigned long)md[3] << 24);
}

std::string pem(const uint8_t* der, size_t n) {
    static const char kB64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (size_t i = 0; i < n; i += 3) {
        const uint32_t v = (uint32_t)der[i] << 16
                         | (i + 1 < n ? (uint32_t)der[i + 1] << 8 : 0)
                         | (i + 2 < n ? (uint32_t)der[i + 2] : 0);
        b64 += kB64[(v >> 18) & 63];
        b64 += kB64[(v >> 12) & 63];
        b64 += i + 1 < n ? kB64[(v >> 6) & 63] : '=';
        b64 += i + 2 < n ? kB64[v & 63] : '=';
    }
    std::string out = "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) out += b64.substr(i, 64) + "\n";
    out += "-----END CERTIFICATE-----\n";
    return out;
}

bool write_file(const std::string& path, const std::string& data) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    const bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
    return fclose(f) == 0 && ok;
}

void remove_tree(const std::string& dir) {
    if (DIR* d = opendir(dir.c_str())) {
        while (struct dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            unlink((dir + "/" + e->d_name).c_str());
        }
        closedir(d);
    }
    rmdir(dir.c_str());
}

void mkdirs(const std::string& path) {
    for (size_t i = 1; i <= path.size(); i++) {
        if (i == path.size() || path[i] == '/') mkdir(path.substr(0, i).c_str(), 0755);
    }
}


// ---- admin/user trust settings (Keychain Access > Get Info > Trust) --------
//
// SecTrustCopyAnchorCertificates is ONLY Apple's own roots. An enterprise root
// pushed by MDM (admin domain) or a corporate / mitmproxy / dev CA the user
// trusted (user domain) lives in the trust-settings database instead, and macOS
// itself honours it, so a stack that ignores it fails where Safari works.
// SecTrustSettingsCopyCertificates lists the certs that HAVE settings in a
// domain; what each means is in SecTrustSettingsCopyTrustSettings (Security
// SecTrustSettings.h): an EMPTY array = "always trust as a root"; otherwise
// each dictionary may carry kSecTrustSettingsResult (absent = TrustRoot) and
// may be scoped to one policy via kSecTrustSettingsPolicy. We want the TLS
// answer, so a dictionary scoped to a non-SSL policy (S/MIME, code signing) is
// skipped. TrustRoot/TrustAsRoot trust; Deny distrusts and wins over a trust in
// the other domain (and over the Apple anchor), as macOS does; Unspecified is
// "no opinion". MACAPK_SYSTEM_TRUST=0 turns all of this off.
bool system_trust_enabled() {
    const char* e = getenv("MACAPK_SYSTEM_TRUST");
    return !(e && e[0] == '0');
}

bool policy_is_ssl_or_unscoped(CFDictionaryRef d) {
    SecPolicyRef pol = (SecPolicyRef)CFDictionaryGetValue(d, kSecTrustSettingsPolicy);
    if (!pol) return true;
    bool ssl = false;
    CFDictionaryRef props = SecPolicyCopyProperties(pol);
    if (props) {
        CFTypeRef oid = CFDictionaryGetValue(props, kSecPolicyOid);
        ssl = oid && CFEqual(oid, kSecPolicyAppleSSL);
        CFRelease(props);
    }
    return ssl;
}

// 1 = trusted as root, -1 = denied, 0 = no opinion, for one cert in one domain.
int trust_verdict(SecCertificateRef c, SecTrustSettingsDomain domain) {
    CFArrayRef settings = nullptr;
    if (SecTrustSettingsCopyTrustSettings(c, domain, &settings) != errSecSuccess || !settings)
        return 0;
    int verdict = 0;
    if (CFArrayGetCount(settings) == 0) verdict = 1;     // "always trust as root"
    for (CFIndex i = 0, n = CFArrayGetCount(settings); i < n; i++) {
        CFDictionaryRef d = (CFDictionaryRef)CFArrayGetValueAtIndex(settings, i);
        if (!d || CFGetTypeID(d) != CFDictionaryGetTypeID() || !policy_is_ssl_or_unscoped(d)) continue;
        int32_t r = kSecTrustSettingsResultTrustRoot;     // absent result = TrustRoot
        CFNumberRef rn = (CFNumberRef)CFDictionaryGetValue(d, kSecTrustSettingsResult);
        if (rn) CFNumberGetValue(rn, kCFNumberSInt32Type, &r);
        if (r == kSecTrustSettingsResultDeny) { verdict = -1; break; }
        if (r == kSecTrustSettingsResultTrustRoot || r == kSecTrustSettingsResultTrustAsRoot)
            verdict = 1;
    }
    CFRelease(settings);
    return verdict;
}

std::vector<uint8_t> cert_der(SecCertificateRef c) {
    std::vector<uint8_t> out;
    if (CFDataRef d = SecCertificateCopyData(c)) {
        const uint8_t* b = CFDataGetBytePtr(d);
        out.assign(b, b + CFDataGetLength(d));
        CFRelease(d);
    }
    return out;
}

// Certs trusted / denied by the admin and user domains (DER).
void collect_trust_settings(std::vector<std::vector<uint8_t>>* trusted,
                            std::vector<std::vector<uint8_t>>* denied) {
    for (SecTrustSettingsDomain dom : {kSecTrustSettingsDomainAdmin, kSecTrustSettingsDomainUser}) {
        CFArrayRef certs = nullptr;
        if (SecTrustSettingsCopyCertificates(dom, &certs) != errSecSuccess || !certs) continue;
        for (CFIndex i = 0, n = CFArrayGetCount(certs); i < n; i++) {
            SecCertificateRef c = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
            const int v = trust_verdict(c, dom);
            if (v == 0) continue;
            std::vector<uint8_t> der = cert_der(c);
            if (!der.empty()) (v > 0 ? trusted : denied)->push_back(std::move(der));
        }
        CFRelease(certs);
    }
}

std::string build_store() {
    const char* home = getenv("HOME");
    if (!home || !*home) return {};
    CFArrayRef anchors = nullptr;
    if (SecTrustCopyAnchorCertificates(&anchors) != errSecSuccess || !anchors) return {};
    std::vector<std::vector<uint8_t>> ders;
    for (CFIndex i = 0, n = CFArrayGetCount(anchors); i < n; i++) {
        SecCertificateRef c = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, i);
        CFDataRef d = c ? SecCertificateCopyData(c) : nullptr;
        if (!d) continue;
        const uint8_t* b = CFDataGetBytePtr(d);
        ders.emplace_back(b, b + CFDataGetLength(d));
        CFRelease(d);
    }
    CFRelease(anchors);
    if (system_trust_enabled()) {
        std::vector<std::vector<uint8_t>> trusted, denied;
        collect_trust_settings(&trusted, &denied);
        std::vector<std::vector<uint8_t>> merged;
        for (auto* src : {&ders, &trusted}) {
            for (auto& d : *src) {
                bool skip = false;
                for (const auto& x : denied) if (x == d) { skip = true; break; }
                for (const auto& x : merged) if (!skip && x == d) { skip = true; break; }
                if (!skip) merged.push_back(std::move(d));
            }
        }
        ders.swap(merged);   // folded into the digest below, so the store refreshes
    }
    if (ders.empty()) return {};

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    for (const auto& d : ders) CC_SHA256_Update(&ctx, d.data(), (CC_LONG)d.size());
    unsigned char sum[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(sum, &ctx);
    char key[17];
    for (int i = 0; i < 8; i++) snprintf(key + 2 * i, 3, "%02x", sum[i]);

    const std::string base = std::string(home) + "/Library/Caches/MacApk/android-cacerts";
    const std::string dir = base + "/" + key;
    struct stat st;
    if (stat((dir + "/.complete").c_str(), &st) == 0) return dir;

    mkdirs(base);
    const std::string tmp = dir + ".tmp" + std::to_string(getpid());
    remove_tree(tmp);
    if (mkdir(tmp.c_str(), 0755) != 0) return {};
    std::map<unsigned long, int> used;
    int written = 0;
    for (const auto& d : ders) {
        const uint8_t* subj;
        size_t sn;
        if (!der_subject(d.data(), d.size(), &subj, &sn)) continue;
        const unsigned long h = subject_hash_old(subj, sn);
        char name[32];
        snprintf(name, sizeof name, "%08lx.%d", h, used[h]++);
        if (write_file(tmp + "/" + name, pem(d.data(), d.size()))) written++;
    }
    write_file(tmp + "/.complete", std::to_string(written) + "\n");
    if (rename(tmp.c_str(), dir.c_str()) != 0) {
        remove_tree(tmp);   // another process won the race: use its copy
        if (stat((dir + "/.complete").c_str(), &st) != 0) return {};
    }
    fprintf(stderr, "[cacerts] Android system CA store: %d roots from the macOS trust store at %s\n",
            written, dir.c_str());
    return dir;
}

}  // namespace

// The host directory that answers /system/etc/security/cacerts, or null when
// it is off or could not be built (the path then stays absent, as before).
extern "C" const char* __macapk_android_cacerts_dir() {
    static std::once_flag once;
    static std::string dir;
    std::call_once(once, [] {
        const char* e = getenv("MACAPK_SYSTEM_CACERTS");
        if (e && e[0] == '0') return;
        dir = build_store();
    });
    return dir.empty() ? nullptr : dir.c_str();
}

// The admin/user-domain roots (DER), for the JVM's TLS trust (SystemTrust.java
// reaches this through dlsym). Calls cb once per cert; returns the count, 0
// when MACAPK_SYSTEM_TRUST=0.
extern "C" size_t __macapk_user_trust_roots(void (*cb)(const uint8_t*, size_t, void*), void* ctx) {
    if (!system_trust_enabled()) return 0;
    std::vector<std::vector<uint8_t>> trusted, denied;
    collect_trust_settings(&trusted, &denied);
    size_t n = 0;
    for (const auto& d : trusted) {
        bool dup = false;
        for (const auto& x : denied) if (x == d) { dup = true; break; }
        if (dup) continue;
        cb(d.data(), d.size(), ctx);
        n++;
    }
    return n;
}
