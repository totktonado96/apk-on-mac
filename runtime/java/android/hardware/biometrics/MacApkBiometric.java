// android.hardware.biometrics.MacApkBiometric -- the Java half of
// biometric_bridge.mm: Touch ID / login password via LocalAuthentication.
//
// WHY here: BiometricManager, BiometricPrompt and KeyguardManager all need the
// same three facts (can the Mac verify the user, run a verification, when did
// one last succeed), so they share this one class instead of three native
// registrations. MACAPK_BIOMETRIC=0 restores the old "no biometric hardware"
// answers everywhere.
package android.hardware.biometrics;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class MacApkBiometric {
    private MacApkBiometric() {}

    private static final boolean ON = !"0".equals(System.getenv("MACAPK_BIOMETRIC"));

    // LAError codes (LocalAuthentication/LAError.h).
    static final int LA_AUTH_FAILED = -1, LA_USER_CANCEL = -2, LA_USER_FALLBACK = -3,
            LA_SYSTEM_CANCEL = -4, LA_PASSCODE_NOT_SET = -5, LA_BIOMETRY_NOT_AVAILABLE = -6,
            LA_BIOMETRY_NOT_ENROLLED = -7, LA_BIOMETRY_LOCKOUT = -8, LA_APP_CANCEL = -9,
            LA_INVALID_CONTEXT = -10, LA_NOT_INTERACTIVE = -1004;

    private static native int nativeCanEvaluate(boolean deviceCredential);
    private static native void nativeAuthenticate(int id, boolean deviceCredential,
            String reason, String cancelTitle);
    private static native void nativeCancel(int id);

    interface Listener { void onResult(int laCode); }

    private static final AtomicInteger sIds = new AtomicInteger(1);
    private static final ConcurrentHashMap<Integer, Listener> sPending = new ConcurrentHashMap<>();

    /** Wall-clock (System.currentTimeMillis) of the last successful prompt in this
     *  process, or -1. The keystore has no enforcement hook (see
     *  MacApkKeyStoreBackend: entries do not persist KeyGenParameterSpec's
     *  userAuthentication fields), so this feeds only
     *  BiometricManager.getLastAuthenticationTime for now. */
    private static volatile long sLastAuthMillis = -1L;

    public static long lastAuthenticationMillis() { return sLastAuthMillis; }

    public static boolean enabled() { return ON; }

    /** Raw LAError (0 = can evaluate) or LA_BIOMETRY_NOT_AVAILABLE when the
     *  bridge is off/unlinked. */
    static int canEvaluate(boolean deviceCredential) {
        if (!ON) return LA_BIOMETRY_NOT_AVAILABLE;
        try {
            return nativeCanEvaluate(deviceCredential);
        } catch (UnsatisfiedLinkError e) {
            return LA_BIOMETRY_NOT_AVAILABLE;
        }
    }

    /** BiometricManager.BIOMETRIC_* for an Authenticators mask (AOSP
     *  BiometricManager.canAuthenticate(int)): success when ANY requested class
     *  is usable, otherwise the most specific reason. */
    public static int canAuthenticate(int authenticators) {
        final boolean wantCred = (authenticators & BiometricManager.Authenticators.DEVICE_CREDENTIAL) != 0;
        final boolean wantBio = (authenticators & 0xFF) != 0;
        if (!wantCred && !wantBio) return BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED;
        int bio = wantBio ? canEvaluate(false) : LA_BIOMETRY_NOT_AVAILABLE;
        if (wantBio && bio == 0) return BiometricManager.BIOMETRIC_SUCCESS;
        if (wantCred) {
            int cred = canEvaluate(true);
            if (cred == 0) return BiometricManager.BIOMETRIC_SUCCESS;
            if (!wantBio) return cred == LA_PASSCODE_NOT_SET
                    ? BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
                    : BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
        }
        switch (bio) {
            case LA_BIOMETRY_NOT_ENROLLED: return BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED;
            case LA_BIOMETRY_LOCKOUT: return BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE;
            default: return BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
        }
    }

    /** True when a login password exists (LAPolicyDeviceOwnerAuthentication can
     *  evaluate) -- the Mac's equivalent of KeyguardManager.isDeviceSecure. */
    public static boolean isDeviceSecure() { return canEvaluate(true) == 0; }

    /** Start a prompt; returns an id for cancel(), or -1 if it could not start
     *  (the listener is then NOT called). */
    static int authenticate(boolean deviceCredential, String reason, String cancelTitle,
            Listener l) {
        if (!ON) return -1;
        final int id = sIds.getAndIncrement();
        sPending.put(id, l);
        try {
            nativeAuthenticate(id, deviceCredential, reason, cancelTitle);
            return id;
        } catch (UnsatisfiedLinkError e) {
            sPending.remove(id);
            return -1;
        }
    }

    static void cancel(int id) {
        try { nativeCancel(id); } catch (UnsatisfiedLinkError ignored) {}
    }

    /** Called from biometric_bridge.mm on a LocalAuthentication thread. */
    static void macapkOnResult(int id, int laCode) {
        if (laCode == 0) sLastAuthMillis = System.currentTimeMillis();
        Listener l = sPending.remove(id);
        if (l != null) {
            try { l.onResult(laCode); } catch (Throwable ignored) {}
        }
    }
}
