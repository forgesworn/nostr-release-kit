package dev.forgesworn.release;

/**
 * The comparison that decides whether a downloaded APK is the one that was
 * asked for: its package name and its signing certificate. Pure Java (no
 * Android classes) so it can be tested on the host JDK
 * (ApkCheckTest); {@link Updater} reads the package and certificate out of the
 * file with PackageManager and hands them here.
 *
 * <p>Sibling apps installed from a catalog use {@code strict}: the package
 * and BOTH certificates (the catalog's pinned one and the one the signed
 * release event names) must be present and equal what the APK says; anything
 * missing is a refusal. This app's own update keeps a looser rule for the
 * certificate: it enforces what could be read, because Android's own install-time
 * signature check is the one that counts there. An APK with several signers is refused
 * either way.
 */
final class ApkCheck {
    private ApkCheck() {}

    /** 64 lowercase hex digits. */
    static boolean isHex64(String s) {
        if (s == null || s.length() != 64) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param gotPkg      the APK's package name ("" if unreadable)
     * @param gotCert     SHA-256 hex of the APK's one signing certificate ("" if unreadable)
     * @param wantPkg     the package it must be
     * @param pinnedCert  the certificate pinned in the app (may be "" only when not strict)
     * @param releaseCert the certificate the release event names (may be "" only when not strict)
     * @param strict      every one of the above must be present and equal
     * @param multipleSigners the APK has more than one signer: refused, strict or not
     */
    static boolean verify(String gotPkg, String gotCert, String wantPkg, String pinnedCert, String releaseCert, boolean strict, boolean multipleSigners) {
        if (multipleSigners) {
            return false;
        }
        if (wantPkg == null || wantPkg.isEmpty() || gotPkg == null || !gotPkg.equals(wantPkg)) {
            return false;
        }
        if (strict) {
            return isHex64(gotCert) && isHex64(pinnedCert) && isHex64(releaseCert) && gotCert.equals(pinnedCert) && gotCert.equals(releaseCert);
        }
        // Loose: a certificate that was read must equal each one that was given.
        if (gotCert == null || gotCert.isEmpty()) {
            return true;
        }
        return (pinnedCert == null || pinnedCert.isEmpty() || gotCert.equals(pinnedCert)) && (releaseCert == null || releaseCert.isEmpty() || gotCert.equals(releaseCert));
    }

    /**
     * Whether a start for {@code want} must be refused because an attempt for another package is in
     * flight. {@code active} is the package of the current attempt ("" or null when none was started).
     * The same package is not refused (it re-attaches to its own attempt).
     */
    static boolean busyWithAnother(boolean inFlight, String active, String want) {
        return inFlight && (want == null || !want.equals(active));
    }
}
