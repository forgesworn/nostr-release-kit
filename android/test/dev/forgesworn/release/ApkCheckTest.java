package dev.forgesworn.release;

/**
 * Host-JDK test of ApkCheck (run by tools/build-apk.sh before d8; not in the
 * APK). Exit status 0 = pass.
 */
public final class ApkCheckTest {
    private static int failures = 0;

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + what);
        }
    }

    private static final String PKG = "org.example.sibling";
    private static final String A = "a".repeat(64);
    private static final String B = "b".repeat(64);

    public static void main(String[] args) {
        // Strict (a sibling app from the catalog): package and both certificates must match.
        check(ApkCheck.verify(PKG, A, PKG, A, A, true, false), "strict: everything matches");
        check(!ApkCheck.verify("org.example.imposter", A, PKG, A, A, true, false), "strict: another package is refused");
        check(!ApkCheck.verify("", A, PKG, A, A, true, false), "strict: an unreadable package is refused");
        check(!ApkCheck.verify(PKG, B, PKG, A, A, true, false), "strict: another signer is refused");
        check(!ApkCheck.verify(PKG, A, PKG, B, A, true, false), "strict: not the catalog's pinned certificate");
        check(!ApkCheck.verify(PKG, A, PKG, A, B, true, false), "strict: not the release event's certificate");
        check(!ApkCheck.verify(PKG, "", PKG, A, A, true, false), "strict: an unreadable signer is refused");
        check(!ApkCheck.verify(PKG, A, PKG, "", A, true, false), "strict: no pinned certificate is refused");
        check(!ApkCheck.verify(PKG, A, PKG, A, "", true, false), "strict: no release certificate is refused");
        check(!ApkCheck.verify(PKG, A, "", A, A, true, false), "strict: no wanted package is refused");
        check(!ApkCheck.verify(PKG, A, PKG, A.toUpperCase(), A, true, false), "strict: certificates are lowercase hex");
        check(!ApkCheck.verify(PKG, "zz", PKG, "zz", "zz", true, false), "strict: not hex");
        check(!ApkCheck.verify(null, A, PKG, A, A, true, false), "strict: null package");
        check(!ApkCheck.verify(PKG, null, PKG, A, A, true, false), "strict: null certificate");

        // Several signers: refused, for a sibling and for this app's own update alike.
        check(!ApkCheck.verify(PKG, "", PKG, A, A, true, true), "strict: an APK with several signers is refused");
        check(!ApkCheck.verify(PKG, A, PKG, A, A, true, true), "strict: several signers are refused even with a matching certificate");
        check(!ApkCheck.verify(PKG, "", PKG, A, "", false, true), "loose: an APK with several signers is refused");
        check(!ApkCheck.verify(PKG, "", PKG, "", "", false, true), "loose: several signers are refused when the own certificate is unknown too");
        check(ApkCheck.verify(PKG, "", PKG, A, "", false, false), "loose: an unreadable signer (not several) is still left to Android");

        // Loose (this app's own update): the package must match; a certificate that could be read must too.
        check(ApkCheck.verify(PKG, A, PKG, A, "", false, false), "loose: own certificate matches");
        check(ApkCheck.verify(PKG, A, PKG, "", "", false, false), "loose: own certificate unknown, nothing to compare");
        check(ApkCheck.verify(PKG, "", PKG, A, "", false, false), "loose: the APK's certificate could not be read");
        check(!ApkCheck.verify(PKG, B, PKG, A, "", false, false), "loose: another signer is refused");
        check(!ApkCheck.verify("org.other", A, PKG, A, "", false, false), "loose: another package is refused");
        check(!ApkCheck.verify(PKG, A, PKG, A, B, false, false), "loose: a release certificate that differs is refused");

        // One installer: a start for another package is refused while an attempt runs; the same package re-attaches.
        final String own = "org.example.app";
        check(ApkCheck.busyWithAnother(true, PKG, own), "busy: this app's own start is refused during a sibling's attempt");
        check(ApkCheck.busyWithAnother(true, own, PKG), "busy: a sibling's start is refused during this app's own attempt");
        check(ApkCheck.busyWithAnother(true, PKG, "org.example.other"), "busy: another sibling is refused");
        check(!ApkCheck.busyWithAnother(true, PKG, PKG), "busy: the same package re-attaches");
        check(!ApkCheck.busyWithAnother(false, PKG, "org.example.other"), "busy: nothing in flight, anything may start");
        check(ApkCheck.busyWithAnother(true, "", PKG), "busy: an unknown owner is not assumed to be this one");
        check(ApkCheck.busyWithAnother(true, null, PKG), "busy: null owner");

        check(ApkCheck.isHex64(A) && !ApkCheck.isHex64(A.substring(1)) && !ApkCheck.isHex64(null), "isHex64");

        // The vectors the Rust mirror of this decision (archive_ok) is tested against too:
        // one decision, two implementations. Path of apk-check-vectors.tsv is the first argument.
        if (args.length > 0) {
            int n = 0;
            try {
                for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get(args[0]))) {
                    if (line.trim().isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] f = line.split("\t", -1);
                    check(f.length == 8, "vector has 8 fields: " + line);
                    if (f.length != 8) {
                        continue;
                    }
                    for (int i = 0; i < 5; i++) {
                        if (f[i].equals("-")) {
                            f[i] = "";
                        }
                    }
                    boolean got = ApkCheck.verify(f[0], f[1], f[2], f[3], f[4], f[5].equals("strict"), f[6].equals("many"));
                    check(got == f[7].equals("ok"), "vector: " + line);
                    n++;
                }
            } catch (java.io.IOException e) {
                check(false, "cannot read the vectors: " + e);
            }
            check(n >= 10, "enough vectors: " + n);
        }

        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("ApkCheckTest ok");
    }
}
