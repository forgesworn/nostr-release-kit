package dev.forgesworn.release;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-app updates (the Rust crate nostr-release-kit is the native side, which decides
 * WHAT to install from a signed nostr release event). This class only moves bytes:
 *
 * <ol>
 *   <li>{@link #start} downloads the APK on a "release-update" thread with
 *       HttpURLConnection into cacheDir/release-kit, hashing as it streams, and
 *       aborts past size + 1 MiB;</li>
 *   <li>refuses unless it is exactly {@code size} bytes with SHA-256
 *       {@code sha256} (Rust got both from the verified event);</li>
 *   <li>writes it into a PackageInstaller session and commits it. Android
 *       answers {@code STATUS_PENDING_USER_ACTION} to {@link UpdateReceiver},
 *       which parks the system's confirm Intent here; {@link #status} then
 *       launches it from the Activity. Installing is always the user's tap
 *       in Android's own prompt, never silent.</li>
 * </ol>
 *
 * The same path installs a sibling app from a catalog ({@link #startSibling}): the
 * target app's package and signing certificate are then also checked, against
 * the catalog's pinned certificate and the release event's, on the downloaded
 * file before the installer session is committed ({@link ApkCheck}). This app's
 * own update gets the package check and, when its own certificate is
 * readable, the certificate check on the same file.
 *
 * The kit touches only what it made: files in {@code cacheDir/release-kit}, and the
 * installer sessions whose ids it recorded there. Sessions or cache files of the host app
 * are left alone.
 *
 * One worker at a time (a guard, not just the state), hashing covers exactly
 * the bytes handed to the installer (the install re-hashes while it copies and
 * abandons the session on a mismatch), only the current session's statuses are
 * believed, and a prompt the user walked away from (Home) times out into
 * "Tap Update to try again" instead of leaving the screen stuck.
 *
 * No native methods: Rust polls {@link #status}, {@link #done}, {@link #total}
 * and {@link #message}, so nothing here needs the app's native library.
 * Every entry point catches everything: trouble becomes FAILED with a message,
 * never a crash.
 */
public final class Updater {
    private static final String TAG = "release-kit";
    /** Under cacheDir: everything the kit writes (never the host app's own files). */
    private static final String KIT_DIR = "release-kit";
    /** In KIT_DIR: the ids of the installer sessions the kit created (one per line). */
    private static final String SESSIONS_FILE = "sessions.txt";
    /** What the user is told when a download is not the package or signer expected (the Rust side says the same). */
    static final String DIDNT_CHECK_OUT = "This download didn't check out, so it wasn't installed.";

    // Codes returned by status(); the Rust side (android.rs) mirrors these.
    static final int IDLE = 0;
    static final int DOWNLOADING = 1;
    static final int INSTALLING = 2;
    /** The system's confirm Intent is parked; status() launches it. */
    static final int CONFIRM_READY = 3;
    /** The system prompt is up. */
    static final int WAITING_USER = 4;
    static final int NEEDS_PERMISSION = 5;
    static final int FAILED = 6;
    static final int INSTALLED = 7;

    /** The download may overshoot the announced size by this much before it is cut off. */
    private static final long OVERRUN = 1024 * 1024;
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_MS = 20000;
    private static final int MAX_REDIRECTS = 4;
    /** The whole download must finish within this much, plus 1 s per 32 KiB of the announced size. */
    private static final long DEADLINE_FLOOR_MS = 5 * 60 * 1000L;
    /** Back in the app with Android's prompt unanswered this long: give up on it (a Home press sends no status). */
    private static final long RESUME_GRACE_MS = 6000;

    private static final Object LOCK = new Object();
    private static WeakReference<Activity> activity = new WeakReference<>(null);
    private static volatile int state = IDLE;
    private static volatile long done;
    private static volatile long total;
    private static volatile String message = "";
    private static Intent confirm;
    /** Only one download/install worker thread at a time. */
    private static final AtomicBoolean worker = new AtomicBoolean(false);
    /** Set by cancel(); the worker checks it on every chunk. */
    private static volatile boolean cancelled;
    private static volatile HttpURLConnection liveConn;
    /** The PackageInstaller session this attempt committed; statuses for any other session are ignored. -1 = none. */
    private static int sessionId = -1;
    /**
     * The package the current (or most recent) attempt is for: this app's own, or a catalog app's.
     * Set when a start is taken, kept through FAILED / INSTALLED so a late reader still knows whose
     * message it is, "" before any attempt. Each Rust follower believes {@link #status} only while
     * this is its own package ({@link #activePkg}).
     */
    private static volatile String activePkg = "";
    /** When the Activity came back to the front while Android's prompt was unanswered (0 = not since it was shown). */
    private static long resumedAt;

    private Updater() {}

    /** From the app's Activity.onCreate: the Activity that can start the system prompts. */
    public static void attach(Activity a) {
        activity = new WeakReference<>(a);
        // A fresh process holds no attempt: whatever an earlier one left in the kit's own
        // directory is dead weight. Only the kit's directory and only its download files.
        try {
            if (state == IDLE && !worker.get()) {
                File[] old = kitDir(a.getCacheDir()).listFiles();
                if (old != null) {
                    for (File f : old) {
                        if (f.getName().endsWith(".apk") || f.getName().endsWith(".part")) {
                            f.delete();
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: cleanup", t);
        }
    }

    /** The one directory the kit writes its downloads and its session record into. */
    private static File kitDir(File cacheDir) {
        return new File(cacheDir, KIT_DIR);
    }

    /**
     * From the app's Activity.onResume. If Android's prompt is up and the user came
     * back without answering it (Home, then the launcher), Android sends no
     * status, so start the clock that status() uses to give up on it.
     */
    public static void onResume() {
        synchronized (LOCK) {
            if (state == WAITING_USER) {
                resumedAt = SystemClock.elapsedRealtime();
            }
        }
    }

    private static Context context() {
        Activity a = activity.get();
        return a == null ? null : a.getApplicationContext();
    }

    // ─── What native polls ──────────────────────────────────────────────────

    /**
     * One of the codes above. When the system prompt is ready to be shown it
     * is launched from here (from the Activity, not from the receiver, which
     * trips background-start rules on some phones) and the answer is WAITING_USER.
     */
    public static int status() {
        try {
            Intent toLaunch = null;
            synchronized (LOCK) {
                if (state == CONFIRM_READY && confirm != null) {
                    toLaunch = confirm;
                } else if (state == WAITING_USER && resumedAt != 0 && SystemClock.elapsedRealtime() - resumedAt > RESUME_GRACE_MS) {
                    // The user left the prompt and came back; nothing will ever arrive. The next
                    // start() abandons the old session and installs again from the verified file.
                    fail("The update wasn't confirmed. Tap Update to try again.");
                }
            }
            if (toLaunch != null) {
                Activity a = activity.get();
                if (a != null) {
                    try {
                        a.startActivity(toLaunch);
                        synchronized (LOCK) {
                            confirm = null;
                            resumedAt = 0;
                            if (state == CONFIRM_READY) {
                                state = WAITING_USER;
                            }
                        }
                    } catch (RuntimeException e) {
                        Log.w(TAG, "updater: could not show the install prompt", e);
                        fail("Couldn't open Android's install prompt.");
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: status", t);
        }
        return state;
    }

    /** The package the current (or most recent) attempt is for; "" when none was started. */
    public static String activePkg() {
        return activePkg;
    }

    public static long done() {
        return done;
    }

    public static long total() {
        return total;
    }

    /** Why the last attempt FAILED, for the user. */
    public static String message() {
        return message;
    }

    /** This app's package name ({@code Context.getPackageName()}), or "". The Rust side checks its {@code own_package} against it. */
    public static String ownPackage() {
        try {
            Context c = context();
            return c == null ? "" : c.getPackageName();
        } catch (Throwable t) {
            Log.w(TAG, "updater: ownPackage", t);
            return "";
        }
    }

    // ─── This app's signing certificate ─────────────────────────────────────

    /** Lowercase hex SHA-256 of the certificate this app is signed with, or "". */
    @SuppressWarnings("deprecation")
    public static String certSha256() {
        try {
            Context c = context();
            if (c == null) {
                return "";
            }
            PackageManager pm = c.getPackageManager();
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                sigs = Api28.signers(pm, c.getPackageName());
            } else {
                PackageInfo pi = pm.getPackageInfo(c.getPackageName(), PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }
            if (sigs == null || sigs.length == 0) {
                Log.w(TAG, "updater: no signing certificate readable; the early cert check is skipped");
                return "";
            }
            return hex(MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray()));
        } catch (Throwable t) {
            Log.w(TAG, "updater: cert", t);
            return "";
        }
    }

    /** API 28+ signing info, in its own class so older phones never resolve SigningInfo. */
    private static final class Api28 {
        static Signature[] signers(PackageManager pm, String pkg) throws PackageManager.NameNotFoundException {
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo si = pi.signingInfo;
            // The certificate that signs the installed APK: apksigner's "Signer #1".
            return si == null ? null : si.getApkContentsSigners();
        }

        /** The signers of an APK file read with getPackageArchiveInfo (several if it has several; null if none can be read). */
        static Signature[] archiveSigners(PackageInfo pi) {
            SigningInfo si = pi.signingInfo;
            return si == null ? null : si.getApkContentsSigners();
        }

        static boolean multipleSigners(PackageInfo pi) {
            SigningInfo si = pi.signingInfo;
            return si != null && si.hasMultipleSigners();
        }

        static long longVersionCode(PackageInfo pi) {
            return pi.getLongVersionCode();
        }
    }

    // ─── Start ──────────────────────────────────────────────────────────────

    /**
     * Download, verify and install. {@code urls} is newline-separated, tried in
     * order. Returns at once; poll {@link #status}. If this app may not install
     * packages yet the answer is NEEDS_PERMISSION and nothing is downloaded.
     * Returns false when an attempt for ANOTHER package is in flight (nothing changed:
     * the caller must say so); true when this attempt is now the current one.
     */
    public static boolean start(String urls, String sha256, long size) {
        return startFor(urls, sha256, size, null, null, null);
    }

    /**
     * {@link #start} for a sibling app from a catalog: the downloaded APK must be
     * package {@code pkg} and signed with the certificate {@code cert} (the
     * catalog's) AND {@code releaseCert} (the release event's), both SHA-256
     * lowercase hex, or it is deleted and not installed.
     */
    public static boolean startSibling(String urls, String sha256, long size, String pkg, String cert, String releaseCert) {
        return startFor(urls, sha256, size, pkg == null ? "" : pkg, cert == null ? "" : cert, releaseCert == null ? "" : releaseCert);
    }

    /** What the downloaded file must be: its package, and the certificates that must have signed it. */
    private static final class Target {
        final String pkg;
        final String cert;
        final String releaseCert;
        final boolean strict;

        Target(String pkg, String cert, String releaseCert, boolean strict) {
            this.pkg = pkg;
            this.cert = cert;
            this.releaseCert = releaseCert;
            this.strict = strict;
        }
    }

    /** An attempt is in flight: a download, the copy into the installer, or Android's prompt. */
    private static boolean inFlight() {
        return state == DOWNLOADING || state == INSTALLING || state == CONFIRM_READY || state == WAITING_USER;
    }

    private static boolean startFor(String urls, String sha256, long size, String siblingPkg, String siblingCert, String siblingReleaseCert) {
        try {
            Context c = context();
            if (c == null) {
                fail("The app isn't ready yet.");
                return true;
            }
            final boolean sibling = siblingPkg != null;
            // this app's own update: this package, this app's own certificate (if it can be read).
            final Target target = sibling ? new Target(siblingPkg, siblingCert, siblingReleaseCert, true) : new Target(c.getPackageName(), certSha256(), "", false);
            final boolean targetOk = !sibling || (!siblingPkg.isEmpty() && !siblingPkg.equals(c.getPackageName()) && ApkCheck.isHex64(siblingCert) && ApkCheck.isHex64(siblingReleaseCert));
            synchronized (LOCK) {
                if (inFlight()) {
                    // Another package's attempt is left alone (its follower and its prompt stay its
                    // own) and the caller is told. The same package re-attaches to the running
                    // attempt, as an Activity that was recreated does.
                    return !ApkCheck.busyWithAnother(true, activePkg, target.pkg);
                }
                activePkg = target.pkg;
                if (worker.get()) {
                    // A cancelled or failed attempt is still winding down: one at a time.
                    message = "The last attempt is still stopping. Try again in a moment.";
                    state = FAILED;
                    return true;
                }
                message = "";
                sessionId = -1;
                resumedAt = 0;
                cancelled = false;
                done = 0;
                total = size;
                confirm = null;
                if (Build.VERSION.SDK_INT >= 26 && !c.getPackageManager().canRequestPackageInstalls()) {
                    state = NEEDS_PERMISSION;
                    return true;
                }
                if (size <= 0 || sha256 == null || sha256.length() != 64 || urls == null || urls.isEmpty() || !targetOk) {
                    state = FAILED;
                    message = "The update announcement was malformed.";
                    return true;
                }
                if (!worker.compareAndSet(false, true)) {
                    return true;
                }
                state = DOWNLOADING;
            }
            final String[] list = urls.split("\n");
            final String want = sha256.toLowerCase(Locale.ROOT);
            final long wantSize = size;
            final Context app = c;
            Thread t = new Thread(() -> run(app, list, want, wantSize, target), "release-update");
            t.setDaemon(true);
            try {
                t.start();
            } catch (Throwable e) {
                worker.set(false);
                throw e;
            }
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "updater: start", t);
            fail("Couldn't start the update.");
            return true;
        }
    }

    /**
     * Stop the current attempt. A download or the copy into the installer is
     * stopped by the worker at its next chunk (or at once if it is blocked
     * reading); the state then turns to FAILED so Update works again. An attempt
     * parked at Android's prompt (CONFIRM_READY, WAITING_USER) is dropped here:
     * its session is abandoned, so no prompt appears after the user left, and
     * the state turns to FAILED at once. Terminal states: nothing to cancel.
     */
    public static void cancel() {
        try {
            int abandon = -1;
            synchronized (LOCK) {
                if (state == DOWNLOADING || state == INSTALLING) {
                    cancelled = true;
                } else if (state == CONFIRM_READY || state == WAITING_USER) {
                    abandon = sessionId;
                    sessionId = -1;
                    fail("The update was cancelled.");
                } else {
                    return;
                }
            }
            if (abandon >= 0) {
                abandonSession(abandon);
            }
            HttpURLConnection c = liveConn;
            if (c != null) {
                c.disconnect();
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: cancel", t);
        }
    }

    /** The session ids recorded in {@code f} (empty if there is none or it cannot be read). */
    private static List<Integer> readSessionIds(File f) {
        List<Integer> ids = new ArrayList<>();
        try {
            if (f.isFile()) {
                java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
                try (InputStream in = new FileInputStream(f)) {
                    byte[] buf = new byte[256];
                    int n;
                    while ((n = in.read(buf)) > 0 && all.size() < 4096) {
                        all.write(buf, 0, n);
                    }
                }
                for (String line : new String(all.toByteArray(), "UTF-8").split("\n")) {
                    try {
                        ids.add(Integer.parseInt(line.trim()));
                    } catch (NumberFormatException e) {
                        // not an id: ignore the line
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            Log.w(TAG, "updater: session record", e);
        }
        return ids;
    }

    /** Record {@code id} as the kit's only open session (older ones were abandoned just before). */
    private static void writeSessionIds(File f, int id) {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write((id + "\n").getBytes("UTF-8"));
        } catch (IOException e) {
            Log.w(TAG, "updater: session record", e);
        }
    }

    /** Drop one PackageInstaller session of ours (its late statuses are ignored: the session id no longer matches). */
    private static void abandonSession(int id) {
        try {
            Context c = context();
            if (c != null && id >= 0) {
                c.getPackageManager().getPackageInstaller().abandonSession(id);
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: abandon session " + id, t);
        }
    }

    /** "Install unknown apps" for this app (API 26+; older Android has one global switch). */
    public static void openInstallSettings() {
        try {
            Context c = context();
            if (c == null) {
                return;
            }
            Intent i = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + c.getPackageName()));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Activity a = activity.get();
            if (a != null) {
                a.startActivity(i);
            } else {
                c.startActivity(i);
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: install settings", t);
        }
    }

    // ─── The worker ─────────────────────────────────────────────────────────

    private static void run(Context c, String[] urls, String sha256, long size, Target target) {
        try {
            runInner(c, urls, sha256, size, target);
        } finally {
            liveConn = null;
            worker.set(false);
        }
    }

    private static void runInner(Context c, String[] urls, String sha256, long size, Target target) {
        final long deadline = SystemClock.elapsedRealtime() + DEADLINE_FLOOR_MS + (size / (32 * 1024)) * 1000L;
        try {
            File dir = kitDir(c.getCacheDir());
            if (!dir.isDirectory() && !dir.mkdirs()) {
                fail("Couldn't make room for the update.");
                return;
            }
            File apk = new File(dir, sha256 + ".apk");
            // Anything else in the kit's own directory is an old download (the session record stays).
            File[] old = dir.listFiles();
            if (old != null) {
                for (File f : old) {
                    if (!f.equals(apk) && !f.getName().equals(SESSIONS_FILE)) {
                        f.delete();
                    }
                }
            }
            if (!(apk.isFile() && apk.length() == size && sha256.equals(hashOf(apk)))) {
                apk.delete();
                String last = "The download failed. Check your connection and try again.";
                boolean ok = false;
                for (String u : urls) {
                    if (!u.startsWith("https://")) {
                        continue;
                    }
                    try {
                        download(u, new File(dir, sha256 + ".apk.part"), apk, sha256, size, deadline);
                        ok = true;
                        break;
                    } catch (Stopped s) {
                        fail(s.getMessage());
                        return;
                    } catch (Mismatch m) {
                        last = m.getMessage();
                        Log.w(TAG, "updater: " + u + ": " + m.getMessage());
                    } catch (IOException e) {
                        Log.w(TAG, "updater: " + u + ": " + e);
                    }
                }
                if (!ok) {
                    fail(last);
                    return;
                }
            }
            done = size;
            // The bytes are the announced ones; are they the right app, from the right signer? Before
            // anything reaches the installer. (install() hashes the file again as it copies it in.)
            if (!archiveMatches(c, apk, target)) {
                apk.delete();
                fail(DIDNT_CHECK_OUT);
                return;
            }
            synchronized (LOCK) {
                if (state != DOWNLOADING) {
                    return;
                }
                state = INSTALLING;
            }
            try {
                install(c, apk, sha256, size, target.pkg);
            } catch (Stopped s) {
                fail(s.getMessage());
            } catch (Mismatch m) {
                // Not the verified bytes any more: never reuse that file.
                apk.delete();
                fail(m.getMessage());
            }
        } catch (Throwable t) {
            Log.w(TAG, "updater: run", t);
            fail("The update failed.");
        }
    }

    /** The bytes (or where they came from) were not what the announcement allowed. */
    private static final class Mismatch extends IOException {
        private static final long serialVersionUID = 1L;

        Mismatch(String m) {
            super(m);
        }
    }

    /** The user cancelled, or the download ran out of time. Not a reason to try the next mirror. */
    private static final class Stopped extends IOException {
        private static final long serialVersionUID = 1L;

        Stopped(String m) {
            super(m);
        }
    }

    private static void checkStop(long deadline) throws Stopped {
        if (cancelled) {
            throw new Stopped("The update was cancelled.");
        }
        if (SystemClock.elapsedRealtime() > deadline) {
            throw new Stopped("The download took too long. Check your connection and tap Update to try again.");
        }
    }

    private static void download(String url, File part, File dest, String sha256, long size, long deadline) throws IOException {
        part.delete();
        HttpURLConnection conn = null;
        try {
            String cur = url;
            for (int hops = 0;; hops++) {
                checkStop(deadline);
                conn = (HttpURLConnection) new URL(cur).openConnection();
                liveConn = conn;
                conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                conn.setReadTimeout(READ_TIMEOUT_MS);
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("User-Agent", "release-kit-updater");
                int code = conn.getResponseCode();
                if (code / 100 == 3 && hops < MAX_REDIRECTS) {
                    // Follow by hand, a few hops, and only to public https (RedirectRule):
                    // no login in the address, no other port, no bare IP or local name.
                    String loc = conn.getHeaderField("Location");
                    conn.disconnect();
                    if (loc == null) {
                        throw new IOException("redirect without a location");
                    }
                    cur = new URL(new URL(cur), loc).toString();
                    if (!RedirectRule.allows(cur)) {
                        throw new Mismatch("The download was sent somewhere it shouldn't go, so it was not installed.");
                    }
                    continue;
                }
                if (code != 200) {
                    throw new IOException("HTTP " + code);
                }
                break;
            }
            long announced = conn.getContentLengthLong();
            if (announced > size + OVERRUN) {
                throw new Mismatch("The download was larger than announced.");
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long got = 0;
            byte[] buf = new byte[64 * 1024];
            try (InputStream in = conn.getInputStream(); FileOutputStream out = new FileOutputStream(part)) {
                for (;;) {
                    checkStop(deadline);
                    int n = in.read(buf);
                    if (n < 0) {
                        break;
                    }
                    got += n;
                    if (got > size + OVERRUN) {
                        throw new Mismatch("The download was larger than announced.");
                    }
                    md.update(buf, 0, n);
                    out.write(buf, 0, n);
                    done = got;
                }
                out.getFD().sync();
            }
            if (got != size || !sha256.equals(hex(md.digest()))) {
                throw new Mismatch("The download didn't match what was announced, so it was not installed.");
            }
            dest.delete();
            if (!part.renameTo(dest)) {
                throw new IOException("rename failed");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(e);
        } catch (Stopped e) {
            throw e;
        } catch (IOException e) {
            if (cancelled) {
                throw new Stopped("The update was cancelled.");
            }
            if (SystemClock.elapsedRealtime() > deadline) {
                throw new Stopped("The download took too long. Check your connection and tap Update to try again.");
            }
            throw e;
        } finally {
            liveConn = null;
            if (conn != null) {
                conn.disconnect();
            }
            if (part.exists()) {
                part.delete();
            }
        }
    }

    // ─── Install ────────────────────────────────────────────────────────────

    private static void install(Context c, File apk, String sha256, long size, String pkg) throws IOException {
        PackageInstaller pi = c.getPackageManager().getPackageInstaller();
        File sessionsFile = new File(kitDir(c.getCacheDir()), SESSIONS_FILE);
        // The kit's own earlier, unfinished sessions only hold storage. Only the ids it recorded
        // are abandoned: a session the host app made for anything else is not the kit's to touch.
        try {
            List<Integer> recorded = readSessionIds(sessionsFile);
            if (!recorded.isEmpty()) {
                for (PackageInstaller.SessionInfo s : pi.getMySessions()) {
                    if (recorded.contains(s.getSessionId())) {
                        pi.abandonSession(s.getSessionId());
                    }
                }
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "updater: old sessions", e);
        }
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(pkg);
        params.setSize(size);
        if (Build.VERSION.SDK_INT >= 26) {
            params.setInstallReason(PackageManager.INSTALL_REASON_USER);
        }
        int id = pi.createSession(params);
        writeSessionIds(sessionsFile, id);
        PackageInstaller.Session session = pi.openSession(id);
        try {
            // The hash of the bytes that GO INTO the session, not of the file as it was earlier:
            // nothing can slip in between the check and the install.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            try (InputStream in = new FileInputStream(apk); OutputStream out = session.openWrite("base.apk", 0, size)) {
                byte[] buf = new byte[64 * 1024];
                for (;;) {
                    if (cancelled) {
                        throw new Stopped("The update was cancelled.");
                    }
                    int n = in.read(buf);
                    if (n < 0) {
                        break;
                    }
                    copied += n;
                    if (copied > size) {
                        throw new Mismatch("The update file changed after it was checked, so it was not installed.");
                    }
                    md.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
                if (copied != size || !sha256.equals(hex(md.digest()))) {
                    throw new Mismatch("The update file changed after it was checked, so it was not installed.");
                }
                session.fsync(out);
            }
            if (cancelled) {
                throw new Stopped("The update was cancelled.");
            }
            synchronized (LOCK) {
                sessionId = id;
            }
            // Mutable: the system fills in the status extras. Explicit, as API 34 requires of a mutable PendingIntent.
            Intent result = new Intent(c, UpdateReceiver.class);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (Build.VERSION.SDK_INT >= 31) {
                flags |= PendingIntent.FLAG_MUTABLE;
            }
            IntentSender sender = PendingIntent.getBroadcast(c, id, result, flags).getIntentSender();
            session.commit(sender);
        } catch (IOException | RuntimeException | java.security.NoSuchAlgorithmException e) {
            synchronized (LOCK) {
                sessionId = -1;
            }
            session.abandon();
            if (e instanceof IOException) {
                throw (IOException) e;
            }
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new IOException(e);
        } finally {
            session.close();
        }
    }

    // ─── The package and signer of a downloaded file ────────────────────────

    /**
     * Read the APK's package name and signing certificate with PackageManager
     * ({@code getPackageArchiveInfo}, as Android itself would see them) and compare
     * them with the target ({@link ApkCheck#verify}). An APK with more than one signer is
     * refused for a sibling and for this app's own update. A sibling app must be readable and
     * match on all counts. For this app's own update the archive must be one
     * Android can describe too (an unreadable one is refused here, not left to
     * the installer: a file that cannot be described is not worth offering); it
     * must be this package and, if this app's own certificate and the file's
     * signer can both be read, the same signer.
     */
    @SuppressWarnings("deprecation")
    private static boolean archiveMatches(Context c, File apk, Target t) {
        String gotPkg = "";
        String gotCert = "";
        boolean multiple = false;
        try {
            PackageManager pm = c.getPackageManager();
            PackageInfo pi;
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                pi = pm.getPackageArchiveInfo(apk.getPath(), PackageManager.GET_SIGNING_CERTIFICATES);
                sigs = pi == null ? null : Api28.archiveSigners(pi);
                multiple = pi != null && Api28.multipleSigners(pi);
            } else {
                pi = pm.getPackageArchiveInfo(apk.getPath(), PackageManager.GET_SIGNATURES);
                sigs = pi == null ? null : legacySignatures(pi);
            }
            if (pi == null) {
                Log.w(TAG, "updater: the archive could not be read");
                return false;
            }
            gotPkg = pi.packageName == null ? "" : pi.packageName;
            // Exactly one signer, for a sibling and for this app's own update alike: a second
            // signer is not what was pinned or announced, and is refused (ApkCheck.verify).
            multiple = multiple || (sigs != null && sigs.length > 1);
            if (!multiple && sigs != null && sigs.length == 1) {
                gotCert = hex(MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray()));
            }
        } catch (Throwable e) {
            Log.w(TAG, "updater: archive check", e);
            return false;
        }
        boolean ok = ApkCheck.verify(gotPkg, gotCert, t.pkg, t.cert, t.releaseCert, t.strict, multiple);
        if (!ok) {
            Log.w(TAG, "updater: the file is package " + gotPkg + " signed " + gotCert + ", wanted " + t.pkg + " signed " + t.cert + " / " + t.releaseCert);
        }
        return ok;
    }

    @SuppressWarnings("deprecation")
    private static Signature[] legacySignatures(PackageInfo pi) {
        return pi.signatures;
    }

    // ─── Other apps (a catalog) ─────────────────────────────────────

    /** The installed versionCode of {@code pkg}, or -1 when it is not installed (or not visible: see the manifest's queries). */
    @SuppressWarnings("deprecation")
    public static long installedVersionCode(String pkg) {
        try {
            Context c = context();
            if (c == null || pkg == null || pkg.isEmpty()) {
                return -1;
            }
            PackageInfo pi = c.getPackageManager().getPackageInfo(pkg, 0);
            return Build.VERSION.SDK_INT >= 28 ? Api28.longVersionCode(pi) : pi.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        } catch (Throwable t) {
            Log.w(TAG, "updater: installedVersionCode", t);
            return -1;
        }
    }

    /** Open an installed app by its launcher intent. False if it is not there or would not start. */
    public static boolean launch(String pkg) {
        try {
            Context c = context();
            if (c == null || pkg == null || pkg.isEmpty()) {
                return false;
            }
            Intent i = c.getPackageManager().getLaunchIntentForPackage(pkg);
            if (i == null) {
                return false;
            }
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Activity a = activity.get();
            if (a != null) {
                a.startActivity(i);
            } else {
                c.startActivity(i);
            }
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "updater: launch", t);
            return false;
        }
    }

    // ─── From UpdateReceiver ────────────────────────────────────────────────

    /** The installer's answer for our session (UpdateReceiver.onReceive). */
    @SuppressWarnings("deprecation")
    static void onInstallStatus(Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        String detail = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
        int sid = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1);
        synchronized (LOCK) {
            if (sid < 0 || sid != sessionId) {
                // An old attempt's prompt answered late (or one from before a restart): not ours.
                Log.i(TAG, "updater: ignoring status " + status + " for session " + sid + " (current " + sessionId + ")");
                return;
            }
        }
        Log.i(TAG, "updater: install status " + status + " " + detail);
        switch (status) {
            case PackageInstaller.STATUS_PENDING_USER_ACTION: {
                Intent next = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                if (next == null) {
                    fail("Android didn't show its install prompt.");
                    return;
                }
                next.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                boolean late;
                synchronized (LOCK) {
                    late = cancelled;
                    if (late) {
                        sessionId = -1;
                    } else {
                        confirm = next;
                        resumedAt = 0;
                        state = CONFIRM_READY;
                    }
                }
                if (late) {
                    // The user cancelled (left the screen) after the commit: no prompt now.
                    abandonSession(sid);
                    fail("The update was cancelled.");
                }
                return;
            }
            case PackageInstaller.STATUS_SUCCESS:
                synchronized (LOCK) {
                    state = INSTALLED;
                }
                return;
            case PackageInstaller.STATUS_FAILURE_ABORTED:
                fail("The update wasn't installed. Tap Update to try again.");
                return;
            case PackageInstaller.STATUS_FAILURE_CONFLICT:
                fail("Android refused the update: it doesn't match the installed app (a different signing key).");
                return;
            case PackageInstaller.STATUS_FAILURE_INCOMPATIBLE:
                fail("This phone can't run that version.");
                return;
            case PackageInstaller.STATUS_FAILURE_STORAGE:
                fail("Not enough storage to install the update.");
                return;
            case PackageInstaller.STATUS_FAILURE_BLOCKED:
                fail("Android blocked the install on this phone.");
                return;
            case PackageInstaller.STATUS_FAILURE_INVALID:
                fail("Android found the update file invalid.");
                return;
            default:
                fail("Android couldn't install the update.");
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static void fail(String why) {
        synchronized (LOCK) {
            confirm = null;
            message = why;
            state = FAILED;
        }
    }

    private static String hashOf(File f) {
        try (InputStream in = new FileInputStream(f)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[64 * 1024];
            for (;;) {
                int n = in.read(buf);
                if (n < 0) {
                    break;
                }
                md.update(buf, 0, n);
            }
            return hex(md.digest());
        } catch (IOException | java.security.NoSuchAlgorithmException e) {
            return "";
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
