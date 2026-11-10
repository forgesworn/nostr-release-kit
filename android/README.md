# Android half

Three small Java classes in package `dev.forgesworn.release`. They move the
bytes; the Rust crate decides what to install. No Gradle, no AndroidX: plain
`javac` against `android.jar`, then `d8`.

| File | What it does |
|---|---|
| `Updater.java` | Downloads the APK (HttpURLConnection, hashing as it streams), refuses a wrong size or hash, checks the file's package and signing certificate, writes it to a `PackageInstaller` session and commits it. The install is always a tap in Android's own prompt. |
| `ApkCheck.java` | Pure Java: the package and certificate comparison (several signers always refused). Unit-tested on the host JDK. |
| `RedirectRule.java` | Pure Java: which redirect targets a download may follow (https, no login in the address, port 443, a DNS host name). Unit-tested on the host JDK. |
| `UpdateReceiver.java` | Receives the installer session's status and passes it to `Updater`. |

## Compile it into your app

Add `android/java` to the sources you give `javac`, with the platform jar on the
class path, as for the rest of your Java:

```sh
find android/java ../nostr-release-kit/android/java -name '*.java' > sources.txt
javac --release 11 -Xlint:all -d classes -cp "$ANDROID_JAR" @sources.txt
# classes then go to d8 together with your own
```

Run the host-JDK tests in the same build, before `d8` (they are not part of the
APK). `ApkCheckTest` takes the shared vectors file as its argument:

```sh
KIT=../nostr-release-kit
javac --release 11 -d test-classes \
  $KIT/android/java/dev/forgesworn/release/ApkCheck.java \
  $KIT/android/java/dev/forgesworn/release/RedirectRule.java \
  $KIT/android/test/dev/forgesworn/release/ApkCheckTest.java \
  $KIT/android/test/dev/forgesworn/release/RedirectRuleTest.java
java -cp test-classes dev.forgesworn.release.ApkCheckTest $KIT/vectors/apk-check-vectors.tsv
java -cp test-classes dev.forgesworn.release.RedirectRuleTest
```

The Rust side loads `dev.forgesworn.release.Updater` through the Activity's class
loader (feature `android`). The class name is fixed; nothing is templated.

## Manifest

```xml
<uses-permission android:name="android.permission.INTERNET" />
<!-- Needed to hand an APK to the system installer (API 26+ asks the person once). -->
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />

<!-- Needed only for a catalog of sibling apps: Android 11+ hides other
     packages unless they are listed. One line per catalog package. -->
<queries>
    <package android:name="org.example.sibling" />
</queries>

<application ...>
    <!-- Not exported: the system calls it through the PendingIntent that Updater hands to commit. -->
    <receiver android:name="dev.forgesworn.release.UpdateReceiver" android:exported="false" />
</application>
```

`REQUEST_INSTALL_PACKAGES` is needed for any use of the installer, self-update
included. `<queries>` is needed only to see or open sibling apps.

## Activity hooks

Two calls from your Activity (they are `public static`):

```java
import dev.forgesworn.release.Updater;

@Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    Updater.attach(this);      // the Activity that can start the system prompts
    // ...
}

@Override protected void onResume() {
    super.onResume();
    Updater.onResume();        // starts the clock that gives up on an unanswered prompt
    // ...
}
```

`attach` also clears the APK downloads an earlier process left in
`cacheDir/release-kit/`.

The kit touches only what it made: files in `cacheDir/release-kit/` (an older
version of an integrating app may have left `cacheDir/updates/`; the kit does not
read or delete it), and the `PackageInstaller` sessions whose ids it recorded in
`cacheDir/release-kit/sessions.txt`. Your app's own sessions and cache files are
left alone.

## Static API the Rust side polls

`status()`, `done()`, `total()`, `message()`, `activePkg()`, `ownPackage()`, `certSha256()`,
`start(urls, sha256, size)`, `startSibling(urls, sha256, size, pkg, cert,
releaseCert)`, `cancel()`, `openInstallSettings()`, `installedVersionCode(pkg)`,
`launch(pkg)`. There are no native methods, so nothing needs registering in your
`.so`.
