# Integrating nostr-release-kit into an Android app

What an app has to provide to check for, verify and install its own updates (and,
optionally, those of sibling apps) with this kit. Three parts: the Rust side, the
Java and manifest side, and the publisher config. Read [README.md](../README.md) first
for what the kit trusts and what it refuses.

The kit decides what to install; the app supplies what it cannot: reading events from
relays (`ReleaseFetcher`) and, off Android, installing (`ApkInstaller`). The kit opens
no sockets of its own.

## 1. Rust

### Dependency

```toml
[dependencies]
nostr = "=0.44.8"       # the same version as the kit, so the types are one
nostr-release-kit = { git = "https://github.com/forgesworn/nostr-release-kit", features = ["android"] }
```

The `android` feature adds `nostr_release_kit::android::AndroidInstaller` (it needs
JNI). If your crate also builds for desktop, enable it for Android targets only.

### Describe the app: `Config`

`Config::new` returns a `Result`: use `?`. It refuses an empty channel, an invalid
package name, and a version that has no versionCode in the `major.minor.patch` scheme
(`1.4.0-beta`, `2024.11.1`). It never guesses.

```rust
use nostr_release_kit::Config;
use std::path::Path;

fn update_config(data_dir: Option<&Path>) -> Result<Config, String> {
    let mut config = Config::new(
        "exampleapp-android-apk",   // channel: the `d` tag of the release events
        "org.example.app",          // own package: the REAL applicationId
        "Example App",              // name shown in sentences
        env!("CARGO_PKG_VERSION"),  // running version, major.minor.patch
    )?
    .with_release_pubkey_hex("<64 hex: the release key's public half>")?;
    if let Some(dir) = data_dir {
        config = config.with_state_file(dir.join("update.json"));
    }
    Ok(config)
}
```

* **versionCode.** `Config::new` derives the installed versionCode as `major * 1e6 +
  minor * 1e3 + patch`. If your versionCodes follow another scheme, give the real one
  with `Config::new_with_code(channel, package, name, version, code)`. On Android the
  platform's own report for `own_package` replaces it at the first `tick`.
* **`own_package` must be the real package.** At the first `tick` the Android installer
  reports the package the app is really running as. If it differs from `own_package`,
  the updater turns itself off with a visible error (`Updater::setup_error`, also the
  status line of `view`) and never reads another app's versionCode: it checks, offers
  and installs nothing.
* **Release key.** Without `with_release_pubkey_hex` the updater is not `configured()`:
  no key, no check, no network. The key is the public half of the one in the publisher
  config (section 3); a test (below) keeps the two equal.
* Other fields are public and have defaults: `relays` (three public relays),
  `check_interval` (6 h), `fetch_timeout` (8 s), `version_label`.
* **Persist the state file.** `with_state_file` keeps the time of the last check and the
  best verified release event, so a restart does not forget an offer and the
  launch-time check stays throttled. Give it a path in the app's private data
  directory. With none, nothing is read or written. A missing or corrupt file is a
  fresh start; the saved event is verified again on load.

### Read events from relays: `ReleaseFetcher`

```rust
use nostr::Filter;
use nostr_release_kit::{FetchReport, PendingFetch, ReleaseFetcher};
use std::time::Duration;

struct MyFetcher;

struct Pending; // in real code: your handle on the running read

impl PendingFetch for Pending {
    /// Called from the frame loop: must not block. `Some` once, when the read is done.
    fn poll(&mut self) -> Option<FetchReport> {
        None // FetchReport { events, answered, total }
    }
}

impl ReleaseFetcher for MyFetcher {
    /// One REQ per relay carrying every filter; return at once.
    fn start(&mut self, relays: Vec<String>, filters: Vec<Filter>, timeout: Duration) -> Box<dyn PendingFetch> {
        let _ = (relays, filters, timeout); // in real code: spawn the read
        Box::new(Pending)
    }
}
```

`start` takes `Vec<Filter>`: the updater passes one filter, the catalog one per entry.
Hand the whole vector to your relay code. The kit verifies every event itself, so a
fetcher needs no trust in the relays. In the report, `answered` counts the relays that
really answered (an `EOSE`, or a kept event; a `CLOSED` is a refusal), so "nothing
published" and "could not reach the relays" stay different. `ReadyFetch(Some(report))`
is a `PendingFetch` that is already done.

### Install: `ApkInstaller`

On Android use the one the `android` feature provides:

```rust
use nostr_release_kit::android::AndroidInstaller;

let mut installer = AndroidInstaller;
```

Elsewhere implement `ApkInstaller` yourself, or take the defaults: every method but
`running_package` has a "cannot" default, so a platform with no installer implements only
`running_package` (returning `None`). `can_install_apk` is then false, so there is no
launch-time check; a manual check still works. If your platform forwards to
`AndroidInstaller` method by method, forward `running_package` too: it is required so that
the own-package check cannot be left out by accident. In tests use
`testing::RecordingInstaller` (set its `own_package` to the app's package, and
`running_package` to exercise the mismatch check) and `testing::FakeFetcher`. They need
no feature.

### Drive it from the frame loop

```rust
use nostr_release_kit::{UpdateView, Updater};

let mut updater = Updater::new(update_config(Some(&data_dir))?, Box::new(MyFetcher));
updater.enabled = true;                        // allowed to touch the network

// every frame:
updater.tick(dt, &mut installer);              // &mut dyn ApkInstaller
let view: UpdateView = updater.view(unix_now); // status line, tone, offer, progress, buttons

// "Check for updates":
updater.check_now();
// "Update":
updater.install(&mut installer)?;              // Err(notice) while another package installs
// "Cancel download":
updater.cancel_install(&mut installer);
```

If the person has their own relay list, pass it with `updater.set_user_relays(list)`:
those are asked first, then the config's relays. `unix_now` is seconds since the epoch.
Nothing installs silently: the last step is the person's tap in Android's own prompt.

### A catalog of sibling apps (optional)

```rust
use nostr_release_kit::{Catalog, CatalogConfig, CatalogEntry};

const ENTRIES: &[CatalogEntry] = &[CatalogEntry {
    name: "Sibling",
    blurb: "One line.",
    package: "org.example.sibling",
    channel: "siblingapp-android-apk",
    release_pubkey: Some("<64 hex>"),
    cert: Some("<64 hex: the sibling's signing certificate SHA-256>"),
}];

let config = CatalogConfig::new(ENTRIES.to_vec());
config.validate("org.example.app")?;          // at startup or in a test
let mut catalog = Catalog::new(config, Box::new(MyFetcher));

catalog.begin(&user_relays);                  // when the screen opens
catalog.tick(dt, &mut installer);             // every frame
let filters = catalog.filters();              // Vec<Filter>, one per ready entry
let status = catalog.status(0);               // EntryStatus: Get, Update, Open, ComingSoon, ...
catalog.install(0, &mut updater, &mut installer)?;
catalog.open(0, &mut installer);              // launch an installed sibling
```

`catalog.filters()` is what the catalog hands your `ReleaseFetcher` (through `begin`
and `tick`); call it yourself only to show or log the query. An entry with no key, no
certificate or an invalid package name is `ComingSoon` and never fetched.
`validate(own_package)` also rejects an entry whose package is the app's own (a sibling
release would run as an update of this app) and repeated entries. Siblings install
through the app's `Updater` (one install at a time).

### The `testing` feature: demo methods, test-only

`Updater::demo_offer`, `demo_install_state`, `demo_sibling_state`, `demo_release`,
`Catalog::demo`, and the setters `Updater::trust` and `set_installed`, stage a made-up
state for screenshots and tests. They exist only under the `testing` cargo feature (and
in the kit's own tests). `demo_offer` swaps the pinned release key for a throwaway one,
so a shipped build must never have them.

```toml
[target.'cfg(not(target_os = "android"))'.dependencies]
nostr-release-kit = { git = "https://github.com/forgesworn/nostr-release-kit", features = ["testing"] }
```

This needs Cargo resolver 2 (an edition 2021 package has it; a virtual workspace needs
`resolver = "2"`), otherwise the feature is unified into the Android build. As a
backstop, enabling `testing` together with `target_os = "android"` is a
`compile_error!`. `cfg` out the code that calls the demo methods from your release
build.

### A test the app must keep

The publisher cannot see your compiled pin, only `release.json`. If the two drift,
every release is signed by a key no device trusts and nothing complains. Keep a test
that builds the `Config` the app really uses and asserts its release pubkey equals
`release.json`'s:

```rust
#[test]
fn the_publisher_config_matches_the_apps_constants() {
    let json: serde_json::Value = serde_json::from_str(include_str!("../release.json")).unwrap();
    let c = update_config(None).unwrap();            // the Config the app really builds
    assert_eq!(json["channel"], c.channel.as_str());
    assert_eq!(json["package"], c.own_package.as_str());
    assert_eq!(json["release_pubkey"], c.release_pubkey.unwrap().to_hex().as_str());
}
```

(`serde_json` as a dev-dependency; adjust the `include_str!` path to where
`release.json` lives.) Do the same for each catalog entry's pins if you keep copies
elsewhere.

## 2. Java and manifest

The Java half is plain source: no Gradle plugin, no AndroidX. [android/README.md](../android/README.md)
has the full detail.

**Compile it with your sources.** Add the kit's `android/java` to the sources you give
`javac`, with `android.jar` on the class path, then hand all classes to `d8` together:

```sh
find app/java "$KIT/android/java" -name '*.java' > sources.txt
javac --release 11 -Xlint:all -d classes -cp "$ANDROID_JAR" @sources.txt
```

The host-JDK tests (`ApkCheckTest`, `RedirectRuleTest`, with the shared vectors in
`vectors/`) are listed in android/README.md; run them in the same build, before `d8`.

**Manifest.**

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />

<!-- Only for a catalog of sibling apps: Android 11+ hides other packages unless listed. -->
<queries>
    <package android:name="org.example.sibling" />
</queries>

<application ...>
    <receiver android:name="dev.forgesworn.release.UpdateReceiver" android:exported="false" />
</application>
```

The receiver must not be exported: the system reaches it through the `PendingIntent`
the kit hands to the installer. `REQUEST_INSTALL_PACKAGES` is needed for any install, a
self-update included. `<queries>` takes one `<package>` line per sibling in your
catalog (the siblings, not your own app) and is not needed without a catalog.

**Activity hooks.** Two static calls from the Activity that can show system prompts:

```java
import dev.forgesworn.release.Updater;

@Override protected void onCreate(Bundle state) {
    super.onCreate(state);
    Updater.attach(this);      // also clears downloads an earlier process left behind
    // ...
}

@Override protected void onResume() {
    super.onResume();
    Updater.onResume();        // starts the clock that gives up on an unanswered prompt
    // ...
}
```

The Rust side loads `dev.forgesworn.release.Updater` through the Activity's class
loader; the class name is fixed and nothing needs registering in your native library.

## 3. Publisher: `release.json`

The publisher is `tools/publish-release.mjs` (Node; run `npm ci` once in `tools/`; it
needs `aapt2` and `apksigner` from the Android build-tools). Everything that belongs to
the app is in one JSON file you keep in your repository. An unknown field is an error.

```json
{
  "channel": "exampleapp-android-apk",
  "package": "org.example.app",
  "expected_cert_sha256": "<64 hex: the certificate every release carries>",
  "release_pubkey": "<64 hex: the key the app pins>",
  "key_file_env": "EXAMPLEAPP_RELEASE_KEY_FILE",
  "key_file": "~/.exampleapp-release/release-key.hex",
  "relays": ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"],
  "mirrors": ["https://nostr.download"],
  "version_source": "flags",
  "blossom_note": "Release artifact upload"
}
```

| Field | Required | Meaning |
|---|---|---|
| `channel` | yes | The `d` tag: letters, digits, `.` `_` `-`, at most 64, starting with a letter or digit. Must equal the app's `Config` channel. |
| `package` | yes | The app's applicationId. The APK's package must equal it, and so must the app's `own_package`. |
| `expected_cert_sha256` | real publish | SHA-256 (64 lowercase hex) of the signing certificate every release carries. The publisher reads the certificate from the APK (`apksigner`), never from the command line, and refuses a different one unless `--allow-cert-change`. A real publish refuses while this is unset. |
| `release_pubkey` | real publish | The public half of the release key (64 lowercase hex): the one the app pins. The publisher refuses to sign with any other key, and reads the channel's current release with it. |
| `key_file_env` | one of the two | Name of an environment variable holding the path to the key file. Wins over `key_file` when that variable is set. |
| `key_file` | one of the two | Path to the key file (`~/` is the home directory), used when `key_file_env` is not set. |
| `relays` | no | Relays the event is published to and the current release is read from. Default: the three above. Add more per run with `--relay` or `RELEASE_KIT_RELAYS`. |
| `mirrors` | no | Blossom servers the APK is uploaded to. Default: `https://nostr.download`. At least one must serve the bytes back at the canonical address. Add more per run with `--mirror`. |
| `version_source` | no | `"flags"` (default): pass `--version-code` as well as `--version`. `"semver"`: the versionCode is derived from `--version` as `major * 1e6 + minor * 1e3 + patch`. Either way it must equal the APK's own versionCode. |
| `blossom_note` | no | Text of the Blossom upload authorisation. Default `Release artifact upload`. |

Mint the key once, pin the public half it prints in both places (the app's `Config`
and `release_pubkey`), then publish:

```sh
cd tools && npm ci
node publish-release.mjs --config ../release.json --init-key       # prints the public half only
node publish-release.mjs --config ../release.json app.apk --version 0.2.0 --version-code 2000 \
  --notes "What changed." [--dry-run]
```

**The key file** holds one 64-hex secret key and must be mode **0600** or stricter: the
publisher refuses a file that group or others can read, and `--init-key` creates it that
way. Keep it outside the repository, back it up, and never print it. `--dry-run` signs
with a throwaway key and uploads nothing.

Before it signs anything the publisher checks the key, the APK's package, versionCode
and versionName, that the APK is not debuggable and has one signer, the signing
certificate, that the versionCode is above the channel's current release (unless
`--allow-older`), and that the mirrors serve the exact bytes. The README lists the full
set.

## Checklist

* `Config` channel, package and release key match `release.json` (the test above).
* The APK's applicationId is `own_package`; `expected_cert_sha256` is the release
  keystore's certificate.
* `REQUEST_INSTALL_PACKAGES`, the non-exported `UpdateReceiver`, and one `<queries>` line
  per sibling are in the manifest.
* `Updater.attach(this)` in `onCreate`, `Updater.onResume()` in `onResume`.
* `testing` is enabled for non-Android targets only (resolver 2).
