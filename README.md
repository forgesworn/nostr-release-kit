# nostr-release-kit

Publish and verify app releases announced as Nostr kind-30063 events, and check
for and install updates: of the app itself, and of sibling apps from a pinned
catalog. The APK lives on a Blossom server; the signed event names it by SHA-256,
size and signing certificate.

There is no update server and no store. A release is one event signed by one key
the app already trusts, and an APK anyone can mirror.

| Part | Where | What |
|---|---|---|
| Rust crate `nostr-release-kit` | `src/` | The rules (`parse_release`, `judge`, the catalog trust rules) and the `Updater` / `Catalog` state machines. UI-neutral. |
| Android half | `android/java/` | `Updater`, `ApkCheck`, `RedirectRule`, `UpdateReceiver`: download, verify, hand to Android's installer. JNI glue behind the `android` cargo feature. |
| Publisher | `tools/` | `publish-release.mjs`: upload to Blossom, verify the mirror, sign and announce. Driven by a JSON config. |
| Shared vectors | `vectors/` | Read by the Rust, Java and Node tests, so each rule has one definition and several implementations. |

## Trust model

An update is offered only when every one of these holds:

1. **Pinned release key.** The event is signed by the one key the app pins
   (per app: a catalog entry pins its own). Id and signature are verified. A
   relay can carry the event; it cannot forge it. Rotating the key means shipping
   a new APK by hand: there is no in-band rotation.
2. **Channel.** The `d` tag equals the app's channel (for example
   `exampleapp-android-apk`), so one key can sign several apps without their
   events being interchangeable.
3. **Canonical Blossom URLs only.** Every `url` tag is `https://host[:port]/<sha256>`
   or `.../<sha256>.<ext>` with no query, fragment, credentials or extra path. That
   is the one address a Blossom server promises to keep serving. One bad URL
   rejects the whole event.
4. **Hash and size.** The `x` tag is the APK's SHA-256, `size` its exact length
   (capped at 256 MiB). The download is streamed through SHA-256, cut off past
   `size` + 1 MiB, and refused on any mismatch. The bytes are hashed again as they
   are copied into the installer session.
5. **Signing certificate.** The `cert` tag must equal the app's own signing
   certificate (for a self-update) or the certificate pinned in the catalog entry
   (for a sibling). The downloaded file's own certificate is read and compared
   again before the installer sees it, and an APK with more than one signer is
   refused (a sibling or a self-update alike). Android itself refuses an update
   signed with a different certificate.
6. **Package.** The downloaded file's package must equal the app's own (for a
   self-update) or the catalog entry's. For a sibling, package, pinned
   certificate and the event's certificate must all be present and equal (strict).
7. **Newer.** `version_code` is above the installed versionCode.

Also:

* **Nothing is fetched until asked.** The kit opens no sockets; the app's
  `ReleaseFetcher` does, when the kit asks (at launch if the last check is old
  enough, or on a button).
* **No identity is sent.** A check is a plain relay read of public events.
* **Nothing installs silently.** The last step is always the person's tap in
  Android's own install prompt.
* **Redirects.** A download follows at most four redirects, each to https on port
  443 at a DNS host name (no bare IP, `localhost` or login in the address). The rule
  is syntactic: it cannot see what a DNS name resolves to, so it narrows where a
  mirror can send a phone; it does not keep the request on the public web. The
  bytes are hash-checked either way.
* **Event URLs are looser than redirects.** A release event's own `url` tags are
  checked for the canonical Blossom shape (https, no query, fragment or
  credentials), and may carry an IP literal or another port. The event is signed by
  your key, so the host is your choice; the bytes are hash-checked.

## Event format

Kind 30063 (replaceable, addressed by `d`). Tags:

| Tag | Value |
|---|---|
| `d` | the channel |
| `version` | display version, 1 to 32 bytes, no control characters |
| `version_code` | Android versionCode, plain decimal, 1 to 4294967295 |
| `x` | APK SHA-256, 64 lowercase hex |
| `size` | APK length in bytes, plain decimal, at most 268435456 |
| `cert` | SHA-256 of the APK's signing certificate, 64 lowercase hex |
| `url` | one or more canonical Blossom URLs |

`content` is the release notes. Example (signed with a throwaway key):

```json
{
  "kind": 30063,
  "created_at": 1791886220,
  "tags": [
    ["d", "exampleapp-android-apk"],
    ["version", "0.1.0"],
    ["version_code", "1000"],
    ["x", "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c"],
    ["size", "1048576"],
    ["cert", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
    ["url", "https://blossom.example.com/50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c.apk"]
  ],
  "content": "First in-app update release.",
  "pubkey": "e006ba9bc962c9f354d1194d5fab6c5f26907469f8900841181cd1d54a0131ce",
  "id": "6cbc2793d56b8181fab59e3b50ff8c371ebd8a84416f209512ec24cbd2d5f4e8",
  "sig": "a694131deea6060b12025e2c5a7ac4ee6c0f96977017f9dc2c79d738e7d0d7003730167711960b48dcb7ddd59ec187044e988ad6cb1a1f51cefaf5fd81e231ce"
}
```

The highest `version_code` among valid events wins (a later `created_at` breaks a
tie). An older event served by a stale relay never displaces a newer one the app
already knows.

## Integrating

### 1. Rust

```toml
[dependencies]
nostr-release-kit = { git = "https://github.com/forgesworn/nostr-release-kit", features = ["android"] }
```

Describe the app, and give the kit two things only you can provide: a way to read
events from relays, and (off Android) a way to install.

```rust
use nostr_release_kit::{Config, Updater, ReleaseFetcher, PendingFetch, FetchReport};

let config = Config::new(
    "exampleapp-android-apk",   // channel (the `d` tag)
    "org.example.app",          // own package: the real applicationId
    "Example App",              // name shown in sentences
    env!("CARGO_PKG_VERSION"),  // running version, major.minor.patch
)?                              // Err if the version has no versionCode (see below)
.with_release_pubkey_hex("<64 hex: the release key's public half>")?
.with_state_file(data_dir.join("update.json"));
// config.relays, check_interval (6 h), fetch_timeout (8 s) have defaults.

let mut updater = Updater::new(config, Box::new(MyFetcher));
updater.enabled = true;                       // allowed to touch the network

// every frame:
updater.tick(dt, &mut installer);             // installer: &mut dyn ApkInstaller
let view = updater.view(unix_now);            // UpdateView: status line, offer, progress, buttons
// on "Check for updates":  updater.check_now();
// on "Update":             updater.install(&mut installer)?;
```

The two traits:

```rust
pub trait ReleaseFetcher {
    /// Start reading `filters` from `relays` (all at once, one REQ with every filter); return at once.
    fn start(&mut self, relays: Vec<String>, filters: Vec<Filter>, timeout: Duration)
        -> Box<dyn PendingFetch>;
}
pub trait PendingFetch {
    fn poll(&mut self) -> Option<FetchReport>;   // events + how many relays answered
}

pub trait ApkInstaller { /* apk_start, apk_status, apk_cancel, apk_active_package,
    apk_open_install_settings, own_cert_sha256, can_install_apk,
    installed_version_code, open_package; every method has a "cannot" default */ }
```

With the `android` feature, `nostr_release_kit::android::AndroidInstaller` is an
`ApkInstaller` over the Java half. `testing::RecordingInstaller` and
`testing::FakeFetcher` are doubles for your own tests (no feature needed).

**The installed versionCode fails closed.** `Config::new` derives it from the
version (`major * 1e6 + minor * 1e3 + patch`) and returns an error for a version
that has none (`1.4.0-beta`, `2024.11.1`): it never guesses, and an `Updater`
without a versionCode checks and offers nothing. If your versionCodes follow another
scheme, give the real one with `Config::new_with_code`. On Android the platform's
own report for `own_package` (`PackageManager`, through
`ApkInstaller::installed_version_code`) replaces the config's value at the first
`tick`: the real installed code wins, the config's is the fallback.

**Staging is a cargo feature, never a shipped one.** The methods that put an
`Updater` or `Catalog` in a made-up state for screenshots and tests (`demo_offer`,
`demo_install_state`, `demo_sibling_state`, `demo_release`, `Catalog::demo`, and
the test setters `trust` and `set_installed`) exist only under the `testing`
feature (and in this crate's own tests). `demo_offer` swaps the pinned release key
for a throwaway one, so a production `Updater` has no way to replace its pinned
key, with or without a state file. Enable the feature for dev and test builds only,
and `cfg` out the code that calls them from your release build, for example:

```toml
[target.'cfg(not(target_os = "android"))'.dependencies]
nostr-release-kit = { git = "https://github.com/forgesworn/nostr-release-kit", features = ["testing"] }
```

This needs Cargo resolver 2 (an edition 2021 package has it; a virtual workspace needs
`resolver = "2"`): under resolver 1 the feature is unified into the Android build.
Enabling `testing` together with `target_os = "android"` is a `compile_error!`.

**Pin test.** The publisher cannot see your app's compiled pin, only the key in
`release.json`. If the two drift, every release is signed by a key no device trusts
and nothing complains. Keep a test in your app that compares the compiled constants
with the publisher config:

```rust
#[test]
fn the_publisher_config_matches_the_apps_constants() {
    let json: serde_json::Value = serde_json::from_str(include_str!("../release.json")).unwrap();
    let c = update_config(None);                    // the Config the app really builds
    assert_eq!(json["channel"], c.channel.as_str());
    assert_eq!(json["package"], c.own_package.as_str());
    assert_eq!(json["release_pubkey"], c.release_pubkey.unwrap().to_hex().as_str());
}
```

A catalog of sibling apps (each entry pins its package, channel, release key and
signing certificate):

```rust
use nostr_release_kit::{Catalog, CatalogConfig, CatalogEntry};

const ENTRIES: &[CatalogEntry] = &[CatalogEntry {
    name: "Sibling", blurb: "One line.", package: "org.example.sibling",
    channel: "siblingapp-android-apk",
    release_pubkey: Some("<64 hex>"), cert: Some("<64 hex>"),
}];
let mut catalog = Catalog::new(CatalogConfig::new(ENTRIES.to_vec()), Box::new(MyFetcher));
catalog.begin(&user_relays);                  // when the screen opens
catalog.tick(dt, &mut installer);
catalog.status(i);                            // EntryStatus: Get, Update, Open, ComingSoon, ...
catalog.install(i, &mut updater, &mut installer)?;
```

An entry with no key, no certificate or no valid package name is `ComingSoon` and
never fetched. Call `CatalogConfig::validate(own_package)` at startup or in a test:
it also rejects an entry whose package is the app's own (a sibling release would
otherwise run as an update of this app) and repeated entries. The catalog reads
with one filter per entry, so `ReleaseFetcher::start` takes `Vec<Filter>`.

### 2. Java and manifest

See [android/README.md](android/README.md): compile `android/java` with your
sources, declare the receiver, add the two Activity calls. The whole integration,
step by step, is in [docs/integrating.md](docs/integrating.md).

### 3. Publisher

```sh
cd tools && npm ci
node publish-release.mjs --config ../release.json --init-key      # once; prints the public half
node publish-release.mjs --config ../release.json app.apk --version 0.2.0 --version-code 2000 \
  --notes "What changed." [--dry-run]
```

`release.json`:

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
  "version_source": "flags"
}
```

Only `channel` and `package` are required. With `"version_source": "semver"` the
versionCode is `major * 1e6 + minor * 1e3 + patch`, derived from `--version`.
The key file holds a 64-hex secret key; nothing in this repository reads a real
key, and the tests use throwaway ones.

The key file must not be readable by group or others (mode 0600 or stricter): the
publisher refuses a looser one. `npm ci` installs the exact versions in the lockfile.

Before it signs anything the publisher checks: the key matches `release_pubkey`;
the APK's package, versionCode and versionName match the config and flags; the APK
is not debuggable; the APK has exactly one signer (`apksigner` reporting more is
refused, as devices refuse such an APK); the signing certificate (read from the
APK with `apksigner`) equals `expected_cert_sha256` unless `--allow-cert-change`; the versionCode is
above the channel's current release unless `--allow-older`; at least one mirror
takes the upload, and every URL that is announced serves the bytes back at the
canonical address with a direct 200 and the right hash (a mirror that fails to
upload or verify is skipped, and the publish fails if none is left). A mirror whose
canonical address redirects somewhere a device would not follow (not https on 443
at a DNS host name, or more than four hops; the rule in `RedirectRule`) stops the
publish before anything is signed. It needs
`aapt2` and `apksigner` from the Android build-tools (`ANDROID_HOME`).
`--dry-run` signs with a throwaway key and uploads nothing.

## Tests

```sh
cargo test --all-features                       # Rust
cd tools && npm ci && node --test               # publisher
# Java: see android/README.md (ApkCheckTest, RedirectRuleTest)
```

## Limits

* Android only. The Rust rules and the publisher are platform-neutral; the
  installer half is `PackageInstaller` and needs `REQUEST_INSTALL_PACKAGES`.
* One install at a time (Android's installer is one). A second request for a
  different package is refused with a visible notice, never queued.
* One signing certificate per APK: an APK with several signers is refused by the
  device check (sibling and self-update alike) and by the publisher.
* A release is at most 256 MiB.
* APK signing-key rotation (the v3 / v3.1 lineage) is not supported. A device refuses
  an APK signed with a rotated key as a different key, and the publisher does not
  detect a rotation (it reads one signer's certificate). Keep one signing key for the
  life of the app.
* An app that uses `versionCodeMajor` is never offered an update: its installed
  versionCode does not fit 32 bits, so the kit reads it as newer than any release
  (fail closed).
* `Config.own_package` must be the running app's package. The Android installer checks
  it at the first tick; on a mismatch updates are off, with a visible error, and no
  other app's versionCode is ever used.
* The release key cannot be rotated in-band. A compromised key means shipping a
  new APK, with a new pin, by hand.
* A relay or mirror can withhold an update (and a stale relay can serve an old
  one, which is ignored); it cannot make the app install anything unsigned.
* Sideloaded updates only: if the app came from a store, the store's own updater
  and policies apply.

## Licence

MIT. See [LICENSE](LICENSE). Security: see [SECURITY.md](SECURITY.md).
