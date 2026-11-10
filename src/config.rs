//! What an app tells the kit about itself.

use crate::release::{is_package_name, version_code_of};
use nostr::PublicKey;
use std::path::PathBuf;
use std::time::Duration;

/// Where releases are looked for unless the app says otherwise. A relay can only
/// carry an event, never forge one: the pinned release key signs it.
pub const DEFAULT_RELEASE_RELAYS: [&str; 3] = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"];
/// How long the relays get to answer.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(8);
/// The launch-time check runs at most this often.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// Shown while no release key is pinned.
pub const NOT_SET_UP: &str = "Updates aren't set up for this build yet";

/// Everything the [`crate::Updater`] needs to know about the app it updates.
#[derive(Clone, Debug)]
pub struct Config {
    /// The `d` tag of this app's release events, e.g. `exampleapp-android-apk`.
    pub channel: String,
    /// Release relays, asked on top of the user's own (their order first).
    pub relays: Vec<String>,
    /// The pinned release key. `None` disables update checks (and shows [`NOT_SET_UP`]).
    /// Rotating a pinned key means shipping a new APK by hand: there is no in-band rotation.
    pub release_pubkey: Option<PublicKey>,
    /// This app's Android package (its applicationId): the installer's "owner" while the app
    /// updates itself. It must be the real one: a typo makes every self-update read
    /// "Another install is in progress" (the updater logs an error when the platform
    /// does not know the package).
    pub own_package: String,
    /// The app's name, for sentences shown to the person using it.
    pub app_name: String,
    /// The running version, shown to the person. Unless the app gave a versionCode
    /// ([`Config::new_with_code`]) it is `major.minor.patch` and its versionCode is
    /// [`crate::version_code_of`].
    pub version: String,
    /// The installed versionCode the kit compares releases with. Always above zero
    /// ([`Config::new`] refuses anything else). On a platform that can report the real
    /// one for `own_package` (Android: `PackageManager`), the platform's value wins
    /// at the first `Updater::tick`; this one is the fallback (and what desktop uses).
    pub version_code: u32,
    /// What the screens print as the installed version. Default: `v{version}`.
    pub version_label: Option<String>,
    /// The launch-time check runs at most this often.
    pub check_interval: Duration,
    /// How long a relay read may take.
    pub fetch_timeout: Duration,
    /// Where the last check and the best verified release event are kept. `None` = in memory only.
    pub state_file: Option<PathBuf>,
}

impl Config {
    /// A config with the default relays, interval and timeout, no pinned key and no state file.
    /// The installed versionCode is derived from `version` (`major * 1e6 + minor * 1e3 +
    /// patch`, [`crate::version_code_of`]); a version that has none (`1.4.0-beta`,
    /// `2024.11.1`) is an `Err`, never a guess: use [`Config::new_with_code`] to give the
    /// app's real versionCode. An empty channel or an invalid `own_package` is an `Err` too.
    pub fn new(channel: &str, own_package: &str, app_name: &str, version: &str) -> Result<Config, String> {
        let code = version_code_of(version).filter(|c| *c > 0).ok_or_else(|| {
            format!("version {version:?} has no versionCode in the major.minor.patch scheme: give the real one with Config::new_with_code")
        })?;
        Config::new_with_code(channel, own_package, app_name, version, code)
    }

    /// [`Config::new`] with the installed versionCode given (for an app whose versionCode is
    /// not derived from its version). Must be above zero.
    pub fn new_with_code(channel: &str, own_package: &str, app_name: &str, version: &str, version_code: u32) -> Result<Config, String> {
        if version_code == 0 {
            return Err("the installed versionCode must be above zero".into());
        }
        if channel.is_empty() || channel.chars().any(char::is_control) {
            return Err("the channel (the `d` tag) must be a non-empty string".into());
        }
        if !is_package_name(own_package) {
            return Err(format!("own_package {own_package:?} is not an Android package name"));
        }
        Ok(Config {
            channel: channel.to_string(),
            relays: DEFAULT_RELEASE_RELAYS.iter().map(|s| s.to_string()).collect(),
            release_pubkey: None,
            own_package: own_package.to_string(),
            app_name: app_name.to_string(),
            version: version.to_string(),
            version_code,
            version_label: None,
            check_interval: DEFAULT_CHECK_INTERVAL,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            state_file: None,
        })
    }

    /// Pin the release key from its hex (x-only) form.
    pub fn with_release_pubkey_hex(mut self, hex: &str) -> Result<Config, String> {
        self.release_pubkey = Some(PublicKey::from_hex(hex).map_err(|e| format!("not a valid release key: {e}"))?);
        Ok(self)
    }

    /// Keep the update state in this file.
    pub fn with_state_file(mut self, path: impl Into<PathBuf>) -> Config {
        self.state_file = Some(path.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_code_comes_from_the_version_or_from_the_app() {
        assert_eq!(Config::new("c", "org.example.app", "App", "1.4.2").unwrap().version_code, 1_004_002);
        let c = Config::new_with_code("c", "org.example.app", "App", "1.4.0-beta", 77).unwrap();
        assert_eq!((c.version.as_str(), c.version_code), ("1.4.0-beta", 77));
    }

    #[test]
    fn a_version_without_a_version_code_fails_closed() {
        for v in ["1.4.0-beta", "1.4.0+build7", "2024.11.1", "", "x", "0.0.0", "1.2.3.4", "1.1000.0"] {
            assert!(Config::new("c", "org.example.app", "App", v).is_err(), "{v:?}");
        }
        assert!(Config::new_with_code("c", "org.example.app", "App", "1.0.0", 0).is_err());
    }

    #[test]
    fn a_bad_channel_or_package_is_refused() {
        assert!(Config::new("", "org.example.app", "App", "1.0.0").is_err());
        for p in ["", "app", "org..app", ".org.app", "org.app.", "org.1app", "org.exa mple", "org.example.app\n"] {
            assert!(Config::new("c", p, "App", "1.0.0").is_err(), "{p:?}");
        }
        assert!(Config::new("c", "org.example.app_2", "App", "1.0.0").is_ok());
    }
}
