//! The platform's side of an install: download, verify and hand an APK to the
//! system installer. The app implements [`ApkInstaller`] (on Android, with the
//! `android` feature, `android::AndroidInstaller` does).

/// How an APK download and install stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApkStatus {
    /// Nothing started (or the last attempt was reset).
    Idle,
    /// Bytes arriving: `total` is the size the release event announced.
    Downloading { done: u64, total: u64 },
    /// Verified; handing the file to the system installer.
    Installing,
    /// Android's own install prompt is up: the person must tap it.
    WaitingForUser,
    /// "Install unknown apps" is off for this app; the settings page was opened.
    NeedsPermission,
    /// Refused or failed, with a message for the person.
    Failed(String),
    /// The system reported success (an updated app is normally replaced before this is seen).
    Installed,
}

impl ApkStatus {
    /// A download or install is under way (poll again soon).
    pub fn active(&self) -> bool {
        matches!(self, ApkStatus::Downloading { .. } | ApkStatus::Installing | ApkStatus::WaitingForUser)
    }
}

/// What the person is told while the one installer is busy with another package's attempt.
pub const ANOTHER_INSTALL: &str = "Another install is in progress. Try again when it is done.";

/// What the person is told when the downloaded file is not the expected app from the
/// expected signer (`Updater.DIDNT_CHECK_OUT` in the Java source).
pub const DIDNT_CHECK_OUT: &str = "This download didn't check out, so it wasn't installed.";

/// The installer's current attempt belongs to a package other than `mine`: its status,
/// progress and Android prompt are not `mine`'s to show, and polling `apk_status` could even
/// launch that other attempt's parked prompt.
pub fn held_by_another(installer: &mut dyn ApkInstaller, mine: &str) -> bool {
    installer.apk_active_package().is_some_and(|p| p != mine)
}

/// One APK to download, verify and install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApkJob {
    /// Canonical Blossom addresses, tried in order.
    pub urls: Vec<String>,
    /// SHA-256 of the file (lower-case hex) and its exact size, from the signed release event.
    pub sha256: String,
    pub size: u64,
    /// The package the file must be. Empty = this app (an update).
    pub package: String,
    /// The SHA-256 (lower-case hex) of the signing certificate the file must carry:
    /// the one pinned in the catalog (or this app's own, for an update).
    pub cert: String,
    /// The certificate the signed release event names. The platform checks the file against
    /// this one as well, independently of `cert` (a catalog app needs both equal to the file's).
    pub release_cert: String,
}

/// OS services for installing APKs. Every method but `running_package` has a "cannot"
/// default, so an app on a platform with no installer implements only that one
/// (returning `None`).
pub trait ApkInstaller {
    /// This platform can install an APK itself (Android), so the launch-time
    /// update check is worth making. A manual check works anywhere.
    fn can_install_apk(&self) -> bool {
        false
    }

    /// The package name the platform says this app is running as (Android:
    /// `Context.getPackageName()`), `None` if it cannot say. The updater compares it with
    /// `Config.own_package` at the first tick and turns updates off, with a visible error,
    /// when they differ: a wrong `own_package` would otherwise read another app's versionCode.
    ///
    /// Required, with no default, so that an app forwarding the trait method by method
    /// cannot leave the check out by accident. A platform that cannot say returns `None`
    /// (the check is then skipped).
    fn running_package(&mut self) -> Option<String>;

    /// SHA-256 (lowercase hex) of the certificate this app is signed with, for
    /// the update's `cert` check. Android: `PackageManager` signing info.
    fn own_cert_sha256(&mut self) -> Option<String> {
        None
    }

    /// Download the APK (the first URL that works), check it is exactly `size`
    /// bytes with SHA-256 `sha256`, check its package and signing certificate
    /// against the job, and hand it to the system installer. Returns at once;
    /// follow it with [`ApkInstaller::apk_status`]. `Err` when it could not start, in
    /// particular [`ANOTHER_INSTALL`] when an attempt for another package is in flight
    /// (the platform has ONE installer; nothing was changed).
    fn apk_start(&mut self, _job: &ApkJob) -> Result<(), String> {
        Err("Installs run on Android only.".into())
    }

    /// Where the download / install stands now.
    fn apk_status(&mut self) -> ApkStatus {
        ApkStatus::Idle
    }

    /// Stop the current install attempt (the status then turns to Failed): a running
    /// download, the copy into the installer, or an attempt parked at Android's prompt.
    /// It stops whatever attempt is current, whoever started it: check
    /// [`ApkInstaller::apk_active_package`] first.
    fn apk_cancel(&mut self) {}

    /// The package the current (or most recent) install attempt is for (this app's own,
    /// or a catalog app's); `None` before any. The platform runs ONE installer, so the
    /// follower believes [`ApkInstaller::apk_status`] only while this is its own package.
    fn apk_active_package(&mut self) -> Option<String> {
        None
    }

    /// Open the "Install unknown apps" page for this app (Android).
    fn apk_open_install_settings(&mut self) {}

    /// The versionCode of an installed package, `None` if it is not installed
    /// (or cannot be asked). Android: `PackageManager.getPackageInfo`; the
    /// manifest lists each catalog package in `<queries>`.
    fn installed_version_code(&mut self, _package: &str) -> Option<u32> {
        None
    }

    /// Open an installed package's launcher activity. False if it cannot be opened.
    fn open_package(&mut self, _package: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_running_attempt_is_active() {
        assert!(ApkStatus::Downloading { done: 0, total: 1 }.active());
        assert!(ApkStatus::Installing.active() && ApkStatus::WaitingForUser.active());
        for s in [ApkStatus::Idle, ApkStatus::NeedsPermission, ApkStatus::Installed, ApkStatus::Failed("x".into())] {
            assert!(!s.active(), "{s:?}");
        }
    }

    #[test]
    fn the_default_installer_cannot_install() {
        struct None_;
        impl ApkInstaller for None_ {
            fn running_package(&mut self) -> Option<String> {
                None
            }
        }
        let mut i = None_;
        assert!(!i.can_install_apk());
        assert!(i.apk_start(&ApkJob { urls: vec![], sha256: String::new(), size: 0, package: String::new(), cert: String::new(), release_cert: String::new() }).is_err());
        assert_eq!(i.apk_status(), ApkStatus::Idle);
        assert!(!held_by_another(&mut i, "org.example.app"));
        assert!(i.installed_version_code("org.example.app").is_none() && !i.open_package("org.example.app"));
    }
}
