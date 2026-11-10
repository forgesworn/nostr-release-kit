//! Test doubles for apps that embed the kit: an installer that records what it
//! was asked, and a fetcher that answers from memory. They touch neither the OS
//! nor the network.
//!
//! These doubles are always compiled (they have no effect on what an `Updater` trusts).
//! The staging methods that put an `Updater` or `Catalog` in a made-up state
//! (`Updater::demo_offer`, `demo_install_state`, `demo_sibling_state`, `demo_release`,
//! `Catalog::demo`) are not: they exist only in this crate's own tests and with the
//! `testing` cargo feature, because `demo_offer` swaps the pinned release key for a
//! throwaway one. Never enable that feature in a build you ship.

use crate::fetch::{FetchReport, PendingFetch, ReadyFetch, ReleaseFetcher};
use crate::installer::{ApkInstaller, ApkJob, ApkStatus, ANOTHER_INSTALL};
use nostr::Filter;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records every call. Never touches the OS.
#[derive(Debug)]
pub struct RecordingInstaller {
    /// This app's package: what `apk_active_package` reports for a job that names none.
    pub own_package: String,
    /// What `running_package` answers (`None` = the platform cannot say, so no check is made).
    /// Set it to the app's package, or to another one to test a mismatch.
    pub running_package: Option<String>,
    /// The certificate `own_cert_sha256` answers with.
    pub cert: Option<String>,
    /// What `apk_start` was asked.
    pub apk_started: Vec<ApkJob>,
    /// What `apk_status` answers (`None` = Idle).
    pub apk: Option<ApkStatus>,
    /// How many times the install-settings page was opened.
    pub install_settings_opened: u32,
    /// How many times a download cancel was asked for.
    pub apk_cancels: u32,
    /// The package of the current (or most recent) attempt: what `apk_active_package` answers.
    /// Set by `apk_start`, which refuses (as the Android side does) while `apk` is active for another package.
    pub apk_active: Option<String>,
    /// Installed packages and their versionCodes.
    pub installed_packages: HashMap<String, u32>,
    /// Packages `open_package` was asked to open.
    pub opened_packages: Vec<String>,
}

impl Default for RecordingInstaller {
    fn default() -> Self {
        RecordingInstaller {
            own_package: "org.example.app".to_string(),
            running_package: None,
            cert: None,
            apk_started: Vec::new(),
            apk: None,
            install_settings_opened: 0,
            apk_cancels: 0,
            apk_active: None,
            installed_packages: HashMap::new(),
            opened_packages: Vec::new(),
        }
    }
}

impl ApkInstaller for RecordingInstaller {
    fn can_install_apk(&self) -> bool {
        true
    }

    fn running_package(&mut self) -> Option<String> {
        self.running_package.clone()
    }

    fn own_cert_sha256(&mut self) -> Option<String> {
        self.cert.clone()
    }

    fn apk_start(&mut self, job: &ApkJob) -> Result<(), String> {
        // What the Android side does at the top of a start: refuse while an attempt for another
        // package is in flight, otherwise this package becomes the current attempt.
        let pkg = if job.package.is_empty() { self.own_package.as_str() } else { job.package.as_str() };
        let in_flight = self.apk.as_ref().is_some_and(ApkStatus::active);
        if in_flight && self.apk_active.as_deref() != Some(pkg) {
            return Err(ANOTHER_INSTALL.into());
        }
        self.apk_active = Some(pkg.to_string());
        self.apk_started.push(job.clone());
        Ok(())
    }

    fn apk_active_package(&mut self) -> Option<String> {
        self.apk_active.clone()
    }

    fn apk_status(&mut self) -> ApkStatus {
        self.apk.clone().unwrap_or(ApkStatus::Idle)
    }

    fn apk_open_install_settings(&mut self) {
        self.install_settings_opened += 1;
    }

    fn apk_cancel(&mut self) {
        self.apk_cancels += 1;
    }

    fn installed_version_code(&mut self, package: &str) -> Option<u32> {
        self.installed_packages.get(package).copied()
    }

    fn open_package(&mut self, package: &str) -> bool {
        self.opened_packages.push(package.to_string());
        self.installed_packages.contains_key(package)
    }
}

/// One read a [`FakeFetcher`] was asked for.
#[derive(Clone, Debug)]
pub struct FetchCall {
    pub relays: Vec<String>,
    pub filters: Vec<Filter>,
    pub timeout: Duration,
}

/// A [`ReleaseFetcher`] that answers every read with the same report. By default the
/// answer is ready at once; with `polls_before_ready` = n it takes n empty polls first
/// (a read that is still running). Clone it before boxing it to keep a handle on
/// `calls` and `reply`.
#[derive(Clone, Default)]
pub struct FakeFetcher {
    pub calls: Arc<Mutex<Vec<FetchCall>>>,
    pub reply: Arc<Mutex<FetchReport>>,
    pub polls_before_ready: usize,
}

struct DelayedFetch {
    left: usize,
    report: Option<FetchReport>,
}

impl PendingFetch for DelayedFetch {
    fn poll(&mut self) -> Option<FetchReport> {
        if self.left > 0 {
            self.left -= 1;
            return None;
        }
        self.report.take()
    }
}

impl FakeFetcher {
    pub fn new(reply: FetchReport) -> FakeFetcher {
        FakeFetcher { calls: Default::default(), reply: Arc::new(Mutex::new(reply)), polls_before_ready: 0 }
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl ReleaseFetcher for FakeFetcher {
    fn start(&mut self, relays: Vec<String>, filters: Vec<Filter>, timeout: Duration) -> Box<dyn PendingFetch> {
        self.calls.lock().unwrap().push(FetchCall { relays, filters, timeout });
        let report = self.reply.lock().unwrap().clone();
        if self.polls_before_ready == 0 {
            Box::new(ReadyFetch(Some(report)))
        } else {
            Box::new(DelayedFetch { left: self.polls_before_ready, report: Some(report) })
        }
    }
}
