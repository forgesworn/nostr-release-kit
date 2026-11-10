//! The self-update state machine.
//!
//! A release is a signed kind-30063 event from one pinned release key
//! ([`Config::release_pubkey`]), found on the release relays. The event names the
//! APK by SHA-256 and size, says which certificate signed it, and lists where
//! to download it (canonical Blossom URLs only). The [`Updater`]:
//!
//! 1. reads the events from the user's relays (in their order) and the release
//!    relays, all at once, through the app's [`ReleaseFetcher`], at launch if the
//!    last check is older than [`Config::check_interval`], or when the person asks
//!    (never while no key is pinned: no key, no check, no network);
//! 2. keeps only events with a valid id and signature from the pinned key and
//!    well-formed tags ([`parse_release`]), picks the highest `version_code`
//!    ([`pick_latest`]) and offers it only if that is above the installed
//!    versionCode and the `cert` is this app's own ([`judge`]);
//! 3. on a tap, has the [`ApkInstaller`] download it (streaming SHA-256, abort past
//!    `size` + 1 MiB, refuse on any mismatch) and hand it to Android's installer.
//!    The install is always a tap in Android's own prompt.
//!
//! The real trust chain: the pinned key signs `x`; the bytes must hash to `x`;
//! Android itself refuses an update signed with a different certificate.
//! Nothing here installs silently.
//!
//! The same download, verify and install path also installs ANOTHER package from
//! a [`crate::Catalog`] ([`Updater::install_sibling`]): the Java side then checks
//! the downloaded file's package and signing certificate against the catalog
//! before it commits the installer session.

use crate::config::{Config, NOT_SET_UP};
use crate::fetch::{release_relays, FetchReport, PendingFetch, ReleaseFetcher};
use crate::installer::{held_by_another, ApkInstaller, ApkJob, ApkStatus, ANOTHER_INSTALL};
#[cfg(any(test, feature = "testing"))]
use crate::release::RELEASE_KIND;
use crate::release::{is_package_name, judge, parse_release, pick_latest, release_filter, Release, Verdict};
#[cfg(any(test, feature = "testing"))]
use nostr::Kind;
use nostr::{Event, PublicKey};
use serde::{Deserialize, Serialize};

/// What the person is told when a catalog entry names no package, or this app's own.
const NOT_A_SIBLING: &str = "That app can't be installed from here.";

/// How often the installer's download status is read while an install is under way.
const STATUS_POLL_SECS: f32 = 0.25;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    /// Unix seconds of the last check that heard from a relay.
    last_check: u64,
    /// The best verified release event of that check. Kept as the signed
    /// event and verified again on load, so a file edit buys nothing.
    event: Option<Event>,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// How bad a line of update status is (the screens colour it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateTone {
    Dim,
    Accent,
    Gold,
    Danger,
}

/// Everything a screen shows about updates.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateView {
    /// "v0.1.0".
    pub installed: String,
    /// One line: where things stand.
    pub status: String,
    pub tone: UpdateTone,
    /// A release is on offer (or its download is running): "Update to v0.2.0".
    pub offer: Option<OfferView>,
    /// A relay check is running.
    pub checking: bool,
    /// Download progress 0..=1 while bytes arrive.
    pub progress: Option<f32>,
    /// The Check button is live.
    pub can_check: bool,
    /// The Update button is live (offered, and no download under way).
    pub can_install: bool,
    /// Bytes are arriving: the button reads "Cancel download" instead.
    pub downloading: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferView {
    pub version: String,
    /// "27.7 MB".
    pub size: String,
    /// The release notes, one paragraph, trimmed.
    pub notes: String,
}

/// What the download / install in progress (or the last one) is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// An update of this app.
    SelfApp,
    /// A sibling app from the catalog, by package name.
    Sibling(String),
}

pub struct Updater {
    cfg: Config,
    fetcher: Box<dyn ReleaseFetcher>,
    stored: Stored,
    /// The pinned release key; `None` while the app has none: nothing is checked then.
    pinned: Option<PublicKey>,
    /// The installed versionCode releases are compared with: the platform's own report for
    /// `own_package` when it gives one (settled at the first tick), else the config's. Never
    /// zero while `configured()`: an updater without one offers nothing.
    installed: u32,
    /// `own_package` is not the package the app is running as: updates are off, and this says why.
    setup_error: Option<String>,
    /// Allowed to touch the network (off for fake networks and screenshots).
    pub enabled: bool,
    started: bool,
    own_cert: Option<String>,
    verdict: Verdict,
    task: Option<Box<dyn PendingFetch>>,
    /// The last finished check saw nothing valid.
    no_news: bool,
    /// ...and no relay answered at all (as opposed to answering with nothing).
    unreached: bool,
    install: ApkStatus,
    target: Target,
    /// Screenshots: the staged install state is not polled away.
    frozen: bool,
    poll_left: f32,
    /// The user's own relays, asked on top of the release relays.
    user_relays: Vec<String>,
}

impl Updater {
    /// An updater for the app `config` describes. Loads the saved state from
    /// `config.state_file` when there is one (a missing or corrupt file is a fresh
    /// start); with none, nothing is read or written.
    ///
    /// The installed versionCode is `config.version_code`; at the first `tick` the platform's
    /// own report for `config.own_package` (`ApkInstaller::installed_version_code`) replaces it
    /// when there is one: the real installed value wins, the config's is the fallback. If no
    /// versionCode is known (a `Config` built by hand with zero) the updater is not
    /// `configured()`: it checks nothing and offers nothing (fail closed).
    pub fn new(config: Config, fetcher: Box<dyn ReleaseFetcher>) -> Updater {
        if config.version_code == 0 {
            log::error!("release-kit: Config.version_code is 0: updates are off (use Config::new)");
        }
        let stored = config
            .state_file
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Stored>(&b).ok())
            .unwrap_or_default();
        Updater {
            pinned: config.release_pubkey,
            installed: config.version_code,
            setup_error: None,
            cfg: config,
            fetcher,
            stored,
            enabled: false,
            started: false,
            own_cert: None,
            verdict: Verdict::Unknown,
            task: None,
            no_news: false,
            unreached: false,
            install: ApkStatus::Idle,
            target: Target::SelfApp,
            frozen: false,
            poll_left: 0.0,
            user_relays: Vec::new(),
        }
    }

    /// The config this updater was made with.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Is a release key pinned and the installed versionCode known (so that checks can run)?
    pub fn configured(&self) -> bool {
        self.pinned.is_some() && self.installed > 0
    }

    /// Why updates are off although a key is pinned: `Config.own_package` is not the package
    /// the app is running as (found at the first `tick`, when the platform can say). `None` otherwise.
    pub fn setup_error(&self) -> Option<&str> {
        self.setup_error.as_deref()
    }

    /// The installed versionCode releases are compared with (see [`Updater::new`]).
    pub fn installed_code(&self) -> u32 {
        self.installed
    }

    /// The user's relay list changed: later checks ask these too.
    pub fn set_user_relays(&mut self, relays: Vec<String>) {
        self.user_relays = relays;
    }

    /// The relays the next check asks.
    pub fn check_relays(&self) -> Vec<String> {
        release_relays(&self.user_relays, &self.cfg.relays)
    }

    /// Tests: trust another key. Only with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn trust(&mut self, key: PublicKey) {
        self.pinned = Some(key);
    }

    /// Tests: the installed versionCode. Only with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn set_installed(&mut self, code: u32) {
        self.installed = code;
    }

    /// Screenshots and tests: a newer release is out, announced by a throwaway key that is
    /// trusted from now on, replacing the pinned one. Only with the `testing` feature: a
    /// production `Updater` can never replace its pinned key. It also refuses a file-backed
    /// `Updater`: a throwaway-signed event must never reach the state file.
    #[cfg(any(test, feature = "testing"))]
    pub fn demo_offer(&mut self, version: &str, notes: &str) {
        if self.cfg.state_file.is_some() {
            log::warn!("demo_offer ignored on a file-backed Updater");
            return;
        }
        let keys = nostr::Keys::generate();
        self.pinned = Some(keys.public_key());
        let sha = "d".repeat(64);
        let tag = |parts: &[&str]| nostr::Tag::parse(parts.iter().copied()).expect("valid tag");
        let tags = vec![
            tag(&["d", &self.cfg.channel]),
            tag(&["version", version]),
            tag(&["version_code", &(self.installed.saturating_add(1000)).to_string()]),
            tag(&["x", &sha]),
            tag(&["size", "27700000"]),
            tag(&["cert", &"e".repeat(64)]),
            tag(&["url", &format!("https://nostr.download/{sha}.apk")]),
        ];
        let ev = nostr::EventBuilder::new(Kind::Custom(RELEASE_KIND), notes).tags(tags).sign_with_keys(&keys).expect("signs");
        self.apply_events(&[ev], unix_now());
    }

    /// Screenshots: pretend the running download is for `package` and in this state.
    /// Only with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn demo_sibling_state(&mut self, package: &str, st: ApkStatus) {
        if self.cfg.state_file.is_none() {
            self.install = st;
            self.target = Target::Sibling(package.to_string());
            self.frozen = true;
        }
    }

    /// Screenshots: pretend the install of the offer is in this state.
    /// Only with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn demo_install_state(&mut self, st: ApkStatus) {
        if self.cfg.state_file.is_none() {
            self.install = st;
            self.target = Target::SelfApp;
            self.frozen = true;
        }
    }

    fn save(&self) {
        let Some(path) = &self.cfg.state_file else { return };
        let r = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|_| serde_json::to_vec(&self.stored).map_err(std::io::Error::other))
            .and_then(|b| std::fs::write(path, b));
        if let Err(e) = r {
            log::warn!("could not save update state: {e}");
        }
    }

    /// Is the launch-time check due at `now`?
    pub fn due(&self, now: u64) -> bool {
        // A last_check in the future (the clock was wrong when it was taken) counts as due.
        self.stored.last_check == 0 || now < self.stored.last_check || now - self.stored.last_check >= self.cfg.check_interval.as_secs()
    }

    fn rejudge(&mut self) {
        if !self.configured() {
            self.verdict = Verdict::Unknown;
            return;
        }
        let latest = self.pinned.as_ref().and_then(|k| self.stored.event.as_ref().and_then(|e| parse_release(e, k, &self.cfg.channel)));
        self.verdict = judge(latest, self.installed, self.own_cert.as_deref());
    }

    /// Frame hook: the first call settles the saved verdict and, on a platform
    /// that can install and when the last check is old enough, starts the launch
    /// check; later calls collect a finished check and follow an install.
    pub fn tick(&mut self, dt: f32, installer: &mut dyn ApkInstaller) {
        if !self.started {
            self.started = true;
            self.own_cert = installer.own_cert_sha256();
            // `own_package` must be the package this app is running as. If the platform says
            // otherwise, `installed_version_code(own_package)` would be ANOTHER app's versionCode
            // (or none): refuse to check, offer or install, and say why. Never use it.
            let running = installer.running_package();
            if let Some(running) = running.filter(|r| *r != self.cfg.own_package) {
                log::error!("release-kit: Config.own_package {:?} is not this app's package {:?}: updates are off", self.cfg.own_package, running);
                self.setup_error = Some(format!("Updates are off: this build is set up for {} but runs as {}", self.cfg.own_package, running));
                self.installed = 0;
            } else {
                // The platform's report of what is really installed beats the config's derived code.
                match installer.installed_version_code(&self.cfg.own_package) {
                    Some(code) if code > 0 => self.installed = code,
                    None if installer.can_install_apk() => {
                        log::error!("release-kit: the platform does not know own_package {:?}: check Config.own_package", self.cfg.own_package)
                    }
                    _ => {}
                }
            }
            self.rejudge();
            if self.enabled && self.configured() && installer.can_install_apk() && self.due(unix_now()) {
                self.begin_check();
            }
        }
        if let Some(report) = self.task.as_mut().and_then(|t| t.poll()) {
            self.task = None;
            self.apply_report(&report, unix_now());
        }
        if self.install.active() && !self.frozen {
            self.poll_left -= dt;
            if self.poll_left <= 0.0 {
                self.poll_left = STATUS_POLL_SECS;
                if held_by_another(installer, &self.target_package()) {
                    // The one installer is on another package's attempt: its progress and
                    // prompt are not this one's to show (and polling could launch its prompt).
                    self.install = ApkStatus::Failed(ANOTHER_INSTALL.into());
                } else {
                    let st = installer.apk_status();
                    self.follow(st, installer);
                }
            }
        }
    }

    /// Check now ("Check for updates"): unthrottled. Does nothing while no key is pinned.
    pub fn check_now(&mut self) {
        self.begin_check();
    }

    fn begin_check(&mut self) {
        let Some(pinned) = self.pinned.filter(|_| self.installed > 0) else { return };
        if self.task.is_some() {
            return;
        }
        let urls = self.check_relays();
        self.task = Some(self.fetcher.start(urls, vec![release_filter(&pinned, &self.cfg.channel)], self.cfg.fetch_timeout));
        self.no_news = false;
        self.unreached = false;
    }

    /// Take a finished check: the events, and whether any relay answered at
    /// all, so "no update published yet" and "couldn't reach the relays" stay
    /// different.
    pub fn apply_report(&mut self, report: &FetchReport, now: u64) {
        self.apply_events(&report.events, now);
        self.unreached = self.no_news && !report.reached();
        log::info!("update check: {} of {} relays answered, {} event(s)", report.answered, report.total, report.events.len());
    }

    /// Take the events of a finished check: pick the newest verified release,
    /// remember it and when we looked.
    pub fn apply_events(&mut self, events: &[Event], now: u64) {
        let Some(pinned) = self.pinned.filter(|_| self.installed > 0) else { return };
        match pick_latest(events, &pinned, &self.cfg.channel) {
            Some(best) => {
                self.stored.last_check = now;
                // Never step back: a relay still serving an old retained event must not
                // displace a newer one we already know (the saved one is verified again).
                let known = self.stored.event.as_ref().and_then(|e| parse_release(e, &pinned, &self.cfg.channel));
                if known.is_none_or(|k| (best.version_code, best.created_at) >= (k.version_code, k.created_at)) {
                    self.stored.event = Some(best.event);
                }
                self.no_news = false;
                self.unreached = false;
                self.save();
            }
            None => {
                // Heard nothing valid: keep what we had; try again next launch.
                self.no_news = true;
            }
        }
        self.rejudge();
    }

    /// The package the running (or last) attempt is for.
    fn target_package(&self) -> String {
        match &self.target {
            Target::SelfApp => self.cfg.own_package.clone(),
            Target::Sibling(p) => p.clone(),
        }
    }

    /// Start the download and install of the offered release. `Err(notice)`
    /// when a download for ANOTHER package is already running: nothing was
    /// started, and the caller says so.
    pub fn install(&mut self, installer: &mut dyn ApkInstaller) -> Result<(), String> {
        let Verdict::Offer(r) = &self.verdict else { return Ok(()) };
        if self.install.active() {
            return if self.target == Target::SelfApp { Ok(()) } else { Err(ANOTHER_INSTALL.into()) };
        }
        // An empty package means "this app": the Android side installs over itself.
        let job = ApkJob { urls: r.urls.clone(), sha256: r.sha256.clone(), size: r.size, package: String::new(), cert: r.cert.clone(), release_cert: r.cert.clone() };
        let size = r.size;
        self.target = Target::SelfApp;
        match installer.apk_start(&job) {
            Ok(()) => {
                self.install = ApkStatus::Downloading { done: 0, total: size };
                self.poll_left = 0.0;
            }
            Err(e) => self.install = ApkStatus::Failed(e),
        }
        Ok(())
    }

    /// Download and install ANOTHER package from the catalog.
    /// `release` was parsed with the catalog entry's own key and channel;
    /// `cert` is the entry's pinned signing certificate. The Android side checks
    /// the downloaded file's package and certificate against both before the
    /// installer sees it. `Err(notice)` while a download for another package
    /// runs: nothing was started, and the caller says so. The same package tapped
    /// again while it downloads is a no-op.
    pub fn install_sibling(&mut self, installer: &mut dyn ApkInstaller, package: &str, release: &Release, cert: &str) -> Result<(), String> {
        // An empty package means "this app" to the installer, and this app's own package is not a
        // sibling: either would run a sibling-key release as an update of THIS app. Nothing starts.
        if !is_package_name(package) || package == self.cfg.own_package {
            return Err(NOT_A_SIBLING.into());
        }
        if self.install.active() {
            return if self.target == Target::Sibling(package.to_string()) { Ok(()) } else { Err(ANOTHER_INSTALL.into()) };
        }
        self.target = Target::Sibling(package.to_string());
        if release.cert != cert {
            self.install = ApkStatus::Failed("That release is signed with a different key than this app's, so it was not installed.".into());
            return Ok(());
        }
        let job = ApkJob { urls: release.urls.clone(), sha256: release.sha256.clone(), size: release.size, package: package.to_string(), cert: cert.to_string(), release_cert: release.cert.clone() };
        match installer.apk_start(&job) {
            Ok(()) => {
                self.install = ApkStatus::Downloading { done: 0, total: release.size };
                self.poll_left = 0.0;
            }
            Err(e) => self.install = ApkStatus::Failed(e),
        }
        Ok(())
    }

    /// "Cancel download": stop the running download (the installer then reports
    /// a failure, which the screen shows; Update works again).
    /// Only this follower's own attempt is cancelled: the installer's one attempt
    /// may be on another package's (the next poll then says so).
    pub fn cancel_install(&mut self, installer: &mut dyn ApkInstaller) {
        if matches!(self.install, ApkStatus::Downloading { .. }) && !held_by_another(installer, &self.target_package()) {
            installer.apk_cancel();
            self.poll_left = 0.0;
        }
    }

    fn follow(&mut self, st: ApkStatus, installer: &mut dyn ApkInstaller) {
        if st == ApkStatus::NeedsPermission && self.install != ApkStatus::NeedsPermission {
            installer.apk_open_install_settings();
        }
        // The installer forgot (a restart of the Java side): don't spin on it.
        self.install = if st == ApkStatus::Idle { ApkStatus::Failed("The install stopped. Tap to try again.".into()) } else { st };
    }

    /// The verdict on the newest known release.
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// Where the running (or last) download / install stands, whatever it is for.
    pub fn install_status(&self) -> &ApkStatus {
        &self.install
    }

    /// What the running (or last) download / install is for.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// The install state of a sibling's download, `None` if the last job was for something else.
    pub fn sibling_status(&self, package: &str) -> Option<&ApkStatus> {
        matches!(&self.target, Target::Sibling(p) if p == package).then_some(&self.install)
    }

    /// A download or install (of anything) is under way.
    pub fn busy(&self) -> bool {
        self.install.active()
    }

    /// A relay check is running.
    pub fn checking(&self) -> bool {
        self.task.is_some()
    }

    /// The install state as it concerns an update of this app.
    fn self_install(&self) -> &ApkStatus {
        const IDLE: ApkStatus = ApkStatus::Idle;
        if self.target == Target::SelfApp {
            &self.install
        } else {
            &IDLE
        }
    }

    /// An update is on offer, or its download is being followed: the home screen shows a pill.
    pub fn pill(&self) -> Option<String> {
        let Verdict::Offer(r) = &self.verdict else { return None };
        Some(match self.self_install() {
            ApkStatus::Idle | ApkStatus::Installed => format!("Update to v{}", r.version),
            ApkStatus::Downloading { done, total } => format!("Downloading {}%", percent(*done, *total)),
            ApkStatus::Installing => "Installing…".into(),
            ApkStatus::WaitingForUser => "Confirm in Android's prompt".into(),
            ApkStatus::NeedsPermission => "Allow installs, then tap".into(),
            ApkStatus::Failed(_) => "Update failed. Tap to retry".into(),
        })
    }

    /// The pill can be tapped (not mid-download).
    pub fn pill_live(&self) -> bool {
        matches!(self.verdict, Verdict::Offer(_)) && !self.install.active()
    }

    pub fn view(&self, now: u64) -> UpdateView {
        let installed = self.cfg.version_label.clone().unwrap_or_else(|| format!("v{}", self.cfg.version));
        if let Some(e) = &self.setup_error {
            return UpdateView { installed, status: e.clone(), tone: UpdateTone::Danger, offer: None, checking: false, progress: None, can_check: false, can_install: false, downloading: false };
        }
        if !self.configured() {
            return UpdateView { installed, status: NOT_SET_UP.to_string(), tone: UpdateTone::Dim, offer: None, checking: false, progress: None, can_check: false, can_install: false, downloading: false };
        }
        let checking = self.task.is_some();
        let mut offer = None;
        let (mut status, mut tone) = match &self.verdict {
            Verdict::Offer(r) => {
                offer = Some(OfferView { version: r.version.clone(), size: size_text(r.size), notes: notes_text(&r.notes) });
                (format!("Version {} is available ({})", r.version, size_text(r.size)), UpdateTone::Accent)
            }
            Verdict::DifferentKey(r) => (format!("Version {} is out, but it is signed with a different key. Reinstall from the official page.", r.version), UpdateTone::Gold),
            Verdict::UpToDate => (format!("You're up to date{}", ago_suffix(self.stored.last_check, now)), UpdateTone::Dim),
            Verdict::Unknown if self.no_news && self.unreached => ("Couldn't reach the relays".to_string(), UpdateTone::Danger),
            Verdict::Unknown if self.no_news => ("No update published yet".to_string(), UpdateTone::Dim),
            Verdict::Unknown => ("Not checked yet".to_string(), UpdateTone::Dim),
        };
        if checking {
            (status, tone) = ("Checking…".into(), UpdateTone::Dim);
        }
        let mut progress = None;
        if offer.is_some() {
            match self.self_install() {
                ApkStatus::Downloading { done, total } => {
                    status = format!("Downloading… {}%", percent(*done, *total));
                    tone = UpdateTone::Accent;
                    progress = Some((*done as f32 / (*total).max(1) as f32).clamp(0.0, 1.0));
                }
                ApkStatus::Installing => (status, tone) = ("Preparing the install…".into(), UpdateTone::Accent),
                ApkStatus::WaitingForUser => (status, tone) = ("Confirm the update in Android's prompt".into(), UpdateTone::Accent),
                ApkStatus::NeedsPermission => {
                    (status, tone) = (format!("Allow installs from {} in the settings page that opened, then tap Update again", self.cfg.app_name), UpdateTone::Gold)
                }
                ApkStatus::Failed(m) => (status, tone) = (m.clone(), UpdateTone::Danger),
                ApkStatus::Idle | ApkStatus::Installed => {}
            }
        }
        UpdateView {
            installed,
            status,
            tone,
            can_check: !checking && !self.install.active(),
            can_install: offer.is_some() && !self.install.active() && !checking,
            checking,
            progress,
            offer,
            downloading: matches!(self.self_install(), ApkStatus::Downloading { .. }),
        }
    }
}

fn percent(done: u64, total: u64) -> u64 {
    done.saturating_mul(100).checked_div(total).map_or(0, |p| p.min(100))
}

fn size_text(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

/// Release notes as one short paragraph.
fn notes_text(notes: &str) -> String {
    let one: String = notes.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > 160 {
        let cut: String = one.chars().take(159).collect();
        format!("{cut}…")
    } else {
        one
    }
}

fn ago_suffix(last: u64, now: u64) -> String {
    if last == 0 {
        return String::new();
    }
    let s = now.saturating_sub(last);
    let t = match s {
        0..=89 => "just now".to_string(),
        90..=5399 => format!("{} min ago", (s + 30) / 60),
        5400..=129_599 => format!("{} h ago", (s + 1800) / 3600),
        _ => format!("{} d ago", (s + 43_200) / 86_400),
    };
    format!(", checked {t}")
}

/// Screenshots and tests: a release as the parser would return it, announced by a
/// throwaway key that nothing else trusts. Only with the `testing` feature.
#[cfg(any(test, feature = "testing"))]
pub fn demo_release(channel: &str, version: &str, size: u64, cert: &str) -> Release {
    let keys = nostr::Keys::generate();
    let sha = "d".repeat(64);
    let tag = |parts: &[&str]| nostr::Tag::parse(parts.iter().copied()).expect("valid tag");
    let tags = vec![
        tag(&["d", channel]),
        tag(&["version", version]),
        tag(&["version_code", "2000"]),
        tag(&["x", &sha]),
        tag(&["size", &size.to_string()]),
        tag(&["cert", cert]),
        tag(&["url", &format!("https://nostr.download/{sha}.apk")]),
    ];
    let ev = nostr::EventBuilder::new(Kind::Custom(RELEASE_KIND), "").tags(tags).sign_with_keys(&keys).expect("signs");
    parse_release(&ev, &keys.public_key(), channel).expect("a well-formed demo release")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::FetchReport;
    use crate::release::fixtures::*;
    use crate::testing::{FakeFetcher, RecordingInstaller};
    use nostr::Keys;

    const OWN: &str = "org.example.app";

    fn cfg() -> Config {
        Config::new(CHANNEL, OWN, "Example App", "0.1.0").unwrap()
    }

    fn updater_for(keys: &Keys, installed: u32) -> Updater {
        let mut u = Updater::new(cfg(), Box::new(FakeFetcher::default()));
        u.trust(keys.public_key());
        u.installed = installed;
        u
    }

    fn installer() -> RecordingInstaller {
        RecordingInstaller { cert: Some(CERT.into()), ..Default::default() }
    }

    impl Updater {
        fn verdict_code(&self) -> Option<u32> {
            match &self.verdict {
                Verdict::Offer(r) | Verdict::DifferentKey(r) => Some(r.version_code),
                _ => None,
            }
        }
    }

    #[test]
    fn the_installed_version_comes_from_the_config() {
        let u = Updater::new(cfg(), Box::new(FakeFetcher::default()));
        assert_eq!(u.installed_code(), 1000);
        assert_eq!(u.view(0).installed, "v0.1.0");
        let mut c = cfg();
        c.version_label = Some("v0.1.0 build 7".into());
        assert_eq!(Updater::new(c, Box::new(FakeFetcher::default())).view(0).installed, "v0.1.0 build 7");
    }

    #[test]
    fn the_platforms_installed_versioncode_wins_over_the_configs() {
        let keys = Keys::generate();
        // The config says 0.1.0 (1000), the platform says 3000: a release 2000 is old news.
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        p.installed_packages.insert(OWN.into(), 3000);
        u.tick(0.0, &mut p);
        assert_eq!(u.installed_code(), 3000);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5);
        assert!(u.pill().is_none() && matches!(u.verdict(), Verdict::UpToDate));
        // The platform cannot say: the config's derived code is the fallback.
        let mut u = updater_for(&keys, 1000);
        u.tick(0.0, &mut installer());
        assert_eq!(u.installed_code(), 1000);
        // An app whose versionCode is not derived from its version gives it.
        let c = Config::new_with_code(CHANNEL, OWN, "Example App", "1.4.0-beta", 77).unwrap();
        assert_eq!(Updater::new(c, Box::new(FakeFetcher::default())).installed_code(), 77);
    }

    #[test]
    fn an_own_package_that_is_not_the_running_apps_turns_updates_off() {
        let keys = Keys::generate();
        let fetcher = FakeFetcher::new(FetchReport { events: vec![sign(&keys, good_tags(2000))], answered: 3, total: 3 });
        let mut u = Updater::new(cfg(), Box::new(fetcher.clone()));
        u.trust(keys.public_key());
        u.enabled = true;
        // Another app owns `OWN` on this phone, with a versionCode of 9999: it must not be used.
        let mut p = installer();
        p.running_package = Some("org.example.other".into());
        p.installed_packages.insert(OWN.into(), 9999);
        u.tick(0.0, &mut p);
        u.check_now();
        assert!(!u.configured() && !u.checking() && fetcher.call_count() == 0, "no check on a mismatch");
        assert_eq!(u.installed_code(), 0, "the other app's versionCode is never adopted");
        u.apply_events(&[sign(&keys, good_tags(2000))], 5);
        assert!(u.pill().is_none() && matches!(u.verdict(), Verdict::Unknown));
        assert!(u.install(&mut p).is_ok() && p.apk_started.is_empty(), "nothing installs");
        let v = u.view(5);
        assert!(!v.can_check && !v.can_install && v.tone == UpdateTone::Danger, "{v:?}");
        assert!(v.status.contains(OWN) && v.status.contains("org.example.other"), "{}", v.status);
        assert!(u.setup_error().is_some());
        // The matching package, or a platform that cannot say, leaves updates on.
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        p.running_package = Some(OWN.into());
        u.tick(0.0, &mut p);
        assert!(u.configured() && u.setup_error().is_none());
        let mut u = updater_for(&keys, 1000);
        u.tick(0.0, &mut installer());
        assert!(u.configured() && u.setup_error().is_none());
    }

    #[test]
    fn without_a_known_versioncode_nothing_is_checked_or_offered() {
        let keys = Keys::generate();
        // A config built by hand with no versionCode (Config::new refuses to make one): fail closed.
        let mut c = cfg();
        c.version_code = 0;
        let fetcher = FakeFetcher::new(FetchReport { events: vec![sign(&keys, good_tags(2000))], answered: 3, total: 3 });
        let mut u = Updater::new(c, Box::new(fetcher.clone()));
        u.trust(keys.public_key());
        u.enabled = true;
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.check_now();
        assert!(!u.configured() && !u.checking() && fetcher.call_count() == 0, "no versionCode, no network");
        u.apply_events(&[sign(&keys, good_tags(2000))], 5);
        assert!(u.pill().is_none() && matches!(u.verdict(), Verdict::Unknown), "never 'offer everything'");
        assert_eq!(u.view(5).status, NOT_SET_UP);
        // And a platform report of 0 does not make one.
        let mut c = cfg();
        c.version_code = 0;
        let mut z = Updater::new(c, Box::new(FakeFetcher::default()));
        z.trust(keys.public_key());
        p.installed_packages.insert(OWN.into(), 0);
        z.tick(0.0, &mut p);
        assert_eq!(z.installed_code(), 0);
        assert!(!z.configured());
    }

    #[test]
    fn a_pinned_key_must_be_a_real_key() {
        assert!(cfg().with_release_pubkey_hex(&Keys::generate().public_key().to_hex()).is_ok());
        assert!(cfg().with_release_pubkey_hex("nope").is_err());
        assert!(cfg().release_pubkey.is_none(), "no key is pinned until the app pins one");
    }

    #[test]
    fn an_offer_installs_through_the_installer_and_follows_it() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        assert!(u.pill().is_none());
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        assert_eq!(u.pill().as_deref(), Some("Update to v0.2.0"));
        let v = u.view(5_000_100);
        assert!(v.can_install && v.can_check);
        assert_eq!(v.offer.as_ref().unwrap().size, "27.7 MB");

        u.install(&mut p).unwrap();
        // A self-update names no package (the Android side means "this app") and carries the announced certificate.
        assert_eq!(p.apk_started, vec![ApkJob { urls: vec![format!("https://nostr.download/{SHA}.apk")], sha256: SHA.to_string(), size: 27_700_000, package: String::new(), cert: CERT.to_string(), release_cert: CERT.to_string() }]);
        assert_eq!(u.pill().as_deref(), Some("Downloading 0%"));
        // A second tap while it runs does nothing.
        u.install(&mut p).unwrap();
        assert_eq!(p.apk_started.len(), 1);

        p.apk = Some(ApkStatus::Downloading { done: 13_850_000, total: 27_700_000 });
        u.tick(0.3, &mut p);
        let v = u.view(5_000_200);
        assert_eq!(v.progress, Some(0.5));
        assert!(v.status.contains("50%"), "{}", v.status);
        assert!(!v.can_install && !v.can_check);

        p.apk = Some(ApkStatus::WaitingForUser);
        u.tick(0.3, &mut p);
        assert!(u.view(5_000_300).status.contains("prompt"));
    }

    #[test]
    fn a_start_while_the_installer_is_on_another_package_is_refused_visibly() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);

        // The installer is busy with a sibling while this follower is idle (e.g. after a transient failure).
        p.apk = Some(ApkStatus::Downloading { done: 1, total: 2 });
        p.apk_active = Some("org.example.sibling".into());
        u.install(&mut p).unwrap();
        assert!(p.apk_started.is_empty(), "nothing was started");
        assert_eq!(*u.install_status(), ApkStatus::Failed(ANOTHER_INSTALL.into()));
        assert_eq!(u.view(5_000_100).status, ANOTHER_INSTALL);
        assert!(u.view(5_000_100).can_install, "and Update works again");

        // The other direction: the installer is on our own update, a sibling is asked for.
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        p.apk = Some(ApkStatus::WaitingForUser);
        p.apk_active = Some(OWN.into());
        let rel = parse_release(&sign(&keys, good_tags(2000)), &keys.public_key(), CHANNEL).unwrap();
        u.install_sibling(&mut p, "org.example.sibling", &rel, CERT).unwrap();
        assert!(p.apk_started.is_empty());
        assert_eq!(u.sibling_status("org.example.sibling"), Some(&ApkStatus::Failed(ANOTHER_INSTALL.into())));
    }

    #[test]
    fn a_start_while_this_follower_runs_another_package_is_refused_and_changes_nothing() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.install(&mut p).unwrap();
        assert_eq!(u.target(), &Target::SelfApp);
        let rel = parse_release(&sign(&keys, good_tags(2000)), &keys.public_key(), CHANNEL).unwrap();
        assert_eq!(u.install_sibling(&mut p, "org.example.sibling", &rel, CERT), Err(ANOTHER_INSTALL.to_string()));
        assert_eq!(p.apk_started.len(), 1);
        assert_eq!(u.target(), &Target::SelfApp, "still following our own");
        assert!(matches!(u.install_status(), ApkStatus::Downloading { .. }));
        // The same package tapped again is a quiet no-op, not a refusal.
        assert_eq!(u.install(&mut p), Ok(()));
        assert_eq!(p.apk_started.len(), 1);
    }

    #[test]
    fn a_follower_never_shows_or_cancels_another_packages_attempt() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.install(&mut p).unwrap();
        // The installer's current attempt turns out to be a sibling's: ours must not show its progress.
        p.apk = Some(ApkStatus::Downloading { done: 1, total: 2 });
        p.apk_active = Some("org.example.sibling".into());
        u.cancel_install(&mut p);
        assert_eq!(p.apk_cancels, 0, "not ours to cancel");
        u.tick(0.3, &mut p);
        assert_eq!(*u.install_status(), ApkStatus::Failed(ANOTHER_INSTALL.into()));
    }

    #[test]
    fn missing_install_permission_opens_the_settings_page_once() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.install(&mut p).unwrap();
        p.apk = Some(ApkStatus::NeedsPermission);
        u.tick(0.3, &mut p);
        assert_eq!(p.install_settings_opened, 1);
        assert_eq!(*u.install_status(), ApkStatus::NeedsPermission);
        // The wording names the app.
        assert!(u.view(5_000_100).status.contains("Allow installs from Example App"), "{}", u.view(5_000_100).status);
        // Not polled again while parked; tapping Update retries the whole thing.
        u.tick(0.3, &mut p);
        assert_eq!(p.install_settings_opened, 1);
        assert!(u.view(5_000_100).can_install);
        p.apk = Some(ApkStatus::Downloading { done: 1, total: 2 });
        u.install(&mut p).unwrap();
        assert_eq!(p.apk_started.len(), 2);
    }

    #[test]
    fn a_failure_is_shown_and_can_be_retried() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.install(&mut p).unwrap();
        p.apk = Some(ApkStatus::Failed("The download didn't match what was announced.".into()));
        u.tick(0.3, &mut p);
        let v = u.view(5_000_100);
        assert_eq!(v.status, "The download didn't match what was announced.");
        assert_eq!(v.tone, UpdateTone::Danger);
        assert!(v.can_install);
        assert_eq!(u.pill().as_deref(), Some("Update failed. Tap to retry"));
    }

    #[test]
    fn the_update_check_asks_the_release_relays_and_the_users_own_once_each() {
        let mut u = Updater::new(cfg(), Box::new(FakeFetcher::default()));
        let base: Vec<String> = crate::DEFAULT_RELEASE_RELAYS.iter().map(|s| s.to_string()).collect();
        assert_eq!(u.check_relays(), base, "no own relays: the release relays only");
        // Own relays are added; one that is a release relay in another spelling is not repeated.
        u.set_user_relays(vec!["wss://relay.damus.io".into(), "wss://NOS.LOL:443/".into(), "wss://mine.example.com".into(), "wss://relay.primal.net".into(), "wss://mine.example.com/".into()]);
        let got = u.check_relays();
        // Order: the user's own, in their order; then the release relays they did not list.
        assert_eq!(got, vec!["wss://relay.damus.io".to_string(), "wss://NOS.LOL:443/".to_string(), "wss://mine.example.com".to_string(), "wss://relay.primal.net".to_string()]);
        // Clearing the list goes back to the release relays.
        u.set_user_relays(Vec::new());
        assert_eq!(u.check_relays(), base);
    }

    #[test]
    fn desktop_cannot_install_and_says_so() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        // The default installer has no installer.
        struct NoInstaller;
        impl ApkInstaller for NoInstaller {}
        let mut p = NoInstaller;
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.install(&mut p).unwrap();
        assert!(matches!(u.install_status(), ApkStatus::Failed(m) if m.contains("Android")));
    }

    fn temp_state(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("release-kit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("update.json")
    }

    fn reopen(file: &std::path::Path, key: PublicKey, installed: u32) -> Updater {
        let mut u = Updater::new(cfg().with_state_file(file), Box::new(FakeFetcher::default()));
        u.trust(key);
        u.installed = installed;
        u
    }

    #[test]
    fn the_saved_release_is_checked_again_on_load() {
        let file = temp_state("saved");
        let keys = Keys::generate();
        let mut p = installer();

        let mut u = reopen(&file, keys.public_key(), 1000);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        assert!(file.exists());

        // A fresh start offers it straight away, without waiting for the relays.
        let mut again = reopen(&file, keys.public_key(), 1000);
        again.tick(0.0, &mut p);
        assert_eq!(again.pill().as_deref(), Some("Update to v0.2.0"));
        assert!(!again.due(5_000_000 + 3600));
        assert!(again.due(5_000_000 + crate::DEFAULT_CHECK_INTERVAL.as_secs()));

        // Once the new version is installed the saved event is just history...
        let mut after = reopen(&file, keys.public_key(), 2000);
        after.tick(0.0, &mut p);
        assert!(after.pill().is_none());
        assert!(matches!(after.verdict(), Verdict::UpToDate));

        // ...a different signer's genuine event is not ours...
        let mut forged = reopen(&file, Keys::generate().public_key(), 1000);
        forged.tick(0.0, &mut p);
        assert!(matches!(forged.verdict(), Verdict::Unknown));

        // ...an edited file (a bigger version_code under the old id and signature) buys nothing...
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("\"2000\""), "{text}");
        std::fs::write(&file, text.replace("\"2000\"", "\"9000\"")).unwrap();
        let mut edited = reopen(&file, keys.public_key(), 1000);
        edited.tick(0.0, &mut p);
        assert!(matches!(edited.verdict(), Verdict::Unknown), "an edited event must fail id/signature");
        std::fs::write(&file, text).unwrap();

        // ...and garbage in the file is a fresh start.
        std::fs::write(&file, b"{not json").unwrap();
        let fresh = reopen(&file, keys.public_key(), 1000);
        assert!(fresh.due(1) && matches!(fresh.verdict(), Verdict::Unknown));
        let _ = std::fs::remove_dir_all(file.parent().unwrap());
    }

    #[test]
    fn a_check_that_hears_nothing_keeps_what_we_knew() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        assert_eq!(u.view(10).status, "Not checked yet");
        // Relays that answered with nothing: no update has been published.
        u.apply_events(&[], 10);
        assert_eq!(u.view(10).status, "No update published yet");
        assert_eq!(u.view(10).tone, UpdateTone::Dim);
        assert!(u.due(10), "an empty answer doesn't reset the clock");
        // Nobody answered: that is a connection problem, said as one.
        let none = FetchReport { events: vec![], answered: 0, total: 3 };
        u.apply_report(&none, 11);
        assert_eq!(u.view(11).status, "Couldn't reach the relays");
        assert_eq!(u.view(11).tone, UpdateTone::Danger);
        // Two of three answered, with nothing: reached.
        let empty = FetchReport { events: vec![], answered: 2, total: 3 };
        u.apply_report(&empty, 12);
        assert_eq!(u.view(12).status, "No update published yet");
        u.apply_events(&[sign(&keys, good_tags(2000))], 20);
        u.apply_events(&[], 30);
        assert_eq!(u.pill().as_deref(), Some("Update to v0.2.0"), "a later empty answer keeps the known release");
    }

    #[test]
    fn an_older_retained_event_never_displaces_a_newer_known_one() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(3000))], 10);
        u.apply_events(&[sign(&keys, good_tags(2000))], 20);
        assert_eq!(u.verdict_code(), Some(3000), "a relay serving only the older event keeps the newer offer");
        u.apply_events(&[sign(&keys, good_tags(4000))], 30);
        assert_eq!(u.verdict_code(), Some(4000));
    }

    #[test]
    fn a_last_check_in_the_future_is_due() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        u.apply_events(&[sign(&keys, good_tags(2000))], 9_000_000);
        assert!(!u.due(9_000_100));
        assert!(u.due(1_000_000), "the clock was wrong when the check was taken");
    }

    #[test]
    fn cancel_asks_the_installer_only_while_downloading() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5_000_000);
        u.cancel_install(&mut p);
        assert_eq!(p.apk_cancels, 0);
        u.install(&mut p).unwrap();
        assert!(u.view(5_000_100).downloading);
        u.cancel_install(&mut p);
        assert_eq!(p.apk_cancels, 1);
        p.apk = Some(ApkStatus::Failed("The download was cancelled.".into()));
        u.tick(0.3, &mut p);
        let v = u.view(5_000_200);
        assert!(!v.downloading && v.can_install && v.can_check && v.status.contains("cancelled"));
    }

    #[test]
    fn a_demo_offer_never_reaches_the_saved_file() {
        let file = temp_state("demo");
        let mut u = Updater::new(cfg().with_state_file(&file), Box::new(FakeFetcher::default()));
        u.demo_offer("9.9.9", "demo");
        assert!(!file.exists() && matches!(u.verdict(), Verdict::Unknown));
        let mut m = Updater::new(cfg(), Box::new(FakeFetcher::default()));
        m.demo_offer("9.9.9", "demo");
        assert!(matches!(m.verdict(), Verdict::Offer(_)));
        let r = demo_release(CHANNEL, "9.9.9", 1234, CERT);
        assert_eq!((r.version.as_str(), r.size), ("9.9.9", 1234));
    }

    #[test]
    fn the_status_line_for_a_current_install_says_when_it_looked() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 2000);
        let mut p = installer();
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 1_000_000);
        assert_eq!(u.view(1_000_000).status, "You're up to date, checked just now");
        assert_eq!(u.view(1_000_000 + 7200).status, "You're up to date, checked 2 h ago");
        assert!(u.view(1_000_000).offer.is_none() && u.pill().is_none());
    }

    #[test]
    fn a_release_signed_with_another_certificate_is_explained_not_offered() {
        let keys = Keys::generate();
        let mut u = updater_for(&keys, 1000);
        let mut p = RecordingInstaller { cert: Some("c".repeat(64)), ..Default::default() };
        u.tick(0.0, &mut p);
        u.apply_events(&[sign(&keys, good_tags(2000))], 5);
        assert!(u.pill().is_none());
        let v = u.view(5);
        assert!(v.status.contains("different key") && !v.can_install && v.offer.is_none());
    }

    #[test]
    fn with_no_release_key_pinned_nothing_is_checked_and_the_card_says_so() {
        let fetcher = FakeFetcher::default();
        let mut u = Updater::new(cfg(), Box::new(fetcher.clone()));
        u.enabled = true;
        assert!(!u.configured());
        let mut p = installer();
        // The launch check would run on a platform that can install, were a key pinned.
        u.tick(0.0, &mut p);
        assert!(!u.checking());
        u.check_now();
        assert!(!u.checking() && fetcher.call_count() == 0, "no key, no network");
        let v = u.view(100);
        assert_eq!(v.status, NOT_SET_UP);
        assert_eq!(v.tone, UpdateTone::Dim);
        assert!(!v.can_check && !v.can_install && !v.checking && v.offer.is_none());
        // Even a validly signed event is not news without a pinned key.
        let keys = Keys::generate();
        u.apply_events(&[sign(&keys, good_tags(2000))], 5);
        assert!(u.pill().is_none() && matches!(u.verdict(), Verdict::Unknown));
        assert!(u.due(5), "nothing was recorded");
    }

    #[test]
    fn a_check_goes_through_the_fetcher_and_its_report_is_collected_on_tick() {
        let keys = Keys::generate();
        let mut fetcher = FakeFetcher::new(FetchReport { events: vec![sign(&keys, good_tags(2000))], answered: 3, total: 3 });
        fetcher.polls_before_ready = 2;
        let mut u = Updater::new(cfg(), Box::new(fetcher.clone()));
        u.trust(keys.public_key());
        u.installed = 1000;
        u.enabled = true;
        let mut p = installer();
        // The first tick starts the launch check (the platform can install, nothing was checked yet) ...
        u.tick(0.0, &mut p);
        assert_eq!(fetcher.call_count(), 1);
        {
            let call = &fetcher.calls.lock().unwrap()[0];
            assert_eq!(call.relays, crate::DEFAULT_RELEASE_RELAYS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            assert_eq!(call.timeout, crate::DEFAULT_FETCH_TIMEOUT);
            use nostr::util::JsonUtil;
            assert_eq!(call.filters.len(), 1);
            let json = call.filters[0].try_as_json().unwrap();
            assert!(json.contains(CHANNEL) && json.contains(&keys.public_key().to_hex()), "{json}");
        }
        assert!(u.checking());
        // ... a second check while one runs does not start another ...
        u.check_now();
        assert_eq!(fetcher.call_count(), 1);
        // ... the read is still running on the next tick ...
        u.tick(0.0, &mut p);
        assert!(u.checking() && u.pill().is_none());
        // ... and the one after collects the answer.
        u.tick(0.0, &mut p);
        assert!(!u.checking());
        assert_eq!(u.pill().as_deref(), Some("Update to v0.2.0"));
        // The hand-held "Check for updates" asks again.
        u.check_now();
        assert_eq!(fetcher.call_count(), 2);
        // A disabled updater does not check at launch.
        let mut off = Updater::new(cfg(), Box::new(fetcher.clone()));
        off.trust(keys.public_key());
        off.tick(0.0, &mut p);
        assert_eq!(fetcher.call_count(), 2);
    }

    #[test]
    fn notes_are_one_short_paragraph() {
        assert_eq!(notes_text("  Faster\n\nbands.  "), "Faster bands.");
        let long = notes_text(&"word ".repeat(100));
        assert!(long.chars().count() <= 160 && long.ends_with('…'));
    }
}
