//! A catalog of sibling apps, built into the app, that can be installed from
//! there. There is no remote list. Each entry pins the app's package, its release
//! channel, the key that signs its release events and the certificate its APK is
//! signed with.
//!
//! The screen opens one relay pass ([`Catalog::begin`]) and judges every entry
//! with the same rules as the self-update ([`crate::parse_release`]), using THAT
//! entry's key and channel. Installing goes through
//! [`crate::Updater::install_sibling`]; the Java side then reads the downloaded
//! file's package and signing certificate and refuses unless they match the
//! catalog ([`judge_archive`], mirrored in `ApkCheck.java` and tested against the
//! same vectors).

use crate::fetch::{release_relays, FetchReport, PendingFetch, ReleaseFetcher};
use crate::installer::ApkInstaller;
use crate::release::{is_hex64, is_package_name, pick_latest, release_filter, Release};
use crate::updater::Updater;
use nostr::{Event, PublicKey};
use std::time::Duration;

/// One app in the catalog. (An icon is the app's own business: keep it beside the
/// entry, by index.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: &'static str,
    /// One line.
    pub blurb: &'static str,
    /// The Android package.
    pub package: &'static str,
    /// The release channel: the `d` tag of its release events.
    pub channel: &'static str,
    /// The key that signs its releases (hex). `None` = not published yet.
    pub release_pubkey: Option<&'static str>,
    /// SHA-256 of the certificate its APK is signed with (hex). `None` = not known yet.
    pub cert: Option<&'static str>,
}

impl CatalogEntry {
    /// The package is a real Android package name and both pins are known: the entry can be
    /// fetched and installed. Otherwise "Coming soon". (An empty package would make the
    /// installer treat the file as an update of THIS app.)
    pub fn ready(&self) -> bool {
        is_package_name(self.package) && self.release_pubkey.is_some_and(|k| PublicKey::from_hex(k).is_ok()) && self.cert.is_some_and(is_hex64)
    }

    fn key(&self) -> Option<PublicKey> {
        self.release_pubkey.and_then(|k| PublicKey::from_hex(k).ok())
    }
}

/// What the catalog needs besides its entries.
#[derive(Clone, Debug)]
pub struct CatalogConfig {
    /// In the order shown.
    pub entries: Vec<CatalogEntry>,
    /// Release relays, asked on top of the user's own.
    pub relays: Vec<String>,
    /// How long the relays get to answer.
    pub fetch_timeout: Duration,
    /// How often the installed versions are read again while the screen is open.
    pub installed_poll: Duration,
}

impl CatalogConfig {
    /// The default relays, timeout and poll interval.
    pub fn new(entries: Vec<CatalogEntry>) -> CatalogConfig {
        CatalogConfig {
            entries,
            relays: crate::config::DEFAULT_RELEASE_RELAYS.iter().map(|s| s.to_string()).collect(),
            fetch_timeout: crate::config::DEFAULT_FETCH_TIMEOUT,
            installed_poll: Duration::from_secs(1),
        }
    }

    /// Check the entries against the app they live in: every package a real Android package
    /// name, none equal to `own_package` (a sibling release must never run as an update of
    /// THIS app), no package or (key, channel) pair twice. Call it at startup or in a test;
    /// an invalid entry is never fetched or installed either way (it stays "Coming soon").
    pub fn validate(&self, own_package: &str) -> Result<(), String> {
        for (i, e) in self.entries.iter().enumerate() {
            if !is_package_name(e.package) {
                return Err(format!("catalog entry {i} ({}) has no valid package name: {:?}", e.name, e.package));
            }
            if e.package == own_package {
                return Err(format!("catalog entry {i} ({}) is this app's own package", e.name));
            }
            if let Some(j) = self.entries[..i].iter().position(|o| o.package == e.package || (o.channel == e.channel && o.release_pubkey == e.release_pubkey)) {
                return Err(format!("catalog entries {j} and {i} ({}) repeat a package or a channel", e.name));
            }
        }
        Ok(())
    }
}

/// The newest release of `entry`: signed by the entry's own key, on the
/// entry's own channel, well formed with canonical URLs ([`crate::parse_release`]),
/// and carrying the entry's pinned certificate. Anything else is `Err`/`Ok(None)`.
pub fn release_for(entry: &CatalogEntry, events: &[Event]) -> Result<Option<Release>, CertMismatch> {
    let (Some(key), Some(cert)) = (entry.key(), entry.cert) else { return Ok(None) };
    match pick_latest(events, &key, entry.channel) {
        Some(r) if r.cert != cert => Err(CertMismatch { version: r.version }),
        other => Ok(other),
    }
}

/// The newest verified release is signed with a different certificate than the catalog pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertMismatch {
    pub version: String,
}

/// What a card shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryStatus {
    /// No key or certificate pinned yet.
    ComingSoon,
    /// The relay pass is running.
    Checking,
    /// No relay answered.
    CantReach,
    /// Relays answered, no release of this app is published.
    NoRelease,
    /// A release exists but is signed with another key than the catalog's: not offered.
    WrongKey { version: String },
    /// Not installed, a release can be installed.
    Get { version: String, size: u64 },
    /// Installed, nothing newer.
    Open,
    /// Installed, a newer release exists.
    Update { version: String, size: u64 },
}

/// How the relay pass stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    Idle,
    Running,
    /// Relays answered (possibly with nothing).
    Answered,
    /// No relay answered at all.
    Unreached,
}

/// Pure: what a card shows, from what is known.
pub fn status_of(entry: &CatalogEntry, fetch: &Fetch, release: &Result<Option<Release>, CertMismatch>, installed: Option<u32>) -> EntryStatus {
    if !entry.ready() {
        return EntryStatus::ComingSoon;
    }
    match (release, installed) {
        (Ok(Some(r)), Some(code)) if r.version_code > code => EntryStatus::Update { version: r.version.clone(), size: r.size },
        (Ok(Some(r)), None) => EntryStatus::Get { version: r.version.clone(), size: r.size },
        (_, Some(_)) => EntryStatus::Open,
        (Err(m), None) => EntryStatus::WrongKey { version: m.version.clone() },
        (Ok(None), None) => match fetch {
            Fetch::Idle | Fetch::Running => EntryStatus::Checking,
            Fetch::Unreached => EntryStatus::CantReach,
            Fetch::Answered => EntryStatus::NoRelease,
        },
    }
}

/// The catalog screen's data: the relay pass and the installed versions.
pub struct Catalog {
    cfg: CatalogConfig,
    fetcher: Box<dyn ReleaseFetcher>,
    task: Option<Box<dyn PendingFetch>>,
    fetch: Fetch,
    releases: Vec<Result<Option<Release>, CertMismatch>>,
    installed: Vec<Option<u32>>,
    poll_left: f32,
}

impl Catalog {
    pub fn new(config: CatalogConfig, fetcher: Box<dyn ReleaseFetcher>) -> Catalog {
        let n = config.entries.len();
        Catalog { cfg: config, fetcher, task: None, fetch: Fetch::Idle, releases: (0..n).map(|_| Ok(None)).collect(), installed: vec![None; n], poll_left: 0.0 }
    }

    /// The entries, in the order shown.
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.cfg.entries
    }

    /// The filters for the whole catalog: one per ready entry (its key and channel, its own
    /// `limit`), so one entry's many events cannot crowd out another's. Empty when no entry is ready.
    pub fn filters(&self) -> Vec<nostr::Filter> {
        self.cfg.entries.iter().filter(|e| e.ready()).filter_map(|e| e.key().map(|k| release_filter(&k, e.channel))).collect()
    }

    /// The screen opened: one pass over the user's relays then the release relays.
    /// Never touches the network when no entry is ready.
    pub fn begin(&mut self, user_relays: &[String]) {
        let filters = self.filters();
        if filters.is_empty() {
            return;
        }
        self.fetch = Fetch::Running;
        self.task = Some(self.fetcher.start(release_relays(user_relays, &self.cfg.relays), filters, self.cfg.fetch_timeout));
    }

    /// Frame hook: collect the relay pass; read the installed versions now and then.
    pub fn tick(&mut self, dt: f32, installer: &mut dyn ApkInstaller) {
        if let Some(report) = self.task.as_mut().and_then(|t| t.poll()) {
            self.task = None;
            self.apply_report(&report);
        }
        self.poll_left -= dt;
        if self.poll_left <= 0.0 {
            self.poll_left = self.cfg.installed_poll.as_secs_f32();
            for (i, e) in self.cfg.entries.iter().enumerate() {
                self.installed[i] = installer.installed_version_code(e.package);
            }
        }
    }

    /// Take a finished relay pass.
    pub fn apply_report(&mut self, report: &FetchReport) {
        for (i, e) in self.cfg.entries.iter().enumerate() {
            self.releases[i] = release_for(e, &report.events);
        }
        self.fetch = if report.reached() { Fetch::Answered } else { Fetch::Unreached };
        log::info!("catalog: {} of {} relays answered, {} event(s)", report.answered, report.total, report.events.len());
    }

    pub fn fetch(&self) -> Fetch {
        self.fetch
    }

    pub fn status(&self, i: usize) -> EntryStatus {
        match (self.cfg.entries.get(i), self.releases.get(i), self.installed.get(i)) {
            (Some(e), Some(release), Some(installed)) => status_of(e, &self.fetch, release, *installed),
            _ => EntryStatus::ComingSoon,
        }
    }

    /// Get / Update on entry `i`: download, verify and install through the shared updater.
    /// `Err(notice)` when another package's install is running (nothing started): show it.
    pub fn install(&self, i: usize, updates: &mut Updater, installer: &mut dyn ApkInstaller) -> Result<(), String> {
        let Some(e) = self.cfg.entries.get(i) else { return Ok(()) };
        let Some(Ok(Some(r))) = self.releases.get(i) else { return Ok(()) };
        let Some(cert) = e.cert else { return Ok(()) };
        updates.install_sibling(installer, e.package, r, cert)
    }

    /// Open the installed app.
    pub fn open(&self, i: usize, installer: &mut dyn ApkInstaller) -> bool {
        self.cfg.entries.get(i).is_some_and(|e| installer.open_package(e.package))
    }

    /// Screenshots and tests: set what is known. Only with the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn demo(&mut self, fetch: Fetch, installed: Vec<Option<u32>>, releases: Vec<Result<Option<Release>, CertMismatch>>) {
        self.fetch = fetch;
        self.installed = installed;
        self.releases = releases;
    }
}

// ─── Checking the downloaded file ───────────────────────────────────────────

/// The decision made on the downloaded file before the installer session is
/// committed: its package (`got_pkg`) and its one signing certificate (`got_cert`, SHA-256
/// hex; empty = unreadable) against what it must be. `strict` (an app from the
/// catalog): the package, the catalog's pinned certificate AND the release event's
/// certificate must all be present and equal what the file says. Loose (this app's
/// own update): the package must match, and a certificate that was read must equal
/// each one that was given. An APK with more than one signer (`multiple_signers`) is
/// refused either way. This is `ApkCheck.verify` in the Java source; both are
/// tested against `vectors/apk-check-vectors.tsv`.
pub fn archive_ok(got_pkg: &str, got_cert: &str, want_pkg: &str, pinned_cert: &str, release_cert: &str, strict: bool, multiple_signers: bool) -> bool {
    if multiple_signers || want_pkg.is_empty() || got_pkg != want_pkg {
        return false;
    }
    if strict {
        return is_hex64(got_cert) && is_hex64(pinned_cert) && is_hex64(release_cert) && got_cert == pinned_cert && got_cert == release_cert;
    }
    if got_cert.is_empty() {
        return true;
    }
    (pinned_cert.is_empty() || got_cert == pinned_cert) && (release_cert.is_empty() || got_cert == release_cert)
}

/// The same decision as [`archive_ok`], by the name the docs use for it.
pub fn judge_archive(got_pkg: &str, got_cert: &str, want_pkg: &str, pinned_cert: &str, release_cert: &str, strict: bool, multiple_signers: bool) -> bool {
    archive_ok(got_pkg, got_cert, want_pkg, pinned_cert, release_cert, strict, multiple_signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer::{ApkJob, ApkStatus};
    use crate::release::RELEASE_KIND;
    use crate::testing::{FakeFetcher, RecordingInstaller};
    use crate::{Config, DIDNT_CHECK_OUT};
    use nostr::util::JsonUtil;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CERT: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
    const OTHER_CERT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CHANNEL: &str = "siblingapp-android-apk";
    const PKG: &str = "org.example.sibling";

    fn tag(parts: &[&str]) -> Tag {
        Tag::parse(parts.iter().copied()).unwrap()
    }

    fn event(keys: &Keys, channel: &str, code: u32, cert: &str) -> Event {
        let tags = vec![
            tag(&["d", channel]),
            tag(&["version", "1.2.3"]),
            tag(&["version_code", &code.to_string()]),
            tag(&["x", SHA]),
            tag(&["size", "9000000"]),
            tag(&["cert", cert]),
            tag(&["url", &format!("https://nostr.download/{SHA}.apk")]),
        ];
        EventBuilder::new(Kind::Custom(RELEASE_KIND), "notes").tags(tags).sign_with_keys(keys).unwrap()
    }

    /// A catalog entry for tests, pinned to `keys`.
    fn entry_for(keys: &Keys) -> CatalogEntry {
        // The test key's hex has to live as long as the entry: leak it (tests only).
        let hex: &'static str = Box::leak(keys.public_key().to_hex().into_boxed_str());
        CatalogEntry { name: "Test", blurb: "", package: PKG, channel: CHANNEL, release_pubkey: Some(hex), cert: Some(CERT) }
    }

    fn catalog_of(entries: Vec<CatalogEntry>) -> Catalog {
        Catalog::new(CatalogConfig::new(entries), Box::new(FakeFetcher::default()))
    }

    #[test]
    fn an_entry_without_a_key_or_cert_is_coming_soon_and_never_fetched() {
        let mut e = entry_for(&Keys::generate());
        e.release_pubkey = None;
        assert!(!e.ready());
        assert_eq!(status_of(&e, &Fetch::Answered, &Ok(None), None), EntryStatus::ComingSoon);
        let mut e2 = entry_for(&Keys::generate());
        e2.cert = None;
        assert_eq!(status_of(&e2, &Fetch::Answered, &Ok(None), Some(5)), EntryStatus::ComingSoon);
        // Nothing to fetch: no filter, so no network.
        assert!(release_for(&e, &[]).unwrap().is_none());
        let fetcher = FakeFetcher::default();
        let mut c = Catalog::new(CatalogConfig::new(vec![e, e2]), Box::new(fetcher.clone()));
        assert!(c.filters().is_empty());
        c.begin(&[]);
        assert_eq!(fetcher.call_count(), 0);
        assert_eq!(c.fetch(), Fetch::Idle);
    }

    #[test]
    fn an_entry_without_a_valid_package_is_never_ready_or_installed() {
        let key = Keys::generate();
        for bad in ["", "sibling", "org..x"] {
            let mut e = entry_for(&key);
            e.package = bad;
            assert!(!e.ready(), "{bad:?}");
            assert_eq!(status_of(&e, &Fetch::Answered, &Ok(None), None), EntryStatus::ComingSoon);
        }
        // An empty package would route a sibling-key release into the self-update path: refused outright.
        let r = release_for(&entry_for(&key), &[event(&key, CHANNEL, 7, CERT)]).unwrap().unwrap();
        let mut u = updater();
        let mut p = RecordingInstaller::default();
        for pkg in ["", "org.example.app"] {
            assert!(u.install_sibling(&mut p, pkg, &r, CERT).is_err(), "{pkg:?}");
        }
        assert!(p.apk_started.is_empty(), "nothing was started");
    }

    #[test]
    fn the_config_validates_against_the_apps_own_package() {
        let key = Keys::generate();
        let ok = CatalogConfig::new(vec![entry_for(&key)]);
        assert!(ok.validate("org.example.app").is_ok());
        assert!(ok.validate(PKG).unwrap_err().contains("own package"));
        let mut empty = entry_for(&key);
        empty.package = "";
        assert!(CatalogConfig::new(vec![empty]).validate("org.example.app").is_err());
        let twice = CatalogConfig::new(vec![entry_for(&key), entry_for(&key)]);
        assert!(twice.validate("org.example.app").unwrap_err().contains("repeat"));
    }

    #[test]
    fn a_malformed_pin_is_not_ready() {
        let mut e = entry_for(&Keys::generate());
        e.release_pubkey = Some("not-a-key");
        assert!(!e.ready());
        let mut e = entry_for(&Keys::generate());
        e.cert = Some("ABCD");
        assert!(!e.ready());
    }

    #[test]
    fn an_event_counts_only_from_that_entrys_key_and_channel() {
        let (key, other) = (Keys::generate(), Keys::generate());
        let e = entry_for(&key);
        // Right key and channel.
        assert_eq!(release_for(&e, &[event(&key, CHANNEL, 7, CERT)]).unwrap().unwrap().version_code, 7);
        // Another key on the same channel, and the right key on another channel (a different app's).
        assert!(release_for(&e, &[event(&other, CHANNEL, 9, CERT)]).unwrap().is_none());
        assert!(release_for(&e, &[event(&key, "other-android-apk", 9, CERT)]).unwrap().is_none());
        // The highest valid one wins among several.
        let evs = [event(&key, CHANNEL, 5, CERT), event(&key, CHANNEL, 8, CERT), event(&other, CHANNEL, 99, CERT)];
        assert_eq!(release_for(&e, &evs).unwrap().unwrap().version_code, 8);
        // A release signed with another certificate than the catalog pins is not offered.
        assert_eq!(release_for(&e, &[event(&key, CHANNEL, 7, OTHER_CERT)]), Err(CertMismatch { version: "1.2.3".into() }));
    }

    #[test]
    fn statuses_follow_what_is_installed_and_published() {
        let key = Keys::generate();
        let e = entry_for(&key);
        let rel = |code| release_for(&e, &[event(&key, CHANNEL, code, CERT)]);
        let got = |f: Fetch, r: &Result<Option<Release>, CertMismatch>, i: Option<u32>| status_of(&e, &f, r, i);
        let get = EntryStatus::Get { version: "1.2.3".into(), size: 9_000_000 };
        let upd = EntryStatus::Update { version: "1.2.3".into(), size: 9_000_000 };
        assert_eq!(got(Fetch::Answered, &rel(7), None), get);
        assert_eq!(got(Fetch::Answered, &rel(7), Some(7)), EntryStatus::Open);
        assert_eq!(got(Fetch::Answered, &rel(7), Some(9)), EntryStatus::Open);
        assert_eq!(got(Fetch::Answered, &rel(7), Some(6)), upd);
        // Nothing published: honest wording, and an installed app is still just openable.
        assert_eq!(got(Fetch::Answered, &Ok(None), None), EntryStatus::NoRelease);
        assert_eq!(got(Fetch::Unreached, &Ok(None), None), EntryStatus::CantReach);
        assert_eq!(got(Fetch::Running, &Ok(None), None), EntryStatus::Checking);
        assert_eq!(got(Fetch::Unreached, &Ok(None), Some(3)), EntryStatus::Open);
        let bad = release_for(&e, &[event(&key, CHANNEL, 7, OTHER_CERT)]);
        assert_eq!(got(Fetch::Answered, &bad, None), EntryStatus::WrongKey { version: "1.2.3".into() });
    }

    #[test]
    fn the_filter_names_every_ready_key_and_channel() {
        let (a, b) = (Keys::generate(), Keys::generate());
        let mut eb = entry_for(&b);
        eb.channel = "second-android-apk";
        eb.package = "org.example.second";
        let c = catalog_of(vec![entry_for(&a), eb]);
        let filters = c.filters();
        assert_eq!(filters.len(), 2, "one filter per ready entry, each with its own limit");
        let (ja, jb) = (filters[0].try_as_json().unwrap(), filters[1].try_as_json().unwrap());
        assert!(ja.contains(&a.public_key().to_hex()) && ja.contains(CHANNEL) && !ja.contains("second-android-apk"), "{ja}");
        assert!(jb.contains(&b.public_key().to_hex()) && jb.contains("second-android-apk") && jb.contains("30063"), "{jb}");
    }

    #[test]
    fn a_report_is_judged_per_entry_and_unreached_is_not_no_release() {
        // The entry never accepts an event from a throwaway key.
        let mut g = catalog_of(vec![entry_for(&Keys::generate())]);
        let impostor = Keys::generate();
        g.apply_report(&FetchReport { events: vec![event(&impostor, CHANNEL, 7, CERT)], answered: 2, total: 3 });
        assert_eq!(g.status(0), EntryStatus::NoRelease);
        g.apply_report(&FetchReport { events: vec![], answered: 0, total: 3 });
        assert_eq!(g.status(0), EntryStatus::CantReach);
        assert_eq!(g.status(5), EntryStatus::ComingSoon, "out of range");
    }

    #[test]
    fn a_begun_pass_goes_through_the_fetcher_and_is_collected_on_tick() {
        let key = Keys::generate();
        let fetcher = FakeFetcher::new(FetchReport { events: vec![event(&key, CHANNEL, 7, CERT)], answered: 3, total: 3 });
        let mut c = Catalog::new(CatalogConfig::new(vec![entry_for(&key)]), Box::new(fetcher.clone()));
        let mut p = RecordingInstaller::default();
        c.begin(&["wss://mine.example.com".to_string()]);
        assert_eq!(c.fetch(), Fetch::Running);
        assert_eq!(c.status(0), EntryStatus::Checking);
        assert_eq!(fetcher.calls.lock().unwrap()[0].relays[0], "wss://mine.example.com");
        c.tick(0.0, &mut p);
        assert_eq!(c.fetch(), Fetch::Answered);
        assert_eq!(c.status(0), EntryStatus::Get { version: "1.2.3".into(), size: 9_000_000 });
    }

    #[test]
    fn the_installed_version_is_read_from_the_installer() {
        let mut g = catalog_of(vec![entry_for(&Keys::generate())]);
        let mut p = RecordingInstaller::default();
        g.tick(0.0, &mut p);
        assert!(matches!(g.status(0), EntryStatus::Checking | EntryStatus::NoRelease));
        p.installed_packages.insert(PKG.into(), 1000);
        g.tick(1.5, &mut p);
        assert_eq!(g.status(0), EntryStatus::Open);
        assert!(g.open(0, &mut p));
        assert_eq!(p.opened_packages, vec![PKG.to_string()]);
    }

    fn updater() -> Updater {
        Updater::new(Config::new("exampleapp-android-apk", "org.example.app", "Example App", "0.1.0").unwrap(), Box::new(FakeFetcher::default()))
    }

    #[test]
    fn installing_a_sibling_names_its_package_and_pinned_cert_and_leaves_the_self_update_alone() {
        let key = Keys::generate();
        let e = entry_for(&key);
        let r = release_for(&e, &[event(&key, CHANNEL, 7, CERT)]).unwrap().unwrap();
        let mut u = updater();
        let mut p = RecordingInstaller { cert: Some("c".repeat(64)), ..Default::default() };
        u.tick(0.0, &mut p);
        u.install_sibling(&mut p, e.package, &r, CERT).unwrap();
        assert_eq!(p.apk_started, vec![ApkJob { urls: r.urls.clone(), sha256: SHA.into(), size: 9_000_000, package: PKG.into(), cert: CERT.into(), release_cert: CERT.into() }]);
        assert_eq!(*u.install_status(), ApkStatus::Downloading { done: 0, total: 9_000_000 });
        assert_eq!(u.sibling_status(PKG), Some(&ApkStatus::Downloading { done: 0, total: 9_000_000 }));
        assert_eq!(u.sibling_status("org.other"), None);
        // The self-update screens see nothing of it, but cannot start a second download.
        assert!(u.pill().is_none());
        let v = u.view(0);
        assert!(!v.downloading && v.progress.is_none());
        u.install_sibling(&mut p, e.package, &r, CERT).unwrap();
        assert_eq!(p.apk_started.len(), 1, "one download at a time");
        // Progress is followed like any download, and a failure is kept for the card.
        p.apk = Some(ApkStatus::Failed(DIDNT_CHECK_OUT.into()));
        u.tick(0.3, &mut p);
        assert_eq!(u.sibling_status(PKG), Some(&ApkStatus::Failed(DIDNT_CHECK_OUT.into())));
    }

    #[test]
    fn the_catalog_installs_the_entry_it_judged() {
        let key = Keys::generate();
        let mut c = catalog_of(vec![entry_for(&key)]);
        let mut u = updater();
        let mut p = RecordingInstaller::default();
        // Nothing judged yet: nothing starts.
        c.install(0, &mut u, &mut p).unwrap();
        assert!(p.apk_started.is_empty());
        c.apply_report(&FetchReport { events: vec![event(&key, CHANNEL, 7, CERT)], answered: 1, total: 1 });
        c.install(0, &mut u, &mut p).unwrap();
        assert_eq!(p.apk_started.len(), 1);
        assert_eq!(p.apk_started[0].package, PKG);
    }

    #[test]
    fn a_release_whose_cert_differs_from_the_pin_is_not_started() {
        let key = Keys::generate();
        let e = entry_for(&key);
        let r = match release_for(&e, &[event(&key, CHANNEL, 7, OTHER_CERT)]) {
            Err(_) => {
                // release_for refuses it, so build the Release the way the parser would, with the wrong cert.
                crate::parse_release(&event(&key, CHANNEL, 7, OTHER_CERT), &key.public_key(), CHANNEL).unwrap()
            }
            Ok(_) => panic!("must be refused"),
        };
        let mut u = updater();
        let mut p = RecordingInstaller::default();
        u.install_sibling(&mut p, e.package, &r, CERT).unwrap();
        assert!(p.apk_started.is_empty());
        assert!(matches!(u.install_status(), ApkStatus::Failed(m) if m.contains("different key")));
    }

    #[test]
    fn the_archive_vectors_shared_with_the_java_check() {
        // vectors/apk-check-vectors.tsv is read by ApkCheckTest.java too: one decision, two implementations.
        let text = include_str!("../vectors/apk-check-vectors.tsv");
        let mut n = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            let f: Vec<&str> = line.split('\t').map(|x| if x == "-" { "" } else { x }).collect();
            assert_eq!(f.len(), 8, "{line:?}");
            let (strict, many) = (f[5] == "strict", f[6] == "many");
            let got = archive_ok(f[0], f[1], f[2], f[3], f[4], strict, many);
            assert_eq!(got, f[7] == "ok", "{line}");
            assert_eq!(judge_archive(f[0], f[1], f[2], f[3], f[4], strict, many), got);
            n += 1;
        }
        assert!(n >= 20, "{n} vectors");
    }

    /// vectors/publisher-event.json is what the Node publisher signs, with a throwaway key: it is what a
    /// real sibling release event looks like to the catalog's parse path.
    #[test]
    fn a_publisher_event_parses_for_an_entry_pinned_to_its_key() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../vectors/publisher-event.json")).unwrap();
        let ev: Event = serde_json::from_value(v["event"].clone()).unwrap();
        let pubkey: &'static str = Box::leak(v["pubkey"].as_str().unwrap().to_string().into_boxed_str());
        let cert: &'static str = Box::leak(v["cert"].as_str().unwrap().to_string().into_boxed_str());
        let channel: &'static str = Box::leak(v["channel"].as_str().unwrap().to_string().into_boxed_str());
        let entry = CatalogEntry { channel, release_pubkey: Some(pubkey), cert: Some(cert), ..entry_for(&Keys::generate()) };
        let r = release_for(&entry, std::slice::from_ref(&ev)).unwrap().expect("accepted for the key it was signed by");
        assert_eq!((r.version.as_str(), r.size), (v["version"].as_str().unwrap(), v["size"].as_u64().unwrap()));
        // An entry pinned to another key does not accept it.
        let other = CatalogEntry { channel, ..entry_for(&Keys::generate()) };
        assert!(release_for(&other, std::slice::from_ref(&ev)).unwrap().is_none());
    }
}
