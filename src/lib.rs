//! Publish and verify app releases announced as Nostr kind-30063 events, and
//! check for and install updates (of the app itself, and of sibling apps from a
//! pinned catalog).
//!
//! * [`release`]: the pure rules. [`parse_release`] verifies one event,
//!   [`pick_latest`] chooses the newest, [`judge`] decides whether to offer it.
//! * [`catalog`]: the catalog of sibling apps, its trust rules, and [`Catalog`].
//! * [`updater`]: the [`Updater`] state machine for the app's own update.
//! * [`installer`]: the [`ApkInstaller`] trait the app implements (or takes
//!   from the `android` feature) to download and install an APK.
//! * [`fetch`]: the [`ReleaseFetcher`] trait the app implements to read events
//!   from relays.
//!
//! The `testing` cargo feature (off by default; this crate's own tests have it) adds the
//! screenshot/demo staging methods (`Updater::demo_offer`, ...). A shipped build must not
//! enable it. The [`testing`] doubles need no feature: they have no effect on trust.
//!
//! The `testing` feature must never be enabled for `target_os = "android"`: that is a compile error.
//!
//! The kit opens no sockets of its own and sends no identity: nothing is
//! fetched until the app asks.

#[cfg(all(feature = "testing", target_os = "android"))]
compile_error!(
    "nostr-release-kit: the `testing` feature stages made-up update state (including a throwaway release key) and must not be built for Android. \
     Enable it only for non-Android targets, e.g. under [target.'cfg(not(target_os = \"android\"))'.dependencies] with Cargo resolver 2."
);

pub mod catalog;
pub mod config;
pub mod fetch;
pub mod installer;
pub mod release;
pub mod testing;
pub mod updater;

#[cfg(feature = "android")]
pub mod android;

pub use catalog::{archive_ok, judge_archive, release_for, status_of, Catalog, CatalogConfig, CatalogEntry, CertMismatch, EntryStatus, Fetch};
pub use config::{Config, DEFAULT_CHECK_INTERVAL, DEFAULT_FETCH_TIMEOUT, DEFAULT_RELEASE_RELAYS, NOT_SET_UP};
pub use fetch::{normalize_relay_url, release_relays, FetchReport, PendingFetch, ReadyFetch, ReleaseFetcher};
pub use installer::{held_by_another, ApkInstaller, ApkJob, ApkStatus, ANOTHER_INSTALL, DIDNT_CHECK_OUT};
pub use release::{
    is_canonical_blossom_url, judge, parse_release, pick_latest, release_filter, version_code_of, Release, Verdict, MAX_APK_BYTES, RELEASE_KIND,
};
pub use updater::{OfferView, Target, UpdateTone, UpdateView, Updater};
