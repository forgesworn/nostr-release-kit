//! The pure rules: what a release announcement is, which one to believe, and
//! whether to offer it. No I/O, no state.
//!
//! A release is a signed kind-30063 event from one pinned release key. It names
//! the APK by SHA-256 and size, says which certificate signed it, and lists where
//! to download it (canonical Blossom URLs only). Nothing here trusts a relay.

use nostr::{Event, Filter, Kind, PublicKey};

/// Zapstore's "software release" kind number, used with this kit's own tag set.
pub const RELEASE_KIND: u16 = 30063;
/// The largest APK an announcement may name (a signed `size` above this is refused
/// whoever signed it: it would fill the cache partition). The publisher holds the
/// same cap.
pub const MAX_APK_BYTES: u64 = 256 * 1024 * 1024;

/// Android versionCode of a `major.minor.patch` version, `major * 1e6 +
/// minor * 1e3 + patch`. `None` when a part is missing, not a number, or
/// overflows the scheme.
pub fn version_code_of(version: &str) -> Option<u32> {
    let mut it = version.split('.');
    let major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next().unwrap_or("0").parse().ok()?;
    let patch: u32 = it.next().unwrap_or("0").parse().ok()?;
    if it.next().is_some() || minor >= 1000 || patch >= 1000 || major > 2000 {
        return None;
    }
    Some(major * 1_000_000 + minor * 1_000 + patch)
}

/// A verified release announcement.
#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub version: String,
    pub version_code: u32,
    /// APK SHA-256, lowercase hex.
    pub sha256: String,
    pub size: u64,
    /// SHA-256 of the APK's signing certificate, lowercase hex.
    pub cert: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub created_at: u64,
    pub(crate) event: Event,
}

impl Release {
    /// The signed event this release was read from.
    pub fn event(&self) -> &Event {
        &self.event
    }
}

/// An Android package name: at least two dot-separated segments, each a letter followed by
/// letters, digits or underscores, at most 255 bytes.
pub(crate) fn is_package_name(s: &str) -> bool {
    s.len() <= 255
        && s.split('.').count() >= 2
        && s.split('.').all(|seg| {
            let mut b = seg.bytes();
            b.next().is_some_and(|c| c.is_ascii_alphabetic()) && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 18 && s.bytes().all(|b| b.is_ascii_digit())
}

/// The value of the first tag called `name`.
fn tag_value<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.len() >= 2 && s[0] == name).then(|| s[1].as_str())
    })
}

/// Is `url` the blob's canonical Blossom address for `sha256`:
/// `https://host/<sha>` or `https://host/<sha>.<ext>` (BUD-01), with no query,
/// fragment or credentials? That is the one address a Blossom server promises
/// to keep serving; a CDN redirect target is not. Enforced here and in the
/// Node publisher, against the same vectors.
pub fn is_canonical_blossom_url(url: &str, sha256: &str) -> bool {
    if !is_hex64(sha256) {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => return false,
    };
    // Host (and an optional :port): letters, digits, dots, hyphens. No '@' (credentials), no spaces.
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return false;
    }
    if port.is_some_and(|p| p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    // Path is exactly "/<sha>" or "/<sha>.<1-8 alphanumerics>": no query, fragment or extra segments.
    let Some(name) = path.strip_prefix('/') else { return false };
    let (hash, ext) = match name.split_once('.') {
        Some((h, e)) => (h, Some(e)),
        None => (name, None),
    };
    hash == sha256 && ext.is_none_or(|e| (1..=8).contains(&e.len()) && e.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Verify and read one event, in this order: kind, `d` tag, id and signature,
/// signer == the pinned key, then strict tag shapes. Anything off is `None`
/// (the update check treats that as "no news", never as "behind").
pub fn parse_release(ev: &Event, pinned: &PublicKey, channel: &str) -> Option<Release> {
    if ev.kind != Kind::Custom(RELEASE_KIND) || tag_value(ev, "d") != Some(channel) {
        return None;
    }
    ev.verify().ok()?;
    if ev.pubkey != *pinned {
        return None;
    }
    let version = tag_value(ev, "version")?;
    if version.is_empty() || version.len() > 32 || version.chars().any(char::is_control) {
        return None;
    }
    let code = tag_value(ev, "version_code")?;
    if !is_decimal(code) {
        return None;
    }
    let version_code: u32 = code.parse().ok().filter(|c| *c > 0)?;
    let sha256 = tag_value(ev, "x")?;
    if !is_hex64(sha256) {
        return None;
    }
    let size = tag_value(ev, "size")?;
    if !is_decimal(size) {
        return None;
    }
    let size: u64 = size.parse().ok().filter(|s| (1..=MAX_APK_BYTES).contains(s))?;
    let cert = tag_value(ev, "cert")?;
    if !is_hex64(cert) {
        return None;
    }
    let urls: Vec<String> = ev
        .tags
        .iter()
        .filter_map(|t| {
            let s = t.as_slice();
            (s.len() >= 2 && s[0] == "url").then(|| s[1].clone())
        })
        .collect();
    if urls.is_empty() || urls.iter().any(|u| !is_canonical_blossom_url(u, sha256)) {
        return None;
    }
    Some(Release {
        version: version.to_string(),
        version_code,
        sha256: sha256.to_string(),
        size,
        cert: cert.to_string(),
        urls,
        notes: ev.content.clone(),
        created_at: ev.created_at.as_secs(),
        event: ev.clone(),
    })
}

/// The best verified announcement among `events`: the highest `version_code`
/// (a later `created_at` breaks a tie).
pub fn pick_latest(events: &[Event], pinned: &PublicKey, channel: &str) -> Option<Release> {
    events.iter().filter_map(|e| parse_release(e, pinned, channel)).max_by_key(|r| (r.version_code, r.created_at))
}

/// What the newest verified release means for this install.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Nothing verified to compare against (never checked, or no news).
    Unknown,
    /// The newest release is not above what is installed.
    UpToDate,
    /// A newer release, signed with this app's certificate: offer it.
    Offer(Release),
    /// A newer release, but signed with a different certificate: Android would
    /// refuse it, so it is not offered.
    DifferentKey(Release),
}

/// Decide on `latest`: offered only if its `version_code` is above
/// `installed` and its `cert` equals `own_cert`. An unknown own cert (no
/// platform support) skips the early check; Android's install-time signature
/// check is the one that counts.
pub fn judge(latest: Option<Release>, installed: u32, own_cert: Option<&str>) -> Verdict {
    match latest {
        None => Verdict::Unknown,
        Some(r) if r.version_code <= installed => Verdict::UpToDate,
        Some(r) if own_cert.is_some_and(|c| c != r.cert) => Verdict::DifferentKey(r),
        Some(r) => Verdict::Offer(r),
    }
}

/// The relay query for `channel`'s events from the pinned key.
pub fn release_filter(pinned: &PublicKey, channel: &str) -> Filter {
    Filter::new().kind(Kind::Custom(RELEASE_KIND)).author(*pinned).identifier(channel).limit(10)
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Signed-event fixtures shared by the tests.
    use super::*;
    use nostr::{EventBuilder, Keys, Tag};

    pub const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub const CERT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pub const CHANNEL: &str = "exampleapp-android-apk";

    pub fn tag(parts: &[&str]) -> Tag {
        Tag::parse(parts.iter().copied()).unwrap()
    }

    pub fn good_tags(code: u32) -> Vec<Tag> {
        vec![
            tag(&["d", CHANNEL]),
            tag(&["version", "0.2.0"]),
            tag(&["version_code", &code.to_string()]),
            tag(&["x", SHA]),
            tag(&["size", "27700000"]),
            tag(&["cert", CERT]),
            tag(&["url", &format!("https://nostr.download/{SHA}.apk")]),
        ]
    }

    pub fn sign(keys: &Keys, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(RELEASE_KIND), "Faster bands.").tags(tags).sign_with_keys(keys).unwrap()
    }

    /// `good_tags` with every tag called `name` replaced by `with` (or removed).
    pub fn changed(code: u32, name: &str, with: Option<&[&str]>) -> Vec<Tag> {
        let mut t: Vec<Tag> = good_tags(code).into_iter().filter(|t| t.as_slice()[0] != name).collect();
        if let Some(w) = with {
            t.push(tag(w));
        }
        t
    }

    pub fn parse(keys: &Keys, tags: Vec<Tag>) -> Option<Release> {
        parse_release(&sign(keys, tags), &keys.public_key(), CHANNEL)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use nostr::{EventBuilder, Keys};

    #[test]
    fn version_codes_follow_the_semver_scheme() {
        assert_eq!(version_code_of("0.1.0"), Some(1000));
        assert_eq!(version_code_of("0.2.0"), Some(2000));
        assert_eq!(version_code_of("1.2.3"), Some(1_002_003));
        assert_eq!(version_code_of("0.1"), Some(1000));
        assert_eq!(version_code_of("0.1000.0"), None);
        assert_eq!(version_code_of("0.1.0.4"), None);
        assert_eq!(version_code_of("x.1.0"), None);
        // Versions compare as their codes do.
        assert!(version_code_of("0.1.1").unwrap() > version_code_of("0.1.0").unwrap());
        assert!(version_code_of("0.2.0").unwrap() > version_code_of("0.1.999").unwrap());
        assert!(version_code_of("1.0.0").unwrap() > version_code_of("0.999.999").unwrap());
    }

    #[test]
    fn version_codes_match_the_shared_vectors() {
        // vectors/version-code-vectors.json is read by the Node publisher's tests too.
        let list: Vec<serde_json::Value> = serde_json::from_str(include_str!("../vectors/version-code-vectors.json")).unwrap();
        assert!(list.len() >= 10);
        for v in list {
            assert_eq!(version_code_of(v["version"].as_str().unwrap()).map(u64::from), v["code"].as_u64(), "{v}");
        }
    }

    #[test]
    fn a_good_event_parses() {
        let keys = Keys::generate();
        let r = parse(&keys, good_tags(2000)).expect("valid");
        assert_eq!((r.version.as_str(), r.version_code, r.size), ("0.2.0", 2000, 27_700_000));
        assert_eq!((r.sha256.as_str(), r.cert.as_str()), (SHA, CERT));
        assert_eq!(r.urls, vec![format!("https://nostr.download/{SHA}.apk")]);
        assert_eq!(r.notes, "Faster bands.");
    }

    #[test]
    fn another_signer_is_ignored() {
        let (pinned, other) = (Keys::generate(), Keys::generate());
        let ev = sign(&other, good_tags(2000));
        assert!(parse_release(&ev, &pinned.public_key(), CHANNEL).is_none());
    }

    #[test]
    fn a_bad_signature_or_id_is_ignored() {
        let keys = Keys::generate();
        let pinned = keys.public_key();
        let a = sign(&keys, good_tags(2000));
        let b = sign(&keys, good_tags(2001));
        // A genuine signature, but over a different event.
        let mut swapped = a.clone();
        swapped.sig = b.sig;
        assert!(parse_release(&a, &pinned, CHANNEL).is_some());
        assert!(parse_release(&swapped, &pinned, CHANNEL).is_none());
        // Content changed after signing: the id no longer matches.
        let mut edited = a.clone();
        edited.content = "Free money inside.".into();
        assert!(parse_release(&edited, &pinned, CHANNEL).is_none());
    }

    #[test]
    fn wrong_kind_or_channel_is_ignored() {
        let keys = Keys::generate();
        let other_kind = EventBuilder::new(Kind::Custom(30064), "").tags(good_tags(2000)).sign_with_keys(&keys).unwrap();
        assert!(parse_release(&other_kind, &keys.public_key(), CHANNEL).is_none());
        assert!(parse(&keys, changed(2000, "d", Some(&["d", "otherapp-android-apk"]))).is_none());
        assert!(parse(&keys, changed(2000, "d", None)).is_none());
    }

    #[test]
    fn only_canonical_blossom_urls_pass() {
        let ok = |u: &str| is_canonical_blossom_url(u, SHA);
        assert!(ok(&format!("https://nostr.download/{SHA}")));
        assert!(ok(&format!("https://nostr.download/{SHA}.apk")));
        assert!(ok(&format!("https://blossom.example.com:8443/{SHA}.apk")));
        for bad in [
            format!("http://nostr.download/{SHA}.apk"),
            format!("https://nostr.download/{SHA}.apk?x=1"),
            format!("https://nostr.download/{SHA}.apk#frag"),
            format!("https://user@nostr.download/{SHA}.apk"),
            format!("https://user:pw@nostr.download/{SHA}.apk"),
            format!("https://nostr.download/uploads/{SHA}.apk"),
            format!("https://nostr.download/{SHA}.apk/"),
            format!("https://nostr.download/{}.apk", "c".repeat(64)),
            format!("https://nostr.download/{SHA}.apk.exe"),
            format!("https://nostr.download/{SHA}."),
            format!("https://nostr.download/{}", &SHA[..63]),
            format!("https:///{SHA}.apk"),
            format!("https://nostr.download{SHA}"),
            "https://nostr.download".to_string(),
        ] {
            assert!(!ok(&bad), "{bad}");
        }
        assert!(!is_canonical_blossom_url(&format!("https://h/{}", "A".repeat(64)), &"A".repeat(64)), "uppercase hash");
    }

    #[test]
    fn a_non_canonical_url_rejects_the_whole_event() {
        let keys = Keys::generate();
        let mut tags = good_tags(2000);
        tags.push(tag(&["url", &format!("https://cdn.example.com/dl/{SHA}.apk?sig=1")]));
        assert!(parse(&keys, tags).is_none());
        // ...and so does having none.
        assert!(parse(&keys, changed(2000, "url", None)).is_none());
    }

    #[test]
    fn malformed_tags_reject_the_event() {
        let keys = Keys::generate();
        let upper = SHA.to_uppercase();
        let upper_x = ["x", upper.as_str()];
        let cases: Vec<(&str, Option<&[&str]>)> = vec![
            ("version", None),
            ("version", Some(&["version", ""])),
            ("version_code", None),
            ("version_code", Some(&["version_code", "0"])),
            ("version_code", Some(&["version_code", "+5"])),
            ("version_code", Some(&["version_code", "1.5"])),
            ("version_code", Some(&["version_code", "99999999999"])),
            ("x", Some(&["x", "short"])),
            ("x", Some(&upper_x)),
            ("size", Some(&["size", "0"])),
            ("size", Some(&["size", "-1"])),
            ("size", None),
            ("size", Some(&["size", "268435457"])),
            ("size", Some(&["size", "999999999999999999"])),
            ("cert", None),
            ("cert", Some(&["cert", "nope"])),
        ];
        for (name, with) in cases {
            assert!(parse(&keys, changed(2000, name, with)).is_none(), "{name} -> {with:?}");
        }
    }

    #[test]
    fn the_highest_version_code_wins_and_invalid_events_never_do() {
        let keys = Keys::generate();
        let impostor = Keys::generate();
        let events = vec![
            sign(&keys, good_tags(2000)),
            sign(&keys, good_tags(3000)),
            sign(&keys, good_tags(2500)),
            // Higher, but not ours / not valid.
            sign(&impostor, good_tags(9000)),
            sign(&keys, changed(8000, "cert", Some(&["cert", "zz"]))),
        ];
        let best = pick_latest(&events, &keys.public_key(), CHANNEL).unwrap();
        assert_eq!(best.version_code, 3000);
        assert!(pick_latest(&[], &keys.public_key(), CHANNEL).is_none());
        assert!(pick_latest(&events[3..], &keys.public_key(), CHANNEL).is_none());
    }

    #[test]
    fn judge_offers_only_a_newer_release_signed_with_our_cert() {
        let keys = Keys::generate();
        let release = |code| parse(&keys, good_tags(code)).unwrap();
        assert!(matches!(judge(Some(release(2000)), 1000, Some(CERT)), Verdict::Offer(r) if r.version_code == 2000));
        // Equal and older are not offered.
        assert!(matches!(judge(Some(release(1000)), 1000, Some(CERT)), Verdict::UpToDate));
        assert!(matches!(judge(Some(release(999)), 1000, Some(CERT)), Verdict::UpToDate));
        // Another certificate is never offered.
        assert!(matches!(judge(Some(release(2000)), 1000, Some(&"c".repeat(64))), Verdict::DifferentKey(_)));
        // An app that cannot read its own cert skips that early check (Android still enforces it).
        assert!(matches!(judge(Some(release(2000)), 1000, None), Verdict::Offer(_)));
        assert!(matches!(judge(None, 1000, Some(CERT)), Verdict::Unknown));
    }

    #[test]
    fn the_largest_announced_size_is_capped() {
        let keys = Keys::generate();
        assert_eq!(parse(&keys, changed(2000, "size", Some(&["size", "268435456"]))).map(|r| r.size), Some(MAX_APK_BYTES));
        assert!(parse(&keys, changed(2000, "size", Some(&["size", "268435457"]))).is_none());
    }

    #[test]
    fn the_filters_name_the_key_and_channel() {
        use nostr::util::JsonUtil;
        let k = Keys::generate().public_key();
        let json = release_filter(&k, CHANNEL).try_as_json().unwrap();
        assert!(json.contains("30063") && json.contains(CHANNEL) && json.contains(&k.to_hex()), "{json}");
    }

    #[test]
    fn the_url_grammar_matches_the_shared_vectors() {
        // vectors/url-vectors.json is read by the Node publisher's tests too: one grammar, two implementations.
        let list: Vec<serde_json::Value> = serde_json::from_str(include_str!("../vectors/url-vectors.json")).unwrap();
        assert!(list.len() > 20);
        for v in list {
            let url = v["url"].as_str().unwrap().replace("<sha>", SHA).replace("<SHAUP>", &SHA.to_uppercase());
            assert_eq!(is_canonical_blossom_url(&url, SHA), v["ok"].as_bool().unwrap(), "{url:?}");
        }
    }

    #[test]
    fn an_event_from_the_node_publisher_verifies_here() {
        // vectors/publisher-event.json was built by the publisher's own code path
        // (`buildReleaseEvent` + nostr-tools `finalizeEvent`) with a THROWAWAY key whose secret was
        // discarded. Never commit an event signed by a real release key: it would be a publishable announcement.
        let v: serde_json::Value = serde_json::from_str(include_str!("../vectors/publisher-event.json")).unwrap();
        let ev: Event = serde_json::from_value(v["event"].clone()).unwrap();
        let pinned = PublicKey::from_hex(v["pubkey"].as_str().unwrap()).unwrap();
        let channel = v["channel"].as_str().unwrap();
        let r = parse_release(&ev, &pinned, channel).expect("the kit accepts what the publisher signs");
        assert_eq!((r.version.as_str(), r.version_code), (v["version"].as_str().unwrap(), v["version_code"].as_u64().unwrap() as u32));
        assert_eq!(r.size, v["size"].as_u64().unwrap());
        assert_eq!(r.notes, v["notes"].as_str().unwrap());
        // Another pinned key does not trust it, nor does another channel.
        assert!(parse_release(&ev, &Keys::generate().public_key(), channel).is_none());
        assert!(parse_release(&ev, &pinned, "otherapp-android-apk").is_none());
        // The same event is not offered to an install that already has it.
        assert!(matches!(judge(Some(r.clone()), r.version_code, Some(&r.cert)), Verdict::UpToDate));
    }
}
