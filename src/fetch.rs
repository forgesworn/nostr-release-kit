//! Reading release events from relays: the one thing the kit leaves to the app.

use nostr::{Event, Filter};
use std::time::Duration;

/// What a read of the relays found, and how many of them really answered.
#[derive(Debug, Clone, Default)]
pub struct FetchReport {
    /// Stored events matching the filter, deduplicated by id.
    pub events: Vec<Event>,
    /// Relays that answered (sent EOSE themselves, or sent an event that was kept).
    /// A `CLOSED` is a refusal, not an answer.
    pub answered: usize,
    /// Relays asked.
    pub total: usize,
}

impl FetchReport {
    /// At least one relay answered. With no events, the answer was "nothing
    /// published"; without it, the relays could not be reached.
    pub fn reached(&self) -> bool {
        self.answered > 0
    }
}

/// A read in progress. The kit polls it from the app's frame loop; it must not block.
pub trait PendingFetch {
    /// The report, once (`None` until it is ready, and after it was taken).
    fn poll(&mut self) -> Option<FetchReport>;
}

/// A [`PendingFetch`] that is already done.
pub struct ReadyFetch(pub Option<FetchReport>);

impl PendingFetch for ReadyFetch {
    fn poll(&mut self) -> Option<FetchReport> {
        self.0.take()
    }
}

/// Reads events from relays, for the app's own relay code. One-shot: ask every
/// relay at once, take what is stored, hang up. The kit verifies every event
/// itself, so a fetcher needs no trust in the relays.
pub trait ReleaseFetcher {
    /// Start reading `filters` from `relays` (all at once; one REQ per relay carrying every
    /// filter, each with its own `limit`) and return at once; the report is the union of the
    /// events, delivered through the returned handle within about `timeout`.
    fn start(&mut self, relays: Vec<String>, filters: Vec<Filter>, timeout: Duration) -> Box<dyn PendingFetch>;
}

/// A relay URL as a comparison key: scheme and host in lower case, no default
/// port (`:443` for `wss`/`https`, `:80` for `ws`/`http`), no trailing `/`.
/// `wss://Nos.Lol`, `wss://nos.lol:443` and `wss://nos.lol/` are one relay.
pub fn normalize_relay_url(url: &str) -> String {
    let url = url.trim();
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.trim_end_matches('/').to_ascii_lowercase();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "wss" | "https" => ":443",
        "ws" | "http" => ":80",
        _ => "",
    };
    if !default_port.is_empty() && authority.ends_with(default_port) {
        authority.truncate(authority.len() - default_port.len());
    }
    format!("{scheme}://{authority}{}", path.trim_end_matches('/'))
}

/// Where to look for a release: the user's own relays in their order, then the
/// app's release relays they did not list, each once (by normalised address). A
/// relay can only carry the event, never forge it: the pinned release key signs it.
pub fn release_relays(user: &[String], release: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for u in user.iter().chain(release.iter()) {
        let key = normalize_relay_url(u);
        if !seen.contains(&key) {
            seen.push(key);
            out.push(u.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_addresses_compare_by_their_normal_form() {
        assert_eq!(normalize_relay_url("wss://Nos.Lol"), "wss://nos.lol");
        assert_eq!(normalize_relay_url("wss://nos.lol:443"), "wss://nos.lol");
        assert_eq!(normalize_relay_url("wss://nos.lol/"), "wss://nos.lol");
        assert_eq!(normalize_relay_url(" ws://x.example:80/p/ "), "ws://x.example/p");
        assert_eq!(normalize_relay_url("wss://x.example:8443"), "wss://x.example:8443");
        assert_eq!(normalize_relay_url("Bare.Host/"), "bare.host");
    }

    #[test]
    fn user_relays_come_first_and_each_relay_once() {
        let rel: Vec<String> = ["wss://relay.damus.io", "wss://nos.lol"].iter().map(|s| s.to_string()).collect();
        assert_eq!(release_relays(&[], &rel), rel);
        let user = vec!["wss://NOS.LOL:443/".to_string(), "wss://mine.example.com".to_string()];
        assert_eq!(release_relays(&user, &rel), vec!["wss://NOS.LOL:443/".to_string(), "wss://mine.example.com".to_string(), "wss://relay.damus.io".to_string()]);
    }

    #[test]
    fn a_ready_fetch_delivers_once() {
        let mut r = ReadyFetch(Some(FetchReport { events: vec![], answered: 1, total: 1 }));
        assert!(r.poll().is_some_and(|x| x.reached()));
        assert!(r.poll().is_none());
    }
}
