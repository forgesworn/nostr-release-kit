// Pure builders and checks for the release pipeline: no network, no filesystem,
// so `node --test` covers them exactly. Nothing app-specific lives here: the app
// supplies its channel, certificate pin and so on in a JSON config (loadConfig).
//
// The app's compiled-in trust anchor (the release key it pins in the Rust
// Config) is the source of truth for which pubkey is trusted; publish-release.mjs
// checks the key it loads against `release_pubkey` in the config before it signs
// anything, so keep the two equal.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';

export const SOFTWARE_RELEASE_KIND = 30063;
export const DEFAULT_RELEASE_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'];
/** BUD-02 Blossom upload authorization kind. */
export const BLOSSOM_AUTH_KIND = 24242;
/**
 * Default Blossom mirror set; `mirrors` in the config and --mirror add more.
 * Some mirrors only accept small blobs from keys that are not their users; probe a
 * mirror with a real APK-sized upload before relying on it.
 */
export const DEFAULT_BLOSSOM_MIRRORS = ['https://nostr.download'];

const U32_MAX = 4294967295;
/** The largest APK an announcement may name: the same cap as `MAX_APK_BYTES` in the Rust crate. */
export const MAX_APK_BYTES = 256 * 1024 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^[0-9]+$/;
/** https://host[:port]/<sha>[.ext], matched against the raw string (see isCanonicalBlossomUrl). */
const CANONICAL_URL = /^https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/([0-9a-f]{64})(?:\.[A-Za-z0-9]{1,8})?$/;
const CHANNEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PACKAGE = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/;

/**
 * Android versionCode of a `major.minor.patch` version: major * 1e6 + minor * 1e3 + patch.
 * Null when a part is missing, not a number, or overflows. Mirrors `version_code_of`
 * in the Rust crate (shared vectors).
 */
export function versionCodeOf(version) {
	if (typeof version !== 'string') return null;
	const parts = version.split('.');
	if (parts.length > 3) return null;
	const num = (s) => (/^[0-9]+$/.test(s) && s.length <= 9 ? Number(s) : NaN);
	const major = num(parts[0]);
	const minor = parts.length > 1 ? num(parts[1]) : 0;
	const patch = parts.length > 2 ? num(parts[2]) : 0;
	if ([major, minor, patch].some(Number.isNaN) || minor >= 1000 || patch >= 1000 || major > 2000) return null;
	return major * 1_000_000 + minor * 1_000 + patch;
}

/**
 * Validate and normalise an app's release config (the parsed JSON of `--config`).
 *
 *   channel               the `d` tag, e.g. "exampleapp-android-apk"            (required)
 *   package               the APK's package, e.g. "org.example.app"              (required)
 *   expected_cert_sha256  the signing certificate every release carries, 64 hex  (absent = a real publish refuses)
 *   release_pubkey        the release key the app pins, 64 hex                   (required for a real publish)
 *   key_file              the release secret key file (hex), "~/" allowed        \ one of the two
 *   key_file_env          name of an environment variable holding that path      / for key operations
 *   relays                release relays (default: three public ones)
 *   mirrors               Blossom servers (default: nostr.download)
 *   version_source        "flags" (default: --version and --version-code) or "semver" (code derived)
 *   blossom_note          text of the upload authorization (default: "Release artifact upload")
 */
export function loadConfig(raw) {
	if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('the config must be a JSON object');
	const known = new Set(['channel', 'package', 'expected_cert_sha256', 'release_pubkey', 'key_file', 'key_file_env', 'relays', 'mirrors', 'version_source', 'blossom_note']);
	for (const k of Object.keys(raw)) if (!known.has(k)) throw new Error(`unknown config field: ${k}`);
	if (typeof raw.channel !== 'string' || !CHANNEL.test(raw.channel)) throw new Error('config.channel is required (letters, digits, . _ -, at most 64)');
	if (typeof raw.package !== 'string' || !PACKAGE.test(raw.package)) throw new Error('config.package is required (an Android package name)');
	const optHex = (name) => {
		const v = raw[name];
		if (v === undefined || v === null) return null;
		if (typeof v !== 'string' || !HEX64.test(v)) throw new Error(`config.${name} must be 64 lowercase hex characters`);
		return v;
	};
	const versionSource = raw.version_source ?? 'flags';
	if (versionSource !== 'flags' && versionSource !== 'semver') throw new Error('config.version_source must be "flags" or "semver"');
	const list = (name, fallback) => {
		const v = raw[name];
		if (v === undefined) return fallback;
		if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) throw new Error(`config.${name} must be a list of strings`);
		return v;
	};
	for (const f of ['key_file', 'key_file_env', 'blossom_note']) {
		if (raw[f] !== undefined && (typeof raw[f] !== 'string' || raw[f] === '')) throw new Error(`config.${f} must be a non-empty string`);
	}
	return {
		channel: raw.channel,
		package: raw.package,
		expectedCert: optHex('expected_cert_sha256'),
		releasePubkey: optHex('release_pubkey'),
		keyFile: raw.key_file ?? null,
		keyFileEnv: raw.key_file_env ?? null,
		relays: list('relays', DEFAULT_RELEASE_RELAYS),
		mirrors: list('mirrors', DEFAULT_BLOSSOM_MIRRORS),
		versionSource,
		blossomNote: raw.blossom_note ?? 'Release artifact upload'
	};
}

/**
 * Guard for the APK's signing cert (the `cert` tag). Returns normally when the cert is
 * the expected one, or differs and `allowCertChange` is true (returns 'changed' so the
 * caller can warn); throws otherwise. `expected` null/undefined = no cert pinned yet: refuses.
 */
export function checkSigningCert(certSha256, allowCertChange, expected) {
	if (!HEX64.test(expected ?? '')) {
		throw new Error('expected_cert_sha256 is not set in the config yet; refusing to publish');
	}
	const got = typeof certSha256 === 'string' ? certSha256.toLowerCase() : certSha256;
	if (got === expected) return 'ok';
	if (allowCertChange === true) return 'changed';
	throw new Error(
		`the APK's signing certificate sha256 is ${certSha256}, not the expected ${expected}; ` +
			'installed copies cannot update to an APK signed with a different key. ' +
			'Refusing to publish (pass --allow-cert-change if the change is deliberate)'
	);
}

/**
 * A relay address for --relay / the environment: `wss://host[:port][/path]` or a
 * bare host (wss:// is added). Returns it normalised (lower-case host, no default
 * port, no trailing slash); throws on anything else (plain ws://, spaces, no dot).
 */
export function parseRelayUrl(input) {
	const bad = () => new Error(`bad relay ${JSON.stringify(input)}: use wss://host[:port][/path] or a bare host`);
	const t = String(input ?? '').trim();
	if (t === '' || /[\s\x00-\x1f]/.test(t)) throw bad();
	const m = /^(?:([A-Za-z][A-Za-z0-9+.-]*):\/\/)?([^/?#\\]*)((?:\/[^?#\\]*)?)$/.exec(t);
	if (!m) throw bad();
	const [, scheme, authority, path] = m;
	if (scheme !== undefined && scheme.toLowerCase() !== 'wss') throw bad();
	const hp = /^([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(authority);
	if (!hp) throw bad();
	const host = hp[1].toLowerCase();
	const labelOk = (l) => l !== '' && !l.startsWith('-') && !l.endsWith('-');
	if (!host.split('.').every(labelOk) || !(host.includes('.') || host === 'localhost')) throw bad();
	let port = hp[2];
	if (port !== undefined) {
		const n = Number(port);
		if (n < 1 || n > 65535) throw bad();
		if (n === 443) port = undefined;
	}
	return `wss://${host}${port ? `:${Number(port)}` : ''}${path.replace(/\/+$/, '')}`;
}

/**
 * The relays a release is announced on: `base` (the config's), then the extra ones
 * from the environment (comma-separated) and --relay, validated and deduped.
 */
export function resolveReleaseRelays(extra = [], envValue = '', base = DEFAULT_RELEASE_RELAYS) {
	const fromEnv = String(envValue ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter((s) => s !== '');
	const out = [];
	const seen = new Set();
	for (const u of [...base, ...fromEnv, ...extra]) {
		const n = parseRelayUrl(u);
		if (!seen.has(n)) {
			seen.add(n);
			out.push(n);
		}
	}
	return out;
}

/**
 * Does a raw Nostr relay frame TYPE ("EVENT" | "EOSE" | "CLOSED" | "NOTICE" |
 * …) count as the relay having ANSWERED a REQ? EVENT and EOSE do: the relay
 * actually responded to the query (some relays never send EOSE for a REQ they
 * immediately satisfy with EVENTs, so EVENT alone must count too). CLOSED
 * does NOT: it is how a relay reports a REFUSAL of the subscription itself
 * (`auth-required:`, `error:`, `rate-limited:`, …), not an answer to it. A
 * "no relay answered" gate depends on this being false for CLOSED: three relays
 * all refusing the REQ must read as "couldn't determine the latest release",
 * never as "none exists".
 */
export function isAnsweringFrameType(type) {
	return type === 'EVENT' || type === 'EOSE';
}

/** True for a 64-lowercase-hex string — the shape shared by `x` and `cert`. */
function isHex64(value) {
	return typeof value === 'string' && HEX64.test(value);
}

/** True for an already-typed positive integer (buildReleaseEvent's inputs). */
function isPositiveInteger(n) {
	return Number.isInteger(n) && n > 0;
}

/**
 * True for a tag value shaped like a positive integer: plain decimal digits
 * only — no sign, no leading `+`, no `1.5`/`1e2` — and safely representable
 * as a Number. Mirrors `parse_release` in the Rust crate, which takes
 * `version_code` (a u32) and `size` (a u64) as plain decimal digits;
 * summarizeReleaseEvent must reject anything that would make the device's gate
 * reject the event. `max` is the device's type limit (u32 for version_code).
 */
function isPositiveIntegerTag(raw, max = Number.MAX_SAFE_INTEGER) {
	return (
		typeof raw === 'string' &&
		raw.length <= 18 &&
		DECIMAL.test(raw) &&
		Number.isSafeInteger(Number(raw)) &&
		Number(raw) > 0 &&
		Number(raw) <= max
	);
}

/**
 * A URL a device may be told to fetch `sha256` from: https, and the blob at
 * the server ROOT, addressed by its own hash (`https://host/<sha>` or
 * `https://host/<sha>.<ext>`, BUD-01). That path is the one address a
 * Blossom server promises to keep serving. Anything else — in particular a
 * CDN redirect *target* — is an implementation detail that can vanish, and
 * a release pointing at one breaks for every device once it does.
 */
export function isCanonicalBlossomUrl(url, sha256) {
	if (typeof url !== 'string' || !HEX64.test(sha256 ?? '')) return false;
	// The RAW string, not a WHATWG-normalised URL: the device (is_canonical_blossom_url
	// in the Rust crate) matches the raw tag, and normalisation would accept
	// things it rejects (an IPv6 literal, `_` or IDN hosts, `\` as a separator,
	// stripped tabs and newlines). A mirror this passes, every device accepts.
	const m = CANONICAL_URL.exec(url);
	return m !== null && m[1] === sha256;
}

/**
 * Would a device follow a redirect to `url` (already resolved against the page
 * that redirected)? Mirrors `RedirectRule.allows` in the Java sources: https,
 * no userinfo, port absent or 443, and a host that is a plain DNS name — dotted,
 * letters/digits/hyphens, a top-level label that starts with a letter (so no IPv4
 * in any spelling), not `localhost`. The announcement never relies on a redirect
 * (see verifyMirror); this is the rule verifyMirror's redirect GATE applies.
 */
export function isPublicRedirectTarget(url) {
	if (typeof url !== 'string') return false;
	const m = /^https:\/\/([^/?#]*)(?:[/?#].*)?$/is.exec(url);
	if (!m) return false;
	const authority = m[1];
	if (authority === '' || authority.includes('@') || authority.endsWith(':')) return false;
	const colon = authority.indexOf(':');
	const host = (colon < 0 ? authority : authority.slice(0, colon)).toLowerCase();
	if (colon >= 0 && authority.slice(colon + 1) !== '443') return false;
	if (host === '' || host.length > 253 || host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) return false;
	const labels = host.split('.');
	for (const l of labels) {
		if (l === '' || l.length > 63 || l.startsWith('-') || l.endsWith('-') || !/^[a-z0-9-]+$/.test(l)) return false;
	}
	return /^[a-z]/.test(labels[labels.length - 1]);
}

/**
 * The `version` rule (parse_release): 1-32 bytes, no control characters.
 * Same bytes, same Unicode "Cc" class as Rust's `char::is_control`.
 */
export function isValidVersionName(v) {
	return typeof v === 'string' && v.length > 0 && Buffer.byteLength(v, 'utf8') <= 32 && !/\p{Cc}/u.test(v);
}

/**
 * The unsigned kind-30063 template announcing one artifact. Throws on any
 * invalid field — a malformed release event must never reach finalizeEvent.
 * The cert is always required: there is no artifact type here without a signing
 * certificate.
 */
export function buildReleaseEvent({
	channel,
	versionName,
	versionCode,
	sha256,
	sizeBytes,
	urls,
	certSha256,
	notes,
	createdAt
}) {
	if (typeof channel !== 'string' || !CHANNEL.test(channel)) throw new Error(`bad channel: ${channel}`);
	if (!isValidVersionName(versionName))
		throw new Error('versionName must be 1-32 bytes with no control characters');
	if (!isPositiveInteger(versionCode) || versionCode > U32_MAX)
		throw new Error('versionCode must be a positive integer that fits in 32 bits');
	if (!isHex64(sha256)) throw new Error('sha256 must be 64 lowercase hex chars');
	if (!isPositiveInteger(sizeBytes) || sizeBytes > MAX_APK_BYTES)
		throw new Error(`sizeBytes must be a positive integer of at most ${MAX_APK_BYTES} (the device's cap)`);
	if (!Array.isArray(urls) || urls.length === 0) throw new Error('at least one url required');
	for (const u of urls) {
		if (typeof u !== 'string' || !u.startsWith('https://'))
			throw new Error(`mirror url must be https: ${u}`);
		if (!isCanonicalBlossomUrl(u, sha256))
			throw new Error(
				`mirror url must be the blob's canonical root address (https://host/<sha>[.ext]): ${u}`
			);
	}
	if (!isHex64(certSha256)) throw new Error('certSha256 required (64 lowercase hex chars)');
	if (!Number.isInteger(createdAt) || createdAt <= 0) throw new Error('createdAt required');

	const tags = [
		['d', channel],
		['version', versionName],
		['version_code', String(versionCode)],
		['x', sha256],
		['size', String(sizeBytes)],
		['cert', certSha256]
	];
	for (const u of urls) tags.push(['url', u]);
	return {
		kind: SOFTWARE_RELEASE_KIND,
		created_at: createdAt,
		tags,
		content: notes ?? ''
	};
}

/**
 * The unsigned BUD-02 upload-authorization template. Signed with the release
 * key and sent as `Authorization: Nostr <base64(signed json)>` on the PUT.
 */
export function buildBlossomAuth({ sha256, createdAt, note = 'Release artifact upload' }) {
	if (!HEX64.test(sha256)) throw new Error('sha256 must be 64 lowercase hex chars');
	if (!Number.isInteger(createdAt) || createdAt <= 0) throw new Error('createdAt required');
	return {
		kind: BLOSSOM_AUTH_KIND,
		created_at: createdAt,
		tags: [
			['t', 'upload'],
			['x', sha256],
			['expiration', String(createdAt + 600)]
		],
		content: note
	};
}

/**
 * Parse a verified release event's tags into a plain summary object. Returns null
 * if the event doesn't look like a well-formed release on `channel` (the caller is
 * expected to have already run verifyEvent + pubkey checks).
 *
 * Enforces exactly the same tag shapes as the device's own gate, `parse_release`:
 * a non-empty `version`, a positive-integer `version_code`, a 64-lowercase-hex `x`
 * (sha256), a positive-integer `size`, a 64-lowercase-hex `cert`, and at least one
 * `url` tag that all pass `isCanonicalBlossomUrl` against that `x`. A summary this
 * function returns non-null for must be an event the device would also accept —
 * this is the operator-facing "did the publish land correctly" check, so it must
 * never be looser than the device's own verification.
 */
export function summarizeReleaseEvent(ev, channel) {
	if (typeof ev !== 'object' || ev === null) return null;
	const tags = Array.isArray(ev.tags) ? ev.tags : [];
	const get = (name) => tags.find((t) => t[0] === name)?.[1];

	const d = get('d');
	if (typeof channel !== 'string' || d !== channel) return null;

	const version = get('version');
	if (!isValidVersionName(version)) return null;

	const versionCodeRaw = get('version_code');
	if (!isPositiveIntegerTag(versionCodeRaw, U32_MAX)) return null;
	const versionCode = Number(versionCodeRaw);

	const sha256 = get('x');
	if (!isHex64(sha256)) return null;

	const sizeRaw = get('size');
	if (!isPositiveIntegerTag(sizeRaw, MAX_APK_BYTES)) return null;
	const sizeBytes = Number(sizeRaw);

	const certSha256 = get('cert');
	if (!isHex64(certSha256)) return null;

	const urls = tags.filter((t) => t[0] === 'url').map((t) => t[1]);
	if (urls.length === 0 || urls.some((u) => !isCanonicalBlossomUrl(u, sha256))) return null;

	return {
		id: ev.id,
		pubkey: ev.pubkey,
		createdAt: ev.created_at,
		channel: d,
		version,
		versionCode,
		sha256,
		sizeBytes,
		certSha256,
		urls,
		notes: ev.content ?? ''
	};
}

/**
 * True when `aapt2 dump badging` output carries the `application-debuggable` line:
 * the APK was built with android:debuggable, which a release must never be (any
 * app on the phone could attach to it).
 */
export function isDebuggableBadging(output) {
	return /^application-debuggable\s*$/m.test(String(output));
}

/**
 * The best release the channel currently carries, out of the raw events relays
 * returned: well-formed (`summarizeReleaseEvent`), by `pubkey`, of the release
 * kind, and with a signature `verify(event)` accepts. The highest versionCode
 * wins, as on the device. `verify` is passed in (nostr-tools' verifyEvent) to keep
 * this file free of dependencies. Null when there is none.
 */
export function bestCurrentRelease(events, pubkey, verify, channel) {
	let best = null;
	for (const ev of Array.isArray(events) ? events : []) {
		if (typeof ev !== 'object' || ev === null || ev.kind !== SOFTWARE_RELEASE_KIND || ev.pubkey !== pubkey) continue;
		const summary = summarizeReleaseEvent(ev, channel);
		if (summary === null || summary.pubkey !== pubkey) continue;
		let signed = false;
		try {
			signed = verify(ev) === true;
		} catch {
			/* a malformed event is not a release */
		}
		if (!signed) continue;
		if (best === null || summary.versionCode > best.versionCode) best = summary;
	}
	return best;
}

/**
 * Guard against announcing a release the channel's current one outranks (the device
 * only offers a higher versionCode, so an equal or lower one would never reach
 * anybody and could hide a mistake). `current` is `bestCurrentRelease`'s answer;
 * `anyAnswered` says whether any relay answered the query at all. Returns
 * 'newer', 'first' (relays answered, nothing published yet) or 'overridden'
 * (`allowOlder`); throws otherwise. With no answer from any relay it refuses,
 * since "nothing published" cannot be told from "could not look".
 */
export function checkVersionAdvance({ versionCode, current, anyAnswered, allowOlder = false }) {
	if (!isPositiveInteger(versionCode) || versionCode > U32_MAX) throw new Error('versionCode must be a positive integer that fits in 32 bits');
	if (allowOlder) return 'overridden';
	if (!anyAnswered) throw new Error('no relay answered, so the current release could not be checked; try again, or pass --allow-older to publish without the check');
	if (current === null || current === undefined) return 'first';
	if (versionCode <= current.versionCode)
		throw new Error(`versionCode ${versionCode} is not greater than the channel's current ${current.versionCode} (${current.version}); pass --allow-older to publish anyway`);
	return 'newer';
}

/** A device follows at most this many redirects (`MAX_REDIRECTS` in Updater.java). */
export const MAX_REDIRECTS = 4;

/**
 * A mirror's canonical address redirects somewhere a device would not follow (or
 * through more hops than it would take). The publish must stop: a release whose
 * download a phone refuses is not a release. Carries a message for the operator.
 */
export class RedirectRefused extends Error {
	constructor(message) {
		super(message);
		this.name = 'RedirectRefused';
	}
}

/** What a device does with a status: every 3xx is a redirect (Updater.java: `code / 100 == 3`). */
const isRedirectStatus = (status) => Number.isInteger(status) && Math.floor(status / 100) === 3;

/**
 * The redirect GATE. `url` answered with a redirect to `location`; walk the chain
 * the way a device does (Updater.java): each target is resolved against the page
 * that redirected and must pass isPublicRedirectTarget (RedirectRule.allows), and at
 * most MAX_REDIRECTS redirects are followed. Throws RedirectRefused on the first hop
 * a device would refuse, on a redirect without a Location, or past the hop cap.
 * `get(url)` performs ONE request with redirects not followed and returns
 * `{ status, location }`; it is injected so tests need no network. Returns
 * `{ hops, status }` where `status` is what the chain ended on.
 */
export async function checkRedirectChain(url, location, get) {
	let cur = url;
	let loc = location;
	for (let hop = 1; ; hop++) {
		if (loc === null || loc === undefined || loc === '') throw new RedirectRefused(`${cur} redirects without a Location, so a device cannot follow it`);
		if (hop > MAX_REDIRECTS) throw new RedirectRefused(`${url} redirects more than ${MAX_REDIRECTS} times; a device gives up after ${MAX_REDIRECTS}`);
		let target;
		try {
			target = new URL(loc, cur).toString();
		} catch {
			throw new RedirectRefused(`${cur} redirects to an unreadable address (${loc})`);
		}
		if (!isPublicRedirectTarget(target))
			throw new RedirectRefused(
				`${url} redirects to ${target}, which a device would refuse to follow (only https on port 443 at a plain DNS host name). ` +
					'Use a mirror that serves the blob itself, or one whose redirects go only to https on port 443 at a plain DNS host name'
			);
		const r = await get(target);
		if (!isRedirectStatus(r.status)) return { hops: hop, status: r.status };
		cur = target;
		loc = r.location;
	}
}

/**
 * Verify one Blossom mirror the way a DEVICE will use it: GET, no redirects, full-body
 * sha256. The event may only ever carry the blob's CANONICAL root address
 * (isCanonicalBlossomUrl), never a redirect target. A redirecting server still counts
 * as an upload success (the blob is there) but contributes no URL ("blob present, not
 * device-servable") PROVIDED a device would follow its redirects; if the redirect
 * chain leads somewhere a device would refuse, the publish is refused outright
 * (RedirectRefused; see checkRedirectChain). Returns the verified URL, or null.
 * `fetchFn` defaults to the global fetch; `log` receives operator-facing lines.
 */
export async function verifyMirror(server, sha256, { fetchFn = fetch, log = () => {} } = {}) {
	for (const url of [`${server}/${sha256}.apk`, `${server}/${sha256}`]) {
		const res = await fetchFn(url, { redirect: 'manual' });
		if (res.status === 200) {
			const got = createHash('sha256').update(Buffer.from(await res.arrayBuffer())).digest('hex');
			if (got !== sha256) {
				log(`mirror ${url}: serves WRONG bytes (${got})`);
				return null;
			}
			return url;
		}
		if (isRedirectStatus(res.status)) {
			const location = res.headers.get('location');
			await res.body?.cancel().catch(() => {});
			const get = async (u) => {
				const hop = await fetchFn(u, { redirect: 'manual' });
				await hop.body?.cancel().catch(() => {});
				return { status: hop.status, location: hop.headers.get('location') };
			};
			const chain = await checkRedirectChain(url, location, get);
			log(`mirror ${url}: blob present, not device-servable (redirects to ${location}; a device would follow it, ending on HTTP ${chain.status}, but the announcement needs a direct 200)`);
			continue;
		}
		await res.body?.cancel().catch(() => {});
		log(`mirror ${url}: HTTP ${res.status}`);
	}
	return null;
}

/**
 * The signing certificate digest out of `apksigner verify --print-certs` output. An APK
 * with more than one signer is refused (a device refuses it too: one signer, one pin), so
 * the announced cert is never one of several. Returns the lowercase hex digest.
 */
export function singleSignerCertSha256(apksignerOutput) {
	const found = [...String(apksignerOutput).matchAll(/Signer #(\d+) certificate SHA-256 digest:\s*([0-9a-fA-F]{64})/g)];
	if (found.length === 0)
		throw new Error(`could not parse a SHA-256 cert digest from apksigner output:\n${String(apksignerOutput).slice(0, 400)}`);
	if (found.length > 1 || found.some((m) => m[1] !== '1'))
		throw new Error(
			`the APK has ${found.length} signers (apksigner lists Signer #${found.map((m) => m[1]).join(', #')}); a release must have exactly one, so it is refused`
		);
	return found[0][2].toLowerCase();
}

/**
 * Read a 64-hex secret key from a file. Refuses a file that group or others can read
 * (the mode must be 0600 or stricter), and says so without printing anything of the
 * file's content.
 */
export function readSecretKeyFile(keyFile) {
	if (!existsSync(keyFile))
		throw new Error(`no release key at ${keyFile}; run: node publish-release.mjs --config <release.json> --init-key`);
	const mode = statSync(keyFile).mode & 0o777;
	if (process.platform !== 'win32' && (mode & 0o077) !== 0)
		throw new Error(
			`${keyFile} is readable by group or others (mode ${mode.toString(8).padStart(3, '0')}); the release key must be mode 0600 or stricter: chmod 600 it, or make a new key and re-pin it`
		);
	const hex = readFileSync(keyFile, 'utf8').trim();
	if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`${keyFile} is not a 64-hex secret`);
	return Uint8Array.from(Buffer.from(hex, 'hex'));
}
