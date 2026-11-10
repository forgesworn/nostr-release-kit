#!/usr/bin/env node
// Publish one app release: upload the APK to Blossom, verify the mirror the way a
// DEVICE will use it, then announce a signed kind-30063 event on the release relays.
// Everything that belongs to the app (channel, package, certificate pin, release
// key, relays, mirrors) comes from a JSON config; see README.md and loadConfig in
// release-helpers.mjs.
//
//   node publish-release.mjs --config release.json <apk> --version 0.2.0 [--version-code 2000] \
//     [--notes "..."] [--mirror https://extra.mirror] [--relay wss://extra.relay] [--dry-run] \
//     [--allow-cert-change] [--allow-older]
//   node publish-release.mjs --config release.json --init-key       # mint the release key once
//   node publish-release.mjs --config release.json --print-pubkey   # print the release key's PUBLIC half only (hex and npub)
//   node publish-release.mjs --self-test                            # sign + verify a sample, no files, no network
//
// What it checks before it signs anything:
//  * the release key (the file named by config.key_file_env / config.key_file) is the
//    one the app pins (config.release_pubkey, which must equal the key pinned in the
//    app's Rust Config). A real publish is refused while release_pubkey is unset:
//    mint the key with --init-key, then pin its public half in both places;
//  * --version-code and --version equal the APK's own versionCode / versionName
//    (`aapt2 dump badging`) and its package is config.package: the device only
//    offers an update whose version_code is higher than the installed one. With
//    config.version_source = "semver" the versionCode is derived from --version;
//  * the APK is not debuggable (`application-debuggable` in the badging);
//  * the signing certificate sha256 (the `cert` tag) comes from the APK itself
//    via `apksigner verify --print-certs`, never from the command line, and must be
//    config.expected_cert_sha256 unless --allow-cert-change is passed;
//  * the versionCode is strictly greater than the channel's current release, read from
//    the release relays (signature checked). If no relay answers it stops; --allow-older
//    overrides both that and a not-greater code. Read-only, so --dry-run does it too
//    (when config.release_pubkey is set).
//
// Exit non-zero when: no Blossom mirror served the bytes back at their
// canonical address with a direct 200 and a matching sha256; a mirror's canonical
// address redirects somewhere a device would refuse to follow (RedirectRule: https
// on 443 at a plain DNS host, at most four hops), which refuses the whole publish
// before anything is signed; or every relay refused the event. --dry-run signs and prints the event but never uploads
// or publishes (its only network use is the read-only current-release check). It
// signs with an EPHEMERAL throwaway key, never the release key (the file is not even
// read): the printed event is a valid-looking announcement that no device trusts, so
// pasting it anywhere cannot displace a real release.
//
// Env: ANDROID_HOME (default: Android/Sdk in the home directory),
//      RELEASE_KIT_APKSIGNER / RELEASE_KIT_AAPT2 (default: newest build-tools),
//      RELEASE_KIT_RELAYS (comma-separated extra relays, like --relay).
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { nip19 } from 'nostr-tools';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, chmodSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import {
	loadConfig,
	resolveReleaseRelays,
	buildBlossomAuth,
	buildReleaseEvent,
	checkSigningCert,
	isCanonicalBlossomUrl,
	RedirectRefused,
	verifyMirror,
	isDebuggableBadging,
	isAnsweringFrameType,
	bestCurrentRelease,
	checkVersionAdvance,
	versionCodeOf,
	readSecretKeyFile,
	singleSignerCertSha256,
	SOFTWARE_RELEASE_KIND
} from './release-helpers.mjs';

const USAGE =
	'usage: publish-release.mjs --config <release.json> <apk> --version <semver> [--version-code <int>] [--notes "..."] [--mirror <url>] [--relay <wss-url>] [--dry-run] [--allow-cert-change] [--allow-older]  |  --config <release.json> --init-key  |  --config <release.json> --print-pubkey  |  --self-test';

/** Newest build-tools directory under the Android SDK. */
function buildTool(envName, tool) {
	if (process.env[envName]) return process.env[envName];
	const sdk = process.env.ANDROID_HOME ?? join(homedir(), 'Android', 'Sdk');
	const dir = join(sdk, 'build-tools');
	const versions = existsSync(dir)
		? readdirSync(dir).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
		: [];
	if (versions.length === 0) throw new Error(`no Android build-tools under ${dir} (set ANDROID_HOME or ${envName})`);
	return join(dir, versions[versions.length - 1], tool);
}

/** The value after a flag; a missing one is an error, not `undefined`. */
function needValue(argv, i, flag) {
	if (i >= argv.length) throw new Error(`${flag} needs a value`);
	return argv[i];
}

function parseArgs(argv) {
	const args = { notes: '', mirrors: [], relays: [] };
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === '--dry-run') args.dryRun = true;
		else if (a === '--allow-cert-change') args.allowCertChange = true;
		else if (a === '--allow-older') args.allowOlder = true;
		else if (a === '--self-test') args.selfTest = true;
		else if (a === '--init-key') args.initKey = true;
		else if (a === '--print-pubkey') args.printPubkey = true;
		else if (a === '--config') args.configPath = needValue(argv, ++i, a);
		else if (a === '--version') args.version = needValue(argv, ++i, a);
		else if (a === '--version-code') args.versionCode = Number(needValue(argv, ++i, a));
		else if (a === '--notes') args.notes = needValue(argv, ++i, a);
		else if (a === '--mirror') args.mirrors.push(needValue(argv, ++i, a));
		else if (a === '--relay') args.relays.push(needValue(argv, ++i, a));
		else if (a.startsWith('-')) throw new Error(`unknown argument: ${a}`);
		else if (args.apkPath === undefined) args.apkPath = a;
		else throw new Error(`unexpected extra positional argument: ${a}`);
	}
	return args;
}

function readConfig(path) {
	let text;
	try {
		text = readFileSync(path, 'utf8');
	} catch (err) {
		throw new Error(`cannot read the config ${path}: ${err.message}`);
	}
	let raw;
	try {
		raw = JSON.parse(text);
	} catch (err) {
		throw new Error(`the config ${path} is not valid JSON: ${err.message}`);
	}
	return loadConfig(raw);
}

/** Where the release secret key lives: the environment variable the config names, else its key_file. */
function keyFileOf(cfg) {
	let path = cfg.keyFileEnv ? process.env[cfg.keyFileEnv] : undefined;
	path ??= cfg.keyFile ?? undefined;
	if (!path)
		throw new Error(
			`no release key file: set the ${cfg.keyFileEnv ?? 'key_file_env'} environment variable or key_file in the config`
		);
	return path.startsWith('~/') ? join(homedir(), path.slice(2)) : path;
}

/**
 * Tiny hermetic self-test: builds a sample release event with an ephemeral
 * throwaway key, signs it, and checks nostr-tools' own verifyEvent accepts
 * it. Touches no files, no network, no real release key.
 */
function runSelfTest() {
	const sk = generateSecretKey();
	const sha256 = 'a'.repeat(64);
	const event = finalizeEvent(
		buildReleaseEvent({
			channel: 'selftest-android-apk',
			versionName: '0.0.1',
			versionCode: 1,
			sha256,
			sizeBytes: 1234,
			urls: [`https://nostr.download/${sha256}.apk`],
			certSha256: 'b'.repeat(64),
			notes: 'self-test',
			createdAt: Math.floor(Date.now() / 1000)
		}),
		sk
	);
	const ok = verifyEvent(event);
	console.log(`self-test: built + signed a sample kind-${event.kind} event; verifyEvent = ${ok}`);
	if (!ok) {
		console.error('self-test FAILED: signed event did not verify');
		process.exit(1);
	}
	console.log('self-test PASSED');
}

/** Mint the release key once. Prints the public half only; the secret stays in the file. */
function initKey(cfg) {
	const keyFile = keyFileOf(cfg);
	if (existsSync(keyFile)) {
		console.log(`release key already exists at ${keyFile}`);
		printPubkey(getPublicKey(readKey(keyFile)));
		return;
	}
	// Only a directory made here gets 0700: never chmod one that was already there (a relative
	// key_file would make that the current directory, a key in /tmp would make it /tmp).
	const dir = dirname(keyFile);
	const made = !existsSync(dir);
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	if (made) chmodSync(dir, 0o700);
	const sk = generateSecretKey();
	// 'wx': never overwrite a key another run created in the meantime.
	writeFileSync(keyFile, Buffer.from(sk).toString('hex') + '\n', { mode: 0o600, flag: 'wx' });
	chmodSync(keyFile, 0o600);
	console.log(`generated a new release key at ${keyFile} (mode 0600; the secret is never printed)`);
	printPubkey(getPublicKey(sk));
}

function printPubkey(pk) {
	console.log(`  release pubkey (hex)  = ${pk}`);
	console.log(`  release pubkey (npub) = ${nip19.npubEncode(pk)}`);
	console.log('Pin the hex value in the app (the Rust Config release key) and set release_pubkey to it in the config.');
}

function readKey(keyFile) {
	return readSecretKeyFile(keyFile);
}

/**
 * The signing certificate's sha256, read from the APK itself via
 * `apksigner verify --print-certs`, so the announced cert can never drift from
 * what is actually on the artifact being announced.
 */
function certSha256FromApk(apkPath) {
	let out;
	try {
		out = execFileSync(buildTool('RELEASE_KIT_APKSIGNER', 'apksigner'), ['verify', '--print-certs', apkPath], {
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'pipe']
		});
	} catch (err) {
		throw new Error((err.stderr || err.message || '').toString().trim().split('\n')[0] || String(err));
	}
	return singleSignerCertSha256(out);
}

/** The APK's own package, versionCode, versionName and whether it is debuggable (`aapt2 dump badging`). */
function badgingOf(apkPath) {
	const out = execFileSync(buildTool('RELEASE_KIT_AAPT2', 'aapt2'), ['dump', 'badging', apkPath], {
		encoding: 'utf8',
		stdio: ['ignore', 'pipe', 'pipe']
	});
	const m = /^package: name='([^']*)' versionCode='(\d+)' versionName='([^']*)'/m.exec(out);
	if (!m) throw new Error(`could not read the package line from aapt2 output:\n${out.slice(0, 400)}`);
	return { name: m[1], versionCode: Number(m[2]), versionName: m[3], debuggable: isDebuggableBadging(out) };
}

async function uploadToBlossom(server, bytes, sha256, sk, note) {
	const auth = finalizeEvent(buildBlossomAuth({ sha256, createdAt: Math.floor(Date.now() / 1000), note }), sk);
	const header = `Nostr ${Buffer.from(JSON.stringify(auth)).toString('base64')}`;
	const res = await fetch(`${server}/upload`, {
		method: 'PUT',
		headers: {
			Authorization: header,
			'Content-Type': 'application/octet-stream',
			'X-SHA-256': sha256
		},
		body: bytes
	});
	if (!res.ok) throw new Error(`${server}: upload HTTP ${res.status}`);
}

function publishToRelay(url, event, timeoutMs = 10_000) {
	return new Promise((resolve) => {
		let settled = false;
		let ws;
		const done = (ok, reason) => {
			if (settled) return;
			settled = true;
			try {
				ws?.close();
			} catch {
				/* already closed */
			}
			resolve({ url, ok, reason });
		};
		try {
			ws = new WebSocket(url);
		} catch (err) {
			done(false, err.message);
			return;
		}
		const timer = setTimeout(() => done(false, 'timeout'), timeoutMs);
		ws.onopen = () => ws.send(JSON.stringify(['EVENT', event]));
		ws.onmessage = (m) => {
			try {
				const [type, id, ok, reason] = JSON.parse(m.data);
				if (type === 'OK' && id === event.id) {
					clearTimeout(timer);
					done(Boolean(ok), reason ?? '');
				}
			} catch {
				/* ignore non-JSON frames */
			}
		};
		ws.onerror = () => {
			clearTimeout(timer);
			done(false, 'socket error');
		};
		ws.onclose = () => {
			clearTimeout(timer);
			done(false, 'closed-before-ok');
		};
	});
}

/**
 * Ask each relay for the channel's current kind-30063 event(s) from `pubkey`
 * (read-only). `answered` is true when any relay replied to the query (EVENT or
 * EOSE; a CLOSED refusal does not count); `events` is everything returned, still to
 * be verified by the caller.
 */
function fetchChannelEvents(relayUrls, pubkey, channel, timeoutMs = 8000) {
	const filter = { kinds: [SOFTWARE_RELEASE_KIND], authors: [pubkey], '#d': [channel], limit: 10 };
	const one = (url) =>
		new Promise((resolve) => {
			const events = [];
			let answered = false;
			let settled = false;
			let ws;
			const done = () => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				try {
					ws?.close();
				} catch {
					/* already closed */
				}
				resolve({ answered, events });
			};
			const timer = setTimeout(done, timeoutMs);
			try {
				ws = new WebSocket(url);
			} catch {
				done();
				return;
			}
			ws.onopen = () => ws.send(JSON.stringify(['REQ', 'cur', filter]));
			ws.onmessage = (m) => {
				try {
					const frame = JSON.parse(m.data);
					if (isAnsweringFrameType(frame[0])) answered = true;
					if (frame[0] === 'EVENT' && frame[1] === 'cur') events.push(frame[2]);
					if (frame[0] === 'EOSE' || frame[0] === 'CLOSED') done();
				} catch {
					/* ignore non-JSON frames */
				}
			};
			ws.onerror = done;
			ws.onclose = done;
		});
	return Promise.all(relayUrls.map(one)).then((rs) => ({
		answered: rs.some((r) => r.answered),
		events: rs.flatMap((r) => r.events)
	}));
}

async function main() {
	const args = parseArgs(process.argv.slice(2));

	if (args.selfTest && args.apkPath === undefined && args.configPath === undefined) {
		runSelfTest();
		return;
	}
	if (args.configPath === undefined) throw new Error(`--config <release.json> is required\n${USAGE}`);
	const cfg = readConfig(args.configPath);

	if (args.initKey) {
		initKey(cfg);
		return;
	}
	if (args.printPubkey) {
		// The public half only: the secret is read to derive it and never printed or logged.
		const pk = getPublicKey(readKey(keyFileOf(cfg)));
		console.log(`release pubkey (hex)  = ${pk}`);
		console.log(`release pubkey (npub) = ${nip19.npubEncode(pk)}`);
		return;
	}
	if (args.selfTest) {
		runSelfTest();
		return;
	}

	if (args.apkPath === undefined) throw new Error(USAGE);
	if (typeof args.version !== 'string' || args.version.length === 0) throw new Error('--version is required');
	let versionCode = args.versionCode;
	if (cfg.versionSource === 'semver') {
		const derived = versionCodeOf(args.version);
		if (derived === null) throw new Error(`--version ${args.version} is not major.minor.patch within the versionCode scheme`);
		if (versionCode !== undefined && versionCode !== derived)
			throw new Error(`--version-code ${versionCode} but version ${args.version} gives versionCode ${derived} (version_source is "semver")`);
		versionCode = derived;
	}
	if (!Number.isInteger(versionCode) || versionCode <= 0)
		throw new Error('--version-code is required and must be a positive integer');
	if (!existsSync(args.apkPath)) throw new Error(`no such file: ${args.apkPath}`);
	// Guard: with no expected_cert_sha256 in the config a real publish refuses,
	// --allow-cert-change or not, before anything is read or sent; a dry run only warns.
	if (!args.dryRun && cfg.expectedCert === null)
		throw new Error('expected_cert_sha256 is not set in the config yet (no release keystore pinned); refusing to publish');
	// Validated before anything is signed or uploaded.
	const relays = resolveReleaseRelays(args.relays, process.env.RELEASE_KIT_RELAYS, cfg.relays);
	console.log(`relays: ${relays.join(' ')}`);

	// The APK must be what the flags say: the device compares the announced
	// version_code with the installed one, so a mismatch would strand or loop users.
	const badging = badgingOf(args.apkPath);
	if (badging.debuggable)
		throw new Error('the APK is debuggable (application-debuggable); a diagnostic build is never published');
	if (badging.name !== cfg.package) throw new Error(`the APK's package is ${badging.name}, not ${cfg.package}`);
	if (badging.versionCode !== versionCode)
		throw new Error(`--version-code ${versionCode} but the APK's versionCode is ${badging.versionCode}`);
	if (badging.versionName !== args.version)
		throw new Error(`--version ${args.version} but the APK's versionName is ${badging.versionName}`);
	console.log(`apk: ${badging.name} ${badging.versionName} (versionCode ${badging.versionCode})`);

	let sk;
	if (args.dryRun) {
		// Never the release key: a dry run's output gets pasted into tickets and fixtures,
		// and an event signed by the real key is a publishable release announcement.
		sk = generateSecretKey();
		console.log(`DRY RUN: signing with a throwaway key ${getPublicKey(sk)}, NOT the release key; the device would reject this event`);
	} else {
		sk = readKey(keyFileOf(cfg));
		const pk = getPublicKey(sk);
		if (cfg.releasePubkey === null)
			throw new Error("release_pubkey is not set in the config; pin this key's public half in the app and the config before publishing");
		if (cfg.releasePubkey !== pk) throw new Error(`the release key (${pk}) is not the one the config pins (${cfg.releasePubkey}); refusing to sign`);
		console.log(`release key: ${pk} (matches the pinned key)`);
	}

	// Read-only, so it runs under --dry-run too. The channel's events are the pinned release
	// key's (a dry run's throwaway key is not it, but the channel's current event is).
	const channelPubkey = args.dryRun ? cfg.releasePubkey : getPublicKey(sk);
	if (channelPubkey === null) {
		console.warn('WARNING: release_pubkey is not set in the config; the current-release check was skipped (a real publish would refuse)');
	} else {
		const found = await fetchChannelEvents(relays, channelPubkey, cfg.channel);
		const current = bestCurrentRelease(found.events, channelPubkey, verifyEvent, cfg.channel);
		const advance = checkVersionAdvance({ versionCode, current, anyAnswered: found.answered, allowOlder: args.allowOlder === true });
		console.log(
			current
				? `channel now carries ${current.version} (versionCode ${current.versionCode}); this release is versionCode ${versionCode}`
				: found.answered
					? 'no release on the channel yet'
					: 'no relay answered the check for the current release'
		);
		if (advance === 'overridden') console.warn('WARNING: --allow-older: not requiring a versionCode above the current one');
	}

	const bytes = readFileSync(args.apkPath);
	const sha256 = createHash('sha256').update(bytes).digest('hex');
	const sizeBytes = bytes.length; // the same bytes the hash covers
	console.log(`${args.apkPath}: sha256=${sha256} size=${sizeBytes}`);

	const cert = certSha256FromApk(args.apkPath);
	console.log(`signing certificate sha256: ${cert}`);
	if (args.dryRun && cfg.expectedCert === null)
		console.warn('WARNING: expected_cert_sha256 is not set in the config yet; a real publish would refuse. Dry run: the certificate was not compared');
	else if (checkSigningCert(cert, args.allowCertChange === true, cfg.expectedCert) === 'changed')
		console.warn(`WARNING: --allow-cert-change: the cert differs from ${cfg.expectedCert}; installed copies will not be able to update to this APK`);

	const servers = [...new Set([...cfg.mirrors, ...args.mirrors])].map((s) => s.replace(/\/$/, ''));
	// Before anything is uploaded (the BUD-02 auth must not cross in clear, and one bad
	// mirror must not get a release signed that every device then drops): each mirror must
	// be a bare https origin whose blob address the device accepts, byte for byte.
	for (const server of servers) {
		if (!isCanonicalBlossomUrl(`${server}/${sha256}`, sha256))
			throw new Error(`bad --mirror ${JSON.stringify(server)}: it must be https://host[:port] with no path`);
	}

	const urls = [];
	if (args.dryRun) {
		// No upload, no network: derive the canonical addresses the mirrors would serve.
		for (const s of servers) urls.push(`${s}/${sha256}.apk`);
	} else {
		let uploaded = 0;
		for (const server of servers) {
			try {
				await uploadToBlossom(server, bytes, sha256, sk, cfg.blossomNote);
				uploaded++;
				const verified = await verifyMirror(server, sha256, { log: (m) => console.error(m) });
				if (verified) {
					urls.push(verified);
					console.log(`mirror ok: ${verified}`);
				} else {
					console.error(`mirror ${server}: uploaded, but no device-servable URL`);
				}
			} catch (err) {
				if (err instanceof RedirectRefused) {
					// The redirect rule is a gate: a mirror whose address a phone cannot follow stops the publish.
					console.error(`mirror ${server}: ${err.message}\nrefusing to announce a release a device could not download`);
					process.exit(1);
				}
				console.error(`mirror FAILED: ${err.message}`);
			}
		}
		if (uploaded === 0) {
			console.error('no Blossom mirror accepted the upload; refusing to announce');
			process.exit(1);
		}
	}

	if (urls.length === 0) {
		console.error('no Blossom mirror serves these bytes at a canonical address; refusing to announce a release nothing can download');
		process.exit(1);
	}
	const bad = urls.filter((u) => !isCanonicalBlossomUrl(u, sha256));
	if (bad.length) {
		console.error(`refusing to announce non-canonical mirror url(s): ${bad.join(', ')}`);
		process.exit(1);
	}

	const event = finalizeEvent(
		buildReleaseEvent({
			channel: cfg.channel,
			versionName: args.version,
			versionCode,
			sha256,
			sizeBytes,
			urls: [...new Set(urls)],
			certSha256: cert,
			notes: args.notes,
			createdAt: Math.floor(Date.now() / 1000)
		}),
		sk
	);
	if (!verifyEvent(event)) throw new Error('internal error: the signed event does not verify');

	if (args.dryRun) {
		console.log('--dry-run: signed event follows; nothing uploaded or published');
		console.log(JSON.stringify(event, null, 2));
		return;
	}

	const results = await Promise.all(relays.map((r) => publishToRelay(r, event)));
	for (const r of results) {
		console.log(`${r.ok ? 'relay ok  ' : 'relay FAIL'}: ${r.url} ${r.reason ?? ''}`);
	}
	if (!results.some((r) => r.ok)) {
		console.error('every relay refused the release event');
		process.exit(1);
	}
	console.log(`announced ${cfg.channel} ${args.version} (code ${versionCode})`);
}

main().catch((err) => {
	console.error(err.message);
	process.exit(1);
});
