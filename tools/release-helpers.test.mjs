import { test } from 'node:test';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, statSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import {
  SOFTWARE_RELEASE_KIND,
  DEFAULT_RELEASE_RELAYS,
  buildBlossomAuth,
  buildReleaseEvent,
  bestCurrentRelease,
  checkSigningCert,
  checkVersionAdvance,
  isAnsweringFrameType,
  isCanonicalBlossomUrl,
  isDebuggableBadging,
  isPublicRedirectTarget,
  isValidVersionName,
  loadConfig,
  MAX_APK_BYTES,
  RedirectRefused,
  readSecretKeyFile,
  singleSignerCertSha256,
  verifyMirror,
  parseRelayUrl,
  resolveReleaseRelays,
  summarizeReleaseEvent,
  versionCodeOf
} from './release-helpers.mjs';

const CHANNEL = 'exampleapp-android-apk';
const SHA = 'a'.repeat(64);
const CERT = 'b'.repeat(64);
const PUBLISHER = new URL('./publish-release.mjs', import.meta.url).pathname;
const vector = (name) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8'));
const ok = {
  channel: CHANNEL,
  versionName: '0.1.0',
  versionCode: 1,
  sha256: SHA,
  sizeBytes: 27693181,
  urls: [`https://blossom.example.net/${SHA}.apk`],
  certSha256: CERT,
  notes: 'notes',
  createdAt: 1757000000
};

test('buildReleaseEvent emits the tags in the agreed order', () => {
  const ev = buildReleaseEvent(ok);
  assert.equal(ev.kind, SOFTWARE_RELEASE_KIND);
  assert.deepEqual(ev.tags, [
    ['d', CHANNEL],
    ['version', '0.1.0'],
    ['version_code', '1'],
    ['x', SHA],
    ['size', '27693181'],
    ['cert', CERT],
    ['url', `https://blossom.example.net/${SHA}.apk`]
  ]);
  assert.equal(ev.content, 'notes');
});

test('buildReleaseEvent refuses anything malformed, naming the field', () => {
  for (const [bad, want] of [
    [{ channel: 'has space' }, /bad channel/],
    [{ channel: '' }, /bad channel/],
    [{ versionName: '' }, /versionName/],
    [{ versionName: 'x'.repeat(33) }, /versionName/],
    [{ versionName: '1.0\n' }, /versionName/],
    [{ versionCode: 0 }, /versionCode/],
    [{ versionCode: 1.5 }, /versionCode/],
    [{ versionCode: 4294967296 }, /versionCode/],
    [{ sha256: 'short' }, /sha256/],
    [{ sizeBytes: 0 }, /sizeBytes/],
    [{ sizeBytes: MAX_APK_BYTES + 1 }, /sizeBytes/],
    [{ urls: [] }, /at least one url/],
    [{ urls: [`http://h/${SHA}`] }, /must be https/],
    [{ urls: [`https://h/uploads/${SHA}`] }, /canonical root address/],
    [{ urls: [`https://blossom_x.example/${SHA}`] }, /canonical root address/],
    [{ certSha256: 'nope' }, /certSha256/],
    [{ createdAt: 0 }, /createdAt/]
  ]) {
    assert.throws(() => buildReleaseEvent({ ...ok, ...bad }), want, JSON.stringify(bad));
  }
});

// The same list the Rust crate reads (is_canonical_blossom_url): one grammar, two implementations.
test('isCanonicalBlossomUrl agrees with the shared vector list the Rust crate tests against', () => {
  const vectors = vector('url-vectors.json');
  assert.ok(vectors.length > 20);
  for (const { url, ok: want } of vectors) {
    const u = url.replaceAll('<sha>', SHA).replaceAll('<SHAUP>', SHA.toUpperCase());
    assert.equal(isCanonicalBlossomUrl(u, SHA), want, JSON.stringify(u));
  }
});

test('versionCodeOf agrees with the shared vector list the Rust crate tests against', () => {
  const vectors = vector('version-code-vectors.json');
  assert.ok(vectors.length >= 10);
  for (const { version, code } of vectors) assert.equal(versionCodeOf(version), code, JSON.stringify(version));
});

test('an event built by the publisher verifies and summarises; the shared publisher vector is one', () => {
  const v = vector('publisher-event.json');
  assert.equal(verifyEvent(v.event), true, 'the vector is genuinely signed');
  assert.equal(v.event.pubkey, v.pubkey);
  const s = summarizeReleaseEvent(v.event, v.channel);
  assert.equal(s.version, v.version);
  assert.equal(s.versionCode, v.version_code);
  assert.equal(s.sizeBytes, v.size);
  assert.equal(s.certSha256, v.cert);
  assert.equal(summarizeReleaseEvent(v.event, 'other-android-apk'), null);
});

test('isValidVersionName: 1-32 bytes, no control characters', () => {
  assert.equal(isValidVersionName('0.2.0'), true);
  assert.equal(isValidVersionName('x'.repeat(32)), true);
  assert.equal(isValidVersionName('x'.repeat(33)), false);
  assert.equal(isValidVersionName('é'.repeat(17)), false, 'bytes, not characters');
  assert.equal(isValidVersionName('1.0\u0007'), false);
  assert.equal(isValidVersionName('1.0\u0085'), false);
  assert.equal(isValidVersionName(''), false);
});

test('isCanonicalBlossomUrl accepts only the blob root address', () => {
  assert.equal(isCanonicalBlossomUrl(`https://h/${SHA}`, SHA), true);
  assert.equal(isCanonicalBlossomUrl(`https://h/${SHA}.apk`, SHA), true);
  assert.equal(isCanonicalBlossomUrl(`https://h/${SHA}?x=1`, SHA), false);
  assert.equal(isCanonicalBlossomUrl(`https://h/a/b/${SHA}`, SHA), false);
  assert.equal(isCanonicalBlossomUrl(`http://h/${SHA}`, SHA), false);
});

test('CLOSED is a refusal, not an answer', () => {
  assert.equal(isAnsweringFrameType('EVENT'), true);
  assert.equal(isAnsweringFrameType('EOSE'), true);
  assert.equal(isAnsweringFrameType('CLOSED'), false);
  assert.equal(isAnsweringFrameType('NOTICE'), false);
});

test('buildBlossomAuth is a BUD-02 upload template that expires', () => {
  const a = buildBlossomAuth({ sha256: SHA, createdAt: 1757000000 });
  assert.equal(a.kind, 24242);
  assert.deepEqual(a.tags, [
    ['t', 'upload'],
    ['x', SHA],
    ['expiration', String(1757000000 + 600)]
  ]);
  assert.equal(buildBlossomAuth({ sha256: SHA, createdAt: 1757000000, note: 'n' }).content, 'n');
  assert.throws(() => buildBlossomAuth({ sha256: 'short', createdAt: 1 }));
});

test('summarizeReleaseEvent extracts the fields a release checker prints', () => {
  const ev = { ...buildReleaseEvent(ok), id: 'deadbeef', pubkey: 'f'.repeat(64) };
  const summary = summarizeReleaseEvent(ev, CHANNEL);
  assert.equal(summary.version, '0.1.0');
  assert.equal(summary.versionCode, 1);
  assert.equal(summary.sha256, SHA);
  assert.equal(summary.certSha256, CERT);
  assert.deepEqual(summary.urls, [`https://blossom.example.net/${SHA}.apk`]);
});

test('summarizeReleaseEvent rejects a wrong channel or missing version_code', () => {
  const wrongChannel = { ...buildReleaseEvent(ok) };
  wrongChannel.tags = wrongChannel.tags.map((t) => (t[0] === 'd' ? ['d', 'other-apk'] : t));
  assert.equal(summarizeReleaseEvent(wrongChannel, CHANNEL), null);
  assert.equal(summarizeReleaseEvent({ tags: [] }, CHANNEL), null);
  assert.equal(summarizeReleaseEvent(null, CHANNEL), null);
});

// Replaces the value of the first `name` tag on a freshly-built `ok` event —
// used to probe summarizeReleaseEvent with exactly one malformed field at a
// time, the same way parse_release in the Rust crate rejects one bad tag.
function withTag(name, value) {
  const ev = buildReleaseEvent(ok);
  ev.tags = ev.tags.map((t) => (t[0] === name ? [name, value] : t));
  return ev;
}

test('summarizeReleaseEvent rejects everything the device gate (parse_release) rejects', () => {
  const sum = (ev) => summarizeReleaseEvent(ev, CHANNEL);
  // sha256 (`x` tag): must be 64 lowercase hex chars, same as buildReleaseEvent's own check.
  assert.equal(sum(withTag('x', 'short')), null);
  assert.equal(sum(withTag('x', 'A'.repeat(64))), null, 'uppercase hex is not lowercase hex');

  // cert: must be 64 lowercase hex chars.
  assert.equal(sum(withTag('cert', 'nope')), null);
  assert.equal(sum(withTag('cert', 'C'.repeat(64))), null, 'uppercase hex is not lowercase hex');

  // size: must be a positive integer, encoded as a plain decimal tag string.
  assert.equal(sum(withTag('size', '0')), null);
  assert.equal(sum(withTag('size', '-1')), null);
  assert.equal(sum(withTag('size', '1.5')), null);
  assert.equal(sum(withTag('size', 'abc')), null);
  // ... and at most the device's cap (MAX_APK_BYTES in the Rust crate).
  assert.equal(sum(withTag('size', String(MAX_APK_BYTES + 1))), null);
  assert.equal(sum(withTag('size', String(MAX_APK_BYTES)))?.sizeBytes, MAX_APK_BYTES);

  // version_code: same shape requirement as size.
  assert.equal(sum(withTag('version_code', '0')), null);
  assert.equal(sum(withTag('version_code', '1.5')), null);
  assert.equal(sum(withTag('version_code', '4294967296')), null, 'version_code is a u32 on the device');
  assert.notEqual(sum(withTag('version_code', '4294967295')), null);

  // version: must be present and non-empty, at most 32 bytes, no control characters, as parse_release requires.
  assert.equal(sum(withTag('version', '')), null);
  assert.equal(sum(withTag('version', 'x'.repeat(33))), null);
  assert.equal(sum(withTag('version', '1.0\n')), null);

  // url: every url tag must pass isCanonicalBlossomUrl against the event's own sha256 —
  // a CDN path, not the blob's canonical root address, is rejected.
  const nonCanonical = buildReleaseEvent(ok);
  nonCanonical.tags = nonCanonical.tags.map((t) => (t[0] === 'url' ? ['url', `https://h/uploads/${SHA}`] : t));
  assert.equal(sum(nonCanonical), null);

  const noUrls = buildReleaseEvent(ok);
  noUrls.tags = noUrls.tags.filter((t) => t[0] !== 'url');
  assert.equal(sum(noUrls), null);
});

test('with no expected certificate in the config a publish refuses, whatever the cert', () => {
  assert.throws(() => checkSigningCert(CERT, false, null), /not set in the config/);
  assert.throws(() => checkSigningCert(CERT, true, undefined), /not set in the config/);
  assert.throws(() => checkSigningCert(CERT, false, 'UNSET-fill-in'), /not set in the config/);
});

test('the signing cert guard accepts the expected cert and refuses any other', () => {
  const EXPECTED = 'c'.repeat(64);
  assert.equal(checkSigningCert(EXPECTED, false, EXPECTED), 'ok');
  assert.equal(checkSigningCert(EXPECTED.toUpperCase(), false, EXPECTED), 'ok');
  assert.throws(() => checkSigningCert(CERT, false, EXPECTED), /signing certificate.*--allow-cert-change/s);
  assert.throws(() => checkSigningCert(CERT, 'yes', EXPECTED), /Refusing to publish/);
  assert.throws(() => checkSigningCert(undefined, false, EXPECTED), /Refusing to publish/);
});

test('--allow-cert-change overrides the guard for a changed cert only', () => {
  const EXPECTED = 'c'.repeat(64);
  assert.equal(checkSigningCert(CERT, true, EXPECTED), 'changed');
  assert.equal(checkSigningCert(EXPECTED, true, EXPECTED), 'ok');
});

test('relay addresses are validated and normalised', () => {
  assert.equal(parseRelayUrl('wss://Relay.Example.com/'), 'wss://relay.example.com');
  assert.equal(parseRelayUrl('relay.example.com'), 'wss://relay.example.com');
  assert.equal(parseRelayUrl(' relay.example.com:7777/nostr/ '), 'wss://relay.example.com:7777/nostr');
  assert.equal(parseRelayUrl('wss://relay.example.com:443'), 'wss://relay.example.com');
  for (const bad of ['', '  ', 'relay', 'ws://relay.example.com', 'https://relay.example.com', 'wss://', 'a b.com', 'a..b.com', '-a.com', 'a.com:0', 'a.com:70000', 'a.com/x?y=1', 'a.com#f']) {
    assert.throws(() => parseRelayUrl(bad), /bad relay/, JSON.stringify(bad));
  }
});

test('extra relays from the environment and --relay are added after the config relays, deduped', () => {
  assert.deepEqual(resolveReleaseRelays(), DEFAULT_RELEASE_RELAYS);
  const got = resolveReleaseRelays(['mine.example.com', 'wss://NOS.LOL/', 'wss://flag.example.org'], 'env1.example.com, wss://mine.example.com/ ,');
  assert.deepEqual(got, [...DEFAULT_RELEASE_RELAYS, 'wss://env1.example.com', 'wss://mine.example.com', 'wss://flag.example.org']);
  assert.deepEqual(resolveReleaseRelays([], '', ['wss://only.example.com']), ['wss://only.example.com']);
  assert.throws(() => resolveReleaseRelays(['ws://plain.example.com']), /bad relay/);
  assert.throws(() => resolveReleaseRelays([], 'ok.example.com,nonsense'), /bad relay/);
});

test('a config is validated and normalised', () => {
  const c = loadConfig({ channel: CHANNEL, package: 'org.example.app' });
  assert.equal(c.channel, CHANNEL);
  assert.equal(c.expectedCert, null);
  assert.equal(c.releasePubkey, null);
  assert.equal(c.versionSource, 'flags');
  assert.deepEqual(c.relays, DEFAULT_RELEASE_RELAYS);
  assert.deepEqual(c.mirrors, ['https://nostr.download']);
  const full = loadConfig({
    channel: CHANNEL,
    package: 'org.example.app',
    expected_cert_sha256: CERT,
    release_pubkey: 'd'.repeat(64),
    key_file_env: 'EXAMPLE_KEY_FILE',
    key_file: '~/keys/release.hex',
    relays: ['wss://r.example.com'],
    mirrors: ['https://m.example.net'],
    version_source: 'semver'
  });
  assert.equal(full.expectedCert, CERT);
  assert.equal(full.versionSource, 'semver');
  assert.equal(full.keyFileEnv, 'EXAMPLE_KEY_FILE');
  for (const [bad, want] of [
    [null, /JSON object/],
    [[], /JSON object/],
    [{ package: 'org.example.app' }, /channel/],
    [{ channel: 'bad channel', package: 'org.example.app' }, /channel/],
    [{ channel: CHANNEL }, /package/],
    [{ channel: CHANNEL, package: 'nodots' }, /package/],
    [{ channel: CHANNEL, package: 'org.example.app', expected_cert_sha256: 'ABC' }, /expected_cert_sha256/],
    [{ channel: CHANNEL, package: 'org.example.app', release_pubkey: 'short' }, /release_pubkey/],
    [{ channel: CHANNEL, package: 'org.example.app', version_source: 'git' }, /version_source/],
    [{ channel: CHANNEL, package: 'org.example.app', relays: 'wss://x' }, /relays/],
    [{ channel: CHANNEL, package: 'org.example.app', surprise: 1 }, /unknown config field/]
  ]) {
    assert.throws(() => loadConfig(bad), want, JSON.stringify(bad));
  }
});

test('a debuggable APK is recognised from aapt2 badging output', () => {
  const base = [
    "package: name='org.example.app' versionCode='8019' versionName='0.8.19' platformBuildVersionName='15'",
    "sdkVersion:'26'",
    "application-label:'Example App'",
    "application: label='Example App' icon='res/mipmap/ic_launcher.png'"
  ];
  assert.equal(isDebuggableBadging(base.join('\n')), false);
  assert.equal(isDebuggableBadging([...base, 'application-debuggable'].join('\n') + '\n'), true);
  assert.equal(isDebuggableBadging(['application-debuggable', ...base].join('\r\n')), true);
  // Only the flag line counts, not a label that happens to say so.
  assert.equal(isDebuggableBadging("application-label:'application-debuggable'"), false);
  assert.equal(isDebuggableBadging(''), false);
});

test("a new release must have a strictly greater versionCode than the channel's current one", () => {
  const cur = (versionCode) => ({ versionCode, version: '0.8.19' });
  // greater: fine
  assert.equal(checkVersionAdvance({ versionCode: 8020, current: cur(8019), anyAnswered: true }), 'newer');
  // equal and lower: refused, with the numbers in the message
  assert.throws(() => checkVersionAdvance({ versionCode: 8019, current: cur(8019), anyAnswered: true }), /versionCode 8019 is not greater than the channel's current 8019/);
  assert.throws(() => checkVersionAdvance({ versionCode: 8018, current: cur(8019), anyAnswered: true }), /versionCode 8018 is not greater than the channel's current 8019/);
  // nothing published yet, but the relays did answer: a first release is fine
  assert.equal(checkVersionAdvance({ versionCode: 1, current: null, anyAnswered: true }), 'first');
  // no relay answered: stop, whatever the code is
  assert.throws(() => checkVersionAdvance({ versionCode: 9999, current: null, anyAnswered: false }), /no relay answered/);
  // --allow-older overrides every refusal
  assert.equal(checkVersionAdvance({ versionCode: 8019, current: cur(8019), anyAnswered: true, allowOlder: true }), 'overridden');
  assert.equal(checkVersionAdvance({ versionCode: 8018, current: cur(8019), anyAnswered: true, allowOlder: true }), 'overridden');
  assert.equal(checkVersionAdvance({ versionCode: 5, current: null, anyAnswered: false, allowOlder: true }), 'overridden');
  // ... but it does not make an unreadable new code acceptable
  assert.throws(() => checkVersionAdvance({ versionCode: 0, current: null, anyAnswered: true, allowOlder: true }), /versionCode/);
});

test("the channel's current release is the best verified event from the release key", () => {
  const key = 'c'.repeat(64);
  const mk = (code, over = {}) => ({
    id: String(code).padStart(64, '0'),
    pubkey: key,
    kind: SOFTWARE_RELEASE_KIND,
    created_at: 1_790_000_000 + code,
    sig: 'f'.repeat(128),
    content: '',
    tags: [
      ['d', CHANNEL],
      ['version', '0.1.0'],
      ['version_code', String(code)],
      ['x', SHA],
      ['size', '1000'],
      ['cert', CERT],
      ['url', `https://nostr.download/${SHA}.apk`]
    ],
    ...over
  });
  const yes = () => true;
  const best = (events, pk, verify) => bestCurrentRelease(events, pk, verify, CHANNEL);
  assert.equal(best([], key, yes), null);
  assert.equal(best([mk(5), mk(9), mk(7)], key, yes).versionCode, 9, 'the highest versionCode, as the device picks');
  // not signed properly, wrong author, wrong kind, wrong channel, malformed: all ignored
  assert.equal(best([mk(9)], key, () => false), null, 'a bad signature');
  assert.equal(best([mk(9, { pubkey: 'd'.repeat(64) })], key, yes), null);
  assert.equal(best([mk(9, { kind: 1 })], key, yes), null);
  assert.equal(best([mk(9, { tags: mk(9).tags.map((t) => (t[0] === 'd' ? ['d', 'other'] : t)) })], key, yes), null);
  assert.equal(best([mk(9, { tags: [] })], key, yes), null);
  assert.equal(best([mk(9, { pubkey: 'D'.repeat(64) })], 'd'.repeat(64), yes), null, 'pubkey compared as given');
  assert.equal(best([mk(9, { pubkey: 'd'.repeat(64) }), mk(4)], key, yes).versionCode, 4);
  assert.equal(best(null, key, yes), null);
  assert.equal(bestCurrentRelease([mk(9)], key, yes, 'other-android-apk'), null, 'another channel');
});

test('redirects are followed only to public https hosts on port 443 (mirrors RedirectRule.java)', () => {
  const allowed = [
    'https://nostr.download/abc.apk',
    'https://cdn.example.com/a/b?x=1',
    'https://cdn.example.com:443/a',
    'HTTPS://Cdn.Example.COM/a',
    'https://xn--bcher-kva.example/a',
    'https://a-b.c-d.example/a'
  ];
  const refused = [
    'http://nostr.download/abc.apk', 'ftp://nostr.download/abc.apk', 'file:///data/x', '//nostr.download/abc.apk', '/abc.apk', '', null,
    'https://user@nostr.download/a', 'https://user:pw@nostr.download/a', 'https://nostr.download@evil.example/a', 'https://:@nostr.download/a',
    'https://nostr.download:8443/a', 'https://nostr.download:80/a', 'https://nostr.download:444/a', 'https://nostr.download:/a',
    'https://127.0.0.1/a', 'https://10.0.0.5/a', 'https://192.168.1.1:443/a', 'https://[::1]/a', 'https://[2001:db8::1]/a',
    'https://[::ffff:127.0.0.1]/a', 'https://localhost/a', 'https://LOCALHOST/a', 'https://localhost.:443/a', 'https://app.localhost/a',
    'https://intranet/a', 'https://2130706433/a', 'https://0x7f.0x0.0x0.0x1/a', 'https://127.1/a', 'https://example.com./a',
    'https://.example.com/a', 'https://exa_mple.com/a', 'https://exa mple.com/a', 'https:///a', 'https://'
  ];
  for (const u of allowed) assert.equal(isPublicRedirectTarget(u), true, `allowed: ${u}`);
  for (const u of refused) assert.equal(isPublicRedirectTarget(u), false, `refused: ${u}`);
});

function withConfig(config, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'release-kit-test-'));
  try {
    const path = join(dir, 'release.json');
    writeFileSync(path, JSON.stringify(config));
    return fn(path, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const baseConfig = { channel: CHANNEL, package: 'org.example.app' };

test('the publisher CLI knows --allow-cert-change, --allow-older and --relay', () => {
  // No APK given: it must reach the usage error, not "unknown argument". Nothing is
  // uploaded or signed on this path.
  withConfig(baseConfig, (cfg) => {
    for (const flags of [['--allow-cert-change'], ['--allow-older'], ['--relay', 'wss://x.example.com']]) {
      const r = spawnSync(process.execPath, [PUBLISHER, '--config', cfg, ...flags], { encoding: 'utf8' });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /usage: publish-release\.mjs/);
      assert.doesNotMatch(r.stderr, /unknown argument/);
    }
  });
});

test('the publisher CLI refuses to run without a usable config', () => {
  let r = spawnSync(process.execPath, [PUBLISHER, 'some.apk', '--version', '1.0.0'], { encoding: 'utf8' });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /--config <release\.json> is required/);
  r = spawnSync(process.execPath, [PUBLISHER, '--config', '/nonexistent/release.json', '--print-pubkey'], { encoding: 'utf8' });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /cannot read the config/);
  withConfig({ channel: CHANNEL }, (cfg) => {
    r = spawnSync(process.execPath, [PUBLISHER, '--config', cfg, '--print-pubkey'], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /package/);
  });
});

test('a semver config derives the versionCode and refuses a contradicting --version-code', () => {
  withConfig({ ...baseConfig, version_source: 'semver' }, (cfg, dir) => {
    const apk = join(dir, 'x.apk');
    writeFileSync(apk, 'not an apk');
    const r = spawnSync(process.execPath, [PUBLISHER, '--config', cfg, apk, '--version', '1.2.3', '--version-code', '5', '--dry-run'], { encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /gives versionCode 1002003/);
  });
});

test('--self-test needs no config and no network', () => {
  const r = spawnSync(process.execPath, [PUBLISHER, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /self-test PASSED/);
});

test('--print-pubkey prints the public half of the key file and nothing secret', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-kit-key-test-'));
  const secret = '11'.repeat(32); // a throwaway test key, not any real one
  const file = join(dir, 'k.hex');
  writeFileSync(file, secret + '\n', { mode: 0o600 });
  chmodSync(file, 0o600);
  const cfgPath = join(dir, 'release.json');
  writeFileSync(cfgPath, JSON.stringify({ ...baseConfig, key_file_env: 'RELEASE_KIT_TEST_KEY_FILE' }));
  const r = spawnSync(process.execPath, [PUBLISHER, '--config', cfgPath, '--print-pubkey'], {
    encoding: 'utf8',
    env: { ...process.env, RELEASE_KIT_TEST_KEY_FILE: file }
  });
  rmSync(dir, { recursive: true, force: true });
  assert.equal(r.status, 0, r.stderr);
  const pub = getPublicKey(Uint8Array.from(Buffer.from(secret, 'hex')));
  assert.match(r.stdout, new RegExp(`hex\\)\\s+= ${pub}`));
  assert.match(r.stdout, /npub1[0-9a-z]+/);
  assert.ok(!r.stdout.includes(secret) && !r.stderr.includes(secret), 'the secret must never be printed');
  assert.equal(r.stdout.trim().split('\n').length, 2);
});

test('--init-key mints a key file with mode 0600 and prints only the public half', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-kit-init-test-'));
  const file = join(dir, 'sub', 'k.hex');
  const cfgPath = join(dir, 'release.json');
  writeFileSync(cfgPath, JSON.stringify({ ...baseConfig, key_file_env: 'RELEASE_KIT_TEST_KEY_FILE' }));
  const run = () => spawnSync(process.execPath, [PUBLISHER, '--config', cfgPath, '--init-key'], { encoding: 'utf8', env: { ...process.env, RELEASE_KIT_TEST_KEY_FILE: file } });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  const secret = readFileSync(file, 'utf8').trim();
  assert.match(secret, /^[0-9a-f]{64}$/);
  assert.ok(!first.stdout.includes(secret));
  assert.equal((statSync(file).mode & 0o777).toString(8), '600');
  const again = run();
  assert.match(again.stdout, /already exists/);
  assert.equal(readFileSync(file, 'utf8').trim(), secret, 'never overwritten');
  rmSync(dir, { recursive: true, force: true });
});

test('a signed event round-trips through finalizeEvent and verifyEvent', () => {
  const sk = generateSecretKey();
  const ev = finalizeEvent(buildReleaseEvent(ok), sk);
  assert.equal(verifyEvent(ev), true);
  assert.equal(summarizeReleaseEvent(ev, CHANNEL).pubkey, getPublicKey(sk));
});

// ─── The redirect gate (verifyMirror / checkRedirectChain) ──────────────────

/** A stub fetch: `routes` maps a URL to { status, location, body }; anything else is a 404. No network. */
function stubFetch(routes) {
  const seen = [];
  const fn = async (url, opts) => {
    assert.equal(opts?.redirect, 'manual', 'a mirror is probed without following redirects');
    seen.push(url);
    const r = routes[url] ?? { status: 404 };
    return {
      status: r.status,
      headers: { get: (n) => (n.toLowerCase() === 'location' ? (r.location ?? null) : null) },
      arrayBuffer: async () => r.body ?? new ArrayBuffer(0),
      body: { cancel: async () => {} }
    };
  };
  fn.seen = seen;
  return fn;
}

const MIRROR = 'https://blossom.example.net';
const APK_BYTES = new TextEncoder().encode('an apk').buffer;
const APK_SHA = createHash('sha256').update(Buffer.from(APK_BYTES)).digest('hex');
const logTo = () => {
  const lines = [];
  const log = (m) => lines.push(m);
  log.lines = lines;
  return log;
};

test('a mirror that serves the blob directly is verified, with or without the extension', async () => {
  const withExt = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 200, body: APK_BYTES } });
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: withExt }), `${MIRROR}/${APK_SHA}.apk`);
  const bare = stubFetch({ [`${MIRROR}/${APK_SHA}`]: { status: 200, body: APK_BYTES } });
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: bare }), `${MIRROR}/${APK_SHA}`);
});

test('a mirror serving the wrong bytes, or nothing, contributes no URL and does not stop the publish', async () => {
  const log = logTo();
  const wrong = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 200, body: new TextEncoder().encode('other').buffer } });
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: wrong, log }), null);
  assert.match(log.lines[0], /WRONG bytes/);
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: stubFetch({}), log }), null);
});

test('a redirect a device would follow is not announced, but does not stop the publish', async () => {
  const log = logTo();
  const f = stubFetch({
    [`${MIRROR}/${APK_SHA}.apk`]: { status: 302, location: `https://cdn.example.com/blob/${APK_SHA}` },
    [`https://cdn.example.com/blob/${APK_SHA}`]: { status: 200, body: APK_BYTES }
  });
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: f, log }), null, 'the announcement needs a direct 200');
  assert.ok(log.lines.some((l) => /a device would follow it/.test(l)), log.lines.join('\n'));
  // Relative Locations resolve against the page that redirected.
  const rel = stubFetch({
    [`${MIRROR}/${APK_SHA}.apk`]: { status: 307, location: `/mirror/${APK_SHA}` },
    [`${MIRROR}/mirror/${APK_SHA}`]: { status: 200, body: APK_BYTES }
  });
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: rel }), null);
});

test('GATE: a redirect to a place a device would refuse stops the publish', async () => {
  const refused = [
    'http://cdn.example.com/blob',
    'https://user:pw@cdn.example.com/blob',
    'https://cdn.example.com:8443/blob',
    'https://203.0.113.9/blob',
    'https://127.0.0.1/blob',
    'https://localhost/blob',
    'https://intranet/blob',
    'https://[::1]/blob',
    'ftp://cdn.example.com/blob'
  ];
  for (const target of refused) {
    const f = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 302, location: target } });
    await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: f }), (e) => e instanceof RedirectRefused && /would refuse to follow/.test(e.message), target);
    assert.equal(f.seen.length, 1, `a refused target is never requested: ${target}`);
  }
});

test('GATE: every hop is checked, and at most four redirects are followed', async () => {
  const hop = (n) => `https://h${n}.example.com/x`;
  // A bad target on the third hop is caught.
  const bad = stubFetch({
    [`${MIRROR}/${APK_SHA}.apk`]: { status: 302, location: hop(1) },
    [hop(1)]: { status: 301, location: hop(2) },
    [hop(2)]: { status: 308, location: 'https://10.0.0.5/x' }
  });
  await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: bad }), RedirectRefused);
  // Four redirects are followed (a device does); a fifth is refused.
  const chain = (n) => {
    const routes = { [`${MIRROR}/${APK_SHA}.apk`]: { status: 302, location: hop(1) } };
    for (let i = 1; i < n; i++) routes[hop(i)] = { status: 302, location: hop(i + 1) };
    routes[hop(n)] = { status: 200, body: APK_BYTES };
    return stubFetch(routes);
  };
  assert.equal(await verifyMirror(MIRROR, APK_SHA, { fetchFn: chain(4) }), null, 'four redirects: followed');
  await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: chain(5) }), (e) => e instanceof RedirectRefused && /more than 4 times/.test(e.message));
  // A redirect loop is the same thing.
  const loop = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 302, location: hop(1) }, [hop(1)]: { status: 302, location: hop(1) } });
  await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: loop }), RedirectRefused);
});

test('GATE: any 3xx is a redirect to a device, and one without a Location cannot be followed', async () => {
  const f303 = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 303, location: 'http://cdn.example.com/b' } });
  await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: f303 }), RedirectRefused);
  const none = stubFetch({ [`${MIRROR}/${APK_SHA}.apk`]: { status: 302 } });
  await assert.rejects(verifyMirror(MIRROR, APK_SHA, { fetchFn: none }), (e) => e instanceof RedirectRefused && /without a Location/.test(e.message));
});

test('the publisher turns RedirectRefused into a refusal to publish (source check)', () => {
  // The publisher's network path is not run in tests: check the gate error is caught and ends the publish.
  const src = readFileSync(PUBLISHER, 'utf8');
  assert.match(src, /err instanceof RedirectRefused[\s\S]{0,400}process\.exit\(1\)/);
});

const DIGEST = '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809';

test('apksigner output with one signer gives its digest; several signers are refused', () => {
  const one = `Signer #1 certificate DN: CN=Example\nSigner #1 certificate SHA-256 digest: ${DIGEST.toUpperCase()}\nSigner #1 certificate SHA-1 digest: aa\n`;
  assert.equal(singleSignerCertSha256(one), DIGEST);
  const two = `${one}Signer #2 certificate DN: CN=Other\nSigner #2 certificate SHA-256 digest: ${'b'.repeat(64)}\n`;
  assert.throws(() => singleSignerCertSha256(two), /2 signers.*exactly one/);
  // A lone "Signer #2" (numbering that does not start at 1) is not a single signer either.
  assert.throws(() => singleSignerCertSha256(`Signer #2 certificate SHA-256 digest: ${DIGEST}\n`), /exactly one/);
  assert.throws(() => singleSignerCertSha256('nothing useful'), /could not parse/);
  // The publisher uses it for the announced cert (source check).
  assert.match(readFileSync(PUBLISHER, 'utf8'), /return singleSignerCertSha256\(out\)/);
});

test('a release key file readable by group or others is refused; 0600 is read', { skip: process.platform === 'win32' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-kit-key-'));
  try {
    const file = join(dir, 'throwaway-key.hex');
    const sk = generateSecretKey();
    writeFileSync(file, Buffer.from(sk).toString('hex') + '\n', { mode: 0o600 });
    chmodSync(file, 0o600);
    assert.deepEqual(Array.from(readSecretKeyFile(file)), Array.from(sk));
    chmodSync(file, 0o400);
    assert.equal(readSecretKeyFile(file).length, 32, 'stricter than 0600 is fine');
    for (const mode of [0o640, 0o604, 0o644, 0o660, 0o666]) {
      chmodSync(file, mode);
      assert.throws(() => readSecretKeyFile(file), (e) => /readable by group or others/.test(e.message) && /0600/.test(e.message) && !e.message.includes(Buffer.from(sk).toString('hex')), mode.toString(8));
    }
    chmodSync(file, 0o600);
    writeFileSync(file, 'not hex\n');
    assert.throws(() => readSecretKeyFile(file), /not a 64-hex secret/);
    assert.throws(() => readSecretKeyFile(join(dir, 'missing')), /no release key/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('init-key only tightens a directory it made (source check)', () => {
  const src = readFileSync(PUBLISHER, 'utf8');
  assert.match(src, /const made = !existsSync\(dir\);[\s\S]{0,200}if \(made\) chmodSync\(dir, 0o700\)/);
  assert.doesNotMatch(src, /chmodSync\(dirname\(keyFile\)/);
});

test('the publisher CLI refuses a loose key file with a clear message and prints nothing secret', { skip: process.platform === 'win32' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-kit-key-test-'));
  const secret = '22'.repeat(32); // a throwaway test key
  const file = join(dir, 'k.hex');
  writeFileSync(file, secret + '\n', { mode: 0o600 });
  chmodSync(file, 0o644);
  const cfgPath = join(dir, 'release.json');
  writeFileSync(cfgPath, JSON.stringify({ ...baseConfig, key_file_env: 'RELEASE_KIT_TEST_KEY_FILE' }));
  const r = spawnSync(process.execPath, [PUBLISHER, '--config', cfgPath, '--print-pubkey'], {
    encoding: 'utf8',
    env: { ...process.env, RELEASE_KIT_TEST_KEY_FILE: file }
  });
  rmSync(dir, { recursive: true, force: true });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /readable by group or others.*0600/);
  assert.ok(!r.stdout.includes(secret) && !r.stderr.includes(secret));
});
