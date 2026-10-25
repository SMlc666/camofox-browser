import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals';
import { getUserPersistencePaths } from '../../lib/persistence.js';
import {
  buildNativeFingerprintInitScript,
  contextFingerprintOptions,
  getFingerprintProfilePaths,
  loadOrCreateBrowserFingerprint,
  loadOrCreateUserFingerprint,
  readCamoufoxConfig,
  writeCamoufoxConfig,
} from '../../lib/fingerprint-persistence.js';

const runtime = {
  appVersion: '1.18.1',
  camoufoxJsVersion: '0.11.5',
  playwrightVersion: '1.62.1',
  platform: 'linux',
  arch: 'arm64',
  targetOS: 'linux',
  browserVersion: '152.0.4-beta.30',
};

function makeLaunchOptions(config = { 'navigator.userAgent': 'global-agent/152', 'locale:language': 'en', 'locale:region': 'US', 'screen.width': 1280, 'screen.height': 720, 'window.outerWidth': 1280, 'window.outerHeight': 720, 'screen.colorDepth': 24, 'webGl:vendor': 'Intel', 'webGl:renderer': 'Intel GPU' }) {
  const env = {};
  writeCamoufoxConfig(env, config);
  return { executablePath: '/opt/camoufox/camoufox-bin', env };
}

describe('persistent per-user Camoufox fingerprints', () => {
  let profileDir;

  beforeEach(async () => {
    profileDir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-fingerprint-test-'));
  });

  afterEach(async () => {
    await fs.rm(profileDir, { recursive: true, force: true });
  });

  test('persists and restores the exact global CAMOU_CONFIG baseline atomically', async () => {
    const options = makeLaunchOptions();
    const first = await loadOrCreateBrowserFingerprint({ profileDir, options, runtime });
    const firstConfig = readCamoufoxConfig(options.env);

    const restartedOptions = makeLaunchOptions({ 'navigator.userAgent': 'new-random-agent', 'screen.width': 900 });
    const second = await loadOrCreateBrowserFingerprint({ profileDir, options: restartedOptions, runtime });

    expect(second.digest).toBe(first.digest);
    expect(readCamoufoxConfig(restartedOptions.env)).toEqual(firstConfig);
    const stat = await fs.stat(first.path);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test.each(['US', 'JP'])('refuses %s proxy launch options without changing stored identity or incoming GeoIP', async (country) => {
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options: makeLaunchOptions(), runtime });
    const before = await fs.readFile(globalProfile.path);
    const options = makeLaunchOptions({
      timezone: country === 'US' ? 'America/New_York' : 'Asia/Tokyo',
      'locale:language': country === 'US' ? 'en' : 'ja',
      'locale:region': country,
      'geolocation:latitude': country === 'US' ? 40.71 : 35.68,
      'geolocation:longitude': country === 'US' ? -74.01 : 139.69,
      'webrtc:ipv4': country === 'US' ? '192.0.2.1' : '198.51.100.1',
    });
    options.proxy = { server: 'http://proxy.invalid:8080' };
    const incomingEnv = { ...options.env };
    await expect(loadOrCreateBrowserFingerprint({ profileDir, options, runtime }))
      .rejects.toThrow(/direct connections only/);
    expect(options.env).toEqual(incomingEnv);
    expect(await fs.readFile(globalProfile.path)).toEqual(before);
  });

  test.each(['geolocation:latitude', 'geolocation:longitude', 'webrtc:ipv4', 'webrtc:ipv6'])(
    'refuses network-bound launch config %s even if proxy options were stripped', async (key) => {
      await expect(loadOrCreateBrowserFingerprint({
        profileDir, options: makeLaunchOptions({ [key]: key.includes('latitude') ? 35.68 : '198.51.100.1' }), runtime,
      })).rejects.toThrow(/GeoIP\/geolocation or WebRTC IP/);
      expect(await fs.readdir(profileDir)).toEqual([]);
    },
  );

  test('refuses a previously persisted GeoIP baseline even after proxy removal, without rewriting it', async () => {
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options: makeLaunchOptions(), runtime });
    const record = JSON.parse(await fs.readFile(globalProfile.path, 'utf8'));
    // Simulate a valid profile produced before the direct-only policy. Both
    // checksums are valid: rejection must be a network policy error, not damage.
    const stable = (value) => value && typeof value === 'object'
      ? (Array.isArray(value) ? `[${value.map(stable).join(',')}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`)
      : JSON.stringify(value);
    const digest = (value) => crypto.createHash('sha256').update(stable(value)).digest('hex');
    record.camouConfig['webrtc:ipv4'] = '192.0.2.1';
    record.camouConfig['geolocation:latitude'] = 40.71;
    record.camouConfig.timezone = 'America/New_York';
    record.camouConfigDigest = digest(record.camouConfig);
    const { integrity, ...payload } = record;
    record.integrity.digest = digest(payload);
    await fs.writeFile(globalProfile.path, JSON.stringify(record), { mode: 0o600 });
    const before = await fs.readFile(globalProfile.path);
    const options = makeLaunchOptions();
    const incomingEnv = { ...options.env };
    await expect(loadOrCreateBrowserFingerprint({ profileDir, options, runtime }))
      .rejects.toThrow(/network-bound identity/);
    expect(await fs.readFile(globalProfile.path)).toEqual(before);
    expect(options.env).toEqual(incomingEnv);
  });

  test('same userId reuses identity across sessions while other users get different native identity inputs', async () => {
    const storagePaths = getUserPersistencePaths(profileDir, 'account-A');
    await fs.mkdir(storagePaths.userDir, { recursive: true });
    const originalStorageState = JSON.stringify({ cookies: [{ name: 'existing', value: 'keep-me' }], origins: [] });
    await fs.writeFile(storagePaths.storageStatePath, originalStorageState, { mode: 0o600 });
    const options = makeLaunchOptions();
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options, runtime });
    const first = await loadOrCreateUserFingerprint({ profileDir, userId: 'account-A', sessionKey: 'task-1', runtime, globalProfile, globalConfig: globalProfile.config });
    const sameUser = await loadOrCreateUserFingerprint({ profileDir, userId: 'account-A', sessionKey: 'task-2', runtime, globalProfile, globalConfig: globalProfile.config });
    const otherUser = await loadOrCreateUserFingerprint({ profileDir, userId: 'account-B', runtime, globalProfile, globalConfig: globalProfile.config });

    expect(sameUser.profile.identity).toEqual(first.profile.identity);
    expect(otherUser.profile.identity).not.toEqual(first.profile.identity);
    expect(otherUser.profile.identity.userIdHash).not.toBe(first.profile.identity.userIdHash);
    expect(otherUser.profile.identity.audioSeed).not.toBe(first.profile.identity.audioSeed);
    expect(otherUser.profile.identity.fontSpacingSeed).not.toBe(first.profile.identity.fontSpacingSeed);
    expect(otherUser.profile.identity.hardwareConcurrency).toBeGreaterThanOrEqual(1);
    expect(otherUser.profile.identity.scope.contextNative).toContain('hardwareConcurrency');
    expect(otherUser.profile.identity.scope.contextNative).not.toContain('webgl');
    expect(otherUser.profile.identity.scope.sharedAcrossUsers).toContain('webglBaseline');

    const userPaths = getFingerprintProfilePaths(profileDir, 'account-A');
    expect(userPaths.userPath).not.toContain('account-A');
    expect((await fs.stat(userPaths.userPath)).mode & 0o777).toBe(0o600);
    expect(await fs.readFile(storagePaths.storageStatePath, 'utf8')).toBe(originalStorageState);
  });

  test('concurrent first-time contexts atomically converge on one persisted identity', async () => {
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options: makeLaunchOptions(), runtime });
    const [first, second] = await Promise.all([
      loadOrCreateUserFingerprint({ profileDir, userId: 'concurrent-user', runtime, globalProfile, globalConfig: globalProfile.config }),
      loadOrCreateUserFingerprint({ profileDir, userId: 'concurrent-user', runtime, globalProfile, globalConfig: globalProfile.config }),
    ]);
    expect(second.profile.identity).toEqual(first.profile.identity);
    expect(JSON.parse(await fs.readFile(first.path, 'utf8')).integrity.digest)
      .toBe(JSON.parse(await fs.readFile(second.path, 'utf8')).integrity.digest);
  });

  test('fingerprint files with non-0600 permissions fail closed', async () => {
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options: makeLaunchOptions(), runtime });
    const user = await loadOrCreateUserFingerprint({ profileDir, userId: 'permission-user', runtime, globalProfile, globalConfig: globalProfile.config });
    await fs.chmod(user.path, 0o640);
    await expect(loadOrCreateUserFingerprint({ profileDir, userId: 'permission-user', runtime, globalProfile, globalConfig: globalProfile.config }))
      .rejects.toThrow(/permissions must be 0600/);
  });

  test('corrupt and incompatible identity files fail closed instead of silently changing identity', async () => {
    const options = makeLaunchOptions();
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options, runtime });
    const user = await loadOrCreateUserFingerprint({ profileDir, userId: 'account-A', runtime, globalProfile, globalConfig: globalProfile.config });
    const original = await fs.readFile(user.path, 'utf8');
    await fs.writeFile(user.path, `${original.slice(0, -3)}xx\n`, { mode: 0o600 });

    await expect(loadOrCreateUserFingerprint({ profileDir, userId: 'account-A', runtime, globalProfile, globalConfig: globalProfile.config }))
      .rejects.toThrow(/corrupted|integrity check failed/);
    expect(await fs.readFile(user.path, 'utf8')).not.toBe(original);
  });

  test('runtime or global-baseline changes are incompatible and do not regenerate profiles', async () => {
    const options = makeLaunchOptions();
    const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options, runtime });
    await loadOrCreateUserFingerprint({ profileDir, userId: 'account-A', runtime, globalProfile, globalConfig: globalProfile.config });

    await expect(loadOrCreateBrowserFingerprint({
      profileDir,
      options: makeLaunchOptions(),
      runtime: { ...runtime, browserVersion: '153.0.0-beta.1' },
    })).rejects.toThrow(/runtime mismatch/);

    const changedGlobal = { ...globalProfile, digest: 'different-global-digest' };
    await expect(loadOrCreateUserFingerprint({
      profileDir,
      userId: 'account-A',
      runtime,
      globalProfile: changedGlobal,
      globalConfig: globalProfile.config,
    })).rejects.toThrow(/browser-global fingerprint changed/);
  });

  test('context options keep HTTP, locale, and timezone aligned without viewport or DPR fallbacks', () => {
    const options = contextFingerprintOptions({
      userAgent: 'Firefox/152 user',
      locale: 'en-US',
      timezone: 'Asia/Shanghai',
      screen: { deviceScaleFactor: 1 },
    });
    expect(options).toEqual({ userAgent: 'Firefox/152 user', locale: 'en-US', timezoneId: 'Asia/Shanghai' });
    expect(options).not.toHaveProperty('viewport');
    expect(options).not.toHaveProperty('deviceScaleFactor');
  });

  test('uses only native Camoufox setters and makes no JavaScript property-override fallback', () => {
    const script = buildNativeFingerprintInitScript({
      userAgent: 'Firefox/152 user',
      appVersion: '5.0 (X11)',
      platform: 'Linux x86_64',
      oscpu: 'Linux x86_64',
      hardwareConcurrency: 8,
      screen: { width: 1600, height: 900, colorDepth: 24 },
      timezone: 'UTC',
      fontSpacingSeed: 1,
      audioSeed: 2,
      fontList: ['Arimo', 'Cousine'],
      webgl: { vendor: 'Intel', renderer: 'Intel GPU' },
    });
    expect(script).toContain('setNavigatorUserAgent');
    expect(script).toContain('setNavigatorHardwareConcurrency');
    expect(script).toContain('setFontList');
    expect(script).not.toContain('setWebGLVendor');
    expect(script).not.toMatch(/Object\.defineProperty|navigator\.userAgent\s*=/);
    expect(() => new Function('window', script)({})).not.toThrow();
  });

  test('writes Camoufox config chunks in numeric order and detects missing chunks', () => {
    const env = {};
    writeCamoufoxConfig(env, { alpha: 1, text: 'a'.repeat(40000) });
    expect(Object.keys(env).filter((key) => key.startsWith('CAMOU_CONFIG_'))).toEqual(['CAMOU_CONFIG_1', 'CAMOU_CONFIG_2']);
    expect(readCamoufoxConfig(env)).toEqual({ alpha: 1, text: 'a'.repeat(40000) });
    delete env.CAMOU_CONFIG_1;
    expect(() => readCamoufoxConfig(env)).toThrow(/gap|do not contain/);
  });
});
