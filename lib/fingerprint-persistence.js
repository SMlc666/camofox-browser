import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { getUserPersistencePaths } from './persistence.js';
import { assertPrivateStoragePlatform } from '../mcp/lib/private-storage.mjs';
import { fromBrowserforge, generateFingerprint } from 'camoufox-js/dist/fingerprints.js';
import FONTS from 'camoufox-js/dist/mappings/fonts.config.js';

export const FINGERPRINT_SCHEMA_VERSION = 1;
const MAX_PROFILE_BYTES = 2 * 1024 * 1024;
const REQUIRED_NATIVE_SETTERS = [
  'setNavigatorUserAgent',
  'setNavigatorPlatform',
  'setNavigatorOscpu',
  'setNavigatorHardwareConcurrency',
  'setScreenDimensions',
  'setScreenColorDepth',
  'setTimezone',
  'setFontSpacingSeed',
  'setAudioFingerprintSeed',
  'setFontList',
];

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digestObject(value) {
  return sha256(stableStringify(value));
}

function wrapRecord(payload) {
  return {
    ...payload,
    integrity: {
      algorithm: 'sha256',
      digest: digestObject(payload),
    },
  };
}

function payloadOf(record) {
  const { integrity, ...payload } = record;
  return payload;
}

function verifyRecord(record, expectedType) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error(`fingerprint profile is not a JSON object (${expectedType})`);
  }
  if (record.type !== expectedType || record.schemaVersion !== FINGERPRINT_SCHEMA_VERSION) {
    throw new Error(`unsupported or incompatible fingerprint profile: expected ${expectedType} schema ${FINGERPRINT_SCHEMA_VERSION}`);
  }
  if (record.integrity?.algorithm !== 'sha256' || typeof record.integrity?.digest !== 'string') {
    throw new Error(`fingerprint profile integrity metadata is missing (${expectedType})`);
  }
  if (digestObject(payloadOf(record)) !== record.integrity.digest) {
    throw new Error(`fingerprint profile integrity check failed (${expectedType}); refusing to regenerate it`);
  }
}

function profileDirectories(profileDir) {
  const root = path.join(path.resolve(profileDir), '.fingerprints');
  return { root, users: path.join(root, 'users') };
}

export function getFingerprintProfilePaths(profileDir, userId) {
  const { root, users } = profileDirectories(profileDir);
  const userHash = sha256(String(userId));
  return {
    root,
    users,
    browserPath: path.join(root, 'browser.json'),
    browserAnchorPath: path.join(path.resolve(profileDir), '.fingerprint-registry', 'browser.json'),
    userAnchorPath: path.join(path.resolve(profileDir), '.fingerprint-registry', 'users', `${userHash}.json`),
    userPath: path.join(users, `${userHash}.json`),
    userHash,
  };
}

async function ensureSecureDirectory(directory) {
  assertPrivateStoragePlatform();
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`fingerprint profile path is not a real directory: ${directory}`);
  }
  await fs.chmod(directory, 0o700);
  const secured = await fs.lstat(directory);
  if ((secured.mode & 0o777) !== 0o700) {
    throw new Error(`fingerprint profile directory permissions must be 0700: ${directory}`);
  }
}

async function fsyncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, 'r');
    await handle.sync();
  } catch (err) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR', 'EPERM'].includes(err?.code)) throw err;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function createFileIfAbsent(filePath, record) {
  const directory = path.dirname(filePath);
  await ensureSecureDirectory(directory);
  const tempPath = `${filePath}.tmp-${process.pid}-${crypto.randomUUID()}`;
  let handle;
  try {
    handle = await fs.open(tempPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = null;
    try {
      // Hard-linking in the same directory is atomic and fails rather than
      // replacing an identity created concurrently by another server process.
      await fs.link(tempPath, filePath);
      await fsyncDirectory(directory);
      return true;
    } catch (err) {
      if (err?.code === 'EEXIST') return false;
      throw err;
    }
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(tempPath).catch(() => {});
  }
}

async function readRecord(filePath, expectedType) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (err) {
    if (err?.code === 'ENOENT') return undefined;
    throw err;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`fingerprint profile is not a regular file: ${filePath}`);
  }
  if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(`fingerprint profile permissions must be 0600: ${filePath}`);
  }
  if (stat.size <= 0 || stat.size > MAX_PROFILE_BYTES) {
    throw new Error(`fingerprint profile has an invalid size: ${filePath}`);
  }

  let record;
  try {
    record = JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`fingerprint profile is corrupted (${filePath}): ${err.message}; refusing to regenerate it`);
  }
  verifyRecord(record, expectedType);
  return record;
}

async function loadOrCreateRecord(filePath, anchorPath, expectedType, makePayload, validate, beforeCreate) {
  await ensureSecureDirectory(path.dirname(anchorPath));
  const lockPath = `${anchorPath}.lock`;
  const deadline = Date.now() + 10000;
  while (true) {
    try {
      await fs.mkdir(lockPath, { mode: 0o700 });
      break;
    } catch (err) {
      if (err?.code !== 'EEXIST') throw err;
      if (Date.now() >= deadline) {
        throw new Error('fingerprint initialization lock remains busy; an interrupted initialization requires explicit recovery, not identity regeneration');
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  try {
    const anchorType = `${expectedType}-anchor`;
    const anchor = await readRecord(anchorPath, anchorType);
    const record = await readRecord(filePath, expectedType);
    if (Boolean(anchor) !== Boolean(record)) {
      throw new Error('fingerprint identity or its initialization anchor is missing; refusing to regenerate it or pair new fingerprints with old storageState; explicit recovery/migration is required');
    }
    if (record) {
      validate(payloadOf(record));
      if (anchor.identityDigest !== record.integrity.digest) {
        throw new Error('fingerprint initialization anchor does not match the identity; explicit recovery is required');
      }
      return record;
    }
    await beforeCreate?.();
    const candidate = wrapRecord(await makePayload());
    validate(payloadOf(candidate));
    const marker = wrapRecord({
      type: anchorType, schemaVersion: FINGERPRINT_SCHEMA_VERSION,
      createdAt: new Date().toISOString(), identityDigest: candidate.integrity.digest,
    });
    // Anchor first: a crash between publications is incomplete, not first use.
    // Never remove a surviving anchor on error or recover a stale lock silently.
    if (!await createFileIfAbsent(anchorPath, marker) || !await createFileIfAbsent(filePath, candidate)) {
      throw new Error('fingerprint initialization changed concurrently; explicit recovery is required');
    }
    return candidate;
  } finally {
    await fs.rmdir(lockPath);
    await fsyncDirectory(path.dirname(anchorPath));
  }
}

async function pathExists(filePath) {
  try { await fs.lstat(filePath); return true; }
  catch (err) { if (err?.code === 'ENOENT') return false; throw err; }
}

async function refuseUnboundStorage(profileDir, userId, storageState) {
  if (storageState !== undefined || await pathExists(getUserPersistencePaths(profileDir, userId).storageStatePath)) {
    throw new Error('existing storageState has no fingerprint initialization record; refusing to pair old login state with a newly generated identity; explicit migration is required');
  }
}

async function refuseExistingProfileData(profileDir) {
  const entries = await fs.readdir(profileDir, { withFileTypes: true });
  for (const entry of entries) {
    if (/^[a-f0-9]{32}$/.test(entry.name) && await pathExists(path.join(profileDir, entry.name, 'storage-state.json'))) {
      throw new Error('existing storageState has no browser fingerprint initialization record; explicit recovery/migration is required');
    }
  }
  for (const directory of [path.join(profileDir, '.fingerprint-registry', 'users'), path.join(profileDir, '.fingerprints', 'users')]) {
    try {
      if ((await fs.readdir(directory)).length > 0) {
        throw new Error('existing user fingerprint records have no browser identity; explicit recovery is required');
      }
    } catch (err) { if (err?.code !== 'ENOENT') throw err; }
  }
}

function camouConfigChunks(env = {}) {
  const keys = Object.keys(env)
    .filter((key) => /^CAMOU_CONFIG_\d+$/.test(key))
    .sort((a, b) => Number(a.slice('CAMOU_CONFIG_'.length)) - Number(b.slice('CAMOU_CONFIG_'.length)));
  if (keys.length === 0) throw new Error('Camoufox launch options do not contain CAMOU_CONFIG_n fingerprint data');
  for (let i = 0; i < keys.length; i++) {
    if (Number(keys[i].slice('CAMOU_CONFIG_'.length)) !== i + 1) {
      throw new Error('Camoufox launch options contain a gap in CAMOU_CONFIG_n fingerprint data');
    }
  }
  return keys.map((key) => env[key]).join('');
}

export function readCamoufoxConfig(env) {
  let config;
  try {
    config = JSON.parse(camouConfigChunks(env));
  } catch (err) {
    throw new Error(`could not read Camoufox launch fingerprint config: ${err.message}`);
  }
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('Camoufox launch fingerprint config must be an object');
  }
  return config;
}

export function writeCamoufoxConfig(env, config, platform = process.platform) {
  if (!env || typeof env !== 'object') throw new Error('Camoufox launch environment is unavailable');
  for (const key of Object.keys(env)) {
    if (/^CAMOU_CONFIG_\d+$/.test(key)) delete env[key];
  }
  const serialized = JSON.stringify(config);
  const chunkSize = platform === 'win32' ? 2047 : 32767;
  for (let i = 0; i < serialized.length; i += chunkSize) {
    env[`CAMOU_CONFIG_${Math.floor(i / chunkSize) + 1}`] = serialized.slice(i, i + chunkSize);
  }
  if (serialized.length === 0) env.CAMOU_CONFIG_1 = '{}';
}

function runtimeMatches(actual, expected) {
  return stableStringify(actual) === stableStringify(expected);
}

function compatibleProfile(payload, { type, runtime, directIdentity, globalDigest }) {
  if (payload.type !== type || payload.schemaVersion !== FINGERPRINT_SCHEMA_VERSION) {
    throw new Error(`incompatible fingerprint profile ${type}; refusing to regenerate it`);
  }
  if (!runtimeMatches(payload.runtime, runtime)) {
    throw new Error(`fingerprint profile runtime mismatch for ${type}: stored ${JSON.stringify(payload.runtime)}, current ${JSON.stringify(runtime)}; migrate or explicitly remove the fingerprint profile`);
  }
  if (type === 'camoufox-browser-global-fingerprint' && !runtimeMatches(payload.directIdentity, directIdentity || null)) {
    throw new Error('configured CAMOFOX_LOCALE/CAMOFOX_TIMEZONE changed since this fingerprint was created; refusing to replace the stored identity');
  }
  if (type === 'camoufox-user-fingerprint' && payload.globalProfileDigest !== globalDigest) {
    throw new Error('browser-global fingerprint changed since this user identity was created; refusing to replace the stored identity');
  }
}

// GeoIP for a browser launch is not proof of a later Context proxy's egress.
// Until each user's actual egress can be verified and bound to its identity,
// fail closed for all proxies (including fixed-country pools) rather than
// silently restoring stale US/Japan geolocation, locale or WebRTC addresses.
export function assertFingerprintProxyPolicy({ proxyPool, proxy } = {}) {
  if (proxyPool || proxy) {
    throw new Error('persistent fingerprints currently support direct connections only; proxy egress is not verified per user, so fixed and rotating proxies are refused; disable the fingerprint plugin to use proxies');
  }
}

function assertNoPersistedNetworkLocation(config) {
  const networkKeys = Object.keys(config).filter((key) =>
    key.startsWith('geolocation:') || key === 'webrtc:ipv4' || key === 'webrtc:ipv6');
  if (networkKeys.length > 0) {
    throw new Error('persistent fingerprint contains GeoIP/geolocation or WebRTC IP fields; refusing to persist or restore a network-bound identity under the direct-only policy; explicit identity migration is required');
  }
}

export async function loadOrCreateBrowserFingerprint({ profileDir, options, runtime, directIdentity = null }) {
  assertFingerprintProxyPolicy({ proxy: options?.proxy });
  const launchConfig = readCamoufoxConfig(options?.env);
  assertNoPersistedNetworkLocation(launchConfig);
  const { root, browserPath, browserAnchorPath } = getFingerprintProfilePaths(profileDir, '__browser__');
  await ensureSecureDirectory(root);
  const candidate = {
    type: 'camoufox-browser-global-fingerprint',
    schemaVersion: FINGERPRINT_SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    runtime,
    directIdentity: directIdentity || null,
    camouConfig: launchConfig,
    camouConfigDigest: digestObject(launchConfig),
  };
  const validate = (payload) => {
    compatibleProfile(payload, { type: candidate.type, runtime, directIdentity: directIdentity || null });
    if (!payload.camouConfig || typeof payload.camouConfig !== 'object' || Array.isArray(payload.camouConfig)) {
      throw new Error('stored Camoufox global fingerprint config is invalid; refusing to regenerate it');
    }
    assertNoPersistedNetworkLocation(payload.camouConfig);
    if (digestObject(payload.camouConfig) !== payload.camouConfigDigest) {
      throw new Error('stored Camoufox global fingerprint config checksum mismatch; refusing to regenerate it');
    }
  };
  const record = await loadOrCreateRecord(browserPath, browserAnchorPath, candidate.type, async () => candidate, validate, () => refuseExistingProfileData(profileDir));
  const payload = payloadOf(record);
  writeCamoufoxConfig(options.env, payload.camouConfig, process.platform);
  return {
    profile: payload,
    config: payload.camouConfig,
    digest: record.integrity.digest,
    path: browserPath,
  };
}

function configLocale(config) {
  if (typeof config['navigator.language'] === 'string' && config['navigator.language']) {
    return config['navigator.language'];
  }
  const language = config['locale:language'];
  const region = config['locale:region'];
  if (typeof language === 'string' && language) return region ? `${language}-${region}` : language;
  return 'en-US';
}

function configTimezone(config, directIdentity) {
  const timezone = directIdentity?.timezoneId || config.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone });
  } catch {
    throw new Error(`Camoufox fingerprint has an invalid IANA timezone: ${timezone}`);
  }
  return timezone;
}

function randomInt32() {
  return crypto.randomInt(1, 0x1_0000_0000);
}

function makeSeededRandom(seed) {
  let state = seed >>> 0;
  if (state === 0) state = 0x9e3779b9;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function makeFontList(seed, generatedFonts = [], targetOS = 'linux') {
  const fontKey = ({ linux: 'lin', macos: 'mac', windows: 'win' })[targetOS];
  const available = FONTS[fontKey];
  if (!Array.isArray(available) || available.length === 0) {
    throw new Error(`pinned camoufox-js package does not provide a font catalog for ${targetOS}`);
  }
  const essential = new Set([
    'Arimo', 'Cousine', 'Tinos', 'Twemoji Mozilla',
    'Noto Sans Devanagari', 'Noto Sans JP', 'Noto Sans KR', 'Noto Sans SC', 'Noto Sans TC',
  ]);
  const generated = new Set(generatedFonts.filter((font) => available.includes(font)));
  const random = makeSeededRandom(seed);
  const coverage = 0.35 + random() * 0.31;
  return available.filter((font) => essential.has(font) || generated.has(font) || random() < coverage);
}

function createUserIdentity({ userId, runtime, globalConfig, directIdentity }) {
  if (!['linux', 'macos', 'windows'].includes(runtime.targetOS)) {
    throw new Error(`unsupported Camoufox fingerprint operating system: ${runtime.targetOS}`);
  }
  const outerWidth = Math.ceil(Number(globalConfig['window.outerWidth'] || globalConfig['screen.width'] || 1280));
  const outerHeight = Math.ceil(Number(globalConfig['window.outerHeight'] || globalConfig['screen.height'] || 720));
  // Screen constraints can eliminate every BrowserForge sample when a shared
  // Xvfb outer window is unusually large/tall. Generate from the full realistic
  // catalog, then clamp only the spoofed screen to the real shared window bounds.
  const sharedAppVersion = globalConfig['navigator.appVersion'];
  let fingerprint;
  let config;
  for (let attempt = 0; attempt < 32; attempt++) {
    fingerprint = generateFingerprint(undefined, { operatingSystems: [runtime.targetOS] });
    config = fromBrowserforge(fingerprint, runtime.browserVersion.split('.')[0]);
    if (!sharedAppVersion || config['navigator.appVersion'] === sharedAppVersion) break;
  }
  const generatedUserAgent = config['navigator.appVersion'] === sharedAppVersion
    ? config['navigator.userAgent']
    : globalConfig['navigator.userAgent'];
  const required = {
    // appVersion is browser-global in this build. If the sampled UA carries a
    // different Linux distro token, keep the persisted global UA rather than
    // pairing two inconsistent navigator strings or failing context creation.
    userAgent: generatedUserAgent,
    // navigator.appVersion has only a browser-global setter in this build.
    appVersion: sharedAppVersion || config['navigator.appVersion'],
    platform: config['navigator.platform'],
    oscpu: config['navigator.oscpu'],
    hardwareConcurrency: config['navigator.hardwareConcurrency'],
    // Keep screen/WebGL paired with the stored Camoufox baseline: this pinned
    // JS generator samples WebGL independently from screen resolution.
    screenWidth: Math.max(Number(globalConfig['screen.width']) || Number(config['screen.width']) || 0, outerWidth),
    screenHeight: Math.max(Number(globalConfig['screen.height']) || Number(config['screen.height']) || 0, outerHeight),
    colorDepth: Number(globalConfig['screen.colorDepth']) || config['screen.colorDepth'],
    webglVendor: globalConfig['webGl:vendor'],
    webglRenderer: globalConfig['webGl:renderer'],
  };
  for (const [name, value] of Object.entries(required)) {
    if (value === undefined || value === null || value === '') {
      throw new Error(`Camoufox fingerprint generator omitted required identity field ${name}`);
    }
  }
  if (!Number.isInteger(required.hardwareConcurrency) || required.hardwareConcurrency < 1) {
    throw new Error('Camoufox fingerprint generator produced invalid hardwareConcurrency');
  }
  if (typeof required.webglVendor !== 'string' || !required.webglVendor || typeof required.webglRenderer !== 'string' || !required.webglRenderer) {
    throw new Error('stored Camoufox global fingerprint is missing its WebGL vendor/renderer baseline');
  }

  const audioSeed = randomInt32();
  const fontSpacingSeed = randomInt32();
  const fontList = makeFontList(randomInt32(), fingerprint.fonts, runtime.targetOS);
  if (fontList.length === 0) throw new Error('Camoufox produced an empty native font identity');
  const locale = configLocale(globalConfig);
  const timezone = configTimezone(globalConfig, directIdentity);

  return {
    userIdHash: sha256(String(userId)),
    userAgent: required.userAgent,
    appVersion: required.appVersion,
    platform: required.platform,
    oscpu: required.oscpu,
    hardwareConcurrency: required.hardwareConcurrency,
    screen: {
      width: required.screenWidth,
      height: required.screenHeight,
      colorDepth: required.colorDepth,
      // devicePixelRatio is set by the shared browser build and is not currently
      // per-context in this Camoufox patch. Preserve the baseline instead.
      deviceScaleFactor: Number(globalConfig['window.devicePixelRatio']) || 1,
    },
    locale,
    timezone,
    audioSeed,
    fontSpacingSeed,
    fontList,
    webgl: { vendor: required.webglVendor, renderer: required.webglRenderer },
    scope: {
      contextNative: ['userAgent', 'platform', 'oscpu', 'hardwareConcurrency', 'screen', 'timezone', 'fontList', 'audioSeed', 'fontSpacingSeed'],
      sharedAcrossUsers: ['appVersion', 'locale', 'workerLanguage', 'devicePixelRatio', 'windowOuterSize', 'webglBaseline'],
      browserSession: ['canvasPngDeBGChunk'],
    },
  };
}

export async function loadOrCreateUserFingerprint({ profileDir, userId, runtime, globalProfile, globalConfig, directIdentity = null, storageState }) {
  const { users, userPath, userHash, userAnchorPath } = getFingerprintProfilePaths(profileDir, userId);
  await ensureSecureDirectory(users);
  const type = 'camoufox-user-fingerprint';
  const validate = (payload) => {
    compatibleProfile(payload, {
      type,
      runtime,
      globalDigest: globalProfile.digest,
    });
    if (payload.userIdHash !== userHash) {
      throw new Error('fingerprint profile userId hash mismatch; refusing to reuse or regenerate it');
    }
    if (!payload.identity || payload.identity.userIdHash !== userHash) {
      throw new Error('fingerprint profile identity is missing or belongs to another user; refusing to regenerate it');
    }
  };
  const record = await loadOrCreateRecord(userPath, userAnchorPath, type, async () => ({
    type,
    schemaVersion: FINGERPRINT_SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    runtime,
    userIdHash: userHash,
    globalProfileDigest: globalProfile.digest,
    identity: createUserIdentity({ userId, runtime, globalConfig, directIdentity }),
  }), validate, () => refuseUnboundStorage(profileDir, userId, storageState));
  return { profile: payloadOf(record), path: userPath };
}

export function contextFingerprintOptions(identity) {
  return {
    userAgent: identity.userAgent,
    locale: identity.locale,
    timezoneId: identity.timezone,
  };
}

export function buildNativeFingerprintInitScript(identity) {
  const setters = [
    ['setNavigatorUserAgent', [identity.userAgent]],
    ['setNavigatorPlatform', [identity.platform]],
    ['setNavigatorOscpu', [identity.oscpu]],
    ['setNavigatorHardwareConcurrency', [identity.hardwareConcurrency]],
    ['setScreenDimensions', [identity.screen.width, identity.screen.height]],
    ['setScreenColorDepth', [identity.screen.colorDepth]],
    ['setTimezone', [identity.timezone]],
    ['setFontSpacingSeed', [identity.fontSpacingSeed]],
    ['setAudioFingerprintSeed', [identity.audioSeed]],
    ['setFontList', [identity.fontList.join(',')]],
  ];
  return `(() => {\n  const setters = ${JSON.stringify(setters)};\n  for (const [name, args] of setters) {\n    if (typeof window[name] === 'function') window[name](...args);\n  }\n})();`;
}

export async function verifyContextNativeFingerprintSetters(context) {
  let page;
  try {
    // Probe without invoking the one-shot functions. The caller can then
    // register the init script before the context's first real page loads.
    page = await context.newPage();
    const available = await page.evaluate((names) => Object.fromEntries(names.map((name) => [name, typeof window[name]])), [...REQUIRED_NATIVE_SETTERS, 'setCanvasSeed']);
    const missing = REQUIRED_NATIVE_SETTERS.filter((name) => available[name] !== 'function');
    if (missing.length > 0) {
      throw new Error(`Camoufox binary is missing required per-context native fingerprint patches: ${missing.join(', ')}`);
    }
    return { canvasSeed: available.setCanvasSeed === 'function' };
  } finally {
    await Promise.resolve(page?.close()).catch(() => {});
  }
}

export async function verifyNativeFingerprintSetters(browser) {
  let context;
  try {
    context = await browser.newContext({ viewport: null });
    return await verifyContextNativeFingerprintSetters(context);
  } finally {
    await Promise.resolve(context?.close()).catch(() => {});
  }
}

export function nativeFingerprintSetterNames() {
  return [...REQUIRED_NATIVE_SETTERS];
}
