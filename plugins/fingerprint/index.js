import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { resolveProfileDirectory } from '../../lib/config.js';
import { verifyAppliedContextFingerprint } from '../../lib/fingerprint-verification.js';
import {
  assertFingerprintProxyPolicy,
  buildNativeFingerprintInitScript,
  contextFingerprintOptions,
  loadOrCreateBrowserFingerprint,
  loadOrCreateUserFingerprint,
  verifyContextNativeFingerprintSetters,
  verifyNativeFingerprintSetters,
} from '../../lib/fingerprint-persistence.js';

const require = createRequire(import.meta.url);

function installedPackageVersion(name) {
  let current = path.dirname(require.resolve(name));
  while (true) {
    try {
      const manifest = JSON.parse(require('node:fs').readFileSync(path.join(current, 'package.json'), 'utf8'));
      if (manifest.name === name && typeof manifest.version === 'string') return manifest.version;
    } catch {}
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error(`could not resolve installed package version for ${name}`);
}

function targetOSForPlatform(platform) {
  return ({ linux: 'linux', darwin: 'macos', win32: 'windows' })[platform] || platform;
}

async function browserVersionForExecutable(executablePath) {
  if (typeof executablePath !== 'string' || executablePath.length === 0) {
    throw new Error('Camoufox fingerprint persistence requires an explicit executablePath');
  }
  let current = path.dirname(path.resolve(executablePath));
  for (let depth = 0; depth < 6; depth++) {
    const versionPath = path.join(current, 'version.json');
    try {
      const data = JSON.parse(await fs.readFile(versionPath, 'utf8'));
      if (typeof data.version === 'string' && typeof data.release === 'string') {
        return `${data.version}-${data.release}`;
      }
      if (typeof data.version === 'string') return data.version;
      throw new Error(`invalid Camoufox version metadata at ${versionPath}`);
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error(`could not find version.json for Camoufox executable ${executablePath}`);
}

export async function register(_app, ctx, pluginConfig = {}) {
  const { events, config, log, registerSessionContextInitializer } = ctx;
  if (pluginConfig.enabled === false) return;
  if (typeof registerSessionContextInitializer !== 'function') {
    throw new Error('fingerprint plugin requires core session-context initializer support');
  }

  const profileDir = resolveProfileDirectory(config, pluginConfig);
  if (!profileDir) throw new Error('fingerprint persistence requires profileDir');

  const appManifest = JSON.parse(await fs.readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const runtimeBase = {
    appVersion: appManifest.version,
    camoufoxJsVersion: installedPackageVersion('camoufox-js'),
    playwrightVersion: installedPackageVersion('playwright-core'),
    platform: process.platform,
    arch: process.arch,
    targetOS: targetOSForPlatform(process.platform),
  };
  const directIdentity = config.directIdentity || null;
  let browserProfile = null;
  let runtimeReady = Promise.resolve();
  async function loadUserProfile(userId) {
    if (!browserProfile) throw new Error('Camoufox fingerprint profile is unavailable');
    return loadOrCreateUserFingerprint({
      profileDir,
      userId,
      runtime: browserProfile.profile.runtime,
      globalProfile: browserProfile,
      globalConfig: browserProfile.config,
      directIdentity,
    });
  }

  events.on('browser:launching', async ({ options }) => {
    assertFingerprintProxyPolicy({ proxyPool: ctx.proxyPool, proxy: options?.proxy });
    const browserVersion = await browserVersionForExecutable(options?.executablePath);
    const runtime = { ...runtimeBase, browserVersion };
    browserProfile = await loadOrCreateBrowserFingerprint({
      profileDir,
      options,
      runtime,
      directIdentity,
    });
    runtimeReady = Promise.resolve();
    log('info', 'persistent Camoufox browser fingerprint loaded', {
      browserVersion,
      camoufoxJsVersion: runtime.camoufoxJsVersion,
      profilePath: browserProfile.path,
    });
  });

  events.on('browser:launched', ({ browser }) => {
    const expectedVersion = browserProfile?.profile?.runtime?.browserVersion;
    runtimeReady = (async () => {
      if (!browserProfile || !expectedVersion) {
        throw new Error('Camoufox global fingerprint was not initialized before browser launch');
      }
      const actualVersion = await browser.version();
      if (actualVersion !== expectedVersion) {
        throw new Error(`Camoufox binary/runtime version mismatch: profile expects ${expectedVersion}, browser reports ${actualVersion}`);
      }
      const nativeCapabilities = await verifyNativeFingerprintSetters(browser);
      if (!nativeCapabilities.canvasSeed) {
        log('warn', 'pinned Camoufox binary has no per-context Canvas seed setter; Canvas pixels use the persisted browser-global baseline and PNG deBG export metadata rotates per browser process', { browserVersion: actualVersion });
      }
      log('warn', 'pinned Camoufox 152.0.4-beta.30 exposes WebGL setters but they do not apply per-context; WebGL remains on the persisted browser-global baseline', { browserVersion: actualVersion });
    })().catch(async (err) => {
      await Promise.resolve(browser.close()).catch(() => {});
      throw err;
    });
    // browser:launched is a fire-and-forget event; mark the rejection handled
    // here and surface the original failure when a user context is requested.
    runtimeReady.catch(() => {});
  });

  events.on('session:creating', async ({ userId, contextOptions }) => {
    assertFingerprintProxyPolicy({ proxyPool: ctx.proxyPool, proxy: contextOptions?.proxy });
    await runtimeReady;
    if (!browserProfile) throw new Error('Camoufox fingerprint profile is unavailable');

    const { profile, path: profilePath } = await loadUserProfile(userId);
    Object.assign(contextOptions, contextFingerprintOptions(profile.identity));
    log('info', 'persistent per-user Camoufox fingerprint loaded', {
      userId,
      profilePath,
      sharedSignals: profile.identity.scope.sharedAcrossUsers,
      browserSessionSignals: profile.identity.scope.browserSession,
    });
  });

  registerSessionContextInitializer('fingerprint', async ({ userId, context, contextOptions }) => {
    assertFingerprintProxyPolicy({ proxyPool: ctx.proxyPool, proxy: contextOptions?.proxy });
    const { profile } = await loadUserProfile(userId);
    // Check this exact BrowserContext without invoking its one-shot setters,
    // then register them before the first real page. Repeated navigations are
    // safe because the native APIs self-remove and the script is guarded.
    await verifyContextNativeFingerprintSetters(context);
    await context.addInitScript(buildNativeFingerprintInitScript(profile.identity));
    await verifyAppliedContextFingerprint(context, profile.identity);
  });

  log('info', 'persistent per-user Camoufox fingerprint plugin enabled', { profileDir });
}
