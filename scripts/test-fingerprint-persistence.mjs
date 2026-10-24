#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { firefox } from 'playwright-core';
import { launchOptions } from 'camoufox-js/dist/utils.js';
import {
  buildNativeFingerprintInitScript,
  contextFingerprintOptions,
  verifyContextNativeFingerprintSetters,
  getFingerprintProfilePaths,
  loadOrCreateBrowserFingerprint,
  loadOrCreateUserFingerprint,
  verifyNativeFingerprintSetters,
} from '../lib/fingerprint-persistence.js';
import { loadPersistedStorageState, persistStorageState } from '../lib/persistence.js';

const executablePath = process.env.CAMOFOX_FINGERPRINT_TEST_EXECUTABLE;
if (!executablePath) {
  console.error('Set CAMOFOX_FINGERPRINT_TEST_EXECUTABLE to the pinned Camoufox executable.');
  process.exit(2);
}

const require = createRequire(import.meta.url);
function installedVersion(name) {
  let current = path.dirname(require.resolve(name));
  while (true) {
    try {
      const manifest = JSON.parse(require('node:fs').readFileSync(path.join(current, 'package.json'), 'utf8'));
      if (manifest.name === name) return manifest.version;
    } catch {}
    const parent = path.dirname(current);
    if (parent === current) throw new Error(`could not find ${name} package.json`);
    current = parent;
  }
}

async function readVersionFile(executable) {
  let current = path.dirname(path.resolve(executable));
  for (let depth = 0; depth < 6; depth++) {
    try {
      const info = JSON.parse(await fs.readFile(path.join(current, 'version.json'), 'utf8'));
      return `${info.version}-${info.release}`;
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error('version.json not found beside the configured Camoufox executable');
}

function processTreeRssBytes(rootPid) {
  if (!rootPid || process.platform !== 'linux') return undefined;
  try {
    const entries = fsSync.readdirSync('/proc').filter((entry) => /^\d+$/.test(entry));
    const parents = new Map();
    for (const entry of entries) {
      try {
        const raw = fsSync.readFileSync(`/proc/${entry}/stat`, 'utf8');
        const rest = raw.slice(raw.lastIndexOf(')') + 2).split(' ');
        parents.set(Number(entry), Number(rest[1]));
      } catch {}
    }
    const tree = new Set([Number(rootPid)]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [pid, ppid] of parents) {
        if (tree.has(ppid) && !tree.has(pid)) {
          tree.add(pid);
          changed = true;
        }
      }
    }
    let bytes = 0;
    for (const pid of tree) {
      try {
        const status = fsSync.readFileSync(`/proc/${pid}/status`, 'utf8');
        const rssKb = Number(status.match(/^VmRSS:\s+(\d+) kB$/m)?.[1] || 0);
        bytes += rssKb * 1024;
      } catch {}
    }
    return bytes;
  } catch {
    return undefined;
  }
}

import fsSync from 'node:fs';

function startIdentityServer() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({ userAgent: req.headers['user-agent'], acceptLanguage: req.headers['accept-language'] });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><html><body>identity persistence test</body></html>');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, requests, origin: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function launchPinnedBrowser(profileDir, runtime) {
  const options = await launchOptions({
    executable_path: executablePath,
    headless: false,
    os: 'linux',
    locale: 'en-US',
    geoip: false,
    humanize: false,
    enable_cache: false,
    exclude_addons: ['UBO'],
  });
  const globalProfile = await loadOrCreateBrowserFingerprint({ profileDir, options, runtime });
  const browser = await firefox.launch(options);
  assert.equal(await browser.version(), runtime.browserVersion);
  const nativeCapabilities = await verifyNativeFingerprintSetters(browser);
  return { browser, globalProfile, nativeCapabilities };
}

async function openUserContext({ browser, profileDir, userId, runtime, globalProfile, globalConfig, storageState }) {
  const { profile } = await loadOrCreateUserFingerprint({ profileDir, userId, runtime, globalProfile, globalConfig });
  const context = await browser.newContext({
    viewport: null,
    ...contextFingerprintOptions(profile.identity),
    ...(storageState ? { storageState } : {}),
  });
  await verifyContextNativeFingerprintSetters(context);
  await context.addInitScript(buildNativeFingerprintInitScript(profile.identity));
  return { context, profile };
}

async function pageSignals(page, origin, cookieName) {
  await page.goto(origin);
  return page.evaluate(async ({ cookieName }) => {
    const worker = await new Promise((resolve, reject) => {
      const source = `const canvas = new OffscreenCanvas(16,16); const gl = canvas.getContext('webgl'); const ext = gl && gl.getExtension('WEBGL_debug_renderer_info'); const webgl = gl && ext ? [gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)] : null; postMessage({ userAgent: navigator.userAgent, platform: navigator.platform, cores: navigator.hardwareConcurrency, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, webgl });`;
      const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
      const instance = new Worker(url);
      const timeout = setTimeout(() => reject(new Error('worker identity test timed out')), 5000);
      instance.onmessage = (event) => { clearTimeout(timeout); instance.terminate(); URL.revokeObjectURL(url); resolve(event.data); };
      instance.onerror = (error) => { clearTimeout(timeout); instance.terminate(); URL.revokeObjectURL(url); reject(error); };
    });
    const canvas = document.createElement('canvas');
    canvas.width = 32;
    canvas.height = 32;
    const canvasContext = canvas.getContext('2d');
    canvasContext.fillStyle = '#336699';
    canvasContext.fillRect(1, 1, 25, 25);
    const imageData = canvasContext.getImageData(0, 0, canvas.width, canvas.height).data;
    let canvasPixels = 2166136261;
    for (const value of imageData) canvasPixels = Math.imul(canvasPixels ^ value, 16777619);
    const textCanvas = document.createElement('canvas');
    textCanvas.width = 512;
    textCanvas.height = 64;
    const textContext = textCanvas.getContext('2d');
    textContext.font = '32px Arial';
    const fontMetrics = ['Fingerprint persistence', 'The quick brown fox 0123456789', 'Camofox user identity'].map((text) => textContext.measureText(text).width.toFixed(6));
    textContext.fillStyle = '#000';
    textContext.fillText('Fingerprint persistence', 2, 48);
    const textImageData = textContext.getImageData(0, 0, textCanvas.width, textCanvas.height).data;
    let canvasTextPixels = 2166136261;
    for (const value of textImageData) canvasTextPixels = Math.imul(canvasTextPixels ^ value, 16777619);
    const webgl = document.createElement('canvas').getContext('webgl');
    const debug = webgl?.getExtension('WEBGL_debug_renderer_info');
    const webglIdentity = webgl && debug ? [webgl.getParameter(debug.UNMASKED_VENDOR_WEBGL), webgl.getParameter(debug.UNMASKED_RENDERER_WEBGL)] : null;
    // Run the typed-array audio probe in the page's main world; Firefox's
    // automation/debugger world intentionally blocks typed-array reads through Xrays.
    const audioHash = await new Promise((resolve, reject) => {
      const source = `(() => { const ctx = new OfflineAudioContext(1,5000,44100); const osc = ctx.createOscillator(); const comp = ctx.createDynamicsCompressor(); osc.type = 'triangle'; osc.frequency.value = 10000; comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12; comp.attack.value = 0; comp.release.value = 0.25; osc.connect(comp); comp.connect(ctx.destination); osc.start(0); ctx.startRendering().then(buffer => { const data = buffer.getChannelData(0); let sum = 0; let weighted = 0; for (let i = 0; i < data.length; i++) { sum += data[i]; weighted += data[i] * (i + 1); } const samples = Array.from(data.slice(0, 8)).map(value => value.toPrecision(8)).join(','); document.documentElement.setAttribute('data-audio-fingerprint', data.length + ':' + sum.toPrecision(12) + ':' + weighted.toPrecision(12) + ':' + samples); }).catch(error => document.documentElement.setAttribute('data-audio-fingerprint-error', String(error))); })();`;
      let timer;
      const observer = new MutationObserver(() => {
        const error = document.documentElement.getAttribute('data-audio-fingerprint-error');
        const value = document.documentElement.getAttribute('data-audio-fingerprint');
        if (error) { clearTimeout(timer); observer.disconnect(); reject(new Error(error)); }
        if (value) { clearTimeout(timer); observer.disconnect(); document.documentElement.removeAttribute('data-audio-fingerprint'); resolve(value); }
      });
      observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-audio-fingerprint', 'data-audio-fingerprint-error'] });
      const script = document.createElement('script');
      script.textContent = source;
      document.documentElement.append(script);
      script.remove();
      timer = setTimeout(() => { observer.disconnect(); reject(new Error('audio identity test timed out')); }, 5000);
    });
    let indexedDbValue = null;
    if (indexedDB) {
      indexedDbValue = await new Promise((resolve) => {
        const request = indexedDB.open('fingerprint-persistence-test', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('state');
        request.onsuccess = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains('state')) { db.close(); resolve(null); return; }
          const get = db.transaction('state', 'readonly').objectStore('state').get('key');
          get.onsuccess = () => { db.close(); resolve(get.result ?? null); };
          get.onerror = () => { db.close(); resolve(null); };
        };
        request.onerror = () => resolve(null);
      });
    }
    return {
      userAgent: navigator.userAgent,
      appVersion: navigator.appVersion,
      platform: navigator.platform,
      oscpu: navigator.oscpu,
      hardwareConcurrency: navigator.hardwareConcurrency,
      language: navigator.language,
      languages: navigator.languages,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: [screen.width, screen.height, screen.availWidth, screen.availHeight, screen.colorDepth],
      screenCss: [matchMedia(`(device-width: ${screen.width}px)`).matches, matchMedia(`(device-height: ${screen.height}px)`).matches],
      window: [innerWidth, innerHeight, outerWidth, outerHeight, devicePixelRatio],
      worker,
      webgl: webglIdentity,
      audioHash,
      canvasPixels: (canvasPixels >>> 0).toString(16),
      canvasTextPixels: (canvasTextPixels >>> 0).toString(16),
      fontMetrics,
      canvasPng: canvas.toDataURL(),
      cookie: document.cookie.split('; ').find((item) => item.startsWith(`${cookieName}=`)) || null,
      localStorageValue: localStorage.getItem('persisted-value'),
      indexedDbValue,
    };
  }, { cookieName });
}

async function probeWebGLContextSetters(browser) {
  const probes = [];
  for (const [vendor, renderer] of [
    ['FingerprintVendorA', 'FingerprintRendererA'],
    ['FingerprintVendorB', 'FingerprintRendererB'],
  ]) {
    const context = await browser.newContext({ viewport: null });
    try {
      const page = await context.newPage();
      const settersAvailable = await page.evaluate(() =>
        typeof window.setWebGLVendor === 'function' && typeof window.setWebGLRenderer === 'function');
      await context.addInitScript(({ vendor, renderer }) => {
        if (typeof window.setWebGLVendor === 'function') window.setWebGLVendor(vendor);
        if (typeof window.setWebGLRenderer === 'function') window.setWebGLRenderer(renderer);
      }, { vendor, renderer });
      await page.goto('data:text/html,<title>WebGL setter probe</title>');
      const actual = await page.evaluate(() => {
        const gl = document.createElement('canvas').getContext('webgl');
        const debug = gl?.getExtension('WEBGL_debug_renderer_info');
        return debug ? [gl.getParameter(debug.UNMASKED_VENDOR_WEBGL), gl.getParameter(debug.UNMASKED_RENDERER_WEBGL)] : null;
      });
      probes.push({ expected: [vendor, renderer], actual, settersAvailable });
    } finally {
      await context.close();
    }
  }
  return {
    probes,
    settersAvailable: probes.every((probe) => probe.settersAvailable),
    appliesPerContext: probes.every((probe) => JSON.stringify(probe.actual) === JSON.stringify(probe.expected))
      && JSON.stringify(probes[0]?.actual) !== JSON.stringify(probes[1]?.actual),
  };
}

const profileDir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-fingerprint-integration-'));
const identityServer = await startIdentityServer();
const runtime = {
  appVersion: JSON.parse(await fs.readFile(new URL('../package.json', import.meta.url), 'utf8')).version,
  camoufoxJsVersion: installedVersion('camoufox-js'),
  playwrightVersion: installedVersion('playwright-core'),
  platform: process.platform,
  arch: process.arch,
  targetOS: 'linux',
  browserVersion: await readVersionFile(executablePath),
};
let browser;
let restoredBrowser;
try {
  const first = await launchPinnedBrowser(profileDir, runtime);
  browser = first.browser;
  const globalProfile = first.globalProfile;
  const webglSetterProbe = await probeWebGLContextSetters(browser);
  assert.equal(webglSetterProbe.settersAvailable, true, 'pinned build should expose the WebGL setters being evaluated');
  assert.equal(webglSetterProbe.appliesPerContext, false, 'the pinned beta.30 WebGL setters do not override the native browser baseline');
  const browserBaseRss = processTreeRssBytes(process.pid);
  const [userA, userB] = await Promise.all([
    openUserContext({ browser, profileDir, userId: 'integration-user-A', runtime, globalProfile, globalConfig: globalProfile.config }),
    openUserContext({ browser, profileDir, userId: 'integration-user-B', runtime, globalProfile, globalConfig: globalProfile.config }),
  ]);
  const twoEmptyContextRss = processTreeRssBytes(process.pid);
  await Promise.all([userA.context.addCookies([{ name: 'sid', value: 'persisted-cookie', url: identityServer.origin }])]);
  const pageA = await userA.context.newPage();
  const pageB = await userB.context.newPage();
  const pageErrors = [];
  pageA.on('pageerror', (error) => pageErrors.push(error.message));
  const [signalsA, signalsB] = await Promise.all([
    pageSignals(pageA, identityServer.origin, 'sid'),
    pageSignals(pageB, identityServer.origin, 'sid'),
  ]);
  await pageA.evaluate(async () => {
    localStorage.setItem('persisted-value', 'local-storage-ok');
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open('fingerprint-persistence-test', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('state');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('state', 'readwrite');
      transaction.objectStore('state').put('indexeddb-ok', 'key');
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
    });
    db.close();
  });
  const persisted = await persistStorageState({ profileDir, userId: 'integration-user-A', context: userA.context, indexedDB: true });
  assert.equal(persisted.persisted, true, 'existing storage-state persistence must succeed');
  const savedStatePath = await loadPersistedStorageState(profileDir, 'integration-user-A');
  assert.equal(savedStatePath, persisted.storageStatePath);

  assert.equal(signalsA.userAgent, userA.profile.identity.userAgent, 'page UA should match the persisted per-user identity');
  assert.equal(signalsA.userAgent, signalsA.worker.userAgent, 'page/Worker UA should match');
  assert.equal(signalsA.hardwareConcurrency, userA.profile.identity.hardwareConcurrency, 'native hardwareConcurrency should match the stored identity');
  assert.deepEqual(signalsA.screen.slice(0, 2), [userA.profile.identity.screen.width, userA.profile.identity.screen.height]);
  assert.equal(signalsA.timezone, userA.profile.identity.timezone);
  assert.equal(signalsA.platform, signalsA.worker.platform, 'page/Worker platform should match');
  assert.equal(signalsA.hardwareConcurrency, signalsA.worker.cores, 'page/Worker hardwareConcurrency should match');
  assert.equal(signalsA.language, 'en-US');
  assert.equal(signalsA.languages[0], 'en-US');
  assert.equal(signalsA.language, signalsA.worker.language, 'Worker language remains the same global baseline');
  assert.equal(signalsA.timezone, signalsA.worker.timezone, 'page/Worker timezone should match');
  assert.deepEqual(signalsA.worker.webgl, signalsA.webgl, 'OffscreenCanvas WebGL should match page WebGL in Workers');
  assert.deepEqual(signalsB.worker.webgl, signalsB.webgl, 'OffscreenCanvas WebGL should match page WebGL in Workers');
  assert.deepEqual(signalsA.screenCss, [true, true], 'screen APIs should agree with CSS device media queries');
  assert.ok(signalsA.screen[0] >= signalsA.window[2] && signalsA.screen[1] >= signalsA.window[3], 'reported screen must contain the shared outer window');
  assert.deepEqual(signalsB.screenCss, [true, true], 'screen APIs should agree with CSS device media queries');
  assert.equal(signalsA.appVersion, userA.profile.identity.appVersion, 'appVersion should match its recorded shared baseline');
  assert.equal(signalsA.appVersion, globalProfile.config['navigator.appVersion']);
  assert.ok(signalsA.userAgent.includes('Firefox/152.0'));
  assert.ok(signalsB.userAgent.includes('Firefox/152.0'));
  assert.equal(signalsA.screen[4], 24);
  assert.notDeepEqual(userA.profile.identity, userB.profile.identity, 'different userIds must receive different identities');
  assert.equal(signalsB.hardwareConcurrency, userB.profile.identity.hardwareConcurrency, 'user B native cores should match its stored identity');
  assert.deepEqual(signalsB.screen.slice(0, 2), [userB.profile.identity.screen.width, userB.profile.identity.screen.height]);
  assert.equal(signalsB.timezone, userB.profile.identity.timezone);
  assert.notEqual(userA.profile.identity.audioSeed, userB.profile.identity.audioSeed);
  assert.notEqual(userA.profile.identity.fontSpacingSeed, userB.profile.identity.fontSpacingSeed);
  assert.notEqual(signalsA.audioHash, signalsB.audioHash, 'per-context audio output should differ by persisted seed');
  assert.notDeepEqual(signalsA.fontMetrics, signalsB.fontMetrics, 'per-context font-spacing seed should change Canvas text metrics');
  assert.notEqual(signalsA.canvasTextPixels, signalsB.canvasTextPixels, 'per-context font identity should change rendered Canvas text pixels');
  assert.equal(identityServer.requests.find((request) => request.userAgent === signalsA.userAgent)?.acceptLanguage?.startsWith('en-US'), true, 'HTTP headers should agree with page locale/UA');
  assert.equal(identityServer.requests.find((request) => request.userAgent === signalsB.userAgent)?.acceptLanguage?.startsWith('en-US'), true, 'HTTP headers should agree with page locale/UA');
  const secondPageA = await userA.context.newPage();
  secondPageA.on('pageerror', (error) => pageErrors.push(error.message));
  const secondPageSignals = await pageSignals(secondPageA, identityServer.origin, 'sid');
  assert.equal(secondPageSignals.hardwareConcurrency, signalsA.hardwareConcurrency, 'same user identity should persist in a second tab');
  assert.deepEqual(secondPageSignals.webgl, signalsA.webgl);
  assert.equal(secondPageSignals.audioHash, signalsA.audioHash, 'same user audio seed should persist across tabs');
  assert.deepEqual(secondPageSignals.fontMetrics, signalsA.fontMetrics, 'same user font-spacing seed should persist across tabs');
  assert.deepEqual(pageErrors, [], 'one-shot native init script must not throw on navigation or a second tab');
  const twoPopulatedPageRss = processTreeRssBytes(process.pid);
  await Promise.all([userA.context.close(), userB.context.close()]);
  await browser.close();
  browser = undefined;

  const restarted = await launchPinnedBrowser(profileDir, runtime);
  restoredBrowser = restarted.browser;
  assert.equal(restarted.globalProfile.digest, globalProfile.digest, 'global Camoufox config should survive browser restart');
  const restoredA = await openUserContext({
    browser: restoredBrowser,
    profileDir,
    userId: 'integration-user-A',
    runtime,
    globalProfile: restarted.globalProfile,
    globalConfig: restarted.globalProfile.config,
    storageState: savedStatePath,
  });
  const restoredPage = await restoredA.context.newPage();
  const restoredSignals = await pageSignals(restoredPage, identityServer.origin, 'sid');
  assert.deepEqual(restoredA.profile.identity, userA.profile.identity, 'same user identity should be byte-for-byte stable across browser restart');
  assert.equal(restoredSignals.userAgent, signalsA.userAgent);
  assert.equal(restoredSignals.appVersion, signalsA.appVersion);
  assert.equal(restoredSignals.platform, signalsA.platform);
  assert.equal(restoredSignals.hardwareConcurrency, signalsA.hardwareConcurrency);
  assert.equal(restoredSignals.audioHash, signalsA.audioHash, 'per-user audio output should survive browser restart');
  assert.deepEqual(restoredSignals.fontMetrics, signalsA.fontMetrics, 'per-user Canvas text metrics should survive browser restart');
  assert.deepEqual(restoredSignals.screen, signalsA.screen);
  assert.equal(restoredSignals.timezone, signalsA.timezone);
  assert.deepEqual(restoredSignals.webgl, signalsA.webgl, 'WebGL remains stable across restart');
  assert.deepEqual(signalsA.webgl, [userA.profile.identity.webgl.vendor, userA.profile.identity.webgl.renderer]);
  assert.deepEqual(signalsB.webgl, [userB.profile.identity.webgl.vendor, userB.profile.identity.webgl.renderer]);
  assert.deepEqual(signalsA.webgl, signalsB.webgl, 'WebGL is intentionally held to the persisted browser-global baseline in this build');
  assert.deepEqual(signalsA.webgl, [globalProfile.config['webGl:vendor'], globalProfile.config['webGl:renderer']]);
  assert.equal(restoredSignals.canvasPixels, signalsA.canvasPixels, 'raw Canvas pixels should remain stable');
  assert.equal(restoredSignals.canvasTextPixels, signalsA.canvasTextPixels, 'Canvas text pixels should remain stable for the same user');
  assert.notEqual(restoredSignals.canvasPng, signalsA.canvasPng, 'Firefox PNG deBG chunk is expected to rotate at process restart');
  assert.equal(restoredSignals.cookie, 'sid=persisted-cookie');
  assert.equal(restoredSignals.localStorageValue, 'local-storage-ok');
  assert.equal(restoredSignals.indexedDbValue, 'indexeddb-ok');
  await restoredA.context.close();
  await restoredBrowser.close();
  restoredBrowser = undefined;

  const userPaths = getFingerprintProfilePaths(profileDir, 'integration-user-A');
  const original = await fs.readFile(userPaths.userPath);
  await fs.writeFile(userPaths.userPath, Buffer.from('corrupted identity file\n'), { mode: 0o600 });
  await assert.rejects(loadOrCreateUserFingerprint({
    profileDir,
    userId: 'integration-user-A',
    runtime,
    globalProfile: restarted.globalProfile,
    globalConfig: restarted.globalProfile.config,
  }), /corrupted|integrity check failed/);
  const corruptedBytes = await fs.readFile(userPaths.userPath);
  assert.deepEqual(corruptedBytes, Buffer.from('corrupted identity file\n'), 'corrupt profile must not be overwritten with a new identity');
  // Restore only inside this disposable integration profile before cleanup.
  await fs.writeFile(userPaths.userPath, original, { mode: 0o600 });

  console.log(JSON.stringify({
    ok: true,
    runtime,
    users: {
      A: { userAgent: signalsA.userAgent, hardwareConcurrency: signalsA.hardwareConcurrency, screen: signalsA.screen, timezone: signalsA.timezone },
      B: { userAgent: signalsB.userAgent, hardwareConcurrency: signalsB.hardwareConcurrency, screen: signalsB.screen, timezone: signalsB.timezone },
      sameUserAfterRestart: true,
      sharedWebGLBaseline: userA.profile.identity.webgl,
      canvasSeedSetterAvailable: first.nativeCapabilities.canvasSeed,
      webglSetterProbe,
    },
    consistency: {
      requestHeaders: true,
      workerNavigator: true,
      cookieRestored: true,
      localStorageRestored: true,
      indexedDBRestored: true,
      rawCanvasPixelsStableAcrossRestart: restoredSignals.canvasPixels === signalsA.canvasPixels,
      rawCanvasTextPixelsStableAcrossRestart: restoredSignals.canvasTextPixels === signalsA.canvasTextPixels,
      rawCanvasTextPixelsDifferAcrossUsers: signalsA.canvasTextPixels !== signalsB.canvasTextPixels,
      canvasPngDeBGChunkRotatesAcrossRestart: true,
      webglSharedAcrossUsersAndStableAcrossRestart: true,
      offscreenWebGLMatchesPage: true,
      perContextAudioDiffersAndPersists: true,
      perContextFontMetricsDifferAndPersist: true,
      screenApisMatchCssMediaQueries: true,
      corruptProfileNotReplaced: true,
    },
    browserProcessTreeRssBytes: {
      browserBaseline: browserBaseRss,
      twoEmptyContexts: twoEmptyContextRss,
      twoPopulatedPages: twoPopulatedPageRss,
      extraForTwoContexts: browserBaseRss != null && twoEmptyContextRss != null ? twoEmptyContextRss - browserBaseRss : null,
      extraForTwoPagesAndNavigation: twoEmptyContextRss != null && twoPopulatedPageRss != null ? twoPopulatedPageRss - twoEmptyContextRss : null,
    },
  }, null, 2));
} finally {
  await browser?.close().catch(() => {});
  await restoredBrowser?.close().catch(() => {});
  await new Promise((resolve) => identityServer.server.close(resolve));
  await fs.rm(profileDir, { recursive: true, force: true });
}
