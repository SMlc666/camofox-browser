import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { createPluginEvents } from '../../lib/plugins.js';
import { register } from './index.js';

const noop = jest.fn();

describe('fingerprint plugin lifecycle', () => {
  let tempDir;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-fingerprint-plugin-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  test('disabled mode registers no hooks or context initializer and writes no profiles', async () => {
    const events = createPluginEvents();
    const registerInitializer = jest.fn();
    await register({}, {
      events,
      config: { profileDir: tempDir },
      proxyPool: { canRotateSessions: true },
      registerSessionContextInitializer: registerInitializer,
      log: noop,
    }, { enabled: false });
    expect(events.eventNames()).toEqual([]);
    expect(registerInitializer).not.toHaveBeenCalled();
    expect(await fs.readdir(tempDir)).toEqual([]);
  });

  test.each([
    ['rotating proxy pool', { canRotateSessions: true }, undefined],
    ['fixed proxy pool', { canRotateSessions: false }, undefined],
    ['launch proxy override', null, { server: 'http://proxy.invalid:8080' }],
  ])('fails closed for %s before persisting a baseline', async (_name, proxyPool, proxy) => {
    const events = createPluginEvents();
    let initialize;
    await register({}, {
      events, config: { profileDir: tempDir }, proxyPool,
      registerSessionContextInitializer: (_name, callback) => { initialize = callback; },
      log: noop,
    }, { enabled: true });
    await expect(events.emitAsync('browser:launching', { options: { proxy } }))
      .rejects.toThrow(/direct connections only/);
    const contextOptions = { proxy: proxy || { server: 'http://context-proxy.invalid:8080' } };
    await expect(events.emitAsync('session:creating', { userId: 'user', contextOptions }))
      .rejects.toThrow(/direct connections only/);
    await expect(initialize({ userId: 'user', context: {}, contextOptions }))
      .rejects.toThrow(/direct connections only/);
    expect(await fs.readdir(tempDir)).toEqual([]);
  });

  test('restores per-user native identity before the session context is exposed', async () => {
    const binaryDir = path.join(tempDir, 'camoufox');
    await fs.mkdir(binaryDir, { recursive: true });
    await fs.writeFile(path.join(binaryDir, 'camoufox-bin'), 'test fixture');
    await fs.writeFile(path.join(binaryDir, 'version.json'), JSON.stringify({ version: '152.0.4', release: 'beta.30' }));

    const events = createPluginEvents();
    const registerInitializer = jest.fn();
    let initializeContext;
    registerInitializer.mockImplementation((_name, callback) => { initializeContext = callback; });
    const log = jest.fn();
    await register({}, {
      events,
      config: { profileDir: tempDir, directIdentity: null },
      registerSessionContextInitializer: registerInitializer,
      log,
    }, { enabled: true });

    const launchOptions = { executablePath: path.join(binaryDir, 'camoufox-bin'), env: {} };
    const { writeCamoufoxConfig } = await import('../../lib/fingerprint-persistence.js');
    writeCamoufoxConfig(launchOptions.env, {
      'navigator.userAgent': 'Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0',
      'locale:language': 'en',
      'locale:region': 'US',
      'screen.width': 1280,
      'screen.height': 720,
      'window.outerWidth': 1280,
      'window.outerHeight': 720,
      'screen.colorDepth': 24,
      'webGl:vendor': 'Intel',
      'webGl:renderer': 'Intel GPU',
    });
    await events.emitAsync('browser:launching', { options: launchOptions });

    const setterNames = [
      'setNavigatorUserAgent', 'setNavigatorPlatform', 'setNavigatorOscpu',
      'setNavigatorHardwareConcurrency', 'setScreenDimensions', 'setScreenColorDepth',
      'setTimezone', 'setFontSpacingSeed', 'setAudioFingerprintSeed', 'setFontList',
    ];
    const mockPage = {
      evaluate: jest.fn(async (_fn, names) => Object.fromEntries(names.map((name) => [name, 'function']))),
      close: jest.fn(),
    };
    const mockContext = { newPage: jest.fn(async () => mockPage), close: jest.fn(), addInitScript: jest.fn() };
    const browser = {
      version: jest.fn(async () => '152.0.4-beta.30'),
      newContext: jest.fn(async () => mockContext),
      close: jest.fn(),
    };
    events.emit('browser:launched', { browser });

    const contextOptions = { viewport: null };
    await events.emitAsync('session:creating', { userId: 'stable-user', contextOptions });
    await new Promise((resolve) => setImmediate(resolve));

    expect(browser.newContext).toHaveBeenCalledWith({ viewport: null });
    expect(mockPage.evaluate).toHaveBeenCalledWith(expect.any(Function), expect.arrayContaining(setterNames));
    expect(contextOptions.userAgent).toMatch(/Firefox\/152\.0/);
    expect(contextOptions.locale).toBe('en-US');
    expect(contextOptions.timezoneId).toBeTruthy();
    expect(contextOptions.viewport).toBeNull();
    expect(initializeContext).toEqual(expect.any(Function));

    const context = { newPage: jest.fn(async () => mockPage), addInitScript: jest.fn() };
    await initializeContext({ userId: 'stable-user', context });
    const script = context.addInitScript.mock.calls[0][0];
    expect(script).toContain('setNavigatorHardwareConcurrency');
    expect(script).not.toContain('setWebGLVendor');
    expect(script).not.toMatch(/Object\.defineProperty|navigator\.userAgent\s*=/);
    expect(mockContext.close).toHaveBeenCalled();
    expect(mockPage.close).toHaveBeenCalled();
  });

  test('fails closed when the runtime patch set is incomplete', async () => {
    const binaryDir = path.join(tempDir, 'camoufox');
    await fs.mkdir(binaryDir, { recursive: true });
    await fs.writeFile(path.join(binaryDir, 'version.json'), JSON.stringify({ version: '152.0.4', release: 'beta.30' }));

    const events = createPluginEvents();
    let initializeContext;
    await register({}, {
      events,
      config: { profileDir: tempDir, directIdentity: null },
      registerSessionContextInitializer: (_name, callback) => { initializeContext = callback; },
      log: noop,
    }, { enabled: true });
    const options = { executablePath: path.join(binaryDir, 'camoufox-bin'), env: {} };
    const { writeCamoufoxConfig } = await import('../../lib/fingerprint-persistence.js');
    writeCamoufoxConfig(options.env, {
      'navigator.userAgent': 'ua',
      'screen.width': 1280,
      'screen.height': 720,
      'screen.colorDepth': 24,
      'webGl:vendor': 'Intel',
      'webGl:renderer': 'Intel GPU',
    });
    await events.emitAsync('browser:launching', { options });

    const page = {
      evaluate: jest.fn(async (_fn, names) => Object.fromEntries(names.map((name) => [name, name === 'setTimezone' ? 'undefined' : 'function']))),
      close: jest.fn(),
    };
    const context = { newPage: async () => page, close: jest.fn() };
    const browser = { version: async () => '152.0.4-beta.30', newContext: async () => context, close: jest.fn() };
    events.emit('browser:launched', { browser });
    await expect(events.emitAsync('session:creating', { userId: 'user', contextOptions: {} }))
      .rejects.toThrow(/missing required per-context native fingerprint patches: setTimezone/);
    expect(browser.close).toHaveBeenCalled();
    expect(initializeContext).toEqual(expect.any(Function));
  });
});
