import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals';

// Real Node subprocesses exercise dynamic imports/registration, avoiding Jest's
// temp-directory ESM import limitations (not just a mocked loader decision).
const loaderUrl = new URL('../../lib/plugins.js', import.meta.url).href;
let root;
beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'camofox-loader-safety-')); });
afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });

function fixture(configText, source = 'export function register(app) { app.registered = true; }') {
  const pluginsDir = path.join(root, 'plugins');
  const pluginDir = path.join(pluginsDir, 'fingerprint');
  fs.mkdirSync(pluginDir, { recursive: true });
  fs.writeFileSync(path.join(pluginDir, 'package.json'), '{"type":"module"}');
  fs.writeFileSync(path.join(pluginDir, 'index.js'), source);
  const configPath = path.join(root, 'config.json');
  if (configText !== undefined) fs.writeFileSync(configPath, configText);
  return { pluginsDir, configPath };
}

function run(options) {
  const script = `import { loadPlugins } from ${JSON.stringify(loaderUrl)};
    const app = {}; const ctx = { log() {}, config: {} };
    try { const loaded = await loadPlugins(app, ctx, ${JSON.stringify(options)}); console.log(JSON.stringify({loaded, app})); }
    catch (error) { console.log(JSON.stringify({error: error.message})); }`;
  return JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 15000 }));
}

describe('fingerprint explicit opt-in and critical registration policy', () => {
  test.each([
    ['missing config', undefined],
    ['malformed config', '{not json'],
    ['missing plugins', '{}'],
    ['legacy all-plugin config', '{"plugins":null}'],
    ['legacy array', '{"plugins":["fingerprint"]}'],
    ['empty object', '{"plugins":{"fingerprint":{}}}'],
    ['string true', '{"plugins":{"fingerprint":{"enabled":"true"}}}'],
    ['disabled', '{"plugins":{"fingerprint":{"enabled":false}}}'],
  ])('%s does not auto-import or register fingerprint', (_name, config) => {
    // Top-level throw also proves the module is not imported in default mode.
    const result = run(fixture(config, 'throw new Error("must not import");'));
    expect(result).toEqual({ loaded: [], app: {} });
  });

  test('explicit true imports and registers successfully', () => {
    expect(run(fixture('{"plugins":{"fingerprint":{"enabled":true}}}')))
      .toEqual({ loaded: ['fingerprint'], app: { registered: true } });
  });

  test.each([
    ['import failure', 'throw new Error("import exploded");'],
    ['registration failure', 'export function register() { throw new Error("registration exploded"); }'],
    ['missing export', 'export const nope = 1;'],
  ])('explicit enablement propagates %s instead of silently degrading', (_name, source) => {
    expect(run(fixture('{"plugins":{"fingerprint":{"enabled":true}}}', source)).error)
      .toMatch(/required fingerprint plugin failed/);
  });

  test.each(['module', 'directory'])('explicit enablement requires the plugin %s to exist', (missing) => {
    const options = fixture('{"plugins":{"fingerprint":{"enabled":true}}}');
    fs.rmSync(missing === 'module'
      ? path.join(options.pluginsDir, 'fingerprint', 'index.js')
      : options.pluginsDir, { recursive: true, force: true });
    expect(run(options).error).toMatch(/required fingerprint plugin is missing/);
  });
});
