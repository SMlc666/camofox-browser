#!/usr/bin/env node
// Opt-in, real REST + stdio MCP + pinned browser integration. All profiles,
// config, service files, cookies and intentional fault injection are temporary.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { getUserPersistencePaths } from '../lib/persistence.js';
import { getFingerprintProfilePaths } from '../lib/fingerprint-persistence.js';

const executable = process.env.CAMOFOX_FINGERPRINT_TEST_EXECUTABLE;
if (!executable || process.platform !== 'linux') {
  console.error('Requires Linux/Xvfb and CAMOFOX_FINGERPRINT_TEST_EXECUTABLE pointing to pinned Camoufox.');
  process.exit(2);
}
const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-service-fingerprint-'));
const work = path.join(temp, 'service');
const profiles = path.join(temp, 'profiles');
const accessKey = crypto.randomUUID();
const adminKey = crypto.randomUUID();
const clients = new Set();
let service;
let logs = '';
let originServer;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(CAMOFOX|CAMOUFOX|.*_PROXY$)/i.test(key)));
const childEnv = { ...cleanEnv, HOME: path.join(temp, 'home'), CAMOFOX_ACCESS_KEY: accessKey, CAMOFOX_CRASH_REPORT_ENABLED: 'false' };

async function freePort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  return port;
}
const port = await freePort();
const base = `http://127.0.0.1:${port}`;

async function rest(route, { method = 'GET', body, authorized = true, headers = {} } = {}) {
  const response = await fetch(`${base}${route}`, {
    method, headers: { ...(authorized ? { authorization: `Bearer ${accessKey}` } : {}), 'content-type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(90000),
  });
  return { status: response.status, body: await response.json() };
}

async function startService() {
  logs = '';
  service = spawn(process.execPath, [path.join(work, 'server.js')], {
    cwd: work, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...childEnv, PORT: String(port), CAMOFOX_PORT: String(port), CAMOFOX_BIND_HOST: '127.0.0.1',
      CAMOUFOX_EXECUTABLE_PATH: path.resolve(executable), CAMOUFOX_INSTALL_DIR: path.dirname(path.resolve(executable)), CAMOFOX_PROFILE_DIR: profiles,
      CAMOFOX_ADMIN_KEY: adminKey, CAMOFOX_LOCALE: 'en-US', CAMOFOX_TIMEZONE: 'Asia/Shanghai' },
  });
  for (const stream of [service.stdout, service.stderr]) stream.on('data', (chunk) => { logs = (logs + chunk).slice(-24000); });
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (service.exitCode !== null) throw new Error(`test service exited: ${logs}`);
    try { if ((await rest('/health')).status === 200) return; } catch {}
    await sleep(100);
  }
  throw new Error(`test service startup timed out: ${logs}`);
}

async function killService(signal = 'SIGTERM') {
  if (!service) return;
  const child = service;
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    if (signal === 'SIGKILL') process.kill(-child.pid, signal);
    else child.kill(signal);
    const finished = await Promise.race([exited.then(() => true), sleep(15000).then(() => false)]);
    if (!finished) { process.kill(-child.pid, 'SIGKILL'); await exited; }
  }
  // Kill only this test's isolated process group, including any orphan browser.
  try { process.kill(-child.pid, 'SIGKILL'); } catch (err) { if (err.code !== 'ESRCH') throw err; }
  service = undefined;
}

async function mcp(userId, sessionKey) {
  const child = spawn(process.execPath, [path.join(work, 'mcp', 'server.mjs')], {
    cwd: work, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...childEnv, CAMOFOX_BASE_URL: base, CAMOFOX_USER_ID: userId, CAMOFOX_SESSION_KEY: sessionKey },
  });
  const pending = new Map();
  let id = 0;
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4000); });
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const response = JSON.parse(line);
    const task = pending.get(response.id);
    if (!task) return;
    pending.delete(response.id); clearTimeout(task.timer);
    if (response.error) task.reject(new Error(JSON.stringify(response.error)));
    else task.resolve(response.result);
  });
  child.on('exit', () => {
    for (const task of pending.values()) { clearTimeout(task.timer); task.reject(new Error(`MCP exited: ${stderr}`)); }
    pending.clear();
  });
  const request = (method, params) => new Promise((resolve, reject) => {
    const requestId = ++id;
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`MCP timed out: ${method}`)); }, 90000);
    pending.set(requestId, { resolve, reject, timer });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params })}\n`);
  });
  const client = {
    child,
    async call(name, args) {
      const result = await request('tools/call', { name, arguments: args });
      if (result.isError) throw new Error(result.content.map((entry) => entry.text || '').join('\n'));
      return JSON.parse(result.content.find((entry) => entry.type === 'text').text);
    },
    async close(signal = 'SIGTERM') {
      if (child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill(signal); await exited; }
      lines.close(); clients.delete(client);
    },
  };
  clients.add(client);
  await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'fingerprint-service-test', version: '1' } });
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  return client;
}

const signalExpression = `({ ua: navigator.userAgent, cores: navigator.hardwareConcurrency, screen: [screen.width, screen.height], timezone: Intl.DateTimeFormat().resolvedOptions().timeZone })`;
const stateExpression = `(async () => {
  const db = await new Promise((resolve, reject) => { const r = indexedDB.open('identity-state', 1); r.onupgradeneeded = () => r.result.createObjectStore('items'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  const value = await new Promise((resolve, reject) => { const t = db.transaction('items'); const r = t.objectStore('items').get('owner'); r.onsuccess = () => resolve(r.result || null); r.onerror = () => reject(r.error); });
  db.close(); return { cookie: document.cookie, local: localStorage.getItem('owner'), indexedDB: value };
})()`;
const writeState = (owner) => `(async () => {
  document.cookie = 'owner=${owner}; Path=/; SameSite=Lax'; localStorage.setItem('owner', '${owner}');
  const db = await new Promise((resolve, reject) => { const r = indexedDB.open('identity-state', 1); r.onupgradeneeded = () => r.result.createObjectStore('items'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  await new Promise((resolve, reject) => { const t = db.transaction('items', 'readwrite'); t.objectStore('items').put('${owner}', 'owner'); t.oncomplete = resolve; t.onerror = () => reject(t.error); }); db.close(); return true;
})()`;
async function evaluate(client, tabId, expression) { return (await client.call('camofox_evaluate', { tabId, expression })).result; }
async function tab(client, url) { return (await client.call('camofox_create_tab', { url })).tabId; }
async function stopBrowser() { const result = await rest('/stop', { method: 'POST', headers: { 'x-admin-key': adminKey } }); assert.equal(result.status, 200); }

try {
  await fs.mkdir(work);
  await fs.mkdir(childEnv.HOME);
  for (const name of ['server.js', 'lib', 'plugins', 'mcp', 'package.json', 'openapi.json']) {
    await fs.cp(path.join(root, name), path.join(work, name), { recursive: true });
  }
  await fs.symlink(path.join(root, 'node_modules'), path.join(work, 'node_modules'), 'dir');
  await fs.writeFile(path.join(work, 'camofox.config.json'), JSON.stringify({
    plugins: { persistence: { enabled: true, indexedDB: true }, fingerprint: { enabled: true } },
  }));
  originServer = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>service identity test</title>'); });
  originServer.listen(0, '127.0.0.1'); await once(originServer, 'listening');
  const origin = `http://127.0.0.1:${originServer.address().port}/`;
  await startService();
  const denied = await rest('/tabs?userId=A', { authorized: false });
  assert.ok([401, 403].includes(denied.status), 'global key must be required');
  let [a, b] = await Promise.all([mcp('A', 'first'), mcp('B', 'first')]);
  const [ta, tb] = await Promise.all([tab(a, origin), tab(b, origin)]);
  const originalSignals = await evaluate(a, ta, signalExpression);
  await evaluate(a, ta, writeState('A'));
  assert.deepEqual(await evaluate(b, tb, stateExpression), { cookie: '', local: null, indexedDB: null });
  await evaluate(b, tb, writeState('B'));
  assert.equal((await evaluate(a, ta, stateExpression)).local, 'A');
  await assert.rejects(evaluate(b, ta, 'document.cookie'), /not found|no longer exists/i, 'wrong userId cannot find A tab through B context');
  // Deliberately document the actual auth boundary, not a tenant guarantee.
  assert.equal((await rest(`/tabs/${ta}/evaluate`, { method: 'POST', body: { userId: 'A', expression: 'document.cookie' } })).body.result, 'owner=A');
  const anchor = getFingerprintProfilePaths(profiles, 'A');
  assert.equal((await fs.stat(anchor.userPath)).mode & 0o777, 0o600);
  assert.equal((await fs.stat(anchor.userAnchorPath)).mode & 0o777, 0o600);
  const identityBytes = await fs.readFile(anchor.userPath);
  await a.close();
  a = await mcp('A', 'reconnect');
  let currentTab = await tab(a, origin);
  assert.equal((await evaluate(a, currentTab, stateExpression)).local, 'A', 'new MCP sessionKey shares A cookies');
  assert.deepEqual(await evaluate(a, currentTab, signalExpression), originalSignals);
  await a.close('SIGKILL');
  a = await mcp('A', 'after-mcp-crash');
  currentTab = await tab(a, origin);
  assert.equal((await evaluate(a, currentTab, stateExpression)).indexedDB, 'A');
  await stopBrowser(); // awaited checkpoint + actual browser close/relaunch
  currentTab = await tab(a, origin);
  assert.deepEqual(await evaluate(a, currentTab, signalExpression), originalSignals);
  assert.equal((await evaluate(a, currentTab, stateExpression)).indexedDB, 'A');
  await stopBrowser();
  const storagePath = getUserPersistencePaths(profiles, 'A').storageStatePath;
  const checkpointBytes = await fs.readFile(storagePath);
  await killService();
  await startService();
  currentTab = await tab(a, origin);
  assert.deepEqual(await evaluate(a, currentTab, signalExpression), originalSignals);
  assert.equal((await evaluate(a, currentTab, stateExpression)).cookie, 'owner=A');
  // Crash recovery only promises the last completed checkpoint, not unflushed writes.
  await evaluate(a, currentTab, `localStorage.setItem('uncheckpointed', 'volatile')`);
  await killService('SIGKILL');
  await startService();
  currentTab = await tab(a, origin);
  assert.deepEqual(await evaluate(a, currentTab, signalExpression), originalSignals);
  assert.equal((await evaluate(a, currentTab, stateExpression)).local, 'A');
  assert.equal(await evaluate(a, currentTab, `localStorage.getItem('uncheckpointed')`), null);
  assert.deepEqual(await fs.readFile(anchor.userPath), identityBytes);
  assert.deepEqual(await fs.readFile(storagePath), checkpointBytes);
  // Fail closed when a bound user identity is present with unsafe permissions.
  await stopBrowser();
  await fs.chmod(anchor.userPath, 0o640);
  await assert.rejects(tab(a, origin), /permissions must be 0600/);
  await fs.chmod(anchor.userPath, 0o600);
  currentTab = await tab(a, origin);
  assert.equal((await evaluate(a, currentTab, stateExpression)).local, 'A');
  await stopBrowser();
  const beforeLoss = await fs.readFile(storagePath);
  await fs.rm(path.join(profiles, '.fingerprints'), { recursive: true });
  await assert.rejects(tab(a, origin), /initialization anchor is missing|identity.*missing|explicit recovery/i);
  assert.deepEqual(await fs.readFile(storagePath), beforeLoss);
  await assert.rejects(fs.stat(anchor.browserPath), { code: 'ENOENT' });
  await fs.rm(path.join(profiles, '.fingerprint-registry'), { recursive: true });
  await assert.rejects(tab(a, origin), /existing storageState|explicit recovery/i);
  assert.deepEqual(await fs.readFile(storagePath), beforeLoss);
  console.log(JSON.stringify({ ok: true, coverage: {
    realRestAndTwoMcpProcesses: true, userCookieLocalStorageIndexedDBPartition: true,
    globalAuthRequired: true, wrongUserCannotFindOtherTab: true,
    sharedBearerIsNotPerUserAuthorization: true, sameUserNewSessionSharesCookies: true,
    gracefulMcpReconnect: true, killedMcpReconnect: true, serverBrowserStopAndRelaunch: true,
    gracefulServiceRestart: true, killedServiceRecoversLastCheckpoint: true,
    privateFileModesEnforced: true, lostFingerprintDirectoryRefused: true,
    lostFingerprintAndRegistryWithStorageRefused: true,
  } }, null, 2));
} catch (error) {
  // Redact test-only credentials even from diagnostic server logs.
  console.error(logs.replaceAll(accessKey, '<test-key>').replaceAll(adminKey, '<test-admin>'));
  throw error;
} finally {
  await Promise.allSettled([...clients].map((client) => client.close('SIGKILL')));
  await killService('SIGKILL');
  if (originServer) await new Promise((resolve) => originServer.close(resolve));
  await fs.rm(temp, { recursive: true, force: true });
}
