import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals';
import { resolvePersistentMcpUserId } from '../../mcp/lib/user-id.mjs';

const instanceHash = (instanceKey) =>
  crypto.createHash('sha256').update(path.resolve(instanceKey)).digest('hex');

describe('persistent MCP adapter userId', () => {
  let directory;

  beforeEach(async () => {
    directory = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-mcp-user-id-'));
  });

  afterEach(async () => {
    await fs.rm(directory, { recursive: true, force: true });
  });

  test('persists one userId per adapter install across process restarts', async () => {
    const first = await resolvePersistentMcpUserId({ instanceKey: '/opt/camofox/mcp', directory });
    const restarted = await resolvePersistentMcpUserId({ instanceKey: '/opt/camofox/mcp', directory });
    const otherInstall = await resolvePersistentMcpUserId({ instanceKey: '/opt/other/mcp', directory });
    const filePath = path.join(directory, `${instanceHash('/opt/camofox/mcp')}.json`);

    expect(first).toMatch(/^mcp-/);
    expect(restarted).toBe(first);
    expect(otherInstall).not.toBe(first);
    expect((await fs.stat(directory)).mode & 0o777).toBe(0o700);
    expect((await fs.stat(filePath)).mode & 0o777).toBe(0o600);
  });

  test('reuses the same fallback userId across separate Node processes', async () => {
    const moduleUrl = new URL('../../mcp/lib/user-id.mjs', import.meta.url).href;
    const script = `import { resolvePersistentMcpUserId } from ${JSON.stringify(moduleUrl)}; console.log(await resolvePersistentMcpUserId({ instanceKey: '/opt/camofox/mcp' }));`;
    const env = { ...process.env, HOME: directory };
    const first = execFileSync(process.execPath, ['--input-type=module', '-e', script], { env, encoding: 'utf8' }).trim();
    const restarted = execFileSync(process.execPath, ['--input-type=module', '-e', script], { env, encoding: 'utf8' }).trim();
    expect(restarted).toBe(first);
    expect(first).toMatch(/^mcp-/);
  });

  test('concurrent first connections atomically converge on one userId', async () => {
    const ids = await Promise.all(Array.from({ length: 8 }, () =>
      resolvePersistentMcpUserId({ instanceKey: '/opt/camofox/mcp', directory })));
    expect(new Set(ids).size).toBe(1);
  });

  test('explicit CAMOFOX_USER_ID bypasses generated identity storage', async () => {
    const id = await resolvePersistentMcpUserId({
      explicitUserId: 'stable-account',
      instanceKey: '/opt/camofox/mcp',
      directory,
    });
    expect(id).toBe('stable-account');
    expect(await fs.readdir(directory)).toEqual([]);
  });

  test('corrupt or insecure identity files fail closed instead of changing userId', async () => {
    const args = { instanceKey: '/opt/camofox/mcp', directory };
    const originalId = await resolvePersistentMcpUserId(args);
    const filePath = path.join(directory, `${instanceHash(args.instanceKey)}.json`);
    const originalBytes = await fs.readFile(filePath);
    await fs.writeFile(filePath, 'corrupt identity\n', { mode: 0o600 });
    await expect(resolvePersistentMcpUserId(args)).rejects.toThrow(/corrupted|corrupt or incompatible/);
    expect(await fs.readFile(filePath, 'utf8')).toBe('corrupt identity\n');

    await fs.writeFile(filePath, originalBytes, { mode: 0o600 });
    await fs.chmod(filePath, 0o640);
    await expect(resolvePersistentMcpUserId(args)).rejects.toThrow(/permissions must be 0600/);
    await expect(resolvePersistentMcpUserId({ ...args, explicitUserId: 'configured-id' })).resolves.toBe('configured-id');
    expect(originalId).toMatch(/^mcp-/);
  });
});
