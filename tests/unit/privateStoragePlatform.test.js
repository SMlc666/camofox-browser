import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from '@jest/globals';
import { assertPrivateStoragePlatform } from '../../mcp/lib/private-storage.mjs';
import { resolvePersistentMcpUserId } from '../../mcp/lib/user-id.mjs';
import { loadOrCreateBrowserFingerprint, writeCamoufoxConfig } from '../../lib/fingerprint-persistence.js';

const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
afterEach(() => Object.defineProperty(process, 'platform', platformDescriptor));

describe('private identity storage platform policy', () => {
  test.each(['linux', 'darwin', 'freebsd'])('accepts POSIX permission enforcement on %s', (platform) => {
    expect(() => assertPrivateStoragePlatform(platform)).not.toThrow();
  });

  test('does not mistake Windows mode bits for ACL validation', () => {
    expect(() => assertPrivateStoragePlatform('win32')).toThrow(/Windows ACL validation/);
  });

  test('Windows fingerprint storage fails before writes but MCP fallback remains stable without files', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-platform-test-'));
    const env = {};
    writeCamoufoxConfig(env, { 'navigator.userAgent': 'test' });
    try {
      Object.defineProperty(process, 'platform', { ...platformDescriptor, value: 'win32' });
      const first = await resolvePersistentMcpUserId({ directory, instanceKey: 'C:\\camofox' });
      const restarted = await resolvePersistentMcpUserId({ directory, instanceKey: 'c:\\CAMOFOX' });
      const otherInstall = await resolvePersistentMcpUserId({ directory, instanceKey: 'C:\\other' });
      expect(first).toMatch(/^mcp-win-[a-f0-9]{32}$/);
      expect(restarted).toBe(first);
      expect(otherInstall).not.toBe(first);
      await expect(loadOrCreateBrowserFingerprint({ profileDir: directory, options: { env }, runtime: {} }))
        .rejects.toThrow(/Windows ACL validation/);
      await expect(resolvePersistentMcpUserId({ explicitUserId: 'configured-user', directory }))
        .resolves.toBe('configured-user');
      expect(await fs.readdir(directory)).toEqual([]);
    } finally {
      Object.defineProperty(process, 'platform', platformDescriptor);
      await fs.rm(directory, { recursive: true, force: true });
    }
  });
});
