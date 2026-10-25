import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { assertPrivateStoragePlatform } from './private-storage.mjs';

const SCHEMA_VERSION = 1;
const DEFAULT_DIRECTORY = path.join(os.homedir(), '.camofox', 'mcp-identities');

function digestRecord(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function wrapRecord(payload) {
  return {
    ...payload,
    integrity: { algorithm: 'sha256', digest: digestRecord(payload) },
  };
}

function payloadOf(record) {
  const { integrity, ...payload } = record;
  return payload;
}

async function ensureSecureDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`MCP identity directory is not a real directory: ${directory}`);
  }
  await fs.chmod(directory, 0o700);
  const secured = await fs.lstat(directory);
  if ((secured.mode & 0o777) !== 0o700) {
    throw new Error(`MCP identity directory permissions must be 0700: ${directory}`);
  }
}

async function readUserId(filePath, instanceHash) {
  let stat;
  try {
    stat = await fs.lstat(filePath);
  } catch (err) {
    if (err?.code === 'ENOENT') return undefined;
    throw err;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`MCP identity file is not a regular file: ${filePath}`);
  }
  if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(`MCP identity file permissions must be 0600: ${filePath}`);
  }
  if (stat.size <= 0 || stat.size > 16 * 1024) {
    throw new Error(`MCP identity file has an invalid size: ${filePath}`);
  }

  let record;
  try {
    record = JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`MCP identity file is corrupted (${filePath}): ${err.message}; refusing to generate a new userId`);
  }
  const payload = payloadOf(record || {});
  if (
    !record || record.schemaVersion !== SCHEMA_VERSION || record.instanceHash !== instanceHash
    || typeof record.userId !== 'string' || record.userId.length === 0
    || record.integrity?.algorithm !== 'sha256'
    || record.integrity.digest !== digestRecord(payload)
  ) {
    throw new Error(`MCP identity file is corrupt or incompatible (${filePath}); refusing to generate a new userId`);
  }
  return record.userId;
}

async function createUserIdIfAbsent(filePath, instanceHash, userId) {
  const directory = path.dirname(filePath);
  const payload = { schemaVersion: SCHEMA_VERSION, instanceHash, userId };
  const record = wrapRecord(payload);
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
      await fs.link(tempPath, filePath);
      let dirHandle;
      try {
        dirHandle = await fs.open(directory, 'r');
        await dirHandle.sync();
      } catch (err) {
        if (!['EINVAL', 'ENOTSUP', 'EISDIR', 'EPERM'].includes(err?.code)) throw err;
      } finally {
        await dirHandle?.close().catch(() => {});
      }
      return userId;
    } catch (err) {
      if (err?.code === 'EEXIST') return undefined;
      throw err;
    }
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(tempPath).catch(() => {});
  }
}

/**
 * Return an explicit userId when configured; otherwise persist one per adapter
 * installation so a client/server reconnect cannot silently switch identity.
 */
export async function resolvePersistentMcpUserId({
  explicitUserId,
  instanceKey,
  directory = DEFAULT_DIRECTORY,
  prefix = 'mcp',
} = {}) {
  if (explicitUserId != null) {
    const userId = String(explicitUserId);
    if (!userId.trim()) throw new Error('configured MCP userId must not be empty');
    return userId;
  }
  if (typeof instanceKey !== 'string' || !instanceKey.trim()) {
    throw new Error('MCP instanceKey is required to persist its fallback userId');
  }
  if (process.platform === 'win32') {
    // A userId is a public partition label, not a credential. A deterministic
    // per-home/per-install label preserves Windows startup and reconnects
    // without claiming chmod validates ACLs or writing an identity file.
    const scope = JSON.stringify([
      path.win32.resolve(os.homedir()).toLowerCase(),
      path.win32.resolve(instanceKey).toLowerCase(),
    ]);
    return `${prefix}-win-${crypto.createHash('sha256').update(scope).digest('hex').slice(0, 32)}`;
  }
  assertPrivateStoragePlatform();
  const instanceHash = crypto.createHash('sha256').update(path.resolve(instanceKey)).digest('hex');
  await ensureSecureDirectory(directory);
  const filePath = path.join(directory, `${instanceHash}.json`);
  const existing = await readUserId(filePath, instanceHash);
  if (existing) return existing;

  const candidate = `${prefix}-${crypto.randomUUID()}`;
  const created = await createUserIdIfAbsent(filePath, instanceHash, candidate);
  if (created) return created;
  const winner = await readUserId(filePath, instanceHash);
  if (!winner) throw new Error(`MCP identity file disappeared during creation: ${filePath}`);
  return winner;
}
