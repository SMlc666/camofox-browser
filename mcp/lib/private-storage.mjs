/**
 * POSIX mode bits are not Windows ACLs. Do not claim private storage on Windows
 * until an ACL backend has been implemented and tested on a Windows runner.
 * Shared by the independently published MCP adapter and the core plugin.
 */
export function assertPrivateStoragePlatform(platform = process.platform) {
  if (platform === 'win32') {
    throw new Error('private identity storage on Windows requires Windows ACL validation, which is not implemented; keep the fingerprint plugin disabled; MCP can use its file-free Windows fallback or an explicit CAMOFOX_USER_ID');
  }
  if (!['linux', 'darwin', 'freebsd', 'openbsd', 'netbsd', 'aix', 'sunos'].includes(platform)) {
    throw new Error(`private identity storage is unsupported on platform ${platform}`);
  }
}
