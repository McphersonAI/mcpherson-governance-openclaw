// Metadata reads only. No directory enumeration, subprocess, network or write.
import { closeSync, constants as C, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

export function refuse(code) { throw Object.assign(new Error(code), { code }); }
export function inside(root, path) {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}
// Platform aliases /tmp and /var on macOS are allowed only ABOVE the selected
// root. Every existing component from that root down must be owner controlled.
export function assertPath(root, path) {
  if (!inside(root, path)) refuse('FOREIGN_STATE_PATH');
  const parents = [];
  for (let p = resolve(path); inside(root, p); p = dirname(p)) {
    parents.unshift(p);
    if (p === root) break;
  }
  // Reject user-selected symlink ancestors too, allowing only OS-owned aliases.
  for (let p = dirname(root); p !== dirname(p); p = dirname(p)) {
    try {
      const st = lstatSync(p);
      if (st.isSymbolicLink() && !(process.platform === 'darwin' && ['/tmp', '/var'].includes(p) && st.uid === 0)) refuse('UNSAFE_STATE_PATH');
      if (!st.isSymbolicLink() && (!st.isDirectory() || ((st.mode & 0o022) && !(st.mode & 0o1000)))) refuse('UNSAFE_STATE_PATH');
    } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  for (const p of parents) {
    try {
      const st = lstatSync(p);
      if (st.isSymbolicLink() || (process.getuid && st.uid !== process.getuid()) || (st.mode & 0o022)) refuse('UNSAFE_STATE_PATH');
      if (p !== path && !st.isDirectory()) refuse('UNSAFE_STATE_PATH');
      if (st.isFile() && st.nlink !== 1) refuse('UNSAFE_STATE_PATH');
    } catch (e) { if (e.code === 'ENOENT') return; throw e; }
  }
}
export function readBounded(root, path, { maxBytes = 1024 * 1024, tail = false, privateFile = true } = {}) {
  assertPath(root, path);
  let fd;
  try {
    fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || (process.getuid && st.uid !== process.getuid()) || (st.mode & (privateFile ? 0o077 : 0o022))) refuse('UNSAFE_LOCAL_FILE');
    if (!tail && st.size > maxBytes) refuse('LOCAL_FILE_TOO_LARGE');
    const start = tail ? Math.max(0, st.size - maxBytes) : 0;
    const bytes = Buffer.alloc(Math.min(st.size, maxBytes));
    let count = 0;
    while (count < bytes.length) {
      const n = readSync(fd, bytes, count, bytes.length - count, start + count);
      if (!n) break;
      count += n;
    }
    assertPath(root, path);
    const current = lstatSync(path);
    if (current.ino !== st.ino || current.dev !== st.dev) refuse('LOCAL_FILE_CHANGED');
    let text;
    try { text = bytes.subarray(0, count).toString('utf8'); } finally { bytes.fill(0); }
    // A bounded tail drops the first possibly partial record. A truncated final
    // record is treated as corrupt by the consumer, never interpreted loosely.
    if (start) text = text.slice(text.indexOf('\n') + 1);
    return { text, truncated: start > 0 };
  } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  finally { if (fd !== undefined) closeSync(fd); }
}
export function readJson(root, path, options) {
  const data = readBounded(root, path, options);
  if (!data) return null;
  let value;
  try { value = JSON.parse(data.text); } catch { refuse('LOCAL_JSON_INVALID'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) refuse('LOCAL_JSON_INVALID');
  return value;
}
export const agentId = (value) => typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/i.test(value) ? value.toLowerCase() : null;
// Runtime identifiers are metadata. Credential-shaped strings are never labels.
export const toolId = (value) => typeof value === 'string' && /^[a-z][a-z0-9_.:-]{0,95}$/i.test(value) && !/(?:mgd1_|sk[-_]|token|secret|password|api[-_]?key)/i.test(value) ? value : null;
export const timestamp = (value, now) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Date.parse(value) <= now + 5000 && new Date(value).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z') ? new Date(value).toISOString() : null;
