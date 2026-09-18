import { randomBytes } from 'node:crypto';
import { closeSync, constants, fsyncSync, mkdirSync, openSync, readSync, renameSync, writeFileSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { assertPath, readBounded, readJson, refuse } from './safe-local.mjs';
import { resolveProfile } from './providers/openclaw.mjs';

export const ACCESS_HELP = {
  'request-access': `request-access --api-url <https://host> [--name <name> --email <email>]
Request Hosted beta access. Verified email and founder approval are required.
Optional: --organization <company> --use-case <description>.
Review the exact admission metadata before confirming. --yes confirms submission
for noninteractive use. --json requires --yes for a new request; it never prints
verification codes or request credentials. Runtime metadata is self-reported.
Run again with --code-file <0600-file> to verify, or --resend to send a new code (or retry an approved invitation email).
Without --code-file, interactive verification input is hidden. Codes expire in
10 minutes. --new starts a new request only after DENIED, EXPIRED or CANCELLED.
Example: observa request-access --api-url https://observa.example`,
  'request-status': `request-status [--api-url <https://host>] [--json]
Check the request saved for this profile using its private local receipt.
Only this request's owner can check it; a request id alone is insufficient.
Approved: redeem the emailed invitation, sign in, accept beta documents, and
obtain a pairing code in Hosted Observa. Then run observa pair.
Expired: run observa request-access --new --api-url <https://host>.`,
};
export const ACCESS_FLAGS = ['api-url', 'name', 'email', 'organization', 'use-case', 'yes', 'code-file', 'resend', 'new'];
const STATES = new Set(['EMAIL_PENDING', 'PENDING_REVIEW', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED']);
function text(value, max, required = false) {
  if (value === undefined || value === null || value === '') { if (required) refuse('ACCESS_IDENTITY_REQUIRED'); return null; }
  if (typeof value !== 'string' || value.length > max || /[\x00-\x1f\x7f]/.test(value)) refuse('ACCESS_INPUT_INVALID');
  return value.trim();
}
function endpoint(value) {
  let url;
  try { url = new URL(value); } catch { refuse('ACCESS_URL_REQUIRED'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') refuse('ACCESS_URL_REQUIRED');
  return url.origin;
}
function terminal(prompt, secret = false) {
  let fd; let hidden = false;
  try {
    fd = openSync('/dev/tty', 'r+');
    writeSync(fd, prompt);
    if (secret) {
      if (spawnSync('stty', ['-echo'], { stdio: [fd, fd, fd] }).status !== 0) refuse('ACCESS_INPUT_REQUIRED');
      hidden = true;
    }
    const byte = Buffer.alloc(1); const bytes = [];
    while (readSync(fd, byte, 0, 1, null)) {
      if (byte[0] === 10 || byte[0] === 13) break;
      bytes.push(byte[0]);
      if (bytes.length > 4800) refuse('ACCESS_INPUT_INVALID');
    }
    return Buffer.from(bytes).toString('utf8').trim();
  } catch (error) { if (error.code?.startsWith('ACCESS_')) throw error; refuse('ACCESS_INPUT_REQUIRED'); }
  finally {
    if (hidden) { spawnSync('stty', ['echo'], { stdio: [fd, fd, fd] }); writeSync(fd, '\n'); }
    if (fd !== undefined) closeSync(fd);
  }
}
function save(root, path, value, existing) {
  assertPath(root, path);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  assertPath(root, path);
  const temporary = `${path}.${randomBytes(12).toString('hex')}.tmp`;
  const target = existing ? temporary : path;
  const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, JSON.stringify(value)); fsyncSync(fd); } finally { closeSync(fd); }
  if (existing) { assertPath(root, path); renameSync(temporary, path); }
}
async function call(endpointUrl, owner, action, payload, fetcher) {
  let response;
  try {
    response = await fetcher(`${endpointUrl}/access/v1/${action}`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { 'content-type': 'application/json', authorization: `Bearer ${owner}` },
      body: JSON.stringify(payload),
    });
    if (!response.ok) refuse(response.status === 429 ? 'ACCESS_RATE_LIMITED' : 'ACCESS_REFUSED');
    // Bound even a malicious/unexpected server response; never echo its body.
    const reader = response.body.getReader(); const chunks = []; let size = 0;
    for (;;) { const { value, done } = await reader.read(); if (done) break; size += value.length; if (size > 8192) { await reader.cancel(); refuse('ACCESS_REFUSED'); } chunks.push(Buffer.from(value)); }
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch (error) { if (['ACCESS_RATE_LIMITED', 'ACCESS_REFUSED'].includes(error.code)) throw error; refuse('ACCESS_UNAVAILABLE'); }
}
function projection(row, rid) {
  if (!row || row.request_id !== rid || !STATES.has(row.status)) refuse('ACCESS_REFUSED');
  return { request_id: rid, status: row.status, next_action: row.status === 'APPROVED'
    ? 'Redeem the invitation sent to your verified email. Sign in, accept beta documents, obtain a pairing code, then run observa pair. Missing invitation? Run observa request-access --resend.'
    : row.status === 'EXPIRED' ? 'Run observa request-access --new.'
      : row.status === 'EMAIL_PENDING' ? 'Verify with observa request-access --code-file <0600-file>.' : null };
}
export async function runAccess(command, { flags, env, home = homedir(), version, metadata = {}, dependencies = {} }) {
  if ([env, process.env].some(values => Object.hasOwn(values, 'NODE_TLS_REJECT_UNAUTHORIZED') && values.NODE_TLS_REJECT_UNAUTHORIZED !== '1')) refuse('ACCESS_TLS_REQUIRED');
  const { root } = resolveProfile(flags, env, home);
  const path = join(root, 'observa-access', 'request.json');
  let state = readJson(root, path, { maxBytes: 8192 });
  const input = dependencies.accessPrompt ?? terminal;
  const output = dependencies.accessOutput ?? (s => process.stderr.write(`${s}\n`));
  const fetcher = dependencies.accessFetch ?? globalThis.fetch;
  const url = endpoint(flags['api-url'] ?? state?.endpoint);
  if (state && (state.endpoint !== url || !/^req_[a-f0-9]{32}$/.test(state.request_id) || !/^[a-f0-9]{64}$/.test(state.owner_key))) refuse('ACCESS_RECEIPT_INVALID');
  const invoke = (action, payload) => call(url, state.owner_key, action, payload, fetcher);
  if (command === 'request-status') {
    if (!state) refuse('ACCESS_NO_REQUEST');
    return projection(await invoke('status', { request_id: state.request_id }), state.request_id);
  }
  if (flags.new && state) {
    const current = projection(await invoke('status', { request_id: state.request_id }), state.request_id);
    if (!['DENIED', 'EXPIRED', 'CANCELLED'].includes(current.status)) refuse('ACCESS_ALREADY_PENDING');
  }
  const isNew = !state || flags.new;
  if (isNew) {
    const interactive = !flags.json && !flags.yes;
    const data = {
      request_id: `req_${randomBytes(16).toString('hex')}`,
      name: text(flags.name ?? (interactive ? input('Name: ') : null), 120, true),
      email: text(flags.email ?? (interactive ? input('Email: ') : null), 254, true)?.toLowerCase(),
      organization: text(flags.organization ?? (interactive ? input('Organization (optional): ') : null), 160),
      use_case: text(flags['use-case'] ?? (interactive ? input('Use case (optional): ') : null), 1000),
      runtime_type: 'openclaw', runtime_version: /^\d[\w.+-]{0,39}$/.test(metadata.runtime?.version ?? '') ? metadata.runtime.version : null,
      observa_version: version, agent_count: Number.isInteger(metadata.configured_agent_count) && metadata.configured_agent_count >= 0 && metadata.configured_agent_count <= 10000 ? metadata.configured_agent_count : null,
      platform: ['darwin', 'linux', 'win32'].includes(process.platform) ? process.platform : 'unknown',
    };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) refuse('ACCESS_INPUT_INVALID');
    output(`Send to ${url}:\n${JSON.stringify(data, null, 2)}\nA private request receipt authenticates subsequent requests. No runtime credentials or content are sent.`);
    if (!flags.yes && (flags.json || input('Submit this access request? Type yes: ') !== 'yes')) refuse('ACCESS_CONFIRMATION_REQUIRED');
    const previous = Boolean(state);
    state = { endpoint: url, request_id: data.request_id, owner_key: randomBytes(32).toString('hex'), data, created: false, verification_sent: false };
    save(root, path, state, previous);
  } else if (['name', 'email', 'organization', 'use-case'].some(k => flags[k] !== undefined)) refuse('ACCESS_IDENTITY_IMMUTABLE');
  if (!state.created) {
    await invoke('create', { data: state.data });
    state.created = true;
    save(root, path, state, true);
  }
  let row = projection(await invoke('status', { request_id: state.request_id }), state.request_id);
  if (row.status === 'APPROVED' && flags.resend) { await invoke('send', { request_id: state.request_id }); output('A new invitation was sent to your verified email. The previous invitation is no longer usable.'); return row; }
  if (row.status !== 'EMAIL_PENDING') return row;
  if (!state.verification_sent || flags.resend) {
    await invoke('send', { request_id: state.request_id });
    state.verification_sent = true; save(root, path, state, true);
    output('A verification code was sent to your email. It expires in 10 minutes.');
  }
  let code;
  if (flags['code-file']) {
    const codePath = resolve(flags['code-file']);
    code = readBounded(dirname(codePath), codePath, { maxBytes: 128 })?.text.trim();
    if (!code) refuse('ACCESS_CODE_INVALID');
  } else if (!flags.json && !flags.yes) code = input('Verification code (input hidden): ', true);
  if (code) {
    if (!/^[a-f0-9]{32}$/.test(code)) refuse('ACCESS_CODE_INVALID');
    row = projection(await invoke('verify', { request_id: state.request_id, code }), state.request_id);
  }
  return row;
}
