import { DatabaseSync } from 'node:sqlite';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync } from 'node:fs';
import { join } from 'node:path';
import { assertPath } from '../../cli/safe-local.mjs';
import { canonicalizeJson } from './runtime/governance-core/canonical.mjs';
import { ensureSecureDir, fsyncDirectory, readSecureFile, writeExclusiveSecureFile } from './secure-files.mjs';

export const digest = value => 'sha256:' + createHash('sha256').update(canonicalizeJson(value)).digest('hex');
const fail = () => { throw Object.assign(new Error('NATIVE_EVIDENCE_UNAVAILABLE'), { code: 'NATIVE_EVIDENCE_UNAVAILABLE' }); };

function verifyDatabase(db, publicKey) {
  db.exec('BEGIN');
  try {
  let previous = null; let sequence = 0; let last = null; let runtimeVersion = null;
  const deliveries = new Map(); const acknowledgements = new Map(); const claims = new Map(); const invocations = new Map();
  for (const row of db.prepare('SELECT * FROM evidence ORDER BY sequence').iterate()) {
    const body = JSON.parse(row.body); const p = body.payload;
    if (row.sequence !== ++sequence || body.sequence !== sequence || body.previous !== previous || digest(body) !== row.hash
        || !verify(null, Buffer.from(row.body), publicKey, Buffer.from(row.signature, 'base64'))) fail();
    previous = row.hash; last = p.at;
    if (p.adapter === 'openclaw-2026.10.9/v1' && p.runtime_version === '2026.10.9') runtimeVersion = p.runtime_version;
    if (body.delivery_digest) deliveries.set(row.hash, body.delivery_digest);
    if (p.kind === 'HOSTED_ACCEPTANCE') {
      if (!deliveries.has(p.delivery_hash) || acknowledgements.has(p.delivery_hash)) fail();
      acknowledgements.set(p.delivery_hash, p.ack_digest);
    }
    if (p.kind === 'BOUND_EXECUTION_CLAIM') {
      if (!p.correlation_ref || claims.has(p.correlation_ref)) fail();
      claims.set(p.correlation_ref, row.hash);
    }
    if (p.kind === 'TOOL_ATTEMPT' && p.correlation_ref) {
      if (invocations.has(p.correlation_ref)) fail();
      invocations.set(p.correlation_ref, { attempt_hash: row.hash, terminal_hash: null });
    }
    if (p.kind === 'TOOL_OUTCOME' && body.delivery_digest) {
      const invocation = invocations.get(p.correlation_ref);
      if (!invocation || invocation.terminal_hash) fail();
      invocation.terminal_hash = row.hash;
    }
  }
  const checkIndex = (sql, expected, key, value) => {
    let count = 0;
    for (const row of db.prepare(sql).iterate()) {
      if (!expected.has(key(row)) || digest(value(row)) !== digest(expected.get(key(row)))) fail();
      count++;
    }
    if (count !== expected.size) fail();
  };
  checkIndex('SELECT * FROM delivery', deliveries, r => r.hash, r => digest(JSON.parse(r.body)));
  checkIndex('SELECT * FROM acknowledgements', acknowledgements, r => r.hash, r => digest(JSON.parse(r.ack)));
  checkIndex('SELECT * FROM claims', claims, r => r.correlation, r => r.hash);
  checkIndex('SELECT * FROM native_invocations', invocations, r => r.correlation, r => ({ attempt_hash: r.attempt_hash, terminal_hash: r.terminal_hash }));
  db.exec('COMMIT');
  return { records: sequence, head: previous, last, runtimeVersion, pending: deliveries.size - acknowledgements.size };
  } catch (error) { db.exec('ROLLBACK'); throw error; }
}

// Connector-owned state only: this never reads or edits an OpenClaw database.
// FULL synchronous commits durably couple signed evidence and delivery intent.
// ACKs are distinct append-only evidence; acceptance never follows from send().
export class NativeLedger {
  #db; #key; #public; #closed = false;
  constructor(stateDir) {
    const root = join(stateDir, 'native-v1');
    assertPath(stateDir, root); ensureSecureDir(root);
    const keyPath = join(root, 'signing-key.pem');
    assertPath(root, keyPath);
    try { this.#key = createPrivateKey(readSecureFile(keyPath)); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const pair = generateKeyPairSync('ed25519');
      try { writeExclusiveSecureFile(keyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' })); }
      catch (e) { if (e.code !== 'EEXIST') throw e; }
      this.#key = createPrivateKey(readSecureFile(keyPath));
    }
    this.#public = createPublicKey(this.#key);
    const publicPath = join(root, 'signing-public.pem');
    try { writeExclusiveSecureFile(publicPath, this.#public.export({ type: 'spki', format: 'pem' })); }
    catch (e) { if (e.code !== 'EEXIST') throw e; }
    if (!createPublicKey(readSecureFile(publicPath)).equals(this.#public)) fail();
    const path = join(root, 'evidence.sqlite');
    for (const suffix of ['', '-wal', '-shm', '-journal']) assertPath(root, path + suffix);
    const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
    try {
      const s = fstatSync(fd);
      if (!s.isFile() || s.nlink !== 1 || (s.mode & 0o077) || (process.getuid && s.uid !== process.getuid())) fail();
    } finally { closeSync(fd); }
    this.#db = new DatabaseSync(path);
    this.#db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;
      CREATE TABLE IF NOT EXISTS evidence(sequence INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body TEXT NOT NULL, signature TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS delivery(hash TEXT PRIMARY KEY REFERENCES evidence(hash), body TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS acknowledgements(hash TEXT PRIMARY KEY REFERENCES delivery(hash), ack TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS claims(correlation TEXT PRIMARY KEY, hash TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS native_invocations(correlation TEXT PRIMARY KEY, attempt_hash TEXT NOT NULL, terminal_hash TEXT) STRICT;
      CREATE TABLE IF NOT EXISTS delivery_attempts(hash TEXT PRIMARY KEY, last_attempt_ms INTEGER NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS identity(name TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
      CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;
      CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT,'immutable_evidence'); END;`);
    this.#db.prepare('INSERT OR IGNORE INTO identity VALUES (?,?)').run('runtime_id', randomUUID());
    this.runtimeId = this.#db.prepare('SELECT value FROM identity WHERE name=?').get('runtime_id').value;
    this.publicKey = this.#public.export({ type: 'spki', format: 'pem' });
    fsyncDirectory(root);
    try { this.verify(); } catch (error) { this.#db.close(); this.#closed = true; throw error; }
  }
  verify() {
    const { records, head } = verifyDatabase(this.#db, this.#public);
    return { records, head };
  }
  append(payload, delivery = null, claim = null, acceptance = null, transition = null) {
    if (this.#closed) fail();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const last = this.#db.prepare('SELECT sequence,hash FROM evidence ORDER BY sequence DESC LIMIT 1').get();
      const body = { schema: 'observa-openclaw-native-evidence/v1', sequence: (last?.sequence ?? 0) + 1, previous: last?.hash ?? null, payload, delivery_digest: delivery ? digest(delivery) : null };
      const bytes = canonicalizeJson(body);
      if (Buffer.byteLength(bytes) > 65536) fail();
      const hash = digest(body);
      this.#db.prepare('INSERT INTO evidence VALUES (?,?,?,?)').run(body.sequence, hash, bytes, sign(null, Buffer.from(bytes), this.#key).toString('base64'));
      if (claim) this.#db.prepare('INSERT INTO claims VALUES (?,?)').run(claim, hash);
      if (transition?.phase === 'attempt') this.#db.prepare('INSERT INTO native_invocations VALUES (?,?,NULL)').run(transition.correlation, hash);
      if (transition?.phase === 'terminal') {
        const updated = this.#db.prepare('UPDATE native_invocations SET terminal_hash=? WHERE correlation=? AND terminal_hash IS NULL').run(hash, transition.correlation);
        if (updated.changes !== 1) fail();
      }
      if (delivery) this.#db.prepare('INSERT INTO delivery VALUES (?,?)').run(hash, canonicalizeJson(delivery));
      if (acceptance) this.#db.prepare('INSERT OR IGNORE INTO acknowledgements VALUES (?,?)').run(acceptance.hash, canonicalizeJson(acceptance.ack));
      this.#db.exec('COMMIT');
      return hash;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  pending(limit = 16) {
    return this.#db.prepare('SELECT d.hash,d.body,e.body AS evidence FROM delivery d JOIN evidence e ON e.hash=d.hash LEFT JOIN acknowledgements a ON d.hash=a.hash LEFT JOIN delivery_attempts t ON d.hash=t.hash WHERE a.hash IS NULL ORDER BY coalesce(t.last_attempt_ms,0),d.rowid LIMIT ?').all(limit);
  }
  pendingCount() { return this.#db.prepare('SELECT count(*) n FROM delivery d LEFT JOIN acknowledgements a ON d.hash=a.hash WHERE a.hash IS NULL').get().n; }
  attempted(hash) { this.#db.prepare('INSERT INTO delivery_attempts VALUES (?,?) ON CONFLICT(hash) DO UPDATE SET last_attempt_ms=excluded.last_attempt_ms').run(hash, Date.now()); }
  invocation(correlation) {
    const row = this.#db.prepare('SELECT n.*,e.body FROM native_invocations n JOIN evidence e ON e.hash=n.attempt_hash WHERE correlation=?').get(correlation);
    return row ? { identity: JSON.parse(row.body).payload.identity, binding: JSON.parse(row.body).payload.delivery_binding ?? null, terminal: row.terminal_hash !== null } : null;
  }
  hasClaim(correlation) { return Boolean(this.#db.prepare('SELECT 1 FROM claims WHERE correlation=?').get(correlation)); }
  acknowledge(hash, ack) {
    if (this.#db.prepare('SELECT 1 FROM acknowledgements WHERE hash=?').get(hash)) return;
    const row = this.#db.prepare('SELECT body FROM delivery WHERE hash=?').get(hash);
    if (!row || ack?.accepted !== true || ack.request_hash !== JSON.parse(row.body).request_hash) fail();
    this.append({ kind: 'HOSTED_ACCEPTANCE', delivery_hash: hash, request_hash: ack.request_hash, observation_id: ack.observation_id, ack_digest: digest(ack), at: new Date().toISOString() }, null, null, { hash, ack });
  }
  records() { return this.#db.prepare('SELECT body FROM evidence ORDER BY sequence').all().map(r => JSON.parse(r.body)); }
  close() { if (!this.#closed) { this.#db.close(); this.#closed = true; } }
}

// Offline, read-only health inspection: no private key access, migration,
// repair, new database, receipt, network call or synthetic runtime activity.
export function readNativeEvidenceStatus(stateDir) {
  const root = join(stateDir, 'native-v1');
  let db;
  try {
    const path = join(root, 'evidence.sqlite');
    const keyPath = join(root, 'signing-public.pem');
    assertPath(stateDir, path); assertPath(stateDir, keyPath);
    const key = createPublicKey(readSecureFile(keyPath));
    db = new DatabaseSync(path, { readOnly: true });
    const { records: sequence, last, runtimeVersion, pending } = verifyDatabase(db, key);
    return { health: 'VERIFIED_LOCAL_SIGNATURES', records: sequence, pending, last_event_at: last, runtime_version: runtimeVersion,
      native_v3: 'UNSUPPORTED_HOSTED_CONTRACT' };
  } catch (error) {
    return { health: error?.code === 'ENOENT' ? 'NOT_STARTED' : 'UNREADABLE_OR_INVALID', records: null, pending: null, runtime_version: null };
  } finally { db?.close(); }
}
