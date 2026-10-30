// Test operator for the documented Gateway v4 WebSocket/device-auth protocol.
// Only the isolated lab's generated identity and token are used.
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

export async function connectApprovalClient({ port, token, profile, command, record }) {
  const key = generateKeyPairSync('ed25519');
  const raw = key.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const deviceId = createHash('sha256').update(raw).digest('hex');
  writeFileSync(join(profile, `synthetic-device-${deviceId}.pem`), key.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const scopes = ['operator.read', 'operator.write', 'operator.approvals'];
  for (let attempt = 0; attempt < 3; attempt++) {
    const socket = new WebSocket(`ws://127.0.0.1:${port}`);
    const pending = new Map();
    const rpc = (method, params = {}) => new Promise((resolve, reject) => {
      const id = randomUUID();
      const timer = setTimeout(() => { pending.delete(id); reject(Error(`RPC timeout: ${method}`)); }, 15000);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ type: 'req', id, method, params }));
    });
    const hello = new Promise((resolve, reject) => {
      socket.addEventListener('error', () => reject(Error('isolated websocket unavailable')), { once: true });
      socket.addEventListener('message', async event => {
        const m = JSON.parse(String(event.data));
        if (m.type === 'res') {
          const p = pending.get(m.id); if (!p) return; pending.delete(m.id); clearTimeout(p.timer);
          if (m.ok) p.resolve(m.payload); else p.reject(Object.assign(Error(m.error?.message ?? 'RPC refused'), { details: m.error?.details }));
        } else if (m.event === 'connect.challenge') {
          const { nonce, ts } = m.payload;
          const payload = ['v3', deviceId, 'gateway-client', 'ui', 'operator', scopes.join(','), ts, token, nonce, 'macos', ''].join('|');
          try {
            resolve(await rpc('connect', { minProtocol: 4, maxProtocol: 4,
              client: { id: 'gateway-client', version: '2026.10.9-lab', platform: 'macos', mode: 'ui' },
              role: 'operator', scopes, caps: ['plugin-approvals', 'tool-events'], auth: { token },
              device: { id: deviceId, publicKey: raw.toString('base64url'), signature: sign(null, Buffer.from(payload), key.privateKey).toString('base64url'), signedAt: ts, nonce } }));
          } catch (error) { reject(error); }
        } else if (m.event?.includes('approval')) record({ kind: 'HOST_APPROVAL_EVENT', event: m.event, id: m.payload?.id });
      });
    });
    try { await hello; return { rpc, close: () => socket.close() }; }
    catch (error) {
      socket.close();
      const requestId = error.details?.requestId;
      if (!requestId) throw error;
      const result = await command(['devices', 'approve', requestId, '--json'], `approve-synthetic-device-${attempt}`);
      if (result.code !== 0) throw Error('isolated device pairing failed');
      record({ kind: 'SYNTHETIC_OPERATOR_PAIRED', device_id: deviceId });
    }
  }
  throw Error('isolated operator pairing did not complete');
}
