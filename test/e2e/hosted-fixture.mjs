import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';

// Actual current composed Hosted routes, credential store and disk persistence.
// Only the external entitlement/control-plane service is a synthetic fixture.
export async function createDiskHostedFixture(source, profile) {
  const load = relative => import(pathToFileURL(join(source, relative)));
  const { createHostedBetaApp } = await load('hosted-evidence/src/app.mjs');
  const { createConnectorCredential } = await load('src/shadow/v1-connector-store.mjs');
  const { planeStub, capturingLog } = await load('test/helpers/openclaw-shadow-harness.mjs');
  const plane = planeStub(); const logStream = capturingLog();
  const scope = { org_id: 'org_lab_a', workspace_id: 'ws_lab_a', installation_id: 'inst_lab_a001' };
  const codes = new Map(); const access = new Map();
  const { ControlPlaneRefusal } = await load('src/controlplane/client.mjs');
  plane.client.redeemPairingCode = async code => {
    const secret = codes.get(code);
    if (!secret) throw new ControlPlaneRefusal(403, 'pairing_code_not_accepted', '');
    codes.delete(code); plane.secrets.set(secret, { ...scope, credential_id: 'cred_cp_synthetic' });
    return { installation: scope, credential: { credential_id: 'cred_cp_synthetic' }, installation_secret: secret };
  };
  // External admission/notification stub: real Hosted proxy and packaged CLI,
  // no external email, staff approval, account creation or customer submission.
  const verificationCode = randomBytes(16).toString('hex');
  plane.client.call = async (method, path, payload) => {
    assert.equal(method, 'POST'); assert.match(path, /^\/v1\/access\/(create|status|send|verify)$/);
    const action = path.split('/').at(-1); const id = payload.data?.request_id ?? payload.request_id;
    if (action === 'create') { assert.equal(access.has(id), false); access.set(id, { owner: payload.owner_key, status: 'EMAIL_PENDING', sent: false }); }
    const row = access.get(id); assert.equal(row?.owner, payload.owner_key);
    if (action === 'send') row.sent = true;
    if (action === 'verify') { assert.ok(row.sent); assert.equal(payload.code, verificationCode); row.status = 'PENDING_REVIEW'; }
    return { request_id: id, status: row.status };
  };
  const options = { controlPlane: plane.client, reviewDbPath: join(profile, 'hosted-qualification.sqlite'), verifyProvenance: true, logStream, hosted: { refusalFloorMs: 0 } };
  let app = createHostedBetaApp(options);
  return {
    get app() { return app; }, get db() { return app.reviewDb; },
    scope, verificationCode,
    pairingCode() { const code = randomBytes(24).toString('base64url'); codes.set(code, randomBytes(32).toString('base64url')); return code; },
    mint() {
      const credential = createConnectorCredential(app.reviewDb, { orgId: this.scope.org_id, workspaceId: this.scope.workspace_id, installationId: this.scope.installation_id, deploymentId: 'synthetic-deployment', now: () => new Date(), sourceClass: 'LIVE_CAPTURE' });
      plane.secrets.set(credential.token.split('.')[1], { ...this.scope, credential_id: credential.credentialId });
      return credential;
    },
    restart() { app.shutdown(); app = createHostedBetaApp(options); },
    close() { app.shutdown(); },
  };
}
