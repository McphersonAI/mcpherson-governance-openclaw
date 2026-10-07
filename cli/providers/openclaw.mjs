import { realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { agentId, assertPath, inside, readBounded, readJson, refuse, timestamp, toolId } from '../safe-local.mjs';
import { withLeastPrivilegeHookPolicy } from '../../pairing/openclaw-profile-pairing.mjs';

const PLUGIN = 'mcpherson-governance-connector';
const ACTIONS = Object.freeze({ SHADOW_WOULD_ALLOW: 'WOULD_ALLOW', SHADOW_WOULD_DENY: 'WOULD_DENY', SHADOW_WOULD_REQUIRE_APPROVAL: 'WOULD_REQUIRE_APPROVAL', ABSTAIN: 'ABSTAIN', INDETERMINATE: 'INDETERMINATE', ERROR: 'ERROR' });
const VERSION = /^\d{1,4}\.\d{1,3}\.\d{1,3}(?:[-+][a-z0-9.-]{1,32})?$/i;

export function resolveProfile(flags, env = process.env, home = homedir()) {
  const profile = flags.profile ?? env.OPENCLAW_PROFILE ?? 'default';
  if (typeof profile !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,63}$/i.test(profile)) refuse('PROFILE_INVALID');
  const base = resolve(flags['profile-home'] ?? home);
  const named = join(base, profile === 'default' ? '.openclaw' : `.openclaw-${profile}`);
  const explicit = flags['profile-home'] !== undefined || flags.profile !== undefined || env.OPENCLAW_PROFILE !== undefined;
  if (env.OPENCLAW_STATE_DIR && !isAbsolute(env.OPENCLAW_STATE_DIR)) refuse('STATE_PATH_INVALID');
  if (explicit && env.OPENCLAW_STATE_DIR && resolve(env.OPENCLAW_STATE_DIR) !== named) refuse('PROFILE_STATE_CONFLICT');
  const root = resolve(env.OPENCLAW_STATE_DIR || named);
  if (root === dirname(root)) refuse('STATE_PATH_INVALID');
  if (env.OPENCLAW_CONFIG_PATH && resolve(env.OPENCLAW_CONFIG_PATH) !== join(root, 'openclaw.json')) refuse('PROFILE_CONFIG_CONFLICT');
  return { root, profile, home: base };
}

export async function createOpenClawProvider({ flags = {}, env = process.env, home, packageRoot, now = Date.now(), dependencies = {} }) {
  const selection = resolveProfile(flags, env, home);
  const root = selection.root;
  const configPath = join(root, 'openclaw.json');
  const pluginRoot = join(packageRoot, 'plugins/openclaw-connector');
  const load = (name) => import(pathToFileURL(join(pluginRoot, `${name}.mjs`)).href);
  const [configModule, operator, controls, rosterModule, receiptModule, entrypoint, publicationModule] = await Promise.all([
    load('config'), load('operator'), load('controls'), load('runtime-publisher'), load('receipts'),
    load('cli-entrypoint'), load('runtime-publication-status'),
  ]);
  const host = readJson(root, configPath, { privateFile: false });
  // Native config includes / environment substitutions cannot be resolved by a
  // standalone parser; never silently substitute the default profile/config.
  if (host && /"\$include"\s*:|\$\{[^}]+\}/.test(JSON.stringify(host))) refuse('RUNTIME_CONFIG_UNRESOLVED');
  const entry = host?.plugins?.entries?.[PLUGIN];
  if (entry !== undefined && (!entry || typeof entry !== 'object' || Array.isArray(entry))) refuse('PLUGIN_CONFIG_INVALID');
  const source = entry?.config ?? {};
  if (!source || typeof source !== 'object' || Array.isArray(source)) refuse('PLUGIN_CONFIG_INVALID');
  if (entry?.enabled !== undefined && typeof entry.enabled !== 'boolean') refuse('PLUGIN_CONFIG_INVALID');
  for (const key of ['entries', 'list']) {
    const value = host?.agents?.[key];
    if (value !== undefined && (key === 'list' ? !Array.isArray(value) : !value || typeof value !== 'object' || Array.isArray(value))) refuse('ROSTER_INVALID');
  }
  const stateDir = resolve(source.stateDir ?? join(root, PLUGIN));
  const receiptDir = resolve(source.receiptDir ?? join(stateDir, 'receipts'));
  if (!inside(root, stateDir) || stateDir === root || !inside(stateDir, receiptDir) || receiptDir === stateDir) refuse('FOREIGN_STATE_PATH');
  if (flags['state-dir'] && resolve(flags['state-dir']) !== stateDir) refuse('PROFILE_STATE_CONFLICT');
  assertPath(root, stateDir); assertPath(root, receiptDir);
  const pluginEnabled = host !== null && entry !== undefined && host.plugins?.enabled !== false
    && entry.enabled !== false && (!Array.isArray(host.plugins?.allow) || host.plugins.allow.includes(PLUGIN))
    && (!Array.isArray(host.plugins?.deny) || !host.plugins.deny.includes(PLUGIN));
  const config = configModule.loadConnectorConfig({ ...source, enabled: pluginEnabled && source.enabled === true }, { openclawStateDir: root, stateDir, receiptDir });
  // File names come from the source-owned contracts, never user record fields.
  const { RECEIPT_FILE, CREDENTIAL_FILE, PLUGIN_VERSION } = await load('constants');
  for (const name of [CREDENTIAL_FILE, ...['disabled', 'killswitch', 'lock'].map(n => controls.controlPath(stateDir, n).split('/').at(-1))]) assertPath(root, join(stateDir, name));
  for (const [key, field] of [['api-url', 'apiUrl'], ['deployment-id', 'deploymentId'], ['agent-id', 'agentId']]) {
    if (dependencies.legacy && flags[key] !== undefined && flags[key] !== config[field]) refuse('PROFILE_STATE_CONFLICT');
  }
  const status = operator.connectorStatus(config);
  const problems = [];
  if (status.pairing.error) problems.push('CREDENTIAL_UNREADABLE');
  for (const value of Object.values(status.controls)) if (value.startsWith('invalid')) problems.push('CONTROL_INVALID_FAIL_SAFE');
  let installed = 'UNKNOWN';
  const installPath = host?.plugins?.installs?.[PLUGIN]?.installPath;
  const installRoots = installPath === undefined ? [join(root, 'extensions', PLUGIN)] : [installPath];
  for (const dir of installRoots) {
    if (typeof dir !== 'string' || !isAbsolute(dir) || !inside(root, dir) || dir === root) { problems.push('INSTALL_PATH_UNVERIFIED'); continue; }
    try {
      const manifest = readJson(root, join(dir, 'package.json'), { maxBytes: 65536, privateFile: false });
      if (manifest && ['@mcphersonai/mcpherson-governance-openclaw', 'mcpherson-governance-connector'].includes(manifest.name) && VERSION.test(manifest.version)) installed = 'INSTALLED';
      else if (installPath !== undefined) installed = manifest ? 'IDENTITY_UNVERIFIED' : 'RECORDED_INSTALL_MISSING';
    } catch { problems.push('INSTALL_PATH_UNVERIFIED'); }
  }
  const roster = host === null ? null : rosterModule.configuredAgentRoster(host);
  if (roster?.some(a => !toolId(a.agent_id))) refuse('ROSTER_LABEL_UNSAFE');
  if (roster && roster.length > 1024) refuse('ROSTER_TOO_LARGE');
  const configured = new Set((roster ?? []).map(a => a.agent_id));
  let truncated = false;
  const records = (name) => {
    let data;
    try { data = readBounded(root, join(receiptDir, name), { tail: true }); }
    catch { problems.push('EVIDENCE_UNREADABLE'); return []; }
    if (!data) return [];
    truncated ||= data.truncated;
    const rows = [];
    for (const line of data.text.split('\n')) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line) > 16384) { problems.push('EVIDENCE_RECORD_INVALID'); continue; }
      try { const row = JSON.parse(line); if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error(); rows.push(row); }
      catch { problems.push('EVIDENCE_RECORD_INVALID'); }
    }
    return rows;
  };
  const activities = [];
  const decisions = [];
  let lifecycle = null;
  let runtimeVersion = null;
  let versionAt = '';
  const seen = new Set();
  for (const row of records(RECEIPT_FILE)) {
    try {
      // Historical lifecycle schema is unchanged across the inherited releases.
      if (row.record_type === 'connector_lifecycle' && VERSION.test(row.plugin_version)) receiptModule.validateReceipt({ ...row, plugin_version: PLUGIN_VERSION });
      else receiptModule.validateReceipt(row);
    } catch { problems.push('EVIDENCE_RECORD_INVALID'); continue; }
    const at = timestamp(row.timestamp, now);
    if (!at) { problems.push('EVIDENCE_RECORD_INVALID'); continue; }
    if (row.record_type === 'connector_lifecycle') {
      if (!lifecycle || at > lifecycle.at) lifecycle = { at, event: row.event };
      continue;
    }
    if (row.deployment_id !== config.deploymentId) { problems.push('FOREIGN_EVIDENCE_SKIPPED'); continue; }
    if (row.receipt_type !== 'completion_receipt') continue;
    const agent = toolId(row.agent_id) && agentId(row.agent_id); const tool = toolId(row.tool_id);
    if (!agent || !tool) { problems.push('EVIDENCE_LABEL_INVALID'); continue; }
    const key = `${agent}\n${tool}\n${row.correlation_ref}\n${row.request_hash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    activities.push({ at, agent_id: agent, capability: tool, outcome: row.outcome, source: 'completion_receipt' });
  }
  for (const row of records('shadow-v070-evidence.jsonl')) {
    if (row.schema !== 'observa-openclaw-shadow-evidence/v1' || row.mode !== 'SHADOW' || row.authority !== 'NONE' || row.enforcement !== 'OFF' || row.active !== false || row.runtime_name !== 'openclaw') {
      problems.push('EVIDENCE_RECORD_INVALID'); continue;
    }
    const at = timestamp(row.ts, now);
    if (!at) { problems.push('EVIDENCE_RECORD_INVALID'); continue; }
    if (VERSION.test(row.runtime_version) && at > versionAt) { runtimeVersion = row.runtime_version; versionAt = at; }
    if (row.kind !== 'SHADOW_DECISION' || !Object.hasOwn(ACTIONS, row.action)) continue;
    if (row.execution_effect !== 'NONE') { problems.push('EVIDENCE_RECORD_INVALID'); continue; }
    const agent = row.agent_id == null ? null : toolId(row.agent_id) && agentId(row.agent_id);
    const tool = row.tool_name == null ? null : toolId(row.tool_name);
    if ((row.agent_id != null && !agent) || (row.tool_name != null && !tool)) { problems.push('EVIDENCE_LABEL_INVALID'); continue; }
    decisions.push({ at, agent_id: agent, capability: tool, decision: ACTIONS[row.action], source: 'shadow_evidence' });
  }
  const newest = (a, b) => b.at.localeCompare(a.at) || JSON.stringify(a).localeCompare(JSON.stringify(b));
  activities.sort(newest); decisions.sort(newest);
  const allAgents = new Set([...configured, ...activities.map(a => a.agent_id), ...decisions.map(d => d.agent_id).filter(Boolean)]);
  const agents = [...allAgents].sort().map(id => {
    const evidence = activities.filter(a => a.agent_id === id);
    return { agent_id: id, configured: roster === null ? null : configured.has(id), observed: evidence.length > 0,
      state: evidence.length ? (now - Date.parse(evidence[0].at) <= 300000 ? 'ACTIVE' : 'QUIET') : configured.has(id) ? 'CONFIGURED' : 'DECISION_ONLY',
      heartbeat: 'NOT_AVAILABLE', last_activity: evidence[0]?.at ?? null,
      observed_capabilities: [...new Set(evidence.map(a => a.capability))].sort() };
  });
  // The gateway's local publication journal: liveness/identity metadata only,
  // never activity. A missing or invalid journal is simply "not available".
  let publication = null;
  try {
    const journal = readBounded(root, join(stateDir, publicationModule.PUBLICATION_STATUS_FILE), { maxBytes: 8192 });
    if (journal) {
      publication = publicationModule.parsePublicationStatus(journal.text);
      if (publication === null) problems.push('PUBLICATION_JOURNAL_INVALID');
    }
  } catch { problems.push('PUBLICATION_JOURNAL_UNREADABLE'); }
  const hostedModule = await load('hosted-ctl');
  const publicationView = hostedModule.assessPublication(publication, { now, rosterRevision: null });
  // How `observa` resolves: the gateway's last launcher outcome, and what the
  // current PATH actually runs. Metadata only.
  const recorded = entrypoint.readEntrypointRecord(stateDir);
  const onPath = entrypoint.resolveObservaOnPath(env.PATH);
  let installRoot = null;
  try { installRoot = realpathSync(packageRoot); } catch { installRoot = null; }
  const cliEntrypoint = {
    recorded_state: recorded?.state ?? 'NOT_RECORDED', recorded_path: recorded?.path ?? null,
    path_resolution: onPath.kind === 'OWNED' ? (onPath.root === installRoot ? 'THIS_PLUGIN' : 'OTHER_PLUGIN_INSTALL') : onPath.kind,
    path: onPath.path, remediation: recorded?.remediation ?? null,
  };
  const disabled = !status.enabled || status.controls.killswitch !== 'absent' || status.controls.lock !== 'absent';
  const stopped = lifecycle?.event === 'gateway_stop' && (!activities[0] || lifecycle.at >= activities[0].at);
  const observing = disabled ? 'DISABLED' : stopped ? 'STOPPED' : activities[0] && now - Date.parse(activities[0].at) <= 300000 ? 'RECENT_LOCAL_EVIDENCE' : activities.length ? 'STALE_LOCAL_EVIDENCE' : 'NO_LOCAL_EVIDENCE';
  const evidenceHealth = problems.length ? 'DEGRADED' : activities.length || decisions.length ? 'AVAILABLE' : 'EMPTY';
  const summary = {
    pluginId: PLUGIN, ...status, pipeline: null, receipts: null,
    pairing: { paired: status.pairing.paired, credentialId: status.pairing.credentialId, fingerprint: status.pairing.fingerprint, ...(status.pairing.error ? { error: 'CREDENTIAL_UNREADABLE' } : {}) },
    runtime: { type: 'OpenClaw', version: runtimeVersion, version_source: runtimeVersion ? 'local_shadow_evidence' : null, live_state: 'NOT_PROBED' },
    plugin_installed: installed,
    plugin_configured: entry !== undefined, configuration: host === null ? 'MISSING' : 'PROFILE_FILE',
    enabled_source: 'PROFILE_CONFIG_AND_DURABLE_DISABLE', observing, heartbeat: publicationView.heartbeat,
    heartbeat_accepted_at: publicationView.heartbeat_accepted_at, heartbeat_source: publication ? 'GATEWAY_PUBLICATION_JOURNAL' : null,
    cli_entrypoint: cliEntrypoint,
    configured_agent_count: roster === null ? null : configured.size,
    hosted_connection: status.pairing.paired ? 'PAIRED_CONNECTION_NOT_PROBED' : 'UNPAIRED',
    evidence: { health: evidenceHealth, bounded: true, truncated, activity_count: activities.length, decision_count: decisions.length, problems: [...new Set(problems)].sort() },
  };
  return {
    id: 'openclaw',
    snapshot: () => ({ status: summary, agents, activity: activities, decisions, evidence: summary.evidence }),
    async hosted(command) {
      // Operator-invoked and networked by design. The hosted module keeps the
      // same outbound gate, credential reader and contracts as the runtime.
      const options = {
        config, pairing: summary.pairing, roster, publication, now,
        client: dependencies.hostedClient ?? null,
        credentialProvider: dependencies.hostedCredentialProvider,
      };
      if (options.credentialProvider === undefined) delete options.credentialProvider;
      assertPath(root, stateDir);
      if (command === 'hosted-health') return hostedModule.probeHostedHealth({ ...options, configured: entry !== undefined });
      return hostedModule.identifyRuntimeRoster(options);
    },
    async control(command, args, commandFlags) {
      let configUpdated = false;
      if (command === 'enable' && (!pluginEnabled || source.enabled !== true)) {
        // Enable only this plugin. Never widen the host's global plugin gates
        // or overwrite a configuration that changed after our read.
        if (!host || !entry || host.plugins?.enabled === false
            || (Array.isArray(host.plugins?.allow) && !host.plugins.allow.includes(PLUGIN))
            || (Array.isArray(host.plugins?.deny) && host.plugins.deny.includes(PLUGIN))) refuse('ENABLE_REQUIRES_PLUGIN_CONFIG');
        assertPath(root, configPath);
        const current = readJson(root, configPath, { privateFile: false });
        if (JSON.stringify(current) !== JSON.stringify(host)) refuse('LOCAL_FILE_CHANGED');
        // Enabling re-asserts this plugin's least-privilege hook policy so the
        // capability review keeps reporting prompt injection and conversation
        // access as denied. An explicit operator value is never overwritten.
        const next = { ...host, plugins: { ...host.plugins, entries: { ...host.plugins.entries,
          [PLUGIN]: {
            ...entry,
            enabled: true,
            hooks: withLeastPrivilegeHookPolicy(entry),
            config: { ...source, enabled: true },
          } } } };
        const { atomicWriteSecureFile } = await load('secure-files');
        atomicWriteSecureFile(configPath, `${JSON.stringify(next, null, 2)}\n`);
        configUpdated = true;
      }
      // Revalidate before existing lifecycle operations, which retain their own
      // credential verification, transaction journals, controls and authority.
      assertPath(root, stateDir);
      for (const name of [CREDENTIAL_FILE, ...['disabled', 'killswitch', 'lock'].map(n => controls.controlPath(stateDir, n).split('/').at(-1))]) assertPath(root, join(stateDir, name));
      if (command === 'uninstall') {
        const interactive = !commandFlags.json && (dependencies.interactive ?? Boolean(process.stdin.isTTY && process.stdout.isTTY));
        if (commandFlags.yes !== true && !interactive) refuse('UNINSTALL_CONFIRMATION_REQUIRED');
        const result = operator.uninstallConnector({ confirmed: commandFlags.yes === true, interactive, runner: (bin, argv, options) => (dependencies.runner ?? spawnSync)(bin, argv, { ...options, env: { ...env, OPENCLAW_PROFILE: selection.profile, OPENCLAW_STATE_DIR: root, OPENCLAW_CONFIG_PATH: configPath } }) });
        // Only after OpenClaw confirmed the uninstall: remove the `observa`
        // launcher this plugin created for this install, and nothing else.
        let removal = { removed: [], kept: [] };
        if (installRoot) {
          try { removal = entrypoint.removeObservaEntrypoint({ pluginRoot: installRoot, stateDir, argv1: dependencies.argv1 ?? process.argv[1] }); }
          catch { removal = { removed: [], kept: [{ path: null, kind: 'REMOVAL_FAILED' }] }; }
        }
        return { ...result, cliEntrypointRemoved: removal.removed.length > 0, cliEntrypointKept: removal.kept.map(k => k.kind) };
      }
      if (command === 'credential' && commandFlags['new-credential-file']) {
        const delivery = resolve(commandFlags['new-credential-file']);
        assertPath(dirname(delivery), delivery);
      }
      const ctl = await load('connector-ctl-legacy');
      const argv = command === 'credential' ? [args[0]] : [command];
      if (['killswitch', 'lock'].includes(command)) argv.push(`--${args[0]}`);
      for (const key of ['new-credential-file', 'rotation', 'rotation-operator']) if (commandFlags[key]) argv.push(`--${key}`, commandFlags[key]);
      const result = await ctl.runConnectorCtl(argv, { ...dependencies, loadConfig: () => config });
      return configUpdated ? { ...result, configUpdated: true, gatewayReloadMayBeRequired: true } : result;
    },
    pairEnv: () => ({ ...env, OPENCLAW_PROFILE: selection.profile, OPENCLAW_STATE_DIR: root, OPENCLAW_CONFIG_PATH: configPath }),
    pairArgs() {
      // Existing pair helper resolves profiles from a home, so custom state
      // roots cannot safely be coerced into its profile model.
      const expected = join(selection.home, selection.profile === 'default' ? '.openclaw' : `.openclaw-${selection.profile}`);
      if (root !== expected) refuse('PAIR_CUSTOM_STATE_UNSUPPORTED');
      return ['--profile', selection.profile, '--profile-home', selection.home];
    },
  };
}
