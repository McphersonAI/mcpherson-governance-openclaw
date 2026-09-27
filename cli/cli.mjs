import { ACCESS_FLAGS, ACCESS_HELP, runAccess } from './access.mjs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { createOpenClawProvider } from './providers/openclaw.mjs';
import { agentId, readBounded, refuse } from './safe-local.mjs';

export const CLI_VERSION = '0.7.4';
export const POSTURE = Object.freeze({ mode: 'SHADOW', authority: 'NONE', enforcement: 'OFF', active: false });
// A provider supplies a projected metadata snapshot and bounded control/pair
// dispatch. No runtime registry, dynamic plugin loading or tool execution API.
export const RUNTIME_PROVIDERS = Object.freeze({ openclaw: createOpenClawProvider });
const HELP = {
  status: 'status\nShow selected-profile configuration, pairing, controls and local evidence health.\nEnabled is configuration intent; live gateway/Hosted connection are not probed.\nHeartbeat is the gateway\'s last locally recorded Hosted acceptance, when present.\nTo actively check Hosted, run observa hosted-health.',
  agents: 'agents\nList configured agents and agents evidenced locally. ACTIVE means a completion\nin the last 5 minutes, not ACTIVE governance. Capabilities require completion receipts.',
  agent: 'agent <id>\nShow configuration, observed capabilities and recent local activity/decisions.',
  activity: 'activity [--limit <1-100>]\nRecent completion receipts only. Heartbeat, prompts, commands and tool bodies are excluded.',
  decisions: 'decisions [--limit <1-100>]\nLocal SHADOW counterfactual evidence only; activity never becomes a decision.',
  pair: 'pair --api-url <https://host> [--code-file <owner-only-file>]\nUses the existing pairing flow; without --code-file, input is hidden at the terminal.\nOptions: --deployment-id, --installation-name, --ca-file, --agent-id,\n--policy-version, --replace-existing, --preflight-only, --rollback <id>.\nPairing codes are never accepted in arguments.',
  enable: 'enable\nEnable this plugin in the selected profile and clear its durable disable control.\nGlobal plugin gates are preserved. A gateway reload may be needed after a config\nchange. Does not activate governance or enforcement.',
  disable: 'disable\nSet the durable observation disable control. Tools continue normally.',
  killswitch: 'killswitch <on|off>\nToggle the observation/network kill switch. Tools continue normally.',
  lock: 'lock <on|off>\nToggle the observation/network lock. Tools continue normally.',
  credential: 'credential <rotate|recover> --new-credential-file <owner-only-file>\nrotate also requires --rotation <id>. Optional: --rotation-operator <trusted-path>.\nUses existing authenticated lifecycle and recovery; requires the existing trusted\nserver operator. Credential values are never accepted or printed.',
  unpair: 'unpair\nDisable observation, revoke the paired Hosted credential and remove it only\nafter server confirmation. On failure the existing recovery journal is retained.',
  uninstall: 'uninstall [--yes]\nRun the existing OpenClaw plugin uninstaller in the selected profile, then remove\nthe observa command this plugin created (never any other observa command).\nIn a terminal, OpenClaw asks you to confirm; --yes confirms without asking.\nReceipts are preserved; this does not revoke Hosted credentials (use unpair first).',
  'request-access': ACCESS_HELP['request-access'],
  'request-status': ACCESS_HELP['request-status'],
  'hosted-health': 'hosted-health\nActively check the paired Hosted connection: reachability, credential acceptance\nand installation binding (GET /v1/health, GET /v1/credentials/identity), plus the\ngateway\'s recorded heartbeat and roster freshness. Unlike status, this contacts\nHosted. It obeys disable, killswitch and lock, never prints credentials, and writes\nno activity, decision or heartbeat. Unpaired: reports NOT_PAIRED and the next steps.\nExit status: 0 HEALTHY, 2 checked but not healthy, 1 could not run.',
  identify: 'identify\nIdentify the agents this OpenClaw profile configures. When paired, confirm that\nroster on Hosted through the existing runtime roster contract, under the running\ngateway\'s own runtime identity so its heartbeat is never superseded. A changed\nroster is published by the gateway on restart. Obeys disable, killswitch and lock.\nIdentity is not activity: no receipt, activity, decision or heartbeat is written,\nand no agent becomes ACTIVE. Exit status: 0 identified (and confirmed when paired),\n2 Hosted confirmation not completed, 1 could not run.',
};
const ROOT_HELP = `Observa — governance visibility for AI agents

Usage:
  observa <command> [options]
  observa <command> --help

Local (offline; reads this machine only, never contacts Hosted):
  status                  Configuration, pairing, controls and local evidence health
  agents                  Configured and locally evidenced agents
  agent <id>              One agent: configuration, activity and decisions
  activity                Recent completed tool activity (receipts)
  decisions               Local SHADOW counterfactual decisions (WOULD_*)

Hosted access (Hosted dashboard; start here):
  request-access          1. Request Hosted beta access (verified email)
  request-status          2. Check your access request
  pair                    3. Pair this OpenClaw profile with Hosted Observa

Hosted health / refresh (after pairing; contacts Hosted):
  hosted-health           Check Hosted connectivity, binding and heartbeat
  identify                Identify agents locally; confirm the Hosted roster when paired

Controls:
  enable                  Enable this plugin's observation
  disable                 Stop observation and all Hosted traffic
  killswitch <on|off>     Observation/network kill switch
  lock <on|off>           Observation/network lock

Lifecycle:
  credential <rotate|recover>
  unpair
  uninstall

Hosted path: request-access -> request-status -> pair -> hosted-health -> identify

Options:
  --help, -h                  Command help
  --version                  Observa version
  --json                     Deterministic metadata JSON (except interactive pair)
  --runtime openclaw         Runtime provider; other adapters are not in this build
  --profile <name>           OpenClaw profile (default or OPENCLAW_PROFILE)
  --profile-home <dir>       Home containing that profile
  --limit <1-100>            Activity/decisions limit (default 20)

Environment: OPENCLAW_STATE_DIR selects the runtime state root. Conflicting
profile/config selectors are refused. Local commands never contact Hosted or
start a gateway; only request-*, pair, hosted-health, identify, credential and
unpair contact Hosted, and only when you run them.
SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF`;
const UPGRADE = 'Local Observa view. Hosted adds persistent history, AutoMap, Governance Analysis and reports.\nRequest Hosted beta access with observa request-access.';
const NO_ACTIVITY = 'Identity and health are not activity: no receipt, activity, decision or heartbeat was written.';
const COMMON = ['help', 'json', 'runtime', 'profile', 'profile-home', 'state-dir'];
const FLAGS = {
  help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' }, json: { type: 'boolean' },
  runtime: { type: 'string' }, profile: { type: 'string' }, 'profile-home': { type: 'string' },
  'state-dir': { type: 'string' }, limit: { type: 'string' },
  'api-url': { type: 'string' }, 'code-file': { type: 'string' },
  'deployment-id': { type: 'string' }, 'installation-name': { type: 'string' },
  'ca-file': { type: 'string' }, 'agent-id': { type: 'string' }, 'policy-version': { type: 'string' },
  'replace-existing': { type: 'boolean' }, 'preflight-only': { type: 'boolean' }, rollback: { type: 'string' },
  'new-credential-file': { type: 'string' }, rotation: { type: 'string' }, 'rotation-operator': { type: 'string' },
  on: { type: 'boolean' }, off: { type: 'boolean' },
  name: { type: 'string' }, email: { type: 'string' }, organization: { type: 'string' }, 'use-case': { type: 'string' }, yes: { type: 'boolean' }, resend: { type: 'boolean' }, new: { type: 'boolean' },
};
const PAIR_FLAGS = ['api-url', 'code-file', 'deployment-id', 'installation-name', 'ca-file', 'agent-id', 'policy-version', 'replace-existing', 'preflight-only', 'rollback'];
const ERRORS = {
  ACCESS_TLS_REQUIRED: 'Verified TLS is required. Remove the NODE_TLS_REJECT_UNAUTHORIZED override.',
  ACCESS_INPUT_INVALID: 'Use bounded, valid identity fields and metadata.',
  ACCESS_IDENTITY_REQUIRED: 'Name and email are required. See observa request-access --help.',
  ACCESS_URL_REQUIRED: 'Supply --api-url with the HTTPS Hosted Observa origin.',
  ACCESS_INPUT_REQUIRED: 'Use a terminal, or --yes with identity fields and a private --code-file.',
  ACCESS_CONFIRMATION_REQUIRED: 'Nothing submitted. Explicit confirmation or --yes is required.',
  ACCESS_RECEIPT_INVALID: 'The private request receipt is invalid or belongs to another server.',
  ACCESS_NO_REQUEST: 'No request receipt exists in this profile. Run observa request-access.',
  ACCESS_ALREADY_PENDING: 'This profile already has an active request. Run observa request-status.',
  ACCESS_IDENTITY_IMMUTABLE: 'Request identity cannot be changed. A different email requires a new verified request.',
  ACCESS_CODE_INVALID: 'Use the complete verification code from your email.',
  ACCESS_RATE_LIMITED: 'Too many attempts. Wait before trying again.',
  ACCESS_REFUSED: 'The request was refused. Check its status and the verification code; it may have expired or already been used.',
  ACCESS_UNAVAILABLE: 'Hosted access requests are temporarily unavailable. Your private local receipt is retained; try again later.',
  COMMAND_INVALID: 'Unknown command or arguments. Run observa --help.',
  OPTIONS_INVALID: 'Invalid or unsupported option. Run observa <command> --help.',
  AGENT_ID_INVALID: 'Invalid agent id. Use letters, digits, underscores or hyphens (1–64 characters).',
  AGENT_NOT_FOUND: 'No configured agent or local evidence matches this id.',
  RUNTIME_UNAVAILABLE: 'This runtime provider is not available in this build.',
  ENABLE_REQUIRES_PLUGIN_CONFIG: 'The selected OpenClaw plugin is absent or blocked by a global plugin gate. Resolve that host configuration first; other plugins are not enabled automatically.',
  LOCAL_JSON_INVALID: 'Local configuration is corrupt or is not supported plain JSON. No fallback profile was read.',
  PROFILE_STATE_CONFLICT: 'Profile and state directory selectors conflict. No operation was performed.',
  PROFILE_CONFIG_CONFLICT: 'Config path does not belong to the selected profile. No operation was performed.',
  CONFIG_RUNTIME_OBSERVATION_PROFILE_MISMATCH: 'Runtime observation configuration belongs to another profile. No operation was performed.',
  RUNTIME_CONFIG_UNRESOLVED: 'Includes or environment substitutions require runtime resolution; standalone state is unknown.',
  FOREIGN_STATE_PATH: 'Connector state/evidence must remain inside the selected OpenClaw profile.',
  UNSAFE_STATE_PATH: 'Unsafe local path (ownership, permissions, link or profile boundary).',
  UNSAFE_LOCAL_FILE: 'Local file is not a regular owner-controlled file with safe permissions.',
  PAIR_JSON_UNSUPPORTED: 'Interactive pairing does not support --json. Use observa pair --help.',
  UNINSTALL_CONFIRMATION_REQUIRED: 'OpenClaw asks to confirm plugin removal. Run observa uninstall in a terminal, or pass --yes to confirm.',
};
function age(at, now) {
  if (!at) return 'never';
  const s = Math.max(0, Math.floor((now - Date.parse(at)) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
}
function table(rows, columns) {
  const values = rows.map(row => columns.map(([key]) => String(row[key] ?? 'unknown')));
  const widths = columns.map(([, label], i) => Math.max(label.length, ...values.map(r => r[i].length)));
  return [columns.map(([, label], i) => label.padEnd(widths[i])).join('  ').trimEnd(), ...values.map(row => row.map((v, i) => v.padEnd(widths[i])).join('  ').trimEnd())].join('\n');
}
function renderAgents(agents, now) {
  return table(agents.map(a => ({ ...a, configured: a.configured === null ? 'UNKNOWN' : a.configured ? 'YES' : 'NO', observed: a.observed ? 'YES' : 'NO', last: age(a.last_activity, now), capabilities: a.observed_capabilities.join(', ') || 'none evidenced' })), [['agent_id', 'AGENT'], ['configured', 'CONFIGURED'], ['observed', 'OBSERVED'], ['state', 'STATE'], ['heartbeat', 'HEARTBEAT'], ['last', 'LAST ACTIVITY'], ['capabilities', 'OBSERVED CAPABILITIES']]);
}
function renderActivity(rows) { return rows.length ? table(rows, [['at', 'TIME'], ['agent_id', 'AGENT'], ['capability', 'CAPABILITY'], ['outcome', 'OUTCOME']]) : 'No meaningful local activity evidence.'; }
function renderDecisions(rows) { return rows.length ? table(rows, [['at', 'TIME'], ['agent_id', 'AGENT'], ['capability', 'CAPABILITY'], ['decision', 'COUNTERFACTUAL DECISION']]) : 'No local decision evidence. Activity is not a governance decision.'; }
function renderStatus(s, now) {
  const yes = v => v ? 'YES' : 'NO';
  return `Observa ${CLI_VERSION}
Runtime                 ${s.runtime.type} ${s.runtime.version ?? '(version unknown)'}${s.runtime.version ? ' (last local evidence)' : ''}
Plugin installed        ${s.plugin_installed} (selected-profile package evidence; live gateway not probed)
Plugin configured       ${yes(s.plugin_configured)} (${s.configuration})
Paired                  ${yes(s.pairing.paired)}${s.pairing.error ? ' (credential unreadable)' : ''}
Enabled                 ${yes(s.enabled)} (profile config + durable disable; gateway not probed)
Observing               ${s.observing}
Posture                 SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF
Killswitch              ${s.controls.killswitch === 'absent' ? 'OFF' : 'ON'}
Lock                    ${s.controls.lock === 'absent' ? 'OFF' : 'ON'}
Credential fingerprint  ${s.pairing.fingerprint ?? 'unavailable'}
Configured agents       ${s.configured_agent_count ?? 'unknown'}
Heartbeat               ${s.heartbeat === 'NOT_AVAILABLE' ? 'NOT_AVAILABLE (no gateway publication journal)' : `${s.heartbeat} (last accepted ${age(s.heartbeat_accepted_at, now)}; gateway journal, not probed)`}
Evidence health         ${s.evidence.health}${s.evidence.truncated ? ' (bounded tail)' : ''}
Hosted connection       ${s.hosted_connection}${s.pairing.paired ? ' (observa hosted-health probes it)' : ''}
CLI entrypoint          ${renderEntrypoint(s.cli_entrypoint)}`;
}
function renderEntrypoint(e) {
  if (!e) return 'unknown';
  const onPath = e.path_resolution === 'THIS_PLUGIN' ? `observa -> this plugin (${e.path})`
    : e.path_resolution === 'ABSENT' ? 'observa not on PATH' : `observa on PATH is ${e.path_resolution} (${e.path})`;
  return `${onPath}; gateway record ${e.recorded_state}${e.recorded_path && e.recorded_path !== e.path ? ` (${e.recorded_path})` : ''}${e.remediation && e.path_resolution !== 'THIS_PLUGIN' ? `\n                        ${e.remediation}` : ''}`;
}
function renderHostedHealth(h, now) {
  const yes = v => v ? 'YES' : 'NO';
  const p = h.publication;
  const heartbeat = !h.paired && p.heartbeat === 'NOT_AVAILABLE' ? 'NOT_APPLICABLE (unpaired; nothing is published)'
    : p.heartbeat === 'NOT_AVAILABLE' ? 'NOT_AVAILABLE (no gateway publication journal; restart the gateway on this version)'
      : `${p.heartbeat}${p.heartbeat_accepted_at ? ` (accepted ${age(p.heartbeat_accepted_at, now)}; cadence ${p.heartbeat_cadence_seconds}s; gateway journal)` : ''}`;
  const roster = !h.paired && p.roster === 'NOT_AVAILABLE' ? 'NOT_APPLICABLE (unpaired)'
    : p.roster === 'NOT_AVAILABLE' ? 'NOT_AVAILABLE' : `${p.roster}${p.roster_published_at ? ` (${p.roster_agents} agents, published ${age(p.roster_published_at, now)})` : ''}`;
  return `Observa hosted health: ${h.state}
Paired                  ${yes(h.paired)}
Credential              ${h.credential}${h.credential_fingerprint ? ` (fingerprint ${h.credential_fingerprint})` : ''}
Hosted endpoint         ${h.endpoint ?? 'none (unpaired)'}
Hosted reachable        ${h.reachable}
Installation binding    ${h.binding}${h.deployment_id ? ` (deployment ${h.deployment_id})` : ''}
Workspace binding       ${h.workspace_binding} (resolved by Hosted from the credential; not disclosed)
Last Hosted success     ${h.last_success_at ? `${h.last_success_at}${h.last_success_at === h.probed_at ? ' (this check)' : ' (gateway journal)'}` : 'none recorded'}
Runtime heartbeat       ${heartbeat}
Roster                  ${roster}
Connector               configured ${yes(h.connector_configured)}, enabled ${yes(h.connector_enabled)}
Refusal                 ${h.refusal ?? 'none'}
Posture                 SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF
${NO_ACTIVITY}${h.next.length ? `\n\nNext:\n${h.next.map(n => `  ${n}`).join('\n')}` : ''}`;
}
function renderIdentify(r) {
  const local = r.local.state === 'IDENTIFIED'
    ? `Configured agents (${r.local.agents.length}, OpenClaw configured roster):\n${r.local.agents.map(a => `  ${a}`).join('\n')}\nRoster revision         ${r.local.roster_revision}`
    : `Configured agents       ${r.local.state}`;
  const detail = r.hosted.state === 'ROSTER_CONFIRMED'
    ? ` (Hosted's current roster for this installation matches; runtime ${r.hosted.runtime_instance_id}, generation ${r.hosted.runtime_generation})`
    : r.hosted.reason ? ` (${r.hosted.reason})` : '';
  return `Observa identify
${local}
Hosted roster           ${r.hosted.state}${detail}
Posture                 SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF
${NO_ACTIVITY}${r.next.length ? `\n\nNext:\n${r.next.map(n => `  ${n}`).join('\n')}` : ''}`;
}

export async function runObserva(argv, { packageRoot = dirname(dirname(fileURLToPath(import.meta.url))), env = process.env, home, now = Date.now(), providers = RUNTIME_PROVIDERS, dependencies = {}, legacy = false } = {}) {
  let json = argv.includes('--json') || legacy;
  try {
    let parsed;
    try { parsed = parseArgs({ args: argv, options: FLAGS, allowPositionals: true, strict: true, tokens: true }); }
    catch { refuse('OPTIONS_INVALID'); }
    const { values: flags, positionals: pos, tokens } = parsed;
    if (new Set(tokens.filter(t => t.kind === 'option').map(t => t.name)).size !== tokens.filter(t => t.kind === 'option').length) refuse('OPTIONS_INVALID');
    let [command, ...args] = pos;
    if (legacy && ['rotate', 'recover'].includes(command)) { args = [command, ...args]; command = 'credential'; }
    if (legacy && ['killswitch', 'lock'].includes(command) && flags.on !== flags.off) args.push(flags.on ? 'on' : 'off');
    if (flags.version || command === 'version') {
      if (args.length || (command && command !== 'version')) refuse('COMMAND_INVALID');
      return { code: 0, stdout: json ? JSON.stringify({ schema: 'observa-cli/v1', ok: true, command: 'version', version: CLI_VERSION, posture: POSTURE }) : `Observa ${CLI_VERSION}` };
    }
    if (!command || command === 'help') {
      if (args.length > 1 || (args[0] && !HELP[args[0]])) refuse('COMMAND_INVALID');
      return { code: 0, stdout: args[0] ? `Usage: observa ${HELP[args[0]]}\n\nOptions: --json --runtime openclaw --profile <name> --profile-home <dir>` : ROOT_HELP };
    }
    if (!Object.hasOwn(HELP, command)) refuse('COMMAND_INVALID');
    if (flags.help) return { code: 0, stdout: `Usage: observa ${HELP[command]}\n\nOptions: --json --runtime openclaw --profile <name> --profile-home <dir>` };
    const allowed = [...COMMON, ...(command === 'request-access' ? ACCESS_FLAGS : command === 'request-status' ? ['api-url'] : []), ...(legacy ? ['api-url', 'deployment-id', 'agent-id'] : []), ...(command === 'pair' ? PAIR_FLAGS : []), ...(['activity', 'decisions', 'agent'].includes(command) ? ['limit'] : []), ...(command === 'credential' ? ['new-credential-file', 'rotation', 'rotation-operator'] : []), ...(command === 'uninstall' ? ['yes'] : []), ...(legacy && ['killswitch', 'lock'].includes(command) ? ['on', 'off'] : [])];
    if (Object.keys(flags).some(k => !allowed.includes(k))) refuse('OPTIONS_INVALID');
    if (command === 'agent') { if (args.length !== 1 || !agentId(args[0])) refuse('AGENT_ID_INVALID'); }
    else if (['credential', 'killswitch', 'lock'].includes(command)) {
      if (args.length !== 1 || !(command === 'credential' ? ['rotate', 'recover'] : ['on', 'off']).includes(args[0])) refuse('COMMAND_INVALID');
    } else if (args.length) refuse('COMMAND_INVALID');
    if (flags.limit !== undefined && (!/^[1-9][0-9]{0,2}$/.test(flags.limit) || Number(flags.limit) > 100)) refuse('OPTIONS_INVALID');
    const limit = Number(flags.limit ?? 20);
    const runtime = flags.runtime ?? 'openclaw';
    if (!Object.hasOwn(providers, runtime)) refuse('RUNTIME_UNAVAILABLE');
    const envelope = data => ({ schema: 'observa-cli/v1', ok: true, command, version: CLI_VERSION, runtime, posture: POSTURE, ...data });
    if (['request-access', 'request-status'].includes(command)) {
      if (runtime !== 'openclaw') refuse('RUNTIME_UNAVAILABLE');
      let metadata = {};
      if (command === 'request-access') {
        try { metadata = (await providers[runtime]({ flags, env, home, packageRoot, now, dependencies })).snapshot().status; }
        catch { /* Missing runtime metadata never blocks public admission. */ }
      }
      const result = await runAccess(command, { flags, env, home, version: CLI_VERSION, metadata, dependencies });
      return { code: 0, stdout: json ? JSON.stringify(envelope({ request: result }))
        : `Request: ${result.request_id}\nStatus: ${result.status}${result.status === 'PENDING_REVIEW' ? '\nEmail verified. Access request submitted for founder review.' : ''}${result.next_action ? `\n\nNext: ${result.next_action}` : ''}` };
    }
    if (command === 'pair' && flags.json) refuse('PAIR_JSON_UNSUPPORTED');
    const provider = await providers[runtime]({ flags, env, home, packageRoot, now, dependencies: { ...dependencies, legacy } });
    if (command === 'pair') {
      if (flags['code-file'] && !flags['preflight-only'] && !flags.rollback) {
        const path = (await import('node:path')).resolve(flags['code-file']);
        if (!readBounded(dirname(path), path, { maxBytes: 512 })) refuse('PAIR_CODE_FILE_UNAVAILABLE');
      }
      const pairArgs = provider.pairArgs();
      for (const key of PAIR_FLAGS) if (flags[key] !== undefined) pairArgs.push(`--${key}`, ...(flags[key] === true ? [] : [flags[key]]));
      if (!flags['api-url'] && !flags['preflight-only'] && !flags.rollback) refuse('PAIR_API_URL_REQUIRED');
      const result = (dependencies.runner ?? spawnSync)(process.execPath, [join(packageRoot, 'observa-pair-legacy.mjs'), ...pairArgs], { env: provider.pairEnv(), stdio: 'inherit' });
      return { code: result.status === 0 ? 0 : 1, stdout: result.status === 0 ? '' : 'Pairing did not complete. No success is claimed.' };
    }
    if (['hosted-health', 'identify'].includes(command)) {
      const report = await provider.hosted(command);
      const key = command === 'identify' ? 'identify' : 'hosted_health';
      const good = command === 'identify' ? ['ROSTER_CONFIRMED', 'NOT_PAIRED'].includes(report.hosted.state) && report.local.state === 'IDENTIFIED' : report.healthy;
      return { code: good ? 0 : 2, stdout: json ? JSON.stringify(envelope({ [key]: report })) : command === 'identify' ? renderIdentify(report) : renderHostedHealth(report, now) };
    }
    const view = provider.snapshot();
    let data; let human; let legacyResult;
    if (command === 'status') { data = { status: view.status }; human = renderStatus(view.status, now); }
    else if (command === 'agents') { data = { agents: view.agents, evidence: view.evidence }; human = view.agents.length ? renderAgents(view.agents, now) : 'No configured agents or local agent evidence available.'; }
    else if (command === 'agent') {
      const id = agentId(args[0]); const agent = view.agents.find(a => a.agent_id === id);
      if (!agent) refuse('AGENT_NOT_FOUND');
      data = { agent, activity: view.activity.filter(a => a.agent_id === id).slice(0, limit), decisions: view.decisions.filter(d => d.agent_id === id).slice(0, limit), evidence: view.evidence };
      human = `${renderAgents([agent], now)}\n\n${renderActivity(data.activity)}\n\n${renderDecisions(data.decisions)}`;
    } else if (['activity', 'decisions'].includes(command)) {
      data = { [command]: view[command].slice(0, limit), limit, evidence: view.evidence };
      human = command === 'activity' ? renderActivity(data.activity) : renderDecisions(data.decisions);
    } else {
      const result = await provider.control(command, args, flags);
      // Preserve the established alias result schema from the source-owned
      // operator. Its fields are validated by the existing lifecycle contracts.
      legacyResult = result;
      // Lifecycle implementations can return path/recovery internals; project
      // only explicitly non-secret outcomes. No arbitrary result serialization.
      data = { result: { completed: true, config_updated: result.configUpdated === true, gateway_reload_may_be_required: result.gatewayReloadMayBeRequired === true, receipts_preserved: result.receiptsPreserved === true, observation_control: ['enable', 'disable', 'killswitch', 'lock'].includes(command) ? (command === 'enable' ? 'OFF' : command === 'disable' ? 'ON' : args[0].toUpperCase()) : null, ...(command === 'uninstall' ? { cli_entrypoint_removed: result.cliEntrypointRemoved === true } : {}) } };
      human = `${command === 'credential' ? `Credential ${args[0]}` : command} completed.${result.configUpdated ? ' Host config updated; a gateway reload may be needed.' : ''}${command === 'uninstall' ? (result.cliEntrypointRemoved ? ' The observa command this plugin created was removed.' : ' No observa command owned by this plugin was removed; any other observa command was left unchanged.') : ''} SHADOW ONLY / AUTHORITY NONE / ENFORCEMENT OFF / ACTIVE OFF`;
    }
    if (view.evidence?.problems.length && ['status', 'agents', 'agent', 'activity', 'decisions'].includes(command)) human += `\nLocal evidence warning: ${view.evidence.problems.join(', ')}.`;
    if (['agents', 'agent', 'activity', 'decisions'].includes(command)) human += `\n\n${UPGRADE}`;
    // Legacy status keeps its existing top-level fields, now sourced from the
    // profile. New structured views always use the versioned common envelope.
    return { code: 0, stdout: json ? JSON.stringify(legacy ? (command === 'status' ? view.status : legacyResult ?? envelope(data)) : envelope(data)) : human };
  } catch (error) {
    // Never echo argv, raw parse errors, filesystem paths, record bodies,
    // environment values or untrusted exception messages/codes.
    const safeCodes = new Set([...Object.keys(ERRORS), 'PROFILE_INVALID', 'STATE_PATH_INVALID', 'PLUGIN_CONFIG_INVALID', 'LOCAL_FILE_TOO_LARGE', 'LOCAL_FILE_CHANGED', 'ROSTER_TOO_LARGE', 'ROSTER_INVALID', 'ROSTER_LABEL_UNSAFE', 'PAIR_CUSTOM_STATE_UNSUPPORTED', 'PAIR_API_URL_REQUIRED', 'OPTION_REQUIRED', 'UNPAIR_INCOMPLETE', 'UNINSTALL_FAILED', 'UNINSTALL_CONFIRMATION_REQUIRED']);
    const code = safeCodes.has(error?.code) ? error.code : 'LOCAL_OPERATION_FAILED';
    const message = ERRORS[code] ?? 'Operation could not complete safely. Check the selected profile and command help; lifecycle recovery state is retained.';
    return { code: 1, stderr: json ? JSON.stringify({ schema: 'observa-cli/v1', ok: false, code, message }) : `${code}: ${message}` };
  }
}
export async function main(argv = process.argv.slice(2), options = {}) {
  const result = await runObserva(argv, options);
  if (result.stdout) process.stdout.write(`${result.stdout}\n`);
  if (result.stderr) process.stderr.write(`${result.stderr}\n`);
  process.exitCode = result.code;
}
