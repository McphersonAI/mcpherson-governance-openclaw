// Version-specific metadata decoding. Return is not business verification.
function fields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const d = Object.getOwnPropertyDescriptors(value);
  return Object.values(d).some(v => !('value' in v)) ? null : d;
}
export function nativeToolOutcome(event) {
  try {
    const d = fields(event); if (!d) return 'UNKNOWN';
    const error = d.error?.value;
    if (error !== undefined && error !== null && error !== '') {
      if (typeof error !== 'string') return 'UNKNOWN';
      return /^(TIMEOUT|TIMED_OUT)$/.test(error.trim().toUpperCase()) ? 'TIMED_OUT' : 'FAILED';
    }
    const result = fields(d.result?.value); if (!result) return 'UNKNOWN';
    const details = result.details?.value === undefined ? {} : fields(result.details.value);
    if (!details) return 'UNKNOWN';
    if (details.timedOut?.value === true || details.noOutputTimedOut?.value === true) return 'TIMED_OUT';
    if (result.isError?.value === true) return 'FAILED';
    const status = details.status?.value ?? result.status?.value;
    if (['timeout', 'timed_out'].includes(status)) return 'TIMED_OUT';
    if (['error', 'failed', 'denied', 'blocked'].includes(status)) return 'FAILED';
    if (status !== undefined && status !== 'completed') return 'UNKNOWN';
    const exit = details.exitCode?.value;
    if (exit !== undefined && exit !== null) {
      if (!Number.isSafeInteger(exit)) return 'UNKNOWN';
      if (exit !== 0) return 'FAILED';
    }
    // Exec completion requires its documented exit status. Background process
    // handles, queued calls, cancellation and unfamiliar result shapes stay unknown.
    if (['exec', 'openclawexec', 'process'].includes(d.toolName?.value)) {
      return status === 'completed' && exit === 0 ? 'COMPLETED' : 'UNKNOWN';
    }
    // The documented AgentToolResult shape confirms a returned tool result.
    // We do not inspect or persist its content, and never infer business success.
    return Array.isArray(result.content?.value) ? 'COMPLETED' : 'UNKNOWN';
  } catch { return 'UNKNOWN'; }
}
