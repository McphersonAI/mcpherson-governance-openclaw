import { homedir } from 'node:os';
import { join } from 'node:path';
import { readJson, refuse } from './safe-local.mjs';
import { resolveProfile } from './providers/openclaw.mjs';
import publishedBinding from './trusted-hosted.json' with { type: 'json' };

export function validateAccessOrigin(value) {
  let url;
  try { url = new URL(value); } catch { refuse('ACCESS_URL_REQUIRED'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') refuse('ACCESS_URL_REQUIRED');
  return url.origin;
}

// No discovery redirects or environment-supplied hosts. An owner-controlled
// profile binding, a previous explicit request, or configured Hosted origin
// supplies the authority; a receipt's credential never crosses origin changes.
export function resolveAccessOrigin({ flags = {}, env = process.env, home = homedir(), receipt = null, includeReceipt = true }) {
  const { root } = resolveProfile(flags, env, home);
  if (flags['api-url']) return validateAccessOrigin(flags['api-url']);
  if (!receipt && includeReceipt) receipt = readJson(root, join(root, 'observa-access', 'request.json'), { maxBytes: 8192 });
  if (receipt?.endpoint) return validateAccessOrigin(receipt.endpoint);
  const saved = readJson(root, join(root, 'observa-access', 'binding.json'), { maxBytes: 2048 });
  if (saved) {
    if (saved.schema !== 'observa-access-binding/v1' || Object.keys(saved).sort().join(',') !== 'origin,schema') refuse('ACCESS_BINDING_INVALID');
    return validateAccessOrigin(saved.origin);
  }
  const host = readJson(root, join(root, 'openclaw.json'), { maxBytes: 1024 * 1024, privateFile: false });
  const origin = host?.plugins?.entries?.['mcpherson-governance-connector']?.config?.apiUrl;
  if (origin) return validateAccessOrigin(origin);
  return validateAccessOrigin(publishedBinding.origin);
}
