# Dependency review — 2026-10-30

The connector declares zero npm runtime dependencies. Its frozen JavaScript
closure is inventoried separately; the target OpenClaw peer is exact 2026.10.9.
The current installed official host was audited with `npm audit --omit=dev --json`.
This was read-only. Raw results are retained in the isolated lab's
`evidence/candidate5/upstream-runtime-audit.json`.

The audit reports six affected package entries: brace-expansion (high),
ip-address (moderate), postcss-selector-parser (moderate), undici (high), zod
(high), and the OpenClaw parent aggregate (high). These are package counts, not
six unique CVEs. The first three are inside OpenClaw's installed npm package.
The host pins undici 8.11.2 and zod 4.6.5; its npm also contains undici 6.x.
Node 24.22.1's own bundled undici is 7.30.1.

Primary advisory references:

- [undici TLS callback loss](https://github.com/nodejs/undici/security/advisories/GHSA-2m5v-pch6-74hx): applications using function-valued `tls` options are affected. Fix versions include 7.30.1 and 8.12.2.
- [undici excessive response content codings](https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c): a hostile server can terminate an affected fetch process. Fix versions include 7.30.1 and 8.12.2.
- [Zod constrained collection exhaustion](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5): installed 4.6.5 is within the affected range; patched version is 4.6.6.

The connector's pairing and evidence clients use Node HTTPS with certificate
verification; access uses the standalone CLI's built-in fetch, bounded reads,
fixed origin and refused redirects. It imports neither the external undici nor
zod packages. The isolated qualification used loopback services and synthetic
inputs. These facts narrow the connector paths tested; they do not prove
unreachability in OpenClaw's other features or arbitrary deployments. The host
can install a global undici dispatcher in its gateway process.

Disposition: retained upstream dependency risk, separate from connector feature
compatibility. No clean-audit, host-security, universal-compatibility or production
enforcement claim is made. No host dependency override or npm's proposed old
OpenClaw downgrade was applied. Production environments must assess and remediate
the host advisories; separate Control Gate C remains mandatory for enforcement.
