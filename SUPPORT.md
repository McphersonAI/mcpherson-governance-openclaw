# Support

**Version: 0.5.0 — initial public release.**

## Where to get help

Support is provided through **GitHub Issues**:

https://github.com/McphersonAI/mcpherson-governance-openclaw/issues

Best-effort, no SLA, no guaranteed response time. This is an early release from
a small team.

- Repository: https://github.com/McphersonAI/mcpherson-governance-openclaw
- Website: https://mcphersonai.com

## Before asking for help

Most issues resolve faster with this information gathered first:

1. **Connector status** — run `connector-ctl status`. It reports mode, enabled
   state, disable/kill-switch/lock state, and receipt counts.
2. **Versions** — connector version (`0.5.0`), your OpenClaw version, Node
   version, and platform.
3. **Verification** — confirm your install is intact using
   [VERIFY.md](VERIFY.md). A modified connector file is worth knowing about
   before anything else.
4. **Receipts** — receipt counts and the `remote_status` values you are seeing.

**Do not attach raw receipts, credentials, tokens, configuration containing real
identifiers, or customer data to a support request.** Redact identifiers first.

## Common situations that are not bugs

| What you see | Why |
| --- | --- |
| Tools run normally despite `DENY` in receipts | Shadow-only. Remote decisions have no execution authority. |
| Many `404` observations | Unmapped tools. Mapping is manual. They do not block execution. |
| Attempt receipts without completion receipts | `POST_HOOK` truth bound — the connector does not guess outcomes. |
| Observations missing under load | In-flight/queue bounds drop excess by design. Not a complete audit log. |
| Nothing sent to the endpoint | Check `enabled`, kill switch, system lock, and disable state. |

See [LIMITATIONS.md](LIMITATIONS.md) for the full list.

## Security reports

Do **not** use a public support channel for security issues. Email
**admin@mcphersonai.com** privately — see [SECURITY.md](SECURITY.md).

## Scope

Support covers this connector package only. It does not cover OpenClaw itself,
your agent configuration, or the operation of whatever governance endpoint you
configure.
