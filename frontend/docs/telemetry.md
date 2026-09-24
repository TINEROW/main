# Frontend telemetry scrubbing

## Trust boundary

Browser telemetry (console sinks, future analytics hooks) is a **public boundary**.
Evidence Studio, the verification portal, proof workers, and wallet flows may hold
seeds, witnesses, media bytes, and signatures in memory — those values must never
cross into telemetry payloads.

## Behavior

`scrubTelemetryFields` / `emitScrubbedTelemetry` (`src/telemetry/`) redact by:

- Sensitive **key** categories aligned with `backend/analytics/redaction.py`
  (secret, witness, media, proof, wallet_sig, wallet_id, pii)
- Long hex/base64 **value** blobs
- Binary `ArrayBuffer` / typed-array payloads
- Depth and node caps for malformed or hostile nested objects

Stable markers look like `[REDACTED:secret]`. Version tag:
`harpocrates-frontend-telemetry-v1`.

## Failure modes

| Input | Result |
| --- | --- |
| Malformed / unserializable | `[REDACTED:malformed]` or `[REDACTED:unserializable]` |
| Oversized string | Truncated with `…[truncated]` |
| Too deep / too many nodes | Stop with `stopReason` `max_depth` / `max_nodes` |

## Compatibility & rollback

- Additive module; no stored evidence or protocol artifact format changes.
- ErrorBoundary now logs through `emitScrubbedTelemetry` — rollback by restoring
  the previous `console.error` call.
- Compatible with backend redaction category names for cross-layer reviews.

## Threat model notes

Assumes a compromised or verbose console consumer. Does **not** protect against
an attacker with full JS heap access. Session replay and third-party analytics
SDKs remain out of scope unless they call this scrubber.
