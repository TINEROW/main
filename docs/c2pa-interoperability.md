# C2PA Interoperability

Harpocrates can import and export C2PA-compatible authenticity manifests.
This document describes the trust model, the canonical field mapping,
the compatibility matrix, and how to roll back.

---

## Trust model

**A C2PA claim is not a Harpocrates proof.**

The two systems have different trust anchors:

| Property | Harpocrates | C2PA |
|---|---|---|
| Integrity root | Soroban on-chain record + ZK circuit | C2PA claim generator + signing key |
| Privacy | ZK nullifier; Silent Witness tier is anonymous | Not a design goal; identity is in the claim |
| Determinism | SHA-256 canonical metadata hash, on-chain binding | Claim-generator defined |
| Verification | On-chain `get_by_video` + Noir proof | C2PA SDK signature verification |

The C2PA layer in Harpocrates is a **bounded bridge**, not a trust equivalence.
Callers must corroborate the extracted binding against on-chain records using
the standard Harpocrates verification flow before making any trust decision.

### C2paTrustStatus

All API responses and parsed manifests carry an explicit `trust_status` field.
Its values are defined to be free of on-chain terminology:

| Value | Meaning |
|---|---|
| `signature_not_checked` | Default for all imports; no crypto verification performed |
| `signature_valid` | Internal digest binding is self-consistent (no crypto) |
| `unsupported_algorithm` | Manifest references an algorithm not supported by this version |
| `binding_mismatch` | Extracted digests do not match the claimed hashes |
| `parse_failed` | Manifest could not be parsed; no trust can be assigned |

`signature_not_checked` is the only value produced by the current
implementation. The others are reserved for future signing integration.

Callers **must not** treat any C2paTrustStatus as equivalent to the
Harpocrates `confirmed` verification outcome.

---

## Field mapping — version 1

`C2PA_HARPOCRATES_MAPPING_VERSION = 1`

The mapping pins the canonical field names between Harpocrates evidence/proof
digests and C2PA assertion/claim fields.

| Harpocrates field | C2PA assertion data field | Notes |
|---|---|---|
| `videoHash` (embedded, on-chain) | `video_hash` | 32-byte hex, lowercase |
| `metadataHash` | `metadata_hash` | 32-byte hex, lowercase |
| `proofId` | `proof_id` | 32-byte hex, lowercase |
| `tier` | `tier` | `silent` \| `source` \| `seal` |
| `network` | `network` | Stellar network passphrase |
| `contractId` | `contract_id` | Soroban registry contract ID |

The binding is embedded twice: as a named assertion (`harpocrates.binding/v1`)
and as a top-level `harpocrates_binding` object, for both assertion-based and
direct consumers.

### Canonical JSON encoding

The manifest is always serialised with sorted keys and no trailing whitespace.
This makes the export idempotent: identical inputs produce byte-identical JSON
and an identical SHA-256 digest.

### Versioning

A mapping version bump (e.g., to version 2) requires:

1. A new `mapping_version` constant in `backend/c2pa.py` and `frontend/src/c2pa.ts`.
2. A new entry in this table.
3. Updated conformance fixtures in `backend/test_c2pa.py` and `frontend/src/c2pa.test.ts`.
4. A migration note in `MIGRATION_GUIDE.md`.
5. A re-run of all C2PA tests.

The parser rejects manifests whose `mapping_version` differs from the current
constant. This prevents silent drift between import and export.

---

## API reference

### `POST /api/c2pa/export`

Export a C2PA-compatible manifest from Harpocrates evidence digests.

**Request body (JSON):**

```json
{
  "video_hash":     "32-byte hex — embedded video hash",
  "metadata_hash":  "32-byte hex",
  "proof_id":       "32-byte hex",
  "tier":           "silent | source | seal",
  "network":        "Stellar network passphrase",
  "contract_id":    "Soroban registry contract ID",
  "claim_generator": "optional override"
}
```

**Response body (JSON):**

```json
{
  "ok": true,
  "manifest":      { /* C2PA-compatible manifest */ },
  "digest":        "sha256 of canonical JSON",
  "trust_status":  "signature_not_checked",
  "note":          "C2PA trust status is independent of Harpocrates on-chain and ZK verification.",
  "request_id":    "uuid"
}
```

### `POST /api/c2pa/import`

Parse and validate a C2PA-compatible manifest.

**Request body (JSON):**

```json
{
  "manifest": { /* manifest object */ }
}
```

Or with a raw JSON string:

```json
{
  "manifest": "{\"claim_generator\":\"harpocrates\",...}"
}
```

**Response body (JSON):**

```json
{
  "ok": true,
  "binding": {
    "mapping_version": 1,
    "video_hash":     "...",
    "metadata_hash":  "...",
    "proof_id":       "...",
    "tier":           "silent | source | seal",
    "network":        "...",
    "contract_id":    "..."
  },
  "trust_status":        "signature_not_checked",
  "unknown_assertions":  [{ "label": "c2pa.actions", "unsupported_semantics": true }],
  "note":                "Corroborate this binding against on-chain records before trusting it.",
  "request_id":          "uuid"
}
```

**Error response (400):**

```json
{
  "ok": false,
  "error": {
    "code":       "VALIDATION_ERROR",
    "message":    "C2PA manifest parse failed: invalid_value (field: harpocrates_binding.tier)",
    "request_id": "uuid"
  }
}
```

Error messages include only the reason code and optional field name. No
manifest content, digest bytes, or proof material appear in error responses.

---

## Frontend API

```ts
import {
  exportC2paManifest,
  exportC2paManifestFromProof,
  parseC2paManifest,
  verifyRoundTrip,
  C2paParseError,
  C2PA_HARPOCRATES_MAPPING_VERSION,
} from './c2pa'

// Export from raw fields
const exported = exportC2paManifest({
  videoHash, metadataHash, proofId, tier, network, contractId,
})

// Export from an existing ProofManifest
const exported = exportC2paManifestFromProof(proofManifest)

// Import / parse
try {
  const parsed = parseC2paManifest(rawJsonString)
  // parsed.binding.videoHash, .tier, etc.
  // parsed.trustStatus === 'signature_not_checked'
  // parsed.unknownAssertions — safe to display; never act on
} catch (e) {
  if (e instanceof C2paParseError) {
    const { reason, field } = e.toPayload() // only these two fields
  }
}

// Round-trip check
const ok = verifyRoundTrip(exported)
```

---

## Compatibility matrix

| Harpocrates version | C2PA spec target | Mapping version | SHA-256 only |
|---|---|---|---|
| current | 1.3 | 1 | yes |

Only SHA-256 is supported as a hash algorithm. Manifests that declare any
other algorithm (`md5`, `sha512`, etc.) are rejected with `unsupported_algorithm`.

---

## Parser limits

| Limit | Value |
|---|---|
| Maximum manifest size | 256 KiB |
| Maximum assertion count | 64 |
| Maximum assertion label length | 256 chars |
| Maximum assertion data size | 32 KiB |
| Maximum JSON nesting depth | 16 |

These limits are applied in order before any semantic validation, so malformed
or adversarial manifests are rejected early without deep parsing.

---

## Unknown assertions

Assertions whose label is not `harpocrates.binding/v1` are preserved in the
`unknown_assertions` (backend) / `unknownAssertions` (frontend) list with an
explicit `unsupported_semantics: true` flag. They do not affect the parsed
binding and should not be acted upon by callers.

This allows consuming existing C2PA manifests that carry standard C2PA
assertions (e.g., `c2pa.actions`, `c2pa.thumbnail`) without rejecting them.

---

## Rollback

The C2PA feature is additive. No existing endpoints, database schema, contract
storage, Noir circuit, or proof format is modified.

To roll back:

1. Remove or disable the `POST /api/c2pa/export` and `POST /api/c2pa/import`
   routes from `backend/app.py`.
2. Remove or stop importing `frontend/src/c2pa.ts`.
3. No database migration or state repair is required.
4. No on-chain state is affected.

Existing proof events, on-chain records, and ZK artifacts are unchanged.

---

## Running the tests

```bash
# Backend
cd backend && python -m pytest test_c2pa.py -v

# Frontend
cd frontend && npx vitest run src/c2pa.test.ts
```

Both test suites cover valid fixtures, adversarial/malformed inputs, round-trip
preservation, trust status isolation, compatibility matrix assertions, and
bounded fuzzing.
