# Lineage Implementation

## Overview

The Harpocrates lineage feature enables representing cropped, transcoded, blurred, redacted, or composed media as verifiable derivatives of registered evidence.

## Supported Operations

- **crop**: Extract a specific region from the original media
- **transcode**: Convert media to a different format or codec
- **blur**: Apply blur transformation to obscure portions
- **redact**: Redact sensitive information from media
- **compose**: Combine multiple media sources into one derivative

## Architecture

### Frontend (`frontend/src/lineageManifest.ts`)

The frontend defines the `TransformationManifest` type which captures:
- `protocol`: Always "harpocrates"
- `version`: Manifest version (currently 2)
- `parentProofIds`: Array of parent proof IDs (up to 4)
- `operationType`: Type of transformation applied
- `parametersDigest`: SHA-256 digest of transformation parameters
- `toolIdentity`: Identity of the tool that performed transformation
- `toolVersion`: Version of the transformation tool
- `outputDigest`: SHA-256 digest of the resulting derivative
- `network`: Network identifier (e.g., "testnet")
- `actorAddress`: Stellar address of the actor performing the transformation

### Backend (`backend/lineage.py`)

The backend provides:
- **Manifest normalization**: `canonical_lineage_manifest()` - produces deterministic JSON serialization
- **Manifest digesting**: `lineage_manifest_digest()` - computes SHA-256 hash of canonical manifest
- **Graph validation**: `validate_lineage_graph()` - enforces constraints:
  - Depth limit: Maximum 4 levels deep
  - Fan-out limit: Maximum 4 parents per derivative
  - Cycle detection: Prevents self-referential and transitive cycles
  - Actor validation: Requires non-empty actor address

See [`contracts/LINEAGE.md`](contracts/LINEAGE.md) for the on-chain enforcement
of the same bounds: the registry bounds both directions of the edge, derives the
depth from the parents instead of trusting the caller, and rejects empty,
repeated, and unknown parents as well as re-registrations of an existing output
digest.

### Backend API Endpoints

#### Register Lineage
```
POST /api/proofs/lineage
Content-Type: application/json

{
  "parentProofIds": ["hash1", "hash2"],
  "operationType": "crop",
  "parametersDigest": "...",
  "toolIdentity": "harpocrates-studio",
  "toolVersion": "1.2.3",
  "outputDigest": "...",
  "network": "testnet",
  "actorAddress": "GABC123"
}

Response: 201 Created
{
  "ok": true,
  "manifestDigest": "...",
  "db_event": {...}
}
```

#### List Lineage Events
```
GET /api/proofs/lineage?limit=25
Response: 200 OK
{
  "ok": true,
  "events": [...]
}
```

#### Query Lineage by Actor
```
GET /api/lineage/by-actor/<actor_address>?limit=25
Response: 200 OK
{
  "ok": true,
  "events": [...]
}
```

### Database Schema

#### lineage_events table
```sql
CREATE TABLE lineage_events (
  id BIGSERIAL PRIMARY KEY,
  manifest_digest TEXT NOT NULL UNIQUE,
  manifest JSONB NOT NULL,
  actor_address TEXT NOT NULL,
  parent_proof_ids TEXT[] NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX lineage_events_actor_idx ON lineage_events (actor_address);
```

### Soroban Contract (`contracts/contracts/harpocrates-registry/src/lib.rs`)

The contract provides:
- `register_lineage()` - Records a lineage transformation on-chain
- `get_lineage()` - Retrieves a stored lineage record
- `get_lineage_child_count()` - Derivatives already charged against a parent
- Bounds the fan-out in both directions, derives the depth from the parents
  (rejecting a claim that disagrees with the graph), and refuses an empty,
  repeated, or unknown parent and a re-registration of an existing output digest
- Keeps `MAX_LINEAGE_FANOUT` parent digests inside `MAX_LINEAGE_PAYLOAD_BYTES`
  with a compile-time assertion; the manifest body bound belongs to the backend

## Validation Rules

### Constraints Enforced
1. **Duplicate Prevention**: Identical output digest submissions fail with 409 Conflict
2. **Cycle Detection**: 
   - Direct cycles (output digest appears in parents) are rejected
   - Transitive cycles (output would create circular dependency) are rejected
3. **Bounded Depth**: Maximum 4 levels of transformation chain; the registry
   derives the depth from the parents and rejects a caller-supplied `depth` that
   disagrees with the graph (`LineageDepthMismatch`), so the cap cannot be
   bypassed by asserting a smaller number
4. **Bounded Fan-out**: Maximum 4 parent proofs per derivative
   (`LineageFanOutExceeded`) and maximum 4 derivatives per parent
   (`LineageFanOutSaturated`)
5. **Payload Size**: Maximum 4KB for manifest
6. **Actor Requirement**: Every transformation must have an authorized actor address
7. **Hex Validation**: All IDs must be valid 32-byte hex strings

### Success Criteria
- Lineage records survive database re-indexing from contract events
- Concurrent submissions are handled idempotently
- Partial backend failures don't corrupt lineage state
- Privacy boundaries are maintained (no exposure of private evidence)

## Testing

### Backend Tests (`backend/test_lineage.py`)
- Canonical manifest serialization (deterministic)
- Unsupported operation rejection
- Excessive fan-out rejection
- Direct cycle detection
- Missing actor validation
- Valid graph acceptance

### Contract Tests (`contracts/contracts/harpocrates-registry/src/test_lineage.rs`)
- Parent set at the fan-out cap accepted; above the cap rejected
- Empty, repeated, and unknown parents rejected
- Self-referential edge rejected
- Depth derived from the deepest parent
- Understated and overstated depth rejected
- Deepest legal chain accepted; one level deeper rejected
- Per-parent derivative cap enforced, and a saturated parent refuses an edge
  without charging an available parent named alongside it
- A rejected edge leaves the parent's budget untouched
- Re-registration of an existing output digest rejected, original record intact
- A derivative is itself a valid parent

### Frontend Tests (`frontend/src/lineageManifest.test.ts`)
- Manifest creation with deterministic serialization
- Operation type validation
- Type safety

### App Tests (`backend/test_app.py`)
- All existing tests continue to pass
- Lineage endpoint validation

## Migration Considerations

- No breaking changes to existing proof or metadata schemas
- lineage_events table is additive and doesn't require existing data migration
- Existing lint, type checks, tests, and builds remain green

## Privacy and Security

- Lineage records are bound to actor addresses (immutable)
- Manifest hashes are deterministic and reproducible
- No transformation parameters or sensitive evidence details are exposed in lineage queries
- All operations are logged with correlation IDs for auditability

## Future Work

- Live production deployment testing
- Contract event indexing and re-indexing from Testnet
- Dashboard visualization of lineage chains
- Advanced query support (reverse lineage, transitive closure)

## Parent Commitments (#332)

Lineage registrations now persist a parallel `parent_commitments` vector on each
`LineageRecord`, derived on-chain as:

```
SHA-256("harp_lin_pc" || binding_a || binding_b)
```

- Proof parent: `(video_hash, metadata_hash)`
- Lineage parent: `(manifest_digest, output_digest)`

Public `LineageRegistered` events emit commitments (not raw parent proof ids).
`get_lineage_parent_commitments(output_digest)` exposes the same digests for
interop without expanding the trust boundary. Revoked or expired proof parents
are rejected with `LineageParentUnavailable`.

Migration: additive on new registrations; re-register any pre-upgrade lineage
rows that need commitments. Rollback to pre-#332 wasm simply stops writing the
new field/event.

