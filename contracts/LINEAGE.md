# Lineage Graph Bounds

**Version:** 1.0  
**Status:** Active  
**Scope:** `HarpocratesRegistry` (`contracts/contracts/harpocrates-registry`)

A lineage record is an edge from registered evidence — or from another
derivative — to a new derivative, stating that the derivative was produced from
those parents by a named operation. Lineage makes derived media (cropped,
transcoded, blurred, redacted, composed) verifiable against the evidence it came
from without ever revealing that evidence.

This document covers the bounds on that graph. The manifest format, the
canonical serialisation, and the digesting rules live in the backend and the
frontend; see [`../LINEAGE_IMPLEMENTATION.md`](../LINEAGE_IMPLEMENTATION.md).

---

## 1. Graph Bounds

A lineage graph is only as safe as its degree and depth limits. Both directions
of every edge are bounded, so one registered artefact can never be amplified
into an unbounded family:

| Constant | Value | Meaning |
| --- | --- | --- |
| `MAX_LINEAGE_FANOUT` | `4` | Parents a single derivative may name (in-degree), and derivatives a single parent may be charged for (out-degree). |
| `MAX_LINEAGE_DEPTH` | `4` | Maximum distance from the evidence a derivative may sit at. |
| `MAX_LINEAGE_PAYLOAD_BYTES` | `4096` | Budget for the encoded lineage payload a registered edge stands for. |

The registry only ever receives 32-byte digests, so the payload bound it can
check is the parent set. A compile-time assertion in `lib.rs` keeps the two
bounds consistent:

```rust
const _: () = assert!(
    (MAX_LINEAGE_FANOUT as usize) * 32 <= MAX_LINEAGE_PAYLOAD_BYTES as usize,
    "MAX_LINEAGE_FANOUT parent digests must fit inside MAX_LINEAGE_PAYLOAD_BYTES"
);
```

Raising `MAX_LINEAGE_FANOUT` past what `MAX_LINEAGE_PAYLOAD_BYTES` covers
therefore fails the build rather than shipping an unbounded registry. The
manifest body bound is enforced by the backend that owns the manifest.

---

## 2. Public Interface

```text
register_lineage(actor, parent_proof_ids, manifest_digest, operation_type, output_digest, depth) -> LineageRecord

get_lineage(output_digest) -> Option<LineageRecord>
get_lineage_child_count(parent) -> u32
```

`register_lineage` requires the actor's signature and returns the stored record.
The record is immutable: `get_lineage` is the only way to read it back, and there
is no update or delete entry point.

---

## 3. Depth Is Derived, Never Trusted

`depth` is the depth the caller *believes* the derivative sits at. The registry
derives the real depth from the parents and rejects a claim that disagrees:

```text
depth(proof)         = 0
depth(derivative)    = 1 + max(depth(parent) for each parent)

reject if claimed_depth != derived_depth   -> LineageDepthMismatch
reject if derived_depth > MAX_LINEAGE_DEPTH -> LineageTooDeep
```

Because the stored record always carries the derived depth, a caller cannot
claim a shallow position to slip a deeper derivative past the cap, and a reader
can trust `LineageRecord.depth` without re-walking the graph.

---

## 4. Failure Modes

Every rejection is a stable `RegistryError` code; no partial state is written.

| Condition | Error | Code |
| --- | --- | --- |
| Parent set is empty | `InvalidLineage` | 57 |
| A parent is repeated in the same set | `InvalidLineage` | 57 |
| A parent is neither a registered proof nor a lineage record | `InvalidLineage` | 57 |
| A parent is the output digest itself | `LineageCycle` | 58 |
| Derived depth exceeds `MAX_LINEAGE_DEPTH` | `LineageTooDeep` | 59 |
| Parent set exceeds `MAX_LINEAGE_FANOUT` | `LineageFanOutExceeded` | 60 |
| A parent already has `MAX_LINEAGE_FANOUT` derivatives | `LineageFanOutSaturated` | 79 |
| Claimed depth differs from the derived depth | `LineageDepthMismatch` | 80 |
| The output digest already has a lineage record | `DuplicateLineage` | 78 |
| The parent set is empty | `LineageEmptyParents` | 76 |
| A parent proof is revoked or expired | `LineageParentUnavailable` | 77 |

Failed calls emit no event and leave no storage change; in particular a rejected
edge never charges a parent's fan-out budget. Budgets are read for every parent
before any is written, so an edge that names one available parent and one
saturated parent is refused without consuming the available parent's budget.

`LineageFanOutExceeded` (in-degree) and `LineageFanOutSaturated` (out-degree) are
deliberately distinct: the first is a malformed request, the second says the
graph has reached its capacity around that parent.

---

## 5. Storage, Migration, And Rollback

Additive persistent storage:

```text
Lineage(output_digest)           -> LineageRecord   (existing key, unchanged shape)
LineageChildCount(parent_digest) -> u32             (new key)
```

`LineageRecord` keeps its existing fields and shape, so evidence recorded by an
earlier deployment still reads back with the depth it was stored with. Deployments
that predate the out-degree cap have no `LineageChildCount` entries, which reads
as "no derivatives charged yet": the counters warm up as new derivatives are
recorded and the cap is enforced from the first read onward. There is no
migration step and no change to any other exported function signature.

Rollback to a wasm without these bounds drops `LineageChildCount` from use; the
entries become inert and are ignored by the older code, which also stops
enforcing the out-degree cap and the duplicate-output guard. Because the stored
`LineageRecord` shape is unchanged, a rollback loses no evidence.

---

## 6. Threat Notes

* **Amplification.** A single registered artefact can be named by at most
  `MAX_LINEAGE_FANOUT` derivatives, and a derivative can name at most
  `MAX_LINEAGE_FANOUT` parents, so neither degree grows without bound.
* **Depth forgery.** `MAX_LINEAGE_DEPTH` is enforced against the graph, not
  against the caller's word, so a long chain cannot be hidden behind a small
  claimed depth.
* **Budget laundering.** Re-registering an existing output digest is refused, so
  a replay cannot burn a parent's budget without producing a derivative, and a
  replayed edge cannot silently rewrite another actor's recorded derivation.
* **Duplicate edges.** A repeated parent is refused rather than counted twice, so
  the in-degree cap always measures distinct edges.
* **Dangling edges.** A parent must already be a registered proof or a lineage
  record, so an edge can never point at evidence that does not exist.
* **Privacy.** Only 32-byte digests, a `Symbol` operation tag, an `Address`, and
  that address's signature are involved. Lineage never carries transformation
  parameters, evidence bodies, media, or witness values, and no failure path
  logs or returns any of them.
* **Authorization.** `register_lineage` requires the actor's authentication; the
  actor is stored on the record, so a derivative is always attributable. The
  registry keeps no admin-only lineage entry point, so an operator cannot
  silently rewrite a lineage edge.

---

## 7. Tests

`contracts/contracts/harpocrates-registry/src/test_lineage.rs` covers positive,
negative, boundary, and regression cases:

* a bounded registration round-trips through `get_lineage` and charges its parent;
* a parent set exactly at `MAX_LINEAGE_FANOUT` is accepted and charges each
  distinct parent once;
* depth is derived from the deepest parent;
* a parent set above the cap is refused;
* an empty parent set, a repeated parent, and an unknown parent are refused;
* a self-referential edge is refused;
* a derivative past `MAX_LINEAGE_DEPTH` is refused, and the deepest legal chain
  is accepted;
* an understated and an overstated depth are both refused;
* a parent is charged at most `MAX_LINEAGE_FANOUT` times, and the next derivative
  is refused;
* a saturated parent refuses an edge without charging the available parent named
  alongside it;
* a rejected edge — repeated parent or forged depth — leaves the parent's budget
  intact;
* re-registering an existing output digest is refused and the original record is
  unchanged;
* a derivative is itself a valid parent.

The module is wired into the crate with `mod test_lineage;` in `lib.rs`, so
`cargo test --workspace` runs it.
