"""
C2PA interoperability layer for Harpocrates.

This module provides:
- Bounded parsing and validation of C2PA-compatible manifests (JSON envelope).
- Export of a C2PA-compatible manifest that binds Harpocrates evidence digests.
- An explicit, separate trust status enum so C2PA trust is never conflated with
  on-chain or ZK verification status.

Design constraints
------------------
- A C2PA claim is NOT equivalent to a Harpocrates proof.  The ``C2paTrustStatus``
  enum makes that separation mandatory and machine-readable.
- The parser enforces strict size, depth, algorithm, and resource limits before
  touching any assertion content.
- Unknown assertions are preserved verbatim in ``unknown_assertions`` with an
  explicit ``unsupported_semantics`` flag; they do not affect the parsed binding.
- All errors return typed ``C2paParseError`` instances; no raw exceptions escape
  this module's public surface.
- Observability: only the reject *reason code* and optional field *name* are
  logged/returned.  No claim bytes, assertion values, or digest material appear
  in error payloads.

Versioning
----------
``C2PA_HARPOCRATES_MAPPING_VERSION = 1`` pins the canonical field mapping from
Harpocrates evidence/proof digests to C2PA claim/assertion names.  A bump
requires a new mapping entry, migration documentation, and updated fixtures.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Version and constants
# ---------------------------------------------------------------------------

C2PA_HARPOCRATES_MAPPING_VERSION: int = 1
"""Increment when the canonical field mapping changes (not just additions)."""

_MAPPING_LABEL = "harpocrates.binding/v1"
"""C2PA assertion label used to embed the Harpocrates binding."""

_C2PA_MANIFEST_CLAIM_GENERATOR = "harpocrates"
_C2PA_SPEC_VERSION = "1.3"  # Version we target for compatibility labelling.

# Hard limits applied before any semantic parsing.
_MAX_MANIFEST_BYTES: int = 256 * 1024          # 256 KiB
_MAX_ASSERTION_COUNT: int = 64
_MAX_ASSERTION_LABEL_LEN: int = 256
_MAX_ASSERTION_DATA_BYTES: int = 32 * 1024     # 32 KiB per assertion
_MAX_JSON_DEPTH: int = 16

# Supported hash algorithms (lower-case names, SHA-256 only for now).
_SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256"})

# Required top-level manifest keys.
_REQUIRED_MANIFEST_KEYS: frozenset[str] = frozenset(
    {"claim_generator", "assertions", "harpocrates_binding"}
)

# Required keys inside harpocrates_binding.
_REQUIRED_BINDING_KEYS: frozenset[str] = frozenset(
    {
        "mapping_version",
        "video_hash",
        "metadata_hash",
        "proof_id",
        "tier",
        "network",
        "contract_id",
    }
)

# Allowed identity tiers (mirrors envelope.ALLOWED_TIERS).
_ALLOWED_TIERS: frozenset[str] = frozenset({"silent", "source", "seal"})

# Hex-32 pattern (64 lower-case hex chars).
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------------------
# Trust status — MUST be kept separate from on-chain / ZK status
# ---------------------------------------------------------------------------


class C2paTrustStatus(str, Enum):
    """
    Explicit trust verdict for a parsed C2PA manifest.

    This is a *C2PA-level* verdict only.  It is entirely independent of:
    - on-chain registration status (Soroban)
    - ZK proof verification status (Noir / UltraHonk)
    - NeonDB event presence

    Callers MUST NOT treat ``SIGNATURE_VALID`` as equivalent to
    ``confirmed`` in the Harpocrates verification flow.
    """

    SIGNATURE_VALID = "signature_valid"
    """The manifest's self-described digest binding is internally consistent.
    No cryptographic signature verification is performed (out of scope)."""

    SIGNATURE_NOT_CHECKED = "signature_not_checked"
    """Signature verification was not attempted (default for all imports)."""

    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    """The manifest references a hash algorithm not supported by this version."""

    BINDING_MISMATCH = "binding_mismatch"
    """The extracted binding digests do not match the claimed hashes."""

    PARSE_FAILED = "parse_failed"
    """The manifest could not be parsed; no trust can be assigned."""


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class C2paParseError(Exception):
    """Raised when manifest parsing fails.  Never leaks raw manifest bytes."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        self.reason = reason
        self.field = field
        super().__init__(reason if field is None else f"{reason}: {field}")

    def to_dict(self) -> dict[str, str | None]:
        """Privacy-safe error payload: only reason code and field name."""
        return {"reason": self.reason, "field": self.field}


# Reason codes — stable, machine-readable.
class _Reason:
    MANIFEST_TOO_LARGE = "manifest_too_large"
    NOT_JSON = "not_json"
    DEPTH_EXCEEDED = "depth_exceeded"
    NOT_OBJECT = "not_object"
    MISSING_KEY = "missing_key"
    INVALID_TYPE = "invalid_type"
    INVALID_VALUE = "invalid_value"
    ASSERTION_COUNT_EXCEEDED = "assertion_count_exceeded"
    ASSERTION_LABEL_TOO_LONG = "assertion_label_too_long"
    ASSERTION_DATA_TOO_LARGE = "assertion_data_too_large"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    DIGEST_MISMATCH = "digest_mismatch"
    MAPPING_VERSION_MISMATCH = "mapping_version_mismatch"
    RECURSION_DETECTED = "recursion_detected"


# ---------------------------------------------------------------------------
# Parsed / exported data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class C2paHarpocratesBinding:
    """
    The Harpocrates-specific fields extracted from or written into a C2PA manifest.

    These are the canonical bindings between Harpocrates evidence digests and
    C2PA claim assertions.  See ``C2PA_HARPOCRATES_MAPPING_VERSION``.
    """

    mapping_version: int
    video_hash: str          # 32-byte hex (embedded video hash registered on-chain)
    metadata_hash: str       # 32-byte hex
    proof_id: str            # 32-byte hex
    tier: str                # 'silent' | 'source' | 'seal'
    network: str             # Stellar network passphrase
    contract_id: str         # Soroban registry contract ID


@dataclass
class C2paUnknownAssertion:
    """An assertion whose label or content is not recognised by this version."""

    label: str
    data: Any
    unsupported_semantics: bool = True


@dataclass
class C2paParsedManifest:
    """
    Result of a successful ``parse_c2pa_manifest`` call.

    ``trust_status`` is always ``SIGNATURE_NOT_CHECKED`` on import (signature
    verification is out of scope for this module).  The caller must not
    promote this to an on-chain or ZK trust level without additional checks.
    """

    claim_generator: str
    spec_version: str | None
    binding: C2paHarpocratesBinding
    unknown_assertions: list[C2paUnknownAssertion] = field(default_factory=list)
    trust_status: C2paTrustStatus = C2paTrustStatus.SIGNATURE_NOT_CHECKED


@dataclass(frozen=True)
class C2paExportedManifest:
    """
    A serialisable C2PA-compatible manifest produced by ``export_c2pa_manifest``.

    The ``manifest`` field is the canonical JSON-serialisable dict.
    The ``digest`` field is the SHA-256 of the canonical JSON encoding, for
    round-trip integrity verification.
    """

    manifest: dict[str, Any]
    digest: str   # hex-encoded SHA-256 of canonical JSON


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_c2pa_manifest(raw: bytes | str) -> C2paParsedManifest:
    """
    Parse and validate a C2PA-compatible manifest.

    Applies strict size, depth, algorithm, and resource limits before any
    semantic processing.  Unknown assertions are preserved in
    ``C2paParsedManifest.unknown_assertions`` without affecting the binding.

    Args:
        raw: Raw manifest bytes or string (UTF-8 JSON).

    Returns:
        A ``C2paParsedManifest`` on success.

    Raises:
        C2paParseError: On any structural, size, or semantic violation.
            Error payloads contain only reason codes and field names; no
            manifest content is included.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8")

    # 1. Size limit.
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise C2paParseError(_Reason.MANIFEST_TOO_LARGE)

    # 2. JSON parse.
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise C2paParseError(_Reason.NOT_JSON)

    # 3. Depth limit (protects against deeply-nested bombs).
    _check_depth(data, limit=_MAX_JSON_DEPTH)

    # 4. Top-level must be an object.
    if not isinstance(data, dict):
        raise C2paParseError(_Reason.NOT_OBJECT)

    # 5. Required top-level keys.
    for key in _REQUIRED_MANIFEST_KEYS:
        if key not in data:
            raise C2paParseError(_Reason.MISSING_KEY, key)

    # 6. claim_generator.
    claim_generator = data["claim_generator"]
    if not isinstance(claim_generator, str) or not claim_generator.strip():
        raise C2paParseError(_Reason.INVALID_TYPE, "claim_generator")

    # 7. spec_version (optional).
    spec_version: str | None = None
    if "spec_version" in data:
        sv = data["spec_version"]
        if not isinstance(sv, str):
            raise C2paParseError(_Reason.INVALID_TYPE, "spec_version")
        spec_version = sv

    # 8. assertions list.
    assertions_raw = data["assertions"]
    if not isinstance(assertions_raw, list):
        raise C2paParseError(_Reason.INVALID_TYPE, "assertions")
    if len(assertions_raw) > _MAX_ASSERTION_COUNT:
        raise C2paParseError(_Reason.ASSERTION_COUNT_EXCEEDED, "assertions")

    unknown: list[C2paUnknownAssertion] = []
    for idx, assertion in enumerate(assertions_raw):
        if not isinstance(assertion, dict):
            raise C2paParseError(_Reason.INVALID_TYPE, f"assertions[{idx}]")
        label = assertion.get("label", "")
        if not isinstance(label, str):
            raise C2paParseError(_Reason.INVALID_TYPE, f"assertions[{idx}].label")
        if len(label) > _MAX_ASSERTION_LABEL_LEN:
            raise C2paParseError(_Reason.ASSERTION_LABEL_TOO_LONG, f"assertions[{idx}].label")
        # Measure assertion data size.
        try:
            assertion_bytes = json.dumps(assertion, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise C2paParseError(_Reason.INVALID_TYPE, f"assertions[{idx}]")
        if len(assertion_bytes) > _MAX_ASSERTION_DATA_BYTES:
            raise C2paParseError(_Reason.ASSERTION_DATA_TOO_LARGE, f"assertions[{idx}]")
        # Preserve unknown assertions.
        if label != _MAPPING_LABEL:
            unknown.append(
                C2paUnknownAssertion(
                    label=label,
                    data=assertion.get("data"),
                    unsupported_semantics=True,
                )
            )

    # 9. algorithm check (optional field; only SHA-256 supported).
    if "alg" in data:
        alg = data["alg"]
        if not isinstance(alg, str):
            raise C2paParseError(_Reason.INVALID_TYPE, "alg")
        if alg.lower() not in _SUPPORTED_ALGORITHMS:
            raise C2paParseError(_Reason.UNSUPPORTED_ALGORITHM, "alg")

    # 10. harpocrates_binding.
    binding_raw = data["harpocrates_binding"]
    binding = _parse_binding(binding_raw)

    return C2paParsedManifest(
        claim_generator=claim_generator.strip(),
        spec_version=spec_version,
        binding=binding,
        unknown_assertions=unknown,
        trust_status=C2paTrustStatus.SIGNATURE_NOT_CHECKED,
    )


def export_c2pa_manifest(
    *,
    video_hash: str,
    metadata_hash: str,
    proof_id: str,
    tier: str,
    network: str,
    contract_id: str,
    claim_generator: str | None = None,
) -> C2paExportedManifest:
    """
    Export a C2PA-compatible manifest that binds Harpocrates evidence digests.

    The manifest is idempotent: identical inputs always produce byte-identical
    JSON (keys are sorted, separators are compact).

    The trust status of an exported manifest is always
    ``C2paTrustStatus.SIGNATURE_NOT_CHECKED``; the caller is responsible for
    any downstream cryptographic signing.

    Args:
        video_hash:     32-byte hex — the embedded video hash registered on-chain.
        metadata_hash:  32-byte hex — canonical metadata hash.
        proof_id:       32-byte hex — Harpocrates proof ID.
        tier:           Identity tier ('silent' | 'source' | 'seal').
        network:        Stellar network passphrase.
        contract_id:    Soroban registry contract ID.
        claim_generator: Optional override for the claim_generator field.

    Returns:
        A ``C2paExportedManifest`` containing the manifest dict and its SHA-256
        digest for round-trip verification.

    Raises:
        ValueError: If any required field fails validation.
    """
    _validate_hex32(video_hash, "video_hash")
    _validate_hex32(metadata_hash, "metadata_hash")
    _validate_hex32(proof_id, "proof_id")
    if tier not in _ALLOWED_TIERS:
        raise ValueError(f"tier must be one of {sorted(_ALLOWED_TIERS)}, got: {tier!r}")
    if not isinstance(network, str) or not network.strip():
        raise ValueError("network must be a non-empty string")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise ValueError("contract_id must be a non-empty string")

    manifest: dict[str, Any] = {
        "claim_generator": (claim_generator or _C2PA_MANIFEST_CLAIM_GENERATOR).strip(),
        "spec_version": _C2PA_SPEC_VERSION,
        "alg": "sha256",
        "assertions": [
            # The Harpocrates-specific binding assertion.
            {
                "label": _MAPPING_LABEL,
                "data": {
                    "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
                    "video_hash": video_hash.lower(),
                    "metadata_hash": metadata_hash.lower(),
                    "proof_id": proof_id.lower(),
                    "tier": tier,
                    "network": network.strip(),
                    "contract_id": contract_id.strip(),
                },
            }
        ],
        "harpocrates_binding": {
            "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
            "video_hash": video_hash.lower(),
            "metadata_hash": metadata_hash.lower(),
            "proof_id": proof_id.lower(),
            "tier": tier,
            "network": network.strip(),
            "contract_id": contract_id.strip(),
        },
    }

    canonical = _canonical_json(manifest)
    digest = hashlib.sha256(canonical).hexdigest()
    return C2paExportedManifest(manifest=manifest, digest=digest)


def verify_round_trip(exported: C2paExportedManifest) -> bool:
    """
    Verify that an exported manifest survives a parse round-trip intact.

    Returns True if and only if:
    1. The manifest parses without error.
    2. The re-serialised canonical JSON hashes to the same digest as the export.
    3. All binding fields are preserved byte-for-byte.

    This is a determinism check; it does not perform cryptographic signature
    verification.
    """
    try:
        raw = _canonical_json(exported.manifest)
        parsed = parse_c2pa_manifest(raw)
    except C2paParseError:
        return False

    # Re-export using the parsed binding fields and compare digests.
    try:
        re_exported = export_c2pa_manifest(
            video_hash=parsed.binding.video_hash,
            metadata_hash=parsed.binding.metadata_hash,
            proof_id=parsed.binding.proof_id,
            tier=parsed.binding.tier,
            network=parsed.binding.network,
            contract_id=parsed.binding.contract_id,
            claim_generator=parsed.claim_generator,
        )
    except ValueError:
        return False

    return re_exported.digest == exported.digest


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_binding(raw: Any) -> C2paHarpocratesBinding:
    if not isinstance(raw, dict):
        raise C2paParseError(_Reason.INVALID_TYPE, "harpocrates_binding")

    for key in _REQUIRED_BINDING_KEYS:
        if key not in raw:
            raise C2paParseError(_Reason.MISSING_KEY, f"harpocrates_binding.{key}")

    mv = raw["mapping_version"]
    if not isinstance(mv, int) or mv < 1:
        raise C2paParseError(_Reason.INVALID_TYPE, "harpocrates_binding.mapping_version")
    if mv != C2PA_HARPOCRATES_MAPPING_VERSION:
        raise C2paParseError(
            _Reason.MAPPING_VERSION_MISMATCH,
            "harpocrates_binding.mapping_version",
        )

    for hex_field in ("video_hash", "metadata_hash", "proof_id"):
        val = raw[hex_field]
        if not isinstance(val, str):
            raise C2paParseError(_Reason.INVALID_TYPE, f"harpocrates_binding.{hex_field}")
        if not _HEX32_RE.match(val.lower()):
            raise C2paParseError(_Reason.INVALID_VALUE, f"harpocrates_binding.{hex_field}")

    tier = raw["tier"]
    if not isinstance(tier, str) or tier not in _ALLOWED_TIERS:
        raise C2paParseError(_Reason.INVALID_VALUE, "harpocrates_binding.tier")

    network = raw["network"]
    if not isinstance(network, str) or not network.strip():
        raise C2paParseError(_Reason.INVALID_VALUE, "harpocrates_binding.network")

    contract_id = raw["contract_id"]
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise C2paParseError(_Reason.INVALID_VALUE, "harpocrates_binding.contract_id")

    return C2paHarpocratesBinding(
        mapping_version=mv,
        video_hash=raw["video_hash"].lower(),
        metadata_hash=raw["metadata_hash"].lower(),
        proof_id=raw["proof_id"].lower(),
        tier=tier,
        network=network.strip(),
        contract_id=contract_id.strip(),
    )


def _validate_hex32(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _HEX32_RE.match(value.lower()):
        raise ValueError(f"{name} must be a 32-byte lower-case hex string (64 chars)")


def _canonical_json(obj: Any) -> bytes:
    """Deterministic, compact JSON encoding (keys sorted recursively)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _check_depth(obj: Any, limit: int, _current: int = 0) -> None:
    """Raise C2paParseError if the JSON structure exceeds *limit* nesting levels."""
    if _current > limit:
        raise C2paParseError(_Reason.DEPTH_EXCEEDED)
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, limit, _current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, limit, _current + 1)
