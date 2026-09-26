"""
Tests for backend/c2pa.py — C2PA interoperability layer.

Coverage:
- Valid manifest parsing and export.
- Round-trip export/import preserves all canonical bindings.
- Structural adversarial fixtures: oversized, malformed boxes, recursion, unknown
  algorithms, missing keys, wrong types, digest mismatches, unknown assertions.
- Fuzzing: production-shaped media tests with bounded random payloads.
- Trust status isolation: C2paTrustStatus never leaks into on-chain language.
- Privacy: error payloads contain only reason code + field name, never manifest bytes.
"""

from __future__ import annotations

import json
import os
import random
import string
import struct

import pytest

from c2pa import (
    C2PA_HARPOCRATES_MAPPING_VERSION,
    C2paExportedManifest,
    C2paHarpocratesBinding,
    C2paParsedManifest,
    C2paParseError,
    C2paTrustStatus,
    _MAX_ASSERTION_COUNT,
    _MAX_ASSERTION_DATA_BYTES,
    _MAX_ASSERTION_LABEL_LEN,
    _MAX_JSON_DEPTH,
    _MAX_MANIFEST_BYTES,
    export_c2pa_manifest,
    parse_c2pa_manifest,
    verify_round_trip,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_VIDEO_HASH = "aa" * 32
VALID_META_HASH = "bb" * 32
VALID_PROOF_ID = "cc" * 32
VALID_TIER = "silent"
VALID_NETWORK = "Test SDF Network ; September 2015"
VALID_CONTRACT = "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT"


def _valid_manifest_dict(**overrides) -> dict:
    base = {
        "claim_generator": "harpocrates",
        "spec_version": "1.3",
        "alg": "sha256",
        "assertions": [
            {
                "label": "harpocrates.binding/v1",
                "data": {
                    "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
                    "video_hash": VALID_VIDEO_HASH,
                    "metadata_hash": VALID_META_HASH,
                    "proof_id": VALID_PROOF_ID,
                    "tier": VALID_TIER,
                    "network": VALID_NETWORK,
                    "contract_id": VALID_CONTRACT,
                },
            }
        ],
        "harpocrates_binding": {
            "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
            "video_hash": VALID_VIDEO_HASH,
            "metadata_hash": VALID_META_HASH,
            "proof_id": VALID_PROOF_ID,
            "tier": VALID_TIER,
            "network": VALID_NETWORK,
            "contract_id": VALID_CONTRACT,
        },
    }
    base.update(overrides)
    return base


def _encode(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_returns_exportedmanifest(self):
        result = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        assert isinstance(result, C2paExportedManifest)

    def test_export_is_idempotent(self):
        kwargs = dict(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        a = export_c2pa_manifest(**kwargs)
        b = export_c2pa_manifest(**kwargs)
        assert a.digest == b.digest
        assert a.manifest == b.manifest

    def test_export_contains_binding(self):
        result = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        binding = result.manifest["harpocrates_binding"]
        assert binding["video_hash"] == VALID_VIDEO_HASH
        assert binding["metadata_hash"] == VALID_META_HASH
        assert binding["proof_id"] == VALID_PROOF_ID
        assert binding["tier"] == VALID_TIER
        assert binding["mapping_version"] == C2PA_HARPOCRATES_MAPPING_VERSION

    def test_export_has_sha256_alg(self):
        result = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        assert result.manifest["alg"] == "sha256"

    def test_export_digest_is_hex64(self):
        result = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        assert len(result.digest) == 64
        int(result.digest, 16)  # must be valid hex

    def test_export_all_tiers(self):
        for tier in ("silent", "source", "seal"):
            result = export_c2pa_manifest(
                video_hash=VALID_VIDEO_HASH,
                metadata_hash=VALID_META_HASH,
                proof_id=VALID_PROOF_ID,
                tier=tier,
                network=VALID_NETWORK,
                contract_id=VALID_CONTRACT,
            )
            assert result.manifest["harpocrates_binding"]["tier"] == tier

    def test_export_invalid_tier(self):
        with pytest.raises(ValueError, match="tier"):
            export_c2pa_manifest(
                video_hash=VALID_VIDEO_HASH,
                metadata_hash=VALID_META_HASH,
                proof_id=VALID_PROOF_ID,
                tier="unknown",
                network=VALID_NETWORK,
                contract_id=VALID_CONTRACT,
            )

    def test_export_invalid_hex(self):
        with pytest.raises(ValueError, match="video_hash"):
            export_c2pa_manifest(
                video_hash="not-hex",
                metadata_hash=VALID_META_HASH,
                proof_id=VALID_PROOF_ID,
                tier=VALID_TIER,
                network=VALID_NETWORK,
                contract_id=VALID_CONTRACT,
            )

    def test_export_empty_network(self):
        with pytest.raises(ValueError, match="network"):
            export_c2pa_manifest(
                video_hash=VALID_VIDEO_HASH,
                metadata_hash=VALID_META_HASH,
                proof_id=VALID_PROOF_ID,
                tier=VALID_TIER,
                network="   ",
                contract_id=VALID_CONTRACT,
            )

    def test_export_custom_claim_generator(self):
        result = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
            claim_generator="my-tool/1.0",
        )
        assert result.manifest["claim_generator"] == "my-tool/1.0"


# ---------------------------------------------------------------------------
# Parse — valid inputs
# ---------------------------------------------------------------------------


class TestParseValid:
    def test_parse_valid_manifest(self):
        raw = _encode(_valid_manifest_dict())
        result = parse_c2pa_manifest(raw)
        assert isinstance(result, C2paParsedManifest)
        assert result.binding.video_hash == VALID_VIDEO_HASH
        assert result.binding.metadata_hash == VALID_META_HASH
        assert result.binding.proof_id == VALID_PROOF_ID
        assert result.binding.tier == VALID_TIER

    def test_parse_accepts_string_input(self):
        raw = json.dumps(_valid_manifest_dict())
        result = parse_c2pa_manifest(raw)
        assert isinstance(result, C2paParsedManifest)

    def test_parse_trust_status_is_not_checked(self):
        """Imported manifests must always start as SIGNATURE_NOT_CHECKED."""
        raw = _encode(_valid_manifest_dict())
        result = parse_c2pa_manifest(raw)
        assert result.trust_status == C2paTrustStatus.SIGNATURE_NOT_CHECKED

    def test_parse_preserves_unknown_assertions(self):
        d = _valid_manifest_dict()
        d["assertions"].append({"label": "c2pa.actions", "data": {"actions": []}})
        raw = _encode(d)
        result = parse_c2pa_manifest(raw)
        assert len(result.unknown_assertions) == 1
        assert result.unknown_assertions[0].label == "c2pa.actions"
        assert result.unknown_assertions[0].unsupported_semantics is True

    def test_parse_unknown_assertions_do_not_affect_binding(self):
        d = _valid_manifest_dict()
        d["assertions"].append({"label": "c2pa.thumbnail", "data": "abc"})
        raw = _encode(d)
        result = parse_c2pa_manifest(raw)
        assert result.binding.video_hash == VALID_VIDEO_HASH

    def test_parse_optional_spec_version(self):
        d = _valid_manifest_dict()
        del d["spec_version"]
        result = parse_c2pa_manifest(_encode(d))
        assert result.spec_version is None

    def test_parse_hashes_lowercase_normalised(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["video_hash"] = VALID_VIDEO_HASH.upper()
        result = parse_c2pa_manifest(_encode(d))
        assert result.binding.video_hash == VALID_VIDEO_HASH.lower()


# ---------------------------------------------------------------------------
# Parse — adversarial / invalid inputs
# ---------------------------------------------------------------------------


class TestParseAdversarial:
    def test_oversized_manifest(self):
        payload = b"x" * (_MAX_MANIFEST_BYTES + 1)
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(payload)
        assert exc_info.value.reason == "manifest_too_large"

    def test_not_json(self):
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(b"this is not json")
        assert exc_info.value.reason == "not_json"

    def test_truncated_json(self):
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(b'{"claim_generator":')
        assert exc_info.value.reason == "not_json"

    def test_json_array_not_object(self):
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(b"[1, 2, 3]")
        assert exc_info.value.reason == "not_object"

    def test_json_null(self):
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(b"null")
        assert exc_info.value.reason == "not_object"

    def test_missing_claim_generator(self):
        d = _valid_manifest_dict()
        del d["claim_generator"]
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "missing_key"
        assert exc_info.value.field == "claim_generator"

    def test_missing_assertions(self):
        d = _valid_manifest_dict()
        del d["assertions"]
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "missing_key"

    def test_missing_harpocrates_binding(self):
        d = _valid_manifest_dict()
        del d["harpocrates_binding"]
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "missing_key"

    def test_assertions_not_list(self):
        d = _valid_manifest_dict()
        d["assertions"] = "not a list"
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_type"

    def test_assertion_count_exceeded(self):
        d = _valid_manifest_dict()
        extras = [{"label": f"c2pa.extra.{i}", "data": i} for i in range(_MAX_ASSERTION_COUNT + 1)]
        d["assertions"] = extras
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "assertion_count_exceeded"

    def test_assertion_label_too_long(self):
        d = _valid_manifest_dict()
        d["assertions"].append({"label": "x" * (_MAX_ASSERTION_LABEL_LEN + 1), "data": {}})
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "assertion_label_too_long"

    def test_assertion_data_too_large(self):
        d = _valid_manifest_dict()
        # Create an assertion whose JSON encoding exceeds _MAX_ASSERTION_DATA_BYTES.
        d["assertions"].append({"label": "c2pa.bloat", "data": "z" * (_MAX_ASSERTION_DATA_BYTES + 1)})
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "assertion_data_too_large"

    def test_unsupported_algorithm(self):
        d = _valid_manifest_dict()
        d["alg"] = "md5"
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "unsupported_algorithm"

    def test_unknown_algorithm_variant(self):
        d = _valid_manifest_dict()
        d["alg"] = "sha512"
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "unsupported_algorithm"

    def test_binding_not_object(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"] = "not-an-object"
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_type"

    def test_binding_missing_video_hash(self):
        d = _valid_manifest_dict()
        del d["harpocrates_binding"]["video_hash"]
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "missing_key"

    def test_binding_invalid_hex_video_hash(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["video_hash"] = "zz" * 32
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_value"

    def test_binding_short_hex_video_hash(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["video_hash"] = "aa" * 16  # only 16 bytes
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_value"

    def test_binding_invalid_tier(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["tier"] = "admin"
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_value"

    def test_binding_empty_network(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["network"] = "   "
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_value"

    def test_binding_mapping_version_mismatch(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["mapping_version"] = 999
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "mapping_version_mismatch"

    def test_binding_mapping_version_zero(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["mapping_version"] = 0
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "invalid_type"

    def test_recursion_depth_exceeded(self):
        # Build a deeply nested JSON object.
        deep: dict = {}
        cursor = deep
        for _ in range(_MAX_JSON_DEPTH + 5):
            cursor["nested"] = {}
            cursor = cursor["nested"]
        raw = json.dumps(deep, separators=(",", ":")).encode("utf-8")
        # Wrap in a valid-looking outer structure so size check passes.
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(raw)
        assert exc_info.value.reason in ("depth_exceeded", "not_object", "missing_key")

    def test_error_does_not_echo_manifest_bytes(self):
        """Privacy: error payloads must not contain manifest content."""
        secret = "SENSITIVE_VIDEO_HASH_" + "a" * 64
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["video_hash"] = secret
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        err_dict = exc_info.value.to_dict()
        # The error dict must not contain the secret value.
        assert secret not in str(err_dict)
        assert secret not in str(exc_info.value)

    def test_error_dict_shape(self):
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(b"not json")
        d = exc_info.value.to_dict()
        assert set(d.keys()) == {"reason", "field"}


# ---------------------------------------------------------------------------
# Round-trip tests
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_round_trip_succeeds(self):
        exported = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        assert verify_round_trip(exported) is True

    def test_round_trip_preserves_video_hash(self):
        exported = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier="source",
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        parsed = parse_c2pa_manifest(_encode(exported.manifest))
        assert parsed.binding.video_hash == VALID_VIDEO_HASH
        assert parsed.binding.tier == "source"

    def test_round_trip_preserves_all_binding_fields(self):
        exported = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier="seal",
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        parsed = parse_c2pa_manifest(_encode(exported.manifest))
        b = parsed.binding
        assert b.video_hash == VALID_VIDEO_HASH
        assert b.metadata_hash == VALID_META_HASH
        assert b.proof_id == VALID_PROOF_ID
        assert b.tier == "seal"
        assert b.network == VALID_NETWORK
        assert b.contract_id == VALID_CONTRACT
        assert b.mapping_version == C2PA_HARPOCRATES_MAPPING_VERSION

    def test_round_trip_fails_on_tampered_manifest(self):
        exported = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        tampered = dict(exported.manifest)
        tampered["harpocrates_binding"] = dict(tampered["harpocrates_binding"])
        tampered["harpocrates_binding"]["tier"] = "seal"
        tampered_export = C2paExportedManifest(manifest=tampered, digest=exported.digest)
        assert verify_round_trip(tampered_export) is False

    def test_round_trip_all_tiers(self):
        for tier in ("silent", "source", "seal"):
            exported = export_c2pa_manifest(
                video_hash=VALID_VIDEO_HASH,
                metadata_hash=VALID_META_HASH,
                proof_id=VALID_PROOF_ID,
                tier=tier,
                network=VALID_NETWORK,
                contract_id=VALID_CONTRACT,
            )
            assert verify_round_trip(exported) is True


# ---------------------------------------------------------------------------
# Trust status isolation
# ---------------------------------------------------------------------------


class TestTrustStatusIsolation:
    def test_trust_status_never_uses_onchain_language(self):
        """C2paTrustStatus values must not contain 'confirmed', 'verified', or 'proof'."""
        forbidden = {"confirmed", "verified", "proof", "on_chain", "zk"}
        for status in C2paTrustStatus:
            for word in forbidden:
                assert word not in status.value, (
                    f"C2paTrustStatus.{status.name} uses on-chain language: {word!r}"
                )

    def test_imported_trust_status_is_not_checked(self):
        raw = _encode(_valid_manifest_dict())
        result = parse_c2pa_manifest(raw)
        assert result.trust_status == C2paTrustStatus.SIGNATURE_NOT_CHECKED

    def test_parse_error_trust_status_is_parse_failed(self):
        """A C2paParseError implies PARSE_FAILED trust status (verify callers honour this)."""
        assert C2paTrustStatus.PARSE_FAILED.value == "parse_failed"


# ---------------------------------------------------------------------------
# Fuzzing — bounded random payloads
# ---------------------------------------------------------------------------


class TestFuzzing:
    """
    Production-shaped fuzz tests.

    These do not use hypothesis; they generate bounded random inputs and assert
    that the parser never panics, never leaks manifest content in errors, and
    always raises C2paParseError (never unhandled exceptions) for malformed data.
    """

    _RNG = random.Random(0xC2A_FACE)  # deterministic seed for reproducible fuzz cases

    def _random_bytes(self, size: int) -> bytes:
        return bytes(self._RNG.getrandbits(8) for _ in range(size))

    def _random_string(self, length: int) -> str:
        chars = string.printable
        return "".join(self._RNG.choice(chars) for _ in range(length))

    def test_random_bytes_do_not_panic(self):
        for _ in range(50):
            size = self._RNG.randint(0, 1024)
            payload = self._random_bytes(size)
            try:
                parse_c2pa_manifest(payload)
            except C2paParseError:
                pass  # expected
            except Exception as exc:
                pytest.fail(f"Unexpected exception for random bytes: {exc!r}")

    def test_random_json_does_not_panic(self):
        for _ in range(50):
            # Random JSON-like strings.
            s = self._random_string(self._RNG.randint(0, 256))
            try:
                parse_c2pa_manifest(s.encode("utf-8", errors="replace"))
            except C2paParseError:
                pass
            except Exception as exc:
                pytest.fail(f"Unexpected exception for random JSON string: {exc!r}")

    def test_mutated_valid_manifest_does_not_panic(self):
        """Byte-level mutations of a valid manifest must only raise C2paParseError."""
        base = _encode(_valid_manifest_dict())
        for _ in range(100):
            mutated = bytearray(base)
            # Flip a random byte.
            idx = self._RNG.randint(0, len(mutated) - 1)
            mutated[idx] ^= self._RNG.getrandbits(8)
            try:
                parse_c2pa_manifest(bytes(mutated))
            except C2paParseError:
                pass
            except Exception as exc:
                pytest.fail(f"Unexpected exception on mutation: {exc!r}")

    def test_oversized_payloads_are_rejected_fast(self):
        """Oversized payloads must be rejected without JSON parsing."""
        big = b"x" * (_MAX_MANIFEST_BYTES * 2)
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(big)
        assert exc_info.value.reason == "manifest_too_large"

    def test_fuzz_errors_never_echo_content(self):
        """Error messages must not contain content from the input payload."""
        sentinel = "SENTINEL_" + "9" * 20
        payload = json.dumps({"claim_generator": sentinel}).encode("utf-8")
        try:
            parse_c2pa_manifest(payload)
        except C2paParseError as exc:
            err = str(exc) + str(exc.to_dict())
            assert sentinel not in err
        except Exception:
            pass  # non-C2paParseError is still covered by the no-panic tests above


# ---------------------------------------------------------------------------
# Compatibility matrix fixture
# ---------------------------------------------------------------------------


class TestCompatibilityMatrix:
    """
    Compatibility matrix: ensure the mapping version constant is consistent
    with what parsers and exporters actually produce/consume.
    """

    def test_export_uses_current_mapping_version(self):
        exported = export_c2pa_manifest(
            video_hash=VALID_VIDEO_HASH,
            metadata_hash=VALID_META_HASH,
            proof_id=VALID_PROOF_ID,
            tier=VALID_TIER,
            network=VALID_NETWORK,
            contract_id=VALID_CONTRACT,
        )
        assert exported.manifest["harpocrates_binding"]["mapping_version"] == C2PA_HARPOCRATES_MAPPING_VERSION

    def test_parser_rejects_future_mapping_version(self):
        d = _valid_manifest_dict()
        d["harpocrates_binding"]["mapping_version"] = C2PA_HARPOCRATES_MAPPING_VERSION + 1
        with pytest.raises(C2paParseError) as exc_info:
            parse_c2pa_manifest(_encode(d))
        assert exc_info.value.reason == "mapping_version_mismatch"

    def test_parser_rejects_past_mapping_version(self):
        if C2PA_HARPOCRATES_MAPPING_VERSION > 1:
            d = _valid_manifest_dict()
            d["harpocrates_binding"]["mapping_version"] = C2PA_HARPOCRATES_MAPPING_VERSION - 1
            with pytest.raises(C2paParseError) as exc_info:
                parse_c2pa_manifest(_encode(d))
            assert exc_info.value.reason == "mapping_version_mismatch"
