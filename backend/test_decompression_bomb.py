"""
Decompression-bomb regression tests for metadata envelopes - issue #263.

A Harpocrates video carries a zlib-compressed metadata envelope of at most
64 KiB.  ``zlib.decompress`` expands a small, checksum-valid member into an
arbitrarily large buffer, so a hostile upload could exhaust worker memory while
``extract_metadata`` is unpacking the envelope.  These tests pin the bounded
materialisation behaviour of ``envelope.unpack_envelope`` and the matching
pack-time ceiling that stops oversized metadata from being embedded.
"""

from __future__ import annotations

import hashlib
import json
import struct
import tracemalloc
import unittest
import zlib
from datetime import datetime, timezone

from envelope import (
    MAGIC_V1,
    MAGIC_V2,
    MAX_DECOMPRESSED_BYTES,
    MAX_PAYLOAD_BYTES,
    pack_envelope,
    unpack_envelope,
)


def _valid_metadata(**overrides) -> dict:
    metadata = {
        "protocol": "harpocrates",
        "version": 2,
        "tier": "silent",
        "sourceHash": "ab" * 32,
        "proofId": "cd" * 32,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    metadata.update(overrides)
    return metadata


def _canonical(metadata: dict) -> bytes:
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _envelope(magic: bytes, body: bytes) -> bytes:
    """Assemble a raw envelope with a valid checksum around ``body``."""
    return magic + struct.pack(">I", len(body)) + hashlib.sha256(body).digest() + body


def _envelope_with_canonical(canonical: bytes, magic: bytes = MAGIC_V2) -> bytes:
    return _envelope(magic, zlib.compress(canonical, 9))


def _padded_canonical(total_bytes: int) -> bytes:
    """Canonical JSON of exactly ``total_bytes`` bytes (via a repeatable pad field)."""
    fixed = len(_canonical(_valid_metadata(pad="")))
    if total_bytes < fixed:
        raise ValueError("requested size is smaller than the fixed metadata fields")
    canonical = _canonical(_valid_metadata(pad="A" * (total_bytes - fixed)))
    assert len(canonical) == total_bytes, (len(canonical), total_bytes)
    return canonical


class TestDecompressionBomb(unittest.TestCase):
    """A tiny compressed member must never be inflated past the metadata ceiling."""

    def test_high_ratio_bomb_is_rejected(self):
        # A few hundred compressed bytes that inflate to ~2 MiB of metadata.
        canonical = _padded_canonical(MAX_DECOMPRESSED_BYTES * 32)
        body = zlib.compress(canonical, 9)

        # The compressed body comfortably fits the envelope, so the existing
        # body-size guard alone would accept it.
        self.assertLess(len(body), MAX_PAYLOAD_BYTES)
        self.assertGreater(len(canonical), MAX_DECOMPRESSED_BYTES * 8)

        self.assertIsNone(unpack_envelope(_envelope(MAGIC_V2, body)))

    def test_memory_stays_bounded_while_rejecting_bomb(self):
        canonical = _padded_canonical(MAX_DECOMPRESSED_BYTES * 16)
        data = _envelope_with_canonical(canonical)

        tracemalloc.start()
        try:
            self.assertIsNone(unpack_envelope(data))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        # Peak allocation stays near the compressed body + the bounded inflate
        # window instead of the ~1 MiB the member actually expands to.
        self.assertLess(peak, MAX_DECOMPRESSED_BYTES * 4)

    def test_v1_bomb_is_rejected(self):
        canonical = _padded_canonical(MAX_DECOMPRESSED_BYTES * 8)
        body = zlib.compress(canonical, 9)
        self.assertLess(len(body), MAX_PAYLOAD_BYTES)
        self.assertIsNone(unpack_envelope(_envelope(MAGIC_V1, body)))

    def test_many_small_bombs_all_rejected(self):
        for extra in (MAX_DECOMPRESSED_BYTES * 2, MAX_DECOMPRESSED_BYTES * 4 + 7):
            with self.subTest(extra=extra):
                canonical = _padded_canonical(extra)
                self.assertIsNone(unpack_envelope(_envelope_with_canonical(canonical)))


class TestDecompressionBoundary(unittest.TestCase):
    """The inflate ceiling is inclusive: exactly the limit passes, +1 is refused."""

    def test_inflated_at_limit_is_accepted(self):
        recovered = unpack_envelope(_envelope_with_canonical(_padded_canonical(MAX_DECOMPRESSED_BYTES)))
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["protocol"], "harpocrates")

    def test_one_byte_past_limit_is_rejected(self):
        canonical = _padded_canonical(MAX_DECOMPRESSED_BYTES + 1)
        self.assertEqual(len(canonical), MAX_DECOMPRESSED_BYTES + 1)
        self.assertIsNone(unpack_envelope(_envelope_with_canonical(canonical)))


class TestMalformedStreams(unittest.TestCase):
    """Truncated and trailing-garbage members are refused."""

    def test_truncated_zlib_member_rejected(self):
        body = zlib.compress(_canonical(_valid_metadata()), 9)[:6]
        self.assertIsNone(unpack_envelope(_envelope(MAGIC_V2, body)))

    def test_trailing_bytes_after_member_rejected(self):
        body = zlib.compress(_canonical(_valid_metadata()), 9) + b"trailing-garbage"
        self.assertIsNone(unpack_envelope(_envelope(MAGIC_V2, body)))


class TestPackCeiling(unittest.TestCase):
    """pack_envelope must bound the uncompressed metadata, not only its compressed form."""

    def test_pack_rejects_oversized_metadata(self):
        oversized = _valid_metadata(pad="A" * (MAX_PAYLOAD_BYTES * 4))
        # Highly compressible - the compressed body alone would pass the old guard.
        self.assertLess(len(zlib.compress(_canonical(oversized), 9)), MAX_PAYLOAD_BYTES)
        with self.assertRaises(ValueError):
            pack_envelope(oversized, version=2)

    def test_pack_ceiling_boundary(self):
        canonical = _padded_canonical(MAX_DECOMPRESSED_BYTES)
        metadata = json.loads(canonical.decode("utf-8"))
        self.assertIsNotNone(pack_envelope(metadata, version=2))

        over = json.loads(_padded_canonical(MAX_DECOMPRESSED_BYTES + 1).decode("utf-8"))
        with self.assertRaises(ValueError):
            pack_envelope(over, version=2)

    def test_small_round_trip_still_works(self):
        packed = pack_envelope(_valid_metadata(), version=2)
        recovered = unpack_envelope(packed)
        self.assertEqual(recovered["protocol"], "harpocrates")


if __name__ == "__main__":
    unittest.main()
