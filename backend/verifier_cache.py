from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, Optional

from metrics import collector

# Cryptographic domain tag for proof-cache keys.
#
# Every key is a SHA-256 digest computed over length-prefixed fields that start
# with this tag, so verifier results cached under one key space (protocol
# version, network, circuit, verifier) can never collide with, or be replayed
# against, another. The tag must be bumped whenever the key field layout
# changes, which orphans all previously cached entries instead of silently
# reusing results derived under a different scheme.
CACHE_KEY_DOMAIN_TAG = "harpocrates:verifier-cache:v1"


def _encode_cache_key_field(value: str) -> str:
    """Length-prefix a field so framing is unambiguous regardless of content.

    Length-prefixed encoding means field values cannot bleed into each other:
    two distinct field tuples always map to distinct payloads (and therefore
    distinct digests), even when values contain separator-like characters.
    """
    encoded = value.encode("utf-8")
    return f"{len(encoded)}:{value}"


def _normalize_hex_field(value: str) -> str:
    """Canonicalize a hex-ish cache input (trim whitespace, lowercase).

    Proof and public-input hex denote raw bytes, so case is not semantic.
    Canonicalizing prevents the same proof from fragmenting across case-variant
    entries and stops a case-variant twin from being cached (or served) as if
    it were a distinct verification result.
    """
    return value.strip().lower()


class VerifierCache:
    """Bounded, thread-safe cache for Noir verifier results with positive and negative TTLs.

    Cache keys are domain-separated: they are SHA-256 digests over a versioned
    domain tag plus length-prefixed fields (domain, network, circuit version,
    verifier version, proof hex, public-input hex). Keys never expose the
    underlying proof material, and results cannot be shared across domains,
    networks, or verifier versions.
    """

    def __init__(
        self,
        max_size: int = 10000,
        positive_ttl_seconds: float = 86400.0,
        negative_ttl_seconds: float = 300.0,
    ) -> None:
        self.max_size = max_size
        self.positive_ttl_seconds = positive_ttl_seconds
        self.negative_ttl_seconds = negative_ttl_seconds
        
        self._lock = threading.Lock()
        self._cache: Dict[str, tuple[bool, float]] = {}

    def _get_cache_key(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> str:
        """Deterministically derives a domain-separated cache key.

        The payload starts with the versioned domain tag and every field is
        length-prefixed, so the digest is injective over the field tuple:
        ambiguous boundary shifts between fields cannot produce a collision.
        """
        payload = "".join(
            _encode_cache_key_field(field)
            for field in (
                CACHE_KEY_DOMAIN_TAG,
                domain,
                network,
                circuit_version,
                verifier_version,
                _normalize_hex_field(proof_hex),
                _normalize_hex_field(public_inputs_hex),
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> Optional[bool]:
        """Fetch verifier result from cache, evaluating TTL. Emits metrics."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        now = time.monotonic()

        with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                result, expires_at = entry
                if now < expires_at:
                    collector.record_cache_hit()
                    # Refresh LRU by re-inserting
                    self._cache.pop(key)
                    self._cache[key] = entry
                    return result
                else:
                    # Expired
                    self._cache.pop(key)

            collector.record_cache_miss()
            return None

    def set(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
        is_valid: bool,
    ) -> None:
        """Store verifier result in cache with appropriate TTL. Bounded by max_size."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        now = time.monotonic()
        ttl = self.positive_ttl_seconds if is_valid else self.negative_ttl_seconds
        expires_at = now + ttl

        with self._lock:
            if key in self._cache:
                self._cache.pop(key)
            elif len(self._cache) >= self.max_size:
                self._cache.pop(next(iter(self._cache)))
                collector.record_cache_eviction()

            self._cache[key] = (is_valid, expires_at)

    def invalidate(
        self,
        domain: str,
        network: str,
        circuit_version: str,
        verifier_version: str,
        proof_hex: str,
        public_inputs_hex: str,
    ) -> None:
        """Remove specific result from cache."""
        key = self._get_cache_key(
            domain, network, circuit_version, verifier_version, proof_hex, public_inputs_hex
        )
        with self._lock:
            if key in self._cache:
                self._cache.pop(key)

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._cache.clear()
