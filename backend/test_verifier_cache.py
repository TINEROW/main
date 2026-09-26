import hashlib
import time
import unittest
from unittest import mock

import verifier_cache as verifier_cache_module
from verifier_cache import (
    CACHE_KEY_DOMAIN_TAG,
    VerifierCache,
    _encode_cache_key_field,
    _normalize_hex_field,
)
from metrics import collector


class TestVerifierCache(unittest.TestCase):
    def setUp(self):
        collector.reset()
        self.cache = VerifierCache(
            max_size=3,
            positive_ttl_seconds=1.0,
            negative_ttl_seconds=0.1,
        )

    def test_cache_key_determinism(self):
        key1 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        key2 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        self.assertEqual(key1, key2)

    def test_cache_key_collision(self):
        key1 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        key2 = self.cache._get_cache_key("d", "n2", "c", "v", "p", "pi")
        self.assertNotEqual(key1, key2)

    def test_positive_ttl(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", True)
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p", "pi"))

    def test_negative_ttl_expiration(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", False)
        # Should be valid initially
        self.assertFalse(self.cache.get("d", "n", "c", "v", "p", "pi"))
        time.sleep(0.15)
        # Should be expired now
        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p", "pi"))

    def test_lru_eviction(self):
        self.cache.set("d", "n", "c", "v", "p1", "pi", True)
        self.cache.set("d", "n", "c", "v", "p2", "pi", True)
        self.cache.set("d", "n", "c", "v", "p3", "pi", True)
        # max_size is 3, access p1 to make it recent
        self.cache.get("d", "n", "c", "v", "p1", "pi")

        # Add a 4th item, should evict p2 (least recently used)
        self.cache.set("d", "n", "c", "v", "p4", "pi", True)

        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p2", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p1", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p3", "pi"))
        self.assertTrue(self.cache.get("d", "n", "c", "v", "p4", "pi"))

    def test_invalidate(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", True)
        self.cache.invalidate("d", "n", "c", "v", "p", "pi")
        self.assertIsNone(self.cache.get("d", "n", "c", "v", "p", "pi"))


class TestVerifierCacheKeyDomainSeparation(unittest.TestCase):
    """Focused #373 coverage: domain-separated, unambiguous proof-cache keys."""

    def setUp(self):
        collector.reset()
        self.cache = VerifierCache(
            max_size=4,
            positive_ttl_seconds=1.0,
            negative_ttl_seconds=0.1,
        )

    def test_key_is_deterministic_sha256_hex(self):
        key1 = self.cache._get_cache_key("d", "n", "c", "v", "ab", "cd")
        key2 = self.cache._get_cache_key("d", "n", "c", "v", "ab", "cd")
        self.assertEqual(key1, key2)
        self.assertRegex(key1, r"^[0-9a-f]{64}$")

    def test_key_binds_versioned_domain_tag(self):
        self.assertIn("v1", CACHE_KEY_DOMAIN_TAG)
        expected_payload = "".join(
            _encode_cache_key_field(field)
            for field in (CACHE_KEY_DOMAIN_TAG, "d", "n", "c", "v", "ab", "cd")
        )
        expected = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
        self.assertEqual(self.cache._get_cache_key("d", "n", "c", "v", "ab", "cd"), expected)

    def test_length_prefix_framing_prevents_boundary_collisions(self):
        # Regression: with plain "|" concatenation, (domain="d|n", network="c")
        # and (domain="d", network="n|c") produced the same payload and thus
        # the same cache key. Length-prefixed framing keeps them distinct.
        key1 = self.cache._get_cache_key("d|n", "c", "v", "p", "pi", "x")
        key2 = self.cache._get_cache_key("d", "n|c", "v", "p", "pi", "x")
        self.assertNotEqual(key1, key2)

    def test_empty_fields_stay_separated(self):
        key1 = self.cache._get_cache_key("", "n", "c", "v", "p", "pi")
        key2 = self.cache._get_cache_key("n", "", "c", "v", "p", "pi")
        self.assertNotEqual(key1, key2)

    def test_single_field_mutation_always_changes_key(self):
        base = ("d", "n", "c", "v", "ab", "cd")
        baseline = self.cache._get_cache_key(*base)
        for index in range(len(base)):
            mutated = list(base)
            mutated[index] = mutated[index] + "2"
            self.assertNotEqual(
                baseline,
                self.cache._get_cache_key(*mutated),
                f"field at index {index} is not domain-separated",
            )

    def test_hex_inputs_are_case_canonicalized(self):
        key_lower = self.cache._get_cache_key("d", "n", "c", "v", "ab", "cd")
        key_upper = self.cache._get_cache_key("d", "n", "c", "v", "AB", "CD")
        self.assertEqual(key_lower, key_upper)

    def test_hex_inputs_ignore_surrounding_whitespace(self):
        key_plain = self.cache._get_cache_key("d", "n", "c", "v", "ab", "cd")
        key_padded = self.cache._get_cache_key("d", "n", "c", "v", " ab ", "\tcd\n")
        self.assertEqual(key_plain, key_padded)

    def test_case_variant_proof_round_trips_to_same_entry(self):
        self.cache.set("d", "n", "c", "v", "AB", "CD", True)
        self.assertTrue(self.cache.get("d", "n", "c", "v", "ab", "cd"))

    def test_domain_tag_bump_invalidates_prior_keys(self):
        key_v1 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        with mock.patch.object(
            verifier_cache_module, "CACHE_KEY_DOMAIN_TAG", "harpocrates:verifier-cache:v2"
        ):
            key_v2 = self.cache._get_cache_key("d", "n", "c", "v", "p", "pi")
        self.assertNotEqual(key_v1, key_v2)

    def test_domain_tag_bump_invalidates_cached_result(self):
        self.cache.set("d", "n", "c", "v", "p", "pi", True)
        with mock.patch.object(
            verifier_cache_module, "CACHE_KEY_DOMAIN_TAG", "harpocrates:verifier-cache:v2"
        ):
            self.assertIsNone(self.cache.get("d", "n", "c", "v", "p", "pi"))

    def test_encode_field_length_prefix_boundaries(self):
        self.assertEqual(_encode_cache_key_field(""), "0:")
        self.assertEqual(_encode_cache_key_field("ab"), "2:ab")
        self.assertEqual(_encode_cache_key_field("a|b"), "3:a|b")

    def test_normalize_hex_field(self):
        self.assertEqual(_normalize_hex_field("  AB1 "), "ab1")


if __name__ == "__main__":
    unittest.main()
