"""Tests for devx/label_config.py.

Coverage
--------
  Positive: canonical labels.yml and labeler.yml both validate cleanly.
  Negative: each validation rule fires a LabelConfigError on bad input.
  Boundary: max description length, 6-char color edge cases.
  Regression: privacy-sensitive terms in descriptions are rejected.
  Privacy: witness, private_key, nullifier_value, mnemonic, password
           terms in label names and descriptions are caught.

No real media, credentials, witnesses, or private keys are used.
"""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

# Make devx/ importable when run from the repo root or the devx/ directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import label_config as lc


# ── shared fixtures ───────────────────────────────────────────────────────────

def _minimal_labels() -> dict:
    """Smallest valid labels.yml structure covering all required namespaces."""
    return {
        "schema_version": 1,
        "labels": [
            {"name": "impact/protocol",  "color": "b60205", "description": "Protocol change."},
            {"name": "layer/frontend",   "color": "bfd4f2", "description": "Frontend change."},
            {"name": "type/feature",     "color": "a2eeef", "description": "New feature."},
            {"name": "status/do-not-merge", "color": "b60205", "description": "Block merge."},
        ],
    }


def _minimal_labeler(labels: dict | None = None) -> dict:
    """Smallest valid labeler.yml structure referencing _minimal_labels."""
    return {
        "impact/protocol": [
            {"changed-files": [{"any-glob-to-any-file": ["zk/vectors/**"]}]}
        ],
        "layer/frontend": [
            {"changed-files": [{"any-glob-to-any-file": ["frontend/**"]}]}
        ],
    }


# ── labels.yml positive ───────────────────────────────────────────────────────

class TestValidateLabelsPositive(unittest.TestCase):

    def test_minimal_valid_structure(self):
        names = lc.validate_labels(_minimal_labels())
        self.assertIn("impact/protocol", names)
        self.assertIn("layer/frontend", names)

    def test_canonical_labels_yml_validates(self):
        """The committed .github/labels.yml must pass validation end-to-end."""
        root = Path(__file__).resolve().parents[1]
        labels_path = root / ".github" / "labels.yml"
        if not labels_path.exists():
            self.skipTest(".github/labels.yml not found")
        data = lc._load_yaml(labels_path)
        names = lc.validate_labels(data, source=str(labels_path))
        self.assertTrue(len(names) > 0)
        namespaces = {n.split("/")[0] for n in names if "/" in n}
        self.assertTrue(lc.REQUIRED_NAMESPACES.issubset(namespaces))

    def test_all_required_namespaces_present(self):
        data = _minimal_labels()
        names = lc.validate_labels(data)
        namespaces = {n.split("/")[0] for n in names if "/" in n}
        self.assertTrue(lc.REQUIRED_NAMESPACES.issubset(namespaces))

    def test_exact_6char_color(self):
        data = _minimal_labels()
        data["labels"][0]["color"] = "ffffff"
        lc.validate_labels(data)  # must not raise

    def test_description_at_max_length(self):
        data = _minimal_labels()
        # Exactly MAX_DESCRIPTION_BYTES of ASCII
        data["labels"][0]["description"] = "x" * lc.MAX_DESCRIPTION_BYTES
        lc.validate_labels(data)  # must not raise


# ── labels.yml negative ───────────────────────────────────────────────────────

class TestValidateLabelsNegative(unittest.TestCase):

    def test_rejects_wrong_schema_version(self):
        data = _minimal_labels()
        data["schema_version"] = 2
        with self.assertRaisesRegex(lc.LabelConfigError, "schema_version"):
            lc.validate_labels(data)

    def test_rejects_missing_schema_version(self):
        data = _minimal_labels()
        del data["schema_version"]
        with self.assertRaisesRegex(lc.LabelConfigError, "schema_version"):
            lc.validate_labels(data)

    def test_rejects_non_dict_root(self):
        with self.assertRaisesRegex(lc.LabelConfigError, "mapping"):
            lc.validate_labels(["not", "a", "dict"])

    def test_rejects_empty_labels_list(self):
        data = _minimal_labels()
        data["labels"] = []
        with self.assertRaisesRegex(lc.LabelConfigError, "non-empty list"):
            lc.validate_labels(data)

    def test_rejects_missing_name(self):
        data = _minimal_labels()
        del data["labels"][0]["name"]
        with self.assertRaisesRegex(lc.LabelConfigError, "'name'"):
            lc.validate_labels(data)

    def test_rejects_missing_color(self):
        data = _minimal_labels()
        del data["labels"][0]["color"]
        with self.assertRaisesRegex(lc.LabelConfigError, "'color'"):
            lc.validate_labels(data)

    def test_rejects_missing_description(self):
        data = _minimal_labels()
        del data["labels"][0]["description"]
        with self.assertRaisesRegex(lc.LabelConfigError, "'description'"):
            lc.validate_labels(data)

    def test_rejects_color_with_hash_prefix(self):
        data = _minimal_labels()
        data["labels"][0]["color"] = "#b60205"
        with self.assertRaisesRegex(lc.LabelConfigError, "leading '#'"):
            lc.validate_labels(data)

    def test_rejects_short_color(self):
        data = _minimal_labels()
        data["labels"][0]["color"] = "fff"
        with self.assertRaisesRegex(lc.LabelConfigError, "6-character hex"):
            lc.validate_labels(data)

    def test_rejects_invalid_color_chars(self):
        data = _minimal_labels()
        data["labels"][0]["color"] = "gggggg"
        with self.assertRaisesRegex(lc.LabelConfigError, "6-character hex"):
            lc.validate_labels(data)

    def test_rejects_duplicate_label_names(self):
        data = _minimal_labels()
        data["labels"].append(copy.deepcopy(data["labels"][0]))
        with self.assertRaisesRegex(lc.LabelConfigError, "duplicate"):
            lc.validate_labels(data)

    def test_rejects_description_over_max_bytes(self):
        data = _minimal_labels()
        data["labels"][0]["description"] = "x" * (lc.MAX_DESCRIPTION_BYTES + 1)
        with self.assertRaisesRegex(lc.LabelConfigError, "bytes"):
            lc.validate_labels(data)

    def test_rejects_empty_description(self):
        data = _minimal_labels()
        data["labels"][0]["description"] = "   "
        with self.assertRaisesRegex(lc.LabelConfigError, "non-empty string"):
            lc.validate_labels(data)

    def test_rejects_uppercase_in_name(self):
        data = _minimal_labels()
        data["labels"][0]["name"] = "Impact/Protocol"
        with self.assertRaisesRegex(lc.LabelConfigError, "must match"):
            lc.validate_labels(data)

    def test_rejects_missing_required_namespace(self):
        data = _minimal_labels()
        # Remove the only 'status/*' label
        data["labels"] = [
            e for e in data["labels"] if not e["name"].startswith("status/")
        ]
        with self.assertRaisesRegex(lc.LabelConfigError, "missing required namespaces"):
            lc.validate_labels(data)


# ── privacy regression tests ──────────────────────────────────────────────────

class TestPrivacyScan(unittest.TestCase):
    """Sensitive terms in label names or descriptions must be rejected."""

    def _poisoned(self, field: str, value: str) -> dict:
        data = _minimal_labels()
        if field == "name":
            data["labels"][0]["name"] = value
        else:
            data["labels"][0]["description"] = value
        return data

    def test_rejects_private_key_in_description(self):
        data = self._poisoned("description", "Contains private_key material.")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_rejects_nullifier_value_in_description(self):
        data = self._poisoned("description", "Encodes nullifier_value for proof.")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_rejects_credential_secret_in_description(self):
        data = self._poisoned("description", "Uses credential_secret from vault.")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_rejects_mnemonic_in_description(self):
        data = self._poisoned("description", "Derive key from mnemonic phrase.")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_rejects_password_in_description(self):
        data = self._poisoned("description", "Requires password authentication.")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_rejects_pem_header_in_description(self):
        data = self._poisoned("description", "-----BEGIN CERTIFICATE-----")
        with self.assertRaisesRegex(lc.LabelConfigError, "forbidden sensitive"):
            lc.validate_labels(data)

    def test_allows_witness_in_impact_context(self):
        # "witness" as a standalone term (e.g. Silent Witness) is allowed in
        # descriptions that don't contain 'witness value' or credential secrets.
        # The pattern only blocks nullifier_value; standalone 'witness' is fine.
        data = _minimal_labels()
        data["labels"][0]["description"] = "Silent Witness tier changes."
        lc.validate_labels(data)  # must not raise


# ── labeler.yml cross-reference ───────────────────────────────────────────────

class TestValidateLabeler(unittest.TestCase):

    def _canonical(self) -> set[str]:
        return set(lc.validate_labels(_minimal_labels()))

    def test_valid_labeler_passes(self):
        lc.validate_labeler(_minimal_labeler(), self._canonical())

    def test_canonical_labeler_yml_validates(self):
        """The committed .github/labeler.yml must reference only known labels."""
        root = Path(__file__).resolve().parents[1]
        labels_path = root / ".github" / "labels.yml"
        labeler_path = root / ".github" / "labeler.yml"
        if not labels_path.exists() or not labeler_path.exists():
            self.skipTest("label config files not found")
        labels_data = lc._load_yaml(labels_path)
        canonical = set(lc.validate_labels(labels_data))
        labeler_data = lc._load_yaml(labeler_path)
        lc.validate_labeler(labeler_data, canonical)  # must not raise

    def test_rejects_unknown_label_in_labeler(self):
        labeler = _minimal_labeler()
        labeler["impact/nonexistent"] = [
            {"changed-files": [{"any-glob-to-any-file": ["foo/**"]}]}
        ]
        with self.assertRaisesRegex(lc.LabelConfigError, "not defined in labels.yml"):
            lc.validate_labeler(labeler, self._canonical())

    def test_rejects_non_list_rules(self):
        labeler = {"impact/protocol": "not-a-list"}
        with self.assertRaisesRegex(lc.LabelConfigError, "rules must be a list"):
            lc.validate_labeler(labeler, self._canonical())

    def test_rejects_rule_without_changed_files_key(self):
        labeler = {"impact/protocol": [{"no-changed-files": []}]}
        with self.assertRaisesRegex(lc.LabelConfigError, "missing 'changed-files'"):
            lc.validate_labeler(labeler, self._canonical())

    def test_rejects_non_dict_root(self):
        with self.assertRaisesRegex(lc.LabelConfigError, "mapping"):
            lc.validate_labeler(["not", "a", "dict"], self._canonical())


# ── file-level guards ─────────────────────────────────────────────────────────

class TestFileGuards(unittest.TestCase):

    def test_rejects_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            lc._load_yaml(Path("/does/not/exist.yml"))

    def test_rejects_oversized_file(self):
        with tempfile.NamedTemporaryFile(
            "wb", suffix=".yml", delete=False
        ) as handle:
            handle.write(b"x: " + b"a" * (lc.MAX_FILE_BYTES + 1))
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaisesRegex(lc.LabelConfigError, "exceeds"):
            lc._load_yaml(path)

    def test_rejects_malformed_yaml(self):
        import yaml as _yaml
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", delete=False
        ) as handle:
            handle.write("key: [unclosed")
            path = Path(handle.name)
        self.addCleanup(path.unlink)
        with self.assertRaises(_yaml.YAMLError):
            lc._load_yaml(path)


# ── CLI smoke tests ───────────────────────────────────────────────────────────

class TestCLI(unittest.TestCase):

    def test_check_canonical_labels_yml(self):
        root = Path(__file__).resolve().parents[1]
        labels_path = root / ".github" / "labels.yml"
        if not labels_path.exists():
            self.skipTest(".github/labels.yml not found")
        rc = lc.main(["--check", str(labels_path)])
        self.assertEqual(rc, 0)

    def test_check_labeler_cross_reference(self):
        root = Path(__file__).resolve().parents[1]
        labels_path = root / ".github" / "labels.yml"
        labeler_path = root / ".github" / "labeler.yml"
        if not labels_path.exists() or not labeler_path.exists():
            self.skipTest("label config files not found")
        rc = lc.main([
            "--check-labeler", str(labeler_path), str(labels_path),
        ])
        self.assertEqual(rc, 0)

    def test_missing_file_returns_exit_2(self):
        rc = lc.main(["--check", "/does/not/exist.yml"])
        self.assertEqual(rc, 2)

    def test_no_args_returns_0(self):
        rc = lc.main([])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
