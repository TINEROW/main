from __future__ import annotations

import json
import unittest

import validate_c2pa_fixture as vc


class C2paFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = vc.DEFAULT_EXPECTED.read_text(encoding="utf-8")

    def test_fixture_files_exist(self) -> None:
        for path in (vc.DEFAULT_MANIFEST, vc.DEFAULT_RECEIPT, vc.DEFAULT_EXPECTED):
            self.assertTrue(path.is_file(), f"missing fixture: {path}")
        for path in (vc.DEFAULT_MANIFEST, vc.DEFAULT_RECEIPT, vc.DEFAULT_EXPECTED):
            json.loads(path.read_text(encoding="utf-8"))

    def test_expected_export_is_privacy_safe(self) -> None:
        vc.assert_privacy_safe(self.expected)

    def test_expected_export_passes_structure_checks(self) -> None:
        vc.structure_checks(self.expected)

    def test_privacy_safe_rejects_private_key(self) -> None:
        with self.assertRaisesRegex(vc.FixtureError, "sensitive"):
            vc.assert_privacy_safe('{"label":"harpocrates.registry.v1","signCert":"AAAA"}')
        with self.assertRaisesRegex(vc.FixtureError, "BEGIN"):
            vc.assert_privacy_safe("-----BEGIN RSA PRIVATE KEY-----")

    def test_structure_checks_reject_missing_export_assertion(self) -> None:
        parsed = json.loads(self.expected)
        parsed["assertions"] = [
            {"label": "c2pa.actions.v2", "data": {}},
            {"label": "c2pa.hash.data", "data": {}},
            {"label": "harpocrates.registry.v1", "data": {}},
        ]
        with self.assertRaisesRegex(vc.FixtureError, "harpocrates.export.v1"):
            vc.structure_checks(json.dumps(parsed))

    def test_structure_checks_reject_signing_by_exporter(self) -> None:
        parsed = json.loads(self.expected)
        for assertion in parsed["assertions"]:
            if assertion["label"] == "harpocrates.export.v1":
                assertion["data"]["unsigned"] = False
        with self.assertRaisesRegex(vc.FixtureError, "unsigned"):
            vc.structure_checks(json.dumps(parsed))

    def test_canonical_json_sorts_keys(self) -> None:
        lowered = json.loads(vc.canonical_json({"b": 2, "a": 1}).decode("utf-8"))
        self.assertEqual(list(lowered), ["a", "b"])

    def test_expected_labels_present(self) -> None:
        parsed = json.loads(self.expected)
        labels = {a.get("label") for a in parsed["assertions"]}
        self.assertTrue(vc.EXPECTED_LABELS <= labels)


if __name__ == "__main__":
    unittest.main()