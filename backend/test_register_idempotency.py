"""Focused coverage for proof-registration idempotency.

Covers:
- SQL parameter alignment for upsert_register_event (boundary / regression)
- Request-layer decorator status replay and no-DB passthrough
- Semantic idempotency key derivation (positive / negative)
"""

from __future__ import annotations

import ast
import inspect
import re
import unittest
from unittest.mock import MagicMock, patch

from db import make_idempotency_key, upsert_register_event
import idempotency as idem_mod


class UpsertRegisterSqlAlignmentTest(unittest.TestCase):
    """Regression: INSERT placeholders must match column list (was 14 vs 16)."""

    def test_upsert_register_event_values_match_columns(self) -> None:
        source = inspect.getsource(upsert_register_event)
        cols_match = re.search(r"insert into proof_events\s*\(([^)]+)\)", source, re.I | re.S)
        vals_match = re.search(r"values\s*\(([^)]+)\)", source, re.I | re.S)
        self.assertIsNotNone(cols_match)
        self.assertIsNotNone(vals_match)
        columns = [c.strip() for c in cols_match.group(1).split(",") if c.strip()]
        placeholders = vals_match.group(1).count("%s")
        self.assertEqual(len(columns), placeholders)
        self.assertIn("idempotency_key", columns)
        self.assertIn("claimed_capture_time", columns)
        self.assertEqual(len(columns), 16)


class IdempotencyKeyTest(unittest.TestCase):
    def test_positive_deterministic(self) -> None:
        a = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        b = make_idempotency_key("aa" * 32, "bb" * 32, "cc" * 32)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_negative_differs_on_proof_id(self) -> None:
        a = make_idempotency_key("aa" * 32, "bb" * 32, None)
        b = make_idempotency_key("aa" * 32, "ff" * 32, None)
        self.assertNotEqual(a, b)

    def test_boundary_none_tx_equals_empty(self) -> None:
        self.assertEqual(
            make_idempotency_key("aa" * 32, "bb" * 32, None),
            make_idempotency_key("aa" * 32, "bb" * 32, ""),
        )


class IdempotentDecoratorTest(unittest.TestCase):
    def test_no_db_passthrough(self) -> None:
        calls = []

        @idem_mod.idempotent("register")
        def view():
            calls.append(1)
            return {"ok": True}, 201

        with patch.object(idem_mod, "_db_available", return_value=False):
            result = view()
        self.assertEqual(result, ({"ok": True}, 201))
        self.assertEqual(calls, [1])

    def test_completed_replay_preserves_status(self) -> None:
        @idem_mod.idempotent("register")
        def view():
            raise AssertionError("handler must not run on replay")

        stored = {
            "status": "COMPLETED",
            "response_payload": {
                "status": 201,
                "body": {"ok": True, "created": True, "db_event": {"id": 7}},
            },
        }
        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "_canonical_digest", return_value="abc"
        ), patch.object(idem_mod, "get_idempotency_record", return_value=stored):
            # jsonify needs an app context
            from app import app

            with app.app_context():
                result = view()
        self.assertIsInstance(result, tuple)
        response, status = result
        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["db_event"]["id"], 7)

    def test_pending_returns_409(self) -> None:
        @idem_mod.idempotent("register")
        def view():
            raise AssertionError("handler must not run while pending")

        with patch.object(idem_mod, "_db_available", return_value=True), patch.object(
            idem_mod, "_canonical_digest", return_value="abc"
        ), patch.object(
            idem_mod, "get_idempotency_record", return_value={"status": "PENDING"}
        ):
            from app import app

            with app.app_context():
                result = view()
        response, status = result
        self.assertEqual(status, 409)
        self.assertIn("duplicate", response.get_json()["error"])

    def test_extract_preserves_201_from_tuple(self) -> None:
        from flask import jsonify
        from app import app

        with app.app_context():
            body, code = idem_mod._extract_response_parts((jsonify({"ok": True}), 201))
        self.assertEqual(code, 201)
        self.assertEqual(body, {"ok": True})


if __name__ == "__main__":
    unittest.main()
