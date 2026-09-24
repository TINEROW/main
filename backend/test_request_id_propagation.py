"""Focused tests for request-ID propagation through Flask responses.

Issue #265 asks that request IDs are propagated through Flask responses so a
caller can always correlate a response with the server logs that produced it.

These tests exercise the propagation layer in isolation: they build small
Flask applications and never import the heavyweight application module, so a
failure here always points at the propagation contract itself rather than at
unrelated application wiring.
"""

from __future__ import annotations

import json
import unittest

from flask import Flask, Response, jsonify

from errors import (
    error_response,
    init_request_id,
    ok_response,
    propagate_request_id,
    register_request_id_propagation,
)

FORWARDED_ID = "req-forwarded-1"


def _make_app(*, assign_request_id: bool = True) -> Flask:
    """Build a throwaway app wired with the request-id middleware."""
    app = Flask(__name__)
    if assign_request_id:
        init_request_id(app)
    register_request_id_propagation(app)

    @app.get("/object")
    def object_route():
        return jsonify({"ok": True, "events": []})

    @app.get("/list")
    def list_route():
        return jsonify(["a", "b"])

    @app.get("/text")
    def text_route():
        return Response("plain text body", mimetype="text/plain")

    @app.get("/binary")
    def binary_route():
        return Response(b"\x00\x01\x02video", mimetype="video/mp4")

    @app.get("/route-owned-id")
    def route_owned_id():
        # A handler that deliberately chooses its own request id wins.
        return jsonify({"ok": True, "request_id": "route-owned"})

    @app.get("/envelope-error")
    def envelope_error():
        return error_response(
            code="VALIDATION_ERROR",
            message="bad input",
            status=400,
        )

    @app.get("/envelope-ok")
    def envelope_ok():
        return ok_response({"events": []})

    @app.get("/no-content")
    def no_content():
        return Response(status=204)

    return app


class RequestIdPropagationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.app = _make_app()
        self.client = self.app.test_client()

    # ------------------------------------------------------------------
    # Success responses
    # ------------------------------------------------------------------

    def test_json_body_gains_request_id_and_matching_header(self) -> None:
        response = self.client.get("/object", headers={"X-Request-ID": FORWARDED_ID})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)
        self.assertEqual(response.json["request_id"], FORWARDED_ID)
        # The pre-existing payload is preserved.
        self.assertEqual(response.json["ok"], True)
        self.assertEqual(response.json["events"], [])

    def test_generated_request_id_is_consistent_between_header_and_body(self) -> None:
        response = self.client.get("/object")

        request_id = response.headers["X-Request-ID"]
        self.assertTrue(request_id)
        self.assertNotEqual(request_id, "unknown")
        self.assertEqual(response.json["request_id"], request_id)

    def test_distinct_requests_get_distinct_request_ids(self) -> None:
        first = self.client.get("/object")
        second = self.client.get("/object")

        self.assertNotEqual(
            first.headers["X-Request-ID"],
            second.headers["X-Request-ID"],
        )

    def test_content_length_matches_rewritten_body(self) -> None:
        response = self.client.get("/object")

        self.assertEqual(
            int(response.headers["Content-Length"]),
            len(response.data),
        )
        # The rewritten body must remain valid JSON.
        self.assertIsInstance(json.loads(response.data), dict)

    # ------------------------------------------------------------------
    # Error responses
    # ------------------------------------------------------------------

    def test_error_envelope_header_body_and_inner_id_all_agree(self) -> None:
        response = self.client.get(
            "/envelope-error",
            headers={"X-Request-ID": FORWARDED_ID},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)
        self.assertEqual(response.json["request_id"], FORWARDED_ID)
        self.assertEqual(response.json["error"]["request_id"], FORWARDED_ID)
        self.assertEqual(response.json["ok"], False)
        self.assertEqual(response.json["error"]["code"], "VALIDATION_ERROR")

    def test_error_status_is_not_altered_by_propagation(self) -> None:
        response = self.client.get("/envelope-error")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"]["message"], "bad input")

    def test_ok_envelope_keeps_single_top_level_request_id(self) -> None:
        response = self.client.get(
            "/envelope-ok",
            headers={"X-Request-ID": FORWARDED_ID},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["request_id"], FORWARDED_ID)
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    # ------------------------------------------------------------------
    # Bodies that must not be rewritten
    # ------------------------------------------------------------------

    def test_route_owned_request_id_is_never_overwritten(self) -> None:
        response = self.client.get(
            "/route-owned-id",
            headers={"X-Request-ID": FORWARDED_ID},
        )

        self.assertEqual(response.json["request_id"], "route-owned")
        # The header still reflects the correlation id for this request.
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    def test_json_list_body_is_left_untouched(self) -> None:
        response = self.client.get("/list", headers={"X-Request-ID": FORWARDED_ID})

        self.assertEqual(response.json, ["a", "b"])
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    def test_text_body_is_left_untouched(self) -> None:
        response = self.client.get("/text", headers={"X-Request-ID": FORWARDED_ID})

        self.assertEqual(response.data, b"plain text body")
        self.assertEqual(response.mimetype, "text/plain")
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    def test_binary_body_is_left_untouched(self) -> None:
        response = self.client.get("/binary", headers={"X-Request-ID": FORWARDED_ID})

        self.assertEqual(response.data, b"\x00\x01\x02video")
        self.assertEqual(response.mimetype, "video/mp4")
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    def test_no_content_response_only_gains_the_header(self) -> None:
        response = self.client.get("/no-content", headers={"X-Request-ID": FORWARDED_ID})

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.data, b"")
        self.assertEqual(response.headers["X-Request-ID"], FORWARDED_ID)

    # ------------------------------------------------------------------
    # Degraded / direct use
    # ------------------------------------------------------------------

    def test_propagation_without_assignment_hook_still_correlates(self) -> None:
        client = _make_app(assign_request_id=False).test_client()

        response = client.get("/object")

        self.assertNotEqual(response.headers["X-Request-ID"], "unknown")
        self.assertEqual(
            response.json["request_id"],
            response.headers["X-Request-ID"],
        )

    def test_propagate_request_id_accepts_explicit_identifier(self) -> None:
        app = Flask(__name__)

        with app.test_request_context("/object"):
            response = propagate_request_id(
                jsonify({"ok": True}),
                identifier="explicit-id",
            )

            self.assertEqual(response.headers["X-Request-ID"], "explicit-id")
            self.assertEqual(response.get_json()["request_id"], "explicit-id")

    def test_propagation_hook_is_registered_exactly_once(self) -> None:
        app = _make_app()

        self.assertEqual(len(app.after_request_funcs[None]), 1)


if __name__ == "__main__":
    unittest.main()
