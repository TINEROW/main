"""Focused per-client upload rate-limit tests (issue #269).

Each test builds a fresh Flask app backed by a fresh in-memory rate-limit
store, so burst assertions are deterministic and need no wall-clock sleeps.
All payloads are synthetic; no real media, secrets, or credentials are used.
"""
from __future__ import annotations

import io
import json
import os
import unittest

# Configure tight limits BEFORE the app module is imported/reloaded so the
# freshly created Limiter picks them up.
os.environ.setdefault("RATELIMIT_ENABLED", "true")
os.environ["RATELIMIT_UPLOAD_SESSION"] = "2 per minute"
os.environ["RATELIMIT_UPLOAD_CHUNK"] = "2 per minute"
os.environ["RATELIMIT_EMBED"] = "2 per minute"
os.environ["RATELIMIT_STORAGE_URI"] = "memory://"
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("NOIR_WORKER_ENABLED", "false")
os.environ.setdefault("TRUSTED_PROXIES", "")


def _make_fresh_app():
    """Return ``(app, client)`` with an isolated in-memory rate-limit store."""
    import importlib
    import app as app_module
    importlib.reload(app_module)
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app, flask_app.test_client()


def _chunk_file():
    return (io.BytesIO(b"\x00" * 16), "chunk.bin", "application/octet-stream")


def _assert_throttled(case, response):
    """Assert a 429 carries the stable, privacy-safe rate-limit envelope."""
    case.assertEqual(response.status_code, 429)
    body = response.get_json()
    case.assertIsInstance(body, dict)
    case.assertIn("error", body)
    case.assertEqual(body["error"]["code"], "RATE_LIMITED")
    case.assertIn("request_id", body["error"])
    case.assertIn("Retry-After", response.headers)
    case.assertTrue(response.headers["Retry-After"].strip().isdigit())
    case.assertIn("X-Request-ID", response.headers)


class UploadSessionRateLimitTest(unittest.TestCase):
    """POST /api/stego/upload-session - 2/min per client."""

    def setUp(self):
        self.app, self.client = _make_fresh_app()

    def test_within_limit_is_allowed(self):
        for _ in range(2):
            response = self.client.post("/api/stego/upload-session")
            self.assertEqual(response.status_code, 200)
            self.assertNotEqual(response.status_code, 429)

    def test_burst_is_throttled(self):
        for _ in range(2):
            self.client.post("/api/stego/upload-session")
        _assert_throttled(self, self.client.post("/api/stego/upload-session"))

    def test_rate_limit_headers_are_exposed(self):
        response = self.client.post("/api/stego/upload-session")
        self.assertEqual(response.headers.get("X-RateLimit-Limit"), "2")

    def test_spoofed_forwarded_for_cannot_bypass(self):
        for _ in range(2):
            self.client.post(
                "/api/stego/upload-session",
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
        response = self.client.post(
            "/api/stego/upload-session",
            headers={"X-Forwarded-For": "203.0.113.11"},
        )
        self.assertEqual(response.status_code, 429)


class UploadChunkRateLimitTest(unittest.TestCase):
    """PUT /api/stego/upload-session/<id>/chunk/<n> - 2/min per client."""

    def setUp(self):
        os.environ["RATELIMIT_UPLOAD_SESSION"] = "100 per minute"
        self.app, self.client = _make_fresh_app()
        os.environ["RATELIMIT_UPLOAD_SESSION"] = "2 per minute"
        session = self.client.post("/api/stego/upload-session")
        self.assertEqual(session.status_code, 200)
        self.session_id = session.get_json()["sessionId"]

    def _put_chunk(self, index, xff=None):
        headers = {"X-Forwarded-For": xff} if xff else {}
        return self.client.put(
            "/api/stego/upload-session/%s/chunk/%d" % (self.session_id, index),
            data={"chunk": _chunk_file()},
            content_type="multipart/form-data",
            headers=headers,
        )

    def test_within_limit_is_allowed(self):
        for index in range(2):
            response = self._put_chunk(index)
            self.assertNotEqual(response.status_code, 429)

    def test_burst_is_throttled(self):
        for index in range(2):
            self._put_chunk(index)
        _assert_throttled(self, self._put_chunk(2))


class UploadEmbedRateLimitTest(unittest.TestCase):
    """POST /api/stego/embed - 2/min per client (video upload path)."""

    def setUp(self):
        self.app, self.client = _make_fresh_app()

    def _post_embed(self, xff=None):
        headers = {"X-Forwarded-For": xff} if xff else {}
        return self.client.post(
            "/api/stego/embed",
            data={
                "metadata": json.dumps(
                    {
                        "protocol": "harpocrates",
                        "version": 1,
                        "tier": "silent",
                        "sourceHash": "11" * 32,
                        "proofId": "22" * 32,
                        "timestamp": "2026-06-18T00:00:00.000Z",
                    }
                ),
                "video": (io.BytesIO(b"\x00" * 16), "test.mp4", "video/mp4"),
            },
            content_type="multipart/form-data",
            headers=headers,
        )

    def test_within_limit_is_allowed(self):
        for _ in range(2):
            self.assertNotEqual(self._post_embed().status_code, 429)

    def test_burst_is_throttled(self):
        for _ in range(2):
            self._post_embed()
        _assert_throttled(self, self._post_embed())

    def test_spoofed_forwarded_for_cannot_bypass(self):
        for _ in range(2):
            self._post_embed(xff="203.0.113.1")
        self.assertEqual(self._post_embed(xff="203.0.113.2").status_code, 429)


if __name__ == "__main__":
    unittest.main()
