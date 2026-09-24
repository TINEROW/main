from __future__ import annotations

import datetime
import functools
import hashlib
from typing import Any, Optional, Tuple

from flask import Response, jsonify, request

from db import Jsonb, get_connection


# Table: idempotency_records
# Columns:
#   id SERIAL PRIMARY KEY
#   request_digest TEXT NOT NULL
#   request_type TEXT NOT NULL
#   created_at TIMESTAMPTZ NOT NULL DEFAULT now()
#   expires_at TIMESTAMPTZ NOT NULL
#   status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED'))
#   response_payload JSONB NULL
#   error_payload JSONB NULL
#   UNIQUE (request_digest, request_type)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _default_expiry(window_seconds: int = 86400) -> datetime.datetime:
    return _now() + datetime.timedelta(seconds=window_seconds)


def _db_available() -> bool:
    """Return True when persistence is configured for idempotency records."""
    try:
        from db import database_url

        return bool(database_url())
    except Exception:
        return False


def create_idempotency_record(
    request_digest: str, request_type: str, expires_at: Optional[datetime.datetime] = None
) -> Tuple[int, str]:
    """Insert a new idempotency record with status PENDING.

    Returns (record_id, status). If a record already exists, returns its id and current status.
    """
    if expires_at is None:
        expires_at = _default_expiry()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO idempotency_records (request_digest, request_type, expires_at, status)
                VALUES (%s, %s, %s, 'PENDING')
                ON CONFLICT (request_digest, request_type) DO UPDATE SET status = idempotency_records.status
                RETURNING id, status;
                """,
                (request_digest, request_type, expires_at),
            )
            row = cur.fetchone()
            conn.commit()
            return int(row["id"]), row["status"]


def get_idempotency_record(request_digest: str, request_type: str) -> Optional[dict]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM idempotency_records WHERE request_digest = %s AND request_type = %s",
                (request_digest, request_type),
            )
            row = cur.fetchone()
            if row:
                return dict(row)
            return None


def store_response(record_id: int, payload: Any) -> None:
    """Store a successful response payload and mark record as COMPLETED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'COMPLETED', response_payload = %s, error_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(payload), record_id),
            )
            conn.commit()


def store_error(record_id: int, error: dict) -> None:
    """Store an error payload and mark record as FAILED."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE idempotency_records
                SET status = 'FAILED', error_payload = %s, response_payload = NULL
                WHERE id = %s;
                """,
                (Jsonb(error), record_id),
            )
            conn.commit()


def clear_idempotency_record(record_id: int) -> None:
    """Remove a PENDING record so a later retry can re-acquire the lock."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM idempotency_records WHERE id = %s AND status = 'PENDING'",
                (record_id,),
            )
            conn.commit()


def _canonical_digest() -> str:
    """SHA-256 of method, path, query string, and raw body (canonical request identity)."""
    method = request.method.encode()
    path = request.path.encode()
    query = request.query_string  # already bytes
    body = request.get_data() or b""
    data = b"|".join([method, path, query, body])
    return hashlib.sha256(data).hexdigest()


def _extract_response_parts(result: Any) -> tuple[Any, int]:
    """Normalize a Flask view result into (json_body_or_none, status_code)."""
    status = 200
    data = result

    if isinstance(result, tuple):
        data = result[0]
        if len(result) >= 2 and isinstance(result[1], int):
            status = result[1]

    if isinstance(data, Response):
        # Prefer explicit tuple status when provided: return jsonify(x), 201
        if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], int):
            status = result[1]
        else:
            status = data.status_code
        body = data.get_json(silent=True)
        return body, status

    if isinstance(data, (dict, list)):
        return data, status

    return None, status


def _replay_stored(record: dict):
    status = record.get("status")
    if status == "COMPLETED":
        payload = record.get("response_payload") or {}
        if isinstance(payload, dict) and "body" in payload and "status" in payload:
            body = payload.get("body")
            code = int(payload.get("status") or 200)
            if body is None:
                return Response(status=code)
            return jsonify(body), code
        # Legacy: bare JSON body stored without status wrapper
        return jsonify(payload), 200
    if status == "FAILED":
        error = record.get("error_payload") or {"error": "previous request failed"}
        code = 500
        if isinstance(error, dict) and isinstance(error.get("status"), int):
            code = error["status"]
            error = {k: v for k, v in error.items() if k != "status"}
        return jsonify(error), code
    # PENDING – another request is currently processing
    return jsonify({"error": "duplicate request in progress"}), 409


def idempotent(request_type: str):
    """Flask view decorator to enforce idempotent request handling.

    Uses a canonical request digest. Completed records replay the stored JSON
    body and HTTP status. Pending records return 409. When DATABASE_URL is
    unset (local/unit tests), the decorator is a no-op so callers still rely
    on semantic upsert idempotency in the register path.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not _db_available():
                return func(*args, **kwargs)

            digest = _canonical_digest()
            record = get_idempotency_record(digest, request_type)
            if record:
                return _replay_stored(record)

            record_id, status = create_idempotency_record(digest, request_type)
            if status != "PENDING":
                # Lost the race to another worker that already finished (or is in flight).
                existing = get_idempotency_record(digest, request_type) or {
                    "status": status,
                    "response_payload": None,
                    "error_payload": None,
                }
                return _replay_stored(existing)

            try:
                result = func(*args, **kwargs)
                body, code = _extract_response_parts(result)
                if 200 <= code < 500:
                    # Cache 2xx and stable 4xx for exact replay (no raw media/secrets).
                    store_response(record_id, {"status": code, "body": body})
                else:
                    # Do not cache server failures — allow a later retry to re-acquire.
                    clear_idempotency_record(record_id)
                return result
            except Exception:
                # Privacy-safe: never persist exception strings (may contain paths/secrets).
                store_error(record_id, {"error": "request processing failed", "status": 500})
                raise

        return wrapper

    return decorator
