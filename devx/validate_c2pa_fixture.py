#!/usr/bin/env python3
"""Validate the committed C2PA authenticity-assertion export fixture.

The export must be deterministic, privacy-safe, and byte-identical to the
committed ``expected-export.json``. Regeneration runs the built headless CLI
(``node cli/dist/cli.js c2pa``). Run ``npm ci && npm run build`` in ``cli/``
first. The fixture and the validator never use real media, credentials,
witnesses, or private keys.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "devx" / "fixtures" / "c2pa"
DEFAULT_MANIFEST = FIXTURE_DIR / "manifest.json"
DEFAULT_RECEIPT = FIXTURE_DIR / "receipt.json"
DEFAULT_EXPECTED = FIXTURE_DIR / "expected-export.json"
CLI = ROOT / "cli" / "dist" / "cli.js"
MAX_EXPORT_BYTES = 256 * 1024
EXPECTED_LABELS = {
    "c2pa.actions.v2",
    "c2pa.hash.data",
    "harpocrates.export.v1",
    "harpocrates.registry.v1",
}

SENSITIVE_PATTERNS = [
    re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
    re.compile(r"credentialsecret", re.I),
    re.compile(r"nullifiersecret", re.I),
    re.compile(r"private[_-]?key", re.I),
    re.compile(r"sign[_-]?cert", re.I),
]

FORBIDDEN_KEYS = {
    "credentialsecret",
    "nullifiersecret",
    "privatekey",
    "signcert",
    "publicinputs",
    "proof",
    "witness",
    "authorization",
}

DEFAULT_LABELS = {"c2pa.actions.v2", "c2pa.hash.data"}


class FixtureError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _normalize_key(key: object) -> str:
    return "".join(c for c in str(key).lower() if c.isalnum())


def assert_privacy_safe(payload: str) -> None:
    """Fail if the export appears to carry secrets, witnesses, or keys."""
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(payload):
            raise FixtureError(
                f"export leaked sensitive pattern {pattern.pattern}"
            )

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise FixtureError(f"expected export is not valid JSON: {exc}") from exc

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if _normalize_key(key) in FORBIDDEN_KEYS:
                    # Stable messages may embed labels, never raw values.
                    if isinstance(item, str) and len(item) >= 8:
                        raise FixtureError(f"export echoed sensitive key {key}")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(parsed)


def structure_checks(payload: str) -> None:
    if len(payload) > MAX_EXPORT_BYTES:
        raise FixtureError(f"export exceeds the {MAX_EXPORT_BYTES // 1024} KiB output limit")
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise FixtureError("expected export must be a JSON object")
    if parsed.get("claim_generator") != "harpocrates-cli/c2pa":
        raise FixtureError("expected export claim_generator is invalid")
    if parsed.get("format") != "application/json":
        raise FixtureError("expected export format is invalid")

    assertions = parsed.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise FixtureError("expected export must carry a non-empty assertions array")
    labels = {a.get("label") for a in assertions if isinstance(a, dict)}
    missing = {required for required in EXPECTED_LABELS if required not in labels}
    if missing:
        raise FixtureError(f"expected export is missing required assertions: {sorted(missing)}")
    if not (DEFAULT_LABELS <= labels):
        raise FixtureError("expected export must carry the standard C2PA assertions")

    export_assertions = [a for a in assertions if a.get("label") == "harpocrates.export.v1"]
    if len(export_assertions) != 1:
        raise FixtureError("expected export must carry exactly one harpocrates.export.v1 assertion")
    data = export_assertions[0].get("data") or {}
    if data.get("unsigned") is not True:
        raise FixtureError("expected export must declare unsigned=true (exporter never signs)")

    verification = [a for a in assertions if a.get("label") == "harpocrates.verification.v1"]
    if len(verification) != 1:
        raise FixtureError("fixture receipt must produce one verification assertion")
    result = (verification[0].get("data") or {}).get("result")
    if result != "valid":
        raise FixtureError(f"fixture verification assertion result is unexpected: {result}")


def run_export() -> bytes:
    if not CLI.is_file():
        raise FixtureError(
            f"built CLI not found at {CLI}; run: cd cli && npm ci && npm run build"
        )
    command = [
        "node", str(CLI), "c2pa",
        "--manifest", str(DEFAULT_MANIFEST),
        "--receipt", str(DEFAULT_RECEIPT),
    ]
    completed = subprocess.run(command, capture_output=True, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise FixtureError(f"c2pa export failed: {stderr}")
    return completed.stdout


def validate(expected_path: Path) -> None:
    expected = expected_path.read_bytes()

    first = run_export()
    second = run_export()
    if first != second:
        raise FixtureError("c2pa export is not deterministic across runs")

    payload = first.decode("utf-8")
    assert_privacy_safe(payload)
    structure_checks(payload)

    if first != expected:
        raise FixtureError(
            "c2pa export drifted from the committed fixture; regenerate with "
            "python3 devx/validate_c2pa_fixture.py --write"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected",
        type=Path,
        default=DEFAULT_EXPECTED,
        help="Committed expected export to compare against",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the committed expected export instead of comparing",
    )
    args = parser.parse_args(argv)

    try:
        rendered = run_export()
    except FixtureError as exc:
        print(f"c2pa fixture failed: {exc}", file=sys.stderr)
        return 1

    if args.write:
        args.expected.write_bytes(rendered)
        print(
            f"c2pa fixture regenerated: {args.expected} "
            f"({len(rendered)} bytes, sha256={sha256_bytes(rendered)[:16]}…)"
        )
        return 0

    try:
        validate(args.expected.resolve())
    except FixtureError as exc:
        print(f"c2pa fixture failed: {exc}", file=sys.stderr)
        return 1
    print(
        "c2pa fixture passed: deterministic, privacy-safe, and byte-identical "
        "to the committed export"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())