"""Subresource Integrity: parse an integrity attribute and check it against a body.

Follows the W3C SRI rules: unknown algorithms are ignored, only the
strongest algorithm present is compared, and any matching digest of that
algorithm makes the resource valid.
"""

from __future__ import annotations

import base64
import hashlib

ALGORITHMS = {"sha256": 1, "sha384": 2, "sha512": 3}

ABSENT = "absent"
VALID = "valid"
INVALID = "invalid"
MALFORMED = "malformed"
UNVERIFIED = "unverified"


def sri_hash(body: bytes, algorithm: str = "sha384") -> str:
    """Integrity token for ``body``, e.g. ``sha384-oqVu...``."""
    digest = hashlib.new(algorithm, body).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode('ascii')}"


def parse_integrity(value: str | None) -> list[tuple[str, str]]:
    """Return ``(algorithm, base64 digest)`` pairs with a known algorithm."""
    out = []
    for token in (value or "").split():
        algo, sep, rest = token.partition("-")
        if not sep or algo.lower() not in ALGORITHMS:
            continue
        digest = rest.split("?", 1)[0]
        if digest:
            out.append((algo.lower(), digest))
    return out


def _normalize(b64: str) -> str:
    return b64.replace("-", "+").replace("_", "/").rstrip("=")


def check_integrity(value: str | None, body: bytes | None) -> tuple[str, str]:
    """Check ``body`` against an integrity attribute.

    Returns ``(status, detail)`` where status is one of ``absent``,
    ``valid``, ``invalid``, ``malformed`` (attribute present but no usable
    hash, which browsers treat as no integrity) or ``unverified`` (the body
    could not be read).
    """
    if value is None or not value.strip():
        return ABSENT, ""
    tokens = parse_integrity(value)
    if not tokens:
        return MALFORMED, "no sha256/sha384/sha512 hash in the integrity attribute"
    if body is None:
        return UNVERIFIED, "response body not available"
    best = max(ALGORITHMS[a] for a, _ in tokens)
    algo = next(a for a, r in ALGORITHMS.items() if r == best)
    actual = sri_hash(body, algo)
    actual_digest = _normalize(actual.split("-", 1)[1])
    for a, digest in tokens:
        if a == algo and _normalize(digest) == actual_digest:
            return VALID, algo
    return INVALID, f"body hashes to {actual}"
