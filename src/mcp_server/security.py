from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class McpAuthConfig:
    """
    Auth and integrity settings for MCP.

    auth_token
    Shared bearer token for caller identity.

    hmac_secret
    Shared secret used to sign request bodies.

    allowed_clock_skew_seconds
    Server acceptance window for timestamp drift.
    """

    auth_token: str
    hmac_secret: str
    allowed_clock_skew_seconds: int = 60


def compute_signature(
    *,
    secret: str,
    timestamp: str,
    nonce: str,
    body_bytes: bytes,
) -> str:
    """
    Compute a stable HMAC signature.

    We sign a canonical byte string:
    timestamp newline nonce newline sha256(body)

    Returning lowercase hex string.
    """
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode()
    mac = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256)
    return mac.hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_header(headers: dict[str, str], key: str) -> str:
    value = headers.get(key, "")
    if not value:
        raise ValueError(f"missing header {key}")
    return value


def parse_bearer_token(auth_header: str) -> str:
    """
    Parse Authorization: Bearer TOKEN
    """
    parts = auth_header.split()
    if len(parts) != 2:
        raise ValueError("invalid authorization header")
    if parts[0].lower() != "bearer":
        raise ValueError("invalid authorization scheme")
    if not parts[1]:
        raise ValueError("empty token")
    return parts[1]


def headers_to_dict(raw_headers: Any) -> dict[str, str]:
    """
    Convert BaseHTTPRequestHandler headers into a plain dict.
    """
    out: dict[str, str] = {}
    for k in raw_headers.keys():
        out[str(k)] = str(raw_headers.get(k))
    return out
