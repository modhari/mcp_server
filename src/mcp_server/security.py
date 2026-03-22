from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from mcp_server.errors import McpValidationError


@dataclass(frozen=True)
class McpAuthConfig:
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
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode()
    mac = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256)
    return mac.hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_header(headers: dict[str, str], key: str) -> str:
    value = headers.get(key.lower(), "")
    if not value:
        raise McpValidationError(f"missing header {key}")
    return value


def parse_bearer_token(auth_header: str) -> str:
    parts = auth_header.split()
    if len(parts) != 2:
        raise McpValidationError("invalid authorization header")
    if parts[0].lower() != "bearer":
        raise McpValidationError("invalid authorization scheme")
    if not parts[1]:
        raise McpValidationError("empty token")
    return parts[1]


def headers_to_dict(raw_headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for k in raw_headers.keys():
        out[str(k).lower()] = str(raw_headers.get(k))
    return out
