from __future__ import annotations

import json
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from mcp_server.audit import AuditLogger
from mcp_server.codec import (
    decode_request,
    encode_response_error,
    encode_response_ok,
)
from mcp_server.errors import McpValidationError
from mcp_server.replay import NonceStore
from mcp_server.schemas import McpApiVersion, McpMethod
from mcp_server.security import (
    McpAuthConfig,
    compute_signature,
    constant_time_equal,
    headers_to_dict,
    parse_bearer_token,
    require_header,
)

@dataclass(frozen=True)
class McpServerConfig:
    auth: McpAuthConfig
    audit_path: Path = Path("var/audit/mcp_audit.jsonl")
    nonce_ttl_seconds: int = 300


class McpHandler(BaseHTTPRequestHandler):
    server_version = "mcp/1.0"

    def _read_json_bytes(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        cfg: McpServerConfig = self.server.mcp_config  # type: ignore[attr-defined]
        audit: AuditLogger = self.server.mcp_audit  # type: ignore[attr-defined]
        nonces: NonceStore = self.server.mcp_nonces  # type: ignore[attr-defined]

        start = time.time()

        if self.path != "/mcp":
            self._send_json(
                404,
                encode_response_error(McpApiVersion.v1, "unknown", "not_found", "unknown endpoint"),
            )
            return

        request_id = "unknown"
        status_code = 500
        outcome = "error"
        err_code = "server_error"
        err_msg = "unknown"
        method = "unknown"

        try:
            headers = headers_to_dict(self.headers)

            auth_header = require_header(headers, "Authorization")
            token = parse_bearer_token(auth_header)
            if not constant_time_equal(token, cfg.auth.auth_token):
                raise McpValidationError("unauthorized")

            ts = require_header(headers, "X-MCP-Timestamp")
            nonce = require_header(headers, "X-MCP-Nonce")
            sig = require_header(headers, "X-MCP-Signature")

            now = int(time.time())
            ts_int = int(ts)
            skew = abs(now - ts_int)
            if skew > cfg.auth.allowed_clock_skew_seconds:
                raise McpValidationError("timestamp outside allowed skew window")

            if nonces.seen_recently(nonce):
                raise McpValidationError("replay detected")

            body_bytes = self._read_json_bytes()

            expected = compute_signature(
                secret=cfg.auth.hmac_secret,
                timestamp=ts,
                nonce=nonce,
                body_bytes=body_bytes,
            )
            if not constant_time_equal(sig, expected):
                raise McpValidationError("invalid signature")

            payload = json.loads(body_bytes.decode("utf-8"))
            req = decode_request(payload)

            request_id = req.request_id
            method = req.method.value

            if req.method != McpMethod.evaluate_plan:
                status_code = 400
                outcome = "reject"
                err_code = "unsupported_method"
                err_msg = "method not supported"
                self._send_json(
                    400,
                    encode_response_error(req.api_version, req.request_id, err_code, err_msg),
                )
                return

            plan = req.params.get("plan")
            inventory = req.params.get("inventory")

            if not isinstance(plan, dict):
                raise McpValidationError("params.plan must be an object")
            if not isinstance(inventory, dict):
                raise McpValidationError("params.inventory must be an object")

            risk = self._evaluate_plan_dicts(plan, inventory)

            status_code = 200
            outcome = "ok"
            self._send_json(
                200,
                encode_response_ok(req.api_version, req.request_id, risk),
            )

        except McpValidationError as exc:
            status_code = 400
            outcome = "reject"
            err_code = "validation_error"
            err_msg = str(exc)
            self._send_json(
                400,
                encode_response_error(McpApiVersion.v1, request_id, err_code, err_msg),
            )
        except Exception as exc:
            status_code = 500
            outcome = "error"
            err_code = "server_error"
            err_msg = str(exc)
            self._send_json(
                500,
                encode_response_error(McpApiVersion.v1, request_id, err_code, err_msg),
            )
        finally:
            duration_ms = int((time.time() - start) * 1000.0)
            audit.log(
                {
                    "request_id": request_id,
                    "method": method,
                    "http_status": status_code,
                    "outcome": outcome,
                    "error_code": err_code,
                    "error_message": err_msg,
                    "duration_ms": duration_ms,
                    "path": self.path,
                }
            )

    def _evaluate_plan_dicts(
        self, 
        plan: dict[str, Any], 
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        _ = plan
        _ = inventory
        return {
            "risk_level": "high",
            "blast_radius_score": 100,
            "requires_approval": True,
            "reasons": ["server adapter not yet bound to internal risk logic"],
            "evidence": {},
        }


class McpHttpServer(HTTPServer):
    def __init__(self, host: str, port: int, config: McpServerConfig) -> None:
        super().__init__((host, port), McpHandler)
        self.mcp_config = config
        self.mcp_audit = AuditLogger(path=config.audit_path)
        self.mcp_nonces = NonceStore(ttl_seconds=config.nonce_ttl_seconds)


def run_mcp_server(host: str, port: int, config: McpServerConfig) -> None:
    server = McpHttpServer(host, port, config)
    print(f"mcp server listening on http://{host}:{port}/mcp")
    server.serve_forever()
