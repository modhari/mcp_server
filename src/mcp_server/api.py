from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from mcp_server.capabilities.trace_ecmp import trace_ecmp_path


class MCPRequestHandler(BaseHTTPRequestHandler):
    """
    MCP (Model Control Plane) HTTP handler.

    Responsibilities:
    - Enforce auth boundary
    - Route MCP methods
    - Act as policy + capability execution layer
    """

    def log_message(self, format: str, *args: Any) -> None:
        """
        Disable default HTTP logging to keep logs focused.
        """
        return

    def do_POST(self) -> None:
        """
        Handle POST requests sent to the MCP endpoint.
        """
        if self.path != "/mcp":
            self._send_json(self._error("not_found", "unknown endpoint"))
            return

        auth_header = self.headers.get("Authorization")
        if not auth_header:
            self._send_json(
                self._error("validation_error", "missing Authorization header")
            )
            return

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            request = json.loads(raw_body)
        except Exception:
            self._send_json(
                self._error("invalid_json", "unable to parse request body")
            )
            return

        print("=== MCP REQUEST ===", flush=True)
        print(request, flush=True)
        print("===================", flush=True)

        method = request.get("method")

        if method == "evaluate_plan":
            response = self._handle_evaluate_plan(request)
        elif method == "trace_ecmp_path":
            response = self._handle_trace_ecmp_path(request)
        else:
            response = self._error(
                "not_implemented",
                f"unsupported method {method}",
                request,
            )

        self._send_json(response)

    def _handle_trace_ecmp_path(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the ECMP trace capability.

        Expected params:
        {
            "source": "leaf-01",
            "destination": "leaf-02",
            "mode": "data_plane",
            "flow": {
                "src_ip": "1.1.1.1",
                "dst_ip": "10.1.1.1",
                "src_port": 12345,
                "dst_port": 443,
                "protocol": "tcp"
            }
        }
        """
        params = request.get("params", {})

        source = str(params.get("source", ""))
        destination = str(params.get("destination", ""))
        mode = str(params.get("mode", "data_plane"))
        flow = params.get("flow", {})

        if not source:
            return self._error(
                "validation_error",
                "missing required field source",
                request,
            )

        if not destination:
            return self._error(
                "validation_error",
                "missing required field destination",
                request,
            )

        try:
            result = trace_ecmp_path(
                source=source,
                destination=destination,
                flow=flow if isinstance(flow, dict) else {},
                mode=mode,
            )

            return {
                "api_version": "v1",
                "request_id": request.get("request_id", "unknown"),
                "ok": True,
                "result": result,
            }

        except Exception as exc:
            return {
                "api_version": "v1",
                "request_id": request.get("request_id", "unknown"),
                "ok": False,
                "error": {
                    "code": "trace_failed",
                    "message": str(exc),
                },
            }

    def _handle_evaluate_plan(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministic plan risk evaluation logic.
        """
        params = request.get("params", {})
        plan = params.get("plan", {})
        inventory = params.get("inventory", {})

        actions = plan.get("actions", [])
        devices = inventory.get("devices", [])

        touched_devices = {a.get("device") for a in actions if "device" in a}
        device_index = {d.get("name"): d for d in devices if isinstance(d, dict)}

        blast_radius = 0
        reasons: list[str] = []

        touches_bgp = False

        for action in actions:
            device = action.get("device", "unknown")
            paths = action.get("model_paths", {})

            for path, value in paths.items():
                path_str = str(path)

                if "interfaces/interface" in path_str:
                    blast_radius += 10
                    reasons.append("interface configuration change detected")

                if "bgp/neighbors" in path_str:
                    touches_bgp = True
                    blast_radius += 30
                    reasons.append("plan modifies bgp related model paths")

                    if value is False:
                        blast_radius += 10
                        reasons.append("bgp neighbor disable requested")

            role = str(device_index.get(device, {}).get("role", "unknown"))

            if role == "spine":
                blast_radius += 20
                reasons.append("plan touches spine tier")

                if touches_bgp:
                    blast_radius += 20
                    reasons.append(
                        "spine + bgp change increases blast radius significantly"
                    )

        requires_approval = blast_radius >= 50

        if blast_radius >= 50:
            risk_level = "high"
        elif blast_radius >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "api_version": "v1",
            "request_id": request.get("request_id", "unknown"),
            "ok": True,
            "result": {
                "risk_level": risk_level,
                "blast_radius_score": blast_radius,
                "requires_approval": requires_approval,
                "reasons": reasons,
            },
        }

    def _send_json(self, payload: Dict[str, Any]) -> None:
        """
        Send JSON response to the client.
        """
        data = json.dumps(payload).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()

        self.wfile.write(data)

    def _error(
        self,
        code: str,
        message: str,
        request: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """
        Build a standard MCP error response.
        """
        return {
            "api_version": "v1",
            "request_id": (request or {}).get("request_id", "unknown"),
            "ok": False,
            "error": {
                "code": code,
                "message": message,
            },
        }


def run_server() -> None:
    """
    MCP server entrypoint.
    """
    server = HTTPServer(("0.0.0.0", 8080), MCPRequestHandler)
    print("mcp server listening on http://0.0.0.0:8080/mcp", flush=True)
    server.serve_forever()
