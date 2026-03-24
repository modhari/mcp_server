from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict


class MCPRequestHandler(BaseHTTPRequestHandler):
    """
    MCP (Model Control Plane) HTTP handler.

    Responsibilities:
    - Enforce security boundary (Authorization header)
    - Parse incoming requests from lattice
    - Evaluate plan risk
    - Return structured risk decisions

    This service acts as a policy and safety layer between:
    lattice (execution engine)
    and
    the network infrastructure
    """

    def log_message(self, format: str, *args: Any) -> None:
        """
        Disable default HTTP logging to keep logs clean.
        """
        return

    def do_POST(self) -> None:
        """
        Handle POST requests.

        Expected endpoint:
        /mcp

        This is the main evaluation interface used by lattice.
        """

        # ---------------------------------------------------------
        # Validate endpoint
        # ---------------------------------------------------------
        if self.path != "/mcp":
            self._send_json(
                {
                    "api_version": "v1",
                    "request_id": "unknown",
                    "ok": False,
                    "error": {
                        "code": "not_found",
                        "message": "unknown endpoint",
                    },
                }
            )
            return

        # ---------------------------------------------------------
        # Validate auth boundary
        # ---------------------------------------------------------
        auth_header = self.headers.get("Authorization")
        if not auth_header:
            self._send_json(
                {
                    "api_version": "v1",
                    "request_id": "unknown",
                    "ok": False,
                    "error": {
                        "code": "validation_error",
                        "message": "missing header Authorization",
                    },
                }
            )
            return

        # ---------------------------------------------------------
        # Read request body
        # ---------------------------------------------------------
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        try:
            request = json.loads(raw_body)
        except Exception:
            self._send_json(
                {
                    "api_version": "v1",
                    "request_id": "unknown",
                    "ok": False,
                    "error": {
                        "code": "invalid_json",
                        "message": "unable to parse request body",
                    },
                }
            )
            return

        # ---------------------------------------------------------
        # Debug logging
        # ---------------------------------------------------------
        print("=== MCP REQUEST ===", flush=True)
        print(request, flush=True)
        print("===================", flush=True)

        method = request.get("method")

        # ---------------------------------------------------------
        # Route request
        # ---------------------------------------------------------
        if method == "evaluate_plan":
            response = self._handle_evaluate_plan(request)
        else:
            response = {
                "api_version": "v1",
                "request_id": request.get("request_id", "unknown"),
                "ok": False,
                "error": {
                    "code": "not_implemented",
                    "message": f"unsupported method {method}",
                },
            }

        self._send_json(response)

    def _handle_evaluate_plan(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core risk evaluation logic.

        Target classification behavior:
        - interface_enable on leaf → low
        - leaf_bgp_disable → medium
        - spine_bgp_disable → high (requires approval)

        The model evaluates:
        - configuration paths touched
        - protocol impact (BGP, OSPF, external)
        - topology role impact (leaf vs spine vs super spine)
        - device count
        """

        params = request.get("params", {})
        plan = params.get("plan", {})
        inventory = params.get("inventory", {})

        actions = plan.get("actions", [])
        devices = inventory.get("devices", [])

        # ---------------------------------------------------------
        # Build lookup structures
        # ---------------------------------------------------------
        touched_devices = {a.get("device") for a in actions if "device" in a}
        device_index = {d.get("name"): d for d in devices if isinstance(d, dict)}

        # ---------------------------------------------------------
        # Initialize scoring variables
        # ---------------------------------------------------------
        blast_radius = 0
        reasons: list[str] = []

        touches_bgp = False
        touches_ospf = False
        touches_external = False

        role_counts = {
            "leaf": 0,
            "spine": 0,
            "super_spine": 0,
            "unknown": 0,
        }

        # ---------------------------------------------------------
        # Analyze each action in the plan
        # ---------------------------------------------------------
        for action in actions:
            device = action.get("device", "unknown")
            paths = action.get("model_paths", {})

            for path, value in paths.items():
                path_str = str(path)

                # -----------------------------
                # Interface changes → low risk
                # -----------------------------
                if "interfaces/interface" in path_str:
                    blast_radius += 10
                    reasons.append("interface configuration change detected")

                # -----------------------------
                # BGP changes → higher risk
                # -----------------------------
                if "bgp/neighbors" in path_str:
                    touches_bgp = True
                    blast_radius += 30
                    reasons.append("plan modifies bgp related model paths")

                    if value is False:
                        blast_radius += 10
                        reasons.append("bgp neighbor disable requested")

                # -----------------------------
                # OSPF changes
                # -----------------------------
                if "ospf" in path_str:
                    touches_ospf = True
                    blast_radius += 20
                    reasons.append("plan modifies ospf related model paths")

                # -----------------------------
                # External connectivity
                # -----------------------------
                if "external" in path_str or "internet" in path_str:
                    touches_external = True
                    blast_radius += 20
                    reasons.append("plan touches external connectivity")

            # -----------------------------------------------------
            # Topology role weighting
            # -----------------------------------------------------
            device_record = device_index.get(device, {})
            role = str(device_record.get("role", "unknown"))

            if role in role_counts:
                role_counts[role] += 1
            else:
                role_counts["unknown"] += 1

            if role == "leaf":
                blast_radius += 0

            elif role == "spine":
                blast_radius += 20  # <- key increase to push into HIGH
                reasons.append("plan touches spine tier")

            elif role == "super_spine":
                blast_radius += 30
                reasons.append("plan touches super spine tier")

            else:
                blast_radius += 5

        device_count = len(touched_devices)

        # ---------------------------------------------------------
        # Final risk classification
        # ---------------------------------------------------------
        requires_approval = False

        if blast_radius >= 50:
            risk_level = "high"
            requires_approval = True

        elif blast_radius >= 20:
            risk_level = "medium"

        else:
            risk_level = "low"

        # ---------------------------------------------------------
        # Build structured response
        # ---------------------------------------------------------
        result = {
            "risk_level": risk_level,
            "blast_radius_score": blast_radius,
            "requires_approval": requires_approval,
            "reasons": reasons,
            "evidence": {
                "device_count": device_count,
                "devices": sorted([d for d in touched_devices if d]),
                "role_counts": role_counts,
                "touches": {
                    "external": touches_external,
                    "bgp": touches_bgp,
                    "ospf": touches_ospf,
                },
            },
        }

        return {
            "api_version": "v1",
            "request_id": request.get("request_id", "unknown"),
            "ok": True,
            "result": result,
        }

    def _send_json(self, payload: Dict[str, Any]) -> None:
        """
        Send JSON response back to lattice.
        """
        response_bytes = json.dumps(payload).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()

        self.wfile.write(response_bytes)


def run_server() -> None:
    """
    MCP server entrypoint.

    Starts HTTP server on port 8080.
    """
    server = HTTPServer(("0.0.0.0", 8080), MCPRequestHandler)

    print("mcp server listening on http://0.0.0.0:8080/mcp", flush=True)

    server.serve_forever()
