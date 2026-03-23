"""
MCP Server API

Simple HTTP server exposing /mcp endpoint for plan evaluation.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from mcp_server.errors import McpValidationError


class MCPRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send_json(
                404,
                {
                    "ok": False,
                    "error": {"code": "not_found", "message": "unknown endpoint"},
                },
            )
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            body_bytes = self.rfile.read(content_length)

            payload = json.loads(body_bytes.decode("utf-8"))

            print("=== MCP REQUEST ===", flush=True)
            print(payload, flush=True)
            print("===================", flush=True)

            method = payload.get("method")
            params = payload.get("params", {})

            if method != "evaluate_plan":
                raise McpValidationError(f"unsupported method: {method}")

            plan = params.get("plan", {})
            inventory = params.get("inventory", {})

            result = self._evaluate_plan_dicts(plan, inventory)

            response = {
                "api_version": "v1",
                "request_id": payload.get("request_id", "unknown"),
                "ok": True,
                "result": result,
            }

            self._send_json(200, response)

        except McpValidationError as exc:
            self._send_json(
                400,
                {
                    "ok": False,
                    "error": {"code": "validation_error", "message": str(exc)},
                },
            )

        except Exception as exc:
            self._send_json(
                500,
                {
                    "ok": False,
                    "error": {"code": "internal_error", "message": str(exc)},
                },
            )

    def _evaluate_plan_dicts(
        self,
        plan: dict[str, Any],
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        actions = plan.get("actions", [])
        devices = inventory.get("devices", [])

        if not isinstance(actions, list):
            raise McpValidationError("plan.actions must be a list")
        if not isinstance(devices, list):
            raise McpValidationError("inventory.devices must be a list")

        device_index: dict[str, dict[str, Any]] = {}
        for dev in devices:
            if isinstance(dev, dict):
                name = str(dev.get("name", ""))
                if name:
                    device_index[name] = dev

        touched_devices: list[str] = []
        reasons: list[str] = []
        evidence: dict[str, Any] = {
            "device_count": len(devices),
            "action_count": len(actions),
            "touched_devices": [],
            "change_types": [],
        }

        blast_radius_score = 0
        risk_level = "low"
        requires_approval = False

        for action in actions:
            if not isinstance(action, dict):
                continue

            device = str(action.get("device", ""))
            model_paths = action.get("model_paths", {})
            if not isinstance(model_paths, dict):
                model_paths = {}

            if device:
                touched_devices.append(device)

            change_types_for_action: list[str] = []

            for path, value in model_paths.items():
                path_str = str(path)

                if "bgp/neighbors/neighbor" in path_str:
                    change_types_for_action.append("bgp_neighbor_change")
                    blast_radius_score += 40
                    reasons.append(f"BGP neighbor change on {device}")

                    if value is False:
                        blast_radius_score += 30
                        reasons.append(f"BGP neighbor disable requested on {device}")

                elif "interfaces/interface" in path_str:
                    change_types_for_action.append("interface_change")
                    blast_radius_score += 15
                    reasons.append(f"Interface configuration change on {device}")

                    if value is False:
                        blast_radius_score += 20
                        reasons.append(f"Interface disable requested on {device}")

                else:
                    change_types_for_action.append("generic_config_change")
                    blast_radius_score += 10
                    reasons.append(f"Generic config change on {device}")

            device_record = device_index.get(device)
            if device_record:
                role = str(device_record.get("role", ""))
                if role == "spine":
                    blast_radius_score += 25
                    reasons.append(f"Change touches spine device {device}")
                elif role == "leaf":
                    blast_radius_score += 10
                    reasons.append(f"Change touches leaf device {device}")

                links = device_record.get("links", [])
                if isinstance(links, list):
                    blast_radius_score += min(len(links) * 5, 20)
                    reasons.append(f"Topology fanout considered for {device}")

            evidence["change_types"].extend(change_types_for_action)

        unique_devices = sorted(set(touched_devices))
        evidence["touched_devices"] = unique_devices

        if blast_radius_score >= 70:
            risk_level = "high"
            requires_approval = True
        elif blast_radius_score >= 35:
            risk_level = "medium"
            requires_approval = True
        else:
            risk_level = "low"
            requires_approval = False

        return {
            "risk_level": risk_level,
            "blast_radius_score": blast_radius_score,
            "requires_approval": requires_approval,
            "reasons": reasons,
            "evidence": evidence,
        }


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = HTTPServer((host, port), MCPRequestHandler)
    print(f"mcp server listening on http://{host}:{port}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
