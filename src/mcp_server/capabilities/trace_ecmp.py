from __future__ import annotations

import os
from typing import Any

import requests

from mcp_server.capabilities.tsdb import write_trace_result


def trace_ecmp_path(
    source: str,
    destination: str,
    flow: dict[str, Any] | None = None,
    mode: str = "data_plane",
) -> dict[str, Any]:
    """
    MCP capability wrapper for ECMP aware trace.

    Current behavior:
    calls the in cluster ECMP trace service
    optionally writes the result to TSDB
    returns structured trace output

    Expected request shape:
    {
        "source": "leaf-01",
        "destination": "10.1.1.1",
        "flow": {
            "src_ip": "1.1.1.1",
            "dst_ip": "10.1.1.1",
            "src_port": 12345,
            "dst_port": 443,
            "protocol": "tcp"
        },
        "mode": "data_plane"
    }
    """
    service_url = os.environ.get("ECMP_TRACE_URL", "http://ecmp-trace:8081")

    payload = {
        "source": source,
        "destination": destination,
        "flow": flow or {},
        "mode": mode,
    }

    response = requests.post(
        f"{service_url}/trace",
        json=payload,
        timeout=10,
    )
    response.raise_for_status()

    result = response.json()

    if os.environ.get("TRACE_WRITE_TSDB", "true").lower() == "true":
        write_trace_result(result)

    return result
