from __future__ import annotations

import json
import os
from typing import Any

import requests


def write_trace_result(result: dict[str, Any]) -> None:
    """
    Write a compact trace result into VictoriaMetrics using
    a very simple JSON line style payload placeholder.

    This is intentionally minimal for now.
    You can later replace this with:
    Prometheus remote write
    VictoriaMetrics import API
    ClickHouse
    """
    vm_url = os.environ.get(
        "TRACE_TSDB_URL",
        "http://victoriametrics:8428/api/v1/import",
    )

    payload = {
        "metric": {
            "__name__": "ecmp_trace_result",
            "source": str(result.get("source", "")),
            "destination": str(result.get("destination", "")),
            "mode": str(result.get("mode", "data_plane")),
        },
        "values": [float(result.get("ecmp_width", 0))],
        "timestamps": [int(result.get("timestamp_unix_ms", 0))],
    }

    try:
        requests.post(
            vm_url,
            data=json.dumps(payload) + "\n",
            timeout=5,
        )
    except Exception:
        # Do not break trace capability on telemetry write failure.
        pass
