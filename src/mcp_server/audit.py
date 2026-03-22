from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditLogger:
    """
    JSON line audit logger.

    Each call appends one JSON object per line.
    """

    path: Path

    def log(self, event: dict[str, Any]) -> None:
        payload = dict(event)
        payload["ts_unix"] = int(time.time())
        line = json.dumps(payload, sort_keys=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
