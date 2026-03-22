from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class NonceStore:
    """
    In memory nonce store with ttl.

    This protects against replay attacks for a single server instance.
    For multi instance, move this to a shared store later.
    """

    ttl_seconds: int = 300
    _nonces: dict[str, float] = field(default_factory=dict)

    def seen_recently(self, nonce: str) -> bool:
        now = time.time()
        self._evict(now)

        ts = self._nonces.get(nonce)
        if ts is not None:
            return True

        self._nonces[nonce] = now
        return False

    def _evict(self, now: float) -> None:
        cutoff = now - float(self.ttl_seconds)
        stale = [n for n, t in self._nonces.items() if t < cutoff]
        for n in stale:
            self._nonces.pop(n, None)
