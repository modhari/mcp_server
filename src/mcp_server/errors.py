from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class McpValidationError(Exception):
    """
    Raised when an MCP request or response fails schema validation.

    message is safe to return to the caller.
    """

    message: str

    def __str__(self) -> str:
        return self.message
