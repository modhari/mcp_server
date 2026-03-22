from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class McpApiVersion(StrEnum):
    v1 = "v1"


class McpMethod(StrEnum):
    evaluate_plan = "evaluate_plan"


@dataclass(frozen=True)
class McpRequest:
    """
    Strict MCP request schema.

    api_version must be present and known.
    request_id must be a stable id for tracing.
    method must be one of the allowed methods.
    params is a dict with method specific schema.
    """

    api_version: McpApiVersion
    request_id: str
    method: McpMethod
    params: dict[str, Any]


@dataclass(frozen=True)
class McpError:
    """
    Strict error schema.

    code is a stable machine readable code.
    message is a human readable message.
    details is structured data, optional.
    """

    code: str
    message: str
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class McpResponse:
    """
    Strict MCP response schema.

    ok indicates success.
    result is present only on success.
    error is present only on failure.
    """

    api_version: McpApiVersion
    request_id: str
    ok: bool
    result: dict[str, Any] | None = None
    error: McpError | None = None
