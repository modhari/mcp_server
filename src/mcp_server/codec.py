from __future__ import annotations

from typing import Any

from datacenter_orchestrator.mcp.errors import McpValidationError
from datacenter_orchestrator.mcp.schemas import (
    McpApiVersion,
    McpError,
    McpMethod,
    McpRequest,
    McpResponse,
)


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise McpValidationError(f"{name} must be an object")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise McpValidationError(f"{name} must be a non empty string")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise McpValidationError(f"{name} must be a boolean")
    return value


def decode_request(payload: Any) -> McpRequest:
    obj = _require_dict(payload, "request")

    api_version_raw = _require_str(obj.get("api_version"), "api_version")
    request_id = _require_str(obj.get("request_id"), "request_id")
    method_raw = _require_str(obj.get("method"), "method")
    params = obj.get("params")

    if params is None:
        params = {}
    params = _require_dict(params, "params")

    try:
        api_version = McpApiVersion(api_version_raw)
    except ValueError as exc:
        raise McpValidationError("unsupported api_version") from exc

    try:
        method = McpMethod(method_raw)
    except ValueError as exc:
        raise McpValidationError("unsupported method") from exc

    return McpRequest(
        api_version=api_version,
        request_id=request_id,
        method=method,
        params=params,
    )


def encode_request(req: McpRequest) -> dict[str, Any]:
    return {
        "api_version": req.api_version.value,
        "request_id": req.request_id,
        "method": req.method.value,
        "params": req.params,
    }


def decode_response(payload: Any) -> McpResponse:
    obj = _require_dict(payload, "response")

    api_version_raw = _require_str(obj.get("api_version"), "api_version")
    request_id = _require_str(obj.get("request_id"), "request_id")
    ok = _require_bool(obj.get("ok"), "ok")

    try:
        api_version = McpApiVersion(api_version_raw)
    except ValueError as exc:
        raise McpValidationError("unsupported api_version") from exc

    result = obj.get("result")
    error = obj.get("error")

    if ok:
        if error is not None:
            raise McpValidationError("ok response must not include error")
        if result is None:
            result = {}
        result = _require_dict(result, "result")
        return McpResponse(
            api_version=api_version,
            request_id=request_id,
            ok=True,
            result=result,
            error=None,
        )

    if result is not None:
        raise McpValidationError("error response must not include result")

    err_obj = _require_dict(error, "error")
    code = _require_str(err_obj.get("code"), "error.code")
    message = _require_str(err_obj.get("message"), "error.message")
    details_raw = err_obj.get("details")

    details: dict[str, Any] | None
    if details_raw is None:
        details = None
    else:
        details = _require_dict(details_raw, "error.details")

    return McpResponse(
        api_version=api_version,
        request_id=request_id,
        ok=False,
        result=None,
        error=McpError(code=code, message=message, details=details),
    )


def encode_response_ok(
    api_version: McpApiVersion,
    request_id: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "api_version": api_version.value,
        "request_id": request_id,
        "ok": True,
        "result": result,
    }


def encode_response_error(
    api_version: McpApiVersion,
    request_id: str,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "api_version": api_version.value,
        "request_id": request_id,
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if details is not None:
        payload["error"]["details"] = details
    return payload
