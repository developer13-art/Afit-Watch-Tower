"""The one error shape every cloud response uses.

The contract fixes it as `{"error": {"code", "message", "request_id"}}`, and `request_id` is
the string a person quotes in a support ticket, so it is generated before anything else can
fail and echoed in the `x-request-id` header even on a success response.

Messages here are written for a recipient on a phone. They never contain a SQL fragment, a
filesystem path, an internal identifier of another user, or anything derived from an exception
that was not authored in this package - see `CloudError` for the one place text enters.
"""

from __future__ import annotations

import logging
import re
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..security.secrets import client_safe, redact

REQUEST_ID_HEADER = "x-request-id"
HEX = re.compile(r"^[0-9a-f]{20,64}$")
LOGGER = logging.getLogger("watchtower.cloud.errors")

# The stable names the contract already uses for these statuses, so a framework refusal reads the
# same as a deliberate one.
_FRAMEWORK_CODES = {
    400: "invalid_request",
    401: "authentication_required",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    413: "payload_too_large",
    415: "content_type_unsupported",
    429: "rate_limited",
    500: "internal_error",
    503: "storage_unavailable",
}


class CloudError(Exception):
    """A refusal the service chose. `code` is machine-readable and stable."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = headers or {}


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"


def error_body(code: str, message: str, request_id: str) -> dict:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "") or new_request_id()


def _respond(request: Request, code: str, message: str, status_code: int, headers=None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error_body(code, message, _request_id(request)),
        headers=headers,
    )


def install_error_handlers(app: FastAPI) -> None:
    """Every failure path leaves through here, so the envelope never varies."""

    @app.exception_handler(CloudError)
    async def _cloud_error(request: Request, exc: CloudError) -> JSONResponse:
        return _respond(request, exc.code, exc.message, exc.status_code, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted({ ".".join(str(part) for part in item["loc"][1:]) or "body" for item in exc.errors() })
        return _respond(
            request,
            "validation_failed",
            f"Request body or query is invalid ({', '.join(fields[:6])}).",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(ValidationError)
    async def _model_invalid(request: Request, exc: ValidationError) -> JSONResponse:
        return _respond(
            request,
            "validation_failed",
            "Request body or query is invalid.",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _framework(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # The routers in this package raise `CloudError`. What reaches here is a refusal the
        # framework made on our behalf - an unmatched path, a wrong method, a body the parser
        # rejected before FastAPI saw it - and those are still failures a phone has to render.
        # Answering them in `{"detail": ...}` would mean two error shapes in one API.
        code = _FRAMEWORK_CODES.get(exc.status_code) or f"http_{exc.status_code}"
        message = safe_detail(str(exc.detail)) or "The request could not be handled."
        return _respond(request, code, message, exc.status_code, dict(exc.headers or {}))

    @app.exception_handler(SQLAlchemyError)
    async def _database(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        # A database fault is logged in full (redacted) and answered with nothing but a code:
        # the statement text can contain values, and a phone is not the audience for them.
        LOGGER.error("database fault: %s", redact(str(exc)))
        return _respond(
            request,
            "storage_unavailable",
            "The service could not complete the request. Quote the request id when reporting.",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        LOGGER.error("unhandled fault: %s", redact(str(exc)))
        return _respond(
            request,
            "internal_error",
            "The service failed unexpectedly. Quote the request id when reporting.",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


def safe_detail(text: str) -> str:
    """Client-facing text derived from something we did not author."""
    return client_safe(text)[:200]
