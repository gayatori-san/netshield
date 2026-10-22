"""One error envelope for every API failure.

Raising ``ApiError`` anywhere inside a route produces the same JSON shape, so
the dashboard never has to special-case Flask's HTML error pages.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify


class ApiError(Exception):
    status = 400
    code = "bad_request"

    def __init__(
        self,
        message: str,
        *,
        detail: Any = None,
        status: int | None = None,
        code: str | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.detail = detail
        if status is not None:
            self.status = status
        if code is not None:
            self.code = code

    def to_dict(self) -> dict:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.detail is not None:
            error["detail"] = self.detail
        return {"ok": False, "error": error}

    def response(self):
        return jsonify(self.to_dict()), self.status


class ValidationError(ApiError):
    status = 400
    code = "invalid_parameter"


class NotFoundError(ApiError):
    status = 404
    code = "not_found"


class ConflictError(ApiError):
    status = 409
    code = "conflict"


class ForbiddenError(ApiError):
    status = 403
    code = "forbidden"


class UnauthenticatedError(ApiError):
    status = 401
    code = "unauthenticated"

    def response(self):
        response, status = super().response()
        response.headers["WWW-Authenticate"] = 'Bearer realm="netshield"'
        return response, status


class CsrfError(ApiError):
    status = 403
    code = "csrf_required"


class AuthUnavailableError(ApiError):
    status = 503
    code = "auth_unavailable"


class RateLimitError(ApiError):
    status = 429
    code = "rate_limited"

    def __init__(self, message: str, *, retry_after: int = 60, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = max(1, int(retry_after))

    def response(self):
        response, status = super().response()
        response.headers["Retry-After"] = str(self.retry_after)
        return response, status


def register_error_handlers(app) -> None:
    @app.errorhandler(ApiError)
    def handle_api_error(error: ApiError):
        return error.response()

    @app.errorhandler(404)
    def handle_404(error):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {"code": "not_found", "message": "resource not found"},
                }
            ),
            404,
        )

    @app.errorhandler(405)
    def handle_405(error):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {
                        "code": "method_not_allowed",
                        "message": "method not allowed for this resource",
                    },
                }
            ),
            405,
        )

    @app.errorhandler(413)
    def handle_413(error):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {
                        "code": "payload_too_large",
                        "message": "upload exceeds the 25 MB limit",
                    },
                }
            ),
            413,
        )

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception):
        app.logger.exception("unhandled API error")
        return (
            jsonify(
                {
                    "ok": False,
                    "error": {
                        "code": "internal_error",
                        "message": "an unexpected error occurred; check the server log",
                    },
                }
            ),
            500,
        )
