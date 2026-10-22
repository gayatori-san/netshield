"""Firebase Authentication integration."""

from netshield.auth.backend import (
    AuthBackendError,
    AuthUnavailable,
    AuthUser,
    FirebaseAuthManager,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    build_auth_manager,
    load_web_config,
)
from netshield.auth.guard import (
    current_user,
    ensure_permission,
    install_auth_guard,
    require_permission,
)
from netshield.auth.rate_limit import SlidingWindowLimiter

__all__ = [
    "AuthBackendError",
    "AuthUnavailable",
    "AuthUser",
    "FirebaseAuthManager",
    "SlidingWindowLimiter",
    "TokenExpired",
    "TokenInvalid",
    "TokenRevoked",
    "build_auth_manager",
    "current_user",
    "ensure_permission",
    "install_auth_guard",
    "load_web_config",
    "require_permission",
]
