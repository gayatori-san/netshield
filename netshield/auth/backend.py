"""Firebase Authentication backend.

Two different kinds of configuration are involved:

* **Web configuration** (``FIREBASE_WEB_API_KEY``, auth domain, project ID,
  app ID, ...) is public by design. It is embedded in the login page so the
  Firebase JavaScript SDK can talk to Google. It is not a secret.
* **Admin credentials** (``FIREBASE_SERVICE_ACCOUNT_JSON`` or Application
  Default Credentials) can mint session cookies and verify token signatures.
  They are read from the environment only, are never written to disk, and are
  never logged or returned in an API response.

If either half is missing or broken the backend reports ``ready == False``.
Protected routes then fail closed (401 for missing tokens, 503 for an
unavailable verifier) instead of silently becoming public.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Mapping

LOGGER = logging.getLogger(__name__)

COOKIE_NAME = "netshield_session"
SESSION_MAX_AGE_DEFAULT = 5 * 24 * 60 * 60
MAX_TOKEN_LENGTH = 20_000

WEB_ENV_KEYS: dict[str, str] = {
    "apiKey": "FIREBASE_WEB_API_KEY",
    "authDomain": "FIREBASE_AUTH_DOMAIN",
    "projectId": "FIREBASE_PROJECT_ID",
    "storageBucket": "FIREBASE_STORAGE_BUCKET",
    "messagingSenderId": "FIREBASE_MESSAGING_SENDER_ID",
    "appId": "FIREBASE_APP_ID",
}
WEB_REQUIRED_KEYS = ("apiKey", "authDomain", "projectId", "appId")

_ADMIN_LOCK = threading.Lock()
_ADMIN_APP = None


class AuthBackendError(Exception):
    """Base class for authentication failures with a stable client code."""

    status = 401
    code = "auth_error"


class TokenExpired(AuthBackendError):
    code = "token_expired"


class TokenRevoked(AuthBackendError):
    code = "token_revoked"


class TokenInvalid(AuthBackendError):
    code = "invalid_token"


class AuthUnavailable(AuthBackendError):
    status = 503
    code = "auth_unavailable"


@dataclass(frozen=True)
class AuthUser:
    """The small, safe subset of verified claims the application needs."""

    uid: str
    email: str | None = None
    name: str | None = None
    picture: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "AuthUser":
        if not isinstance(claims, Mapping):
            raise TokenInvalid("The authentication token has no usable claims.")
        uid = claims.get("uid") or claims.get("user_id") or claims.get("sub")
        if not isinstance(uid, str) or not uid.strip():
            raise TokenInvalid("The authentication token does not identify a user.")
        email = claims.get("email")
        name = claims.get("name")
        picture = claims.get("picture")
        return cls(
            uid=uid.strip(),
            email=email.strip() if isinstance(email, str) and email.strip() else None,
            name=name.strip() if isinstance(name, str) and name.strip() else None,
            picture=picture if isinstance(picture, str) and picture else None,
            claims=dict(claims),
        )

    @property
    def display_name(self) -> str:
        return self.name or self.email or self.uid

    @property
    def initials(self) -> str:
        if self.name:
            parts = [part for part in self.name.split() if part]
            if len(parts) >= 2:
                return (parts[0][0] + parts[-1][0]).upper()
            if parts:
                return parts[0][:2].upper()
        if self.email:
            return self.email[:2].upper()
        return "NS"

    @property
    def permissions(self) -> tuple[str, ...]:
        raw = self.claims.get("permissions")
        if isinstance(raw, (list, tuple, set)):
            return tuple(sorted(str(item) for item in raw if isinstance(item, str)))
        return ()

    @property
    def is_admin(self) -> bool:
        return self.claims.get("admin") is True or "admin" in self.permissions

    def has_permission(self, permission: str) -> bool:
        if permission == "admin" or self.is_admin:
            return self.is_admin
        return permission in self.permissions

    def public_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "email": self.email,
            "name": self.name,
            "picture": self.picture,
            "is_admin": self.is_admin,
        }


def load_web_config(environ: Mapping[str, str]) -> tuple[dict[str, str] | None, str | None]:
    """Return public Firebase web config and an actionable error if incomplete."""

    config: dict[str, str] = {}
    missing: list[str] = []
    for key, env_name in WEB_ENV_KEYS.items():
        raw = (environ.get(env_name) or "").strip()
        if raw:
            config[key] = raw
        elif key in WEB_REQUIRED_KEYS:
            missing.append(env_name)

    if missing:
        if len(missing) == len(WEB_REQUIRED_KEYS):
            return (
                None,
                "Firebase Authentication is not configured. Set "
                + ", ".join(missing)
                + ". See README -> Firebase setup.",
            )
        return (
            None,
            "Firebase web configuration is incomplete. Missing: "
            + ", ".join(missing)
            + ". See README -> Firebase setup.",
        )
    return config, None


def _admin_source(environ: Mapping[str, str]) -> tuple[str, str | None, str | None]:
    """Return (mode, project_id, error). Never includes credential material."""

    raw_json = (environ.get("FIREBASE_SERVICE_ACCOUNT_JSON") or "").strip()
    credentials_path = (environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()
    use_adc = (environ.get("FIREBASE_USE_ADC") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    if raw_json:
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return "", None, (
                "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON. Re-copy the "
                "service-account key without editing it."
            )
        if not isinstance(data, dict):
            return "", None, "FIREBASE_SERVICE_ACCOUNT_JSON must contain a JSON object."
        missing = [
            key
            for key in ("type", "project_id", "private_key", "client_email")
            if not isinstance(data.get(key), str) or not data.get(key)
        ]
        if missing:
            return "", None, (
                "FIREBASE_SERVICE_ACCOUNT_JSON is missing required fields: "
                + ", ".join(missing)
            )
        project_id = data.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            project_id = None
        return "service_account_json", project_id, None

    if credentials_path:
        path = Path(credentials_path).expanduser()
        if not path.is_file():
            return "", None, (
                "GOOGLE_APPLICATION_CREDENTIALS does not point to a readable file."
            )
        return "credentials_file", None, None

    if use_adc:
        return "adc", None, None

    return (
        "",
        None,
        "Firebase Admin credentials are missing. Set "
        "FIREBASE_SERVICE_ACCOUNT_JSON on Render, or "
        "GOOGLE_APPLICATION_CREDENTIALS / FIREBASE_USE_ADC for local ADC.",
    )


def _load_credential(mode: str, environ: Mapping[str, str]):
    from firebase_admin import credentials

    if mode == "service_account_json":
        data = json.loads((environ.get("FIREBASE_SERVICE_ACCOUNT_JSON") or "").strip())
        return credentials.Certificate(data)
    if mode == "credentials_file":
        return credentials.Certificate(
            str(Path((environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()).expanduser())
        )
    return credentials.ApplicationDefault()


def initialize_firebase_admin(
    environ: Mapping[str, str],
    *,
    initializer: Callable[..., Any] | None = None,
) -> Any:
    """Initialize the named Firebase Admin app exactly once per process."""

    global _ADMIN_APP

    mode, project_id, error = _admin_source(environ)
    if error:
        raise AuthUnavailable(error)
    if not mode:
        raise AuthUnavailable("Firebase Admin is not configured.")

    web_project = (environ.get("FIREBASE_PROJECT_ID") or "").strip()
    if project_id and web_project and project_id != web_project:
        raise AuthUnavailable(
            "FIREBASE_PROJECT_ID does not match the service account's project_id."
        )

    with _ADMIN_LOCK:
        if _ADMIN_APP is not None:
            return _ADMIN_APP

        try:
            import firebase_admin
            from firebase_admin import credentials  # noqa: F401  (import check)

            credential = _load_credential(mode, environ)
            options = {"projectId": project_id} if project_id else {}
            init = initializer or firebase_admin.initialize_app
            try:
                app = init(credential, options, name="netshield")
            except ValueError:
                # A previous create_app() in the same process already made it.
                app = firebase_admin.get_app("netshield")
        except AuthUnavailable:
            raise
        except ImportError as exc:
            raise AuthUnavailable(
                "firebase-admin is not installed in this environment."
            ) from exc
        except Exception as exc:  # never echo credential contents or raw errors
            LOGGER.warning("Firebase Admin initialization failed (%s)", type(exc).__name__)
            raise AuthUnavailable(
                "Firebase Admin could not be initialized. Verify the service-account "
                "JSON, its project ID, and the server clock."
            ) from exc

        _ADMIN_APP = app
        return app


def _translate_sdk_error(exc: Exception) -> AuthBackendError:
    try:
        from firebase_admin import auth as fb_auth
    except ImportError:
        return AuthUnavailable("firebase-admin is not available.")

    if isinstance(exc, (fb_auth.ExpiredIdTokenError, fb_auth.ExpiredSessionCookieError)):
        return TokenExpired("Your authentication has expired. Sign in again.")
    if isinstance(
        exc,
        (
            fb_auth.RevokedIdTokenError,
            fb_auth.RevokedSessionCookieError,
            fb_auth.UserNotFoundError,
        ),
    ):
        return TokenRevoked("This session was revoked. Sign in again.")
    if isinstance(exc, fb_auth.UserDisabledError):
        return TokenInvalid("This account is disabled. Contact an administrator.")
    if isinstance(
        exc,
        (
            fb_auth.InvalidIdTokenError,
            fb_auth.InvalidSessionCookieError,
            ValueError,
        ),
    ):
        return TokenInvalid("The authentication token is invalid or malformed.")
    if isinstance(exc, fb_auth.CertificateFetchError):
        return AuthUnavailable(
            "Firebase public keys could not be fetched. Check outbound network access."
        )
    if isinstance(exc, fb_auth.InsufficientPermissionError):
        return AuthUnavailable(
            "Firebase Admin lacks permission to verify this user. Check the "
            "service account's IAM roles."
        )
    return AuthUnavailable("Authentication could not be verified right now.")


def _verify_with_sdk(token: str, app: Any) -> Mapping[str, Any]:
    from firebase_admin import auth as fb_auth

    return fb_auth.verify_id_token(token, check_revoked=True, app=app)


def _create_cookie_with_sdk(token: str, expires_in: timedelta, app: Any) -> str:
    from firebase_admin import auth as fb_auth

    return fb_auth.create_session_cookie(token, expires_in=expires_in, app=app)


def _verify_cookie_with_sdk(cookie: str, app: Any) -> Mapping[str, Any]:
    from firebase_admin import auth as fb_auth

    return fb_auth.verify_session_cookie(cookie, check_revoked=True, app=app)


class FirebaseAuthManager:
    """Verifies ID tokens and Firebase session cookies.

    The callables are injectable so unit tests can run without a real
    Firebase project or network access.
    """

    def __init__(
        self,
        *,
        web_config: Mapping[str, str] | None,
        web_error: str | None,
        admin_ready: bool,
        admin_error: str | None,
        verifier: Callable[[str], Mapping[str, Any]] | None = None,
        session_creator: Callable[[str, timedelta], str] | None = None,
        session_verifier: Callable[[str], Mapping[str, Any]] | None = None,
        admin_app: Any = None,
        session_max_age: int = SESSION_MAX_AGE_DEFAULT,
        cookie_secure_mode: str = "auto",
    ) -> None:
        self.web_config = dict(web_config) if web_config else None
        self.web_error = web_error
        self.admin_ready = bool(admin_ready)
        self.admin_error = admin_error
        self.session_max_age = session_max_age
        self.cookie_secure_mode = cookie_secure_mode
        self._admin_app = admin_app
        self._verifier = verifier
        self._session_creator = session_creator
        self._session_verifier = session_verifier

    @property
    def cookie_name(self) -> str:
        return COOKIE_NAME

    @property
    def ready(self) -> bool:
        return self.web_config is not None and self.admin_ready

    @property
    def status(self) -> str:
        if self.ready:
            return "ready"
        if self.web_config is None or not self.admin_ready:
            return "unconfigured"
        return "error"

    def cookie_secure(self, request_is_secure: bool) -> bool:
        if self.cookie_secure_mode == "true":
            return True
        if self.cookie_secure_mode == "false":
            return False
        return request_is_secure

    def _require_admin(self) -> None:
        if not self.admin_ready:
            raise AuthUnavailable(
                self.admin_error
                or "Firebase Admin is not configured; authenticated routes are locked."
            )

    def verify_id_token(self, token: str) -> AuthUser:
        self._require_admin()
        if not isinstance(token, str) or not token.strip():
            raise TokenInvalid("A Firebase ID token is required.")
        token = token.strip()
        if len(token) > MAX_TOKEN_LENGTH:
            raise TokenInvalid("The authentication token is too large.")
        verifier = self._verifier or (
            lambda value: _verify_with_sdk(value, self._admin_app)
        )
        try:
            claims = verifier(token)
        except AuthBackendError:
            raise
        except Exception as exc:
            raise _translate_sdk_error(exc) from exc
        return AuthUser.from_claims(claims)

    def create_session_cookie(self, token: str) -> str:
        self._require_admin()
        creator = self._session_creator or (
            lambda value, expires: _create_cookie_with_sdk(
                value, expires, self._admin_app
            )
        )
        try:
            return creator(token, timedelta(seconds=self.session_max_age))
        except AuthBackendError:
            raise
        except Exception as exc:
            raise _translate_sdk_error(exc) from exc

    def verify_session_cookie(self, cookie: str) -> AuthUser:
        self._require_admin()
        if not isinstance(cookie, str) or not cookie.strip():
            raise TokenInvalid("A session cookie is required.")
        verifier = self._session_verifier or (
            lambda value: _verify_cookie_with_sdk(value, self._admin_app)
        )
        try:
            claims = verifier(cookie)
        except AuthBackendError:
            raise
        except Exception as exc:
            raise _translate_sdk_error(exc) from exc
        return AuthUser.from_claims(claims)


def _env_int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("Ignoring non-numeric %s", name)
        return default


def build_auth_manager(
    environ: Mapping[str, str] | None = None,
    *,
    initializer: Callable[..., Any] | None = None,
) -> FirebaseAuthManager:
    """Build the process-wide manager from environment configuration."""

    source = os.environ if environ is None else environ
    web_config, web_error = load_web_config(source)

    admin_ready = False
    admin_error: str | None = None
    admin_app = None
    mode, project_id, source_error = _admin_source(source)
    if source_error:
        admin_error = source_error
    else:
        try:
            admin_app = initialize_firebase_admin(source, initializer=initializer)
            admin_ready = True
        except AuthUnavailable as exc:
            admin_error = str(exc)
        except Exception as exc:  # defensive: never fail open or echo secrets
            LOGGER.warning("Unexpected Firebase Admin error (%s)", type(exc).__name__)
            admin_error = "Firebase Admin could not be initialized."

    if not admin_ready and not admin_error:
        admin_error = "Firebase Admin is not configured."

    max_age = _env_int(source, "NETSHIELD_SESSION_MAX_AGE", SESSION_MAX_AGE_DEFAULT)
    if not 300 <= max_age <= 14 * 24 * 60 * 60:
        LOGGER.warning(
            "NETSHIELD_SESSION_MAX_AGE must be between 300 and 1209600; using default"
        )
        max_age = SESSION_MAX_AGE_DEFAULT

    secure_mode = (source.get("NETSHIELD_COOKIE_SECURE") or "auto").strip().lower()
    if secure_mode not in ("auto", "true", "false"):
        LOGGER.warning("NETSHIELD_COOKIE_SECURE must be auto/true/false; using auto")
        secure_mode = "auto"

    manager = FirebaseAuthManager(
        web_config=web_config,
        web_error=web_error,
        admin_ready=admin_ready,
        admin_error=admin_error,
        admin_app=admin_app,
        session_max_age=max_age,
        cookie_secure_mode=secure_mode,
    )
    if not manager.ready:
        LOGGER.warning(
            "Firebase Authentication is not ready (%s). Protected routes stay locked.",
            "web config missing" if web_config is None else "admin unavailable",
        )
    return manager
