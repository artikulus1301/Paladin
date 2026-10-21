import hmac
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from paladin.config.settings import settings

SECRET_KEY = settings.dashboard_secret
ALGORITHM = "HS256"
ADMIN_USERNAME = "admin"
TOKEN_TTL = timedelta(hours=12)

# Brute-force protection: max failed logins per client within the window
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300

security = HTTPBearer()
_failed_logins: dict[str, deque] = defaultdict(deque)


def check_credentials(username: str, password: str) -> bool:
    """Constant-time comparison so response timing doesn't leak the password."""
    user_ok = hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.dashboard_admin_password.encode())
    return user_ok and pass_ok


def login_locked(client: str) -> bool:
    """True if `client` exceeded LOGIN_MAX_FAILURES within the window."""
    attempts = _failed_logins[client]
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    while attempts and attempts[0] < cutoff:
        attempts.popleft()
    return len(attempts) >= LOGIN_MAX_FAILURES


def record_login_failure(client: str) -> None:
    _failed_logins[client].append(time.monotonic())


def reset_login_failures(client: str) -> None:
    _failed_logins.pop(client, None)


def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc) + TOKEN_TTL})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_ws_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        return None
