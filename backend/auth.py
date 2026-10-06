import os
from datetime import datetime, timedelta
from typing import Optional
import jwt
import logging

log = logging.getLogger("netscan.auth")

SECRET_KEY = os.getenv("NETSCAN_SECRET_KEY", "change-this-to-a-long-random-string-in-production")
DEFAULT_USERNAME = "netscan"
DEFAULT_PASSWORD = "Mustberich16"
TOKEN_EXPIRY_HOURS = 24


def verify_credentials(username: str, password: str) -> bool:
    """Verify username and password against environment variables or defaults."""
    valid_username = os.getenv("NETSCAN_USERNAME", DEFAULT_USERNAME)
    valid_password = os.getenv("NETSCAN_PASSWORD", DEFAULT_PASSWORD)
    
    if not valid_username or not valid_password:
        log.error("Username or password not configured. Set NETSCAN_USERNAME and NETSCAN_PASSWORD")
        return False
    
    return username == valid_username and password == valid_password


def create_access_token(username: str, expires_delta: Optional[timedelta] = None) -> tuple[str, int]:
    """Create a JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(hours=TOKEN_EXPIRY_HOURS)
    
    expire = datetime.utcnow() + expires_delta
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.utcnow()
    }
    
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return encoded_jwt, int(expires_delta.total_seconds())


def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return username if valid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.ExpiredSignatureError:
        log.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as exc:
        log.warning("Invalid token: %s", exc)
        return None
