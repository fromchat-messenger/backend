from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from types import SimpleNamespace
from ..dependencies import get_current_user
from ..models import User
from ..utils import verify_token


def extract_token_from_data(data: dict) -> str | None:
    """Extract authentication token from WebSocket message data.
    
    Args:
        data: WebSocket message data dictionary
        
    Returns:
        Token string or None if not present
    """
    credentials = data.get("credentials")
    if credentials and isinstance(credentials, dict):
        return credentials.get("credentials")
    return None


def extract_session_id_from_data(data: dict) -> str | None:
    """Extract device session id from WebSocket message credentials."""
    token = extract_token_from_data(data)
    if not token:
        return None
    payload = verify_token(token)
    if not payload:
        return None
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return None
    return session_id


def get_current_user_from_token(token: str, db: Session) -> User | None:
    """Get user from authentication token.

    Re-raises HTTP 403 (suspended/deleted) so WebSocket handlers can surface them.
    Returns None only for missing/invalid credentials (401-class failures).
    """
    try:
        # Ensure session is in a usable state before querying
        try:
            db.rollback()
        except Exception:
            pass

        dummy_request = SimpleNamespace()
        dummy_request.state = SimpleNamespace()

        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=token,
        )
        return get_current_user(dummy_request, credentials, db)
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        return None
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def authenticate_user(data: dict, db: Session, authRequired: bool) -> User | None:
    """Authenticate user from WebSocket message data.
    
    Args:
        data: WebSocket message data dictionary
        db: Database session
        authRequired: If True, raises 401 on missing/invalid token
        
    Returns:
        User object (guaranteed not None if authRequired=True) or None
        
    Raises:
        HTTPException: 401 if authRequired=True and token is missing/invalid
        HTTPException: 403 if account is suspended/deleted
    """
    token = extract_token_from_data(data)

    if authRequired:
        if not token:
            raise HTTPException(status_code=401, detail="Missing credentials")

        user = get_current_user_from_token(token, db)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        return user
    else:
        if token:
            return get_current_user_from_token(token, db)
        return None
