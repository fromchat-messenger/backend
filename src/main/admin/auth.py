from __future__ import annotations

from fastapi import Depends, HTTPException, status

from ..dependencies import get_current_user
from ..models import User


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require authenticated user with id == 1."""
    if current_user.id != 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def is_admin(user: User) -> bool:
    return user.id == 1
