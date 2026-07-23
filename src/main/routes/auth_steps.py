"""Step-based auth endpoints for Android (and future Web migration)."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from user_agents import parse as parse_ua

from ..auth.oauth_flags import oauth_required
from ..auth.vk_oauth import (
    exchange_code_for_registration_proof as exchange_vk_code_for_registration_proof,
    public_vk_oauth_params,
    verify_registration_proof as verify_vk_registration_proof,
    vk_is_configured,
)
from ..auth.yandex_oauth import (
    exchange_code_for_registration_proof as exchange_yandex_code_for_registration_proof,
    public_yandex_oauth_params,
    verify_registration_proof as verify_yandex_registration_proof,
    yandex_is_configured,
)
from ..constants import OWNER_USERNAME
from ..dependencies import get_db
from ..models import DeviceSession, User
from ..security.audit import log_security
from ..security.chat_filter import contains_profanity
from ..security.rate_limit import rate_limit_per_ip
from ..utils import create_token, get_client_ip, get_password_hash, verify_password
from ..username import username_taken
from ..validation import is_valid_display_name, is_valid_password, is_valid_username
from .account import (
    _record_failed_login,
    _reset_failed_logins,
    _FAILED_ATTEMPT_WINDOW_SECONDS,
    _failed_login_attempts,
    _broadcast_registered_user_count_task,
    allocate_user_id,
    convert_user,
)

router = APIRouter()


class UsernameStepRequest(BaseModel):
    username: str


class PasswordStepRequest(BaseModel):
    username: str
    password: str


class YandexExchangeRequest(BaseModel):
    code: str
    code_verifier: str


class VkExchangeRequest(BaseModel):
    code: str
    code_verifier: str
    device_id: str
    state: str


class RegisterConfirmRequest(BaseModel):
    username: str
    password: str
    confirm_password: str
    display_name: str
    bio: str | None = None
    registration_proof: str | None = None
    yandex_code: str | None = None
    code_verifier: str | None = None
    vk_registration_proof: str | None = None
    vk_code: str | None = None
    vk_code_verifier: str | None = None
    vk_device_id: str | None = None
    vk_state: str | None = None


def _create_device_session(db: Session, user: User, request: Request) -> str:
    raw_ua = request.headers.get("user-agent")
    device_name = request.headers.get("x-device-name")
    ua = parse_ua(raw_ua or "")
    session_id = uuid.uuid4().hex
    device = DeviceSession(
        user_id=user.id,
        raw_user_agent=raw_ua,
        device_name=device_name,
        device_type=(
            "mobile"
            if ua.is_mobile
            else "tablet"
            if ua.is_tablet
            else "bot"
            if ua.is_bot
            else "desktop"
        ),
        os_name=(ua.os.family or None),
        os_version=(ua.os.version_string or None),
        browser_name=(ua.browser.family or None),
        browser_version=(ua.browser.version_string or None),
        brand=(ua.device.brand or None),
        model=(ua.device.model or None),
        session_id=session_id,
        created_at=datetime.now(),
        last_seen=datetime.now(),
        revoked=False,
    )
    db.add(device)
    db.commit()
    return session_id


def _login_success_payload(db: Session, user: User, request: Request) -> dict:
    client_ip = get_client_ip(request)
    session_id = _create_device_session(db, user, request)
    token = create_token(user.id, user.username, session_id)

    identifiers = [f"user:{user.username}"]
    if client_ip:
        identifiers.append(f"ip:{client_ip}")
    for identifier in identifiers:
        _reset_failed_logins(identifier)

    raw_ua = request.headers.get("user-agent")
    ua = parse_ua(raw_ua or "")
    log_security(
        "login_success",
        username=user.username,
        user_id=user.id,
        ip=client_ip,
        os=ua.os.family,
        browser=ua.browser.family,
    )
    return {
        "status": "success",
        "message": "Login successful",
        "token": token,
        "user": convert_user(user, db),
    }


def _handle_failed_login(username: str, client_ip: str | None) -> None:
    log_security(
        "login_failed",
        severity="warning",
        username=username,
        ip=client_ip,
        reason="invalid_credentials",
    )
    identifiers = [f"user:{username}"]
    if client_ip:
        identifiers.append(f"ip:{client_ip}")

    suspicious = False
    for identifier in identifiers:
        if _record_failed_login(identifier):
            suspicious = True

    if suspicious:
        total_failures = {
            identifier: len(_failed_login_attempts.get(identifier, []))
            for identifier in identifiers
        }
        log_security(
            "auth_bruteforce_detected",
            severity="warning",
            username=username,
            ip=client_ip,
            failures=total_failures,
            window_seconds=_FAILED_ATTEMPT_WINDOW_SECONDS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in a few minutes.",
        )
    raise HTTPException(
        status_code=401,
        detail="Неверное имя пользователя или пароль",
    )


def _resolve_oauth_ids_for_register(body: RegisterConfirmRequest) -> tuple[str | None, str | None]:
    """Return (yandex_id, vk_id). When OAUTH_REQUIRED, exactly one must be provided."""
    has_yandex = bool(
        (body.registration_proof and body.registration_proof.strip())
        or (body.yandex_code and body.code_verifier)
    )
    has_vk = bool(
        (body.vk_registration_proof and body.vk_registration_proof.strip())
        or (body.vk_code and body.vk_code_verifier and body.vk_device_id and body.vk_state)
    )

    if not oauth_required():
        return None, None

    if has_yandex and has_vk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide verification from either Yandex or VK ID, not both.",
        )

    if has_yandex:
        if not yandex_is_configured():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Yandex verification is not available on this server.",
            )
        if body.registration_proof and body.registration_proof.strip():
            return verify_yandex_registration_proof(body.registration_proof.strip()), None
        proof = exchange_yandex_code_for_registration_proof(body.yandex_code, body.code_verifier)
        return verify_yandex_registration_proof(proof), None

    if has_vk:
        if not vk_is_configured():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="VK verification is not available on this server.",
            )
        if body.vk_registration_proof and body.vk_registration_proof.strip():
            return None, verify_vk_registration_proof(body.vk_registration_proof.strip())
        proof = exchange_vk_code_for_registration_proof(
            body.vk_code,
            body.vk_code_verifier,
            body.vk_device_id,
            body.vk_state,
        )
        return None, verify_vk_registration_proof(proof)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Identity verification is required to create an account. Sign in with Yandex or VK ID.",
    )


@router.post("/auth/steps/username")
@rate_limit_per_ip("30/minute")
def auth_step_username(
    request: Request,
    body: UsernameStepRequest,
    db: Session = Depends(get_db),
):
    username = body.username.strip()
    if not is_valid_username(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        )
    if contains_profanity(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя содержит запрещённые слова",
        )
    exists = username_taken(db, username)
    return {"ok": True, "exists": exists}


@router.post("/auth/steps/password")
@rate_limit_per_ip("5/minute")
def auth_step_password(
    request: Request,
    body: PasswordStepRequest,
    db: Session = Depends(get_db),
):
    username = body.username.strip()
    password = body.password.strip()
    client_ip = get_client_ip(request)

    if contains_profanity(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя содержит запрещённые слова",
        )
    if not is_valid_username(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        )

    user = db.query(User).filter(func.lower(User.username) == username.lower()).first()
    if user is None:
        verification_required = oauth_required()
        payload: dict = {
            "status": "needs_register",
            "verification_required": verification_required,
        }
        if verification_required:
            if yandex_is_configured():
                payload["yandex"] = public_yandex_oauth_params()
            if vk_is_configured():
                payload["vk"] = public_vk_oauth_params()
        return payload

    if not verify_password(password, user.password_hash):
        _handle_failed_login(username, client_ip)

    return _login_success_payload(db, user, request)


@router.post("/auth/yandex/exchange")
@rate_limit_per_ip("10/minute")
def auth_yandex_exchange(
    request: Request,
    body: YandexExchangeRequest,
    db: Session = Depends(get_db),
):
    proof = exchange_yandex_code_for_registration_proof(body.code, body.code_verifier)
    yandex_id = verify_yandex_registration_proof(proof)
    linked = db.query(User).filter(User.yandex_id == yandex_id).first()
    if linked is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This Yandex account is already linked to another FromChat user.",
        )
    return {"registration_proof": proof}


@router.post("/auth/vk/exchange")
@rate_limit_per_ip("10/minute")
def auth_vk_exchange(
    request: Request,
    body: VkExchangeRequest,
    db: Session = Depends(get_db),
):
    proof = exchange_vk_code_for_registration_proof(
        body.code,
        body.code_verifier,
        body.device_id,
        body.state,
    )
    vk_id = verify_vk_registration_proof(proof)
    linked = db.query(User).filter(User.vk_id == vk_id).first()
    if linked is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This VK account is already linked to another FromChat user.",
        )
    return {"registration_proof": proof}


@router.post("/auth/steps/register/confirm")
@rate_limit_per_ip("3/hour")
def auth_step_register_confirm(
    request: Request,
    body: RegisterConfirmRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    username = body.username.strip()
    display_name = body.display_name.strip()
    password = body.password.strip()
    confirm_password = body.confirm_password.strip()
    client_ip = get_client_ip(request)

    owner_exists = (
        db.query(User)
        .filter(func.lower(User.username) == OWNER_USERNAME.lower())
        .first()
        is not None
    )

    if not is_valid_username(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        )
    if contains_profanity(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Имя пользователя содержит запрещённые слова",
        )
    if not is_valid_display_name(display_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Отображаемое имя должно быть от 1 до 64 символов и не может быть пустым",
        )
    if contains_profanity(display_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Отображаемое имя содержит запрещённые слова",
        )
    if not is_valid_password(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен быть от 5 до 50 символов и не содержать пробелов",
        )
    if password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароли не совпадают",
        )

    if username_taken(db, username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Это имя пользователя уже занято",
        )

    bio_text = (body.bio or "").strip() or None
    if bio_text and len(bio_text) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Описание должно быть не длиннее 500 символов",
        )
    if bio_text and contains_profanity(bio_text):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Описание содержит запрещённые слова",
        )

    yandex_id, vk_id = _resolve_oauth_ids_for_register(body)
    if yandex_id is not None:
        linked = db.query(User).filter(User.yandex_id == yandex_id).first()
        if linked is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This Yandex account is already linked to another FromChat user.",
            )
    if vk_id is not None:
        linked = db.query(User).filter(User.vk_id == vk_id).first()
        if linked is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This VK account is already linked to another FromChat user.",
            )

    is_owner = not owner_exists and username.lower() == OWNER_USERNAME.lower()
    new_user = User(
        id=allocate_user_id(db),
        username=username,
        display_name=display_name,
        password_hash=get_password_hash(password),
        bio=bio_text,
        verified=is_owner,
        yandex_id=yandex_id,
        vk_id=vk_id,
    )
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Это имя пользователя уже занято",
        )
    db.refresh(new_user)

    session_id = _create_device_session(db, new_user, request)
    token = create_token(new_user.id, new_user.username, session_id)

    raw_ua = request.headers.get("user-agent")
    ua = parse_ua(raw_ua or "")
    os_name = ua.os.family or "Unknown OS"
    if ua.os.version_string:
        os_name = f"{os_name} {ua.os.version_string}"
    browser_name = ua.browser.family or "Unknown browser"
    if ua.browser.version_string:
        browser_name = f"{browser_name} {ua.browser.version_string}"

    log_security(
        "registration_success",
        username=new_user.username,
        display_name=new_user.display_name,
        user_id=new_user.id,
        ip=client_ip,
        user_agent=f"{os_name}, {browser_name}",
        owner=is_owner,
        yandex_linked=bool(yandex_id),
        vk_linked=bool(vk_id),
    )
    background_tasks.add_task(_broadcast_registered_user_count_task)

    return {
        "status": "success",
        "message": "Регистрация прошла успешно",
        "token": token,
        "user": convert_user(new_user, db),
    }
