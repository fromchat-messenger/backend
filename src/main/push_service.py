import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session
from pywebpush import webpush, WebPushException
from .models import PushSubscription, User, Message, DMEnvelope, FcmToken
from .db import SessionLocal
import firebase_admin
from firebase_admin import credentials as firebase_credentials
from firebase_admin import messaging as firebase_messaging

logger = logging.getLogger("uvicorn.error")

def _resolve_firebase_cert_path() -> Path:
    explicit = os.getenv("FIREBASE_CERT_PATH", "").strip()
    if explicit:
        return Path(explicit)
    return Path(__file__).resolve().parents[2] / "secrets" / "firebase-cert.json"


_FIREBASE_CERT_PATH = _resolve_firebase_cert_path()
_PUBLIC_CHAT_COLLAPSE_KEY = "public_chat"


def _load_firebase_service_account_dict(cert_path: Path) -> dict:
    """Load Firebase service account JSON from ``cert_path`` (must exist)."""
    cert_path = cert_path.resolve()
    if not cert_path.is_file():
        raise FileNotFoundError(
            f"Firebase credentials file missing or not a file: {cert_path} (expected backend/secrets/firebase-cert.json)"
        )

    with cert_path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or data.get("type") != "service_account":
        raise ValueError("Firebase credentials file must be a service account JSON object")
    return data


@dataclass(frozen=True)
class PublicPushSnapshot:
    """Immutable snapshot for a public-chat push job (safe after request session closes)."""

    message_id: int
    sender_id: int
    exclude_user_id: Optional[int]
    title: str
    body: str
    icon: Optional[str]
    sender_username: str
    sender_display_name: str


class PublicPushScheduler:
    """Latest-wins in-process queue for public FCM/web-push wakes.

    Pending depth stays at most 1. The worker always completes a full fan-out to
    every eligible recipient, then drains any newer pending snapshot so all
    clients still get woken under spam.
    """

    def __init__(self, service: "PushNotificationService"):
        self._service = service
        self._pending: Optional[PublicPushSnapshot] = None
        self._worker_task: Optional[asyncio.Task] = None

    def enqueue(self, snapshot: PublicPushSnapshot) -> None:
        """Replace any pending job with ``snapshot`` and ensure a worker is running.

        Safe on the asyncio event-loop thread used by FastAPI request handlers.
        """
        previous = self._pending
        if previous is not None and previous.message_id != snapshot.message_id:
            logger.info(
                "Public push superseded: pending_message_id=%s replaced_by=%s",
                previous.message_id,
                snapshot.message_id,
            )
        self._pending = snapshot
        if self._worker_task is None or self._worker_task.done():
            try:
                self._worker_task = asyncio.create_task(self._run())
            except RuntimeError:
                logger.error(
                    "Public push enqueue failed: no running event loop (message_id=%s)",
                    snapshot.message_id,
                )
                self._worker_task = None

    async def _run(self) -> None:
        try:
            while True:
                job = self._pending
                self._pending = None
                if job is None:
                    return

                logger.info(
                    "Public push worker fan-out start: message_id=%s sender_id=%s",
                    job.message_id,
                    job.sender_id,
                )
                try:
                    with SessionLocal() as db:
                        await self._service.send_public_push_snapshot(db, job)
                except Exception as e:
                    logger.error(
                        "Public push worker fan-out failed: message_id=%s error=%s",
                        job.message_id,
                        e,
                    )
        finally:
            # Avoid dropping a job enqueued between "pending is None" and task end.
            self._worker_task = None
            if self._pending is not None:
                self.enqueue(self._pending)

class PushNotificationService:
    def _short_token(self, token: str) -> str:
        value = (token or "").strip()
        if len(value) <= 14:
            return value
        return f"...{value[-8:]}"

    def __init__(self):
        self.vapid_private_key = os.getenv("VAPID_PRIVATE_KEY")
        self.vapid_public_key = os.getenv("VAPID_PUBLIC_KEY")
        # Firebase Admin enables FCM; optional cert at backend/secrets/firebase-cert.json.
        self.firebase_initialized = False
        try:
            sa_dict = _load_firebase_service_account_dict(_FIREBASE_CERT_PATH)

            cred = firebase_credentials.Certificate(sa_dict)
            firebase_admin.initialize_app(cred)
            self.firebase_initialized = True
            logger.info("Firebase Admin SDK initialized (%s)", _FIREBASE_CERT_PATH)
        except FileNotFoundError:
            logger.warning(
                "Firebase credentials not found at %s; FCM push disabled",
                _FIREBASE_CERT_PATH,
            )
        except Exception as e:
            logger.warning(
                "Firebase Admin SDK initialization failed (%s); FCM push disabled: %s",
                _FIREBASE_CERT_PATH,
                e,
            )

        if (not self.vapid_public_key) or (not self.vapid_private_key):
            raise ValueError("VAPID public or private key is None")

        self.vapid_claims = {
            "sub": "mailto:support@fromchat.ru",
            "aud": "https://fcm.googleapis.com"
        }
        self.public_push_scheduler = PublicPushScheduler(self)

    def enqueue_public_message_notification(
        self,
        message: Message,
        exclude_user_id: Optional[int] = None,
        sender: Optional[User] = None,
    ) -> None:
        """Schedule a public-chat push wake without blocking the send path."""
        author = sender or message.author
        username = author.username if author else ""
        display_name = (author.display_name if author else None) or ""
        content = message.content or ""
        snapshot = PublicPushSnapshot(
            message_id=message.id,
            sender_id=message.user_id,
            exclude_user_id=exclude_user_id,
            title=f"{display_name or username}",
            body=content[:100] + ("..." if len(content) > 100 else ""),
            icon=author.profile_picture if author else None,
            sender_username=username,
            sender_display_name=display_name,
        )
        logger.info(
            "Public push enqueued: message_id=%s sender_id=%s exclude_user=%s",
            snapshot.message_id,
            snapshot.sender_id,
            snapshot.exclude_user_id,
        )
        self.public_push_scheduler.enqueue(snapshot)

    async def send_public_push_snapshot(self, db: Session, snapshot: PublicPushSnapshot) -> None:
        """Full fan-out of a public push wake to every eligible recipient."""
        logger.info(
            "send_public_push_snapshot start: message_id=%s sender_id=%s exclude_user=%s",
            snapshot.message_id,
            snapshot.sender_id,
            snapshot.exclude_user_id,
        )
        try:
            excluded_ids = {snapshot.sender_id}
            if snapshot.exclude_user_id is not None:
                excluded_ids.add(snapshot.exclude_user_id)

            fcm_user_ids = {
                row[0]
                for row in db.query(FcmToken.user_id)
                .filter(~FcmToken.user_id.in_(excluded_ids))
                .distinct()
                .all()
            }
            web_user_ids = {
                row[0]
                for row in db.query(PushSubscription.user_id)
                .filter(~PushSubscription.user_id.in_(excluded_ids))
                .distinct()
                .all()
            }
            recipient_ids = sorted(fcm_user_ids | web_user_ids)
            logger.info(
                "send_public_push_snapshot recipients=%s (fcm=%s web=%s) for message_id=%s",
                len(recipient_ids),
                len(fcm_user_ids),
                len(web_user_ids),
                snapshot.message_id,
            )

            payload_data = {
                "type": "public_message",
                "message_id": snapshot.message_id,
                "sender_id": snapshot.sender_id,
                "sender_username": snapshot.sender_username,
                "sender_display_name": snapshot.sender_display_name,
            }

            for user_id in recipient_ids:
                fcm_rows = db.query(FcmToken).filter(FcmToken.user_id == user_id).all()
                logger.debug(
                    "send_public_push_snapshot: user=%s fcm_tokens=%d",
                    user_id,
                    len(fcm_rows),
                )

                if fcm_rows and self.firebase_initialized:
                    for fcm in fcm_rows:
                        try:
                            # Data-only: client builds a single MessagingStyle conversation.
                            response = await asyncio.to_thread(
                                self._send_fcm_to_token,
                                fcm.token,
                                snapshot.title,
                                snapshot.body,
                                payload_data,
                                False,
                                _PUBLIC_CHAT_COLLAPSE_KEY,
                            )
                            logger.info(
                                "FCM public push sent user=%s token=%s response=%s",
                                user_id,
                                self._short_token(fcm.token),
                                response,
                            )
                        except Exception as e:
                            logger.error(
                                "Failed to send FCM to user %s token %s: %s",
                                user_id,
                                self._short_token(fcm.token),
                                e,
                            )
                            self._cleanup_failed_fcm_token(db, fcm, str(e))
                elif fcm_rows and not self.firebase_initialized:
                    logger.warning(
                        "Firebase SDK not initialized, skipped FCM pushes for message %s",
                        snapshot.message_id,
                    )

                if user_id in web_user_ids:
                    await self._send_notification_to_user(
                        db,
                        user_id,
                        snapshot.title,
                        snapshot.body,
                        snapshot.icon,
                        payload_data,
                    )
        except Exception as e:
            logger.error(f"Failed to send public message notifications: {e}")

    async def send_public_message_notification(
        self,
        db: Session,
        message: Message,
        exclude_user_id: Optional[int] = None,
    ) -> None:
        """Send public push immediately (tests / legacy). Prefer enqueue for send path."""
        author = message.author
        username = author.username if author else ""
        display_name = (author.display_name if author else None) or ""
        content = message.content or ""
        snapshot = PublicPushSnapshot(
            message_id=message.id,
            sender_id=message.user_id,
            exclude_user_id=exclude_user_id,
            title=f"{display_name or username}",
            body=content[:100] + ("..." if len(content) > 100 else ""),
            icon=author.profile_picture if author else None,
            sender_username=username,
            sender_display_name=display_name,
        )
        await self.send_public_push_snapshot(db, snapshot)

    async def subscribe_user(self, db: Session, user_id: int, endpoint: str, p256dh_key: str, auth_key: str) -> bool:
        """Subscribe a user to push notifications"""
        try:
            # Check if user already has a subscription
            existing_sub = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).first()
            
            if existing_sub:
                # Update existing subscription
                existing_sub.endpoint = endpoint
                existing_sub.p256dh_key = p256dh_key
                existing_sub.auth_key = auth_key
            else:
                # Create new subscription
                new_sub = PushSubscription(
                    user_id=user_id,
                    endpoint=endpoint,
                    p256dh_key=p256dh_key,
                    auth_key=auth_key
                )
                db.add(new_sub)
            
            db.commit()
            logger.info(f"Push subscription saved for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to save push subscription for user {user_id}: {e}")
            db.rollback()
            return False

    async def send_dm_notification(self, db: Session, dm_envelope: DMEnvelope, sender: User):
        """Send push notification for a new DM"""
        logger.info(
            "send_dm_notification start: dm_id=%s sender_id=%s recipient=%s",
            dm_envelope.id,
            sender.id,
            dm_envelope.recipient_id,
        )
        try:
            title = f"{sender.display_name or sender.username}"
            body = "New direct message"
            payload_data = {
                "type": "dm",
                "dm_id": dm_envelope.id,
                "sender_id": sender.id,
                "sender_username": sender.username,
                "sender_display_name": sender.display_name or "",
            }

            fcm_rows = db.query(FcmToken).filter(FcmToken.user_id == dm_envelope.recipient_id).all()
            logger.debug(
                "send_dm_notification: recipient=%s fcm_tokens=%d",
                dm_envelope.recipient_id,
                len(fcm_rows),
            )
            if fcm_rows and self.firebase_initialized:
                for fcm in fcm_rows:
                    try:
                        response = await asyncio.to_thread(
                            self._send_fcm_to_token,
                            fcm.token,
                            title,
                            body,
                            payload_data,
                            False,
                            None,
                        )
                        logger.info(
                            "FCM dm push sent recipient=%s token=%s response=%s",
                            dm_envelope.recipient_id,
                            self._short_token(fcm.token),
                            response,
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to send FCM to user %s token %s: %s",
                            dm_envelope.recipient_id,
                            self._short_token(fcm.token),
                            e,
                        )
                        # Check if this is a permanent failure and clean up the token
                        self._cleanup_failed_fcm_token(db, fcm, str(e))
                if fcm_rows and not self.firebase_initialized:
                    logger.warning(
                        "Firebase SDK not initialized, skipped FCM DM push for dm %s",
                        dm_envelope.id,
                    )

            await self._send_notification_to_user(
                db, dm_envelope.recipient_id, title, body, sender.profile_picture, payload_data
            )
        except Exception as e:
            logger.error(f"Failed to send DM notification: {e}")

    async def _send_notification_to_user(self, db: Session, user_id: int, title: str, body: str, icon: Optional[str], data: dict):
        """Send a push notification to a specific user"""
        try:
            subscription = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).first()
            if not subscription:
                logger.debug("No web push subscription for user %s", user_id)
            if not subscription:
                return

            payload = {
                "title": title,
                "body": body,
                "icon": icon or "about:blank",
                "tag": f"message_{user_id}",
                "data": data
            }

            subscription_info = {
                "endpoint": subscription.endpoint,
                "keys": {
                    "p256dh": subscription.p256dh_key,
                    "auth": subscription.auth_key
                }
            }

            await asyncio.to_thread(
                webpush,
                subscription_info=subscription_info,
                data=json.dumps(payload),
                vapid_private_key=self.vapid_private_key,
                vapid_claims=self.vapid_claims,
            )
            logger.info("WebPush sent to user=%s", user_id)
            
        except WebPushException as e:
            logger.error(f"WebPush error for user {user_id}: {e}")
            # If the subscription is invalid, remove it
            if hasattr(e, 'response') and e.response and e.response.status_code in [410, 404]:
                db.query(PushSubscription).filter(PushSubscription.user_id == user_id).delete()
                db.commit()
        except Exception as e:
            logger.error(f"Failed to send push notification to user {user_id}: {e}")

    def _send_fcm_to_token(
        self,
        token: str,
        title: str,
        body: str,
        data: dict,
        include_notification: bool = True,
        collapse_key: Optional[str] = None,
    ):
        """Send an FCM push to a single device token using Firebase Admin SDK.

        By default this sends both notification + data payloads, but callers can disable
        the notification payload for custom client-side rendering.
        """
        if not self.firebase_initialized:
            raise RuntimeError("Firebase Admin SDK not initialized")

        try:
            payload = {
                "title": title,
                "body": body,
                **{k: str(v) for k, v in (data or {}).items()}
            }

            android_kwargs = {"priority": "high"}
            if collapse_key:
                android_kwargs["collapse_key"] = collapse_key

            if include_notification:
                # Send notification + data payload:
                # notification ensures visibility in system tray when app is background,
                # data keeps app-level handling usable when app is foreground.
                msg = firebase_messaging.Message(
                    token=token,
                    notification=firebase_messaging.Notification(
                        title=title,
                        body=body,
                    ),
                    data=payload,
                    android=firebase_messaging.AndroidConfig(**android_kwargs),
                    apns=firebase_messaging.APNSConfig(headers={"apns-priority": "10"})
                )
            else:
                # Data-only push for custom client-side rendering.
                msg = firebase_messaging.Message(
                    token=token,
                    data=payload,
                    android=firebase_messaging.AndroidConfig(**android_kwargs),
                    apns=firebase_messaging.APNSConfig(headers={"apns-priority": "10"})
                )
            resp = firebase_messaging.send(msg)
            logger.debug("Firebase message queued token=%s", self._short_token(token))
            return resp
        except Exception as e:
            logger.error("Firebase Admin send failed for token %s: %s", self._short_token(token), e)
            raise

    def _cleanup_failed_fcm_token(self, db: Session, fcm_token_entry, error_message: str):
        """Clean up FCM tokens that have permanent failures"""
        try:
            # Check for permanent failure indicators in the error message
            permanent_errors = [
                "unregistered", "invalidregistration", "notregistered",
                "sender_id_mismatch", "invalid_argument"
            ]

            error_lower = error_message.lower()
            is_permanent = any(permanent_error in error_lower for permanent_error in permanent_errors)

            if is_permanent:
                logger.info(
                    "Removing permanently failed FCM token for user %s: %s",
                    fcm_token_entry.user_id,
                    self._short_token(fcm_token_entry.token),
                )
                db.query(FcmToken).filter(FcmToken.id == fcm_token_entry.id).delete()
                db.commit()
            else:
                logger.debug(
                    "Temporary FCM failure for token %s, keeping token: %s",
                    self._short_token(fcm_token_entry.token),
                    error_message,
                )
        except Exception as e:
            logger.error(
                "Failed to cleanup FCM token for user %s: %s",
                fcm_token_entry.user_id,
                e,
            )
            try:
                db.rollback()
            except Exception:
                pass

    async def unsubscribe_user(self, db: Session, user_id: int) -> bool:
        """Unsubscribe a user from push notifications"""
        try:
            db.query(PushSubscription).filter(PushSubscription.user_id == user_id).delete()
            db.commit()
            logger.info(f"Push subscription removed for user {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove push subscription for user {user_id}: {e}")
            db.rollback()
            return False

# Global instance
push_service = PushNotificationService()
