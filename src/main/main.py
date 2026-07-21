import asyncio
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import subprocess
import sys
import os
import logging
from sqlalchemy.orm.exc import DetachedInstanceError

# Import from same directory
from .routes import account, messaging, profile, public_chat, push, devices, moderation, download, keys, envelope_messaging, livekit, static as static_routes, auth_steps, admin
from .routes.account import get_server_instance_id
from .models import User
from .constants import OWNER_USERNAME
from .utils import get_client_ip
from .db import POOL_CONFIG, SessionLocal
from .logging_config import access_logger  # noqa: F401 - ensure loggers configured
from .security.audit import log_access
from .security.rate_limit import limiter
from .admin.ip_history import record_ip
from slowapi.middleware import SlowAPIMiddleware

logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = None
    key_lifecycle_task = None
    yandex_id_task = None
    message_stats_task = None
    analytics_task = None

    # Startup - run migration in subprocess to avoid logging interference
    try:
        logger.info("Starting database migration check...")
        # Run migration in a separate process
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.append('.'); from migration import run_migrations; run_migrations()"
            ],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            logger.error(f"Migration subprocess failed with code {result.returncode}")
            if result.stdout:
                logger.error(f"Migration stdout: {result.stdout}")
            if result.stderr:
                logger.error(f"Migration stderr: {result.stderr}")
        else:
            logger.info("Database migrations completed successfully")
    except Exception as e:
        logger.error(f"Failed to run database migrations: {e}")
        raise

    try:
        with SessionLocal() as db:
            owner = db.query(User).filter(User.id == 1).first()
            if owner and not owner.verified:
                owner.verified = True
                db.commit()
                logger.info(f"Owner user '{OWNER_USERNAME}' has been verified")
            elif owner and owner.verified:
                logger.info(f"Owner user '{OWNER_USERNAME}' is already verified")
            else:
                logger.warning(f"Owner user '{OWNER_USERNAME}' not found")
    except Exception as e:
        logger.error(f"Failed to ensure owner verification: {e}")

    logger.info(
        "SQLAlchemy pool configured (size=%s, max_overflow=%s, timeout=%ss, recycle=%ss, pre_ping=%s)",
        POOL_CONFIG["pool_size"],
        POOL_CONFIG["max_overflow"],
        POOL_CONFIG["pool_timeout"],
        POOL_CONFIG["pool_recycle"],
        POOL_CONFIG["pool_pre_ping"],
    )

    # Start the messaging cleanup task
    try:
        # Use absolute import to avoid import errors when package context differs
        from src.main.routes.messaging import messagingManager
        messagingManager.start_cleanup_task()
        logger.info("Messaging cleanup task started")
    except Exception as e:
        logger.error(f"Failed to start messaging cleanup task: {e}")

    # Reset all rate limits on startup to ensure clean state
    # This prevents rate limits from persisting across restarts
    try:
        from .security.rate_limit import reset_all_rate_limits
        cleared = reset_all_rate_limits()
        if cleared > 0:
            logger.info(f"Cleared {cleared} rate limit entries on startup")
    except Exception as e:
        logger.warning(f"Failed to reset rate limits on startup: {e}")

    # Start the rate limit cleanup task
    try:
        from .security.rate_limit import start_rate_limit_cleanup_task
        cleanup_task = asyncio.create_task(start_rate_limit_cleanup_task())
        logger.info("Rate limit cleanup task started")
    except Exception as e:
        logger.error(f"Failed to start rate limit cleanup task: {e}")
        cleanup_task = None

    try:
        from .key_lifecycle_task import key_lifecycle_poll_seconds, start_key_lifecycle_cleanup_task
        _poll = key_lifecycle_poll_seconds()
        if _poll is not None:
            key_lifecycle_task = asyncio.create_task(start_key_lifecycle_cleanup_task(_poll))
            logger.info("Key lifecycle cleanup task started (interval=%ss)", _poll)
        else:
            key_lifecycle_task = None
            logger.info("Key lifecycle cleanup disabled (MESSAGE_RETENTION_DAYS is 0 or -1)")
    except Exception as e:
        logger.error("Failed to start key lifecycle cleanup task: %s", e)
        key_lifecycle_task = None

    try:
        from .yandex_id_lifecycle_task import start_yandex_id_release_task
        yandex_id_task = asyncio.create_task(start_yandex_id_release_task())
        logger.info("Yandex ID release task started")
    except Exception as e:
        logger.error("Failed to start yandex id release task: %s", e)
        yandex_id_task = None

    try:
        from .message_stats_task import start_message_stats_task
        message_stats_task = asyncio.create_task(start_message_stats_task())
        logger.info("Admin message stats sync task started")
    except Exception as e:
        logger.error("Failed to start message stats sync task: %s", e)
        message_stats_task = None

    try:
        from .analytics_task import start_analytics_task
        analytics_task = asyncio.create_task(start_analytics_task())
        logger.info("Admin analytics sample task started")
    except Exception as e:
        logger.error("Failed to start analytics sample task: %s", e)
        analytics_task = None

    yield

    # Shutdown — stop background tasks and force-close WebSockets so Ctrl+C / SIGTERM exits.
    try:
        from src.main.routes.messaging import messagingManager
        await messagingManager.shutdown()
    except Exception as e:
        logger.warning("Messaging manager shutdown failed: %s", e)

    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

    if key_lifecycle_task:
        key_lifecycle_task.cancel()
        try:
            await key_lifecycle_task
        except asyncio.CancelledError:
            pass

    if yandex_id_task:
        yandex_id_task.cancel()
        try:
            await yandex_id_task
        except asyncio.CancelledError:
            pass

    if message_stats_task:
        message_stats_task.cancel()
        try:
            await message_stats_task
        except asyncio.CancelledError:
            pass

    if analytics_task:
        analytics_task.cancel()
        try:
            await analytics_task
        except asyncio.CancelledError:
            pass

INSTANCE_ID_HEADER = "X-FromChat-Instance-Id"

# Initialize FastAPI
app = FastAPI(title="FromChat", lifespan=lifespan)


@app.middleware("http")
async def server_instance_id_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers[INSTANCE_ID_HEADER] = get_server_instance_id()
    return response

# Add rate limiting middleware
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


def _get_username_for_log(user) -> str | None:
    """
    Safely extract username for access logs.

    If the ORM instance is detached, we transparently open a short-lived session,
    reload the user by ID and read the username from that fresh instance.
    Logging must never break request handling.
    """
    if user is None:
        return None

    # Fast path: instance is still bound to a session.
    try:
        return getattr(user, "username", None)
    except DetachedInstanceError:
        # Session is gone; try to reload user by primary key.
        try:
            user_id = getattr(user, "id", None)
        except Exception:
            user_id = None

        if not user_id:
            return None

        try:
            with SessionLocal() as db:
                fresh = db.query(User).filter(User.id == user_id).first()
                return getattr(fresh, "username", None) if fresh is not None else None
        except Exception:
            return None
    except Exception:
        # Fall back to no user information if anything else goes wrong.
        return None


@app.middleware("http")
async def access_logging_middleware(request: Request, call_next):
    # Log incoming request and Authorization header presence for debugging auth issues
    # Skip logging for health check requests
    if request.url.path != "/health":
        try:
            auth_header = request.headers.get("authorization")
            if auth_header:
                short = auth_header[:20] + "..." if len(auth_header) > 20 else auth_header
                logger.info("Incoming request %s %s Authorization=%s", request.method, request.url.path, short)
            else:
                logger.info("Incoming request %s %s Authorization=NONE", request.method, request.url.path)
        except Exception:
            pass
    client_ip = get_client_ip(request)

    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        duration = time.perf_counter() - start
        user = getattr(getattr(request, "state", None), "current_user", None)
        log_access(
            "http_error",
            method=request.method,
            path=request.url.path,
            status="error",
            user=_get_username_for_log(user),
            ip=client_ip,
            duration=f"{duration:.3f}s",
            error=str(exc),
        )
        raise
    else:
        duration = time.perf_counter() - start
        user = getattr(getattr(request, "state", None), "current_user", None)
        if user is not None and getattr(user, "id", None):
            try:
                record_ip(int(user.id), client_ip)
            except Exception:
                pass
        log_access(
            "http_request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            user=_get_username_for_log(user),
            ip=client_ip,
            duration=f"{duration:.3f}s",
        )
        try:
            from .admin.analytics_store import note_event
            note_event("requests")
        except Exception:
            pass
        return response


# Add security middleware (request size limiting and audit logging)
try:
    from src.shared.middleware import add_security_middleware
except ImportError:
    try:
        from src.shared.middleware import add_security_middleware
    except ImportError:
        add_security_middleware = None

if add_security_middleware:
    add_security_middleware(app)

# CORS
_cors_origins = [
    "https://fromchat.ru",
    "https://beta.fromchat.ru",
    "https://www.fromchat.ru",
    "https://admin.fromchat.ru",
    "http://127.0.0.1:8301",
    "http://127.0.0.1:8300",
    "http://127.0.0.1:8306",
    "http://localhost:8301",
    "http://localhost:8300",
    "http://localhost:8306",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*", INSTANCE_ID_HEADER],
)

# Routes
app.include_router(account.router)
app.include_router(auth_steps.router)
app.include_router(envelope_messaging.router)
app.include_router(messaging.router)
app.include_router(public_chat.router)
app.include_router(profile.router)
app.include_router(push.router, prefix="/push")
app.include_router(livekit.router, prefix="/livekit")
app.include_router(devices.router, prefix="/devices")
app.include_router(moderation.router)
app.include_router(admin.router)
app.include_router(download.router)
app.include_router(keys.router)
app.include_router(static_routes.router)


@app.get("/health")
async def health_check():
    """Health check endpoint for Docker health checks."""
    return {"status": "healthy", "service": "main"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8300"))
    uvicorn.run(app, host="0.0.0.0", port=port, timeout_graceful_shutdown=5)
