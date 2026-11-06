import os
from pathlib import Path


def resolve_data_dir() -> Path:
    """App data root. Defaults to /app/data (Docker); override with DATA_DIR."""
    explicit = os.getenv("DATA_DIR")
    if explicit:
        return Path(explicit)
    return Path("/app/data")


DATA_DIR = resolve_data_dir()
_logs_override = os.getenv("LOGS_DIR")
LOGS_DIR = Path(_logs_override) if _logs_override else DATA_DIR / "logs"

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise SystemExit(
        "DATABASE_URL is not set. PostgreSQL is required "
        "(e.g. postgresql://user:pass@postgres:5432/fromchat_main)."
    )
if not DATABASE_URL.startswith("postgresql"):
    raise SystemExit(
        f"DATABASE_URL must be a PostgreSQL URL, got scheme from: {DATABASE_URL.split(':', 1)[0]!r}"
    )

JWT_ALGORITHM = "HS256"
TOKEN_INACTIVITY_EXPIRE_HOURS = 30 * 24
MAX_TOKEN_LIFETIME_HOURS = 365 * 24
# Absolute lifetime for device sessions created while the client is in incognito mode.
INCOGNITO_SESSION_TTL_HOURS = 12
SESSION_KIND_STANDARD = "standard"
SESSION_KIND_INCOGNITO = "incognito"
INCOGNITO_REQUEST_HEADER = "X-FromChat-Incognito"
OWNER_USERNAME = "denis0001-dev"
JWT_SECRET_KEY = os.getenv("JWT_SECRET")

if not JWT_SECRET_KEY:
    raise ValueError("JWT secret key empty")

MESSAGING_SERVICE_URL = os.getenv("MESSAGING_SERVICE_URL")
if not MESSAGING_SERVICE_URL:
    raise SystemExit("MESSAGING_SERVICE_URL is not set.")

FILE_STORAGE_SERVICE_URL = os.getenv("FILE_STORAGE_SERVICE_URL")
if not FILE_STORAGE_SERVICE_URL:
    raise SystemExit("FILE_STORAGE_SERVICE_URL is not set.")

_ENABLE_CHAT_FILTER_RAW = os.getenv("ENABLE_CHAT_FILTER")
if _ENABLE_CHAT_FILTER_RAW is None:
    CHAT_FILTER_DISABLED = False
else:
    _enable = _ENABLE_CHAT_FILTER_RAW.strip().lower()
    if _enable in ("0", "false", "no", "off"):
        CHAT_FILTER_DISABLED = True
    elif _enable in ("1", "true", "yes", "on"):
        CHAT_FILTER_DISABLED = False
    elif not _enable:
        raise SystemExit(
            "ENABLE_CHAT_FILTER is empty. Omit it to enable the chat filter "
            "(default), or set ENABLE_CHAT_FILTER=0 to disable."
        )
    else:
        raise SystemExit(
            f"Invalid ENABLE_CHAT_FILTER={_ENABLE_CHAT_FILTER_RAW!r}. "
            "Use 1/true/yes/on, 0/false/no/off, or omit for enabled (default)."
        )

CHAT_FILTER_URL = (os.getenv("CHAT_FILTER_URL") or "").strip()
if not CHAT_FILTER_DISABLED and not CHAT_FILTER_URL:
    raise SystemExit(
        "CHAT_FILTER_URL is not set. Set it to the chat-filter service URL "
        "(e.g. http://chat_filter:8305), or set ENABLE_CHAT_FILTER=0 to disable."
    )
