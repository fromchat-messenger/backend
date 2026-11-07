import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql://main_user:test@localhost:5432/fromchat_main")
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-for-pytest-only")
os.environ.setdefault("MESSAGING_SERVICE_URL", "http://localhost:8301")
os.environ.setdefault("FILE_STORAGE_SERVICE_URL", "http://localhost:8302")
os.environ.setdefault("ENABLE_CHAT_FILTER", "0")
os.environ.setdefault("MESSAGE_RETENTION_DAYS", "180")
os.environ.setdefault("ENCRYPTION_MODE", "compliance")
