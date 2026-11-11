from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _fake_create_engine(*_args, **_kwargs):
    engine = MagicMock(name="sqlalchemy_engine")
    conn = MagicMock(name="sqlalchemy_connection")
    conn.execute = MagicMock()
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=conn)
    ctx.__exit__ = MagicMock(return_value=False)
    engine.connect.return_value = ctx
    return engine


# Minimal env so `src.main.constants` can import during tests.
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@127.0.0.1:5432/fromchat_test")
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-pytest-only-32chars")
os.environ.setdefault("MESSAGING_SERVICE_URL", "http://127.0.0.1:8301")
os.environ.setdefault("FILE_STORAGE_SERVICE_URL", "http://127.0.0.1:8302")
os.environ.setdefault("MESSAGE_RETENTION_DAYS", "30")
os.environ.setdefault("CHAT_FILTER_URL", "http://127.0.0.1:8303")
os.environ.setdefault("DATA_DIR", "/tmp/fromchat-pytest-data")
os.environ.setdefault("LOGS_DIR", "/tmp/fromchat-pytest-logs")

patch("sqlalchemy.create_engine", side_effect=_fake_create_engine).start()

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
