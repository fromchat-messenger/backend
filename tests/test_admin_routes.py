from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from main.admin.auth import require_admin
from main.suspension_task import process_expired_suspensions


def test_require_admin_rejects_non_owner():
    user = SimpleNamespace(id=2, username="alice")
    with pytest.raises(HTTPException) as exc:
        require_admin(user)  # type: ignore[arg-type]
    assert exc.value.status_code == 403


def test_require_admin_allows_owner():
    user = SimpleNamespace(id=1, username="owner")
    assert require_admin(user) is user  # type: ignore[arg-type]


def test_process_expired_suspensions_clears_user():
    db = MagicMock()
    expired_user = SimpleNamespace(
        id=42,
        suspended=True,
        suspension_reason="timed",
        suspension_until=datetime.now() - timedelta(minutes=1),
    )
    db.query.return_value.filter.return_value.all.return_value = [expired_user]

    cleared = process_expired_suspensions(db)
    assert cleared == [42]
    assert expired_user.suspended is False
    assert expired_user.suspension_reason is None
    assert expired_user.suspension_until is None
    db.commit.assert_called_once()


def _route_paths(module_name: str) -> set[str]:
    import importlib

    mod = importlib.import_module(module_name)
    return {getattr(r, "path", "") for r in mod.router.routes}


def test_admin_router_has_compliance_bundle_route():
    paths = _route_paths("main.routes.admin")
    assert "/admin/compliance/bundle" in paths


def test_admin_extras_users_route():
    paths = _route_paths("main.routes.admin_extras")
    assert "/admin/users" in paths
    assert "/admin/moderation/events" in paths
