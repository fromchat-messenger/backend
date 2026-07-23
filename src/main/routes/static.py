"""
Static legal documents and expressive icons served from the instance deploy.
"""

from html import escape
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["static"])

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_ICONS_DIR = _STATIC_DIR / "icons"

# Deep link the HTTPS VK ID callback forwards to (Android WebView / app).
_VK_OAUTH_DEEP_LINK = "fromchat://oauth/vk"


@router.get("/oauth/vk", response_class=HTMLResponse)
async def vk_oauth_redirect_landing(request: Request) -> HTMLResponse:
    """
    Trusted HTTPS redirect URL for VK ID (Web apps require https).

    Forwards to fromchat://oauth/vk with the same query string (meta refresh, no JS).
    The Android WebView intercepts the HTTPS URL before this page renders.
    """
    qs = request.url.query
    deep_link = _VK_OAUTH_DEEP_LINK
    if qs:
        deep_link = f"{deep_link}?{qs}"
    href = escape(deep_link, quote=True)
    html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="refresh" content="0;url={href}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>FromChat</title>\n"
        "</head>\n"
        "<body></body>\n"
        "</html>\n"
    )
    return HTMLResponse(content=html, status_code=200)


@router.get("/static/PRIVACY.md")
async def privacy_markdown() -> FileResponse:
    path = _STATIC_DIR / "PRIVACY.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="PRIVACY.md not found")
    return FileResponse(path, media_type="text/markdown; charset=utf-8")


@router.get("/static/TERMS.md")
async def terms_markdown() -> FileResponse:
    path = _STATIC_DIR / "TERMS.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="TERMS.md not found")
    return FileResponse(path, media_type="text/markdown; charset=utf-8")


@router.get("/static/icons/{name}.webp")
async def static_icon(name: str) -> FileResponse:
    safe = Path(name).name
    if safe != name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid icon name")
    path = _ICONS_DIR / f"{safe}.webp"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Icon not found")
    return FileResponse(path, media_type="image/webp")
