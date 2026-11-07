import re

def is_valid_username(username: str) -> bool:
    if len(username) < 3 or len(username) > 20:
        return False
    # Only allow English letters, numbers, dashes and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False
    return True


def is_valid_display_name(display_name: str) -> bool:
    if len(display_name) < 1 or len(display_name) > 64:
        return False
    # Check if not blank (only whitespace)
    if not display_name.strip():
        return False
    return True


def is_valid_password(password: str) -> bool:
    """Legacy check for derived auth secrets (login) and backward-compatible register paths."""
    if len(password) < 5 or len(password) > 50:
        return False
    if re.search(r'[\s\u180E\u200B-\u200D\u2060\uFEFF]', password):
        return False
    return True


_COMMON_PASSWORDS = frozenset({
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "qwerty123",
    "qwertyui",
    "letmein1",
    "welcome1",
    "admin123",
    "passw0rd",
    "changeme",
    "fromchat1",
})


def is_valid_new_password_plaintext(password: str) -> bool:
    """Stricter rules for new registrations and password changes (plaintext, client-side mirror)."""
    if len(password) < 8 or len(password) > 50:
        return False
    if re.search(r'[\s\u180E\u200B-\u200D\u2060\uFEFF]', password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^a-zA-Z0-9]", password):
        return False
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        return False
    if re.fullmatch(r"(.+)\1+", lowered):
        return False
    return True