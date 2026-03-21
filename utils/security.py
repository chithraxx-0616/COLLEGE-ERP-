"""
utils/security.py — Cryptographic & Input-Security Utilities

Covers:
  1. Password hashing with bcrypt
  2. Input validation helpers
  3. SQLi pattern detector for audit warnings
"""

import bcrypt
import re
import html


# ── 1. PASSWORD HASHING ────────────────────────────────────────────────────────

BCRYPT_ROUNDS = 12


def hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── 2. INPUT VALIDATION ────────────────────────────────────────────────────────

def validate_email(email: str) -> bool:
    pattern = r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email.strip()))


def validate_phone(phone: str) -> bool:
    return bool(re.match(r"^\+?[\d\s\-]{7,15}$", phone.strip()))


def sanitize_string(value: str, max_len: int = 255) -> str:
    value = value.strip()[:max_len]
    return html.escape(value)


def validate_integer(value: str, min_val: int = 0, max_val: int = 9999):
    try:
        n = int(value)
        return n if min_val <= n <= max_val else None
    except (ValueError, TypeError):
        return None


def validate_date(value: str) -> bool:
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", value.strip()))


# ── 3. SQLI PATTERN DETECTOR ───────────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(--|;|/\*|\*/)",
    r"\b(OR|AND)\b\s+[\w'\"]+\s*=\s*[\w'\"]+",
    r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|EXECUTE|SLEEP|BENCHMARK)\b",
    r"('|\")(\s*)(=|OR|AND)",
    r"xp_cmdshell|information_schema|sys\.",
    r"0x[0-9a-fA-F]+",
    r"char\s*\(",
]

_SQLI_RE = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


def detect_sqli(value: str) -> bool:
    return bool(_SQLI_RE.search(value))


def check_input_for_sqli(field_name: str, value: str, audit_fn=None) -> str:
    if detect_sqli(value):
        warning = f"SQLI PATTERN DETECTED in field '{field_name}': {value!r}"
        print(f"\033[91m  WARNING: {warning}\033[0m")
        if audit_fn:
            audit_fn(None, "SQLI_ATTEMPT", warning)
    return value