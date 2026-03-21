"""
modules/auth.py — Secure Authentication Manager

Security features:
  - bcrypt password verification
  - Account lockout after 5 failed attempts
  - SQLi pattern detection on login inputs
  - All DB queries parameterized
"""

from utils.security import verify_password, check_input_for_sqli
from utils.display import print_colored, safe_input

MAX_FAILED_ATTEMPTS = 5


class AuthManager:
    def __init__(self, db, audit):
        self.db    = db
        self.audit = audit

    def login(self):
        for attempt in range(3):
            username = safe_input("Username: ")
            password = safe_input("Password: ")

            # SQLi Intrusion Detection
            check_input_for_sqli("username", username,
                audit_fn=lambda u, a, d: self.audit.log(None, a, d))
            check_input_for_sqli("password", password,
                audit_fn=lambda u, a, d: self.audit.log(None, a, d))

            # Fetch user — PARAMETERIZED
            user = self.db.fetchone(
                "SELECT id, username, password_hash, role, is_locked, failed_attempts "
                "FROM users WHERE username = %s",
                (username,)
            )

            if not user:
                print_colored("  X  Invalid credentials.\n", "red")
                self.audit.log(None, "LOGIN_FAIL",
                               f"Unknown username: {username!r}")
                continue

            if user["is_locked"]:
                print_colored("  Account is LOCKED. Contact admin.\n", "red")
                self.audit.log(user["id"], "LOGIN_LOCKED",
                               "Attempt on locked account")
                return None

            if verify_password(password, user["password_hash"]):
                self.db.execute(
                    "UPDATE users SET failed_attempts = 0 WHERE id = %s",
                    (user["id"],)
                )
                return {
                    "user_id":  user["id"],
                    "username": user["username"],
                    "role":     user["role"],
                }
            else:
                new_count = user["failed_attempts"] + 1
                lock = 1 if new_count >= MAX_FAILED_ATTEMPTS else 0
                self.db.execute(
                    "UPDATE users SET failed_attempts = %s, "
                    "is_locked = %s WHERE id = %s",
                    (new_count, lock, user["id"])
                )
                self.audit.log(user["id"], "LOGIN_FAIL",
                    f"Failed attempt {new_count}/{MAX_FAILED_ATTEMPTS}")
                if lock:
                    print_colored(
                        "  Too many failures. Account LOCKED.\n", "red")
                    return None
                print_colored(
                    f"  Wrong password. "
                    f"{MAX_FAILED_ATTEMPTS - new_count} attempts left.\n",
                    "red"
                )

        return None

    def create_user(self, username: str, plain_password: str, role: str):
        from utils.security import hash_password
        existing = self.db.fetchone(
            "SELECT id FROM users WHERE username = %s", (username,)
        )
        if existing:
            print_colored(
                f"  Username '{username}' already exists.\n", "yellow")
            return None
        uid = self.db.lastrowid(
            "INSERT INTO users (username, password_hash, role) "
            "VALUES (%s, %s, %s)",
            (username, hash_password(plain_password), role)
        )
        return uid