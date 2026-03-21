"""
modules/audit.py — Audit Logger & Intrusion Log Viewer
Every sensitive action is recorded with parameterized inserts.
"""

import socket
from utils.display import print_colored, print_table, print_menu, safe_input
from utils.rbac import require_role


def _get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


class AuditLogger:
    def __init__(self, db):
        self.db = db
        self.ip = _get_ip()

    def log(self, user_id, action: str, detail: str = ""):
        self.db.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip_address) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, action, detail, self.ip)
        )

    def view_logs(self, session):
        if not require_role(session, "audit:view"):
            return

        while True:
            print_menu("AUDIT LOG VIEWER", [
                "Latest 50 Entries",
                "Filter by Action",
                "Filter by User ID",
                "SQLi Attempts Only",
                "Back"
            ])
            ch = safe_input("Choice: ")

            if ch == "1":
                rows = self.db.fetchall(
                    "SELECT al.id, u.username, al.action, al.detail, "
                    "al.ip_address, al.timestamp "
                    "FROM audit_log al "
                    "LEFT JOIN users u ON al.user_id = u.id "
                    "ORDER BY al.timestamp DESC LIMIT 50",
                    ()
                )
                print_table(
                    ["id", "username", "action",
                     "detail", "ip_address", "timestamp"],
                    rows
                )

            elif ch == "2":
                action = safe_input("Action keyword (e.g. LOGIN): ")
                rows = self.db.fetchall(
                    "SELECT al.id, u.username, al.action, "
                    "al.detail, al.timestamp "
                    "FROM audit_log al "
                    "LEFT JOIN users u ON al.user_id = u.id "
                    "WHERE al.action LIKE %s "
                    "ORDER BY al.timestamp DESC LIMIT 100",
                    (f"%{action}%",)
                )
                print_table(
                    ["id", "username", "action", "detail", "timestamp"],
                    rows
                )

            elif ch == "3":
                uid = safe_input("User ID: ")
                rows = self.db.fetchall(
                    "SELECT id, action, detail, ip_address, timestamp "
                    "FROM audit_log WHERE user_id = %s "
                    "ORDER BY timestamp DESC LIMIT 100",
                    (uid,)
                )
                print_table(
                    ["id", "action", "detail", "ip_address", "timestamp"],
                    rows
                )

            elif ch == "4":
                rows = self.db.fetchall(
                    "SELECT al.id, u.username, al.detail, "
                    "al.ip_address, al.timestamp "
                    "FROM audit_log al "
                    "LEFT JOIN users u ON al.user_id = u.id "
                    "WHERE al.action = 'SQLI_ATTEMPT' "
                    "ORDER BY al.timestamp DESC",
                    ()
                )
                if rows:
                    print_colored(
                        "\n  *** SQLI INTRUSION ATTEMPTS ***\n", "red")
                else:
                    print_colored(
                        "\n  No SQLi attempts logged.\n", "green")
                print_table(
                    ["id", "username", "detail",
                     "ip_address", "timestamp"],
                    rows
                )

            elif ch == "5":
                break
            else:
                print_colored("  Invalid choice.\n", "yellow")