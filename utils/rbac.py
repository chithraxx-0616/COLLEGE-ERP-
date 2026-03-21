"""
utils/rbac.py — Role-Based Access Control

Defines which roles can perform which actions.
"""

from utils.display import print_colored


# ── Permission Map ─────────────────────────────────────────────────────────────

PERMISSIONS = {
    # Student operations
    "student:add":          {"admin"},
    "student:edit":         {"admin"},
    "student:delete":       {"admin"},
    "student:view_all":     {"admin", "faculty"},
    "student:view_self":    {"admin", "faculty", "student"},

    # Faculty operations
    "faculty:add":          {"admin"},
    "faculty:edit":         {"admin"},
    "faculty:delete":       {"admin"},
    "faculty:view_all":     {"admin"},

    # Course operations
    "course:add":           {"admin"},
    "course:edit":          {"admin"},
    "course:delete":        {"admin"},
    "course:view_all":      {"admin", "faculty", "student"},
    "course:enroll":        {"admin"},
    "course:view_enrolled": {"admin", "faculty", "student"},
    "course:view_mine":     {"admin", "faculty"},

    # Fee operations
    "fees:add":             {"admin"},
    "fees:pay":             {"admin"},
    "fees:view_all":        {"admin"},
    "fees:view_self":       {"admin", "student"},

    # Audit log
    "audit:view":           {"admin"},
}


def has_permission(role: str, action: str) -> bool:
    allowed_roles = PERMISSIONS.get(action, set())
    return role in allowed_roles


def require_role(session: dict, action: str) -> bool:
    if not has_permission(session.get("role", ""), action):
        print_colored(
            f"\n  ACCESS DENIED — '{action}' requires role: "
            f"{PERMISSIONS.get(action, set())}\n",
            "red"
        )
        return False
    return True