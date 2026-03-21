"""
SECURE COLLEGE ERP SYSTEM
Python + MySQL
Security: SQLi Prevention | RBAC | Auth | Audit Log
"""

from modules.auth import AuthManager
from modules.student import StudentManager
from modules.faculty import FacultyManager
from modules.course import CourseManager
from modules.fees import FeesManager
from modules.audit import AuditLogger
from utils.db import Database
from utils.display import print_banner, print_menu, print_colored


def main():
    print_banner()
    db = Database()
    db.initialize_schema()

    audit = AuditLogger(db)
    auth  = AuthManager(db, audit)

    print_colored("\n  Please login to continue.\n", "cyan")
    session = auth.login()

    if not session:
        print_colored("  Authentication failed. Exiting.\n", "red")
        return

    print_colored(
        f"\n  Welcome, {session['username']}! "
        f"Role: {session['role'].upper()}\n",
        "green"
    )
    audit.log(session["user_id"], "LOGIN",
              f"User logged in with role={session['role']}")

    run_menu(session, db, audit)

    audit.log(session["user_id"], "LOGOUT", "User session ended")
    db.close()
    print_colored("\n  Goodbye! Session closed.\n", "cyan")


def run_menu(session, db, audit):
    student_mgr = StudentManager(db, audit, session)
    faculty_mgr = FacultyManager(db, audit, session)
    course_mgr  = CourseManager(db, audit, session)
    fees_mgr    = FeesManager(db, audit, session)

    role = session["role"]

    menus = {
        "admin": [
            ("Manage Students",   student_mgr.menu),
            ("Manage Faculty",    faculty_mgr.menu),
            ("Manage Courses",    course_mgr.menu),
            ("Manage Fees",       fees_mgr.menu),
            ("View Audit Logs",   lambda: AuditLogger(db).view_logs(session)),
            ("Logout",            None),
        ],
        "faculty": [
            ("View My Courses",   course_mgr.view_my_courses),
            ("View Students",     student_mgr.view_students),
            ("Logout",            None),
        ],
        "student": [
            ("View My Profile",   student_mgr.view_my_profile),
            ("View My Courses",   course_mgr.view_enrolled),
            ("View Fee Status",   fees_mgr.view_my_fees),
            ("Logout",            None),
        ],
    }

    options = menus.get(role, [])

    while True:
        print_menu(
            f"MAIN MENU [{role.upper()}]",
            [o[0] for o in options]
        )
        choice = safe_input("Enter choice: ")

        if not choice.isdigit() or \
           not (1 <= int(choice) <= len(options)):
            print_colored("  Invalid choice.\n", "yellow")
            continue

        label, action = options[int(choice) - 1]

        if action is None:
            break

        action()


if __name__ == "__main__":
    from utils.display import safe_input
    main()