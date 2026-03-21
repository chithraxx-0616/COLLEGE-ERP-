"""
modules/faculty.py — Faculty Management
All queries parameterized. RBAC enforced on every action.
"""

from utils.display import print_colored, print_table, print_menu, safe_input
from utils.rbac import require_role
from utils.security import validate_email, sanitize_string


class FacultyManager:
    def __init__(self, db, audit, session):
        self.db      = db
        self.audit   = audit
        self.session = session

    def menu(self):
        while True:
            print_menu("FACULTY MANAGEMENT", [
                "Add Faculty",
                "View All Faculty",
                "Edit Faculty",
                "Delete Faculty",
                "Back"
            ])
            ch = safe_input("Choice: ")
            if ch == "1":   self.add_faculty()
            elif ch == "2": self.view_faculty()
            elif ch == "3": self.edit_faculty()
            elif ch == "4": self.delete_faculty()
            elif ch == "5": break
            else: print_colored("  Invalid choice.\n", "yellow")

    def add_faculty(self):
        if not require_role(self.session, "faculty:add"):
            return
        from modules.auth import AuthManager
        print_colored("\n  --- Add New Faculty ---\n", "cyan")
        username    = safe_input("Login username: ")
        password    = safe_input("Login password: ")
        full_name   = safe_input("Full Name: ")
        dept        = safe_input("Department: ")
        designation = safe_input("Designation: ")
        email       = safe_input("Email: ")
        phone       = safe_input("Phone: ")

        if email and not validate_email(email):
            print_colored("  Invalid email format.\n", "yellow")
            return

        auth = AuthManager(self.db, self.audit)
        uid  = auth.create_user(username, password, "faculty")
        if not uid:
            return

        fid = self.db.lastrowid(
            "INSERT INTO faculty "
            "(user_id, full_name, department, designation, email, phone) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (uid,
             sanitize_string(full_name),
             sanitize_string(dept),
             sanitize_string(designation),
             email or None,
             phone or None)
        )
        self.audit.log(self.session["user_id"], "FACULTY_ADD",
                       f"Added faculty id={fid}")
        print_colored(f"\n  Faculty added successfully (ID: {fid}).\n",
                      "green")

    def view_faculty(self):
        if not require_role(self.session, "faculty:view_all"):
            return
        rows = self.db.fetchall(
            "SELECT id, full_name, department, designation, email "
            "FROM faculty ORDER BY id",
            ()
        )
        print_table(
            ["id", "full_name", "department", "designation", "email"],
            rows
        )

    def edit_faculty(self):
        if not require_role(self.session, "faculty:edit"):
            return
        fid = safe_input("Faculty ID to edit: ")
        row = self.db.fetchone(
            "SELECT * FROM faculty WHERE id = %s", (fid,)
        )
        if not row:
            print_colored("  Faculty not found.\n", "yellow")
            return
        print(f"  Editing: {row['full_name']}")
        dept  = safe_input(f"Department [{row['department']}]: ") \
                or row['department']
        desig = safe_input(f"Designation [{row['designation']}]: ") \
                or row['designation']
        email = safe_input(f"Email [{row['email']}]: ") \
                or row['email']
        self.db.execute(
            "UPDATE faculty SET department = %s, "
            "designation = %s, email = %s WHERE id = %s",
            (sanitize_string(str(dept)),
             sanitize_string(str(desig)),
             email, fid)
        )
        self.audit.log(self.session["user_id"], "FACULTY_EDIT",
                       f"Edited faculty id={fid}")
        print_colored("  Updated successfully.\n", "green")

    def delete_faculty(self):
        if not require_role(self.session, "faculty:delete"):
            return
        fid     = safe_input("Faculty ID to delete: ")
        confirm = safe_input("Type 'DELETE' to confirm: ")
        if confirm != "DELETE":
            print_colored("  Cancelled.\n", "yellow")
            return
        self.db.execute(
            "DELETE FROM faculty WHERE id = %s", (fid,)
        )
        self.audit.log(self.session["user_id"], "FACULTY_DELETE",
                       f"Deleted faculty id={fid}")
        print_colored("  Deleted successfully.\n", "green")