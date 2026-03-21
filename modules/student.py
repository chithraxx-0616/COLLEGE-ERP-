"""
modules/student.py — Student Management
All queries parameterized. RBAC enforced on every action.
"""

from utils.display import print_colored, print_table, print_menu, safe_input
from utils.rbac import require_role
from utils.security import (check_input_for_sqli, validate_email,
                             sanitize_string)


class StudentManager:
    def __init__(self, db, audit, session):
        self.db      = db
        self.audit   = audit
        self.session = session

    def _sqli_check(self, field, val):
        check_input_for_sqli(
            field, val,
            lambda u, a, d: self.audit.log(self.session["user_id"], a, d)
        )

    def menu(self):
        while True:
            print_menu("STUDENT MANAGEMENT", [
                "Add Student",
                "View All Students",
                "Search Student",
                "Edit Student",
                "Delete Student",
                "Back"
            ])
            ch = safe_input("Choice: ")
            if ch == "1":   self.add_student()
            elif ch == "2": self.view_students()
            elif ch == "3": self.search_student()
            elif ch == "4": self.edit_student()
            elif ch == "5": self.delete_student()
            elif ch == "6": break
            else: print_colored("  Invalid choice.\n", "yellow")

    def add_student(self):
        if not require_role(self.session, "student:add"):
            return
        from modules.auth import AuthManager
        print_colored("\n  --- Add New Student ---\n", "cyan")
        username  = safe_input("Login username: ")
        password  = safe_input("Login password: ")
        full_name = safe_input("Full Name: ")
        roll_no   = safe_input("Roll Number: ")
        dept      = safe_input("Department: ")
        sem       = safe_input("Semester (1-8): ")
        email     = safe_input("Email: ")
        phone     = safe_input("Phone: ")
        dob       = safe_input("DOB (YYYY-MM-DD): ")

        for f, v in [("username", username),
                     ("full_name", full_name),
                     ("roll_no", roll_no)]:
            self._sqli_check(f, v)

        if email and not validate_email(email):
            print_colored("  Invalid email format.\n", "yellow")
            return

        auth = AuthManager(self.db, self.audit)
        uid  = auth.create_user(username, password, "student")
        if not uid:
            return

        sid = self.db.lastrowid(
            "INSERT INTO students "
            "(user_id, full_name, roll_no, department, "
            "semester, email, phone, dob) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (uid,
             sanitize_string(full_name),
             sanitize_string(roll_no),
             sanitize_string(dept),
             sem or None,
             email or None,
             phone or None,
             dob or None)
        )
        self.audit.log(self.session["user_id"], "STUDENT_ADD",
                       f"Added student id={sid} roll={roll_no}")
        print_colored(f"\n  Student added successfully (ID: {sid}).\n",
                      "green")

    def view_students(self):
        if not require_role(self.session, "student:view_all"):
            return
        rows = self.db.fetchall(
            "SELECT id, full_name, roll_no, department, semester, email "
            "FROM students ORDER BY id",
            ()
        )
        print_table(
            ["id", "full_name", "roll_no", "department", "semester", "email"],
            rows
        )

    def view_my_profile(self):
        row = self.db.fetchone(
            "SELECT s.* FROM students s "
            "JOIN users u ON s.user_id = u.id "
            "WHERE u.id = %s",
            (self.session["user_id"],)
        )
        if row:
            print_colored("\n  --- My Profile ---\n", "cyan")
            for k, v in row.items():
                print(f"    {k:<15}: {v}")
            print()
        else:
            print_colored("  Profile not found.\n", "yellow")

    def search_student(self):
        if not require_role(self.session, "student:view_all"):
            return
        term = safe_input("Search by name or roll number: ")
        self._sqli_check("search", term)
        rows = self.db.fetchall(
            "SELECT id, full_name, roll_no, department, semester, email "
            "FROM students "
            "WHERE full_name LIKE %s OR roll_no LIKE %s",
            (f"%{term}%", f"%{term}%")
        )
        print_table(
            ["id", "full_name", "roll_no", "department", "semester", "email"],
            rows
        )

    def edit_student(self):
        if not require_role(self.session, "student:edit"):
            return
        sid = safe_input("Student ID to edit: ")
        row = self.db.fetchone(
            "SELECT * FROM students WHERE id = %s", (sid,)
        )
        if not row:
            print_colored("  Student not found.\n", "yellow")
            return
        print(f"  Editing: {row['full_name']} ({row['roll_no']})")
        dept  = safe_input(f"Department [{row['department']}]: ") \
                or row['department']
        sem   = safe_input(f"Semester [{row['semester']}]: ") \
                or row['semester']
        email = safe_input(f"Email [{row['email']}]: ") \
                or row['email']
        self.db.execute(
            "UPDATE students SET department = %s, "
            "semester = %s, email = %s WHERE id = %s",
            (sanitize_string(str(dept)), sem, email, sid)
        )
        self.audit.log(self.session["user_id"], "STUDENT_EDIT",
                       f"Edited student id={sid}")
        print_colored("  Updated successfully.\n", "green")

    def delete_student(self):
        if not require_role(self.session, "student:delete"):
            return
        sid     = safe_input("Student ID to delete: ")
        confirm = safe_input(
            f"Type 'DELETE' to confirm removal of student #{sid}: "
        )
        if confirm != "DELETE":
            print_colored("  Cancelled.\n", "yellow")
            return
        self.db.execute(
            "DELETE FROM students WHERE id = %s", (sid,)
        )
        self.audit.log(self.session["user_id"], "STUDENT_DELETE",
                       f"Deleted student id={sid}")
        print_colored("  Deleted successfully.\n", "green")