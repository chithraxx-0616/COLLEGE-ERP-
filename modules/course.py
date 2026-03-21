"""
modules/course.py — Course & Enrollment Management
All queries parameterized. RBAC enforced on every action.
"""

from utils.display import print_colored, print_table, print_menu, safe_input
from utils.rbac import require_role
from utils.security import sanitize_string


class CourseManager:
    def __init__(self, db, audit, session):
        self.db      = db
        self.audit   = audit
        self.session = session

    def menu(self):
        while True:
            print_menu("COURSE MANAGEMENT", [
                "Add Course",
                "View All Courses",
                "Enroll Student",
                "View Enrollments",
                "Delete Course",
                "Back"
            ])
            ch = safe_input("Choice: ")
            if ch == "1":   self.add_course()
            elif ch == "2": self.view_courses()
            elif ch == "3": self.enroll_student()
            elif ch == "4": self.view_enrollments()
            elif ch == "5": self.delete_course()
            elif ch == "6": break
            else: print_colored("  Invalid choice.\n", "yellow")

    def add_course(self):
        if not require_role(self.session, "course:add"):
            return
        print_colored("\n  --- Add New Course ---\n", "cyan")
        code   = safe_input("Course Code (e.g. CS101): ")
        name   = safe_input("Course Name: ")
        dept   = safe_input("Department: ")
        creds  = safe_input("Credits [3]: ") or "3"
        fac_id = safe_input("Faculty ID (leave blank if none): ")

        cid = self.db.lastrowid(
            "INSERT INTO courses "
            "(code, name, department, credits, faculty_id) "
            "VALUES (%s, %s, %s, %s, %s)",
            (sanitize_string(code),
             sanitize_string(name),
             sanitize_string(dept),
             creds,
             fac_id or None)
        )
        self.audit.log(self.session["user_id"], "COURSE_ADD",
                       f"Added course id={cid} code={code}")
        print_colored(f"\n  Course added successfully (ID: {cid}).\n",
                      "green")

    def view_courses(self):
        rows = self.db.fetchall(
            "SELECT c.id, c.code, c.name, c.department, "
            "c.credits, f.full_name AS faculty "
            "FROM courses c "
            "LEFT JOIN faculty f ON c.faculty_id = f.id "
            "ORDER BY c.id",
            ()
        )
        print_table(
            ["id", "code", "name", "department", "credits", "faculty"],
            rows
        )

    def view_my_courses(self):
        fac = self.db.fetchone(
            "SELECT id FROM faculty WHERE user_id = %s",
            (self.session["user_id"],)
        )
        if not fac:
            print_colored("  Faculty profile not found.\n", "yellow")
            return
        rows = self.db.fetchall(
            "SELECT id, code, name, department, credits "
            "FROM courses WHERE faculty_id = %s",
            (fac["id"],)
        )
        print_table(
            ["id", "code", "name", "department", "credits"],
            rows
        )

    def view_enrolled(self):
        stu = self.db.fetchone(
            "SELECT id FROM students WHERE user_id = %s",
            (self.session["user_id"],)
        )
        if not stu:
            print_colored("  Student profile not found.\n", "yellow")
            return
        rows = self.db.fetchall(
            "SELECT c.code, c.name, c.department, "
            "c.credits, f.full_name AS faculty "
            "FROM enrollments e "
            "JOIN courses c ON e.course_id = c.id "
            "LEFT JOIN faculty f ON c.faculty_id = f.id "
            "WHERE e.student_id = %s",
            (stu["id"],)
        )
        print_table(
            ["code", "name", "department", "credits", "faculty"],
            rows
        )

    def enroll_student(self):
        if not require_role(self.session, "course:enroll"):
            return
        sid = safe_input("Student ID: ")
        cid = safe_input("Course ID: ")
        self.db.execute(
            "INSERT IGNORE INTO enrollments (student_id, course_id) "
            "VALUES (%s, %s)",
            (sid, cid)
        )
        self.audit.log(self.session["user_id"], "ENROLL",
                       f"Enrolled student={sid} course={cid}")
        print_colored("  Student enrolled successfully.\n", "green")

    def view_enrollments(self):
        rows = self.db.fetchall(
            "SELECT s.full_name, s.roll_no, c.code, "
            "c.name, e.enrolled_at "
            "FROM enrollments e "
            "JOIN students s ON e.student_id = s.id "
            "JOIN courses c  ON e.course_id  = c.id "
            "ORDER BY e.enrolled_at DESC LIMIT 100",
            ()
        )
        print_table(
            ["full_name", "roll_no", "code", "name", "enrolled_at"],
            rows
        )

    def delete_course(self):
        if not require_role(self.session, "course:delete"):
            return
        cid     = safe_input("Course ID to delete: ")
        confirm = safe_input("Type 'DELETE' to confirm: ")
        if confirm != "DELETE":
            print_colored("  Cancelled.\n", "yellow")
            return
        self.db.execute(
            "DELETE FROM courses WHERE id = %s", (cid,)
        )
        self.audit.log(self.session["user_id"], "COURSE_DELETE",
                       f"Deleted course id={cid}")
        print_colored("  Deleted successfully.\n", "green")