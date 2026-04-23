"""
SECURE COLLEGE ERP — Flask Web Application
Main application file
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import mysql.connector
from mysql.connector import Error
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ── Database Config ────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "user":     os.getenv("DB_USER",     "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME",     "college_erp"),
    "charset":  "utf8mb4",
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# ── Auth Helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator

def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def hash_password(plain):
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

def log_audit(user_id, action, detail=""):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip_address) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, action, detail, request.remote_addr)
        )
        db.commit()
        db.close()
    except:
        pass

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, username, password_hash, role, "
                "is_locked, failed_attempts FROM users "
                "WHERE username = %s", (username,)
            )
            user = cursor.fetchone()
            db.close()

            if not user:
                flash("Invalid username or password.", "danger")
                log_audit(None, "LOGIN_FAIL", f"Unknown user: {username}")
                return render_template("auth/login.html")

            if user["is_locked"]:
                flash("Account is locked. Contact admin.", "danger")
                return render_template("auth/login.html")

            if verify_password(password, user["password_hash"]):
                db = get_db()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0 WHERE id = %s",
                    (user["id"],)
                )
                db.commit()
                db.close()

                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session["role"]     = user["role"]

                log_audit(user["id"], "LOGIN", f"Role: {user['role']}")
                flash(f"Welcome, {user['username']}!", "success")
                return redirect(url_for("dashboard"))
            else:
                new_count = user["failed_attempts"] + 1
                lock = 1 if new_count >= 5 else 0
                db = get_db()
                cursor = db.cursor()
                cursor.execute(
                    "UPDATE users SET failed_attempts = %s, "
                    "is_locked = %s WHERE id = %s",
                    (new_count, lock, user["id"])
                )
                db.commit()
                db.close()
                log_audit(user["id"], "LOGIN_FAIL",
                          f"Attempt {new_count}/5")
                if lock:
                    flash("Account locked after too many attempts.", "danger")
                else:
                    flash(f"Wrong password. {5 - new_count} attempts left.",
                          "danger")

        except Error as e:
            flash(f"Database error: {e}", "danger")

    return render_template("auth/login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "principal":
        return redirect(url_for("principal_dashboard"))
    elif role == "hod":
        return redirect(url_for("hod_dashboard"))
    elif role == "faculty":
        return redirect(url_for("faculty_dashboard"))
    elif role == "student":
        return redirect(url_for("student_dashboard"))
    else:
        flash("Unknown role.", "danger")
        return redirect(url_for("logout"))


@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as count FROM students")
    students = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM faculty")
    faculty = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM courses")
    courses = cursor.fetchone()["count"]
    cursor.execute(
        "SELECT COUNT(*) as count FROM fees WHERE status != 'paid'"
    )
    pending_fees = cursor.fetchone()["count"]
    cursor.execute(
        "SELECT al.action, al.detail, al.timestamp, u.username "
        "FROM audit_log al LEFT JOIN users u ON al.user_id = u.id "
        "ORDER BY al.timestamp DESC LIMIT 8"
    )
    logs = cursor.fetchall()
    db.close()
    return render_template("admin/dashboard.html",
        students=students, faculty=faculty,
        courses=courses, pending_fees=pending_fees, logs=logs
    )


@app.route("/principal")
@login_required
@role_required("principal", "admin")
def principal_dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as count FROM students")
    students = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM faculty")
    faculty = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM courses")
    courses = cursor.fetchone()["count"]
    cursor.execute(
        "SELECT f.full_name, f.department, f.designation, "
        "COUNT(c.id) as course_count "
        "FROM faculty f LEFT JOIN courses c ON f.id = c.faculty_id "
        "GROUP BY f.id ORDER BY f.department"
    )
    faculty_list = cursor.fetchall()
    cursor.execute(
        "SELECT lr.*, f.full_name, f.department "
        "FROM leave_requests lr "
        "JOIN faculty f ON lr.faculty_id = f.id "
        "ORDER BY lr.created_at DESC LIMIT 10"
    )
    leaves = cursor.fetchall()
    db.close()
    return render_template("principal/dashboard.html",
        students=students, faculty=faculty,
        courses=courses, faculty_list=faculty_list, leaves=leaves
    )


@app.route("/hod")
@login_required
@role_required("hod", "admin")
def hod_dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT department FROM faculty WHERE user_id = %s",
        (session["user_id"],)
    )
    hod = cursor.fetchone()
    dept = hod["department"] if hod else ""
    cursor.execute(
        "SELECT * FROM faculty WHERE department = %s", (dept,)
    )
    faculty_list = cursor.fetchall()
    cursor.execute(
        "SELECT * FROM students WHERE department = %s", (dept,)
    )
    students = cursor.fetchall()
    cursor.execute(
        "SELECT * FROM events WHERE department = %s "
        "OR department = 'ALL' ORDER BY event_date DESC LIMIT 5",
        (dept,)
    )
    events = cursor.fetchall()
    db.close()
    return render_template("hod/dashboard.html",
        dept=dept, faculty_list=faculty_list,
        students=students, events=events
    )


@app.route("/faculty")
@login_required
@role_required("faculty", "admin")
def faculty_dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.*, u.username FROM faculty f "
        "JOIN users u ON f.user_id = u.id "
        "WHERE f.user_id = %s", (session["user_id"],)
    )
    faculty = cursor.fetchone()
    if faculty:
        cursor.execute(
            "SELECT * FROM courses WHERE faculty_id = %s",
            (faculty["id"],)
        )
        courses = cursor.fetchall()
        cursor.execute(
            "SELECT * FROM leave_requests WHERE faculty_id = %s "
            "ORDER BY created_at DESC LIMIT 5",
            (faculty["id"],)
        )
        leaves = cursor.fetchall()
    else:
        courses = []
        leaves  = []
    db.close()
    return render_template("faculty/dashboard.html",
        faculty=faculty, courses=courses, leaves=leaves
    )


@app.route("/student")
@login_required
@role_required("student", "admin")
def student_dashboard_extra():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT s.*, u.username FROM students s "
        "JOIN users u ON s.user_id = u.id "
        "WHERE s.user_id = %s", (session["user_id"],)
    )
    student = cursor.fetchone()
    if student:
        cursor.execute(
            "SELECT m.*, c.name as course_name, c.code "
            "FROM marks m JOIN courses c ON m.course_id = c.id "
            "WHERE m.student_id = %s", (student["id"],)
        )
        marks = cursor.fetchall()
        cursor.execute(
            "SELECT * FROM fees WHERE student_id = %s",
            (student["id"],)
        )
        fees = cursor.fetchall()
    else:
        marks = []
        fees  = []
    db.close()
    return render_template("student/dashboard.html",
        student=student, marks=marks, fees=fees
    )


@app.route("/logout")
def logout():
    log_audit(session.get("user_id"), "LOGOUT", "User logged out")
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# ══════════════════════════════════════════════════════════════════
# ADMIN — STUDENTS
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/students")
@login_required
@role_required("admin")
def admin_students():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT s.*, u.username FROM students s "
        "JOIN users u ON s.user_id = u.id "
        "ORDER BY s.id"
    )
    students = cursor.fetchall()
    db.close()
    return render_template("admin/students.html", students=students)


@app.route("/admin/students/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_add_student():
    if request.method == "POST":
        username  = request.form.get("username").strip()
        password  = request.form.get("password").strip()
        full_name = request.form.get("full_name").strip()
        roll_no   = request.form.get("roll_no").strip()
        dept      = request.form.get("department").strip()
        semester  = request.form.get("semester").strip()
        email     = request.form.get("email").strip()
        phone     = request.form.get("phone").strip()
        dob       = request.form.get("dob").strip()
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id FROM users WHERE username = %s", (username,)
            )
            if cursor.fetchone():
                flash("Username already exists!", "danger")
                return redirect(url_for("admin_add_student"))
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, 'student')",
                (username, hash_password(password))
            )
            db.commit()
            user_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO students (user_id, full_name, roll_no, "
                "department, semester, email, phone, dob) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (user_id, full_name, roll_no, dept,
                 semester, email, phone, dob or None)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "STUDENT_ADD",
                      f"Added student {full_name} ({roll_no})")
            flash(f"Student {full_name} added successfully!", "success")
            return redirect(url_for("admin_students"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    DEPTS = ["AIML","AIDS","CYBERSECURITY","CSE",
             "ISE","CIVIL","MECHANICAL","ECE"]
    return render_template("admin/add_student.html", depts=DEPTS)


@app.route("/admin/students/delete/<int:sid>")
@login_required
@role_required("admin")
def admin_delete_student(sid):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, full_name FROM students WHERE id = %s",
            (sid,)
        )
        student = cursor.fetchone()
        if student:
            cursor.execute(
                "DELETE FROM students WHERE id = %s", (sid,)
            )
            cursor.execute(
                "DELETE FROM users WHERE id = %s",
                (student["user_id"],)
            )
            db.commit()
            log_audit(session["user_id"], "STUDENT_DELETE",
                      f"Deleted student id={sid}")
            flash("Student deleted successfully!", "success")
        db.close()
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("admin_students"))


# ══════════════════════════════════════════════════════════════════
# ADMIN — FACULTY
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/faculty")
@login_required
@role_required("admin")
def admin_faculty():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.*, u.username FROM faculty f "
        "JOIN users u ON f.user_id = u.id "
        "ORDER BY f.department"
    )
    faculty = cursor.fetchall()
    db.close()
    return render_template("admin/faculty.html", faculty=faculty)


@app.route("/admin/faculty/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_add_faculty():
    if request.method == "POST":
        username    = request.form.get("username").strip()
        password    = request.form.get("password").strip()
        full_name   = request.form.get("full_name").strip()
        dept        = request.form.get("department").strip()
        designation = request.form.get("designation").strip()
        email       = request.form.get("email").strip()
        phone       = request.form.get("phone").strip()
        role        = request.form.get("role", "faculty").strip()
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id FROM users WHERE username = %s", (username,)
            )
            if cursor.fetchone():
                flash("Username already exists!", "danger")
                return redirect(url_for("admin_add_faculty"))
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, %s)",
                (username, hash_password(password), role)
            )
            db.commit()
            user_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO faculty (user_id, full_name, department, "
                "designation, email, phone) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, full_name, dept,
                 designation, email, phone)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "FACULTY_ADD",
                      f"Added faculty {full_name} ({dept})")
            flash(f"Faculty {full_name} added!", "success")
            return redirect(url_for("admin_faculty"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    DEPTS = ["AIML","AIDS","CYBERSECURITY","CSE",
             "ISE","CIVIL","MECHANICAL","ECE"]
    return render_template("admin/add_faculty.html", depts=DEPTS)


@app.route("/admin/faculty/delete/<int:fid>")
@login_required
@role_required("admin")
def admin_delete_faculty(fid):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, full_name FROM faculty WHERE id = %s",
            (fid,)
        )
        fac = cursor.fetchone()
        if fac:
            cursor.execute(
                "DELETE FROM faculty WHERE id = %s", (fid,)
            )
            cursor.execute(
                "DELETE FROM users WHERE id = %s", (fac["user_id"],)
            )
            db.commit()
            log_audit(session["user_id"], "FACULTY_DELETE",
                      f"Deleted faculty id={fid}")
            flash("Faculty deleted!", "success")
        db.close()
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("admin_faculty"))


# ══════════════════════════════════════════════════════════════════
# ADMIN — COURSES
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/courses")
@login_required
@role_required("admin")
def admin_courses():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT c.*, f.full_name as faculty_name "
        "FROM courses c "
        "LEFT JOIN faculty f ON c.faculty_id = f.id "
        "ORDER BY c.department"
    )
    courses = cursor.fetchall()
    db.close()
    return render_template("admin/courses.html", courses=courses)


@app.route("/admin/courses/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_add_course():
    if request.method == "POST":
        code       = request.form.get("code").strip()
        name       = request.form.get("name").strip()
        dept       = request.form.get("department").strip()
        credits    = request.form.get("credits", 3)
        faculty_id = request.form.get("faculty_id") or None
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO courses (code, name, department, "
                "credits, faculty_id) VALUES (%s,%s,%s,%s,%s)",
                (code, name, dept, credits, faculty_id)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "COURSE_ADD",
                      f"Added course {code} - {name}")
            flash(f"Course {name} added!", "success")
            return redirect(url_for("admin_courses"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, full_name, department FROM faculty ORDER BY department")
    faculty = cursor.fetchall()
    db.close()
    DEPTS = ["AIML","AIDS","CYBERSECURITY","CSE",
             "ISE","CIVIL","MECHANICAL","ECE"]
    return render_template("admin/add_course.html",
                           faculty=faculty, depts=DEPTS)


@app.route("/admin/courses/delete/<int:cid>")
@login_required
@role_required("admin")
def admin_delete_course(cid):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM courses WHERE id = %s", (cid,))
        db.commit()
        db.close()
        log_audit(session["user_id"], "COURSE_DELETE",
                  f"Deleted course id={cid}")
        flash("Course deleted!", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("admin_courses"))


# ══════════════════════════════════════════════════════════════════
# ADMIN — FEES
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/fees")
@login_required
@role_required("admin")
def admin_fees():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.*, s.full_name, s.roll_no, s.department "
        "FROM fees f JOIN students s ON f.student_id = s.id "
        "ORDER BY f.status, f.due_date"
    )
    fees = cursor.fetchall()
    db.close()
    return render_template("admin/fees.html", fees=fees)


@app.route("/admin/fees/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_add_fee():
    if request.method == "POST":
        student_id = request.form.get("student_id")
        semester   = request.form.get("semester")
        amount     = request.form.get("amount")
        due_date   = request.form.get("due_date")
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO fees (student_id, semester, "
                "amount, due_date) VALUES (%s,%s,%s,%s)",
                (student_id, semester, amount, due_date)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "FEE_ADD",
                      f"Fee added for student id={student_id}")
            flash("Fee record added!", "success")
            return redirect(url_for("admin_fees"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, full_name, roll_no FROM students ORDER BY full_name"
    )
    students = cursor.fetchall()
    db.close()
    return render_template("admin/add_fee.html", students=students)


@app.route("/admin/fees/pay/<int:fid>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_pay_fee(fid):
    if request.method == "POST":
        amount = float(request.form.get("amount", 0))
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT amount, paid FROM fees WHERE id = %s", (fid,)
            )
            fee = cursor.fetchone()
            new_paid = float(fee["paid"]) + amount
            total    = float(fee["amount"])
            status   = "paid" if new_paid >= total else (
                "partial" if new_paid > 0 else "pending"
            )
            cursor.execute(
                "UPDATE fees SET paid = %s, status = %s WHERE id = %s",
                (new_paid, status, fid)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "FEE_PAYMENT",
                      f"Payment {amount} for fee id={fid}")
            flash(f"Payment recorded! Status: {status.upper()}", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        return redirect(url_for("admin_fees"))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.*, s.full_name FROM fees f "
        "JOIN students s ON f.student_id = s.id WHERE f.id = %s",
        (fid,)
    )
    fee = cursor.fetchone()
    db.close()
    return render_template("admin/pay_fee.html", fee=fee)


# ══════════════════════════════════════════════════════════════════
# ADMIN — AUDIT LOG
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/audit")
@login_required
@role_required("admin")
def admin_audit():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT al.*, u.username FROM audit_log al "
        "LEFT JOIN users u ON al.user_id = u.id "
        "ORDER BY al.timestamp DESC LIMIT 200"
    )
    logs = cursor.fetchall()
    db.close()
    return render_template("admin/audit.html", logs=logs)


# ══════════════════════════════════════════════════════════════════
# ADMIN — USERS
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, username, role, is_locked, "
        "failed_attempts, created_at FROM users ORDER BY role"
    )
    users = cursor.fetchall()
    db.close()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/unlock/<int:uid>")
@login_required
@role_required("admin")
def admin_unlock_user(uid):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET is_locked = 0, failed_attempts = 0 "
        "WHERE id = %s", (uid,)
    )
    db.commit()
    db.close()
    log_audit(session["user_id"], "USER_UNLOCK",
              f"Unlocked user id={uid}")
    flash("User unlocked successfully!", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_add_user():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        role     = request.form.get("role").strip()
        try:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute(
                "SELECT id FROM users WHERE username = %s", (username,)
            )
            if cursor.fetchone():
                flash("Username already exists!", "danger")
                return redirect(url_for("admin_add_user"))
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, %s)",
                (username, hash_password(password), role)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "USER_ADD",
                      f"Added user {username} ({role})")
            flash(f"User {username} created!", "success")
            return redirect(url_for("admin_users"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template("admin/add_user.html")
# ══════════════════════════════════════════════════════════════════
# FACULTY — MARKS
# ══════════════════════════════════════════════════════════════════

@app.route("/faculty/marks", methods=["GET", "POST"])
@login_required
@role_required("faculty", "admin")
def faculty_marks():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id FROM faculty WHERE user_id = %s",
        (session["user_id"],)
    )
    fac = cursor.fetchone()
    if not fac:
        flash("Faculty profile not found.", "danger")
        return redirect(url_for("faculty_dashboard"))

    if request.method == "POST":
        student_id  = request.form.get("student_id")
        course_id   = request.form.get("course_id")
        marks       = request.form.get("marks_obtained")
        max_marks   = request.form.get("max_marks", 100)
        exam_type   = request.form.get("exam_type", "internal")
        try:
            cursor.execute(
                "SELECT id FROM marks WHERE student_id=%s "
                "AND course_id=%s AND exam_type=%s",
                (student_id, course_id, exam_type)
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE marks SET marks_obtained=%s, "
                    "max_marks=%s WHERE id=%s",
                    (marks, max_marks, existing["id"])
                )
            else:
                cursor.execute(
                    "INSERT INTO marks (student_id, course_id, "
                    "marks_obtained, max_marks, exam_type) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    (student_id, course_id, marks, max_marks, exam_type)
                )
            db.commit()
            log_audit(session["user_id"], "MARKS_ENTRY",
                      f"Marks entered for student={student_id} "
                      f"course={course_id}")
            flash("Marks saved successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT * FROM courses WHERE faculty_id = %s",
        (fac["id"],)
    )
    courses = cursor.fetchall()

    cursor.execute(
        "SELECT s.id, s.full_name, s.roll_no, s.department "
        "FROM students s JOIN enrollments e ON s.id = e.student_id "
        "JOIN courses c ON e.course_id = c.id "
        "WHERE c.faculty_id = %s",
        (fac["id"],)
    )
    students = cursor.fetchall()

    cursor.execute(
        "SELECT m.*, s.full_name, s.roll_no, c.name as course_name "
        "FROM marks m JOIN students s ON m.student_id = s.id "
        "JOIN courses c ON m.course_id = c.id "
        "WHERE c.faculty_id = %s ORDER BY m.id DESC",
        (fac["id"],)
    )
    marks_list = cursor.fetchall()
    db.close()
    return render_template("faculty/marks.html",
        courses=courses, students=students, marks_list=marks_list
    )


# ══════════════════════════════════════════════════════════════════
# FACULTY — ATTENDANCE
# ══════════════════════════════════════════════════════════════════

@app.route("/faculty/attendance", methods=["GET", "POST"])
@login_required
@role_required("faculty", "admin")
def faculty_attendance():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id FROM faculty WHERE user_id = %s",
        (session["user_id"],)
    )
    fac = cursor.fetchone()
    if not fac:
        flash("Faculty profile not found.", "danger")
        return redirect(url_for("faculty_dashboard"))

    if request.method == "POST":
        course_id = request.form.get("course_id")
        date      = request.form.get("date")
        students  = request.form.getlist("student_ids")
        present   = request.form.getlist("present")
        try:
            for sid in students:
                status = "present" if sid in present else "absent"
                cursor.execute(
                    "SELECT id FROM attendance WHERE "
                    "student_id=%s AND course_id=%s AND date=%s",
                    (sid, course_id, date)
                )
                existing = cursor.fetchone()
                if existing:
                    cursor.execute(
                        "UPDATE attendance SET status=%s WHERE id=%s",
                        (status, existing["id"])
                    )
                else:
                    cursor.execute(
                        "INSERT INTO attendance (student_id, course_id,"
                        " date, status, marked_by) "
                        "VALUES (%s,%s,%s,%s,%s)",
                        (sid, course_id, date, status,
                         session["user_id"])
                    )
            db.commit()
            log_audit(session["user_id"], "ATTENDANCE_MARKED",
                      f"Attendance marked for course={course_id} "
                      f"date={date}")
            flash("Attendance saved successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT * FROM courses WHERE faculty_id = %s", (fac["id"],)
    )
    courses = cursor.fetchall()

    selected_course = request.args.get("course_id")
    students = []
    attendance_records = []

    if selected_course:
        cursor.execute(
            "SELECT s.id, s.full_name, s.roll_no "
            "FROM students s JOIN enrollments e ON s.id=e.student_id "
            "WHERE e.course_id=%s ORDER BY s.roll_no",
            (selected_course,)
        )
        students = cursor.fetchall()
        cursor.execute(
            "SELECT a.*, s.full_name, s.roll_no "
            "FROM attendance a JOIN students s ON a.student_id=s.id "
            "WHERE a.course_id=%s ORDER BY a.date DESC LIMIT 50",
            (selected_course,)
        )
        attendance_records = cursor.fetchall()

    db.close()
    from datetime import date
    return render_template("faculty/attendance.html",
        courses=courses,
        students=students,
        attendance_records=attendance_records,
        selected_course=selected_course,
        today=date.today()
    )


# ══════════════════════════════════════════════════════════════════
# FACULTY — LEAVE
# ══════════════════════════════════════════════════════════════════

@app.route("/faculty/leave", methods=["GET", "POST"])
@login_required
@role_required("faculty", "hod", "admin")
def faculty_leave():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id FROM faculty WHERE user_id = %s",
        (session["user_id"],)
    )
    fac = cursor.fetchone()
    if not fac:
        flash("Faculty profile not found.", "danger")
        return redirect(url_for("faculty_dashboard"))

    if request.method == "POST":
        from_date = request.form.get("from_date")
        to_date   = request.form.get("to_date")
        reason    = request.form.get("reason")
        try:
            cursor.execute(
                "INSERT INTO leave_requests "
                "(faculty_id, from_date, to_date, reason) "
                "VALUES (%s,%s,%s,%s)",
                (fac["id"], from_date, to_date, reason)
            )
            db.commit()
            log_audit(session["user_id"], "LEAVE_APPLY",
                      f"Leave applied {from_date} to {to_date}")
            flash("Leave application submitted!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT * FROM leave_requests WHERE faculty_id = %s "
        "ORDER BY created_at DESC",
        (fac["id"],)
    )
    leaves = cursor.fetchall()
    db.close()
    return render_template("faculty/leave.html", leaves=leaves)


# ══════════════════════════════════════════════════════════════════
# FACULTY — TIMETABLE
# ══════════════════════════════════════════════════════════════════

@app.route("/faculty/timetable", methods=["GET", "POST"])
@login_required
@role_required("faculty", "hod", "admin")
def faculty_timetable():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.id, f.department FROM faculty f "
        "WHERE f.user_id = %s",
        (session["user_id"],)
    )
    fac = cursor.fetchone()
    if not fac:
        flash("Faculty profile not found.", "danger")
        return redirect(url_for("faculty_dashboard"))

    if request.method == "POST":
        day        = request.form.get("day")
        period     = request.form.get("period")
        course_id  = request.form.get("course_id")
        start_time = request.form.get("start_time")
        end_time   = request.form.get("end_time")
        try:
            cursor.execute(
                "SELECT id FROM timetable WHERE faculty_id=%s "
                "AND day=%s AND period=%s",
                (fac["id"], day, period)
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE timetable SET course_id=%s, "
                    "start_time=%s, end_time=%s WHERE id=%s",
                    (course_id, start_time, end_time, existing["id"])
                )
            else:
                cursor.execute(
                    "INSERT INTO timetable (department, day, period,"
                    " course_id, faculty_id, start_time, end_time) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (fac["department"], day, period, course_id,
                     fac["id"], start_time, end_time)
                )
            db.commit()
            log_audit(session["user_id"], "TIMETABLE_SET",
                      f"Timetable set day={day} period={period}")
            flash("Timetable updated!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT t.*, c.name as course_name, c.code "
        "FROM timetable t LEFT JOIN courses c ON t.course_id=c.id "
        "WHERE t.faculty_id = %s ORDER BY "
        "FIELD(t.day,'Monday','Tuesday','Wednesday',"
        "'Thursday','Friday','Saturday'), t.period",
        (fac["id"],)
    )
    timetable = cursor.fetchall()

    cursor.execute(
        "SELECT id, name, code FROM courses WHERE faculty_id=%s",
        (fac["id"],)
    )
    courses = cursor.fetchall()
    db.close()

    days = ["Monday","Tuesday","Wednesday",
            "Thursday","Friday","Saturday"]
    return render_template("faculty/timetable.html",
        timetable=timetable, courses=courses, days=days
    )


# ══════════════════════════════════════════════════════════════════
# FACULTY — MESSAGES
# ══════════════════════════════════════════════════════════════════

@app.route("/faculty/messages", methods=["GET", "POST"])
@login_required
@role_required("faculty", "hod", "admin")
def faculty_messages():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        receiver_id = request.form.get("receiver_id")
        subject     = request.form.get("subject")
        body        = request.form.get("body")
        try:
            cursor.execute(
                "INSERT INTO messages "
                "(sender_id, receiver_id, subject, body) "
                "VALUES (%s,%s,%s,%s)",
                (session["user_id"], receiver_id, subject, body)
            )
            db.commit()
            log_audit(session["user_id"], "MESSAGE_SENT",
                      f"Message sent to user={receiver_id}")
            flash("Message sent successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT m.*, u.username as sender_name "
        "FROM messages m JOIN users u ON m.sender_id=u.id "
        "WHERE m.receiver_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    inbox = cursor.fetchall()

    cursor.execute(
        "SELECT m.*, u.username as receiver_name "
        "FROM messages m JOIN users u ON m.receiver_id=u.id "
        "WHERE m.sender_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    sent = cursor.fetchall()

    cursor.execute(
        "SELECT id, username, role FROM users "
        "WHERE id != %s ORDER BY role",
        (session["user_id"],)
    )
    users = cursor.fetchall()

    cursor.execute(
        "UPDATE messages SET is_read=1 WHERE receiver_id=%s",
        (session["user_id"],)
    )
    db.commit()
    db.close()

    return render_template("faculty/messages.html",
        inbox=inbox, sent=sent, users=users
    )
# ══════════════════════════════════════════════════════════════════
# HOD — HELPER: GET HOD DEPT
# ══════════════════════════════════════════════════════════════════

def get_hod_dept():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT department FROM faculty WHERE user_id = %s",
        (session["user_id"],)
    )
    hod = cursor.fetchone()
    db.close()
    return hod["department"] if hod else None


# ══════════════════════════════════════════════════════════════════
# HOD — FACULTY
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/faculty")
@login_required
@role_required("hod", "admin")
def hod_faculty():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT f.*, u.username, "
        "(SELECT COUNT(*) FROM courses c WHERE c.faculty_id=f.id) "
        "as course_count, "
        "(SELECT COUNT(*) FROM leave_requests lr "
        "WHERE lr.faculty_id=f.id AND lr.status='pending') "
        "as pending_leaves "
        "FROM faculty f JOIN users u ON f.user_id=u.id "
        "WHERE f.department=%s ORDER BY f.designation",
        (dept,)
    )
    faculty = cursor.fetchall()
    db.close()
    return render_template("hod/faculty.html",
                           faculty=faculty, dept=dept)


# ══════════════════════════════════════════════════════════════════
# HOD — STUDENTS
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/students")
@login_required
@role_required("hod", "admin")
def hod_students():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    semester = request.args.get("semester", "")
    if semester:
        cursor.execute(
            "SELECT s.*, u.username FROM students s "
            "JOIN users u ON s.user_id=u.id "
            "WHERE s.department=%s AND s.semester=%s "
            "ORDER BY s.roll_no",
            (dept, semester)
        )
    else:
        cursor.execute(
            "SELECT s.*, u.username FROM students s "
            "JOIN users u ON s.user_id=u.id "
            "WHERE s.department=%s ORDER BY s.semester, s.roll_no",
            (dept,)
        )
    students = cursor.fetchall()
    db.close()
    return render_template("hod/students.html",
        students=students, dept=dept, semester=semester
    )


# ══════════════════════════════════════════════════════════════════
# HOD — TIMETABLE
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/timetable")
@login_required
@role_required("hod", "admin")
def hod_timetable():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT t.*, c.name as course_name, c.code, "
        "f.full_name as faculty_name "
        "FROM timetable t "
        "LEFT JOIN courses c ON t.course_id=c.id "
        "LEFT JOIN faculty f ON t.faculty_id=f.id "
        "WHERE t.department=%s "
        "ORDER BY FIELD(t.day,'Monday','Tuesday','Wednesday',"
        "'Thursday','Friday','Saturday'), t.period",
        (dept,)
    )
    timetable = cursor.fetchall()
    db.close()
    days = ["Monday","Tuesday","Wednesday",
            "Thursday","Friday","Saturday"]
    periods = list(range(1, 9))
    return render_template("hod/timetable.html",
        timetable=timetable, dept=dept,
        days=days, periods=periods
    )


# ══════════════════════════════════════════════════════════════════
# HOD — EVENTS
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/events")
@login_required
@role_required("hod", "admin")
def hod_events():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM events WHERE department=%s OR department='ALL' "
        "ORDER BY event_date DESC",
        (dept,)
    )
    events = cursor.fetchall()
    db.close()
    return render_template("hod/events.html",
                           events=events, dept=dept)


@app.route("/hod/events/add", methods=["GET", "POST"])
@login_required
@role_required("hod", "admin")
def hod_add_event():
    dept = get_hod_dept()
    if request.method == "POST":
        title       = request.form.get("title").strip()
        description = request.form.get("description").strip()
        event_date  = request.form.get("event_date")
        department  = request.form.get("department", dept)
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO events "
                "(title, description, event_date, "
                "department, created_by) "
                "VALUES (%s,%s,%s,%s,%s)",
                (title, description, event_date,
                 department, session["user_id"])
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "EVENT_ADD",
                      f"Event added: {title}")
            flash(f"Event '{title}' added!", "success")
            return redirect(url_for("hod_events"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    return render_template("hod/add_event.html", dept=dept)


@app.route("/hod/events/delete/<int:eid>")
@login_required
@role_required("hod", "admin")
def hod_delete_event(eid):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM events WHERE id=%s", (eid,))
    db.commit()
    db.close()
    flash("Event deleted!", "success")
    return redirect(url_for("hod_events"))


# ══════════════════════════════════════════════════════════════════
# HOD — MESSAGES
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/messages", methods=["GET", "POST"])
@login_required
@role_required("hod", "admin")
def hod_messages():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        receiver_id  = request.form.get("receiver_id")
        subject      = request.form.get("subject")
        body         = request.form.get("body")
        send_to_all  = request.form.get("send_to_all")
        try:
            if send_to_all == "students":
                cursor.execute(
                    "SELECT u.id FROM users u "
                    "JOIN students s ON u.id=s.user_id "
                    "WHERE s.department=%s", (dept,)
                )
                receivers = cursor.fetchall()
                for r in receivers:
                    cursor.execute(
                        "INSERT INTO messages "
                        "(sender_id,receiver_id,subject,body) "
                        "VALUES (%s,%s,%s,%s)",
                        (session["user_id"], r["id"], subject, body)
                    )
            elif send_to_all == "faculty":
                cursor.execute(
                    "SELECT u.id FROM users u "
                    "JOIN faculty f ON u.id=f.user_id "
                    "WHERE f.department=%s", (dept,)
                )
                receivers = cursor.fetchall()
                for r in receivers:
                    cursor.execute(
                        "INSERT INTO messages "
                        "(sender_id,receiver_id,subject,body) "
                        "VALUES (%s,%s,%s,%s)",
                        (session["user_id"], r["id"], subject, body)
                    )
            else:
                cursor.execute(
                    "INSERT INTO messages "
                    "(sender_id,receiver_id,subject,body) "
                    "VALUES (%s,%s,%s,%s)",
                    (session["user_id"], receiver_id, subject, body)
                )
            db.commit()
            log_audit(session["user_id"], "MESSAGE_SENT",
                      f"HOD sent message: {subject}")
            flash("Message sent successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    # Inbox
    cursor.execute(
        "SELECT m.*, u.username as sender_name "
        "FROM messages m JOIN users u ON m.sender_id=u.id "
        "WHERE m.receiver_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    inbox = cursor.fetchall()

    # Sent
    cursor.execute(
        "SELECT m.*, u.username as receiver_name "
        "FROM messages m JOIN users u ON m.receiver_id=u.id "
        "WHERE m.sender_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    sent = cursor.fetchall()

    # Dept users for sending
    cursor.execute(
        "SELECT u.id, u.username, u.role FROM users u "
        "JOIN faculty f ON u.id=f.user_id "
        "WHERE f.department=%s AND u.id!=%s",
        (dept, session["user_id"])
    )
    dept_faculty = cursor.fetchall()

    cursor.execute(
        "SELECT u.id, u.username, u.role FROM users u "
        "JOIN students s ON u.id=s.user_id "
        "WHERE s.department=%s",
        (dept,)
    )
    dept_students = cursor.fetchall()

    cursor.execute(
        "UPDATE messages SET is_read=1 WHERE receiver_id=%s",
        (session["user_id"],)
    )
    db.commit()
    db.close()

    return render_template("hod/messages.html",
        inbox=inbox, sent=sent,
        dept_faculty=dept_faculty,
        dept_students=dept_students,
        dept=dept
    )


# ══════════════════════════════════════════════════════════════════
# HOD — LEAVE APPROVAL
# ══════════════════════════════════════════════════════════════════

@app.route("/hod/leaves")
@login_required
@role_required("hod", "admin")
def hod_leaves():
    dept = get_hod_dept()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT lr.*, f.full_name, f.designation "
        "FROM leave_requests lr "
        "JOIN faculty f ON lr.faculty_id=f.id "
        "WHERE f.department=%s ORDER BY lr.created_at DESC",
        (dept,)
    )
    leaves = cursor.fetchall()
    db.close()
    return render_template("hod/leaves.html",
                           leaves=leaves, dept=dept)


@app.route("/hod/leaves/<int:lid>/<action>")
@login_required
@role_required("hod", "admin")
def hod_leave_action(lid, action):
    if action not in ["approved", "rejected"]:
        flash("Invalid action.", "danger")
        return redirect(url_for("hod_leaves"))
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE leave_requests SET status=%s WHERE id=%s",
        (action, lid)
    )
    db.commit()
    db.close()
    log_audit(session["user_id"], f"LEAVE_{action.upper()}",
              f"Leave request id={lid} {action}")
    flash(f"Leave {action} successfully!", "success")
    return redirect(url_for("hod_leaves"))
# ══════════════════════════════════════════════════════════════════
# STUDENT — HELPER: GET STUDENT PROFILE
# ══════════════════════════════════════════════════════════════════

def get_student_profile():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM students WHERE user_id = %s",
        (session["user_id"],)
    )
    student = cursor.fetchone()
    db.close()
    return student


@app.route("/student/dashboard")
@login_required
@role_required("student", "admin")
def student_dashboard():
    student = get_student_profile()
    if not student:
        flash("Student profile not found. Contact admin.", "danger")
        return redirect(url_for("login"))

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Attendance
    cursor.execute(
        "SELECT COUNT(*) as total, SUM(status='present') as present "
        "FROM attendance WHERE student_id=%s",
        (student["id"],)
    )
    att = cursor.fetchone()
    att_pct = round((att["present"] / att["total"]) * 100) if att["total"] else 0

    # Fee due
    cursor.execute(
        "SELECT COALESCE(SUM(amount - paid), 0) as due "
        "FROM fees WHERE student_id=%s",
        (student["id"],)
    )
    fee_due = cursor.fetchone()["due"] or 0

    # Open queries
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM queries "
        "WHERE student_id=%s AND status='open'",
        (student["id"],)
    )
    open_queries = cursor.fetchone()["cnt"]

    # Unread messages
    cursor.execute(
        "SELECT COUNT(*) as cnt FROM messages "
        "WHERE receiver_id=%s AND is_read=0",
        (session["user_id"],)
    )
    unread = cursor.fetchone()["cnt"]

    db.close()

    return render_template("student/dashboard.html",
        student=student,
        att_pct=att_pct,
        fee_due=fee_due,
        open_queries=open_queries,
        unread=unread
    )



# ══════════════════════════════════════════════════════════════════
# STUDENT — MARKS
# ══════════════════════════════════════════════════════════════════

@app.route("/student/marks")
@login_required
@role_required("student", "admin")
def student_marks():
    student = get_student_profile()
    if not student:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT m.*, c.name as course_name, c.code "
        "FROM marks m JOIN courses c ON m.course_id=c.id "
        "WHERE m.student_id=%s ORDER BY c.name, m.exam_type",
        (student["id"],)
    )
    marks = cursor.fetchall()

    summary = {}
    for m in marks:
        cname = m["course_name"]
        if cname not in summary:
            summary[cname] = {
                "code": m["code"],
                "exams": [],
                "total": 0,
                "max": 0
            }
        summary[cname]["exams"].append(m)
        summary[cname]["total"] += float(m["marks_obtained"])
        summary[cname]["max"]   += float(m["max_marks"])

    db.close()
    return render_template("student/marks.html",
        student=student, marks=marks, summary=summary
    )


# ══════════════════════════════════════════════════════════════════
# STUDENT — ATTENDANCE
# ══════════════════════════════════════════════════════════════════

@app.route("/student/attendance")
@login_required
@role_required("student", "admin")
def student_attendance():
    student = get_student_profile()
    if not student:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT a.*, c.name as course_name, c.code "
        "FROM attendance a JOIN courses c ON a.course_id=c.id "
        "WHERE a.student_id=%s ORDER BY c.name, a.date DESC",
        (student["id"],)
    )
    records = cursor.fetchall()

    course_stats = {}
    for r in records:
        cname = r["course_name"]
        if cname not in course_stats:
            course_stats[cname] = {
                "code":    r["code"],
                "total":   0,
                "present": 0
            }
        course_stats[cname]["total"] += 1
        if r["status"] == "present":
            course_stats[cname]["present"] += 1

    for cname in course_stats:
        t = course_stats[cname]["total"]
        p = course_stats[cname]["present"]
        course_stats[cname]["percentage"] = (
            round((p / t) * 100) if t > 0 else 0
        )

    db.close()
    return render_template("student/attendance.html",
        student=student,
        records=records,
        course_stats=course_stats
    )


# ══════════════════════════════════════════════════════════════════
# STUDENT — FEES
# ══════════════════════════════════════════════════════════════════

@app.route("/student/fees")
@login_required
@role_required("student", "admin")
def student_fees():
    student = get_student_profile()
    if not student:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM fees WHERE student_id=%s ORDER BY semester",
        (student["id"],)
    )
    fees = cursor.fetchall()

    total_amount = sum(float(f["amount"]) for f in fees)
    total_paid   = sum(float(f["paid"])   for f in fees)
    total_due    = total_amount - total_paid

    db.close()
    return render_template("student/fees.html",
        student=student,
        fees=fees,
        total_amount=total_amount,
        total_paid=total_paid,
        total_due=total_due
    )


# ══════════════════════════════════════════════════════════════════
# STUDENT — QUERIES
# ══════════════════════════════════════════════════════════════════

@app.route("/student/queries", methods=["GET", "POST"])
@login_required
@role_required("student", "admin")
def student_queries():
    student = get_student_profile()
    if not student:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))

    if request.method == "POST":
        subject = request.form.get("subject").strip()
        body    = request.form.get("body").strip()
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO queries (student_id, subject, body) "
                "VALUES (%s,%s,%s)",
                (student["id"], subject, body)
            )
            db.commit()
            db.close()
            log_audit(session["user_id"], "QUERY_RAISED",
                      f"Query: {subject}")
            flash("Query submitted successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM queries WHERE student_id=%s "
        "ORDER BY created_at DESC",
        (student["id"],)
    )
    queries = cursor.fetchall()
    db.close()
    return render_template("student/queries.html",
        student=student, queries=queries
    )


# ══════════════════════════════════════════════════════════════════
# STUDENT — MESSAGES
# ══════════════════════════════════════════════════════════════════

@app.route("/student/messages", methods=["GET", "POST"])
@login_required
@role_required("student", "admin")
def student_messages():
    student = get_student_profile()
    if not student:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))

    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        receiver_id = request.form.get("receiver_id")
        subject     = request.form.get("subject")
        body        = request.form.get("body")
        try:
            cursor.execute(
                "INSERT INTO messages "
                "(sender_id, receiver_id, subject, body) "
                "VALUES (%s,%s,%s,%s)",
                (session["user_id"], receiver_id, subject, body)
            )
            db.commit()
            log_audit(session["user_id"], "MESSAGE_SENT",
                      f"Student sent message to user={receiver_id}")
            flash("Message sent!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")

    cursor.execute(
        "SELECT m.*, u.username as sender_name "
        "FROM messages m JOIN users u ON m.sender_id=u.id "
        "WHERE m.receiver_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    inbox = cursor.fetchall()

    cursor.execute(
        "SELECT m.*, u.username as receiver_name "
        "FROM messages m JOIN users u ON m.receiver_id=u.id "
        "WHERE m.sender_id=%s ORDER BY m.created_at DESC",
        (session["user_id"],)
    )
    sent = cursor.fetchall()

    cursor.execute(
        "SELECT u.id, u.username, f.designation "
        "FROM users u JOIN faculty f ON u.id=f.user_id "
        "WHERE f.department=%s ORDER BY f.designation",
        (student["department"],)
    )
    faculty = cursor.fetchall()

    cursor.execute(
        "UPDATE messages SET is_read=1 WHERE receiver_id=%s",
        (session["user_id"],)
    )
    db.commit()
    db.close()

    return render_template("student/messages.html",
        inbox=inbox, sent=sent, faculty=faculty,
        student=student
    )

# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)