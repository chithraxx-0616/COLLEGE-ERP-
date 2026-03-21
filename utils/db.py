"""
utils/db.py — Secure Database Manager
All queries use parameterized statements — prevents SQL Injection.
"""

import mysql.connector
from mysql.connector import Error
from utils.display import print_colored
import os
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":       os.getenv("DB_HOST",     "localhost"),
    "user":       os.getenv("DB_USER",     "root"),
    "password":   os.getenv("DB_PASSWORD", ""),
    "database":   os.getenv("DB_NAME",     "college_erp"),
    "charset":    "utf8mb4",
    "autocommit": False,
}


class Database:
    def __init__(self):
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = mysql.connector.connect(**DB_CONFIG)
            print_colored("  DB Connected Successfully.\n", "green")
        except Error as e:
            print_colored(f"  DB Connection Error: {e}", "red")
            raise SystemExit(1)

    def close(self):
        if self.conn and self.conn.is_connected():
            self.conn.close()

    # ── Core Execute — PARAMETERIZED ONLY ─────────────────────────────────────
    def execute(self, sql: str, params: tuple = ()):
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            self.conn.commit()
            return cursor
        except Error as e:
            self.conn.rollback()
            print_colored(f"  DB Error: {e}", "red")
            return None

    def fetchone(self, sql: str, params: tuple = ()):
        try:
            cursor = self.conn.cursor(dictionary=True)
            cursor.execute(sql, params)
            return cursor.fetchone()
        except Error as e:
            print_colored(f"  DB Error: {e}", "red")
            return None

    def fetchall(self, sql: str, params: tuple = ()):
        try:
            cursor = self.conn.cursor(dictionary=True)
            cursor.execute(sql, params)
            return cursor.fetchall()
        except Error as e:
            print_colored(f"  DB Error: {e}", "red")
            return []

    def lastrowid(self, sql: str, params: tuple = ()):
        cursor = self.execute(sql, params)
        return cursor.lastrowid if cursor else None

    # ── Schema Bootstrap ───────────────────────────────────────────────────────
    def initialize_schema(self):
        statements = [
            """CREATE TABLE IF NOT EXISTS users (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                username      VARCHAR(60)  NOT NULL UNIQUE,
                password_hash VARCHAR(256) NOT NULL,
                role          ENUM('admin','faculty','student') NOT NULL,
                is_locked     TINYINT(1) DEFAULT 0,
                failed_attempts INT DEFAULT 0,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",

            """CREATE TABLE IF NOT EXISTS students (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                user_id     INT,
                full_name   VARCHAR(120) NOT NULL,
                roll_no     VARCHAR(30)  NOT NULL UNIQUE,
                department  VARCHAR(80),
                semester    INT,
                email       VARCHAR(120) UNIQUE,
                phone       VARCHAR(20),
                dob         DATE,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )""",

            """CREATE TABLE IF NOT EXISTS faculty (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                user_id     INT,
                full_name   VARCHAR(120) NOT NULL,
                department  VARCHAR(80),
                designation VARCHAR(80),
                email       VARCHAR(120) UNIQUE,
                phone       VARCHAR(20),
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )""",

            """CREATE TABLE IF NOT EXISTS courses (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                code        VARCHAR(20)  NOT NULL UNIQUE,
                name        VARCHAR(120) NOT NULL,
                department  VARCHAR(80),
                credits     INT DEFAULT 3,
                faculty_id  INT,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (faculty_id) REFERENCES faculty(id) ON DELETE SET NULL
            )""",

            """CREATE TABLE IF NOT EXISTS enrollments (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                student_id  INT NOT NULL,
                course_id   INT NOT NULL,
                enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uq_enroll (student_id, course_id),
                FOREIGN KEY (student_id) REFERENCES students(id),
                FOREIGN KEY (course_id)  REFERENCES courses(id)
            )""",

            """CREATE TABLE IF NOT EXISTS fees (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                student_id  INT NOT NULL,
                semester    INT NOT NULL,
                amount      DECIMAL(10,2) NOT NULL,
                paid        DECIMAL(10,2) DEFAULT 0,
                due_date    DATE,
                status      ENUM('pending','partial','paid') DEFAULT 'pending',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id)
            )""",

            """CREATE TABLE IF NOT EXISTS audit_log (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                user_id     INT,
                action      VARCHAR(80) NOT NULL,
                detail      TEXT,
                ip_address  VARCHAR(45),
                timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )""",
        ]

        for stmt in statements:
            self.execute(stmt)

        self._seed_default_admin()

    def _seed_default_admin(self):
        from utils.security import hash_password
        existing = self.fetchone(
            "SELECT id FROM users WHERE role = %s LIMIT 1", ("admin",)
        )
        if not existing:
            hashed = hash_password("Admin@1234")
            self.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                ("admin", hashed, "admin")
            )
            print_colored(
                "  Default admin created — username: admin | password: Admin@1234\n",
                "yellow"
            )