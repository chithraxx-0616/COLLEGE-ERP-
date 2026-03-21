# 🔐 Secure College ERP System
### Python + MySQL | DBMS Project with Cybersecurity Focus

---

## 📋 Project Overview
A full-featured College ERP system built in Python with MySQL, 
demonstrating four core cybersecurity principles.

### Modules
- **Students** — Add, view, search, edit, delete student records
- **Faculty** — Department-wise faculty management
- **Courses** — Course catalog + student enrollment
- **Fees** — Fee records, payment tracking, due reports
- **Audit Log** — Complete action trail, SQLi attempt log

---

## 🔐 Security Features

### 1. SQL Injection Prevention
All queries use parameterized statements — injection is impossible.
```python
# SECURE — used everywhere in this project
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### 2. Role-Based Access Control (RBAC)
| Action | Admin | Faculty | Student |
|--------|-------|---------|---------|
| Manage Students | ✅ | ❌ | ❌ |
| View All Students | ✅ | ✅ | ❌ |
| View Own Profile | ✅ | ✅ | ✅ |
| Manage Fees | ✅ | ❌ | ❌ |
| View Audit Log | ✅ | ❌ | ❌ |

### 3. Password Hashing — bcrypt
- Passwords are NEVER stored in plaintext
- bcrypt with 12 salt rounds
- Constant-time comparison prevents timing attacks

### 4. Audit Logging & Intrusion Detection
- Every action is logged with timestamp and IP address
- SQLi attempts are detected and flagged
- Account locks after 5 failed login attempts

---

## 🚀 Setup & Run

### Prerequisites
- Python 3.10+
- MySQL 8.x or 9.x

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Create database in MySQL
CREATE DATABASE college_erp;

# Run the project
python main.py
```

### Default Login
```
Username: admin
Password: Admin@1234
```

---

## 📁 Project Structure
```
college_erp/
├── main.py                  # Entry point
├── requirements.txt         # Dependencies
├── .env                     # DB credentials (not in GitHub)
├── sql/
│   └── schema.sql           # Database schema
├── modules/
│   ├── auth.py              # Login & lockout
│   ├── audit.py             # Audit logger
│   ├── student.py           # Student CRUD
│   ├── faculty.py           # Faculty CRUD
│   ├── course.py            # Course management
│   └── fees.py              # Fee tracking
└── utils/
    ├── db.py                # DB connection (parameterized)
    ├── security.py          # bcrypt + SQLi detector
    ├── rbac.py              # Permission map
    └── display.py           # Terminal UI
```

---

## 🧪 Security Testing

### Test SQLi Prevention
```
Username: admin' OR '1'='1
Password: anything
→ Login FAILS + SQLI_ATTEMPT logged in audit_log
```

### Test RBAC
```
Login as student → try audit logs
→ ACCESS DENIED
```

### Test Brute Force Lockout
```
Enter wrong password 5 times
→ Account LOCKED automatically
```

---

## 📚 Tech Stack
| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Database | MySQL 8.x / 9.x |
| DB Connector | mysql-connector-python |
| Password Hash | bcrypt (12 rounds) |
| Interface | Command Line |