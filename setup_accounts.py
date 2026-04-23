import bcrypt
import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="ALEX",  
    database="college_erp"
)
cursor = db.cursor()

# Fix ENUM first
cursor.execute("""
    ALTER TABLE users MODIFY COLUMN role 
    ENUM('admin','principal','hod','faculty','student') NOT NULL
""")
db.commit()
print("ENUM updated!")

def create_user(username, password, role):
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")
    cursor.execute(
        "SELECT id FROM users WHERE username = %s", (username,)
    )
    existing = cursor.fetchone()
    if existing:
        print(f"  Already exists: {username}")
        return existing[0]
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) "
        "VALUES (%s, %s, %s)",
        (username, hashed, role)
    )
    db.commit()
    return cursor.lastrowid

def create_faculty(user_id, full_name, dept, designation, email):
    cursor.execute(
        "SELECT id FROM faculty WHERE email = %s", (email,)
    )
    if cursor.fetchone():
        return
    cursor.execute(
        "INSERT INTO faculty "
        "(user_id, full_name, department, designation, email) "
        "VALUES (%s, %s, %s, %s, %s)",
        (user_id, full_name, dept, designation, email)
    )
    db.commit()

# Principal
uid = create_user("principal", "Principal@1234", "principal")
print(f"Created: principal")

# HODs
hod_data = [
    ("hod_aiml",  "Dr. Priya Sharma",  "AIML",          "hod_aiml@college.edu"),
    ("hod_aids",  "Dr. Rahul Mehta",   "AIDS",          "hod_aids@college.edu"),
    ("hod_cyber", "Dr. Anita Nair",    "CYBERSECURITY", "hod_cyber@college.edu"),
    ("hod_cse",   "Dr. Suresh Kumar",  "CSE",           "hod_cse@college.edu"),
    ("hod_ise",   "Dr. Kavitha Rao",   "ISE",           "hod_ise@college.edu"),
    ("hod_civil", "Dr. Ramesh Patil",  "CIVIL",         "hod_civil@college.edu"),
    ("hod_mech",  "Dr. Vijay Reddy",   "MECHANICAL",    "hod_mech@college.edu"),
    ("hod_ece",   "Dr. Sunita Joshi",  "ECE",           "hod_ece@college.edu"),
]

for username, full_name, dept, email in hod_data:
    uid = create_user(username, "Hod@1234", "hod")
    create_faculty(uid, full_name, dept, "HOD & Professor", email)
    print(f"Created HOD: {username} ({dept})")

# Faculty
faculty_data = [
    ("fac_aiml1",  "Prof. Deepa Krishnan", "AIML",          "Assistant Professor", "deepa@college.edu"),
    ("fac_aiml2",  "Prof. Arjun Verma",    "AIML",          "Associate Professor", "arjun@college.edu"),
    ("fac_aids1",  "Prof. Sneha Patel",    "AIDS",          "Assistant Professor", "sneha@college.edu"),
    ("fac_aids2",  "Prof. Kiran Desai",    "AIDS",          "Associate Professor", "kiran@college.edu"),
    ("fac_cyber1", "Prof. Rohit Singh",    "CYBERSECURITY", "Assistant Professor", "rohit@college.edu"),
    ("fac_cyber2", "Prof. Meera Iyer",     "CYBERSECURITY", "Associate Professor", "meera@college.edu"),
    ("fac_cse1",   "Prof. Anil Kumar",     "CSE",           "Assistant Professor", "anil@college.edu"),
    ("fac_cse2",   "Prof. Pooja Mishra",   "CSE",           "Associate Professor", "pooja@college.edu"),
    ("fac_ise1",   "Prof. Ravi Shankar",   "ISE",           "Assistant Professor", "ravi@college.edu"),
    ("fac_ise2",   "Prof. Divya Nair",     "ISE",           "Associate Professor", "divya@college.edu"),
    ("fac_civil1", "Prof. Sunil Joshi",    "CIVIL",         "Assistant Professor", "sunil@college.edu"),
    ("fac_civil2", "Prof. Anjali Gupta",   "CIVIL",         "Associate Professor", "anjali@college.edu"),
    ("fac_mech1",  "Prof. Manoj Tiwari",   "MECHANICAL",    "Assistant Professor", "manoj@college.edu"),
    ("fac_mech2",  "Prof. Rekha Pillai",   "MECHANICAL",    "Associate Professor", "rekha@college.edu"),
    ("fac_ece1",   "Prof. Ganesh Bhat",    "ECE",           "Assistant Professor", "ganesh@college.edu"),
    ("fac_ece2",   "Prof. Lakshmi Menon",  "ECE",           "Associate Professor", "lakshmi@college.edu"),
]

for username, full_name, dept, designation, email in faculty_data:
    uid = create_user(username, "Faculty@1234", "faculty")
    create_faculty(uid, full_name, dept, designation, email)
    print(f"Created Faculty: {username} ({dept})")

db.close()
print("\n✅ All accounts created successfully!")
print("\nCredentials:")
print("principal  → Principal@1234")
print("hod_aiml   → Hod@1234")
print("hod_cse    → Hod@1234")
print("fac_cse1   → Faculty@1234")
print("(same pattern for all)")