"""
modules/fees.py — Fee Management
All queries parameterized. RBAC enforced on every action.
"""

from utils.display import print_colored, print_table, print_menu, safe_input
from utils.rbac import require_role


class FeesManager:
    def __init__(self, db, audit, session):
        self.db      = db
        self.audit   = audit
        self.session = session

    def menu(self):
        while True:
            print_menu("FEES MANAGEMENT", [
                "Add Fee Record",
                "View All Fees",
                "Record Payment",
                "View Pending Fees",
                "Back"
            ])
            ch = safe_input("Choice: ")
            if ch == "1":   self.add_fee()
            elif ch == "2": self.view_all_fees()
            elif ch == "3": self.record_payment()
            elif ch == "4": self.view_pending()
            elif ch == "5": break
            else: print_colored("  Invalid choice.\n", "yellow")

    def add_fee(self):
        if not require_role(self.session, "fees:add"):
            return
        print_colored("\n  --- Add Fee Record ---\n", "cyan")
        sid      = safe_input("Student ID: ")
        semester = safe_input("Semester: ")
        amount   = safe_input("Amount (INR): ")
        due_date = safe_input("Due Date (YYYY-MM-DD): ")

        fid = self.db.lastrowid(
            "INSERT INTO fees "
            "(student_id, semester, amount, due_date) "
            "VALUES (%s, %s, %s, %s)",
            (sid, semester, amount, due_date or None)
        )
        self.audit.log(self.session["user_id"], "FEE_ADD",
                       f"Fee record id={fid} student={sid}")
        print_colored(
            f"\n  Fee record created successfully (ID: {fid}).\n",
            "green"
        )

    def view_all_fees(self):
        if not require_role(self.session, "fees:view_all"):
            return
        rows = self.db.fetchall(
            "SELECT f.id, s.full_name, s.roll_no, "
            "f.semester, f.amount, f.paid, f.status, f.due_date "
            "FROM fees f "
            "JOIN students s ON f.student_id = s.id "
            "ORDER BY f.id",
            ()
        )
        print_table(
            ["id", "full_name", "roll_no",
             "semester", "amount", "paid", "status", "due_date"],
            rows
        )

    def record_payment(self):
        if not require_role(self.session, "fees:pay"):
            return
        fid    = safe_input("Fee Record ID: ")
        amount = safe_input("Payment amount (INR): ")

        try:
            pay = float(amount)
        except ValueError:
            print_colored("  Invalid amount.\n", "yellow")
            return

        rec = self.db.fetchone(
            "SELECT amount, paid FROM fees WHERE id = %s", (fid,)
        )
        if not rec:
            print_colored("  Fee record not found.\n", "yellow")
            return

        new_paid = float(rec["paid"]) + pay
        total    = float(rec["amount"])

        if new_paid >= total:
            status = "paid"
        elif new_paid > 0:
            status = "partial"
        else:
            status = "pending"

        self.db.execute(
            "UPDATE fees SET paid = %s, status = %s WHERE id = %s",
            (new_paid, status, fid)
        )
        self.audit.log(self.session["user_id"], "FEE_PAYMENT",
                       f"Payment {pay} for fee id={fid} | status={status}")
        print_colored(
            f"\n  Payment recorded. Status: {status.upper()}\n",
            "green"
        )

    def view_pending(self):
        if not require_role(self.session, "fees:view_all"):
            return
        rows = self.db.fetchall(
            "SELECT f.id, s.full_name, s.roll_no, "
            "f.semester, f.amount, f.paid, f.due_date "
            "FROM fees f "
            "JOIN students s ON f.student_id = s.id "
            "WHERE f.status != 'paid' "
            "ORDER BY f.due_date",
            ()
        )
        print_table(
            ["id", "full_name", "roll_no",
             "semester", "amount", "paid", "due_date"],
            rows
        )

    def view_my_fees(self):
        if not require_role(self.session, "fees:view_self"):
            return
        stu = self.db.fetchone(
            "SELECT id FROM students WHERE user_id = %s",
            (self.session["user_id"],)
        )
        if not stu:
            print_colored("  Student profile not found.\n", "yellow")
            return
        rows = self.db.fetchall(
            "SELECT id, semester, amount, paid, status, due_date "
            "FROM fees WHERE student_id = %s",
            (stu["id"],)
        )
        print_table(
            ["id", "semester", "amount", "paid", "status", "due_date"],
            rows
        )