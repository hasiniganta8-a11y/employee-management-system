from flask import Flask, request, redirect, render_template, session
import sqlite3
import re
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# Secret key for sessions
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key"
)


# =========================================================
# LOGIN PROTECTION
# =========================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    connection = sqlite3.connect("users.db")
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# CREATE / UPDATE DATABASE
# =========================================================

def create_database():

    connection = get_db_connection()
    cursor = connection.cursor()

    # =====================================================
    # USERS TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            fullname TEXT,
            email TEXT,
            password TEXT,
            theme TEXT DEFAULT 'light'
        )
    """)

    # Get existing user columns
    cursor.execute("PRAGMA table_info(users)")

    user_columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    # Add missing columns if necessary

    if "username" not in user_columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN username TEXT DEFAULT ''
        """)

    if "fullname" not in user_columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN fullname TEXT DEFAULT ''
        """)

    if "email" not in user_columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN email TEXT DEFAULT ''
        """)

    if "password" not in user_columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN password TEXT DEFAULT ''
        """)

    if "theme" not in user_columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN theme TEXT DEFAULT 'light'
        """)

    # =====================================================
    # EMPLOYEES TABLE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT,
            email TEXT,
            department TEXT,
            phone TEXT,
            salary REAL,
            joiningdate TEXT,
            address TEXT
        )
    """)

    # Get existing employee columns
    cursor.execute("PRAGMA table_info(employees)")

    employee_columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    # Add missing employee columns

    if "fullname" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN fullname TEXT DEFAULT ''
        """)

    if "email" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN email TEXT DEFAULT ''
        """)

    if "department" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN department TEXT DEFAULT ''
        """)

    if "phone" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN phone TEXT DEFAULT ''
        """)

    if "salary" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN salary REAL DEFAULT 0
        """)

    if "joiningdate" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN joiningdate TEXT DEFAULT ''
        """)

    if "address" not in employee_columns:
        cursor.execute("""
            ALTER TABLE employees
            ADD COLUMN address TEXT DEFAULT ''
        """)

    connection.commit()
    connection.close()


# Create database when application starts
create_database()


# =========================================================
# START PAGE
# =========================================================

@app.route("/")
def home():
    return redirect("/login")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        fullname = request.form["fullname"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # =================================================
        # PASSWORD VALIDATION
        # =================================================

        # Exactly 6 characters
        # At least:
        # 1 uppercase
        # 1 lowercase
        # 1 number
        # 1 special character

        password_pattern = (
            r"^(?=.*[A-Z])"
            r"(?=.*[a-z])"
            r"(?=.*\d)"
            r"(?=.*[^A-Za-z0-9])"
            r".{6}$"
        )

        if not re.match(password_pattern, password):

            return """
            <h2>Invalid Password</h2>

            <p>Password must be exactly 6 characters.</p>

            <p>It must contain:</p>

            <ul>
                <li>One uppercase letter</li>
                <li>One lowercase letter</li>
                <li>One number</li>
                <li>One special character</li>
            </ul>

            <a href="/register">Go Back</a>
            """

        # =================================================
        # CHECK IF EMAIL ALREADY EXISTS
        # =================================================

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT id
            FROM users
            WHERE email = ?
        """, (email,))

        existing_user = cursor.fetchone()

        if existing_user:

            connection.close()

            return """
            <h2>Email already registered!</h2>
            <a href="/login">Go to Login</a>
            """

        # =================================================
        # HASH PASSWORD
        # =================================================

        hashed_password = generate_password_hash(password)

        # =================================================
        # INSERT USER
        # =================================================

        cursor.execute("""
            INSERT INTO users
            (
                username,
                fullname,
                email,
                password,
                theme
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            fullname,
            email,
            hashed_password,
            "light"
        ))

        connection.commit()
        connection.close()

        # After registration → login
        return redirect("/login")

    return render_template("registerdemo.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        # Get username from login form
        username = request.form.get(
            "username",
            ""
        ).strip()

        # Get password
        password = request.form.get(
            "password",
            ""
        )

        # Get selected theme
        selected_theme = request.form.get(
            "theme",
            "light"
        )

        # Only allow light or dark
        if selected_theme not in ["light", "dark"]:
            selected_theme = "light"

        # =================================================
        # FIND USER
        # =================================================

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER(?)
        """, (username,))

        user = cursor.fetchone()

        # Username not found
        if user is None:

            connection.close()

            return "Invalid username or password!"

        stored_password = user["password"]

        # =================================================
        # CHECK PASSWORD
        # =================================================

        password_correct = False

        try:
            password_correct = check_password_hash(
                stored_password,
                password
            )

        except Exception:
            password_correct = False

        # =================================================
        # SUPPORT OLD PLAIN-TEXT PASSWORDS
        # =================================================

        if not password_correct and stored_password == password:

            password_correct = True

            new_hashed_password = generate_password_hash(
                password
            )

            cursor.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (
                new_hashed_password,
                user["id"]
            ))

        # =================================================
        # INVALID PASSWORD
        # =================================================

        if not password_correct:

            connection.close()

            return "Invalid username or password!"

        # =================================================
        # SAVE THEME
        # =================================================

        cursor.execute("""
            UPDATE users
            SET theme = ?
            WHERE id = ?
        """, (
            selected_theme,
            user["id"]
        ))

        connection.commit()

        # =================================================
        # CREATE SESSION
        # =================================================

        session["user"] = user["fullname"]
        session["username"] = user["username"]
        session["user_id"] = user["id"]
        session["theme"] = selected_theme

        connection.close()

        # Login successful
        return redirect("/employees")

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# =========================================================
# EMPLOYEES
# =========================================================

@app.route("/employees")
@login_required
def employees():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM employees
    """)

    employees = cursor.fetchall()

    connection.close()

    return render_template(
        "employees.html",
        employees=employees
    )


# =========================================================
# ADD EMPLOYEE
# =========================================================

@app.route("/addemployee", methods=["GET", "POST"])
@login_required
def addemployee():

    if request.method == "POST":

        fullname = request.form["fullname"]
        email = request.form["email"]
        department = request.form["department"]
        phone = request.form["phone"]
        salary = request.form["salary"]
        joiningdate = request.form["joiningdate"]
        address = request.form["address"]

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO employees
            (
                fullname,
                email,
                department,
                phone,
                salary,
                joiningdate,
                address
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            fullname,
            email,
            department,
            phone,
            salary,
            joiningdate,
            address
        ))

        connection.commit()
        connection.close()

        return redirect("/employees")

    return render_template("addemployee.html")


# =========================================================
# EDIT EMPLOYEE
# =========================================================

@app.route("/edit/<int:id>")
@login_required
def edit_employee(id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM employees
        WHERE id = ?
    """, (id,))

    employee = cursor.fetchone()

    connection.close()

    if employee is None:
        return "Employee not found!"

    return render_template(
        "editemployee.html",
        employee=employee
    )


# =========================================================
# UPDATE EMPLOYEE
# =========================================================

@app.route("/update/<int:id>", methods=["POST"])
@login_required
def update_employee(id):

    fullname = request.form["fullname"]
    email = request.form["email"]
    department = request.form["department"]
    phone = request.form["phone"]
    salary = request.form["salary"]
    joiningdate = request.form["joiningdate"]
    address = request.form["address"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE employees
        SET
            fullname = ?,
            email = ?,
            department = ?,
            phone = ?,
            salary = ?,
            joiningdate = ?,
            address = ?
        WHERE id = ?
    """, (
        fullname,
        email,
        department,
        phone,
        salary,
        joiningdate,
        address,
        id
    ))

    connection.commit()
    connection.close()

    return redirect("/employees")


# =========================================================
# DELETE EMPLOYEE
# =========================================================

@app.route("/delete/<int:id>")
@login_required
def delete_employee(id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM employees
        WHERE id = ?
    """, (id,))

    connection.commit()
    connection.close()

    return redirect("/employees")


# =========================================================
# SEARCH
# =========================================================

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():

    employees = []

    if request.method == "POST":

        search_text = request.form["search"]

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM employees
            WHERE fullname LIKE ?
            OR email LIKE ?
            OR department LIKE ?
            OR phone LIKE ?
        """, (
            "%" + search_text + "%",
            "%" + search_text + "%",
            "%" + search_text + "%",
            "%" + search_text + "%"
        ))

        employees = cursor.fetchall()

        connection.close()

    return render_template(
        "search.html",
        employees=employees
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )