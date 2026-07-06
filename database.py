import sqlite3
from datetime import datetime

DATABASE = "password_audit.db"


# ==========================
# Create Database & Table
# ==========================

def initialize_database():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT NOT NULL,

        password_hash TEXT NOT NULL,

        score INTEGER,

        status TEXT,

        nist INTEGER,

        owasp INTEGER,

        date TEXT,

        time TEXT

    )
    """)

    conn.commit()
    conn.close()


# ==========================
# Save Analysis
# ==========================

def save_analysis(username, password_hash, score, status, nist, owasp):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    now = datetime.now()

    date = now.strftime("%d-%m-%Y")

    time = now.strftime("%H:%M:%S")

    cursor.execute("""
    INSERT INTO password_history
    (username,password_hash,score,status,nist,owasp,date,time)

    VALUES(?,?,?,?,?,?,?,?)
    """,(username,password_hash,score,status,nist,owasp,date,time))

    conn.commit()

    conn.close()


# ==========================
# Read History
# ==========================

def get_history():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
    username,
    score,
    status,
    nist,
    owasp,
    date,
    time

    FROM password_history

    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
def get_report():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM password_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE status='Strong'")
    strong = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE status='Medium'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM password_history WHERE status='Weak'")
    weak = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(score) FROM password_history")
    avg_score = cursor.fetchone()[0] or 0

    cursor.execute("SELECT AVG(nist) FROM password_history")
    avg_nist = cursor.fetchone()[0] or 0

    cursor.execute("SELECT AVG(owasp) FROM password_history")
    avg_owasp = cursor.fetchone()[0] or 0

    conn.close()

    return {
        "total": total,
        "strong": strong,
        "medium": medium,
        "weak": weak,
        "avg_score": round(avg_score,2),
        "avg_nist": round(avg_nist,2),
        "avg_owasp": round(avg_owasp,2)
    }