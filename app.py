from flask import Flask, render_template, request
from security import analyze_password
from database import (
    initialize_database,
    save_analysis,
    get_history,
    get_report
)
import bcrypt

app = Flask(__name__)

# Create database automatically
initialize_database()

# ==========================
# Home Page
# ==========================

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ==========================
# Analyze Password
# ==========================

@app.route("/analyze", methods=["POST"])
def analyze():

    username = request.form["username"]
    password = request.form["password"]

    # Analyze Password
    result = analyze_password(username, password)

    # Hash Password
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Save into SQLite
    save_analysis(
        username,
        password_hash,
        result["score"],
        result["status"],
        result["nist"],
        result["owasp"]
    )

    return render_template(
        "result.html",
        username=username,
        score=result["score"],
        status=result["status"],
        nist=result["nist"],
        owasp=result["owasp"],
        checks=result["checks"],
        suggestions=result["suggestions"]
    )


# ==========================
# History
# ==========================

@app.route("/history")
def history():

    history_data = get_history()

    return render_template(
        "history.html",
        history=history_data
    )


# ==========================
# Reports
# ==========================

@app.route("/reports")
def reports():

    report = get_report()

    return render_template(
        "reports.html",
        report=report
    )


# ==========================
# Run Application
# ==========================

if __name__ == "__main__":
    app.run(debug=True)