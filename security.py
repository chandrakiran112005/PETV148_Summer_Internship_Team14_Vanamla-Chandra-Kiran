import re

# Common weak passwords
COMMON_PASSWORDS = [
    "password",
    "123456",
    "12345678",
    "admin",
    "admin123",
    "qwerty",
    "welcome",
    "letmein",
    "abc123",
    "password123"
]


def analyze_password(username, password):

    checks = []
    suggestions = []

    score = 0
    nist = 0
    owasp = 0

    # -----------------------
    # Length
    # -----------------------
    if len(password) >= 12:
        checks.append(("Minimum 12 Characters", True))
        score += 20
        nist += 20
    else:
        checks.append(("Minimum 12 Characters", False))
        suggestions.append("Use at least 12 characters.")

    # -----------------------
    # Uppercase
    # -----------------------
    if re.search(r"[A-Z]", password):
        checks.append(("Uppercase Letter", True))
        score += 10
        owasp += 10
    else:
        checks.append(("Uppercase Letter", False))
        suggestions.append("Add an uppercase letter.")

    # -----------------------
    # Lowercase
    # -----------------------
    if re.search(r"[a-z]", password):
        checks.append(("Lowercase Letter", True))
        score += 10
        owasp += 10
    else:
        checks.append(("Lowercase Letter", False))
        suggestions.append("Add a lowercase letter.")

    # -----------------------
    # Number
    # -----------------------
    if re.search(r"\d", password):
        checks.append(("Contains Number", True))
        score += 10
        owasp += 10
    else:
        checks.append(("Contains Number", False))
        suggestions.append("Include at least one number.")

    # -----------------------
    # Special Character
    # -----------------------
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        checks.append(("Special Character", True))
        score += 10
        owasp += 10
    else:
        checks.append(("Special Character", False))
        suggestions.append("Include a special character.")

    # -----------------------
    # Username Check
    # -----------------------
    if username.lower() in password.lower():
        checks.append(("Username Not Used", False))
        suggestions.append("Do not include your username in the password.")
    else:
        checks.append(("Username Not Used", True))
        score += 10
        nist += 10

    # -----------------------
    # Common Password
    # -----------------------
    if password.lower() in COMMON_PASSWORDS:
        checks.append(("Common Password", False))
        suggestions.append("This password is commonly used.")
        score -= 20
    else:
        checks.append(("Common Password", True))
        score += 10
        nist += 10

    # -----------------------
    # Sequential Pattern
    # -----------------------
    bad_patterns = [
        "1234",
        "abcd",
        "qwerty",
        "asdf",
        "0000"
    ]

    found = False

    for pattern in bad_patterns:
        if pattern in password.lower():
            found = True
            break

    if found:
        checks.append(("Sequential Pattern", False))
        suggestions.append("Avoid sequential patterns.")
        score -= 10
    else:
        checks.append(("Sequential Pattern", True))
        score += 10

    # -----------------------
    # Repeated Characters
    # -----------------------
    if re.search(r"(.)\1\1", password):
        checks.append(("Repeated Characters", False))
        suggestions.append("Avoid repeating the same character.")
        score -= 10
    else:
        checks.append(("Repeated Characters", True))
        score += 10

    # -----------------------
    # Limit Scores
    # -----------------------
    score = max(0, min(score, 100))
    nist = max(0, min(nist, 100))
    owasp = max(0, min(owasp, 100))

    # -----------------------
    # Status
    # -----------------------
    if score >= 80:
        status = "Strong"
    elif score >= 55:
        status = "Medium"
    else:
        status = "Weak"

    return {
        "score": score,
        "status": status,
        "nist": nist,
        "owasp": owasp,
        "checks": checks,
        "suggestions": suggestions
    }