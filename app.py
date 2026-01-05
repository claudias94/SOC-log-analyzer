from flask import Flask, render_template, request, redirect, url_for, session, flash
import re
from collections import Counter
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_this_to_something_secret'

LOG_FILE = "logs/auth.log"

# Hardcoded user credentials (for demo purposes)
USERNAME = "admin"
PASSWORD = "StrongPassword123"

def analyze_logs():
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    failed_logs = []
    failed_ips = []
    root_sessions = 0

    with open(LOG_FILE, "r") as f:
        for line in f:
            if "Failed password" in line:
                failed_logs.append(line.strip())
                match = re.search(ip_pattern, line)
                if match:
                    failed_ips.append(match.group(1))
            elif "session opened for user root" in line:
                root_sessions += 1

    ip_counter = Counter(failed_ips)
    incident_detected = len(failed_logs) > 0

    if not incident_detected:
        severity = "NONE"
        attack_type = "No malicious activity detected"
        mitre_attack = "N/A"
    else:
        max_attempts = max(ip_counter.values())
        if max_attempts >= 10:
            severity = "HIGH"
        elif max_attempts >= 5:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        attack_type = "SSH Brute Force Attack (Credential Access)"
        mitre_attack = "T1110 - Brute Force"

    return {
        "root_sessions": root_sessions,
        "failed_login_count": len(failed_logs),
        "attack_type": attack_type,
        "severity": severity,
        "mitre_attack": mitre_attack,
        "ip_attempts": ip_counter,
        "sample_failed_logs": failed_logs[:10]
    }

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@login_required
def index():
    data = analyze_logs()
    return render_template("dashboard.html", data=data)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

