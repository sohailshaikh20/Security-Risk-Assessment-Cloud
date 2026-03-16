"""
Starbucks Order Microservice — INTENTIONALLY VULNERABLE
=========================================================
This application contains deliberate security flaws designed
to be detected by Semgrep (SAST) and Trivy (SCA) scanners.
DO NOT deploy this application in any real environment.
"""

import os
import sqlite3
import hashlib
import subprocess
import logging
import yaml
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)

# ==========================================
# VULNERABILITY: Hardcoded secrets
# ==========================================

DATABASE_URL = "sqlite:///orders.db"
SECRET_KEY = "super-secret-key-12345"
API_KEY = "ak_live_xJ9kP2mN5vQ8rT3wY6zA"
JWT_SECRET = "jwt-secret-never-change"

app.config["SECRET_KEY"] = SECRET_KEY


# ==========================================
# VULNERABILITY: SQL Injection
# ==========================================

def get_db():
    conn = sqlite3.connect("orders.db")
    return conn


@app.route("/orders", methods=["GET"])
def get_orders():
    customer = request.args.get("customer", "")

    conn = get_db()

    # VULN: SQL injection via string concatenation
    query = "SELECT * FROM orders WHERE customer = '" + customer + "'"
    results = conn.execute(query).fetchall()

    return jsonify(results)


@app.route("/order/<order_id>", methods=["GET"])
def get_order(order_id):
    conn = get_db()

    # VULN: SQL injection via format string
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    result = conn.execute(query).fetchone()

    return jsonify(result)


# ==========================================
# VULNERABILITY: Command Injection
# ==========================================

@app.route("/health", methods=["GET"])
def health_check():
    host = request.args.get("host", "localhost")

    # VULN: OS command injection
    result = os.popen(f"ping -c 1 {host}").read()

    return jsonify({"status": result})


@app.route("/logs", methods=["GET"])
def get_logs():
    filename = request.args.get("file", "app.log")

    # VULN: command injection via subprocess
    output = subprocess.check_output(
        f"cat /var/log/{filename}",
        shell=True
    )

    return output


# ==========================================
# VULNERABILITY: Path Traversal
# ==========================================

@app.route("/menu", methods=["GET"])
def get_menu():
    category = request.args.get("category", "drinks")

    # VULN: path traversal
    filepath = os.path.join("/data/menus", category + ".json")

    with open(filepath) as f:
        return f.read()


# ==========================================
# VULNERABILITY: Insecure Deserialization
# ==========================================

@app.route("/import", methods=["POST"])
def import_config():
    data = request.get_data()

    # VULN: unsafe YAML deserialization
    config = yaml.load(data, Loader=yaml.FullLoader)

    return jsonify({"imported": True})


# ==========================================
# VULNERABILITY: Weak Cryptography
# ==========================================

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    # VULN: MD5 is broken for password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password_hash)
    )
    conn.commit()

    return jsonify({"user": username})


# ==========================================
# VULNERABILITY: Open Redirect
# ==========================================

@app.route("/redirect", methods=["GET"])
def open_redirect():
    url = request.args.get("url", "/")

    # VULN: unvalidated redirect
    return redirect(url)


# ==========================================
# VULNERABILITY: Debug mode / Info Exposure
# ==========================================

@app.route("/debug", methods=["GET"])
def debug_info():
    # VULN: exposes environment variables
    return jsonify({
        "env": dict(os.environ),
        "secret_key": SECRET_KEY,
        "api_key": API_KEY,
    })


# ==========================================
# VULNERABILITY: Missing security headers,
# debug mode enabled
# ==========================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # VULN: debug=True in production
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=True
    )
