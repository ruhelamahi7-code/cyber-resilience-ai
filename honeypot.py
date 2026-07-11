from flask import Flask, request, jsonify
import datetime
import json
import os

app = Flask(__name__)
LOG_FILE = "attack_logs.json"
BLOCKLIST_FILE = "blocklist.txt"

STOLEN_CREDENTIALS = [
    {"username": "john.doe", "password": "Summer2024!"},
    {"username": "admin.user", "password": "Company@123"},
    {"username": "finance_head", "password": "Welcome1!"},
    {"username": "ceo_account", "password": "Board@2024"},
    {"username": "sysadmin", "password": "Root@Linux1"},
]

def write_log(entry):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def is_blocked(ip):
    if not os.path.exists(BLOCKLIST_FILE):
        return False
    with open(BLOCKLIST_FILE, "r") as f:
        blocked = [line.strip() for line in f.readlines()]
    return ip in blocked

@app.route("/login", methods=["POST"])
def login():
    # Get real IP or simulated IP from header
    forwarded_ip = request.headers.get("X-Forwarded-For")
    ip = forwarded_ip if forwarded_ip else request.remote_addr

    # Check blocklist BEFORE processing
    if is_blocked(ip):
        print(f"[HONEYPOT] 🚫 BLOCKED request from {ip} — connection refused")
        return jsonify({"error": "Connection refused"}), 403

    data = request.json
    username = data.get("username", "unknown")
    password = data.get("password", "unknown")

    is_valid = any(
        c["username"] == username and c["password"] == password
        for c in STOLEN_CREDENTIALS
    )

    status = "success" if is_valid else "failed"
    http_code = 200 if is_valid else 401

    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "source_ip": ip,
        "username": username,
        "password": password,
        "endpoint": "/login",
        "status": status,
        "attack_type": "T1078" if is_valid else "T1110"
    }

    write_log(entry)
    print(f"[HONEYPOT] {'✅ SUCCESS' if is_valid else '❌ FAILED'} login from {ip} - user: {username}")

    if is_valid:
        return jsonify({"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.fake_token"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running"}), 200

if __name__ == "__main__":
    print("[HONEYPOT] Starting fake login server on port 5001...")
    app.run(host="0.0.0.0", port=5001, debug=False)