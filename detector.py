import json
import os
import datetime
import sqlite3
import requests

LOG_FILE = "attack_logs.json"
DB_FILE = "audit.db"

MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "description": "Adversary attempts to gain access by guessing passwords",
        "threshold": 5,
        "severity": "HIGH"
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Adversary uses stolen credentials to gain access",
        "threshold": 1,
        "severity": "CRITICAL"
    }
}

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            confidence INTEGER,
            decision TEXT,
            action_taken TEXT,
            verification_result TEXT,
            escalated TEXT,
            reasoning TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("[DETECTOR] Database ready.")

def read_attack_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return []

# AGENT 1 — Watcher
def watcher_agent(logs):
    print("\n[AGENT 1 — WATCHER] Reading attack logs...")
    
    ip_attempts = {}
    successful_logins = {}
    
    for entry in logs:
        ip = entry.get("source_ip")
        status = entry.get("status", "failed")
        attack_type = entry.get("attack_type", "T1110")
        
        if ip not in ip_attempts:
            ip_attempts[ip] = []
        ip_attempts[ip].append(entry)
        
        if status == "success":
            if ip not in successful_logins:
                successful_logins[ip] = []
            successful_logins[ip].append(entry)
    
    suspicious = {}
    
    for ip, attempts in ip_attempts.items():
        failed = [a for a in attempts if a.get("status") == "failed"]
        if len(failed) >= 5:
            suspicious[ip] = {"attempts": attempts, "type": "T1110"}
            print(f"[AGENT 1 — WATCHER] T1110 Brute Force from {ip} — {len(failed)} failed attempts")
    
    for ip, successes in successful_logins.items():
        suspicious[ip] = {"attempts": successes, "type": "T1078"}
        print(f"[AGENT 1 — WATCHER] T1078 Valid Accounts from {ip} — {len(successes)} successful logins with stolen credentials")
    
    return suspicious

# AGENT 2 — Judge
def judge_agent(suspicious):
    print("\n[AGENT 2 — JUDGE] Analyzing patterns against MITRE ATT&CK...")
    
    verdicts = []
    for ip, data in suspicious.items():
        attempts = data["attempts"]
        attack_type = data["type"]
        technique = MITRE_TECHNIQUES[attack_type]
        count = len(attempts)
        
        if attack_type == "T1078":
            confidence = 90
            decision = "AUTO_BLOCK"
            reasoning = f"{count} successful login(s) using stolen credentials from {ip}. Matches MITRE T1078 Valid Accounts. Immediate containment required."
        else:
            if count >= 15:
                confidence = 95
            elif count >= 10:
                confidence = 85
            else:
                confidence = 70
            decision = "AUTO_BLOCK"
            reasoning = f"{count} failed login attempts from same IP matches MITRE T1110 Brute Force pattern. Confidence: {confidence}%"
        
        verdict = {
            "source_ip": ip,
            "mitre_id": attack_type,
            "mitre_name": technique["name"],
            "attempt_count": count,
            "confidence": confidence,
            "decision": decision,
            "severity": technique["severity"],
            "reasoning": reasoning
        }
        
        verdicts.append(verdict)
        print(f"[AGENT 2 — JUDGE] {ip} → {technique['name']} ({attack_type}) | Confidence: {confidence}% | Severity: {technique['severity']} | Decision: {decision}")
    
    return verdicts

# AGENT 3 — Doer
def doer_agent(verdicts):
    print("\n[AGENT 3 — DOER] Executing containment actions...")
    
    blocklist_file = "blocklist.txt"
    blocked = []
    
    existing = []
    if os.path.exists(blocklist_file):
        with open(blocklist_file, "r") as f:
            existing = f.read().splitlines()
    
    for verdict in verdicts:
        if verdict["decision"] == "AUTO_BLOCK":
            ip = verdict["source_ip"]
            if ip not in existing:
                with open(blocklist_file, "a") as f:
                    f.write(ip + "\n")
                print(f"[AGENT 3 — DOER] BLOCKED {ip} — added to blocklist")
                blocked.append(ip)
            else:
                print(f"[AGENT 3 — DOER] {ip} already blocked")
                blocked.append(ip)
    
    return blocked

# AGENT 4 — Checker
# AGENT 4 — Checker
def checker_agent(blocked_ips):
    print("\n[AGENT 4 — CHECKER] Verifying containment independently...")
    
    HONEYPOT_URL = "http://127.0.0.1:5001/login"
    results = {}
    
    for ip in blocked_ips:
        # Test 1 — blocked IP should be refused
        try:
            response = requests.post(
                HONEYPOT_URL,
                json={"username": "test", "password": "test"},
                headers={"X-Forwarded-For": ip},
                timeout=5
            )
            if response.status_code == 403:
                results[ip] = "VERIFIED"
                print(f"[AGENT 4 — CHECKER] {ip} — blocked IP got 403 REFUSED — containment VERIFIED ✅")
            else:
                results[ip] = "FAILED"
                print(f"[AGENT 4 — CHECKER] {ip} — blocked IP still got {response.status_code} — containment FAILED ❌")
        except Exception as e:
            results[ip] = "FAILED"
            print(f"[AGENT 4 — CHECKER] {ip} — connection error: {e} — containment FAILED ❌")
    
    # Test 2 — innocent IP should still get through
    innocent_ip = "10.0.0.99"
    try:
        response = requests.post(
            HONEYPOT_URL,
            json={"username": "test", "password": "test"},
            headers={"X-Forwarded-For": innocent_ip},
            timeout=5
        )
        if response.status_code in [200, 401]:
            print(f"[AGENT 4 — CHECKER] {innocent_ip} — innocent IP still gets through ({response.status_code}) — no collateral damage ✅")
        else:
            print(f"[AGENT 4 — CHECKER] {innocent_ip} — innocent IP unexpectedly blocked ({response.status_code}) ⚠️")
    except Exception as e:
        print(f"[AGENT 4 — CHECKER] Innocent IP test failed: {e}")
    
    return results

# AGENT 5 — Fixer
def fixer_agent(verdicts, verification_results):
    print("\n[AGENT 5 — FIXER] Checking for failures...")
    
    failed = [ip for ip, result in verification_results.items() if result == "FAILED"]
    
    if not failed:
        print("[AGENT 5 — FIXER] All containments verified. No escalation needed. ✅")
        return
    
    for ip in failed:
        print(f"[AGENT 5 — FIXER] Containment failed for {ip} — escalating to human via Slack")
        send_slack_alert(ip, verdicts)

def send_slack_alert(ip, verdicts):
    verdict = next((v for v in verdicts if v["source_ip"] == ip), None)
    if not verdict:
        return

    import requests
    
    SLACK_WEBHOOK = "https://hooks.slack.com/services/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"
    from dotenv import load_dotenv
    import os
    load_dotenv()
    SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
    
    message = {
        "text": f"""🚨 *CYBERSHIELD AI — CRITICAL ALERT*
        
*Threat Detected & Containment Failed*

- *Source IP:* `{ip}`
- *Technique:* {verdict['mitre_name']} (`{verdict['mitre_id']}`)
- *Confidence:* {verdict['confidence']}%
- *Attempts:* {verdict['attempt_count']}
- *Decision:* {verdict['decision']}
- *Time:* {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

*Reasoning:* {verdict['reasoning']}

⚠️ Human intervention required — automated containment failed."""
    }
    
    try:
        response = requests.post(SLACK_WEBHOOK, json=message)
        if response.status_code == 200:
            print(f"[AGENT 5 — FIXER] ✅ Slack alert sent successfully")
        else:
            print(f"[AGENT 5 — FIXER] ❌ Slack failed: {response.status_code}")
    except Exception as e:
        print(f"[AGENT 5 — FIXER] ❌ Slack error: {e}")

def write_audit_log(verdicts, verification_results):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    for verdict in verdicts:
        ip = verdict["source_ip"]
        verification = verification_results.get(ip, "NOT_CHECKED")
        escalated = "YES" if verification == "FAILED" else "NO"
        
        c.execute('''
            INSERT INTO audit_log 
            (timestamp, source_ip, mitre_technique_id, mitre_technique_name,
             confidence, decision, action_taken, verification_result, escalated, reasoning)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(),
            ip,
            verdict["mitre_id"],
            verdict["mitre_name"],
            verdict["confidence"],
            verdict["decision"],
            "BLOCKED — added to blocklist",
            verification,
            escalated,
            verdict["reasoning"]
        ))
    
    conn.commit()
    conn.close()
    print("\n[AUDIT LOG] All actions written to audit.db ✅")

def run_pipeline():
    print("=" * 60)
    print("  CYBER RESILIENCE AI — INCIDENT RESPONSE PIPELINE")
    print("=" * 60)
    
    setup_database()
    logs = read_attack_logs()
    
    if not logs:
        print("[SYSTEM] No attack logs found. Run honeypot.py and attacker.py first.")
        return
    
    print(f"[SYSTEM] {len(logs)} log entries loaded.")
    
    suspicious = watcher_agent(logs)
    
    if not suspicious:
        print("[SYSTEM] No suspicious activity detected.")
        return
    
    verdicts = judge_agent(suspicious)
    blocked = doer_agent(verdicts)
    verification_results = checker_agent(blocked)
    fixer_agent(verdicts, verification_results)
    write_audit_log(verdicts, verification_results)
    
    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()
