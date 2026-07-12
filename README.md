# 🛡️ CyberShield AI — Autonomous Cyber Resilience Platform

> ET AI Hackathon 2.0 | Problem Statement 7 | Economic Times x Unstop 2026

---

## 📌 Problem Statement

India's critical national infrastructure faces escalating cyber threats. CERT-In reported over 1.59 million cybersecurity incidents in 2023. Most organizations discover breaches weeks after initial infiltration — because they rely on signature-based detection that fails against new attack patterns.

**CyberShield AI** addresses this by building a behavioural intelligence layer that detects anomalies autonomously, maps them to known threat frameworks, and executes containment — compressing response time from hours to seconds.

---

## 🎯 Solution Overview

An AI-powered autonomous incident response pipeline with 5 specialized agents that detect, analyze, contain, verify, and escalate cyberattacks — with full audit logging and zero human intervention required for standard threats.

---

## 🤖 The 5 Agents

| Agent | Role | What it does |
|-------|------|-------------|
| 👁 **Watcher** | Detection | Monitors honeypot logs, groups attempts by IP, flags suspicious activity |
| ⚖ **Judge** | Analysis | Maps patterns to MITRE ATT&CK framework, assigns confidence score and severity |
| 🔒 **Doer** | Containment | Executes autonomous block — writes IP to blocklist, enforced by honeypot |
| ✓ **Checker** | Verification | Independently verifies containment by sending real HTTP request and confirming 403 response |
| 🔧 **Fixer** | Escalation | If verification fails, sends formatted Slack alert with full reasoning trail |

---

## 🎯 Attack Patterns Detected

### T1110 — Brute Force (HIGH Severity)
Detects repeated failed login attempts from the same IP address. Threshold: 5+ attempts triggers autonomous block.

### T1078 — Valid Accounts (CRITICAL Severity)
Detects successful logins using stolen credentials. Even a single successful login with known stolen credentials triggers immediate containment.

---

## ✅ Key Differentiators

**Real Independent Verification**
Most systems trust their own API when it says "blocked." Our Checker agent independently sends a fresh HTTP request from the blocked IP and confirms it receives a 403 REFUSED response — not just reads back the file it wrote.

**No Collateral Damage Check**
After blocking an attacker IP, Checker also sends a request from an innocent IP and confirms it still gets through — proving the block is targeted, not blanket.

**Full Reasoning Audit Trail**
Every agent decision is logged with timestamp, technique ID, confidence score, and human-readable reasoning — making the system fully auditable.

**Two MITRE ATT&CK Techniques**
Detects both failed-login brute force (T1110) and successful stolen-credential attacks (T1078) with different severity levels and confidence scoring.

---

## 📊 Benchmark Results

Evaluated against a synthetic dataset modelled on CICIDS2017 Tuesday statistics (13.7% attack ratio):

| Metric | Result |
|--------|--------|
| Detection Rate | 100% |
| False Positive Rate | 0% |
| Precision | 100% |
| Accuracy | 100% |
| Total Flows Tested | 1,000 |
| Attack Flows | 137 |
| Benign Flows | 863 |

Full results in `benchmark_results.json`

---

## 🏗️ Architecture
Attacker (simulated)
↓
Honeypot Server (Flask — port 5001)

Logs all attempts to attack_logs.json
Enforces blocklist before processing requests
↓
Detector Pipeline
├── Agent 1: Watcher — reads logs, detects suspicious IPs
├── Agent 2: Judge — MITRE ATT&CK mapping, confidence scoring
├── Agent 3: Doer — writes to blocklist.txt
├── Agent 4: Checker — HTTP verification (real 403 check)
└── Agent 5: Fixer — Slack escalation if verification fails
↓
Audit Log (SQLite) + Dashboard (Flask — port 5002)


---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.9 |
| Web Framework | Flask |
| Database | SQLite |
| Alerts | Slack SDK + Incoming Webhooks |
| Frontend | HTML/CSS/JavaScript |
| Benchmarking | Custom synthetic dataset (CICIDS2017 methodology) |

---

## 🚀 How to Run

### Prerequisites
```bash
pip3 install flask requests slack-sdk python-dotenv
```

### Setup
Create a `.env` file in the project root:
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

### Running the Demo

**Terminal 1 — Start honeypot:**
```bash
python3 honeypot.py
```

**Terminal 2 — Simulate brute force attack:**
```bash
python3 attacker.py
```

**Terminal 2 — Simulate stolen credentials attack:**
```bash
python3 attacker.py t1078
```

**Terminal 3 — Run detection pipeline:**
```bash
python3 detector.py
```

**Terminal 4 — Start dashboard:**
```bash
python3 dashboard.py
```
Open browser at `http://127.0.0.1:5002`

### Run Benchmark
```bash
python3 benchmark.py
```

---

## 📁 File Structure
cyber-resilience-ai/
├── honeypot.py          # Fake login server — trap for attackers
├── attacker.py          # Attack simulator (T1110 + T1078)
├── detector.py          # 5-agent detection pipeline
├── dashboard.py         # Live web dashboard
├── benchmark.py         # Detection accuracy evaluation
├── benchmark_results.json  # Benchmark output
├── .gitignore           # Excludes .env and sensitive files
└── README.md

---

## 🔒 Security Note

This system runs entirely on sandboxed infrastructure. All attack traffic is self-generated against our own honeypot. No external systems are targeted or scanned. In production deployment, the same agent pipeline connects to real SCADA/ICS environments via secure API integration.

---

## 📋 Judging Criteria Coverage

| Criteria | How We Address It |
|----------|------------------|
| Anomaly detection rate | 100% on CICIDS2017-modelled benchmark |
| False positive rate | 0% — threshold-based detection is precise |
| MITRE ATT&CK attribution | T1110 and T1078 correctly identified with confidence scores |
| Autonomous response % | 100% — no human needed for standard containment |
| Detection/response time | Sub-second detection, instant containment |
| Full auditability | Every agent decision logged with timestamp and reasoning |

---

## 👤 Team

Built for ET AI Hackathon 2.0 — Phase 2 Build Sprint
Problem Statement 7: AI-Driven Cyber Resilience for Critical National Infrastructure
