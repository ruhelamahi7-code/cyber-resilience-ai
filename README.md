# CyberShield AI — Autonomous Cyber Resilience Platform

ET AI Hackathon 2.0 | Problem Statement 7 | Economic Times x Unstop

## Overview
An AI-powered autonomous incident response system that detects, contains, and verifies cyberattacks using a 5-agent pipeline mapped to the MITRE ATT&CK framework.

## Attack Patterns Detected
- T1110 — Brute Force (HIGH severity)
- T1078 — Valid Accounts (CRITICAL severity)

## How to Run
1. Start honeypot: `python3 honeypot.py`
2. Simulate attack: `python3 attacker.py`
3. Run detection: `python3 detector.py`
4. View dashboard: `python3 dashboard.py` → http://127.0.0.1:5002

## Note
Create a `.env` file with your `SLACK_WEBHOOK_URL` before running.

## Benchmark Results
- Detection Rate: 100%
- False Positive Rate: 0%
- Dataset: Simulated based on CICIDS2017 Tuesday statistics
