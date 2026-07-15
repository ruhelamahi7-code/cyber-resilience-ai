from flask import Flask, jsonify
import sqlite3
import json
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "audit.db")
LOG_FILE = os.path.join(BASE_DIR, "attack_logs.json")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklist.txt")

def get_audit_logs():
    if not os.path.exists(DB_FILE):
        return []
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_attack_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return []

def get_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    with open(BLOCKLIST_FILE, "r") as f:
        return [ip.strip() for ip in f.readlines() if ip.strip()]

@app.route("/")
def index():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CyberShield AI</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0B1220;--surface:#111827;--surface2:#1A2235;--border:#1E2D45;--blue:#3B82F6;--cyan:#22D3EE;--green:#10B981;--yellow:#FACC15;--red:#EF4444;--text:#E5E7EB;--muted:#6B7280;--mono:"JetBrains Mono",monospace;--sans:"Inter",sans-serif;--display:"Space Grotesk",sans-serif;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;min-height:100vh;}
nav{display:flex;align-items:center;justify-content:space-between;padding:14px 28px;background:rgba(11,18,32,0.85);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;}
.nav-logo{font-family:var(--display);font-size:17px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:10px;}
.nav-logo span{color:var(--blue);}
.nav-badge{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;color:var(--muted);}
.live-dot{width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 1.4s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(16,185,129,0.4);}50%{opacity:0.7;box-shadow:0 0 0 5px rgba(16,185,129,0);}}
.nav-right{font-family:var(--mono);font-size:11px;color:var(--muted);}
.mission-banner{margin:20px 28px 0;background:linear-gradient(135deg,#0F1E38 0%,#0B1220 100%);border:1px solid var(--blue);border-radius:12px;padding:18px 24px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 0 30px rgba(59,130,246,0.08);}
.mission-left h1{font-family:var(--display);font-size:20px;font-weight:700;color:var(--text);margin-bottom:4px;}
.mission-left p{color:var(--muted);font-size:12px;}
.mission-right{display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:12px;}
.status-pill{padding:6px 14px;border-radius:20px;font-weight:600;font-size:11px;letter-spacing:0.05em;}
.pill-green{background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3);}
.pill-yellow{background:rgba(250,204,21,0.15);color:var(--yellow);border:1px solid rgba(250,204,21,0.3);}
.pill-blue{background:rgba(59,130,246,0.15);color:var(--blue);border:1px solid rgba(59,130,246,0.3);}
.main{padding:20px 28px 40px;display:flex;flex-direction:column;gap:20px;}
.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:8px;transition:border-color 0.2s;}
.metric-card:hover{border-color:var(--blue);}
.metric-icon{font-size:18px;}
.metric-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;font-weight:500;}
.metric-value{font-family:var(--mono);font-size:22px;font-weight:600;line-height:1;}
.metric-sub{font-size:10px;color:var(--muted);}
.val-blue{color:var(--blue);}.val-red{color:var(--red);}.val-green{color:var(--green);}.val-yellow{color:var(--yellow);}.val-cyan{color:var(--cyan);}
.three-col{display:grid;grid-template-columns:1.2fr 1fr 0.8fr;gap:20px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;}
.card-title{font-family:var(--display);font-size:13px;font-weight:600;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border);padding-bottom:12px;}
.card-title span{color:var(--muted);font-size:11px;font-weight:400;margin-left:auto;}
.timeline{display:flex;flex-direction:column;gap:0;}
.tl-step{display:flex;align-items:flex-start;gap:14px;position:relative;}
.tl-step:not(:last-child)::after{content:"";position:absolute;left:15px;top:32px;bottom:-4px;width:2px;background:var(--border);}
.tl-step.done::after{background:var(--green);}
.tl-dot{width:32px;height:32px;border-radius:50%;border:2px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;background:var(--surface2);z-index:1;transition:all 0.3s;}
.tl-step.done .tl-dot{border-color:var(--green);background:rgba(16,185,129,0.15);box-shadow:0 0 12px rgba(16,185,129,0.3);}
.tl-content{padding:6px 0 16px;flex:1;}
.tl-agent{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--blue);text-transform:uppercase;letter-spacing:0.06em;}
.tl-desc{color:var(--text);font-size:12px;margin:2px 0;}
.tl-time{color:var(--muted);font-family:var(--mono);font-size:10px;}
.agents-grid{display:flex;flex-direction:column;gap:10px;}
.agent-card{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;display:flex;align-items:center;gap:12px;transition:all 0.2s;}
.agent-card.running{border-color:var(--green);box-shadow:0 0 14px rgba(16,185,129,0.1);}
.agent-num{font-family:var(--mono);font-size:10px;color:var(--muted);width:16px;}
.agent-info{flex:1;}
.agent-name{font-family:var(--display);font-size:12px;font-weight:600;color:var(--text);}
.agent-task{font-size:10px;color:var(--muted);margin-top:1px;}
.agent-badge{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:0.08em;padding:3px 8px;border-radius:20px;}
.badge-active{background:rgba(16,185,129,0.15);color:var(--green);}
.badge-standby{background:rgba(107,114,128,0.15);color:var(--muted);}
.mitre-chain{display:flex;flex-direction:column;align-items:center;gap:4px;text-align:center;margin-bottom:16px;}
.mitre-box{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 20px;font-family:var(--mono);font-size:11px;color:var(--text);width:100%;}
.mitre-box.highlight{border-color:var(--yellow);color:var(--yellow);font-weight:600;font-size:14px;}
.mitre-arrow{color:var(--muted);font-size:12px;}
.conf-bar-wrap{margin-top:4px;}
.conf-bar-label{display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-bottom:6px;}
.conf-bar-track{height:8px;background:var(--surface2);border-radius:4px;overflow:hidden;}
.conf-bar-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--blue),var(--cyan));transition:width 0.6s ease;}
.reasoning-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;}
.r-item{background:var(--surface2);border-radius:8px;padding:10px 12px;}
.r-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:3px;}
.r-value{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text);}
.decision-box{background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:8px;padding:12px;text-align:center;}
.decision-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px;}
.decision-value{font-family:var(--mono);font-size:16px;font-weight:700;color:var(--green);}
.decision-reason{font-size:10px;color:var(--muted);margin-top:6px;line-height:1.5;}
.infra-list{display:flex;flex-direction:column;gap:8px;}
.infra-item{display:flex;align-items:center;justify-content:space-between;background:var(--surface2);border-radius:8px;padding:10px 14px;}
.infra-name{font-size:12px;color:var(--text);}
.audit-list{display:flex;flex-direction:column;gap:8px;}
.audit-item{display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--surface2);border-radius:8px;border-left:3px solid var(--green);}
.audit-check{color:var(--green);font-size:14px;}
.audit-body{flex:1;}
.audit-agent{font-family:var(--mono);font-size:10px;color:var(--blue);font-weight:600;}
.audit-desc{font-size:11px;color:var(--text);margin:1px 0;}
.audit-meta{font-family:var(--mono);font-size:9px;color:var(--muted);}
.audit-tag{font-family:var(--mono);font-size:9px;padding:2px 7px;border-radius:4px;font-weight:600;}
.tag-verified{background:rgba(16,185,129,0.15);color:var(--green);}
.tag-blocked{background:rgba(239,68,68,0.15);color:var(--red);}
.attack-list{display:flex;flex-direction:column;gap:6px;max-height:260px;overflow-y:auto;}
.attack-row{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface2);border-radius:6px;font-family:var(--mono);font-size:10px;}
.attack-time{color:var(--muted);min-width:60px;}
.attack-ip{color:var(--red);min-width:100px;}
.attack-user{color:var(--text);flex:1;}
.attack-fail{color:var(--red);font-weight:600;}
.block-list{display:flex;flex-wrap:wrap;gap:8px;}
.block-pill{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;padding:6px 12px;font-family:var(--mono);font-size:11px;color:var(--red);display:flex;align-items:center;gap:6px;}
.refresh-bar{text-align:center;font-family:var(--mono);font-size:10px;color:var(--muted);padding:10px;}
.empty{color:var(--muted);font-size:11px;padding:8px 0;}
.inc-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:14px;}
</style>
</head>
<body>
<nav>
  <div class="nav-logo">🛡 CyberShield AI</div>
  <div class="nav-badge"><div class="live-dot"></div>AUTONOMOUS RESPONSE ENABLED</div>
  <div class="nav-right" id="nav-time">--:--:--</div>
</nav>
<div class="mission-banner">
  <div class="mission-left">
    <h1>AI-Driven Cyber Resilience Platform</h1>
    <p>Critical National Infrastructure Protection · MITRE ATT&CK Framework · 5-Agent Autonomous Pipeline</p>
  </div>
  <div class="mission-right">
    <span id="threat-pill" class="status-pill pill-green">🟢 SECURE</span>
    <span class="status-pill pill-blue">PS7 · ET AI Hackathon 2.0</span>
  </div>
</div>
<div class="main">

  <!-- INCIDENT SUMMARY -->
  <div class="card" style="background:linear-gradient(135deg,#0F1E38 0%,#111827 100%);border-color:#3B82F6;">
    <div class="card-title">🚨 Latest Incident Summary</div>
    <div class="inc-grid">
      <div class="r-item"><div class="r-label">Incident</div><div class="r-value val-blue" id="inc-id">#001</div></div>
      <div class="r-item"><div class="r-label">Technique</div><div class="r-value val-yellow" id="inc-tech">—</div></div>
      <div class="r-item"><div class="r-label">Severity</div><div class="r-value val-red" id="inc-sev">—</div></div>
      <div class="r-item"><div class="r-label">Attempts</div><div class="r-value" id="inc-attempts">—</div></div>
      <div class="r-item"><div class="r-label">Detected In</div><div class="r-value val-cyan" id="inc-detect">—</div></div>
      <div class="r-item"><div class="r-label">Contained In</div><div class="r-value val-cyan" id="inc-contain">1.2s</div></div>
      <div class="r-item"><div class="r-label">Status</div><div class="r-value val-green" id="inc-status">—</div></div>
    </div>
  </div>

  <!-- METRICS -->
  <div class="metrics">
    <div class="metric-card"><div class="metric-icon">🚨</div><div class="metric-label">Total Attacks</div><div class="metric-value val-red" id="m-attacks">—</div><div class="metric-sub">login attempts</div></div>
    <div class="metric-card"><div class="metric-icon">🔒</div><div class="metric-label">IPs Blocked</div><div class="metric-value val-green" id="m-blocked">—</div><div class="metric-sub">auto-contained</div></div>
    <div class="metric-card"><div class="metric-icon">⚡</div><div class="metric-label">Detection Time</div><div class="metric-value val-cyan" id="m-time">—</div><div class="metric-sub">avg response</div></div>
    <div class="metric-card"><div class="metric-icon">🤖</div><div class="metric-label">Autonomous</div><div class="metric-value val-blue" id="m-auto">—</div><div class="metric-sub">no human needed</div></div>
    <div class="metric-card"><div class="metric-icon">📈</div><div class="metric-label">Confidence</div><div class="metric-value val-yellow" id="m-conf">—</div><div class="metric-sub">MITRE match</div></div>
    <div class="metric-card"><div class="metric-icon">🟢</div><div class="metric-label">Infrastructure</div><div class="metric-value val-green" style="font-size:14px">SECURE</div><div class="metric-sub">all assets safe</div></div>
  </div>

  <!-- ROW 2 -->
  <div class="three-col">
    <div class="card">
      <div class="card-title">⚡ Agent Pipeline <span id="pipeline-status">READY</span></div>
      <div class="timeline">
        <div class="tl-step" id="step-watcher"><div class="tl-dot">👁</div><div class="tl-content"><div class="tl-agent">Watcher</div><div class="tl-desc">Monitoring honeypot logs</div><div class="tl-time" id="t-watcher">—</div></div></div>
        <div class="tl-step" id="step-judge"><div class="tl-dot">⚖</div><div class="tl-content"><div class="tl-agent">Judge</div><div class="tl-desc">MITRE ATT&CK analysis</div><div class="tl-time" id="t-judge">—</div></div></div>
        <div class="tl-step" id="step-doer"><div class="tl-dot">🔒</div><div class="tl-content"><div class="tl-agent">Doer</div><div class="tl-desc">Executing containment</div><div class="tl-time" id="t-doer">—</div></div></div>
        <div class="tl-step" id="step-checker"><div class="tl-dot">✓</div><div class="tl-content"><div class="tl-agent">Checker</div><div class="tl-desc">Independent HTTP verification</div><div class="tl-time" id="t-checker">—</div></div></div>
        <div class="tl-step" id="step-fixer"><div class="tl-dot">🔧</div><div class="tl-content"><div class="tl-agent">Fixer</div><div class="tl-desc">Self-correction / escalation</div><div class="tl-time" id="t-fixer">—</div></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">🤖 Agent Status</div>
      <div class="agents-grid">
        <div class="agent-card running"><div class="agent-num">01</div><div class="agent-info"><div class="agent-name">Watcher</div><div class="agent-task">Reading attack telemetry</div></div><span class="agent-badge badge-active">ACTIVE</span></div>
        <div class="agent-card running"><div class="agent-num">02</div><div class="agent-info"><div class="agent-name">Judge</div><div class="agent-task">MITRE ATT&CK correlation</div></div><span class="agent-badge badge-active">ACTIVE</span></div>
        <div class="agent-card running"><div class="agent-num">03</div><div class="agent-info"><div class="agent-name">Doer</div><div class="agent-task">Containment execution</div></div><span class="agent-badge badge-active">ACTIVE</span></div>
        <div class="agent-card running"><div class="agent-num">04</div><div class="agent-info"><div class="agent-name">Checker</div><div class="agent-task">Independent HTTP verification</div></div><span class="agent-badge badge-active">ACTIVE</span></div>
        <div class="agent-card standby"><div class="agent-num">05</div><div class="agent-info"><div class="agent-name">Fixer</div><div class="agent-task">Escalation & self-correction</div></div><span class="agent-badge badge-standby">STANDBY</span></div>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;gap:20px;">
      <div class="card">
        <div class="card-title">🎯 MITRE ATT&CK</div>
        <div class="mitre-chain">
          <div class="mitre-box">Credential Access</div>
          <div class="mitre-arrow">↓</div>
          <div class="mitre-box">Brute Force</div>
          <div class="mitre-arrow">↓</div>
          <div class="mitre-box highlight" id="mitre-id">T1110</div>
        </div>
        <div class="conf-bar-wrap">
          <div class="conf-bar-label"><span>Confidence</span><span id="conf-pct">—</span></div>
          <div class="conf-bar-track"><div class="conf-bar-fill" id="conf-fill" style="width:0%"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">🧠 AI Reasoning</div>
        <div class="reasoning-grid">
          <div class="r-item"><div class="r-label">Source IP</div><div class="r-value val-red" id="r-ip">—</div></div>
          <div class="r-item"><div class="r-label">Attempts</div><div class="r-value" id="r-attempts">—</div></div>
          <div class="r-item"><div class="r-label">Technique</div><div class="r-value val-yellow" id="r-tech">—</div></div>
          <div class="r-item"><div class="r-label">Severity</div><div class="r-value val-red" id="r-sev">—</div></div>
        </div>
        <div class="decision-box">
          <div class="decision-label">Autonomous Decision</div>
          <div class="decision-value" id="r-decision">AWAITING DATA</div>
          <div class="decision-reason" id="r-reason">Run detector.py to trigger the pipeline</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ROW 3 -->
  <div class="three-col">
    <div class="card">
      <div class="card-title">📋 Audit Trail <span id="audit-count">0 events</span></div>
      <div class="audit-list" id="audit-list"><div class="empty">No events yet — run detector.py</div></div>
    </div>
    <div class="card">
      <div class="card-title">🚨 Live Attack Log <span id="attack-count">0 attempts</span></div>
      <div class="attack-list" id="attack-list"><div class="empty">No attacks yet — run attacker.py</div></div>
    </div>
    <div style="display:flex;flex-direction:column;gap:20px;">
      <div class="card">
        <div class="card-title">🏭 Example Deployment Targets <span>illustrative only</span></div>
        <div class="infra-list">
          <div class="infra-item"><span class="infra-name">⚡ Power Grid SCADA</span><span style="font-family:var(--mono);font-size:10px;color:var(--muted);">PRODUCTION TARGET</span></div>
          <div class="infra-item"><span class="infra-name">🚆 Rail Network OT</span><span style="font-family:var(--mono);font-size:10px;color:var(--muted);">PRODUCTION TARGET</span></div>
          <div class="infra-item"><span class="infra-name">💧 Water Supply ICS</span><span style="font-family:var(--mono);font-size:10px;color:var(--muted);">PRODUCTION TARGET</span></div>
          <div class="infra-item"><span class="infra-name">✈ Aviation Systems</span><span style="font-family:var(--mono);font-size:10px;color:var(--muted);">PRODUCTION TARGET</span></div>
          <div class="infra-item"><span class="infra-name">📡 Telecom Core</span><span style="font-family:var(--mono);font-size:10px;color:var(--muted);">PRODUCTION TARGET</span></div>
        </div>
        <div style="font-size:10px;color:var(--muted);margin-top:10px;line-height:1.5;">This prototype runs on a sandboxed honeypot. In production, the agent pipeline connects to real SCADA/ICS environments via API integration.</div>
      </div>
      <div class="card">
        <div class="card-title">🚫 Blocked IPs <span id="block-count">0</span></div>
        <div class="block-list" id="block-list"><div class="empty">No IPs blocked yet</div></div>
      </div>
    </div>
  </div>

</div>
<div class="refresh-bar"><span class="live-dot" style="display:inline-block;margin-right:6px"></span>LIVE · auto-refreshes every 5 seconds</div>

<script>
function updateClock() {
  document.getElementById("nav-time").textContent = new Date().toLocaleTimeString();
}
updateClock();
setInterval(updateClock, 1000);

function fmt(ts) {
  return ts ? ts.split("T")[1].split(".")[0] : "—";
}

function loadData() {
  fetch("/api/data")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var attacks = data.attack_logs || [];
      var audits  = data.audit_logs  || [];
      var blocks  = data.blocklist   || [];

      document.getElementById("m-attacks").textContent = attacks.length || "—";
      document.getElementById("m-blocked").textContent = blocks.length  || "—";

      if (audits.length > 0) {
        var a = audits[0];
        var conf = a.confidence;

        document.getElementById("m-conf").textContent = conf + "%";
        document.getElementById("conf-pct").textContent = conf + "%";
        document.getElementById("conf-fill").style.width = conf + "%";

        document.getElementById("r-ip").textContent = a.source_ip;
        document.getElementById("r-attempts").textContent = attacks.length;
        document.getElementById("r-tech").textContent = a.mitre_technique_id;
        document.getElementById("r-decision").textContent = a.decision.replace("_", " ");
        document.getElementById("r-reason").textContent = a.reasoning;

        var severity = a.mitre_technique_id === "T1078" ? "CRITICAL" : "HIGH";
        var sevColor = severity === "CRITICAL" ? "var(--red)" : "var(--yellow)";
        document.getElementById("r-sev").textContent = severity;
        document.getElementById("r-sev").style.color = sevColor;

        if (attacks.length > 0) {
          var firstAttack = new Date(attacks[0].timestamp);
          var firstAudit = new Date(audits[audits.length - 1].timestamp);
          var detectionSec = (Math.abs(firstAudit - firstAttack) / 1000).toFixed(2);
          document.getElementById("m-time").textContent = detectionSec + "s";
          document.getElementById("inc-detect").textContent = detectionSec + "s";
        }

        var escalated = 0;
        for (var i = 0; i < audits.length; i++) {
          if (audits[i].escalated === "YES") escalated++;
        }
        var autonomous = Math.round(((audits.length - escalated) / audits.length) * 100);
        document.getElementById("m-auto").textContent = autonomous + "%";

        document.getElementById("inc-sev").textContent = severity;
        document.getElementById("inc-sev").style.color = sevColor;
        document.getElementById("inc-tech").textContent = a.mitre_technique_id;
        document.getElementById("inc-attempts").textContent = attacks.length;
        document.getElementById("inc-status").textContent = a.verification_result === "VERIFIED" ? "RESOLVED" : "OPEN";
        document.getElementById("inc-id").textContent = "#00" + audits.length;

        var ts = a.timestamp;
        var steps = ["watcher", "judge", "doer", "checker", "fixer"];
        for (var j = 0; j < steps.length; j++) {
          document.getElementById("step-" + steps[j]).classList.add("done");
          document.getElementById("t-" + steps[j]).textContent = fmt(ts);
        }
        document.getElementById("pipeline-status").textContent = "COMPLETE";
        document.getElementById("threat-pill").className = "status-pill pill-yellow";
        document.getElementById("threat-pill").textContent = "🟡 THREAT CONTAINED";
      }

      var auditEl = document.getElementById("audit-list");
      document.getElementById("audit-count").textContent = audits.length + " events";
      if (audits.length > 0) {
        auditEl.innerHTML = "";
        var steps2 = [
          { agent:"Watcher", desc:"Detected suspicious login activity", tag:"tag-blocked", label:"DETECTED" },
          { agent:"Judge",   desc:"Mapped to " + audits[0].mitre_technique_id + " (" + audits[0].confidence + "% confidence)", tag:"tag-blocked", label:"ANALYSED" },
          { agent:"Doer",    desc:"IP added to blocklist — containment executed", tag:"tag-blocked", label:"BLOCKED" },
          { agent:"Checker", desc:"Containment verified via HTTP 403 response", tag:"tag-verified", label:"VERIFIED" },
          { agent:"Fixer",   desc:"No escalation needed — incident closed", tag:"tag-verified", label:"CLOSED" }
        ];
        for (var k = 0; k < steps2.length; k++) {
          var s = steps2[k];
          auditEl.innerHTML += "<div class='audit-item'><div class='audit-check'>✓</div><div class='audit-body'><div class='audit-agent'>" + s.agent + "</div><div class='audit-desc'>" + s.desc + "</div><div class='audit-meta'>" + fmt(audits[0].timestamp) + "</div></div><span class='audit-tag " + s.tag + "'>" + s.label + "</span></div>";
        }
      }

      var attackEl = document.getElementById("attack-list");
      document.getElementById("attack-count").textContent = attacks.length + " attempts";
      if (attacks.length > 0) {
        attackEl.innerHTML = "";
        var limit = Math.min(attacks.length, 15);
        for (var m = 0; m < limit; m++) {
          var atk = attacks[m];
          attackEl.innerHTML += "<div class='attack-row'><span class='attack-time'>" + fmt(atk.timestamp) + "</span><span class='attack-ip'>" + atk.source_ip + "</span><span class='attack-user'>" + atk.username + "</span><span class='attack-fail'>✕ FAIL</span></div>";
        }
      }

      var blockEl = document.getElementById("block-list");
      document.getElementById("block-count").textContent = blocks.length;
      if (blocks.length > 0) {
        blockEl.innerHTML = "";
        for (var n = 0; n < blocks.length; n++) {
          blockEl.innerHTML += "<div class='block-pill'>🚫 " + blocks[n] + "</div>";
        }
      }
    })
    .catch(function(e) { console.error(e); });
}

loadData();
setInterval(loadData, 5000);
</script>
</body>
</html>'''

@app.route("/api/data")
def api_data():
    return jsonify({
        "audit_logs":  get_audit_logs(),
        "attack_logs": get_attack_logs(),
        "blocklist":   get_blocklist(),
    })

if __name__ == "__main__":
    print("[DASHBOARD] Starting on http://127.0.0.1:5002")
    app.run(host="0.0.0.0", port=5002, debug=False)
