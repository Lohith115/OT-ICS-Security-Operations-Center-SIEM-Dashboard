# OT/ICS Security Operations Center — SIEM Dashboard

> A production-grade Security Information and Event Management (SIEM) system purpose-built for Operational Technology (OT) and Industrial Control System (ICS) environments. Detects, correlates, and visualizes cyber threats targeting critical infrastructure.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-green?style=flat-square&logo=flask)
![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-orange?style=flat-square&logo=sqlite)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Detection Rules](#detection-rules)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Screenshots](#screenshots)
- [Future Roadmap](#future-roadmap)

---

## Overview

Most SIEM tools are designed for IT networks — this one is built with OT/ICS environments in mind. Industrial systems (power grids, water treatment, manufacturing) run protocols like Modbus TCP, DNP3, and IEC 104 that traditional SIEM tools don't understand. This dashboard bridges that gap.

**What makes this different from a generic log analyzer:**

- SCADA-aware log parsing and threat correlation
- MITRE ATT&CK for ICS technique mapping (not just enterprise ATT&CK)
- Real-time threat intelligence enrichment via AbuseIPDB and VirusTotal
- ML-based anomaly detection using Isolation Forest
- Automated Incident Response playbook generation
- Alert lifecycle management (NEW → IN_PROGRESS → RESOLVED)

This project was built as a portfolio piece to demonstrate end-to-end SOC engineering capability — from raw log ingestion to actionable alert triage.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Log Sources                          │
│   SSH Auth Logs │ Apache/Nginx Logs │ SCADA Event Logs  │
└────────────────────────┬────────────────────────────────┘
                         │ POST /api/ingest
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  Flask REST API (app.py)                 │
│              Content-Security-Policy Headers             │
└──────┬──────────────┬───────────────────────────────────┘
       │              │
       ▼              ▼
┌──────────────┐  ┌───────────────────────────────────────┐
│  log_parser  │  │         correlation_engine             │
│  .py         │  │  SSH Brute Force │ Web Scan │ Admin    │
│              │  │  Probe Detection │ Rule Engine         │
└──────┬───────┘  └──────────────────┬────────────────────┘
       │                             │
       ▼                             ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐
│  database.py │  │ mitre_attack │  │   threat_intel.py     │
│  SQLite WAL  │  │  _mapper.py  │  │  AbuseIPDB│VirusTotal │
│  logs table  │  │  TTP mapping │  │  IP Reputation Lookup │
│  alerts table│  │  Risk Scoring│  └──────────────────────┘
└──────────────┘  └──────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│              anomaly_detector.py                         │
│    Isolation Forest ML │ 5-Feature Extraction │ Baseline │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│              Frontend Dashboard                          │
│  Chart.js Visualizations │ Leaflet.js GeoIP Map          │
│  Alert Lifecycle Panel   │ Dynamic Risk Level Indicator  │
└──────────────────────────────────────────────────────────┘
```

---

## Features

### Core SIEM Capabilities
- **Real-time log ingestion** via REST API — accepts SSH auth logs, Apache/Nginx access logs, and SCADA event logs
- **Correlation rules engine** — stateful detection across multiple log entries using configurable time windows
- **Alert lifecycle management** — track each alert through NEW → IN_PROGRESS → RESOLVED workflow
- **Severity triage** — four levels: LOW, MEDIUM, HIGH, CRITICAL with visual differentiation

### Threat Intelligence
- **AbuseIPDB integration** — checks attacker IPs against community abuse reports (1000 free requests/day)
- **VirusTotal integration** — cross-references IPs against 70+ threat intelligence feeds
- **Result caching** — 1-hour TTL cache prevents redundant API calls
- **Enriched alert descriptions** — threat intel summary appended directly to each alert

### ML Anomaly Detection
- **Algorithm:** Isolation Forest (unsupervised, no labeled data required)
- **5 engineered features:** logs/hour, unique IPs, failed attempt ratio, HTTP error ratio, geographic diversity
- **Baseline training:** learns normal behavior from historical logs automatically at startup
- **Persistent model:** trained model saved to disk, loaded on restart
- **Anomaly interpretation:** human-readable explanation of *why* traffic is anomalous

### Visualization
- **GeoIP attack map** — Leaflet.js interactive world map with attacker IP markers sized by alert count
- **Real-time charts** — Chart.js log volume trends and alert type distribution
- **Top attackers panel** — ranked list with alert counts
- **Dynamic risk indicator** — dashboard risk level changes color and label based on active alert count

---

## Detection Rules

| Rule | Trigger Condition | Severity | MITRE Technique |
|------|-------------------|----------|-----------------|
| SSH Brute Force | 5+ failed auth attempts from same IP in 5 min | CRITICAL | T1110.001 |
| Web Directory Scanning | 10+ HTTP 404 errors from same IP in 5 min | HIGH | T1595.002 |
| Admin Panel Probing | Access to `/admin`, `/wp-login`, `/phpmyadmin`, `/.env` | MEDIUM | T1083 |
| ML Anomaly | Isolation Forest detects behavioral deviation from baseline | HIGH | TA0000 |

All thresholds are configurable constants in `correlation_engine.py`:

```python
SSH_FAILURE_THRESHOLD = 5       # Failed attempts to trigger alert
SSH_TIME_WINDOW_MINUTES = 5     # Time window for counting
WEB_404_THRESHOLD = 10          # 404 errors to trigger alert
```

---

## MITRE ATT&CK Mapping

Every alert is automatically enriched with MITRE ATT&CK for ICS context:

| Alert Type | Tactic | Technique | Risk Score |
|------------|--------|-----------|------------|
| SSH_BRUTE_FORCE | TA0001 — Initial Access | T1110.001 — Password Guessing | 8.5/10 |
| WEB_SCANNING | TA0043 — Reconnaissance | T1595.002 — Vulnerability Scanning | 6.0/10 |
| ADMIN_PROBE | TA0007 — Discovery | T1083 — File and Directory Discovery | 7.0/10 |
| SCADA_UNAUTHORIZED_ACCESS | TA0108 — Initial Access (ICS) | T0817 — Drive-by Compromise | 9.5/10 |

The `generate_attack_chain_report()` function detects multi-stage attacks by identifying when alerts span 3+ distinct MITRE tactics — a strong indicator of a coordinated campaign.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Backend | Python 3.8+, Flask 2.3+ | REST API, request routing |
| Database | SQLite with WAL mode | Concurrent read/write, log + alert storage |
| ML | scikit-learn, numpy | Isolation Forest anomaly detection |
| Frontend | HTML5, CSS3, JavaScript | Dashboard UI |
| Charts | Chart.js | Log volume and alert distribution charts |
| Maps | Leaflet.js + OpenStreetMap | GeoIP attack origin visualization |
| Threat Intel | AbuseIPDB, VirusTotal APIs | IP reputation enrichment |
| GeoIP | ip-api.com | Attacker geolocation (free, no key required) |
| Security | Flask-CORS, CSP Headers | Cross-origin protection, XSS prevention |

---

## Project Structure

```
siem/
├── backend/
│   ├── app.py                  # Flask application, API routes, security headers
│   ├── database.py             # SQLite manager (WAL mode, schema, CRUD)
│   ├── log_parser.py           # Regex parsers for SSH and Apache/Nginx logs
│   ├── correlation_engine.py   # Stateful rule engine, GeoIP enrichment
│   ├── mitre_attack_mapper.py  # ATT&CK TTP mapping and attack chain detection
│   ├── anomaly_detector.py     # Isolation Forest ML anomaly detection
│   └── threat_intel.py         # AbuseIPDB and VirusTotal API integration
├── frontend/
│   ├── index.html              # Dashboard UI structure
│   ├── dashboard.js            # Real-time polling, chart rendering, alert management
│   └── style_industrial.css    # SCADA-themed industrial UI stylesheet
├── logs/
│   ├── send_logs.py            # Sample log generator and ingestion script
│   ├── test_siem.py            # Core functionality tests
│   └── test_enhanced_features.py # ML and threat intel tests
├── requirements.txt
└── .gitignore
```

---

## Setup & Installation

### Prerequisites
- Python 3.8+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/Lohith115/ot-ics-siem.git
cd ot-ics-siem
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys (optional but recommended)

Create a `.env` file in the `backend/` directory:

```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
FLASK_DEBUG=False
```

> The dashboard works without API keys. Threat intel features will show "No data available" until keys are configured. Get free keys at [abuseipdb.com](https://www.abuseipdb.com/api) and [virustotal.com](https://www.virustotal.com/gui/join-us).

### 5. Start the server

```bash
cd backend
python3 app.py
```

Dashboard available at: `http://localhost:5000`

### 6. Ingest sample logs

In a second terminal:

```bash
cd logs
python3 send_logs.py
```

This sends sample SSH brute force and web scanning logs to trigger alerts immediately.

---

## Usage

### Manual Log Injection

Navigate to the **Log Injector** tab in the dashboard. Paste raw log lines in the terminal-style input box:

```
# SSH auth logs
Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2

# Apache/Nginx access logs
192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 404 512
```

### Alert Management

In the **Operations** tab, each alert has action buttons:
- **Investigate** — marks alert as IN_PROGRESS
- **Resolve** — marks alert as RESOLVED
- Alert counts update the dashboard risk indicator in real time

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest` | Ingest raw log lines |
| GET | `/api/logs?limit=50` | Retrieve recent logs |
| GET | `/api/alerts?limit=20` | Retrieve recent alerts with MITRE data |
| GET | `/api/stats` | Dashboard statistics including alert status breakdown |
| PUT | `/api/alerts/<id>/status` | Update alert status |

---

## API Reference

### POST `/api/ingest`

```json
{
  "logs": [
    "Jan 15 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] \"GET /admin HTTP/1.1\" 404 512"
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "processed": 2,
  "alerts_triggered": 1
}
```

### GET `/api/alerts`

```json
[
  {
    "id": 1,
    "timestamp": "2026-03-19T14:23:01",
    "alert_type": "SSH_BRUTE_FORCE",
    "severity": "Critical",
    "source_ip": "192.168.1.100",
    "description": "SSH Brute Force detected: 5 failed attempts | TI: ⚠️ THREAT DETECTED",
    "status": "NEW",
    "mitre_tactic": "TA0001 - Initial Access",
    "mitre_technique": "T1110.001 - Password Guessing",
    "risk_score": 8.5,
    "latitude": 51.5074,
    "longitude": -0.1278
  }
]
```

---

## Future Roadmap

- [ ] SCADA log parser — Modbus TCP and DNP3 event log support
- [ ] Incident Response Playbook Generator — auto-generated remediation steps per alert type
- [ ] Splunk/ELK integration — forward alerts to enterprise SIEM via syslog
- [ ] Multi-user authentication — role-based access (Analyst / Admin)
- [ ] Docker deployment — containerized setup with `docker-compose`
- [ ] Real-time WebSocket updates — replace polling with push notifications
- [ ] Export functionality — alerts to CSV/PDF for incident reports

---

## Author

**T Lohith** — M.Tech Networks & Cybersecurity, Amity University Gurugram

Specializing in OT/ICS security and Blue Team operations. This project is part of a cybersecurity portfolio targeting SOC Analyst and Security Engineer roles.

- GitHub: [github.com/Lohith115](https://github.com/Lohith115)
- LinkedIn: [linkedin.com/in/its-lohith-944909318](https://linkedin.com/in/its-lohith-944909318)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
