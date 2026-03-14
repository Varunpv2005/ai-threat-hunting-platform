<div align="center">

<img src="https://img.shields.io/badge/🛡️_SOC-SENTINEL-00ff88?style=for-the-badge&labelColor=080c10&color=00ff88" alt="SOC Sentinel"/>

# AI Threat Hunting & Incident Response Platform

**A production-grade Security Operations Center built with Machine Learning, automated incident response, and a real-time React dashboard**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-97_passing-00ff88?style=flat-square)](#)

<br/>

![Dashboard](screenshots/dashboard.png)

<br/>

> 🎓 Final Year CSE Project — Built entirely from scratch  
> Detects, classifies, and auto-responds to cyber attacks in real time

</div>

---

## 🔥 What makes this different

Most security tools just alert you. **This one fights back.**

| Capability | What it does |
|---|---|
| 🧠 **ML Detection** | IsolationForest trained on 5,000 events scores every log 0–100 for anomalousness |
| 🎯 **Threat Classification** | 37 behavioural features classify attacks into 6 categories with MITRE ATT&CK mapping |
| ⚡ **SOAR Automation** | 10 response rules fire automatically — block IP, disable user, quarantine host |
| 🔗 **Incident Correlation** | Groups individual threats into campaigns and detects multi-stage attacks |
| 🗺️ **Global Threat Map** | Live world map showing attacker origins with pulsing markers |
| 📊 **SOC Dashboard** | Real-time React dashboard with Chart.js — timeline, severity, categories |

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────┐
  Browser           │      Docker Network          │
    │               │                              │
    ▼ :3000         │                              │
  ┌─────────────┐   │   ┌────────────────────┐    │
  │   React     │───┼──▶│   FastAPI :8000    │    │
  │  Dashboard  │   │   │                    │    │
  │  Chart.js   │   │   │  IsolationForest   │    │
  │  Leaflet.js │   │   │  ThreatClassifier  │    │
  └─────────────┘   │   │  SOAR RuleEngine   │    │
                    │   │  IncidentCorrelator│    │
                    │   └────────┬───────────┘    │
                    │            │                 │
                    │   ┌────────┴────────┐        │
                    │   │                 │        │
                    │ postgres:5432   redis:6379    │
                    │ (logs·threats   (cache·      │
                    │  ·alerts)        cooldowns)  │
                    └─────────────────────────────┘
```

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/Varunpv2005/ai-threat-hunting-platform.git
cd ai-threat-hunting-platform

# 2. Configure
cp .env.example .env

# 3. Launch
docker compose up -d --build

# 4. Wait for model training (~30s)
docker compose logs -f backend
# Look for: INFO  API ready.
```

**Open:** http://localhost:3000 — SOC Dashboard  
**Open:** http://localhost:8000/docs — Interactive API

---

## 🧠 ML Pipeline

```
Raw Log Event
      │
      ▼
Feature Engineering ──── 37 behavioural features
(pandas + numpy)         user_failure_rate, ip_spray_flag,
                         log_bytes_read, hour_sin/cos, etc.
      │
      ▼
IsolationForest ──────── Anomaly Score [0–100]
(unsupervised ML)        Trained on 5,000 normal events
      │
      ▼
ThreatClassifier ──────── Category + Confidence
(rule-based)              brute_force → T1110.001
                          priv_esc   → T1548.003
                          exfiltration → T1005
      │
      ▼
SOAR RuleEngine ──────── Automated Response
(10 rules)                block_ip / disable_user /
                          quarantine_host / enforce_mfa
```

**Detection results on synthetic test data:**

| Attack Type | Avg Anomaly Score | Severity |
|---|---|---|
| Brute Force | **100.0** | 🔴 CRITICAL |
| Privilege Escalation | **98.5** | 🔴 CRITICAL |
| Data Exfiltration | **86.4** | 🔴 CRITICAL |
| Password Spray | **79.3** | 🟠 HIGH |
| Suspicious Login | **86.1** | 🟠 HIGH |
| Automated Scanner | **68.7** | 🟡 MEDIUM |

**ROC-AUC: 0.89** on synthetic test set

---

## ⚡ SOAR Response Rules

When a threat is detected the rule engine fires automatically — no human needed:

| Attack | Trigger Condition | Actions |
|---|---|---|
| 🔴 Brute Force | `failed_logins > 20` | `block_ip(24h)` + `disable_user` + `send_alert` |
| 🔴 Privilege Escalation | `admin_spike + sensitive_files` | `disable_user` + `quarantine_host` + `rotate_credentials` |
| 🔴 Data Exfiltration | `bytes_read > 5MB + sensitive` | `block_ip(72h)` + `rate_limit_user` |
| 🟠 Password Spray | `unique_users > 5 from 1 IP` | `block_ip(48h)` + `send_alert` |
| 🟠 Suspicious Login | `high_risk_country + no_MFA` | `enforce_mfa` + `disable_user` |
| 🟡 Automated Scanner | `request_rate < 1s` | `rate_limit_ip(2rpm)` |

---

## 🗺️ Supported Attack Scenarios

```bash
# Simulate any attack type via API
POST /api/v1/simulate_attack

{
  "attack_type": "brute_force",        # or privilege_escalation
  "geo_country": "RU",                 #    data_exfiltration
  "intensity": "high",                 #    suspicious_login
  "dry_run": false                     #    password_spray
}                                      #    automated_scanner
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `GET` | `/api/v1/threats` | All detected threats |
| `GET` | `/api/v1/alerts` | Security alerts |
| `GET` | `/api/v1/rules` | Active SOAR rules |
| `POST` | `/api/v1/simulate_attack` | Simulate an attack |
| `POST` | `/api/v1/ingest` | Ingest raw log events |
| `POST` | `/api/v1/alerts/{id}/acknowledge` | Acknowledge alert |
| `POST` | `/api/v1/alerts/{id}/resolve` | Resolve alert |

Full interactive docs: **http://localhost:8000/docs**

---

## 🛠️ Tech Stack

<table>
<tr>
<td><b>Backend</b></td>
<td>Python 3.11 · FastAPI · uvicorn · asyncpg · SQLAlchemy</td>
</tr>
<tr>
<td><b>ML</b></td>
<td>scikit-learn · IsolationForest · pandas · numpy · joblib</td>
</tr>
<tr>
<td><b>Frontend</b></td>
<td>React 18 · Chart.js · Leaflet.js · Vite · nginx</td>
</tr>
<tr>
<td><b>Database</b></td>
<td>PostgreSQL 16 · Redis 7</td>
</tr>
<tr>
<td><b>DevOps</b></td>
<td>Docker · Docker Compose · multi-stage builds · health checks</td>
</tr>
<tr>
<td><b>Security</b></td>
<td>MITRE ATT&CK · SOAR · IDS/IPS concepts · SOC workflows</td>
</tr>
</table>

---

## 📁 Project Structure

```
ai-threat-hunting-platform/
│
├── backend/
│   ├── api/
│   │   ├── main.py              # FastAPI app — 9 endpoints
│   │   ├── store.py             # Data store + ML pipeline
│   │   └── schemas.py           # Request/response models
│   │
│   ├── ml/
│   │   ├── anomaly/             # IsolationForest detector
│   │   └── classifier/          # ThreatClassifier + 37 features
│   │
│   ├── incident_response/
│   │   ├── actions.py           # 8 SOAR action types
│   │   ├── rule_engine.py       # 10 response rules
│   │   └── correlator.py        # Incident + campaign detection
│   │
│   ├── log_simulator/           # 6 attack scenario generators
│   └── tests/                   # 97 automated tests ✅
│
├── dashboard/
│   └── src/
│       └── SOCDashboard.jsx     # Full React dashboard
│
├── docker/
│   ├── backend.Dockerfile       # Two-stage Python build
│   ├── frontend.Dockerfile      # Node build + nginx serve
│   ├── nginx.conf               # SPA routing + /api proxy
│   └── postgres/init.sql        # Schema + seed data
│
├── docker-compose.yml           # All 4 services
├── .env.example                 # Configuration template
├── Makefile                     # Developer shortcuts
└── README.md
```

---

## 🧪 Tests

```bash
# Run full test suite inside container
docker compose exec soc_backend python backend/tests/test_api.py

# Output:
# 40 tests | 40 passed | 0 failed   (API integration)
# 57 tests | 57 passed | 0 failed   (Rule engine)
```

---

## ⚙️ Environment Variables

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | `socpassword` | ⚠️ Change in production |
| `REDIS_PASSWORD` | `redispass` | ⚠️ Change in production |
| `SECRET_KEY` | *(change me)* | Run `openssl rand -hex 32` |
| `TRAIN_ON_STARTUP` | `true` | Train ML model at boot |
| `N_TRAIN_EVENTS` | `5000` | Training set size |
| `WORKERS` | `2` | Uvicorn worker processes |

---

## 🔮 Roadmap

- [ ] XGBoost supervised classifier (ROC-AUC comparison)
- [ ] JWT authentication + role-based access
- [ ] WebSocket real-time alert push
- [ ] Elasticsearch SIEM integration
- [ ] Slack / email notifications
- [ ] Cloud deployment (Railway / AWS)

---

## 👤 Author

**Varun P V** — Final Year CSE Student  

[![GitHub](https://img.shields.io/badge/GitHub-Varunpv2005-181717?style=flat-square&logo=github)](https://github.com/Varunpv2005)

---

## 📄 License

MIT License — free to use, modify and distribute.

---

<div align="center">

**If this project helped you, please ⭐ star the repo**

*Built with 🛡️ for cybersecurity education*

</div>
