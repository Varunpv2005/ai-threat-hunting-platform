# AI Threat Hunting & Incident Response Platform

Full-stack cybersecurity platform: IsolationForest anomaly detection → threat
classification → SOAR automated response, served by a FastAPI backend and a
React SOC dashboard, all containerised with Docker Compose.

---

## Architecture

```
Browser
  │
  ▼ :3000
frontend  (nginx)
  │  static assets cached
  │  /api/*  ──proxy──►  backend:8000  (FastAPI + uvicorn)
  │                          │
  │                    IsolationForest
  │                    ThreatClassifier
  │                    SOAR RuleEngine
  │                          │
  │                    postgres:5432  (logs · threats · alerts)
  │                    redis:6379     (model cache · cooldowns)
  │                    [elasticsearch:9200  --profile elk]
  │                    [kibana:5601         --profile elk]
```

| Service         | Image                  | Default port |
|-----------------|------------------------|--------------|
| `frontend`      | nginx:1.25-alpine      | **3000**     |
| `backend`       | python:3.11-slim       | **8000**     |
| `postgres`      | postgres:16-alpine     | 5432         |
| `redis`         | redis:7-alpine         | 6379         |
| `elasticsearch` | elasticsearch:8.12     | 9200 (elk)   |
| `kibana`        | kibana:8.12            | 5601 (elk)   |

---

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Docker | 24.0 |
| Docker Compose v2 | bundled with Docker Desktop |
| RAM | 4 GB (8 GB with ELK) |

Verify: `docker compose version`

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/your-org/soc-platform.git
cd soc-platform

# 2. Configure (defaults work out of the box)
cp .env.example .env

# 3. Build and start
docker compose up -d --build

# 4. Follow startup logs (model training takes ~30 s)
docker compose logs -f backend
# Wait for:  INFO  API ready.

# 5. Open
open http://localhost:3000          # SOC Dashboard
open http://localhost:8000/docs     # Swagger UI
```

---

## All commands

### Using Make (recommended)

```bash
make up           # build + start full stack
make dev          # hot-reload backend + local Vite frontend
make elk          # add Elasticsearch + Kibana
make down         # stop all containers
make logs         # tail all logs
make logs-api     # tail backend only
make ps           # container status
make build        # (re)build images
make rebuild      # build with --no-cache
make clean        # remove containers + images
make clean-vols   # ⚠ remove all data volumes
make test         # run test suite in container
make shell-api    # bash shell in backend
make shell-db     # psql in postgres
make simulate     # fire a test brute-force attack
make health       # ping all services
```

### Using docker compose directly

```bash
# Start default stack
docker compose up -d --build

# Start with Elasticsearch + Kibana
docker compose --profile elk up -d --build

# Hot-reload dev mode
docker compose --profile dev up -d

# View logs
docker compose logs -f
docker compose logs -f backend

# Stop
docker compose down

# Stop + remove volumes  ⚠ destructive
docker compose down -v

# Rebuild one service
docker compose up -d --build backend

# Scale backend workers
docker compose up -d --scale backend=3

# Open a shell
docker compose exec backend bash
docker compose exec postgres psql -U socuser -d socdb
docker compose exec redis redis-cli -a redispass

# Run tests
docker compose exec backend python backend/tests/test_api.py
```

---

## API quick reference

```bash
# Health
curl http://localhost:8000/

# Simulate an attack (brute force, high intensity)
curl -X POST http://localhost:8000/api/v1/simulate_attack \
  -H "Content-Type: application/json" \
  -d '{"attack_type":"brute_force","geo_country":"RU","intensity":"high"}'

# All attack types:
#   brute_force | privilege_escalation | data_exfiltration
#   suspicious_login | password_spray | automated_scanner

# Fetch threats
curl "http://localhost:8000/api/v1/threats?severity=CRITICAL&limit=10"

# Fetch open alerts
curl "http://localhost:8000/api/v1/alerts?status=open"

# Acknowledge an alert
curl -X POST http://localhost:8000/api/v1/alerts/<alert_id>/acknowledge \
  -H "Content-Type: application/json" \
  -d '{"analyst":"alice"}'

# Ingest raw log events
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{"events":[{"event_type":"login_failed","user":"alice",
       "ip_address":"185.220.101.15","geo_country":"RU",
       "timestamp":"2024-01-15T03:22:00Z","bytes_read":0}]}'

# Dashboard stats
curl http://localhost:8000/api/v1/stats

# Active response rules
curl http://localhost:8000/api/v1/rules
```

---

## Environment variables

| Variable | Default | Notes |
|----------|---------|-------|
| `APP_ENV` | `production` | `development` enables debug |
| `SECRET_KEY` | *(change me)* | Run `openssl rand -hex 32` |
| `POSTGRES_DB` | `socdb` | |
| `POSTGRES_USER` | `socuser` | |
| `POSTGRES_PASSWORD` | `socpassword` | **Change in production** |
| `REDIS_PASSWORD` | `redispass` | **Change in production** |
| `TRAIN_ON_STARTUP` | `true` | Train IsolationForest at boot |
| `N_TRAIN_EVENTS` | `5000` | Training set size |
| `WORKERS` | `2` | Uvicorn worker processes |
| `BACKEND_PORT` | `8000` | Exposed host port |
| `FRONTEND_PORT` | `3000` | Exposed host port |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warning` |

---

## Development workflow

```bash
# Start infrastructure only
docker compose up -d postgres redis

# Run backend locally with hot-reload
pip install -r backend/requirements.txt
uvicorn backend.api.main:app --reload --port 8000

# Run frontend locally with HMR
cd dashboard && npm install && npm run dev
# → http://localhost:5173  (Vite proxies /api → localhost:8000)

# Run tests
python backend/tests/test_api.py
```

---

## Project layout

```
.
├── backend/
│   ├── api/
│   │   ├── main.py            FastAPI app + all routes
│   │   ├── store.py           In-memory + PostgreSQL data store
│   │   └── schemas.py         Request / response models
│   ├── ml/
│   │   ├── anomaly/           IsolationForest detector
│   │   └── classifier/        ThreatClassifier + feature pipeline
│   ├── incident_response/
│   │   ├── actions.py         SOAR action implementations
│   │   └── rule_engine.py     Declarative response rule engine
│   ├── log_simulator/         Attack scenario event generator
│   ├── tests/                 Test suite (97 tests, all passing)
│   └── requirements.txt
├── dashboard/
│   ├── src/
│   │   ├── main.jsx
│   │   └── SOCDashboard.jsx   Full React dashboard
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── docker/
│   ├── backend.Dockerfile     Two-stage Python build
│   ├── frontend.Dockerfile    Node build + nginx serve
│   ├── nginx.conf             SPA routing + /api proxy
│   └── postgres/
│       └── init.sql           Schema + seed data
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── Makefile
└── README.md
```

---

## Production checklist

```bash
# Rotate all secrets
SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)

# Edit .env, then rebuild
docker compose up -d --build

# Add resource limits to docker-compose.yml per service:
#   deploy:
#     resources:
#       limits:
#         cpus: '2'
#         memory: 2G

# Enable HTTPS: add a certbot/Let's Encrypt sidecar and update nginx.conf
# Enable ES security: set xpack.security.enabled=true and provision certs
```
