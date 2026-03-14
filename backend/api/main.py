"""
FastAPI Backend — AI Threat Hunting & Incident Response Platform
================================================================

Endpoints
---------
GET  /                       Health check + API manifest
GET  /api/v1/logs            Paginated log event feed with filters
GET  /api/v1/threats         Detected threats with severity/category filters
GET  /api/v1/alerts          Security alerts with status management
POST /api/v1/alerts/{id}/acknowledge   Acknowledge an open alert
POST /api/v1/alerts/{id}/resolve       Resolve an alert
GET  /api/v1/stats           Live dashboard summary statistics
POST /api/v1/simulate_attack Trigger a simulated attack and return full pipeline output
POST /api/v1/ingest          Ingest raw log events (for Kafka/Filebeat integration)
GET  /api/v1/rules           List all active response rules
GET  /docs                   Interactive Swagger UI
GET  /redoc                  ReDoc documentation

Run with:
    uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000

Requirements:
    pip install fastapi uvicorn pydantic
"""

import logging
import math
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

# ── FastAPI imports ────────────────────────────────────────────────────────
# These are used when FastAPI is installed.  The try/except lets the file
# also be imported for testing without FastAPI present.
try:
    from fastapi import FastAPI, HTTPException, Query, Path, Body, Request, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# ── Project imports ────────────────────────────────────────────────────────
from backend.api.store import store
from backend.api.schemas import SimulateAttackRequest

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic request/response models  (FastAPI-native when available)
# ─────────────────────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:

    class SimulateAttackBody(BaseModel):
        attack_type: str = Field(
            "brute_force",
            description="One of: brute_force, privilege_escalation, data_exfiltration, "
                        "suspicious_login, password_spray, automated_scanner",
        )
        source_ip:   Optional[str] = Field(None, description="Source IP (auto-generated if omitted)")
        username:    Optional[str] = Field(None, description="Target username (auto-generated if omitted)")
        geo_country: Optional[str] = Field(None, description="ISO country code of attacker origin")
        intensity:   str = Field("medium", description="Attack intensity: low | medium | high")
        dry_run:     bool = Field(False, description="If true, run pipeline but don't persist results")

    class IngestBody(BaseModel):
        events: list[dict] = Field(..., description="Raw log event dicts to ingest")

    class AcknowledgeBody(BaseModel):
        analyst: str = Field("analyst", description="Analyst username acknowledging the alert")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def paginate(items: list, total: int, page: int, limit: int) -> dict:
    return {
        "data": items,
        "pagination": {
            "total": total,
            "page":  page,
            "limit": limit,
            "pages": math.ceil(total / max(limit, 1)),
        },
    }


def success(data: Any, **extra) -> dict:
    return {"status": "ok", "data": data, **extra}


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Bootstrap the data store on startup."""
        logger.info("Starting up — bootstrapping ML models and data store…")
        store.bootstrap(n_train=5000)
        logger.info("Startup complete. API ready.")
        yield
        logger.info("Shutdown complete.")

    app = FastAPI(
        title="AI Threat Hunting & Incident Response API",
        description=(
            "Real-time cybersecurity API integrating IsolationForest anomaly detection, "
            "rule-based threat classification, and automated SOAR incident response."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request timing middleware ────────────────────────────────────────────
    @app.middleware("http")
    async def add_timing(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        ms = (time.perf_counter() - t0) * 1000
        response.headers["X-Response-Time-Ms"] = f"{ms:.1f}"
        return response

    # ── Global exception handler ─────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exc(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": str(exc)},
        )

    # ────────────────────────────────────────────────────────────────────────
    # GET /
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/", tags=["Health"])
    async def root():
        """Health check and API manifest."""
        return {
            "status": "ok",
            "service": "AI Threat Hunting API",
            "version": "1.0.0",
            "endpoints": {
                "GET  /api/v1/logs":                    "Paginated log event feed",
                "GET  /api/v1/threats":                 "Detected threats",
                "GET  /api/v1/alerts":                  "Security alerts",
                "POST /api/v1/alerts/{id}/acknowledge": "Acknowledge an alert",
                "POST /api/v1/alerts/{id}/resolve":     "Resolve an alert",
                "GET  /api/v1/stats":                   "Dashboard statistics",
                "POST /api/v1/simulate_attack":         "Simulate an attack",
                "POST /api/v1/ingest":                  "Ingest raw log events",
                "GET  /api/v1/rules":                   "Active response rules",
            },
        }

    # ────────────────────────────────────────────────────────────────────────
    # GET /api/v1/logs
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/v1/logs", tags=["Logs"])
    async def get_logs(
        page:       int           = Query(1,    ge=1,  description="Page number"),
        limit:      int           = Query(50,   ge=1, le=500, description="Results per page"),
        event_type: Optional[str] = Query(None, description="Filter by event type"),
        username:   Optional[str] = Query(None, description="Filter by username"),
        source_ip:  Optional[str] = Query(None, description="Filter by source IP"),
        label:      Optional[int] = Query(None, description="0=normal, 1=attack"),
        since:      Optional[str] = Query(None, description="ISO timestamp lower bound"),
    ):
        """
        Paginated log event feed with optional filters.

        Returns raw log events enriched with metadata.  Supports filtering
        by event type, username, source IP, ground-truth label, and time range.

        **Example:**
        ```
        GET /api/v1/logs?event_type=login_failed&limit=20
        GET /api/v1/logs?label=1&since=2024-01-01T00:00:00Z
        ```
        """
        rows, total = store.get_logs(
            page=page, limit=limit,
            event_type=event_type, username=username,
            source_ip=source_ip, label=label, since=since,
        )
        return success(
            data=rows,
            pagination={"total": total, "page": page,
                        "limit": limit, "pages": math.ceil(total / max(limit, 1))},
            filters={"event_type": event_type, "username": username,
                     "source_ip": source_ip, "label": label, "since": since},
        )

    # ────────────────────────────────────────────────────────────────────────
    # GET /api/v1/threats
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/v1/threats", tags=["Threats"])
    async def get_threats(
        page:     int           = Query(1,    ge=1),
        limit:    int           = Query(50,   ge=1, le=500),
        severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
        category: Optional[str] = Query(None, description="brute_force | privilege_escalation | …"),
        since:    Optional[str] = Query(None, description="ISO timestamp lower bound"),
    ):
        """
        Detected threats sorted by anomaly score descending.

        Each threat record includes:
        - Anomaly score from IsolationForest [0–100]
        - Threat category from the classifier
        - Confidence score from rule matching
        - MITRE ATT&CK technique IDs
        - Top classification rules that fired

        **Example:**
        ```
        GET /api/v1/threats?severity=CRITICAL
        GET /api/v1/threats?category=brute_force&limit=10
        ```
        """
        rows, total = store.get_threats(
            page=page, limit=limit,
            severity=severity, category=category, since=since,
        )
        # Summary stats
        from collections import Counter
        cat_counts = Counter(r["threat_category"] for r in store._threats)
        sev_counts = Counter(r["severity"]         for r in store._threats)

        return success(
            data=rows,
            pagination={"total": total, "page": page,
                        "limit": limit, "pages": math.ceil(total / max(limit, 1))},
            summary={
                "total_threats":     total,
                "by_category":       dict(cat_counts),
                "by_severity":       dict(sev_counts),
            },
        )

    # ────────────────────────────────────────────────────────────────────────
    # GET /api/v1/alerts
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/v1/alerts", tags=["Alerts"])
    async def get_alerts(
        page:     int           = Query(1,    ge=1),
        limit:    int           = Query(50,   ge=1, le=500),
        severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
        status:   Optional[str] = Query(None, description="open | acknowledged | resolved"),
        category: Optional[str] = Query(None),
    ):
        """
        Security alerts with status management.

        Each alert includes:
        - Linked threat_id
        - Human-readable title and description
        - Automated actions that were triggered
        - Current status (open / acknowledged / resolved)

        **Example:**
        ```
        GET /api/v1/alerts?status=open&severity=CRITICAL
        GET /api/v1/alerts?category=data_exfiltration
        ```
        """
        rows, total = store.get_alerts(
            page=page, limit=limit,
            severity=severity, status=status, category=category,
        )
        from collections import Counter
        sev_cnt  = Counter(a["severity"] for a in store._alerts)
        stat_cnt = Counter(a["status"]   for a in store._alerts)

        return success(
            data=rows,
            pagination={"total": total, "page": page,
                        "limit": limit, "pages": math.ceil(total / max(limit, 1))},
            counts={
                "by_severity": dict(sev_cnt),
                "by_status":   dict(stat_cnt),
            },
        )

    # ────────────────────────────────────────────────────────────────────────
    # POST /api/v1/alerts/{alert_id}/acknowledge
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/v1/alerts/{alert_id}/acknowledge", tags=["Alerts"])
    async def acknowledge_alert(
        alert_id: str = Path(..., description="Alert UUID"),
        body: AcknowledgeBody = Body(default=AcknowledgeBody()),
    ):
        """Mark an alert as acknowledged by a named analyst."""
        updated = store.acknowledge_alert(alert_id, by=body.analyst)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
        return success(data=updated, message="Alert acknowledged")

    # ────────────────────────────────────────────────────────────────────────
    # POST /api/v1/alerts/{alert_id}/resolve
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/v1/alerts/{alert_id}/resolve", tags=["Alerts"])
    async def resolve_alert(alert_id: str = Path(..., description="Alert UUID")):
        """Mark an alert as resolved."""
        updated = store.resolve_alert(alert_id)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
        return success(data=updated, message="Alert resolved")

    # ────────────────────────────────────────────────────────────────────────
    # GET /api/v1/stats
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/v1/stats", tags=["Dashboard"])
    async def get_stats():
        """
        Live dashboard summary statistics.

        Returns aggregate counts, top attacker IPs, top targeted users,
        and category/severity breakdowns — all computed from the in-memory store.
        """
        return success(data=store.stats())

    # ────────────────────────────────────────────────────────────────────────
    # POST /api/v1/simulate_attack
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/v1/simulate_attack", tags=["Simulation"], status_code=201)
    async def simulate_attack(body: SimulateAttackBody):
        """
        Simulate a cyber attack and run it through the full AI pipeline.

        **Steps executed:**
        1. Generate realistic attack log events
        2. Extract 37 behavioural features
        3. Score with IsolationForest (anomaly_score 0–100)
        4. Classify into threat category (brute_force, privilege_escalation, …)
        5. Evaluate 10 SOAR response rules
        6. Execute matched response actions (block_ip, disable_user, …)
        7. Return full audit trail

        **Supported attack types:**
        - `brute_force` — high-volume failed logins from single IP
        - `privilege_escalation` — sudo abuse + sensitive file reads
        - `data_exfiltration` — bulk reads of large sensitive files
        - `suspicious_login` — login from high-risk country without MFA
        - `password_spray` — one IP targeting many user accounts
        - `automated_scanner` — sub-second request rate from external IP

        **Example:**
        ```json
        {
          "attack_type": "brute_force",
          "source_ip": "185.220.101.15",
          "geo_country": "RU",
          "intensity": "high"
        }
        ```
        """
        valid_types = {
            "brute_force", "privilege_escalation", "data_exfiltration",
            "suspicious_login", "password_spray", "automated_scanner",
        }
        if body.attack_type not in valid_types:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid attack_type {body.attack_type!r}. "
                       f"Choose from: {sorted(valid_types)}",
            )

        req = SimulateAttackRequest(
            attack_type=body.attack_type,
            source_ip=body.source_ip,
            username=body.username,
            geo_country=body.geo_country,
            intensity=body.intensity,
            dry_run=body.dry_run,
        )

        result = store.simulate_attack(req)
        return success(data=result.to_dict(), message="Simulation complete")

    # ────────────────────────────────────────────────────────────────────────
    # POST /api/v1/ingest
    # ────────────────────────────────────────────────────────────────────────

    @app.post("/api/v1/ingest", tags=["Ingestion"], status_code=201)
    async def ingest_events(body: IngestBody):
        """
        Ingest raw log events from an external source (Kafka, Filebeat, syslog).

        Events are enriched, scored, classified, and fed through the
        automated response engine.  Threats and alerts are created automatically.

        Each event dict should include at minimum:
        - `event_type` (login_success | login_failed | file_access | admin_access | password_change)
        - `user`
        - `ip_address`
        - `timestamp` (ISO-8601 UTC)

        **Example payload:**
        ```json
        {
          "events": [
            {
              "event_type": "login_failed",
              "user": "alice",
              "ip_address": "185.220.101.15",
              "geo_country": "RU",
              "timestamp": "2024-01-15T03:22:00Z",
              "attempt_count": 1,
              "bytes_read": 0,
              "mfa_used": null
            }
          ]
        }
        ```
        """
        if not body.events:
            raise HTTPException(status_code=422, detail="events list is empty")
        if len(body.events) > 10_000:
            raise HTTPException(status_code=413, detail="Batch too large (max 10,000 events)")

        enriched = store.ingest_events(body.events)
        return success(
            data={"ingested": len(enriched)},
            message=f"Ingested {len(enriched)} events",
        )

    # ────────────────────────────────────────────────────────────────────────
    # GET /api/v1/rules
    # ────────────────────────────────────────────────────────────────────────

    @app.get("/api/v1/rules", tags=["Rules"])
    async def list_rules():
        """
        List all configured SOAR response rules sorted by priority.

        Rules are evaluated in priority order (0 = highest).
        Each rule specifies conditions, target, and actions.
        """
        return success(
            data=store._rule_engine.list_rules(),
            total=len(store._rule_engine.list_rules()),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Standalone HTTP demo server (no FastAPI needed)
# ─────────────────────────────────────────────────────────────────────────────

else:
    # FastAPI not installed — expose a minimal stdlib HTTP server
    # that demonstrates all route logic with real ML pipeline calls.

    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass   # suppress default logging

        def _send(self, data: dict, code: int = 200):
            body = json.dumps(data, indent=2, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        def _qs(self) -> dict:
            return parse_qs(urlparse(self.path).query)

        def _int(self, key: str, default: int, mn: int = 1, mx: int = 500) -> int:
            v = self._qs().get(key, [str(default)])
            return max(mn, min(mx, int(v[0])))

        def _str(self, key: str) -> Optional[str]:
            v = self._qs().get(key)
            return v[0] if v else None

        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                if path in ("", "/"):
                    self._send({"status": "ok", "service": "AI Threat Hunting API",
                                "note": "Install FastAPI for full OpenAPI support"})

                elif path == "/api/v1/stats":
                    self._send(success(store.stats()))

                elif path == "/api/v1/logs":
                    page, limit = self._int("page", 1), self._int("limit", 50)
                    rows, total = store.get_logs(
                        page=page, limit=limit,
                        event_type=self._str("event_type"),
                        username=self._str("username"),
                        source_ip=self._str("source_ip"),
                    )
                    self._send(success(data=rows,
                                       pagination={"total":total,"page":page,"limit":limit,
                                                   "pages":math.ceil(total/max(limit,1))}))

                elif path == "/api/v1/threats":
                    page, limit = self._int("page", 1), self._int("limit", 50)
                    rows, total = store.get_threats(
                        page=page, limit=limit,
                        severity=self._str("severity"),
                        category=self._str("category"),
                    )
                    self._send(success(data=rows,
                                       pagination={"total":total,"page":page,"limit":limit,
                                                   "pages":math.ceil(total/max(limit,1))}))

                elif path == "/api/v1/alerts":
                    page, limit = self._int("page", 1), self._int("limit", 50)
                    rows, total = store.get_alerts(
                        page=page, limit=limit,
                        severity=self._str("severity"),
                        status=self._str("status"),
                    )
                    self._send(success(data=rows,
                                       pagination={"total":total,"page":page,"limit":limit,
                                                   "pages":math.ceil(total/max(limit,1))}))

                elif path == "/api/v1/rules":
                    rules = store._rule_engine.list_rules()
                    self._send(success(data=rules, total=len(rules)))

                else:
                    self._send({"error": "not_found", "path": path}, 404)

            except Exception as exc:
                self._send({"error": str(exc)}, 500)

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length)) if length else {}
            try:
                if path == "/api/v1/simulate_attack":
                    req = SimulateAttackRequest.from_dict(body)
                    result = store.simulate_attack(req)
                    self._send(success(data=result.to_dict()), 201)

                elif path == "/api/v1/ingest":
                    events = body.get("events", [])
                    enriched = store.ingest_events(events)
                    self._send(success(data={"ingested": len(enriched)}), 201)

                elif "/acknowledge" in path:
                    alert_id = path.split("/")[-2]
                    updated = store.acknowledge_alert(alert_id, by=body.get("analyst","analyst"))
                    if not updated:
                        self._send({"error": "not_found"}, 404)
                    else:
                        self._send(success(data=updated))

                elif "/resolve" in path:
                    alert_id = path.split("/")[-2]
                    updated = store.resolve_alert(alert_id)
                    if not updated:
                        self._send({"error": "not_found"}, 404)
                    else:
                        self._send(success(data=updated))

                else:
                    self._send({"error": "not_found"}, 404)

            except Exception as exc:
                self._send({"error": str(exc)}, 500)

    def run_dev_server(host: str = "0.0.0.0", port: int = 8000):
        store.bootstrap()
        print(f"\n  AI Threat Hunting API — dev server")
        print(f"  http://{host}:{port}/")
        print(f"  (Install FastAPI+uvicorn for full OpenAPI / async support)\n")
        server = HTTPServer((host, port), _Handler)
        server.serve_forever()


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if FASTAPI_AVAILABLE:
        import uvicorn
        uvicorn.run("backend.api.main:app", host="0.0.0.0", port=8000, reload=True)
    else:
        run_dev_server()
