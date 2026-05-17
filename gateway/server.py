"""
Gateway Server — FastAPI Bridge from LoRa Network to Ranger Dashboard

Receives decoded LoRa payloads (via webhook or simulation POST),
stores them in SQLite, and serves them to the dashboard via REST + SSE.
Also serves the built dashboard as static files.
"""

import os
import json
import time
import asyncio
import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from gateway.decoder import decode_hex, decode_to_dict

logger = logging.getLogger(__name__)

# --- Database Setup ---
DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "alerts.db"
)

# In-memory alert queue for SSE streaming
_alert_queue: asyncio.Queue = asyncio.Queue()


def _init_db():
    """Create the alerts table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_type TEXT NOT NULL,
            threat_class TEXT,
            confidence INTEGER DEFAULT 0,
            latitude REAL,
            longitude REAL,
            gps_valid INTEGER DEFAULT 0,
            timestamp INTEGER,
            timestamp_iso TEXT,
            node_id INTEGER,
            battery_pct INTEGER,
            cpu_temp_c INTEGER,
            audio_db INTEGER,
            raw_json TEXT,
            received_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_PATH}")


def _insert_alert(alert_dict: dict):
    """Insert a decoded alert into SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO alerts
        (msg_type, threat_class, confidence, latitude, longitude,
         gps_valid, timestamp, timestamp_iso, node_id, battery_pct,
         cpu_temp_c, audio_db, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert_dict["msg_type"],
            alert_dict["threat"]["class"],
            alert_dict["threat"]["confidence"],
            alert_dict["location"]["latitude"],
            alert_dict["location"]["longitude"],
            1 if alert_dict["location"]["gps_valid"] else 0,
            alert_dict["timestamp"],
            alert_dict["timestamp_iso"],
            alert_dict["node"]["id"],
            alert_dict["node"]["battery_pct"],
            alert_dict["node"]["cpu_temp_c"],
            alert_dict["node"]["audio_db"],
            json.dumps(alert_dict),
        ),
    )
    conn.commit()
    conn.close()


def _get_alerts(limit: int = 100, threat_only: bool = False) -> list:
    """Fetch recent alerts from SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM alerts"
    if threat_only:
        query += " WHERE threat_class NOT IN ('AMBIENT', 'UNKNOWN')"
    query += " ORDER BY id DESC LIMIT ?"

    rows = conn.execute(query, (limit,)).fetchall()
    conn.close()

    return [
        json.loads(row["raw_json"]) for row in rows
    ]


def _get_nodes() -> list:
    """Get latest status for each node."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT node_id, battery_pct, cpu_temp_c, timestamp_iso,
               MAX(id) as latest
        FROM alerts
        GROUP BY node_id
        ORDER BY node_id
    """).fetchall()
    conn.close()

    return [
        {
            "node_id": row["node_id"],
            "battery_pct": row["battery_pct"],
            "cpu_temp_c": row["cpu_temp_c"],
            "last_seen": row["timestamp_iso"],
        }
        for row in rows
    ]


# --- FastAPI App ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    logger.info("Gateway server started")
    yield
    logger.info("Gateway server stopped")


app = FastAPI(
    title="Eco-Acoustic Mesh Gateway",
    description="LoRa → Dashboard bridge for anti-poaching sentinel network",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- API Endpoints ---

@app.post("/api/webhook")
async def receive_webhook(request: Request):
    """Receive a decoded LoRa payload from TTN/ChirpStack webhook."""
    body = await request.json()

    # Handle TTN format or raw hex
    if "payload_hex" in body:
        alert = decode_hex(body["payload_hex"])
    elif "payload_raw" in body:
        raw_bytes = bytes.fromhex(body["payload_raw"])
        alert = decode_to_dict(raw_bytes)
    else:
        # Assume it's already a decoded alert dict
        alert = body

    _insert_alert(alert)
    await _alert_queue.put(alert)

    logger.info(
        f"Webhook received: {alert['msg_type']} — "
        f"{alert['threat']['class']}"
    )
    return {"status": "ok", "alert": alert}


@app.post("/api/simulate")
async def simulate_alert(request: Request):
    """Inject a simulated alert (for demo/testing)."""
    body = await request.json()
    _insert_alert(body)
    await _alert_queue.put(body)
    return {"status": "ok", "simulated": True}


@app.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    threats_only: bool = False,
):
    """Get recent alerts."""
    alerts = _get_alerts(limit=limit, threat_only=threats_only)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/api/nodes")
async def get_nodes():
    """Get status of all sentinel nodes."""
    nodes = _get_nodes()
    return {"nodes": nodes}


@app.get("/api/alerts/stream")
async def stream_alerts():
    """SSE endpoint for real-time alert streaming."""
    async def event_generator():
        while True:
            try:
                alert = await asyncio.wait_for(
                    _alert_queue.get(), timeout=30.0
                )
                yield f"data: {json.dumps(alert)}\n\n"
            except asyncio.TimeoutError:
                # Send keepalive
                yield f": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/stats")
async def get_stats():
    """Get aggregated analytics for the dashboard."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Total counts by threat class
    threat_counts = {}
    rows = conn.execute("""
        SELECT threat_class, COUNT(*) as cnt
        FROM alerts
        WHERE threat_class NOT IN ('AMBIENT', 'UNKNOWN')
        GROUP BY threat_class
    """).fetchall()
    for row in rows:
        threat_counts[row["threat_class"]] = row["cnt"]

    # Total alerts and threats
    total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
    total_threats = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE threat_class NOT IN ('AMBIENT', 'UNKNOWN')"
    ).fetchone()["c"]

    # Hourly activity (last 24h) — use received_at for time bucketing
    hourly = []
    rows = conn.execute("""
        SELECT
            CAST(strftime('%H', datetime(received_at, 'unixepoch', 'localtime')) AS INTEGER) as hour,
            COUNT(*) as total,
            SUM(CASE WHEN threat_class NOT IN ('AMBIENT', 'UNKNOWN') THEN 1 ELSE 0 END) as threats
        FROM alerts
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    hour_map = {row["hour"]: {"total": row["total"], "threats": row["threats"]} for row in rows}
    for h in range(24):
        hourly.append({
            "hour": h,
            "total": hour_map.get(h, {}).get("total", 0),
            "threats": hour_map.get(h, {}).get("threats", 0),
        })

    # Per-node summary
    node_stats = []
    rows = conn.execute("""
        SELECT
            node_id,
            COUNT(*) as total_reports,
            SUM(CASE WHEN threat_class NOT IN ('AMBIENT', 'UNKNOWN') THEN 1 ELSE 0 END) as threat_count,
            AVG(CASE WHEN battery_pct IS NOT NULL THEN battery_pct END) as avg_battery,
            AVG(CASE WHEN cpu_temp_c IS NOT NULL THEN cpu_temp_c END) as avg_temp,
            MAX(timestamp_iso) as last_seen
        FROM alerts
        GROUP BY node_id
        ORDER BY node_id
    """).fetchall()
    for row in rows:
        node_stats.append({
            "node_id": row["node_id"],
            "total_reports": row["total_reports"],
            "threat_count": row["threat_count"],
            "avg_battery": round(row["avg_battery"] or 0, 1),
            "avg_temp": round(row["avg_temp"] or 0, 1),
            "last_seen": row["last_seen"],
        })

    # System uptime (time between first and last alert)
    first_ts = conn.execute("SELECT MIN(received_at) as t FROM alerts").fetchone()["t"]
    last_ts = conn.execute("SELECT MAX(received_at) as t FROM alerts").fetchone()["t"]
    uptime_seconds = (last_ts - first_ts) if first_ts and last_ts else 0

    conn.close()

    return {
        "threat_counts": threat_counts,
        "total_alerts": total_alerts,
        "total_threats": total_threats,
        "hourly_activity": hourly,
        "node_stats": node_stats,
        "uptime_seconds": round(uptime_seconds, 0),
        "active_nodes": len(node_stats),
    }


@app.get("/api/export/csv")
async def export_csv():
    """Export all alerts as a downloadable CSV file."""
    import io
    import csv

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT timestamp_iso, msg_type, threat_class, confidence,
               latitude, longitude, node_id, battery_pct, cpu_temp_c,
               audio_db, received_at
        FROM alerts ORDER BY id DESC
    """).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Type", "Threat", "Confidence",
        "Latitude", "Longitude", "Node ID", "Battery %",
        "CPU Temp (C)", "Audio dB", "Received At",
    ])
    for row in rows:
        writer.writerow([
            row["timestamp_iso"], row["msg_type"], row["threat_class"],
            row["confidence"], row["latitude"], row["longitude"],
            row["node_id"], row["battery_pct"], row["cpu_temp_c"],
            row["audio_db"], row["received_at"],
        ])

    csv_content = output.getvalue()
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=ecomesh_alerts.csv",
        },
    )


@app.get("/api/export/report")
async def export_report():
    """Generate a structured JSON summary report."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
    threats = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE threat_class NOT IN ('AMBIENT', 'UNKNOWN')"
    ).fetchone()["c"]

    by_type = {}
    for row in conn.execute(
        "SELECT threat_class, COUNT(*) as c FROM alerts GROUP BY threat_class"
    ).fetchall():
        by_type[row["threat_class"]] = row["c"]

    nodes = []
    for row in conn.execute("""
        SELECT node_id, COUNT(*) as reports,
               SUM(CASE WHEN threat_class NOT IN ('AMBIENT','UNKNOWN') THEN 1 ELSE 0 END) as threats,
               MIN(timestamp_iso) as first_seen, MAX(timestamp_iso) as last_seen,
               AVG(battery_pct) as avg_battery
        FROM alerts GROUP BY node_id
    """).fetchall():
        nodes.append({
            "node_id": row["node_id"],
            "reports": row["reports"],
            "threats": row["threats"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "avg_battery": round(row["avg_battery"] or 0, 1),
        })

    first_ts = conn.execute("SELECT MIN(received_at) as t FROM alerts").fetchone()["t"]
    last_ts = conn.execute("SELECT MAX(received_at) as t FROM alerts").fetchone()["t"]
    conn.close()

    return {
        "report_type": "Eco-Acoustic Mesh — Ranger Shift Report",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "monitoring_period": {
            "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first_ts)) if first_ts else None,
            "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_ts)) if last_ts else None,
            "duration_seconds": round(last_ts - first_ts, 0) if first_ts and last_ts else 0,
        },
        "summary": {
            "total_reports": total,
            "total_threats": threats,
            "threat_rate_pct": round((threats / total * 100) if total else 0, 1),
        },
        "threats_by_type": by_type,
        "node_performance": nodes,
    }


@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}


# --- Static file serving for dashboard ---
# Serve from source dir (no build step needed — vanilla HTML/CSS/JS)
_dashboard_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "dashboard",
)
# Also check dist/ for production builds
_dashboard_dist = os.path.join(_dashboard_dir, "dist")

_serve_dir = _dashboard_dist if os.path.isdir(_dashboard_dist) else _dashboard_dir
if os.path.isdir(_serve_dir):
    app.mount(
        "/",
        StaticFiles(directory=_serve_dir, html=True),
        name="dashboard",
    )


def start_server(host="0.0.0.0", port=8000):
    """Start the gateway server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_server()
