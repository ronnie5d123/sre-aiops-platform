
from fastapi import FastAPI
from datetime import datetime, timezone
from pathlib import Path
import logging
import sqlite3
import json
import os
from contextlib import contextmanager
from analyzer import analyze_application
from ai_investigator import investigate_incident

app = FastAPI(
    title="SRE Incident Engine",
    description="Receives, processes and stores monitoring incidents",
    version="2.0.0"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("incident-engine")

# Store the database alongside this Python file.
DB_PATH = Path(
    os.getenv(
        "INCIDENT_DB_PATH",
        str(Path(__file__).with_name("incidents.db"))
    )
)


@contextmanager
def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def is_non_empty_string(value):
    return isinstance(value, str) and bool(value.strip())


def is_non_empty_string_list(value):
    return (
        isinstance(value, list)
        and bool(value)
        and all(is_non_empty_string(item) for item in value)
    )


def is_valid_root_cause_hypothesis(hypothesis):
    return (
        isinstance(hypothesis, dict)
        and is_non_empty_string(hypothesis.get("hypothesis"))
        and is_non_empty_string_list(
            hypothesis.get("supporting_evidence")
        )
        and is_non_empty_string_list(hypothesis.get("missing_evidence"))
        and hypothesis.get("confidence") in ("low", "medium", "high")
    )


def is_successful_complete_investigation(investigation_json):
    if not investigation_json:
        return False

    try:
        investigation = json.loads(investigation_json)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not isinstance(investigation, dict):
        return False

    monitoring = investigation.get("monitoring_analysis")
    ai_report = investigation.get("ai_investigation")
    required_ai_fields = {
        "incident_summary",
        "observed_evidence",
        "root_cause_hypotheses",
        "recommended_actions",
        "confirmed_root_cause",
    }

    if (
        not isinstance(monitoring, dict)
        or monitoring.get("monitoring_status") != "complete"
        or not isinstance(ai_report, dict)
        or not required_ai_fields.issubset(ai_report)
    ):
        return False

    if "status" in ai_report and ai_report["status"] != "success":
        return False

    confirmed_root_cause = ai_report["confirmed_root_cause"]
    return (
        is_non_empty_string(ai_report["incident_summary"])
        and is_non_empty_string_list(ai_report["observed_evidence"])
        and isinstance(ai_report["root_cause_hypotheses"], list)
        and all(
            is_valid_root_cause_hypothesis(hypothesis)
            for hypothesis in ai_report["root_cause_hypotheses"]
        )
        and is_non_empty_string_list(ai_report["recommended_actions"])
        and (
            confirmed_root_cause is None
            or is_non_empty_string(confirmed_root_cause)
        )
    )


def has_successful_complete_investigation(
    investigation_json, starts_at, stored_starts_at
):
    if not starts_at or stored_starts_at != starts_at:
        return False

    try:
        investigation = json.loads(investigation_json)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not isinstance(investigation, dict):
        return False

    investigation_starts_at = investigation.get(
        "alert_starts_at", stored_starts_at
    )
    return (
        investigation_starts_at == starts_at
        and is_successful_complete_investigation(investigation_json)
    )


def preserve_investigation_for_episode(investigation_json, starts_at):
    if not investigation_json:
        return None

    try:
        investigation = json.loads(investigation_json)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return investigation_json

    if not isinstance(investigation, dict):
        return investigation_json

    investigation.setdefault("alert_starts_at", starts_at)
    return json.dumps(investigation)


def initialize_database():
    with get_db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                alert_name TEXT NOT NULL,
                severity TEXT,
                summary TEXT,
                status TEXT,
                starts_at TEXT,
                first_received_at TEXT NOT NULL,
                last_received_at TEXT NOT NULL,
                resolved_at TEXT
            )

        """)

                # Add investigation storage to existing databases.
        columns = connection.execute(
            "PRAGMA table_info(incidents)"
        ).fetchall()

        column_names = [column["name"] for column in columns]

        if "investigation_json" not in column_names:
            connection.execute("""
                ALTER TABLE incidents
                ADD COLUMN investigation_json TEXT
            """)

    logger.info("Incident database initialized")


@app.on_event("startup")
async def startup_event():
    initialize_database()


@app.get("/health")
async def health():
    return {
        "service": "incident-engine",
        "status": "healthy",
        "database": "connected"
    }


@app.post("/webhook")
async def receive_alert(payload: dict):

    alerts = payload.get("alerts", [])

    logger.info("Received %s alert(s)", len(alerts))

    processed_incidents = []

    with get_db_connection() as connection:

        for alert in alerts:

            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})

            fingerprint = alert.get("fingerprint")

            # Alertmanager normally provides a fingerprint.
            if not fingerprint:
                logger.warning("Alert missing fingerprint; skipping")
                continue

            status = alert.get("status", "unknown")
            starts_at = alert.get("startsAt")
            investigation = None
            existing = connection.execute(
                """
                SELECT starts_at, first_received_at, investigation_json
                FROM incidents
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()

            if status == "firing":
                if not (
                    existing
                    and has_successful_complete_investigation(
                        existing["investigation_json"],
                        starts_at,
                        existing["starts_at"],
                    )
                ):
                    try:
                        analysis = analyze_application()
                    except Exception as error:
                        logger.exception("Monitoring analysis failed")
                        analysis = {
                            "status": "failed",
                            "error": str(error),
                        }

                    incident_data = {
                        "alert_name": labels.get("alertname", "Unknown"),
                        "severity": labels.get("severity", "unknown"),
                        "summary": annotations.get(
                            "summary", "No summary available"
                        ),
                        "description": annotations.get(
                            "description", "No description available"
                        ),
                        "monitoring_analysis": analysis,
                    }

                    ai_report = {
                        "status": "skipped",
                        "reason": "Monitoring analysis is incomplete",
                    }

                    if (
                        isinstance(analysis, dict)
                        and analysis.get("monitoring_status") == "complete"
                    ):
                        try:
                            ai_report = investigate_incident(incident_data)
                            logger.info(
                                "AI investigation completed for %s",
                                incident_data["alert_name"],
                            )
                        except Exception as error:
                            logger.exception("AI investigation failed")
                            ai_report = {
                                "status": "failed",
                                "error": str(error),
                            }

                    investigation = {
                        "alert_starts_at": starts_at,
                        "monitoring_analysis": analysis,
                        "ai_investigation": ai_report,
                    }

                    previous_is_successful = (
                        existing is not None
                        and is_successful_complete_investigation(
                            existing["investigation_json"]
                        )
                    )
                    new_is_successful = is_successful_complete_investigation(
                        json.dumps(investigation)
                    )

                    if previous_is_successful and not new_is_successful:
                        investigation_json = preserve_investigation_for_episode(
                            existing["investigation_json"], existing["starts_at"]
                        )
                    else:
                        investigation_json = json.dumps(investigation)
                else:
                    investigation_json = None
            else:
                investigation_json = (
                    preserve_investigation_for_episode(
                        existing["investigation_json"], existing["starts_at"]
                    )
                    if existing
                    else None
                )

            received_at = datetime.now(timezone.utc).isoformat()

            incident = {
                "fingerprint": fingerprint,
                "alert_name": labels.get("alertname", "Unknown"),
                "severity": labels.get("severity", "unknown"),
                "summary": annotations.get(
                    "summary", "No summary available"
                ),
                "status": status,
                "starts_at": starts_at,
                "first_received_at": (
                    existing["first_received_at"] if existing else received_at
                ),
                "last_received_at": received_at,
                "resolved_at": received_at if status == "resolved" else None,
            }
            connection.execute("""
                INSERT INTO incidents (
                    fingerprint,
                    alert_name,
                    severity,
                    summary,
                    status,
                    starts_at,
                    first_received_at,
                    last_received_at,
                    resolved_at,
                    investigation_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(fingerprint) DO UPDATE SET
                    alert_name = excluded.alert_name,
                    severity = excluded.severity,
                    summary = excluded.summary,
                    status = excluded.status,
                    starts_at = excluded.starts_at,
                    last_received_at = excluded.last_received_at,
                    resolved_at = CASE
                        WHEN excluded.status = 'resolved'
                        THEN excluded.last_received_at
                        ELSE NULL
                    END,
                    investigation_json = COALESCE(
                        excluded.investigation_json,
                        incidents.investigation_json
                    )
            """, (
                incident["fingerprint"],
                incident["alert_name"],
                incident["severity"],
                incident["summary"],
                incident["status"],
                incident["starts_at"],
                incident["first_received_at"],
                incident["last_received_at"],
                incident["resolved_at"],
                investigation_json
            ))

            processed_incidents.append(incident)

            logger.info(
                "Incident stored: %s | %s",
                incident["alert_name"],
                incident["status"]
            )

    return {
        "message": "Alerts processed successfully",
        "incident_count": len(processed_incidents),
        "incidents": processed_incidents
    }


@app.get("/incidents")
async def get_incidents():

    with get_db_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM incidents
            ORDER BY id DESC
        """).fetchall()

    return {
        "incident_count": len(rows),
        "incidents": [dict(row) for row in rows]
    }
