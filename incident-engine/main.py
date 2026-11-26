
from fastapi import Depends, FastAPI, HTTPException, Path as FastAPIPath, Query
from fastapi.security import APIKeyHeader
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
import hashlib
import logging
import sqlite3
import json
import os
import secrets
from contextlib import contextmanager
from pydantic import BaseModel, Field, StrictStr
from analyzer import analyze_application
from ai_investigator import investigate_incident
from remediation import RemediationSimulator, validate_action_parameters

app = FastAPI(
    title="SRE Incident Engine",
    description="Receives, processes and stores monitoring incidents",
    version="2.0.0"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("incident-engine")

remediation_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def get_remediation_actor(
    api_key: str | None = Depends(remediation_api_key_header),
) -> str:
    expected_api_key = os.getenv("REMEDIATION_API_KEY")
    if (
        not expected_api_key
        or not expected_api_key.strip()
        or not api_key
        or not secrets.compare_digest(
            api_key.encode("utf-8"),
            expected_api_key.encode("utf-8"),
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    return "api_operator"


class RemediationProposalRequest(BaseModel):
    action_key: StrictStr
    parameters: dict[str, Any] = Field(default_factory=dict)


class RemediationDecisionRequest(BaseModel):
    decision_note: StrictStr | None = Field(default=None, max_length=500)


class _RemediationExecutionFailure(Exception):
    pass


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
        connection.execute("PRAGMA foreign_keys = ON")
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

        connection.execute("""
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                episode_starts_at TEXT NOT NULL,
                action_key TEXT NOT NULL CHECK (
                    action_key IN (
                        'restart_application',
                        'scale_application',
                        'clear_application_cache'
                    )
                ),
                parameters_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL CHECK (
                    status IN (
                        'pending_approval',
                        'approved',
                        'rejected',
                        'executed',
                        'execution_failed'
                    )
                ),
                dedupe_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                proposed_by TEXT NOT NULL,
                approved_at TEXT,
                approved_by TEXT,
                rejected_at TEXT,
                rejected_by TEXT,
                decision_note TEXT,
                executed_at TEXT,
                execution_result_json TEXT,
                execution_error TEXT,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE RESTRICT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS remediation_action_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (action_id)
                    REFERENCES remediation_actions(id) ON DELETE RESTRICT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS simulator_state (
                state_key TEXT PRIMARY KEY,
                state_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS remediation_actions_incident_status_idx
            ON remediation_actions (incident_id, status)
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


@app.post("/incidents/{incident_id}/remediation-actions")
async def create_remediation_action(
    incident_id: int,
    proposal: RemediationProposalRequest,
    actor_id: str = Depends(get_remediation_actor),
):
    try:
        parameters = validate_action_parameters(
            proposal.action_key,
            proposal.parameters,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    parameters_json = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
    )

    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        incident = connection.execute(
            """
            SELECT status, starts_at
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()

        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        episode_starts_at = incident["starts_at"]
        if (
            incident["status"] != "firing"
            or not is_non_empty_string(episode_starts_at)
        ):
            raise HTTPException(
                status_code=409,
                detail="Incident is not eligible for remediation proposals",
            )

        dedupe_material = json.dumps(
            [
                incident_id,
                episode_starts_at,
                proposal.action_key,
                parameters_json,
            ],
            separators=(",", ":"),
        )
        dedupe_key = hashlib.sha256(
            dedupe_material.encode("utf-8")
        ).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute(
            """
            INSERT INTO remediation_actions (
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                dedupe_key,
                created_at,
                proposed_by
            )
            VALUES (?, ?, ?, ?, 'pending_approval', ?, ?, ?)
            ON CONFLICT(dedupe_key) DO NOTHING
            """,
            (
                incident_id,
                episode_starts_at,
                proposal.action_key,
                parameters_json,
                dedupe_key,
                created_at,
                actor_id,
            ),
        )

        if cursor.rowcount == 1:
            details_json = json.dumps(
                {
                    "action_key": proposal.action_key,
                    "parameters": parameters,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                """
                INSERT INTO remediation_action_events (
                    action_id,
                    event_type,
                    actor_id,
                    occurred_at,
                    details_json
                )
                VALUES (?, 'proposal_created', ?, ?, ?)
                """,
                (
                    cursor.lastrowid,
                    actor_id,
                    created_at,
                    details_json,
                ),
            )

        action = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by
            FROM remediation_actions
            WHERE dedupe_key = ?
            """,
            (dedupe_key,),
        ).fetchone()

    return {
        "id": action["id"],
        "incident_id": action["incident_id"],
        "episode_starts_at": action["episode_starts_at"],
        "action_key": action["action_key"],
        "parameters": json.loads(action["parameters_json"]),
        "status": action["status"],
        "created_at": action["created_at"],
        "proposed_by": action["proposed_by"],
    }


def _serialize_remediation_action(row):
    try:
        parameters = json.loads(row["parameters_json"])
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=500,
            detail="Stored remediation parameters are invalid",
        ) from error
    if not isinstance(parameters, dict):
        raise HTTPException(
            status_code=500,
            detail="Stored remediation parameters are invalid",
        )

    return {
        "id": row["id"],
        "incident_id": row["incident_id"],
        "episode_starts_at": row["episode_starts_at"],
        "action_key": row["action_key"],
        "parameters": parameters,
        "status": row["status"],
        "created_at": row["created_at"],
        "proposed_by": row["proposed_by"],
        "approved_at": row["approved_at"],
        "approved_by": row["approved_by"],
        "rejected_at": row["rejected_at"],
        "rejected_by": row["rejected_by"],
        "decision_note": row["decision_note"],
        "executed_at": row["executed_at"],
    }


@app.get("/remediation-actions")
async def list_remediation_actions(
    status: Literal[
        "pending_approval",
        "approved",
        "rejected",
        "executed",
        "execution_failed",
    ] | None = None,
    incident_id: int | None = Query(default=None, gt=0),
    _actor_id: str = Depends(get_remediation_actor),
):
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by,
                approved_at,
                approved_by,
                rejected_at,
                rejected_by,
                decision_note,
                executed_at
            FROM remediation_actions
            WHERE (? IS NULL OR status = ?)
                AND (? IS NULL OR incident_id = ?)
            ORDER BY created_at DESC, id DESC
            """,
            (status, status, incident_id, incident_id),
        ).fetchall()

    actions = [_serialize_remediation_action(row) for row in rows]

    return {
        "action_count": len(actions),
        "actions": actions,
    }


@app.get("/remediation-actions/{action_id}")
async def get_remediation_action(
    action_id: int = FastAPIPath(gt=0),
    _actor_id: str = Depends(get_remediation_actor),
):
    with get_db_connection() as connection:
        action = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by,
                approved_at,
                approved_by,
                rejected_at,
                rejected_by,
                decision_note,
                executed_at
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    return _serialize_remediation_action(action)


@app.post("/remediation-actions/{action_id}/approve")
async def approve_remediation_action(
    action_id: int = FastAPIPath(gt=0),
    decision: RemediationDecisionRequest = ...,
    actor_id: str = Depends(get_remediation_actor),
):
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        action = connection.execute(
            """
            SELECT id, incident_id, episode_starts_at, status
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

        if action is None:
            raise HTTPException(
                status_code=404,
                detail="Remediation action not found",
            )
        if action["status"] != "pending_approval":
            raise HTTPException(
                status_code=409,
                detail="Remediation action is not pending approval",
            )

        incident = connection.execute(
            """
            SELECT status, starts_at
            FROM incidents
            WHERE id = ?
            """,
            (action["incident_id"],),
        ).fetchone()
        if (
            incident is None
            or incident["status"] != "firing"
            or incident["starts_at"] != action["episode_starts_at"]
        ):
            raise HTTPException(
                status_code=409,
                detail="Incident is no longer eligible for approval",
            )

        decided_at = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute(
            """
            UPDATE remediation_actions
            SET
                status = 'approved',
                approved_at = ?,
                approved_by = ?,
                decision_note = ?
            WHERE id = ? AND status = 'pending_approval'
            """,
            (
                decided_at,
                actor_id,
                decision.decision_note,
                action_id,
            ),
        )
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=409,
                detail="Remediation action is not pending approval",
            )

        connection.execute(
            """
            INSERT INTO remediation_action_events (
                action_id,
                event_type,
                actor_id,
                occurred_at,
                details_json
            )
            VALUES (?, 'approved', ?, ?, ?)
            """,
            (
                action_id,
                actor_id,
                decided_at,
                json.dumps(
                    {"decision_note": decision.decision_note},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        updated_action = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by,
                approved_at,
                approved_by,
                rejected_at,
                rejected_by,
                decision_note,
                executed_at
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

    return _serialize_remediation_action(updated_action)


@app.post("/remediation-actions/{action_id}/reject")
async def reject_remediation_action(
    action_id: int = FastAPIPath(gt=0),
    decision: RemediationDecisionRequest = ...,
    actor_id: str = Depends(get_remediation_actor),
):
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        action = connection.execute(
            """
            SELECT id, status
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

        if action is None:
            raise HTTPException(
                status_code=404,
                detail="Remediation action not found",
            )
        if action["status"] != "pending_approval":
            raise HTTPException(
                status_code=409,
                detail="Remediation action is not pending approval",
            )

        decided_at = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute(
            """
            UPDATE remediation_actions
            SET
                status = 'rejected',
                rejected_at = ?,
                rejected_by = ?,
                decision_note = ?
            WHERE id = ? AND status = 'pending_approval'
            """,
            (
                decided_at,
                actor_id,
                decision.decision_note,
                action_id,
            ),
        )
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=409,
                detail="Remediation action is not pending approval",
            )

        connection.execute(
            """
            INSERT INTO remediation_action_events (
                action_id,
                event_type,
                actor_id,
                occurred_at,
                details_json
            )
            VALUES (?, 'rejected', ?, ?, ?)
            """,
            (
                action_id,
                actor_id,
                decided_at,
                json.dumps(
                    {"decision_note": decision.decision_note},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        updated_action = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by,
                approved_at,
                approved_by,
                rejected_at,
                rejected_by,
                decision_note,
                executed_at
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

    return _serialize_remediation_action(updated_action)


def _record_remediation_execution_failure(action_id, actor_id):
    executed_at = datetime.now(timezone.utc).isoformat()
    safe_error = "Simulation failed"

    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE remediation_actions
            SET
                status = 'execution_failed',
                executed_at = ?,
                execution_result_json = NULL,
                execution_error = ?
            WHERE id = ? AND status = 'approved'
            """,
            (executed_at, safe_error, action_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=409,
                detail="Remediation action is no longer approved",
            )

        connection.execute(
            """
            INSERT INTO remediation_action_events (
                action_id,
                event_type,
                actor_id,
                occurred_at,
                details_json
            )
            VALUES (?, 'execution_failed', ?, ?, ?)
            """,
            (
                action_id,
                actor_id,
                executed_at,
                json.dumps(
                    {"error": safe_error},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        action = connection.execute(
            """
            SELECT
                id,
                incident_id,
                episode_starts_at,
                action_key,
                parameters_json,
                status,
                created_at,
                proposed_by,
                approved_at,
                approved_by,
                rejected_at,
                rejected_by,
                decision_note,
                executed_at
            FROM remediation_actions
            WHERE id = ?
            """,
            (action_id,),
        ).fetchone()

    return _serialize_remediation_action(action)


@app.post("/remediation-actions/{action_id}/execute")
async def execute_remediation_action(
    action_id: int = FastAPIPath(gt=0),
    actor_id: str = Depends(get_remediation_actor),
):
    try:
        with get_db_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            action = connection.execute(
                """
                SELECT
                    id,
                    incident_id,
                    episode_starts_at,
                    action_key,
                    parameters_json,
                    status
                FROM remediation_actions
                WHERE id = ?
                """,
                (action_id,),
            ).fetchone()

            if action is None:
                raise HTTPException(
                    status_code=404,
                    detail="Remediation action not found",
                )
            if action["status"] != "approved":
                raise HTTPException(
                    status_code=409,
                    detail="Remediation action is not approved",
                )

            incident = connection.execute(
                """
                SELECT status, starts_at
                FROM incidents
                WHERE id = ?
                """,
                (action["incident_id"],),
            ).fetchone()
            if (
                incident is None
                or incident["status"] != "firing"
                or incident["starts_at"] != action["episode_starts_at"]
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Incident is no longer eligible for execution",
                )

            executed_at = datetime.now(timezone.utc).isoformat()
            simulator = RemediationSimulator()
            try:
                result = simulator.simulate_with_state(
                    connection,
                    action["action_key"],
                    json.loads(action["parameters_json"]),
                    executed_at,
                )
                result_json = json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            except sqlite3.Error:
                raise
            except Exception as error:
                raise _RemediationExecutionFailure from error

            cursor = connection.execute(
                """
                UPDATE remediation_actions
                SET
                    status = 'executed',
                    executed_at = ?,
                    execution_result_json = ?,
                    execution_error = NULL
                WHERE id = ? AND status = 'approved'
                """,
                (executed_at, result_json, action_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(
                    status_code=409,
                    detail="Remediation action is no longer approved",
                )

            connection.execute(
                """
                INSERT INTO remediation_action_events (
                    action_id,
                    event_type,
                    actor_id,
                    occurred_at,
                    details_json
                )
                VALUES (?, 'executed', ?, ?, ?)
                """,
                (
                    action_id,
                    actor_id,
                    executed_at,
                    result_json,
                ),
            )
            updated_action = connection.execute(
                """
                SELECT
                    id,
                    incident_id,
                    episode_starts_at,
                    action_key,
                    parameters_json,
                    status,
                    created_at,
                    proposed_by,
                    approved_at,
                    approved_by,
                    rejected_at,
                    rejected_by,
                    decision_note,
                    executed_at
                FROM remediation_actions
                WHERE id = ?
                """,
                (action_id,),
            ).fetchone()
    except _RemediationExecutionFailure:
        return _record_remediation_execution_failure(action_id, actor_id)

    return _serialize_remediation_action(updated_action)
