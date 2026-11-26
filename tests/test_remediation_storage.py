import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


INCIDENT_ENGINE_DIR = Path(__file__).resolve().parents[1] / "incident-engine"
sys.path.insert(0, str(INCIDENT_ENGINE_DIR))
main_spec = importlib.util.spec_from_file_location(
    "incident_engine_main_storage",
    INCIDENT_ENGINE_DIR / "main.py",
)
if main_spec is None or main_spec.loader is None:
    raise ImportError("Could not load incident-engine/main.py")

incident_main = importlib.util.module_from_spec(main_spec)
main_spec.loader.exec_module(incident_main)


class RemediationStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "incidents.db"
        self.db_path_patch = patch.object(incident_main, "DB_PATH", self.db_path)
        self.db_path_patch.start()
        incident_main.initialize_database()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def insert_incident(self):
        with incident_main.get_db_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    fingerprint,
                    alert_name,
                    first_received_at,
                    last_received_at,
                    investigation_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "storage-test-fingerprint",
                    "StorageTestAlert",
                    "2026-11-26T00:00:00Z",
                    "2026-11-26T00:00:00Z",
                    '{"existing": true}',
                ),
            )
            return cursor.lastrowid

    def insert_action(self, incident_id, **overrides):
        values = {
            "incident_id": incident_id,
            "episode_starts_at": "2026-11-26T00:00:00Z",
            "action_key": "restart_application",
            "parameters_json": "{}",
            "status": "pending_approval",
            "dedupe_key": "storage-test-dedupe-key",
            "created_at": "2026-11-26T00:01:00Z",
            "proposed_by": "storage-test-operator",
        }
        values.update(overrides)

        return """
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
            VALUES (
                :incident_id,
                :episode_starts_at,
                :action_key,
                :parameters_json,
                :status,
                :dedupe_key,
                :created_at,
                :proposed_by
            )
        """, values

    def test_initialization_creates_tables_and_index(self):
        with incident_main.get_db_connection() as connection:
            schema_objects = {
                row["name"]: row["type"]
                for row in connection.execute(
                    """
                    SELECT name, type
                    FROM sqlite_master
                    WHERE name IN (
                        'remediation_actions',
                        'remediation_action_events',
                        'simulator_state',
                        'remediation_actions_incident_status_idx'
                    )
                    """
                )
            }

            self.assertEqual(
                schema_objects,
                {
                    "remediation_actions": "table",
                    "remediation_action_events": "table",
                    "simulator_state": "table",
                    "remediation_actions_incident_status_idx": "index",
                },
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM simulator_state"
                ).fetchone()[0],
                0,
            )

    def test_initialization_is_idempotent(self):
        incident_main.initialize_database()
        incident_main.initialize_database()

        with incident_main.get_db_connection() as connection:
            tables = connection.execute(
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                    AND name IN (
                        'remediation_actions',
                        'remediation_action_events',
                        'simulator_state'
                    )
                """
            ).fetchone()[0]
            indexes = connection.execute(
                """
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'index'
                    AND name = 'remediation_actions_incident_status_idx'
                """
            ).fetchone()[0]

        self.assertEqual(tables, 3)
        self.assertEqual(indexes, 1)

    def test_existing_incident_and_investigation_survive_initialization(self):
        incident_id = self.insert_incident()

        incident_main.initialize_database()
        incident_main.initialize_database()

        with incident_main.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT fingerprint, investigation_json
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertEqual(row["fingerprint"], "storage-test-fingerprint")
        self.assertEqual(row["investigation_json"], '{"existing": true}')

    def test_foreign_keys_are_enabled_on_each_new_connection(self):
        for _ in range(3):
            with incident_main.get_db_connection() as connection:
                self.assertEqual(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0],
                    1,
                )

    def test_action_rejects_nonexistent_incident(self):
        insert_sql, values = self.insert_action(incident_id=999)

        with self.assertRaises(sqlite3.IntegrityError):
            with incident_main.get_db_connection() as connection:
                connection.execute(insert_sql, values)

    def test_event_rejects_nonexistent_action(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with incident_main.get_db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO remediation_action_events (
                        action_id,
                        event_type,
                        actor_id,
                        occurred_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        999,
                        "proposal_created",
                        "storage-test-operator",
                        "2026-11-26T00:01:00Z",
                    ),
                )

    def test_action_key_check_rejects_unsupported_values(self):
        incident_id = self.insert_incident()
        insert_sql, values = self.insert_action(
            incident_id,
            action_key="unsupported_action",
        )

        with self.assertRaises(sqlite3.IntegrityError):
            with incident_main.get_db_connection() as connection:
                connection.execute(insert_sql, values)

    def test_status_check_rejects_unsupported_values(self):
        incident_id = self.insert_incident()
        insert_sql, values = self.insert_action(
            incident_id,
            status="unsupported_status",
        )

        with self.assertRaises(sqlite3.IntegrityError):
            with incident_main.get_db_connection() as connection:
                connection.execute(insert_sql, values)

    def test_dedupe_key_must_be_unique(self):
        incident_id = self.insert_incident()
        insert_sql, values = self.insert_action(incident_id)

        with incident_main.get_db_connection() as connection:
            connection.execute(insert_sql, values)

        values["episode_starts_at"] = "2026-11-26T00:05:00Z"
        with self.assertRaises(sqlite3.IntegrityError):
            with incident_main.get_db_connection() as connection:
                connection.execute(insert_sql, values)


if __name__ == "__main__":
    unittest.main()
