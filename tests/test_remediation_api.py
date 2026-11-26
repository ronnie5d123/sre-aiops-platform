import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


INCIDENT_ENGINE_DIR = Path(__file__).resolve().parents[1] / "incident-engine"
sys.path.insert(0, str(INCIDENT_ENGINE_DIR))

import remediation

main_spec = importlib.util.spec_from_file_location(
    "incident_engine_main_api",
    INCIDENT_ENGINE_DIR / "main.py",
)
if main_spec is None or main_spec.loader is None:
    raise ImportError("Could not load incident-engine/main.py")

incident_main = importlib.util.module_from_spec(main_spec)
main_spec.loader.exec_module(incident_main)


class RemediationProposalAPITests(unittest.TestCase):
    api_key = "test-remediation-api-key"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "incidents.db"
        self.db_path_patch = patch.object(incident_main, "DB_PATH", self.db_path)
        self.db_path_patch.start()
        self.environment_patch = patch.dict(
            os.environ,
            {"REMEDIATION_API_KEY": self.api_key},
        )
        self.environment_patch.start()
        incident_main.initialize_database()
        self.incident_id = self.insert_incident()
        self.client = TestClient(incident_main.app)
        original_simulate = remediation.RemediationSimulator.simulate
        self.simulator_patch = patch.object(
            remediation.RemediationSimulator,
            "simulate",
        )
        self.simulator_mock = self.simulator_patch.start()
        self.simulator_mock.side_effect = lambda action_key, parameters: (
            original_simulate(
                remediation.RemediationSimulator(),
                action_key,
                parameters,
            )
        )

    def tearDown(self):
        self.simulator_patch.stop()
        self.environment_patch.stop()
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def insert_incident(self, status="firing", starts_at="2026-11-26T01:00:00Z"):
        with incident_main.get_db_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    fingerprint,
                    alert_name,
                    status,
                    starts_at,
                    first_received_at,
                    last_received_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"api-test-{status}-{starts_at}",
                    "RemediationApiTest",
                    status,
                    starts_at,
                    "2026-11-26T01:00:00Z",
                    "2026-11-26T01:00:00Z",
                ),
            )
            return cursor.lastrowid

    def post_proposal(self, payload=None, incident_id=None, api_key=None):
        headers = {}
        if api_key is not None:
            headers["X-API-Key"] = api_key
        if payload is None:
            payload = {"action_key": "restart_application"}
        target_incident_id = (
            self.incident_id if incident_id is None else incident_id
        )
        return self.client.post(
            f"/incidents/{target_incident_id}/remediation-actions",
            json=payload,
            headers=headers,
        )

    def get_actions(self, query_params=None, api_key=None):
        headers = {}
        if api_key is not None:
            headers["X-API-Key"] = api_key
        return self.client.get(
            "/remediation-actions",
            params=query_params,
            headers=headers,
        )

    def get_action(self, action_id, api_key=None):
        headers = {}
        if api_key is not None:
            headers["X-API-Key"] = api_key
        return self.client.get(
            f"/remediation-actions/{action_id}",
            headers=headers,
        )

    def post_execute(self, action_id, api_key=None):
        headers = {}
        if api_key is not None:
            headers["X-API-Key"] = api_key
        return self.client.post(
            f"/remediation-actions/{action_id}/execute",
            headers=headers,
        )

    def post_decision(self, action_id, decision, payload=None, api_key=None):
        headers = {}
        if api_key is not None:
            headers["X-API-Key"] = api_key
        if payload is None:
            payload = {}
        return self.client.post(
            f"/remediation-actions/{action_id}/{decision}",
            json=payload,
            headers=headers,
        )

    def insert_remediation_action(
        self,
        incident_id,
        *,
        status="pending_approval",
        created_at="2026-11-26T01:00:00+00:00",
        dedupe_key="api-list-test-key",
        parameters_json='{"replicas":2}',
        **overrides,
    ):
        values = {
            "incident_id": incident_id,
            "episode_starts_at": "2026-11-26T01:00:00Z",
            "action_key": "scale_application",
            "parameters_json": parameters_json,
            "status": status,
            "dedupe_key": dedupe_key,
            "created_at": created_at,
            "proposed_by": "api_operator",
            "approved_at": None,
            "approved_by": None,
            "rejected_at": None,
            "rejected_by": None,
            "decision_note": None,
            "executed_at": None,
            "execution_result_json": None,
            "execution_error": None,
        }
        values.update(overrides)

        with incident_main.get_db_connection() as connection:
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
                    proposed_by,
                    approved_at,
                    approved_by,
                    rejected_at,
                    rejected_by,
                    decision_note,
                    executed_at,
                    execution_result_json,
                    execution_error
                )
                VALUES (
                    :incident_id,
                    :episode_starts_at,
                    :action_key,
                    :parameters_json,
                    :status,
                    :dedupe_key,
                    :created_at,
                    :proposed_by,
                    :approved_at,
                    :approved_by,
                    :rejected_at,
                    :rejected_by,
                    :decision_note,
                    :executed_at,
                    :execution_result_json,
                    :execution_error
                )
                """,
                values,
            )
            return cursor.lastrowid

    def get_simulator_state(self, state_key):
        with incident_main.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT state_value, updated_at
                FROM simulator_state
                WHERE state_key = ?
                """,
                (state_key,),
            ).fetchone()
        return None if row is None else dict(row)

    def test_missing_api_key_returns_401(self):
        response = self.post_proposal()

        self.assertEqual(response.status_code, 401)

    def test_wrong_api_key_returns_401(self):
        response = self.post_proposal(api_key="incorrect-key")

        self.assertEqual(response.status_code, 401)

    def test_missing_server_api_key_configuration_returns_401(self):
        with patch.dict(os.environ, {"REMEDIATION_API_KEY": ""}):
            response = self.post_proposal(api_key=self.api_key)

        self.assertEqual(response.status_code, 401)

    def test_valid_key_creates_a_pending_proposal(self):
        response = self.post_proposal(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(
            set(result),
            {
                "id",
                "incident_id",
                "episode_starts_at",
                "action_key",
                "parameters",
                "status",
                "created_at",
                "proposed_by",
            },
        )
        self.assertIsInstance(result["id"], int)
        self.assertEqual(result["incident_id"], self.incident_id)
        self.assertEqual(result["episode_starts_at"], "2026-11-26T01:00:00Z")
        self.assertEqual(result["action_key"], "restart_application")
        self.assertEqual(result["parameters"], {})
        self.assertEqual(result["status"], "pending_approval")
        self.assertTrue(result["created_at"])
        self.assertEqual(result["proposed_by"], "api_operator")

        with incident_main.get_db_connection() as connection:
            event = connection.execute(
                """
                SELECT event_type, actor_id
                FROM remediation_action_events
                """
            ).fetchone()

        self.assertEqual(event["event_type"], "proposal_created")
        self.assertEqual(event["actor_id"], "api_operator")

    def test_missing_incident_returns_404(self):
        response = self.post_proposal(incident_id=999, api_key=self.api_key)

        self.assertEqual(response.status_code, 404)

    def test_resolved_incident_returns_409(self):
        resolved_incident_id = self.insert_incident(
            status="resolved",
            starts_at="2026-11-26T01:05:00Z",
        )

        response = self.post_proposal(
            incident_id=resolved_incident_id,
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 409)

    def test_firing_incident_without_starts_at_returns_409(self):
        incident_id = self.insert_incident(
            status="firing",
            starts_at=None,
        )

        response = self.post_proposal(
            incident_id=incident_id,
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 409)

    def test_unsupported_action_returns_422(self):
        response = self.post_proposal(
            {"action_key": "unsupported_action"},
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 422)

    def test_invalid_scale_parameters_return_422(self):
        response = self.post_proposal(
            {
                "action_key": "scale_application",
                "parameters": {"replicas": True},
            },
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 422)

    def test_malformed_request_payload_returns_422(self):
        response = self.post_proposal(
            {
                "action_key": "restart_application",
                "parameters": [],
            },
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 422)

    def test_duplicate_proposal_returns_same_action_and_one_event(self):
        first_response = self.post_proposal(api_key=self.api_key)
        duplicate_response = self.post_proposal(api_key=self.api_key)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(duplicate_response.status_code, 200)
        self.assertEqual(
            duplicate_response.json()["id"],
            first_response.json()["id"],
        )

        with incident_main.get_db_connection() as connection:
            action_count = connection.execute(
                "SELECT COUNT(*) FROM remediation_actions"
            ).fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM remediation_action_events"
            ).fetchone()[0]

        self.assertEqual(action_count, 1)
        self.assertEqual(event_count, 1)

    def test_different_episode_timestamp_allows_new_proposal(self):
        first_response = self.post_proposal(api_key=self.api_key)
        with incident_main.get_db_connection() as connection:
            connection.execute(
                "UPDATE incidents SET starts_at = ? WHERE id = ?",
                ("2026-11-26T02:00:00Z", self.incident_id),
            )

        second_response = self.post_proposal(api_key=self.api_key)

        self.assertNotEqual(
            first_response.json()["id"],
            second_response.json()["id"],
        )
        self.assertEqual(
            second_response.json()["episode_starts_at"],
            "2026-11-26T02:00:00Z",
        )

        with incident_main.get_db_connection() as connection:
            action_count = connection.execute(
                "SELECT COUNT(*) FROM remediation_actions"
            ).fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM remediation_action_events"
            ).fetchone()[0]

        self.assertEqual(action_count, 2)
        self.assertEqual(event_count, 2)

    def test_authenticated_actor_is_used_instead_of_request_identity(self):
        response = self.post_proposal(
            {
                "action_key": "restart_application",
                "proposed_by": "untrusted_body_actor",
                "actor_id": "untrusted_body_actor",
            },
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["proposed_by"], "api_operator")

        with incident_main.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT proposed_by
                FROM remediation_actions
                WHERE id = ?
                """,
                (response.json()["id"],),
            ).fetchone()

        self.assertEqual(row["proposed_by"], "api_operator")

    def test_proposal_creation_never_executes_the_simulator(self):
        response = self.post_proposal(
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        self.simulator_mock.assert_not_called()

    def test_listing_requires_an_api_key(self):
        response = self.get_actions()

        self.assertEqual(response.status_code, 401)

    def test_listing_rejects_an_invalid_api_key(self):
        response = self.get_actions(api_key="incorrect-key")

        self.assertEqual(response.status_code, 401)

    def test_listing_empty_remediation_table_returns_empty_list(self):
        response = self.get_actions(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"action_count": 0, "actions": []})

    def test_listing_without_filters_returns_all_actions(self):
        first_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="all-actions-1",
        )
        second_incident_id = self.insert_incident(
            status="resolved",
            starts_at="2026-11-26T01:10:00Z",
        )
        second_id = self.insert_remediation_action(
            second_incident_id,
            dedupe_key="all-actions-2",
        )

        response = self.get_actions(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action_count"], 2)
        self.assertEqual(
            {action["id"] for action in result["actions"]},
            {first_id, second_id},
        )

    def test_listing_status_filter_returns_only_matching_actions(self):
        pending_id = self.insert_remediation_action(
            self.incident_id,
            status="pending_approval",
            dedupe_key="status-pending",
        )
        executed_id = self.insert_remediation_action(
            self.incident_id,
            status="executed",
            dedupe_key="status-executed",
        )

        response = self.get_actions(
            query_params={"status": "executed"},
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action_count"], 1)
        self.assertEqual([action["id"] for action in result["actions"]], [executed_id])
        self.assertNotEqual(pending_id, executed_id)

    def test_listing_incident_filter_returns_only_matching_actions(self):
        first_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="incident-filter-1",
        )
        second_incident_id = self.insert_incident(
            status="firing",
            starts_at="2026-11-26T01:20:00Z",
        )
        self.insert_remediation_action(
            second_incident_id,
            dedupe_key="incident-filter-2",
        )

        response = self.get_actions(
            query_params={"incident_id": self.incident_id},
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action_count"], 1)
        self.assertEqual([action["id"] for action in result["actions"]], [first_id])

    def test_listing_combined_filters_work(self):
        expected_id = self.insert_remediation_action(
            self.incident_id,
            status="executed",
            dedupe_key="combined-match",
        )
        self.insert_remediation_action(
            self.incident_id,
            status="pending_approval",
            dedupe_key="combined-wrong-status",
        )
        other_incident_id = self.insert_incident(
            status="firing",
            starts_at="2026-11-26T01:30:00Z",
        )
        self.insert_remediation_action(
            other_incident_id,
            status="executed",
            dedupe_key="combined-wrong-incident",
        )

        response = self.get_actions(
            query_params={
                "status": "executed",
                "incident_id": self.incident_id,
            },
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action_count"], 1)
        self.assertEqual([action["id"] for action in result["actions"]], [expected_id])

    def test_listing_rejects_unknown_status(self):
        response = self.get_actions(
            query_params={"status": "unknown"},
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 422)

    def test_listing_rejects_non_positive_incident_id(self):
        for incident_id in ("0", "-1"):
            with self.subTest(incident_id=incident_id):
                response = self.get_actions(
                    query_params={"incident_id": incident_id},
                    api_key=self.api_key,
                )
                self.assertEqual(response.status_code, 422)

    def test_listing_order_is_deterministic(self):
        older_id = self.insert_remediation_action(
            self.incident_id,
            created_at="2026-11-26T01:00:00+00:00",
            dedupe_key="ordering-older",
        )
        same_time_lower_id = self.insert_remediation_action(
            self.incident_id,
            created_at="2026-11-26T02:00:00+00:00",
            dedupe_key="ordering-same-time-1",
        )
        same_time_higher_id = self.insert_remediation_action(
            self.incident_id,
            created_at="2026-11-26T02:00:00+00:00",
            dedupe_key="ordering-same-time-2",
        )

        response = self.get_actions(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [action["id"] for action in response.json()["actions"]],
            [same_time_higher_id, same_time_lower_id, older_id],
        )

    def test_listing_hides_internal_fields(self):
        self.insert_remediation_action(
            self.incident_id,
            dedupe_key="internal-fields",
            execution_result_json='{"internal":true}',
            execution_error="internal error",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO remediation_action_events (
                    action_id,
                    event_type,
                    actor_id,
                    occurred_at,
                    details_json
                )
                SELECT id, 'test', 'api_operator', ?, ?
                FROM remediation_actions
                WHERE dedupe_key = ?
                """,
                (
                    "2026-11-26T03:00:00Z",
                    '{"private":"audit details"}',
                    "internal-fields",
                ),
            )

        response = self.get_actions(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        action = response.json()["actions"][0]
        self.assertEqual(
            set(action),
            {
                "id",
                "incident_id",
                "episode_starts_at",
                "action_key",
                "parameters",
                "status",
                "created_at",
                "proposed_by",
                "approved_at",
                "approved_by",
                "rejected_at",
                "rejected_by",
                "decision_note",
                "executed_at",
            },
        )
        self.assertEqual(action["parameters"], {"replicas": 2})

    def test_listing_does_not_modify_database_or_call_simulator(self):
        self.insert_remediation_action(
            self.incident_id,
            dedupe_key="read-only-listing",
        )
        with incident_main.get_db_connection() as connection:
            before_counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM remediation_actions"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM remediation_action_events"
                ).fetchone()[0],
            )

        response = self.get_actions(api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        with incident_main.get_db_connection() as connection:
            after_counts = (
                connection.execute(
                    "SELECT COUNT(*) FROM remediation_actions"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM remediation_action_events"
                ).fetchone()[0],
            )

        self.assertEqual(after_counts, before_counts)
        self.simulator_mock.assert_not_called()

    def test_detail_requires_an_api_key(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="detail-missing-key",
        )

        response = self.get_action(action_id)

        self.assertEqual(response.status_code, 401)

    def test_detail_rejects_an_invalid_api_key(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="detail-invalid-key",
        )

        response = self.get_action(action_id, api_key="incorrect-key")

        self.assertEqual(response.status_code, 401)

    def test_existing_action_detail_returns_public_fields_and_decoded_parameters(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            dedupe_key="detail-existing",
            parameters_json='{"replicas":3}',
            approved_at="2026-11-26T02:00:00+00:00",
            approved_by="api_operator",
            decision_note="Approved for simulation",
        )

        response = self.get_action(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["id"], action_id)
        self.assertEqual(result["incident_id"], self.incident_id)
        self.assertEqual(result["episode_starts_at"], "2026-11-26T01:00:00Z")
        self.assertEqual(result["action_key"], "scale_application")
        self.assertEqual(result["parameters"], {"replicas": 3})
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["approved_by"], "api_operator")
        self.assertEqual(
            result["approved_at"],
            "2026-11-26T02:00:00+00:00",
        )
        self.assertEqual(result["decision_note"], "Approved for simulation")

    def test_unknown_action_detail_returns_404(self):
        response = self.get_action(999, api_key=self.api_key)

        self.assertEqual(response.status_code, 404)

    def test_detail_rejects_zero_and_negative_action_ids(self):
        for action_id in (0, -1):
            with self.subTest(action_id=action_id):
                response = self.get_action(action_id, api_key=self.api_key)
                self.assertEqual(response.status_code, 422)

    def test_detail_does_not_expose_sensitive_or_internal_fields(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="detail-private-fields",
            execution_result_json='{"private":"result"}',
            execution_error="private error",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO remediation_action_events (
                    action_id,
                    event_type,
                    actor_id,
                    occurred_at,
                    details_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    "test",
                    "api_operator",
                    "2026-11-26T03:00:00Z",
                    '{"private":"audit details"}',
                ),
            )

        response = self.get_action(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(
            set(result),
            {
                "id",
                "incident_id",
                "episode_starts_at",
                "action_key",
                "parameters",
                "status",
                "created_at",
                "proposed_by",
                "approved_at",
                "approved_by",
                "rejected_at",
                "rejected_by",
                "decision_note",
                "executed_at",
            },
        )
        self.assertNotIn("dedupe_key", result)
        self.assertNotIn("parameters_json", result)
        self.assertNotIn("execution_result_json", result)
        self.assertNotIn("execution_error", result)
        self.assertNotIn("events", result)

    def test_detail_retrieval_does_not_modify_database(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="detail-read-only",
        )
        with incident_main.get_db_connection() as connection:
            before_action = dict(
                connection.execute(
                    "SELECT * FROM remediation_actions WHERE id = ?",
                    (action_id,),
                ).fetchone()
            )
            before_events = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM remediation_action_events WHERE action_id = ?",
                    (action_id,),
                )
            ]

        response = self.get_action(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        with incident_main.get_db_connection() as connection:
            after_action = dict(
                connection.execute(
                    "SELECT * FROM remediation_actions WHERE id = ?",
                    (action_id,),
                ).fetchone()
            )
            after_events = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM remediation_action_events WHERE action_id = ?",
                    (action_id,),
                )
            ]

        self.assertEqual(after_action, before_action)
        self.assertEqual(after_events, before_events)
        self.simulator_mock.assert_not_called()

    def test_detail_never_executes_the_simulator(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="detail-no-simulator",
        )

        response = self.get_action(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        self.simulator_mock.assert_not_called()

    def test_decision_endpoints_require_valid_api_key(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="decision-auth",
        )

        for decision in ("approve", "reject"):
            with self.subTest(decision=decision):
                missing_key_response = self.post_decision(action_id, decision)
                invalid_key_response = self.post_decision(
                    action_id,
                    decision,
                    api_key="incorrect-key",
                )
                self.assertEqual(missing_key_response.status_code, 401)
                self.assertEqual(invalid_key_response.status_code, 401)

    def test_approval_records_authenticated_actor_note_and_single_event(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="approve-success",
        )
        with incident_main.get_db_connection() as connection:
            incident_before = dict(
                connection.execute(
                    """
                    SELECT status, starts_at, investigation_json
                    FROM incidents
                    WHERE id = ?
                    """,
                    (self.incident_id,),
                ).fetchone()
            )

        response = self.post_decision(
            action_id,
            "approve",
            {
                "decision_note": "Approved after review",
                "approved_by": "untrusted_body_actor",
            },
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["id"], action_id)
        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["approved_by"], "api_operator")
        self.assertEqual(result["decision_note"], "Approved after review")
        self.assertTrue(result["approved_at"])
        self.assertEqual(result["rejected_at"], None)

        with incident_main.get_db_connection() as connection:
            events = connection.execute(
                """
                SELECT event_type, actor_id, details_json
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchall()
            incident_after = dict(
                connection.execute(
                    """
                    SELECT status, starts_at, investigation_json
                    FROM incidents
                    WHERE id = ?
                    """,
                    (self.incident_id,),
                ).fetchone()
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "approved")
        self.assertEqual(events[0]["actor_id"], "api_operator")
        self.assertEqual(
            json.loads(events[0]["details_json"]),
            {"decision_note": "Approved after review"},
        )
        self.assertEqual(incident_after, incident_before)
        self.simulator_mock.assert_not_called()

    def test_rejection_records_actor_and_allows_omitted_note_after_resolution(self):
        resolved_incident_id = self.insert_incident(
            status="resolved",
            starts_at="2026-11-26T04:00:00Z",
        )
        action_id = self.insert_remediation_action(
            resolved_incident_id,
            dedupe_key="reject-after-resolution",
        )

        response = self.post_decision(
            action_id,
            "reject",
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["rejected_by"], "api_operator")
        self.assertTrue(result["rejected_at"])
        self.assertIsNone(result["decision_note"])

        with incident_main.get_db_connection() as connection:
            events = connection.execute(
                """
                SELECT event_type, actor_id
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchall()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "rejected")
        self.assertEqual(events[0]["actor_id"], "api_operator")
        self.simulator_mock.assert_not_called()

    def test_missing_action_returns_404_for_both_decisions(self):
        for decision in ("approve", "reject"):
            with self.subTest(decision=decision):
                response = self.post_decision(
                    999,
                    decision,
                    api_key=self.api_key,
                )
                self.assertEqual(response.status_code, 404)

    def test_decision_endpoints_reject_non_positive_action_ids(self):
        for action_id, decision in ((0, "approve"), (-1, "reject")):
            with self.subTest(action_id=action_id, decision=decision):
                response = self.post_decision(
                    action_id,
                    decision,
                    api_key=self.api_key,
                )
                self.assertEqual(response.status_code, 422)

    def test_approval_rejects_already_decided_actions_without_changes(self):
        for status in ("approved", "rejected"):
            with self.subTest(status=status):
                action_id = self.insert_remediation_action(
                    self.incident_id,
                    status=status,
                    dedupe_key=f"approval-already-{status}",
                )

                response = self.post_decision(
                    action_id,
                    "approve",
                    api_key=self.api_key,
                )

                self.assertEqual(response.status_code, 409)
                with incident_main.get_db_connection() as connection:
                    action = connection.execute(
                        "SELECT status FROM remediation_actions WHERE id = ?",
                        (action_id,),
                    ).fetchone()
                    event_count = connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM remediation_action_events
                        WHERE action_id = ?
                        """,
                        (action_id,),
                    ).fetchone()[0]

                self.assertEqual(action["status"], status)
                self.assertEqual(event_count, 0)

    def test_rejection_of_already_decided_action_returns_409(self):
        for status in ("approved", "rejected"):
            with self.subTest(status=status):
                action_id = self.insert_remediation_action(
                    self.incident_id,
                    status=status,
                    dedupe_key=f"rejection-already-{status}",
                )

                response = self.post_decision(
                    action_id,
                    "reject",
                    api_key=self.api_key,
                )

                self.assertEqual(response.status_code, 409)
                with incident_main.get_db_connection() as connection:
                    action = connection.execute(
                        "SELECT status FROM remediation_actions WHERE id = ?",
                        (action_id,),
                    ).fetchone()
                    event_count = connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM remediation_action_events
                        WHERE action_id = ?
                        """,
                        (action_id,),
                    ).fetchone()[0]

                self.assertEqual(action["status"], status)
                self.assertEqual(event_count, 0)

    def test_approval_fails_after_incident_resolution_without_changes(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="approval-resolved",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                ("resolved", self.incident_id),
            )

        response = self.post_decision(
            action_id,
            "approve",
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 409)
        with incident_main.get_db_connection() as connection:
            action = connection.execute(
                "SELECT status FROM remediation_actions WHERE id = ?",
                (action_id,),
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()[0]

        self.assertEqual(action["status"], "pending_approval")
        self.assertEqual(event_count, 0)

    def test_approval_fails_when_incident_episode_changes_without_changes(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="approval-stale-episode",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                "UPDATE incidents SET starts_at = ? WHERE id = ?",
                ("2026-11-26T05:00:00Z", self.incident_id),
            )

        response = self.post_decision(
            action_id,
            "approve",
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 409)
        with incident_main.get_db_connection() as connection:
            action = connection.execute(
                "SELECT status FROM remediation_actions WHERE id = ?",
                (action_id,),
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()[0]

        self.assertEqual(action["status"], "pending_approval")
        self.assertEqual(event_count, 0)

    def test_decision_note_must_not_exceed_500_characters(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            dedupe_key="decision-note-too-long",
        )

        response = self.post_decision(
            action_id,
            "approve",
            {"decision_note": "x" * 501},
            api_key=self.api_key,
        )

        self.assertEqual(response.status_code, 422)
        with incident_main.get_db_connection() as connection:
            action = connection.execute(
                "SELECT status FROM remediation_actions WHERE id = ?",
                (action_id,),
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchone()[0]

        self.assertEqual(action["status"], "pending_approval")
        self.assertEqual(event_count, 0)

    def test_execution_requires_valid_api_key(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            dedupe_key="execute-auth",
        )

        missing_key_response = self.post_execute(action_id)
        invalid_key_response = self.post_execute(
            action_id,
            api_key="incorrect-key",
        )

        self.assertEqual(missing_key_response.status_code, 401)
        self.assertEqual(invalid_key_response.status_code, 401)
        self.assertIsNone(self.get_simulator_state("restart_count"))

    def test_restart_execution_increments_state_and_records_result(self):
        first_action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-restart-1",
        )
        second_action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-restart-2",
        )
        self.assertIsNone(self.get_simulator_state("restart_count"))

        first_response = self.post_execute(first_action_id, api_key=self.api_key)
        second_response = self.post_execute(second_action_id, api_key=self.api_key)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(first_response.json()["status"], "executed")
        self.assertNotIn("execution_result_json", first_response.json())
        self.assertNotIn("execution_error", first_response.json())
        self.assertEqual(self.get_simulator_state("restart_count")["state_value"], "2")

        with incident_main.get_db_connection() as connection:
            action = connection.execute(
                """
                SELECT status, executed_at, execution_result_json, execution_error
                FROM remediation_actions
                WHERE id = ?
                """,
                (first_action_id,),
            ).fetchone()
            events = connection.execute(
                """
                SELECT event_type, actor_id, occurred_at, details_json
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (first_action_id,),
            ).fetchall()

        self.assertEqual(action["status"], "executed")
        self.assertTrue(action["executed_at"].endswith("+00:00"))
        self.assertIsNone(action["execution_error"])
        simulation_result = json.loads(action["execution_result_json"])
        self.assertIs(simulation_result["simulated"], True)
        self.assertIs(simulation_result["real_infrastructure_modified"], False)
        self.assertEqual(simulation_result["details"]["previous_value"], 0)
        self.assertEqual(simulation_result["details"]["current_value"], 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "executed")
        self.assertEqual(events[0]["actor_id"], "api_operator")
        self.assertEqual(events[0]["occurred_at"], action["executed_at"])
        self.assertEqual(
            json.loads(events[0]["details_json"]),
            simulation_result,
        )
        self.assertEqual(self.simulator_mock.call_count, 2)

    def test_scale_execution_sets_replica_count_from_default(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="scale_application",
            parameters_json='{"replicas":4}',
            dedupe_key="execute-scale",
        )

        response = self.post_execute(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        state = self.get_simulator_state("replica_count")
        self.assertEqual(state["state_value"], "4")
        result = json.loads(
            self.read_action_execution(action_id)["execution_result_json"]
        )
        self.assertEqual(result["details"]["previous_value"], 1)
        self.assertEqual(result["details"]["current_value"], 4)
        self.assertIs(result["real_infrastructure_modified"], False)

    def test_cache_clear_increments_generation_across_actions(self):
        action_ids = [
            self.insert_remediation_action(
                self.incident_id,
                status="approved",
                action_key="clear_application_cache",
                parameters_json="{}",
                dedupe_key=f"execute-cache-{index}",
            )
            for index in (1, 2)
        ]
        self.assertIsNone(self.get_simulator_state("cache_generation"))

        responses = [
            self.post_execute(action_id, api_key=self.api_key)
            for action_id in action_ids
        ]

        self.assertEqual([response.status_code for response in responses], [200, 200])
        self.assertEqual(
            self.get_simulator_state("cache_generation")["state_value"],
            "2",
        )
        first_result = json.loads(
            self.read_action_execution(action_ids[0])["execution_result_json"]
        )
        self.assertEqual(first_result["details"]["previous_value"], 0)
        self.assertEqual(first_result["details"]["current_value"], 1)

    def test_unknown_action_returns_404(self):
        response = self.post_execute(999, api_key=self.api_key)

        self.assertEqual(response.status_code, 404)

    def test_execution_rejects_non_positive_action_ids(self):
        for action_id in (0, -1):
            with self.subTest(action_id=action_id):
                response = self.post_execute(
                    action_id,
                    api_key=self.api_key,
                )
                self.assertEqual(response.status_code, 422)

    def test_non_approved_lifecycle_states_cannot_execute(self):
        for status in (
            "pending_approval",
            "rejected",
            "executed",
            "execution_failed",
        ):
            with self.subTest(status=status):
                action_id = self.insert_remediation_action(
                    self.incident_id,
                    status=status,
                    dedupe_key=f"execute-invalid-state-{status}",
                )

                response = self.post_execute(
                    action_id,
                    api_key=self.api_key,
                )

                self.assertEqual(response.status_code, 409)
                self.assertIsNone(self.get_simulator_state("replica_count"))
                with incident_main.get_db_connection() as connection:
                    action = connection.execute(
                        "SELECT status FROM remediation_actions WHERE id = ?",
                        (action_id,),
                    ).fetchone()
                    event_count = connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM remediation_action_events
                        WHERE action_id = ?
                        """,
                        (action_id,),
                    ).fetchone()[0]

                self.assertEqual(action["status"], status)
                self.assertEqual(event_count, 0)

    def test_resolved_incident_cannot_execute_or_change_simulator_state(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-resolved",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                ("resolved", self.incident_id),
            )

        response = self.post_execute(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 409)
        self.assertIsNone(self.get_simulator_state("restart_count"))
        self.assertEqual(
            self.read_action_execution(action_id)["status"],
            "approved",
        )
        self.assertEqual(self.get_event_count(action_id), 0)
        self.simulator_mock.assert_not_called()

    def test_changed_incident_episode_cannot_execute_or_change_state(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-stale-episode",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                "UPDATE incidents SET starts_at = ? WHERE id = ?",
                ("2026-11-26T06:00:00Z", self.incident_id),
            )

        response = self.post_execute(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 409)
        self.assertIsNone(self.get_simulator_state("restart_count"))
        self.assertEqual(
            self.read_action_execution(action_id)["status"],
            "approved",
        )
        self.assertEqual(self.get_event_count(action_id), 0)
        self.simulator_mock.assert_not_called()

    def test_duplicate_execution_returns_conflict_without_reapplying_state(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-duplicate",
        )

        first_response = self.post_execute(action_id, api_key=self.api_key)
        duplicate_response = self.post_execute(action_id, api_key=self.api_key)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(duplicate_response.status_code, 409)
        self.assertEqual(
            self.get_simulator_state("restart_count")["state_value"],
            "1",
        )
        self.assertEqual(self.get_event_count(action_id), 1)
        self.assertEqual(self.simulator_mock.call_count, 1)

    def test_concurrent_execution_applies_state_once(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-concurrent",
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(
                executor.map(
                    lambda _: self.post_execute(
                        action_id,
                        api_key=self.api_key,
                    ),
                    range(2),
                )
            )

        self.assertCountEqual(
            [response.status_code for response in responses],
            [200, 409],
        )
        self.assertEqual(
            self.get_simulator_state("restart_count")["state_value"],
            "1",
        )
        self.assertEqual(self.get_event_count(action_id), 1)
        self.assertEqual(self.simulator_mock.call_count, 1)

    def test_simulator_failure_rolls_back_state_and_records_safe_failure(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-simulator-failure",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO simulator_state (state_key, state_value, updated_at)
                VALUES (?, ?, ?)
                """,
                (
                    "restart_count",
                    "7",
                    "2026-11-26T00:00:00+00:00",
                ),
            )
        self.simulator_mock.side_effect = RuntimeError(
            "sensitive simulator details"
        )

        response = self.post_execute(action_id, api_key=self.api_key)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "execution_failed")
        self.assertNotIn("sensitive simulator details", response.text)
        state = self.get_simulator_state("restart_count")
        self.assertEqual(state["state_value"], "7")
        self.assertEqual(state["updated_at"], "2026-11-26T00:00:00+00:00")
        action = self.read_action_execution(action_id)
        self.assertEqual(action["status"], "execution_failed")
        self.assertEqual(action["execution_error"], "Simulation failed")
        self.assertIsNone(action["execution_result_json"])
        self.assertTrue(action["executed_at"].endswith("+00:00"))
        events = self.get_action_events(action_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "execution_failed")
        self.assertEqual(events[0]["actor_id"], "api_operator")
        self.assertEqual(
            json.loads(events[0]["details_json"]),
            {"error": "Simulation failed"},
        )

    def test_executed_status_update_database_error_rolls_back_without_failure_record(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-status-database-error",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_executed_status
                BEFORE UPDATE OF status ON remediation_actions
                WHEN NEW.status = 'executed'
                BEGIN
                    SELECT RAISE(FAIL, 'forced status persistence error');
                END
                """
            )

        with self.assertRaises(sqlite3.IntegrityError):
            self.post_execute(action_id, api_key=self.api_key)

        self.assertIsNone(self.get_simulator_state("restart_count"))
        action = self.read_action_execution(action_id)
        self.assertEqual(action["status"], "approved")
        self.assertIsNone(action["executed_at"])
        self.assertIsNone(action["execution_result_json"])
        self.assertIsNone(action["execution_error"])
        self.assertEqual(self.get_event_count(action_id), 0)

    def test_audit_insert_database_error_rolls_back_without_failure_record(self):
        action_id = self.insert_remediation_action(
            self.incident_id,
            status="approved",
            action_key="restart_application",
            parameters_json="{}",
            dedupe_key="execute-audit-database-error",
        )
        with incident_main.get_db_connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_executed_audit
                BEFORE INSERT ON remediation_action_events
                WHEN NEW.event_type = 'executed'
                BEGIN
                    SELECT RAISE(FAIL, 'forced audit persistence error');
                END
                """
            )

        with self.assertRaises(sqlite3.IntegrityError):
            self.post_execute(action_id, api_key=self.api_key)

        self.assertIsNone(self.get_simulator_state("restart_count"))
        action = self.read_action_execution(action_id)
        self.assertEqual(action["status"], "approved")
        self.assertIsNone(action["executed_at"])
        self.assertIsNone(action["execution_result_json"])
        self.assertIsNone(action["execution_error"])
        self.assertEqual(self.get_event_count(action_id), 0)

    def read_action_execution(self, action_id):
        with incident_main.get_db_connection() as connection:
            row = connection.execute(
                """
                SELECT status, executed_at, execution_result_json, execution_error
                FROM remediation_actions
                WHERE id = ?
                """,
                (action_id,),
            ).fetchone()
        return dict(row)

    def get_event_count(self, action_id):
        return len(self.get_action_events(action_id))

    def get_action_events(self, action_id):
        with incident_main.get_db_connection() as connection:
            rows = connection.execute(
                """
                SELECT event_type, actor_id, occurred_at, details_json
                FROM remediation_action_events
                WHERE action_id = ?
                """,
                (action_id,),
            ).fetchall()
        return [dict(row) for row in rows]


if __name__ == "__main__":
    unittest.main()
