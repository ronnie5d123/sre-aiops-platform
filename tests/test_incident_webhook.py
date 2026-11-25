import asyncio
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


INCIDENT_ENGINE_DIR = Path(__file__).resolve().parents[1] / "incident-engine"
sys.path.insert(0, str(INCIDENT_ENGINE_DIR))

main_spec = importlib.util.spec_from_file_location(
    "incident_engine_main", INCIDENT_ENGINE_DIR / "main.py"
)
if main_spec is None or main_spec.loader is None:
    raise ImportError("Could not load incident-engine/main.py")

incident_main = importlib.util.module_from_spec(main_spec)
main_spec.loader.exec_module(incident_main)


def complete_analysis():
    return {
        "monitoring_status": "complete",
        "overall_severity": "critical",
    }


def incomplete_analysis():
    return {
        "monitoring_status": "incomplete",
        "overall_severity": "unknown",
    }


def successful_ai_report():
    return {
        "incident_summary": "Investigation summary",
        "observed_evidence": ["Monitoring evidence"],
        "root_cause_hypotheses": [],
        "recommended_actions": ["Review application logs"],
        "confirmed_root_cause": None,
    }


def investigation_json(ai_report=None, monitoring=None):
    return json.dumps({
        "monitoring_analysis": (
            monitoring
            if monitoring is not None
            else {"monitoring_status": "complete"}
        ),
        "ai_investigation": (
            ai_report
            if ai_report is not None
            else {
                "incident_summary": "Investigation summary",
                "observed_evidence": [
                    "Prometheus reports the service is available."
                ],
                "root_cause_hypotheses": [
                    {
                        "hypothesis": "A downstream dependency may be slow.",
                        "supporting_evidence": ["P95 latency is elevated."],
                        "missing_evidence": [
                            "Dependency-specific latency data."
                        ],
                        "confidence": "medium",
                    }
                ],
                "recommended_actions": [
                    "Inspect dependency latency metrics."
                ],
                "confirmed_root_cause": None,
            }
        ),
    })


def webhook_payload(status="firing", starts_at="2026-11-25T10:00:00Z"):
    return {
        "alerts": [
            {
                "status": status,
                "fingerprint": "test-fingerprint",
                "startsAt": starts_at,
                "labels": {
                    "alertname": "TestAlert",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Test incident",
                    "description": "Webhook test",
                },
            }
        ]
    }


class IncidentWebhookTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "incidents.db"
        self.db_path_patch = patch.object(incident_main, "DB_PATH", self.db_path)
        self.db_path_patch.start()
        incident_main.initialize_database()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def receive(self, payload):
        return asyncio.run(incident_main.receive_alert(payload))

    def stored_incident(self):
        with incident_main.get_db_connection() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE fingerprint = ?",
                ("test-fingerprint",),
            ).fetchone()
        return dict(row)

    def test_repeated_firing_skips_analysis_and_ai_after_success(self):
        with (
            patch.object(
                incident_main, "analyze_application", return_value=complete_analysis()
            ) as analyze,
            patch.object(
                incident_main, "investigate_incident", return_value=successful_ai_report()
            ) as investigate,
        ):
            first_response = self.receive(webhook_payload())
            original = self.stored_incident()
            repeated_response = self.receive(webhook_payload())
            updated = self.stored_incident()

        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(investigate.call_count, 1)
        self.assertEqual(
            updated["first_received_at"], original["first_received_at"]
        )
        self.assertEqual(
            json.loads(updated["investigation_json"]),
            json.loads(original["investigation_json"]),
        )
        self.assertEqual(
            repeated_response["incidents"][0]["first_received_at"],
            first_response["incidents"][0]["first_received_at"],
        )

    def test_incomplete_analysis_is_retried_and_ai_waits_for_complete_evidence(self):
        with (
            patch.object(
                incident_main,
                "analyze_application",
                side_effect=[incomplete_analysis(), complete_analysis()],
            ) as analyze,
            patch.object(
                incident_main, "investigate_incident", return_value=successful_ai_report()
            ) as investigate,
        ):
            self.receive(webhook_payload())
            first_investigation = json.loads(
                self.stored_incident()["investigation_json"]
            )
            self.receive(webhook_payload())
            final_investigation = json.loads(
                self.stored_incident()["investigation_json"]
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(investigate.call_count, 1)
        self.assertEqual(
            first_investigation["monitoring_analysis"]["monitoring_status"],
            "incomplete",
        )
        self.assertEqual(
            final_investigation["monitoring_analysis"]["monitoring_status"],
            "complete",
        )

    def test_new_episode_does_not_reuse_prior_episode_investigation(self):
        with (
            patch.object(
                incident_main,
                "analyze_application",
                side_effect=[complete_analysis(), incomplete_analysis(), complete_analysis()],
            ) as analyze,
            patch.object(
                incident_main,
                "investigate_incident",
                return_value=successful_ai_report(),
            ) as investigate,
        ):
            self.receive(webhook_payload())
            old_investigation = json.loads(
                self.stored_incident()["investigation_json"]
            )

            new_episode = webhook_payload(starts_at="2026-11-25T11:00:00Z")
            self.receive(new_episode)
            after_incomplete = json.loads(
                self.stored_incident()["investigation_json"]
            )

            self.receive(new_episode)
            after_retry = json.loads(
                self.stored_incident()["investigation_json"]
            )

        self.assertEqual(analyze.call_count, 3)
        self.assertEqual(investigate.call_count, 2)
        self.assertEqual(
            after_incomplete["monitoring_analysis"],
            old_investigation["monitoring_analysis"],
        )
        self.assertEqual(
            after_incomplete["alert_starts_at"], "2026-11-25T10:00:00Z"
        )
        self.assertEqual(
            after_retry["monitoring_analysis"]["monitoring_status"],
            "complete",
        )

    def test_ai_failure_in_new_episode_preserves_previous_success(self):
        with (
            patch.object(
                incident_main, "analyze_application", return_value=complete_analysis()
            ) as analyze,
            patch.object(
                incident_main,
                "investigate_incident",
                side_effect=[successful_ai_report(), RuntimeError("model unavailable"),
                             successful_ai_report()],
            ) as investigate,
        ):
            self.receive(webhook_payload())
            original = json.loads(self.stored_incident()["investigation_json"])

            new_episode = webhook_payload(starts_at="2026-11-25T11:00:00Z")
            self.receive(new_episode)
            after_failure = json.loads(
                self.stored_incident()["investigation_json"]
            )

            self.receive(new_episode)
            after_retry = json.loads(
                self.stored_incident()["investigation_json"]
            )

        self.assertEqual(analyze.call_count, 3)
        self.assertEqual(investigate.call_count, 3)
        self.assertEqual(after_failure, original)
        self.assertEqual(after_retry["alert_starts_at"], "2026-11-25T11:00:00Z")

    def test_resolved_notification_preserves_investigation(self):
        with (
            patch.object(
                incident_main, "analyze_application", return_value=complete_analysis()
            ) as analyze,
            patch.object(
                incident_main, "investigate_incident", return_value=successful_ai_report()
            ) as investigate,
        ):
            self.receive(webhook_payload())
            original = self.stored_incident()
            self.receive(webhook_payload(status="resolved"))
            resolved = self.stored_incident()

        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(investigate.call_count, 1)
        self.assertEqual(
            resolved["investigation_json"], original["investigation_json"]
        )
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolved_at"], resolved["last_received_at"])


class InvestigationValidationTests(unittest.TestCase):
    def test_accepts_complete_investigation_with_optional_success_status(self):
        report = json.loads(investigation_json())
        self.assertTrue(
            incident_main.is_successful_complete_investigation(json.dumps(report))
        )

        report["ai_investigation"]["status"] = "success"
        self.assertTrue(
            incident_main.is_successful_complete_investigation(json.dumps(report))
        )

    def test_accepts_null_confirmed_root_cause(self):
        self.assertTrue(
            incident_main.is_successful_complete_investigation(
                investigation_json()
            )
        )

    def test_accepts_empty_root_cause_hypotheses_list(self):
        report = json.loads(investigation_json())
        report["ai_investigation"]["root_cause_hypotheses"] = []

        self.assertTrue(
            incident_main.is_successful_complete_investigation(json.dumps(report))
        )

    def test_rejects_blank_confirmed_root_cause(self):
        report = json.loads(investigation_json())
        report["ai_investigation"]["confirmed_root_cause"] = "  "

        self.assertFalse(
            incident_main.is_successful_complete_investigation(json.dumps(report))
        )

    def test_rejects_hypothesis_with_empty_missing_evidence(self):
        report = json.loads(investigation_json())
        report["ai_investigation"]["root_cause_hypotheses"][0][
            "missing_evidence"
        ] = []

        self.assertFalse(
            incident_main.is_successful_complete_investigation(json.dumps(report))
        )

    def test_rejects_missing_required_ai_fields(self):
        required_fields = {
            "incident_summary",
            "observed_evidence",
            "root_cause_hypotheses",
            "recommended_actions",
            "confirmed_root_cause",
        }

        for field in required_fields:
            with self.subTest(field=field):
                report = json.loads(investigation_json())
                del report["ai_investigation"][field]
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

    def test_rejects_empty_incident_summary(self):
        for summary in ("", "  ", None, 42):
            with self.subTest(summary=summary):
                report = json.loads(investigation_json())
                report["ai_investigation"]["incident_summary"] = summary
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

    def test_rejects_empty_or_malformed_observed_evidence(self):
        for evidence in ([], [""], ["  "], ["valid evidence", 42], "evidence"):
            with self.subTest(evidence=evidence):
                report = json.loads(investigation_json())
                report["ai_investigation"]["observed_evidence"] = evidence
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

    def test_rejects_incorrect_field_types_and_malformed_hypotheses(self):
        invalid_values = {
            "incident_summary": ["summary"],
            "observed_evidence": None,
            "root_cause_hypotheses": "not a list",
            "recommended_actions": [],
            "confirmed_root_cause": 7,
        }

        for field, value in invalid_values.items():
            with self.subTest(field=field):
                report = json.loads(investigation_json())
                report["ai_investigation"][field] = value
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

        for hypothesis in (
            "not an object",
            {"hypothesis": "Missing required fields"},
            {
                "hypothesis": "Missing confidence.",
                "supporting_evidence": ["Evidence."],
                "missing_evidence": ["More evidence."],
                "confidence": "certain",
            },
            {
                "hypothesis": "Empty support.",
                "supporting_evidence": [""],
                "missing_evidence": ["More evidence."],
                "confidence": "low",
            },
        ):
            with self.subTest(hypothesis=hypothesis):
                report = json.loads(investigation_json())
                report["ai_investigation"]["root_cause_hypotheses"] = [
                    hypothesis
                ]
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

    def test_rejects_invalid_ai_statuses(self):
        for status in ("failed", "skipped", "complete", "", None):
            with self.subTest(status=status):
                report = json.loads(investigation_json())
                report["ai_investigation"]["status"] = status
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )

    def test_rejects_malformed_json_and_non_object_json(self):
        for raw in ("{not-json", "[]", "null", 42, b"\xff"):
            with self.subTest(raw=raw):
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(raw)
                )

    def test_rejects_incomplete_monitoring_analysis(self):
        for monitoring in (
            {"monitoring_status": "incomplete"},
            {"monitoring_status": "Complete"},
            [],
        ):
            with self.subTest(monitoring=monitoring):
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        investigation_json(monitoring=monitoring)
                    )
                )

    def test_rejects_failed_or_skipped_ai_reports(self):
        for status in ("failed", "skipped"):
            with self.subTest(status=status):
                report = json.loads(investigation_json())
                report["ai_investigation"] = {
                    "status": status,
                    "error": "Investigation unavailable",
                }
                self.assertFalse(
                    incident_main.is_successful_complete_investigation(
                        json.dumps(report)
                    )
                )


if __name__ == "__main__":
    unittest.main()
