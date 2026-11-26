import sys
import unittest
from pathlib import Path


INCIDENT_ENGINE_DIR = Path(__file__).resolve().parents[1] / "incident-engine"
sys.path.insert(0, str(INCIDENT_ENGINE_DIR))

from remediation import (  # noqa: E402
    RemediationSimulator,
    SUPPORTED_ACTION_KEYS,
    validate_action_parameters,
)


class RemediationParameterValidationTests(unittest.TestCase):
    def test_supported_action_keys(self):
        self.assertEqual(
            SUPPORTED_ACTION_KEYS,
            {
                "restart_application",
                "scale_application",
                "clear_application_cache",
            },
        )

    def test_actions_that_need_no_parameters_accept_empty_objects(self):
        self.assertEqual(
            validate_action_parameters("restart_application", {}),
            {},
        )
        self.assertEqual(
            validate_action_parameters("clear_application_cache", {}),
            {},
        )

    def test_scale_application_accepts_replica_limits(self):
        self.assertEqual(
            validate_action_parameters("scale_application", {"replicas": 1}),
            {"replicas": 1},
        )
        self.assertEqual(
            validate_action_parameters("scale_application", {"replicas": 5}),
            {"replicas": 5},
        )

    def test_scale_application_requires_replicas(self):
        with self.assertRaisesRegex(ValueError, "requires a replicas"):
            validate_action_parameters("scale_application", {})

    def test_actions_reject_unexpected_parameters(self):
        for action_key in (
            "restart_application",
            "clear_application_cache",
        ):
            with self.subTest(action_key=action_key):
                with self.assertRaisesRegex(ValueError, "does not accept"):
                    validate_action_parameters(action_key, {"extra": True})

        with self.assertRaisesRegex(ValueError, "unexpected parameters"):
            validate_action_parameters(
                "scale_application",
                {"replicas": 2, "extra": True},
            )

    def test_scale_application_rejects_non_integer_values(self):
        for replicas in (True, False, 2.0, "2"):
            with self.subTest(replicas=replicas):
                with self.assertRaisesRegex(ValueError, "must be an integer"):
                    validate_action_parameters(
                        "scale_application",
                        {"replicas": replicas},
                    )

    def test_scale_application_rejects_out_of_range_values(self):
        for replicas in (0, 6, -1):
            with self.subTest(replicas=replicas):
                with self.assertRaisesRegex(ValueError, "between 1 and 5"):
                    validate_action_parameters(
                        "scale_application",
                        {"replicas": replicas},
                    )

    def test_unknown_action_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported remediation action"):
            validate_action_parameters("run_shell_command", {})

    def test_parameters_must_be_an_object(self):
        for parameters in (None, [], "{}", 1):
            with self.subTest(parameters=parameters):
                with self.assertRaisesRegex(ValueError, "must be an object"):
                    validate_action_parameters("restart_application", parameters)


class RemediationSimulatorTests(unittest.TestCase):
    def setUp(self):
        self.simulator = RemediationSimulator()

    def test_each_action_returns_a_simulated_result(self):
        actions = (
            ("restart_application", {}),
            ("scale_application", {"replicas": 3}),
            ("clear_application_cache", {}),
        )

        for action_key, parameters in actions:
            with self.subTest(action_key=action_key):
                result = self.simulator.simulate(action_key, parameters)

                self.assertEqual(result["action_key"], action_key)
                self.assertEqual(result["status"], "simulated")
                self.assertIs(result["simulated"], True)
                self.assertIs(result["real_infrastructure_modified"], False)
                self.assertEqual(result["details"]["target"], "application")
                self.assertEqual(result["details"]["effect"], "simulated_only")

    def test_scale_result_reports_requested_replica_count(self):
        result = self.simulator.simulate(
            "scale_application",
            {"replicas": 4},
        )

        self.assertEqual(result["details"]["requested_replicas"], 4)

    def test_simulator_rejects_invalid_action_parameters(self):
        with self.assertRaises(ValueError):
            self.simulator.simulate("scale_application", {"replicas": True})


if __name__ == "__main__":
    unittest.main()
