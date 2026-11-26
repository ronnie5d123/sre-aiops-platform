SUPPORTED_ACTION_KEYS = frozenset(
    {
        "restart_application",
        "scale_application",
        "clear_application_cache",
    }
)

_EMPTY_PARAMETER_ACTIONS = {
    "restart_application",
    "clear_application_cache",
}


def validate_action_parameters(action_key, parameters):
    if not isinstance(action_key, str) or action_key not in SUPPORTED_ACTION_KEYS:
        raise ValueError(f"Unsupported remediation action: {action_key!r}")

    if not isinstance(parameters, dict):
        raise ValueError("Action parameters must be an object")

    if action_key in _EMPTY_PARAMETER_ACTIONS:
        if parameters:
            raise ValueError(f"{action_key} does not accept parameters")
        return {}

    unexpected_parameters = set(parameters) - {"replicas"}
    if unexpected_parameters:
        raise ValueError(
            "scale_application received unexpected parameters: "
            f"{sorted(unexpected_parameters, key=repr)!r}"
        )

    if "replicas" not in parameters:
        raise ValueError("scale_application requires a replicas parameter")

    replicas = parameters["replicas"]
    if type(replicas) is not int:
        raise ValueError("replicas must be an integer")
    if not 1 <= replicas <= 5:
        raise ValueError("replicas must be between 1 and 5")

    return {"replicas": replicas}


class RemediationSimulator:
    """Return simulated outcomes without performing external side effects."""

    def simulate(self, action_key, parameters):
        validated_parameters = validate_action_parameters(
            action_key,
            parameters,
        )

        details = {
            "target": "application",
            "effect": "simulated_only",
        }
        if action_key == "scale_application":
            details["requested_replicas"] = validated_parameters["replicas"]

        return {
            "action_key": action_key,
            "status": "simulated",
            "simulated": True,
            "real_infrastructure_modified": False,
            "details": details,
        }

    def simulate_with_state(
        self,
        connection,
        action_key,
        parameters,
        updated_at,
    ):
        validated_parameters = validate_action_parameters(
            action_key,
            parameters,
        )

        if action_key == "restart_application":
            state_key = "restart_count"
            initial_value = 0
        elif action_key == "scale_application":
            state_key = "replica_count"
            initial_value = 1
        else:
            state_key = "cache_generation"
            initial_value = 0

        state_row = connection.execute(
            """
            SELECT state_value
            FROM simulator_state
            WHERE state_key = ?
            """,
            (state_key,),
        ).fetchone()
        previous_value = (
            int(state_row["state_value"])
            if state_row is not None
            else initial_value
        )

        if action_key == "restart_application":
            state_value = previous_value + 1
        elif action_key == "scale_application":
            state_value = validated_parameters["replicas"]
        else:
            state_value = previous_value + 1

        connection.execute(
            """
            INSERT INTO simulator_state (state_key, state_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(state_key) DO UPDATE SET
                state_value = excluded.state_value,
                updated_at = excluded.updated_at
            """,
            (state_key, str(state_value), updated_at),
        )

        result = self.simulate(action_key, validated_parameters)
        result["details"].update(
            {
                "state_key": state_key,
                "previous_value": previous_value,
                "current_value": state_value,
            }
        )
        return result
