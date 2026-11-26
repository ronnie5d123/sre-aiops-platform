import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ai_investigator import MODEL, OLLAMA_URL, investigate_incident


INCIDENT = {
    "alert_name": "HighErrorRate",
    "severity": "critical",
    "availability": 1.0,
    "http_5xx_ratio": 1.0,
    "endpoint_errors": [
        {
            "endpoint": "/simulate-error",
            "http_status": "500",
            "count": 20,
        }
    ],
    "findings": [
        "Application is reachable.",
        "/simulate-error is returning HTTP 500.",
        "The application health endpoint remains available.",
    ],
}

VALID_REPORT = {
    "incident_summary": "Elevated HTTP 500 responses.",
    "observed_evidence": ["/simulate-error returned HTTP 500."],
    "root_cause_hypotheses": [
        {
            "hypothesis": "The endpoint is failing.",
            "supporting_evidence": ["/simulate-error returned HTTP 500."],
            "missing_evidence": ["Application logs"],
            "confidence": "low",
        }
    ],
    "recommended_actions": ["Inspect application logs."],
    "confirmed_root_cause": None,
}


def test_investigate_incident_parses_successful_ollama_response():
    response = MagicMock()
    response.json.return_value = {
        "message": {"content": json.dumps(VALID_REPORT)}
    }

    with patch("ai_investigator.requests.post", return_value=response) as post:
        report = investigate_incident(INCIDENT)

    assert report == VALID_REPORT
    response.raise_for_status.assert_called_once_with()
    post.assert_called_once()
    args, kwargs = post.call_args
    assert args == (OLLAMA_URL,)
    assert kwargs["timeout"] == 180
    assert kwargs["json"]["model"] == MODEL
    assert kwargs["json"]["stream"] is False
    assert kwargs["json"]["format"] == "json"


def test_investigate_incident_propagates_http_failure():
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError("server error")

    with patch("ai_investigator.requests.post", return_value=response):
        with pytest.raises(requests.HTTPError, match="server error"):
            investigate_incident(INCIDENT)

    response.json.assert_not_called()


def test_investigate_incident_propagates_network_failure():
    with patch(
        "ai_investigator.requests.post",
        side_effect=requests.ConnectionError("connection failed"),
    ) as post:
        with pytest.raises(requests.ConnectionError, match="connection failed"):
            investigate_incident(INCIDENT)

    post.assert_called_once()


def run_ollama_integration_check():
    report = investigate_incident(INCIDENT)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    run_ollama_integration_check()
