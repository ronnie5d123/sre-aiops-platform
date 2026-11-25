from ai_investigator import investigate_incident
import json

test_incident = {
    "alert_name": "HighErrorRate",
    "severity": "critical",
    "availability": 1.0,
    "http_5xx_ratio": 1.0,
    "endpoint_errors": [
        {
            "endpoint": "/simulate-error",
            "http_status": "500",
            "count": 20
        }
    ],
    "findings": [
        "Application is reachable.",
        "/simulate-error is returning HTTP 500.",
        "The application health endpoint remains available."
    ]
}

report = investigate_incident(test_incident)

print("\n========== AI INCIDENT INVESTIGATION ==========\n")
print(json.dumps(report, indent=2))