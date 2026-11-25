
import json
import requests

OLLAMA_URL = "http://host.docker.internal:11434/api/chat"
MODEL = "qwen2.5:3b"


def investigate_incident(incident_data: dict) -> dict:

    system_prompt = """
You are an experienced Site Reliability Engineer investigating incidents.

Analyze only the evidence provided.

Rules:
1. Never invent metrics, logs, services, or dependencies.
2. Separate confirmed evidence from possible explanations.
3. Do not claim a root cause unless the evidence proves it.
4. If information is missing, explicitly identify it.
5. A hypothesis must include supporting evidence and missing evidence.
6. Use low, medium, or high confidence for each hypothesis.
7. Set confirmed_root_cause to null unless the evidence is conclusive.
8. Return valid JSON only. Do not include Markdown or extra text.
9. Never confuse the location of a failure with its underlying root cause.
   An endpoint returning HTTP 500 identifies where errors occur, not why.
"""

    user_prompt = f"""
Investigate this incident:

{json.dumps(incident_data, indent=2)}

Return exactly this JSON structure:

{{
  "incident_summary": "Short incident summary",
  "observed_evidence": [
    "Evidence directly supported by the input"
  ],
  "root_cause_hypotheses": [
    {{
      "hypothesis": "Possible explanation",
      "supporting_evidence": ["Evidence supporting it"],
      "missing_evidence": ["Evidence still needed"],
      "confidence": "low"
    }}
  ],
  "recommended_actions": [
    "Prioritized investigation step"
  ],
  "confirmed_root_cause": null
}}
"""

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "format": "json",
        "stream": False
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=180
    )

    response.raise_for_status()

    result = response.json()
    content = result["message"]["content"]

    try:
        report = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"AI returned invalid JSON: {content}"
        ) from error

    required_fields = {
        "incident_summary",
        "observed_evidence",
        "root_cause_hypotheses",
        "recommended_actions",
        "confirmed_root_cause"
    }

    if not required_fields.issubset(report):
        raise ValueError("AI report is missing required fields")

    return report
