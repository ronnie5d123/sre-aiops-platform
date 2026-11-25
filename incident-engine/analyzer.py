
from prometheus_api import (
    get_application_metrics,
    get_endpoint_latency,
    get_endpoint_errors,
    get_endpoint_error_rates,
    get_endpoint_error_ratios
)


# Initial operational thresholds
ERROR_RATIO_WARNING = 0.05
ERROR_RATIO_CRITICAL = 0.20

P95_LATENCY_WARNING = 1.0
P95_LATENCY_CRITICAL = 3.0


def analyze_application():

    metrics = get_application_metrics()

    endpoint_latencies = get_endpoint_latency()

    endpoint_errors = get_endpoint_errors()

    endpoint_error_rates = get_endpoint_error_rates()

    endpoint_error_ratios = get_endpoint_error_ratios()

    worst_error_endpoint = (
        max(endpoint_error_ratios, key=lambda item: item["value"])
        if endpoint_error_ratios
        else None
    )

    slowest_endpoint = (
        max(endpoint_latencies, key=lambda item: item["value"])
        if endpoint_latencies
        else None
    )

    findings = []
    recommendations = []
    severities = []

    availability = metrics.get("availability")
    error_rate = metrics.get("http_5xx_rate")
    error_ratio = metrics.get("http_5xx_ratio")
    p95_latency = metrics.get("p95_latency")

    # 1. Availability analysis
    if availability is None:
        findings.append({
            "category": "availability",
            "severity": "unknown",
            "message": "Application availability metric is unavailable.",
            "evidence": {"availability": None}
        })

        recommendations.append(
            "Check Prometheus connectivity and scrape configuration."
        )

    elif availability == 0:
        findings.append({
            "category": "availability",
            "severity": "critical",
            "message": "Application is unreachable by Prometheus.",
            "evidence": {"availability": availability}
        })

        severities.append("critical")

        recommendations.append(
            "Check application container status, health endpoint and logs."
        )

    else:
        findings.append({
            "category": "availability",
            "severity": "healthy",
            "message": "Application is reachable by Prometheus.",
            "evidence": {"availability": availability}
        })

    # 2. HTTP 5xx error analysis
    if error_rate is None or error_ratio is None:
        findings.append({
            "category": "http_errors",
            "severity": "unknown",
            "message": "HTTP 5xx error metrics are unavailable.",
            "evidence": {
                "http_5xx_rate": error_rate,
                "http_5xx_ratio": error_ratio
            }
        })

    elif error_ratio >= ERROR_RATIO_CRITICAL:
        findings.append({
            "category": "http_errors",
            "severity": "critical",
            "message": "Critical HTTP 5xx error ratio detected.",
            "evidence": {
                "http_5xx_rate": error_rate,
                "http_5xx_ratio": error_ratio,
                "threshold": ERROR_RATIO_CRITICAL
            }
        })

        severities.append("critical")

        recommendations.append(
            "Investigate failing endpoints, application exceptions and dependencies."
        )

    elif error_ratio >= ERROR_RATIO_WARNING:
        findings.append({
            "category": "http_errors",
            "severity": "warning",
            "message": "HTTP 5xx error ratio exceeds the warning threshold.",
            "evidence": {
                "http_5xx_rate": error_rate,
                "http_5xx_ratio": error_ratio,
                "threshold": ERROR_RATIO_WARNING
            }
        })

        severities.append("warning")

        recommendations.append(
            "Inspect application logs and identify endpoints returning server errors."
        )

    else:
        findings.append({
            "category": "http_errors",
            "severity": "healthy",
            "message": "HTTP 5xx error ratio is within the warning threshold.",
            "evidence": {
                "http_5xx_rate": error_rate,
                "http_5xx_ratio": error_ratio
            }
        })

    # 3. Latency analysis
    if p95_latency is None:
        findings.append({
            "category": "latency",
            "severity": "unknown",
            "message": "P95 latency metric is unavailable.",
            "evidence": {"p95_latency": None}
        })

    elif p95_latency >= P95_LATENCY_CRITICAL:
        findings.append({
            "category": "latency",
            "severity": "critical",
            "message": "Critical application latency detected.",
            "evidence": {
                "p95_latency": p95_latency,
                "threshold": P95_LATENCY_CRITICAL
            }
        })

        severities.append("critical")

        recommendations.append(
            "Investigate slow endpoints, database queries and downstream dependencies."
        )

    elif p95_latency >= P95_LATENCY_WARNING:
        findings.append({
            "category": "latency",
            "severity": "warning",
            "message": "P95 latency exceeds the warning threshold.",
            "evidence": {
                "p95_latency": p95_latency,
                "threshold": P95_LATENCY_WARNING
            }
        })

        severities.append("warning")

        recommendations.append(
            "Identify slow endpoints and inspect their response-time distribution."
        )

    else:
        findings.append({
            "category": "latency",
            "severity": "healthy",
            "message": "P95 latency is within the warning threshold.",
            "evidence": {"p95_latency": p95_latency}
        })


    # 4. Endpoint-level diagnosis
    if slowest_endpoint is not None:
        endpoint = slowest_endpoint["endpoint"]
        latency = slowest_endpoint["value"]

        if latency >= P95_LATENCY_CRITICAL:
            endpoint_severity = "critical"
        elif latency >= P95_LATENCY_WARNING:
            endpoint_severity = "warning"
        else:
            endpoint_severity = "healthy"

        findings.append({
            "category": "endpoint_latency",
            "severity": endpoint_severity,
            "message": (
                f"Slowest endpoint is {endpoint} "
                f"with P95 latency of {latency:.3f} seconds."
            ),
            "evidence": {
                "endpoint": endpoint,
                "p95_latency": latency,
                "threshold_warning": P95_LATENCY_WARNING,
                "threshold_critical": P95_LATENCY_CRITICAL
            }
        })

        if endpoint_severity == "critical":
            recommendations.append(
                f"Urgently investigate {endpoint}: "
                "check blocking operations, application logs "
                "and downstream dependencies."
            )

        elif endpoint_severity == "warning":
            recommendations.append(
                f"Investigate {endpoint} for slow processing "
                "and downstream dependency delays."
            )


    # 5. Endpoint-level error diagnosis
    if worst_error_endpoint is not None:
        endpoint = worst_error_endpoint["endpoint"]
        error_ratio = worst_error_endpoint["value"]

        if error_ratio >= ERROR_RATIO_CRITICAL:
            endpoint_severity = "critical"
        elif error_ratio >= ERROR_RATIO_WARNING:
            endpoint_severity = "warning"
        else:
            endpoint_severity = "healthy"

        findings.append({
            "category": "endpoint_errors",
            "severity": endpoint_severity,
            "message": (
                f"Endpoint {endpoint} has a recent "
                f"HTTP 5xx error ratio of {error_ratio:.2%}."
            ),
            "evidence": {
                "endpoint": endpoint,
                "error_ratio": error_ratio,
                "threshold_warning": ERROR_RATIO_WARNING,
                "threshold_critical": ERROR_RATIO_CRITICAL
            }
        })

        if endpoint_severity == "critical":
            recommendations.append(
                f"Urgently investigate {endpoint}: "
                "inspect application logs, exceptions "
                "and downstream dependencies."
            )

        elif endpoint_severity == "warning":
            recommendations.append(
                f"Investigate elevated HTTP 5xx errors "
                f"on {endpoint}."
            )

    # 6. Determine overall severity
    severity_priority = {
    "healthy": 0,
    "warning": 1,
    "critical": 2
    }

    unknown_findings = [
        finding["category"]
        for finding in findings
        if finding["severity"] == "unknown"
    ]

    all_severities = severities + [
        finding["severity"]
        for finding in findings
        if finding["severity"] in severity_priority
    ]

    if "critical" in all_severities:
        overall_severity = "critical"
    elif "warning" in all_severities:
        overall_severity = "warning"
    elif unknown_findings:
        overall_severity = "unknown"
    elif "healthy" in all_severities:
        overall_severity = "healthy"
    else:
        overall_severity = "unknown"

    monitoring_status = (
        "incomplete" if unknown_findings else "complete"
    )


    return {
    "overall_severity": overall_severity,
    "metrics": metrics,
    "endpoint_latencies": endpoint_latencies,
    "slowest_endpoint": slowest_endpoint,
    "endpoint_errors": endpoint_errors,
    "endpoint_error_rates": endpoint_error_rates,
    "monitoring_status": monitoring_status,
    "unknown_findings": unknown_findings,
    "findings": findings,
    "recommendations": recommendations
}
