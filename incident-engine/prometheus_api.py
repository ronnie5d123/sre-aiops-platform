
import requests
import math
import os

PROMETHEUS_URL = os.getenv(
    "PROMETHEUS_URL",
    "http://localhost:9090"
)


def query_prometheus(query: str):
    """
    Execute an instant PromQL query against Prometheus.
    Returns a finite float or None when no usable result is available.
    """

    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5
        )

        response.raise_for_status()
        result = response.json()

        if result.get("status") != "success":
            return None

        data = result.get("data", {}).get("result", [])

        if not data:
            return None

        value = float(data[0]["value"][1])

        if not math.isfinite(value):
            return None

        return value

    except requests.RequestException as error:
        print(f"Prometheus connection error: {error}")
        return None

    except (KeyError, IndexError, TypeError, ValueError) as error:
        print(f"Prometheus response error: {error}")
        return None


def query_prometheus_vector(query: str):
    """
    Execute an instant PromQL query and return all result series,
    preserving their metric labels.
    """

    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5
        )

        response.raise_for_status()
        result = response.json()

        if result.get("status") != "success":
            return []

        data = result.get("data", {}).get("result", [])

        results = []

        for item in data:
            labels = item.get("metric", {})

            try:
                value = float(item["value"][1])
            except (KeyError, IndexError, TypeError, ValueError):
                continue

            if not math.isfinite(value):
                continue

            results.append({
                **labels,
                "value": value
            })

        return results

    except requests.RequestException as error:
        print(f"Prometheus connection error: {error}")
        return []


def get_application_metrics():

    queries = {
        "availability": 'min(up{job="fastapi"})',

        "http_500_rate": (
            'sum(rate(app_requests_total'
            '{http_status="500"}[5m]))'
        ),

        "http_5xx_rate": (
            'sum(rate(app_requests_total'
            '{http_status=~"5.."}[5m]))'
        ),

        "http_5xx_ratio": (
            'sum(rate(app_requests_total'
            '{http_status=~"5.."}[5m]))'
            ' / '
            'clamp_min(sum(rate(app_requests_total[5m])), 0.001)'
        ),

        "p95_latency": (
            'histogram_quantile(0.95, '
            'sum by (le) ('
            'rate(app_request_duration_seconds_bucket[5m])'
            '))'
        )
    }

    metrics = {}

    for metric_name, promql in queries.items():
        metrics[metric_name] = query_prometheus(promql)

    return metrics


def get_endpoint_latency():

    query = (
        'histogram_quantile(0.95, '
        'sum by (endpoint, le) ('
        'rate(app_request_duration_seconds_bucket[5m])'
        '))'
    )

    return query_prometheus_vector(query)


def get_endpoint_errors():

    query = (
        'sum by (endpoint, http_status) '
        '(app_requests_total{http_status=~"5.."})'
    )

    return query_prometheus_vector(query)


def get_endpoint_error_rates():

    query = (
        'sum by (endpoint, http_status) '
        '(rate(app_requests_total{http_status=~"5.."}[5m]))'
    )

    return query_prometheus_vector(query)

def get_endpoint_error_ratios():

    query = (
        'sum by (endpoint) '
        '(rate(app_requests_total{http_status=~"5.."}[5m]))'
        ' / '
        'clamp_min('
        'sum by (endpoint) (rate(app_requests_total[5m])), '
        '0.001'
        ')'
    )

    return query_prometheus_vector(query)
