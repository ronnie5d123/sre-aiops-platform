
import asyncio
import time

from fastapi import FastAPI, HTTPException, Query, Request, Response
from prometheus_client import (
    Counter,
    Histogram,
    CONTENT_TYPE_LATEST,
    generate_latest,
)

app = FastAPI(
    title="SRE AIOps Platform",
    description="A monitored application for SRE and AIOps experiments",
    version="1.0.0",
)

# Total HTTP requests, grouped by method, endpoint and status
REQUEST_COUNT = Counter(
    "app_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "http_status"],
)

# Request processing duration
REQUEST_LATENCY = Histogram(
    "app_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)


@app.middleware("http")
async def collect_metrics(request: Request, call_next):
    start_time = time.perf_counter()

    response = await call_next(request)

    duration = time.perf_counter() - start_time

    # Use the registered route pattern rather than arbitrary URL paths
    route = request.scope.get("route")
    endpoint = route.path if route else "unmatched"

    # Avoid counting Prometheus scraping its own metrics endpoint
    if endpoint != "/metrics":
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=endpoint,
            http_status=str(response.status_code),
        ).inc()

        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=endpoint,
        ).observe(duration)

    return response


@app.get("/")
async def root():
    return {
        "application": "SRE AIOps Platform",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/simulate-error")
async def simulate_error():
    raise HTTPException(
        status_code=500,
        detail="Intentional internal server error for testing",
    )


@app.get("/simulate-delay")
async def simulate_delay(
    seconds: float = Query(default=2, ge=0, le=10)
):
    await asyncio.sleep(seconds)

    return {
        "message": "Artificial delay completed",
        "delay_seconds": seconds,
    }


@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
