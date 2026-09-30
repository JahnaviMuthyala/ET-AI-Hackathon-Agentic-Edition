"""Structured logging and in-memory metrics.

Good enough for a hackathon demo and a real starting point: every
request's full trace is logged as one JSON line (pipe into any log
aggregator), and simple counters back the /metrics endpoint so you can
show per-attack-type detection counts live during your demo.
"""
import json
import logging
import sys
from collections import Counter
from threading import Lock

logger = logging.getLogger("firewall")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)

_lock = Lock()
_counts_by_type: Counter = Counter()
_counts_by_verdict: Counter = Counter()
_total_requests = 0


def log_trace(trace_id: str, content_preview: str, response) -> None:
    """Log one structured JSON line per request and update counters."""
    global _total_requests
    with _lock:
        _total_requests += 1
        _counts_by_type[response.attack_type] += 1
        _counts_by_verdict[response.verdict] += 1

    logger.info(json.dumps({
        "trace_id": trace_id,
        "content_preview": content_preview[:120],
        "verdict": response.verdict,
        "action": response.action,
        "attack_type": response.attack_type,
        "confidence": response.confidence,
        "total_latency_ms": response.total_latency_ms,
        "layers": [
            {"layer": l.layer, "ran": l.ran, "attack_type": l.attack_type,
             "confidence": l.confidence, "latency_ms": l.latency_ms}
            for l in response.layers
        ],
    }))


def get_metrics() -> dict:
    with _lock:
        return {
            "total_requests": _total_requests,
            "by_attack_type": dict(_counts_by_type),
            "by_verdict": dict(_counts_by_verdict),
        }
