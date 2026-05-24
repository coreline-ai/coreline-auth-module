from __future__ import annotations

from io import StringIO

from coreline_auth import InMemoryMetricSink, JsonLineSecurityEventSink, PrometheusTextMetricSink


def test_in_memory_and_prometheus_metric_sinks() -> None:
    memory = InMemoryMetricSink()
    prom = PrometheusTextMetricSink()

    memory("auth.rate_limited", {"retry_after_seconds": 10})
    memory("auth.rate_limited", {"retry_after_seconds": 20})
    prom("auth.rate_limited", {})

    assert memory.count("auth.rate_limited") == 2
    assert memory.events[0][1]["retry_after_seconds"] == 10
    assert "coreline_auth_auth_rate_limited_total 1" in prom.render()


def test_jsonline_security_event_sink() -> None:
    out = StringIO()
    sink = JsonLineSecurityEventSink(out)

    sink("auth.login.failed", {"reason": "bad_password"})

    assert '"event": "auth.login.failed"' in out.getvalue()
    assert '"reason": "bad_password"' in out.getvalue()
