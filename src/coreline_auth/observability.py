"""Small observability sinks for host applications.

Coreline Auth stays exporter-neutral: production hosts can forward metrics or
security events to Prometheus/Grafana/SIEM by wiring these sinks or by adapting
this simple callable protocol.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from threading import RLock
from typing import Protocol, TextIO


class MetricSink(Protocol):
    def __call__(self, name: str, values: dict[str, object]) -> None: ...


class InMemoryMetricSink:
    """Thread-safe in-process metric sink for tests and embedded demos."""

    def __init__(self) -> None:
        self._lock = RLock()
        self.counters: Counter[str] = Counter()
        self.events: list[tuple[str, dict[str, object]]] = []

    def __call__(self, name: str, values: dict[str, object]) -> None:
        with self._lock:
            self.counters[name] += 1
            self.events.append((name, dict(values)))

    def count(self, name: str) -> int:
        with self._lock:
            return self.counters[name]


class LoggingMetricSink:
    """Metric sink that writes structured records to Python logging."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("coreline_auth.metrics")

    def __call__(self, name: str, values: dict[str, object]) -> None:
        self.logger.info("coreline_auth.metric", extra={"metric": name, "values": dict(values)})


class PrometheusTextMetricSink:
    """Minimal counter-only Prometheus text exporter.

    It intentionally avoids external dependencies. Host apps can expose
    `render()` from their own `/metrics` endpoint.
    """

    def __init__(self, *, prefix: str = "coreline_auth") -> None:
        self.prefix = prefix.rstrip("_")
        self._lock = RLock()
        self._counters: Counter[str] = Counter()

    def __call__(self, name: str, values: dict[str, object]) -> None:
        metric_name = self._normalize_name(name)
        with self._lock:
            self._counters[metric_name] += 1

    def render(self) -> str:
        with self._lock:
            items = sorted(self._counters.items())
        lines: list[str] = []
        for name, value in items:
            lines.append(f"# TYPE {name}_total counter")
            lines.append(f"{name}_total {value}")
        return "\n".join(lines) + ("\n" if lines else "")

    def _normalize_name(self, name: str) -> str:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name.lower()).strip("_")
        return f"{self.prefix}_{safe}"


class JsonLineSecurityEventSink:
    """Append-only JSONL sink suitable for SIEM/log-forwarder ingestion."""

    def __init__(self, path_or_file: str | Path | TextIO) -> None:
        self._lock = RLock()
        self._owns_file = not hasattr(path_or_file, "write")
        self._file: TextIO
        if self._owns_file:
            path = Path(path_or_file)  # type: ignore[arg-type]
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = path.open("a", encoding="utf-8")
        else:
            self._file = path_or_file  # type: ignore[assignment]

    def __call__(self, name: str, values: dict[str, object]) -> None:
        record = {"event": name, "values": dict(values)}
        with self._lock:
            self._file.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            self._file.flush()

    def close(self) -> None:
        if self._owns_file:
            with self._lock:
                self._file.close()
