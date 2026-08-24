"""
Production Observability Layer.
Exports traces to Jaeger/OTLP, metrics to Prometheus, logs structured JSON.
"""
import logging
import json
import time
from functools import wraps
from contextlib import asynccontextmanager
from typing import Callable

try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class StructuredLogger:
    """JSON structured logger for ELK/Loki ingestion."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def _emit(self, level: str, event: str, **kwargs):
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "level": level,
            "event": event,
            "service": "netra-core",
            **kwargs
        }
        getattr(self.logger, level.lower())(json.dumps(record))

    def info(self, event: str, **kwargs): self._emit("INFO", event, **kwargs)
    def warning(self, event: str, **kwargs): self._emit("WARNING", event, **kwargs)
    def error(self, event: str, **kwargs): self._emit("ERROR", event, **kwargs)
    def critical(self, event: str, **kwargs): self._emit("CRITICAL", event, **kwargs)


def setup_observability(app=None, otlp_endpoint: str = None):
    """Initialize OpenTelemetry tracing + metrics."""
    logger = StructuredLogger("netra.otel")

    if not OTEL_AVAILABLE:
        logger.warning("otel_not_installed", hint="pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp")
        return

    # Tracing
    provider = TracerProvider()
    if otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    else:
        exporter = ConsoleSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Metrics
    if otlp_endpoint:
        metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint)
    else:
        metric_exporter = ConsoleMetricExporter()
    reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=15000)
    metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))

    if app is not None:
        FastAPIInstrumentor.instrument_app(app)

    logger.info("otel_initialized", otlp_endpoint=otlp_endpoint or "console")


# Tracing decorator
def traced(name: str = None):
    def decorator(fn: Callable):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            if not OTEL_AVAILABLE:
                return await fn(*args, **kwargs)
            tracer = trace.get_tracer("netra")
            span_name = name or fn.__name__
            with tracer.start_as_current_span(span_name) as span:
                span.set_attribute("function.name", fn.__name__)
                try:
                    result = await fn(*args, **kwargs)
                    span.set_status(trace.StatusCode.OK)
                    return result
                except Exception as e:
                    span.set_status(trace.StatusCode.ERROR, str(e))
                    span.record_exception(e)
                    raise
        return wrapper
    return decorator


# Metric counters (singleton-style)
class Metrics:
    def __init__(self):
        if OTEL_AVAILABLE:
            meter = metrics.get_meter("netra.metrics")
            self.cases_total = meter.create_counter("netra.cases.total")
            self.findings_total = meter.create_counter("netra.findings.total")
            self.module_duration = meter.create_histogram("netra.module.duration_seconds")
            self.api_errors = meter.create_counter("netra.api.errors")
        else:
            self.cases_total = self.findings_total = self.api_errors = _Noop()
            self.module_duration = _Noop()


class _Noop:
    def add(self, *a, **k): pass
    def record(self, *a, **k): pass


metrics_instance = Metrics()
