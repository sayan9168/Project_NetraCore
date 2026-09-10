"""
Lightweight in-process metrics registry with Prometheus exposition.

Zero dependencies — safe to import anywhere. For clustered deployments
scrape each replica; REDIS-backed aggregation is intentionally out of scope.
"""

import threading
from collections import Counter, defaultdict


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.cases_total = 0
        self.findings_total = Counter()  # severity -> count
        self.module_runs = Counter()  # module -> runs
        self.module_failures = Counter()  # module -> failures
        self.module_duration_sum = defaultdict(float)
        self.http_requests = Counter()  # (method, route, status_class) -> count
        self.http_duration_sum = defaultdict(float)
        self.api_errors = 0
        self.auth_failures = 0
        self.ws_connections = 0
        self.soc_alerts_sent = 0

    # ── recorders ─────────────────────────────────────────────────────────
    def case_completed(self, findings_by_severity: dict) -> None:
        with self._lock:
            self.cases_total += 1
            for severity, count in findings_by_severity.items():
                self.findings_total[severity] += count

    def module_run(self, module: str, duration_s: float, failed: bool = False) -> None:
        with self._lock:
            self.module_runs[module] += 1
            self.module_duration_sum[module] += duration_s
            if failed:
                self.module_failures[module] += 1

    def observe_http(self, method: str, path: str, status: int, duration_s: float) -> None:
        route = self._normalize_route(path)
        key = (method.upper(), route, f"{status // 100}xx")
        with self._lock:
            self.http_requests[key] += 1
            self.http_duration_sum[key] += duration_s
            if status >= 500:
                self.api_errors += 1

    def auth_failure(self) -> None:
        with self._lock:
            self.auth_failures += 1

    def ws_connect(self, delta: int = 1) -> None:
        with self._lock:
            self.ws_connections = max(0, self.ws_connections + delta)

    def soc_alert(self, count: int = 1) -> None:
        with self._lock:
            self.soc_alerts_sent += count

    @staticmethod
    def _normalize_route(path: str) -> str:
        """Collapse high-cardinality path segments so series stay bounded."""
        parts = [p for p in path.split("/") if p]
        out = []
        for part in parts:
            if len(part) > 24 or (any(c.isdigit() for c in part) and "-" in part):
                out.append("{id}")
            else:
                out.append(part)
        return "/" + "/".join(out) if out else "/"

    # ── exposition ────────────────────────────────────────────────────────
    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP netra_cases_total Total forensic cases executed",
                "# TYPE netra_cases_total counter",
                f"netra_cases_total {self.cases_total}",
                "# HELP netra_findings_total Findings by severity",
                "# TYPE netra_findings_total counter",
            ]
            for severity, count in sorted(self.findings_total.items()):
                lines.append(f'netra_findings_total{{severity="{severity}"}} {count}')
            lines += [
                "# HELP netra_module_runs_total Module executions",
                "# TYPE netra_module_runs_total counter",
            ]
            for module, count in sorted(self.module_runs.items()):
                lines.append(f'netra_module_runs_total{{module="{module}"}} {count}')
            lines += [
                "# HELP netra_module_failures_total Module failures",
                "# TYPE netra_module_failures_total counter",
            ]
            for module, count in sorted(self.module_failures.items()):
                lines.append(f'netra_module_failures_total{{module="{module}"}} {count}')
            lines += [
                "# HELP netra_http_requests_total HTTP requests",
                "# TYPE netra_http_requests_total counter",
            ]
            for (method, route, status), count in sorted(self.http_requests.items()):
                lines.append(
                    f'netra_http_requests_total{{method="{method}",route="{route}",'
                    f'status="{status}"}} {count}'
                )
            lines += [
                "# HELP netra_api_errors_total HTTP 5xx responses",
                "# TYPE netra_api_errors_total counter",
                f"netra_api_errors_total {self.api_errors}",
                "# HELP netra_auth_failures_total Authentication failures",
                "# TYPE netra_auth_failures_total counter",
                f"netra_auth_failures_total {self.auth_failures}",
                "# HELP netra_ws_connections Active SOC websocket connections",
                "# TYPE netra_ws_connections gauge",
                f"netra_ws_connections {self.ws_connections}",
                "# HELP netra_soc_alerts_sent_total SOC alerts broadcast",
                "# TYPE netra_soc_alerts_sent_total counter",
                f"netra_soc_alerts_sent_total {self.soc_alerts_sent}",
            ]
            return "\n".join(lines) + "\n"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "cases_total": self.cases_total,
                "findings_by_severity": dict(self.findings_total),
                "module_runs": dict(self.module_runs),
                "module_failures": dict(self.module_failures),
                "api_errors": self.api_errors,
                "auth_failures": self.auth_failures,
                "ws_connections": self.ws_connections,
                "soc_alerts_sent": self.soc_alerts_sent,
            }


metrics = MetricsRegistry()
