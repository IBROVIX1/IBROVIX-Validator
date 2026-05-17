"""Config filtering engine.

Supports filtering by:
  - Protocol type (vmess, vless, trojan, ssh)
  - Alive/dead status
  - Minimum/maximum latency
  - Country/region (from geolocation)
  - Name regex
  - Transport type (tcp, ws, grpc, etc.)
  - TLS mode
  - Format validity
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class FilterRule:
    """A single filter rule definition."""
    field: str
    op: str           # eq, neq, gt, lt, gte, lte, in, regex, exists
    value: object
    label: str = ""


class FilterEngine:
    """Chainable filter engine for proxy config lists."""

    def __init__(self, configs: list[dict]):
        self.configs = list(configs)
        self._rules: list[FilterRule] = []
        self._sort_key: Optional[str] = None
        self._sort_ascending: bool = True

    def clone(self) -> "FilterEngine":
        """Create a copy with same configs but empty rules."""
        return FilterEngine(list(self.configs))

    def by_protocol(self, *protocols: str) -> "FilterEngine":
        """Filter to specific protocol types."""
        self._rules.append(FilterRule("type", "in", list(protocols)))
        return self

    def alive(self, alive: bool = True) -> "FilterEngine":
        """Filter by alive status."""
        self._rules.append(FilterRule("alive", "eq", alive))
        return self

    def valid_format(self, valid: bool = True) -> "FilterEngine":
        """Filter by format validity."""
        self._rules.append(FilterRule("format_valid", "eq", valid))
        return self

    def min_latency(self, ms: float) -> "FilterEngine":
        """Filter configs with latency >= ms."""
        self._rules.append(FilterRule("latency_ms", "gte", ms))
        return self

    def max_latency(self, ms: float) -> "FilterEngine":
        """Filter configs with latency <= ms."""
        self._rules.append(FilterRule("latency_ms", "lte", ms))
        return self

    def latency_between(self, lo: float, hi: float) -> "FilterEngine":
        """Filter configs with latency in [lo, hi] ms."""
        self.min_latency(lo)
        self.max_latency(hi)
        return self

    def name_contains(self, substring: str) -> "FilterEngine":
        """Filter by name containing a substring."""
        self._rules.append(FilterRule("name", "regex", re.escape(substring)))
        return self

    def name_matches(self, pattern: str) -> "FilterEngine":
        """Filter by name regex pattern."""
        self._rules.append(FilterRule("name", "regex", pattern))
        return self

    def by_transport(self, *transports: str) -> "FilterEngine":
        """Filter by transport type (tcp, ws, grpc, etc.)."""
        self._rules.append(FilterRule("net", "in", list(transports)))
        return self

    def by_tls(self, tls_mode: str) -> "FilterEngine":
        """Filter by TLS mode (tls, none, reality)."""
        self._rules.append(FilterRule("tls", "eq", tls_mode))
        return self

    def by_host(self, host: str) -> "FilterEngine":
        """Filter by host containing a substring."""
        self._rules.append(FilterRule("host", "regex", re.escape(host)))
        return self

    def by_port(self, port: int) -> "FilterEngine":
        """Filter by exact port."""
        self._rules.append(FilterRule("port", "eq", port))
        return self

    def with_error(self) -> "FilterEngine":
        """Filter configs that have errors."""
        self._rules.append(FilterRule("error", "exists", True))
        self._rules.append(FilterRule("error", "neq", None))
        return self

    def without_error(self) -> "FilterEngine":
        """Filter configs without errors."""
        self._rules.append(FilterRule("error", "exists", False))
        return self

    def with_handshake_error(self) -> "FilterEngine":
        """Filter configs that failed handshake."""
        self._rules.append(FilterRule("handshake_error", "exists", True))
        return self

    def sort_by(self, field: str, ascending: bool = True) -> "FilterEngine":
        """Sort results by a given field."""
        self._sort_key = field
        self._sort_ascending = ascending
        return self

    def sort_by_latency(self, ascending: bool = True) -> "FilterEngine":
        """Sort results by latency (ascending = fastest first)."""
        self._sort_key = "latency_ms"
        self._sort_ascending = ascending
        return self

    def custom(self, field: str, op: str, value: object, label: str = "") -> "FilterEngine":
        """Add a custom filter rule."""
        self._rules.append(FilterRule(field, op, value, label))
        return self

    def apply(self) -> list[dict]:
        """Execute all rules and return filtered (and optionally sorted) configs."""
        if not self._rules:
            results = list(self.configs)
        else:
            results = []
            for cfg in self.configs:
                if self._matches_all(cfg):
                    results.append(cfg)

        if self._sort_key:
            multiplier = 1 if self._sort_ascending else -1
            results.sort(
                key=lambda c: (
                    c.get(self._sort_key) is None,  # Nones always last regardless of direction
                    (c.get(self._sort_key) or 0) * multiplier,
                ),
            )
        return results

    def _matches_all(self, cfg: dict) -> bool:
        """Check if a config matches all active rules."""
        for rule in self._rules:
            if not self._evaluate(rule, cfg):
                return False
        return True

    def _evaluate(self, rule: FilterRule, cfg: dict) -> bool:
        """Evaluate a single rule against a config."""
        val = cfg.get(rule.field)

        if rule.op == "eq":
            return val == rule.value
        elif rule.op == "neq":
            return val != rule.value
        elif rule.op == "gt":
            try:
                return float(val) > float(rule.value) if val is not None else False
            except (TypeError, ValueError):
                return False
        elif rule.op == "gte":
            try:
                return float(val) >= float(rule.value) if val is not None else False
            except (TypeError, ValueError):
                return False
        elif rule.op == "lt":
            try:
                return float(val) < float(rule.value) if val is not None else False
            except (TypeError, ValueError):
                return False
        elif rule.op == "lte":
            try:
                return float(val) <= float(rule.value) if val is not None else False
            except (TypeError, ValueError):
                return False
        elif rule.op == "in":
            return val in rule.value if isinstance(rule.value, (list, tuple, set)) else val == rule.value
        elif rule.op == "regex":
            try:
                return bool(re.search(str(rule.value), str(val or "")))
            except re.error:
                return False
        elif rule.op == "exists":
            # exists=True means "field exists in config"
            # exists=False means "field does NOT exist in config"
            if isinstance(rule.value, bool):
                if rule.value is True:
                    return rule.field in cfg
                else:
                    return rule.field not in cfg
            return rule.value in cfg
        else:
            return True

    def count(self) -> int:
        """Return count of matching configs."""
        return len(self.apply())

    def stats(self) -> dict:
        """Return aggregate statistics on current (unfiltered) configs."""
        total = len(self.configs)
        by_type: dict[str, int] = {}
        alive = 0
        dead = 0
        latencies = []

        for cfg in self.configs:
            ptype = cfg.get("type", "unknown")
            by_type[ptype] = by_type.get(ptype, 0) + 1

            if cfg.get("alive") is True:
                alive += 1
            elif cfg.get("alive") is False:
                dead += 1

            lat = cfg.get("latency_ms")
            if lat is not None:
                latencies.append(lat)

        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        min_lat = min(latencies) if latencies else 0
        max_lat = max(latencies) if latencies else 0

        return {
            "total": total,
            "by_type": by_type,
            "alive": alive,
            "dead": dead,
            "untested": total - alive - dead,
            "avg_latency_ms": round(avg_lat, 1),
            "min_latency_ms": round(min_lat, 1),
            "max_latency_ms": round(max_lat, 1),
        }
