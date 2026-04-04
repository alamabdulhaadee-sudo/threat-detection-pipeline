from collections import deque
from datetime import datetime, timedelta
from detectors.base import BaseDetector, Alert


class BruteForceDetector(BaseDetector):
    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("thresholds", {}).get("brute_force", {})
        self._max_failures = cfg.get("max_failures", 5)
        self._window_seconds = cfg.get("window_seconds", 60)
        self._windows: dict = {}  # source_ip -> deque of datetimes

    def process(self, event: dict) -> None:
        if event.get("action") != "failed_login":
            return

        source_ip = event.get("source_ip", "")
        if not source_ip:
            return

        if source_ip not in self._windows:
            self._windows[source_ip] = deque()

        window = self._windows[source_ip]

        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            ts = datetime.utcnow()

        window.append(ts)

        # Evict entries outside the window
        cutoff = ts - timedelta(seconds=self._window_seconds)
        while window and window[0] < cutoff:
            window.popleft()

        # Fire alert exactly at threshold crossing
        if len(window) == self._max_failures:
            self.alerts.append(Alert(
                timestamp=ts.isoformat(),
                rule_name="brute_force",
                severity="HIGH",
                source_ip=source_ip,
                username=event.get("username", ""),
                raw_log=event.get("raw", ""),
                description=(
                    f"Brute force detected: {self._max_failures} failed login attempts "
                    f"from {source_ip} within {self._window_seconds}s"
                ),
            ))
