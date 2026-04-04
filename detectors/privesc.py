from collections import deque
from datetime import datetime, timedelta
from detectors.base import BaseDetector, Alert

PRIVESC_ACTIONS = {"sudo_failure", "su_failure"}


class PrivescDetector(BaseDetector):
    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("thresholds", {}).get("privesc", {})
        self._max_attempts = cfg.get("max_attempts", 3)
        self._window_seconds = cfg.get("window_seconds", 120)
        self._windows: dict = {}  # (source_ip, username) -> deque

    def process(self, event: dict) -> None:
        if event.get("action") not in PRIVESC_ACTIONS:
            return

        source_ip = event.get("source_ip", "")
        username = event.get("username", "")
        key = (source_ip, username)

        if key not in self._windows:
            self._windows[key] = deque()

        window = self._windows[key]

        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            ts = datetime.utcnow()

        window.append(ts)

        cutoff = ts - timedelta(seconds=self._window_seconds)
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) == self._max_attempts:
            severity = "CRITICAL" if username == "root" else "HIGH"
            self.alerts.append(Alert(
                timestamp=ts.isoformat(),
                rule_name="privilege_escalation",
                severity=severity,
                source_ip=source_ip,
                username=username,
                raw_log=event.get("raw", ""),
                description=(
                    f"Privilege escalation detected: {self._max_attempts} {event['action']} attempts "
                    f"by user '{username}' from {source_ip} within {self._window_seconds}s"
                ),
            ))
