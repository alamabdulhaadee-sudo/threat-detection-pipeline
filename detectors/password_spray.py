from collections import deque
from datetime import datetime, timedelta
from detectors.base import BaseDetector, Alert


class PasswordSprayDetector(BaseDetector):
    """Detects password spraying attacks.

    Password spraying is distinct from brute force: a brute force attack hammers
    many passwords against a single account, while password spraying tries one
    (or few) passwords across many different accounts from the same source IP.
    This detector tracks the number of distinct usernames targeted by a single IP
    within a sliding time window and fires when that count hits the configured
    threshold.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("thresholds", {}).get("password_spray", {})
        self._max_usernames = cfg.get("max_usernames", 5)
        self._window_seconds = cfg.get("window_seconds", 60)
        self._windows: dict = {}

    def process(self, event: dict) -> None:
        if event.get("action") != "failed_login":
            return

        source_ip = event.get("source_ip", "")
        username = event.get("username", "")
        if not source_ip or not username:
            return

        if source_ip not in self._windows:
            self._windows[source_ip] = deque()

        window = self._windows[source_ip]

        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            ts = datetime.utcnow()

        window.append((ts, username))

        cutoff = ts - timedelta(seconds=self._window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

        unique_usernames = {u for _, u in window}

        if len(unique_usernames) == self._max_usernames:
            self.alerts.append(Alert(
                timestamp=ts.isoformat(),
                rule_name="password_spray",
                severity="HIGH",
                source_ip=source_ip,
                username=event.get("username", ""),
                raw_log=event.get("raw", ""),
                description=(
                    f"Password spray detected: {source_ip} attempted {len(unique_usernames)} distinct usernames "
                    f"within {self._window_seconds}s "
                    f"(users: {', '.join(sorted(unique_usernames))})"
                ),
            ))
