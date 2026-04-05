from datetime import datetime
from detectors.base import BaseDetector, Alert


class AnomalousHoursDetector(BaseDetector):
    """
    Detects logins outside expected working hours.

    A single successful login outside the configured window (e.g. 9 AM–6 PM)
    is flagged as MEDIUM. Attackers often operate during off-hours to avoid
    detection by on-call staff.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("thresholds", {}).get("anomalous_hours", {})
        self._start_hour = cfg.get("start_hour", 9)   # inclusive
        self._end_hour = cfg.get("end_hour", 18)       # exclusive

    def process(self, event: dict) -> None:
        if event.get("action") != "login_success":
            return

        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            return

        hour = ts.hour
        if self._start_hour <= hour < self._end_hour:
            return  # within normal hours, nothing to do

        username = event.get("username", "unknown")
        source_ip = event.get("source_ip", "")

        self.alerts.append(Alert(
            timestamp=ts.isoformat(),
            rule_name="anomalous_hours",
            severity="MEDIUM",
            source_ip=source_ip,
            username=username,
            raw_log=event.get("raw", ""),
            description=(
                f"Login outside expected hours: user '{username}' logged in at "
                f"{ts.strftime('%H:%M')} from {source_ip}"
            ),
        ))
