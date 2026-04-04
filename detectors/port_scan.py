from collections import deque
from datetime import datetime, timedelta
from detectors.base import BaseDetector, Alert


class PortScanDetector(BaseDetector):
    """
    Detects port scanning: one source IP probing many distinct destination
    ports in a short time window.

    Key distinction from brute force: we track *unique ports*, not attempt
    count. Hitting port 22 ten times is brute force. Hitting ports 22, 80,
    443, 3306, 8080... in quick succession is reconnaissance.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        cfg = config.get("thresholds", {}).get("port_scan", {})
        self._max_ports = cfg.get("max_ports", 10)
        self._window_seconds = cfg.get("window_seconds", 30)
        # source_ip -> deque of (timestamp, dest_port) tuples
        self._windows: dict = {}

    def process(self, event: dict) -> None:
        if event.get("action") != "port_scan":
            return

        source_ip = event.get("source_ip", "")
        dest_port = event.get("dest_port")
        if not source_ip or dest_port is None:
            return

        if source_ip not in self._windows:
            self._windows[source_ip] = deque()

        window = self._windows[source_ip]

        try:
            ts = datetime.fromisoformat(event["timestamp"])
        except (ValueError, KeyError):
            ts = datetime.utcnow()

        window.append((ts, int(dest_port)))

        # Evict entries outside the time window
        cutoff = ts - timedelta(seconds=self._window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

        # Count distinct ports within the current window
        unique_ports = {port for _, port in window}

        if len(unique_ports) == self._max_ports:
            self.alerts.append(Alert(
                timestamp=ts.isoformat(),
                rule_name="port_scan",
                severity="MEDIUM",
                source_ip=source_ip,
                username=event.get("username", ""),
                raw_log=event.get("raw", ""),
                description=(
                    f"Port scan detected: {source_ip} probed {len(unique_ports)} distinct ports "
                    f"within {self._window_seconds}s "
                    f"(ports: {', '.join(str(p) for p in sorted(unique_ports))})"
                ),
            ))
