from datetime import datetime, timedelta


class Deduplicator:
    def __init__(self, cooldown_seconds: int = 300):
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._seen: dict = {}  # (rule_name, source_ip) -> datetime

    def is_duplicate(self, alert: dict) -> bool:
        key = (alert.get("rule_name", ""), alert.get("source_ip", ""))
        now = datetime.utcnow()
        if key in self._seen:
            if now - self._seen[key] < self._cooldown:
                return True
        self._seen[key] = now
        return False

    def purge_expired(self) -> None:
        now = datetime.utcnow()
        expired = [k for k, v in self._seen.items() if now - v >= self._cooldown]
        for k in expired:
            del self._seen[k]
