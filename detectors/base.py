from abc import ABC, abstractmethod
from typing import TypedDict


class Alert(TypedDict):
    timestamp: str
    rule_name: str
    severity: str   # LOW | MEDIUM | HIGH | CRITICAL
    source_ip: str
    username: str
    raw_log: str
    description: str


class BaseDetector(ABC):
    def __init__(self, config: dict):
        self.config = config
        self.alerts: list = []

    @abstractmethod
    def process(self, event: dict) -> None:
        """Ingest one event. Append to self.alerts if a rule fires."""
        ...

    def flush_alerts(self) -> list:
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts
