from datetime import datetime, timedelta
from detectors.brute_force import BruteForceDetector
from alerting.deduplicator import Deduplicator


def make_event(ip="192.168.1.100", action="failed_login", seconds_offset=0):
    ts = datetime(2026, 3, 25, 14, 23, 0) + timedelta(seconds=seconds_offset)
    return {
        "timestamp": ts.isoformat(),
        "source_ip": ip,
        "username": "testuser",
        "action": action,
        "process": "",
        "port": 22,
        "raw": "raw line",
        "source_file": "auth.log",
    }


def test_no_alert_below_threshold(test_config):
    detector = BruteForceDetector(test_config)
    for i in range(1):  # threshold is 2, send only 1
        detector.process(make_event(seconds_offset=i * 5))
    assert detector.flush_alerts() == []


def test_alert_at_threshold(test_config):
    detector = BruteForceDetector(test_config)
    for i in range(2):  # threshold is 2
        detector.process(make_event(seconds_offset=i * 5))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "brute_force"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "192.168.1.100"


def test_no_alert_different_ips(test_config):
    detector = BruteForceDetector(test_config)
    for i in range(5):
        detector.process(make_event(ip=f"192.168.1.{i+1}", seconds_offset=i * 5))
    assert detector.flush_alerts() == []


def test_no_alert_outside_window(test_config):
    detector = BruteForceDetector(test_config)
    # threshold=2, window=60s — send 2 events 90 seconds apart
    detector.process(make_event(seconds_offset=0))
    detector.process(make_event(seconds_offset=90))
    assert detector.flush_alerts() == []


def test_dedup_suppresses_repeat(test_config, sample_alert):
    dedup = Deduplicator(cooldown_seconds=300)
    # First alert should NOT be a duplicate
    assert dedup.is_duplicate(sample_alert) is False
    # Same alert immediately after should be a duplicate
    assert dedup.is_duplicate(sample_alert) is True
