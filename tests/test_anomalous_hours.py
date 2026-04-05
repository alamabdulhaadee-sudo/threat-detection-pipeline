from detectors.anomalous_hours import AnomalousHoursDetector


def make_event(hour: int, minute: int = 0, ip="192.168.1.50", username="alice"):
    ts = f"2026-03-25T{hour:02d}:{minute:02d}:00"
    return {
        "timestamp": ts,
        "source_ip": ip,
        "username": username,
        "action": "login_success",
        "raw": f"Accepted password for {username} from {ip}",
        "source_file": "auth.log",
    }


def test_no_alert_during_business_hours(test_config):
    """Login at 10 AM should not trigger — within the 9–18 window."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=10))
    assert detector.flush_alerts() == []


def test_no_alert_at_start_boundary(test_config):
    """Login exactly at 9 AM (start_hour) should not trigger."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=9))
    assert detector.flush_alerts() == []


def test_no_alert_just_before_end(test_config):
    """Login at 17:59 should not trigger — still within window."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=17, minute=59))
    assert detector.flush_alerts() == []


def test_alert_at_end_boundary(test_config):
    """Login at exactly 18:00 (end_hour) should trigger — exclusive upper bound."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=18))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "anomalous_hours"
    assert alerts[0]["severity"] == "MEDIUM"


def test_alert_early_morning(test_config):
    """Login at 2 AM should fire."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=2, minute=14))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert "02:14" in alerts[0]["description"]
    assert "alice" in alerts[0]["description"]
    assert "192.168.1.50" in alerts[0]["description"]


def test_alert_late_night(test_config):
    """Login at 23:00 should fire."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=23, username="bob", ip="10.0.0.5"))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["username"] == "bob"
    assert alerts[0]["source_ip"] == "10.0.0.5"


def test_non_login_action_ignored(test_config):
    """Events with action other than login_success should be ignored."""
    detector = AnomalousHoursDetector(test_config)
    event = make_event(hour=2)
    event["action"] = "failed_login"
    detector.process(event)
    assert detector.flush_alerts() == []


def test_each_login_fires_independently(test_config):
    """Two off-hours logins from different users should each fire."""
    detector = AnomalousHoursDetector(test_config)
    detector.process(make_event(hour=3, username="alice", ip="10.0.0.1"))
    detector.process(make_event(hour=22, username="bob", ip="10.0.0.2"))
    alerts = detector.flush_alerts()
    assert len(alerts) == 2
    usernames = {a["username"] for a in alerts}
    assert usernames == {"alice", "bob"}
