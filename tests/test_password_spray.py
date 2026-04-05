from datetime import datetime, timedelta
from detectors.password_spray import PasswordSprayDetector


BASE_TIME = datetime(2026, 3, 25, 14, 0, 0)

USERNAMES = ["alice", "bob", "charlie", "dave", "eve"]


def make_event(ip="10.0.0.1", username="alice", seconds_offset=0, action="failed_login"):
    ts = BASE_TIME + timedelta(seconds=seconds_offset)
    return {
        "timestamp": ts.isoformat(),
        "source_ip": ip,
        "username": username,
        "action": action,
        "raw": f"Failed login attempt for {username} from {ip}",
        "source_file": "auth.log",
    }


def test_no_alert_below_threshold(test_config):
    """Targeting fewer distinct usernames than the threshold should not fire."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES[:4]):  # threshold is 5 in defaults
        detector.process(make_event(username=user, seconds_offset=i * 2))
    assert detector.flush_alerts() == []


def test_alert_at_threshold(test_config):
    """Hitting exactly 5 distinct usernames from one IP should fire once."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES):  # exactly 5 distinct usernames
        detector.process(make_event(username=user, seconds_offset=i * 2))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "password_spray"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "10.0.0.1"


def test_duplicate_usernames_do_not_count(test_config):
    """Repeated attempts against the same username should not increment the distinct count."""
    detector = PasswordSprayDetector(test_config)
    # 10 attempts all against "alice" — only 1 distinct username
    for i in range(10):
        detector.process(make_event(username="alice", seconds_offset=i))
    assert detector.flush_alerts() == []


def test_no_alert_outside_window(test_config):
    """Usernames spread beyond the time window should not accumulate toward threshold."""
    detector = PasswordSprayDetector(test_config)
    # Each event is 30s apart — the 60s window means earlier events expire before the 5th arrives
    for i, user in enumerate(USERNAMES):
        detector.process(make_event(username=user, seconds_offset=i * 30))
    assert detector.flush_alerts() == []


def test_different_ips_tracked_independently(test_config):
    """Two IPs both hitting the threshold should each fire a separate alert."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES):
        detector.process(make_event(ip="10.0.0.1", username=user, seconds_offset=i))
        detector.process(make_event(ip="10.0.0.2", username=user, seconds_offset=i))
    alerts = detector.flush_alerts()
    assert len(alerts) == 2
    ips = {a["source_ip"] for a in alerts}
    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_non_failed_login_events_ignored(test_config):
    """Successful logins and other actions should not count toward the spray threshold."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES):
        event = make_event(username=user, seconds_offset=i, action="login_success")
        detector.process(event)
    assert detector.flush_alerts() == []


def test_alert_description_lists_usernames(test_config):
    """Alert description should include all targeted usernames."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES):
        detector.process(make_event(username=user, seconds_offset=i * 2))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    desc = alerts[0]["description"]
    for user in USERNAMES:
        assert user in desc


def test_alert_severity_is_high(test_config):
    """Password spray alert severity must be HIGH, not MEDIUM."""
    detector = PasswordSprayDetector(test_config)
    for i, user in enumerate(USERNAMES):
        detector.process(make_event(username=user, seconds_offset=i * 2))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
