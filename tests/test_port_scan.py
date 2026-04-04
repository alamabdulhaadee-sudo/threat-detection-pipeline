from datetime import datetime, timedelta
from detectors.port_scan import PortScanDetector


BASE_TIME = datetime(2026, 3, 25, 14, 0, 0)


def make_event(ip="10.0.0.1", dest_port=80, seconds_offset=0):
    ts = BASE_TIME + timedelta(seconds=seconds_offset)
    return {
        "timestamp": ts.isoformat(),
        "source_ip": ip,
        "dest_port": dest_port,
        "action": "port_scan",
        "username": "",
        "raw": f"Connection attempt from {ip} to port {dest_port}",
        "source_file": "firewall.log",
    }


def test_no_alert_below_threshold(test_config):
    """Scanning fewer ports than threshold should not fire."""
    detector = PortScanDetector(test_config)
    for port in [22, 80, 443]:  # threshold is 5 in test_config
        detector.process(make_event(dest_port=port, seconds_offset=1))
    assert detector.flush_alerts() == []


def test_alert_at_threshold(test_config):
    """Hitting exactly the threshold of distinct ports should fire once."""
    detector = PortScanDetector(test_config)
    for i, port in enumerate([22, 80, 443, 3306, 8080]):  # threshold is 5
        detector.process(make_event(dest_port=port, seconds_offset=i * 2))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "port_scan"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["source_ip"] == "10.0.0.1"


def test_duplicate_ports_do_not_trigger(test_config):
    """Hitting the same port repeatedly should NOT count as a port scan."""
    detector = PortScanDetector(test_config)
    for i in range(10):  # 10 hits, all on port 22
        detector.process(make_event(dest_port=22, seconds_offset=i))
    assert detector.flush_alerts() == []


def test_no_alert_outside_window(test_config):
    """Ports spread beyond the time window should not accumulate."""
    detector = PortScanDetector(test_config)
    ports = [22, 80, 443, 3306, 8080]
    for i, port in enumerate(ports):
        # Each event is 30s apart — well outside the 60s window
        detector.process(make_event(dest_port=port, seconds_offset=i * 30))
    assert detector.flush_alerts() == []


def test_different_ips_tracked_independently(test_config):
    """Two IPs scanning simultaneously should not interfere with each other."""
    detector = PortScanDetector(test_config)
    ports = [22, 80, 443, 3306, 8080]
    for i, port in enumerate(ports):
        detector.process(make_event(ip="10.0.0.1", dest_port=port, seconds_offset=i))
        detector.process(make_event(ip="10.0.0.2", dest_port=port, seconds_offset=i))
    alerts = detector.flush_alerts()
    # Both IPs should fire independently
    assert len(alerts) == 2
    ips = {a["source_ip"] for a in alerts}
    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_non_port_scan_events_ignored(test_config):
    """Events with a different action should be ignored entirely."""
    detector = PortScanDetector(test_config)
    for i, port in enumerate([22, 80, 443, 3306, 8080]):
        event = make_event(dest_port=port, seconds_offset=i)
        event["action"] = "failed_login"  # wrong action
        detector.process(event)
    assert detector.flush_alerts() == []


def test_alert_description_lists_ports(test_config):
    """Alert description should include the scanned port list."""
    detector = PortScanDetector(test_config)
    ports = [22, 80, 443, 3306, 8080]
    for i, port in enumerate(ports):
        detector.process(make_event(dest_port=port, seconds_offset=i * 2))
    alerts = detector.flush_alerts()
    assert len(alerts) == 1
    desc = alerts[0]["description"]
    for port in ports:
        assert str(port) in desc
