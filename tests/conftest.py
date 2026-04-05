import pytest
from datetime import datetime


@pytest.fixture
def sample_event():
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.100",
        "username": "testuser",
        "action": "failed_login",
        "process": "",
        "port": 22,
        "raw": "Mar 25 14:23:01 server sshd[1234]: Failed password for testuser from 192.168.1.100 port 43210 ssh2",
        "source_file": "auth.log",
    }


@pytest.fixture
def sample_alert():
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "rule_name": "brute_force",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "username": "testuser",
        "raw_log": "raw log line",
        "description": "Test alert description",
    }


@pytest.fixture
def test_config():
    return {
        "thresholds": {
            "brute_force": {
                "max_failures": 2,
                "window_seconds": 60,
            },
            "privesc": {
                "max_attempts": 2,
                "window_seconds": 120,
            },
            "port_scan": {
                "max_ports": 5,
                "window_seconds": 60,
            },
            "password_spray": {
                "max_usernames": 5,
                "window_seconds": 60,
            },
            "anomalous_hours": {
                "start_hour": 9,
                "end_hour": 18,
            },
            "malware": {
                "blocklist_ips": ["185.220.101.1", "198.51.100.99"],
                "suspicious_processes": ["mimikatz", "netcat", "meterpreter"],
            },
        },
        "alerting": {
            "cooldown_seconds": 300,
            "slack_enabled": False,
        },
    }
