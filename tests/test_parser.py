from ingestion.parser import parse_line, _parse_auth_log, _parse_json_line, _parse_csv_line


def test_parse_auth_log_failed_login():
    line = "Mar 25 14:23:01 server sshd[1234]: Failed password for john from 192.168.1.105 port 43210 ssh2"
    event = parse_line(line, "auth.log")
    assert event is not None
    assert event["action"] == "failed_login"
    assert event["source_ip"] == "192.168.1.105"
    assert event["username"] == "john"
    assert event["source_file"] == "auth.log"
    assert event["raw"] == line


def test_parse_auth_log_sudo_failure():
    line = "Mar 25 14:24:01 server sudo[2001]: pam_unix(sudo:auth): authentication failure; logname=dave uid=1001 euid=0 tty=/dev/pts/0 rhost= user=dave"
    event = parse_line(line, "auth.log")
    assert event is not None
    assert event["action"] == "sudo_failure"
    assert event["username"] == "dave"


def test_parse_auth_log_login_success():
    line = "Mar 25 14:22:55 server sshd[1201]: Accepted password for alice from 192.168.1.50 port 52341 ssh2"
    event = parse_line(line, "auth.log")
    assert event is not None
    assert event["action"] == "login_success"
    assert event["username"] == "alice"
    assert event["source_ip"] == "192.168.1.50"


def test_parse_json_line():
    line = '{"timestamp": "2026-03-25T14:23:01", "src_ip": "10.0.0.5", "event_type": "failed_login", "username": "bob", "process": "", "port": 22}'
    event = parse_line(line, "events.json")
    assert event is not None
    assert event["action"] == "failed_login"
    assert event["source_ip"] == "10.0.0.5"
    assert event["username"] == "bob"


def test_parse_unknown_line_returns_none():
    event = parse_line("this is not a log line at all !!!@#$%", "unknown.log")
    assert event is None


def test_parse_csv_line():
    line = "2026-03-25T14:23:01,192.168.1.10,failed_login,sshd,22"
    event = _parse_csv_line(line)
    assert event is not None
    assert event["source_ip"] == "192.168.1.10"
    assert event["action"] == "failed_login"
    assert event["port"] == 22
