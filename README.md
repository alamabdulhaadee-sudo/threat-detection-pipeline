# Threat Detection & Alerting Pipeline

An automated log ingestion and threat detection pipeline that monitors system logs, detects Indicators of Compromise (IOCs), and delivers real-time Slack alerts — built to mirror real SOC analyst workflows.

## Features

- **Real-time log monitoring** — watches auth.log, system.log, and custom log files using file system events
- **Detection rules:**
  - Brute force SSH (configurable failure threshold + time window)
  - Privilege escalation (sudo/su failures per user)
  - Malware C2 IPs (blocklist matching)
  - Malicious processes (mimikatz, netcat, meterpreter, etc.)
- **Slack alerting** — formatted Block Kit messages with severity-based color coding
- **Alert deduplication** — cooldown window prevents alert flooding
- **SQLite persistence** — every alert stored locally for audit and reporting
- **Terminal + HTML reports** — on-demand or daily scheduled summaries

## Tech Stack

Python 3.10+ · watchdog · PyYAML · python-dotenv · requests · APScheduler · SQLite · pytest

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure Slack webhook
cp .env.example .env
# Edit .env and add your SLACK_WEBHOOK_URL

# 3. Run in batch mode (processes sample logs, prints report)
python3 main.py

# 4. Run in real-time watch mode
python3 main.py --watch

# 5. Generate a report on-demand
python3 main.py --report --since 24
```

## Configuration

Edit `config.yaml` to customize:

```yaml
log_paths:
  - /var/log/auth.log
  - /var/log/system.log

thresholds:
  brute_force:
    max_failures: 5
    window_seconds: 60
  privesc:
    max_attempts: 3
    window_seconds: 120
  malware:
    blocklist_ips:
      - "185.220.101.1"
    suspicious_processes:
      - "mimikatz"
      - "netcat"
```

## Project Structure

```
threat-detection-pipeline/
├── main.py                      # Entry point (batch, watch, report modes)
├── config.yaml                  # Thresholds, log paths, alerting config
├── ingestion/
│   ├── parser.py                # Normalizes auth.log, JSON, CSV → Event dicts
│   └── log_reader.py            # Batch reader + real-time watchdog watcher
├── detectors/
│   ├── base.py                  # BaseDetector + Alert TypedDict
│   ├── brute_force.py           # SSH brute force detection
│   ├── privesc.py               # Privilege escalation detection
│   └── malware_indicators.py   # C2 IP + malicious process detection
├── alerting/
│   ├── slack_sender.py          # Slack Block Kit webhook sender
│   └── deduplicator.py          # Cooldown-based alert deduplication
├── storage/
│   └── db.py                    # SQLite alert persistence
├── reporting/
│   └── summary.py               # Terminal + HTML report generator
├── sample_logs/                 # Demo log files for testing
└── tests/                       # pytest suite (15 tests)
```

## Running Tests

```bash
pytest tests/ -v
```

## Sample Alert Output

```
[ALERT] [HIGH] brute_force | 10.10.10.99 | Brute force detected: 5 failed login attempts from 10.10.10.99 within 60s | slack=sent
[ALERT] [HIGH] privilege_escalation | user hacker | 3 sudo_failure attempts within 120s | slack=sent
[ALERT] [CRITICAL] malware_c2_ip | 185.220.101.1 | Connection from known C2/malicious IP | slack=sent
[ALERT] [CRITICAL] malware_process | mimikatz detected on 10.10.10.99 | slack=sent
```

## Author

Abdul Haadee Alam — Cybersecurity Student | SOC Analyst  
[GitHub](https://github.com/alamabdulhaadee-sudo) · [LinkedIn](https://linkedin.com/in/abdulhaadeealam)
