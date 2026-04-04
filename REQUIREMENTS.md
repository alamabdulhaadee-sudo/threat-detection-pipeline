# Threat Detection & Alerting Pipeline — Requirements

## Project Overview

An automated log ingestion and threat detection pipeline that monitors log sources, detects Indicators of Compromise (IOCs), and fires alerts via Slack/ticket. Built with Python, designed to mirror real SOC workflows.

---

## Goals

- Ingest logs from one or more sources (file, syslog, or simulated)
- Detect IOC patterns: brute force, port scans, privilege escalation, malware indicators
- Generate structured alerts with severity, timestamp, and context
- Deliver alerts to Slack (and optionally a ticketing system)
- Produce a daily summary report (HTML or terminal)

---

## Functional Requirements

### 1. Log Ingestion
- [ ] Read from local log files (e.g., `/var/log/auth.log`, Windows Event Log exports, CSV)
- [ ] Support JSON-formatted logs (common SIEM export format)
- [ ] Watch a directory for new log files (real-time mode)
- [ ] Accept simulated log input for testing/demo purposes

### 2. Detection Engine
- [ ] Failed login threshold detection (brute force) — e.g., 5+ failures in 60s from same IP
- [ ] Port scan detection — multiple ports hit from single source in short window
- [ ] Privilege escalation indicators — `sudo` failures, `su` attempts, UAC events
- [ ] Malware indicators — known bad process names, suspicious outbound IPs (blocklist)
- [ ] Configurable thresholds via `config.yaml`

### 3. Alerting
- [ ] Slack webhook integration — sends formatted alert message
- [ ] Alert schema: `{ timestamp, rule_name, severity, source_ip, raw_log, description }`
- [ ] Severity levels: LOW / MEDIUM / HIGH / CRITICAL
- [ ] Deduplication — don't re-alert on same event within a cooldown window
- [ ] Optional: write alerts to a local SQLite DB for tracking

### 4. Reporting
- [ ] CLI summary: total events processed, alerts fired, breakdown by rule
- [ ] Optional: generate HTML report (good for portfolio screenshots)

### 5. Configuration
- [ ] `config.yaml` controls: log paths, thresholds, Slack webhook URL, cooldown periods
- [ ] `.env` file for secrets (webhook URL, API keys) — never hardcoded

---

## Non-Functional Requirements

- Python 3.10+
- Runs on Linux and macOS (Windows stretch goal)
- No paid services required — fully runnable locally
- Clean GitHub repo with README, sample logs, and setup instructions

---

## Out of Scope (for v1)

- Live network packet capture (that's project #5)
- Full ticketing system integration (Jira/ServiceNow) — stretch goal
- ML-based anomaly detection — future version

---

## Tech Stack

| Component        | Tool/Library                        |
|------------------|-------------------------------------|
| Language         | Python 3.10+                        |
| Log parsing      | `re`, `json`, `csv`                 |
| File watching    | `watchdog`                          |
| Config           | `PyYAML`, `python-dotenv`           |
| Alerting         | Slack Incoming Webhooks (`requests`)|
| Storage          | `sqlite3` (stdlib)                  |
| Scheduling       | `APScheduler` or cron               |
| Testing          | `pytest` + sample log fixtures      |
| Packaging        | `requirements.txt`, optional Docker |

---

## Milestones

| Phase | Description                          | Deliverable                        |
|-------|--------------------------------------|------------------------------------|
| 1     | Project scaffold + config system     | Repo structure, config.yaml, .env  |
| 2     | Log ingestion + parser               | Working log reader for auth.log    |
| 3     | Detection engine (3 rules minimum)   | Brute force, port scan, privesc    |
| 4     | Slack alerting                       | Alerts firing to Slack channel     |
| 5     | Reporting + polish                   | CLI summary, README, sample output |

---

## Resume Talking Points (after completion)

- "Built an automated threat detection pipeline in Python that ingests logs, applies IOC detection rules, and delivers real-time Slack alerts"
- "Designed a configurable detection engine with tunable thresholds, deduplication logic, and severity classification"
- "Mirrors SOC L1 triage workflows — reduced hypothetical analyst response time by automating first-pass detection"
