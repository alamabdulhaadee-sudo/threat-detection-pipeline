# Project Plan — Threat Detection & Alerting Pipeline

## Phase Breakdown

### Phase 1 — Scaffold & Config
- Set up folder structure
- `config.yaml` with thresholds, log paths, cooldowns
- `.env` for secrets
- `requirements.txt`

### Phase 2 — Log Ingestion & Parser
- Log reader that handles `auth.log` format and JSON logs
- Normalize parsed entries into a common event schema
- File watcher for real-time mode (`watchdog`)

### Phase 3 — Detection Engine
- Rule: Brute force (failed SSH logins)
- Rule: Privilege escalation (sudo/su failures)
- Rule: Suspicious process / malware indicator
- Rule: Port scan (stretch)
- Each rule is its own module under `detectors/`

### Phase 4 — Alerting
- Slack webhook sender
- Alert deduplication with cooldown
- SQLite log of all fired alerts

### Phase 5 — Reporting & Polish
- CLI summary output
- Sample log files for demo/testing
- README with setup instructions + screenshots
- Cleanup for GitHub

---

## Folder Structure (Target)

```
threat-detection-pipeline/
├── config.yaml
├── .env.example
├── requirements.txt
├── README.md
├── main.py                  # Entry point
├── ingestion/
│   ├── log_reader.py        # Reads/watches log files
│   └── parser.py            # Normalizes log lines to event dicts
├── detectors/
│   ├── base.py              # Base detector class
│   ├── brute_force.py
│   ├── privesc.py
│   └── malware_indicators.py
├── alerting/
│   ├── slack_sender.py      # Slack webhook
│   └── deduplicator.py      # Cooldown/dedup logic
├── storage/
│   └── db.py                # SQLite alert storage
├── reporting/
│   └── summary.py           # CLI report generator
├── sample_logs/
│   ├── auth.log.sample
│   └── events.json.sample
└── tests/
    ├── test_parser.py
    ├── test_brute_force.py
    └── test_slack.py
```

---

## Current Status

- [x] Requirements defined
- [x] Project plan created
- [ ] Phase 1 — Scaffold
- [ ] Phase 2 — Ingestion
- [ ] Phase 3 — Detection
- [ ] Phase 4 — Alerting
- [ ] Phase 5 — Polish
