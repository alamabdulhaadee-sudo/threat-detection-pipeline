import argparse
import os
import time
import yaml
from datetime import datetime, timedelta
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from ingestion.log_reader import read_all_files, start_watcher
from detectors.brute_force import BruteForceDetector
from detectors.privesc import PrivescDetector
from detectors.malware_indicators import MalwareDetector
from alerting.deduplicator import Deduplicator
from alerting.slack_sender import SlackSender
from storage.db import AlertDatabase
from reporting.summary import generate_terminal_report, run_scheduled_report


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Threat Detection & Alerting Pipeline")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--watch", action="store_true", help="Enable real-time watch mode")
    parser.add_argument("--report", action="store_true", help="Generate report and exit")
    parser.add_argument("--since", type=int, default=24, help="Report window in hours (default: 24)")
    args = parser.parse_args()

    config = load_config(args.config)

    db = AlertDatabase(config["storage"]["db_path"])
    deduplicator = Deduplicator(config["alerting"]["cooldown_seconds"])
    slack = SlackSender(
        webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
        enabled=config["alerting"]["slack_enabled"],
    )

    detectors = [
        BruteForceDetector(config),
        PrivescDetector(config),
        MalwareDetector(config),
    ]

    # Report-only mode
    if args.report:
        since = datetime.utcnow() - timedelta(hours=args.since)
        generate_terminal_report(db, since)
        db.close()
        return

    def process_event(event: dict) -> None:
        for detector in detectors:
            detector.process(event)
            for alert in detector.flush_alerts():
                if not deduplicator.is_duplicate(alert):
                    sent = slack.send(alert)
                    db.save_alert(alert)
                    status = "sent" if sent else "send_failed"
                    print(
                        f"[ALERT] [{alert['severity']}] {alert['rule_name']} | "
                        f"{alert['source_ip']} | {alert['description'][:80]} | slack={status}"
                    )

    watch_mode = args.watch or config.get("watch_mode", False)

    if not watch_mode:
        # Batch mode
        print("[*] Running in batch mode...")
        events = list(read_all_files(config["log_paths"]))
        print(f"[*] Parsed {len(events)} events from {len(config['log_paths'])} file(s)")
        for event in events:
            process_event(event)
        db.log_processing_run("batch", len(events))
        since = datetime.utcnow() - timedelta(hours=args.since)
        generate_terminal_report(db, since)
    else:
        # Watch mode
        print("[*] Running in watch mode — press Ctrl+C to stop")
        observer = start_watcher(config["log_paths"], process_event)

        scheduler = BackgroundScheduler()
        scheduler.add_job(
            run_scheduled_report,
            CronTrigger.from_crontab(config["reporting"]["schedule_cron"]),
            args=[config, db],
        )
        scheduler.start()

        try:
            while True:
                deduplicator.purge_expired()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            observer.stop()
            scheduler.shutdown()
            observer.join()

    db.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()
