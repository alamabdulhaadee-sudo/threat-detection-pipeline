import requests
from datetime import datetime

SEVERITY_COLORS = {
    "LOW": "#36a64f",
    "MEDIUM": "#ffcc00",
    "HIGH": "#ff6600",
    "CRITICAL": "#cc0000",
}


class SlackSender:
    def __init__(self, webhook_url: str, enabled: bool = True):
        self._url = webhook_url
        self.enabled = enabled

    def send(self, alert: dict) -> bool:
        if not self.enabled:
            print(f"[SLACK DISABLED] Would send alert: {alert.get('rule_name')} / {alert.get('severity')}")
            return True

        if not self._url:
            print("[WARN] SLACK_WEBHOOK_URL not set — skipping alert")
            return False

        severity = alert.get("severity", "LOW")
        color = SEVERITY_COLORS.get(severity, "#36a64f")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"[{severity}] {alert.get('rule_name', 'unknown').replace('_', ' ').title()}",
                            },
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": alert.get("description", "No description"),
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": (
                                        f"*Time:* {alert.get('timestamp', '')} | "
                                        f"*Source IP:* {alert.get('source_ip', 'N/A')} | "
                                        f"*User:* {alert.get('username', 'N/A')}"
                                    ),
                                }
                            ],
                        },
                    ],
                }
            ]
        }

        try:
            response = requests.post(self._url, json=payload, timeout=5)
            if response.status_code != 200:
                print(f"[ERROR] Slack returned {response.status_code}: {response.text}")
                return False
            return True
        except requests.RequestException as e:
            print(f"[ERROR] Slack request failed: {e}")
            return False
