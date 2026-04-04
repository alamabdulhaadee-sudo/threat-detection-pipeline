from unittest.mock import patch, MagicMock
from alerting.slack_sender import SlackSender


def make_alert():
    return {
        "timestamp": "2026-03-25T14:23:01",
        "rule_name": "brute_force",
        "severity": "HIGH",
        "source_ip": "192.168.1.100",
        "username": "testuser",
        "raw_log": "raw line",
        "description": "Brute force detected from 192.168.1.100",
    }


@patch("requests.post")
def test_send_success(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    sender = SlackSender("https://hooks.slack.com/test", enabled=True)
    result = sender.send(make_alert())
    assert result is True
    assert mock_post.called


@patch("requests.post")
def test_send_failure(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    sender = SlackSender("https://hooks.slack.com/test", enabled=True)
    result = sender.send(make_alert())
    assert result is False


@patch("requests.post")
def test_send_disabled(mock_post):
    sender = SlackSender("https://hooks.slack.com/test", enabled=False)
    result = sender.send(make_alert())
    assert result is True
    mock_post.assert_not_called()


@patch("requests.post")
def test_payload_structure(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    sender = SlackSender("https://hooks.slack.com/test", enabled=True)
    sender.send(make_alert())

    call_kwargs = mock_post.call_args.kwargs
    payload = call_kwargs["json"]
    assert "attachments" in payload
    attachment = payload["attachments"][0]
    assert "color" in attachment
    assert "blocks" in attachment
    assert attachment["color"] == "#ff6600"  # HIGH severity color
