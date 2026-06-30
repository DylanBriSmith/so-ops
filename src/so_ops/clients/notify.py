"""Pluggable notification providers — all stdlib, no external deps."""

from __future__ import annotations

import base64
import json
import logging
import smtplib
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger("so-ops.notify")


# ── Provider functions ───────────────────────────────────────────────
# Each: send(cfg_dict, subject, body, short) -> bool


def _send_email(cfg: dict, subject: str, body: str, short: str) -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["from_address"]
    msg["To"] = cfg["to_address"]
    msg.attach(MIMEText(body, "plain"))
    try:
        with smtplib.SMTP_SSL(cfg["smtp_host"], cfg.get("smtp_port", 465), timeout=30) as server:
            server.login(cfg["from_address"], cfg["password"])
            server.sendmail(cfg["from_address"], cfg["to_address"], msg.as_string())
        log.info("Email sent to %s", cfg["to_address"])
        return True
    except Exception as exc:
        log.error("Failed to send email: %s", exc)
        return False


def _send_sms(cfg: dict, subject: str, body: str, short: str) -> bool:
    if not cfg.get("twilio_account_sid"):
        return False
    message = f"{subject}\n{short}"
    if len(message) > 1500:
        message = message[:1497] + "..."

    url = f"https://api.twilio.com/2010-04-01/Accounts/{cfg['twilio_account_sid']}/Messages.json"
    creds = base64.b64encode(
        f"{cfg['twilio_account_sid']}:{cfg['twilio_auth_token']}".encode()
    ).decode()

    data = urllib.parse.urlencode(
        {
            "To": cfg["to_number"],
            "From": cfg["from_number"],
            "Body": message,
        }
    ).encode()

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Basic {creds}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
        log.info("SMS sent to %s, SID: %s", cfg["to_number"], result.get("sid", "?"))
        return True
    except Exception as exc:
        log.error("Failed to send SMS: %s", exc)
        return False


def _send_discord(cfg: dict, subject: str, body: str, short: str) -> bool:
    payload = json.dumps({"content": f"**{subject}**\n{short}"}).encode()
    req = urllib.request.Request(cfg["webhook_url"], data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("Discord notification sent")
        return True
    except Exception as exc:
        log.error("Failed to send Discord notification: %s", exc)
        return False


def _send_slack(cfg: dict, subject: str, body: str, short: str) -> bool:
    payload = json.dumps({"text": f"*{subject}*\n{short}"}).encode()
    req = urllib.request.Request(cfg["webhook_url"], data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("Slack notification sent")
        return True
    except Exception as exc:
        log.error("Failed to send Slack notification: %s", exc)
        return False


def _send_ntfy(cfg: dict, subject: str, body: str, short: str) -> bool:
    url = f"{cfg.get('url', 'https://ntfy.sh').rstrip('/')}/{cfg['topic']}"
    data = short.encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    # HTTP headers are latin-1; replace anything outside that range
    safe_subject = subject.encode("latin-1", errors="replace").decode("latin-1")
    req.add_header("Title", safe_subject)
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("ntfy notification sent to %s", cfg["topic"])
        return True
    except Exception as exc:
        log.error("Failed to send ntfy notification: %s", exc)
        return False


def _send_gotify(cfg: dict, subject: str, body: str, short: str) -> bool:
    url = f"{cfg['url'].rstrip('/')}/message"
    payload = json.dumps({"title": subject, "message": short}).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if cfg.get("token"):
        req.add_header("X-Gotify-Key", cfg["token"])
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("Gotify notification sent")
        return True
    except Exception as exc:
        log.error("Failed to send Gotify notification: %s", exc)
        return False


def _send_webhook(cfg: dict, subject: str, body: str, short: str) -> bool:
    payload = json.dumps({"subject": subject, "body": body}).encode()
    req = urllib.request.Request(cfg["url"], data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("Webhook notification sent to %s", cfg["url"])
        return True
    except Exception as exc:
        log.error("Failed to send webhook notification: %s", exc)
        return False


def _send_teams(cfg: dict, subject: str, body: str, short: str) -> bool:
    severity = (
        "HIGH" if "HIGH" in subject.upper() else "MEDIUM" if "MEDIUM" in subject.upper() else "LOW"
    )
    color = "Attention" if severity == "HIGH" else "Warning" if severity == "MEDIUM" else "Good"

    body_blocks = [
        {
            "type": "TextBlock",
            "text": f"&#x26A0; {subject}",
            "wrap": True,
            "size": "Large",
            "weight": "Bolder",
            "color": color,
        },
    ]
    for line in body.splitlines():
        body_blocks.append(
            {"type": "TextBlock", "text": line or "​", "wrap": True, "spacing": "None"}
        )

    payload = json.dumps(
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body_blocks,
                    },
                }
            ],
        }
    ).encode()

    req = urllib.request.Request(cfg["url"], data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=15)
        log.info("Teams notification sent")
        return True
    except Exception as exc:
        log.error("Failed to send Teams notification: %s", exc)
        return False


# ── Dispatcher ───────────────────────────────────────────────────────

PROVIDERS: dict[str, callable] = {
    "email": _send_email,
    "sms": _send_sms,
    "discord": _send_discord,
    "slack": _send_slack,
    "ntfy": _send_ntfy,
    "gotify": _send_gotify,
    "webhook": _send_webhook,
    "teams": _send_teams,
}


def notify_all(
    notifications_cfg: dict, subject: str, body: str, short: str = ""
) -> dict[str, bool]:
    """Send to all enabled notification providers. Returns {provider: success}."""
    results: dict[str, bool] = {}
    short = short or body[:300]
    for name, pcfg in notifications_cfg.items():
        if not pcfg.get("enabled", False):
            continue
        fn = PROVIDERS.get(name)
        if fn:
            results[name] = fn(pcfg, subject, body, short)
        else:
            log.warning("Unknown notification provider: %s", name)
    return results
