"""
notify.py — best-effort alert delivery for --watch regressions.

Slack webhooks were already supported; this adds SMTP email (roadmap #22) and
centralizes both. Every function is best-effort and NEVER raises — an alert
failing must not crash a monitoring run.

SMTP is configured from the environment (no secrets on the command line):
    AI_RT_SMTP_HOST, AI_RT_SMTP_PORT (default 587), AI_RT_SMTP_USER,
    AI_RT_SMTP_PASS, AI_RT_SMTP_FROM (defaults to USER),
    AI_RT_SMTP_STARTTLS (default on; set 0 to disable).

Public API:
    send_slack(webhook_url, text)                 -> bool
    send_email(to, subject, body, config=None)    -> (ok: bool, reason: str)
    build_email(to, subject, body, from_addr)     -> email.message.EmailMessage
    smtp_config()                                 -> dict
"""

import os
import smtplib
import ssl
from email.message import EmailMessage


def send_slack(webhook_url: str, text: str) -> bool:
    """POST *text* to a Slack incoming webhook. Returns True on apparent success."""
    if not webhook_url:
        return False
    try:
        import requests
        requests.post(webhook_url, json={"text": text}, timeout=10)
        return True
    except Exception:
        return False


def smtp_config() -> dict:
    """Read SMTP settings from the environment."""
    try:
        port = int(os.environ.get("AI_RT_SMTP_PORT", "587") or 587)
    except ValueError:
        port = 587
    user = os.environ.get("AI_RT_SMTP_USER")
    return {
        "host": os.environ.get("AI_RT_SMTP_HOST"),
        "port": port,
        "user": user,
        "password": os.environ.get("AI_RT_SMTP_PASS"),
        "from": os.environ.get("AI_RT_SMTP_FROM") or user or "ai-redteam@localhost",
        "starttls": os.environ.get("AI_RT_SMTP_STARTTLS", "1").lower()
                    not in ("0", "false", "no", "off"),
    }


def build_email(to: str, subject: str, body: str, from_addr: str) -> EmailMessage:
    """Construct a plain-text email message (pure — no network)."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr or "ai-redteam@localhost"
    msg["To"] = to
    msg.set_content(body)
    return msg


def send_email(to: str, subject: str, body: str, config: dict = None) -> tuple:
    """Send an alert email via SMTP. Returns (ok, reason). Never raises.

    Falls back to a clear reason string when no recipient or no SMTP host is
    configured, so the caller can surface why nothing was sent.
    """
    if not to:
        return (False, "no recipient (--alert-email not set)")
    cfg = config or smtp_config()
    if not cfg.get("host"):
        return (False, "SMTP not configured — set AI_RT_SMTP_HOST/PORT/USER/PASS/FROM")
    try:
        msg = build_email(to, subject, body, cfg.get("from"))
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            if cfg.get("starttls"):
                try:
                    s.starttls(context=ssl.create_default_context())
                except Exception:
                    pass  # server may not support STARTTLS; try to send anyway
            if cfg.get("user"):
                s.login(cfg["user"], cfg.get("password") or "")
            s.send_message(msg)
        return (True, "sent")
    except Exception as exc:
        return (False, str(exc))
