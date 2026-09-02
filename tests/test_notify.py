"""Tests for notify.py — Slack + SMTP email alerts (no real network)."""
import notify


def test_build_email_is_plaintext():
    m = notify.build_email("to@x.com", "subj", "body text", "from@x.com")
    assert m["To"] == "to@x.com" and m["From"] == "from@x.com" and m["Subject"] == "subj"
    assert "body text" in m.get_content()


def test_smtp_config_reads_env(monkeypatch):
    monkeypatch.setenv("AI_RT_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("AI_RT_SMTP_PORT", "2525")
    monkeypatch.setenv("AI_RT_SMTP_USER", "u@x.com")
    cfg = notify.smtp_config()
    assert cfg["host"] == "smtp.example.com" and cfg["port"] == 2525
    assert cfg["from"] == "u@x.com" and cfg["starttls"] is True


def test_send_email_no_recipient():
    ok, why = notify.send_email("", "s", "b")
    assert ok is False and "recipient" in why


def test_send_email_not_configured(monkeypatch):
    monkeypatch.delenv("AI_RT_SMTP_HOST", raising=False)
    ok, why = notify.send_email("to@x.com", "s", "b", config={"host": None})
    assert ok is False and "SMTP not configured" in why


def test_send_email_success_mocked(monkeypatch):
    sent = {}

    class _FakeSMTP:
        def __init__(self, host, port, timeout=15): sent["host"] = host
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): sent["tls"] = True
        def login(self, u, p): sent["login"] = u
        def send_message(self, msg): sent["msg"] = msg["To"]

    monkeypatch.setattr(notify.smtplib, "SMTP", _FakeSMTP)
    cfg = {"host": "smtp.x", "port": 587, "user": "u", "password": "p",
           "from": "f@x", "starttls": True}
    ok, why = notify.send_email("to@x.com", "subj", "body", config=cfg)
    assert ok is True and why == "sent"
    assert sent["host"] == "smtp.x" and sent["msg"] == "to@x.com" and sent["tls"] is True


def test_send_email_never_raises(monkeypatch):
    class _Boom:
        def __init__(self, *a, **k): raise OSError("connection refused")
    monkeypatch.setattr(notify.smtplib, "SMTP", _Boom)
    ok, why = notify.send_email("to@x.com", "s", "b", config={"host": "h", "port": 1})
    assert ok is False and "refused" in why


def test_send_slack_no_url():
    assert notify.send_slack("", "hi") is False
