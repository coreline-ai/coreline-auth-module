from __future__ import annotations

import pytest

from coreline_auth import AuthValidationError, EmailTemplate, EmailTemplateSet, SmtpEmailSender


class FakeSMTP:
    sent_messages = []
    calls = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        FakeSMTP.calls.append(("connect", host, port, timeout))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def starttls(self, context=None) -> None:
        FakeSMTP.calls.append(("starttls", context is not None))

    def login(self, username: str, password: str) -> None:
        FakeSMTP.calls.append(("login", username, password))

    def send_message(self, message) -> None:
        FakeSMTP.sent_messages.append(message)


def test_template_rendering_is_safe_substitution() -> None:
    rendered = EmailTemplate(subject="Hello ${name}", text_body="Token ${token} ${missing}").render(name="A", token="T")
    assert rendered.subject == "Hello A"
    assert rendered.text_body == "Token T ${missing}"


def test_smtp_sender_sends_magic_link_with_templates(monkeypatch) -> None:
    FakeSMTP.sent_messages.clear()
    FakeSMTP.calls.clear()
    monkeypatch.setattr("coreline_auth.email.smtplib.SMTP", FakeSMTP)

    sender = SmtpEmailSender(
        host="smtp.example.com",
        port=587,
        username="smtp-user",
        password="smtp-password",
        from_email="auth@example.com",
        base_url="https://auth.example.com/",
        templates=EmailTemplateSet(magic_link=EmailTemplate(subject="Sign in", text_body="Token=${token} Return=${return_to}")),
    )
    sender.send_magic_link(email="user@example.com", token="raw-dev-token", return_to="/dashboard")

    assert ("connect", "smtp.example.com", 587, 10.0) in FakeSMTP.calls
    assert ("starttls", True) in FakeSMTP.calls
    assert ("login", "smtp-user", "smtp-password") in FakeSMTP.calls
    message = FakeSMTP.sent_messages[-1]
    assert message["From"] == "auth@example.com"
    assert message["To"] == "user@example.com"
    assert message["Subject"] == "Sign in"
    assert "Token=raw-dev-token Return=/dashboard" in message.get_content()


def test_smtp_sender_rejects_invalid_sender_and_recipient(monkeypatch) -> None:
    FakeSMTP.sent_messages.clear()
    FakeSMTP.calls.clear()
    monkeypatch.setattr("coreline_auth.email.smtplib.SMTP", FakeSMTP)

    with pytest.raises(ValueError):
        SmtpEmailSender(host="smtp.example.com", from_email="auth\r\n@example.com", base_url="https://auth.example.com")

    sender = SmtpEmailSender(host="smtp.example.com", from_email="AUTH@EXAMPLE.COM", base_url="https://auth.example.com", use_tls=False)
    with pytest.raises(AuthValidationError):
        sender.send_magic_link(email="victim@example.com\r\nBcc: attacker@example.com", token="raw-dev-token", return_to="/dashboard")
    assert FakeSMTP.sent_messages == []
    assert sender.from_email == "auth@example.com"


def test_smtp_sender_default_magic_link_template_url_and_html_escape_return_to(monkeypatch) -> None:
    FakeSMTP.sent_messages.clear()
    FakeSMTP.calls.clear()
    monkeypatch.setattr("coreline_auth.email.smtplib.SMTP", FakeSMTP)

    sender = SmtpEmailSender(host="smtp.example.com", from_email="auth@example.com", base_url="https://auth.example.com", use_tls=False)
    sender.send_magic_link(email="user@example.com", token="dev-token", return_to="/dashboard?next=/' onclick='alert(1)&x=<tag>")

    message = FakeSMTP.sent_messages[-1]
    text = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()

    assert "%27+onclick%3D%27alert%281%29" in text
    assert "%3Ctag%3E" in text
    assert "&amp;return_to=" in html
    assert "' onclick='" not in html
    assert "<tag>" not in html


class FakeSMTPSSL(FakeSMTP):
    def __init__(self, host: str, port: int, timeout: float, context=None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        FakeSMTP.calls.append(("connect_ssl", host, port, timeout, context is not None))


def test_smtp_sender_supports_direct_smtps_with_context(monkeypatch) -> None:
    FakeSMTP.sent_messages.clear()
    FakeSMTP.calls.clear()
    monkeypatch.setattr("coreline_auth.email.smtplib.SMTP_SSL", FakeSMTPSSL)

    sender = SmtpEmailSender(host="smtp.example.com", port=465, from_email="auth@example.com", base_url="https://auth.example.com", use_tls=False, use_ssl=True)
    sender.send_password_reset(email="user@example.com", token="reset-token")

    assert ("connect_ssl", "smtp.example.com", 465, 10.0, True) in FakeSMTP.calls
    assert not any(call[0] == "starttls" for call in FakeSMTP.calls)
    assert FakeSMTP.sent_messages[-1]["To"] == "user@example.com"
