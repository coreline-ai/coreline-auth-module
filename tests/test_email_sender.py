from __future__ import annotations

from coreline_auth import EmailTemplate, EmailTemplateSet, SmtpEmailSender


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
