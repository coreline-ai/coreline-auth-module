"""Email delivery interfaces and simple production sender."""

from __future__ import annotations

import smtplib
import ssl
from html import escape as html_escape
from dataclasses import dataclass
from email.message import EmailMessage
from string import Template
from typing import Protocol
from urllib.parse import quote, urlencode

from .errors import AuthValidationError
from .security import normalize_email_address


class EmailSender(Protocol):
    def send_magic_link(self, *, email: str, token: str, return_to: str) -> None: ...
    def send_email_verification(self, *, email: str, token: str) -> None: ...
    def send_password_reset(self, *, email: str, token: str) -> None: ...


@dataclass(frozen=True, slots=True)
class SentMagicLink:
    email: str
    token: str
    return_to: str


@dataclass(frozen=True, slots=True)
class SentEmailVerification:
    email: str
    token: str


@dataclass(frozen=True, slots=True)
class SentPasswordReset:
    email: str
    token: str


@dataclass(frozen=True, slots=True)
class EmailTemplate:
    subject: str
    text_body: str
    html_body: str | None = None

    def render(self, **values: str) -> "RenderedEmail":
        return RenderedEmail(
            subject=Template(self.subject).safe_substitute(values),
            text_body=Template(self.text_body).safe_substitute(values),
            html_body=Template(self.html_body).safe_substitute(values) if self.html_body is not None else None,
        )


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    subject: str
    text_body: str
    html_body: str | None = None


def _auth_url(base_url: str, path: str, params: dict[str, str]) -> str:
    return f"{base_url}{path}?{urlencode(params)}"


@dataclass(frozen=True, slots=True)
class EmailTemplateSet:
    magic_link: EmailTemplate = EmailTemplate(
        subject="Your Coreline sign-in link",
        text_body="Use this link to sign in: ${magic_link_url}\n\nIf you did not request this, ignore this email.",
        html_body="<p>Use this link to sign in:</p><p><a href='${magic_link_url_html}'>Sign in</a></p><p>If you did not request this, ignore this email.</p>",
    )
    email_verification: EmailTemplate = EmailTemplate(
        subject="Verify your Coreline email",
        text_body="Verify your email: ${email_verification_url}\n\nIf you did not create an account, ignore this email.",
        html_body="<p>Verify your email:</p><p><a href='${email_verification_url_html}'>Verify email</a></p><p>If you did not create an account, ignore this email.</p>",
    )
    password_reset: EmailTemplate = EmailTemplate(
        subject="Reset your Coreline password",
        text_body="Reset your password: ${password_reset_url}\n\nIf you did not request this, ignore this email.",
        html_body="<p>Reset your password:</p><p><a href='${password_reset_url_html}'>Reset password</a></p><p>If you did not request this, ignore this email.</p>",
    )


class InMemoryEmailSender:
    """Test/dev sender that captures auth lifecycle emails in memory."""

    def __init__(self) -> None:
        self.sent_magic_links: list[SentMagicLink] = []
        self.sent_email_verifications: list[SentEmailVerification] = []
        self.sent_password_resets: list[SentPasswordReset] = []

    def send_magic_link(self, *, email: str, token: str, return_to: str) -> None:
        self.sent_magic_links.append(SentMagicLink(email=email, token=token, return_to=return_to))

    def send_email_verification(self, *, email: str, token: str) -> None:
        self.sent_email_verifications.append(SentEmailVerification(email=email, token=token))

    def send_password_reset(self, *, email: str, token: str) -> None:
        self.sent_password_resets.append(SentPasswordReset(email=email, token=token))


class SmtpEmailSender:
    """Small SMTP sender using stdlib only.

    It keeps Coreline Auth deployable without a vendor SDK. Applications can swap
    this for SendGrid/SES/etc. by implementing ``EmailSender``.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int = 587,
        username: str | None = None,
        password: str | None = None,
        from_email: str,
        base_url: str,
        use_tls: bool = True,
        use_ssl: bool = False,
        timeout_seconds: float = 10.0,
        templates: EmailTemplateSet | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not host:
            raise ValueError("SMTP host is required")
        try:
            normalized_from_email = normalize_email_address(from_email)
        except AuthValidationError as exc:
            raise ValueError("valid from_email is required") from exc
        if not normalized_from_email:
            raise ValueError("valid from_email is required")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an absolute http(s) URL")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = normalized_from_email
        self.base_url = base_url.rstrip("/")
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.timeout_seconds = timeout_seconds
        self.templates = templates or EmailTemplateSet()
        self.ssl_context = ssl_context or ssl.create_default_context()

    def send_magic_link(self, *, email: str, token: str, return_to: str) -> None:
        magic_link_url = _auth_url(self.base_url, "/magic-link/consume", {"token": token, "return_to": return_to})
        rendered = self.templates.magic_link.render(
            base_url=self.base_url,
            token=token,
            token_html=html_escape(token, quote=True),
            return_to=return_to,
            return_to_url=quote(return_to, safe=""),
            return_to_html=html_escape(return_to, quote=True),
            magic_link_url=magic_link_url,
            magic_link_url_html=html_escape(magic_link_url, quote=True),
        )
        self._send(email=email, rendered=rendered)

    def send_email_verification(self, *, email: str, token: str) -> None:
        email_verification_url = _auth_url(self.base_url, "/email-verification/consume", {"token": token})
        rendered = self.templates.email_verification.render(
            base_url=self.base_url,
            token=token,
            token_html=html_escape(token, quote=True),
            email_verification_url=email_verification_url,
            email_verification_url_html=html_escape(email_verification_url, quote=True),
        )
        self._send(email=email, rendered=rendered)

    def send_password_reset(self, *, email: str, token: str) -> None:
        password_reset_url = _auth_url(self.base_url, "/password-reset/consume", {"token": token})
        rendered = self.templates.password_reset.render(
            base_url=self.base_url,
            token=token,
            token_html=html_escape(token, quote=True),
            password_reset_url=password_reset_url,
            password_reset_url_html=html_escape(password_reset_url, quote=True),
        )
        self._send(email=email, rendered=rendered)

    def _send(self, *, email: str, rendered: RenderedEmail) -> None:
        to_email = normalize_email_address(email)
        message = EmailMessage()
        message["From"] = self.from_email
        message["To"] = to_email
        message["Subject"] = rendered.subject
        message.set_content(rendered.text_body)
        if rendered.html_body is not None:
            message.add_alternative(rendered.html_body, subtype="html")

        if self.use_ssl:
            smtp_context = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout_seconds, context=self.ssl_context)
        else:
            smtp_context = smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds)

        with smtp_context as smtp:
            if self.use_tls and not self.use_ssl:
                smtp.starttls(context=self.ssl_context)
            if self.username is not None:
                smtp.login(self.username, self.password or "")
            smtp.send_message(message)
