from __future__ import annotations

import json

from coreline_auth.ops_readiness import ReadinessStatus, checks_to_json, checks_to_text, collect_readiness


def test_collect_readiness_marks_missing_and_ready_without_values() -> None:
    checks = collect_readiness(
        {
            "CORELINE_AUTH_GOOGLE_CLIENT_ID": "google-client-id",
            "CORELINE_AUTH_GOOGLE_CLIENT_SECRET": "super-secret-google-value",
            "CORELINE_AUTH_SMTP_HOST": "smtp.example.com",
            "CORELINE_AUTH_SMTP_FROM": "auth@example.com",
        }
    )
    by_key = {check.key: check for check in checks}

    assert by_key["google_oauth"].status == ReadinessStatus.READY
    assert by_key["smtp"].status == ReadinessStatus.READY
    assert by_key["facebook_oauth"].status == ReadinessStatus.MISSING
    assert "super-secret-google-value" not in checks_to_text(checks)
    assert "super-secret-google-value" not in checks_to_json(checks)


def test_readiness_json_is_machine_readable_and_secret_safe() -> None:
    output = checks_to_json(collect_readiness({"CORELINE_AUTH_REDIS_URL": "redis://:secret@localhost:6379/0"}))
    parsed = json.loads(output)

    assert isinstance(parsed, list)
    assert any(item["key"] == "redis_rate_limit" and item["ready"] is True for item in parsed)
    assert "redis://:secret" not in output


def test_webauthn_is_optional_until_rp_configured() -> None:
    checks = {check.key: check for check in collect_readiness({})}
    assert checks["webauthn_passkey"].status == ReadinessStatus.OPTIONAL

    ready = {check.key: check for check in collect_readiness({"CORELINE_AUTH_WEBAUTHN_RP_ID": "localhost", "CORELINE_AUTH_WEBAUTHN_ORIGIN": "http://localhost:8010"})}
    assert ready["webauthn_passkey"].status == ReadinessStatus.READY
