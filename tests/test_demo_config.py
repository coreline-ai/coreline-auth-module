from __future__ import annotations

from coreline_auth.examples.saas_demo.config import load_demo_settings


def test_demo_csrf_secret_persists_across_reload_when_env_absent(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("CORELINE_AUTH_DEMO_CSRF_SECRET", raising=False)
    monkeypatch.setenv("CORELINE_AUTH_DEMO_DB", str(tmp_path / "auth.sqlite3"))

    first = load_demo_settings()
    second = load_demo_settings()

    assert first.csrf_secret == second.csrf_secret
    assert (tmp_path / "csrf.secret").exists()
    assert not first.csrf_secret_configured


def test_demo_csrf_secret_env_override_wins(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CORELINE_AUTH_DEMO_DB", str(tmp_path / "auth.sqlite3"))
    monkeypatch.setenv("CORELINE_AUTH_DEMO_CSRF_SECRET", "configured-secret-value-with-32-chars")

    settings = load_demo_settings()

    assert settings.csrf_secret == "configured-secret-value-with-32-chars"
    assert settings.csrf_secret_configured
    assert not (tmp_path / "csrf.secret").exists()
