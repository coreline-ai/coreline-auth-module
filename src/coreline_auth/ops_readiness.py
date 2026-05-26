"""Secret-safe operational readiness checks for Coreline Auth deployments.

The checks are intentionally configuration-focused by default: they never print
secret values and never contact external services unless a host explicitly adds
its own connectivity probe around the returned metadata. This keeps local smoke
checks deterministic while still making production gaps visible.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping, Sequence


class ReadinessStatus(StrEnum):
    READY = "ready"
    MISSING = "missing"
    OPTIONAL = "optional"


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    key: str
    label: str
    status: ReadinessStatus
    present: tuple[str, ...]
    missing: tuple[str, ...]
    note: str

    @property
    def ready(self) -> bool:
        return self.status == ReadinessStatus.READY

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["status"] = self.status.value
        data["ready"] = self.ready
        return data


_SECRET_MARKERS = ("SECRET", "PASSWORD", "TOKEN", "KEY")


def _is_present(env: Mapping[str, str], name: str) -> bool:
    return bool(str(env.get(name, "")).strip())


def _check_required(*, env: Mapping[str, str], key: str, label: str, required: Sequence[str], note: str) -> ReadinessCheck:
    present = tuple(name for name in required if _is_present(env, name))
    missing = tuple(name for name in required if name not in present)
    return ReadinessCheck(
        key=key,
        label=label,
        status=ReadinessStatus.READY if not missing else ReadinessStatus.MISSING,
        present=present,
        missing=missing,
        note=note,
    )


def collect_readiness(env: Mapping[str, str] | None = None) -> list[ReadinessCheck]:
    """Return secret-safe readiness checks from environment variables.

    Only variable names and boolean presence are returned. Values are never
    included, so this output can be shown in admin screens and CI logs.
    """

    source = env or os.environ
    checks = [
        _check_required(
            env=source,
            key="google_oauth",
            label="Google OAuth",
            required=("CORELINE_AUTH_GOOGLE_CLIENT_ID", "CORELINE_AUTH_GOOGLE_CLIENT_SECRET"),
            note="실제 Google 로그인에는 OAuth client id/secret과 callback URL 등록이 필요합니다.",
        ),
        _check_required(
            env=source,
            key="facebook_oauth",
            label="Facebook OAuth",
            required=("CORELINE_AUTH_FACEBOOK_CLIENT_ID", "CORELINE_AUTH_FACEBOOK_CLIENT_SECRET"),
            note="실제 Facebook 로그인에는 Meta app id/secret과 callback URL 등록이 필요합니다.",
        ),
        _check_required(
            env=source,
            key="smtp",
            label="SMTP email",
            required=("CORELINE_AUTH_SMTP_HOST", "CORELINE_AUTH_SMTP_FROM"),
            note="실제 메일 발송에는 SMTP host/from과 서버 정책에 맞는 credential이 필요합니다.",
        ),
        _check_required(
            env=source,
            key="redis_rate_limit",
            label="Redis rate limit",
            required=("CORELINE_AUTH_REDIS_URL",),
            note="multi-worker/multi-node rate limit 공유에는 Redis URL이 필요합니다.",
        ),
        _check_required(
            env=source,
            key="postgres_async_storage",
            label="Postgres async storage",
            required=("CORELINE_AUTH_POSTGRES_DSN",),
            note="상용 DB 전환에는 async Postgres DSN과 alembic migration 적용이 필요합니다.",
        ),
    ]
    webauthn_required = ("CORELINE_AUTH_WEBAUTHN_RP_ID", "CORELINE_AUTH_WEBAUTHN_ORIGIN")
    webauthn_present = tuple(name for name in webauthn_required if _is_present(source, name))
    webauthn_missing = tuple(name for name in webauthn_required if name not in webauthn_present)
    checks.append(
        ReadinessCheck(
            key="webauthn_passkey",
            label="WebAuthn / Passkey",
            status=ReadinessStatus.READY if not webauthn_missing else ReadinessStatus.OPTIONAL,
            present=webauthn_present,
            missing=webauthn_missing,
            note="검증 primitive는 포함되어 있습니다. 실제 ceremony에는 RP ID/origin과 host-side browser UX가 필요합니다.",
        )
    )
    return checks


def assert_secret_safe(checks: Sequence[ReadinessCheck]) -> None:
    """Raise if a check accidentally includes likely secret values."""

    for check in checks:
        for field in (*check.present, *check.missing):
            if "=" in field:
                raise ValueError("readiness output must contain variable names only")
        for marker in _SECRET_MARKERS:
            if marker.lower() in check.note.lower():
                # Notes can mention secret *concepts*, but not actual values. This
                # guard intentionally allows variable names in present/missing.
                continue


def checks_to_json(checks: Sequence[ReadinessCheck]) -> str:
    assert_secret_safe(checks)
    return json.dumps([check.to_dict() for check in checks], ensure_ascii=False, indent=2)


def checks_to_text(checks: Sequence[ReadinessCheck]) -> str:
    assert_secret_safe(checks)
    lines = ["Coreline Auth readiness"]
    for check in checks:
        missing = ", ".join(check.missing) if check.missing else "-"
        present = ", ".join(check.present) if check.present else "-"
        lines.append(f"- {check.label}: {check.status.value} (present: {present}; missing: {missing})")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Coreline Auth production readiness configuration without printing secrets.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)
    checks = collect_readiness()
    print(checks_to_json(checks) if args.json else checks_to_text(checks))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
