"""A complete but small SaaS-style web app for self-testing Coreline Auth.

Run:
  cd packages/coreline-auth
  uv run uvicorn coreline_auth.examples.saas_app:app --reload --port 8010

Default admin login:
  owner@example.com / CORELINE_AUTH_DEMO_OWNER_PASSWORD default

This demo also supports local email/password signup. Google/Facebook links start
real OAuth when provider credentials are configured, and otherwise use the
development social connector for local end-to-end testing.
"""

from __future__ import annotations

import html
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from coreline_auth import AuditEvent, AuthProfile, AuthSession, AuthUser, AuthenticationFailed, CorelineAdminService, CorelineAuthConfig, CorelineAuthService, CsrfProtector, DevSocialConnector, EmailTemplateSet, FacebookOAuthConnector, GoogleOAuthConnector, InMemoryEmailSender, JWKSCache, OAuthPKCE, OIDCMetadataClient, Role, discover_oidc_metadata
from coreline_auth.fastapi_adapter import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, mount_admin_routes, mount_auth_routes, request_context
from coreline_auth.storage import SQLiteAuthStorage
from coreline_auth.examples.saas_demo.config import load_demo_settings
from coreline_auth.examples.saas_demo.csrf import csrf_token_for_page, demo_csrf_middleware
from coreline_auth.examples.saas_demo.layout import render_page
from coreline_auth.models import UserStatus, now_utc
from coreline_auth.ops_readiness import collect_readiness
from coreline_auth.security import generate_token, hash_secret, verify_password

settings = load_demo_settings()
OWNER_EMAIL = settings.owner_email
OWNER_PASSWORD = settings.owner_password
DB_PATH = settings.db_path
DEMO_MODE = settings.demo_mode

storage = SQLiteAuthStorage(DB_PATH)
email_sender = InMemoryEmailSender()
audit_events: list[AuditEvent] = []
csrf = CsrfProtector(secret_key=settings.csrf_secret, allow_weak_dev_secret=DEMO_MODE and settings.csrf_secret_configured)
auth = CorelineAuthService(
    storage=storage,
    config=CorelineAuthConfig(profile=AuthProfile.RBAC, owner_email=None, require_email_verified=False),
    email_sender=email_sender,
    audit_sink=audit_events.append,
)
existing_owner = auth.storage.get_user_by_email(OWNER_EMAIL)
if existing_owner is None:
    auth.create_user(email=OWNER_EMAIL, role=Role.ADMIN, password=OWNER_PASSWORD, email_verified=True, display_name="Coreline Admin")
elif DEMO_MODE:
    # Keep the local self-test app recoverable even when a previous demo DB was
    # created with a different password during development.
    auth.set_password(existing_owner.id, OWNER_PASSWORD, revoke_sessions=False)

app = FastAPI(title="Coreline Auth Demo SaaS")
mount_auth_routes(app, auth, expose_magic_link_token=DEMO_MODE, secure_cookies=False, csrf_protector=csrf)
mount_admin_routes(app, auth, csrf_protector=csrf)
_oidc_jwks_caches: dict[str, JWKSCache] = {}


def page(title: str, body: str, *, public: bool = False) -> HTMLResponse:
    return render_page(
        title=title,
        body=body,
        csrf_token=csrf_token_for_page(csrf),
        public=public,
        demo_mode=DEMO_MODE,
    )


def safe_next_path(value: str | None, *, default: str = "/") -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\r" in value or "\n" in value:
        return default
    return value


def current_principal(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        return auth.verify_session(token)
    except AuthenticationFailed:
        return None


LOGIN_AUDIT_ACTIONS = {"auth.login.password", "auth.magic_link.consume", "auth.login.social"}
ROLE_DASHBOARD_ORDER = (Role.OWNER, Role.ADMIN, Role.USER, Role.VIEWER)
ROLE_DESCRIPTIONS = {
    Role.OWNER: "전체 시스템 권한과 최종 소유권을 가진 계정",
    Role.ADMIN: "사용자, 권한, 감사 로그를 관리하는 운영 관리자",
    Role.USER: "대시보드와 자기 계정 기능을 사용하는 일반 사용자",
    Role.VIEWER: "대시보드와 운영 상태를 읽기만 하는 조회 전용 사용자",
}
PERMISSION_MATRIX = (
    ("프로필", "profile:read"),
    ("대시보드", "dashboard:read"),
    ("서비스", "services:read"),
    ("사용자 조회", "users:read"),
    ("감사 로그", "audit:read"),
)


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _compact_hash(value: str | None, *, length: int = 12) -> str:
    if not value:
        return "—"
    return value[:length]


def _safe_fragment(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value)


def _metadata_preview(metadata: dict[str, Any], *, limit: int = 120) -> str:
    if not metadata:
        return "—"
    preview = str(metadata)
    if len(preview) > limit:
        preview = preview[: limit - 1] + "…"
    return preview


def _user_activity_events(user_id: str) -> list[AuditEvent]:
    by_key: dict[tuple[str, str, str | None, str | None, str], AuditEvent] = {}
    for event in [
        *auth.list_audit_events(actor_user_id=user_id, limit=100),
        *auth.list_audit_events(target_user_id=user_id, limit=100),
    ]:
        key = (
            event.action,
            event.created_at.isoformat(),
            event.actor_user_id,
            event.target_user_id,
            str(sorted(event.metadata.items())),
        )
        by_key[key] = event
    return sorted(by_key.values(), key=lambda item: item.created_at, reverse=True)


def _session_is_active(session: AuthSession) -> bool:
    now = datetime.now(timezone.utc)
    return (
        session.revoked_at is None
        and session.expires_at > now
        and (session.idle_expires_at is None or session.idle_expires_at > now)
    )


def _render_user_activity_card(user: AuthUser, *, sessions: list[AuthSession], events: list[AuditEvent]) -> str:
    fragment = f"user-card-{_safe_fragment(user.id)}"
    login_events = [event for event in events if event.action in LOGIN_AUDIT_ACTIONS]
    logout_events = [event for event in events if event.action == "auth.logout"]
    active_session_count = sum(1 for session in sessions if _session_is_active(session))
    latest_login = max((event.created_at for event in login_events), default=user.last_login_at)
    latest_logout = max((event.created_at for event in logout_events), default=None)

    metric_items = [
        ("로그인 횟수", str(len(login_events))),
        ("활성 세션", str(active_session_count)),
        ("마지막 로그인", _format_datetime(latest_login)),
        ("마지막 로그아웃", _format_datetime(latest_logout)),
    ]
    metrics = "".join(
        f"<div class='activity-metric'><span>{html.escape(label)}</span><b>{html.escape(value)}</b></div>"
        for label, value in metric_items
    )

    session_rows = "".join(
        f"""<tr><td><code>{html.escape(_compact_hash(session.id, length=10))}</code></td><td>{html.escape(session.provider or '—')}</td><td>{html.escape(session.assurance_level.value)}</td><td>{html.escape(_format_datetime(session.created_at))}</td><td>{html.escape(_format_datetime(session.last_seen_at))}</td><td>{html.escape(_format_datetime(session.revoked_at))}</td><td>{html.escape(_format_datetime(session.expires_at))}</td><td><code>{html.escape(_compact_hash(session.user_agent_hash))}</code></td><td><code>{html.escape(_compact_hash(session.ip_hash))}</code></td></tr>"""
        for session in sorted(sessions, key=lambda item: item.created_at, reverse=True)[:12]
    ) or "<tr><td colspan='9'>세션 기록이 없습니다.</td></tr>"

    event_rows = "".join(
        f"""<tr><td>{html.escape(_format_datetime(event.created_at))}</td><td><code>{html.escape(event.action)}</code></td><td><code>{html.escape(event.actor_user_id or '-')}</code></td><td><code>{html.escape(event.target_user_id or '-')}</code></td><td><code>{html.escape(_metadata_preview(event.metadata))}</code></td></tr>"""
        for event in events[:16]
    ) or "<tr><td colspan='5'>개인 활동 이벤트가 없습니다.</td></tr>"

    return f"""
    <section id='{html.escape(fragment)}' class='user-popover' aria-label='개인 로그인 정보'>
      <a class='user-popover-backdrop' href='#admin-users' aria-label='닫기'></a>
      <article class='user-popover-card'>
        <div class='section-toolbar'>
          <div>
            <p class='muted'>개인 로그인 정보</p>
            <h2>{html.escape(user.primary_email)}</h2>
            <p class='muted'>사용자 ID <code>{html.escape(user.id)}</code> · 가입 {html.escape(_format_datetime(user.created_at))} · 업데이트 {html.escape(_format_datetime(user.updated_at))}</p>
          </div>
          <a class='button secondary' href='#admin-users'>닫기</a>
        </div>
        <div class='activity-metrics'>{metrics}</div>
        <div class='grid'>
          <section>
            <h3>계정 상태</h3>
            <p><span class='pill'>role</span> {html.escape(user.role.value)} <span class='pill'>status</span> {html.escape(user.status.value)} <span class='pill'>email verified</span> {html.escape(str(user.primary_email_verified))}</p>
            <p class='muted'>표시 이름: {html.escape(user.display_name or '—')}</p>
          </section>
          <section>
            <h3>활동 요약</h3>
            <p class='muted'>로그인·로그아웃·관리자 변경·MFA·비밀번호·이메일 검증 이벤트를 최근순으로 합산합니다.</p>
          </section>
        </div>
        <h3>세션 타임라인</h3>
        <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Session</th><th>Provider</th><th>AAL</th><th>생성</th><th>마지막 활동</th><th>로그아웃 시간</th><th>만료</th><th>UA hash</th><th>IP hash</th></tr></thead><tbody>{session_rows}</tbody></table></div>
        <h3>개인 활동 로그</h3>
        <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Metadata</th></tr></thead><tbody>{event_rows}</tbody></table></div>
      </article>
    </section>
    """


def _login_events(events: list[AuditEvent]) -> list[AuditEvent]:
    return [event for event in events if event.action in LOGIN_AUDIT_ACTIONS]


def _last_activity_at(*, user: AuthUser, sessions: list[AuthSession], events: list[AuditEvent]) -> datetime | None:
    candidates = [
        user.updated_at,
        *(session.last_seen_at for session in sessions if session.last_seen_at is not None),
        *(event.created_at for event in events),
    ]
    return max(candidates) if candidates else None


def _render_admin_kpis(
    *,
    users: list[AuthUser],
    sessions_by_user: dict[str, list[AuthSession]],
    events_by_user: dict[str, list[AuditEvent]],
) -> str:
    sessions = [session for per_user in sessions_by_user.values() for session in per_user]
    active_users = sum(1 for user in users if user.status == UserStatus.ACTIVE)
    active_sessions = sum(1 for session in sessions if _session_is_active(session))
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_logins = sum(1 for events in events_by_user.values() for event in _login_events(events) if event.created_at >= since)
    verified = sum(1 for user in users if user.primary_email_verified)
    cards = [
        ("전체 가입자", str(len(users)), "필터와 관계없는 전체 사용자 수"),
        ("활성 사용자", str(active_users), "status=active 계정"),
        ("활성 세션", str(active_sessions), "만료/로그아웃되지 않은 세션"),
        ("최근 24h 로그인", str(recent_logins), "audit auth.login.* 기준"),
        ("이메일 인증률", f"{verified}/{len(users)}", "verified / total"),
    ]
    return "".join(
        f"<article class='admin-stat'><span>{html.escape(label)}</span><b>{html.escape(value)}</b><p>{html.escape(note)}</p></article>"
        for label, value, note in cards
    )


def _role_summary(
    *,
    role: Role,
    users: list[AuthUser],
    sessions_by_user: dict[str, list[AuthSession]],
    events_by_user: dict[str, list[AuditEvent]],
) -> dict[str, Any]:
    role_users = [user for user in users if user.role == role]
    role_sessions = [session for user in role_users for session in sessions_by_user.get(user.id, [])]
    role_events = [event for user in role_users for event in events_by_user.get(user.id, [])]
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    last_activity = max(
        (
            _last_activity_at(user=user, sessions=sessions_by_user.get(user.id, []), events=events_by_user.get(user.id, []))
            for user in role_users
        ),
        default=None,
    )
    return {
        "role": role,
        "users": role_users,
        "user_count": len(role_users),
        "active_sessions": sum(1 for session in role_sessions if _session_is_active(session)),
        "login_count_24h": sum(1 for event in _login_events(role_events) if event.created_at >= since),
        "last_activity": last_activity,
    }


def _render_role_cards(
    *,
    users: list[AuthUser],
    sessions_by_user: dict[str, list[AuthSession]],
    events_by_user: dict[str, list[AuditEvent]],
    selected_role: str,
) -> str:
    parts: list[str] = []
    for role_item in ROLE_DASHBOARD_ORDER:
        summary = _role_summary(role=role_item, users=users, sessions_by_user=sessions_by_user, events_by_user=events_by_user)
        members = ", ".join(user.primary_email for user in summary["users"][:3])
        if summary["user_count"] > 3:
            members += f" 외 {summary['user_count'] - 3}명"
        if not members:
            members = "아직 배정된 사용자가 없습니다."
        active_class = " active" if selected_role == role_item.value else ""
        parts.append(
            f"""<a class='role-card{active_class}' href='/admin?role={html.escape(role_item.value)}#admin-users'>
              <div class='role-card-top'><h3>{html.escape(role_item.value)}</h3><b>{summary['user_count']}명</b></div>
              <p>{html.escape(ROLE_DESCRIPTIONS[role_item])}</p>
              <div class='role-card-metrics'><span>활성 세션 {summary['active_sessions']}</span><span>24h 로그인 {summary['login_count_24h']}</span></div>
              <p class='role-members'>{html.escape(members)}</p>
            </a>"""
        )
    return "".join(parts)


def _render_role_activity_table(
    *,
    users: list[AuthUser],
    sessions_by_user: dict[str, list[AuthSession]],
    events_by_user: dict[str, list[AuditEvent]],
) -> str:
    rows = "".join(
        f"""<tr><td><code>{html.escape(role_item.value)}</code></td><td>{summary['user_count']}</td><td>{summary['active_sessions']}</td><td>{summary['login_count_24h']}</td><td>{html.escape(_format_datetime(summary['last_activity']))}</td><td>{html.escape(', '.join(user.primary_email for user in summary['users'][:4]) or '—')}</td></tr>"""
        for role_item in ROLE_DASHBOARD_ORDER
        for summary in [_role_summary(role=role_item, users=users, sessions_by_user=sessions_by_user, events_by_user=events_by_user)]
    )
    return f"<div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Role</th><th>Users</th><th>Active Sessions</th><th>Logins 24h</th><th>Last Activity</th><th>Members</th></tr></thead><tbody>{rows}</tbody></table></div>"


def _render_permission_matrix() -> str:
    header = "".join(f"<th>{html.escape(label)}</th>" for label, _ in PERMISSION_MATRIX)
    rows: list[str] = []
    for role_item in ROLE_DASHBOARD_ORDER:
        permissions = auth.policy.permissions_for(role=role_item)
        cells = "".join(
            f"<td>{'✅' if auth.policy.allows(permissions, permission) else '—'}</td>"
            for _, permission in PERMISSION_MATRIX
        )
        rows.append(f"<tr><td><code>{html.escape(role_item.value)}</code></td>{cells}</tr>")
    return f"<div class='activity-table-wrap'><table class='activity-table permission-matrix'><thead><tr><th>Role</th>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"


def _render_permission_chips(permissions: tuple[str, ...]) -> str:
    if not permissions:
        return "<span class='pill'>권한 없음</span>"
    return "".join(f"<span class='permission-chip'>{html.escape(permission)}</span>" for permission in permissions)


def _stat_value_class(value: str) -> str:
    return " class='long-value'" if "UTC" in value or len(value) > 16 else ""


def _render_my_dashboard(principal) -> str:
    user = principal.user
    session = principal.session
    sessions = auth.storage.list_sessions_for_user(user.id)
    events = _user_activity_events(user.id)
    login_events = _login_events(events)
    logout_events = [event for event in events if event.action == "auth.logout"]
    active_session_count = sum(1 for item in sessions if _session_is_active(item))
    latest_login = max((event.created_at for event in login_events), default=user.last_login_at)
    latest_logout = max((event.created_at for event in logout_events), default=None)
    can_admin = auth.policy.allows(session.permissions, "users:read")
    metric_items = [
        ("내 role", session.role.value, ROLE_DESCRIPTIONS.get(session.role, "현재 로그인 role")),
        ("활성 세션", str(active_session_count), "내 계정의 현재 유효 세션"),
        ("로그인 횟수", str(len(login_events)), "감사 로그 auth.login.* 기준"),
        ("마지막 로그인", _format_datetime(latest_login), "최근 로그인 시간"),
        ("마지막 로그아웃", _format_datetime(latest_logout), "최근 로그아웃 시간"),
    ]
    metrics = "".join(
        f"<article class='admin-stat'><span>{html.escape(label)}</span><b{_stat_value_class(value)}>{html.escape(value)}</b><p>{html.escape(note)}</p></article>"
        for label, value, note in metric_items
    )
    current_session_rows = f"""<tr><td><code>{html.escape(_compact_hash(session.id, length=10))}</code></td><td>{html.escape(session.provider or '—')}</td><td>{html.escape(session.assurance_level.value)}</td><td>{html.escape(_format_datetime(session.created_at))}</td><td>{html.escape(_format_datetime(session.last_seen_at))}</td><td>{html.escape(_format_datetime(session.idle_expires_at))}</td><td>{html.escape(_format_datetime(session.expires_at))}</td></tr>"""
    recent_event_rows = "".join(
        f"""<tr><td>{html.escape(_format_datetime(event.created_at))}</td><td><code>{html.escape(event.action)}</code></td><td><code>{html.escape(_metadata_preview(event.metadata))}</code></td></tr>"""
        for event in events[:8]
    ) or "<tr><td colspan='3'>아직 개인 활동 이벤트가 없습니다.</td></tr>"
    admin_link = "<a class='button secondary' href='/admin'>관리자 대시보드</a>" if can_admin else "<a class='button secondary' href='/admin'>관리자 접근 테스트</a>"
    return f"""
    <section class='card'>
      <div class='section-toolbar'>
        <div>
          <h2>내 계정 요약</h2>
          <p class='muted'>일반 사용자도 자신의 계정, 권한, 세션, 최근 활동을 GUI 카드로 확인할 수 있습니다.</p>
        </div>
        <span class='pill'>{html.escape(user.status.value)}</span>
      </div>
      <div class='profile-hero'>
        <div class='profile-avatar'>{html.escape((user.display_name or user.primary_email or '?')[:1].upper())}</div>
        <div>
          <h3>{html.escape(user.display_name or user.primary_email)}</h3>
          <p class='muted'>{html.escape(user.primary_email)} · user id <code>{html.escape(user.id)}</code></p>
          <p><span class='pill'>email verified</span> {html.escape(str(user.primary_email_verified))} <span class='pill'>created</span> {html.escape(_format_datetime(user.created_at))}</p>
        </div>
      </div>
      <div class='admin-stat-grid'>{metrics}</div>
    </section>
    <section class='card'>
      <h2>내 권한</h2>
      <p class='muted'>현재 세션에 부여된 permission입니다. 실제 서버 권한 검사는 이 값과 정책 엔진 기준으로 수행됩니다.</p>
      <div class='permission-chip-list'>{_render_permission_chips(session.permissions)}</div>
    </section>
    <section class='card'>
      <h2>현재 세션</h2>
      <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Session</th><th>Provider</th><th>AAL</th><th>생성</th><th>마지막 활동</th><th>Idle 만료</th><th>절대 만료</th></tr></thead><tbody>{current_session_rows}</tbody></table></div>
    </section>
    <section class='card'>
      <h2>내 최근 활동</h2>
      <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Time</th><th>Action</th><th>Metadata</th></tr></thead><tbody>{recent_event_rows}</tbody></table></div>
      <div class='nav'>{admin_link}<a class='button secondary' href='/account'>내 계정</a><form method='post' action='/logout' style='display:inline'><button class='danger'>로그아웃</button></form></div>
    </section>
    """


def _admin_forbidden_page(*, title: str, required_permission: str, token: str | None) -> HTMLResponse:
    current = None
    if token:
        try:
            current = auth.verify_session(token)
        except AuthenticationFailed:
            current = None
    current_role = current.session.role.value if current else "unknown"
    current_email = current.email if current else "로그인 정보 없음"
    response = page(
        title,
        f"""
        <section class='forbidden-overlay' aria-label='관리자 접근 금지'>
          <article class='forbidden-dialog'>
            <div class='forbidden-icon'>!</div>
            <p class='muted'>403 Forbidden</p>
            <h1>관리자 권한이 필요합니다</h1>
            <p>이 페이지는 관리자 권한이 있는 계정만 볼 수 있습니다. 현재 계정은 필요한 권한을 갖고 있지 않아 접근이 차단되었습니다.</p>
            <div class='forbidden-detail'>
              <span>현재 계정</span><b>{html.escape(current_email)}</b>
              <span>현재 role</span><code>{html.escape(current_role)}</code>
              <span>필요 권한</span><code>{html.escape(required_permission)}</code>
            </div>
            <div class='nav'>
              <a class='button' href='/'>대시보드로 돌아가기</a>
              <form method='post' action='/logout' style='display:inline'><button class='danger'>다른 계정으로 로그인</button></form>
            </div>
            <p class='muted'>테스트하려면 왼쪽 권한 계정에서 <code>owner</code> 또는 <code>admin</code> 계정으로 로그인하세요.</p>
          </article>
        </section>
        """,
    )
    response.status_code = 403
    return response


def _require_principal_response(request: Request):
    principal = current_principal(request)
    if principal is None:
        return None, RedirectResponse("/login", status_code=303)
    return principal, None


def _account_nav(active: str) -> str:
    items = [
        ("/account", "계정 정보", "profile"),
        ("/account/security", "보안", "security"),
        ("/account/sessions", "세션", "sessions"),
        ("/account/activity", "활동", "activity"),
    ]
    links = "".join(
        f"<a class='button{' secondary' if key != active else ''}' href='{href}'>{html.escape(label)}</a>"
        for href, label, key in items
    )
    return f"<div class='nav account-nav'>{links}</div>"


def _render_mfa_status(user_id: str) -> str:
    factors = auth.storage.list_mfa_factors(user_id)
    if not factors:
        return """
        <div class='notice'>
          <b>MFA 미등록</b>
          <p class='muted'>이 데모는 TOTP/Recovery/WebAuthn primitive를 보유하지만, 브라우저 ceremony는 별도 phase에서 연결합니다. 운영에서는 민감 작업 전 AAL2 step-up을 권장합니다.</p>
        </div>
        """
    rows = "".join(
        f"""<tr><td><code>{html.escape(factor.factor_type.value)}</code></td><td>{html.escape(factor.name)}</td><td>{html.escape(str(factor.enabled))}</td><td>{html.escape(_format_datetime(factor.created_at))}</td><td>{html.escape(_format_datetime(factor.last_used_at))}</td><td>{html.escape(str(factor.last_used_counter or '—'))}</td></tr>"""
        for factor in factors
    )
    return f"<div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Type</th><th>Name</th><th>Enabled</th><th>Created</th><th>Last Used</th><th>Counter</th></tr></thead><tbody>{rows}</tbody></table></div>"


def _render_session_rows(sessions: list[AuthSession], *, current_session_id: str | None = None, admin_actions: bool = False) -> str:
    rows: list[str] = []
    for session in sorted(sessions, key=lambda item: item.created_at, reverse=True):
        status = "active" if _session_is_active(session) else "inactive"
        current = " <span class='pill'>current</span>" if session.id == current_session_id else ""
        action = "—"
        if admin_actions:
            action = f"<form method='post' action='/admin/sessions/{html.escape(session.id)}/revoke'><button class='danger'>Revoke</button></form>"
        elif _session_is_active(session):
            label = "현재 세션 로그아웃" if session.id == current_session_id else "이 세션 종료"
            action = f"<form method='post' action='/account/sessions/{html.escape(session.id)}/revoke'><button class='danger'>{html.escape(label)}</button></form>"
        rows.append(
            f"""<tr><td><code>{html.escape(_compact_hash(session.id, length=10))}</code>{current}</td><td>{html.escape(status)}</td><td>{html.escape(session.provider or '—')}</td><td>{html.escape(session.assurance_level.value)}</td><td>{html.escape(_format_datetime(session.created_at))}</td><td>{html.escape(_format_datetime(session.last_seen_at))}</td><td>{html.escape(_format_datetime(session.revoked_at))}</td><td>{html.escape(_format_datetime(session.expires_at))}</td><td>{action}</td></tr>"""
        )
    return "".join(rows) or "<tr><td colspan='9'>세션이 없습니다.</td></tr>"


def _render_activity_rows(events: list[AuditEvent], *, limit: int = 50) -> str:
    return "".join(
        f"""<tr><td>{html.escape(_format_datetime(event.created_at))}</td><td><code>{html.escape(event.action)}</code></td><td><code>{html.escape(event.actor_user_id or '-')}</code></td><td><code>{html.escape(event.target_user_id or '-')}</code></td><td><code>{html.escape(_metadata_preview(event.metadata, limit=180))}</code></td></tr>"""
        for event in events[:limit]
    ) or "<tr><td colspan='5'>활동 이벤트가 없습니다.</td></tr>"


def _parse_filter_datetime(value: str) -> datetime | None:
    normalized = value.strip()
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("날짜는 ISO 형식으로 입력하세요. 예: 2026-05-26T09:00:00+00:00") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _password_change_error(message: str) -> HTMLResponse:
    return page(
        "Password change failed",
        f"<h1>보안</h1>{_account_nav('security')}<section class='card error'><h2>비밀번호 변경 실패</h2><p>{html.escape(message)}</p><a class='button secondary' href='/account/security'>보안 페이지로 돌아가기</a></section>",
    )


def _template_preview_rows() -> str:
    templates = EmailTemplateSet()
    values = {"base_url": "http://127.0.0.1:8010", "token": "demo-token-redacted", "return_to": "/"}
    items = [
        ("Magic link", templates.magic_link.render(**values)),
        ("Email verification", templates.email_verification.render(**values)),
        ("Password reset", templates.password_reset.render(**values)),
    ]
    return "".join(
        f"""<tr><td>{html.escape(name)}</td><td>{html.escape(rendered.subject)}</td><td><pre>{html.escape(rendered.text_body)}</pre></td><td><pre>{html.escape(rendered.html_body or '—')}</pre></td></tr>"""
        for name, rendered in items
    )


def _email_queue_rows() -> str:
    rows: list[str] = []
    for item in reversed(email_sender.sent_magic_links[-10:]):
        rows.append(f"<tr><td>magic_link</td><td>{html.escape(item.email)}</td><td><code>{html.escape(_token_fingerprint(item.token))}</code></td><td>{html.escape(item.return_to)}</td></tr>")
    for item in reversed(email_sender.sent_email_verifications[-10:]):
        rows.append(f"<tr><td>email_verification</td><td>{html.escape(item.email)}</td><td><code>{html.escape(_token_fingerprint(item.token))}</code></td><td>—</td></tr>")
    for item in reversed(email_sender.sent_password_resets[-10:]):
        rows.append(f"<tr><td>password_reset</td><td>{html.escape(item.email)}</td><td><code>{html.escape(_token_fingerprint(item.token))}</code></td><td>—</td></tr>")
    return "".join(rows) or "<tr><td colspan='4'>개발용 발송 큐가 비어 있습니다.</td></tr>"


def _token_fingerprint(token: str) -> str:
    return hash_secret(token)[:12]


def _readiness_rows() -> str:
    return "".join(
        f"<tr><td>{html.escape(check.label)}</td><td><span class='pill'>{html.escape(check.status.value)}</span></td><td>{html.escape(check.note)}</td></tr>"
        for check in collect_readiness()
    )


def _admin_context(request: Request, *, required_permission: str = "users:read"):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None, None, RedirectResponse("/login", status_code=303)
    try:
        principal = auth.verify_session(token, required_permission=required_permission)
    except Exception:
        return None, None, _admin_forbidden_page(title="관리자 접근 금지", required_permission=required_permission, token=token)
    return token, principal, None


def _same_site_referer_path(request: Request, *, default: str = "/admin") -> str:
    referer = request.headers.get("referer")
    if not referer:
        return default
    parsed = urlparse(referer)
    if parsed.scheme and parsed.netloc and parsed.netloc != request.url.netloc:
        return default
    path = parsed.path or default
    if not path.startswith("/") or path.startswith("//"):
        return default
    suffix = ""
    if parsed.query:
        suffix += f"?{parsed.query}"
    if parsed.fragment:
        suffix += f"#{parsed.fragment}"
    return path + suffix


app.middleware("http")(demo_csrf_middleware(csrf))

@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    principal = current_principal(request)
    if principal is None:
        return RedirectResponse("/login", status_code=303)
    my_dashboard = _render_my_dashboard(principal)
    return page(
        "Coreline Auth Dashboard",
        f"""
        <h1>Coreline Auth Demo</h1>
        <p class='muted'>가입, 로그인, 세션, 권한 보호 페이지를 검증하는 자체 테스트 앱입니다.</p>
        {my_dashboard}
        """,
    )


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, saved: str = ""):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    user = principal.user
    notice = "<div class='banner'>프로필이 저장되었습니다.</div>" if saved == "1" else ""
    return page(
        "Account",
        f"""
        <h1>내 계정</h1>
        {_account_nav('profile')}
        {notice}
        <section class='card'>
          <div class='profile-hero'>
            <div class='profile-avatar'>{html.escape((user.display_name or user.primary_email or '?')[:1].upper())}</div>
            <div>
              <h2>{html.escape(user.display_name or user.primary_email)}</h2>
              <p class='muted'>{html.escape(user.primary_email)} · <code>{html.escape(user.id)}</code></p>
              <p><span class='pill'>role</span> {html.escape(user.role.value)} <span class='pill'>status</span> {html.escape(user.status.value)} <span class='pill'>verified</span> {html.escape(str(user.primary_email_verified))}</p>
            </div>
          </div>
        </section>
        <section class='card'>
          <h2>프로필 수정</h2>
          <form method='post' action='/account/profile'>
            <label>Display name</label>
            <input name='display_name' type='text' maxlength='120' value='{html.escape(user.display_name or "", quote=True)}' placeholder='표시 이름'>
            <button>저장</button>
          </form>
        </section>
        """,
    )


@app.post("/account/profile")
def account_profile_update(request: Request, display_name: str = Form("")):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    normalized = display_name.strip()[:120] or None
    updated = replace(principal.user, display_name=normalized, updated_at=now_utc())
    auth.storage.update_user(updated)
    auth._audit("auth.account.profile_update", actor_user_id=principal.user_id, target_user_id=principal.user_id)
    return RedirectResponse("/account?saved=1", status_code=303)


@app.get("/account/security", response_class=HTMLResponse)
def account_security_page(request: Request, password: str = ""):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    changed = "<div class='banner'>비밀번호가 변경되었고 다른 세션은 종료되었습니다.</div>" if password == "changed" else ""
    mfa_status = _render_mfa_status(principal.user_id)
    return page(
        "Account security",
        f"""
        <h1>보안 센터</h1>
        {_account_nav('security')}
        {changed}
        <section class='card'>
          <h2>비밀번호 변경</h2>
          <p class='muted'>현재 비밀번호를 확인한 뒤 새 비밀번호를 저장합니다. 성공 시 현재 세션을 제외한 다른 세션은 종료됩니다.</p>
          <form method='post' action='/account/password'>
            <label>현재 비밀번호</label><input name='current_password' type='password' autocomplete='current-password' required>
            <label>새 비밀번호</label><input name='new_password' type='password' minlength='8' autocomplete='new-password' required>
            <label>새 비밀번호 확인</label><input name='confirm_password' type='password' minlength='8' autocomplete='new-password' required>
            <button>비밀번호 변경</button>
          </form>
        </section>
        <section class='card'>
          <h2>MFA 상태</h2>
          <p class='muted'>민감 작업에는 AAL2 step-up을 권장합니다. 현재 세션 AAL: <code>{html.escape(principal.session.assurance_level.value)}</code></p>
          {mfa_status}
        </section>
        <section class='card'>
          <h2>복구 코드 / Passkey</h2>
          <p class='muted'>Recovery code와 WebAuthn/Passkey primitive는 core에 포함되어 있으며, 이 데모에서는 상태 확인과 운영 가이드 표면화에 한정합니다.</p>
        </section>
        """,
    )


@app.post("/account/password")
def account_password_change(request: Request, current_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...)):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    if new_password != confirm_password:
        return _password_change_error("새 비밀번호 확인이 일치하지 않습니다.")
    credential = auth.storage.get_password_credential(principal.user_id)
    if credential is None or not credential.password_hash or not verify_password(credential.password_hash, current_password):
        return _password_change_error("현재 비밀번호가 올바르지 않습니다.")
    try:
        auth.set_password(principal.user_id, new_password, except_session_id=principal.session.id)
    except Exception as exc:
        return _password_change_error(str(exc))
    auth._audit("auth.account.password_change", actor_user_id=principal.user_id, target_user_id=principal.user_id)
    return RedirectResponse("/account/security?password=changed", status_code=303)


@app.get("/account/sessions", response_class=HTMLResponse)
def account_sessions_page(request: Request):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    sessions = auth.storage.list_sessions_for_user(principal.user_id)
    rows = _render_session_rows(sessions, current_session_id=principal.session.id)
    return page(
        "Account sessions",
        f"""
        <h1>내 세션</h1>
        {_account_nav('sessions')}
        <section class='card'>
          <h2>세션 관리</h2>
          <p class='muted'>현재 계정으로 발급된 세션을 확인하고 필요 시 종료합니다.</p>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Session</th><th>Status</th><th>Provider</th><th>AAL</th><th>생성</th><th>마지막 활동</th><th>로그아웃</th><th>만료</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>
        </section>
        """,
    )


@app.post("/account/sessions/{session_id}/revoke")
def account_session_revoke(request: Request, session_id: str):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    owned = {session.id for session in auth.storage.list_sessions_for_user(principal.user_id)}
    if session_id not in owned:
        return Response("Forbidden", status_code=403)
    auth.revoke_session(session_id, actor_user_id=principal.user_id)
    if session_id == principal.session.id:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return response
    return RedirectResponse("/account/sessions", status_code=303)


@app.get("/account/activity", response_class=HTMLResponse)
def account_activity_page(request: Request):
    principal, redirect = _require_principal_response(request)
    if redirect is not None:
        return redirect
    rows = _render_activity_rows(_user_activity_events(principal.user_id), limit=80)
    return page(
        "Account activity",
        f"""
        <h1>내 활동</h1>
        {_account_nav('activity')}
        <section class='card'>
          <h2>최근 활동 이벤트</h2>
          <p class='muted'>로그인, 로그아웃, 비밀번호 변경, 세션 종료, 관리자 변경 이벤트를 사용자 기준으로 모아 보여줍니다.</p>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Metadata</th></tr></thead><tbody>{rows}</tbody></table></div>
        </section>
        """,
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    selected_email = request.query_params.get("email") if DEMO_MODE else None
    next_path = safe_next_path(request.query_params.get("next"))
    if current_principal(request) is not None and not selected_email:
        return RedirectResponse(next_path, status_code=303)
    last = email_sender.sent_magic_links[-1] if email_sender.sent_magic_links else None
    magic = ""
    if DEMO_MODE and last:
        magic = f"<div class='banner'><b>개발용 매직링크:</b> <a class='button secondary' href='/magic-link/consume?token={html.escape(last.token)}'>매직링크로 로그인</a><p class='muted'>운영에서는 이메일 발송기로 대체합니다.</p></div>"
    owner_hint = (
        f"<p class='muted'>관리자 계정: <code>{html.escape(OWNER_EMAIL)}</code> / <code>{html.escape(OWNER_PASSWORD)}</code></p>"
        if DEMO_MODE
        else "<p class='muted'>관리자 계정 정보는 환경변수로 설정하며 운영 모드에서는 화면에 표시하지 않습니다.</p>"
    )
    if selected_email and ("@" not in selected_email or len(selected_email) > 320):
        selected_email = None
    email_value = html.escape(selected_email or OWNER_EMAIL) if DEMO_MODE else ""
    password_value = html.escape(OWNER_PASSWORD) if DEMO_MODE else ""
    next_notice = f"<div class='banner'>로그인 후 <code>{html.escape(next_path)}</code> 화면으로 이동합니다.</div>" if next_path != "/" else ""
    role_account_hint = ""
    return page(
        "Login",
        f"""
        <h1>Coreline Auth Login</h1>
        {owner_hint}
        <div class='nav'><a class='button secondary' href='/signup'>새 계정 가입</a><a class='button secondary' href='/password-reset'>비밀번호 재설정</a><a class='button secondary' href='/social/google'>Google 로그인</a><a class='button secondary' href='/social/facebook'>Facebook 로그인</a></div>
        <div class='notice'>Google/Facebook은 provider credential이 있으면 실제 OAuth redirect를 시작하고, 없으면 개발용 social connector로 테스트합니다.</div>
        {next_notice}
        <div class='login-grid'>
          <section class='card'><h2>이메일/비밀번호 로그인</h2><form method='post' action='/login'>
            <label>Email</label><input name='email' type='email' value='{email_value}' autocomplete='username' required>
            <label>Password</label><input name='password' type='password' value='{password_value}' autocomplete='current-password' required>
            <input type='hidden' name='next' value='{html.escape(next_path, quote=True)}'>
            <button>로그인</button> <a class='button secondary' href='/password-reset'>비밀번호 재설정</a>
          </form></section>
          <section class='card'><h2>매직링크 로그인</h2><form method='post' action='/magic-link/request'>
            <label>Email</label><input name='email' type='email' value='{email_value}' autocomplete='username' required>
            <input type='hidden' name='return_to' value='/'>
            <button class='secondary'>매직링크 요청</button>
          </form>{magic}</section>
        </div>
        {role_account_hint}
        """,
        public=True,
    )


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if current_principal(request) is not None:
        return RedirectResponse("/", status_code=303)
    return page(
        "Sign up",
        """
        <h1>Coreline Auth Sign up</h1>
        <p class='muted'>데모에서는 가입 계정이 <code>user</code> 권한으로 생성됩니다. 관리자 페이지는 admin 계정만 접근 가능합니다.</p>
        <section class='card'><form method='post' action='/signup'>
          <label>Email</label><input name='email' type='email' placeholder='new-user@example.com' autocomplete='username' required>
          <label>Password</label><input name='password' type='password' minlength='8' placeholder='8자 이상' autocomplete='new-password' required>
          <label>Display name</label><input name='display_name' type='text' placeholder='홍길동'>
          <button>가입하고 로그인</button> <a class='button secondary' href='/login'>로그인으로 돌아가기</a>
        </form></section>
        """,
        public=True,
    )


@app.post("/signup")
def signup_form(request: Request, email: str = Form(...), password: str = Form(...), display_name: str = Form("")):
    try:
        user = auth.create_user(email=email, role=Role.USER, password=password, email_verified=True, display_name=display_name or None)
        issued = auth.login_password(email=user.primary_email, password=password, context=request_context(request))
    except Exception as exc:
        return page("Sign up failed", f"<div class='card error'><h1>가입 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/signup'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.get("/social/{provider}", response_class=HTMLResponse)
def social_start(request: Request, provider: str):
    if provider not in {"google", "facebook"}:
        return Response("Unknown provider", status_code=404)
    connector = configured_connector(provider, request)
    if connector is not None:
        nonce = generate_token() if connector.config.issuer else None
        pkce = OAuthPKCE.create() if connector.config.issuer else None
        state = auth.begin_social_login(provider=provider, return_to="/", nonce=nonce)
        start = connector.start_authorization(state=state, nonce=nonce, pkce=pkce)
        response = RedirectResponse(start.authorization_url, status_code=303)
        if start.nonce:
            _set_oauth_cookie(response, request, provider=provider, name="nonce", value=start.nonce)
        if start.code_verifier:
            _set_oauth_cookie(response, request, provider=provider, name="code_verifier", value=start.code_verifier)
        return response
    provider_name = "Google" if provider == "google" else "Facebook"
    return page(
        f"{provider_name} login",
        f"""
        <h1>{html.escape(provider_name)} 로그인</h1>
        <section class='card'>
          <p>실제 OAuth를 사용하려면 <code>CORELINE_AUTH_{provider.upper()}_CLIENT_ID</code>, <code>CORELINE_AUTH_{provider.upper()}_CLIENT_SECRET</code> 환경변수가 필요합니다.</p>
          <p>현재는 개발용 social connector로 provider identity linking, 사용자 자동 생성, session 발급 흐름을 테스트할 수 있습니다.</p>
          <form method='post' action='/social/{html.escape(provider)}/dev'>
            <label>Demo email</label><input name='email' type='email' value='{html.escape(provider)}-user@example.com' required>
            <label>Display name</label><input name='display_name' type='text' value='Demo {html.escape(provider_name)} User'>
            <button>{html.escape(provider_name)} 개발용 로그인</button>
            <a class='button secondary' href='/login'>돌아가기</a>
          </form>
        </section>
        """,
        public=True,
    )


def configured_connector(provider: str, request: Request):
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/social/{provider}/callback"
    if provider == "google":
        client_id = os.getenv("CORELINE_AUTH_GOOGLE_CLIENT_ID", "")
        client_secret = os.getenv("CORELINE_AUTH_GOOGLE_CLIENT_SECRET", "")
        if client_id and client_secret:
            return GoogleOAuthConnector.from_credentials(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
    if provider == "facebook":
        client_id = os.getenv("CORELINE_AUTH_FACEBOOK_CLIENT_ID", "")
        client_secret = os.getenv("CORELINE_AUTH_FACEBOOK_CLIENT_SECRET", "")
        if client_id and client_secret:
            return FacebookOAuthConnector.from_credentials(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
    return None


def _oauth_cookie_name(provider: str, name: str) -> str:
    return f"coreline_auth_oauth_{provider}_{name}"


def _set_oauth_cookie(response: Response, request: Request, *, provider: str, name: str, value: str) -> None:
    response.set_cookie(
        _oauth_cookie_name(provider, name),
        value,
        max_age=auth.config.login_flow_ttl_seconds,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )


def _delete_oauth_cookies(response: Response, provider: str) -> None:
    response.delete_cookie(_oauth_cookie_name(provider, "nonce"), path="/")
    response.delete_cookie(_oauth_cookie_name(provider, "code_verifier"), path="/")


def _oidc_jwks_for_connector(connector):
    issuer = connector.config.issuer
    if not issuer:
        return None
    issuer_host = (urlparse(issuer).hostname or "").lower()
    metadata = discover_oidc_metadata(issuer=issuer, fetcher=OIDCMetadataClient(allowed_hosts={issuer_host}))
    if not metadata.jwks_uri:
        raise AuthenticationFailed("OIDC provider metadata does not include jwks_uri")
    jwks_host = (urlparse(metadata.jwks_uri).hostname or "").lower()
    cache = _oidc_jwks_caches.get(metadata.jwks_uri)
    if cache is None:
        cache = JWKSCache(OIDCMetadataClient(allowed_hosts={jwks_host}))
        _oidc_jwks_caches[metadata.jwks_uri] = cache
    return cache.get_jwks(metadata.jwks_uri)


@app.get("/social/{provider}/callback")
def social_callback(request: Request, provider: str, code: str, state: str):
    connector = configured_connector(provider, request)
    if connector is None:
        return Response("Provider is not configured", status_code=400)
    try:
        if connector.config.issuer:
            nonce = request.cookies.get(_oauth_cookie_name(provider, "nonce"))
            code_verifier = request.cookies.get(_oauth_cookie_name(provider, "code_verifier"))
            if not nonce or not code_verifier:
                raise AuthenticationFailed("missing OAuth nonce or PKCE verifier")
            auth.consume_social_login_state(provider=provider, state=state, nonce=nonce)
            profile = connector.exchange_code(
                code=code,
                code_verifier=code_verifier,
                expected_nonce=nonce,
                id_token_jwks=_oidc_jwks_for_connector(connector),
            )
            issued = auth.login_social(profile=profile, context=request_context(request))
        else:
            profile = connector.exchange_code(code=code)
            issued = auth.login_social(profile=profile, state=state, context=request_context(request))
    except Exception as exc:
        response = page("Social login failed", f"<div class='card error'><h1>소셜 로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
        _delete_oauth_cookies(response, provider)
        return response
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    _delete_oauth_cookies(response, provider)
    return response


@app.post("/social/{provider}/dev")
def social_dev_login(request: Request, provider: str, email: str = Form(...), display_name: str = Form("")):
    if provider not in {"google", "facebook"}:
        return Response("Unknown provider", status_code=404)
    profile = DevSocialConnector(provider).fake_profile(email=email, display_name=display_name or None)
    try:
        issued = auth.login_social(profile=profile, context=request_context(request))
    except Exception as exc:
        return page("Social login failed", f"<div class='card error'><h1>소셜 로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.post("/login")
def login_form(request: Request, email: str = Form(...), password: str = Form(...), next: str = Form("/")):
    try:
        issued = auth.login_password(email=email, password=password, context=request_context(request))
    except Exception as exc:
        return page("Login failed", f"<div class='card error'><h1>로그인 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse(safe_next_path(next), status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.get("/password-reset", response_class=HTMLResponse)
def password_reset_page():
    last = email_sender.sent_password_resets[-1] if email_sender.sent_password_resets else None
    dev_link = ""
    if DEMO_MODE and last:
        dev_link = f"<div class='banner'><b>개발용 reset token:</b> <a class='button secondary' href='/password-reset/consume?token={html.escape(last.token)}'>새 비밀번호 설정</a></div>"
    return page(
        "Password reset",
        f"""
        <h1>비밀번호 재설정</h1>
        <section class='card'>
          <form method='post' action='/password-reset/request'>
            <label>Email</label><input name='email' type='email' value='{html.escape(OWNER_EMAIL)}' required>
            <button>재설정 메일 요청</button> <a class='button secondary' href='/login'>로그인으로</a>
          </form>
          {dev_link}
        </section>
        """,
        public=True,
    )


@app.post("/password-reset/request")
def password_reset_request(email: str = Form(...)):
    try:
        auth.request_password_reset(email)
    except Exception:
        # Public UI keeps the same response shape to avoid account enumeration.
        pass
    return RedirectResponse("/password-reset", status_code=303)


@app.get("/password-reset/consume", response_class=HTMLResponse)
def password_reset_consume_page(token: str):
    return page(
        "Set new password",
        f"""
        <h1>새 비밀번호 설정</h1>
        <section class='card'>
          <form method='post' action='/password-reset/consume'>
            <input type='hidden' name='token' value='{html.escape(token, quote=True)}'>
            <label>New password</label><input name='password' type='password' minlength='8' autocomplete='new-password' required>
            <button>비밀번호 변경</button> <a class='button secondary' href='/login'>취소</a>
          </form>
        </section>
        """,
        public=True,
    )


@app.post("/password-reset/consume")
def password_reset_consume_form(token: str = Form(...), password: str = Form(...)):
    try:
        auth.consume_password_reset(token, password)
    except Exception as exc:
        return page("Password reset failed", f"<div class='card error'><h1>재설정 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/password-reset'>돌아가기</a></div>", public=True)
    return page("Password reset complete", "<div class='card'><h1>비밀번호가 변경되었습니다</h1><a class='button' href='/login'>로그인</a></div>", public=True)


@app.post("/magic-link/request")
def magic_link_request(email: str = Form(...), return_to: str = Form("/")):
    try:
        auth.request_magic_link(email=email, return_to=return_to)
    except Exception as exc:
        return page("Magic link failed", f"<div class='card error'><h1>요청 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    return RedirectResponse("/login", status_code=303)


@app.get("/magic-link/consume")
def magic_link_consume(request: Request, token: str):
    try:
        issued = auth.consume_magic_link(token=token, context=request_context(request))
    except Exception as exc:
        return page("Magic link failed", f"<div class='card error'><h1>매직링크 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/login'>돌아가기</a></div>", public=True)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, httponly=True, samesite="lax", path="/")
    return response


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        auth.logout(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/logout", response_class=HTMLResponse)
def logout_confirm(request: Request):
    if current_principal(request) is None:
        return RedirectResponse("/login", status_code=303)
    csrf_notice = (
        "<div class='notice'><b>보안 토큰이 만료되었습니다.</b><p class='muted'>개발 서버 reload 또는 오래 열린 탭 때문에 이전 로그아웃 요청이 만료되었습니다. 아래 버튼을 한 번 더 누르면 새 토큰으로 안전하게 로그아웃됩니다.</p></div>"
        if request.query_params.get("csrf") == "expired"
        else ""
    )
    return page(
        "Logout",
        f"""
        <h1>로그아웃 확인</h1>
        {csrf_notice}
        <section class='card'>
          <p class='muted'>주소창에서 <code>/logout</code>을 직접 열어도 안전하게 처리하기 위해, 실제 로그아웃은 아래 버튼으로 POST 요청을 보낼 때만 실행합니다.</p>
          <form method='post' action='/logout'>
            <button class='danger'>로그아웃</button>
            <a class='button secondary' href='/'>취소</a>
          </form>
        </section>
        """,
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, query: str = "", status: str = "", role: str = ""):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        principal = auth.verify_session(token, required_permission="users:read")
    except Exception:
        return _admin_forbidden_page(title="관리자 접근 금지", required_permission="users:read", token=token)
    from coreline_auth import CorelineAdminService

    admin_service = CorelineAdminService(auth)
    try:
        all_users = admin_service.list_users(actor_session_token=token)
        users = admin_service.list_users(actor_session_token=token, query=query, status=status, role=role)
    except Exception as exc:
        return page("Admin filter failed", f"<div class='card error'><h1>관리자 필터 오류</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/admin'>필터 초기화</a></div>")

    def select_options(values: list[tuple[str, str]], current: str) -> str:
        return "".join(
            f"<option value='{html.escape(value)}'{' selected' if value == current else ''}>{html.escape(label)}</option>"
            for value, label in values
        )

    role_values = [(role_item.value, role_item.value) for role_item in ROLE_DASHBOARD_ORDER]
    filter_role_options = select_options([("", "전체 role")] + role_values, role)
    filter_status_options = select_options([("", "전체 status"), ("active", "active"), ("disabled", "disabled"), ("banned", "banned")], status)
    sessions_by_user: dict[str, list[AuthSession]] = {}
    events_by_user: dict[str, list[AuditEvent]] = {}
    for user in all_users:
        sessions_by_user[user.id] = admin_service.list_sessions_for_user(actor_session_token=token, user_id=user.id)
        events_by_user[user.id] = _user_activity_events(user.id)

    rows_parts: list[str] = []
    cards_parts: list[str] = []
    for user in users:
        sessions = sessions_by_user.get(user.id, [])
        activity_events = events_by_user.get(user.id, [])
        card_fragment = f"user-card-{_safe_fragment(user.id)}"
        login_count = len(_login_events(activity_events))
        active_session_count = sum(1 for session in sessions if _session_is_active(session))
        latest_login = max((event.created_at for event in _login_events(activity_events)), default=user.last_login_at)
        cards_parts.append(_render_user_activity_card(user, sessions=sessions, events=activity_events))
        rows_parts.append(
            f"""<tr><td><a href='/admin/users/{html.escape(user.id)}'>{html.escape(user.primary_email)}</a></td><td>{html.escape(user.role.value)}</td><td>{html.escape(user.status.value)}</td><td>{html.escape(_format_datetime(latest_login))}</td><td>{login_count}</td><td>{active_session_count}</td><td>
        <a class='button secondary' href='/admin/users/{html.escape(user.id)}'>상세</a>
        <a class='button secondary' href='#{html.escape(card_fragment)}'>정보 카드</a>
        <form method='post' action='/admin/users/{html.escape(user.id)}/role' style='display:inline-block;min-width:180px'><select name='role'>{select_options(role_values, user.role.value)}</select><button class='secondary'>Role 변경</button></form>
        <form method='post' action='/admin/users/{html.escape(user.id)}/ban' style='display:inline-block;min-width:220px'><input name='reason' type='text' placeholder='Ban reason' aria-label='Ban reason for {html.escape(user.primary_email)}'><button class='danger'>Ban</button></form>
        <form method='post' action='/admin/users/{html.escape(user.id)}/unban' style='display:inline-block'><input name='reason' type='text' placeholder='Unban reason'><button class='secondary'>Unban</button></form>
        </td></tr>"""
        )
    rows = "".join(rows_parts) or "<tr><td colspan='7'>조건에 맞는 사용자가 없습니다.</td></tr>"
    cards = "".join(cards_parts)
    selected_role_text = role or "전체"
    admin_kpis = _render_admin_kpis(users=all_users, sessions_by_user=sessions_by_user, events_by_user=events_by_user)
    role_cards = _render_role_cards(users=all_users, sessions_by_user=sessions_by_user, events_by_user=events_by_user, selected_role=role)
    role_activity_table = _render_role_activity_table(users=all_users, sessions_by_user=sessions_by_user, events_by_user=events_by_user)
    permission_matrix = _render_permission_matrix()
    return page(
        "Admin",
        f"""<h1>전체 사용자 대시보드</h1><p class='muted'>{html.escape(principal.email)} 계정으로 가입자, role 분포, 세션, 권한 매트릭스를 관리합니다.</p>
        <section class='card'><h2>운영 KPI</h2><div class='admin-stat-grid'>{admin_kpis}</div></section>
        <section class='card'><div class='section-toolbar'><div><h2>권한별 사용자 현황</h2><p class='muted'>role 카드를 누르면 아래 사용자 목록이 해당 권한으로 필터링됩니다.</p></div><a class='button secondary' href='/admin#admin-users'>전체 보기</a></div><div class='role-card-grid'>{role_cards}</div></section>
        <section class='card'><h2>권한별 활동 요약</h2>{role_activity_table}</section>
        <section class='card'><h2>검색/필터</h2><form method='get' action='/admin'>
          <label>Query</label><input name='query' type='search' placeholder='email, display name, user id' value='{html.escape(query)}'>
          <div class='grid'><div><label>Status</label><select name='status'>{filter_status_options}</select></div><div><label>Role</label><select name='role'>{filter_role_options}</select></div></div>
          <button>검색</button> <a class='button secondary' href='/admin'>초기화</a>
        </form></section>
        <section id='admin-users' class='card'><div class='section-toolbar'><div><h2>사용자 목록</h2><p class='muted'>선택된 role: <code>{html.escape(selected_role_text)}</code> · 표시 사용자 {len(users)}명 / 전체 {len(all_users)}명</p></div><a class='button secondary' href='/admin/audit'>감사 로그</a></div><table style='width:100%;border-spacing:0 10px'><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Login Count</th><th>Active Sessions</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table><a class='button' href='/'>대시보드</a> <a class='button secondary' href='/admin/audit'>감사 로그</a></section>
        <section class='card'><h2>권한 매트릭스</h2><p class='muted'>RBAC role별 실제 permission 허용 여부입니다. 체크는 서버 측 정책 엔진 기준입니다.</p>{permission_matrix}</section>{cards}""",
    )


@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(request: Request, user_id: str, updated: str = ""):
    token, principal, redirect = _admin_context(request, required_permission="users:read")
    if redirect is not None:
        return redirect
    target = auth.storage.get_user(user_id)
    if target is None:
        return Response("Not found", status_code=404)
    admin_service = CorelineAdminService(auth)
    sessions = admin_service.list_sessions_for_user(actor_session_token=token, user_id=target.id)
    events = _user_activity_events(target.id)
    factors = auth.storage.list_mfa_factors(target.id)
    role_options = "".join(
        f"<option value='{html.escape(role_item.value)}'{' selected' if role_item == target.role else ''}>{html.escape(role_item.value)}</option>"
        for role_item in ROLE_DASHBOARD_ORDER
    )
    status_notice = "<div class='banner'>관리 작업이 반영되었습니다.</div>" if updated == "1" else ""
    session_rows = _render_session_rows(sessions, admin_actions=True)
    event_rows = _render_activity_rows(events, limit=50)
    factor_rows = _render_mfa_status(target.id)
    active_session_count = sum(1 for session in sessions if _session_is_active(session))
    login_count = len(_login_events(events))
    metrics = "".join(
        f"<article class='admin-stat'><span>{html.escape(label)}</span><b{_stat_value_class(value)}>{html.escape(value)}</b><p>{html.escape(note)}</p></article>"
        for label, value, note in [
            ("Role", target.role.value, "현재 권한"),
            ("Status", target.status.value, "계정 상태"),
            ("Active Sessions", str(active_session_count), "현재 유효 세션"),
            ("Login Count", str(login_count), "감사 로그 기준"),
            ("Last Login", _format_datetime(target.last_login_at), "마지막 로그인"),
        ]
    )
    enable_disable = (
        f"<form method='post' action='/admin/users/{html.escape(target.id)}/enable'><input name='reason' placeholder='Enable reason'><button>Enable</button></form>"
        if target.status == UserStatus.DISABLED
        else f"<form method='post' action='/admin/users/{html.escape(target.id)}/disable'><input name='reason' placeholder='Disable reason'><button class='danger'>Disable</button></form>"
    )
    return page(
        "Admin user detail",
        f"""
        <h1>사용자 상세</h1>
        <p class='muted'>{html.escape(principal.email)} 계정으로 <code>{html.escape(target.primary_email)}</code> 사용자를 관리합니다.</p>
        {status_notice}
        <div class='nav'><a class='button secondary' href='/admin#admin-users'>사용자 목록</a><a class='button secondary' href='/admin/audit'>감사 로그</a><a class='button secondary' href='/system'>시스템 상태</a></div>
        <section class='card'>
          <div class='profile-hero'>
            <div class='profile-avatar'>{html.escape((target.display_name or target.primary_email or '?')[:1].upper())}</div>
            <div>
              <h2>{html.escape(target.display_name or target.primary_email)}</h2>
              <p class='muted'>{html.escape(target.primary_email)} · <code>{html.escape(target.id)}</code></p>
              <p><span class='pill'>created</span> {html.escape(_format_datetime(target.created_at))} <span class='pill'>updated</span> {html.escape(_format_datetime(target.updated_at))}</p>
            </div>
          </div>
          <div class='admin-stat-grid'>{metrics}</div>
        </section>
        <section class='card'>
          <h2>권한/상태 관리</h2>
          <div class='grid'>
            <form method='post' action='/admin/users/{html.escape(target.id)}/role'>
              <label>Role</label><select name='role'>{role_options}</select><button>Role 변경</button>
            </form>
            <div>
              {enable_disable}
              <form method='post' action='/admin/users/{html.escape(target.id)}/ban'><input name='reason' placeholder='Ban reason'><button class='danger'>Ban</button></form>
              <form method='post' action='/admin/users/{html.escape(target.id)}/unban'><input name='reason' placeholder='Unban reason'><button class='secondary'>Unban</button></form>
            </div>
          </div>
        </section>
        <section class='card'>
          <h2>관리자 비밀번호 설정</h2>
          <p class='muted'>테스트/복구 목적의 admin action입니다. 성공 시 대상 사용자의 기존 세션은 정책에 따라 종료됩니다.</p>
          <form method='post' action='/admin/users/{html.escape(target.id)}/password'>
            <label>새 비밀번호</label><input name='password' type='password' minlength='8' autocomplete='new-password' required>
            <button>비밀번호 설정</button>
          </form>
        </section>
        <section class='card'>
          <h2>MFA / Security Center</h2>
          <p class='muted'>사용자별 MFA factor 상태입니다. 민감 작업에는 AAL2 step-up을 권장합니다.</p>
          {factor_rows}
        </section>
        <section class='card'>
          <h2>세션</h2>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Session</th><th>Status</th><th>Provider</th><th>AAL</th><th>생성</th><th>마지막 활동</th><th>로그아웃</th><th>만료</th><th>Action</th></tr></thead><tbody>{session_rows}</tbody></table></div>
        </section>
        <section class='card'>
          <h2>활동</h2>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Metadata</th></tr></thead><tbody>{event_rows}</tbody></table></div>
        </section>
        """,
    )


@app.get("/admin/audit", response_class=HTMLResponse)
def admin_audit_page(
    request: Request,
    action: str = "",
    actor_user_id: str = "",
    target_user_id: str = "",
    since: str = "",
    until: str = "",
    limit: int = 100,
    offset: int = 0,
):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        principal = auth.verify_session(token, required_permission="audit:read")
    except Exception:
        return _admin_forbidden_page(title="감사 로그 접근 금지", required_permission="audit:read", token=token)
    error = ""
    events: list[AuditEvent] = []
    safe_limit = min(max(limit, 1), 500)
    safe_offset = max(offset, 0)
    try:
        parsed_since = _parse_filter_datetime(since)
        parsed_until = _parse_filter_datetime(until)
        events = auth.list_audit_events(
            action=action.strip() or None,
            actor_user_id=actor_user_id.strip() or None,
            target_user_id=target_user_id.strip() or None,
            since=parsed_since,
            until=parsed_until,
            limit=safe_limit,
            offset=safe_offset,
        )
    except ValueError as exc:
        error = str(exc)
    error_box = f"<div class='card error'><h2>필터 오류</h2><p>{html.escape(error)}</p></div>" if error else ""
    filter_summary = ", ".join(
        f"{label}={value}"
        for label, value in [
            ("action", action.strip()),
            ("actor", actor_user_id.strip()),
            ("target", target_user_id.strip()),
            ("since", since.strip()),
            ("until", until.strip()),
            ("limit", str(safe_limit)),
            ("offset", str(safe_offset)),
        ]
        if value
    )
    if not filter_summary:
        filter_summary = "최근 이벤트"
    rows = "".join(
        f"""<tr><td>{html.escape(event.created_at.isoformat())}</td><td>{html.escape(event.action)}</td><td>{html.escape(event.actor_user_id or '-')}</td><td>{html.escape(event.target_user_id or '-')}</td><td><code>{html.escape(str(event.metadata))}</code></td></tr>"""
        for event in events
    ) or "<tr><td colspan='5'>아직 감사 이벤트가 없습니다.</td></tr>"
    return page(
        "Audit log",
        f"""<h1>감사 로그</h1><p class='muted'>{html.escape(principal.email)} 계정으로 최근 100개 이벤트를 확인합니다.</p>
        {error_box}
        <section class='card'>
          <h2>감사 로그 필터</h2>
          <form method='get' action='/admin/audit'>
            <label>Action</label><input name='action' type='search' placeholder='auth.login.failed' value='{html.escape(action, quote=True)}'>
            <div class='grid'>
              <div><label>Actor user id</label><input name='actor_user_id' type='search' value='{html.escape(actor_user_id, quote=True)}'></div>
              <div><label>Target user id</label><input name='target_user_id' type='search' value='{html.escape(target_user_id, quote=True)}'></div>
            </div>
            <div class='grid'>
              <div><label>Since</label><input name='since' type='text' placeholder='2026-05-26T09:00:00+00:00' value='{html.escape(since, quote=True)}'></div>
              <div><label>Until</label><input name='until' type='text' placeholder='2026-05-26T10:00:00+00:00' value='{html.escape(until, quote=True)}'></div>
            </div>
            <div class='grid'>
              <div><label>Limit</label><input name='limit' type='number' min='1' max='500' value='{safe_limit}'></div>
              <div><label>Offset</label><input name='offset' type='number' min='0' value='{safe_offset}'></div>
            </div>
            <button>필터 적용</button> <a class='button secondary' href='/admin/audit'>초기화</a>
          </form>
          <p class='muted'>현재 필터: {html.escape(filter_summary)} · 결과 {len(events)}건</p>
        </section>
        <section class='card'><table style='width:100%;border-spacing:0 10px'><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Metadata</th></tr></thead><tbody>{rows}</tbody></table><a class='button secondary' href='/admin'>관리자</a> <a class='button secondary' href='/system'>시스템 상태</a></section>""",
    )


@app.post("/admin/users/{user_id}/role")
def admin_role(request: Request, user_id: str, role: str = Form(...)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).update_user_role(actor_session_token=token, user_id=user_id, role=Role(role))
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/ban")
def admin_ban(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).ban_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/unban")
def admin_unban(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    from coreline_auth import CorelineAdminService
    try:
        CorelineAdminService(auth).unban_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/disable")
def admin_disable(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        CorelineAdminService(auth).disable_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse(f"/admin/users/{user_id}?updated=1", status_code=303)


@app.post("/admin/users/{user_id}/enable")
def admin_enable(request: Request, user_id: str, reason: str = Form("")):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        CorelineAdminService(auth).enable_user(actor_session_token=token, user_id=user_id, reason=reason)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse(f"/admin/users/{user_id}?updated=1", status_code=303)


@app.post("/admin/users/{user_id}/password")
def admin_password_set(request: Request, user_id: str, password: str = Form(...)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        CorelineAdminService(auth).set_user_password(actor_session_token=token, user_id=user_id, password=password)
    except Exception as exc:
        return page("Admin password failed", f"<div class='card error'><h1>비밀번호 설정 실패</h1><p>{html.escape(str(exc))}</p><a class='button secondary' href='/admin/users/{html.escape(user_id)}'>돌아가기</a></div>")
    return RedirectResponse(f"/admin/users/{user_id}?updated=1", status_code=303)


@app.post("/admin/sessions/{session_id}/revoke")
def admin_session_revoke(request: Request, session_id: str):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return RedirectResponse("/login", status_code=303)
    try:
        CorelineAdminService(auth).revoke_session(actor_session_token=token, session_id=session_id)
    except Exception:
        return Response("Forbidden", status_code=403)
    return RedirectResponse(_same_site_referer_path(request), status_code=303)


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request):
    token, principal, redirect = _admin_context(request, required_permission="audit:read")
    if redirect is not None:
        return redirect
    health_ok = True
    health_message = "OK"
    try:
        auth.health_check()
    except Exception as exc:
        health_ok = False
        health_message = str(exc)
    users = auth.storage.list_users()
    sessions = [session for user in users for session in auth.storage.list_sessions_for_user(user.id)]
    active_sessions = sum(1 for session in sessions if _session_is_active(session))
    metrics = "".join(
        f"<article class='admin-stat'><span>{html.escape(label)}</span><b>{html.escape(value)}</b><p>{html.escape(note)}</p></article>"
        for label, value, note in [
            ("Health", "OK" if health_ok else "FAIL", health_message),
            ("Users", str(len(users)), "storage list_users"),
            ("Active Sessions", str(active_sessions), "만료/로그아웃 제외"),
            ("Magic Links", str(len(email_sender.sent_magic_links)), "개발용 email sender queue"),
            ("Password Resets", str(len(email_sender.sent_password_resets)), "개발용 email sender queue"),
        ]
    )
    readiness = _readiness_rows()
    return page(
        "System health",
        f"""
        <h1>시스템 상태</h1>
        <p class='muted'>{html.escape(principal.email)} 계정으로 데모 런타임과 storage health를 확인합니다.</p>
        <section class='card'><h2>Health</h2><div class='admin-stat-grid'>{metrics}</div></section>
        <section class='card'>
          <h2>Provider readiness</h2>
          <p class='muted'>secret 값은 표시하지 않고, 현재 프로세스에 필요한 환경변수가 있는지만 점검합니다.</p>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Provider</th><th>Status</th><th>Note</th></tr></thead><tbody>{readiness}</tbody></table></div>
        </section>
        <section class='card'>
          <h2>Runbook</h2>
          <ul>
            <li>로그인 실패: 감사 로그에서 <code>auth.login.failed</code>와 rate-limit 이벤트를 확인합니다.</li>
            <li>CSRF 오류: <code>/logout?csrf=expired</code> 흐름처럼 새 페이지에서 토큰을 재발급합니다.</li>
            <li>운영 배포: secure cookie, 외부 SMTP, Redis rate limiter, Postgres adapter 여부를 확인합니다.</li>
          </ul>
          <div class='nav'><a class='button secondary' href='/admin'>관리자</a><a class='button secondary' href='/admin/audit'>감사 로그</a><a class='button secondary' href='/system/email'>이메일 Outbox</a></div>
        </section>
        """,
    )


@app.get("/system/email", response_class=HTMLResponse)
def system_email_page(request: Request):
    token, principal, redirect = _admin_context(request, required_permission="audit:read")
    if redirect is not None:
        return redirect
    queue_rows = _email_queue_rows()
    template_rows = _template_preview_rows()
    metrics = "".join(
        f"<article class='admin-stat'><span>{html.escape(label)}</span><b>{html.escape(value)}</b><p>{html.escape(note)}</p></article>"
        for label, value, note in [
            ("Magic links", str(len(email_sender.sent_magic_links)), "개발용 sign-in links"),
            ("Email verifications", str(len(email_sender.sent_email_verifications)), "개발용 verification links"),
            ("Password resets", str(len(email_sender.sent_password_resets)), "개발용 reset links"),
        ]
    )
    return page(
        "Email outbox",
        f"""
        <h1>이메일 Outbox</h1>
        <p class='muted'>{html.escape(principal.email)} 계정으로 개발용 email sender 큐와 기본 template을 확인합니다. Token은 앞부분만 축약 표시합니다.</p>
        <section class='card'><h2>Queue summary</h2><div class='admin-stat-grid'>{metrics}</div></section>
        <section class='card'>
          <h2>최근 개발 발송 큐</h2>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Kind</th><th>Email</th><th>Token fingerprint</th><th>Return to</th></tr></thead><tbody>{queue_rows}</tbody></table></div>
        </section>
        <section class='card'>
          <h2>Template preview</h2>
          <div class='activity-table-wrap'><table class='activity-table'><thead><tr><th>Template</th><th>Subject</th><th>Text</th><th>HTML</th></tr></thead><tbody>{template_rows}</tbody></table></div>
          <div class='nav'><a class='button secondary' href='/system'>시스템 상태</a><a class='button secondary' href='/admin/audit'>감사 로그</a></div>
        </section>
        """,
    )
