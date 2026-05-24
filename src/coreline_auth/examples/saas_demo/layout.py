"""HTML layout and design system for the Coreline Auth SaaS demo."""

from __future__ import annotations

import html
from collections.abc import Sequence

from fastapi.responses import HTMLResponse

from coreline_auth.fastapi_adapter import CSRF_COOKIE_NAME

STYLE = """
<style>
:root{
  color-scheme:dark;
  --background:oklch(0.18 0.005 285.823);
  --foreground:oklch(0.985 0 0);
  --card:oklch(0.21 0.006 285.885);
  --muted:oklch(0.274 0.006 286.033);
  --muted-foreground:oklch(0.705 0.015 286.067);
  --border:oklch(1 0 0 / 10%);
  --input:oklch(1 0 0 / 15%);
  --brand:oklch(0.65 0.16 255);
  --success:oklch(0.65 0.15 145);
  --warning:oklch(0.70 0.16 85);
  --destructive:oklch(0.704 0.191 22.216);
  --radius-card:.875rem;
  --radius-panel:.75rem;
  --radius-control:.625rem;
}
*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;background:var(--background);color:var(--foreground);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.55}
a{color:color-mix(in oklab,var(--brand) 86%,white);text-decoration:none}a:hover{text-decoration:underline}code{border:1px solid var(--border);border-radius:.45rem;background:color-mix(in oklab,var(--muted) 70%,black);padding:2px 6px;color:var(--foreground);font-size:12px}table{border-collapse:separate;border-spacing:0 8px;width:100%;font-size:13px}th{color:var(--muted-foreground);font-weight:500;text-align:left;padding:0 10px 4px}td{border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:color-mix(in oklab,var(--card) 84%,var(--muted));padding:10px;vertical-align:top}td:first-child{border-left:1px solid var(--border);border-radius:.75rem 0 0 .75rem}td:last-child{border-right:1px solid var(--border);border-radius:0 .75rem .75rem 0}
.app-shell{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:100vh}.sidebar{border-right:1px solid var(--border);background:color-mix(in oklab,var(--card) 90%,black);padding:18px 14px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;overflow:auto}.brand{display:flex;gap:10px;align-items:center;padding:4px 8px 18px}.brand-mark{display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--border);border-radius:10px;background:var(--muted);color:var(--brand);font-weight:600}.brand-title{font-size:14px;font-weight:500}.brand-subtitle{font-size:12px;color:var(--muted-foreground)}.nav-group{margin:14px 0}.nav-label{padding:0 8px 6px;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted-foreground)}.topnav{display:flex;flex-direction:column;gap:3px;margin:0}.topnav a{display:flex;flex-direction:column;align-items:flex-start;gap:1px;border-radius:.625rem;padding:8px 10px;color:var(--muted-foreground);font-size:13px;text-decoration:none}.topnav a:hover{background:var(--muted);color:var(--foreground)}.topnav a:focus-visible{outline:2px solid color-mix(in oklab,var(--brand) 44%,transparent);outline-offset:1px}.nav-item-title{color:var(--foreground);font-weight:500}.nav-item-subtitle{font-size:11px;color:var(--muted-foreground)}.topnav-compact a{font-size:12px;padding:6px 8px;justify-content:space-between;flex-direction:row;align-items:center}.role-dot{display:inline-flex;width:7px;height:7px;border-radius:999px;background:var(--brand);margin-right:7px}.sidebar-form{margin:0}.sidebar-form button{width:100%;margin-top:4px;background:color-mix(in oklab,var(--destructive) 24%,var(--card));color:var(--foreground)}.sidebar-footer{position:static;margin-top:auto;border:1px solid var(--border);border-radius:.75rem;padding:10px;background:color-mix(in oklab,var(--muted) 56%,transparent);font-size:12px;color:var(--muted-foreground)}.page-wrap{min-width:0}.page-header{height:49px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:color-mix(in oklab,var(--background) 92%,var(--card));position:sticky;top:0;z-index:10}.page-header strong{font-size:13px;font-weight:500}.page-header span{font-size:12px;color:var(--muted-foreground)}main{max-width:1120px;margin:0 auto;padding:24px}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-card);padding:20px;margin:16px 0;box-shadow:none}.card h2{margin:0 0 12px;font-size:14px;font-weight:500}.grid,.login-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.login-grid{grid-template-columns:minmax(0,1.05fr) minmax(280px,.95fr);align-items:start}.nav{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.role-accounts summary{display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;list-style:none}.role-accounts summary::-webkit-details-marker{display:none}.role-accounts summary h2{margin:0}.role-accounts summary .muted{font-size:12px}.role-accounts[open] summary{margin-bottom:12px}.board-row,.comment{border-top:1px solid var(--border);padding:14px 0}.post-body{line-height:1.75;color:color-mix(in oklab,var(--foreground) 92%,var(--muted-foreground));white-space:normal}.comment p{margin:8px 0}.muted{color:var(--muted-foreground)}.notice,.banner{border:1px solid color-mix(in oklab,var(--warning) 36%,var(--border));border-left:4px solid var(--warning);background:color-mix(in oklab,var(--warning) 10%,var(--card));padding:12px;border-radius:.75rem;color:color-mix(in oklab,var(--foreground) 92%,var(--warning));margin:12px 0}.banner{border-left-color:var(--success);border-color:color-mix(in oklab,var(--success) 34%,var(--border));background:color-mix(in oklab,var(--success) 10%,var(--card))}.error{border-left-color:var(--destructive);border-color:color-mix(in oklab,var(--destructive) 36%,var(--border));background:color-mix(in oklab,var(--destructive) 10%,var(--card))}
h1{font-size:16px;line-height:1.4;font-weight:500;margin:0 0 8px}h3{font-size:14px;font-weight:500;margin:0 0 4px}p{margin:8px 0}b{font-weight:500;color:var(--foreground)}label{display:block;margin:12px 0 6px;color:var(--muted-foreground);font-size:12px;font-weight:500}input,textarea,select{width:100%;border:1px solid var(--input);border-radius:var(--radius-control);padding:10px 11px;background:color-mix(in oklab,var(--background) 72%,black);color:var(--foreground);font:inherit}input:focus,textarea:focus,select:focus{outline:2px solid color-mix(in oklab,var(--brand) 44%,transparent);outline-offset:1px}button,.button{display:inline-flex;align-items:center;justify-content:center;gap:6px;margin-top:10px;border:1px solid var(--border);border-radius:var(--radius-control);padding:9px 12px;background:var(--foreground);color:var(--background);font-size:13px;font-weight:500;text-decoration:none;cursor:pointer}.button:hover,button:hover{text-decoration:none;filter:brightness(.96)}.secondary{background:var(--muted);color:var(--foreground)}.danger{background:color-mix(in oklab,var(--destructive) 32%,var(--card));border-color:color-mix(in oklab,var(--destructive) 48%,var(--border));color:var(--foreground)}.disabled{opacity:.55;cursor:not-allowed}.pill{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:2px 8px;background:var(--muted);font-size:12px;color:var(--muted-foreground)}
	.board-toolbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin:16px 0 18px}.board-toolbar h1{margin-bottom:4px}.board-toolbar .nav{margin:0}.board-list{display:flex;flex-direction:column;gap:8px}.board-list-head,.board-list-row{display:grid;grid-template-columns:minmax(260px,1fr) 160px 82px 118px 136px;gap:12px;align-items:center}.board-list-head{padding:0 12px 2px;color:var(--muted-foreground);font-size:11px;text-transform:uppercase;letter-spacing:.04em}.board-list-row{border:1px solid var(--border);border-radius:.875rem;background:color-mix(in oklab,var(--card) 84%,var(--muted));padding:12px}.board-title-cell h3{margin:0 0 5px;font-size:14px}.board-excerpt{margin:0;color:var(--muted-foreground);font-size:12px;line-height:1.45}.board-meta{display:flex;flex-direction:column;gap:3px;color:var(--muted-foreground);font-size:12px}.board-count{display:inline-flex;align-items:center;justify-content:center;width:max-content;min-width:38px;border:1px solid var(--border);border-radius:999px;background:var(--muted);padding:3px 8px;color:var(--foreground);font-size:12px}.board-actions{display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap}.board-actions .button{margin-top:0;padding:7px 9px}.board-role-summary{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}.board-empty{border:1px dashed var(--border);border-radius:.875rem;padding:18px;text-align:center;color:var(--muted-foreground);background:color-mix(in oklab,var(--muted) 42%,transparent)}
	@media(max-width:980px){.board-list-head{display:none}.board-list-row{grid-template-columns:1fr}.board-actions{justify-content:flex-start}.board-toolbar{display:block}.board-toolbar .nav{margin-top:12px}}
	@media(max-width:860px){.app-shell{display:block}.sidebar{position:relative;height:auto;border-right:0;border-bottom:1px solid var(--border)}.sidebar-footer{position:static;margin-top:14px}.topnav{flex-direction:row;flex-wrap:wrap}.page-header{position:static}.grid,.login-grid{grid-template-columns:1fr}main{padding:18px 14px}table{display:block;overflow-x:auto;white-space:nowrap}.role-accounts summary{display:block}}
</style>
"""

def render_page(*, title: str, body: str, csrf_token: str, public: bool = False, demo_mode: bool = False, role_entries: Sequence[object] = ()) -> HTMLResponse:
    csrf_field = f"<input type='hidden' name='csrf_token' value='{html.escape(csrf_token, quote=True)}'>"
    body = body.replace("</form>", f"{csrf_field}</form>")
    role_links = ""
    if demo_mode and not public:
        role_links = "".join(
            f"<a href='/login?email={html.escape(entry.email, quote=True)}'><span><span class='role-dot'></span>{html.escape(entry.role.value)}</span><code>{html.escape(entry.email.split('@', 1)[0])}</code></a>"
            for entry in role_entries
        )
        role_links = f"""
        <div class='nav-group'>
          <div class='nav-label'>권한 계정</div>
          <nav class='topnav topnav-compact'>{role_links}</nav>
        </div>
        """
    if public:
        menu = f"""
        <div class='brand'>
          <div class='brand-mark'>CA</div>
          <div><div class='brand-title'>Coreline Auth</div><div class='brand-subtitle'>Login demo console</div></div>
        </div>
        <div class='nav-group'>
          <div class='nav-label'>Authentication</div>
          <nav class='topnav'>
            <a href='/login'><span class='nav-item-title'>로그인</span><span class='nav-item-subtitle'>이메일/비밀번호 + 매직링크</span></a>
            <a href='/signup'><span class='nav-item-title'>가입</span><span class='nav-item-subtitle'>author 권한 계정 생성</span></a>
            <a href='/password-reset'><span class='nav-item-title'>비밀번호 재설정</span><span class='nav-item-subtitle'>reset token 흐름 검증</span></a>
            <a href='/social/google'><span class='nav-item-title'>Google 로그인</span><span class='nav-item-subtitle'>OAuth 또는 개발용 connector</span></a>
            <a href='/social/facebook'><span class='nav-item-title'>Facebook 로그인</span><span class='nav-item-subtitle'>OAuth 또는 개발용 connector</span></a>
          </nav>
        </div>
        <div class='nav-group'>
          <div class='nav-label'>Demo app</div>
          <nav class='topnav'>
            <a href='/login?next=/'><span class='nav-item-title'>대시보드</span><span class='nav-item-subtitle'>로그인 후 세션/권한 요약 보기</span></a>
            <a href='/login?next=/board'><span class='nav-item-title'>게시판</span><span class='nav-item-subtitle'>로그인 후 RBAC 게시판 열기</span></a>
            <a href='/login?next=/board/new'><span class='nav-item-title'>새 게시글</span><span class='nav-item-subtitle'>로그인 후 작성 권한 테스트</span></a>
          </nav>
        </div>
        """
        footer = "게시판은 로그인 후 열립니다. 왼쪽 게시판 메뉴를 누르면 로그인 뒤 자동 이동합니다."
    else:
        menu = f"""
        <div class='brand'>
          <div class='brand-mark'>CA</div>
          <div><div class='brand-title'>Coreline Auth</div><div class='brand-subtitle'>RBAC demo console</div></div>
        </div>
        <div class='nav-group'>
          <div class='nav-label'>Application</div>
          <nav class='topnav'>
            <a href='/'><span class='nav-item-title'>대시보드</span><span class='nav-item-subtitle'>현재 세션과 권한 요약</span></a>
            <a href='/board'><span class='nav-item-title'>게시판</span><span class='nav-item-subtitle'>RBAC 읽기/댓글/수정 검증</span></a>
            <a href='/board/new'><span class='nav-item-title'>새 게시글</span><span class='nav-item-subtitle'>작성 권한 테스트</span></a>
          </nav>
        </div>
        <div class='nav-group'>
          <div class='nav-label'>Admin</div>
          <nav class='topnav'>
            <a href='/admin'><span class='nav-item-title'>관리자</span><span class='nav-item-subtitle'>사용자 상태와 role 변경</span></a>
            <a href='/admin/audit'><span class='nav-item-title'>감사 로그</span><span class='nav-item-subtitle'>인증/관리 이벤트 확인</span></a>
          </nav>
        </div>
        {role_links}
        """
        footer = "필수 데모 메뉴만 표시합니다. 로그인/가입/소셜/재설정은 Login 화면 안에서 테스트하세요."
    shell = f"""
    <div class='app-shell'>
      <aside class='sidebar'>{menu}<div class='sidebar-footer'>{html.escape(footer)}</div></aside>
      <div class='page-wrap'>
        <header class='page-header'><strong>{html.escape(title)}</strong><span>Gateway design language</span></header>
        <main>{body}</main>
      </div>
    </div>
    """
    response = HTMLResponse(f"<!doctype html><html class='dark'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>{STYLE}</head><body>{shell}</body></html>")
    response.set_cookie(CSRF_COOKIE_NAME, csrf_token, httponly=False, samesite="lax", path="/")
    return response


