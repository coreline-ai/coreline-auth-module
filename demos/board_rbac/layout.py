"""Standalone board RBAC demo layout."""

from __future__ import annotations

import html

from fastapi.responses import HTMLResponse

BOARD_CSS = """
:root{color-scheme:light dark;--bg:#f8fafc;--fg:#0f172a;--muted:#64748b;--card:#fff;--border:#e2e8f0;--brand:#2563eb;--danger:#b91c1c;--ok:#15803d}@media(prefers-color-scheme:dark){:root{--bg:#020617;--fg:#e2e8f0;--muted:#94a3b8;--card:#0f172a;--border:#1e293b;--brand:#60a5fa;--danger:#f87171;--ok:#4ade80}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6}.shell{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.sidebar{border-right:1px solid var(--border);background:var(--card);padding:20px;position:sticky;top:0;height:100vh}.brand{font-weight:800;margin-bottom:20px}.brand small{display:block;color:var(--muted);font-weight:500}.topnav{display:grid;gap:8px}.topnav a{padding:9px 10px;border-radius:10px;color:var(--fg);text-decoration:none}.topnav a:hover{background:color-mix(in oklab,var(--brand) 10%,transparent)}main{max-width:1120px;margin:0 auto;padding:28px}.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px;margin:16px 0}.muted{color:var(--muted)}.nav{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0}.button,button{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:10px;background:var(--brand);color:white;text-decoration:none;padding:8px 12px;font-weight:650;cursor:pointer}.secondary{background:transparent;color:var(--fg)}.danger{background:var(--danger);color:white}.disabled{opacity:.55;cursor:not-allowed}input,textarea,select{width:100%;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--fg);padding:10px;margin:5px 0 12px}.pill{display:inline-flex;border:1px solid var(--border);border-radius:999px;padding:3px 9px;font-size:12px;color:var(--muted)}.ok{color:var(--ok)}.board-toolbar{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.board-role-summary{display:flex;gap:8px;flex-wrap:wrap}.board-list{display:grid;gap:10px}.board-list-row{display:grid;grid-template-columns:minmax(260px,1fr) 160px 64px 118px 140px;gap:12px;align-items:center;border:1px solid var(--border);border-radius:14px;padding:14px;background:color-mix(in oklab,var(--card) 88%,var(--brand))}.board-excerpt{color:var(--muted);font-size:13px}.board-meta{display:grid;color:var(--muted);font-size:13px}.board-count{border:1px solid var(--border);border-radius:999px;padding:3px 8px;text-align:center}.board-actions{display:flex;gap:6px;justify-content:flex-end}.comment{border-top:1px solid var(--border);padding:12px 0}.error{border-color:color-mix(in oklab,var(--danger) 40%,var(--border));background:color-mix(in oklab,var(--danger) 8%,var(--card))}.account-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.account-card{display:flex;flex-direction:column;gap:8px;border:1px solid var(--border);border-radius:16px;background:color-mix(in oklab,var(--card) 92%,var(--brand));padding:14px;text-decoration:none;color:var(--fg)}.account-card:hover{border-color:var(--brand);text-decoration:none}.account-card h3{margin:0}.account-card code{font-size:12px}.role-table{width:100%;border-collapse:separate;border-spacing:0 8px}.role-table th{color:var(--muted);text-align:left;font-size:12px}.role-table td{border-top:1px solid var(--border);border-bottom:1px solid var(--border);padding:10px;background:color-mix(in oklab,var(--card) 92%,var(--brand))}.role-table td:first-child{border-left:1px solid var(--border);border-radius:10px 0 0 10px}.role-table td:last-child{border-right:1px solid var(--border);border-radius:0 10px 10px 0}@media(max-width:900px){.shell{display:block}.sidebar{height:auto;position:static}.board-list-row{grid-template-columns:1fr}.board-actions{justify-content:flex-start}.role-table{display:block;overflow:auto}}
"""


def clean_path(value: str) -> str:
    normalized = value.rstrip("/")
    return normalized or "/"


def render_page(
    title: str,
    body: str,
    *,
    board_prefix: str = "/demo-board",
    login_path: str = "/login",
    logout_path: str = "/logout",
    dashboard_path: str = "/",
) -> HTMLResponse:
    board_path = clean_path(board_prefix)
    return HTMLResponse(
        f"""<!doctype html><html lang='ko'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>{BOARD_CSS}</style></head>
        <body><div class='shell'><aside class='sidebar'><div class='brand'>Coreline Auth<small>Board RBAC demo fixture</small></div><nav class='topnav'><a href='{html.escape(dashboard_path, quote=True)}'>테스트 계정</a><a href='{html.escape(board_path, quote=True)}'>게시판</a><a href='{html.escape(login_path, quote=True)}'>로그인</a><a href='{html.escape(logout_path, quote=True)}'>로그아웃</a></nav></aside><main>{body}</main></div></body></html>"""
    )
