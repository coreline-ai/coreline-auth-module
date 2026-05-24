"""Board web UI for the Coreline Auth demo app.

The UI is intentionally thin: it verifies the session cookie and delegates all
ownership/role decisions to ``BoardService``. This keeps the demo close to a
real SaaS integration where the web layer never hand-rolls authorization rules.
"""

from __future__ import annotations

import html
from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from coreline_auth import AuthenticationFailed, AuthorizationDenied, AuthValidationError, CorelineAuthService, Principal
from coreline_auth.fastapi_adapter import SESSION_COOKIE_NAME

from .board_models import BoardComment, BoardPost
from .board_service import BoardService

RenderPage = Callable[[str, str], HTMLResponse]


def mount_board_routes(
    app: FastAPI,
    auth: CorelineAuthService,
    *,
    board_service: BoardService | None = None,
    render_page: RenderPage | None = None,
    prefix: str = "/board",
) -> APIRouter:
    """Mount cookie-session based board pages onto the demo app."""

    service = board_service or BoardService(auth)
    page = render_page or _default_page
    router = APIRouter(prefix=prefix, tags=["coreline-auth-board"])

    def require_session(request: Request) -> tuple[Principal, str] | RedirectResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return RedirectResponse("/login", status_code=303)
        try:
            return auth.verify_session(token), token
        except AuthenticationFailed:
            response = RedirectResponse("/login", status_code=303)
            response.delete_cookie(SESSION_COOKIE_NAME, path="/")
            return response

    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    def board_index(request: Request):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        principal, token = auth_result
        try:
            posts = service.list_posts(token)
        except AuthorizationDenied as exc:
            return _error_page(page, "권한 없음", str(exc), status_code=403)
        post_cards = "".join(
            _post_card(
                auth,
                service,
                token,
                principal,
                post,
                comment_count=len(service.list_comments(token, post.id)),
            )
            for post in posts
        )
        if not post_cards:
            post_cards = "<div class='board-empty'>아직 게시글이 없습니다. 첫 글을 작성해 권한 흐름을 확인하세요.</div>"
        can_create = "post:create" in principal.session.permissions
        return page(
            "게시판",
            f"""
            <div class='board-toolbar'>
              <div>
                <h1>게시판</h1>
                <p class='muted'>실제 게시판 형태로 목록/상세/댓글/수정·삭제 권한을 한 화면에서 검증합니다.</p>
                <div class='board-role-summary'>
                  <span class='pill'>총 {len(posts)}개 게시글</span>
                  <span class='pill'>role: {html.escape(principal.session.role.value)}</span>
                  <span class='pill'>{'작성 가능' if can_create else '읽기 전용'}</span>
                </div>
              </div>
              <div class='nav'>
                <a class='button' href='/board/new'>새 글 작성</a>
                <a class='button secondary' href='/'>대시보드</a>
              </div>
            </div>
            {_board_nav(principal)}
            <section class='card'>
              <h2>게시글 목록</h2>
              <div class='board-list'>
                <div class='board-list-head'>
                  <span>제목</span><span>작성자</span><span>댓글</span><span>권한 상태</span><span style='text-align:right'>작업</span>
                </div>
                {post_cards}
              </div>
            </section>
            """,
        )

    @router.get("/new", response_class=HTMLResponse)
    def new_post(request: Request):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        principal, _ = auth_result
        return page(
            "새 게시글",
            f"""
            <h1>새 게시글</h1>
            {_board_nav(principal)}
            <section class='card'>
              <form method='post' action='/board'>
                <label>제목</label><input name='title' maxlength='160' required>
                <label>본문</label><textarea name='body' rows='9' required></textarea>
                <button>게시글 등록</button>
                <a class='button secondary' href='/board'>목록으로</a>
              </form>
            </section>
            """,
        )

    @router.post("")
    @router.post("/")
    def create_post(request: Request, title: str = Form(...), body: str = Form(...)):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        _, token = auth_result
        try:
            post = service.create_post(token, title=title, body=body)
        except (AuthorizationDenied, AuthValidationError) as exc:
            return _error_page(page, "게시글 작성 실패", str(exc), status_code=403 if isinstance(exc, AuthorizationDenied) else 400)
        return RedirectResponse(f"/board/{post.id}", status_code=303)

    @router.get("/{post_id}", response_class=HTMLResponse)
    def post_detail(request: Request, post_id: str):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        principal, token = auth_result
        try:
            detail = service.get_post_detail(token, post_id)
        except AuthValidationError:
            return Response("Not found", status_code=404)
        except AuthorizationDenied as exc:
            return _error_page(page, "권한 없음", str(exc), status_code=403)
        comments = "".join(_comment_row(auth, comment) for comment in detail.comments) or "<p class='muted'>아직 댓글이 없습니다.</p>"
        return page(
            detail.post.title,
            f"""
            <h1>{html.escape(detail.post.title)}</h1>
            {_board_nav(principal)}
            <section class='card'>
              <p class='muted'>작성자: {html.escape(_author_email(auth, detail.post.author_user_id))} · 작성: {_format_dt(detail.post.created_at)} · 수정: {_format_dt(detail.post.updated_at)}</p>
              <div class='post-body'>{html.escape(detail.post.body).replace(chr(10), '<br>')}</div>
              {_post_actions(service, token, detail.post)}
            </section>
            <section class='card'>
              <h2>댓글</h2>
              {comments}
              <form method='post' action='/board/{html.escape(post_id)}/comments'>
                <label>댓글 작성</label><textarea name='body' rows='4' required></textarea>
                <button>댓글 등록</button>
              </form>
            </section>
            """,
        )

    @router.post("/{post_id}/comments")
    def create_comment(request: Request, post_id: str, body: str = Form(...)):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        _, token = auth_result
        try:
            service.create_comment(token, post_id, body=body)
        except AuthValidationError:
            return Response("Not found", status_code=404)
        except AuthorizationDenied as exc:
            return _error_page(page, "댓글 작성 실패", str(exc), status_code=403)
        return RedirectResponse(f"/board/{html.escape(post_id)}", status_code=303)

    @router.get("/{post_id}/edit", response_class=HTMLResponse)
    def edit_post(request: Request, post_id: str):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        principal, token = auth_result
        try:
            post = service.get_post(token, post_id)
        except AuthValidationError:
            return Response("Not found", status_code=404)
        if not service.can_update_post(token, post_id):
            return _error_page(page, "권한 없음", "다른 사용자의 게시글은 수정할 수 없습니다.", status_code=403)
        return page(
            "게시글 수정",
            f"""
            <h1>게시글 수정</h1>
            {_board_nav(principal)}
            <section class='card'>
              <form method='post' action='/board/{html.escape(post_id)}/edit'>
                <label>제목</label><input name='title' value='{html.escape(post.title, quote=True)}' maxlength='160' required>
                <label>본문</label><textarea name='body' rows='9' required>{html.escape(post.body)}</textarea>
                <button>저장</button>
                <a class='button secondary' href='/board/{html.escape(post_id)}'>취소</a>
              </form>
            </section>
            """,
        )

    @router.post("/{post_id}/edit")
    def update_post(request: Request, post_id: str, title: str = Form(...), body: str = Form(...)):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        _, token = auth_result
        try:
            service.update_post(token, post_id, title=title, body=body)
        except AuthValidationError:
            return Response("Not found", status_code=404)
        except AuthorizationDenied as exc:
            return _error_page(page, "게시글 수정 실패", str(exc), status_code=403)
        return RedirectResponse(f"/board/{html.escape(post_id)}", status_code=303)

    @router.post("/{post_id}/delete")
    def delete_post(request: Request, post_id: str):
        auth_result = require_session(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        _, token = auth_result
        try:
            service.delete_post(token, post_id)
        except AuthValidationError:
            return Response("Not found", status_code=404)
        except AuthorizationDenied as exc:
            return _error_page(page, "게시글 삭제 실패", str(exc), status_code=403)
        return RedirectResponse("/board", status_code=303)

    app.include_router(router)
    return router


def _post_card(auth: CorelineAuthService, service: BoardService, token: str, principal: Principal, post: BoardPost, *, comment_count: int) -> str:
    author_email = _author_email(auth, post.author_user_id)
    owner_note = "내 글" if post.author_user_id == principal.user_id else html.escape(author_email)
    status = "수정 가능" if service.can_update_post(token, post.id) else ("내 글" if post.author_user_id == principal.user_id else "읽기")
    action = ""
    if service.can_update_post(token, post.id):
        action = f"<a class='button secondary' href='/board/{html.escape(post.id)}/edit'>수정</a>"
    detail_link = f"<a class='button secondary' href='/board/{html.escape(post.id)}'>보기</a>"
    return f"""
    <article class='board-list-row'>
      <div class='board-title-cell'>
        <h3><a href='/board/{html.escape(post.id)}'>{html.escape(post.title)}</a></h3>
        <p class='board-excerpt'>{html.escape(_excerpt(post.body))}</p>
      </div>
      <div class='board-meta'><b>{owner_note}</b><span>{_format_dt(post.created_at)}</span></div>
      <span class='board-count'>{comment_count}</span>
      <span class='pill'>{html.escape(status)}</span>
      <div class='board-actions'>{detail_link}{action}</div>
    </article>
    """


def _post_actions(service: BoardService, token: str, post: BoardPost) -> str:
    post_id = html.escape(post.id)
    if service.can_update_post(token, post.id) or service.can_delete_post(token, post.id):
        edit_link = f"<a class='button secondary' href='/board/{post_id}/edit'>수정</a>" if service.can_update_post(token, post.id) else ""
        delete_form = f"""
          <form method='post' action='/board/{post_id}/delete' style='display:inline'>
            <button class='danger'>삭제</button>
          </form>
        """ if service.can_delete_post(token, post.id) else ""
        return f"<div class='nav'>{edit_link}{delete_form}</div>"
    return "<p class='notice'>다른 사용자의 글은 수정/삭제할 수 없습니다.</p>"


def _comment_row(auth: CorelineAuthService, comment: BoardComment) -> str:
    return f"""
    <article class='comment'>
      <p>{html.escape(comment.body).replace(chr(10), '<br>')}</p>
      <p class='muted'>{html.escape(_author_email(auth, comment.author_user_id))} · {_format_dt(comment.created_at)}</p>
    </article>
    """


def _board_nav(principal: Principal) -> str:
    return f"""
    <div class='nav'>
      <a class='button' href='/board/new'>새 글 작성</a>
      <a class='button secondary' href='/board'>게시판</a>
      <a class='button secondary' href='/'>대시보드</a>
      <a class='button secondary' href='/admin'>관리자</a>
      <form method='post' action='/logout' style='display:inline'><button class='danger'>로그아웃</button></form>
    </div>
    <p class='muted'>현재 사용자: {html.escape(principal.email)} / role <code>{html.escape(principal.session.role.value)}</code></p>
    """


def _author_email(auth: CorelineAuthService, user_id: str) -> str:
    user = auth.storage.get_user(user_id)
    return user.primary_email if user else user_id


def _excerpt(value: str, *, limit: int = 96) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + "…"


def _error_page(page: RenderPage, title: str, message: str, *, status_code: int) -> HTMLResponse:
    response = page(
        title,
        f"""
        <section class='card error'>
          <h1>{html.escape(title)}</h1>
          <p>{html.escape(message)}</p>
          <a class='button secondary' href='/board'>게시판으로 돌아가기</a>
        </section>
        """,
    )
    response.status_code = status_code
    return response


def _default_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>{_DEFAULT_STYLE}</head><body><main>{body}</main></body></html>"
    )


def _format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


_DEFAULT_STYLE = """
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e5e7eb}
main{max-width:920px;margin:0 auto;padding:48px 20px}.card{background:#111827;border:1px solid #334155;border-radius:18px;padding:24px;margin:18px 0;box-shadow:0 10px 30px rgba(0,0,0,.25)}
h1{font-size:34px;margin:0 0 10px}.muted{color:#94a3b8}label{display:block;margin:14px 0 6px;color:#cbd5e1}input,textarea{width:100%;box-sizing:border-box;border:1px solid #475569;border-radius:12px;padding:12px;background:#020617;color:#e5e7eb}
button,.button{display:inline-block;margin-top:16px;background:#10b981;color:#04111d;border:0;border-radius:12px;padding:11px 16px;font-weight:700;text-decoration:none;cursor:pointer}.secondary{background:#334155;color:#e5e7eb}.danger{background:#fb7185;color:#2b0b12}.nav{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.notice{border-left:4px solid #f59e0b;background:#3a280a;padding:12px;border-radius:10px;color:#fde68a}.error{border-left-color:#fb7185;background:#3b1119}.board-row,.comment{border-top:1px solid #334155;padding:14px 0}.post-body{line-height:1.7;white-space:normal}
a{color:#7dd3fc}
</style>
"""
