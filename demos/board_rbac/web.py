"""FastAPI routes for the repo-local board RBAC demo."""

from __future__ import annotations

import html
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .auth_adapter import SessionVerifier, StaticUserDirectory, UserDirectory
from .csrf import csrf_field, csrf_token_for_request, issue_csrf_cookie, require_csrf
from .errors import BoardAuthenticationError, BoardAuthorizationError, BoardNotFoundError, BoardValidationError
from .models import BoardActor, BoardComment, BoardPost
from .permissions import BOARD_COMMENT_CREATE, BOARD_POST_CREATE
from .service import BoardService

RenderPage = Callable[[str, str], HTMLResponse]


@dataclass(frozen=True, slots=True)
class BoardWebSettings:
    prefix: str = "/demo-board"
    login_path: str = "/login"
    logout_path: str = "/logout"
    dashboard_path: str = "/"
    session_cookie_name: str = "coreline_board_demo_session"
    session_cookie_path: str = "/"
    csrf_cookie_name: str = "coreline_board_demo_csrf"
    secure_cookies: bool = False
    cookie_samesite: str = "lax"

    @property
    def normalized_prefix(self) -> str:
        value = self.prefix.rstrip("/")
        return value or "/"


@dataclass(frozen=True, slots=True)
class BoardUrls:
    prefix: str = "/demo-board"

    def path(self, suffix: str = "") -> str:
        base = self.prefix.rstrip("/") or ""
        if not suffix:
            return base or "/"
        clean = suffix.strip("/")
        return f"{base}/{clean}" if base else f"/{clean}"

    def new(self) -> str:
        return self.path("new")

    def post(self, post_id: str) -> str:
        return self.path(quote(post_id, safe=""))

    def post_edit(self, post_id: str) -> str:
        return self.path(f"{quote(post_id, safe='')}/edit")

    def post_delete(self, post_id: str) -> str:
        return self.path(f"{quote(post_id, safe='')}/delete")

    def comments(self, post_id: str) -> str:
        return self.path(f"{quote(post_id, safe='')}/comments")


def mount_board_routes(
    app: FastAPI,
    *,
    session_verifier: SessionVerifier,
    board_service: BoardService | None = None,
    user_directory: UserDirectory | None = None,
    render_page: RenderPage | None = None,
    settings: BoardWebSettings | None = None,
) -> APIRouter:
    config = settings or BoardWebSettings()
    service = board_service or BoardService()
    directory = user_directory or StaticUserDirectory()
    page = render_page or _default_page
    urls = BoardUrls(config.normalized_prefix)
    router = APIRouter(prefix=config.normalized_prefix, tags=["coreline-auth-board-rbac-demo"])

    def page_response(request: Request, title: str, body: str, *, status_code: int = 200, csrf_token: str | None = None) -> HTMLResponse:
        token = csrf_token or csrf_token_for_request(request, config)
        response = page(title, body)
        response.status_code = status_code
        issue_csrf_cookie(response, token, config)
        return response

    def require_actor(request: Request) -> BoardActor | RedirectResponse:
        token = request.cookies.get(config.session_cookie_name)
        if not token:
            return RedirectResponse(f"{config.login_path}?next={quote(str(request.url.path), safe='/')}", status_code=303)
        try:
            return session_verifier.verify(token)
        except BoardAuthenticationError:
            response = RedirectResponse(f"{config.login_path}?next={quote(str(request.url.path), safe='/')}", status_code=303)
            response.delete_cookie(config.session_cookie_name, path=config.session_cookie_path)
            return response

    def can_create_post(actor: BoardActor) -> bool:
        return service.can(actor, BOARD_POST_CREATE)

    def can_create_comment(actor: BoardActor) -> bool:
        return service.can(actor, BOARD_COMMENT_CREATE)

    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    def board_index(request: Request):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            posts = service.list_posts(actor)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "권한 없음", str(exc), status_code=403)
        post_cards = "".join(_post_card(service, directory, urls, actor, post, comment_count=len(service.list_comments(actor, post.id))) for post in posts)
        if not post_cards:
            post_cards = "<div class='board-empty'>아직 게시글이 없습니다. 첫 글을 작성해 권한 흐름을 확인하세요.</div>"
        create_state = "작성 가능" if can_create_post(actor) else "읽기 전용"
        create_link = f"<a class='button' href='{urls.new()}'>새 글 작성</a>" if can_create_post(actor) else "<span class='button secondary disabled'>새 글 작성 불가</span>"
        return page_response(
            request,
            "게시판",
            f"""
            <div class='board-toolbar'>
              <div><h1>게시판</h1><p class='muted'>coreline-auth repo-local board RBAC demo입니다.</p>
              <div class='board-role-summary'><span class='pill'>총 {len(posts)}개 게시글</span><span class='pill'>board role: {html.escape(actor.role)}</span><span class='pill'>{create_state}</span></div></div>
              <div class='nav'>{create_link}<a class='button secondary' href='{html.escape(config.dashboard_path)}'>테스트 계정</a></div>
            </div>
            {_board_nav(urls, can_create=can_create_post(actor))}
            <section class='card'><h2>게시글 목록</h2><div class='board-list'>{post_cards}</div></section>
            """,
        )

    @router.get("/new", response_class=HTMLResponse)
    def new_post(request: Request):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        if not can_create_post(actor):
            return _error_page(request, page_response, "게시글 작성 실패", "missing permission: post:create", status_code=403)
        token = csrf_token_for_request(request, config)
        return page_response(
            request,
            "새 게시글",
            f"""
            <h1>새 게시글</h1>{_board_nav(urls, can_create=True)}
            <section class='card'><form method='post' action='{urls.path()}'>
              {csrf_field(token)}
              <label>제목</label><input name='title' maxlength='160' required>
              <label>본문</label><textarea name='body' rows='9' required></textarea>
              <button>게시글 등록</button> <a class='button secondary' href='{urls.path()}'>목록으로</a>
            </form></section>
            """,
            csrf_token=token,
        )

    @router.post("")
    @router.post("/")
    def create_post(request: Request, title: str = Form(...), body: str = Form(...), csrf_token: str = Form("")):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            require_csrf(request, csrf_token, config)
            post = service.create_post(actor, title=title, body=body)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "게시글 작성 실패", str(exc), status_code=403)
        except BoardValidationError as exc:
            return _error_page(request, page_response, "게시글 작성 실패", str(exc), status_code=400)
        return RedirectResponse(urls.post(post.id), status_code=303)

    @router.get("/{post_id}", response_class=HTMLResponse)
    def post_detail(request: Request, post_id: str):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            detail = service.get_post_detail(actor, post_id)
        except BoardNotFoundError:
            return Response("Not found", status_code=404)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "권한 없음", str(exc), status_code=403)
        comments = "".join(_comment_row(directory, comment) for comment in detail.comments) or "<p class='muted'>아직 댓글이 없습니다.</p>"
        token = csrf_token_for_request(request, config)
        comment_form = (
            f"<form method='post' action='{urls.comments(post_id)}'>{csrf_field(token)}<label>댓글 작성</label><textarea name='body' rows='4' required></textarea><button>댓글 등록</button></form>"
            if can_create_comment(actor)
            else "<p class='muted'>댓글 작성 권한이 없습니다.</p>"
        )
        return page_response(
            request,
            detail.post.title,
            f"""
            <h1>{html.escape(detail.post.title)}</h1>{_board_nav(urls, can_create=can_create_post(actor))}
            <section class='card'><p class='muted'>작성자: {html.escape(directory.label_for_user(detail.post.author_user_id))} · 작성: {_format_dt(detail.post.created_at)} · 수정: {_format_dt(detail.post.updated_at)}</p><div class='post-body'>{html.escape(detail.post.body).replace(chr(10), '<br>')}</div>{_post_actions(service, urls, actor, detail.post, token)}</section>
            <section class='card'><h2>댓글</h2>{comments}{comment_form}</section>
            """,
            csrf_token=token,
        )

    @router.post("/{post_id}/comments")
    def create_comment(request: Request, post_id: str, body: str = Form(...), csrf_token: str = Form("")):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            require_csrf(request, csrf_token, config)
            service.create_comment(actor, post_id, body=body)
        except BoardNotFoundError:
            return Response("Not found", status_code=404)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "댓글 작성 실패", str(exc), status_code=403)
        except BoardValidationError as exc:
            return _error_page(request, page_response, "댓글 작성 실패", str(exc), status_code=400)
        return RedirectResponse(urls.post(post_id), status_code=303)

    @router.get("/{post_id}/edit", response_class=HTMLResponse)
    def edit_post(request: Request, post_id: str):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            post = service.get_post(actor, post_id)
        except BoardNotFoundError:
            return Response("Not found", status_code=404)
        if not service.can_update_post(actor, post_id):
            return _error_page(request, page_response, "권한 없음", "다른 사용자의 게시글은 수정할 수 없습니다.", status_code=403)
        token = csrf_token_for_request(request, config)
        return page_response(
            request,
            "게시글 수정",
            f"""
            <h1>게시글 수정</h1>{_board_nav(urls, can_create=can_create_post(actor))}
            <section class='card'><form method='post' action='{urls.post_edit(post_id)}'>{csrf_field(token)}
              <label>제목</label><input name='title' value='{html.escape(post.title, quote=True)}' maxlength='160' required>
              <label>본문</label><textarea name='body' rows='9' required>{html.escape(post.body)}</textarea>
              <button>저장</button> <a class='button secondary' href='{urls.post(post_id)}'>취소</a>
            </form></section>
            """,
            csrf_token=token,
        )

    @router.post("/{post_id}/edit")
    def update_post(request: Request, post_id: str, title: str = Form(...), body: str = Form(...), csrf_token: str = Form("")):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            require_csrf(request, csrf_token, config)
            service.update_post(actor, post_id, title=title, body=body)
        except BoardNotFoundError:
            return Response("Not found", status_code=404)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "게시글 수정 실패", str(exc), status_code=403)
        except BoardValidationError as exc:
            return _error_page(request, page_response, "게시글 수정 실패", str(exc), status_code=400)
        return RedirectResponse(urls.post(post_id), status_code=303)

    @router.post("/{post_id}/delete")
    def delete_post(request: Request, post_id: str, csrf_token: str = Form("")):
        auth_result = require_actor(request)
        if isinstance(auth_result, RedirectResponse):
            return auth_result
        actor = auth_result
        try:
            require_csrf(request, csrf_token, config)
            service.delete_post(actor, post_id)
        except BoardNotFoundError:
            return Response("Not found", status_code=404)
        except BoardAuthorizationError as exc:
            return _error_page(request, page_response, "게시글 삭제 실패", str(exc), status_code=403)
        return RedirectResponse(urls.path(), status_code=303)

    app.include_router(router)
    return router


def _post_card(service: BoardService, directory: UserDirectory, urls: BoardUrls, actor: BoardActor, post: BoardPost, *, comment_count: int) -> str:
    author_label = directory.label_for_user(post.author_user_id)
    owner_note = "내 글" if post.author_user_id == actor.id else html.escape(author_label)
    status = "수정 가능" if service.can_update_post(actor, post.id) else ("내 글" if post.author_user_id == actor.id else "읽기")
    action = f"<a class='button secondary' href='{urls.post_edit(post.id)}'>수정</a>" if service.can_update_post(actor, post.id) else ""
    return f"""
    <article class='board-list-row'><div class='board-title-cell'><h3><a href='{urls.post(post.id)}'>{html.escape(post.title)}</a></h3><p class='board-excerpt'>{html.escape(_excerpt(post.body))}</p></div><div class='board-meta'><b>{owner_note}</b><span>{_format_dt(post.created_at)}</span></div><span class='board-count'>{comment_count}</span><span class='pill'>{html.escape(status)}</span><div class='board-actions'><a class='button secondary' href='{urls.post(post.id)}'>보기</a>{action}</div></article>
    """


def _post_actions(service: BoardService, urls: BoardUrls, actor: BoardActor, post: BoardPost, csrf_token: str) -> str:
    if service.can_update_post(actor, post.id) or service.can_delete_post(actor, post.id):
        edit_link = f"<a class='button secondary' href='{urls.post_edit(post.id)}'>수정</a>" if service.can_update_post(actor, post.id) else ""
        delete_form = f"<form method='post' action='{urls.post_delete(post.id)}' style='display:inline'>{csrf_field(csrf_token)}<button class='danger'>삭제</button></form>" if service.can_delete_post(actor, post.id) else ""
        return f"<div class='nav'>{edit_link}{delete_form}</div>"
    return "<p class='muted'>수정/삭제할 수 없습니다.</p>"


def _comment_row(directory: UserDirectory, comment: BoardComment) -> str:
    return f"<article class='comment'><p>{html.escape(comment.body)}</p><p class='muted'>{html.escape(directory.label_for_user(comment.author_user_id))} · {_format_dt(comment.created_at)}</p></article>"


def _board_nav(urls: BoardUrls, *, can_create: bool) -> str:
    create = f"<a class='button' href='{urls.new()}'>새 글 작성</a>" if can_create else "<span class='button secondary disabled'>새 글 작성 불가</span>"
    return f"<div class='nav'>{create}<a class='button secondary' href='{urls.path()}'>게시판</a></div>"


def _excerpt(value: str, *, limit: int = 96) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _error_page(request: Request, page_response, title: str, detail: str, *, status_code: int) -> HTMLResponse:
    return page_response(request, title, f"<section class='card error'><h1>{html.escape(title)}</h1><p>{html.escape(detail)}</p></section>", status_code=status_code)


def _default_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><title>{html.escape(title)}</title>{body}")
