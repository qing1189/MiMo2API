"""Web 管理面板密码验证模块。

通过环境变量 WEB_PASSWORD 控制：
 - 为空 → 完全禁用鉴权（保持向后兼容）
 - 非空 → 管理页面 / /admin / /api/* 都需要先登录

鉴权机制：
 - POST /api/login  ← 登录，成功设置 HttpOnly 签名 Cookie
 - POST /api/logout ← 退出，清除 Cookie
 - GET  /api/auth/status ← 查询状态（enabled / logged_in）
 - GET  /login      ← 登录页 HTML

Cookie 使用 HMAC-SHA256 签名，签名密钥 = sha256(WEB_PASSWORD)。
更换密码会自动让所有已发 Cookie 失效。
"""

from __future__ import annotations

import hmac
import hashlib
import os
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware


# ─── 配置 ─────────────────────────────────────────────────────

COOKIE_NAME = "mimo_web_auth"
COOKIE_MAX_AGE = 7 * 24 * 3600  # 7 天

# 受保护的路径前缀（以下任一匹配即需要登录）
PROTECTED_PREFIXES = ("/api/",)
PROTECTED_EXACT = {"/", "/admin"}

# 始终放行的路径（登录相关、登录页、静态资源等）
PUBLIC_PATHS = {
    "/login",
    "/api/login",
    "/api/logout",
    "/api/auth/status",
}


# ─── 密码 / 签名工具 ──────────────────────────────────────────

def get_web_password() -> str:
    """从环境变量读取管理面板密码。"""
    return (os.getenv("WEB_PASSWORD") or "").strip()


def auth_enabled() -> bool:
    """是否启用了 Web 鉴权。"""
    return bool(get_web_password())


def _signing_key() -> bytes:
    """签名密钥：sha256(password)。"""
    return hashlib.sha256(get_web_password().encode("utf-8")).digest()


def _sign(expire_ts: int) -> str:
    """生成 'expire.sig' 格式的签名串。"""
    msg = str(expire_ts).encode("ascii")
    sig = hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()
    return f"{expire_ts}.{sig}"


def verify_cookie_token(token: Optional[str]) -> bool:
    """校验 cookie token 是否合法且未过期。"""
    if not token or "." not in token:
        return False
    try:
        exp_str, sig = token.split(".", 1)
        expire_ts = int(exp_str)
    except Exception:
        return False
    if expire_ts < int(time.time()):
        return False
    expected = hmac.new(_signing_key(), exp_str.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def issue_cookie_token(max_age: int = COOKIE_MAX_AGE) -> str:
    """签发一个新的 cookie token。"""
    expire_ts = int(time.time()) + max_age
    return _sign(expire_ts)


def is_request_authed(request: Request) -> bool:
    """请求是否已通过鉴权（已登录或鉴权未启用）。"""
    if not auth_enabled():
        return True
    token = request.cookies.get(COOKIE_NAME)
    return verify_cookie_token(token)


# ─── 中间件 ───────────────────────────────────────────────────

def _is_protected(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return False
    if path in PROTECTED_EXACT:
        return True
    for prefix in PROTECTED_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _wants_json(request: Request) -> bool:
    """根据 Accept 头或路径判断客户端期望 JSON 响应。"""
    path = request.url.path
    if path.startswith("/api/"):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept.lower()


class WebAuthMiddleware(BaseHTTPMiddleware):
    """Web 管理面板鉴权中间件。

    未启用密码时直接放行；否则对受保护路径进行 Cookie 校验，
    未通过则根据请求类型返回 401 JSON 或跳转到 /login。
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if not auth_enabled() or not _is_protected(path):
            return await call_next(request)

        token = request.cookies.get(COOKIE_NAME)
        if verify_cookie_token(token):
            return await call_next(request)

        if _wants_json(request):
            return JSONResponse(
                {"error": "unauthorized", "message": "请先登录管理面板"},
                status_code=401,
            )
        # 页面请求 → 跳转到 /login
        next_url = request.url.path
        if request.url.query:
            next_url += "?" + request.url.query
        return RedirectResponse(url=f"/login?next={next_url}", status_code=302)


# ─── 路由 ─────────────────────────────────────────────────────

router = APIRouter()

_LOGIN_HTML_PATH = Path(__file__).parent.parent / "web" / "login.html"


@router.get("/login")
async def login_page():
    """登录页（HTML）。"""
    if not auth_enabled():
        # 未启用密码直接跳回主页
        return RedirectResponse(url="/", status_code=302)
    html = _LOGIN_HTML_PATH.read_text(encoding="utf-8")
    return HTMLResponse(html)


@router.post("/api/login")
async def api_login(request: Request):
    """登录接口。成功后设置 HttpOnly Cookie。"""
    if not auth_enabled():
        return {"ok": True, "enabled": False}
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, "invalid json")

    supplied = (data.get("password") or "").strip()
    if not supplied:
        return JSONResponse({"ok": False, "error": "请输入密码"}, status_code=400)

    # 为避免时序攻击使用 compare_digest
    if not secrets.compare_digest(supplied, get_web_password()):
        return JSONResponse({"ok": False, "error": "密码错误"}, status_code=401)

    token = issue_cookie_token()
    resp = JSONResponse({"ok": True})
    # Cookie: HttpOnly + SameSite=Lax；这里没有强制 Secure，方便 http 反代场景
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return resp


@router.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@router.get("/api/auth/status")
async def api_auth_status(request: Request):
    """返回鉴权配置与当前登录状态。前端据此决定跳不跳转 /login。"""
    return {
        "enabled": auth_enabled(),
        "logged_in": is_request_authed(request),
    }
