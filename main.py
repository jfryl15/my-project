#!/usr/bin/env python3
"""
ALOO PANEL ULTIMATE: professional multi-server VLESS management platform.
Version 3.0.0 — Phase 1: modular core, rebrand, hardened auth,
rich dashboard, advanced user management.
"""
import asyncio
import base64
import hashlib
import io
import json
import os
import re
import secrets
import time
import uuid as uuid_lib
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import quote

import httpx
import psutil
import qrcode
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from storage import store, hash_password, verify_password, DATA_DIR, DB_PATH
import xray_manager
import telegram_bot
import plugins as plugin_registry
import ai_assistant
from core import users as core_users
from core import servers as core_servers
from core import security as core_security
from colo_map import describe_colo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = "3.1.1"
APP_NAME = "ALOO PANEL"
APP_EDITION = "ULTIMATE"
PANEL_NAME = os.environ.get("PANEL_NAME", "ALOO PANEL")
TELEGRAM_CONTACT = os.environ.get("TELEGRAM_CONTACT", "https://t.me/ITSESMAT")
OTA_REPO = "youdidking/stanngv2"
OTA_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": f"ALOO-PANEL/{APP_VERSION}",
}
SESSION_COOKIE = "stanng_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7
LOGIN_MAX_ATTEMPTS = 6
LOGIN_LOCK_SECONDS = 5 * 60

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

runtime = {
    "active": {},
    "pending_traffic": {},
    "lock": asyncio.Lock(),
}
last_seen = {}  # ✅ اضافه شده: uid -> timestamp of last traffic

DOH_PRIMARY = "https://1.1.1.1/dns-query"
DOH_SECONDARY = "https://8.8.8.8/dns-query"
doh_http_client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    flush_task = asyncio.create_task(_periodic_flush())
    keepalive_task = asyncio.create_task(_keep_alive_loop())
    housekeep_task = asyncio.create_task(_housekeeping_loop())
    tg_task = asyncio.create_task(_telegram_poll_loop())
    srv_task = asyncio.create_task(_server_poll_loop())
    bkp_task = asyncio.create_task(_backup_loop())

    db = await store.get()
    xray_manager.generate_xray_config(
        live_inbounds_for_xray(db),
        log_level=((db.get("settings") or {}).get("xray_log_level") or "warning"))
    xray_manager.restart_xray()

    yield
    for t in (flush_task, keepalive_task, housekeep_task, tg_task, srv_task, bkp_task):
        t.cancel()
    await doh_http_client.aclose()


app = FastAPI(title="ALOO PANEL ULTIMATE", version=APP_VERSION, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in core_security.SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


MAINT_ALLOW_PATHS = {"/", "/health", "/login", "/setup", "/api/login", "/api/2fa/login",
                     "/api/setup-status", "/api/setup"}
# End-user infrastructure keeps working during maintenance; only the
# management panel is gated.
MAINT_ALLOW_PREFIXES = ("/static", "/sub/", "/s/", "/status/", "/api/status/", "/dns-query")


@app.middleware("http")
async def _maintenance_gate(request: Request, call_next):
    try:
        db = await store.get()
        s = db.get("settings") or {}
        if db.get("admin") and s.get("maintenance_enabled"):
            path = request.url.path
            if path not in MAINT_ALLOW_PATHS and not path.startswith(MAINT_ALLOW_PREFIXES):
                user = await current_username(request)
                if not user:
                    msg = s.get("maintenance_message") or "Under maintenance."
                    if path.startswith("/api/"):
                        return JSONResponse({"detail": "maintenance"}, status_code=503)
                    return HTMLResponse(
                        f"<!DOCTYPE html><html lang='fa' dir='rtl'><head><meta charset='utf-8'>"
                        f"<title>تعمیرات</title></head><body style='font-family:Tahoma;display:grid;"
                        f"place-items:center;min-height:100vh;background:#111;color:#eee'>"
                        f"<div style='text-align:center'><h1>🛠 تعمیرات</h1><p>{msg}</p></div>"
                        f"</body></html>", status_code=503)
    except Exception:
        pass
    return await call_next(request)


# ------------------------------------------------------------------ helpers
def get_serializer(db) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(db["secret_key"], salt="stanng-session")


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def find_admin(db, username: str):
    for a in db.get("admins", []):
        if a.get("username") == username:
            return a
    return None


def admin_credential_ok(admin, password: str) -> bool:
    if not admin or not admin.get("enabled", True):
        return False
    try:
        return verify_password(password, admin.get("salt", ""), admin.get("password_hash", ""))
    except Exception:
        return False


async def current_username(request: Request) -> Optional[str]:
    db = await store.get()
    if not db.get("admin"):
        return None
    # 1) API token (for Telegram bot / external integrations): "Authorization: Bearer sspanel_..."
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        raw = auth.split(None, 1)[1].strip()
        digest = hashlib.sha256(raw.encode()).hexdigest()
        for t in db.get("api_tokens", []):
            if secrets.compare_digest(t.get("hash", ""), digest):
                return f"token:{t.get('name', 'api')}"
        return None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    s = get_serializer(db)
    try:
        data = s.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    username = data.get("u")
    admin = find_admin(db, username)
    if admin is not None:
        if not admin.get("enabled", True):
            return None
        if data.get("v") != (admin.get("password_hash") or "")[:12]:
            return None
        return admin["username"]
    # legacy fallback (pre-v8 single admin)
    admin = db["admin"]
    if data.get("u") != admin.get("username"):
        return None
    if data.get("v") != admin.get("password_hash", "")[:12]:
        return None
    return admin["username"]


async def require_auth(request: Request) -> str:
    user = await current_username(request)
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    if user.startswith("token:"):
        auth = request.headers.get("authorization", "")
        raw = auth.split(None, 1)[1].strip() if " " in auth else ""
        dg = hashlib.sha256(raw.encode()).hexdigest()

        def _touch(db, _dg=dg):
            for t in db.get("api_tokens", []):
                if secrets.compare_digest(t.get("hash", ""), _dg):
                    t["last_used"] = time.time()
        try:
            await store.mutate(_touch)
        except Exception:
            pass
    return user


async def actor_role(request: Request, db=None) -> str:
    """Role of the caller: owner for API tokens, admin record role for sessions."""
    db = db or await store.get()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        raw = auth.split(None, 1)[1].strip() if " " in auth else ""
        dg = hashlib.sha256(raw.encode()).hexdigest()
        for t in db.get("api_tokens", []):
            if secrets.compare_digest(t.get("hash", ""), dg):
                return "owner"
        return ""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return ""
    s = get_serializer(db)
    try:
        data = s.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return ""
    admin = find_admin(db, data.get("u"))
    if admin is not None:
        return admin.get("role", "viewer") if admin.get("enabled", True) else ""
    if db.get("admin") and data.get("u") == db["admin"].get("username"):
        return "owner"
    return ""


def _role_overrides(db) -> dict:
    ov = (db.get("settings") or {}).get("role_overrides") or {}
    return ov if isinstance(ov, dict) else {}


def require_perm(perm: str):
    async def dep(request: Request) -> str:
        user = await current_username(request)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        db = await store.get()
        role = await actor_role(request, db)
        if not core_security.has_perm(role, perm, _role_overrides(db)):
            raise HTTPException(status_code=403, detail="forbidden")
        return user
    return dep


async def log_audit(actor: str, action: str, detail: str = "", ip: str = "", ref: str = ""):
    def _a(db):
        logs = db.setdefault("audit_log", [])
        logs.append({"ts": time.time(), "actor": actor[:64], "action": action[:64],
                     "detail": (detail or "")[:500], "ip": (ip or "")[:64], "ref": (ref or "")[:64]})
        while len(logs) > 500:
            logs.pop(0)
    try:
        await store.mutate(_a)
    except Exception:
        pass


NOTIF_DEDUPE_SECONDS = 6 * 3600


async def push_notification(severity: str, code: str, params: dict | None = None):
    """Append an in-panel notification. Same code+key is not repeated within 6h."""
    params = params or {}
    if severity not in ("info", "warning", "error"):
        severity = "info"
    nid = {"v": None}

    def _a(db):
        notifs = db.setdefault("notifications", [])
        now = time.time()
        key = params.get("key") or params.get("name") or ""
        for n in reversed(notifs[-30:]):
            if n.get("code") == code and (n.get("params") or {}).get("key", n.get("params", {}).get("name")) == key:
                if now - n.get("ts", 0) < NOTIF_DEDUPE_SECONDS:
                    return
                break
        nid["v"] = gen_uid()
        notifs.append({"id": nid["v"], "ts": now, "severity": severity,
                       "code": code[:64], "params": {k: str(v)[:120] for k, v in params.items()},
                       "read": False})
        while len(notifs) > 200:
            notifs.pop(0)
    try:
        await store.mutate(_a)
    except Exception:
        pass
    return nid["v"]


def collect_user_alerts(db) -> list:
    """Scan users for quota/expiry crossings. Mutates notified flags, returns
    fresh events (no IO — the caller sends telegram + pushes notifications)."""
    events = []
    s = db.setdefault("settings", {})
    warned_pct = float(s.get("quota_warn_percent") or 80)
    warn_days = int(s.get("expiry_warn_days") or 3)
    notified = db.setdefault("notified", {})
    now = time.time()
    for ib in db.get("inbounds", []):
        try:
            st = inbound_status(ib)
        except Exception:
            continue
        key = notified.setdefault(ib.get("uid", ""), {})
        if s.get("notify_quota", True) and st["quota_bytes"] > 0:
            pct = (st["used"] / st["quota_bytes"]) * 100 if st["quota_bytes"] else 0
            if (pct >= warned_pct or st["quota_exceeded"]) and not key.get("quota"):
                key["quota"] = True
                events.append({
                    "kind": "quota", "uid": ib.get("uid"), "name": ib.get("name", "?"),
                    "text": f"⚠️ <b>هشدار حجم</b>\n👤 {ib.get('name')}\n📦 مصرف: {st['used']/1024**3:.2f}GB",
                    "params": {"name": ib.get("name", "?"), "pct": round(pct, 1),
                               "key": ib.get("uid", "")},
                })
            elif pct < warned_pct - 5 and not st["quota_exceeded"]:
                key["quota"] = False
        if s.get("notify_expiry", True) and ib.get("expire_at"):
            days = (ib["expire_at"] - now) / 86400
            if (days <= warn_days or st["expired"]) and not key.get("expiry"):
                key["expiry"] = True
                left = "منقضی شده" if st["expired"] else f"{days:.1f} روز مانده"
                events.append({
                    "kind": "expiry", "uid": ib.get("uid"), "name": ib.get("name", "?"),
                    "text": f"⏳ <b>هشدار انقضا</b>\n👤 {ib.get('name')}\n📅 {left}",
                    "params": {"name": ib.get("name", "?"), "days": round(days, 1),
                               "key": ib.get("uid", "")},
                })
            elif days > warn_days + 1:
                key["expiry"] = False
    return events


_active_sys_alerts: set = set()


def live_inbounds_for_xray(db) -> list:
    """Return only users that should be active in xray (respects auto_disable)."""
    s = db.get("settings", {}) or {}
    if not s.get("auto_disable_exhausted", True):
        return [ib for ib in db.get("inbounds", []) if ib.get("enabled", True)]
    out = []
    for ib in db.get("inbounds", []):
        if not ib.get("enabled", True):
            continue
        try:
            st = inbound_status(ib)
            if not st["live_enabled"]:
                continue
        except Exception:
            pass
        out.append(ib)
    return out


def refresh_xray(db):
    try:
        level = ((db.get("settings") or {}).get("xray_log_level") or "warning").strip()
        if level not in ("debug", "info", "warning", "error", "none"):
            level = "warning"
        xray_manager.generate_xray_config(live_inbounds_for_xray(db), log_level=level)
        xray_manager.restart_xray()
    except Exception:
        pass


def set_session_cookie(response: Response, request: Request, db, username: str):
    s = get_serializer(db)
    admin = find_admin(db, username)
    if admin is None and db.get("admin", {}).get("username") == username:
        admin = db["admin"]
    v = (admin.get("password_hash") or "")[:12] if admin else ""
    token = s.dumps({"u": username, "v": v})
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_MAX_AGE, httponly=True,
        samesite="lax", secure=(request.url.scheme == "https"),
        path="/",
    )


def gen_uid() -> str:
    return secrets.token_hex(8)


def gen_uuid() -> str:
    return str(uuid_lib.uuid4())


def public_host(request: Request, db) -> str:
    override = (db.get("settings") or {}).get("public_domain") or ""
    if override:
        return override.strip().split(":")[0]
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname or ""
    if host.startswith("["):
        return host.split("]")[0].lstrip("[")
    return host.split(":")[0]


def get_scheme(request: Request = None) -> str:
    return "https"


def inbound_by_uid(db, uid: str):
    for ib in db["inbounds"]:
        if ib["uid"] == uid:
            return ib
    return None


def plan_by_id(db, pid: str):
    for p in db.get("plans", []):
        if p.get("id") == pid:
            return p
    return None


def apply_plan_to_inbound(ib, plan, now: float | None = None):
    """Apply a plan's quota/duration/device-limit to a user (keeps usage)."""
    now = now if now is not None else time.time()
    ib["plan_id"] = plan["id"]
    ib["plan_name"] = plan.get("name", "")
    ib["quota_gb"] = float(plan.get("traffic_gb") or 0)
    ib["max_connections"] = int(plan.get("device_limit") or 0)
    dur = int(plan.get("duration_days") or 0)
    ib["expire_days"] = dur
    ib["expire_at"] = (now + dur * 86400) if dur > 0 else None


def resolve_sub(db, ref: str):
    """Find a user by uid (legacy) or sub_token (canonical)."""
    for ib in db.get("inbounds", []):
        if ib.get("uid") == ref or ib.get("sub_token") == ref:
            return ib
    return None


def sub_token_of(ib) -> str:
    return ib.get("sub_token") or ib.get("uid")


def canonical_sub_url(request: Request, db, ib) -> str:
    return f"{get_scheme(request)}://{public_host(request, db)}/s/{sub_token_of(ib)}"


def require_active_sub(ib):
    if ib.get("sub_enabled", True) is False:
        raise HTTPException(403, "subscription-disabled")


def inbound_status(ib) -> dict:
    now = time.time()
    quota_bytes = (ib.get("quota_gb") or 0) * 1024 ** 3
    used = (ib.get("used_up") or 0) + (ib.get("used_down") or 0)
    quota_exceeded = quota_bytes > 0 and used >= quota_bytes
    expired = False
    expire_at = ib.get("expire_at")
    if expire_at:
        expired = now >= expire_at
    live_enabled = ib.get("enabled", True) and not quota_exceeded and not expired
    active_count = len(runtime["active"].get(ib["uid"], {}))
    req_exceeded = (ib.get("max_requests") or 0) > 0 and (ib.get("request_count") or 0) >= ib["max_requests"]
    return {
        "quota_bytes": quota_bytes,
        "used": used,
        "quota_exceeded": quota_exceeded,
        "expired": expired,
        "live_enabled": live_enabled and not req_exceeded,
        "active_connections": active_count,
        "request_exceeded": req_exceeded,
        "days_left": max(0, int((expire_at - now) // 86400)) if expire_at else None,
    }


# ------------------------------------------------------------------ background tasks
async def _periodic_flush():
    global last_seen
    while True:
        try:
            await asyncio.sleep(5)
            snapshot = await xray_manager.get_xray_stats()

            def _apply(db, snap=snapshot):
                total_up = total_down = 0
                if snap:
                    for uid, delta in snap.items():
                        ib = inbound_by_uid(db, uid)
                        if ib:
                            ib["used_up"] = ib.get("used_up", 0) + delta.get("up", 0)
                            ib["used_down"] = ib.get("used_down", 0) + delta.get("down", 0)
                            total_up += delta.get("up", 0)
                            total_down += delta.get("down", 0)
                        # ✅ به‌روزرسانی زمان آخرین فعالیت کاربر
                        last_seen[uid] = time.time()
                    db["stats"]["total_up"] = db["stats"].get("total_up", 0) + total_up
                    db["stats"]["total_down"] = db["stats"].get("total_down", 0) + total_down

                hourly = db["stats"].setdefault("hourly", [])
                bucket = int(time.time() // 3600) * 3600
                if hourly and hourly[-1]["t"] == bucket:
                    hourly[-1]["up"] += total_up
                    hourly[-1]["down"] += total_down
                else:
                    hourly.append({"t": bucket, "up": total_up, "down": total_down})
                while len(hourly) > 72:
                    hourly.pop(0)

            await store.mutate(_apply)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(2)
        try:
            xray_manager.parse_access_log()
        except Exception:
            pass


async def _housekeeping_loop():
    while True:
        try:
            await asyncio.sleep(30)

            # 1) scan quota/expiry crossings (sync mutation, no IO inside)
            events = []

            def _wrap(db):
                events.extend(collect_user_alerts(db))
            await store.mutate(_wrap)

            # 2) deliver: telegram + in-panel notifications (outside the lock)
            for ev in events:
                try:
                    await telegram_bot.notify(store, ev["kind"], ev["text"])
                except Exception:
                    pass
                try:
                    if ev["kind"] == "quota":
                        await push_notification("warning", "quota_warning", ev["params"])
                    else:
                        await push_notification("warning", "expiry_warning", ev["params"])
                except Exception:
                    pass

            # 3) system load transitions (edge-triggered, no spam)
            try:
                cpu = float(psutil.cpu_percent(interval=0.5))
                mem = float(psutil.virtual_memory().percent)
                pairs = (("high_cpu", cpu, 85, 75), ("high_mem", mem, 90, 80))
                for code, val, on, off in pairs:
                    if val >= on and code not in _active_sys_alerts:
                        _active_sys_alerts.add(code)
                        await push_notification("warning", code, {"v": round(val, 1), "key": code})
                    elif val < off and code in _active_sys_alerts:
                        _active_sys_alerts.discard(code)
            except Exception:
                pass

            # 4) xray / telegram error transitions (edge-triggered, no spam)
            try:
                import xray_manager as _xm
                xb = os.path.exists(getattr(_xm, "XRAY_BIN", "/usr/local/bin/xray"))
                proc = getattr(_xm, "xray_process", None)
                x_down = xb and (proc is None or proc.poll() is not None)
                if x_down and "xray_error" not in _active_sys_alerts:
                    _active_sys_alerts.add("xray_error")
                    await push_notification("error", "xray_error", {"key": "xray"})
                    try:
                        await telegram_bot.notify(store, "server",
                            "🔴 <b>خطای Xray</b>\nموتور Xray متوقف شده است.")
                    except Exception:
                        pass
                elif not x_down and "xray_error" in _active_sys_alerts:
                    _active_sys_alerts.discard("xray_error")
                poll = telegram_bot.poll_state_summary()
                db0 = await store.get()
                tg_bad = bool((db0.get("settings") or {}).get("telegram_bot_token", "").strip()) \
                    and bool(poll.get("last_ts")) and poll.get("last_ok") is False and not poll.get("fresh")
                if tg_bad and "telegram_error" not in _active_sys_alerts:
                    _active_sys_alerts.add("telegram_error")
                    await push_notification("error", "telegram_error",
                                            {"key": "telegram", "error": poll.get("error", "")})
                elif not tg_bad and "telegram_error" in _active_sys_alerts:
                    _active_sys_alerts.discard("telegram_error")
            except Exception:
                pass

            # refresh xray to enforce expiry/quota
            try:
                db = await store.get()
                refresh_xray(db)
            except Exception:
                pass
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(5)


async def _telegram_poll_loop():
    def _creds():
        db = store.get_sync()
        s = (db.get("settings") or {})
        token, chat, _src = telegram_bot.resolve_creds(s)
        return (token, chat, bool(s.get("telegram_enabled")))
    try:
        await telegram_bot.poll_loop(store, _creds)
    except asyncio.CancelledError:
        pass
    except Exception:
        await asyncio.sleep(5)


# ------------------------- Phase 3: multi-server federation -------------------------
# A "server" is either this panel (local) or another ALOO PANEL reachable
# through its real HTTP API with an API token (Settings → API Tokens on
# the remote panel). No fake nodes: every value shown comes from a live
# /stats + /api/me (+ /api/system) poll, cached every 30s.
SERVER_POLL_INTERVAL = 30
SERVER_FAIL_THRESHOLD = 2


def normalize_host(raw: str) -> str:
    h = (raw or "").strip().rstrip("/")
    if not h:
        return ""
    if not h.startswith(("http://", "https://")):
        h = "https://" + h
    return h


def mask_server(srv: dict) -> dict:
    tok = srv.get("token") or ""
    out = {k: srv.get(k) for k in (
        "id", "name", "host", "ip", "port", "country", "city", "provider",
        "stype", "os", "arch", "weight", "maintenance",
        "enabled", "created_at", "last_check", "last_seen", "last_success",
        "online", "fail_count", "metrics", "note", "latency_ms",
        "version_compat", "health", "load", "group_ids",
        "error_rate", "packet_loss", "agent_version", "tags")}
    out["has_token"] = bool(tok)
    out["token_prefix"] = (tok[:10] + "…") if len(tok) > 14 else ""
    return out


def server_by_id(db, sid: str):
    for s in db.get("servers", []):
        if s.get("id") == sid:
            return s
    return None


async def fetch_remote_metrics(host: str, token: str):
    """Live poll of a remote ALOO PANEL. Raises on any failure."""
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=8) as c:
        me = await c.get(host + "/api/me", headers=headers)
        me.raise_for_status()
        st = await c.get(host + "/stats", headers=headers)
        st.raise_for_status()
        try:
            sy = await c.get(host + "/api/system", headers=headers)
            sys_j = sy.json() if sy.status_code == 200 else {}
        except Exception:
            sys_j = {}
        try:
            lv = await c.get(host + "/api/live", headers=headers)
            live_j = lv.json() if lv.status_code == 200 else {}
        except Exception:
            live_j = {}
    return me.json(), st.json(), sys_j, live_j


def summarize_remote_metrics(me_j: dict, st_j: dict, sys_j: dict | None = None, live_j: dict | None = None) -> dict:
    buckets = st_j.get("users_by_status") or {}
    sys_j = sys_j or {}
    live_j = live_j or {}
    disk = (sys_j.get("disk") or {})
    return {
        "users": int(buckets.get("total") or st_j.get("inbounds_count") or 0),
        "users_by_status": buckets,
        "total_up": int(st_j.get("total_up") or 0),
        "total_down": int(st_j.get("total_down") or 0),
        "cpu": round(float(st_j.get("cpu_percent") or 0), 1),
        "mem": round(float(st_j.get("mem_percent") or 0), 1),
        "disk_percent": disk.get("percent"),
        "disk_used_gb": disk.get("used_gb"),
        "disk_total_gb": disk.get("total_gb"),
        "net_up_bps": live_j.get("net_up_bps"),
        "net_down_bps": live_j.get("net_down_bps"),
        "active_connections": int(st_j.get("active_connections") or 0),
        "uptime_seconds": int(st_j.get("uptime_seconds") or 0),
        "version": me_j.get("app_version") or "?",
        "xray": ((st_j.get("services") or {}).get("xray") or {}).get("status", "?"),
        "location": (st_j.get("location") or {}).get("city") or "?",
        "platform": sys_j.get("platform") or "",
        "arch": sys_j.get("arch") or "",
    }


HISTORY_PER_SERVER = 1000
HISTORY_TOTAL = 5000


def _record_history(db, sid: str, metrics: dict, health, now: float):
    hist = db.setdefault("metrics_history", [])
    m = metrics or {}
    hist.append({"server_id": sid, "ts": now,
                 "cpu": m.get("cpu"), "mem": m.get("mem"),
                 "disk": (m.get("disk_percent")),
                 "net_up": m.get("net_up_bps"), "net_down": m.get("net_down_bps"),
                 "conns": m.get("active_connections"),
                 "latency": m.get("latency_ms"), "health": health,
                 "error_rate": m.get("error_rate", 0),
                 "packet_loss": m.get("packet_loss")})


def _prune_history(db):
    s = db.get("settings") or {}
    try:
        keep_days = float(s.get("history_retention_days") or 7)
    except Exception:
        keep_days = 7
    cutoff = time.time() - max(1, keep_days) * 86400
    hist = db.get("metrics_history", [])
    if cutoff:
        hist = [h for h in hist if h.get("ts", 0) >= cutoff]
    # per-server cap, then global cap (oldest dropped first)
    by_srv: dict = {}
    for h in hist:
        by_srv.setdefault(h.get("server_id"), []).append(h)
    kept = []
    for _sid, items in by_srv.items():
        items.sort(key=lambda x: x.get("ts", 0))
        kept.extend(items[-HISTORY_PER_SERVER:])
    kept.sort(key=lambda x: x.get("ts", 0))
    db["metrics_history"] = kept[-HISTORY_TOTAL:]


ALERT_TYPES = ("high_cpu", "high_mem", "high_disk", "high_latency",
               "high_conns", "xray_down", "offline")


async def _evaluate_server_alerts(sid: str):
    """Open/resolve threshold alerts from the latest cached metrics. Real I/O
    (notifications, audit) happens after the mutation."""
    db = await store.get()
    srv = server_by_id(db, sid)
    if not srv:
        return
    s = db.get("settings") or {}
    th = {"high_cpu": float(s.get("alert_cpu") or 80),
          "high_mem": float(s.get("alert_mem") or 85),
          "high_disk": float(s.get("alert_disk") or 90),
          "high_latency": float(s.get("alert_latency_ms") or 1000),
          "high_conns": float(s.get("alert_conns") or 200)}
    m = srv.get("metrics") or {}
    vals = {"high_cpu": m.get("cpu"), "high_mem": m.get("mem"),
            "high_disk": m.get("disk_percent"), "high_latency": m.get("latency_ms"),
            "high_conns": m.get("active_connections")}
    online = srv.get("online")
    changed: dict = {}

    def _a(db):
        for atype in ("high_cpu", "high_mem", "high_disk", "high_latency", "high_conns"):
            v = vals.get(atype)
            try:
                bad = v is not None and float(v) >= th[atype]
            except (TypeError, ValueError):
                bad = False
            if bad:
                # _eopen is async but body is sync; call inline
                found = any(x.get("server_id") == sid and x.get("type") == atype and x.get("status") == "active"
                            for x in db.get("server_alerts", []))
                if not found:
                    rec = {"id": gen_uid(), "server_id": sid, "type": atype, "severity": "warning",
                           "value": v, "threshold": th[atype], "status": "active",
                           "opened_at": time.time(), "resolved_at": None}
                    db.setdefault("server_alerts", []).append(rec)
                    changed.setdefault("opened", []).append(rec)
            else:
                for x in db.get("server_alerts", []):
                    if x.get("server_id") == sid and x.get("type") == atype and x.get("status") == "active":
                        x["status"] = "resolved"
                        x["resolved_at"] = time.time()
                        changed.setdefault("resolved", []).append(x)
        # xray / offline lifecycle
        if online is False:
            found = any(x.get("server_id") == sid and x.get("type") == "offline" and x.get("status") == "active"
                        for x in db.get("server_alerts", []))
            if not found:
                rec = {"id": gen_uid(), "server_id": sid, "type": "offline", "severity": "error",
                       "value": None, "threshold": None, "status": "active",
                       "opened_at": time.time(), "resolved_at": None}
                db.setdefault("server_alerts", []).append(rec)
                changed.setdefault("opened", []).append(rec)
        else:
            for x in db.get("server_alerts", []):
                if x.get("server_id") == sid and x.get("type") == "offline" and x.get("status") == "active":
                    x["status"] = "resolved"
                    x["resolved_at"] = time.time()
                    changed.setdefault("resolved", []).append(x)
        if (m.get("xray") not in (None, "?", "mock")) and m.get("xray") != "online":
            found = any(x.get("server_id") == sid and x.get("type") == "xray_down" and x.get("status") == "active"
                        for x in db.get("server_alerts", []))
            if not found:
                rec = {"id": gen_uid(), "server_id": sid, "type": "xray_down", "severity": "error",
                       "value": m.get("xray"), "threshold": "online", "status": "active",
                       "opened_at": time.time(), "resolved_at": None}
                db.setdefault("server_alerts", []).append(rec)
                changed.setdefault("opened", []).append(rec)
        else:
            for x in db.get("server_alerts", []):
                if x.get("server_id") == sid and x.get("type") == "xray_down" and x.get("status") == "active":
                    x["status"] = "resolved"
                    x["resolved_at"] = time.time()
                    changed.setdefault("resolved", []).append(x)
        # cap stored alerts
        al = db.get("server_alerts", [])
        if len(al) > 500:
            db["server_alerts"] = al[-500:]
    await store.mutate(_a)
    for rec in changed.get("opened", []):
        await push_notification("error" if rec["severity"] == "error" else "warning",
                                "server_" + rec["type"],
                                {"name": srv.get("name", sid), "key": sid,
                                 "value": rec.get("value"), "threshold": rec.get("threshold")})
        await log_audit("system", "alert_open", f"{srv.get('name', sid)}:{rec['type']}={rec.get('value')}", ref=sid)
    for rec in changed.get("resolved", []):
        await log_audit("system", "alert_resolved", f"{srv.get('name', sid)}:{rec['type']}", ref=sid)
        await push_notification("info", "server_" + rec["type"] + "_ok",
                                {"name": srv.get("name", sid), "key": sid})


async def poll_server(sid: str):
    """Heartbeat poll: live metrics + latency + health/load + history + alerts.

    Offline is declared after SERVER_FAIL_THRESHOLD consecutive failures OR
    when the last success is older than server_offline_after seconds.
    """
    db = await store.get()
    srv = server_by_id(db, sid)
    if not srv or not srv.get("enabled", True):
        return {"ok": False, "reason": "disabled-or-not-found"}
    was_online = srv.get("online")  # None = never successfully polled
    settings = db.get("settings") or {}
    offline_after = int(settings.get("server_offline_after") or 90)

    try:
        t0 = time.time()
        me_j, st_j, _sys, _live = await fetch_remote_metrics(srv["host"], srv.get("token") or "")
        latency = round((time.time() - t0) * 1000, 1)
        metrics = summarize_remote_metrics(me_j, st_j, _sys, _live)
        metrics["latency_ms"] = latency
        health = core_servers.health_score(metrics, True)
        load = core_servers.load_pct(metrics)
        compat = core_servers.version_compat(APP_VERSION, metrics.get("version") or "")
        now = time.time()

        def _ok(db):
            s = server_by_id(db, sid)
            if not s:
                return
            s["metrics"] = metrics
            s["latency_ms"] = latency
            s["health"] = health
            s["load"] = load
            s["version_compat"] = compat
            s["last_check"] = now
            s["last_seen"] = now
            s["last_success"] = now
            s["online"] = True
            s["fail_count"] = 0
            # OS/arch from remote platform string (e.g. "Windows-11-...-AMD64")
            plat = (metrics.get("platform") or "")
            if plat and not s.get("os"):
                s["os"] = plat.split("-")[0][:40]
            _record_history(db, sid, metrics, health, now)
            _prune_history(db)
        await store.mutate(_ok)
        await _evaluate_server_alerts(sid)
        if was_online is False:
            await record_server_event(sid, "server_online", f"{srv.get('name', sid)} came back online", "info")
            await log_audit("system", "server_online", srv.get("name", sid), ref=sid)
            await push_notification("info", "server_online",
                                    {"name": srv.get("name", sid), "key": sid})
            try:
                db2 = await store.get()
                if (db2.get("settings") or {}).get("notify_server", True):
                    await telegram_bot.notify(store, "server",
                        f"✅ <b>سرور برگشت</b>\n🖥 {srv.get('name', sid)}")
            except Exception:
                pass
        return {"ok": True, "metrics": metrics}
    except Exception as e:
        state = {}

        def _fail(db):
            s = server_by_id(db, sid)
            if not s:
                return
            s["fail_count"] = int(s.get("fail_count") or 0) + 1
            s["last_check"] = time.time()
            state["fails"] = s["fail_count"]
            last_ok = s.get("last_success") or 0
            if s["fail_count"] >= SERVER_FAIL_THRESHOLD or \
                    (last_ok and time.time() - last_ok > offline_after):
                s["online"] = False
                s["health"] = 0
        await store.mutate(_fail)
        await _evaluate_server_alerts(sid)
        if was_online is True and state.get("fails", 0) >= SERVER_FAIL_THRESHOLD:
            await record_server_event(sid, "server_offline", f"{srv.get('name', sid)} went offline", "error")
            await log_audit("system", "server_offline", srv.get("name", sid), ref=sid)
            await push_notification("error", "server_offline",
                                    {"name": srv.get("name", sid), "key": sid})
            try:
                db2 = await store.get()
                if (db2.get("settings") or {}).get("notify_server", True):
                    await telegram_bot.notify(store, "server",
                        f"🔴 <b>سرور آفلاین شد</b>\n🖥 {srv.get('name', sid)}")
            except Exception:
                pass
        return {"ok": False, "reason": str(e)[:200]}


async def _server_poll_loop():
    await asyncio.sleep(20)
    while True:
        try:
            db = await store.get()
            try:
                interval = int((db.get("settings") or {}).get("server_poll_interval") or 30)
            except (TypeError, ValueError):
                interval = 30
            interval = max(15, min(600, interval))
            for srv in list(db.get("servers", [])):
                if srv.get("enabled", True):
                    try:
                        await poll_server(srv["id"])
                    except Exception:
                        pass
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(5)


async def _keep_alive_loop():
    await asyncio.sleep(15)
    while True:
        try:
            db = await store.get()
            interval = 600
            await asyncio.sleep(interval)
            if not (db.get("settings") or {}).get("keep_alive", True):
                continue
            port = os.environ.get("PANEL_PORT") or os.environ.get("PORT") or "10000"
            async with httpx.AsyncClient(timeout=5) as client:
                await client.get(f"http://127.0.0.1:{port}/health")
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(5)


# ------------------------------------------------------------------ health and doh
@app.get("/health")
async def health_check():
    return {"status": "ok", "version": APP_VERSION}


@app.api_route("/dns-query", methods=["GET", "POST", "OPTIONS"])
async def doh_endpoint(request: Request):
    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Accept",
            }
        )

    accept = request.headers.get("accept", "application/dns-message")
    content_type = request.headers.get("content-type", "application/dns-message")
    req_headers = {"accept": accept}

    try:
        if request.method == "POST":
            req_headers["content-type"] = content_type
            body = await request.body()
            try:
                upstream_res = await doh_http_client.post(DOH_PRIMARY, content=body, headers=req_headers)
            except Exception:
                upstream_res = await doh_http_client.post(DOH_SECONDARY, content=body, headers=req_headers)
        else:
            params = dict(request.query_params)
            try:
                upstream_res = await doh_http_client.get(DOH_PRIMARY, params=params, headers=req_headers)
            except Exception:
                upstream_res = await doh_http_client.get(DOH_SECONDARY, params=params, headers=req_headers)

        res_content_type = upstream_res.headers.get("content-type", "application/dns-message")
        return Response(
            content=upstream_res.content,
            status_code=upstream_res.status_code,
            media_type=res_content_type,
            headers={
                "Cache-Control": upstream_res.headers.get("cache-control", "max-age=300"),
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Accept",
            }
        )
    except Exception:
        return Response(content=b"", status_code=502)


# ------------------------------------------------------------------ page routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    db = await store.get()
    if not db.get("admin"):
        return RedirectResponse("/setup")
    user = await current_username(request)
    if user:
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    db = await store.get()
    if db.get("admin"):
        return RedirectResponse("/login")
    return templates.TemplateResponse(request, "setup.html", {"app_version": APP_VERSION, "telegram_contact": TELEGRAM_CONTACT})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    db = await store.get()
    if not db.get("admin"):
        return RedirectResponse("/setup")
    if await current_username(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse(request, "login.html", {"app_version": APP_VERSION, "telegram_contact": TELEGRAM_CONTACT})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    db = await store.get()
    if not db.get("admin"):
        return RedirectResponse("/setup")
    if not await current_username(request):
        return RedirectResponse("/login")
    return templates.TemplateResponse(request, "dashboard.html", {
        "app_version": APP_VERSION,
        "panel_name": PANEL_NAME,
        "telegram_contact": TELEGRAM_CONTACT,
    })


@app.get("/status/{uid}", response_class=HTMLResponse)
async def status_page(request: Request, uid: str):
    db = await store.get()
    ib = inbound_by_uid(db, uid)
    if not ib:
        return HTMLResponse("<h1>404</h1><p>Not found.</p>", status_code=404)
    return templates.TemplateResponse(request, "status.html", {
        "uid": uid, "app_version": APP_VERSION,
        "panel_name": PANEL_NAME,
        "telegram_contact": TELEGRAM_CONTACT,
    })


# ------------------------------------------------------------------ auth api
@app.get("/api/setup-status")
async def setup_status():
    db = await store.get()
    return {"needs_setup": not bool(db.get("admin"))}


@app.post("/api/setup")
async def api_setup(request: Request):
    payload = await request.json()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    db = await store.get()
    if db.get("admin"):
        raise HTTPException(400, "already-configured")
    if not core_security.valid_username(username):
        raise HTTPException(400, "invalid-username")
    if len(password) < core_security.MIN_PASSWORD_LEN:
        raise HTTPException(400, "weak-password")

    hp = hash_password(password)

    def _apply(db):
        db["admin"] = {
            "username": username,
            "password_hash": hp["hash"],
            "salt": hp["salt"],
            "created_at": time.time(),
        }
        db.setdefault("admins", []).append({
            "id": "admin_" + gen_uid(),
            "username": username,
            "password_hash": hp["hash"],
            "salt": hp["salt"],
            "role": "owner",
            "enabled": True,
            "created_at": time.time(),
            "totp_secret": None,
        })

    db = await store.mutate(_apply)
    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, request, db, username)
    return resp


@app.post("/api/login")
async def api_login(request: Request):
    payload = await request.json()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    ip = _client_ip(request)
    db = await store.get()

    attempts = db.get("login_attempts", {}).get(ip, {})
    if attempts.get("locked_until", 0) > time.time():
        remain = int(attempts["locked_until"] - time.time())
        raise HTTPException(429, f"locked:{remain}")

    admin = find_admin(db, username)
    if admin is None and db.get("admin") and db["admin"].get("username") == username:
        admin = db["admin"]
    ok = admin_credential_ok(admin, password)

    def _record(db):
        la = db.setdefault("login_attempts", {})
        if ok:
            la.pop(ip, None)
        else:
            rec = la.setdefault(ip, {"count": 0, "locked_until": 0})
            rec["count"] += 1
            if rec["count"] >= LOGIN_MAX_ATTEMPTS:
                rec["locked_until"] = time.time() + LOGIN_LOCK_SECONDS
                rec["count"] = 0

    db = await store.mutate(_record)

    if not ok:
        await log_audit(username or "?", "login_failed", ip, ip=ip)
        raise HTTPException(401, "invalid-credentials")

    # Phase 5: TOTP second factor
    if admin.get("totp_secret"):
        s2 = URLSafeTimedSerializer(db["secret_key"], salt="aloo-2fa")
        tmp = s2.dumps({"u": username, "ip": ip})
        return JSONResponse({"ok": True, "need_2fa": True, "tmp": tmp})

    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, request, db, username)
    await log_audit(username, "login", ip, ip=ip)
    try:
        await telegram_bot.notify(store, "login", f"🔐 <b>ورود به پنل</b>\n👤 {username}\n🌐 {ip}")
    except Exception:
        pass
    return resp


@app.post("/api/2fa/login")
async def api_2fa_login(request: Request):
    """Complete a password-first login with a TOTP code."""
    payload = await request.json()
    tmp = payload.get("tmp") or ""
    code = (payload.get("code") or "").strip()
    ip = _client_ip(request)
    db = await store.get()
    s2 = URLSafeTimedSerializer(db["secret_key"], salt="aloo-2fa")
    try:
        data = s2.loads(tmp, max_age=300)
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, "expired-challenge")
    username = data.get("u", "")
    admin = find_admin(db, username)
    if admin is None and db.get("admin") and db["admin"].get("username") == username:
        admin = db["admin"]
    if not admin or not admin.get("totp_secret"):
        raise HTTPException(400, "2fa-not-enabled")
    if not core_security.verify_totp(admin["totp_secret"], code):
        await log_audit(username, "login_failed", f"{ip} (bad-2fa)", ip=ip)
        raise HTTPException(401, "invalid-2fa")
    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, request, db, username)
    await log_audit(username, "login", f"{ip} (+2fa)", ip=ip)
    try:
        await telegram_bot.notify(store, "login", f"🔐 <b>ورود به پنل (+2FA)</b>\n👤 {username}\n🌐 {ip}")
    except Exception:
        pass
    return resp


@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    user = await current_username(request)
    db = await store.get()
    role = await actor_role(request, db) if user else ""
    admin = find_admin(db, user) if user and not user.startswith("token:") else None
    return {
        "logged_in": bool(user),
        "username": user,
        "role": role or ("owner" if user and user.startswith("token:") else ""),
        "totp_enabled": bool(admin and admin.get("totp_secret")),
        "maintenance": bool((db.get("settings") or {}).get("maintenance_enabled")),
        "settings": db.get("settings", {}),
        "app_version": APP_VERSION,
        "app_name": APP_NAME,
        "app_edition": APP_EDITION,
    }


@app.post("/api/change-password")
async def api_change_password(request: Request, user: str = Depends(require_auth)):
    payload = await request.json()
    old_password = payload.get("old_password") or ""
    new_password = payload.get("new_password") or ""
    new_username = (payload.get("new_username") or "").strip()
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    db = await store.get()
    admin = find_admin(db, user) or (db.get("admin") if db.get("admin", {}).get("username") == user else None)
    if not admin or not admin_credential_ok(admin, old_password):
        raise HTTPException(401, "wrong-old-password")
    if new_username and not core_security.valid_username(new_username):
        raise HTTPException(400, "invalid-username")
    if new_username and new_username != user and find_admin(db, new_username):
        raise HTTPException(409, "username-taken")
    if new_password and len(new_password) < core_security.MIN_PASSWORD_LEN:
        raise HTTPException(400, "weak-password")
    final = {"u": new_username or user}

    def _apply(db):
        rec = find_admin(db, user)
        target = rec if rec is not None else db.get("admin")
        if new_password:
            hp = hash_password(new_password)
            target["password_hash"] = hp["hash"]
            target["salt"] = hp["salt"]
        if new_username:
            target["username"] = new_username
            if rec is None and db.get("admin"):
                # keep legacy + admins[] consistent
                for a in db.get("admins", []):
                    if a.get("username") == user:
                        a["username"] = new_username

    db = await store.mutate(_apply)
    # username renames must also refresh legacy copy when edited via admins[]
    async def _sync_legacy():
        def _s(db):
            if db.get("admin") and find_admin(db, final["u"]) and db["admin"].get("username") == user:
                for a in db.get("admins", []):
                    if a.get("username") == final["u"]:
                        db["admin"]["password_hash"] = a["password_hash"]
                        db["admin"]["salt"] = a["salt"]
                        db["admin"]["username"] = a["username"]
        try:
            await store.mutate(_s)
        except Exception:
            pass
    await _sync_legacy()
    await log_audit(user, "password_change", "")
    resp = JSONResponse({"ok": True})
    set_session_cookie(resp, request, db, final["u"])
    return resp


# ------------------------- Phase 5: roles, admins, 2FA, security -------------------------
def mask_admin(a: dict, is_self: bool = False) -> dict:
    return {"id": a.get("id"), "username": a.get("username"), "role": a.get("role", "viewer"),
            "enabled": bool(a.get("enabled", True)), "created_at": a.get("created_at"),
            "totp_enabled": bool(a.get("totp_secret")), "is_self": is_self}


def _owner_count(db) -> int:
    return sum(1 for a in db.get("admins", [])
               if a.get("role") == "owner" and a.get("enabled", True))


@app.get("/api/roles")
async def api_roles(user: str = Depends(require_auth)):
    db = await store.get()
    ov = _role_overrides(db)
    return {"roles": list(core_security.ROLES),
            "permissions": list(core_security.PERMISSIONS),
            "matrix": {r: sorted(core_security.role_perms(r, ov)) if r != "owner" else ["*"]
                       for r in core_security.ROLES},
            "overrides": ov}


@app.patch("/api/roles/{role}")
async def api_roles_update(role: str, request: Request, user: str = Depends(require_perm("admins.manage"))):
    """Owner-controlled per-role permission set (owner itself is always *)."""
    if role not in core_security.ROLES or role == "owner":
        raise HTTPException(400, "role-locked")
    try:
        p = await request.json()
    except Exception:
        p = {}
    perms = p.get("permissions")
    if not isinstance(perms, list):
        raise HTTPException(400, "invalid-permissions")
    clean = sorted({x for x in perms if x in core_security.PERMISSIONS})

    def _a(db):
        ov = db.setdefault("settings", {}).setdefault("role_overrides", {})
        ov[role] = clean
    await store.mutate(_a)
    await log_audit(user, "role_update", f"{role}:{len(clean)}")
    return {"ok": True, "role": role, "permissions": clean}


@app.get("/api/admins")
async def api_admins_list(user: str = Depends(require_perm("admins.manage"))):
    db = await store.get()
    me = user.split(":", 1)[-1] if user.startswith("token:") else user
    return {"admins": [mask_admin(a, a.get("username") == me) for a in db.get("admins", [])]}


@app.post("/api/admins")
async def api_admins_create(request: Request, user: str = Depends(require_perm("admins.manage"))):
    p = await request.json()
    username = (p.get("username") or "").strip()
    password = p.get("password") or ""
    role = (p.get("role") or "viewer").strip()
    if not core_security.valid_username(username):
        raise HTTPException(400, "invalid-username")
    if len(password) < core_security.MIN_PASSWORD_LEN:
        raise HTTPException(400, "weak-password")
    if role not in core_security.ROLES:
        raise HTTPException(400, "invalid-role")
    hp = hash_password(password)
    rec = {"id": "admin_" + gen_uid(), "username": username,
           "password_hash": hp["hash"], "salt": hp["salt"], "role": role,
           "enabled": True, "created_at": time.time(), "totp_secret": None}

    def _a(db):
        if find_admin(db, username):
            raise HTTPException(409, "username-taken")
        db.setdefault("admins", []).append(rec)
    await store.mutate(_a)
    await log_audit(user, "admin_create", f"{username}:{role}")
    return {"ok": True, "admin": mask_admin(rec)}


@app.patch("/api/admins/{aid}")
async def api_admins_update(aid: str, request: Request, user: str = Depends(require_perm("admins.manage"))):
    p = await request.json()
    me = user.split(":", 1)[-1] if user.startswith("token:") else user
    out = {}

    def _a(db):
        rec = next((a for a in db.get("admins", []) if a.get("id") == aid), None)
        if not rec:
            raise HTTPException(404, "not-found")
        is_self = rec.get("username") == me
        if "role" in p:
            nr = str(p["role"]).strip()
            if nr not in core_security.ROLES:
                raise HTTPException(400, "invalid-role")
            if is_self and nr != rec.get("role"):
                raise HTTPException(400, "cannot-change-own-role")
            if rec.get("role") == "owner" and nr != "owner" and _owner_count(db) <= 1:
                raise HTTPException(400, "last-owner")
            rec["role"] = nr
        if "enabled" in p:
            nv = bool(p["enabled"])
            if is_self and not nv:
                raise HTTPException(400, "cannot-disable-self")
            if rec.get("role") == "owner" and not nv and _owner_count(db) <= 1:
                raise HTTPException(400, "last-owner")
            rec["enabled"] = nv
        if p.get("password"):
            if len(p["password"]) < core_security.MIN_PASSWORD_LEN:
                raise HTTPException(400, "weak-password")
            hp = hash_password(p["password"])
            rec["password_hash"] = hp["hash"]
            rec["salt"] = hp["salt"]
        out.update(mask_admin(rec, is_self))
    await store.mutate(_a)
    await log_audit(user, "admin_update", aid)
    return {"ok": True, "admin": out}


@app.delete("/api/admins/{aid}")
async def api_admins_delete(aid: str, user: str = Depends(require_perm("admins.manage"))):
    me = user.split(":", 1)[-1] if user.startswith("token:") else user
    gone = {"v": False}

    def _a(db):
        rec = next((a for a in db.get("admins", []) if a.get("id") == aid), None)
        if not rec:
            return
        if rec.get("username") == me:
            raise HTTPException(400, "cannot-delete-self")
        if rec.get("role") == "owner" and _owner_count(db) <= 1:
            raise HTTPException(400, "last-owner")
        db["admins"] = [a for a in db.get("admins", []) if a.get("id") != aid]
        gone["v"] = True
    await store.mutate(_a)
    if not gone["v"]:
        raise HTTPException(404, "not-found")
    await log_audit(user, "admin_delete", aid)
    return {"ok": True}


pending_2fa: dict = {}


@app.post("/api/2fa/setup")
async def api_2fa_setup(request: Request, user: str = Depends(require_auth)):
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    p = await request.json()
    db = await store.get()
    admin = find_admin(db, user)
    if not admin or not admin_credential_ok(admin, p.get("password") or ""):
        raise HTTPException(401, "wrong-old-password")
    if admin.get("totp_secret"):
        raise HTTPException(409, "already-enabled")
    secret = core_security.gen_totp_secret()
    pending_2fa[admin["id"]] = {"secret": secret, "exp": time.time() + 600}
    await log_audit(user, "2fa_setup", "")
    return {"ok": True, "secret": secret,
            "otpauth_url": core_security.otpauth_url(secret, user)}


@app.get("/api/2fa/qr")
async def api_2fa_qr(user: str = Depends(require_auth)):
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    db = await store.get()
    admin = find_admin(db, user)
    pend = pending_2fa.get(admin["id"]) if admin else None
    if not pend or pend["exp"] < time.time():
        raise HTTPException(404, "no-pending-setup")
    img = qrcode.make(core_security.otpauth_url(pend["secret"], user), border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.post("/api/2fa/verify")
async def api_2fa_verify(request: Request, user: str = Depends(require_auth)):
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    p = await request.json()
    code = (p.get("code") or "").strip()
    done = {"v": False}

    def _a(db):
        admin = find_admin(db, user)
        if not admin:
            raise HTTPException(404, "not-found")
        pend = pending_2fa.get(admin["id"])
        if not pend or pend["exp"] < time.time():
            raise HTTPException(404, "no-pending-setup")
        if not core_security.verify_totp(pend["secret"], code):
            raise HTTPException(401, "invalid-2fa")
        admin["totp_secret"] = pend["secret"]
        pending_2fa.pop(admin["id"], None)
        # keep legacy copy in sync when it's the same human
        if db.get("admin", {}).get("username") == user:
            db["admin"]["totp_secret"] = pend["secret"]
        done["v"] = True
    await store.mutate(_a)
    await log_audit(user, "2fa_enable", "")
    return {"ok": True}


@app.post("/api/2fa/disable")
async def api_2fa_disable(request: Request, user: str = Depends(require_auth)):
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    p = await request.json()

    def _a(db):
        admin = find_admin(db, user)
        if not admin or not admin_credential_ok(admin, p.get("password") or ""):
            raise HTTPException(401, "wrong-old-password")
        admin["totp_secret"] = None
        if db.get("admin", {}).get("username") == user:
            db["admin"]["totp_secret"] = None
    await store.mutate(_a)
    await log_audit(user, "2fa_disable", "")
    return {"ok": True}


@app.get("/api/security/overview")
async def api_security_overview(request: Request, user: str = Depends(require_perm("security.manage"))):
    db = await store.get()
    now = time.time()
    locked = []
    for ip, rec in (db.get("login_attempts") or {}).items():
        lu = rec.get("locked_until", 0)
        if lu > now:
            locked.append({"ip": ip, "remaining": int(lu - now)})
    failed = [l for l in db.get("audit_log", [])
              if l.get("action") == "login_failed" and now - l.get("ts", 0) < 86400]
    recent = list(reversed(failed))[:10]
    logins = [l for l in db.get("audit_log", []) if l.get("action") == "login"]
    recent_logins = list(reversed(logins))[-10:][::-1][:10]
    return {
        "policy": {"min_password_len": core_security.MIN_PASSWORD_LEN,
                   "max_attempts": LOGIN_MAX_ATTEMPTS,
                   "lock_seconds": LOGIN_LOCK_SECONDS},
        "locked_ips": locked,
        "failed_24h": len(failed),
        "recent_failed": recent,
        "recent_logins": [{"ts": l.get("ts"), "actor": l.get("actor"),
                           "ip": l.get("ip") or l.get("detail", "")} for l in recent_logins],
        "session": {"actor": user, "type": "token" if user.startswith("token:") else "admin"},
        "admins_count": len(db.get("admins", [])),
    }


@app.post("/api/security/unblock")
async def api_security_unblock(request: Request, user: str = Depends(require_perm("security.manage"))):
    p = await request.json()
    ip = (p.get("ip") or "").strip()
    if not ip:
        raise HTTPException(400, "ip-required")

    def _a(db):
        (db.get("login_attempts") or {}).pop(ip, None)
    await store.mutate(_a)
    await log_audit(user, "ip_unblock", ip)
    return {"ok": True}


@app.post("/api/sessions/revoke-all")
async def api_sessions_revoke(request: Request, user: str = Depends(require_perm("security.manage"))):
    """Rotate the cookie-signing secret: every session (incl. this one) dies."""
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    p = await request.json()
    db = await store.get()
    admin = find_admin(db, user)
    if not admin or not admin_credential_ok(admin, p.get("password") or ""):
        raise HTTPException(401, "wrong-old-password")

    def _a(db):
        db["secret_key"] = secrets.token_hex(32)
    await store.mutate(_a)
    await log_audit(user, "sessions_revoke", "")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.post("/api/settings")
async def api_update_settings(request: Request, user: str = Depends(require_perm("settings.manage"))):
    payload = await request.json()
    allowed = {
        "lang", "theme", "public_domain", "keep_alive",
        "default_fingerprint", "default_alpn", "sni_override",
        "fragment_enabled", "fragment_packets", "fragment_length", "fragment_interval",
        # v2.0 luxury additions:
        "telegram_bot_token", "telegram_chat_id", "telegram_enabled",
        "notify_new_user", "notify_quota", "notify_expiry", "notify_login",
        "panel_name", "sub_remark_prefix", "auto_disable_exhausted",
        "quota_warn_percent", "expiry_warn_days", "xray_log_level",
        "load_balancer_enabled",
        # Phase 6: backups / maintenance (+ shop keys wired in Phase 6b)
        "backup_enabled", "backup_hour", "backup_minute", "backup_keep",
        "backup_send_telegram", "maintenance_enabled", "maintenance_message",
        # Phase 6b: shop bot
        "shop_enabled", "support_username", "shop_test_gb", "shop_test_days",
        "referral_bonus",
        # Phase 3: heartbeat / load / alerts
        "server_offline_after", "server_poll_interval", "lb_strategy",
        "history_retention_days",
        "alert_cpu", "alert_mem", "alert_disk", "alert_latency_ms", "alert_conns",
        # Phase 3 enhanced: agent / heartbeat
        "agent_auth_secret", "heartbeat_threshold",
    }
    valid_fp = {"chrome", "ios", "firefox", "edge", "random"}
    valid_alpn = {"http/1.1", "h2,http/1.1", "h3,h2,http/1.1"}
    valid_log = {"debug", "info", "warning", "error", "none"}
    valid_lb = {"least_load", "least_connections", "lowest_latency", "weighted", "health"}

    def _apply(db):
        s = db.setdefault("settings", {})
        for k, v in payload.items():
            if k not in allowed:
                continue
            if k == "default_fingerprint" and v not in valid_fp:
                continue
            if k == "default_alpn" and v not in valid_alpn:
                continue
            if k == "xray_log_level" and v not in valid_log:
                continue
            if k == "lb_strategy" and v not in valid_lb:
                continue
            if k in ("server_offline_after",):
                try:
                    s[k] = max(30, min(3600, int(v)))
                except (TypeError, ValueError):
                    continue
                continue
            if k in ("server_poll_interval",):
                try:
                    s[k] = max(15, min(600, int(v)))
                except (TypeError, ValueError):
                    continue
                continue
            if k in ("history_retention_days",):
                try:
                    s[k] = max(1, min(90, int(v)))
                except (TypeError, ValueError):
                    continue
                continue
            if k in ("alert_cpu", "alert_mem", "alert_disk", "alert_latency_ms", "alert_conns"):
                try:
                    s[k] = max(1, float(v))
                except (TypeError, ValueError):
                    continue
                continue
            if k in ("heartbeat_threshold",):
                try:
                    s[k] = max(30, min(600, int(v)))
                except (TypeError, ValueError):
                    continue
                continue
            if k == "agent_auth_secret":
                s[k] = str(v or "")[:200]
                continue
            if k in ("telegram_enabled", "notify_new_user", "notify_quota",
                     "notify_expiry", "notify_login", "notify_server", "keep_alive",
                     "fragment_enabled", "auto_disable_exhausted",
                     "load_balancer_enabled", "shop_enabled",
                     "backup_enabled", "backup_send_telegram",
                     "maintenance_enabled"):
                s[k] = bool(v)
                continue
            if k in ("quota_warn_percent", "expiry_warn_days", "shop_test_gb",
                     "shop_test_days", "referral_bonus", "backup_hour",
                     "backup_minute", "backup_keep"):
                try:
                    s[k] = float(v) if k in ("quota_warn_percent", "shop_test_gb",
                                             "referral_bonus") else int(v)
                    if k in ("backup_hour",):
                        s[k] = max(0, min(23, int(s[k])))
                    if k in ("backup_minute",):
                        s[k] = max(0, min(59, int(s[k])))
                    if k in ("backup_keep",):
                        s[k] = max(1, min(60, int(s[k])))
                    if k in ("shop_test_gb", "shop_test_days", "referral_bonus"):
                        s[k] = max(0, s[k])
                except Exception:
                    continue
                continue
            s[k] = v

    db = await store.mutate(_apply)
    await log_audit(user, "update_settings", ",".join(list(payload.keys())[:8]))
    return {"ok": True, "settings": db["settings"]}


# ------------------------------------------------------------------ inbounds api
def serialize_inbound(ib) -> dict:
    st = inbound_status(ib)
    out = dict(ib)
    try:
        ipinfo = xray_manager.get_ip_info(ib.get("uid", ""))
    except Exception:
        ipinfo = {"ips": [], "last": None}
    out["active_ips"] = ipinfo.get("ips") or []
    out["last_conn"] = ipinfo.get("last")
    out["server"] = "local"
    out.update({"status": st})
    return out


@app.get("/api/inbounds")
async def api_list_inbounds(user: str = Depends(require_perm("users.read"))):
    db = await store.get()
    return {"inbounds": [serialize_inbound(ib) for ib in db["inbounds"]]}


@app.post("/api/inbounds")
async def api_create_inbound(request: Request, user: str = Depends(require_perm("users.create"))):
    payload = await request.json()
    db = await store.get()
    name = (payload.get("name") or "User").strip()[:64]
    quota_gb = float(payload.get("quota_gb") or 0)
    expire_days = int(payload.get("expire_days") or 0)
    max_connections = int(payload.get("max_connections") or 0)
    max_requests = int(payload.get("max_requests") or 0)
    fp = payload.get("fp") or (db.get("settings") or {}).get("default_fingerprint", "chrome")
    strict_single_ip = bool(payload.get("strict_single_ip") or False)

    ib = {
        "uid": gen_uid(),
        "uuid": gen_uuid(),
        "name": name,
        "enabled": True,
        "created_at": time.time(),
        "expire_days": expire_days,
        "expire_at": (time.time() + expire_days * 86400) if expire_days > 0 else None,
        "quota_gb": quota_gb,
        "max_connections": max_connections,
        "max_requests": max_requests,
        "request_count": 0,
        "used_up": 0,
        "used_down": 0,
        "fp": fp,
        "strict_single_ip": strict_single_ip,
        "note": payload.get("note", "")[:200] if payload.get("note") else "",
        "sub_token": secrets.token_hex(12),
        "sub_enabled": True,
        "plan_id": None,
        "plan_name": "",
    }
    plan_id = (payload.get("plan_id") or "").strip()
    if plan_id:
        plan = plan_by_id(db, plan_id)
        if not plan:
            raise HTTPException(404, "plan-not-found")
        if not plan.get("enabled", True):
            raise HTTPException(400, "plan-disabled")
        apply_plan_to_inbound(ib, plan)

    def _apply(db):
        db["inbounds"].append(ib)

    db = await store.mutate(_apply)
    refresh_xray(db)
    await log_audit(user, "create_user", name)
    try:
        db2 = await store.get()
        await telegram_bot.notify(store, "new_user",
            f"✅ <b>کاربر جدید ساخته شد</b>\n👤 {name}\n🔗 <code>{canonical_sub_url(request, db2, ib)}</code>")
    except Exception:
        pass
    return {"ok": True, "inbound": serialize_inbound(ib)}


# ------------------------- Phase 2: plans -------------------------
@app.get("/api/plans")
async def api_plans_list(user: str = Depends(require_perm("users.read"))):
    db = await store.get()
    return {"plans": db.get("plans", [])}


@app.post("/api/plans")
async def api_plans_create(request: Request, user: str = Depends(require_perm("users.edit"))):
    p = await request.json()
    name = (p.get("name") or "").strip()[:40]
    if not name:
        raise HTTPException(400, "plan-name-required")
    try:
        traffic = max(0.0, float(p.get("traffic_gb") or 0))
        duration = max(0, int(p.get("duration_days") or 0))
        devices = max(0, int(p.get("device_limit") or 0))
        price = max(0.0, float(p.get("price") or 0))
    except Exception:
        raise HTTPException(400, "plan-invalid-numbers")
    rec = {"id": "plan_" + gen_uid(), "name": name, "traffic_gb": traffic,
           "duration_days": duration, "device_limit": devices, "price": price,
           "description": (p.get("description") or "")[:200],
           "enabled": bool(p.get("enabled", True)), "created_at": time.time()}

    def _a(db):
        db.setdefault("plans", []).append(rec)
    await store.mutate(_a)
    await log_audit(user, "plan_create", name)
    return {"ok": True, "plan": rec}


@app.patch("/api/plans/{pid}")
async def api_plans_update(pid: str, request: Request, user: str = Depends(require_perm("users.edit"))):
    p = await request.json()
    editable = {"name", "traffic_gb", "duration_days", "device_limit", "description", "enabled", "price"}
    out = {}

    def _a(db):
        plan = plan_by_id(db, pid)
        if not plan:
            raise HTTPException(404, "plan-not-found")
        for k, v in p.items():
            if k not in editable:
                continue
            if k == "name":
                plan[k] = str(v or "").strip()[:40] or plan["name"]
            elif k in ("traffic_gb", "duration_days", "device_limit", "price"):
                try:
                    plan[k] = max(0, float(v or 0) if k in ("traffic_gb", "price") else int(v or 0))
                except Exception:
                    continue
            elif k == "description":
                plan[k] = str(v or "")[:200]
            else:
                plan[k] = bool(v)
        out.update(plan)
    await store.mutate(_a)
    await log_audit(user, "plan_update", pid)
    return {"ok": True, "plan": out}


@app.delete("/api/plans/{pid}")
async def api_plans_delete(pid: str, user: str = Depends(require_perm("users.edit"))):
    found = {"v": False}

    def _a(db):
        before = len(db.get("plans", []))
        db["plans"] = [x for x in db.get("plans", []) if x.get("id") != pid]
        found["v"] = len(db["plans"]) != before
    await store.mutate(_a)
    if not found["v"]:
        raise HTTPException(404, "plan-not-found")
    await log_audit(user, "plan_delete", pid)
    return {"ok": True}


@app.post("/api/inbounds/{uid}/apply-plan")
async def api_apply_plan(uid: str, request: Request, user: str = Depends(require_perm("users.edit"))):
    p = await request.json()
    pid = (p.get("plan_id") or "").strip()
    if not pid:
        raise HTTPException(400, "plan-required")

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        plan = plan_by_id(db, pid)
        if not plan:
            raise HTTPException(404, "plan-not-found")
        if not plan.get("enabled", True):
            raise HTTPException(400, "plan-disabled")
        apply_plan_to_inbound(ib, plan)
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "apply_plan", f"{uid}:{pid}")
    return {"ok": True, "inbound": serialize_inbound(inbound_by_uid(db, uid))}


@app.post("/api/inbounds/{uid}/adjust-traffic")
async def api_adjust_traffic(uid: str, request: Request, user: str = Depends(require_perm("users.edit"))):
    """Add (positive) or remove (negative) quota GB. Floored at 0."""
    p = await request.json()
    try:
        delta = float(p.get("add_gb") or 0)
    except Exception:
        raise HTTPException(400, "invalid-amount")

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["quota_gb"] = max(0.0, round((ib.get("quota_gb") or 0) + delta, 2))
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "adjust_traffic", f"{uid}:{delta:+g}GB")
    return {"ok": True, "inbound": serialize_inbound(inbound_by_uid(db, uid))}


@app.patch("/api/inbounds/{uid}")
async def api_update_inbound(uid: str, request: Request, user: str = Depends(require_perm("users.edit"))):
    payload = await request.json()
    editable = {"name", "enabled", "quota_gb", "expire_days", "max_connections",
                "max_requests", "fp", "strict_single_ip", "note"}
    updated = {}

    def _apply(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        for k, v in payload.items():
            if k in editable:
                ib[k] = v
        if "expire_days" in payload:
            days = int(payload["expire_days"] or 0)
            ib["expire_at"] = (ib["created_at"] + days * 86400) if days > 0 else None
        updated.update(ib)

    db = await store.mutate(_apply)
    refresh_xray(db)
    await log_audit(user, "update_user", uid)
    return {"ok": True, "inbound": serialize_inbound(updated)}


@app.delete("/api/inbounds/{uid}")
async def api_delete_inbound(uid: str, request: Request, user: str = Depends(require_perm("users.delete"))):
    found = {"v": False, "name": ""}

    def _apply(db):
        before = len(db["inbounds"])
        for ib in db["inbounds"]:
            if ib["uid"] == uid:
                found["name"] = ib.get("name", "")
        db["inbounds"] = [ib for ib in db["inbounds"] if ib["uid"] != uid]
        found["v"] = len(db["inbounds"]) != before

    await store.mutate(_apply)
    runtime["active"].pop(uid, None)
    if not found["v"]:
        raise HTTPException(404, "not-found")

    db = await store.get()
    refresh_xray(db)
    await log_audit(user, "delete_user", found["name"])
    return {"ok": True}


@app.post("/api/inbounds/{uid}/reset-usage")
async def api_reset_usage(uid: str, user: str = Depends(require_perm("users.edit"))):
    def _apply(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["used_up"] = 0
        ib["used_down"] = 0
        ib["request_count"] = 0

    db = await store.mutate(_apply)
    return {"ok": True, "inbound": serialize_inbound(inbound_by_uid(db, uid))}


@app.post("/api/inbounds/{uid}/regenerate")
async def api_regenerate_uuid(uid: str, user: str = Depends(require_perm("users.edit"))):
    """Anti-resale: instantly revoke old links by rotating the VLESS uuid."""
    def _apply(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["uuid"] = gen_uuid()

    db = await store.mutate(_apply)
    runtime["active"].pop(uid, None)
    refresh_xray(db)
    await log_audit(user, "regenerate", uid)
    return {"ok": True, "inbound": serialize_inbound(inbound_by_uid(db, uid))}


# ------------------------- v2.0: bulk & power actions -------------------------
@app.post("/api/inbounds/bulk")
async def api_bulk_create(request: Request, user: str = Depends(require_perm("users.create"))):
    """Create many users at once: {count, name_prefix, quota_gb, expire_days, ...}"""
    p = await request.json()
    try:
        count = max(1, min(100, int(p.get("count") or 1)))
    except Exception:
        count = 1
    prefix = (p.get("name_prefix") or "User").strip()[:32] or "User"
    quota_gb = float(p.get("quota_gb") or 0)
    expire_days = int(p.get("expire_days") or 0)
    created = []
    now = time.time()
    for i in range(1, count + 1):
        created.append({
            "uid": gen_uid(), "uuid": gen_uuid(), "name": f"{prefix}-{i:03d}",
            "enabled": True, "created_at": now,
            "expire_days": expire_days,
            "expire_at": (now + expire_days * 86400) if expire_days > 0 else None,
            "quota_gb": quota_gb, "max_connections": int(p.get("max_connections") or 0),
            "max_requests": 0, "request_count": 0, "used_up": 0, "used_down": 0,
            "fp": p.get("fp") or "chrome", "strict_single_ip": False, "note": "bulk",
            "sub_token": secrets.token_hex(12), "sub_enabled": True,
            "plan_id": None, "plan_name": "",
        })

    def _a(db):
        db["inbounds"].extend(created)
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "bulk_create", f"{count}x {prefix}")
    return {"ok": True, "count": count, "inbounds": [serialize_inbound(x) for x in created]}


@app.post("/api/inbounds/{uid}/toggle")
async def api_toggle(uid: str, user: str = Depends(require_perm("users.edit"))):
    out = {}

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["enabled"] = not ib.get("enabled", True)
        out.update(ib)
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "toggle", uid)
    return {"ok": True, "inbound": serialize_inbound(out)}


@app.post("/api/inbounds/{uid}/clone")
async def api_clone(uid: str, user: str = Depends(require_perm("users.edit"))):
    new = {}

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        c = dict(ib)
        c["uid"] = gen_uid()
        c["uuid"] = gen_uuid()
        c["name"] = (ib.get("name", "User") + " (copy)")[:64]
        c["used_up"] = 0
        c["used_down"] = 0
        c["request_count"] = 0
        c["created_at"] = time.time()
        db["inbounds"].append(c)
        new.update(c)
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "clone", uid)
    return {"ok": True, "inbound": serialize_inbound(new)}


@app.post("/api/inbounds/{uid}/extend")
async def api_extend(uid: str, request: Request, user: str = Depends(require_perm("users.edit"))):
    p = await request.json()
    days = int(p.get("days") or 0)
    add_gb = float(p.get("add_gb") or 0)

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        base = ib.get("expire_at") or time.time()
        if days:
            ib["expire_at"] = max(time.time(), base) + days * 86400
            ib["expire_days"] = int(((ib["expire_at"] - ib["created_at"]) // 86400))
        if add_gb:
            ib["quota_gb"] = max(0.0, round((ib.get("quota_gb") or 0) + add_gb, 2))
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "extend", f"{uid} +{days}d +{add_gb}GB")
    return {"ok": True, "inbound": serialize_inbound(inbound_by_uid(db, uid))}


@app.post("/api/inbounds/reset-all-usage")
async def api_reset_all(user: str = Depends(require_perm("users.edit"))):
    def _a(db):
        for ib in db["inbounds"]:
            ib["used_up"] = 0
            ib["used_down"] = 0
            ib["request_count"] = 0
        db["notified"] = {}
    await store.mutate(_a)
    await log_audit(user, "reset_all", "")
    return {"ok": True}


@app.post("/api/inbounds/cleanup")
async def api_cleanup(request: Request, user: str = Depends(require_perm("users.delete"))):
    """Delete expired / exhausted users. {mode: expired|exhausted|both}"""
    p = await request.json()
    mode = (p.get("mode") or "both").strip()
    removed = {"n": 0}

    def _a(db):
        keep = []
        for ib in db["inbounds"]:
            st = inbound_status(ib)
            drop = (mode in ("expired", "both") and st["expired"]) or \
                   (mode in ("exhausted", "both") and st["quota_exceeded"])
            if drop:
                removed["n"] += 1
            else:
                keep.append(ib)
        db["inbounds"] = keep
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "cleanup", f"{mode}:{removed['n']}")
    return {"ok": True, "removed": removed["n"]}


# ------------------------- v2.0: Telegram integration -------------------------
@app.get("/api/telegram/status")
async def api_tg_status(user: str = Depends(require_auth)):
    db = await store.get()
    s = db.get("settings", {})
    token, chat_id, src = telegram_bot.resolve_creds(s)
    masked = (token[:6] + "…" + token[-4:]) if len(token) > 14 else ("set" if token else "")
    return {"enabled": bool(s.get("telegram_enabled")), "has_token": bool(token),
            "masked": masked, "chat_id": chat_id,
            "token_source": src,
            "notify_new_user": s.get("notify_new_user", True),
            "notify_quota": s.get("notify_quota", True),
            "notify_expiry": s.get("notify_expiry", True),
            "notify_login": s.get("notify_login", False),
            "notify_server": s.get("notify_server", True),
            "bot_username": s.get("bot_username") or "",
            "shop": {
                "enabled": bool(s.get("shop_enabled", True)),
                "support_username": s.get("support_username") or "ITSESMAT",
                "test_gb": float(s.get("shop_test_gb") or 1),
                "test_days": int(s.get("shop_test_days") or 1),
                "referral_bonus": float(s.get("referral_bonus") or 0),
            },
            "poll": telegram_bot.poll_state_summary()}


@app.post("/api/telegram/save")
async def api_tg_save(request: Request, user: str = Depends(require_perm("telegram.manage"))):
    p = await request.json()
    token = (p.get("bot_token") or "").strip()
    chat_id = str(p.get("chat_id") or "").strip()
    if token:
        ok, info = await telegram_bot.validate_token(token)
        if not ok:
            raise HTTPException(400, f"invalid-token: {info}")

    def _a(db):
        s = db.setdefault("settings", {})
        if "bot_token" in p or "telegram_bot_token" in p:
            s["telegram_bot_token"] = token
        if "chat_id" in p or "telegram_chat_id" in p:
            s["telegram_chat_id"] = chat_id
        for k in ("telegram_enabled", "notify_new_user", "notify_quota", "notify_expiry", "notify_login",
                  "notify_server"):
            if k in p:
                s[k] = bool(p[k])
    db = await store.mutate(_a)
    await log_audit(user, "telegram_save", chat_id)
    ok, info = (True, {}) if not token else await telegram_bot.validate_token(token)
    bot_name = (info.get("username") if isinstance(info, dict) else "") or ""

    def _bn(db):
        if bot_name:
            db.setdefault("settings", {})["bot_username"] = bot_name
    try:
        await store.mutate(_bn)
    except Exception:
        pass
    return {"ok": True, "bot_username": bot_name}


@app.post("/api/telegram/test")
async def api_tg_test(request: Request, user: str = Depends(require_perm("telegram.manage"))):
    db = await store.get()
    s = db.get("settings", {})
    _tok, chat, _src = telegram_bot.resolve_creds(s)
    token = _tok
    p = {}
    try:
        p = await request.json()
    except Exception:
        pass
    if p.get("chat_id"):
        chat = str(p["chat_id"]).strip()
    if not token or not chat:
        raise HTTPException(400, "token-or-chat-missing")
    sent = await telegram_bot.send_message(token, chat,
        "✅ <b>ALOO PANEL ULTIMATE</b> — اتصال ربات تلگرام با موفقیت برقرار شد!\n🚀 از این پس اعلان‌ها را اینجا دریافت می‌کنید.")
    if not sent:
        raise HTTPException(502, "send-failed")
    await log_audit(user, "telegram_test", chat)
    return {"ok": True}


# ------------------------- Phase 6b: shop admin APIs -------------------------
@app.get("/api/shop/overview")
async def api_shop_overview(user: str = Depends(require_perm("telegram.manage"))):
    db = await store.get()
    s = db.get("settings") or {}
    topups = db.get("topup_requests", [])
    approved = sum(float(t.get("amount") or 0) for t in topups if t.get("status") == "approved")
    return {"enabled": bool(s.get("shop_enabled", True)),
            "customers": len(db.get("bot_users", [])),
            "pending_topups": sum(1 for t in topups if t.get("status") == "pending"),
            "approved_total": approved,
            "support_username": s.get("support_username") or "ITSESMAT",
            "bot_username": s.get("bot_username") or ""}


@app.get("/api/shop/users")
async def api_shop_users(user: str = Depends(require_perm("telegram.manage"))):
    db = await store.get()
    out = []
    for u in db.get("bot_users", []):
        d = dict(u)
        out.append(d)
    out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return {"users": out[:300]}


@app.post("/api/shop/adjust-balance")
async def api_shop_adjust_balance(request: Request, user: str = Depends(require_perm("telegram.manage"))):
    p = await request.json()
    try:
        tg_id = int(p.get("tg_id") or 0)
        delta = float(p.get("delta") or 0)
    except Exception:
        raise HTTPException(400, "invalid-amount")
    found = {"v": False}

    def _a(db):
        for u in db.get("bot_users", []):
            if int(u.get("tg_id") or 0) == tg_id:
                u["balance"] = round(float(u.get("balance") or 0) + delta, 2)
                found["v"] = True
    await store.mutate(_a)
    if not found["v"]:
        raise HTTPException(404, "not-found")
    await log_audit(user, "shop_balance", f"{tg_id}:{delta:+g}")
    return {"ok": True}


@app.get("/api/shop/topups")
async def api_shop_topups(user: str = Depends(require_perm("telegram.manage"))):
    db = await store.get()
    lst = list(db.get("topup_requests", []))
    lst.reverse()
    return {"topups": lst[:200]}


@app.post("/api/shop/topups/{rid}/decide")
async def api_shop_topup_decide(rid: str, request: Request, user: str = Depends(require_perm("telegram.manage"))):
    p = await request.json()
    approve = bool(p.get("approve"))
    req = await telegram_bot.topup_decide(store, rid, approve, by=user)
    if not req:
        raise HTTPException(404, "not-found-or-decided")
    await log_audit(user, "shop_topup", f"{rid}:{'ok' if approve else 'no'}")
    return {"ok": True}


# ------------------------- v2.0: API tokens (for external bots/apps) -------------------------
def _mask_token(raw: str) -> str:
    return (raw[:10] + "…" + raw[-4:]) if len(raw) > 16 else "***"


@app.get("/api/tokens")
async def api_tokens_list(user: str = Depends(require_perm("security.manage"))):
    db = await store.get()
    return {"tokens": [
        {"id": t.get("id"), "name": t.get("name"), "prefix": t.get("prefix"),
         "created_at": t.get("created_at"), "last_used": t.get("last_used"),
         "note": t.get("note", "")} for t in db.get("api_tokens", [])]}


@app.post("/api/tokens")
async def api_tokens_create(request: Request, user: str = Depends(require_perm("security.manage"))):
    p = await request.json()
    name = (p.get("name") or "bot").strip()[:40] or "bot"
    raw = "sspanel_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    rec = {"id": gen_uid(), "name": name, "prefix": raw[:12] + "…",
           "hash": digest, "created_at": time.time(), "last_used": None,
           "note": (p.get("note") or "")[:200]}
    def _a(db):
        db.setdefault("api_tokens", []).append(rec)
    await store.mutate(_a)
    await log_audit(user, "token_create", name)
    # NOTE: raw token is shown ONLY once
    return {"ok": True, "token": raw,
            "record": {k: rec[k] for k in ("id", "name", "prefix", "created_at")},
            "hint": "Use as: Authorization: Bearer <token>"}


@app.delete("/api/tokens/{tid}")
async def api_tokens_revoke(tid: str, user: str = Depends(require_perm("security.manage"))):
    def _a(db):
        db["api_tokens"] = [t for t in db.get("api_tokens", []) if t.get("id") != tid]
    await store.mutate(_a)
    await log_audit(user, "token_revoke", tid)
    return {"ok": True}


# ------------------------- v2.0: backup / audit / system -------------------------
@app.get("/api/backup/export")
async def api_backup_export(user: str = Depends(require_perm("backup.manage"))):
    db = await store.get()
    await log_audit(user, "backup_export", "")
    return {"ok": True, "version": APP_VERSION, "exported_at": time.time(), "db": db}


@app.post("/api/backup/import")
async def api_backup_import(request: Request, user: str = Depends(require_perm("backup.manage"))):
    p = await request.json()
    data = p.get("db") or p
    if not isinstance(data, dict) or "inbounds" not in data:
        raise HTTPException(400, "invalid-backup")
    inbounds = data.get("inbounds", [])
    if not isinstance(inbounds, list) or len(inbounds) > 5000:
        raise HTTPException(400, "invalid-backup")
    mode = (p.get("mode") or "merge").strip()  # merge | replace

    def _a(db):
        if mode == "replace":
            db["inbounds"] = inbounds
            if isinstance(data.get("settings"), dict):
                for k, v in data["settings"].items():
                    if k in ("secret_key",):
                        continue
                    db.setdefault("settings", {})[k] = v
        else:
            have = {ib.get("uid") for ib in db["inbounds"]}
            for ib in inbounds:
                if not isinstance(ib, dict) or not ib.get("uid"):
                    continue
                if ib["uid"] not in have:
                    db["inbounds"].append(ib)
    db = await store.mutate(_a)
    refresh_xray(db)
    await log_audit(user, "backup_import", mode)
    return {"ok": True, "inbounds_count": len((await store.get())["inbounds"])}


@app.get("/api/audit")
async def api_audit(user: str = Depends(require_perm("security.manage")), action: str = ""):
    db = await store.get()
    logs = list(db.get("audit_log", []))
    if action:
        logs = [l for l in logs if l.get("action") == action]
    logs = logs[-150:]
    logs.reverse()
    actions = sorted({l.get("action", "") for l in db.get("audit_log", []) if l.get("action")})
    return {"logs": logs, "actions": actions}


# ------------------------- Phase 4: notification center -------------------------
@app.get("/api/notifications")
async def api_notifications(user: str = Depends(require_auth), unread_only: bool = False, limit: int = 100):
    db = await store.get()
    notifs = list(db.get("notifications", []))
    notifs.reverse()
    try:
        limit = max(1, min(200, int(limit)))
    except Exception:
        limit = 100
    if unread_only:
        notifs = [n for n in notifs if not n.get("read")]
    unread = sum(1 for n in db.get("notifications", []) if not n.get("read"))
    return {"notifications": notifs[:limit], "unread": unread}


@app.post("/api/notifications/read")
async def api_notifications_read(request: Request, user: str = Depends(require_auth)):
    try:
        p = await request.json()
    except Exception:
        p = {}
    ids = p.get("ids")
    marked = {"n": 0}

    def _a(db):
        for n in db.get("notifications", []):
            if (ids == "all" or ids is None) or n.get("id") in (ids or []):
                if not n.get("read"):
                    n["read"] = True
                    marked["n"] += 1
    await store.mutate(_a)
    return {"ok": True, "marked": marked["n"]}


# ------------------------- Phase 6: scheduled backups -------------------------
def _backups_dir() -> str:
    d = os.path.join(DATA_DIR, "backups")
    os.makedirs(d, exist_ok=True)
    return d


async def do_backup(auto: bool = False, actor: str = "system"):
    """Snapshot db.json to a file + history. Optionally ships to Telegram."""
    raw = None
    last_err = None
    for _ in range(3):  # tolerate transient file locks (e.g. mid-rotation reads)
        try:
            with open(DB_PATH, "rb") as f:
                raw = f.read()
            break
        except Exception as e:
            last_err = e
            await asyncio.sleep(0.5)
    if raw is None:
        raise HTTPException(500, f"backup-read-failed: {last_err}")
    ts = time.time()
    fname = "aloo-backup-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(ts)) + ".json"
    dest = os.path.join(_backups_dir(), fname)
    with open(dest, "wb") as f:
        f.write(raw)
    rec = {"id": gen_uid(), "ts": ts, "file": fname, "size": len(raw), "auto": bool(auto)}
    db = await store.get()
    keep = int((db.get("settings") or {}).get("backup_keep") or 7)

    def _a(db):
        bl = db.setdefault("backups", [])
        bl.append(rec)
        while len(bl) > max(1, keep):
            old = bl.pop(0)
            try:
                os.remove(os.path.join(_backups_dir(), old.get("file", "")))
            except Exception:
                pass
    await store.mutate(_a)
    await log_audit(actor, "backup_create", f"{fname} ({len(raw)}B)")
    # ship to admin chat like the shop bots do (real document upload)
    try:
        db2 = await store.get()
        s2 = db2.get("settings") or {}
        if auto and s2.get("backup_send_telegram", True) and s2.get("telegram_enabled"):
            tok, chat, _src = telegram_bot.resolve_creds(s2)
            if tok and chat:
                await telegram_bot.send_document(
                    tok, chat, raw, fname,
                    f"💾 بکاپ خودکار دیتابیس\n📅 {time.strftime('%Y-%m-%d %H:%M')}\n📦 حجم: {len(raw)/1024:.1f} مگابایت")
    except Exception:
        pass
    return rec


async def _backup_loop():
    await asyncio.sleep(25)
    while True:
        try:
            db = await store.get()
            s = db.get("settings") or {}
            if s.get("backup_enabled"):
                now = time.localtime()
                want = (int(s.get("backup_hour") or 4), int(s.get("backup_minute") or 0))
                today = time.strftime("%Y-%m-%d", now)
                if (now.tm_hour, now.tm_min) >= want and s.get("last_backup_day") != today:
                    try:
                        await do_backup(auto=True)
                    except Exception:
                        pass
                    else:
                        def _mark(db):
                            db.setdefault("settings", {})["last_backup_day"] = today
                        try:
                            await store.mutate(_mark)
                        except Exception:
                            pass
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(5)


@app.get("/api/backups")
async def api_backups_list(user: str = Depends(require_perm("backup.manage"))):
    db = await store.get()
    s = db.get("settings") or {}
    bl = list(db.get("backups", []))
    bl.reverse()
    return {"backups": bl, "schedule": {
        "enabled": bool(s.get("backup_enabled")),
        "hour": int(s.get("backup_hour") or 4),
        "minute": int(s.get("backup_minute") or 0),
        "keep": int(s.get("backup_keep") or 7),
        "send_telegram": bool(s.get("backup_send_telegram", True)),
        "last_day": s.get("last_backup_day") or "",
    }}


@app.post("/api/backups")
async def api_backups_create(user: str = Depends(require_perm("backup.manage"))):
    rec = await do_backup(auto=False, actor=user)
    return {"ok": True, "backup": rec}


@app.get("/api/backups/{bid}/download")
async def api_backups_download(bid: str, user: str = Depends(require_perm("backup.manage"))):
    db = await store.get()
    rec = next((b for b in db.get("backups", []) if b.get("id") == bid), None)
    if not rec:
        raise HTTPException(404, "not-found")
    path = os.path.join(_backups_dir(), rec.get("file", ""))
    if not os.path.isfile(path):
        raise HTTPException(404, "file-missing")
    with open(path, "rb") as f:
        raw = f.read()
    return Response(content=raw, media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={rec['file']}"})


@app.post("/api/backups/restore")
async def api_backups_restore(request: Request, user: str = Depends(require_perm("backup.manage"))):
    """Restore a snapshot. Sessions survive (secret_key is preserved)."""
    p = await request.json()
    bid = (p.get("id") or "").strip()
    password = p.get("password") or ""
    if user.startswith("token:"):
        raise HTTPException(403, "forbidden")
    db = await store.get()
    admin = find_admin(db, user)
    if not admin or not admin_credential_ok(admin, password):
        raise HTTPException(401, "wrong-old-password")
    rec = next((b for b in db.get("backups", []) if b.get("id") == bid), None)
    if not rec:
        raise HTTPException(404, "not-found")
    path = os.path.join(_backups_dir(), rec.get("file", ""))
    try:
        with open(path, "r", encoding="utf-8") as f:
            snap = json.load(f)
    except Exception:
        raise HTTPException(400, "corrupt-backup")
    if not isinstance(snap, dict) or not isinstance(snap.get("inbounds"), list):
        raise HTTPException(400, "invalid-backup")

    def _a(db):
        keep_secret = db.get("secret_key")
        keep_attempts = db.get("login_attempts", {})
        db.clear()
        db.update(snap)
        db["secret_key"] = keep_secret
        db["login_attempts"] = keep_attempts
    await store.mutate(_a)
    db2 = await store.get()
    refresh_xray(db2)
    await log_audit(user, "backup_restore", rec.get("file", ""))
    return {"ok": True}


@app.delete("/api/backups/{bid}")
async def api_backups_delete(bid: str, user: str = Depends(require_perm("backup.manage"))):
    gone = {"v": False}

    def _a(db):
        for b in db.get("backups", []):
            if b.get("id") == bid:
                try:
                    os.remove(os.path.join(_backups_dir(), b.get("file", "")))
                except Exception:
                    pass
        before = len(db.get("backups", []))
        db["backups"] = [b for b in db.get("backups", []) if b.get("id") != bid]
        gone["v"] = len(db["backups"]) != before
    await store.mutate(_a)
    if not gone["v"]:
        raise HTTPException(404, "not-found")
    await log_audit(user, "backup_delete", bid)
    return {"ok": True}


# ------------------------- Phase 6: diagnostics -------------------------
def _diag(ok_key: str, status: str, detail: str = "", hint: str = "") -> dict:
    return {"key": ok_key, "status": status, "detail": detail[:300], "hint": hint[:300]}


@app.get("/api/diagnostics/run")
async def api_diagnostics_run(user: str = Depends(require_perm("security.manage"))):
    import socket
    import subprocess
    import xray_manager as _xm
    db = await store.get()
    out = []
    # xray binary / process / config
    xb = getattr(_xm, "XRAY_BIN", "")
    if os.path.exists(xb):
        try:
            p = subprocess.run([xb, "--version"], capture_output=True, text=True, timeout=5)
            out.append(_diag("xray_binary", "ok", (p.stdout or "").splitlines()[0][:120] if p.stdout else "present"))
        except Exception as e:
            out.append(_diag("xray_binary", "error", str(e)[:200]))
    else:
        out.append(_diag("xray_binary", "warning", "not installed (mock mode)",
                         "On Railway the Dockerfile installs xray automatically."))
    proc = getattr(_xm, "xray_process", None)
    if proc is not None and proc.poll() is None:
        out.append(_diag("xray_process", "ok", "running"))
    elif os.path.exists(xb):
        out.append(_diag("xray_process", "error", "not running", "Use Xray → Restart."))
    else:
        out.append(_diag("xray_process", "warning", "mock mode (no binary)"))
    try:
        with open(getattr(_xm, "XRAY_CONFIG_PATH", ""), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        n = sum(len(i.get("settings", {}).get("clients", [])) for i in cfg.get("inbounds", []))
        out.append(_diag("xray_config", "ok", f"valid JSON, {n} tracked clients"))
    except Exception as e:
        out.append(_diag("xray_config", "error", f"unreadable: {e}"[:200]))
    # database
    try:
        probe = os.path.join(DATA_DIR, ".diag_probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        out.append(_diag("database", "ok",
                         f"{len(db.get('inbounds', []))} users, {len(db.get('audit_log', []))} audit entries"))
    except Exception as e:
        out.append(_diag("database", "error", str(e)[:200], "Check the /app/data volume."))
    # disk / memory / cpu
    try:
        du = psutil.disk_usage(DATA_DIR)
        st = "error" if du.percent >= 90 else ("warning" if du.percent >= 80 else "ok")
        out.append(_diag("disk", st, f"{du.percent}% used"))
    except Exception as e:
        out.append(_diag("disk", "warning", str(e)[:200]))
    try:
        mm = psutil.virtual_memory()
        st = "error" if mm.percent >= 95 else ("warning" if mm.percent >= 85 else "ok")
        out.append(_diag("memory", st, f"{mm.percent}% used"))
    except Exception as e:
        out.append(_diag("memory", "warning", str(e)[:200]))
    # network egress / dns / panel port
    try:
        t0 = time.time()
        async with httpx.AsyncClient(timeout=6) as c:
            r = await c.get("https://1.1.1.1/cdn-cgi/trace")
            r.raise_for_status()
        out.append(_diag("network", "ok", f"egress {int((time.time()-t0)*1000)}ms"))
    except Exception as e:
        out.append(_diag("network", "error", str(e)[:200][:200], "Server cannot reach the internet."))
    try:
        socket.gethostbyname("github.com")
        out.append(_diag("dns", "ok", "github.com resolves"))
    except Exception as e:
        out.append(_diag("dns", "error", str(e)[:200]))
    try:
        port = int(os.environ.get("PANEL_PORT") or os.environ.get("PORT") or 10000)
        sk = socket.create_connection(("127.0.0.1", port), timeout=3)
        sk.close()
        out.append(_diag("panel_port", "ok", f"127.0.0.1:{port} accepts connections"))
    except Exception as e:
        out.append(_diag("panel_port", "error", str(e)[:200]))
    # telegram
    s = db.get("settings") or {}
    if (s.get("telegram_bot_token") or "").strip():
        ok, info = await telegram_bot.validate_token((s.get("telegram_bot_token") or "").strip())
        if ok:
            out.append(_diag("telegram", "ok", "@" + str((info or {}).get("username") or "?")))
        else:
            out.append(_diag("telegram", "error", str(info)[:200], "Re-save the token in Telegram settings."))
    else:
        out.append(_diag("telegram", "warning", "no bot token configured"))
    # backups
    bl = db.get("backups", [])
    if not s.get("backup_enabled"):
        out.append(_diag("backups", "warning", "scheduled backups are off"))
    elif not bl:
        out.append(_diag("backups", "warning", "enabled but no snapshot yet"))
    else:
        age_h = (time.time() - max(b.get("ts", 0) for b in bl)) / 3600
        out.append(_diag("backups", "ok" if age_h < 49 else "warning",
                         f"{len(bl)} snapshots, latest {age_h:.1f}h ago"))
    await log_audit(user, "diagnostics_run", "")
    return {"checks": out}


@app.get("/api/system")
async def api_system(user: str = Depends(require_perm("analytics.read"))):
    import platform
    db = await store.get()
    try:
        disk = psutil.disk_usage("/")
        disk_info = {"percent": disk.percent, "used_gb": round(disk.used / 1024**3, 1), "total_gb": round(disk.total / 1024**3, 1)}
    except Exception:
        disk_info = {}
    try:
        la = list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else []
    except Exception:
        la = []
    return {"cpu_count": psutil.cpu_count(), "load_avg": la, "disk": disk_info,
            "python": platform.python_version(), "platform": platform.platform(),
            "arch": platform.machine(),
            "version": APP_VERSION, "tokens": len(db.get("api_tokens", [])),
            "users": len(db.get("inbounds", []))}


@app.get("/api/online")
async def api_online(user: str = Depends(require_perm("analytics.read"))):
    db = await store.get()
    now = time.time()
    out = []
    for ib in db["inbounds"]:
        ts = last_seen.get(ib["uid"])
        if ts and now - ts < 90:
            out.append({"uid": ib["uid"], "name": ib.get("name"),
                        "last_seen_ago": int(now - ts)})
    return {"online": out, "count": len(out)}


# ------------------------- Phase 7: AI assistant (real-data analysis) -------------------------
@app.get("/api/ai/brief")
async def api_ai_brief(user: str = Depends(require_perm("analytics.read"))):
    db = await store.get()
    try:
        cpu = float(psutil.cpu_percent(interval=0.2))
        mem = float(psutil.virtual_memory().percent)
    except Exception:
        cpu = mem = None
    findings = ai_assistant.analyze(db, cpu, mem)
    return {"findings": findings,
            "cpu": cpu, "mem": mem,
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "warnings": sum(1 for f in findings if f["severity"] == "warning")}


@app.post("/api/ai/chat")
async def api_ai_chat(request: Request, user: str = Depends(require_perm("analytics.read"))):
    try:
        p = await request.json()
    except Exception:
        p = {}
    text = str(p.get("message") or "")[:500]
    if not text.strip():
        raise HTTPException(400, "empty-message")
    db = await store.get()
    try:
        cpu = float(psutil.cpu_percent(interval=0.2))
        mem = float(psutil.virtual_memory().percent)
    except Exception:
        cpu = mem = None
    return ai_assistant.answer(db, text, cpu, mem)


# ------------------------- Phase 3: analytics -------------------------
HOURLY_RETENTION_HOURS = 72


@app.get("/api/analytics")
async def api_analytics(user: str = Depends(require_perm("analytics.read")),
                        range: str = "24h", from_ts: float = 0, to_ts: float = 0):
    """Traffic analytics over real stored hourly buckets.

    ranges: today | yesterday | 24h | 7d | 30d | custom (from_ts/to_ts).
    Only ~72h of hourly history is retained — responses flag `partial`
    whenever the requested window exceeds available data.
    """
    db = await store.get()
    now = time.time()
    presets = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
    if range == "custom":
        try:
            start, end = float(from_ts or 0), float(to_ts or 0)
        except Exception:
            raise HTTPException(400, "invalid-range")
        if not start or not end or end <= start or (end - start) > 90 * 86400:
            raise HTTPException(400, "invalid-range")
        start, end = min(start, now), min(end, now)
    elif range in ("today", "yesterday"):
        lt = time.localtime(now)
        midnight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
        if range == "today":
            start, end = midnight, now
        else:
            start, end = midnight - 86400, midnight
    else:
        span = presets.get(range, 86400)
        end, start = now, now - span

    hourly = sorted((h for h in db["stats"].get("hourly", []) if "t" in h),
                    key=lambda h: h["t"])
    oldest = hourly[0]["t"] if hourly else now
    buckets = [{"t": h["t"], "up": int(h.get("up") or 0), "down": int(h.get("down") or 0)}
               for h in hourly if start <= h["t"] <= end]
    total_up = sum(b["up"] for b in buckets)
    total_down = sum(b["down"] for b in buckets)
    peak = max(buckets, key=lambda b: b["up"] + b["down"]) if buckets else None

    users = []
    for ib in db.get("inbounds", []):
        used = int(ib.get("used_up") or 0) + int(ib.get("used_down") or 0)
        active_conns = len(runtime["active"].get(ib["uid"], {}))
        users.append({"uid": ib["uid"], "name": ib.get("name", ""),
                      "used_up": int(ib.get("used_up") or 0),
                      "used_down": int(ib.get("used_down") or 0),
                      "used": used,
                      "active_connections": active_conns})
    users.sort(key=lambda u: u["used"], reverse=True)
    users_by_conns = sorted(users, key=lambda u: u["active_connections"], reverse=True)

    per_server = [{
        "id": "local", "name": "Local Server",
        "up": int(db["stats"].get("total_up", 0)),
        "down": int(db["stats"].get("total_down", 0)),
        "users": len(db.get("inbounds", [])),
    }]
    for srv in db.get("servers", []):
        m = srv.get("metrics") or {}
        per_server.append({
            "id": srv["id"], "name": srv.get("name", ""),
            "up": int(m.get("total_up") or 0), "down": int(m.get("total_down") or 0),
            "users": int(m.get("users") or 0),
            "online": srv.get("online"),
        })

    total = total_up + total_down
    return {
        "range": range, "from": start, "to": end,
        "retention_hours": HOURLY_RETENTION_HOURS,
        "partial": oldest > start,
        "oldest_available": oldest,
        "total_up": total_up, "total_down": total_down, "total": total,
        "up_share": round(total_up / total, 4) if total else 0,
        "down_share": round(total_down / total, 4) if total else 0,
        "avg_per_hour": round(total / max(1, len(buckets)), 1) if buckets else 0,
        "peak_hour": peak,
        "buckets": buckets,
        "top_users": users[:15],
        "top_users_by_connections": users_by_conns[:15],
        "per_server": per_server,
        # user totals are cumulative counters, NOT range-limited:
        "user_totals_note": "cumulative",
    }


# ------------------------- Phase 3: live snapshot -------------------------
_net_prev = {"ts": 0.0, "sent": 0, "recv": 0}


@app.get("/api/live")
async def api_live(user: str = Depends(require_perm("analytics.read"))):
    """Near-real-time local snapshot (poll every ~3s from the Live view)."""
    global last_seen, _net_prev
    db = await store.get()
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    now = time.time()
    try:
        net = psutil.net_io_counters()
        prev = _net_prev
        dt = max(0.001, now - prev["ts"]) if prev["ts"] else 0
        up_bps = (net.bytes_sent - prev["sent"]) / dt if dt else 0
        down_bps = (net.bytes_recv - prev["recv"]) / dt if dt else 0
        _net_prev = {"ts": now, "sent": net.bytes_sent, "recv": net.bytes_recv}
    except Exception:
        up_bps = down_bps = 0
    active = sum(1 for ts in last_seen.values() if now - ts < 30)
    return {
        "ts": now,
        "cpu_percent": cpu,
        "mem_percent": mem.percent,
        "net_up_bps": max(0, round(up_bps, 1)),
        "net_down_bps": max(0, round(down_bps, 1)),
        "active_connections": active,
        "users": len(db.get("inbounds", [])),
        "xray": xray_service_status(),
        "uptime_seconds": now - db["stats"].get("started_at", now),
    }


def build_links(request: Request, db, ib) -> dict:
    host = public_host(request, db)
    uuidv = ib["uuid"]
    name = ib["name"]
    prefix = ((db.get("settings") or {}).get("sub_remark_prefix") or "ALOO").strip() or "ALOO"
    fp = ib.get("fp") or (db.get("settings") or {}).get("default_fingerprint", "chrome")
    alpn = (db.get("settings") or {}).get("default_alpn", "http/1.1")
    sni = (db.get("settings") or {}).get("sni_override") or host
    port_tls = 443

    vl_ws_tls = f"vless://{uuidv}@{host}:{port_tls}?encryption=none&security=tls&type=ws&host={quote(host)}&path={quote('/vl-ws', safe='/')}&sni={quote(sni)}&fp={fp}&alpn={quote(alpn, safe=',/')}#{quote(f'{prefix}-{name}-VL-WS-TLS')}"

    def make_vmess(port, tls_mode, remark):
        vm_json = {
            "v": "2", "ps": remark, "add": host, "port": port, "id": uuidv,
            "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": host, "path": "/vm-ws", "tls": tls_mode, "sni": sni, "alpn": alpn
        }
        b64 = base64.b64encode(json.dumps(vm_json).encode()).decode()
        return f"vmess://{b64}"

    vm_ws_tls = make_vmess(port_tls, "tls", f"{prefix}-{name}-VM-WS-TLS")
    vl_xh_tls = f"vless://{uuidv}@{host}:{port_tls}?encryption=none&security=tls&type=xhttp&host={quote(host)}&path={quote('/vl-xhttp', safe='/')}&sni={quote(sni)}&fp={fp}&alpn=h2#{quote(f'{prefix}-{name}-VL-XHTTP-TLS')}"

    st = inbound_status(ib)
    quota_gb = ib.get("quota_gb") or 0
    used_gb = st["used"] / (1024 ** 3)
    quota_txt = f"{used_gb:.2f}/{quota_gb:g}GB" if quota_gb > 0 else f"{used_gb:.2f}GB used"
    days_txt = f"{st['days_left']}d left" if ib.get("expire_at") else "no expiry"
    status_remark = f"📊 {quota_txt} | ⏳ {days_txt}"
    free_remark = f"{prefix} Multi-Protocol"

    dummy_uuid_status = "00000000-0000-0000-0000-000000000001"
    dummy_uuid_credit = "00000000-0000-0000-0000-000000000002"
    dummy_link_status = f"vless://{dummy_uuid_status}@127.0.0.1:10001?encryption=none&security=none&type=tcp&headerType=none#{quote(status_remark)}"
    dummy_link_credit = f"vless://{dummy_uuid_credit}@127.0.0.1:10002?encryption=none&security=none&type=tcp&headerType=none#{quote(free_remark)}"
    info_configs = [
        {"remark": status_remark, "link": dummy_link_status, "kind": "status"},
        {"remark": free_remark, "link": dummy_link_credit, "kind": "credit"},
    ]

    all_links = [vl_ws_tls, vm_ws_tls, vl_xh_tls]

    return {
        "tls": vl_ws_tls,
        "all_links": all_links,
        "info_configs": info_configs,
    }


@app.get("/api/inbounds/{uid}/links")
async def api_inbound_links(uid: str, request: Request, user: str = Depends(require_perm("users.read"))):
    db = await store.get()
    ib = inbound_by_uid(db, uid)
    if not ib:
        raise HTTPException(404, "not-found")
    host = public_host(request, db)
    scheme = get_scheme(request)
    links = build_links(request, db, ib)
    return {
        "links": links,
        "sub_url": canonical_sub_url(request, db, ib),
        "sub_legacy_url": f"{scheme}://{host}/sub/{uid}",
        "sub_json_url": f"{scheme}://{host}/s/{sub_token_of(ib)}/json",
        "sub_clash_url": f"{scheme}://{host}/sub/{sub_token_of(ib)}/clash",
        "sub_singbox_url": f"{scheme}://{host}/sub/{sub_token_of(ib)}/singbox",
        "sub_enabled": ib.get("sub_enabled", True),
        "status_url": f"{scheme}://{host}/status/{uid}",
        "doh_url": f"{scheme}://{host}/dns-query",
    }


@app.post("/api/inbounds/{uid}/regen-sub")
async def api_regen_sub(uid: str, user: str = Depends(require_perm("users.edit"))):
    """Rotate the subscription token: old /s/ links die instantly, configs keep working."""
    new_tok = {"v": None}

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["sub_token"] = secrets.token_hex(12)
        new_tok["v"] = ib["sub_token"]
    await store.mutate(_a)
    await log_audit(user, "regen_sub", uid)
    return {"ok": True, "sub_token": new_tok["v"]}


@app.post("/api/inbounds/{uid}/sub-toggle")
async def api_sub_toggle(uid: str, user: str = Depends(require_perm("users.edit"))):
    out = {}

    def _a(db):
        ib = inbound_by_uid(db, uid)
        if not ib:
            raise HTTPException(404, "not-found")
        ib["sub_enabled"] = not ib.get("sub_enabled", True)
        out["sub_enabled"] = ib["sub_enabled"]
    await store.mutate(_a)
    await log_audit(user, "sub_toggle", f"{uid}:{out['sub_enabled']}")
    return {"ok": True, **out}


@app.get("/api/inbounds/{uid}/config-file")
async def api_config_file(uid: str, request: Request, user: str = Depends(require_perm("users.read"))):
    """Download all configs as a .txt file."""
    db = await store.get()
    ib = inbound_by_uid(db, uid)
    if not ib:
        raise HTTPException(404, "not-found")
    links = build_links(request, db, ib)
    body = f"# ALOO PANEL ULTIMATE — {ib.get('name', '')}\n# exported {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n" \
        + "\n".join(links["all_links"]) + "\n"
    return Response(content=body, media_type="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=aloo-{uid}-configs.txt"})


@app.get("/api/inbounds/{uid}/qr")
async def api_inbound_qr(uid: str, request: Request, user: str = Depends(require_perm("users.read")), link: str = "tls"):
    """QR for one target: tls (default), sub, or 0/1/2 (individual configs)."""
    db = await store.get()
    ib = inbound_by_uid(db, uid)
    if not ib:
        raise HTTPException(404, "not-found")
    links = build_links(request, db, ib)
    targets = {"tls": links["tls"], "sub": canonical_sub_url(request, db, ib)}
    for i, l in enumerate(links["all_links"]):
        targets[str(i)] = l
    text = targets.get((link or "tls").strip().lower(), links["tls"])
    img = qrcode.make(text, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ------------------------- Phase 2: Xray integration -------------------------
def _xray_version() -> str | None:
    import subprocess
    import xray_manager as _xm
    xb = getattr(_xm, "XRAY_BIN", "/usr/local/bin/xray")
    if not os.path.exists(xb):
        return None
    try:
        p = subprocess.run([xb, "--version"], capture_output=True, text=True, timeout=5)
        line = (p.stdout or "").strip().splitlines()
        return line[0][:120] if line else "unknown"
    except Exception:
        return "unknown"


@app.get("/api/xray/status")
async def api_xray_status(user: str = Depends(require_perm("servers.read"))):
    import xray_manager as _xm
    db = await store.get()
    st = xray_service_status()
    try:
        with open(getattr(_xm, "XRAY_CONFIG_PATH", ""), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        clients = sum(len(ib.get("settings", {}).get("clients", []))
                      for ib in cfg.get("inbounds", []) if isinstance(ib, dict))
    except Exception:
        clients = None
    return {
        **st,
        "version": _xray_version(),
        "config_path": getattr(_xm, "XRAY_CONFIG_PATH", ""),
        "log_level": (db.get("settings") or {}).get("xray_log_level", "warning"),
        "tracked_clients": clients,
        "ports": {"panel": 10000, "vless_ws": 10001, "vmess_ws": 10002,
                  "vless_xhttp": 10004, "api": 10085},
    }


@app.get("/api/xray/config")
async def api_xray_config(user: str = Depends(require_perm("servers.read"))):
    import xray_manager as _xm
    try:
        with open(getattr(_xm, "XRAY_CONFIG_PATH", ""), "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="application/json")
    except Exception:
        raise HTTPException(404, "config-not-found")


@app.post("/api/xray/restart")
async def api_xray_restart(user: str = Depends(require_perm("servers.manage"))):
    db = await store.get()
    refresh_xray(db)
    await log_audit(user, "xray_restart", "")
    return {"ok": True, "status": xray_service_status()}


@app.post("/api/xray/start")
async def api_xray_start(user: str = Depends(require_perm("servers.manage"))):
    res = xray_manager.start_xray()
    await log_audit(user, "xray_start", "")
    return {"ok": bool(res.get("started") or res.get("already")), **res,
            "status": xray_service_status()}


@app.post("/api/xray/stop")
async def api_xray_stop(user: str = Depends(require_perm("servers.manage"))):
    res = xray_manager.stop_xray()
    await log_audit(user, "xray_stop", "")
    return {"ok": True, **res, "status": xray_service_status()}


@app.get("/api/xray/validate")
async def api_xray_validate(user: str = Depends(require_perm("servers.read"))):
    return xray_manager.validate_config()


# ------------------------- Phase 3: servers API -------------------------
@app.get("/api/servers")
async def api_servers_list(user: str = Depends(require_perm("servers.read"))):
    db = await store.get()
    local = {
        "id": "local", "name": "Local Server", "local": True,
        "host": "local", "country": "", "enabled": True,
        "online": True, "last_check": time.time(),
        "metrics": {
            "users": len(db.get("inbounds", [])),
            "total_up": int(db["stats"].get("total_up", 0)),
            "total_down": int(db["stats"].get("total_down", 0)),
            "version": APP_VERSION,
            "xray": xray_service_status()["status"],
        },
        "has_token": False, "token_prefix": "", "note": "this panel",
    }
    return {"servers": [local] + [mask_server(s) for s in db.get("servers", [])],
            "load_balancer_enabled": bool((db.get("settings") or {}).get("load_balancer_enabled", True))}


@app.post("/api/servers")
async def api_servers_add(request: Request, user: str = Depends(require_perm("servers.manage"))):
    p = await request.json()
    name = (p.get("name") or "").strip()[:40]
    host = normalize_host(p.get("host") or "")
    token = (p.get("token") or "").strip()
    country = (p.get("country") or "").strip()[:40]
    if not name:
        raise HTTPException(400, "name-required")
    if not host or not token:
        raise HTTPException(400, "host-token-required")
    try:
        weight = max(1, min(1000, int(p.get("weight") or 100)))
    except (TypeError, ValueError):
        raise HTTPException(400, "invalid-weight")
    # Real validation: the remote must answer as an ALOO PANEL with this token.
    try:
        me_j, st_j, _sys, _live = await fetch_remote_metrics(host, token)
    except Exception as e:
        raise HTTPException(502, f"remote-unreachable: {str(e)[:120]}")
    metrics = summarize_remote_metrics(me_j, st_j, _sys, _live)
    import urllib.parse as _up
    ip = ""
    try:
        ip = (_up.urlparse(host).hostname or "")
    except Exception:
        pass
    rec = {"id": "srv_" + gen_uid(), "name": name, "host": host, "token": token,
           "ip": ip, "port": 443,
           "country": country, "city": metrics.get("location") or "",
           "provider": (p.get("provider") or "")[:40], "stype": (p.get("stype") or "panel")[:20],
           "os": "", "arch": "",
           "weight": weight, "maintenance": False,
           "enabled": True, "created_at": time.time(),
           "last_check": time.time(), "last_seen": time.time(), "last_success": time.time(),
           "online": True, "fail_count": 0,
           "latency_ms": metrics.get("latency_ms"),
           "health": core_servers.health_score(metrics, True),
           "load": core_servers.load_pct(metrics),
           "version_compat": core_servers.version_compat(APP_VERSION, metrics.get("version") or ""),
           "metrics": metrics, "group_ids": [],
           "note": (p.get("note") or "")[:200]}

    def _a(db):
        if any(s.get("host") == host for s in db.get("servers", [])):
            raise HTTPException(409, "duplicate-host")
        db.setdefault("servers", []).append(rec)
    await store.mutate(_a)
    await log_audit(user, "server_add", f"{name} {host}", ref=rec["id"])
    await record_server_event(rec["id"], "server_added", f"{name} ({host}) added", "info")
    out = mask_server(rec)
    return {"ok": True, "server": out}


@app.patch("/api/servers/{sid}")
async def api_servers_update(sid: str, request: Request, user: str = Depends(require_perm("servers.manage"))):
    p = await request.json()
    out = {}
    new_host = normalize_host(p.get("host") or "") if "host" in p else None
    new_token = (p.get("token") or "").strip() if "token" in p else None
    # If connectivity params change, re-validate against the real remote.
    if new_host or new_token:
        db0 = await store.get()
        srv0 = server_by_id(db0, sid)
        if not srv0:
            raise HTTPException(404, "not-found")
        try:
            await fetch_remote_metrics(new_host or srv0["host"], new_token or srv0.get("token") or "")
        except Exception as e:
            raise HTTPException(502, f"remote-unreachable: {str(e)[:120]}")

    def _a(db):
        srv = server_by_id(db, sid)
        if not srv:
            raise HTTPException(404, "not-found")
        if "name" in p and str(p["name"]).strip():
            srv["name"] = str(p["name"]).strip()[:40]
        for k in ("country", "city", "provider", "note"):
            if k in p:
                srv[k] = str(p.get(k) or "")[:200 if k == "note" else 40]
        if "stype" in p and str(p["stype"]).strip() in ("panel", "edge", "backup"):
            srv["stype"] = str(p["stype"]).strip()
        if "weight" in p:
            try:
                srv["weight"] = max(1, min(1000, int(p["weight"])))
            except (TypeError, ValueError):
                raise HTTPException(400, "invalid-weight")
        if "maintenance" in p:
            srv["maintenance"] = bool(p["maintenance"])
        if "enabled" in p:
            srv["enabled"] = bool(p["enabled"])
        if new_host:
            srv["host"] = new_host
            import urllib.parse as _up2
            try:
                srv["ip"] = (_up2.urlparse(new_host).hostname or "")
            except Exception:
                pass
        if new_token:
            srv["token"] = new_token
        if new_host or new_token or "enabled" in p:
            srv["fail_count"] = 0
            srv["online"] = None if (new_host or new_token) else srv.get("online")
        out.update(mask_server(srv))
    await store.mutate(_a)
    await log_audit(user, "server_update", sid, ref=sid)
    await record_server_event(sid, "server_updated", f"Server settings updated", "info")
    return {"ok": True, "server": out}


@app.delete("/api/servers/{sid}")
async def api_servers_delete(sid: str, user: str = Depends(require_perm("servers.manage"))):
    found = {"v": False, "name": ""}

    def _a(db):
        for s in db.get("servers", []):
            if s.get("id") == sid:
                found["name"] = s.get("name", "")
        before = len(db.get("servers", []))
        db["servers"] = [s for s in db.get("servers", []) if s.get("id") != sid]
        found["v"] = len(db["servers"]) != before
    await store.mutate(_a)
    if not found["v"]:
        raise HTTPException(404, "not-found")
    await log_audit(user, "server_delete", found["name"], ref=sid)
    return {"ok": True}


@app.post("/api/servers/{sid}/test")
async def api_servers_test(sid: str, user: str = Depends(require_perm("servers.manage"))):
    """Force a live poll now and return the fresh result."""
    res = await poll_server(sid)
    if not res.get("ok"):
        raise HTTPException(502, res.get("reason") or "unreachable")
    await log_audit(user, "server_test", sid, ref=sid)
    return {"ok": True, "metrics": res["metrics"]}


@app.get("/api/servers/best")
async def api_servers_best(user: str = Depends(require_perm("servers.read"))):
    """Intelligent selection over REAL metrics.

    Strategies (settings.lb_strategy): least_load | least_connections |
    lowest_latency | weighted | health. Maintenance/disabled/offline servers
    are never candidates.
    """
    db = await store.get()
    s = db.get("settings") or {}
    lb_on = bool(s.get("load_balancer_enabled", True))
    strategy = (s.get("lb_strategy") or "least_load").strip()
    if strategy not in ("least_load", "least_connections", "lowest_latency", "weighted", "health"):
        strategy = "least_load"
    cands = [{
        "id": "local", "name": "Local Server", "local": True, "weight": 100,
        "users": len(db.get("inbounds", [])),
        "cpu": round(float(psutil.cpu_percent(interval=0.1)), 1),
        "mem": round(float(psutil.virtual_memory().percent), 1),
        "conns": 0, "latency_ms": 0.0,
        "health": 100, "load": None, "online": True,
    }]
    for srv in db.get("servers", []):
        if not srv.get("enabled", True) or srv.get("online") is not True \
                or srv.get("maintenance"):
            continue
        m = srv.get("metrics") or {}
        cands.append({
            "id": srv["id"], "name": srv.get("name", ""), "local": False,
            "weight": int(srv.get("weight") or 100),
            "users": int(m.get("users") or 0),
            "cpu": round(float(m.get("cpu") or 0), 1),
            "mem": round(float(m.get("mem") or 0), 1),
            "conns": int(m.get("active_connections") or 0),
            "latency_ms": m.get("latency_ms"),
            "health": srv.get("health"),
            "load": srv.get("load"),
            "online": True,
        })
    for cnd in cands:
        load = cnd.get("load")
        if load is None:
            load = round(0.5 * (cnd.get("cpu") or 0) + 0.3 * (cnd.get("mem") or 0)
                         + 0.2 * min(100.0, cnd.get("conns") or 0), 1)
            cnd["load"] = load
        lat = cnd.get("latency_ms")
        lat = float(lat) if lat is not None else 9999.0
        health = cnd.get("health")
        health = float(health) if health is not None else 50.0
        if strategy == "least_connections":
            cnd["score"] = round(cnd["conns"] + cnd["users"] / 10, 2)
        elif strategy == "lowest_latency":
            cnd["score"] = round(lat + load, 2)
        elif strategy == "weighted":
            cnd["score"] = round(load * 100 / max(1, cnd.get("weight") or 100), 2)
        elif strategy == "health":
            cnd["score"] = round((100 - health) * 2 + load, 2)
        else:  # least_load
            cnd["score"] = round(load, 2)
    cands.sort(key=lambda c: c["score"])
    return {"candidates": cands,
            "recommended": (cands[0]["id"] if cands and lb_on else None),
            "load_balancer_enabled": lb_on, "strategy": strategy}


def _group_by_id(db, gid: str):
    for g in db.get("server_groups", []):
        if g.get("id") == gid:
            return g
    return None


# ------------------------- Phase 3: server groups -------------------------
@app.get("/api/server-groups")
async def api_groups_list(user: str = Depends(require_perm("servers.read"))):
    db = await store.get()
    return {"groups": db.get("server_groups", [])}


@app.post("/api/server-groups")
async def api_groups_create(request: Request, user: str = Depends(require_perm("servers.manage"))):
    p = await request.json()
    name = (p.get("name") or "").strip()[:40]
    if not name:
        raise HTTPException(400, "name-required")
    rec = {"id": "grp_" + gen_uid(), "name": name,
           "description": (p.get("description") or "")[:200],
           "server_ids": [], "created_at": time.time()}

    def _a(db):
        if any(g.get("name", "").lower() == name.lower() for g in db.get("server_groups", [])):
            raise HTTPException(409, "duplicate-group")
        db.setdefault("server_groups", []).append(rec)
    await store.mutate(_a)
    await log_audit(user, "group_create", name)
    return {"ok": True, "group": rec}


@app.patch("/api/server-groups/{gid}")
async def api_groups_update(gid: str, request: Request, user: str = Depends(require_perm("servers.manage"))):
    p = await request.json()
    out = {}

    def _a(db):
        g = _group_by_id(db, gid)
        if not g:
            raise HTTPException(404, "not-found")
        if "name" in p and str(p["name"]).strip():
            nm = str(p["name"]).strip()[:40]
            if any(x.get("name", "").lower() == nm.lower() and x.get("id") != gid
                   for x in db.get("server_groups", [])):
                raise HTTPException(409, "duplicate-group")
            g["name"] = nm
        if "description" in p:
            g["description"] = str(p.get("description") or "")[:200]
        if "server_ids" in p and isinstance(p["server_ids"], list):
            valid = {s.get("id") for s in db.get("servers", [])} | {"local"}
            g["server_ids"] = [x for x in p["server_ids"] if x in valid][:100]
        out.update(g)
    await store.mutate(_a)
    await log_audit(user, "group_update", gid)
    return {"ok": True, "group": out}


@app.delete("/api/server-groups/{gid}")
async def api_groups_delete(gid: str, user: str = Depends(require_perm("servers.manage"))):
    found = {"v": False}

    def _a(db):
        before = len(db.get("server_groups", []))
        db["server_groups"] = [g for g in db.get("server_groups", []) if g.get("id") != gid]
        found["v"] = len(db["server_groups"]) != before
        for s in db.get("servers", []):
            if gid in (s.get("group_ids") or []):
                s["group_ids"] = [x for x in s["group_ids"] if x != gid]
    await store.mutate(_a)
    if not found["v"]:
        raise HTTPException(404, "not-found")
    await log_audit(user, "group_delete", gid)
    return {"ok": True}


@app.post("/api/server-groups/{gid}/servers")
async def api_groups_members(gid: str, request: Request, user: str = Depends(require_perm("servers.manage"))):
    """Set group membership: {server_ids: [...]}. Real two-way sync."""
    p = await request.json()
    ids = p.get("server_ids") or []
    if not isinstance(ids, list):
        raise HTTPException(400, "invalid-members")

    def _a(db):
        g = _group_by_id(db, gid)
        if not g:
            raise HTTPException(404, "not-found")
        valid = {s.get("id") for s in db.get("servers", [])} | {"local"}
        ids_clean = [x for x in ids if x in valid][:100]
        g["server_ids"] = ids_clean
        for s in db.get("servers", []):
            gs = set(s.get("group_ids") or [])
            if s.get("id") in ids_clean:
                gs.add(gid)
            else:
                gs.discard(gid)
            s["group_ids"] = sorted(gs)
    await store.mutate(_a)
    await log_audit(user, "group_members", f"{gid}:{len(ids)}")
    return {"ok": True}


# ------------------------- Phase 3: per-server detail APIs -------------------------
@app.get("/api/servers/{sid}/health")
async def api_server_health(sid: str, user: str = Depends(require_perm("servers.read"))):
    db = await store.get()
    if sid == "local":
        return {"id": "local", "health": 100, "load": None, "online": True,
                "maintenance": False, "formula": "see docs/SERVERS.md"}
    srv = server_by_id(db, sid)
    if not srv:
        raise HTTPException(404, "not-found")
    return {"id": sid, "health": srv.get("health"), "load": srv.get("load"),
            "online": srv.get("online"), "maintenance": bool(srv.get("maintenance")),
            "latency_ms": srv.get("latency_ms"), "version_compat": srv.get("version_compat"),
            "formula": "see docs/SERVERS.md"}


@app.get("/api/servers/{sid}/metrics")
async def api_server_metrics(sid: str, user: str = Depends(require_perm("servers.read")),
                             range: str = "24h"):
    """Monitoring history for one server (retention-capped real samples)."""
    db = await store.get()
    now = time.time()
    spans = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
    span = spans.get(range, 86400)
    if sid == "local":
        hourly = [h for h in db["stats"].get("hourly", []) if h.get("t", 0) >= now - span]
        return {"id": "local", "range": range,
                "samples": [{"ts": h["t"], "up": h.get("up"), "down": h.get("down")} for h in hourly],
                "kind": "traffic"}
    srv = server_by_id(db, sid)
    if not srv:
        raise HTTPException(404, "not-found")
    samples = [h for h in db.get("metrics_history", [])
               if h.get("server_id") == sid and h.get("ts", 0) >= now - span]
    samples.sort(key=lambda x: x.get("ts", 0))
    return {"id": sid, "range": range, "samples": samples[-500:], "kind": "system"}


@app.get("/api/servers/{sid}/events")
async def api_server_events(sid: str, user: str = Depends(require_perm("servers.read"))):
    """Event timeline: real audit entries referencing this server."""
    db = await store.get()
    if sid != "local" and not server_by_id(db, sid):
        raise HTTPException(404, "not-found")
    out = [l for l in db.get("audit_log", []) if l.get("ref") == sid]
    out = out[-100:]
    out.reverse()
    return {"id": sid, "events": out}


@app.get("/api/servers/{sid}/alerts")
async def api_server_alerts(sid: str, user: str = Depends(require_perm("servers.read")),
                            status: str = ""):
    db = await store.get()
    if sid != "local" and not server_by_id(db, sid):
        raise HTTPException(404, "not-found")
    out = [a for a in db.get("server_alerts", []) if a.get("server_id") == sid]
    if status in ("active", "resolved"):
        out = [a for a in out if a.get("status") == status]
    out.sort(key=lambda x: x.get("opened_at", 0), reverse=True)
    return {"id": sid, "alerts": out[:200]}


@app.get("/api/alerts")
async def api_alerts_list(user: str = Depends(require_perm("servers.read")), status: str = "active"):
    db = await store.get()
    out = list(db.get("server_alerts", []))
    if status in ("active", "resolved"):
        out = [a for a in out if a.get("status") == status]
    out.sort(key=lambda x: x.get("opened_at", 0), reverse=True)
    names = {}
    for s in db.get("servers", []):
        names[s.get("id")] = s.get("name", "")
    for a in out:
        a = dict(a)
        a["server_name"] = names.get(a.get("server_id"), a.get("server_id"))
    return {"alerts": out[:200]}


# ------------------------- Phase 3 enhanced: server events -------------------------
async def record_server_event(sid: str, etype: str, message: str, severity: str = "info"):
    """Write a structured event to the dedicated server_events timeline."""
    rec = {"id": gen_uid(), "server_id": sid, "type": etype, "message": message,
           "ts": time.time(), "severity": severity}

    def _a(db):
        evts = db.setdefault("server_events", [])
        evts.append(rec)
        while len(evts) > 2000:
            evts.pop(0)
    try:
        await store.mutate(_a)
    except Exception:
        pass


@app.get("/api/server-events")
async def api_server_events_global(user: str = Depends(require_perm("servers.read")),
                                   limit: int = 100, server_id: str = ""):
    """Global server event timeline across all servers."""
    db = await store.get()
    evts = list(db.get("server_events", []))
    if server_id:
        evts = [e for e in evts if e.get("server_id") == server_id]
    evts.sort(key=lambda x: x.get("ts", 0), reverse=True)
    try:
        limit = max(1, min(500, int(limit)))
    except Exception:
        limit = 100
    names = {}
    for s in db.get("servers", []):
        names[s.get("id")] = s.get("name", "")
    names["local"] = "Local Server"
    out = []
    for e in evts[:limit]:
        d = dict(e)
        d["server_name"] = names.get(e.get("server_id"), e.get("server_id"))
        out.append(d)
    return {"events": out, "total": len(evts)}


@app.get("/api/servers/monitoring")
async def api_servers_monitoring(user: str = Depends(require_perm("servers.read"))):
    """Global multi-server monitoring overview with aggregated metrics."""
    db = await store.get()
    servers = db.get("servers", [])
    online = [s for s in servers if s.get("online") is True]
    offline = [s for s in servers if s.get("online") is False]
    maintenance = [s for s in servers if s.get("maintenance")]
    healths = [s.get("health") for s in servers if s.get("health") is not None]
    loads = [s.get("load") for s in servers if s.get("load") is not None]
    latencies = [s.get("latency_ms") for s in servers if s.get("latency_ms") is not None]
    total_users = sum(int((s.get("metrics") or {}).get("users") or 0) for s in servers)
    total_conns = sum(int((s.get("metrics") or {}).get("active_connections") or 0) for s in servers)
    total_up = sum(int((s.get("metrics") or {}).get("total_up") or 0) for s in servers)
    total_down = sum(int((s.get("metrics") or {}).get("total_down") or 0) for s in servers)
    active_alerts = sum(1 for a in db.get("server_alerts", []) if a.get("status") == "active")
    return {
        "total_servers": len(servers),
        "online": len(online),
        "offline": len(offline),
        "maintenance": len(maintenance),
        "avg_health": round(sum(healths) / len(healths), 1) if healths else None,
        "avg_load": round(sum(loads) / len(loads), 1) if loads else None,
        "avg_latency": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "total_users": total_users,
        "total_connections": total_conns,
        "total_upload": total_up,
        "total_download": total_down,
        "active_alerts": active_alerts,
    }


@app.get("/api/servers/top")
async def api_servers_top(user: str = Depends(require_perm("servers.read")),
                          sort_by: str = "health", limit: int = 10):
    """Top-performing servers ranked by health, load, latency, or uptime."""
    db = await store.get()
    servers = db.get("servers", [])
    cands = []
    for s in servers:
        if not s.get("enabled", True) or s.get("online") is not True:
            continue
        cands.append({
            "id": s["id"], "name": s.get("name", ""),
            "health": s.get("health"), "load": s.get("load"),
            "latency_ms": s.get("latency_ms"),
            "uptime_seconds": int((s.get("metrics") or {}).get("uptime_seconds") or 0),
            "users": int((s.get("metrics") or {}).get("users") or 0),
            "country": s.get("country", ""), "city": s.get("city", ""),
        })
    reverse = True
    key_map = {
        "health": lambda x: x.get("health") or 0,
        "load": lambda x: -(x.get("load") or 0),
        "latency": lambda x: -(x.get("latency_ms") or 9999),
        "uptime": lambda x: x.get("uptime_seconds") or 0,
    }
    sort_key = key_map.get(sort_by, key_map["health"])
    cands.sort(key=sort_key, reverse=reverse)
    try:
        limit = max(1, min(50, int(limit)))
    except Exception:
        limit = 10
    return {"servers": cands[:limit], "sort_by": sort_by}


@app.post("/api/agent/heartbeat")
async def api_agent_heartbeat(request: Request):
    """Remote agent self-report endpoint. Authenticated via agent_secret header.

    The agent POSTs its local metrics; the panel stores them just like a poll.
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing-token")
    token = auth.split(None, 1)[1].strip()
    db = await store.get()
    agent_secret = (db.get("settings") or {}).get("agent_auth_secret") or ""
    if agent_secret and not secrets.compare_digest(token, agent_secret):
        raise HTTPException(401, "invalid-token")
    payload = await request.json()
    server_id = (payload.get("server_id") or "").strip()
    if not server_id:
        raise HTTPException(400, "server_id-required")
    srv = server_by_id(db, server_id)
    if not srv:
        raise HTTPException(404, "server-not-found")
    if not srv.get("enabled", True):
        raise HTTPException(403, "server-disabled")
    metrics = {
        "cpu": payload.get("cpu"), "mem": payload.get("mem"),
        "disk_percent": payload.get("disk_percent"),
        "net_up_bps": payload.get("net_up_bps"),
        "net_down_bps": payload.get("net_down_bps"),
        "active_connections": payload.get("active_connections", 0),
        "uptime_seconds": payload.get("uptime_seconds", 0),
        "version": payload.get("version", ""),
        "xray": payload.get("xray_status", "unknown"),
        "error_rate": payload.get("error_rate", 0),
        "packet_loss": payload.get("packet_loss"),
    }
    now = time.time()
    health = core_servers.health_score(metrics, True)
    load = core_servers.load_pct(metrics)
    compat = core_servers.version_compat(APP_VERSION, metrics.get("version") or "")

    def _a(db):
        s = server_by_id(db, server_id)
        if not s:
            return
        s["metrics"] = metrics
        s["health"] = health
        s["load"] = load
        s["version_compat"] = compat
        s["last_check"] = now
        s["last_seen"] = now
        s["last_success"] = now
        s["online"] = True
        s["fail_count"] = 0
        s["error_rate"] = metrics.get("error_rate", 0)
        s["packet_loss"] = metrics.get("packet_loss")
        s["agent_version"] = payload.get("agent_version", "")
        _record_history(db, server_id, metrics, health, now)
        _prune_history(db)
    await store.mutate(_a)
    await _evaluate_server_alerts(server_id)
    was_online = srv.get("online")
    if was_online is False:
        await record_server_event(server_id, "server_online", f"{srv.get('name', server_id)} recovered via agent", "info")
        await log_audit("system", "server_online", srv.get("name", server_id), ref=server_id)
        await push_notification("info", "server_online",
                                {"name": srv.get("name", server_id), "key": server_id})
    return {"ok": True, "health": health, "load": load}


@app.post("/api/servers/{sid}/toggle-maintenance")
async def api_server_toggle_maintenance(sid: str, user: str = Depends(require_perm("servers.manage"))):
    """Toggle maintenance mode on/off for a server."""
    out = {}

    def _a(db):
        srv = server_by_id(db, sid)
        if not srv:
            raise HTTPException(404, "not-found")
        srv["maintenance"] = not srv.get("maintenance", False)
        out["maintenance"] = srv["maintenance"]
    await store.mutate(_a)
    mode = "enabled" if out["maintenance"] else "disabled"
    await record_server_event(sid, f"maintenance_{mode}", f"Maintenance {mode}", "warning")
    await log_audit(user, f"maintenance_{mode}", sid, ref=sid)
    return {"ok": True, **out}


@app.get("/api/servers/{sid}/users")
async def api_server_users(sid: str, user: str = Depends(require_perm("servers.manage"))):
    """Live user list of a remote server via its real API (owner token)."""
    db = await store.get()
    if sid == "local":
        return {"id": "local", "users": [serialize_inbound(ib) for ib in db["inbounds"]]}
    srv = server_by_id(db, sid)
    if not srv:
        raise HTTPException(404, "not-found")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(srv["host"] + "/api/inbounds",
                            headers={"Authorization": f"Bearer {srv.get('token') or ''}"})
            r.raise_for_status()
            return {"id": sid, "users": r.json().get("inbounds", [])}
    except Exception as e:
        raise HTTPException(502, f"remote-unreachable: {str(e)[:120]}")


# ------------------------- Phase 3: assignment + failover -------------------------
def _build_local_inbound(db, name: str, quota_gb: float, expire_days: int,
                         max_connections: int, fp, note: str, plan_id=None):
    """Build a local inbound dict (plan applied). None if plan missing."""
    ib = {
        "uid": gen_uid(), "uuid": gen_uuid(), "name": (name or "User").strip()[:64] or "User",
        "enabled": True, "created_at": time.time(), "expire_days": expire_days,
        "expire_at": (time.time() + expire_days * 86400) if expire_days > 0 else None,
        "quota_gb": quota_gb, "max_connections": max_connections,
        "max_requests": 0, "request_count": 0, "used_up": 0, "used_down": 0,
        "fp": fp or (db.get("settings") or {}).get("default_fingerprint", "chrome"),
        "strict_single_ip": False, "note": (note or "")[:200],
        "sub_token": secrets.token_hex(12), "sub_enabled": True,
        "plan_id": None, "plan_name": "", "server_id": "local",
    }
    if plan_id:
        plan = plan_by_id(db, plan_id)
        if not plan:
            return None
        apply_plan_to_inbound(ib, plan)
    return ib


async def _create_remote_inbound(srv: dict, body: dict):
    async with httpx.AsyncClient(timeout=12) as c:
        r = await c.post(srv["host"] + "/api/inbounds", json=body,
                         headers={"Authorization": f"Bearer {srv.get('token') or ''}"})
        r.raise_for_status()
        return r.json().get("inbound", {})


def _assignment_target_check(db, sid: str):
    """Pre-assignment health/load/availability check (real data)."""
    if sid == "local":
        return {"ok": True, "server_id": "local", "reason": "local-always-available"}
    srv = server_by_id(db, sid)
    if not srv:
        return {"ok": False, "reason": "not-found"}
    if not srv.get("enabled", True):
        return {"ok": False, "reason": "disabled"}
    if srv.get("online") is not True:
        return {"ok": False, "reason": "offline"}
    if srv.get("maintenance"):
        return {"ok": False, "reason": "maintenance"}
    health = srv.get("health")
    if health is not None and health < 20:
        return {"ok": False, "reason": f"unhealthy:{health}"}
    return {"ok": True, "server_id": sid, "health": health, "load": srv.get("load")}


@app.post("/api/assign")
async def api_assign(request: Request, user: str = Depends(require_perm("users.create"))):
    """Create a user on the chosen server after real pre-checks.

    Local: normal inbound (server_id=local). Remote: created through the
    remote panel API; a local assignment record tracks it (no user-data
    duplication — live data is always read from the owning server).
    """
    p = await request.json()
    db = await store.get()
    sid = (p.get("server_id") or "local").strip()
    name = (p.get("name") or "User").strip()[:64]
    check = _assignment_target_check(db, sid)
    if not check["ok"]:
        raise HTTPException(409, f"target-rejected:{check['reason']}")
    quota_gb = float(p.get("quota_gb") or 0)
    expire_days = int(p.get("expire_days") or 0)
    plan_id = (p.get("plan_id") or "").strip() or None
    if plan_id and not plan_by_id(db, plan_id):
        raise HTTPException(404, "plan-not-found")

    if sid == "local":
        ib = _build_local_inbound(db, name, quota_gb, expire_days,
                                  int(p.get("max_connections") or 0),
                                  p.get("fp"), (p.get("note") or "")[:200], plan_id)
        if ib is None:
            raise HTTPException(404, "plan-not-found")

        def _a(db):
            db["inbounds"].append(ib)
        db = await store.mutate(_a)
        refresh_xray(db)
        await log_audit(user, "assign_create", f"local:{name}")
        return {"ok": True, "server_id": "local", "check": check,
                "inbound": serialize_inbound(ib)}

    srv = server_by_id((await store.get()), sid)
    body = {"name": name, "quota_gb": quota_gb, "expire_days": expire_days,
            "max_connections": int(p.get("max_connections") or 0),
            "note": (p.get("note") or "")[:200]}
    if plan_id:
        # translate plan to raw values the remote understands
        plan = plan_by_id(await store.get(), plan_id)
        body.update({"quota_gb": float(plan.get("traffic_gb") or 0),
                     "expire_days": int(plan.get("duration_days") or 0),
                     "max_connections": int(plan.get("device_limit") or 0)})
    try:
        created = await _create_remote_inbound(srv, body)
    except Exception as e:
        raise HTTPException(502, f"remote-create-failed: {str(e)[:150]}")
    rec = {"id": "asg_" + gen_uid(), "server_id": sid, "remote_uid": created.get("uid"),
           "name": name, "plan_id": plan_id, "quota_gb": created.get("quota_gb", quota_gb),
           "created_at": time.time(), "created_by": user, "status": "active"}

    def _b(db):
        db.setdefault("assignments", []).append(rec)
    await store.mutate(_b)
    await log_audit(user, "assign_create", f"{sid}:{name}", ref=sid)
    return {"ok": True, "server_id": sid, "check": check, "assignment": rec}


@app.get("/api/assignments")
async def api_assignments_list(user: str = Depends(require_perm("users.read"))):
    db = await store.get()
    out = list(db.get("assignments", []))
    out.reverse()
    return {"assignments": out[:300]}


@app.post("/api/servers/{sid}/failover")
async def api_failover(sid: str, request: Request, user: str = Depends(require_perm("users.create"))):
    """Suggest (and, only with explicit confirm, execute) a replacement server.

    Step 1 (no confirm): ranked alternatives for an assignment.
    Step 2 (confirm + target): creates the replacement. The failed source is
    NEVER touched automatically — no disruptive auto-migration.
    """
    try:
        p = await request.json()
    except Exception:
        p = {}
    db = await store.get()
    aid = (p.get("assignment_id") or "").strip()
    asg = next((a for a in db.get("assignments", []) if a.get("id") == aid), None)
    if not aid or not asg:
        raise HTTPException(404, "assignment-not-found")
    best = await api_servers_best(request)
    alts = [c for c in best["candidates"] if c["id"] != sid][:3]
    if not p.get("confirm"):
        return {"ok": True, "confirmed": False, "alternatives": alts,
                "note": "re-run with confirm:true and target to execute"}
    target = (p.get("target") or "").strip()
    if not target or not any(c["id"] == target for c in alts):
        raise HTTPException(400, "invalid-target")
    check = _assignment_target_check(await store.get(), target)
    if not check["ok"]:
        raise HTTPException(409, f"target-rejected:{check['reason']}")
    # execute: clone the assignment spec onto the target (source untouched)
    fresh = await store.get()
    tsrv = None if target == "local" else server_by_id(fresh, target)
    if target == "local":
        ib = _build_local_inbound(fresh, (asg.get("name") or "User") + " (failover)",
                                  asg.get("quota_gb") or 0, 0, 0, None, "",
                                  asg.get("plan_id"))

        def _d(db):
            db["inbounds"].append(ib)
            for a in db.get("assignments", []):
                if a.get("id") == aid:
                    a["status"] = "failed-over"
        db2 = await store.mutate(_d)
        refresh_xray(db2)
        result = {"ok": True, "server_id": "local", "inbound": serialize_inbound(ib)}
    else:
        body = {"name": (asg.get("name") or "User") + " (failover)",
                "quota_gb": asg.get("quota_gb") or 0, "expire_days": 0,
                "max_connections": 0, "note": "failover"}
        try:
            created = await _create_remote_inbound(tsrv, body)
        except Exception as e:
            raise HTTPException(502, f"remote-create-failed: {str(e)[:150]}")
        rec = {"id": "asg_" + gen_uid(), "server_id": target,
               "remote_uid": created.get("uid"), "name": body["name"],
               "plan_id": asg.get("plan_id"), "quota_gb": created.get("quota_gb", 0),
               "created_at": time.time(), "created_by": user, "status": "active"}

        def _e(db):
            db.setdefault("assignments", []).append(rec)
            for a in db.get("assignments", []):
                if a.get("id") == aid:
                    a["status"] = "failed-over"
        await store.mutate(_e)
        result = {"ok": True, "server_id": target, "assignment": rec}
    await log_audit(user, "failover", f"{sid}->{target}:{aid}", ref=sid)
    return {"ok": True, "confirmed": True, "target": target, "result": result}


# ------------------------------------------------------------------ subscriptions
# Every route accepts a uid (legacy) or sub_token (canonical /s/ links).
def _load_sub_or_404(db, ref: str):
    ib = resolve_sub(db, ref)
    if not ib:
        raise HTTPException(404, "not-found")
    require_active_sub(ib)
    return ib


@app.get("/sub/{uid}")
async def sub_plain(uid: str, request: Request):
    return await _serve_sub_plain(uid, request)


@app.get("/s/{ref}")
async def sub_short(ref: str, request: Request):
    """Canonical rotatable subscription URL (see links API)."""
    return await _serve_sub_plain(ref, request)


async def _serve_sub_plain(ref: str, request: Request):
    db = await store.get()
    ib = _load_sub_or_404(db, ref)
    st = inbound_status(ib)
    links = build_links(request, db, ib)
    
    combined = (
        [c["link"] for c in links["info_configs"]]
        + links["all_links"]
    )
    raw = "\n".join(combined)
    b64 = base64.b64encode(raw.encode()).decode()
    
    used_up = int(ib.get("used_up") or 0)
    used_down = int(ib.get("used_down") or 0)
    total_bytes = int(st["quota_bytes"])
    expire_ts = int(ib.get("expire_at") or 0)
    user_info_header = f"upload={used_up}; download={used_down}; total={total_bytes}; expire={expire_ts}"

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Subscription-Userinfo": user_info_header,
        "subscription-userinfo": user_info_header,
        "Profile-Update-Interval": "1",
        "profile-update-interval": "1",
        # تغییر زیر اعمال شده است:
        "Profile-Title": "base64:2YHZhNi02YUgU3Rhbk5HINeo2YXYs9in2YUg2YHZg9in2YUg2YHZhiDYsdmF2KfbjCDZiNiv2YbYqg==",
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Powered-By": "SsPanel",
    }
    return Response(content=b64, media_type="text/plain", headers=headers)


@app.get("/sub/{uid}/json")
async def sub_json(uid: str, request: Request):
    return await _serve_sub_json(uid, request)


@app.get("/s/{ref}/json")
async def sub_short_json(ref: str, request: Request):
    return await _serve_sub_json(ref, request)


async def _serve_sub_json(ref: str, request: Request):
    db = await store.get()
    ib = _load_sub_or_404(db, ref)
    st = inbound_status(ib)
    links = build_links(request, db, ib)
    used_up = int(ib.get("used_up") or 0)
    used_down = int(ib.get("used_down") or 0)
    total_bytes = int(st["quota_bytes"])
    expire_ts = int(ib.get("expire_at") or 0)
    user_info_header = f"upload={used_up}; download={used_down}; total={total_bytes}; expire={expire_ts}"
    headers = {
        "Subscription-Userinfo": user_info_header,
        "subscription-userinfo": user_info_header,
        "Profile-Update-Interval": "1",
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Powered-By": "SsPanel",
    }
    return JSONResponse({
        "name": ib["name"],
        "uid": ib["uid"],
        "enabled": st["live_enabled"],
        "quota_gb": ib.get("quota_gb"),
        "used_gb": round(st["used"] / (1024 ** 3), 3),
        "used_bytes": st["used"],
        "quota_bytes": st["quota_bytes"],
        "days_left": st["days_left"],
        "expire_at": ib.get("expire_at"),
        "max_connections": ib.get("max_connections"),
        "active_connections": st["active_connections"],
        "links": {
            "tls": links["tls"],
            "all_links": links["all_links"],
            "info_configs": links["info_configs"],
        },
    }, headers=headers)


@app.get("/api/inbounds/{uid}/sub")
async def api_inbound_sub_alias(uid: str, request: Request, user: str = Depends(require_perm("users.read"))):
    return await sub_json(uid, request)


@app.get("/sub/{uid}/clash")
async def sub_clash(uid: str, request: Request):
    """Clash-Meta YAML subscription."""
    db = await store.get()
    ib = _load_sub_or_404(db, uid)
    host = public_host(request, db)
    sni = (db.get("settings") or {}).get("sni_override") or host
    fp = ib.get("fp") or (db.get("settings") or {}).get("default_fingerprint", "chrome")
    name = f"{ib['name']}-VL-WS-TLS"
    yaml_text = (
        "mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info\n"
        "external-controller: 127.0.0.1:9090\n"
        "proxies:\n"
        f"  - name: \"{name}\"\n    type: vless\n"
        f"    server: {host}\n    port: 443\n"
        f"    uuid: {ib['uuid']}\n    encryption: none\n"
        "    udp: true\n    tls: true\n"
        f"    servername: {sni}\n    fingerprint: {fp}\n"
        "    network: ws\n"
        f"    ws-opts:\n      path: /vl-ws\n      headers:\n        Host: {host}\n"
        "proxy-groups:\n  - name: PROXY\n    type: select\n"
        f"    proxies: [\"{name}\", DIRECT]\n"
        "rules:\n  - MATCH,PROXY\n"
    )
    return Response(content=yaml_text, media_type="text/yaml",
                    headers={"Content-Disposition": f"attachment; filename={uid}.yaml"})


@app.get("/sub/{uid}/singbox")
async def sub_singbox(uid: str, request: Request):
    """Sing-Box JSON subscription."""
    db = await store.get()
    ib = _load_sub_or_404(db, uid)
    host = public_host(request, db)
    sni = (db.get("settings") or {}).get("sni_override") or host
    cfg = {
        "log": {"level": "info"},
        "dns": {"servers": [{"tag": "remote", "address": "https://1.1.1.1/dns-query"}]},
        "outbounds": [{
            "type": "vless", "tag": f"{ib['name']}-VL-WS-TLS",
            "server": host, "server_port": 443, "uuid": ib["uuid"],
            "tls": {"enabled": True, "server_name": sni,
                    "utls": {"enabled": True,
                             "fingerprint": ib.get("fp") or "chrome"}},
            "transport": {"type": "ws", "path": "/vl-ws",
                          "headers": {"Host": host}},
        }, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "final": ib["name"] + "-VL-WS-TLS"},
    }
    return JSONResponse(cfg, headers={"Content-Disposition": f"attachment; filename={uid}.json"})


# ------------------------------------------------------------------ public status api
@app.get("/api/status/{uid}")
async def api_public_status(uid: str):
    db = await store.get()
    ib = inbound_by_uid(db, uid)
    if not ib:
        raise HTTPException(404, "not-found")
    st = inbound_status(ib)
    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    }
    return JSONResponse({
        "name": ib["name"],
        "enabled": st["live_enabled"],
        "quota_gb": ib.get("quota_gb"),
        "used_gb": round(st["used"] / (1024 ** 3), 4),
        "used_bytes": st["used"],
        "quota_bytes": st["quota_bytes"],
        "days_left": st["days_left"],
        "expire_at": ib.get("expire_at"),
        "max_connections": ib.get("max_connections"),
        "active_connections": st["active_connections"],
        "max_requests": ib.get("max_requests"),
        "request_count": ib.get("request_count"),
    }, headers=headers)


# ------------------------------------------------------------------ system / stats
@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time()}


@app.get("/stats")
async def stats(request: Request, user: str = Depends(require_perm("analytics.read"))):
    global last_seen
    db = await store.get()
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    started = db["stats"].get("started_at", time.time())
    uptime = time.time() - started

    colo = "?"
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get("https://www.cloudflare.com/cdn-cgi/trace")
            for line in r.text.splitlines():
                if line.startswith("colo="):
                    colo = line.split("=", 1)[1]
    except Exception:
        pass

    # ========== روش جدید: شمارش کاربرانی که در ۳۰ ثانیه اخیر ترافیک داشتند ==========
    def get_active_connections():
        now = time.time()
        active = sum(1 for ts in last_seen.values() if now - ts < 30)
        return active

    total_active = get_active_connections()
    # ==============================================================

    raw_hourly = {item["t"]: item for item in db["stats"].get("hourly", []) if "t" in item}
    now_bucket = int(time.time() // 3600) * 3600
    hourly_series = []
    for i in range(23, -1, -1):
        bucket_t = now_bucket - (i * 3600)
        if bucket_t in raw_hourly:
            hourly_series.append({
                "t": bucket_t,
                "up": raw_hourly[bucket_t].get("up", 0),
                "down": raw_hourly[bucket_t].get("down", 0)
            })
        else:
            hourly_series.append({"t": bucket_t, "up": 0, "down": 0})

    return {
        "cpu_percent": cpu,
        "mem_percent": mem.percent,
        "mem_used_mb": round(mem.used / 1024 / 1024, 1),
        "mem_total_mb": round(mem.total / 1024 / 1024, 1),
        "uptime_seconds": uptime,
        "total_up": db["stats"].get("total_up", 0),
        "total_down": db["stats"].get("total_down", 0),
        "hourly": hourly_series,
        "inbounds_count": len(db["inbounds"]),
        "active_connections": total_active,
        "location": describe_colo(colo),
        # ---- Phase 1 (ALOO ULTIMATE): buckets, services, alerts, activity ----
        "users_by_status": core_users.summarize(
            db["inbounds"],
            warn_days=int((db.get("settings") or {}).get("expiry_warn_days") or 3)),
        "services": {
            "xray": xray_service_status(),
            "database": {
                "status": "ok",
                "users": len(db.get("inbounds", [])),
                "audit_entries": len(db.get("audit_log", [])),
                "tokens": len(db.get("api_tokens", [])),
            },
            "telegram": {
                "enabled": bool((db.get("settings") or {}).get("telegram_enabled")),
                "configured": bool((db.get("settings") or {}).get("telegram_bot_token")
                                    and (db.get("settings") or {}).get("telegram_chat_id")),
            },
        },
        "alerts": build_alerts(db, cpu, mem.percent),
        "recent_activity": list(reversed(db.get("audit_log", [])))[-8:][::-1][:8],
        "app": {"name": APP_NAME, "edition": APP_EDITION, "version": APP_VERSION},
    }


def xray_service_status() -> dict:
    """Truthful xray state: live process, mock mode (no binary), or down."""
    import xray_manager as _xm
    proc = getattr(_xm, "xray_process", None)
    binary = os.path.exists(getattr(_xm, "XRAY_BIN", "/usr/local/bin/xray"))
    if proc is not None and proc.poll() is None:
        return {"status": "online", "mode": "live"}
    if not binary:
        return {"status": "mock", "mode": "mock"}
    return {"status": "offline", "mode": "live"}


def build_alerts(db, cpu_percent: float, mem_percent: float) -> list:
    """Computed from real data. Codes are resolved to text by the frontend."""
    alerts = []
    try:
        buckets = core_users.summarize(
            db["inbounds"],
            warn_days=int((db.get("settings") or {}).get("expiry_warn_days") or 3))
    except Exception:
        buckets = {}
    if buckets.get("expired"):
        alerts.append({"severity": "error", "code": "users_expired", "count": buckets["expired"]})
    if buckets.get("quota_reached"):
        alerts.append({"severity": "error", "code": "users_quota", "count": buckets["quota_reached"]})
    if buckets.get("near_expiry"):
        alerts.append({"severity": "warning", "code": "users_near_expiry", "count": buckets["near_expiry"]})
    try:
        if float(cpu_percent) >= 85:
            alerts.append({"severity": "warning", "code": "high_cpu", "count": round(float(cpu_percent), 1)})
    except Exception:
        pass
    try:
        if float(mem_percent) >= 90:
            alerts.append({"severity": "warning", "code": "high_mem", "count": round(float(mem_percent), 1)})
    except Exception:
        pass
    if xray_service_status()["status"] == "offline":
        alerts.append({"severity": "error", "code": "xray_offline", "count": 1})
    return alerts


@app.get("/api/plugins")
async def api_plugins(user: str = Depends(require_auth)):
    """List installed extensions (truthful scan of plugins/)."""
    return {"plugins": plugin_registry.list_plugins()}


@app.get("/api/plugins/widgets")
async def api_plugins_widgets(user: str = Depends(require_auth)):
    """Live cards contributed by enabled plugin widgets."""
    db = await store.get()
    return {"cards": plugin_registry.load_widgets(db)}


@app.post("/api/plugins/{pid}/toggle")
async def api_plugins_toggle(pid: str, request: Request, user: str = Depends(require_perm("settings.manage"))):
    try:
        p = await request.json()
    except Exception:
        p = {}
    try:
        m = plugin_registry.set_enabled(pid, bool(p.get("enabled", True)))
    except FileNotFoundError:
        raise HTTPException(404, "not-found")
    except (ValueError, OSError):
        raise HTTPException(400, "invalid-plugin")
    await log_audit(user, "plugin_toggle", f"{pid}:{bool(p.get('enabled', True))}")
    return {"ok": True, "enabled": bool(m.get("enabled", True))}


def _ver_tuple(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


async def _resolve_latest_release(repo: str, current: str, client: httpx.AsyncClient):
    latest, url, zip_url = current, f"https://github.com/{repo}/releases", None
    try:
        r = await client.get(f"https://api.github.com/repos/{repo}/releases/latest", headers=OTA_HEADERS)
        if r.status_code == 200:
            data = r.json()
            tag = (data.get("tag_name") or "").lstrip("v")
            if tag:
                latest = tag
                url = data.get("html_url", url)
                zip_url = data.get("zipball_url") or f"https://api.github.com/repos/{repo}/zipball/{data.get('tag_name')}"
        else:
            r2 = await client.get(f"https://api.github.com/repos/{repo}/tags", headers=OTA_HEADERS)
            if r2.status_code == 200 and r2.json():
                tags = r2.json()
                if tags:
                    tag_info = tags[0]
                    tag_name = tag_info.get("name") or current
                    latest = tag_name.lstrip("v")
                    url = f"https://github.com/{repo}/releases/tag/{tag_name}"
                    zip_url = tag_info.get("zipball_url") or f"https://api.github.com/repos/{repo}/zipball/{tag_name}"
    except Exception:
        pass
    return latest, url, zip_url


@app.get("/api/ota/check")
async def api_ota_check(user: str = Depends(require_auth)):
    current = APP_VERSION
    latest = current
    url = f"https://github.com/{OTA_REPO}/releases"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            latest, url, _zip = await _resolve_latest_release(OTA_REPO, current, client)
    except Exception:
        pass

    update_available = _ver_tuple(latest) > _ver_tuple(current)
    return {"current": current, "latest": latest, "update_available": update_available, "url": url}


# ------------------------------------------------------------------ OTA self-update
UPDATE_LOCK = asyncio.Lock()
NEVER_TOUCH = {"data"}


def _safe_extract_zip(zip_path: str, dest_dir: str):
    import zipfile
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        if not names:
            raise RuntimeError("empty archive")
        root_prefix = names[0].split("/")[0] + "/"
        for member in names:
            if not member.startswith(root_prefix):
                continue
            rel = member[len(root_prefix):]
            if not rel:
                continue
            target = os.path.normpath(os.path.join(dest_dir, rel))
            if not target.startswith(os.path.normpath(dest_dir) + os.sep) and target != os.path.normpath(dest_dir):
                raise RuntimeError(f"unsafe path in archive: {member}")
            if member.endswith("/"):
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())


def _apply_staged_update(staged_dir: str, live_dir: str) -> list:
    import shutil
    touched = []
    for entry in os.listdir(staged_dir):
        if entry in NEVER_TOUCH:
            continue
        src = os.path.join(staged_dir, entry)
        dst = os.path.join(live_dir, entry)
        if os.path.isdir(src):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        touched.append(entry)
    return touched


@app.post("/api/ota/update")
async def api_ota_update(request: Request, user: str = Depends(require_auth)):
    if UPDATE_LOCK.locked():
        raise HTTPException(409, "update-already-in-progress")

    async with UPDATE_LOCK:
        import tempfile
        import shutil as _shutil

        current = APP_VERSION
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                latest, html_url, zip_url = await _resolve_latest_release(OTA_REPO, current, client)
                if _ver_tuple(latest) <= _ver_tuple(current):
                    return {"ok": False, "reason": "already-up-to-date", "current": current, "latest": latest}
                if not zip_url:
                    zip_url = f"https://api.github.com/repos/{OTA_REPO}/zipball/{latest}"

                tmp_root = tempfile.mkdtemp(prefix="stanng_ota_")
                zip_path = os.path.join(tmp_root, "release.zip")
                staged_dir = os.path.join(tmp_root, "staged")
                os.makedirs(staged_dir, exist_ok=True)

                async with client.stream("GET", zip_url, headers=OTA_HEADERS) as resp:
                    if resp.status_code != 200:
                        raise HTTPException(502, f"download-failed-{resp.status_code}")
                    with open(zip_path, "wb") as f:
                        async for chunk in resp.aiter_bytes():
                            f.write(chunk)

            _safe_extract_zip(zip_path, staged_dir)

            if not os.path.exists(os.path.join(staged_dir, "main.py")):
                _shutil.rmtree(tmp_root, ignore_errors=True)
                raise HTTPException(502, "downloaded-archive-missing-main.py")

            staged_data = os.path.join(staged_dir, "data")
            if os.path.isdir(staged_data):
                _shutil.rmtree(staged_data, ignore_errors=True)

            touched = _apply_staged_update(staged_dir, BASE_DIR)
            if not touched:
                _shutil.rmtree(tmp_root, ignore_errors=True)
                raise HTTPException(502, "update-failed-no-files-copied")
            _shutil.rmtree(tmp_root, ignore_errors=True)

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"update-failed: {e}")

        async def _delayed_restart():
            await asyncio.sleep(1.5)
            os._exit(87)

        asyncio.create_task(_delayed_restart())
        return {
            "ok": True,
            "previous_version": current,
            "new_version": latest,
            "files_updated": touched,
            "restarting": True,
        }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PANEL_PORT") or os.environ.get("PORT") or 10000)
    uvicorn.run("main:app", host="127.0.0.1", port=port, log_level="info")
