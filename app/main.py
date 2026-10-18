"""Простое приложение с авторизацией. Цель — быть удобным объектом для эксплуатации:
health/ready пробы, метрики, JSON-логи, graceful shutdown, 12-factor конфиг из env."""
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "60"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true") == "true"
VERSION = os.getenv("APP_VERSION", "dev")


# ---------- логи в JSON (чтобы Loki/Grafana могли фильтровать по полям) ----------
class JsonFormatter(logging.Formatter):
    def format(self, r):
        d = {"ts": self.formatTime(r), "level": r.levelname, "msg": r.getMessage(), "version": VERSION}
        d.update(getattr(r, "extra", {}))
        return json.dumps(d, ensure_ascii=False)


h = logging.StreamHandler(sys.stdout)
h.setFormatter(JsonFormatter())
log = logging.getLogger("app")
log.addHandler(h)
log.setLevel(logging.INFO)

# ---------- метрики: RED (rate/errors/duration) + бизнес-метрика логинов ----------
REQS = Counter("http_requests_total", "HTTP requests", ["method", "path", "status"])
LAT = Histogram("http_request_duration_seconds", "Latency", ["method", "path"],
                buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5))
LOGINS = Counter("auth_logins_total", "Login attempts", ["result"])  # ok | bad_credentials
REGS = Counter("auth_registrations_total", "Registrations", ["result"])

ph = PasswordHasher()
pool: ConnectionPool | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global pool
    pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=int(os.getenv("DB_POOL_MAX", "5")),
                          timeout=5, open=True)
    # Для простоты схема создаётся тут. В реальности — миграции (Alembic) отдельным Job/ArgoCD PreSync hook.
    with pool.connection() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())""")
    log.info("started")
    yield
    log.info("shutting down")
    pool.close()


app = FastAPI(lifespan=lifespan, title="auth-app")


@app.middleware("http")
async def metrics_mw(request: Request, call_next):
    t = time.perf_counter()
    status = 500
    try:
        resp = await call_next(request)
        status = resp.status_code
        return resp
    finally:
        # route template, а не сырой путь — иначе взрыв кардинальности меток
        route = request.scope.get("route")
        path = route.path if route else "unmatched"
        if path not in ("/metrics", "/healthz", "/readyz"):
            REQS.labels(request.method, path, str(status)).inc()
            LAT.labels(request.method, path).observe(time.perf_counter() - t)
            log.info("request", extra={"extra": {"method": request.method, "path": path,
                                                 "status": status, "ms": round((time.perf_counter() - t) * 1000, 1)}})


class Creds(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=8, max_length=128)


def current_user(request: Request) -> str:
    tok = request.cookies.get("session")
    if not tok:
        raise HTTPException(401, "not authenticated")
    try:
        return jwt.decode(tok, JWT_SECRET, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid session")


# ---------- probes ----------
@app.get("/healthz")  # liveness: процесс жив. НЕ ходит в БД (иначе падение БД = рестарт всех подов)
def healthz():
    return {"status": "ok"}


@app.get("/readyz")  # readiness: можем ли обслуживать трафик (БД доступна)
def readyz():
    try:
        with pool.connection(timeout=2) as c:
            c.execute("SELECT 1")
    except Exception:
        raise HTTPException(503, "db unavailable")
    return {"status": "ready", "version": VERSION}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ---------- auth API ----------
@app.post("/api/register", status_code=201)
def register(c: Creds):
    try:
        with pool.connection() as conn:
            conn.execute("INSERT INTO users(email,pw_hash) VALUES (%s,%s)",
                         (c.email.lower(), ph.hash(c.password)))
    except UniqueViolation:
        REGS.labels("duplicate").inc()
        raise HTTPException(409, "email already registered")
    REGS.labels("ok").inc()
    return {"status": "created"}


@app.post("/api/login")
def login(c: Creds, response: Response):
    with pool.connection() as conn:
        row = conn.execute("SELECT pw_hash FROM users WHERE email=%s", (c.email.lower(),)).fetchone()
    try:
        if not row:
            ph.hash("dummy")  # выравниваем время ответа, чтобы не светить существование email
            raise VerifyMismatchError()
        ph.verify(row[0], c.password)
    except VerifyMismatchError:
        LOGINS.labels("bad_credentials").inc()
        raise HTTPException(401, "bad credentials")
    LOGINS.labels("ok").inc()
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_TTL_MIN)
    token = jwt.encode({"sub": c.email.lower(), "exp": exp}, JWT_SECRET, algorithm="HS256")
    response.set_cookie("session", token, httponly=True, secure=COOKIE_SECURE,
                        samesite="strict", max_age=JWT_TTL_MIN * 60)
    return {"status": "ok"}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie("session")
    return {"status": "bye"}


@app.get("/api/me")
def me(user: str = Depends(current_user)):
    return {"email": user, "served_by": os.getenv("HOSTNAME", "?"), "version": VERSION}


PAGE = """<!doctype html><meta charset=utf-8><title>auth-app</title>
<style>body{font:16px system-ui;max-width:420px;margin:4rem auto;padding:0 1rem}
input,button{display:block;width:100%;margin:.4rem 0;padding:.6rem;box-sizing:border-box}pre{background:#eee;padding:.6rem}</style>
<h2>auth-app</h2>
<input id=e placeholder=email><input id=p type=password placeholder="password (8+)">
<button onclick="go('register')">Register</button><button onclick="go('login')">Login</button>
<button onclick="me()">Who am I?</button><button onclick="go('logout')">Logout</button><pre id=o></pre>
<script>
const o=document.getElementById('o');
async function go(a){const r=await fetch('/api/'+a,{method:'POST',headers:{'content-type':'application/json'},
 body:JSON.stringify({email:e.value,password:p.value})});o.textContent=r.status+' '+await r.text()}
async function me(){const r=await fetch('/api/me');o.textContent=r.status+' '+await r.text()}
</script>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE
