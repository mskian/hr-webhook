import json
import logging
import os
import re
import secrets
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import asyncio
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

import redis.asyncio as aioredis

APP_TITLE = "Live Heart Rate"
APP_VERSION = "2.0.0"
SOURCE_NAME = "HR PUSH"

WEBHOOK_TOKEN = os.getenv("HR_WEBHOOK_TOKEN", "").strip()

# --- Redis (shared state) ---------------------------------------------------
# On Vercel, a WebSocket connection is pinned to a single Function instance
# for its lifetime, and different requests (the webhook POST vs an open /ws
# connection) are NOT guaranteed to land on the same instance. An in-process
# Python object (deque/set/dict) is therefore invisible across instances,
# which is why the UI used to go stale even while pings kept working.
# Redis is the shared store every instance can read/write, per Vercel's own
# guidance ("For durable state across WebSocket connections, we recommend
# using Redis from the Vercel Marketplace").
REDIS_URL = os.getenv("REDIS_URL", "").strip()
REDIS_LATEST_KEY = "hr:latest"
REDIS_HISTORY_KEY = "hr:history"
REDIS_CHANNEL = "hr:updates"

redis_client: Optional["aioredis.Redis"] = None

MIN_HEART_RATE = 25
MAX_HEART_RATE = 250
MAX_HISTORY = 120
STALE_AFTER_SECONDS = 15
HEARTBEAT_INTERVAL_SECONDS = 25
WS_RECEIVE_TIMEOUT_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3
WS_SEND_TIMEOUT_SECONDS = 5
LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

IST = timezone(timedelta(hours=5, minutes=30))

HR_FIELD_CANDIDATES: Tuple[str, ...] = (
    "heart_rate",
    "heartRate",
    "bpm",
    "hr",
    "value",
    "heartRateValue",
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "accelerometer=(), gyroscope=(), magnetometer=()"
    ),
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

SECURE_CONTEXT_HEADERS = {
    "Cross-Origin-Opener-Policy": "same-origin",
}
HTTPS_ONLY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def _request_scheme(scope: Scope, headers: Dict[bytes, bytes]) -> str:
    forwarded_proto = headers.get(b"x-forwarded-proto", b"").decode().split(",")[0].strip().lower()
    if forwarded_proto:
        return forwarded_proto
    return str(scope.get("scheme", "http")).lower()


def _request_host(scope: Scope, headers: Dict[bytes, bytes]) -> str:
    host_header = headers.get(b"host", b"").decode()
    if host_header:
        return host_header.rsplit(":", 1)[0]
    server = scope.get("server")
    return server[0] if server else ""


def _is_secure_context(scope: Scope, headers: Dict[bytes, bytes]) -> bool:
    scheme = _request_scheme(scope, headers)
    if scheme == "https":
        return True
    return _request_host(scope, headers) in LOCALHOST_HOSTS


IP_PATTERN = re.compile(
    r"""
    (?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?
    |
    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
    |
    [0-9a-fA-F:]*::[0-9a-fA-F:]*
    """,
    re.VERBOSE,
)


class IPRedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = IP_PATTERN.sub("[ip-hidden]", record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: IP_PATTERN.sub("[ip-hidden]", value) if isinstance(value, str) else value
                    for key, value in record.args.items()
                }
            else:
                record.args = tuple(
                    IP_PATTERN.sub("[ip-hidden]", arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )
        return True


class HackerFormatter(logging.Formatter):
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    LEVEL_COLORS = {
        logging.DEBUG: "\x1b[38;5;244m",
        logging.INFO: "\x1b[38;5;82m",
        logging.WARNING: "\x1b[38;5;220m",
        logging.ERROR: "\x1b[38;5;203m",
        logging.CRITICAL: "\x1b[1;38;5;196m",
    }
    LEVEL_ICONS = {
        logging.DEBUG: "🔍",
        logging.INFO: "⚡",
        logging.WARNING: "⚠️ ",
        logging.ERROR: "💥",
        logging.CRITICAL: "☠️ ",
    }

    def __init__(self, use_color: bool) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, self.datefmt)
        icon = self.LEVEL_ICONS.get(record.levelno, "•")
        message = record.getMessage()

        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"

        if not self.use_color:
            return f"{timestamp} {icon} {record.levelname:<8} {record.name:<14} {message}"

        color = self.LEVEL_COLORS.get(record.levelno, "")
        return (
            f"{self.DIM}{timestamp}{self.RESET} {icon} "
            f"{color}{self.BOLD}{record.levelname:<8}{self.RESET} "
            f"{self.DIM}{record.name:<14}{self.RESET} "
            f"{color}{message}{self.RESET}"
        )


def configure_logging() -> logging.Logger:
    use_color = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    formatter = HackerFormatter(use_color=use_color)
    ip_filter = IPRedactingFilter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(ip_filter)

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "live-heart-rate"):
        target = logging.getLogger(logger_name)
        target.handlers.clear()
        target.addHandler(handler)
        target.addFilter(ip_filter)
        target.setLevel(logging.INFO)
        target.propagate = False

    return logging.getLogger("live-heart-rate")


logger = configure_logging()


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_headers = dict(scope.get("headers") or [])
        scheme = _request_scheme(scope, request_headers)
        secure_context = _is_secure_context(scope, request_headers)

        async def send_wrapper(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                if secure_context:
                    for name, value in SECURE_CONTEXT_HEADERS.items():
                        headers.setdefault(name, value)
                if scheme == "https":
                    for name, value in HTTPS_ONLY_HEADERS.items():
                        headers.setdefault(name, value)
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


@dataclass(frozen=True)
class Measurement:
    heart_rate: int
    timestamp: str
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(IST).isoformat(timespec="milliseconds")


# --- Redis-backed state helpers ---------------------------------------------

async def store_measurement(measurement: Measurement) -> None:
    """Persist the reading and fan it out to every instance's subscribers."""
    payload = json.dumps(measurement.to_dict(), separators=(",", ":"))
    async with redis_client.pipeline(transaction=True) as pipe:
        pipe.set(REDIS_LATEST_KEY, payload)
        pipe.lpush(REDIS_HISTORY_KEY, payload)
        pipe.ltrim(REDIS_HISTORY_KEY, 0, MAX_HISTORY - 1)
        await pipe.execute()
    message = json.dumps(
        {"type": "heart_rate", "data": measurement.to_dict()},
        separators=(",", ":"),
    )
    await redis_client.publish(REDIS_CHANNEL, message)


async def get_latest() -> Optional[Dict[str, Any]]:
    raw = await redis_client.get(REDIS_LATEST_KEY)
    return json.loads(raw) if raw else None


async def get_history() -> List[Dict[str, Any]]:
    # Stored newest-first via LPUSH; reverse for chronological order.
    items = await redis_client.lrange(REDIS_HISTORY_KEY, 0, MAX_HISTORY - 1)
    return [json.loads(item) for item in reversed(items)]


async def connected_client_count() -> int:
    # PUBSUB NUMSUB is answered by Redis itself, so it reflects subscribers
    # across every Vercel Function instance, not just this one.
    try:
        _, count = (await redis_client.pubsub_numsub(REDIS_CHANNEL))[0]
        return int(count)
    except Exception:
        return 0


def _startup_banner() -> str:
    auth_state = "🔐 ENABLED" if WEBHOOK_TOKEN else "🔓 DISABLED"
    redis_state = "🟢 CONFIGURED" if REDIS_URL else "🔴 MISSING (REDIS_URL not set)"
    lines = [
        f"💓  {APP_TITLE.upper()}  ·  v{APP_VERSION:<10}",
        "🌐  Web UI ........... /",
        "📡  HR Webhook ....... POST /webhook/hr",
        "🩺  Health ........... GET  /api/health",
        "❤️   Current HR ....... GET  /api/hr",
        "📈  History .......... GET  /api/history",
        "🔌  WebSocket ........ /ws",
        f"{auth_state:<52}",
        f"{redis_state:<52}",
    ]
    return "\n".join(lines)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    global redis_client

    if not REDIS_URL:
        raise RuntimeError(
            "REDIS_URL is not set. On Vercel this app needs a Redis instance "
            "(Vercel Marketplace → Redis, or Upstash) so the webhook and "
            "every WebSocket-holding Function instance share the same state. "
            "Add it in Project Settings → Environment Variables."
        )

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    await redis_client.ping()

    for line in _startup_banner().splitlines():
        logger.info(line)
    logger.info("🚀 Ready and listening for heartbeats...")
    try:
        yield
    finally:
        logger.info("🛑 Shutting down")
        await redis_client.aclose()


app = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None,  openapi_url=None,)
app.add_middleware(SecurityHeadersMiddleware)


def envelope(
    *,
    success: bool,
    message: str,
    http_status: int,
    data: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {
        "success": success,
        "message": message,
        "timestamp": now_iso(),
    }
    if data is not None:
        payload["data"] = data
    return JSONResponse(status_code=http_status, content=payload)


def extract_heart_rate(payload: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    for source in (payload, payload.get("data") if isinstance(payload.get("data"), dict) else None):
        if not source:
            continue
        for field in HR_FIELD_CANDIDATES:
            if field not in source:
                continue
            value = source[field]
            if isinstance(value, bool):
                return None, f"Field '{field}' must be numeric, not boolean"
            if isinstance(value, (int, float)):
                return float(value), None
            if isinstance(value, str):
                try:
                    return float(value.strip()), None
                except ValueError:
                    return None, f"Field '{field}' is not a valid number"
            return None, f"Field '{field}' has an unsupported type"
    return None, None


def normalize_heart_rate(value: float) -> Tuple[Optional[int], Optional[str]]:
    if value != value or value in (float("inf"), float("-inf")):
        return None, "Heart rate must be a finite number"
    if not MIN_HEART_RATE <= value <= MAX_HEART_RATE:
        return None, f"Heart rate must be between {MIN_HEART_RATE} and {MAX_HEART_RATE} BPM"
    return int(round(value)), None


def token_is_valid(request: Request) -> bool:
    if not WEBHOOK_TOKEN:
        return True
    supplied = request.headers.get("X-Webhook-Token", "")
    return compare_digest(supplied, WEBHOOK_TOKEN)


HTML_PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<script nonce="%%NONCE%%">
(function () {
  try {
    var saved = localStorage.getItem("hr-theme");
    var theme = saved === "dark" || saved === "light"
      ? saved
      : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.dataset.theme = theme;
  } catch (e) {
    document.documentElement.dataset.theme = "light";
  }
})();
</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#fafafa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0b0b0d" media="(prefers-color-scheme: dark)">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<title>Live Heart Rate</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,300..600,0..1,-25..200&display=swap">
<style nonce="%%NONCE%%">
:root {
  --bg: #fafafa;
  --surface: #ffffff;
  --border: #ececec;
  --text: #18181b;
  --muted: #8b8b93;
  --accent: #f43f5e;
  --accent-soft: #ffe4e8;
  --live: #10b981;
  --live-soft: #d7f9ec;
  --offline: #f43f5e;
  --offline-soft: #ffe4e8;
  --icon-btn-bg: #f4f4f5;
  --icon-btn-hover: #ececec;
  --radius: 26px;
  --shadow: 0 20px 60px rgba(24, 24, 27, 0.06);
  --ecg-line: #22e29a;
  --ecg-grid: rgba(34, 226, 154, 0.16);
  --ecg-grid-strong: rgba(34, 226, 154, 0.3);
}
[data-theme="dark"] {
  --bg: #0b0b0d;
  --surface: #131316;
  --border: #232327;
  --text: #f4f4f5;
  --muted: #97979f;
  --accent-soft: #3a1420;
  --live-soft: #0c2e22;
  --offline-soft: #3a1420;
  --icon-btn-bg: #1c1c20;
  --icon-btn-hover: #26262b;
  --shadow: 0 20px 60px rgba(0, 0, 0, 0.55);
}
* { box-sizing: border-box; }
html { color-scheme: light dark; }
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: max(24px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right)) max(24px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
  color: var(--text);
  background: var(--bg);
  font-family: "Geist Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  transition: background-color .25s ease, color .25s ease;
}
.material-symbols-rounded {
  font-variation-settings: "FILL" 0, "wght" 500, "GRAD" 0, "opsz" 24;
  font-size: 20px;
  line-height: 1;
  user-select: none;
}
.dashboard { width: min(720px, 100%); }
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 14px;
  padding: 0 4px;
  flex-wrap: wrap;
}
.brand { font-size: 14px; font-weight: 600; letter-spacing: -0.01em; }
.topbar-right { display: flex; align-items: center; gap: 8px; }
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 999px;
  background: var(--offline-soft);
  color: var(--offline);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  transition: background-color .2s ease, color .2s ease;
}
.pill.live { background: var(--live-soft); color: var(--live); }
.pill .material-symbols-rounded { font-size: 15px; }
.pill.live .material-symbols-rounded { animation: pulse 1.6s ease-in-out infinite; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
.icon-btn {
  display: inline-grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border: none;
  border-radius: 12px;
  background: var(--icon-btn-bg);
  color: var(--text);
  cursor: pointer;
  transition: background-color .15s ease, transform .1s ease;
}
.icon-btn:hover { background: var(--icon-btn-hover); }
.icon-btn:active { transform: scale(0.94); }
.card {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow);
  overflow: hidden;
  transition: background-color .25s ease, border-color .25s ease;
}
.main { padding: 40px 28px 24px; text-align: center; }
.heart {
  display: inline-grid;
  place-items: center;
  width: 52px;
  height: 52px;
  margin-bottom: 16px;
  border-radius: 16px;
  background: var(--accent-soft);
  color: var(--accent);
  transition: transform .15s ease;
}
.heart .material-symbols-rounded { font-size: 26px; }
.heart.beat { transform: scale(1.15); }
.bpm {
  font-size: clamp(64px, 16vw, 140px);
  line-height: .92;
  font-weight: 700;
  letter-spacing: -0.05em;
  font-variant-numeric: tabular-nums;
}
.unit {
  margin-top: 12px;
  color: var(--muted);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}
.meta { margin-top: 18px; color: var(--muted); font-size: 12px; }
.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  border-top: 1px solid var(--border);
}
.stat { padding: 16px 8px; text-align: center; }
.stat + .stat { border-left: 1px solid var(--border); }
.stat-label {
  color: var(--muted);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.stat-value {
  margin-top: 5px;
  font-size: 18px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.monitor {
  margin: 4px 16px 18px;
  padding: 12px;
  border-radius: 18px;
  background: #05070a;
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.06);
}
canvas { display: block; width: 100%; height: 130px; }
@media (max-width: 520px) {
  .main { padding: 30px 16px 18px; }
  .stats { grid-template-columns: 1fr; }
  .stat + .stat { border-left: 0; border-top: 1px solid var(--border); }
  .monitor { margin: 4px 10px 14px; }
  canvas { height: 110px; }
  .brand { font-size: 13px; }
}
@media (max-width: 360px) {
  .bpm { font-size: clamp(56px, 18vw, 96px); }
}
</style>
</head>
<body>
<main class="dashboard">
  <div class="topbar">
    <div class="brand">Heart Rate Monitor</div>
    <div class="topbar-right">
      <div id="pill" class="pill">
        <span id="pillIcon" class="material-symbols-rounded">sensors_off</span>
        <span id="connectionText">Connecting</span>
      </div>
      <button id="themeToggle" class="icon-btn" type="button" aria-label="Toggle theme">
        <span id="themeIcon" class="material-symbols-rounded">dark_mode</span>
      </button>
    </div>
  </div>

  <section class="card">
    <div class="main">
      <div id="heart" class="heart" aria-hidden="true">
        <span class="material-symbols-rounded">favorite</span>
      </div>
      <div id="bpm" class="bpm">--</div>
      <div class="unit">BPM</div>
      <div id="meta" class="meta">Waiting for heart-rate data</div>
    </div>

    <div class="stats">
      <div class="stat">
        <div class="stat-label">Minimum</div>
        <div id="min" class="stat-value">--</div>
      </div>
      <div class="stat">
        <div class="stat-label">Average</div>
        <div id="avg" class="stat-value">--</div>
      </div>
      <div class="stat">
        <div class="stat-label">Maximum</div>
        <div id="max" class="stat-value">--</div>
      </div>
    </div>

    <div class="monitor">
      <canvas id="chart"></canvas>
    </div>
  </section>
</main>

<script type="module" nonce="%%NONCE%%">
const MAX_POINTS = 120;
const STALE_MS = 15000;
const HEARTBEAT_MS = 25000;
const MAX_BACKOFF_MS = 15000;
const THEME_KEY = "hr-theme";

const el = Object.fromEntries(
  ["bpm", "meta", "pill", "pillIcon", "connectionText", "heart", "min", "avg", "max", "chart", "themeToggle", "themeIcon"]
    .map((id) => [id, document.getElementById(id)])
);
const ctx = el.chart.getContext("2d");

const state = {
  history: [],
  socket: null,
  backoffMs: 1000,
  staleTimer: null,
  heartbeatTimer: null,
  reconnectTimer: null,
  resizePending: false,
  connecting: false,
};

function safeStorage() {
  try {
    localStorage.setItem("__hr_probe__", "1");
    localStorage.removeItem("__hr_probe__");
    return localStorage;
  } catch {
    return null;
  }
}
const storage = safeStorage();

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  el.themeIcon.textContent = theme === "dark" ? "light_mode" : "dark_mode";
  el.themeToggle.setAttribute(
    "aria-label",
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
  );
}

function initTheme() {
  const current = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  applyTheme(current);

  el.themeToggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    storage?.setItem(THEME_KEY, next);
  });

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (event) => {
    if (storage?.getItem(THEME_KEY)) return;
    applyTheme(event.matches ? "dark" : "light");
  });
}

function setConnection(live, text) {
  el.pill.classList.toggle("live", live);
  el.connectionText.textContent = text;
  el.pillIcon.textContent = live ? "sensors" : "sensors_off";
}

function formatTime(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "--";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function numericValues() {
  const values = [];
  for (const item of state.history) {
    const v = Number(item?.heart_rate);
    if (Number.isFinite(v)) values.push(v);
  }
  return values;
}

function updateStats(values) {
  if (!values.length) {
    el.min.textContent = el.avg.textContent = el.max.textContent = "--";
    return;
  }
  let min = values[0], max = values[0], sum = 0;
  for (const v of values) {
    if (v < min) min = v;
    if (v > max) max = v;
    sum += v;
  }
  el.min.textContent = Math.round(min);
  el.avg.textContent = Math.round(sum / values.length);
  el.max.textContent = Math.round(max);
}

function drawGrid(width, height, dpr) {
  const minor = 16 * dpr;
  ctx.save();
  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue("--ecg-grid").trim();
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let x = 0; x <= width; x += minor) {
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
  }
  for (let y = 0; y <= height; y += minor) {
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
  }
  ctx.stroke();

  const major = minor * 5;
  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue("--ecg-grid-strong").trim();
  ctx.beginPath();
  for (let x = 0; x <= width; x += major) {
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
  }
  for (let y = 0; y <= height; y += major) {
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
  }
  ctx.stroke();
  ctx.restore();
}

function renderChart(values) {
  const rect = el.chart.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(1, Math.round(rect.width * dpr));
  const height = Math.max(1, Math.round(rect.height * dpr));

  if (el.chart.width !== width || el.chart.height !== height) {
    el.chart.width = width;
    el.chart.height = height;
  }

  ctx.clearRect(0, 0, width, height);
  drawGrid(width, height, dpr);

  if (values.length < 2) return;

  let min = values[0], max = values[0];
  for (const v of values) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  min -= 5;
  max += 5;
  const range = Math.max(1, max - min);

  const padX = 8 * dpr;
  const padY = 14 * dpr;
  const plotWidth = width - padX * 2;
  const plotHeight = height - padY * 2;
  const step = plotWidth / Math.max(1, values.length - 1);

  const points = values.map((value, index) => ({
    x: padX + index * step,
    y: padY + (1 - (value - min) / range) * plotHeight,
  }));

  ctx.save();
  ctx.shadowColor = "#22e29a";
  ctx.shadowBlur = 8 * dpr;
  ctx.lineWidth = 2 * dpr;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  ctx.strokeStyle = "#22e29a";
  ctx.beginPath();
  points.forEach((point, index) => {
    index === 0 ? ctx.moveTo(point.x, point.y) : ctx.lineTo(point.x, point.y);
  });
  ctx.stroke();
  ctx.restore();

  const last = points[points.length - 1];
  ctx.save();
  ctx.fillStyle = "#22e29a";
  ctx.shadowColor = "#22e29a";
  ctx.shadowBlur = 10 * dpr;
  ctx.beginPath();
  ctx.arc(last.x, last.y, 3 * dpr, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

function refresh() {
  const values = numericValues();
  updateStats(values);
  renderChart(values);
}

function renderData(data) {
  const bpm = Number(data?.heart_rate);
  if (!Number.isFinite(bpm)) return;

  el.bpm.textContent = Math.round(bpm);
  el.meta.textContent = `Last update: ${formatTime(data.timestamp)}`;

  state.history.push(data);
  if (state.history.length > MAX_POINTS) state.history.shift();

  refresh();

  el.heart.classList.remove("beat");
  void el.heart.offsetWidth;
  el.heart.classList.add("beat");

  clearTimeout(state.staleTimer);
  state.staleTimer = setTimeout(() => setConnection(false, "Stale data"), STALE_MS);
}

function handleMessage(raw) {
  let message;
  try {
    message = JSON.parse(raw);
  } catch {
    return;
  }

  if (message.type === "snapshot") {
    state.history = Array.isArray(message.history) ? message.history.slice(-MAX_POINTS) : [];
    message.data ? renderData(message.data) : refresh();
    return;
  }

  if (message.type === "heart_rate" && message.data) {
    renderData(message.data);
  }
}

function sendHeartbeat() {
  const socket = state.socket;
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  try {
    socket.send("ping");
  } catch {
    try {
      socket.close();
    } catch {}
  }
}

function scheduleReconnect() {
  clearTimeout(state.reconnectTimer);
  const delay = state.backoffMs + Math.random() * 400;
  state.backoffMs = Math.min(state.backoffMs * 1.7, MAX_BACKOFF_MS);
  state.reconnectTimer = setTimeout(connect, delay);
}

function connect() {
  if (state.connecting || (state.socket && state.socket.readyState === WebSocket.OPEN)) return;
  state.connecting = true;
  clearTimeout(state.reconnectTimer);
  setConnection(false, "Connecting");

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);
  state.socket = socket;

  socket.onopen = () => {
    state.connecting = false;
    setConnection(true, "Live");
    state.backoffMs = 1000;
    clearInterval(state.heartbeatTimer);
    state.heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_MS);
  };

  socket.onmessage = (event) => handleMessage(event.data);

  socket.onclose = () => {
    state.connecting = false;
    clearInterval(state.heartbeatTimer);
    if (state.socket === socket) state.socket = null;
    setConnection(false, "Reconnecting");
    scheduleReconnect();
  };

  socket.onerror = () => {
    try {
      socket.close();
    } catch {}
  };
}

function ensureConnected() {
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    sendHeartbeat();
    return;
  }
  if (state.socket && state.socket.readyState === WebSocket.CONNECTING) return;
  state.backoffMs = 1000;
  connect();
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") ensureConnected();
});

window.addEventListener("online", ensureConnected);
window.addEventListener("focus", ensureConnected);

const resizeObserver = new ResizeObserver(() => {
  if (state.resizePending) return;
  state.resizePending = true;
  requestAnimationFrame(() => {
    state.resizePending = false;
    refresh();
  });
});
resizeObserver.observe(el.chart);

initTheme();
connect();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )
    return HTMLResponse(
        content=HTML_PAGE.replace("%%NONCE%%", nonce),
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": csp,
        },
    )


@app.get("/api/health")
async def health() -> JSONResponse:
    latest = await get_latest()
    return envelope(
        success=True,
        message="Service is healthy",
        http_status=status.HTTP_200_OK,
        data={
            "service": "live-heart-rate",
            "version": APP_VERSION,
            "connected_clients": await connected_client_count(),
            "has_heart_rate": latest is not None,
            "latest_heart_rate": latest["heart_rate"] if latest else None,
        },
    )


@app.get("/api/hr")
async def current_heart_rate() -> JSONResponse:
    latest = await get_latest()
    if latest is None:
        return envelope(
            success=False,
            message="No heart-rate reading received yet",
            http_status=status.HTTP_404_NOT_FOUND,
            data={"heart_rate": None},
        )
    return envelope(
        success=True,
        message="Latest heart-rate reading",
        http_status=status.HTTP_200_OK,
        data=latest,
    )


@app.get("/api/history")
async def heart_rate_history() -> JSONResponse:
    history = await get_history()
    return envelope(
        success=True,
        message="Recent heart-rate history",
        http_status=status.HTTP_200_OK,
        data={
            "count": len(history),
            "items": history,
        },
    )


@app.post("/webhook/hr")
async def receive_hr(request: Request) -> JSONResponse:
    if not token_is_valid(request):
        logger.warning("🔒 Rejected webhook: invalid or missing token")
        return envelope(
            success=False,
            message="Invalid or missing webhook token",
            http_status=status.HTTP_401_UNAUTHORIZED,
        )

    content_type = request.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        return envelope(
            success=False,
            message="Content-Type must be application/json",
            http_status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    try:
        payload = await request.json()
    except Exception:
        return envelope(
            success=False,
            message="Request body contains invalid JSON",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    if not isinstance(payload, dict):
        return envelope(
            success=False,
            message="JSON body must be an object",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    raw_value, extract_error = extract_heart_rate(payload)

    if extract_error:
        return envelope(
            success=False,
            message=extract_error,
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    if raw_value is None:
        return envelope(
            success=False,
            message=(
                "Heart rate not found. Supported fields: "
                + ", ".join(HR_FIELD_CANDIDATES)
            ),
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    heart_rate, normalize_error = normalize_heart_rate(raw_value)

    if normalize_error:
        return envelope(
            success=False,
            message=normalize_error,
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    measurement = Measurement(heart_rate=heart_rate, timestamp=now_iso(), source=SOURCE_NAME)
    await store_measurement(measurement)

    clients_reached = await connected_client_count()
    logger.info("💓 %s BPM accepted → %s subscriber(s) notified via Redis", heart_rate, clients_reached)

    return envelope(
        success=True,
        message="Heart-rate reading accepted",
        http_status=status.HTTP_202_ACCEPTED,
        data={**measurement.to_dict(), "connected_clients": clients_reached},
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    logger.info("🟢 Client connected")

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(REDIS_CHANNEL)

    async def forward_redis_messages() -> None:
        # Runs alongside the receive loop below so a broadcast published by
        # ANY instance's webhook reaches this client immediately, instead of
        # only reading from process-local memory.
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                await asyncio.wait_for(
                    websocket.send_text(message["data"]), timeout=WS_SEND_TIMEOUT_SECONDS
                )
            except Exception:
                break

    forward_task = asyncio.create_task(forward_redis_messages())

    try:
        latest = await get_latest()
        history = await get_history()
        snapshot = {
            "type": "snapshot",
            "data": latest,
            "history": history,
            "server_time": now_iso(),
        }
        await websocket.send_text(json.dumps(snapshot, separators=(",", ":")))

        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(), timeout=WS_RECEIVE_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                logger.warning("⌛ Client timed out (no heartbeat)")
                break

            if message != "ping":
                continue

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("💥 Unexpected WebSocket error")
    finally:
        forward_task.cancel()
        try:
            await forward_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            await pubsub.unsubscribe(REDIS_CHANNEL)
            await pubsub.aclose()
        except Exception:
            pass
        logger.info("🔴 Client disconnected")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return envelope(
        success=False,
        message="Request validation failed",
        http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        data={"errors": exc.errors()},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return envelope(success=False, message=str(exc.detail), http_status=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    logger.exception("💥 Unhandled server error")
    return envelope(
        success=False,
        message="Internal server error",
        http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )