"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  worker_app.py  —  HAIDER SNIPER Dual-Engine Cluster Worker
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  High-performance autonomous worker supporting:
    1. Hash API Engine (Fast hash-based Fragment API queries)
    2. Direct Scan Engine (curl_cffi Chrome TLS + aiohttp fallback)
    3. Live Mode Switcher (Switch between Direct & Hash manually via UI button)
    4. Auto-sync with Main Bot (https://thomasthere-fragment.hf.space)
    5. Instant Snipe Alert Dispatch to Main Bot
    6. ZeroGPU / Hugging Face Spaces compatibility + Raven Host compatibility
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import random
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional

import aiohttp
from aiohttp import web

# Import proven scanning logic
import scraper

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ── Config ────────────────────────────────────────────────────────────────────
MAIN_URL      = os.environ.get("MAIN_URL", "https://thomasthere-fragment.hf.space").rstrip("/")
WORKER_SECRET = os.environ.get("WORKER_SECRET", "haider_secret_v17")
_configured_wid = os.environ.get("WORKER_ID")
if _configured_wid:
    WORKER_ID = _configured_wid
else:
    _sp_id = os.environ.get("SPACE_ID", "")
    if "worker" in _sp_id.lower():
        w_name = _sp_id.split("/")[-1].replace("-", "_")
        WORKER_ID = f"hf_{w_name}" if not w_name.startswith("hf_") else w_name
    else:
        WORKER_ID = "raven_worker"
INITIAL_MODE  = os.environ.get("SCAN_MODE", "hash").lower()
PORT          = int(float(os.environ.get("PORT", os.environ.get("SERVER_PORT", "7860"))))
PING_INTERVAL = int(float(os.environ.get("PING_INTERVAL", "15")))
N_WORKERS     = int(float(os.environ.get("FRAG_WORKERS", "20")))
DUTY_CYCLE_MINS = int(float(os.environ.get("DUTY_CYCLE", "30" if "blitz" in WORKER_ID.lower() else "0")))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(f"haider.{WORKER_ID}")

# Set initial scanning engine
if INITIAL_MODE in ("direct", "direct_scan"):
    scraper.set_scan_mode("direct")
else:
    scraper.set_scan_mode("hash")

# ── ZeroGPU / Gradio Anchor for Hugging Face Spaces ──────────────────────────
try:
    import gradio as gr
    from gradio.routes import App
    from starlette.responses import HTMLResponse, JSONResponse
    from starlette.requests import Request as StarletteRequest
    HAS_GRADIO = True
except Exception:
    HAS_GRADIO = False

try:
    import spaces
    @spaces.GPU(duration=10)
    def _zero_gpu_worker(prompt: str, history: list):
        return f"Worker Active ({scraper.get_scan_mode().upper()})"
except Exception:
    def _zero_gpu_worker(prompt: str, history: list):
        return f"Worker Active ({scraper.get_scan_mode().upper()})"

# ── State & Stats ─────────────────────────────────────────────────────────────
_STATE = {
    "running": True,
    "paused": False,
    "current_mode": scraper.get_scan_mode(),
    "upstream_connected": False,
    "last_upstream_ping": 0.0,
    "upstream_error": "",
    "duty_cycle_enabled": (DUTY_CYCLE_MINS > 0),
    "duty_state": "scanning",
    "cycle_switch_at": time.time() + (DUTY_CYCLE_MINS * 60 if DUTY_CYCLE_MINS > 0 else 999999999),
    "last_sentinel_ping": 0.0,
}

_STATS = {
    "start_time": time.time(),
    "checks": 0,
    "triggers": 0,
    "speed": 0,
    "last_check": "",
    "last_trigger": "None",
    "watchlist_size": 0,
    "rounds": 0,
}

_watchlist: List[str] = []
_scan_queue: asyncio.Queue = asyncio.Queue()
_worker_tasks: List[asyncio.Task] = []
_recent_logs: List[dict] = []
_recent_scan_events: deque = deque(maxlen=40)
_main_session: Optional[aiohttp.ClientSession] = None

def _log_event(msg: str, level: str = "info"):
    _recent_logs.append({
        "time": time.strftime("%H:%M:%S"),
        "msg": msg,
        "level": level,
    })
    if len(_recent_logs) > 60:
        _recent_logs.pop(0)

# ── Main Bot Communication ───────────────────────────────────────────────────

async def _get_main_session() -> aiohttp.ClientSession:
    global _main_session
    if _main_session is None or _main_session.closed:
        _main_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"X-Worker-Secret": WORKER_SECRET},
        )
    return _main_session

async def _ping_main() -> Optional[dict]:
    if not MAIN_URL:
        return None
    try:
        sess = await _get_main_session()
        payload = {
            "source": WORKER_ID,
            "worker_id": WORKER_ID,
            "checks": _STATS["checks"],
            "triggers": _STATS["triggers"],
            "speed": _STATS["speed"],
            "mode": scraper.get_scan_mode(),
            "total": _STATS["watchlist_size"],
            "is_vip": False,
            "events": list(_recent_scan_events),
            "last_check": _STATS.get("last_check", ""),
            "last_trigger": _STATS.get("last_trigger", "None"),
            "duty_state": _STATE.get("duty_state", "scanning"),
            "cooldown_s": max(0, int(_STATE.get("cycle_switch_at", 0) - time.time())) if _STATE.get("duty_state") == "resting" else 0,
        }
        async with sess.post(f"{MAIN_URL}/worker_ping", json=payload) as resp:
            if resp.status == 200:
                _STATE["upstream_connected"] = True
                _STATE["last_upstream_ping"] = time.time()
                _STATE["upstream_error"] = ""
                return await resp.json()
            else:
                _STATE["upstream_connected"] = False
                _STATE["upstream_error"] = f"HTTP {resp.status}"
    except Exception as e:
        _STATE["upstream_connected"] = False
        _STATE["upstream_error"] = str(e)
        log.warning(f"Ping main ({MAIN_URL}) failed: {e}")
    return None

async def _report_hit(username: str) -> bool:
    if not MAIN_URL:
        return False
    try:
        sess = await _get_main_session()
        async with sess.post(
            f"{MAIN_URL}/snipe_alert",
            json={"username": username, "source": WORKER_ID},
            headers={"X-Worker-Secret": WORKER_SECRET},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                log.info(f"Snipe alert for @{username} acknowledged by Main Bot!")
                _log_event(f"🎯 Snipe alert for @{username} confirmed by Main Bot", "success")
                return data.get("triggered", False)
    except Exception as e:
        log.error(f"Report hit failed @{username}: {e}")
        _log_event(f"❌ Failed to report snipe alert @{username}: {e}", "error")
    return False

async def _run_sentinel_pings():
    """Pings cluster nodes to prevent idle sleep/inactivity during Blitz rest cycle."""
    sentinel_targets = [
        f"{MAIN_URL}/health",
        "https://thomasthere-worker-1.hf.space/health",
        "https://thomasthere-fragment.hf.space/api/stats",
    ]
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as sess:
            for url in sentinel_targets:
                try:
                    async with sess.get(url) as resp:
                        pass
                except Exception:
                    pass
        log.info("🛡 Sentinel Keep-Alive: Pinged cluster nodes to keep instances awake.")
    except Exception as e:
        log.warning(f"Sentinel ping error: {e}")

# ── Sync Loop ─────────────────────────────────────────────────────────────────

async def _sync_loop():
    last_check_count = 0
    last_speed_time = time.time()

    while _STATE["running"]:
        try:
            await asyncio.sleep(PING_INTERVAL)
            now = time.time()
            elapsed = now - last_speed_time
            if elapsed > 0:
                _STATS["speed"] = int((_STATS["checks"] - last_check_count) / elapsed * 60)
            last_check_count = _STATS["checks"]
            last_speed_time = now

            # Duty cycle manager (e.g. Blitz 30m Scan / 30m Rest)
            if _STATE.get("duty_cycle_enabled"):
                if now >= _STATE.get("cycle_switch_at", 0):
                    if _STATE.get("duty_state") == "scanning":
                        _STATE["duty_state"] = "resting"
                        _STATE["cycle_switch_at"] = now + (DUTY_CYCLE_MINS * 60)
                        log.info(f"⏸ Duty Cycle: Switching to RESTING for {DUTY_CYCLE_MINS}m cooldown...")
                        _log_event(f"⏸ Duty Cycle: Cooldown started ({DUTY_CYCLE_MINS}m rest)", "info")
                    else:
                        _STATE["duty_state"] = "scanning"
                        _STATE["cycle_switch_at"] = now + (DUTY_CYCLE_MINS * 60)
                        log.info(f"⚡ Duty Cycle: Waking up! Scanning for {DUTY_CYCLE_MINS}m...")
                        _log_event(f"⚡ Duty Cycle: Scanning active ({DUTY_CYCLE_MINS}m)", "success")

                # If resting, run Sentinel Keep-Alive Pings to keep Main Bot & Workers awake!
                if _STATE.get("duty_state") == "resting" and (now - _STATE.get("last_sentinel_ping", 0)) > 90:
                    _STATE["last_sentinel_ping"] = now
                    asyncio.create_task(_run_sentinel_pings())

            data = await _ping_main()
            if data and data.get("ok"):
                if data.get("status") == "paused":
                    _STATE["paused"] = True
                else:
                    _STATE["paused"] = False

                # Dynamic scan mode synchronization from Main Bot
                upstream_mode = data.get("scan_mode") or data.get("mode")
                if upstream_mode and upstream_mode in ("direct", "hash_api", "hash"):
                    norm_mode = "hash_api" if upstream_mode in ("hash", "hash_api") else "direct"
                    if scraper.get_scan_mode() != norm_mode:
                        scraper.set_scan_mode(norm_mode)
                        log.info(f"🔄 Extra Worker synced scan mode from Main Bot: {norm_mode.upper()}")
                        _log_event(f"🔄 Engine mode synced to {norm_mode.upper()} from Main Bot", "info")

                raw_list = data.get("watchlist", [])
                if raw_list:
                    _watchlist.clear()
                    _watchlist.extend(raw_list)
                    _STATS["watchlist_size"] = len(_watchlist)

                new_proxies = data.get("proxy_pool", []) + data.get("proxy_pool_slow", [])
                if new_proxies:
                    scraper.load_proxies_from_text("\n".join(new_proxies))

        except Exception as e:
            log.error(f"Sync loop error: {e}")

# ── Scan Worker Logic ────────────────────────────────────────────────────────

async def _scan_worker(wid: int):
    while _STATE["running"]:
        try:
            if _STATE["paused"] or _STATE.get("duty_state") == "resting":
                await asyncio.sleep(2)
                continue

            try:
                username = _scan_queue.get_nowait()
            except asyncio.QueueEmpty:
                if not _watchlist:
                    await asyncio.sleep(1)
                    continue
                _STATS["rounds"] += 1
                for u in _watchlist:
                    await _scan_queue.put(u)
                await asyncio.sleep(0.05)
                continue

            _STATS["checks"] += 1
            _STATS["last_check"] = username

            # Correct tuple unpacking: is_snipe_window (bool), status_label (str)
            t0 = time.perf_counter()
            is_window, status = await scraper.check_target(username)
            latency_ms = max(1, int((time.perf_counter() - t0) * 1000))

            _recent_scan_events.append({
                "time": time.strftime("%H:%M:%S"),
                "worker": WORKER_ID,
                "target": username,
                "status": "🎯 CLAIMABLE" if is_window else status,
                "latency_ms": latency_ms,
                "is_hit": is_window
            })

            # ONLY alert when is_window is genuinely True!
            if is_window is True:
                _STATS["triggers"] += 1
                _STATS["last_trigger"] = f"@{username} ({time.strftime('%H:%M:%S')})"
                log.info(f"🚨 CLAIMABLE WINDOW: @{username} via {scraper.get_scan_mode()} — Alerting Main Bot!")
                _log_event(f"🚨 CLAIMABLE WINDOW: @{username}! Alerting Main Bot...", "success")
                try:
                    while username in _watchlist:
                        _watchlist.remove(username)
                    _STATS["watchlist_size"] = len(_watchlist)
                except Exception:
                    pass
                asyncio.create_task(_report_hit(username))

            await asyncio.sleep(0.02)

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error(f"Worker#{wid} error: {e}")
            await asyncio.sleep(1)

async def _start_workers(count: int = N_WORKERS):
    global _worker_tasks
    for t in _worker_tasks:
        t.cancel()
    _worker_tasks.clear()
    while not _scan_queue.empty():
        try:
            _scan_queue.get_nowait()
        except:
            break
    for i in range(count):
        t = asyncio.create_task(_scan_worker(i), name=f"scan:{i}")
        _worker_tasks.append(t)
    log.info(f"Started {count} scanning tasks (engine={scraper.get_scan_mode()})")
    _log_event(f"Started {count} scanning workers in {scraper.get_scan_mode().upper()} mode")

# ── Dashboard HTML ────────────────────────────────────────────────────────────

def _render_worker_html() -> str:
    current_mode = scraper.get_scan_mode().upper()
    is_hash = (current_mode in ("HASH", "HASH_API"))
    up = int(time.time() - _STATS["start_time"])
    h, r = divmod(up, 3600); m, s = divmod(r, 60)
    uptime_str = f"{h}h {m}m {s}s"

    upstream_badge = (
        '<span style="background:#065f46;color:#34d399;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;">🟢 CONNECTED</span>'
        if _STATE["upstream_connected"]
        else f'<span style="background:#7f1d1d;color:#f87171;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;">🔴 DISCONNECTED ({_STATE["upstream_error"][:20]})</span>'
    )

    mode_badge = (
        '<span style="background:#1e1b4b;color:#a5b4fc;border:1px solid #4338ca;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;">⚡ HASH API</span>'
        if is_hash
        else '<span style="background:#064e3b;color:#6ee7b7;border:1px solid #059669;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;">🎯 DIRECT SCAN</span>'
    )

    logs_html = "".join([
        f'<div style="padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:13px;font-family:monospace;">'
        f'<span style="color:#64748b;">[{l["time"]}]</span> '
        f'<span style="color:{"#10b981" if l["level"]=="success" else "#ef4444" if l["level"]=="error" else "#94a3b8"};">{html.escape(l["msg"])}</span>'
        f'</div>'
        for l in reversed(_recent_logs[-15:])
    ]) or '<div style="color:#64748b;font-style:italic;">No events recorded yet...</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HAIDER SNIPER • {WORKER_ID.upper()} Worker</title>
  <style>
    :root {{
      --bg: #090d16;
      --card: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #3b82f6;
      --accent-green: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 24px;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }}
    .title {{ font-size: 20px; font-weight: 800; }}
    .title span {{ color: var(--accent); }}
    .status-group {{ display: flex; gap: 8px; align-items: center; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }}
    .card-label {{ font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 6px; }}
    .card-val {{ font-size: 26px; font-weight: 800; }}
    .controls {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .btn {{
      padding: 10px 18px;
      font-size: 13px;
      font-weight: 700;
      border-radius: 8px;
      border: 1px solid transparent;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .btn-hash {{ background: #4338ca; color: #fff; }}
    .btn-hash:hover {{ background: #4f46e5; }}
    .btn-direct {{ background: #059669; color: #fff; }}
    .btn-direct:hover {{ background: #10b981; }}
    .btn-secondary {{ background: #1f2937; color: #e5e7eb; border-color: #374151; }}
    .btn-secondary:hover {{ background: #374151; }}
    .logs-panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }}
    .logs-title {{ font-size: 14px; font-weight: 700; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">HAIDER SNIPER <span>// {html.escape(WORKER_ID.upper())}</span></div>
      <div class="status-group">
        {mode_badge}
        {upstream_badge}
      </div>
    </div>

    <div class="cards">
      <div class="card">
        <div class="card-label">Scanning Speed</div>
        <div class="card-val" style="color:var(--accent-green);">{_STATS['speed']:,} <span style="font-size:14px;font-weight:500;color:var(--muted)">c/min</span></div>
      </div>
      <div class="card">
        <div class="card-label">Watchlist Queue</div>
        <div class="card-val" style="color:var(--accent);">{_STATS['watchlist_size']:,} <span style="font-size:14px;font-weight:500;color:var(--muted)">targets</span></div>
      </div>
      <div class="card">
        <div class="card-label">Total Checks</div>
        <div class="card-val">{_STATS['checks']:,}</div>
      </div>
      <div class="card">
        <div class="card-label">Triggers Detected</div>
        <div class="card-val" style="color:#f59e0b;">{_STATS['triggers']}</div>
      </div>
    </div>

    <div class="controls">
      <div style="font-size:13px;font-weight:700;margin-right:8px;">MANUAL SCAN ENGINE:</div>
      <button class="btn btn-hash" onclick="setMode('hash')">⚡ Switch to HASH API</button>
      <button class="btn btn-direct" onclick="setMode('direct')">🎯 Switch to DIRECT SCAN</button>
      <button class="btn btn-secondary" onclick="togglePause()">{'▶ Resume' if _STATE['paused'] else '⏸ Pause'}</button>
      <button class="btn btn-secondary" onclick="location.reload()">🔄 Refresh</button>
    </div>

    <div class="logs-panel">
      <div class="logs-title">Live Activity Logs • Uptime: {uptime_str} • Upstream: <a href="{MAIN_URL}/dashboard" target="_blank" style="color:var(--accent);text-decoration:none;">{MAIN_URL}</a></div>
      <div id="logs-box">
        {logs_html}
      </div>
    </div>
  </div>

  <script>
    async function setMode(mode) {{
      try {{
        let res = await fetch('/api/set_mode?mode=' + mode, {{ method: 'POST' }});
        let data = await res.json();
        if (data.ok) location.reload();
        else alert('Error: ' + (data.error || 'unknown'));
      }} catch (e) {{ alert('Network error: ' + e); }}
    }}

    async function togglePause() {{
      try {{
        let res = await fetch('/api/toggle_pause', {{ method: 'POST' }});
        let data = await res.json();
        if (data.ok) location.reload();
        else alert('Error: ' + e);
      }} catch (e) {{ alert('Error: ' + e); }}
    }}

    setInterval(() => {{ location.reload(); }}, 8000);
  </script>
</body>
</html>"""

# ── Web Server Setup ──────────────────────────────────────────────────────────

async def _start_aiohttp_server():
    async def _root(_: web.Request) -> web.Response:
        return web.Response(text=_render_worker_html(), content_type="text/html")

    async def _health(_: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "worker_id": WORKER_ID,
            "engine": scraper.get_scan_mode(),
            "speed": _STATS["speed"],
            "checks": _STATS["checks"],
            "triggers": _STATS["triggers"],
            "watchlist": _STATS["watchlist_size"],
            "paused": _STATE["paused"],
            "upstream_connected": _STATE["upstream_connected"],
            "uptime_s": int(time.time() - _STATS["start_time"]),
        })

    async def _api_set_mode(req: web.Request) -> web.Response:
        mode = req.query.get("mode", "").strip().lower()
        if mode not in ("hash", "direct"):
            return web.json_response({"ok": False, "error": "Mode must be 'hash' or 'direct'"}, status=400)
        scraper.set_scan_mode(mode)
        _STATE["current_mode"] = mode
        log.info(f"Manual mode switch: Switched worker engine to {mode.upper()}")
        _log_event(f"Switched engine to {mode.upper()} mode via Dashboard Button", "success")
        return web.json_response({"ok": True, "mode": mode})

    async def _api_toggle_pause(_: web.Request) -> web.Response:
        _STATE["paused"] = not _STATE["paused"]
        st = "PAUSED" if _STATE["paused"] else "RESUMED"
        _log_event(f"Worker {st} manually", "warn" if _STATE["paused"] else "success")
        return web.json_response({"ok": True, "paused": _STATE["paused"]})

    app = web.Application()
    app.router.add_get("/", _root)
    app.router.add_get("/dashboard", _root)
    app.router.add_get("/health", _health)
    app.router.add_post("/api/set_mode", _api_set_mode)
    app.router.add_get("/api/set_mode", _api_set_mode)
    app.router.add_post("/api/toggle_pause", _api_toggle_pause)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info(f"Worker aiohttp webserver listening on :{PORT}")

# ── Main Async Runner ─────────────────────────────────────────────────────────

async def main():
    log.info(f"Starting Cluster Worker {WORKER_ID} (initial_mode={scraper.get_scan_mode()}, port={PORT})...")
    _log_event(f"Worker {WORKER_ID} starting up (Engine: {scraper.get_scan_mode().upper()})")

    await scraper.init_sessions()
    try:
        await scraper.init_hash_pool(n_tokens=5)
    except Exception as e:
        log.warning(f"Hash pool init warning: {e}")

    # Start aiohttp server if not using Gradio gateway
    if not (HAS_GRADIO and os.environ.get("SERVER_PORT") is None):
        await _start_aiohttp_server()

    await _start_workers(N_WORKERS)
    asyncio.create_task(_sync_loop())

    while _STATE["running"]:
        await asyncio.sleep(1)

# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # If on Hugging Face Spaces (Gradio available & no SERVER_PORT)
    if HAS_GRADIO and os.environ.get("SERVER_PORT") is None:
        gateway_app = App(title=f"Worker Gateway {WORKER_ID}")

        async def _fastapi_root(request: StarletteRequest):
            return HTMLResponse(_render_worker_html())

        async def _fastapi_health(request: StarletteRequest):
            return JSONResponse({
                "status": "ok",
                "worker_id": WORKER_ID,
                "engine": scraper.get_scan_mode(),
                "speed": _STATS["speed"],
                "checks": _STATS["checks"],
                "triggers": _STATS["triggers"],
                "watchlist": _STATS["watchlist_size"],
                "paused": _STATE["paused"],
                "upstream_connected": _STATE["upstream_connected"],
                "uptime_s": int(time.time() - _STATS["start_time"]),
            })

        async def _fastapi_set_mode(request: StarletteRequest):
            mode = request.query_params.get("mode", "").strip().lower()
            if mode not in ("hash", "direct"):
                return JSONResponse({"ok": False, "error": "Mode must be 'hash' or 'direct'"}, status_code=400)
            scraper.set_scan_mode(mode)
            _STATE["current_mode"] = mode
            log.info(f"Manual mode switch: Switched worker engine to {mode.upper()}")
            _log_event(f"Switched engine to {mode.upper()} mode via Dashboard Button", "success")
            return JSONResponse({"ok": True, "mode": mode})

        async def _fastapi_toggle_pause(request: StarletteRequest):
            _STATE["paused"] = not _STATE["paused"]
            st = "PAUSED" if _STATE["paused"] else "RESUMED"
            _log_event(f"Worker {st} manually", "warn" if _STATE["paused"] else "success")
            return JSONResponse({"ok": True, "paused": _STATE["paused"]})

        gateway_app.add_api_route("/", _fastapi_root, methods=["GET", "HEAD"])
        gateway_app.add_api_route("/dashboard", _fastapi_root, methods=["GET", "HEAD"])
        gateway_app.add_api_route("/health", _fastapi_health, methods=["GET", "HEAD"])
        gateway_app.add_api_route("/api/set_mode", _fastapi_set_mode, methods=["GET", "POST"])
        gateway_app.add_api_route("/api/toggle_pause", _fastapi_toggle_pause, methods=["GET", "POST"])

        demo = gr.ChatInterface(
            fn=_zero_gpu_worker,
            title=f"Fragment Dual Worker • {WORKER_ID}",
            description="Autonomous ZeroGPU Worker"
        )

        def _bg_run():
            asyncio.run(main())

        t = threading.Thread(target=_bg_run, name="WorkerAsyncThread", daemon=True)
        t.start()
        demo.launch(_app=gateway_app, server_name="0.0.0.0", server_port=PORT, ssr_mode=False)
    else:
        # Standard server (Raven Host / VPS)
        try:
            asyncio.run(main())
        except (KeyboardInterrupt, asyncio.CancelledError):
            sys.exit(0)
        except Exception as exc:
            log.critical(f"FATAL: {exc}")
            sys.exit(1)
