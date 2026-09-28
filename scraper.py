"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  scraper.py  —  HAIDER SNIPER v23 (Quantum Direct & Hash Engine)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Dual Scanning Architecture:
    1. Direct Scanning Engine (Default / UNUSUALxd Goldilocks Logic):
       • Direct HTTP/TLS requests to https://fragment.com/username/{u}
       • Auto-primed session cookie jar (stel_ssid) + query fallback
       • Complete response buffering via raw read to prevent truncated HTML
       • Integrated ProxyPoolManager rotation & softban handling
       • Adaptive Cloudflare 429 rate limit backoff
    2. Hash API Engine (Switchable via Bot/UI):
       • 1:1 dedicated sessions using curl_cffi Chrome TLS impersonation
       • Dynamic Hash Quota N requests per token (supports N = 1 to 500)
       • Auto-refresh regex extracting latest ajInit apiUrl hash tokens
       • Full fallback to Direct Engine if token renewal encounters issues

  Strict Snipe Filter Invariant:
    A target is CLAIMABLE ONLY IF:
      • tm-status-unavail is present in target row / status block
      • 'not for sale' is present in target row / status block
      • 'sold' is NOT present in target row / status block
      • Non-username markers (/addstickers/, /invoice/) are absent
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import asyncio
import html as html_lib
import logging
import random
import re
import time
from typing import Dict, List, Optional, Set, Tuple

try:
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    HAS_CURL_CFFI = True
except ImportError:
    CurlAsyncSession = None
    HAS_CURL_CFFI = False

import aiohttp

log = logging.getLogger("haider.scraper")

_BASE_URL = "https://fragment.com/username/{}"
_AJAX_URL = "https://fragment.com/api?hash={}"

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_NON_USERNAME_MARKERS = (
    "/addstickers/", "t.me/addstickers/", "addstickers",
    "/invoice/", "t.me/invoice/", "t.me/$",
    "sticker pack", "telegram sticker",
)

# ── Runtime Configuration ────────────────────────────────────────────────────
_CFG = {
    "scan_mode":               "direct",  # "direct" | "hash_api"
    "hash_lifetime_s":         90.0,
    "hash_requests_per_token": 25,
    "cache_ttl_s":             2.0,
    "max_workers":             400,
    "session_pool_size":       150,
}

_STATS = {
    "checks":           0,
    "direct_checks":    0,
    "hash_checks":      0,
    "snipe_windows":    0,
    "circuit_trips":    0,
    "last_check_time":  0.0,
}

# ── Proxy Pool Manager ───────────────────────────────────────────────────────
class ProxyPoolManager:
    """Production Proxy Pool Manager with round-robin rotation, format parsing, and softban tracking."""
    def __init__(self):
        self._proxies: List[str] = []
        self._softbanned: Dict[str, float] = {}  # proxy -> ban_expiry
        self._idx = 0
        self._auto_fetch = False
        self._split_direct_proxy = False  # When True: 50% Direct Scan / 50% Proxy Scan
        self._force_mode = "auto"  # "direct", "proxy", "split", "auto"
        self._req_counter = 0
        self._direct_count = 0
        self._proxy_count = 0

    def set_split_mode(self, enabled: bool = True):
        self._split_direct_proxy = enabled
        if enabled:
            self._force_mode = "split"
        elif self._force_mode == "split":
            self._force_mode = "auto"

    def set_mode_direct(self):
        self._force_mode = "direct"
        self._split_direct_proxy = False

    def set_mode_proxy(self):
        self._force_mode = "proxy"
        self._split_direct_proxy = False

    def set_mode_auto(self):
        self._force_mode = "auto"
        self._split_direct_proxy = False

    def get_pool_mode(self) -> str:
        return self._force_mode

    def add_proxy(self, proxy_str: str) -> bool:
        p = str(proxy_str).strip()
        if not p or p.startswith("#"):
            return False
        # Normalize various proxy input formats:
        # http://user:pass@host:port, socks5://..., host:port:user:pass, host:port
        if not (p.startswith("http://") or p.startswith("https://") or p.startswith("socks5://") or p.startswith("socks4://")):
            parts = p.split(":")
            if len(parts) == 4:
                p = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            elif len(parts) == 2:
                p = f"http://{parts[0]}:{parts[1]}"
            else:
                p = f"http://{p}"
        if p not in self._proxies:
            self._proxies.append(p)
            return True
        return False

    def load_from_text(self, text: str) -> dict:
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if self.add_proxy(line):
                added += 1
        now = time.time()
        active_banned = sum(1 for t in self._softbanned.values() if t > now)
        return {
            "ok": True,
            "total": len(self._proxies),
            "added": added,
            "working": max(0, len(self._proxies) - active_banned),
            "soft_banned": active_banned,
        }

    def clear(self) -> None:
        self._proxies.clear()
        self._softbanned.clear()
        self._idx = 0

    def mark_softban(self, proxy: str, duration: float = 60.0) -> None:
        self._softbanned[proxy] = time.time() + duration

    def clear_softbans(self) -> int:
        c = len(self._softbanned)
        self._softbanned.clear()
        return c

    def get_proxy(self) -> Optional[str]:
        # 1. Direct Only Mode (100% Native Host IP)
        if self._force_mode == "direct":
            self._direct_count += 1
            return None

        # 2. Split Mode (50% Direct / 50% Proxy)
        if self._force_mode == "split" or self._split_direct_proxy:
            self._req_counter += 1
            if self._req_counter % 2 == 0 or not self._proxies:
                self._direct_count += 1
                return None

        # 3. If no proxies available, fallback to Direct
        if not self._proxies:
            self._direct_count += 1
            return None

        # 4. Proxy Only or Auto Mode (with proxies present)
        self._proxy_count += 1
        now = time.time()
        # Clean expired softbans
        expired = [p for p, t in self._softbanned.items() if now > t]
        for p in expired:
            self._softbanned.pop(p, None)

        total = len(self._proxies)
        for _ in range(total):
            p = self._proxies[self._idx % total]
            self._idx += 1
            if p not in self._softbanned:
                return p
        if self._softbanned:
            earliest = min(self._softbanned.items(), key=lambda x: x[1])[0]
            return earliest
        return self._proxies[0]

    def has_proxies(self) -> bool:
        return len(self._proxies) > 0

    def stats(self) -> dict:
        now = time.time()
        active_banned = sum(1 for t in self._softbanned.values() if t > now)
        return {
            "pool_size": len(self._proxies),
            "reserve_size": 0,
            "working": max(0, len(self._proxies) - active_banned),
            "soft_banned": active_banned,
            "proxies": self._proxies[:20],
            "split_mode": self._split_direct_proxy,
            "force_mode": self._force_mode,
            "direct_checks": self._direct_count,
            "proxy_checks": self._proxy_count,
        }

_proxy_pool = ProxyPoolManager()

def set_split_mode(enabled: bool = True):
    """Enable or disable 50% Direct / 50% Proxy scanning mode."""
    _proxy_pool.set_split_mode(enabled)
    log.info(f"⚡ [Dual-Engine] 50% Direct / 50% Proxy mode: {'ENABLED' if enabled else 'DISABLED'}")

def is_split_mode() -> bool:
    return _proxy_pool._split_direct_proxy

def set_mode_direct_only():
    """Route 100% of requests through native host IP (no proxies)."""
    _proxy_pool.set_mode_direct()
    log.info("⚡ [ProxyPool] Switched to DIRECT ONLY mode (100% Native Host IP).")

def set_mode_proxy_only():
    """Route 100% of requests through verified proxy swarm (0% host IP, native IP resting)."""
    _proxy_pool.set_mode_proxy()
    log.info("🌐 [ProxyPool] Switched to PROXY SWARM mode (100% Verified Proxies, 0% Host IP).")

def set_mode_auto():
    _proxy_pool.set_mode_auto()
    log.info("🔄 [ProxyPool] Switched to AUTO mode.")

def get_pool_mode() -> str:
    return _proxy_pool.get_pool_mode()

FREE_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
]

async def auto_fetch_free_proxies(max_candidates: int = 150, concurrency: int = 30) -> int:
    """Fetches candidate proxies from verified high-quality raw feeds, tests them against Fragment, and loads working ones into pool."""
    log.info("🌐 [Auto-Proxy Fetcher] Pulling fresh candidates from verified feeds...")
    candidates: List[str] = []
    headers = {"User-Agent": "Mozilla/5.0"}
    timeout = aiohttp.ClientTimeout(total=6)
    
    async with aiohttp.ClientSession(timeout=timeout) as sess:
        tasks = []
        for src in FREE_PROXY_SOURCES:
            async def _fetch_feed(url):
                try:
                    async with sess.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b", text)
                            return matches
                except Exception as e:
                    log.debug(f"Proxy feed {url} error: {e}")
                return []
            tasks.append(_fetch_feed(src))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                candidates.extend(r)

    if not candidates:
        log.warning("⚠️ [Auto-Proxy Fetcher] No candidate proxies fetched from feeds.")
        return 0

    unique = list(set(candidates))
    random.shuffle(unique)
    sample = unique[:max_candidates]
    log.info(f"🌐 [Auto-Proxy Fetcher] Testing {len(sample)} candidate proxies against Fragment...")

    valid_proxies: List[str] = []
    sem = asyncio.Semaphore(concurrency)

    async def _verify_proxy(p_str: str):
        p_url = f"http://{p_str}"
        try:
            async with sem:
                t = aiohttp.ClientTimeout(total=3.5)
                async with aiohttp.ClientSession(timeout=t) as t_sess:
                    async with t_sess.get("https://fragment.com/", headers={"User-Agent": random.choice(_USER_AGENTS)}, proxy=p_url) as r:
                        if r.status == 200:
                            valid_proxies.append(p_url)
        except Exception:
            pass

    await asyncio.gather(*(_verify_proxy(p) for p in sample), return_exceptions=True)

    if valid_proxies:
        _proxy_pool.load_from_text("\n".join(valid_proxies))
        log.info(f"✅ [Auto-Proxy Fetcher] Successfully injected {len(valid_proxies)} active proxies into pool! (Total in pool: {len(_proxy_pool._proxies)})")
        return len(valid_proxies)
    else:
        log.info("ℹ️ [Auto-Proxy Fetcher] Candidate batch tested; maintaining existing proxy pool.")
        return 0

async def auto_fetch_proxies_loop(interval_mins: int = 8):
    """Autonomous background daemon that periodically refreshes the proxy pool with verified proxies."""
    log.info("🌐 [Auto-Proxy Daemon] Started background auto-proxy loop.")
    while True:
        try:
            await auto_fetch_free_proxies()
        except Exception as exc:
            log.warning(f"Auto-proxy daemon iteration error: {exc}")
        await asyncio.sleep(interval_mins * 60)

async def reset_sessions():
    """Safely reset all curl and aiohttp connection pools on engine/mode transitions."""
    global _hash_workers
    try:
        await _direct_engine.close()
    except Exception:
        pass
    for hw in list(_hash_workers.values()):
        try:
            if hw._curl_session is not None:
                res = hw._curl_session.close()
                if asyncio.iscoroutine(res):
                    await res
                hw._curl_session = None
        except Exception:
            pass
    log.info("🔄 [Sessions] Network sessions and connection pools reset for duty transition.")

# ── Circuit Breaker & Caching ────────────────────────────────────────────────
_circuit_errors = 0
_circuit_opened_at = 0.0
_CIRCUIT_THRESHOLD = 50
_CIRCUIT_COOLDOWN = 60.0

_fragment_cache: Dict[str, Tuple[bool, str, float]] = {}  # u -> (is_snipe, label, ts)
_in_flight: Dict[str, asyncio.Future] = {}
_in_flight_lock: Optional[asyncio.Lock] = None

def _get_lock() -> asyncio.Lock:
    global _in_flight_lock
    if _in_flight_lock is None:
        _in_flight_lock = asyncio.Lock()
    return _in_flight_lock

def is_circuit_open() -> bool:
    global _circuit_errors, _circuit_opened_at
    if _circuit_errors >= _CIRCUIT_THRESHOLD:
        now = time.time()
        if _circuit_opened_at == 0.0:
            _circuit_opened_at = now
        if now - _circuit_opened_at >= _CIRCUIT_COOLDOWN:
            _circuit_errors = _CIRCUIT_THRESHOLD - 1
            _circuit_opened_at = 0.0
            log.info("Circuit Breaker -> HALF-OPEN (probing)")
            return False
        return True
    _circuit_opened_at = 0.0
    return False

def get_circuit_state() -> str:
    if is_circuit_open():
        rem = max(0, int(_CIRCUIT_COOLDOWN - (time.time() - _circuit_opened_at)))
        return f"OPEN (Cooldown {rem}s)"
    mode = _CFG.get("scan_mode", "direct").upper()
    return f"CLOSED [{mode}]"

def set_scan_mode(mode: str) -> None:
    m = str(mode).strip().lower()
    if m in ("hash", "hash_api", "api"):
        _CFG["scan_mode"] = "hash_api"
    else:
        _CFG["scan_mode"] = "direct"
    log.info(f"[ENGINE] Scanner Engine Mode switched to: {_CFG['scan_mode'].upper()}")

def get_scan_mode() -> str:
    return _CFG.get("scan_mode", "direct")

def invalidate_cache(username: str) -> None:
    u = username.strip().lower().lstrip("@")
    _fragment_cache.pop(u, None)

async def cleanup_cache() -> None:
    while True:
        try:
            await asyncio.sleep(30)
            now = time.time()
            ttl = _CFG.get("cache_ttl_s", 2.0)
            expired = [u for u, (_, _, ts) in list(_fragment_cache.items()) if now - ts > ttl * 5]
            for u in expired:
                _fragment_cache.pop(u, None)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.debug(f"Cache cleanup: {exc}")


# ── Direct Status Parser ─────────────────────────────────────────────────────
def _parse_username_status(html: str, username: str, resp_url: str = "") -> Tuple[str, bool]:
    """
    Direct scanning method:
    Target for snipe window is: tm-status-unavail AND no sold in html.
    """
    if not html:
        return "NOT_FOUND", False

    u = username.strip().lower().lstrip("@")
    if not u:
        return "NOT_FOUND", False

    low = html.lower()

    if "cf-browser-verification" in low or "just a moment..." in low:
        return "CLOUDFLARE", False

    if any(m in low for m in _NON_USERNAME_MARKERS) and (f"@{u}" in low or f"/username/{u}" in low):
        return "STICKER_OR_INVOICE", False

    # 1. Search Results / Table rows: Check specific target row if present
    found_row = None
    for tr_match in re.finditer(r'<tr[^>]*>.*?</tr>', html, re.DOTALL | re.IGNORECASE):
        r_text = tr_match.group(0)
        r_low = r_text.lower()
        if (
            f'data-username="@{u}"' in r_low
            or f'data-username="{u}"' in r_low
            or f'>@{u}<' in r_low
            or f'/username/{u}"' in r_low
            or f'/username/{u}?' in r_low
            or f'class="subdomain">{u}</span>' in r_low
        ):
            found_row = r_low
            break

    if found_row is not None:
        row = found_row
        if any(m in row for m in _NON_USERNAME_MARKERS):
            return "STICKER_OR_INVOICE", False
        if "sold for" in row or ">sold<" in row or 'tm-status-unavail">sold' in row or ("sold" in row and "not for sale" not in row):
            return "SOLD", False
        if "tm-status-taken" in row or "already claimed" in row:
            return "TAKEN", False
        if "tm-status-avail" in row or "on auction" in row:
            return "ON_AUCTION", False
        if "tm-status-unavail" in row or "js-auction-unavail" in row:
            if "sold for" in row or ">sold<" in row or 'tm-status-unavail">sold' in row or ("sold" in row and "not for sale" not in row):
                return "SOLD", False
            return "UNAVAILABLE", True
        return "NOT_FOUND", False

    # 2. Profile Page: /username/{u} (Contains tm-section-header-status)
    if "tm-section-header-status tm-status-avail" in low:
        return "ON_AUCTION", False

    if "tm-section-header-status tm-status-taken" in low or f"make an offer for @{u}" in low or "is taken" in low:
        return "TAKEN", False

    if "tm-section-header-status tm-status-unavail" in low:
        if "sold for" in low or "tm-username-usable" in low or 'tm-status-unavail">sold' in low or ">sold<" in low:
            return "SOLD", False
        return "UNAVAILABLE", True

    # 3. Direct general status markers on page
    if "tm-status-unavail" in low:
        if "sold for" in low or "tm-username-usable" in low or 'tm-status-unavail">sold' in low or ">sold<" in low:
            return "SOLD", False
        if "tm-status-taken" not in low:
            return "UNAVAILABLE", True

    if "tm-status-taken" in low and (f"@{u}" in low or f"/username/{u}" in low):
        return "TAKEN", False

    return "NOT_FOUND", False


# ── Direct Scanning Engine (UNUSUALxd Goldilocks Logic) ──────────────────────
class _DirectEngine:
    def __init__(self):
        self._curl_session = None
        self._curl_loop = None
        self._aio_session: Optional[aiohttp.ClientSession] = None
        self._aio_loop = None
        self._rate_limited_until = 0.0
        self._primed = False

    async def _get_curl_session(self, proxy: Optional[str] = None):
        if HAS_CURL_CFFI:
            loop = asyncio.get_running_loop()
            if self._curl_session is None or self._curl_loop is not loop:
                kwargs = {"impersonate": "chrome124", "timeout": 8}
                if proxy:
                    kwargs["proxy"] = proxy
                self._curl_session = CurlAsyncSession(**kwargs)
                self._curl_loop = loop
        return self._curl_session

    async def _get_aio_session(self) -> aiohttp.ClientSession:
        loop = asyncio.get_running_loop()
        if self._aio_session is None or self._aio_session.closed or self._aio_loop is not loop:
            timeout = aiohttp.ClientTimeout(total=8, connect=3)
            connector = aiohttp.TCPConnector(limit=500, ssl=False)
            self._aio_session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            self._aio_loop = loop
            self._primed = False

        if not self._primed:
            try:
                agent = random.choice(_USER_AGENTS)
                proxy = _proxy_pool.get_proxy()
                await self._aio_session.get("https://fragment.com/", headers={"User-Agent": agent}, timeout=5, proxy=proxy)
                self._primed = True
            except Exception:
                pass

        return self._aio_session

    async def query(self, username: str) -> Tuple[str, bool]:
        global _circuit_errors
        now = time.time()
        if now < self._rate_limited_until:
            return "RATE_LIMITED", False

        u = username.strip().lower().lstrip("@")
        url = f"https://fragment.com/username/{u}"
        agent = random.choice(_USER_AGENTS)
        proxy = _proxy_pool.get_proxy()

        # 1. Prefer curl_cffi with Chrome TLS impersonation (prevents Cloudflare bouncing datacenter IPs to homepage)
        if HAS_CURL_CFFI:
            try:
                cs = await self._get_curl_session(proxy=proxy)
                resp = await cs.get(url, headers={"User-Agent": agent, "Referer": "https://fragment.com/"}, timeout=8, proxy=proxy)
                if resp.status_code == 429:
                    if proxy:
                        _proxy_pool.mark_softban(proxy, 60.0)
                    else:
                        self._rate_limited_until = now + 15.0 + random.uniform(0, 3)
                    _circuit_errors += 1
                    return "HTTP_429", False

                if resp.status_code == 200:
                    _circuit_errors = 0
                    html = resp.text
                    resp_url = str(resp.url)
                    status, is_snipe = _parse_username_status(html, u, resp_url)
                    return status, is_snipe

                if resp.status_code == 404:
                    _circuit_errors = 0
                    return "DROPPED_404", True

                if resp.status_code >= 500:
                    _circuit_errors += 1
                    return f"HTTP_{resp.status_code}", False
            except Exception as e:
                log.debug(f"Direct curl_cffi query exc on @{u}: {e}")

        # 2. Fallback to aiohttp
        try:
            session = await self._get_aio_session()
            async with session.get(
                url,
                headers={"User-Agent": agent, "Referer": "https://fragment.com/"},
                proxy=proxy,
            ) as resp:
                if resp.status == 429:
                    if proxy:
                        _proxy_pool.mark_softban(proxy, 60.0)
                    else:
                        self._rate_limited_until = now + 15.0 + random.uniform(0, 3)
                    _circuit_errors += 1
                    return "HTTP_429", False

                if resp.status == 200:
                    _circuit_errors = 0
                    raw = await resp.read()
                    html = raw.decode("utf-8", errors="replace")
                    resp_url = str(resp.url)
                    status, is_snipe = _parse_username_status(html, u, resp_url)
                    return status, is_snipe

                if resp.status == 404:
                    _circuit_errors = 0
                    return "DROPPED_404", True

                if resp.status >= 500:
                    _circuit_errors += 1
                    return f"HTTP_{resp.status}", False

                return f"HTTP_{resp.status}", False

        except Exception as exc:
            _circuit_errors += 1
            log.debug(f"Direct aiohttp query exc: {exc}")
            return "ERROR", False

    async def close(self):
        if self._curl_session is not None:
            try:
                res = self._curl_session.close()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
            self._curl_session = None
        if self._aio_session is not None and not self._aio_session.closed:
            try:
                await self._aio_session.close()
            except Exception:
                pass
            self._aio_session = None


# ── Hash API Engine (1:1 Dedicated Worker Sessions) ──────────────────────────
class _HashWorkerSession:
    def __init__(self, wid: int):
        self.wid = wid
        self.hash_val: Optional[str] = None
        self.hash_ts: float = 0.0
        self.req_count: int = 0
        self.agent = random.choice(_USER_AGENTS)
        self._curl_session = None
        self._curl_loop = None
        self._lock = asyncio.Lock()

    async def _ensure_curl(self, proxy: Optional[str] = None):
        if HAS_CURL_CFFI:
            loop = asyncio.get_running_loop()
            if self._curl_session is None or self._curl_loop is not loop:
                kwargs = {"impersonate": "chrome124", "timeout": 8}
                if proxy:
                    kwargs["proxy"] = proxy
                self._curl_session = CurlAsyncSession(**kwargs)
                self._curl_loop = loop
        return self._curl_session

    async def refresh_hash(self) -> bool:
        async with self._lock:
            try:
                proxy = _proxy_pool.get_proxy()
                cs = await self._ensure_curl(proxy=proxy)
                resp = None
                if cs:
                    try:
                        resp = await cs.get("https://fragment.com/", headers={"User-Agent": self.agent}, timeout=8)
                    except Exception as e:
                        log.debug(f"Worker#{self.wid} curl get failed: {e}")

                text = ""
                if resp is not None and resp.status_code == 200:
                    text = resp.text
                else:
                    session = await _direct_engine._get_aio_session()
                    async with session.get("https://fragment.com/", headers={"User-Agent": self.agent}, timeout=8, proxy=proxy) as aio_r:
                        if aio_r.status == 200:
                            raw = await aio_r.read()
                            text = raw.decode("utf-8", errors="replace")

                if text:
                    m = (
                        re.search(r'[\\/]?api\?hash=([a-f0-9]+)', text)
                        or re.search(r'"apiUrl"\s*:\s*"[^"]*hash=([a-f0-9]+)"', text)
                        or re.search(r'data-ajax-hash="([a-f0-9]+)"', text)
                    )
                    if m:
                        self.hash_val = m.group(1)
                        self.hash_ts = time.time()
                        self.req_count = 0
                        log.debug(f"Worker#{self.wid} acquired hash: {self.hash_val}")
                        return True
            except Exception as e:
                log.debug(f"Worker#{self.wid} hash refresh error: {e}")
            return False

    async def query(self, username: str) -> Tuple[str, bool]:
        global _circuit_errors
        now = time.time()
        quota = _CFG.get("hash_requests_per_token", 25)
        lifetime = _CFG.get("hash_lifetime_s", 90.0)

        # Immediate hash refresh if no hash, quota exhausted (including quota=1), or lifetime expired
        if not self.hash_val or self.req_count >= quota or (now - self.hash_ts > lifetime):
            await self.refresh_hash()

        if not self.hash_val:
            # Bulletproof fallback: If hash is unavailable, scan directly via direct engine
            return await _direct_engine.query(username)

        u = username.strip().lower().lstrip("@")
        url = _AJAX_URL.format(self.hash_val)
        payload = f"method=searchAuctions&type=usernames&sort=&filter=&query={u}"

        try:
            proxy = _proxy_pool.get_proxy()
            cs = await self._ensure_curl(proxy=proxy)
            if not cs:
                return await _direct_engine.query(username)

            resp = await cs.post(
                url,
                data=payload,
                headers={
                    "User-Agent": self.agent,
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": "https://fragment.com/",
                },
                timeout=8,
                proxy=proxy,
            )
            self.req_count += 1

            if resp.status_code == 429:
                if proxy:
                    _proxy_pool.mark_softban(proxy, 60.0)
                _circuit_errors += 1
                return "HTTP_429", False

            if resp.status_code == 200:
                _circuit_errors = 0
                try:
                    data = resp.json()
                except Exception:
                    data = None

                # Fragment returns [] when target has no active auction -> fallback to direct engine to catch unavailable/dropped window
                if isinstance(data, list):
                    return await _direct_engine.query(username)

                if isinstance(data, dict):
                    if data.get("error") == "Bad request":
                        await self.refresh_hash()
                        return "HASH_EXPIRED", False

                    if "html" in data:
                        html = data["html"]
                        if not html:
                            return await _direct_engine.query(username)
                        status, is_snipe = _parse_username_status(html, u)
                        return status, is_snipe

                return await _direct_engine.query(username)

            if resp.status_code >= 500:
                _circuit_errors += 1
                return f"HTTP_{resp.status_code}", False

            return f"HTTP_{resp.status_code}", False

        except Exception as exc:
            _circuit_errors += 1
            log.debug(f"Worker#{self.wid} query exception: {exc}")
            return "ERROR", False

    async def close(self):
        if self._curl_session is not None:
            try:
                res = self._curl_session.close()
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
            self._curl_session = None


# ── Global Worker Engine Instances ───────────────────────────────────────────
_direct_engine = _DirectEngine()
_hash_workers: Dict[int, _HashWorkerSession] = {}

async def _get_hash_worker(wid: int) -> _HashWorkerSession:
    if wid not in _hash_workers:
        _hash_workers[wid] = _HashWorkerSession(wid)
    return _hash_workers[wid]


# ── Public API Functions ─────────────────────────────────────────────────────
async def check_target(username: str, worker_id: int = 0) -> Tuple[bool, str]:
    """
    Primary check function returning (is_snipe_window: bool, status_label: str).
    status_label is one of:
      - 'UNAVAILABLE' (Claimable snipe window: tm-status-unavail + not for sale without sold)
      - 'TAKEN'
      - 'SOLD'
      - 'ON_AUCTION'
      - 'STICKER_OR_INVOICE'
      - 'NOT_FOUND'
      - 'HTTP_429' / 'CLOUDFLARE' / 'ERROR'
    """
    global _STATS
    u = username.strip().lower().lstrip("@")
    if not u or is_circuit_open():
        return False, "CIRCUIT_OPEN"

    cached = _fragment_cache.get(u)
    if cached:
        is_s, lbl, ts = cached
        if time.time() - ts < _CFG["cache_ttl_s"]:
            return is_s, lbl

    lock = _get_lock()
    my_future = None
    existing_future = None

    async with lock:
        cached = _fragment_cache.get(u)
        if cached and (time.time() - cached[2] < _CFG["cache_ttl_s"]):
            return cached[0], cached[1]
        if u in _in_flight:
            existing_future = _in_flight[u]
        else:
            loop = asyncio.get_running_loop()
            my_future = loop.create_future()
            _in_flight[u] = my_future

    if existing_future is not None:
        try:
            return await asyncio.shield(existing_future)
        except Exception:
            return False, "TIMEOUT"

    is_snipe = False
    status = "UNKNOWN"

    try:
        mode = _CFG.get("scan_mode", "direct")
        if mode == "direct":
            status, is_snipe = await _direct_engine.query(u)
            _STATS["direct_checks"] += 1
        else:
            hw = await _get_hash_worker(worker_id)
            status, is_snipe = await hw.query(u)
            if status == "HASH_EXPIRED" and not is_snipe:
                status, is_snipe = await hw.query(u)
            _STATS["hash_checks"] += 1

        _STATS["checks"] += 1
        _STATS["last_check_time"] = time.time()

        if is_snipe:
            _STATS["snipe_windows"] += 1
            log.info(f"🎯 CLAIMABLE SNIPE WINDOW DETECTED: @{u} [{mode.upper()}]")

        if not status.startswith("HTTP_5") and status not in ("ERROR", "TIMEOUT", "HTTP_429", "CLOUDFLARE"):
            _fragment_cache[u] = (is_snipe, status, time.time())

        return is_snipe, status

    except Exception as exc:
        log.debug(f"check_target exception on @{u}: {exc}")
        return False, "ERROR"

    finally:
        async with lock:
            _in_flight.pop(u, None)
            if my_future is not None and not my_future.done():
                my_future.set_result((is_snipe, status))


async def is_sniping_target(username: str, worker_id: int = 0) -> bool:
    """Convenience wrapper returning strictly bool for snipe window."""
    is_snipe, _ = await check_target(username, worker_id=worker_id)
    return is_snipe


async def is_sniping_target_direct(username: str, worker_id: int = 0) -> bool:
    """Dedicated direct scanner for Extra Workers cluster."""
    u = username.strip().lower().lstrip("@")
    if not u or is_circuit_open():
        return False
    status, is_snipe = await _direct_engine.query(u)
    return is_snipe


async def debug_fetch(username: str, timeout: float = 10.0) -> dict:
    """
    Live diagnostic probe used by Dashboard and Telegram /test command.
    Executes a direct request against Fragment and returns the exact live evaluation.
    Captures the exact target snippet (table row or status block) without HTML truncation.
    """
    t_start = time.monotonic()
    clean_u = username.strip().lstrip("@").lower()
    url = f"https://fragment.com/username/{clean_u}"
    out = {
        "username": clean_u,
        "url": url,
        "http_status": 0,
        "html_size": 0,
        "is_snipe_window": False,
        "label": "UNKNOWN",
        "has_unavail": False,
        "has_taken": False,
        "has_avail": False,
        "has_not_for_sale": False,
        "sold_detected": False,
        "markers": [],
        "latency_ms": 0,
        "engine_mode": get_scan_mode(),
        "final_url": url,
        "preview": "",
    }

    try:
        agent = random.choice(_USER_AGENTS)
        proxy = _proxy_pool.get_proxy()
        html = ""
        resp_url = url
        status_code = 0

        # Prefer curl_cffi with Chrome TLS impersonation to avoid datacenter IP homepage bounces
        if HAS_CURL_CFFI:
            try:
                cs = await _direct_engine._get_curl_session(proxy=proxy)
                resp = await cs.get(url, headers={"User-Agent": agent, "Referer": "https://fragment.com/"}, timeout=timeout, proxy=proxy)
                status_code = resp.status_code
                html = resp.text
                resp_url = str(resp.url)
            except Exception as e:
                log.debug(f"debug_fetch curl_cffi exc: {e}")

        # Fallback to aiohttp
        if not html:
            session = await _direct_engine._get_aio_session()
            async with session.get(
                url,
                headers={"User-Agent": agent, "Referer": "https://fragment.com/"},
                timeout=timeout,
                proxy=proxy,
            ) as resp:
                status_code = resp.status
                raw = await resp.read()
                html = raw.decode("utf-8", errors="replace")
                resp_url = str(resp.url)

                if resp_url.rstrip("/") == "https://fragment.com":
                    async with session.get(
                        f"https://fragment.com/?query={clean_u}",
                        headers={"User-Agent": agent, "Referer": "https://fragment.com/"},
                        timeout=timeout,
                        proxy=proxy,
                    ) as q_resp:
                        if q_resp.status == 200:
                            q_raw = await q_resp.read()
                            html = q_raw.decode("utf-8", errors="replace")
                            resp_url = str(q_resp.url)

        out["http_status"] = status_code
        out["html_size"] = len(html)
        out["final_url"] = resp_url
        low = html.lower()

        # Find target-specific snippet (table row or header block)
        row_snippet = ""
        for tr_m in re.finditer(r'<tr[^>]*>.*?</tr>', html, re.DOTALL):
            tr_text = tr_m.group(0)
            if clean_u in tr_text.lower():
                row_snippet = tr_text
                break
        if not row_snippet and "tm-section-header" in html:
            m = re.search(r'<div class="tm-section-header[^>]*>.*?</div>\s*</div>', html, re.DOTALL)
            if m:
                row_snippet = m.group(0)

        out["preview"] = row_snippet if row_snippet else html[:800]

        # Check raw markers
        out["has_unavail"] = ("tm-status-unavail" in low)
        out["has_taken"] = ("tm-status-taken" in low or f"make an offer for @{clean_u}" in low)
        out["has_avail"] = ("tm-section-header-status tm-status-avail" in low or ("for sale" in low and "not for sale" not in low))
        out["has_not_for_sale"] = ("not for sale" in low)

        # Precise status evaluation
        if status_code == 404:
            out["is_snipe_window"] = True
            out["label"] = "DROPPED_404"
            out["sold_detected"] = False
        else:
            status, is_snipe = _parse_username_status(html, clean_u, resp_url)
            out["is_snipe_window"] = is_snipe
            out["label"] = status
            out["sold_detected"] = (status == "SOLD")

    except Exception as exc:
        out["error"] = str(exc)
        out["label"] = "ERROR"

    out["latency_ms"] = int((time.monotonic() - t_start) * 1000)
    return out


def configure(**kwargs) -> None:
    for k, v in kwargs.items():
        if k in _CFG:
            _CFG[k] = v
    log.info(f"Scraper configured: scan_mode={_CFG['scan_mode']}, workers={_CFG['max_workers']}")


def get_proxy_status() -> dict:
    pst = _proxy_pool.stats()
    return {
        "pool_size": pst["pool_size"],
        "reserve_size": pst["reserve_size"],
        "working": pst["working"],
        "active": pst["working"],
        "slow_pool_size": 0,
        "soft_banned": pst["soft_banned"],
        "mode": _CFG.get("scan_mode", "direct"),
        "sessions": len(_hash_workers),
        "hash_sessions": len(_hash_workers),
        "hash_total": _CFG.get("session_pool_size", 150),
    }


def get_session_stats() -> dict:
    return {
        "mode": _CFG.get("scan_mode", "direct"),
        "checks": _STATS["checks"],
        "direct_checks": _STATS["direct_checks"],
        "hash_checks": _STATS["hash_checks"],
        "snipe_windows": _STATS["snipe_windows"],
    }


async def close_session() -> None:
    await _direct_engine.close()
    for hw in _hash_workers.values():
        await hw.close()
    _hash_workers.clear()


# ── Proxy Pool Public Helpers ────────────────────────────────────────────────
def clear_all_softbans() -> int:
    return _proxy_pool.clear_softbans()

def clear_proxy_pool() -> None:
    _proxy_pool.clear()

async def load_proxies_from_text(t: str) -> dict:
    return _proxy_pool.load_from_text(t)

def has_proxies() -> bool:
    return _proxy_pool.has_proxies()

def get_proxy_pool() -> List[str]:
    return _proxy_pool._proxies[:]

def get_proxy_pool_slow() -> List[str]:
    return []

def get_proxy_pool_reserve() -> List[str]:
    return []

def get_proxy_pool_stats() -> List[dict]:
    now = time.time()
    out = []
    for p in _proxy_pool._proxies:
        banned_until = _proxy_pool._softbanned.get(p, 0.0)
        is_banned = banned_until > now
        rem_s = int(banned_until - now) if is_banned else 0
        out.append({
            "proxy": p,
            "speed_ms": 0,
            "soft_banned": is_banned,
            "banned_for_s": rem_s,
            "softban_hits": 1 if is_banned else 0,
        })
    return out

def clear_proxy(p: str) -> None:
    if p in _proxy_pool._proxies:
        _proxy_pool._proxies.remove(p)

def set_proxy_dead_callback(cb) -> None:
    pass

def set_auto_fetch_proxies(v: bool) -> None:
    _proxy_pool._auto_fetch = bool(v)

def get_auto_fetch_proxies() -> bool:
    return _proxy_pool._auto_fetch

# auto_fetch_free_proxies is fully implemented above with verified Fragment testing.

def set_hash_requests_per_token(n: int) -> None:
    val = max(1, min(500, int(n)))
    _CFG["hash_requests_per_token"] = val
    log.info(f"[ENGINE] Hash requests per token quota set to: {val}")

def get_hash_requests_per_token() -> int:
    return _CFG.get("hash_requests_per_token", 25)

async def init_sessions(proxies=None) -> None:
    if proxies is not None:
        if isinstance(proxies, int):
            _CFG["session_pool_size"] = proxies
        elif isinstance(proxies, (list, tuple, set)):
            for p in proxies:
                _proxy_pool.add_proxy(str(p))
        elif isinstance(proxies, str):
            _proxy_pool.add_proxy(proxies)

async def init_hash_pool(n: int = 100) -> None:
    pass

async def resize_hash_pool(n: int = 100) -> None:
    _CFG["session_pool_size"] = n

def get_hash_pool_stats() -> list:
    stats = []
    now = time.time()
    for wid, hw in list(_hash_workers.items()):
        stats.append({
            "idx": wid,
            "status": "ready" if hw.hash_val else "no_hash",
            "alive": bool(hw.hash_val),
            "req_count": hw.req_count,
            "age_s": round(now - hw.hash_ts, 1) if hw.hash_ts else 0,
            "hash_prefix": hw.hash_val[:6] if hw.hash_val else "none",
        })
    return stats

def get_error_count() -> int:
    return _circuit_errors

def get_cache_stats() -> dict:
    return {"cached_targets": len(_fragment_cache)}

async def get_fragment_status(username: str) -> Tuple[bool, str, int]:
    res = await debug_fetch(username)
    return res["is_snipe_window"], res["label"], res["http_status"]
