import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import time
from typing import Optional, Dict, Tuple

from fastapi import FastAPI, Response, HTTPException, Query
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ======================
# Defaults (env)
# ======================

DEFAULT_FORCE_REFRESH = False
DEFAULT_AUTHENT_URL = os.getenv(
    "COCKPIT_URL", "")
DEFAULT_USERNAME = os.getenv(
    "OIDC_USERNAME", "")
DEFAULT_PASSWORD = os.getenv("OIDC_PASSWORD", "")

DEFAULT_USERNAME_SELECTOR = os.getenv("USERNAME_SELECTOR", "input#username")
DEFAULT_PASSWORD_SELECTOR = os.getenv("PASSWORD_SELECTOR", "input#password")
DEFAULT_SUBMIT_SELECTOR = os.getenv("SUBMIT_SELECTOR", "button#kc-login")

DEFAULT_TOKEN_URL_SUBSTRING = os.getenv(
    "TOKEN_URL_SUBSTRING", "/protocol/openid-connect/token")

DEFAULT_HEADLESS = os.getenv("HEADLESS", "false").lower() == "true"
DEFAULT_NAV_TIMEOUT_MS = int(os.getenv("NAV_TIMEOUT_MS", "30000"))
DEFAULT_WAIT_TOKEN_TIMEOUT_MS = int(os.getenv("WAIT_TOKEN_TIMEOUT_MS", "3000"))

# "Skew" means: refresh the token this many seconds BEFORE it expires.
DEFAULT_REFRESH_SKEW_SECONDS = int(os.getenv("REFRESH_SKEW_SECONDS", "10"))


app = FastAPI(title="OIDC Playwright Token Service", version="1.1")


# ======================
# Helpers
# ======================

def decode_jwt_exp(jwt_token: str) -> Optional[int]:
    """
    Decode JWT payload without verifying signature to extract exp.
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # base64url padding
        payload = json.loads(base64.urlsafe_b64decode(
            payload_b64.encode("utf-8")))
        exp = payload.get("exp")
        return exp if isinstance(exp, int) else None
    except Exception:
        return None


def parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def parse_selectors(selectors_raw: Optional[str]) -> Tuple[str, str, str]:
    """
    Accept selectors as either:
    - JSON string: {"username":"input#username","password":"input#password","submit":"button#kc-login"}
    - OR compact: username=input#username;password=input#password;submit=button#kc-login
    If not provided, uses env defaults.
    """
    if not selectors_raw or not selectors_raw.strip():
        return DEFAULT_USERNAME_SELECTOR, DEFAULT_PASSWORD_SELECTOR, DEFAULT_SUBMIT_SELECTOR

    raw = selectors_raw.strip()

    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            u = str(data["username"])
            p = str(data["password"])
            s = str(data["submit"])
            return u, p, s
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid selectors JSON: {exc}")

    data: Dict[str, str] = {}
    try:
        for pair in raw.split(";"):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise ValueError(
                    f"Bad selectors pair '{pair}' (expected key=value)")
            k, v = pair.split("=", 1)
            data[k.strip()] = v.strip()

        u = data.get("username", DEFAULT_USERNAME_SELECTOR)
        p = data.get("password", DEFAULT_PASSWORD_SELECTOR)
        s = data.get("submit", DEFAULT_SUBMIT_SELECTOR)
        return u, p, s
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid selectors format: {exc}")


# ======================
# Config + caching (per-config)
# ======================
@dataclasses.dataclass(frozen=True)
class TokenConfig:
    cockpit_url: str
    username: str
    password: str
    headless: bool
    username_selector: str
    password_selector: str
    submit_selector: str
    token_url_substring: str
    nav_timeout_ms: int
    wait_token_timeout_ms: int
    refresh_skew_seconds: int
    # if set, force refresh after N seconds even if exp is long
    refresh_frequency_seconds: Optional[int]


def config_cache_key(cfg: TokenConfig) -> str:
    """
    Stable cache key. Includes password (so different creds don't share tokens).
    Not logged, not returned.
    """
    material = json.dumps(dataclasses.asdict(
        cfg), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class TokenCacheEntry:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.token: Optional[str] = None
        self.exp: int = 0
        self.next_forced_refresh: int = 0  # epoch seconds, 0 = disabled

    def valid(self, skew_seconds: int) -> bool:
        if not self.token:
            return False

        now = int(time.time())

        # Forced refresh interval (if configured)
        if self.next_forced_refresh > 0 and now >= self.next_forced_refresh:
            return False

        # Exp-based validity
        if self.exp <= 0:
            return True  # exp unknown, treat as valid until forced refresh
        return now < (self.exp - skew_seconds)


class TokenCacheManager:
    def __init__(self) -> None:
        self._entries: Dict[str, TokenCacheEntry] = {}
        self._guard = asyncio.Lock()

    async def get_entry(self, key: str) -> TokenCacheEntry:
        async with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = TokenCacheEntry()
                self._entries[key] = entry
            return entry

    async def invalidate_all(self) -> None:
        async with self._guard:
            self._entries.clear()


cache_mgr = TokenCacheManager()


async def fetch_token_via_playwright(cfg: TokenConfig) -> str:
    if not cfg.password:
        raise RuntimeError(
            "Password is empty (provide password param or OIDC_PASSWORD env var).")

    token_json: dict = {}
    token_event = asyncio.Event()

    def maybe_capture_token_response(url: str) -> bool:
        return cfg.token_url_substring in url

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=cfg.headless)
        context = await browser.new_context()
        page = await context.new_page()

        async def on_response(resp):
            nonlocal token_json
            try:
                if not maybe_capture_token_response(resp.url):
                    return
                data = await resp.json()
                if isinstance(data, dict) and "access_token" in data:
                    token_json = data
                    token_event.set()
            except Exception:
                return

        page.on("response", on_response)

        await page.goto(cfg.cockpit_url, wait_until="domcontentloaded", timeout=cfg.nav_timeout_ms)

        try:
            await page.wait_for_selector(cfg.username_selector, timeout=cfg.nav_timeout_ms)
        except PlaywrightTimeoutError as e:
            current = page.url
            await context.close()
            await browser.close()
            raise RuntimeError(
                f"Username field not found. Current URL: {current}") from e

        await page.fill(cfg.username_selector, cfg.username)
        await page.click(cfg.submit_selector)

        try:
            await page.wait_for_selector(cfg.password_selector, timeout=cfg.nav_timeout_ms)
        except PlaywrightTimeoutError as e:
            current = page.url
            await context.close()
            await browser.close()
            raise RuntimeError(
                f"Password field not found. Current URL: {current}") from e

        await page.fill(cfg.password_selector, cfg.password)
        await page.click(cfg.submit_selector)

        try:
            await asyncio.wait_for(token_event.wait(), timeout=cfg.wait_token_timeout_ms / 1000)
        except asyncio.TimeoutError as e:
            current = page.url
            await context.close()
            await browser.close()
            raise RuntimeError(
                f"Timed out waiting for token JSON response. Still at URL: {current}. "
                f"Check token_url_substring or whether tokens are fetched differently."
            ) from e

        await context.close()
        await browser.close()

    access_token = token_json.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise RuntimeError(
            "Captured token JSON but access_token is missing/empty.")
    return access_token.strip()


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/token")
async def token(
    url: str = Query(DEFAULT_AUTHENT_URL),
    username: str = Query(DEFAULT_USERNAME),
    password: str = Query(DEFAULT_PASSWORD),
    headless: Optional[str] = Query(
        None, description="true/false (overrides env HEADLESS)"),

    # Caching knobs
    refresh_frequency: Optional[int] = Query(
        None, ge=5, le=86400,
        description="Force refresh after N seconds (independent of JWT exp)."
    ),
    refresh_skew_seconds: int = Query(
        DEFAULT_REFRESH_SKEW_SECONDS, ge=0, le=86400,
        description="Refresh this many seconds before JWT exp."
    ),

    selectors: Optional[str] = Query(
        None,
        description=(
            "Selectors as JSON or key=value pairs. "
            "JSON: {\"username\":\"input#username\",\"password\":\"input#password\",\"submit\":\"button#kc-login\"} "
            "Pairs: username=input#username;password=input#password;submit=button#kc-login"
        ),
    ),

    token_url_substring: str = Query(DEFAULT_TOKEN_URL_SUBSTRING),
    nav_timeout_ms: int = Query(DEFAULT_NAV_TIMEOUT_MS, ge=1000, le=180000),
    wait_token_timeout_ms: int = Query(
        DEFAULT_WAIT_TOKEN_TIMEOUT_MS, ge=500, le=60000),

    force: bool = Query(
        False, description="Force refresh even if cached token is valid."),
):
    """
    Returns ONLY the raw JWT as plain text.
    """
    try:
        u_sel, p_sel, s_sel = parse_selectors(selectors)
        cfg = TokenConfig(
            cockpit_url=url,
            username=username,
            password=password,
            headless=parse_bool(headless, DEFAULT_HEADLESS),
            username_selector=u_sel,
            password_selector=p_sel,
            submit_selector=s_sel,
            token_url_substring=token_url_substring,
            nav_timeout_ms=nav_timeout_ms,
            wait_token_timeout_ms=wait_token_timeout_ms,
            refresh_skew_seconds=refresh_skew_seconds,
            refresh_frequency_seconds=refresh_frequency,
        )

        key = config_cache_key(cfg)
        entry = await cache_mgr.get_entry(key)

        async with entry.lock:
            if not force and entry.valid(cfg.refresh_skew_seconds):
                # type: ignore[arg-type]
                return Response(content=entry.token, media_type="text/plain")

            token_value = await fetch_token_via_playwright(cfg)
            exp = decode_jwt_exp(token_value) or 0

            entry.token = token_value
            entry.exp = exp

            if cfg.refresh_frequency_seconds is not None:
                entry.next_forced_refresh = int(
                    time.time()) + cfg.refresh_frequency_seconds
            else:
                entry.next_forced_refresh = 0

            return Response(content=token_value, media_type="text/plain")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/invalidate")
async def invalidate():
    await cache_mgr.invalidate_all()
    return {"ok": True}
