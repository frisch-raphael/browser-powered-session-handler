import asyncio
import base64
import hashlib
import json
import re
import time
from http.cookies import SimpleCookie
from typing import Optional, Dict, List, Any
import os
from urllib.parse import urlparse

from fastapi import FastAPI, Response, HTTPException
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


# ======================
# Defaults
# ======================

DEFAULT_NAV_TIMEOUT_MS = 30000
DEFAULT_WAIT_TOKEN_TIMEOUT_MS = 3000
DEFAULT_REFRESH_SKEW_SECONDS = 10


app = FastAPI(
    title="Browser Powered Session Handler Token Service", version="2.0")


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


class AuthStep(BaseModel):
    type: str
    selector: str
    value: Optional[str] = None
    pin: Optional[str] = None
    cert_cn: Optional[str] = None


class TokenParsingConfig(BaseModel):
    mode: str
    path: Optional[str] = None
    cookie_name: Optional[str] = None


class TokenConfig(BaseModel):
    token_url_substring: str
    refresh_frequency_seconds: Optional[int] = Field(None, ge=5, le=86400)
    refresh_skew_seconds: int = Field(
        DEFAULT_REFRESH_SKEW_SECONDS, ge=0, le=86400)
    nav_timeout_ms: int = Field(
        DEFAULT_NAV_TIMEOUT_MS, ge=1000, le=180000)
    wait_token_timeout_ms: int = Field(
        DEFAULT_WAIT_TOKEN_TIMEOUT_MS, ge=500, le=60000)
    parsing: TokenParsingConfig


class TokenRequest(BaseModel):
    authentication_url: str
    headless: bool
    steps: List[AuthStep]
    force: bool = False
    mtls_enabled: bool = False
    mtls_hostname: Optional[str] = None
    mtls_pin: Optional[str] = None
    mtls_cert_cn: Optional[str] = None


def validate_token_config(cfg: TokenConfig) -> None:
    if not cfg.token_url_substring:
        raise HTTPException(
            status_code=400, detail="token.token_url_substring is required")
    if cfg.parsing.mode not in ("json_path", "cookie"):
        raise HTTPException(
            status_code=400, detail="token.parsing.mode must be json_path or cookie")
    if cfg.parsing.mode == "json_path" and not cfg.parsing.path:
        raise HTTPException(
            status_code=400, detail="token.parsing.path is required for json_path mode")
    if cfg.parsing.mode == "cookie" and not cfg.parsing.cookie_name:
        raise HTTPException(
            status_code=400, detail="token.parsing.cookie_name is required for cookie mode")


def validate_token_request(req: TokenRequest) -> None:
    if not req.authentication_url:
        raise HTTPException(
            status_code=400, detail="authentication_url is required")
    if not req.steps or len(req.steps) < 1:
        raise HTTPException(
            status_code=400, detail="At least one authentication step is required")
    for i, step in enumerate(req.steps):
        if step.type not in ("click", "input", "wait_load_state"):
            raise HTTPException(
                status_code=400, detail=f"Invalid step type at index {i}")
        if step.type in ("click", "input") and not step.selector:
            raise HTTPException(
                status_code=400, detail=f"Missing selector at index {i}")
        if step.type == "input" and (step.value is None or not str(step.value).strip()):
            raise HTTPException(
                status_code=400, detail=f"Missing input value at index {i}")
        if step.type == "wait_load_state":
            state = (step.value or "load").strip().lower()
            if state not in ("load", "domcontentloaded", "networkidle"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid load state at index {i} (load, domcontentloaded, networkidle)",
                )


# ======================
# Config + caching (per-config)
# ======================
def config_cache_key(token_cfg: TokenConfig, auth_req: TokenRequest) -> str:
    """
    Stable cache key. Includes all config fields (so different configs don't share tokens).
    Not logged, not returned.
    """
    auth_data = auth_req.dict()
    auth_data["force"] = False
    material = json.dumps(
        {"token": token_cfg.dict(), "auth": auth_data},
        sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
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

config_guard = asyncio.Lock()
active_token_config: Optional[TokenConfig] = None


def parse_json_path(path: str) -> List[Any]:
    tokens: List[Any] = []
    for match in re.finditer(r"([^\.\[\]]+)|\[(\d+)\]", path):
        key, idx = match.groups()
        if key is not None:
            tokens.append(key)
        elif idx is not None:
            tokens.append(int(idx))
    return tokens


def extract_json_path(data: Any, path: str) -> Optional[Any]:
    tokens = parse_json_path(path)
    current = data
    try:
        for token in tokens:
            if isinstance(token, int):
                if not isinstance(current, list) or token >= len(current):
                    return None
                current = current[token]
            else:
                if not isinstance(current, dict) or token not in current:
                    return None
                current = current[token]
        return current
    except Exception:
        return None


async def run_auth_steps(page, token_cfg: TokenConfig, auth_req: TokenRequest) -> None:
    for step in auth_req.steps:
        if step.type == "wait_load_state":
            state = (step.value or "load").strip().lower()
            await page.wait_for_load_state(state=state, timeout=token_cfg.nav_timeout_ms)
            continue

        try:
            await page.wait_for_selector(step.selector, timeout=token_cfg.nav_timeout_ms)
        except PlaywrightTimeoutError as e:
            current = page.url
            raise RuntimeError(
                f"Selector not found for step '{step.type}'. Current URL: {current}") from e
        if step.type == "input":
            await page.fill(step.selector, step.value)
        else:
            await page.click(step.selector)


def should_run_mtls(req: TokenRequest, url: str) -> bool:
    if not req.mtls_enabled:
        return False
    hostname = (req.mtls_hostname or "").strip().lower()
    if not hostname:
        return True
    target_host = (urlparse(url).hostname or "").lower()
    return hostname in target_host


async def goto_with_optional_mtls(page, token_cfg: TokenConfig, auth_req: TokenRequest) -> None:
    goto_task = asyncio.create_task(
        page.goto(
            auth_req.authentication_url,
            wait_until="load",
            timeout=token_cfg.nav_timeout_ms,
        )
    )

    if should_run_mtls(auth_req, auth_req.authentication_url):
        try:
            from mtls_authent_service import run_mtls_auth
        except Exception as exc:
            raise RuntimeError(
                "mTLS is enabled but mtls_authent_service is unavailable"
            ) from exc
        time.sleep(3)
        loop = asyncio.get_running_loop()
        pin = (auth_req.mtls_pin or "").strip() or None
        cert_cn = (auth_req.mtls_cert_cn or "").strip() or None
        hostname = (auth_req.mtls_hostname or "").strip() or None
        await loop.run_in_executor(None, run_mtls_auth, pin, cert_cn, hostname)

    await goto_task


async def fetch_token_via_playwright(token_cfg: TokenConfig, auth_req: TokenRequest) -> str:
    token_json: dict = {}
    token_raw: Optional[str] = None
    token_event = asyncio.Event()

    def maybe_capture_token_response(url: str) -> bool:
        return token_cfg.token_url_substring in url

    async with async_playwright() as p:
        FIREFOX_EXE = "C:\\Users\\Rapha\\AppData\\Local\\ms-playwright\\firefox-1497\\firefox\\firefox.exe"
        PROFILE_DIR = "C:\\tmp\\pw-firefox-profile"
        browser = await p.firefox.launch_persistent_context(
            headless=auth_req.headless,
            user_data_dir=PROFILE_DIR,
            executable_path=FIREFOX_EXE,
            ignore_https_errors=True,
            env={
                **os.environ,
                "SOFTHSM2_CONF": r"C:\SoftHSM2\etc\softhsm2.conf",
            },
        )

        page = await browser.new_page()

        async def on_response(resp):
            nonlocal token_json, token_raw
            try:
                if not maybe_capture_token_response(resp.url):
                    return
                if token_cfg.parsing.mode == "cookie":
                    cookie_name = (token_cfg.parsing.cookie_name or "").strip()
                    header_value = resp.headers.get("set-cookie")
                    if header_value:
                        jar = SimpleCookie()
                        jar.load(header_value)
                        if cookie_name in jar:
                            token_raw = jar[cookie_name].value.strip()
                            if token_raw:
                                token_event.set()
                            return
                data = await resp.json()
                if isinstance(data, dict):
                    token_json = data
                    token_event.set()
            except Exception:
                return

        page.on("response", on_response)

        await goto_with_optional_mtls(page, token_cfg, auth_req)
        await run_auth_steps(page, token_cfg, auth_req)

        try:
            await asyncio.wait_for(token_event.wait(), timeout=token_cfg.wait_token_timeout_ms / 1000)
        except asyncio.TimeoutError as e:
            current = page.url
            # await context.close()
            await browser.close()
            raise RuntimeError(
                f"Timed out waiting for token JSON response. Still at URL: {current}. "
                f"Check token_url_substring or whether tokens are fetched differently."
            ) from e

        # await context.close()
        await browser.close()

    if token_cfg.parsing.mode == "cookie":
        if token_raw:
            if token_raw.lower().startswith("bearer "):
                token_raw = token_raw[7:].strip()
            return token_raw
        raise RuntimeError("Token cookie was missing or empty.")

    token_value = extract_json_path(token_json, token_cfg.parsing.path or "")
    if not isinstance(token_value, str) or not token_value.strip():
        raise RuntimeError("Token not found at configured JSON path.")
    return token_value.strip()


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/config")
async def update_config(cfg: TokenConfig):
    validate_token_config(cfg)
    async with config_guard:
        global active_token_config
        active_token_config = cfg
    await cache_mgr.invalidate_all()
    return {"ok": True}


@app.post("/token")
async def token(req: TokenRequest):
    """
    Returns ONLY the raw JWT as plain text.
    """
    try:
        async with config_guard:
            token_cfg = active_token_config
        if token_cfg is None:
            raise HTTPException(
                status_code=400, detail="Configuration not set. Update config first.")
        validate_token_config(token_cfg)
        validate_token_request(req)
        key = config_cache_key(token_cfg, req)
        entry = await cache_mgr.get_entry(key)

        async with entry.lock:
            if not req.force and entry.valid(token_cfg.refresh_skew_seconds):
                # type: ignore[arg-type]
                return Response(content=entry.token, media_type="text/plain")

            token_value = await fetch_token_via_playwright(token_cfg, req)
            exp = decode_jwt_exp(token_value) or 0

            entry.token = token_value
            entry.exp = exp

            if token_cfg.refresh_frequency_seconds is not None:
                entry.next_forced_refresh = int(
                    time.time()) + token_cfg.refresh_frequency_seconds
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
