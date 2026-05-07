import asyncio
import time
from typing import Optional

from token_models import TokenConfig
from token_utils import extract_json_path, normalize_token_value


async def wait_for_cookie_token(context, token_cfg: TokenConfig) -> str:
    cookie_name = (token_cfg.parsing.cookie_name or "").strip()
    deadline = time.monotonic() + (token_cfg.wait_token_timeout_ms / 1000)

    while time.monotonic() < deadline:
        cookies = await context.cookies()
        token = next(
            (
                normalize_token_value(cookie["value"])
                for cookie in cookies
                if cookie["name"] == cookie_name and cookie.get("value")
            ),
            None,
        )
        if token:
            return token
        await asyncio.sleep(0.05)

    raise RuntimeError(f"Timed out waiting for token cookie '{cookie_name}'.")


class JsonResponseTokenExtractor:
    def __init__(self, token_cfg: TokenConfig) -> None:
        self.token_cfg = token_cfg
        self.token_json: dict = {}
        self.token_event = asyncio.Event()
        self.token_error: Optional[Exception] = None

    async def before_auth(self, page, context) -> None:
        page.on("response", self.on_response)

    async def on_response(self, resp) -> None:
        try:
            if self.token_cfg.token_url_substring not in resp.url:
                return
            data = await resp.json()
            if isinstance(data, dict):
                self.token_json = data
                self.token_event.set()
        except Exception as exc:
            self.token_error = exc
            self.token_event.set()

    async def wait_for_token(self, page, context) -> str:
        try:
            await asyncio.wait_for(
                self.token_event.wait(),
                timeout=self.token_cfg.wait_token_timeout_ms / 1000,
            )
        except asyncio.TimeoutError as e:
            raise RuntimeError(
                f"Timed out waiting for token response. Still at URL: {page.url}. "
                f"Check token_url_substring or whether tokens are fetched differently."
            ) from e

        if self.token_error is not None:
            raise RuntimeError(
                "Failed to parse token response as JSON.") from self.token_error

        token_value = extract_json_path(
            self.token_json, self.token_cfg.parsing.path or "")
        if not isinstance(token_value, str) or not token_value.strip():
            raise RuntimeError("Token not found at configured JSON path.")
        return normalize_token_value(token_value)


class CookieTokenExtractor:
    def __init__(self, token_cfg: TokenConfig) -> None:
        self.token_cfg = token_cfg

    async def before_auth(self, page, context) -> None:
        await context.clear_cookies(name=(self.token_cfg.parsing.cookie_name or "").strip())

    async def wait_for_token(self, page, context) -> str:
        return await wait_for_cookie_token(context, self.token_cfg)


def make_token_extractor(token_cfg: TokenConfig):
    if token_cfg.parsing.mode == "cookie":
        return CookieTokenExtractor(token_cfg)
    return JsonResponseTokenExtractor(token_cfg)
