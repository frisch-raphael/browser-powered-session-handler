import asyncio
from urllib.parse import urlparse

from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from token_models import TokenConfig, TokenRequest
from token_validation import parse_wait_time_ms


async def run_auth_steps(page, token_cfg: TokenConfig, auth_req: TokenRequest) -> None:
    for step in auth_req.steps:
        if step.type == "wait_load_state":
            state = (step.value or "load").strip().lower()
            await page.wait_for_load_state(state=state, timeout=token_cfg.nav_timeout_ms)
            continue
        if step.type == "wait_url":
            url_pattern = (step.value or "").strip()
            await page.wait_for_url(url_pattern, timeout=token_cfg.nav_timeout_ms)
            continue
        if step.type == "wait_time":
            wait_ms = parse_wait_time_ms(step.value or "")
            await asyncio.sleep(wait_ms / 1000)
            continue
        if step.type == "wait_selector":
            try:
                await page.wait_for_selector(step.selector, timeout=token_cfg.nav_timeout_ms)
            except PlaywrightTimeoutError as e:
                current = page.url
                raise RuntimeError(
                    f"Selector not found for step '{step.type}'. Current URL: {current}"
                ) from e
            continue

        try:
            await page.wait_for_selector(step.selector, timeout=token_cfg.nav_timeout_ms)
        except PlaywrightTimeoutError as e:
            current = page.url
            raise RuntimeError(
                f"Selector not found for step '{step.type}'. Current URL: {current}") from e
        if step.type in ("input", "secure_input"):
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
        await asyncio.sleep(3)
        loop = asyncio.get_running_loop()
        pin = (auth_req.mtls_pin or "").strip() or None
        cert_cn = (auth_req.mtls_cert_cn or "").strip() or None
        hostname = (auth_req.mtls_hostname or "").strip() or None
        await loop.run_in_executor(None, run_mtls_auth, pin, cert_cn, hostname)

    await goto_task
