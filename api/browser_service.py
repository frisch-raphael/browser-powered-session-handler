import asyncio
import os

from playwright.async_api import async_playwright

from auth_flow import goto_with_optional_mtls, run_auth_steps
from browser_profiles import profile_dir_for_cache_key, resolve_firefox_executable
from token_extractors import make_token_extractor
from token_models import TokenConfig, TokenRequest


browser_guard = asyncio.Lock()


async def fetch_token_via_playwright(token_cfg: TokenConfig, auth_req: TokenRequest, cache_key: str) -> str:
    async with browser_guard:
        return await _fetch_token_via_playwright(token_cfg, auth_req, cache_key)


async def _fetch_token_via_playwright(token_cfg: TokenConfig, auth_req: TokenRequest, cache_key: str) -> str:
    async with async_playwright() as p:
        api_dir = os.path.dirname(__file__)
        firefox_exe = resolve_firefox_executable(api_dir)
        profile_dir = profile_dir_for_cache_key(api_dir, cache_key)
        proxy = (auth_req.proxy or "").strip() or None
        launch_args = {
            "headless": auth_req.headless,
            "user_data_dir": profile_dir,
            "ignore_https_errors": True,
            "proxy": {"server": proxy} if proxy else None,
            "env": {
                **os.environ
                # "SOFTHSM2_CONF": r"C:\SoftHSM2\etc\softhsm2.conf",
            },
        }
        if firefox_exe:
            launch_args["executable_path"] = firefox_exe
        context = await p.firefox.launch_persistent_context(**launch_args)

        page = context.pages[0] if context.pages else await context.new_page()
        extractor = make_token_extractor(token_cfg)

        try:
            await extractor.before_auth(page, context)
            await goto_with_optional_mtls(page, token_cfg, auth_req)
            await run_auth_steps(page, token_cfg, auth_req)
            return await extractor.wait_for_token(page, context)
        finally:
            await context.close()
