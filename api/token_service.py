import asyncio
import sys
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Response

from browser_service import fetch_token_via_playwright
from token_cache import TokenCacheManager, config_cache_key
from token_models import TokenConfig, TokenRequest
from token_utils import decode_jwt_exp
from token_validation import validate_token_config, validate_token_request


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


app = FastAPI(
    title="Browser Powered Session Handler Token Service", version="2.0")

cache_mgr = TokenCacheManager()
config_guard = asyncio.Lock()
active_token_config: Optional[TokenConfig] = None


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
        token_cfg = req.token_config
        if token_cfg is None:
            async with config_guard:
                token_cfg = active_token_config
        if token_cfg is None:
            raise HTTPException(
                status_code=400, detail="Configuration not set. Update config first or embed token_config.")

        validate_token_config(token_cfg)
        validate_token_request(req)
        key = config_cache_key(token_cfg, req)
        entry = await cache_mgr.get_entry(key)

        async with entry.lock:
            if not req.force and entry.valid(token_cfg.refresh_skew_seconds):
                # type: ignore[arg-type]
                return Response(content=entry.token, media_type="text/plain")

            token_value = await fetch_token_via_playwright(token_cfg, req, key)
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


@app.get("/cache")
async def cache():
    entries = await cache_mgr.snapshot()
    items = []
    for key, entry in entries.items():
        items.append({
            "key": key,
            "token": entry.token,
            "exp": entry.exp,
            "next_forced_refresh": entry.next_forced_refresh,
        })
    return {"count": len(items), "entries": items}
