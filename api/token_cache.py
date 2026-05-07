import asyncio
import hashlib
import json
import time
from typing import Dict, Optional

from token_models import TokenConfig, TokenRequest


def config_cache_key(token_cfg: TokenConfig, auth_req: TokenRequest) -> str:
    """
    Stable cache key. Includes all config fields (so different configs don't share tokens).
    Not logged, not returned.
    """
    auth_data = auth_req.dict()
    auth_data["force"] = False
    auth_data.pop("token_config", None)
    token_data = token_cfg.dict()
    token_data.pop("refresh_frequency_seconds", None)
    token_data.pop("refresh_skew_seconds", None)
    token_data.pop("nav_timeout_ms", None)
    token_data.pop("wait_token_timeout_ms", None)
    material = json.dumps(
        {"token": token_data, "auth": auth_data},
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

        if self.next_forced_refresh > 0 and now >= self.next_forced_refresh:
            return False

        # Exp-based validity is intentionally disabled for now.
        # if self.exp <= 0:
        #     return True
        # return now < (self.exp - skew_seconds)
        return True


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

    async def snapshot(self) -> Dict[str, TokenCacheEntry]:
        async with self._guard:
            return dict(self._entries)
